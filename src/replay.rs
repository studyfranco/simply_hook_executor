//! Single-use enforcement for `CANONICAL_V1` signatures.
//!
//! The timestamp window in [`crate::middleware`] bounds *how long* a captured request stays useful;
//! it does nothing about the request being used more than once inside that window. Those are
//! different properties, and only the second one is replay protection in the sense an attacker
//! cares about: someone who can observe a signed `POST /api/hooks/{id}/execute` — a TLS-terminating
//! proxy, a log aggregator that captured headers, anyone on the wire before TLS — can resend it
//! verbatim and run the hook again. The signature is valid, the timestamp is fresh, and every check
//! that existed before this module passes.
//!
//! [`ReplayGuard`] closes that by remembering which signatures have already been accepted and
//! refusing a second use. A signature is only ever recorded **after** it has been verified, which is
//! what keeps this from becoming a memory-exhaustion target: filling the map requires producing
//! valid HMACs, which requires the signing secret.
//!
//! Scope is deliberately narrow. `BODY_ONLY` keys are not tracked here — that mode signs the body
//! alone and carries no timestamp, so there is no window to be single-use *within*, and per
//! `AGENT.MD` it exists precisely to accept third-party senders whose format cannot be changed.
//! Recording those would silently break the redelivery that GitHub-style senders perform on
//! purpose. See the Convergence Parity Check in `AGENT_NOTES.MD`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

// `tokio`'s monotonic clock rather than `std`'s, for two reasons. It is the same monotonic source in
// production — immune to NTP steps and manual clock changes, which a wall clock is not, and which
// would otherwise let a backwards jump resurrect expired entries or a forwards one retire live ones.
// And under `#[tokio::test(start_paused = true)]` it can be advanced instantly, which is what lets
// the expiry and capacity behaviour below be asserted at all: the alternative is a test that sleeps
// for the length of a real replay window.
use tokio::time::Instant;
use uuid::Uuid;

/// How often expired entries are swept out, as a fraction of the replay window.
///
/// Pruning on every insertion would be O(n) per request inside the lock every authenticated request
/// must take; pruning never would let the map hold every signature since boot. Sweeping once per
/// window-quarter bounds the map at roughly the signatures accepted in 1.25 windows while keeping
/// the amortized cost per request negligible.
const PRUNE_INTERVAL_DIVISOR: u32 = 4;

/// Minimum spacing between two *capacity-triggered* sweeps, as a fraction of the replay window.
///
/// A capacity sweep deliberately bypasses the routine interval so the ceiling is enforced promptly.
/// Without a floor on how often that may happen, a map saturated with entries that are all still
/// live would sweep on *every single request* — freeing nothing, because nothing has expired, and
/// reinstating exactly the per-request O(n) scan under the global mutex that
/// [`PRUNE_INTERVAL_DIVISOR`] exists to remove. That turns a memory-pressure symptom into a
/// throughput collapse precisely when the daemon is busiest. Backing off to a sixteenth of the
/// window (≈18s at the default 300s) keeps the response prompt while bounding the wasted work.
const CAPACITY_BACKOFF_DIVISOR: u32 = 16;

/// Hard ceiling on tracked signatures, past which the guard sweeps early and complains.
///
/// Only reachable by a caller that legitimately holds a signing secret and is issuing signed
/// requests faster than the window expires them, so this is a runaway-client alarm rather than an
/// attack control. At 32 bytes of digest plus overhead, 250k entries is a few tens of MiB — large
/// enough never to be hit by real traffic, small enough to stay bounded if it is.
///
/// Passing it does **not** disable the guard. The map is allowed to grow beyond this point rather
/// than be flushed: over-retention costs memory, whereas under-retention costs the security
/// property outright, and only one of those can be fixed by adding hardware.
const MAX_TRACKED_SIGNATURES: usize = 250_000;

/// Identifies one accepted signature.
///
/// Keyed by the API key as well as the digest so two keys cannot collide, even though an HMAC
/// collision across distinct secrets is already not something an attacker can arrange. The digest is
/// stored as raw bytes rather than the header's hex text so `SHA256=AB…` and `sha256=ab…` — the same
/// signature, differently spelled — cannot be presented as two distinct entries.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct SignatureId {
    /// The key that signed it.
    key_id: Uuid,
    /// The raw HMAC digest.
    digest: Vec<u8>,
}

/// When the next routine and capacity-triggered sweeps become due.
///
/// Both live under one lock so a sweep decision is atomic: two threads arriving together must not
/// each conclude that it is the one that should sweep, which is how a backoff quietly becomes no
/// backoff at exactly the concurrency where it matters.
#[derive(Debug)]
struct PruneSchedule {
    /// Next routine sweep.
    next: Instant,
    /// Earliest instant at which a capacity-triggered sweep may run again.
    next_capacity: Instant,
}

/// Remembers recently accepted signatures so none is honoured twice.
///
/// Shared through [`crate::state::AppState`], so every handler and every worker sees one set of
/// accepted signatures rather than each keeping its own — a per-clone guard would accept a replay on
/// any request that happened to be served through a different clone, which is to say most of them.
#[derive(Debug)]
pub struct ReplayGuard {
    /// Accepted signatures mapped to the instant they stop being remembered.
    ///
    /// A `std::sync::Mutex` rather than a `tokio` one: every operation is a hash lookup and an
    /// occasional retain, the lock is never held across an `.await`, and an async mutex would add a
    /// scheduling round-trip to a critical section measured in nanoseconds.
    seen: Mutex<HashMap<SignatureId, Instant>>,
    /// When sweeps are next due.
    schedule: Mutex<PruneSchedule>,
    /// How long a signature stays remembered. Mirrors the timestamp window: once a signature's
    /// timestamp is too old to pass [`crate::middleware`], the timestamp check rejects it and there
    /// is nothing left for this to remember.
    window: Duration,
    /// Routine sweep interval, precomputed from [`ReplayGuard::window`].
    prune_interval: Duration,
    /// Floor on the spacing between capacity-triggered sweeps. See [`CAPACITY_BACKOFF_DIVISOR`].
    capacity_backoff: Duration,
}

impl ReplayGuard {
    /// Builds a guard remembering signatures for `window_seconds`.
    ///
    /// A non-positive or absurd window is clamped into range rather than trusted: this value comes
    /// from `SIGNATURE_MAX_AGE_SECONDS`, and a typo there must not be able to switch replay
    /// protection off or turn the map into an unbounded allocation.
    pub fn new(window_seconds: i64) -> Self {
        let window = Duration::from_secs(window_seconds.clamp(1, 3600) as u64);
        let prune_interval = window / PRUNE_INTERVAL_DIVISOR;
        let capacity_backoff = window / CAPACITY_BACKOFF_DIVISOR;
        let now = Instant::now();
        Self {
            seen: Mutex::new(HashMap::new()),
            schedule: Mutex::new(PruneSchedule {
                next: now + prune_interval,
                // Deliberately `now`, not `now + capacity_backoff`: the first time the ceiling is
                // reached the sweep must be immediate, not deferred by a window the guard has not
                // yet had any occasion to use.
                next_capacity: now,
            }),
            window,
            prune_interval,
            capacity_backoff,
        }
    }

    /// Records a verified signature, reporting whether it had already been used.
    ///
    /// Returns `true` when this is the signature's first use (the request may proceed) and `false`
    /// when it has been seen inside the window (a replay, which the caller must reject).
    ///
    /// Call this **only after** the signature has been verified. Recording unverified digests would
    /// let an unauthenticated caller fill the map with garbage, and — worse — would let it burn a
    /// legitimate signature it had merely observed, turning this control into a denial-of-service
    /// primitive against the client it was meant to protect.
    ///
    /// A poisoned lock fails **closed**: the request is treated as a replay and rejected. A guard
    /// that cannot prove a signature is fresh must not claim that it is.
    pub fn check_and_record(&self, key_id: Uuid, digest: &[u8]) -> bool {
        let now = Instant::now();
        self.prune_if_due(now);

        let Ok(mut seen) = self.seen.lock() else {
            tracing::error!(
                "Replay guard lock is poisoned; rejecting the request rather than accepting a \
                 signature that cannot be checked for reuse."
            );
            return false;
        };

        let id = SignatureId { key_id, digest: digest.to_vec() };
        match seen.get(&id) {
            // An entry that has outlived the window is stale bookkeeping the sweep has not reached
            // yet, not a replay — its timestamp could no longer pass the window check anyway.
            Some(expires_at) if *expires_at > now => false,
            _ => {
                seen.insert(id, now + self.window);
                true
            }
        }
    }

    /// Number of signatures currently tracked.
    ///
    /// Test-only, so a suite can assert that expired entries are actually *released* rather than
    /// merely stopped from being honoured. Nothing in the request path needs it, so it is compiled
    /// out of release builds rather than left as public surface no caller uses.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }

    /// Drops expired entries when a sweep is due, or when the map has reached its ceiling.
    ///
    /// Amortized O(1) per request: the O(n) retain runs at most once per [`PRUNE_INTERVAL_DIVISOR`]
    /// fraction of the window, or once per [`CAPACITY_BACKOFF_DIVISOR`] fraction while saturated.
    /// Without the second bound a saturated guard whose entries are all still live would retain on
    /// every request and free nothing each time.
    ///
    /// The two locks are taken strictly one after the other, never nested, so this cannot deadlock
    /// against [`ReplayGuard::check_and_record`].
    fn prune_if_due(&self, now: Instant) {
        let over_capacity = self.seen.lock().is_ok_and(|seen| seen.len() >= MAX_TRACKED_SIGNATURES);

        {
            let Ok(mut schedule) = self.schedule.lock() else {
                // A poisoned schedule costs pruning, not correctness: entries still expire on read
                // via the `expires_at > now` comparison in `check_and_record`, so nothing stale is
                // ever honoured.
                return;
            };
            let routine_due = now >= schedule.next;
            let capacity_due = over_capacity && now >= schedule.next_capacity;
            if !routine_due && !capacity_due {
                return;
            }
            schedule.next = now + self.prune_interval;
            if capacity_due {
                schedule.next_capacity = now + self.capacity_backoff;
            }
        }

        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        seen.retain(|_, expires_at| *expires_at > now);

        if seen.len() >= MAX_TRACKED_SIGNATURES {
            tracing::warn!(
                tracked = seen.len(),
                ceiling = MAX_TRACKED_SIGNATURES,
                "Replay guard is at capacity even after sweeping expired entries: a client is \
                 issuing signed requests faster than the anti-replay window expires them. Replay \
                 protection is STILL ENFORCED — the map is allowed to grow rather than be flushed, \
                 since flushing it would make every signature accepted in this window replayable."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn a_signature_is_accepted_once_and_refused_afterwards() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)), "first use is the legitimate request");
        assert!(!guard.check_and_record(key, &digest(1)), "the same signature is a replay");
        assert!(!guard.check_and_record(key, &digest(1)), "and stays one on every later attempt");
    }

    #[test]
    fn distinct_signatures_and_distinct_keys_do_not_collide() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();
        let other_key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert!(guard.check_and_record(key, &digest(2)), "a different signature is not a replay");
        // The same digest under a different key must not be mistaken for reuse — otherwise one
        // tenant's traffic could deny another's.
        assert!(guard.check_and_record(other_key, &digest(1)));
    }

    /// The window is what bounds memory. Once a signature is too old for the timestamp check to
    /// pass, remembering it buys nothing, so the entry must actually be released.
    #[tokio::test(start_paused = true)]
    async fn entries_expire_and_are_swept() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert_eq!(guard.tracked(), 1);

        tokio::time::advance(Duration::from_secs(301)).await;

        // Accepted again: the original is now outside the window, where the timestamp check owns
        // the rejection instead.
        assert!(guard.check_and_record(key, &digest(1)), "an expired entry is not a replay");
        assert_eq!(guard.tracked(), 1, "the sweep released the expired entry rather than stacking");
    }

    /// Saturation must never flush the map.
    ///
    /// Flushing would be the tempting way to honour the ceiling, and it is catastrophic: every
    /// signature accepted in the current window becomes replayable at once, and because the guard is
    /// process-global, one key's burst would disable replay protection for every other key. The map
    /// is therefore allowed to grow past the ceiling instead — over-retention costs memory, which is
    /// recoverable; under-retention costs the security property, which is not.
    #[tokio::test(start_paused = true)]
    async fn reaching_capacity_sweeps_and_warns_but_never_flushes() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        // Fill to the ceiling with entries that are all still live, so a sweep can free nothing.
        {
            let mut seen = guard.seen.lock().expect("a fresh mutex is not poisoned");
            let expires_at = Instant::now() + Duration::from_secs(300);
            for n in 0..MAX_TRACKED_SIGNATURES {
                seen.insert(SignatureId { key_id: key, digest: n.to_le_bytes().to_vec() }, expires_at);
            }
        }
        assert_eq!(guard.tracked(), MAX_TRACKED_SIGNATURES);

        // A brand-new signature is still accepted...
        assert!(guard.check_and_record(key, &digest(0xFF)));
        // ...the map grew rather than being flushed...
        assert!(
            guard.tracked() > MAX_TRACKED_SIGNATURES,
            "a saturated guard must retain its entries, not clear them"
        );
        // ...and, decisively, every pre-existing entry is still enforced.
        assert!(
            !guard.check_and_record(key, 0usize.to_le_bytes().as_ref()),
            "capacity pressure must never make an already-used signature replayable"
        );
        assert!(!guard.check_and_record(key, &digest(0xFF)), "the new entry is enforced too");
    }

    /// The backoff itself: a saturated guard whose entries are all live must not retain on every
    /// request.
    ///
    /// Without [`CAPACITY_BACKOFF_DIVISOR`] the capacity branch fires on every call, so each request
    /// pays an O(n) scan under the global mutex — freeing nothing, because nothing has expired. This
    /// asserts the schedule is actually pushed forward, which is the observable consequence: after
    /// the first capacity sweep, the next is deferred by `window / 16` rather than being due
    /// immediately.
    #[tokio::test(start_paused = true)]
    async fn a_saturated_guard_backs_off_instead_of_sweeping_every_request() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        {
            let mut seen = guard.seen.lock().expect("a fresh mutex is not poisoned");
            let expires_at = Instant::now() + Duration::from_secs(300);
            for n in 0..MAX_TRACKED_SIGNATURES {
                seen.insert(SignatureId { key_id: key, digest: n.to_le_bytes().to_vec() }, expires_at);
            }
        }

        // The first request over the ceiling sweeps immediately — `next_capacity` starts at `now`
        // precisely so the ceiling is enforced without waiting out a window first.
        assert!(guard.check_and_record(key, &digest(0xF0)));

        let now = Instant::now();
        let scheduled = guard.schedule.lock().expect("a fresh mutex is not poisoned").next_capacity;
        assert!(
            scheduled > now,
            "a capacity sweep must push the next one into the future, not leave it due"
        );
        assert_eq!(
            scheduled - now,
            Duration::from_secs(300) / CAPACITY_BACKOFF_DIVISOR,
            "the backoff is one sixteenth of the replay window"
        );

        // Requests arriving inside the backoff must not move it again — that is what makes them
        // cheap rather than each paying for its own full scan. Each uses a distinct digest so every
        // iteration is a genuine acceptance against a still-saturated map.
        for n in 0xF1u8..0xF6 {
            assert!(guard.check_and_record(key, &digest(n)), "still accepting new signatures");
            let again = guard.schedule.lock().expect("a fresh mutex is not poisoned").next_capacity;
            assert_eq!(again, scheduled, "a request inside the backoff must not re-arm the sweep");
        }
    }

    /// The other half of the capacity contract: once entries genuinely expire, the sweep reclaims
    /// them and the map returns to a normal size on its own, with no restart and no manual flush.
    #[tokio::test(start_paused = true)]
    async fn a_saturated_guard_recovers_once_its_entries_expire() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        {
            let mut seen = guard.seen.lock().expect("a fresh mutex is not poisoned");
            let expires_at = Instant::now() + Duration::from_secs(300);
            for n in 0..MAX_TRACKED_SIGNATURES {
                seen.insert(SignatureId { key_id: key, digest: n.to_le_bytes().to_vec() }, expires_at);
            }
        }
        assert_eq!(guard.tracked(), MAX_TRACKED_SIGNATURES);

        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(guard.check_and_record(key, &digest(1)));

        assert_eq!(guard.tracked(), 1, "the sweep reclaimed the whole saturated map");
    }

    /// A misconfigured `SIGNATURE_MAX_AGE_SECONDS` must not be able to disable the guard.
    #[test]
    fn a_nonsensical_window_is_clamped_rather_than_honoured() {
        let key = Uuid::new_v4();
        for window in [0, -1, i64::MIN, i64::MAX] {
            let guard = ReplayGuard::new(window);
            assert!(guard.check_and_record(key, &digest(7)));
            assert!(
                !guard.check_and_record(key, &digest(7)),
                "window {window} must still enforce single use"
            );
        }
    }
}
