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
use std::time::{Duration, Instant};

use uuid::Uuid;

/// How often expired entries are swept out, as a fraction of the replay window.
///
/// Pruning on every insertion would be O(n) per request; pruning never would let the map hold every
/// signature since boot. Sweeping once per window-quarter bounds the map at roughly the signatures
/// accepted in 1.25 windows while keeping the amortized cost per request negligible.
const PRUNE_INTERVAL_DIVISOR: u32 = 4;

/// Hard ceiling on tracked signatures, past which the guard sweeps early and complains.
///
/// Only reachable by a caller that legitimately holds a signing secret and is issuing signed
/// requests faster than the window expires them, so this is a runaway-client alarm rather than an
/// attack control. At 32 bytes of digest plus overhead, 250k entries is a few tens of MiB — large
/// enough never to be hit by real traffic, small enough to stay bounded if it is.
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
    /// When the next sweep is due.
    next_prune: Mutex<Instant>,
    /// How long a signature stays remembered. Mirrors the timestamp window: once a signature's
    /// timestamp is too old to pass [`crate::middleware`], the timestamp check rejects it and there
    /// is nothing left for this to remember.
    window: Duration,
}

impl ReplayGuard {
    /// Builds a guard remembering signatures for `window_seconds`.
    ///
    /// A non-positive or absurd window is clamped into range rather than trusted: this value comes
    /// from `SIGNATURE_MAX_AGE_SECONDS`, and a typo there must not be able to switch replay
    /// protection off or turn the map into an unbounded allocation.
    pub fn new(window_seconds: i64) -> Self {
        let window = Duration::from_secs(window_seconds.clamp(1, 3600) as u64);
        Self {
            seen: Mutex::new(HashMap::new()),
            next_prune: Mutex::new(Instant::now() + window / PRUNE_INTERVAL_DIVISOR),
            window,
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

    /// Number of signatures currently tracked. Test-facing, so a suite can assert that expired
    /// entries are actually released rather than merely ignored.
    pub fn tracked(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }

    /// Drops expired entries when the sweep is due, or when the map has grown past its ceiling.
    fn prune_if_due(&self, now: Instant) {
        let over_capacity = self.seen.lock().is_ok_and(|seen| seen.len() >= MAX_TRACKED_SIGNATURES);

        {
            let Ok(mut next_prune) = self.next_prune.lock() else {
                return;
            };
            if now < *next_prune && !over_capacity {
                return;
            }
            *next_prune = now + self.window / PRUNE_INTERVAL_DIVISOR;
        }

        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        seen.retain(|_, expires_at| *expires_at > now);

        if seen.len() >= MAX_TRACKED_SIGNATURES {
            tracing::warn!(
                tracked = seen.len(),
                "Replay guard is at capacity even after pruning: a client is issuing signed \
                 requests faster than the anti-replay window expires them. Replay protection is \
                 still enforced, but memory use is being watched."
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
    #[test]
    fn entries_expire_and_are_swept() {
        let guard = ReplayGuard::new(1);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert_eq!(guard.tracked(), 1);

        std::thread::sleep(Duration::from_millis(1100));

        // Accepted again: the original is now outside the window, where the timestamp check owns
        // the rejection instead.
        assert!(guard.check_and_record(key, &digest(1)), "an expired entry is not a replay");
        assert_eq!(guard.tracked(), 1, "the sweep released the expired entry rather than stacking");
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
