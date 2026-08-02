# Comparative Security Audit — `simply_ip_vault` vs `simply_hook_executor`

**Closing pass.** Strictly read-only: no file under `src/` or `./example` was modified, and no
application code was written. The only file produced by this audit is this report.

**Date:** 2026-08-02
**Subject A (reference):** `simply_ip_vault`, at `./example/simply_ip_vault`
**Subject B (this repo):** `simply_hook_executor`, at HEAD `e1669a5`

---

## Reference freshness

**Status: CURRENT — corroborated against the reference's own source, still not pinnable to a commit hash.**

`./example/simply_ip_vault` is not a git checkout. `git -C ./example/simply_ip_vault rev-parse
--show-toplevel` walks up and answers with *this* repository, and `example/` is gitignored — so there
is no `.git` directory, no `HEAD`, and no commit hash on disk to record. Freshness was therefore
established from mtimes, then verified by reading the reference's code against the claims in its own
notes.

| Marker | Timestamp |
| :--- | :--- |
| `example/simply_ip_vault/AGENT_NOTES.MD` | 2026-08-02 17:37 |
| `example/simply_ip_vault/Cargo.toml` | 2026-08-02 17:36:54 |
| `example/simply_ip_vault/src/crypto.rs` | 2026-08-02 17:34:56 |
| `example/simply_ip_vault/src/replay.rs`, `src/config.rs` | 2026-08-02 17:32:39 |
| `example/simply_ip_vault/src/api.rs`, `src/middleware.rs`, `src/state.rs` | 2026-08-02 17:12:06 |
| `example/simply_ip_vault/static/app.js` | 2026-08-02 21:28:09 |
| **This repo's HEAD (`e1669a5`)** | **2026-08-02 17:35:12** |

The reference is **newer than our HEAD**, not stale. Its `AGENT_NOTES.MD` claims two sessions landed
today — Session 26 (hardening from the last cross-audit) and Session 27 (legacy-crypto purge, dead
code, dependencies). Those claims were **verified against the reference's source rather than trusted**:
`src/replay.rs` really is rebuilt on the monotonic clock with no `clear()`; `src/crypto.rs` really has
no `aesgcm256:` branch and `Cargo.toml` really has no `aes-gcm` dependency; `revoke_key_group_permission`
really carries the two new guards; `tests/security_tests.rs` really contains a file-backed WAL probe.
Every **CLOSED** verdict below rests on reading the code, not on reading a commit message.

---

## 1. Proxy & IP Middleware

| Aspect | simply_ip_vault (./example) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| Positive DNS TTL | `POSITIVE_TTL = 30s` (`config.rs:97`) | `TRUSTED_PROXY_DNS_TTL = 30s` (`config.rs:23`) | Equivalent. Same value, same rationale. |
| Negative DNS TTL | `NEGATIVE_TTL = 5s` (`config.rs:108`) | `TRUSTED_PROXY_DNS_NEGATIVE_TTL = 5s` (`config.rs:38`) | Equivalent. Both split the clocks so a failing name retries fast while a healthy one is not re-queried per request. |
| Boot grace period | `BOOT_GRACE_PERIOD = 60s`, retry driven by `TrustedProxies::prime_with_grace` (`config.rs:374`) | `TRUSTED_PROXY_BOOT_GRACE = 60s`, retry driven by `main::prime_trusted_proxies` (`main.rs:166`) | Equivalent behaviour; the retry loop lives on the type there and in `main` here. Cosmetic placement. |
| Boot re-resolution forces a real query | `prime()` clears `cache.hosts` before refreshing (`config.rs:357`) | `prime()` calls `refresh_stale(.., force = true)` (`config.rs:334`) | Equivalent. Neither answers "is this name resolvable *now*" from cache. |
| Concurrent-expiry collapse | Read lock, then re-check under the write lock (`config.rs:289–312`) | Read lock, then re-check under the write lock (`config.rs:304–318`) | Equivalent. Both bound a request burst to one lookup per name per window. |
| DNS failure direction | Unresolvable ⇒ contributes no networks ⇒ untrusted (`resolve_hostname`, `config.rs:432`) | Identical (`resolve_hostname`, `config.rs:348`) | Equivalent. Neither lets a DNS outage *widen* the trusted set. |
| `resolve_hostname` return shape | `Vec<IpNetwork>`; success inferred from `!addresses.is_empty()` | `(Vec<IpNetwork>, bool)`; success reported separately | Equivalent trust behaviour — an empty answer is untrusted and negatively cached on both. Diagnosability only; already registered as an accepted divergence in the peer's checker. |
| Snapshot representation | `Arc<Vec<IpNetwork>>` rebuilt on refresh (`config.rs:340`) | `Arc<Vec<IpNetwork>>` rebuilt on refresh (`config.rs:282`) | Equivalent. Steady state is a refcount bump on both. |
| No-hostname fast path | Returns `Arc::clone(&self.networks)`, touching neither lock nor resolver | Identical (`config.rs:300`) | Equivalent. |
| `X-Forwarded-For` chain walk | Right-to-left, `.rev().find(\|ip\| !is_trusted(..))` (`config.rs:575–590`) | Byte-for-byte the same algorithm (`config.rs:428–443`) | Equivalent — **machine-verified**. `scripts/verify_convergence.sh` normalizes and diffs both function bodies: `[OK] X-Forwarded-For chain walk (converged)`. |
| Forwarding headers gated on peer trust | `if !is_trusted(peer, trusted) { return peer; }` before any header is read | Identical | Equivalent. The load-bearing check on both sides; neither has drifted. |
| `X-Real-IP` precedence | Consulted only when XFF is absent or yields nothing, under the same trust precondition | Identical | Equivalent. |
| IPv4-mapped normalization | `normalize_ip` on the peer, on every parsed hop, and on resolved addresses | Identical | Equivalent. Stops a dual-stack proxy silently failing an IPv4 CIDR match. |
| Fallback when the chain is all-proxy or garbage | Falls back to `peer`, never to an unvalidated claim | Identical | Equivalent. |
| `bound_ips` enforced on master keys | Enforced for every key; `is_master` grants no exemption (`middleware.rs:274`) | Enforced for every key (`middleware.rs:439`) | Equivalent. The old master exemption is gone on both sides. |
| `bound_ips` checked *after* authentication | Step 6 of 6, after HMAC and replay (`middleware.rs:256`) | Step 7 of 7, after HMAC and replay (`middleware.rs:421`) | Equivalent. Both close the `403`-vs-`401` oracle that would let a caller holding only a leaked `X-API-Key` map the deployment's network topology. |
| Malformed `TRUSTED_PROXIES` entry | Dropped; `parse_trusted_proxies` **returns** the rejected list so startup can name every bad entry | Dropped with an inline `tracing::warn!`; no list returned (`config.rs:781`) | **simply_ip_vault marginally stronger** on diagnosability. Identical fail-safe direction — a dropped entry is an untrusted proxy. |
| Hostname plausibility screening | `is_plausible_hostname`: rejects `/`, `:`, all-digits-and-dots, leading `-`/`.`, trailing `-` | `is_hostname_like`: same, and additionally requires **both edges** alphanumeric (`config.rs:738`) | **simply_hook_executor marginally stricter** — it also rejects a trailing `.`, at the cost of the rarely-used FQDN root-dot spelling (`proxy.internal.`). A near-miss CIDR surfaces as a configuration error on both. |

Both sides now implement the same trusted-proxy design down to the constants, and the one function
where divergence would be dangerous — `resolve_client_ip` — is held byte-identical by a mechanical
check rather than by review. The two remaining differences concern where a rejected entry is reported
and one edge character in the hostname screen; neither changes who is trusted.

---

## 2. RBAC & Privilege-Escalation Guards

| Aspect | simply_ip_vault (./example) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| **Re-verified finding A — `revoke_key_group_permission`, per-group check** | Reads the existing grant, then feeds it to `guard_delegated_group_grant(.., "revoke", ..)` (`api.rs:1985–1998`). A caller with no row on the group is refused outright. | N/A — no group model | **CLOSED.** Verified in source, not from the commit message: the caller must now hold at least the verbs it is removing, per verb. |
| **Re-verified finding A — master-target half** | No `guard_master_target` call in the revoke handler; instead `update_key_group_permissions` refuses `target_key.is_master` outright (`api.rs:1824`), so a master can never hold a permission row and the revoke path `404`s at the row lookup. | N/A | **CLOSED**, structurally rather than by an explicit check. Worth noting: the guarantee is an invariant maintained by a *different* handler. Impact of a stray row would still be nil — a master's group access is implicit. |
| **Re-verified finding B — per-verb grant proportionality** | `guard_delegated_group_grant` checks `can_read`/`can_write`/`can_delete` independently (`api.rs:155–157`) | `guard_delegated_hook_grant` checks `can_execute`/`can_manage` independently via the `wanted && !held` shape (`api.rs:481–486`) | **CLOSED.** A caller holding `can_manage: true, can_execute: false` can no longer write `can_execute` onto a second key it controls and run the hook as that key. |
| **Per-verb proportionality on _revoke_** | Enforced — the same guard governs both directions (`api.rs:1986`) | **Not enforced.** `revoke_key_hook_permission` requires only `can_manage` on the hook (`api.rs:2375–2377`) | **simply_ip_vault stronger.** A caller holding `can_manage` but not `can_execute` on hook H can strip another key's `can_execute` on H — authority it does not hold. Escalation-neutral, but a denial of service against another key's automation. The un-closed mirror of the grant-side hole above. |
| **Self-revocation of one's own grants** | Refused for non-masters (`api.rs:1958–1967`) | **Not refused** — `revoke_key_hook_permission` has no `id == key.id` check | **simply_ip_vault stronger.** Low impact (self-demotion only; re-granting is already blocked), but it is an asymmetry with our own grant path, which *does* refuse self-targeting (`api.rs:2275`). |
| Self-granting refused | Refused for non-masters (`api.rs:1837`) | Refused for non-masters (`api.rs:2275`) | Equivalent. Both remove the ratchet where a caller widens its own grant one verb at a time. |
| Global scopes a non-master may not hand out | `MASTER_ONLY_SCOPES = [is_master, can_manage_keys, can_create_groups]` | `require_master_to_grant_scopes(is_master, can_manage_keys, can_manage_hooks)` | Equivalent. Both lists are "`is_master` plus every scope that is a path back to it" — `can_create_groups` there (the creator is auto-granted full rights), `can_manage_hooks` here (hook creation auto-provisions rights). |
| Idempotent re-submission of a scope the target already holds | Permitted — `guard_scope_elevation` compares against the target's current values (`api.rs:199–222`) | Refused — any `Some(true)` from a non-master is rejected regardless of the target's current state (`api.rs:343–370`) | **simply_hook_executor marginally stricter**; the peer is friendlier to a dashboard that PUTs every field. Neither permits an actual elevation, so this is not a defect on either side. |
| Master key as the *target* of administration | `guard_master_target` on rotate / rotate-secret / update / delete (`api.rs:225`) | `require_master_to_administer` on the same operations (`api.rs:378`) | Equivalent. Both close the one-request credential theft in which rotating a master key returns its new plaintext secret to the caller. |
| M:N permission rows on a master key | Refused: "Cannot configure M:N permissions on a master key" (`api.rs:1824`) | Refused, same message (`api.rs:2266`) | Equivalent. |
| `404`-vs-`403` ordering on revoke | `404` for a nonexistent grant precedes the proportionality guard, so a caller learns "no such grant" before anything about its own standing (`api.rs:1982`) | `403` from `require_manage` precedes the row lookup, so grant existence is never confirmed to a caller who does not manage the hook | Both defensible; they take opposite sides of the same trade and neither leaks a credential. Equivalent in effect. |
| Privileged-target guard (`run_as_user`) | No analogue — the service executes nothing | `require_master_for_privileged_hook` gates every mutation of an elevated hook *and* distributing rights over it (`api.rs:410`, `api.rs:2316`) | Domain difference, not a gap. Only this service runs scripts, so only this service needs it. |
| Read-scope modelling | `can_read` is a stored column | `can_read` is derived (`can_execute \|\| can_manage`), never stored | Domain difference per `SCHEMA.MD`. Equivalent enforcement. |

Both re-verified findings are genuinely closed, confirmed by reading the handlers rather than the
changelogs. The pass did surface the mirror of one of them on this side: the peer closed its revoke
path in the same session that closed its grant path, whereas we closed only the grant path.

---

## 3. Cryptography, HMAC, Authentication Posture & Replay Protection

| Aspect | simply_ip_vault (./example) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| **Authentication posture** | Mandatory full-URI HMAC + anti-replay on **every** key. No per-key mode, no opt-out switch, no exempt route (`middleware.rs:111–117`) | Per-key `hmac_mode` (`CANONICAL_V1` / `BODY_ONLY`), plus an optional `REQUIRE_SIGNED_REQUESTS` global promotion | **Intentional asymmetry — do not unify.** The higher-trust internal service versus the one that must interoperate with third-party senders whose signing format cannot be changed. |
| Canonical string | `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`, LF-delimited, no trailing newline (`crypto.rs:80`) | Same construction (`middleware.rs:66`) | Equivalent — **machine-verified**: `[OK] Signature canonicalization (converged)`. |
| Signed target scope | Full `path_and_query`, query string included (`crypto.rs:96`) | Full `path_and_query` (`middleware.rs:362`) | Equivalent. Neither signs `path()` alone, so a captured request cannot be rewritten with an escalating query parameter inside the window. |
| `OriginalUri` under `Router::nest` | Used, with `parts.uri` only as an un-nested fallback | Identical | Equivalent. Both avoid the failure where nesting strips `/api` and every signature mismatches. |
| Constant-time digest comparison | `Mac::verify_slice` → `CtOutput::eq` → `subtle::ConstantTimeEq::ct_eq` (`crypto.rs:165`) | Same chain (`middleware.rs:195`) | Equivalent. Neither compares hex text or decoded bytes with `==`; the peer's checker additionally asserts the *absence* of such a comparison. |
| Wrong-length tag handling | Rejected by `verify_slice` before comparison; tested at 1 / 31 / 33 bytes and empty | Rejected likewise; tested at the same widths, plus a per-byte × 3-mask mutation sweep over all 32 bytes | Equivalent behaviour; **simply_hook_executor's test is more exhaustive** — the mutation sweep is the deterministic fingerprint of a full-width compare. |
| Digest handed to the replay guard | `verify_signature` returns the raw decoded bytes (`crypto.rs:167`) | `verify_signature` returns the raw decoded bytes (`middleware.rs:198`) | Equivalent. Both normalize `sha256=AB…` vs `sha256=ab…` by construction rather than by lowercasing at a distance. |
| **`X-Timestamp` validated before the API-key DB lookup** | Yes — `validate_timestamp` at `middleware.rs:155`, `ApiKey::find()` at `:175`. Unconditional, since every key is `CANONICAL_V1`. | Yes — `prevalidate_timestamp_header` at `middleware.rs:281`, `ApiKey::find()` at `:288`. Scoped to requests carrying **both** `X-Timestamp` and `X-Signature-256`, with the authoritative check retained unconditionally in the `CANONICAL_V1` branch (`:333`). | **CLOSED.** Equivalent for `CANONICAL_V1` traffic, the only mode that has a window. The scoping is forced by the posture asymmetry — `hmac_mode` lives in the row the lookup fetches, so "is a timestamp required here?" is undecidable before it. Keeping the authoritative check in the branch means the property does not rest on an invariant held two functions apart. |
| Timestamp window symmetry | `skew.abs() > MAX_TIMESTAMP_SKEW_SECS` (300s, fixed const) | `skew.abs() > signature_max_age_seconds` (300s default, `SIGNATURE_MAX_AGE_SECONDS`) | Equivalent. Both refuse forward-dated requests, which would otherwise stay replayable for the length of the skew. Our configurability is clamped to `[1, 3600]` in `ReplayGuard::new`. |
| Timestamp fed to the HMAC verbatim | Raw header text, never re-serialized | Raw header text, never re-serialized | Equivalent, and tested on both sides. |
| **Ciphertext format acceptance** | **Fail-closed.** `open()` accepts exactly `v1.plain.` and `v1.xchacha20poly1305.`; anything else is `MalformedCiphertext` (`crypto.rs:381`) | **Fail-closed.** Same two shapes; the `SEALED_PREFIX` strip is `.ok_or(MalformedCiphertext)?` (`crypto.rs:147–149`) | Equivalent — **neither side decrypts an unrecognized or legacy prefix as though it were plaintext.** The accepted set equals what `seal()` can produce on both. |
| Legacy ciphertext format carried | **Removed this session.** `aesgcm256:`, its second nonce width, its SHA-256-of-raw-env-text key derivation, and the `aes-gcm` dependency are all gone; a negative test pins the format shut | Never existed — this service has only ever written XChaCha20-Poly1305 | Equivalent end state. Neither carries a second AEAD or a second key-derivation rule. |
| Unprefixed / empty stored value | Refused, with a dedicated test asserting the `MalformedCiphertext` **variant** across both cipher modes | Refused; `malformed_keys_and_values_are_rejected` covers `""` and `"garbage"` but asserts only `is_err()` | Equivalent behaviour; **simply_ip_vault's test is more specific** — it names the variant and states the anti-property, so a future prefix-agnostic fallback fails there. |
| Sealed row with no key configured | `DecryptionFailed`, not `MalformedCiphertext` — points the operator at the env var | Identical (`crypto.rs:160–164`) | Equivalent. Neither hands ciphertext back as if it were the secret. |
| Encryption-key validation | Exactly 64 hex characters; a passphrase is refused, never stretched | Identical | Equivalent. Neither can confuse `openssl rand -hex 32` with `password`. |
| `from_env` fail-closed coverage | Tested through `from_hex_key` only | Tested through `from_env` directly: `a_malformed_key_aborts_startup_instead_of_downgrading_to_plaintext` and `the_alias_is_honoured_but_validated_just_as_strictly` | **simply_hook_executor stronger.** Ours exercises the real startup path, including that the primary variable wins over the alias and that the alias is held to the same standard. |
| `Debug` redaction of key material | `SecretCipher::Sealed(<redacted>)`, tested | Identical, tested | Equivalent. |
| **Replay clock source** | `tokio::time::Instant` — monotonic **and** pausable (`replay.rs:35`) | `std::time::Instant` — monotonic (`replay.rs:24`) | Equivalent security: both are monotonic, so neither can have live entries evicted by an NTP step. **simply_ip_vault stronger on testability** — `#[tokio::test(start_paused = true)]` drives expiry deterministically, where our expiry test relies on a real `thread::sleep(1100ms)`. |
| **Behaviour at capacity** | Sweeps and warns, **never** flushes; the map may grow past the ceiling (`replay.rs:247–256`) | Sweeps and warns, **never** flushes; the map may grow (`replay.rs:154–161`) | Equivalent, and **CLOSED** on the peer side — the `seen.clear()` that made every in-window signature replayable at once, process-globally across all keys, is gone. |
| **Capacity-sweep backoff** | `CAPACITY_BACKOFF_DIVISOR = 16` — a ~18s floor between capacity-triggered sweeps (`replay.rs:53`) | **None.** `over_capacity` bypasses the interval entirely, so a saturated guard runs a full `retain` on **every** authenticated request (`replay.rs:143`) | **simply_ip_vault stronger.** At 250k live entries every request pays an O(n) scan inside the global mutex every other request must also take — reinstating precisely the per-request cost the amortized sweep exists to remove. Availability, not bypass: replay protection stays enforced throughout. |
| Routine sweep strategy | Interval-based, `window / 4` | Interval-based, `window / 4` | Equivalent. |
| Sweep-decision atomicity | `PruneSchedule { next, next_capacity }` under **one** lock, so two threads cannot both elect to sweep | Single `next_prune` mutex | Equivalent for the routine path; the peer's second field is what the backoff requires. |
| Replay key | `(key_id, raw digest bytes)` | `(key_id, raw digest bytes)` | Equivalent. Keying on the API key as well means one tenant's traffic cannot deny another's. |
| Recorded only after verification | Yes, documented as the ordering constraint | Yes, same constraint documented | Equivalent. Neither lets an observer burn a signature a legitimate client is about to send. |
| Poisoned-lock behaviour | Fails **closed** — treated as a replay, request rejected | Fails **closed** (`replay.rs:109–115`) | Equivalent. |
| Window clamp | `[1, 3600]`, tested against `0`, `-1`, `i64::MIN`, `i64::MAX` | Identical clamp, identical test | Equivalent. |
| Tracked-signature ceiling | `100_000` | `250_000` | Neutral. Different alarm thresholds for a runaway-client condition; neither is a security control. |
| Capacity-path test coverage | Two tests: `reaching_capacity_sweeps_and_warns_but_never_flushes`, `a_saturated_guard_recovers_once_its_entries_expire` | **None.** No test fills the map or asserts the no-flush property | **simply_ip_vault stronger.** Our no-flush behaviour is correct but unasserted — a future "optimization" reintroducing `clear()` would pass our entire suite. |
| Test-only accessor visibility | `#[cfg(test)] fn tracked()` — compiled out of release builds | `pub fn tracked()` — public library surface, compiled into release (`replay.rs:131`) | **simply_ip_vault tighter.** Ours is reachable only from its own test module in practice, which is why the last cleanup pass counted it as live; `#[cfg(test)]` is the more honest expression. |
| Replay-guard scope | Every request (there is only one mode) | `CANONICAL_V1` only; `BODY_ONLY` is deliberately untracked | Consequence of the intentional asymmetry — `BODY_ONLY` carries no timestamp, so there is no window to be single-use within, and GitHub-style senders redeliver on purpose. |

The two contested items in this section are settled: the peer's `seen.clear()` is gone, and both
services' `open()` now accept only what their own `seal()` can produce. The genuinely new finding is
the missing capacity backoff in our `ReplayGuard` — the peer hit that problem, named it, and fixed it,
while our copy of the same module kept the unbounded-sweep shape. Our replay module is also the
least-tested security primitive we own relative to its counterpart.

---

## 4. Database Configuration & Edge Cases

| Aspect | simply_ip_vault (./example) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| `PRAGMA journal_mode=WAL` | Applied, **non-fatal** (`state.rs:58`) | Applied, **non-fatal** (`db.rs:49`) | Equivalent. Neither refuses to boot over a concurrency setting that did not apply. |
| `PRAGMA busy_timeout` | `5000ms`, non-fatal | `5000ms`, non-fatal | Equivalent. |
| Mode read back rather than inferred | Reads back `journal_mode` instead of trusting a clean return | Identical | Equivalent. SQLite declines WAL silently on in-memory databases, so a clean return proves nothing. |
| Scoped by backend, not URL text | `if db.get_database_backend() != DatabaseBackend::Sqlite { return; }` | Identical (`db.rs:51`) | Equivalent. Both keep `PRAGMA` away from PostgreSQL/MySQL. |
| **WAL exercised on a file-backed database** | `tests/security_tests.rs:2607` — `tempfile::tempdir()`, asserts `journal_mode == wal` and `busy_timeout == 5000`, then reopens the file to prove WAL is inherited | `src/db.rs:106` — same shape: temp file, both pragmas asserted, plus a second connection asserting inheritance | **CLOSED on both.** Neither suite is limited to `sqlite::memory:` any more, which is where WAL cannot engage and the assertion would have been vacuous. |
| In-memory declines WAL, non-fatally | Asserted, and the pragma call is run twice for idempotence | Asserted, with `assert_ne!(mode, "wal")` so the tolerance is proven rather than assumed | Equivalent. |
| Non-SQLite backend skipped | Enforced by a checker rule (`verify_convergence.sh:270` greps for a propagating `?;`) | Enforced by a direct test, `the_pragmas_are_scoped_to_sqlite_by_backend_not_by_url_text` | Equivalent guarantee, reached two different ways. |
| Pragma function signature | Returns `()` — cannot propagate | Returns `Result<(), DbErr>`; `main.rs:238` logs and continues | Equivalent in effect. Registered as `[KNOWN]` in our checker: "Peer returns `()`; ours returns `Result` and the caller swallows it. Both non-fatal — cosmetic." |
| Router body limit | `DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)`, 3 MiB, applied exactly once | Identical, 3 MiB, applied exactly once | Equivalent — **machine-verified**: `[OK] Request body ceiling (3 * 1024 * 1024)`. |
| Signature-buffer constant derivation | `const MAX_SIGNED_BODY_BYTES: usize = crate::MAX_REQUEST_BODY_BYTES;` | Byte-identical declaration | Equivalent. Neither leaves a band of sizes that one layer buffers and HMACs only for the other to reject. |
| `TRUSTED_PROXIES` DNS failure at boot | Per-entry, never fatal; failures named at startup and retried once after 60s | Identical | Equivalent. A name that does not resolve disables only itself. |
| Soft-delete retention default | 92 days | 92 days | Equivalent — machine-verified. |
| **Convergence-checker coverage** | 5 cross-repo block diffs **plus ~25 `assert_present` / `assert_absent` property rules** (crypto primitives, replay internals, body limits, retention, posture) | 5 cross-repo block diffs; **no property assertions** (`scripts/verify_convergence.sh`) | **simply_ip_vault stronger.** Ours detects semantic drift precisely inside five anchored functions; theirs additionally catches a property *disappearing* — `assert_absent "a saturated replay guard is never flushed"` would have caught the `clear()` regression, and nothing in our checker would. |
| End-to-end suite | 2438 lines, 407 checks (last recorded by the peer) | 2525 lines, 632 checks (last recorded here) | **simply_hook_executor broader**, reflecting the larger surface (execution, parameters, `sudo`). |

The two checkers are complementary rather than one being a subset of the other: ours normalizes and
fingerprints whole function bodies, catching a semantic edit the peer's greps would miss, while the
peer's property rules catch a security property being deleted outright — which is the failure mode
that actually occurred this cycle. Adopting the `assert_absent` style alongside our block diffs is the
single highest-value tooling change available to either side.

---

## Executive Summary

Sixty-five rows were compared across four categories: **fifty-four are equivalent**, one is the
**permanent, intentional authentication-posture asymmetry**, and **ten are discrepancies**, four of
them cosmetic (rejected-entry reporting, hostname edge characters, the `Result`-vs-`()` pragma
signature, `resolve_hostname`'s return shape). **Every finding the last round claimed to close is
genuinely closed, verified against source rather than changelog:** `simply_ip_vault`'s
`revoke_key_group_permission` now enforces per-verb proportionality and refuses self-revocation, with
the master-target case unreachable because master keys are barred from holding permission rows at all;
`simply_hook_executor`'s grant handler now requires the caller to hold each verb independently;
`SecretCipher::open` is strictly fail-closed on both sides, with the peer's `aesgcm256:` bridge and its
`aes-gcm` dependency removed and a negative test pinning it shut; the `X-Timestamp`-before-lookup
reordering holds on both; and both suites now exercise WAL on a file-backed database rather than only
in memory. The six discrepancies that merit convergence all point the same direction — **toward this
repository** — and cluster in two modules. In `src/replay.rs`: no capacity-sweep backoff, so a
saturated guard reinstates an O(n) scan per request inside the global mutex; no test at all for the
capacity path, leaving our correct no-flush behaviour unasserted against exactly the regression the
peer just fixed; and `tracked()` needlessly `pub` in release builds. In `src/api.rs`:
`revoke_key_hook_permission` neither enforces per-verb proportionality against the grant it deletes nor
refuses self-revocation, making it the un-closed mirror of the grant-side hole we did close —
escalation-neutral, but it lets a `can_manage`-only holder disable another key's automation. The sixth
is tooling: our `verify_convergence.sh` carries no property assertions, so a security property deleted
outright would pass it silently. Nothing found in this pass is exploitable for privilege escalation or
authentication bypass on either service.
