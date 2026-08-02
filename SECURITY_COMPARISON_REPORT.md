# Comparative Security Audit — `simply_ip_vault` vs `simply_hook_executor`

**Date:** 2026-08-02
**Mode: strictly read-only.** No file under `src/` or `./example` was modified, and no application
code was written. The only file produced by this audit is this report.
**Subject A (reference):** `simply_ip_vault`, at `./example/simply_ip_vault`
**Subject B (this repo):** `simply_hook_executor`, at HEAD `8b70b2c`

---

## Reference freshness (Task 1)

**Reference freshness: CORROBORATED BUT NOT PINNED — no commit hash exists on disk for `./example`.**

| Check | Result |
| :--- | :--- |
| `git -C ./example/simply_ip_vault rev-parse HEAD` | Returns `8b70b2c690ddbf53927260b78feebdd708f5973a` — **this repository's HEAD**, not the reference's. `git` walked up out of `./example` into the enclosing repo. |
| `git -C ./example/simply_ip_vault rev-parse --show-toplevel` | `/home/fallrik/Documents/workspaces/simply_hook_executor` — confirms the above. |
| `find example -name ".git*"` | Nothing. `./example` is a plain directory copy with no VCS metadata of its own. |
| `git ls-files example` | Empty — `example/*` is in this repo's `.gitignore`, so it is not tracked here either. |
| Stale `.git` file, gitlink, or worktree pointer | None present. |
| An `AGENT_NOTES.MD` inside `./example` naming a different last-audited commit | Present, but it records no commit identifier for itself anywhere. |

**Closest available marker, and what it says.** Modification times in `./example/simply_ip_vault` run
to **2026-08-02 11:39–11:46** (`src/config.rs` 11:42, `src/main.rs` 11:39,
`scripts/verify_convergence.sh` 11:42, `AGENT_NOTES.MD` 11:46, `SCHEMA.MD` 11:44). This repository's
convergence commit `8b70b2c` is dated **2026-08-02 11:35:50**. The reference therefore postdates our
own convergence work by four to eleven minutes.

Content corroborates the timestamps. `./example/simply_ip_vault/AGENT_NOTES.MD` carries a
**"Session 24 — Cross-service security convergence (`simply_ip_vault` half)"** entry with a validation
table (143 unit/integration tests, 377/377 E2E), and the source matches that entry rather than merely
claiming it: `signed_target()` uses `path_and_query()`, `ReplayGuard` exists in `state.rs`,
`DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)` is applied in `lib.rs`, and `apply_sqlite_pragmas`
returns `()`. **This is not the stale, pre-hardening reference an earlier cross-audit encountered.**
Every finding below was verified by reading the source at these paths, not by trusting those notes.

**One genuine staleness caveat, in the opposite direction.** The reference's own *"Convergence Parity
Check"* section describes `simply_hook_executor` from a copy predating commit `8b70b2c` — it states
this repo has a 1 MiB body limit, no replay guard, and checks `bound_ips` before the signature. All
three were closed by `8b70b2c` and are **no longer true**. That table should not be relied on as a
description of this repository.

Per the task instruction, `./example` was not fetched, pulled, or updated.

---

## 1. Proxy & IP middleware (`src/middleware.rs`, `src/config.rs`)

| Aspect | simply_ip_vault (`./example`) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| `TRUSTED_PROXIES` entry types | `parse_trusted_proxies` accepts CIDR, bare address (widened to a host route), or hostname → `ProxyMatcher::{Network,Hostname}` | `parse_trusted_proxies` accepts the same three → `ProxySpec::{Network,Hostname}` | Equivalent; identical precedence (CIDR → address → hostname) |
| Hostname resolution | `resolve_hostname` via `tokio::net::lookup_host((name, 0u16))`, addresses normalized and merged | Same call, same normalization; returns `(Vec<IpNetwork>, bool)` so the caller can distinguish "resolved to nothing" from "lookup failed" | Equivalent; this repo carries one extra bit of state, used only to pick the TTL |
| Resolution shape | Whole-set flat snapshot: `resolved() -> Arc<Vec<IpNetwork>>` merges literals with every hostname's addresses | Identical: `resolved() -> Arc<Vec<IpNetwork>>` over `ResolvedProxies { hosts, merged }` | Equivalent — and this shape is what makes the chain walk below correct for hostname-identified hops on both sides |
| Positive cache TTL | `POSITIVE_TTL = 30s`, per hostname | `TRUSTED_PROXY_DNS_TTL = 30s`, per hostname | Equivalent |
| No-hostname fast path | `resolved()` returns `Arc::clone(&self.networks)`, touching neither lock nor resolver | Identical early return | Equivalent |
| Concurrent-refresh collapsing | Freshness re-checked under the `tokio::sync::RwLock` write guard; lookups run while it is held | Identical (`all_fresh` re-checked under the write guard; `refresh_stale` awaits under it) | Equivalent — a burst arriving on one expiry costs a single DNS query on both sides |
| Malformed-entry rejection | `is_plausible_hostname`: rejects `/`, `:`, all-digits-and-dots, leading `-`/`.`, trailing `-`, length > 253 | `is_hostname_like`: rejects `/`, `:`, all-digits-and-dots, length > 253, and requires **alphanumeric first and last characters** | Both close the "typo'd IPv4 becomes a never-resolving hostname" hole. This repo is marginally stricter (it also rejects the legal trailing-dot FQDN `proxy.internal.`); neither direction is a security defect |
| Rejected-entry reporting | `parse_trusted_proxies` returns `(matchers, rejected)` for the caller to log at startup | Emits `tracing::warn!` inline per rejected entry | Equivalent operator visibility; cosmetic plumbing difference |
| Peer-trust precondition | `resolve_client_ip`: `if !is_trusted(peer, trusted) { return peer; }` before any header is read | Byte-identical guard | Equivalent — the load-bearing anti-spoofing check is the same on both sides |
| `X-Forwarded-For` parsing | Split on `,`, trim, drop unparseable, `normalize_ip`, `.rev()`, `.find(\|ip\| !is_trusted(*ip, trusted))` | Byte-identical expression | Equivalent. Neither performs unconditional rightmost extraction; both walk right-to-left skipping trusted hops |
| Hostname-identified hop inside the chain | Skipped exactly like a CIDR hop — the flat snapshot makes them indistinguishable to the walk | Skipped identically | Equivalent. This closed a real prior gap on the reference side, where `is_literal_network` returned `false` for every hostname matcher and so never peeled a container-named hop |
| Header listing only trusted proxies | Falls through to `X-Real-IP`, then to `peer` — never invents a client | Identical fallthrough | Equivalent; both fail to the unforgeable TCP peer rather than open |
| `X-Real-IP` | Consulted only when the peer is trusted **and** `X-Forwarded-For` yielded nothing; single value, normalized | Identical | Equivalent |
| IPv4-mapped IPv6 normalization | `normalize_ip` via `to_ipv4_mapped()`, applied to the peer, every XFF hop, `X-Real-IP`, and every resolved hostname address | Identical function, identical application points | Equivalent |
| `bound_ips` and Master keys | `networks.is_empty() \|\| networks.iter().any(\|net\| net.contains(client_ip))` — **no `is_master` exemption**; an empty value is the only opt-out | Identical expression, identical no-exemption rationale in-code | Equivalent — both removed the exemption that made the most powerful credential the only one whose network restriction was decorative |
| `bound_ips` position in the pipeline | Last, after signature and replay (*"Now that the caller has proven it holds the signing secret"*) | Last, after signature and replay, under the `── Authorization ──` banner | Equivalent — neither side exposes a `401`/`403` oracle to a caller who cannot authenticate |
| Bootstrap key default `bound_ips` | `BOOTSTRAP_SUBNET`, default `0.0.0.0/0,::/0` (`main.rs:103`) | `BOOTSTRAP_SUBNET`, default `0.0.0.0/0,::/0` (`main.rs:96`), matched by the initial-schema migration default | Equivalent; both avoid stranding an IPv6-first bootstrap now that master keys are bound |

This category is fully converged: the trust precondition, the chain walk, the normalization, and the
`bound_ips` enforcement are the same algorithm in the same order, and both sides ship a
`scripts/verify_convergence.sh` that diffs these functions mechanically so drift is caught by CI
rather than by the next audit. The only surviving deltas are hostname *syntax* strictness at the
edges and where rejected entries are logged — neither changes which address a request is authorized
as.

---

## 2. RBAC & privilege-escalation guards (`src/api.rs`)

The vocabulary differs by domain — the reference gates group access (`can_create_groups`,
`can_manage_webhooks`, `api_key_group_permission{can_read,can_write,can_delete}`), this repo gates
hook access (`can_manage_hooks`, `api_key_hook_permission{can_execute,can_manage}`) — so each row
compares the *guard*, not the field name.

| Aspect | simply_ip_vault (`./example`) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| Key-administration entry gate | `if !key.is_master && !key.can_manage_keys { Forbidden }` on create/list/update/delete/rotate | Same predicate on the same set of handlers | Equivalent |
| Global scopes a non-master may grant | `MASTER_ONLY_SCOPES = ["is_master", "can_manage_keys", "can_create_groups"]`; `can_manage_webhooks` is deliberately delegable | `require_master_to_grant_scopes` covers `is_master`, `can_manage_keys`, `can_manage_hooks` — **every** global scope is master-only | This repo has the smaller surface, having no delegable global scope at all; the reference's exclusion is argued in-code (`can_manage_webhooks` confers no authority over keys or groups). No security delta |
| Elevation-guard semantics | `guard_scope_elevation(caller, requested, held)` rejects `Some(true)` only where the **target does not already hold** the scope, so an idempotent full-field `PUT` succeeds | `require_master_to_grant_scopes` rejects any `Some(true)` from a non-master regardless of the target's current value | This repo is strictly more conservative; the reference is more ergonomic and equally safe, since re-asserting a scope the target already holds authorizes nothing new. Behavioural divergence to arbitrate on UX grounds, not a security finding |
| `is_master` on the update payload | `UpdateApiKeyPayload` deliberately omits the field — promotion via `PUT` is impossible | `UpdateApiKeyPayload` likewise omits it; `require_master_to_grant_scopes(&key, None, …)` passes `None` explicitly | Equivalent |
| Operating on a Master target | `guard_master_target(caller, target)` — `target.is_master && !caller.is_master` → `403` | `require_master_to_administer(key, target, action)` — same predicate, plus the action name in the message | Equivalent |
| Master-target guard coverage | `update_api_key`, `delete_api_key`, `rotate_api_key`, `rotate_signing_secret` | `update_api_key` (`api.rs:2006`), `delete_api_key` (`api.rs:2079`), `rotate_api_key` (`api.rs:2129`) | Equivalent; the reference has a fourth site only because it splits secret rotation from key rotation |
| Rotation treated as credential theft | Guarded, because the response returns the new plaintext secret | Guarded, with the same reasoning stated at the call site | Equivalent |
| Self-deletion | `if id == key.id { Forbidden("Cannot delete yourself") }` | Identical check and message | Equivalent |
| Self-granting a global scope | Explicit block: `id == key.id && !key.is_master && payload.can_manage_webhooks == Some(true) && !key.can_manage_webhooks` | Not required — every global scope is already master-only to grant, so self and non-self are covered by one guard | Equivalent outcome; this repo needs one guard where the reference needs two because it has no delegable scope |
| Self-granting a resource permission | Covered by `guard_delegated_group_grant`, which measures the request against the caller's own row | Explicit block in `update_key_hook_permissions`: `if !key.is_master && id == key.id { Forbidden }` | Equivalent outcome by different means |
| **Delegated grant — per-verb proportionality** | `guard_delegated_group_grant` checks **each verb independently** against the caller's own row: `(requested.can_read && !held.can_read) \|\| (can_write …) \|\| (can_delete …)` → `403` | `update_key_hook_permissions` requires `require_manage(caller, hook)` but then writes `can_execute`/`can_manage` **verbatim from the payload** — a caller holding `can_manage` but not `can_execute` can grant `can_execute` to a second key it controls | **Reference is stronger.** Proportionality is enforced at the resource level here but not per verb. Genuine discrepancy; merits a follow-up convergence pass |
| Delegated grant — caller must hold the resource | Implied by `guard_delegated_group_grant` (no row → `403`) | `require_manage(&state.db, &key, hook_model.id)` before any write | Equivalent at the resource level |
| Delegated grant — privileged resource | N/A (no elevated-execution concept) | `require_master_for_privileged_hook(&key, &hook_model, "grant permissions on")` — distributing rights over a `run_as_user` hook stays master-only even for its manager | An additional control with no reference counterpart; not a discrepancy |
| **Revoking a resource permission** | `revoke_key_group_permission` checks only `is_master \|\| can_manage_keys`, then deletes — **no per-group check and no master-target check**. Any key manager can strip any key's access to any group | `revoke_key_hook_permission` applies `require_manage(&state.db, &key, hook_model.id)` for non-masters, mirroring the grant path | **This repo is stronger.** The reference leaves an ungated cross-tenant tampering / availability path on revoke. Genuine discrepancy; merits a follow-up convergence pass |
| Permissions on a Master target key | `update_key_group_permissions`: `if target_key.is_master { … }` (`api.rs:1815`) | `update_key_hook_permissions`: `if target_key.is_master { InvalidInput("Cannot configure M:N permissions on a master key") }` | Equivalent |
| Mutating a privileged resource | N/A | `require_master_for_privileged_hook` on update, delete, and all three parameter handlers — covering `script_path`, the parameter contract, and the timeout, not merely the `run_as_user` field | Domain-specific to this repo; nothing to score against |
| Audit-log read access | Master-only | Master-only (`list_audit_logs`, `api.rs:2353`) | Equivalent |
| Soft-delete lifecycle operations | Restore and hard-purge are `is_master`-only (`api.rs:1049`, `api.rs:1120`) | Restore and purge of trashed hooks are `is_master`-only | Equivalent |

Both services now enforce the same three-layer model — an entry scope, a master-only set of global
scopes, and a master-target guard on every administrative verb. The two remaining defects point in
**opposite** directions, so neither codebase can adopt the other wholesale: the reference's grant path
is the more precise one (per verb) while its revoke path is under-guarded, and this repo's revoke path
is correctly gated while its grant path checks only resource-level management.

---

## 3. Cryptography, HMAC & authentication posture (`src/crypto.rs`, `src/middleware.rs`, `src/api.rs`)

| Aspect | simply_ip_vault (`./example`) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| **Authentication posture** | Mandatory full-URI HMAC + anti-replay on **every** key. No per-key mode, no `REQUIRE_SIGNED_REQUESTS`, no exempt route — asserted by `verify_convergence.sh` | Per-key `api_keys.hmac_mode` ∈ {`CANONICAL_V1`, `BODY_ONLY`} plus a `REQUIRE_SIGNED_REQUESTS` switch, to interoperate with third-party senders that sign with their own conventions or not at all | **Intentional asymmetry — do not unify** |
| Signature comparison primitive | `mac.verify_slice(&provided_bytes).is_ok()` in `crypto::verify_signature` | `mac.verify_slice(&expected)?` in `middleware::verify_signature` | Equivalent; both constant-time via `Mac::verify_slice → CtOutput::eq → subtle::ConstantTimeEq::ct_eq` |
| Any `==`/`!=` against a secret, signature, digest, or MAC | None in `src/` — grep for `==`/`!=` on secret/signature/digest/token/mac identifiers returns no non-test hits | None in `src/` — same grep, same result | Equivalent; both clean, and both assert the absence in their convergence checker |
| API-key lookup by digest | `Sha256(presented) → hex → filter(Column::KeyHash.eq(hash))` | Identical | Equivalent — and correctly **not** treated as a secret comparison: this is an indexed DB lookup on a one-way digest, where a timing signal would leak which index pages were visited, not the key |
| Canonical string layout | `METHOD\nTARGET\nTIMESTAMP\nBODY`, LF-delimited, no trailing newline (`crypto::canonical_v1_payload`) | Byte-identical construction (`middleware::signature_base`) | Equivalent; both delimit explicitly to prevent component-boundary shifting |
| **Canonicalization scope** | `signed_target()` → `uri.path_and_query()`, falling back to `uri.path()` only when no query exists | Same expression inline in `auth_middleware`, same fallback | Equivalent — the query string is signed on both sides. This closed a real prior gap on the reference side, where `?hard=true` was freely appendable to a captured signed `DELETE` |
| Nested-route URI recovery | `OriginalUri` extension preferred over `parts.uri`, because `.nest("/api", …)` strips the prefix inner layers observe | Identical, with the same rationale recorded | Equivalent |
| Raw-body binding | Signature computed over the buffered bytes verbatim, which are then re-attached to the request | Identical | Equivalent — the bytes verified are the bytes parsed on both sides |
| Timestamp window | `MAX_TIMESTAMP_SKEW_SECS = 300`, symmetric via `.abs()`, rejected as `401` | `SIGNATURE_MAX_AGE_SECONDS` default `300`, symmetric via `.abs()`, rejected as `401` | Equivalent; both refuse forward-dated requests, without which the window would be one-sided |
| Timestamp check placement | `validate_timestamp` runs **before** the API-key database lookup | `verify_timestamp` runs **after** the key lookup, inside the signature branch | **Reference is marginally stronger**: a stale or malformed timestamp costs it no DB round-trip, so unauthenticated traffic cannot force a query. Low severity, but a free ordering win |
| **Anti-replay — single-use tracking** | `ReplayGuard::observe(key_id, signature, timestamp)` in `state.rs` tracks accepted `(key, signature)` pairs; the window alone is not relied on | `ReplayGuard::check_and_record(key_id, digest)` in `replay.rs` — the same property, applied to `CANONICAL_V1` keys | Equivalent for full-HMAC keys, which is the standard this repo's `CANONICAL_V1` mode is held to. `BODY_ONLY` is untracked by design: it carries no timestamp, so there is no window to be single-use within, and those senders redeliver on purpose |
| Replay entry identity | `format!("{key_id}:{signature}")`, where the middleware trims, strips `sha256=`, and lowercases first | `SignatureId { key_id: Uuid, digest: Vec<u8> }` — the raw verified digest, never the header text | This repo is marginally stronger: normalization is structural rather than performed by string surgery, so no header spelling can produce two entries for one signature |
| Replay recorded only after verification | Yes — `observe` is called after `verify_signature` returns true, with the reasoning stated in-code | Yes — `check_and_record` takes the digest returned by `verify_signature` | Equivalent; neither lets an observer burn a signature the legitimate client is about to send |
| Replay expiry clock | Wall clock — entries carry the request's `X-Timestamp` and are retained while `(now - ts).abs() <= 300` | Monotonic — entries carry `Instant::now() + window` | This repo is marginally stronger: a backward NTP step cannot expire entries early. The reference's choice is internally consistent with its own timestamp check, so the exposure is narrow |
| Replay pruning strategy | `seen.retain(…)` on **every** `observe` call — O(n) per authenticated request | `prune_if_due` sweeps at most once per `window / 4`, plus an early sweep at capacity — amortized O(1) per request | This repo is stronger on availability: at the reference's ceiling, every signed request walks 100k entries |
| **Replay behaviour at capacity** | `MAX_TRACKED_SIGNATURES = 100_000`; on overflow the map is **cleared** (`seen.clear()`), logged as *"Replay protection is degraded for the current window"* | `MAX_TRACKED_SIGNATURES = 250_000`; on overflow it sweeps expired entries early, **keeps enforcing**, and warns | **This repo is stronger, and this is the most consequential finding.** The reference fails *open*, and the map is global across keys: any single key holding a valid signing secret can flood the guard to clear it and reopen the replay window for **every other key, master included** |
| Replay-guard lock poisoning | Fails closed — the request is rejected | Fails closed — the request is rejected | Equivalent |
| At-rest AEAD | XChaCha20-Poly1305, 24-byte random nonce per operation | XChaCha20-Poly1305, 24-byte random nonce per operation | Equivalent; both moved off 96-bit nonces and their birthday bound |
| Encryption-key requirement | Exactly 64 hex characters; anything else → `CryptoError::InvalidKey` → startup abort | Exactly 64 hex characters; identical error and identical abort | Equivalent. Both closed the "SHA-256 of any passphrase" derivation |
| Cipher lifetime and `Debug` | Built once at startup, held in `AppState`; `Debug` renders `SecretCipher::Sealed(<redacted>)` | Built once at startup, held in `AppState`; `Debug` renders `SecretCipher::Sealed(<redacted>)` | Equivalent; neither re-reads the environment per request, and neither can leak key material through a state dump |
| Stored-secret formats accepted by `open()` | `v1.xchacha20poly1305.`, `v1.plain.`, legacy `aesgcm256:` (AES-GCM under SHA-256 of the hex key text), **and any unprefixed value returned verbatim as the secret** | `v1.xchacha20poly1305.`, `v1.plain.`; anything else → `CryptoError::MalformedCiphertext` | **This repo is stronger.** The reference's terminal `Ok(stored.to_owned())` means a row whose prefix is truncated or corrupted is silently used as a plaintext HMAC secret instead of failing. It is a deliberate, documented AES-migration affordance — but it is a fail-open path this repo does not have |
| Encryption env var | `VAULT_ENCRYPTION_KEY` primary, `SIGNING_SECRET_KEY` alias | `SIGNING_SECRET_KEY` primary, `VAULT_ENCRYPTION_KEY` alias | Primary and alias are reversed, but **both accept both**, so one provisioning system serves both services. Cosmetic |
| Signature-mode downgrade guard | N/A — one mode exists | `X-Hub-Signature-256` is honoured **only** for `BODY_ONLY` keys; a `CANONICAL_V1` key cannot be downgraded to body-only signing by sending the other header name | A control this repo needs precisely because of the intentional asymmetry, and implements correctly. Nothing to unify |

The authentication-posture row is recorded as a permanent architectural decision and is not scored.
Everything else here is held to one standard, and this repo's `CANONICAL_V1` mode meets it: the same
canonical string, the same full-URI scope, the same `Mac::verify_slice`, and the same
verify-then-record ordering. Replay-guard capacity behaviour is the one place where two
implementations of a shared requirement diverge in a way that changes the security property rather
than only the cost of achieving it.

---

## 4. Database configuration & edge cases (`src/main.rs`, `src/state.rs`)

| Aspect | simply_ip_vault (`./example`) | simply_hook_executor (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| `PRAGMA journal_mode=WAL` | Applied at startup; the result is read back and logged, and a non-WAL answer (in-memory databases) is logged as normal rather than as an error | Applied at startup; read back via `try_get::<String>("", "journal_mode")` and logged identically | Equivalent |
| `PRAGMA busy_timeout` | Applied, 5000 ms | Applied, `SQLITE_BUSY_TIMEOUT_MS = 5_000` | Equivalent |
| Backend guard | `if db.get_database_backend() != DatabaseBackend::Sqlite { return; }` | Same guard, same early return | Equivalent; neither inspects URL text, so `AGENT.MD`'s SQL-agnostic rule survives a PostgreSQL move |
| **Pragma failure handling** | **Non-fatal by construction** — `apply_sqlite_pragmas` returns `()`. Every failure inside is logged and swallowed; the function is structurally incapable of aborting startup | Non-fatal in effect — returns `Result<(), DbErr>`, but every internal failure is logged and swallowed, and `main.rs:238` treats an `Err` as `tracing::warn!` plus "Starting anyway" | Behaviourally identical. The reference is marginally stronger by construction: its signature makes it impossible for a future caller to reintroduce a `?`. Cosmetic, but a free type-level guarantee |
| Pragma ordering relative to migrations | Pragmas applied before `Migrator::up` | Pragmas applied before `Migrator::up` (`main.rs:238`, then `main.rs:246`) | Equivalent |
| Module location | `state.rs` | `db.rs` | Cosmetic; flagged as a documented divergence by both `verify_convergence.sh` scripts |
| Cipher-init failure at startup | Propagated out of `setup_state`, so the process exits — falling back to plaintext would write secrets in the clear for an operator who believes they are encrypted | `crypto::SecretCipher::from_env()?` at `main.rs:251`, so the process exits | Equivalent; both fail closed on the one condition that must be fatal |
| **`TRUSTED_PROXIES` DNS negative caching** | `NEGATIVE_TTL = 5s`, tracked per hostname in `HostnameState { resolved, attempted_at }` and selected by `is_fresh(positive, negative)` | `TRUSTED_PROXY_DNS_NEGATIVE_TTL = 5s`, per hostname in `HostnameEntry { resolved, at }`, selected by an identically-shaped `is_fresh(positive, negative)` | Equivalent. Both bound a dead name to one query per 5s per name regardless of inbound rate, so neither can be turned into a DNS amplifier against its own resolver |
| Per-hostname failure isolation | One failing name does not drag healthy names onto the short retry interval | Identical — `refresh_stale` skips still-fresh entries name by name | Equivalent |
| **Boot grace / delayed re-check** | `prime_with_grace()`: detached task primes, logs the specific failing names, sleeps `BOOT_GRACE_PERIOD = 60s`, re-primes, logs a definitive verdict. **Never aborts** | `prime_trusted_proxies()`: detached task calls `prime()`, logs failing names, sleeps `TRUSTED_PROXY_BOOT_GRACE = 60s`, calls `prime()` again with `force = true`, logs a definitive verdict. **Never aborts** | Equivalent. Both treat an unresolvable proxy as one disabled entry rather than a crash loop, and both fail closed for that entry alone |
| Boot re-check freshness | `prime()` clears `cache.hosts` first, forcing a real lookup rather than reusing what a concurrent request just cached | `refresh_stale(cache, force = true)` bypasses the TTL check for the same reason | Equivalent |
| **`DefaultBodyLimit`** | `DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)` = 3 MiB, applied **outside** `.nest("/api", …)` so the static fallback is covered too; set exactly once, no route overrides it | `DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)` = 3 MiB, applied outside **both** `.nest("/api", …)` and `.nest("/webhook", …)` as well as the static fallback; set exactly once | Equivalent — same value, same placement discipline, and on both sides a limit that cannot be sidestepped by aiming at a different route |
| **Signature-buffering constant** | `middleware::MAX_SIGNED_BODY_BYTES = crate::MAX_REQUEST_BODY_BYTES` | `middleware::MAX_SIGNED_BODY_BYTES = crate::MAX_REQUEST_BODY_BYTES` | Equivalent — derived from the same value on both sides, so no band of sizes exists that one layer buffers and HMACs only for the other to reject |
| Soft-delete retention default | 92 days, overridable via `IP_RETENTION_DAYS` | 92 days, overridable via `DELETED_HOOK_RETENTION_DAYS` | Equivalent, and both are now env-configurable independently of log retention |
| Purge predicate | `is_deleted = true` **AND** `deleted_at IS NOT NULL` **AND** `deleted_at < threshold` | `IsDeleted.eq(true)` **AND** `DeletedAt.is_not_null()` **AND** `DeletedAt.lt(threshold)` | Equivalent — three explicit guards on both sides, so a live or restored record is never purged on the strength of a stale `deleted_at` |
| Non-positive retention value | `<= 0` disables purging; the sweep is a no-op | `<= 0` disables purging; the sweep is a no-op | Equivalent |

The two services now share one startup contract: pragmas are a performance setting that can never
take the daemon down, an unresolvable proxy hostname disables one entry rather than the process, and
a malformed encryption key is the single condition that *must* abort. The only divergence is the
pragma helper's return type — a type-level guarantee on the reference side, a caller-side convention
here — which is identical in behaviour today and differs only in resistance to a careless future
edit.

---

## Executive summary

Across the four categories this audit compared **65 rows** — 15 on proxy and IP middleware, 17 on
RBAC and privilege-escalation guards, 20 on cryptography and authentication, and 13 on database
configuration and edge cases. **Fifty-four are equivalent or byte-identical**, reflecting that both
services have now completed their halves of the arbitrated convergence: the `X-Forwarded-For` chain
walk, `bound_ips` enforcement including on master keys, authenticate-before-authorize ordering,
full-URI canonicalization, `Mac::verify_slice` with no `==` anywhere near a digest,
XChaCha20-Poly1305 under a strictly-validated key, a 3 MiB `DefaultBodyLimit` sharing its constant
with the signature buffer, non-fatal SQLite pragmas, negative DNS caching with a 60-second boot
grace, and a 92-day soft-delete purge are the same on both sides. **One row is the intentional,
permanent architectural asymmetry** — mandatory full-HMAC on every `simply_ip_vault` key versus this
repo's per-key posture — and is recorded rather than scored; where a `simply_hook_executor` key does
use `CANONICAL_V1`, it meets the reference's standard in every respect measured here. That leaves
**ten genuine discrepancies**, four of which are cosmetic or purely ergonomic (env-var primary/alias
ordering, pragma module placement, hostname-syntax strictness at the edges, and the
idempotent-resubmission baseline in the scope-elevation guard), and **six that merit a follow-up
convergence pass**. Ranked by consequence: (1) the reference's `ReplayGuard` **clears its entire map
at 100k entries**, so any one key holding a valid signing secret can flood the guard and reopen the
replay window for every other key including master, where this repo prunes and keeps enforcing — the
only finding here that converts into a concrete cross-key attack; (2) this repo's per-hook grant path
checks resource-level management but **not per-verb proportionality**, so a `can_manage`-only holder
can grant `can_execute` to a second key it controls, which the reference's
`guard_delegated_group_grant` blocks; (3) the reference's `revoke_key_group_permission` is gated only
on `can_manage_keys` and applies **no per-group and no master-target check**, permitting cross-tenant
revocation that this repo's `require_manage` prevents; (4) the reference's `SecretCipher::open()`
returns an unprefixed stored value **verbatim as the signing secret** rather than erroring — a
documented AES-migration affordance that is nonetheless a fail-open path; (5) the reference prunes
its replay map on **every** authenticated request (O(n)) where this repo sweeps once per
quarter-window; and (6) this repo validates `X-Timestamp` **after** the API-key database lookup
rather than before, so a stale timestamp costs a query it need not. Findings 1, 3, 4 and 5 are for
the reference to close; findings 2 and 6 are for this repository.
