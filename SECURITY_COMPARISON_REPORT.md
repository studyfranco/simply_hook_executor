# Comparative Security Audit — `simply_ip_vault` vs `simply_hook_executor`

**Date:** 2026-08-01
**Mode:** Strictly read-only. No source file was modified; no code was written.
**Subject A (reference):** `simply_ip_vault`, at `./example/simply_ip_vault`
**Subject B (this repo):** `simply_hook_executor`, at HEAD `49d347a`
**Scope:** `src/config.rs`, `src/middleware.rs`, `src/api.rs`, `src/crypto.rs`, `src/main.rs`, `src/state.rs`, `src/db.rs`, `src/lib.rs`, `src/retention.rs`, `src/webhooks.rs`

---

## 0. Executive summary

The two projects have converged on the same architecture and, in most places, on byte-identical
security logic — the `X-Forwarded-For` chain walk in particular is now the same algorithm in both.
Where they diverge, **neither project is uniformly stronger.** Each holds a control the other lacks,
and each carries a weakness the other has already closed.

| # | Control | `simply_ip_vault` | `simply_hook_executor` | Stronger |
|---|---|---|---|---|
| 1 | XFF chain walk (right-to-left, skip trusted) | Yes | Yes | tie |
| 2 | Hostname entries in `TRUSTED_PROXIES` | Yes (per-name cache) | Yes (merged cache) | vault (marginal) |
| 3 | Hostname hops skipped *inside* the chain walk | **No** | Yes | **hook_executor** |
| 4 | `bound_ips` enforced against master keys | Yes | Yes | tie |
| 5 | Authenticate-then-authorize ordering | Yes | **No** | **vault** |
| 6 | Signature mandatory | Yes, always | **No**, opt-in | **vault** |
| 7 | Query string covered by the signature | **No** | Yes | **hook_executor** |
| 8 | Replayable inbound auth mode accepted | No | Yes (`BODY_ONLY`) | **vault** |
| 9 | Constant-time MAC comparison | Yes | Yes | tie |
| 10 | AEAD for secrets at rest | AES-GCM (96-bit nonce) | XChaCha20-Poly1305 (192-bit) | **hook_executor** |
| 11 | Malformed encryption key fails closed | **No** (any passphrase) | Yes (hard error) | **hook_executor** |
| 12 | Per-verb grant proportionality | Yes | **No** | **vault** |
| 13 | Master-only scope gating | Yes | Yes | tie |
| 14 | Self-grant refusal | Yes | Yes | tie |
| 15 | Explicit request body limit | **No** (Axum implicit) | Yes (1 MiB, shared) | **hook_executor** |
| 16 | SQLite WAL + `busy_timeout` | Yes | Yes | tie (see §4.1) |

**The four findings worth acting on first:**

- **V-1 (vault, high):** the HMAC signs the path but **not the query string**, while `DELETE /api/ips`
  merges query parameters *over* the signed JSON body and `DELETE /api/ips/{id}` reads `?hard=true`
  from the query. The signature therefore does not bind what the request does.
- **H-1 (hook_executor, high):** `bound_ips` is evaluated **before** the signature, inverting the
  reference's authenticate-then-authorize order and creating a 401/403 oracle.
- **H-2 (hook_executor, medium-high):** request signing is **optional by default**
  (`REQUIRE_SIGNED_REQUESTS=false`), and the `BODY_ONLY` HMAC mode is accepted **inbound** with no
  timestamp and therefore no replay protection at all.
- **V-2 (vault, medium):** `VAULT_ENCRYPTION_KEY` accepts any string and SHA-256's it into a key, so
  a one-character passphrase produces a valid-looking encrypted database.

---

## 1. Proxy & IP middleware

### 1.1 `TRUSTED_PROXIES` parsing and representation

**`simply_ip_vault`** — [`config.rs:164`](example/simply_ip_vault/src/config.rs#L164)
`parse_trusted_proxies` returns `(Vec<ProxyMatcher>, Vec<String>)` — matchers **and the rejected
entries**, which `from_env` logs at `error!` level with a count. Entries are classified CIDR →
bare address → hostname, with `is_plausible_hostname` ([`:189`](example/simply_ip_vault/src/config.rs#L189))
as the last gate. That gate is deliberately permissive: `999.1.1.1` is accepted **as a hostname**
because it is a legal DNS label, on the reasoning that a name which never resolves fails in the same
safe direction.

**`simply_hook_executor`** — [`config.rs:602`](src/config.rs#L602)
`parse_trusted_proxies` returns a bare `Vec<ProxySpec>` and warns inline per rejected entry. Same
three-way classification, but `is_hostname_like` ([`:562`](src/config.rs#L562)) is **stricter**: it
rejects anything made only of digits and dots, so `999.1.1.1` is reported as a malformed address
rather than silently becoming a name.

**Difference.** The vault surfaces rejects as an aggregated startup `error!`; hook_executor emits
per-entry `warn!`. The vault's is easier to notice in a busy log. Conversely hook_executor catches
one more class of typo — a fat-fingered IPv4 literal — as a configuration error instead of a
never-resolving name.

**Analysis.** Roughly even, with a small edge to hook_executor on classification and a small edge to
the vault on reporting. Both fail in the safe direction (a dropped entry means *less* trust). The
ideal is hook_executor's stricter `is_hostname_like` combined with the vault's aggregated
`(accepted, rejected)` return and `error!`-level summary.

### 1.2 Hostname resolution and caching

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Cache granularity | per hostname | one merged network list |
| Lock | `std::sync::RwLock` | `tokio::sync::RwLock` |
| TTL | 30s ([`:30`](example/simply_ip_vault/src/config.rs#L30)) | 30s ([`:21`](src/config.rs#L21)) |
| Failure caching | not cached — retried next request | cached for the full TTL |
| Thundering herd | possible | prevented (double-checked write lock) |
| Zero-hostname cost | iterates matchers | `Arc::clone`, no lock ([`:163`](src/config.rs#L163)) |

**Difference.** These are two genuinely different trade-offs on the same 30-second window.

The vault caches nothing on a resolution failure, so a DNS blip costs at most one request's worth of
untrusted proxy — but during a sustained DNS outage **every request fires a fresh lookup**, putting
resolver latency and load on the hot path. hook_executor caches the partial result, so a failed
hostname stays untrusted for up to 30s (visible as `403`s), but the resolver is hit at most once per
TTL regardless of how badly DNS is behaving.

**Analysis.** hook_executor's is the more robust behaviour under adverse conditions — DNS being down
should not turn into a request-rate-multiplied lookup storm against the resolver, which is a
self-inflicted amplification path. The vault's is the more responsive under normal conditions. The
vault's *per-name* cache is the better structure, though: one unresolvable name in hook_executor
does not poison the others' addresses (they are merged into the same list before caching), but it
does mean the whole merged list is recomputed on any expiry.

### 1.3 `X-Forwarded-For` parsing

**Both projects walk the chain right-to-left, skipping addresses that are themselves trusted
proxies, and fall back to the TCP peer when the header yields nothing.** The code is
substantively identical:

- vault: [`config.rs:251`](example/simply_ip_vault/src/config.rs#L251) `resolve_client_ip`
- hook_executor: [`config.rs:266`](src/config.rs#L266) `resolve_client_ip`

Both gate the entire header path behind `if !is_trusted(peer) { return peer; }` — the load-bearing
check that stops an arbitrary client from satisfying `bound_ips` by writing an address into a
header. Both normalize IPv4-mapped IPv6 on **both** sides of every comparison. Both prefer
`X-Forwarded-For` over `X-Real-IP` so a proxy setting both cannot be played off against itself.

**One real divergence.** The vault's chain walk uses `is_literal_network`
([`:223`](example/simply_ip_vault/src/config.rs#L223)), which consults **only** `ProxyMatcher::Network`
entries and deliberately ignores hostnames — documented as an intentional latency trade-off. The
consequence, which the vault's own doc comment states: *a chained hop identified only by hostname is
treated as a client rather than skipped.* hook_executor resolves hostnames into the same
`Arc<Vec<IpNetwork>>` used for the whole walk ([`middleware.rs:188`](src/middleware.rs#L188)), so a
hostname-named intermediate hop **is** skipped correctly.

Concretely, with `TRUSTED_PROXIES=traefik,nginx` and a chain `client → nginx → traefik → us`:
- hook_executor resolves the client correctly.
- The vault stops at `nginx`'s address and attributes the request to the proxy.

This is the same class of bug the vault cross-check previously found in hook_executor (unconditional
rightmost extraction), surviving in the vault for hostname-only configurations. It is
**conservative** — it never trusts an address further left than it should — but it does mean
`bound_ips` and the audit trail record infrastructure instead of callers in an all-hostname Docker
deployment, which is exactly the deployment hostname support exists to serve.

**Analysis.** **hook_executor is stronger here**, and at no real cost: it already resolves hostnames
once per TTL into a flat network list, so reusing that list inside the walk is free. The vault's
stated cost ("a DNS lookup per header entry") only applies to its per-name-lazy design.

### 1.4 `bound_ips` enforcement, including master keys

**Both projects apply `bound_ips` to every key with no master exemption**, and both document the
removal of that exemption in near-identical terms:

- vault: [`middleware.rs:203`](example/simply_ip_vault/src/middleware.rs#L203)
- hook_executor: [`middleware.rs:230`](src/middleware.rs#L230)

```rust
let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(client_ip));
```

Both treat empty `bound_ips` as "unrestricted" (the opt-out), both reject an unparseable stored CIDR
as `Internal` rather than failing open, and both log the denial with the key prefix.

**The one difference is *where* this check sits in the pipeline**, which is significant enough to be
its own finding — see §3.4.

**Analysis.** Tie on the logic itself. Both got this right, and both got it right for the same
stated reason: a master key whose network restriction is decorative while the dashboard displays it
as enforced is worse than not offering the field.

---

## 2. RBAC & privilege-escalation guards

### 2.1 Key minting and scope elevation

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Guard | `guard_scope_elevation` [`api.rs:190`](example/simply_ip_vault/src/api.rs#L190) | `require_master_to_grant_scopes` [`api.rs:343`](src/api.rs#L343) |
| Master-only scopes | `is_master`, `can_manage_keys`, `can_create_groups` | `is_master`, `can_manage_keys`, `can_manage_hooks` |
| Delegable scope | `can_manage_webhooks` | — |
| Baseline-aware | **Yes** — compares against target's current values | **No** — any `true` is a grant |
| `is_master` via update | not exposed in payload | not exposed in payload |
| Revocation | always allowed | always allowed |

Both refuse a non-master minting a key with a master-only scope, and both give the same reason: a
`can_manage_keys` key that can mint `is_master` is operationally identical to `is_master`, just less
visible in the dashboard.

**Difference.** The vault passes the target's *current* scope values as a baseline, so re-submitting
a scope the key already holds is a no-op rather than a rejection. hook_executor treats every `true`
as a grant regardless of current state.

hook_executor's is stricter but breaks idempotent `PUT`: a non-master key manager cannot re-save an
existing key that already carries `can_manage_hooks`, because the dashboard posts every field. This
is a usability cost, not a vulnerability — the failure is a spurious `403`, which is the safe
direction.

**Analysis.** The vault's baseline-aware form is the better design and is not weaker: permitting
`requested == true && current == true` authorizes nothing new. hook_executor should adopt it.

### 2.2 Rotation and deletion of master keys

**Functionally identical.**

- vault: `guard_master_target` [`api.rs:216`](example/simply_ip_vault/src/api.rs#L216)
- hook_executor: `require_master_to_administer` [`api.rs:378`](src/api.rs#L378)

Both reduce to `if target.is_master && !caller.is_master → 403`, both are applied to update, delete,
and rotate, and both log the attempt. hook_executor's takes an `action` string so the error names
the operation; the vault's emits one message covering all three.

Both also refuse self-deletion (`id == key.id`) before anything else.

**Analysis.** Tie. The rationale is stated identically in both: rotation returns the new plaintext
secret in its response, making "rotate the master key" a one-request credential theft that also
locks out the legitimate holder.

### 2.3 Self-granting and cross-tenant escalation

**Both refuse self-granting outright** rather than merely bounding it:

- vault: [`api.rs:1828`](example/simply_ip_vault/src/api.rs#L1828) — `if id == key.id && !key.is_master → 403`
- hook_executor: [`api.rs:2204`](src/api.rs#L2204) — same shape

The vault's comment articulates why refusal beats bounding, and it is the correct argument: a
"cannot grant beyond what you hold" check compares against grants held *at this instant*, so a
caller allowed to target itself can **ratchet** — grant itself `can_read` on a group it can already
read, then use that row as the basis for widening to `can_write`. Requiring a second party removes
the ratchet by construction.

Both also refuse to configure M:N permissions on a master key at all.

**Difference — and this is a gap in hook_executor.** The vault additionally enforces **per-verb
proportionality** via `guard_delegated_group_grant`
([`api.rs:131`](example/simply_ip_vault/src/api.rs#L131)): a non-master may not grant `can_read`,
`can_write`, or `can_delete` on a group unless it holds that *same verb* itself. Each verb is checked
independently — holding `can_read` does not confer the right to grant `can_write`.

hook_executor checks only that the caller **manages** the hook
([`api.rs:2233`](src/api.rs#L2233), `require_manage`), plus a master-only gate for privileged hooks.
There is no check that the caller holds `can_execute` before granting `can_execute`. So a key with
`can_manage_keys` globally and `can_manage` (but **not** `can_execute`) on a hook can:

1. create a new API key (permitted — it holds `can_manage_keys`),
2. grant that key `can_execute` on the hook (permitted — it manages the hook, and the self-grant
   check does not apply because the target is a *different* key),
3. authenticate as the new key and execute.

The blast radius is bounded: `require_master_for_privileged_hook`
([`api.rs:410`](src/api.rs#L410)) blocks this entirely for any hook with `run_as_user` set, and a
`can_manage` holder can already rewrite the hook's `script_path`, so execution authority is arguably
implied by management authority in this schema. But the two scopes are modelled as **separate
columns** on `api_key_hook_permission`, which means an operator can grant `can_manage` without
`can_execute` and reasonably expect that to mean something. Today it does not.

**Analysis.** **The vault is stronger.** Its verb-by-verb proportionality rule is the more complete
model, and it is the one hook_executor should adopt: if `can_execute` and `can_manage` are distinct
columns, granting either should require holding it.

### 2.4 Hook/record-level privilege guards (no direct counterpart)

hook_executor carries one guard with no analogue in the vault, because the vault has nothing
equivalent to guard: `require_master_for_privileged_hook`
([`api.rs:410`](src/api.rs#L410)) makes **every** mutation of a hook with a non-empty `run_as_user`
master-only — `script_path`, parameters, timeouts, permission grants, and deletion, plus clearing
the elevation itself. It is applied at eight call sites.

The reasoning is sound and worth recording: guarding only the `run_as_user` *field* would leave a
`can_manage` holder able to repoint an existing root hook at a different script without ever
touching the protected field.

Conversely, the vault's `can_create_groups` scope is master-only specifically because group creation
auto-grants the creator full read/write/delete — the one path to group access without a master
signing off. hook_executor has no auto-grant-on-create path, so no equivalent is needed.

**Analysis.** Both are correct for their own domain. Not comparable.

---

## 3. Cryptography & HMAC

### 3.1 Constant-time comparison — both correct

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Comparison | `mac.verify_slice(...)` [`crypto.rs:141`](example/simply_ip_vault/src/crypto.rs#L141) | `mac.verify_slice(...)` [`middleware.rs:139`](src/middleware.rs#L139) |
| Chain | `verify_slice → CtOutput::eq → subtle::ConstantTimeEq` | same |
| Wrong-length tag | rejected by `verify_slice` | rejected, plus an explicit test |

Neither project compares hex strings with `==`. hook_executor additionally carries a test that flips
**every bit at every byte position** of a valid tag and asserts each is rejected
([`middleware.rs:420`](src/middleware.rs#L420)) — a deterministic fingerprint that would catch a
prefix-only or truncated comparison being introduced later.

**Analysis.** Tie on the control; hook_executor has the stronger regression test around it.

### 3.2 Canonical string construction

Both build `METHOD \n PATH \n TIMESTAMP \n RAW_BODY`, both use LF delimiters for the same stated
reason (`"POST" + "/api/x"` and `"POS" + "T/api/x"` are identical under plain concatenation), and
both use the raw body verbatim rather than a re-serialization. Both carry a test proving the
boundary-shift case.

**The one divergence is the query string, and it matters.**

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Signed target | `uri.path()` — **query excluded** ([`middleware.rs:154`](example/simply_ip_vault/src/middleware.rs#L154)) | `path_and_query()` — **query included** ([`middleware.rs:312`](src/middleware.rs#L312)) |
| `OriginalUri` used | yes | yes |

The vault documents the omission as a deliberate trade-off — reverse proxies reorder and re-encode
query strings — on the premise that *"query parameters on `/api/*` are read-only filters, while every
mutating field travels in the signed body."*

**That premise is no longer true in the vault's own code.** Two routes violate it:

1. **`DELETE /api/ips/{id}?hard=true`** — [`api.rs:949`](example/simply_ip_vault/src/api.rs#L949)
   reads `DeleteRecordQuery { hard }` from the query string. `hard=true` converts a reversible soft
   delete into permanent destruction of the row and its cascade. Since the query is unsigned, a
   signed soft-delete request can be rewritten in transit — or replayed within the 300s window — as
   a hard delete, and the signature still verifies.

2. **`DELETE /api/ips`** — [`api.rs:1203`](example/simply_ip_vault/src/api.rs#L1203) computes
   `query_params.merge(body_params)`, where `merge` resolves each field as
   `self.<field>.or(other.<field>)` — **the query wins over the signed body.** An in-flight signed
   request with body `{"target_address":"1.2.3.4","group_name":"low-risk"}` can have
   `?target_address=9.9.9.9&group_name=critical` appended; the body is untouched, the path is
   unchanged, the signature verifies, and the handler acts on the attacker's parameters.

The second case does not even require capture-and-replay — appending a query string to a request in
transit is sufficient. RBAC still applies to the substituted group, so this is an integrity break
bounded by the caller's own permissions rather than a straight escalation. But it means **the
signature does not bind what the request does**, which is the entire property the signature exists
to provide.

hook_executor's inclusion of the query is not theoretical either: it now serves
`DELETE /api/hooks/{id}?hard=true`, `GET /api/hooks?include_deleted=true`, and
`POST /api/system/purge-hooks`. Its doc comment cites exactly this class of attack.

**Analysis.** **hook_executor is materially stronger.** The proxy-rewriting concern the vault cites
is real, but it is a *compatibility* argument being traded against an *integrity* guarantee, and the
vault has since added mutating query parameters that make the trade unsound. Recommended
unification: adopt `path_and_query` in the vault.

### 3.3 Inbound signature modes and anti-replay

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Signature required inbound | **always** | **optional** unless `REQUIRE_SIGNED_REQUESTS=true` (default `false`) |
| `X-Timestamp` required | always | only in `CANONICAL_V1`, and only when a signature is present |
| Accepted inbound modes | `CANONICAL_V1` only | per-key `CANONICAL_V1` **or** `BODY_ONLY` |
| Window | ±300s symmetric ([`crypto.rs:35`](example/simply_ip_vault/src/crypto.rs#L35)) | ±300s symmetric, configurable ([`config.rs:322`](src/config.rs#L322)) |
| Nonce/jti replay cache | none | none |
| `sha256=` prefix | optional | **mandatory** |
| Alternate header | none | `X-Hub-Signature-256`, `BODY_ONLY` keys only |

Both validate the timestamp **before** the expensive work — the vault before the DB lookup, and
hook_executor before recovering the secret and hashing the body. Both are symmetric, and both
document why: a forward-dated request would otherwise stay replayable for the length of its skew.

**Two divergences, both favouring the vault.**

*First,* hook_executor's `require_signed_requests` defaults to `false`
([`config.rs:385`](src/config.rs#L385)), so out of the box possession of `X-API-Key` alone
authenticates. The vault's middleware has no such switch — a request without a valid
`X-Signature-256` never reaches a handler. The vault states the resulting property directly: *"a
leaked key is useless without its signing secret."* hook_executor does not have that property by
default. The stated reason (a bearer-only client keeps working after an upgrade) is a legitimate
migration concern, but the default is the insecure one.

*Second,* hook_executor accepts `BODY_ONLY` **inbound**. That mode signs the body alone, requires no
`X-Timestamp`, and therefore has **no anti-replay whatsoever** — a captured request is replayable
indefinitely. hook_executor is honest about this (`describe_hmac_mode` writes *"BODY_ONLY —
body-only, no replay protection"* into the audit trail), and the mode exists for GitHub-style webhook
senders that cannot produce a canonical string. The vault supports `BODY_ONLY` too, but **only for
outbound webhook dispatch** ([`webhooks.rs:298`](example/simply_ip_vault/src/webhooks.rs#L298)) —
it is never an inbound authentication mode.

**Analysis.** **The vault is stronger on posture.** Its "always signed, always timestamped,
one mode" stance is simpler to reason about and has no insecure configuration. hook_executor's
flexibility is a deliberate product requirement, but it should be paired with `REQUIRE_SIGNED_REQUESTS`
defaulting to `true`, and `BODY_ONLY` keys should be visibly marked in the dashboard as
replay-vulnerable (the audit string already says so; the UI does not).

**Shared gap:** *neither* project maintains a nonce/`jti` cache, so within the 300s window an
identical `CANONICAL_V1` request can be replayed verbatim in both. The window bounds it, but for
non-idempotent routes (`POST /api/hooks/{id}/execute`, `POST /api/ban`) the exposure is real.

### 3.4 Middleware check ordering — a finding in hook_executor

| Step | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| 1 | resolve client IP | resolve client IP |
| 2 | validate timestamp | look up key by hash |
| 3 | look up key by hash | **`bound_ips` CIDR check** |
| 4 | recover signing secret | validate timestamp *(if signed)* |
| 5 | buffer body, verify signature | recover secret, buffer body, verify signature |
| 6 | **`bound_ips` CIDR check** | — |

The vault's comment states the rationale explicitly:

> Verify the HMAC signature *before* the CIDR check: authenticate, then authorize. Running the
> network-binding check first would let a caller who cannot prove possession of the signing secret
> learn — from the 403-vs-401 distinction alone — whether a key it merely guessed is bound to the
> caller's own network.

**hook_executor runs them in the opposite order** ([`middleware.rs:212–241`](src/middleware.rs#L212)),
so an attacker holding only a leaked `X-API-Key` (no signing secret) can distinguish:

- `403 Client IP not allowed` → the key exists **and** is bound to networks excluding the attacker
- `401 Invalid request signature` → the key exists and the attacker's network is permitted

That is a network-topology oracle available to someone who cannot authenticate. It is low severity
on its own — the attacker already needs a valid `X-API-Key`, and with signing optional by default
that key is usually sufficient anyway — but it is free to fix and the reference already models the
correct order.

**Analysis.** **The vault is stronger.** hook_executor should move the `bound_ips` block to after
signature verification. Note the two findings compound: with `REQUIRE_SIGNED_REQUESTS=false` the
ordering barely matters because the key alone authenticates; fixing H-2 without also fixing H-1
would make the oracle *newly* meaningful.

### 3.5 Secret encryption at rest

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| AEAD | AES-GCM-256 | XChaCha20-Poly1305 |
| Nonce width | 96 bits, random | **192 bits**, random |
| Env var | `VAULT_ENCRYPTION_KEY` | `SIGNING_SECRET_KEY` (accepts `VAULT_ENCRYPTION_KEY` as alias) |
| Key derivation | SHA-256 of **any** passphrase ([`crypto.rs:150`](example/simply_ip_vault/src/crypto.rs#L150)) | requires exactly 64 hex chars ([`crypto.rs:98`](src/crypto.rs#L98)) |
| Malformed key | impossible — anything works | **hard error**, no plaintext fallback |
| Structure | free functions, env read per call | `SecretCipher` built once, held in `AppState` |
| Plaintext mode | stores the secret **verbatim** | hex-encoded behind `v1.plain.` |
| Unknown-format value | returned **as-is** as the secret | `MalformedCiphertext` error |
| Versioned prefix | `aesgcm256:` | `v1.xchacha20poly1305.` / `v1.plain.` |

Four differences favour hook_executor:

1. **Nonce width.** AES-GCM with a *random* 96-bit nonce has a birthday bound around 2³² messages
   under one key before collision risk becomes non-negligible — and a GCM nonce collision is
   catastrophic, not gradual. Signing secrets are sealed rarely, so this is not an operational
   concern today, but XChaCha20's 192-bit nonce makes random generation collision-safe by
   construction with no counting argument required.

2. **Key validation.** The vault SHA-256's whatever string it finds, so `VAULT_ENCRYPTION_KEY=x`
   yields a valid 32-byte key and a database that *looks* encrypted while carrying one character of
   entropy. hook_executor rejects anything that is not 64 hex characters, and treats a malformed key
   as fatal rather than falling back to plaintext — its comment names the reason: *"an operator who
   set the variable believes their secrets are encrypted."*

3. **Fail-closed parsing.** The vault's `open_signing_secret`
   ([`crypto.rs:203`](example/simply_ip_vault/src/crypto.rs#L203)) returns any value lacking the
   sealed prefix **verbatim as the secret**. A corrupted or partially-written row is silently
   accepted as key material. hook_executor requires a recognized prefix and errors otherwise.

4. **Structure.** The vault reads the environment variable inside `encryption_key()` on every seal
   and open — i.e. once per authenticated request on the hot path. hook_executor resolves it once at
   startup into `AppState.cipher`, which is both faster and immune to mid-process env mutation.

The vault holds one advantage: `encryption_enabled()` and its startup logging make the mode visible,
and its dev fallback needs no migration. hook_executor's hex-encoded plaintext mode is a genuine
small win — the raw secret is never a substring of the stored column, so a `grep` of a database dump
does not surface it.

**Analysis.** **hook_executor is clearly stronger.** The vault should adopt the length-validated key
(rejecting short passphrases outright), the fail-closed prefix requirement, and construction-once
into `AppState`. Migrating AES-GCM → XChaCha20 is lower priority given the low seal volume, but the
`v1.` prefix scheme makes such a migration straightforward and is worth adopting on its own.

### 3.6 Outbound webhook templates (vault only)

hook_executor has no outbound dispatch, so this is informational. The vault's
`resolve_hmac_template` ([`webhooks.rs:131`](example/simply_ip_vault/src/webhooks.rs#L131)) expands
`{method}`, `{path}`, `{timestamp}`, `{body}` and treats any other `{...}` as literal text so a JSON
body template can coexist with the syntax. Its test suite covers the case that matters — a **body
containing template syntax** must land in the signed string verbatim and not be re-expanded — and
asserts that `DEFAULT_HMAC_TEMPLATE` reproduces `canonical_v1_payload` byte-for-byte, so an outbound
dispatch is verifiable by an inbound middleware.

That last property is the interoperability contract between the two projects, and it holds: a vault
`CANONICAL_V1` dispatch produces exactly the bytes hook_executor's middleware reconstructs — **for
requests with no query string.** Where a query string is present the two now disagree (§3.2), so a
vault-signed dispatch to a hook_executor URL carrying query parameters will fail verification. This
is a concrete interop consequence of the §3.2 divergence, not merely a stylistic one.

---

## 4. Database configuration & edge cases

### 4.1 SQLite initialization

Both projects apply the same two pragmas at startup, both gated on
`DatabaseBackend::Sqlite` rather than on the URL string:

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Location | `state.rs:35` `apply_sqlite_pragmas` | `db.rs` `apply_sqlite_pragmas` |
| `journal_mode=WAL` | yes, result read back and logged | yes, result read back and logged |
| `busy_timeout` | 5000 ms via `execute_unprepared` | 5000 ms via `execute_raw` |
| On failure | **propagates** — `?` in `main.rs:202`, startup aborts | **logs and continues** |
| Tests | — | file-backed WAL persistence + in-memory no-op |

Both correctly note that WAL is persistent (it lives in the database file header, so it survives
reconnection and covers the whole pool) whereas `busy_timeout` is per-connection. hook_executor's
notes additionally record that SQLx's own `busy_timeout` default is already 5s, which is what makes
the pool-wide guarantee hold rather than the single statement issued here — a distinction the vault
does not draw.

**Difference.** Failure handling. The vault aborts startup if a pragma fails; hook_executor logs and
continues, degrading to rollback-journal mode.

**Analysis.** Marginal edge to the vault. A `journal_mode` that silently failed to apply produces
writer-blocks-reader stalls under load that are hard to diagnose later — failing loudly at startup
is the better signal, and there is no availability argument for continuing, since the pragma cannot
fail on a healthy SQLite database. hook_executor's read-back-and-log does surface the same
information, just at a level an operator may not be watching.

### 4.2 Request body limits

| | `simply_ip_vault` | `simply_hook_executor` |
|---|---|---|
| Router-level limit | **none declared** — Axum's implicit 2 MiB default | explicit `DefaultBodyLimit::max(1 MiB)` [`lib.rs:118`](src/lib.rs#L118) |
| Signing buffer cap | 2 MiB, independent constant | `crate::MAX_REQUEST_BODY_BYTES` — **the same constant** [`middleware.rs:38`](src/middleware.rs#L38) |
| Applies to unauthenticated requests | via Axum default | yes, layer is outside both nests |

**Difference.** The vault declares no explicit limit and hard-codes an independent 2 MiB in the
middleware. Those two numbers happen to coincide today, but nothing enforces that they stay
coincident — and if the middleware constant were ever raised above the extractor's, a body between
the two would be fully buffered and HMAC'd before being rejected, paying the memory cost of a
payload already decided against.

hook_executor derives the middleware cap **from** the router constant, so the two cannot drift.

**Analysis.** **hook_executor is stronger** — not because 1 MiB beats 2 MiB, but because the
relationship between the two limits is expressed in code rather than maintained by coincidence.

### 4.3 Retention and soft delete

Both implement soft delete with a 92-day purge and a background sweep. Structurally identical:
`is_deleted` / `deleted_at` / `deleted_by` columns, hidden from reads, master-only restore, master-only
`?hard=true`, and a purge that filters on **both** `is_deleted = true` and `deleted_at < threshold`.
Both document the same reason for the redundant flag check: a restored row keeps its old
`deleted_at`, and matching on the timestamp alone would destroy live data.

**Differences:**

- The vault's 92-day window is configurable via `IP_RETENTION_DAYS`; hook_executor hard-codes
  `DELETED_HOOK_RETENTION_DAYS = 92` deliberately, so that shortening log retention to save disk
  does not silently shrink the undo window for deleted automation.
- hook_executor runs **two** sweeps on one schedule (executions + trashed hooks) and keeps the
  worker alive when `LOG_RETENTION_DAYS=0` so the hook purge still runs.
- Neither project's `?hard=true` is reachable by a non-master.

**Analysis.** Tie, with a note: the vault's configurability is a legitimate operator convenience,
but hook_executor's argument for decoupling the two windows is the sounder default. Both would
benefit from the vault's env override applied to a *separate* variable rather than a shared one.

---

## 5. Shared gaps — present in both

These are not comparative findings; both projects have them.

1. **No replay nonce cache.** Within the ±300s window an identical signed request replays
   successfully in both. Bounded but real for non-idempotent routes.
2. **No "last master key" guard.** Both refuse self-deletion, but a master can delete the only
   *other* master, and two masters can lock each other out, leaving the system with no master
   credential and no recovery path short of direct database access.
3. **`TRUSTED_PROXIES` is only as tight as the operator makes it.** `TRUSTED_PROXIES=0.0.0.0/0`
   re-opens full header spoofing in both, with only a startup log to notice it. Neither warns on an
   over-broad entry specifically.
4. **A non-master key manager may edit `bound_ips` on non-master keys** in both, widening another
   key's network reach without master involvement.
5. **Audit-log volume is unbounded** in both — `retention.rs` purges records/executions but not
   `audit_logs`.

---

## 6. Unification recommendations

Ordered by security value, not effort. **No code was changed to produce this report; these are
proposals for arbitration.**

### Adopt into `simply_ip_vault` (from hook_executor)

| Pri | Change | Ref |
|---|---|---|
| **1** | Sign `path_and_query`, not `path` — closes the `?hard=true` and query-overrides-body integrity breaks | §3.2 |
| **2** | Reject `VAULT_ENCRYPTION_KEY` values that are not 64 hex chars; fail hard rather than deriving a key from a one-character passphrase | §3.5 |
| **3** | Require a recognized prefix in `open_signing_secret`; never return an unrecognized value as the secret | §3.5 |
| 4 | Resolve hostname matchers inside the XFF chain walk so hostname-named hops are skipped | §1.3 |
| 5 | Declare an explicit `DefaultBodyLimit` and derive the middleware's signing cap from it | §4.2 |
| 6 | Build the cipher once into `AppState` instead of reading the env var per seal/open | §3.5 |
| 7 | Hex-encode plaintext-mode secrets so they are not greppable in a database dump | §3.5 |

### Adopt into `simply_hook_executor` (from the vault)

| Pri | Change | Ref |
|---|---|---|
| **1** | Move the `bound_ips` check **after** signature verification — authenticate, then authorize | §3.4 |
| **2** | Default `REQUIRE_SIGNED_REQUESTS` to `true` | §3.3 |
| **3** | Add per-verb grant proportionality: require `can_execute` to grant `can_execute` | §2.3 |
| 4 | Make `require_master_to_grant_scopes` baseline-aware so an idempotent `PUT` of an existing scope is not a `403` | §2.1 |
| 5 | Abort startup when a SQLite pragma fails instead of logging and continuing | §4.1 |
| 6 | Cache resolved hostnames **per name** rather than as one merged list | §1.2 |
| 7 | Return `(accepted, rejected)` from `parse_trusted_proxies` and log rejects as an aggregated `error!` | §1.1 |

### Adopt into both

| Pri | Change | Ref |
|---|---|---|
| **1** | Refuse deletion of the last remaining master key | §5.2 |
| 2 | Add a bounded replay-nonce cache keyed on `(key_id, signature)` with the anti-replay window as its TTL | §5.1 |
| 3 | Warn loudly at startup when `TRUSTED_PROXIES` contains `0.0.0.0/0` or `::/0` | §5.3 |
| 4 | Apply retention to `audit_logs` | §5.5 |
| 5 | Require master to modify `bound_ips` on any key | §5.4 |

---

## 7. Verification notes

Every claim above was read directly from source at the cited line. Three were checked with
particular care because they assert a weakness rather than a difference:

- **§3.2 / V-1** — confirmed by reading three separate sites: the vault's middleware uses
  `original.0.path()` (query excluded), `DeleteRecordQuery` declares `hard: Option<bool>` behind
  `Query<...>`, and `delete_ip` calls `query_params.merge(body_params)` where `merge` is
  `self.<field>.or(other.<field>)` — establishing that the query operand wins over the signed body.
- **§3.4 / H-1** — confirmed by reading both middlewares end to end and comparing the statement
  order; the vault's own comment names the 403-vs-401 oracle as the reason for its ordering.
- **§1.3** — confirmed from `is_literal_network`'s body, which matches only `ProxyMatcher::Network`
  and returns `false` for every `Hostname`. The vault's own doc comment acknowledges the resulting
  behaviour; this report's contribution is noting that it bites exactly the Docker/Traefik
  deployment hostname support was added to serve.

No test suite was executed and no file other than this report and `AGENT_NOTES.MD` was written.
