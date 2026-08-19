# Simply Hook Executor - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_hook_executor`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, process execution rules, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.
4. **`example/`**: Live clones of this service's **sibling projects** — real services, not sample code. They are the ecosystem's reference points for security posture, architecture and testing strategy. **Read [The `example/` Directory](#-the-example-directory--sibling-projects-as-live-references) before reading anything in here, and synchronize first.**

---

## 🧬 The `example/` Directory — Sibling Projects as Live References

`example/` holds **live git clones of this service's sibling projects**, not flat snapshots and not
sample code. They are working checkouts of production services built by the same authors against the
same specification, kept here so that alignment can be *measured* rather than remembered.

### Why they exist

This ecosystem's convergence originated with **two** services — **`simply_ip_vault`** and
**`simply_hook_executor`** (this one). They were aligned first and most tightly: they are the two
named in `RBAC_MODEL.md`'s Scope line, the two whose shared logic `scripts/verify_convergence.sh`
holds byte-identical, and the pair every later service was built against. **Treat them as the gold
standard.** Where a third service differs from both of them, the third service is usually the one
that drifted.

The ecosystem has since grown. Current occupants:

| Project | Domain | Relationship |
| :--- | :--- | :--- |
| `simply_ip_vault` | IP blocklists, webhook dispatch | **Gold standard.** In `RBAC_MODEL.md`'s scope; diffed by `verify_convergence.sh` |
| `simply_ip_exporter` | Aggregated feed serving | Later adopter |
| `simply_ip_sync` | External-source ingestion into vaults | Later adopter; restates `RBAC_MODEL.md` in its own terminology |

### What they are for

Three things, and they are the reason a peer checkout earns its disk space:

1. **Security posture parity.** The same normative rules are enforced in each service against
   different nouns. When a control here looks correct in isolation, the useful question is how the
   siblings answer the *same* question — and a difference is evidence. The clearest finding of the
   2026-08-18 audit was found exactly this way: three siblings re-check a standing scope before an
   ownership test and this service does not, which is what turned "a defensible design choice" into
   "the only service that answers this differently".
2. **Architectural alignment.** Module layout, naming conventions, error envelopes and audit
   structures are compared against them, not invented locally. A new module here should have an
   obvious address in the siblings; if it does not, that is worth a sentence of justification.
3. **Testing strategy.** Their suites are a source of test *patterns*, not just reassurance. The
   concurrency and error-envelope suites in `tests/` were adapted from sibling projects that were
   asserting properties this service was not.

### Rules

- **They are read-only.** Never modify, stage, or commit inside a peer checkout. `git pull --ff-only`
  is the only write this repository's tooling performs there.
- **Never commit them.** `example/` is `.gitignore`d. Reports *about* the peers belong here; their
  code does not.
- **A peer differing from us is not automatically wrong** — each service has a real domain, and a
  difference is a finding only when it has no domain justification. Say which it is.
- **Synchronize before reading.** See below; this is not optional.

### 🔄 Peer Repository Synchronization

`example/` holds **live git clones** of the peer services, not flat snapshots.
They are what `scripts/verify_convergence.sh` compares against and what every convergence or security report describes.

### Mandatory: pull before you analyse

**Before reading any file under `example/`, and before generating a convergence, parity, or security report, you MUST run:**

```bash
git -C example/<peer_repo> pull
```

for every peer present, and **record the outcome** — `Already up to date.` or the revision range — in `AGENT_NOTES.MD` alongside the report it supports.

### Why this is mandatory rather than advisory

An audit is a claim about a specific tree. A stale peer makes that claim **wrong in the most expensive direction**: it reads as a completed verification while describing code that no longer exists. This has already happened here. A previous `example/simply_ip_vault` was a hand-copied snapshot that kept two files after they were deleted upstream, and an audit written against it produced **two findings about dead code** — both later retracted. Nothing failed; the report was simply false, and stayed false until someone diffed the trees by hand.

The failure mode is worth naming precisely, because it is not "the analysis was sloppy":

| Property | Fresh peer | Stale peer |
| :--- | :--- | :--- |
| Convergence gate | Compares current code | Compares deleted code, reports green |
| "The peer does X" | True | Was true |
| A fixed peer bug | Absent | **Still reported as open** |
| Detection | — | Only by diffing by hand, which is the work the gate exists to replace |

### Rules

- **Pull first, read second.** Not "pull if it looks stale" — staleness is invisible from inside the tree.
- **State the revision.** A report that does not name the peer commit it audited cannot be reproduced or re-checked. Both reports in this repository carry the peer's short SHA in their header.
- **A failed pull is reportable, not ignorable.** If the remote is unreachable, say so in the report and name the local `HEAD` being analysed instead. Silent analysis of an unknown revision is the thing this section exists to prevent.
- **Never commit the peer.** `example/` is `.gitignore`d. Reports about the peer belong in this repository; the peer's own code does not.
- **Read-only.** Never modify, stage, or commit inside a peer checkout. `git pull --ff-only` is the only write this repository's tooling performs there.

### Automation

`scripts/verify_convergence.sh` performs this sync itself for every `example/*/.git` it finds, so the gate is never run against a stale peer by accident. Three properties are deliberate:

| Property | Why |
| :--- | :--- |
| `--ff-only` | A merge or rebase inside a peer checkout is a local modification to a tree this repository only ever reads. If it cannot fast-forward, someone committed there and it needs a human |
| **Non-fatal** | An offline or air-gapped run warns and proceeds against the local checkout. A convergence check that cannot run without a network is one that stops being run — and the local comparison is still worth performing, it simply describes an unverified revision, which is what the warning says |
| `GIT_TERMINAL_PROMPT=0` + 30s timeout | The remotes are HTTPS. Without cached credentials git would block on an interactive username prompt forever, and a gate that *hangs* is worse than one that fails |

`SKIP_PEER_SYNC=1` bypasses it entirely — for a deliberate audit of a pinned peer revision, where the whole point is that the tree must not move.

That automation does **not** discharge the directive above. The script syncs only when it is invoked; an agent that reads `example/simply_ip_vault/src/api/guards.rs` directly has not run it.

---

## 🎯 Project Overview

`simply_hook_executor` is an enterprise-grade, secure hook execution daemon written in Rust. It acts as an automation bridge listening for webhooks or HTTP API requests (e.g. from `simply_ip_vault` or deployment tools), authenticates callers using API keys or HMAC-SHA256 signatures, validates input parameters, and safely executes local system scripts (Bash, Python, binaries) with strict environment isolation, per-key concurrency throttling, execution timeouts, and comprehensive logging. It features an integrated Vanilla JS dashboard governed by a granular multi-tenant Role-Based Access Control (RBAC) system.

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **ORM (SQL-Agnostic):** SeaORM (2.0+). Defaults to **SQLite** for zero-config local development/testing, but MUST remain strictly **SQL-agnostic** (PostgreSQL-ready). **Never write vendor-specific raw SQL queries.** `sea-orm` and `sea-orm-migration` in `Cargo.toml` MUST enable the **same three backend features** (`sqlx-sqlite`, `sqlx-postgres`, `sqlx-mysql`) — they are separate feature lists on separate crates, and `SchemaManager::has_index`/`has_table`/`has_column` (used by `src/master.rs` on every boot) compile one match arm per backend feature *enabled on `sea-orm-migration` specifically*. Narrowing that list compiles cleanly and only fails at runtime, as `DbErr::BackendNotSupported`, on whichever backend was dropped — a hole invisible to `cargo check`. `sea_orm_migration_declares_every_backend_sea_orm_does` (`tests/source_hygiene.rs`) pins the two lists together.
- **Frontend:** STRICTLY Vanilla JS, HTML5, and CSS3. **NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only. Dark theme matching `simply_ip_vault`.
- **Quality & Safety:**
  - Zero compiler warnings, zero `clippy` warnings.
  - **Zero `.unwrap()` or `.expect()`** in production code or HTTP handlers. Use structured `AppError` and Axum's `IntoResponse`.
  - **Mandatory `rustdoc`**: All public modules, structs, enums, functions, and Axum handlers MUST be documented using `///` (or `//!` for crates/modules). Enforce `#![warn(missing_docs)]` in `lib.rs`.

---

## 🏛️ Core Architectural Rules

### 0. Module Layout

`src/api/` is split by domain, with two modules whose existence was decided by measuring coupling rather than by taste (the audit is in `AGENT_NOTES.MD`):

| Module | Holds | Rule |
| :--- | :--- | :--- |
| `api/mod.rs` | Module wiring, router-facing re-exports, shared policy constants | Every handler is re-exported here, so `api::create_hook` resolves as it always did and `src/lib.rs`'s router is untouched by the layout |
| `api/support.rs` | Shared plumbing used by three or more domains — audit-log writing, hook resolution, parameter loading, validation, formatting | **Decides nothing.** Nothing here returns a refusal that depends on *who* is calling. A helper that starts deciding moves to `guards` |
| `api/guards.rs` | Every **cross-domain** authorization decision: hook verbs, R2's conjunction, master guards, §3 lifecycle, §4 *hook* visibility, delegation bounds | **Writes nothing.** A guard answers "may this caller do this", returns `Result<_, AppError>`, and mutates no state |
| `api/keys.rs` | Key CRUD, `GET /api/auth/me`, per-hook grants, the §6 cascade, and §4 **key-subtree** visibility | Identity lives with keys because it shares its view types with the key listing. The visibility helpers live here by the single-consumer rule below, and are module-private |
| `api/hooks.rs` | Hook definitions, parameter contracts, trash/restore/purge | What a hook *is*, not what happens when one fires |
| `api/executions.rs` | Triggering hooks, and reading the records that result | Together because they share `ExecutionView` and nothing else does |
| `api/audit.rs` | Reads over `audit_logs` | Master-only. **Reads only** — writing an entry is `support::create_audit_log`, called from every mutating handler |
| `api/system.rs` | The effective runtime configuration and instance counters | Master-only. Split from `audit.rs` because a shared audience is the weakest reason to share a file |
| `api/health.rs` | Liveness and readiness probes | **The only unauthenticated routes in the service.** Must disclose nothing an anonymous caller could not already infer |

**Handlers import every extractor from `src/extract.rs`, never from `axum::extract`.** There is one
wrapper per extractor this service uses — `StrictJson`, `OptionalStrictJson`, `StrictPath`,
`StrictQuery`, `StrictBytes` — and each renders its rejection as `{"error": "…"}` with
`Content-Type: application/json`, preserving Axum's own status. `axum::extract::{Json, State}` may
still be imported for *responses* and for `State`; what must not appear in a handler signature is a
bare `Path<T>`, `Query<T>`, `Json<T>` or `Bytes`.

**This is a completeness rule, not a style preference.** Every refusal in this service is the
`{"error": …}` envelope. That held for everything a handler returned and, before the wrappers, for
nothing rejected *before* one ran: a malformed body, a mistyped UUID, a bad query value and an
oversized raw body were refused with the right status and a bare `text/plain` body carrying no
`error` field. Those are the most common things a caller gets wrong, and because no handler is
involved, **no handler test can see the gap**. One bare `Path<Uuid>` reopens it for that route.
`tests/concurrency_and_contracts.rs` and e2e §47 assert the envelope on all five extractors rather
than on a representative one, because a contract verified at one of five sites has four places left
to drift.

**They are deliberately *outside* `src/api/`**, in a crate-root module, and must stay there. Three
reasons, in order of weight:

1. **They enforce a `RBAC_MODEL.md` §5 control, so they are not plumbing.** §5 requires that
   `is_master` be *removed from the payload type* rather than rejected in a handler. Absence plus
   `#[serde(deny_unknown_fields)]` is what makes that removal mean something, and `StrictJson` is
   what carries the resulting serde refusal to the caller in the standard envelope.
2. **`support.rs` decides nothing — and an extractor decides.** It rules on whether a request is
   well-formed enough to reach a handler at all, before any handler runs. That is the exact charter
   `support.rs` disclaims.
3. **An Axum `FromRequest` impl is a framework concern, not a domain one.** Keeping it under `api/`
   filed HTTP plumbing inside the tree that models this service's domain.

`simply_ip_vault` has always placed the strict JSON pair in its own `src/extract.rs`. This placement
closes structural divergence **S2** and gives both services one address for "how does a body become a
typed payload here". Moving them back into `api/` would reopen it.

**`guards` is one module, not one per domain, and must stay that way.** `RBAC_MODEL.md`'s rules are cross-cutting: R2's conjunction governs hooks, parameters and execution records alike, and §3's ownership test is consulted from three domains. Splitting guards by caller would put a single sentence of the specification in three files and invite the copies to drift — which is the exact failure the compliance suite exists to catch, and so must not be designed in.

#### Naming conventions inside `guards.rs`

| Prefix | Meaning | Examples |
| :--- | :--- | :--- |
| `guard_*` | **Enforces** a rule. Returns `Result<_, AppError>`, and the `Err` *is* the refusal | `guard_manage`, `guard_hook_manage_conjunction`, `guard_dispatch_configuration`, `guard_canonical_v1_for_key_management`, `guard_lifecycle_authority`, `guard_visibility`, `guard_execute` |
| `is_*` / verb | **Answers** a question. Returns a `bool` or an `Option`, decides nothing on its own | `is_permission_reduction`, `manages_any_hook`, `hook_permission` |

The `guard_*` prefix is shared with `simply_ip_vault`, which has always used it. Guards here were
named `require_*` until this pass; the rename is cosmetic and touched no logic.

**`is_permission_reduction` deliberately keeps its name.** The peer's equivalent is
`widens_permissions`, and the two are **logical inverses** — adopting that name would require
inverting every call site's branch, which is a semantic change to R6 enforcement bought with
cosmetics, and the likeliest way to introduce a real vulnerability while "aligning naming". If the
polarity is ever flipped, it must be a deliberate change with its own tests, separate from any
renaming pass.

#### The single-consumer exception

An authorization helper belongs in its domain module rather than in `guards.rs` when **both** of these hold, and it belongs in `guards.rs` otherwise:

1. **Exactly one handler domain calls it**, and
2. **it is part of a closed cluster** — the group calls only itself and things outside the cluster call only the group's entry points — so relocating it cannot leave one rule split across two files.

Today that describes exactly one group: §4's **key-subtree** visibility — `KeyVisibility`, `descendant_key_ids`, `managed_hook_ids`, `key_visibility`, `load_administrable_key` — which lives in `api/keys.rs`.

Three constraints make the exception safe rather than a hole:

- **The relocated helpers are module-private.** That is what makes "only this domain uses it" a fact the compiler checks rather than a claim in a comment. A second domain needing one breaks the build, forcing an explicit choice — widen the visibility and accept it is cross-domain after all, or move the cluster back — instead of letting it drift.
- **They keep `guards.rs`'s discipline wherever they live:** return `Result<_, AppError>`, write nothing, and preserve §4 oracle discipline (a `None`/`404` must be indistinguishable from what a nonexistent id produces, so callers propagate it rather than converting it to a `403`).
- **"Feels related" is not criterion 1.** The rule counts consumers, because that is checkable. §4's *hook* visibility (`guard_visibility`, `visible_hook_ids`, `execution_visible_hook_ids`) is the same section of the specification and stays in `guards.rs`, because three domains consult it. **One §4 is therefore split across two files.** That is the accepted cost of following consumer count rather than section numbering; the alternative — grouping by section — is the taste-based split that lets a rule get copied.

Outside `src/api/`, one boundary is a rule for the same reason:

| Module | Holds | Rule |
| :--- | :--- | :--- |
| `crypto.rs` | Every cryptographic primitive: `generate_signing_secret`, `canonical_v1_payload`, `compute_signature`, `verify_signature`, and `SecretCipher` | **Pure.** No database, no request, no `AppError`. A refusal is returned as `SignatureRejection`, never as an HTTP status |
| `middleware.rs` | *When* a signature is required, which header carries it, and what a caller is told when one fails | Holds the policy, not the primitive. It must not reimplement an HMAC "just to check something first" |
| `error.rs` | `AppError` and its single `IntoResponse` | **Every refusal in the service renders here.** A handler returning `axum::response::Response` directly takes itself out of that path, which is where a response envelope drifts — see `ConflictWithDetails` below |

`generate_signing_secret` lives in `crypto.rs` and **must not** be moved to or re-exported from `api/support.rs`. `support.rs` mints the *public* `key_id`; the signing secret is the entropy every signature in the system rests on and belongs beside the HMAC that consumes it. `api/support.rs::mint_signing_pair` is where the two meet.

Handlers keep their exact Axum signatures, extractors, error responses and guard calls regardless of which file they live in. A move that changes a signature is not a move.

### 1. Security & Network (Zero-Trust)

- **Middleware Protection:** All `/api/*` and `/webhook/*` routes pass through custom authentication middleware (`src/middleware.rs`). The public surface is exactly three things: the static SPA, and the `/health` and `/ready` monitoring probes (§3d). Nothing else answers without a credential.
- **Authentication:** there is exactly **one** way a caller identifies itself — the `X-API-Key` header, matched against `api_keys.key_hash` (SHA-256). This is the single key lookup path in the system; no other header resolves a key record.
  - A signature (`X-Signature-256`) may accompany it and is then always verified, adding request integrity on top of bearer authentication. `REQUIRE_SIGNED_REQUESTS=true` makes it mandatory.
  - `api_keys.key_id` is a public display/correlation identifier only. It is **not** a credential and **not** an authentication header.
  - A missing `X-API-Key`, an unknown key, and a bad signature all return `401`.

#### HMAC Signature Protocol

Each API key carries an `hmac_mode` selecting how its signatures are verified:

| Mode | Signed material | Headers | Replay protection |
| :--- | :--- | :--- | :--- |
| `CANONICAL_V1` *(default)* | `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY` | `X-Signature-256` + `X-Timestamp` | yes — 300s window **and** single use |
| `BODY_ONLY` | `RAW_BODY` only | `X-Signature-256` **or** `X-Hub-Signature-256`, no timestamp | **none** |

`BODY_ONLY` exists only to accept GitHub/Forgejo/GitLab-style webhooks whose format cannot be changed. It MUST remain opt-in per key, `X-Hub-Signature-256` MUST be ignored for `CANONICAL_V1` keys (so the stricter mode cannot be downgraded by header choice), and it MUST still require *a* signature — it relaxes the format, never the requirement.

**`hmac_mode` is fixed at creation and immutable for the rest of the key's life.** `UpdateApiKeyPayload` does not carry the field at all — not accepted-and-ignored, *absent* — so `#[serde(deny_unknown_fields)]` refuses any request naming it with a `422` before a handler runs, for every caller including the master. Rotation mints a fresh `signing_secret`; it does not touch the mode. This exists because a mutable mode is a downgrade lever: a key minted `CANONICAL_V1` that could later be flipped to `BODY_ONLY` would have its replay protection removable by whoever can already reach the update route, which for a `can_manage_keys` holder is itself.

**`can_manage_keys` requires `hmac_mode = CANONICAL_V1`, checked at both creation and update** (`guard_canonical_v1_for_key_management`, `src/api/guards.rs`). A key that can administer every other credential in the deployment must not be reachable over a scheme with no replay window. This is a service-specific policy layered on top of R4, not part of `RBAC_MODEL.md` itself, and is harmless for the ordinary case: an omitted `hmac_mode` already defaults to `CANONICAL_V1`.

**A non-master `can_manage_keys` holder MUST sign every request, unconditionally — overriding `REQUIRE_SIGNED_REQUESTS=false`.** `auth_middleware`'s `signature_required` is `state.config.require_signed_requests || (key_record.can_manage_keys && !key_record.is_master)`. The two rules above guarantee such a key is always `CANONICAL_V1`-capable, so this can never demand a scheme the key cannot present. **Master is deliberately excluded** even though the bootstrap row's `can_manage_keys` column also reads `true`: RBAC_MODEL.md §1 names Master a distinct, superior tier that bypasses scoping outright rather than a Parent that happens to hold every scope, and that column's value on the master row is a bootstrap artifact, not a grant this policy is about. Master already carries independent, stronger hardening (immutable except `bound_ips`, unrotatable, undeletable).

The rest of this section describes `CANONICAL_V1`. Signatures are HMAC-SHA256, keyed on the API key's `signing_secret` (**never** the bearer key), over a canonical string built from four newline-delimited components:

```text
<METHOD>\n<PATH_AND_QUERY>\n<TIMESTAMP>\n<RAW_BODY>
```

| Header | Required | Content |
| :--- | :--- | :--- |
| `X-Signature-256` | when signing | `sha256=<hex digest>` |
| `X-Timestamp` | with any signature | Unix seconds the signature was computed at |
| `X-API-Key` | always | identifies the key, and hence which `signing_secret` verifies the signature |

Rules the implementation MUST hold to:

- **Newline delimiters are mandatory.** Plain concatenation is ambiguous (`POST` + `/api/x` collides with `POS` + `T/api/x`), which would let a signature be replayed across a different method/path split.
- **`PATH_AND_QUERY` is the target the *client* requested**, including the `/api` prefix and any query string. Because `Router::nest` strips the prefix from the URI inner layers observe, the middleware MUST read `OriginalUri`, not `parts.uri`. Signing only the path would leave `?older_than_days=0` freely rewritable on an otherwise-valid signed request.
- **`RAW_BODY` is the bytes as received**, never a re-serialized form. An absent body signs as the empty string.
- **Anti-replay is two checks, not one.** The window bounds *how long* a captured request stays useful; single-use enforcement bounds *how many times* it may be used. Only both together are replay protection:
  1. **Window:** `X-Timestamp` must be within **300 seconds** (`SIGNATURE_MAX_AGE_SECONDS`) of server time, applied **symmetrically** — a forward-dated request is refused too, since it would otherwise stay replayable for the length of its skew. A missing or malformed timestamp on a signed request is a `401`; it is never coerced to "now".
  2. **Single use:** a `CANONICAL_V1` signature is accepted exactly once. `src/replay.rs` remembers each verified `(api_key_id, digest)` for the length of the window and refuses a second presentation, so an intercepted request cannot simply be resent. The digest is recorded **only after** it verifies — recording unverified signatures would let anyone who merely *observed* a request burn it before the legitimate copy arrived, turning the control into a denial-of-service primitive aimed at the client it protects. `BODY_ONLY` is exempt: it carries no timestamp, so there is no window to be single-use within, and the third-party senders it exists for redeliver on purpose.
- **Constant-time comparison** via `Mac::verify_slice`. Comparing hex strings with `==` would leak the signature one byte at a time.
- **Timestamp before the key lookup, and again before the HMAC.** A timestamp is self-contained, so freshness is checked *first* — before `api_keys` is queried at all, let alone before the secret is decrypted and the body hashed. Otherwise every stale capture, broken client clock and scanner spraying garbage buys an indexed query from an unauthenticated caller; the checks that cost us nothing belong in front of the ones that do. The pre-lookup check is scoped to requests carrying `X-Timestamp` **and** `X-Signature-256`, which is the shape of a `CANONICAL_V1` request and the only shape that has a window: `hmac_mode` lives in the row the lookup fetches, and a stray `X-Timestamp` from a `BODY_ONLY` sender is not part of its signed material and MUST stay ignored. The authoritative window check remains in the `CANONICAL_V1` path, so the guarantee never rests on which header names an earlier step happened to inspect.
- **Authenticate, then authorize.** The whole authentication sequence — key lookup, timestamp, signature, single-use — runs **strictly before** the `bound_ips` CIDR check. Running the network check first let a caller holding only a leaked `X-API-Key` distinguish `403 Client IP not allowed` from `401`, and so learn whether a key it had merely found is bound to networks excluding it: a map of the deployment's topology, handed to someone who had proven nothing. An unauthenticated caller must receive `401` for every key, indistinguishably.
- **`REQUIRE_SIGNED_REQUESTS=true`** makes signatures mandatory on every authenticated route, bearer or not. It defaults to `false` so existing bearer-only clients keep working across an upgrade.

#### Signing Secret Storage

`signing_secret` **cannot** be hashed: verification means recomputing the HMAC, which requires the original bytes. It is therefore encrypted at rest with XChaCha20-Poly1305 under `SIGNING_SECRET_KEY` (alias: `VAULT_ENCRYPTION_KEY`), and returned in plaintext exactly once, at key creation or rotation. If no key is configured the daemon still runs but stores secrets verbatim and says so loudly at startup; a malformed key aborts startup rather than silently downgrading.
- **CIDR Restriction:** API Keys are bound to CIDR network ranges (`bound_ips`, supporting comma-separated IPv4/IPv6 ranges like `127.0.0.1/32, 10.0.0.0/8, ::/0`). Middleware MUST validate the client's IP against these bounds.
  - The check applies to **every** key, including `is_master`. `is_master` bypasses *RBAC* checks; it does not bypass the *network* boundary. An empty `bound_ips` is the only way to express "from anywhere" — a master key whose binding was silently ignored while the dashboard displayed it as enforced was the worst possible combination.
- **Trusted-Proxy IP Extraction:** Do NOT use external IP extraction crates. A forwarding header is a **claim by the sender**, not an observation, and becomes evidence only when the sender is a proxy the operator put there:
  - `X-Forwarded-For` / `X-Real-IP` MUST be parsed **only** when the TCP peer (`axum::extract::ConnectInfo`) matches `TRUSTED_PROXIES`. Entries may be bare IPs, CIDR ranges, **or hostnames** (`traefik`, `proxy.internal`) resolved via `tokio::net::lookup_host` — container platforms assign the proxy's address at runtime, so it cannot be written into configuration ahead of time. Resolution is cached **per hostname**, on two clocks: a **30s positive TTL** so a moved container is picked up without a restart, and a **short negative TTL** for failures. The negative cache is a security-adjacent availability control, not an optimization — without it a single unresolvable entry turns the daemon's own request rate into its DNS query rate, which is a self-inflicted amplification path that bites hardest when the resolver is already unhealthy. An unresolvable name is simply *not trusted* (a DNS outage must never be able to widen trust).
  - **Boot resilience:** hostnames are resolved once at startup so a typo or a not-yet-running proxy is reported while an operator is watching. A failure is **never fatal**. The daemon logs an error, serves with that entry untrusted, and re-checks once after a **1-minute grace period**; if it still does not resolve, it keeps serving with that entry disabled. A name that fails at boot is usually a sibling container that has not finished starting, and this daemon and its reverse proxy come up in no guaranteed order — aborting would convert an ordinary startup race into a crash loop, which is strictly worse than serving given the entry is already fail-closed.
  - From a trusted peer, walk `X-Forwarded-For` **right to left and skip hops that are themselves trusted proxies**; the first remaining address is the client. Rightmost-first is what makes the suffix unforgeable — each proxy appends the address it actually saw, so entries to the left of the last trusted hop are hearsay the client supplied. Skipping trusted entries is what makes a *chain* work: with `client → P1 → P2 → us` the header reads `client, P1` and a naive "rightmost entry" would report the proxy as the caller.
  - A header naming nothing but trusted proxies says nothing about the client; fall back to the peer rather than inventing one. `X-Real-IP` is consulted only when `X-Forwarded-For` yields nothing.
  - Otherwise the TCP peer address is authoritative and the headers MUST be ignored entirely.
  - The trust decision MUST come from the socket **before** any header is consulted. Reading the header first and validating afterwards still lets an untrusted client choose the address the allowlist sees.
  - `TRUSTED_PROXIES` defaults to **empty** (trust nothing). Honouring these headers unconditionally lets any client pick its own apparent source address, which defeats `bound_ips` outright and forges `audit_logs.client_ip` at the same time.
  - **A syntactically invalid entry is fatal.** An entry that parses as neither an IP, nor a CIDR range, nor even a plausible hostname aborts startup with `FATAL: TRUSTED_PROXIES entry '<entry>' is not a valid IP address, CIDR range, or hostname (<reason>). Refusing to start with an ambiguous trust boundary.` — the one exception to this module's otherwise lenient parsing, because it is the one override with no safe substitute. Dropping it with a warning (as the daemon previously did) leaves the operator believing a proxy is trusted while it is not, so requests through it are authorized against the *proxy's* address rather than the client's: a security boundary configured one way and enforced another. One bad entry condemns the whole list — a partially-applied trust boundary is exactly the ambiguity being refused — and the check runs **before** the database is opened, so a refused boot applies no migrations and mints no bootstrap master key. This is *typo versus timing*: contrast the unresolvable-hostname case above, which is well-formed, already fail-closed, self-correcting, and therefore never fatal.

### 2. Granular Multi-Tenant RBAC (M:N)

- **Global Rights:** An `ApiKey` can be `is_master` (bypasses all checks) or hold global booleans (`can_manage_keys`, `can_manage_hooks`).
- **Parent and Daughter, defined for this service.** `RBAC_MODEL.md` §1 names the tiers; this is what they are in `simply_hook_executor`:
  - A key is a **Parent** iff `can_manage_keys == true`. There is no other test, and no derived one: lineage is not consulted (R3), and neither is `can_manage_hooks`.
  - A key is a **Daughter** iff `can_manage_keys == false`. A Daughter holding `can_manage_hooks` is still a Daughter — it may *create* hooks and may never *manage* anyone else's.
  - **Only Master may set either global right**, on create or on update (R4). A non-master request for one is refused with `403` rather than silently downgraded: a `200` carrying a key that lacks what was asked for is the worse failure, because the caller walks away believing it provisioned a Parent and discovers otherwise in production. Enforced by `guard_master_to_grant_scopes`, which gates *granting* only — clearing a scope stays available to any key manager, since removing authority is not escalation.
  - **Therefore every key minted by a Parent is a Daughter**, necessarily and without a separate rule to enforce it.
- **The Master's identity is pinned at boot, not read per request** (`src/master.rs`). Every authorization decision branches on `is_master`, which is a column; an attacker who reaches the database needs one `UPDATE` to become Master. §5's uniqueness constraint refuses that statement, and pinning is the layer behind it for the case where the constraint itself is dropped. At startup `MasterPin::pin_at_boot` asserts the §5 index exists and that exactly one master row exists, then freezes that id for the process lifetime; startup fails loudly on either. The check is applied at **one choke point** — `auth_middleware` demotes any authenticated key whose `is_master` column is set but whose id is not the pinned one, before any handler sees it. That is deliberate: there are dozens of `key.is_master` reads across `src/api/`, and a scheme requiring each to also compare an id would be one forgotten call site away from worthless. Handlers keep reading `key.is_master` and are automatically correct, because the principal they receive is the *effective* one. Restoring a tampered flag to meaning requires a restart, which is an event an operator can see.
- **Exactly one master exists,** and the guarantee is a **database constraint**, not application logic (`RBAC_MODEL.md` §5). `api_keys` carries a `master_marker` column *generated by the engine* from `is_master`, under a plain unique index — see `SCHEMA.MD` and `m20230106_090000_master_key_uniqueness`. The marker is derived rather than assigned precisely so no writer can bypass it, and a plain unique index on a nullable column is used rather than a partial index because MySQL has no `WHERE` clause on `CREATE INDEX` and the MySQL driver is enabled. A database that somehow already holds two masters fails the migration and refuses to boot: which master is legitimate is an operator's judgement, not a schema change's.
- **Hook Rights:** Managed via junction table `ApiKeyHookPermission` linking keys to `Hook` with three explicit flags (`can_execute`, `can_manage`, `can_view_execution`).
- **Least Privilege:** any of the three verbs requires a valid key mapping unless `is_master`.
- **Manage is a conjunction (`RBAC_MODEL.md` R2), with ownership as the one route around it.** A `can_manage` row is *never* sufficient on its own. Editing a specific hook — its definition, its dispatch configuration, its parameter contract, its execution records, its lifecycle — requires `is_master`, **or** being the hook's `owner_key_id`, **or** global `can_manage_keys` **AND** a `can_manage = true` row on that hook. §1's Tiers matrix is why the bare row fails: a Daughter (no `can_manage_keys`) "may manage resources: **Never**". R2 is evaluated in exactly one place, `guard_hook_manage_conjunction`; `guard_manage` is the master-and-owner short-circuit in front of it.
- **Ownership edits, it does not delegate — and it does not reach dispatch configuration.** §3 makes `owner_key_id` "the key answerable for this hook" and the only non-Master identity that may delete or rename it. A model where you may destroy a resource but not edit its description is not one anyone would design on purpose, so ownership carries content editing too — which is also what makes `can_manage_hooks` coherent, since a Daughter that creates a hook can go on maintaining it. What ownership does **not** carry is **delegation** (granting or revoking another key's rights still needs R2 in full via `guard_hook_manage_conjunction`) **or dispatch configuration** — `script_path` and `run_as_user` require the R2 conjunction with no ownership exception, per the permission matrix row below and `guard_dispatch_configuration` (SHE-1). Being answerable for a hook does not make you an administrator of credentials, and it does not make you the one who decides what the hook runs. A Daughter owner can therefore rewrite its own hook's description and cannot widen anyone's access to it or repoint what it executes. Ordering matters: the owner check runs *before* the conjunction, because the conjunction answers `404` when no permission row exists and an owner need not hold one.
- **`can_view_execution` — the audit verb.** Execution records are creator-private (`RBAC_MODEL.md` Terminology + §4), so holding a verb on a hook does not by itself reveal what other keys' runs of it printed. An execution is readable by exactly four identities: **Master**, the **acting key** (`executions.api_key_id`), the **hook's owner**, or a key holding **`can_view_execution` or `can_manage`** on that hook. Everything else is `404`, never `403` — an unreadable record must be indistinguishable from one that was never written, or the endpoint reports how much history exists to someone entitled to none of it. It is its own verb rather than a facet of the other two because folding it into `can_execute` would give every caller entitled to run a hook the output of everyone else's runs, and folding it into `can_manage` would put read-only audit access behind R2, so an auditor could be granted logs only by first being made a Parent with editing rights. `can_manage` is included in the four because a key already entitled to rewrite `script_path` and delete the history outright cannot meaningfully be denied *reading* it. The verb is **read-only in every direction**: it never confers running, editing, or deleting a record.
- **Auto-Provisioning:** When an API Key creates a new `Hook`, the backend MUST automatically generate full rights for that key on the new hook — all three verbs — **and record it as the hook's `owner_key_id`**. The two remain separate facts: the permission row is operational and delegable to others, the ownership column is lifecycle authority and moves only when master says so.
- **Lineage confers nothing.** `api_keys.parent_key_id` records who created a key, for cascading deletion and visibility scoping only. `RBAC_MODEL.md` R3: "A daughter of the Master key is an ordinary daughter key with no elevated standing." No authorization check may read this column — if one ever needs to, the rule has been broken.

#### Effective permission matrix

`can_read` is **derived, not stored** — the schema carries `can_execute`, `can_manage` and `can_view_execution`. Read access to a hook is granted when a key is `is_master`, **or** owns the hook, **or** holds *any* of the three flags on it; a key with no mapping and no ownership sees nothing.

| Operation | Required |
| :--- | :--- |
| `POST /api/hooks/{id}/execute`, `POST /webhook/{id}` | `can_execute` |
| `POST /api/hooks/{id}/test` (dry run) | `can_execute` — the preview reveals the fully-resolved command line and child environment, which is execution-shaped knowledge even though nothing is spawned |
| `GET /api/hooks`, `GET /api/hooks/{id}`, `GET .../parameters` | derived read: ownership, **or** any of `can_execute` / `can_manage` / `can_view_execution`. `can_view_execution` is included because history is unreadable without being able to name the hook that produced it; ownership is included because otherwise a hook could be editable by a key that cannot list it |
| `GET /api/executions`, `GET /api/executions/{id}` | **Creator-private, four routes in** (§4 scope 3): `is_master`, **or** the acting key (`executions.api_key_id`), **or** the hook's `owner_key_id`, **or** a row on that hook carrying `can_view_execution` **or** `can_manage`. Anything else is `404`, byte-identical to a record that never existed. The listing expresses the same disjunction as an indexed `WHERE` rather than filtering after `LIMIT`, which would page wrongly — a limit applied before a visibility filter returns fewer than *n* visible rows and hides the rest behind an offset that never advances past them |
| `PUT`/`PATCH`/`DELETE /api/hooks/{id}`, parameter CRUD, `DELETE /api/executions/{id}` — **general content** (`description`, timeout, parameter contract) | `is_master`, **or** the hook's `owner_key_id`, **or** global `can_manage_keys` **AND** a `can_manage = true` row on that hook. A bare row does not suffice: the Tiers matrix says a Daughter never manages resources. Note `DELETE /api/executions/{id}` is deliberately *stricter* than reading one: `can_view_execution` buys visibility of a record, never the right to destroy it — an auditor is not a redactor. §4 decides the status: no row and no ownership is `404` (invisible), a row short of a conjunct is `403` |
| `PUT`/`PATCH /api/hooks/{id}` naming **`script_path` or `run_as_user`** — **dispatch configuration** | `is_master`, **or** global `can_manage_keys` **AND** a `can_manage = true` row on that hook. **Ownership alone does not suffice here** — this is the one place the general row above and this one diverge, and the divergence is load-bearing (SHE-1): the Terminology section names `script_path` and `run_as_user` as this service's **dispatch configuration** and the R2 conjunction governs editing them **in full**, with no ownership exception. A Daughter that owns a hook (via `can_manage_hooks` auto-provisioning) may still rewrite its description, timeout and parameters, but not repoint what it runs or as whom — otherwise revoking `can_manage_hooks` from a key that had already created hooks would not contain it: ownership and the auto-provisioned `can_manage` row both survive that revocation untouched, so the key could still repoint, and then run, every hook it had already made, forever. Enforced by `guard_dispatch_configuration`, called from `update_hook` only when the payload names either field |
| `POST /api/hooks` (create) | global `can_manage_hooks` (creation auto-provisions full rights on the new hook, and records the creator as `owner_key_id`). Creation is *not* under R2 — the rule is written about "a `can_manage = true` row for that specific resource", and a hook that does not yet exist can have no row. The consequence is deliberate: this scope defines automation, and editing it afterwards additionally needs `can_manage_keys` |
| `POST`/`GET`/`PUT`/`DELETE /api/keys*` | global `can_manage_keys` |
| `GET /api/audit-logs`, `GET /api/settings`, `DELETE /api/executions` (purge) | `is_master` |
| Assigning a non-empty `run_as_user` | `is_master` — checked **immediately after** the endpoint's authorization check and **before any field validation**, so an escalation attempt always surfaces as `403` and can never be masked by a `400` about some other field in the same payload |
| **Granting** `can_manage_keys` or `can_manage_hooks` (create *or* update) | `is_master`. `can_manage_keys` is the right to administer credentials, not to invent authority outranking your own — without this the scope is self-amplifying and therefore identical to `is_master`. **Revoking** a scope stays available to any key manager: removing authority is not an escalation |
| **Setting `is_master`** (create *or* update) | **Nobody, including the master.** Per `RBAC_MODEL.md` §5 the field is not on `CreateApiKeyPayload` or `UpdateApiKeyPayload` at all, and both are `#[serde(deny_unknown_fields)]`, so an `is_master` in either body is a `422` naming the field rather than a silently-dropped no-op. Silence was the wrong failure here: it would return `200` and an ordinary key, leaving the caller believing it had minted a master and leaving nothing in the log for an operator to notice. The only writer is `bootstrap_master_key`, against an empty table |
| `PUT`/`DELETE /api/keys/{id}`, `POST /api/keys/{id}/rotate` where the **target** is `is_master` | **Nobody, including the master itself**, except `bound_ips` (next row). Rotation returns the new plaintext secret, so "only a master may administer a master" collapsed into "the master may rotate itself" the moment exactly one master could exist — one request against a stolen master credential both harvests a fresh secret and locks the operator out. Deletion is barred *regardless of row count*, so the rule does not quietly depend on the uniqueness index for its safety. Regeneration is deliberately out of band: delete the row directly in the database and restart |
| `PUT /api/keys/{id}` setting **only `bound_ips`**, where `{id}` is the master's own id | `is_master`, and the caller must *be* that key. The one editable field, because it is the one an operator has a recurring need to change from inside the running system (the network the master is reachable from moves) and the one that can only ever *reduce* a stolen credential's usefulness. `name`, `max_concurrent_jobs`, and both global scopes are refused by the master-immutability guard, `403`. `hmac_mode` never reaches that guard at all: `UpdateApiKeyPayload` no longer carries the field (it is immutable for every key, not only the master's — see the HMAC Signature Protocol section), so naming it is a `422` from `deny_unknown_fields` before any handler runs |
| `POST /api/keys/{id}/permissions` where `{id}` is the **caller's own key**, and the write *grants* a verb | `is_master` — granting rights to yourself is escalation, not administration. A write that only *reduces* the caller's own row is a revocation under R6 and is permitted; see the revoke row below |
| `POST`/`DELETE /api/keys/{id}/permissions*` — administering **any** hook's grants | `is_master`, **or** `can_manage_keys` **AND** a `can_manage = true` row on that specific hook. This is `RBAC_MODEL.md` **R2**: manage is a conjunction, and neither half alone is sufficient. `can_manage_keys` is *never* a global bypass of per-resource RBAC — a holder that were exempt could mint a key, grant it any verb on any hook, and authenticate as it, which is `is_master` in two requests. Conversely a `can_manage` row without the global flag belongs to a Daughter key, which the tier matrix says never manages resources: the row is operational authority over the hook, not the right to decide who else holds it. **Both failures return one message**, so a caller cannot learn which half to go acquire. A caller failing *both* halves is refused before the target key is fetched, so the endpoint cannot be used to enumerate key UUIDs by reading `404` instead of `403` |
| **Revoking** — `DELETE /api/keys/{id}/permissions/{hook}`, or a `POST` that turns no verb on | The R2 conjunction above, and **nothing more** (`RBAC_MODEL.md` **R6**). No per-verb proportionality, and **self-revocation is allowed**, on either route. Removing a permission can never raise anyone's authority: turning a flag off is a request for `false`, and `false` exceeds nothing, so the outcome is always a strict de-escalation of the target regardless of who asks or what they hold. Granting needs a proof of authority because it can manufacture a capability that was withheld; revoking has nothing to prove. **Which route it arrived on is irrelevant** — R6 classifies a reduction through the general update endpoint as a revocation, because `DELETE` and a `POST` writing every verb to `false` reach the same end state, and a rule enforced on only one spelling is routed around rather than obeyed. Classification is by *effect*: a write is a grant when it turns on a verb the target did not already hold, and a reduction otherwise. A mixed write — one verb up, one down — is a grant; the reduction does not pay for the escalation. The remaining exposure is integrity, not escalation (disabling another tenant's automation), which the R2 gate addresses |
| `POST /api/keys/{id}/permissions` granting a **verb the caller does not itself hold** on that hook | `is_master` only. This is `RBAC_MODEL.md` **R1**, applied on top of R2 — **R7** requires both "simultaneously and without exception", so there is no caller below master for whom either is skipped. Managing a hook is authority to administer its grants, not licence to invent a capability an operator withheld: a manager lacking `can_execute` could otherwise route it to a key it already controls and authenticate as that key, obtaining in two requests exactly what was withheld. `can_execute` and `can_manage` are separate columns precisely so that split is expressible, so each verb is checked **independently** against the caller's own row. **Revoking** is always allowed — turning a flag off can never exceed anything — and re-asserting a verb you already hold is a no-op, so an idempotent re-submission still succeeds. <br><br>*Previously `can_manage_keys` was exempt from this rule and from R2 both. That exemption is gone: it made the scope transitively able to execute any non-privileged hook, and "deputy master" is not a tier this model has.* |
| `DELETE /api/hooks/{id}`, and `PUT`/`PATCH` changing a hook's **`name`** | `is_master`, **or** the R2 conjunction **AND** being the hook's `owner_key_id` (`RBAC_MODEL.md` **§3**). The two stack rather than substitute — R2 says the conjunction governs "lifecycle where §3 permits it", so it is a gate in *front* of ownership, and a caller must clear both. Holding manage — or any operational verb — confers **no** lifecycle authority: "a parent that merely uses a resource must not be able to delete it." Satisfying R2 in full is the right to *operate* the hook (description, `script_path`, timeout, parameter contract); what it does not carry is the right to make the hook cease to exist. **Renaming is grouped with deletion**, not with the other edits, because this service resolves hooks by name on `/webhook/{identifier}` and in grant payloads — a rename silently breaks every caller pointed at the old one, so it is a lifecycle act wearing an edit's clothes. A hook whose `owner_key_id` is `NULL` (predating ownership) is **master-only**, deliberately the conservative direction: reading "no owner" as "anyone who manages it" would make the un-migrated state more permissive than the migrated one |
| `PUT /api/hooks/{id}` setting **`owner_key_id`** | `is_master` only (§3: "Master may reassign `owner_key_id` on any resource ... at any time"). Not delegable, not even to the current owner — letting an owner hand ownership to an arbitrary key would let it walk away from a resource rather than resolve it, which is the step §6's pre-flight inventory exists to make impossible. The target key must exist: a dangling owner would put the hook permanently beyond §3's non-master path |
| `DELETE /api/keys/{id}` where the key's **subtree owns any hook** | Refused with **`409 Conflict`** and a structured pre-flight inventory (`RBAC_MODEL.md` **§6**): `subtree` (every key the cascade would remove) plus `inventory` (every owned entity, with `type`, `id`, `name`, `current_owner`). The caller resubmits with a `resolutions` map naming, for **every** listed id, either `{"action":"delete"}` or `{"action":"reassign","to":"<key-id>"}`. **Partial maps are refused** — a partial map is almost always a stale one, and applying it would delete the keys and orphan whatever arrived after the inventory was taken. A resolution naming an entity the subtree does not own is a `400`, not a no-op. Reassigning *into* the doomed subtree is a `400`: the new owner is about to cease to exist. Deletion cascades **recursively** through the whole daughter subtree, and a subtree owning nothing still deletes in one request with no body |
| **Any** hook route where the caller holds **no permission row at all** — `GET`, execute, test, `PUT`, `DELETE`, parameter CRUD | Returns **`404`, not `403`** (`RBAC_MODEL.md` **§4** oracle discipline): "any key, resource, or dispatch target outside the caller's visibility scope must return the identical status and body the service would return if that id did not exist." Holding *a* row makes the hook visible, so a caller merely short a verb still gets `403` — the split is visibility versus authority, not one status for everything. Resolution by **name** is covered too, since names are guessable in a way UUIDs are not |
| `GET /api/keys` | Scoped per §4, in three tiers. **Own subtree** (transitively, via `parent_key_id`) and the caller itself: the full summary, minus raw secrets. **Shared resource**: any key holding a permission row on a hook the caller `can_manage`, in *minimal* form — `id`, `name`, and that key's rights **on the shared hooks alone**, flagged `partial: true`. No `bound_ips`, no global flags, no prefix, no unrelated memberships: "a single shared resource must never become a keyhole into another parent's whole configuration." **Everything else** is omitted from the listing entirely, which is the listing form of oracle discipline |
| `PUT`/`DELETE /api/keys/{id}`, `POST /api/keys/{id}/rotate` where the target is **outside the caller's subtree** | `404`. Administering the key *entity* needs full visibility; a key met only through a shared resource is a window, not a handle. A `403` here would make `PUT /api/keys/{uuid}` a key-enumeration oracle for any `can_manage_keys` holder. The permission routes are the deliberate exception — they accept a minimally-visible target, because §4's shared-resource scope exists precisely so a hook's manager can see and (per R6) revoke who else holds rights on it |
| `GET /api/executions*` | **Creator-plus-master** (§4, third scope). An execution's `parameters_json`, stdout and stderr are the requesting key's data; hook membership is not a licence to read another tenant's arguments and output. A hook's manager sees *that the hook exists and what it does*, never the runs it did not make. Hook visibility remains a second bound, so history for a hook the caller can no longer see disappears even for its own runs |
| **Any** mutation of a hook whose `run_as_user` is non-empty — `PUT`/`PATCH /api/hooks/{id}`, `DELETE`, all parameter CRUD, granting permissions on it | `is_master`. Every part of a privileged hook's definition decides what runs with the borrowed privileges: `script_path` names the binary, the parameter contract supplies its argv, the timeout bounds it. Guarding only the `run_as_user` field protects nothing. **Clearing** the elevation is covered too, or the attack simply gains a step |
| `GET /api/hooks?include_deleted=true`, `POST /api/hooks/{id}/restore`, `DELETE /api/hooks/{id}?hard=true`, `POST /api/system/purge-hooks` | `is_master`. A trashed hook keeps its `script_path` and `run_as_user`, so reading or reviving one exposes (or reinstates) a definition someone chose to remove; hard delete and purge irreversibly discard execution history, which no scoped `can_manage` grant should be able to do |

Listing endpoints narrow by these rules rather than rejecting: `GET /api/hooks` and `GET /api/executions` return only what the caller may read.

### 3. Safe Script Execution Engine

- **Strict Injection Prevention:** NEVER evaluate commands inside a shell string (e.g., `sh -c "script.sh $VAR"` is FORBIDDEN). Always use `tokio::process::Command::new(script_path).args(arg_list)`.
- **Privileged execution (`hooks.run_as_user`):** when set, the command becomes exactly:

  ```text
  /usr/bin/sudo -n -u <run_as_user> -- <script_path> <param1> <param2> ...
  ```

  - `/usr/bin/sudo` is **hard-coded**, never resolved through `PATH` — `PATH` is an operator-configurable passthrough, and an elevation path that followed it would be an escalation vector.
  - `-n` keeps sudo non-interactive, so a missing `NOPASSWD` rule fails immediately instead of blocking on a prompt nothing can answer until the hook's timeout kills it.
  - `--` is **mandatory** and must sit immediately before the script path, so a script path or parameter beginning with `-` is passed as data rather than absorbed as a sudo option.
  - `run_as_user` MUST be validated against the POSIX-portable username shape (`[A-Za-z_][A-Za-z0-9_-]*`, optional trailing `$`, max 32 chars), which makes an option-shaped value such as `-i` unrepresentable rather than relying on sudo to be defensive.
  - Assigning a non-empty `run_as_user` is **master-only**, checked before any field validation (see the permission matrix above).
  - This field *requests* elevation; `sudoers` remains the sole authority over whether it is granted.
  - **Environment caveat:** `env_clear()` and `HOOK_PARAM_*` injection are applied to the `sudo` process identically to a direct spawn, but sudo's own `env_reset` strips them before `execve`. Positional parameters always survive; preserving the variables additionally requires `Defaults:<user> env_keep += "HOOK_PARAM_*"` in sudoers.
- **Environment Variable Isolation & Controlled Inheritance:**
  - By default, clear all inherited environment variables using `.env_clear()`.
  - Preserve only essential system variables defined in a global passthrough whitelist (configurable via `ALLOWED_ENV_VARS`, defaulting to `PATH,LANG,TERM,SYSTEMROOT`).
  - Inject validated hook parameters as environment variables prefixed with `HOOK_PARAM_<KEY>=<VALUE>` (e.g., `HOOK_PARAM_TARGET_ADDRESS="1.2.3.4"`).
- **Positional CLI Arguments Support:** In addition to environment variables, support passing parameters as positional CLI arguments to scripts (e.g. for Python scripts expecting `sys.argv`).
- **Parameter Validation:**
  - Each `Hook` defines acceptable parameters (`HookParameter`) with `default_value` and `is_required` flags.
  - If a parameter is required and has no default value and is omitted in the request, reject with `400 Bad Request`.
  - If omitted but a `default_value` exists, apply the default value automatically.
- **Per-Key Concurrency Throttling:** Enforce `max_concurrent_jobs` per `ApiKey` using `tokio::sync::Semaphore`. If a key exceeds its concurrency limit, reject the request with `429 Too Many Requests`.
- **Execution Timeouts:** Enforce per-hook timeout (defaults to 30 seconds if unspecified in the hook configuration). If execution exceeds the timeout, kill the process tree (`SIGKILL`) and record status `TIMEOUT`.

### 3b. SQLite Connection Setup

When the backend is SQLite (the zero-config default), `db::connect` builds the pool from
`SqliteConnectOptions` and declares four settings on **every** connection; `db::apply_sqlite_pragmas`
then re-issues them and reads `journal_mode` back so the startup log reports what is actually in
force. This is the one place a backend-specific statement is permitted, and these are *connection
pragmas*, not queries: the SQL-agnostic rule in the Tech Stack section still holds for everything the
ORM issues.

| Setting | Scope | Why |
| :--- | :--- | :--- |
| `journal_mode=WAL` | **persistent** (file header) | Readers proceed against the last committed snapshot while a writer appends. Without it the default rollback journal takes a database-wide exclusive lock for every write, so one hook recording its `executions` row blocks every concurrent reader — the opposite of what a daemon whose job is parallel execution needs |
| `foreign_keys=ON` | per-connection | SQLite is the one supported engine where declaring a constraint and enforcing it are separate decisions. **SQLx already defaults this on**, so declaring it is hardening against a dependency default changing silently, not a repair — see the correction below |
| `synchronous=NORMAL` | per-connection | The standard companion to WAL: full durability against process crashes, giving up only the last transactions in a power loss, in exchange for not fsyncing on every commit. **The one setting here that genuinely changes behaviour** — the driver default is `FULL` |
| `busy_timeout=5000` | per-connection | WAL still allows only one writer, so simultaneous executions can collide; without a timeout the loser fails instantly with `SQLITE_BUSY` as a spurious `500`. Matches SQLx's own default and makes it explicit |

- **Why `connect` declares them rather than relying on the `PRAGMA` statements alone.** SQLx reopens
  a connection that has been closed or invalidated, and a reopened connection replays its *options*
  but not our statements. Declaring them at open time is what makes them survive a recycle.
- **`SQLITE_MAX_CONNECTIONS = 1` is not a tuning knob.** SQLite permits one writer, and a DDL sequence
  spread across connections does not survive `m20230106`'s drop-and-re-add of the generated
  `master_marker` column. SeaORM's own `Database::connect` pins this for SQLite; hand-building a pool
  opts out of that default silently, so it is restored explicitly and asserted.
- Failure to apply any of them is logged, never fatal. An in-memory database (`sqlite::memory:`, used
  throughout the test suite) legitimately cannot use WAL.

> **Correction to an earlier record.** A previous audit stated that the six foreign keys declared in
> `m20230101_090000_initial_schema` were *inert* on SQLite because nothing here set
> `PRAGMA foreign_keys=ON`. **That was wrong.** SQLx enables foreign keys on every SQLite connection
> it opens, so those constraints have always been enforced: `PRAGMA foreign_keys` reads back `1` on a
> bare `Database::connect`, and an orphan insert is refused with `FOREIGN KEY constraint failed`. No
> orphan-cleanup migration is needed, and none was added — writing one would have been a destructive
> no-op. `tests/referential_integrity.rs` now pins the *behaviour* rather than the pragma.

### 3c. Request Body Ceiling

Every request body — authenticated or not, on every nested route — is capped at **3 MiB**
(`MAX_REQUEST_BODY_BYTES`), applied as a single router-wide `DefaultBodyLimit` layer outside both
`nest()` calls.

- **One constant, two enforcement points.** `middleware::auth_middleware` buffers the raw body to
  recompute the HMAC and derives its own cap from this same constant. Two independently-chosen
  numbers would leave a band of sizes that one layer accepts and the other refuses — a parser
  differential, and the shape of a real class of bug.
- **No per-route override may raise it.** An exception granted to whichever route seemed special
  enough would reintroduce exactly the differential the shared constant removes.
- The value is the figure converged with `simply_ip_vault`, so the two services refuse the same
  payloads. A body over the limit is rejected with `413` before it is read to completion.

### 3d. Monitoring Probes

Two unauthenticated routes, mounted on the root router outside both `nest()` calls so no auth layer
is in their path:

| Route | Question | Consumer | Behaviour |
| :--- | :--- | :--- | :--- |
| `GET /health`, `/healthz` | "Is this process alive?" | Orchestrator, deciding whether to **restart** | Always `200`. `{"status":"ok","service":"simply_hook_executor"}` |
| `GET /ready`, `/readyz` | "Can this process serve traffic?" | Load balancer, deciding whether to **route** | `200` `{"status":"ready","database":"up"}`, or `503` `{"status":"unavailable","database":"down"}` |

- **They must not require a credential.** An orchestrator holds no API key, and a liveness check that
  needs one fails exactly when the credential store is what broke.
- **Liveness must not touch the database.** `health_check` takes no `State` — enforced by the
  compiler, not by a comment. If liveness also checked the database, a thirty-second database blip
  would fail liveness on every replica and the orchestrator would restart all of them, which does not
  fix a database and does destroy in-flight executions.
- **Because they are public, they disclose nothing.** No version, no hostname, no row count, no
  driver error. `readiness_check`'s `DbErr` is logged at `warn` and never returned: it renders
  connection strings and driver internals. A test asserts the body is exactly two fixed fields, so a
  field added later has to be justified rather than arriving unnoticed on a public endpoint.
- **A bounded, typed read and nothing more.** `ApiKey::find().select_only().column(Id).limit(1)` —
  at most one id, never `COUNT(*)`, which on a large table would make every probe a scan and turn the
  health check into load. A probe an anonymous caller can amplify into unbounded work is a
  denial-of-service primitive aimed at the endpoint that reports health. It is built with SeaORM's
  typed builder rather than a literal `SELECT 1`, so it needs **no** raw-SQL allowlist entry.
- **The Master identity must be pinned.** `readiness_check` returns `503` when
  `master_pin.get().is_none()`. `main.rs` pins before binding the listener, so in production this
  cannot be `None` — but that ordering is a convention held by one line, and an edit that bound first
  would produce a process reporting itself ready while every master-only route quietly refused. The
  unpinned case reports `"database":"up"`, because it is: the failure is this process's startup
  ordering, and saying `down` would send an operator to investigate a healthy database.
- `503` rather than `500`: nothing about the request failed. The answer *is* "not ready", and it was
  produced successfully.

### 3e. Error Envelope

Every refusal is `{"error": "<message>"}` with the status `AppError` maps it to. One variant
contributes extra fields:

| Variant | Status | Body |
| :--- | :--- | :--- |
| `ConflictWithDetails { message, details }` | `409` | `{"error": message, ...details}` — an object `details` is **merged into** the envelope, not nested |

It exists for `RBAC_MODEL.md` §6: deleting a key whose subtree owns resources is refused with an
inventory of what would be stranded, because the caller is meant to be *shown* what it is about to
orphan and made to resolve each entity explicitly. A bare `Conflict` could carry the sentence but not
the list.

**Handlers must not build `axum::response::Response` by hand to achieve this.** `delete_api_key` did,
and it worked — but it took the handler out of `Result<_, AppError>` and therefore out of the one
place every refusal in the service is rendered, which is exactly where an envelope drifts. Two rules
follow:

- A `details` that is not a JSON object is **dropped** with an error log rather than replacing the
  envelope, so the body's shape never depends on the call site.
- A `details` carrying its own `error` key does **not** overwrite the message. The envelope wins.

### 4. History, Output Capture & Log Retention

- Every execution produces an `Execution` record storing status (`SUCCESS`, `FAILED`, `TIMEOUT`), exit code, full `stdout`, full `stderr`, duration in milliseconds, resolved parameters JSON, and timestamp.
- **Retention Worker:** An asynchronous background task runs two sweeps on the same interval:
  1. `Execution` entries older than `LOG_RETENTION_DAYS` (default: 30 days).
  2. Soft-deleted `Hook` rows trashed more than **92 days** ago, overridable via `DELETED_HOOK_RETENTION_DAYS` (`0` keeps the trash forever), also exposed on demand at `POST /api/system/purge-hooks`. The purge states all three guards explicitly — `is_deleted = true AND deleted_at IS NOT NULL AND deleted_at < threshold` — even though SQL's three-valued logic already makes either of the first two sufficient. This is the one query in the system that destroys audit history, and its safety must not depend on an invariant held elsewhere in the code or on a reader recalling how `NULL` compares.
- The two windows are **separately** governed, and the worker keeps running when either is disabled. `LOG_RETENTION_DAYS=0` means "keep history forever", not "stop maintaining the trash" — an operator shortening log retention to reclaim disk must not silently shrink the undo window for deleted automation as a side effect.
- **Data is never destroyed implicitly** (`RBAC_MODEL.md` §6). A hook must never disappear as a side effect of removing a key: the cascade deletes keys, and every hook the deleted subtree owned must have been explicitly resolved first. Even a resolution of `{"action":"delete"}` moves the hook to the *trash* — explicit does not have to mean irreversible, and the 92-day purge stays the only thing that destroys a definition. `executions.api_key_id` is `ON DELETE SET NULL`, so run history outlives its author and the attribution is nulled rather than cascaded away.
- **Hook deletion is soft by default** for every caller, master included; see `SCHEMA.MD`. The destructive path (`?hard=true`) is the one that has to be asked for explicitly, because it cascades the hook's parameters, permissions, and entire execution history.

### 5. Dry-Run / Test Endpoint (`POST /api/hooks/:id/test`)

- Allows testing parameter resolution and previewing the generated command without actually spawning the sub-process.
- Returns a JSON payload showing:
  - Resolved parameters (merged defaults and overrides).
  - List of missing required parameters (if any).
  - Exact binary/script path and argument list that would be executed.
  - Injected environment variables map.

### 6. Frontend Integration & Dynamic UI

- Single Page Application (SPA) served from `static/`.
- **Authenticates with full-HMAC `CANONICAL_V1` signing, unconditionally.** The session stores both an `X-API-Key` and its signing secret in `localStorage`, and *every* request the dashboard sends carries `X-API-Key`, `X-Timestamp` and `X-Signature-256`. There is no unsigned path, no bearer-only path, and no per-key mode selection in the browser: the SPA is a first-party client whose key we provision ourselves, so it is held to the strongest posture the backend offers rather than the most permissive one it accepts. Signing CANONICAL_V1 is also what puts the dashboard's own traffic under the anti-replay window and the single-use guard in `src/replay.rs`.
  - This is a *client* policy, not a backend one. The per-key `hmac_mode` column and the `BODY_ONLY` mode remain permanent backend features for third-party webhook senders (§1), and the dashboard still **provisions and displays** them for other keys — it simply never uses `BODY_ONLY` for itself. A `BODY_ONLY` key therefore cannot log into the dashboard.
  - **What is mandatory is the signature, not the implementation.** Signing prefers `window.crypto.subtle`, which browsers expose **only in a secure context** (HTTPS or a `localhost` origin) and which is constant-time. Because this daemon is routinely reached over plain HTTP at a LAN address — a deployment choice, not an authentication one — a self-contained pure-JS HMAC-SHA256 (`PureCrypto`, FIPS 180-4 + RFC 2104, no dependencies per the Tech Stack rule) covers the origins where Web Crypto does not exist at all. The two produce **byte-identical** signatures, so the backend cannot distinguish them and the security property never depends on which ran. The fallback validates itself against an RFC 4231 vector before it is trusted with a credential; if *neither* implementation is usable the login screen refuses and says so, rather than silently downgrading. The fallback is not constant-time — an accepted, narrow trade-off, since it runs only on a plain-HTTP origin where the request and its headers are already fully visible on the path.
- **Dynamic Scope Rendering:** On startup, `app.js` calls `GET /api/auth/me` and renders/hides tabs and controls (Executions/Dashboard, Hooks Management, API Keys & Permissions, System Settings) based on the returned permissions. Because that call is itself signed, reaching the dashboard proves the caller holds the signing secret — not merely that the key exists.
- Global fetch wrapper injects and signs the three authentication headers. `401` returns to the login screen (the credential itself is unusable, so the session is unrecoverable); `403` does **not** — the key is valid and merely lacks permission for that one action, so the server's specific message is surfaced as a toast instead of logging the user out. `404` is surfaced the same way, which is also what oracle discipline requires: the dashboard must not translate a `404` into "you lack permission", because the whole point is that the two are indistinguishable.
- Custom dark confirmation modals for deletions (NO native `window.confirm()`).
- High-contrast action buttons and styled custom checkboxes.

#### UI constraints derived from the RBAC model

The dashboard must not offer a control the backend will refuse, and must not *withhold* one it would allow. Both directions are enforced by tests in `tests/source_hygiene.rs`.

- **No `is_master` control, anywhere.** §5 puts the field on no payload, and both key payloads are `deny_unknown_fields` — so a form that sends it does not get it ignored, it gets the whole request rejected with `422`. A "Master Access" checkbox previously existed here and did exactly that: **every key creation from the dashboard failed**, for as long as the control existed. `the_dashboard_never_sends_is_master_in_a_key_payload` is the regression guard.
- **Global scope toggles are Master-only** (R4). The *create* form hides `can_manage_keys` / `can_manage_hooks` for a non-Master caller and explains why — a Parent has no decision to make there, since every key it mints is a Daughter, and a checkbox that can only be left unticked is an invitation to a `403`. The *edit* modal keeps them visible but **disabled**, because a Parent may legitimately need to see what the key it is editing already holds; R4 restricts granting a scope, not looking at one. Both forms **omit the fields entirely** for a non-Master caller rather than sending `false`: the backend refuses a *request* for a scope, and re-sending a value a key already holds is still a request, so a Parent renaming a Parent key would otherwise `403` on a scope it was not trying to change.
- **Hook actions mirror the server's predicates, not a single flag.** `canEditHook` = Master ∨ owner ∨ (`can_manage_keys` ∧ `can_manage`); `canDeleteHook` = Master ∨ owner. Gating Edit on `can_manage` alone — as it once did — both under- and over-promises: it disabled the button for a Daughter that owns the hook and may edit it, and enabled it for a Daughter holding a bare row that may not.
- **Ownership is shown, not just acted on.** An `Owner` badge renders alongside the verb badges, because "why can I edit this?" is otherwise unanswerable from the UI.
- **`can_view_execution` is a first-class toggle** in the hook-rights form and a `V` in the per-key badge summary. The grant endpoint writes the whole row, so an unchecked box is a revocation rather than "leave as is" — the form is labelled accordingly.
- **Every `getElementById` must resolve.** A missing id returns `null` and throws only when something touches the result, usually inside an event handler — so the page loads, one button silently does nothing, and no existing gate notices.

### 7. Audit Logging

- Every mutating configuration change (Key CRUD, Hook CRUD, Permission updates) writes an `AuditLog` entry storing `api_key_id`, `api_key_name`, `api_key_prefix`, `client_ip`, `action`, `target_resource`, `details`, and timestamp.
- **Attribution is `NOT NULL` and must stay that way.** `api_key_id` is `ON DELETE SET NULL`, so the foreign key is allowed to go; `api_key_name`, `api_key_prefix` and `client_ip` are a point-in-time snapshot and are not. A nullable snapshot permits a row that has lost both the reference and the copy — an audit entry attributable to nobody. See `SCHEMA.MD`.
- **`target_resource` carries the affected entity's human-readable name, never a bare UUID.** Identifiers belong in `details`, formatted with `api::support::format_reference`. A bulk operation with no single target writes `NULL`. An entity with no name of its own — an execution record — takes the name of the entity it hangs from. The writer is `api::support::create_audit_log`, whose rustdoc states the convention; `api/audit.rs` only reads.

### 8. Database Bootstrapping & Systemd Integration

- **`INITIAL_MASTER_KEY`, when set, must be exactly 64 ASCII hex characters**, validated by `config::validate_initial_master_key`. Anything else — wrong width, a non-hex character, or set-but-empty — is **fatal**: the process logs the specific defect and exits non-zero. 64 hex is not arbitrary; it is the shape `api::generate_random_key` mints, so the override cannot be a credential of a different class wearing the same name.
  - **Absence is not an error.** An unset variable is the documented zero-config path: the daemon generates a random master key and prints it once. Making absence fatal would mean the service cannot start without an operator-supplied master key, which contradicts this variable being test/CI-only.
  - **Set-but-empty is fatal**, and that distinction is the point: `INITIAL_MASTER_KEY=$UNSET_VAR` is what a broken deployment script produces, and generating a random key there would hand the operator a daemon whose master credential is not the one their tooling believes it configured.
  - Validation runs in `main` **beside `RuntimeConfig::from_env` and before the database is opened**, so a refused boot leaves no migrations applied and no master key minted.
- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG`.
- Migrations run automatically on startup.
- **Master Key Auto-Gen:** If `api_keys` contains no master keys at boot, generate a default Master Key and output it once clearly to `stdout`. This is now the **only** writer of `is_master = true` anywhere in the codebase, and therefore also the only way to regenerate a master: delete the row directly in the database and restart. The banner is the sole source of that key's signing secret, which is why `scripts/test_e2e.sh` scrapes it rather than minting a second master for signing.
- Include a production-ready `simply_hook_executor.service` file for systemd deployment under a dedicated non-root user (`hookrunner`).

### 9. SeaORM Migration Standards

- **Naming convention: `mYYYYMMDD_HHMMSS_<slug>.rs`.** The full timestamp of authorship — date and
  time — then a short snake_case slug describing what it does. Adopted 2026-08-18, replacing this
  project's earlier `mYYYYMMDD_NNNNNN_<slug>.rs` (a per-date sequence number rather than a time),
  which is still what `simply_ip_vault` uses. **This is a deliberate divergence from the peer, not a
  drift** — it was made because this service has no production deployment yet, so there was no
  `seaql_migrations` history anywhere for the rename to break; see the next bullet for why that
  window will not reopen. Every existing migration was renamed in one pass to this shape, with a
  placeholder time (`09:00:00`) rather than a fabricated precise one, since real per-migration
  authorship times were never recorded and inventing them would misstate history more precisely than
  it clarifies it. A future migration should carry its actual authoring time.
- **Applied migration files are never renamed once this service has a production deployment, and
  reordering them is the same mistake.** SeaORM tracks applied migrations by the file-derived version
  string recorded in `seaql_migrations`. Renaming a migration that has already run against a real
  database does not rename the row that recorded it — it produces a *second*, unrecognized version
  string, so that database sees the renamed file as a brand-new, unapplied migration on its next
  start. Against a non-idempotent `up()` (any `ADD COLUMN`, any `CREATE TABLE`) that is a hard failure
  the moment it reapplies against a schema that already has the object; against an idempotent one it
  is silent double-application. **The one-time rename above was safe only because no such database
  existed.** The instant this service is deployed anywhere persistent, that safety margin is gone:
  from that point on, if a filename turns out to be wrong, the fix is a new migration that corrects
  the mistake going forward — never an edit to history.
- **A migration that tightens a constraint on existing data must backfill first, inside the same
  `up()`, before the constraint is applied.** SQLite has no `ALTER TABLE … ADD CONSTRAINT`, so
  tightening an existing column to `NOT NULL` there is a create-copy-drop-rename table rebuild — the
  highest-risk shape of migration there is, because anything the copy step forgets to carry over
  simply stops existing, with no error. No migration in this repository has needed that rebuild yet:
  `audit_logs`' three attribution columns (`api_key_name`, `api_key_prefix`, `client_ip`) were
  declared `NOT NULL` in `m20230101_090000_initial_schema`, the very first migration, so there has
  never been a nullable row to backfill here. If a future migration needs to tighten a *different*
  column that already holds data, `simply_ip_vault`'s `m20260811_000010_audit_attribution_not_null`
  is the reference implementation for the rebuild, and its backfill value convention is worth keeping:
  the literal `"(unknown)"` rather than an empty string, so a reader can tell "not recorded" from
  "recorded as this".
- **A `NOT NULL` denormalized column and an `ON DELETE SET NULL` foreign key are not in conflict —
  they are different columns describing different things.** `audit_logs.api_key_id` is the foreign
  key; it is nullable, and `SET NULL` is what lets the acting key be deleted without deleting its
  history. `audit_logs.api_key_name`, `.api_key_prefix` and `.client_ip` are denormalized snapshots of
  that same key, declared `NOT NULL`, and populated at write time rather than joined at read time —
  deleting the key later clears the FK's target, not the snapshot taken before it was deleted. See §7
  for the attribution rule itself; the point here is structural, and it generalizes: `ON DELETE SET
  NULL` only ever touches the column it is declared on, so a foreign key being nullable is never a
  reason a denormalized copy of the same fact must be.

---

## 🧪 Testing & Validation Standards

- **Integration Tests:** Located in `tests/`. Use SQLite in-memory (`sqlite::memory:`) for test isolation.
- **Mandatory Test Matrix per Endpoint:**
  1. **Positive Assertion (200/201 OK):** Valid request with sufficient permissions executes or updates resource as expected.
  2. **Authentication Check (401 Unauthorized):** Missing or invalid API key / HMAC signature is rejected.
  3. **Authorization Boundary (403 Forbidden):** Key lacking explicit `can_execute` or `can_manage` permission is denied.
  4. **Validation Check (400 Bad Request):** Missing required parameters, malformed JSON, or invalid scripts are rejected.
  5. **Throttling Check (429 Too Many Requests):** Exceeding `max_concurrent_jobs` returns 429.
  6. **Timeout Check:** Slow scripts exceeding timeout are killed and marked as `TIMEOUT`.

### Source-tree properties (`tests/source_hygiene.rs`)

Four things can ship broken while every other gate passes green, because no other gate looks at the artifact in question. Each has a test:

- **`static/app.js` must parse.** `static/` is served straight off disk by `ServeDir` and is never compiled, linted, or executed by anything else here — `cargo check`, `clippy`, the integration suite and the e2e suite all drive the HTTP API and never parse the file they serve. Checked with `oxc_parser` (a parser, not an engine: the file references `document` and `localStorage`, so *running* it would fail for reasons unrelated to syntax). The `oxc` crates are pinned with `=` because they are pre-1.0 and their `0.x` releases carry breaking changes under a caret requirement — a syntax checker that stops the build for reasons unrelated to syntax is worse than none.
- **Every `getElementById` must resolve**, against ids declared in `index.html` *or* injected by the script's own templates.
- **The dashboard must not send `is_master`** in a key payload.
- **No raw SQL on any query path.** `src/` is scanned for `execute_unprepared`, `Statement::from_*`, `query_*_raw`, `execute_raw`, `from_raw_sql` and `Expr::cust`. Exactly **two** files are allowlisted, each with its reason recorded in the test and in `AGENT_NOTES.MD`: `src/db.rs` (SQLite `PRAGMA`s — not queries, and SeaORM's builders cannot express one) and `m20230106_090000_master_key_uniqueness` (`GENERATED ALWAYS AS` DDL, which `ColumnDef` cannot express). **Neither is reachable from a request, and neither interpolates a runtime value** — the sole substitution across both is a compile-time `const`. Those two properties are the test a third entry must pass; in particular, **an exemption must not be granted to a handler.** One was, briefly, for a literal `SELECT 1` in the readiness probe, and it was withdrawn when that probe moved to SeaORM's typed builder: it sat in code that is both request-reachable and unauthenticated, which is the worst place in the service to hold an exception, and it bought only a saved round-trip. A companion test fails if an allowlisted file stops containing raw SQL, so an exemption cannot outlive its justification and be silently inherited by whatever lands at that path next.

### Harness safety

`scripts/test_e2e.sh` and `scripts/verify_convergence.sh` both assert their working directory before doing anything else. Run from the wrong place they do not fail loudly — they silently exercise something else, or skip work and report a green run over checks that never executed. Each asserts twice: the directory basename, which catches an inherited `cd`, and a list of marker files, which catches a directory carrying the right name without being this checkout.

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*