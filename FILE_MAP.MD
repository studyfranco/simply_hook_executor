# File Map — `simply_hook_executor/src/`

**Audience:** an agent or engineer who needs to change something and must find the right file first —
and, just as importantly, must know which file *not* to put it in.

Each entry states three things:

- **Role & scope** — what the file holds, and what it must **not** hold.
- **Key exports** — the primary functions, structs, and handlers.
- **Rationale** — why this code lives here rather than somewhere else. Where a boundary was decided
  by measurement rather than taste, the measurement is named.

Companion documents: `AGENT.MD` (architectural rules), `SCHEMA.MD` (database), `AGENT_NOTES.MD`
(worklog and audits), `RBAC_MODEL.md` (normative authorization spec, read-only),
`SECURITY_COMPARISON_REPORT.md` and `STRUCTURAL_CONVERGENCE_REPORT.md` (peer parity vs
`simply_ip_vault`).

## Coverage

**This index is exhaustive: every `.rs` file under `src/` appears below.** Verified 2026-08-19.

| Group | Files | Where documented here |
| :--- | :--- | :--- |
| Crate root (`src/*.rs`) | 13 | One `###` section each, under **Top level** |
| API layer (`src/api/*.rs`) | 9 | One `###` section each, under **`src/api/`** |
| Entities (`src/entities/*.rs`) | 8 | Table under **`src/entities/`** (6 rows + a combined `mod.rs`/`prelude.rs` row) |
| Migrations (`src/migration/*.rs`) | 12 | Table under **`src/migration/`** (11 migrations + `mod.rs`) |
| **Total** | **42** | — |

To re-verify after adding a file — all three commands print nothing when coverage is complete
(verified passing 2026-08-19, all three silent):

```bash
# 1. Crate-root and API modules, documented as `### `src/…`` headings
diff <(grep -oE '^### `src/[a-z_0-9/]+\.rs`' FILE_MAP.MD | tr -d '#` ' | sort) \
     <(find src -maxdepth 2 -name '*.rs' \
            -not -path 'src/entities/*' -not -path 'src/migration/*' | sort)

# 2. Entities, documented by basename in a table
comm -13 <(grep -oE '`[a-z_0-9]+\.rs`' FILE_MAP.MD | tr -d '`' | sort -u) \
         <(ls src/entities | sort)

# 3. Migrations, documented by name *without* the .rs suffix
comm -13 <(grep -oE '`m[0-9]{8}_[0-9]{6}_[a-z_0-9]+`' FILE_MAP.MD | tr -d '`' | sort -u) \
         <(ls src/migration | grep '^m20' | sed 's/\.rs$//' | sort)
```

The three groups are checked separately because they are documented in three different shapes —
full path for modules, basename for entities, suffix-less for migrations. A single naive `grep` over
paths reports false gaps for the latter two, and false *hits* for `src/api.rs` and `src/webhooks.rs`,
which appear in prose as historical and peer references rather than as index entries.

Line counts in the section headings are indicative and drift between audits; the **Role & scope**
and **Rationale** text is the contract.

---

## Tree

```
src/
├── lib.rs                  Router assembly, module registry, retention worker spawn
├── main.rs                 Binary entrypoint: migrate, bootstrap, pin, bind, shut down
├── state.rs                AppState — the handle every handler receives
├── master.rs               Boot-time Master identity pinning + runtime demotion
├── middleware.rs           Authentication: bearer key, HMAC, replay, bound-IP
├── config.rs               Environment parsing, proxy trust, client-IP resolution
├── crypto.rs               HMAC request signing + signing-secret encryption at rest
├── replay.rs               Single-use enforcement for CANONICAL_V1 signatures
├── executor.rs             Script execution: argv, env isolation, timeout, killpg
├── retention.rs            Background sweeps for expired history and trashed hooks
├── db.rs                   Pool construction, SQLite session pragmas, migrations
├── error.rs                AppError → HTTP status mapping
├── extract.rs              StrictJson / OptionalStrictJson — §5's type-level body control
├── api/
│   ├── mod.rs              Module wiring, router-facing re-exports, policy constants
│   ├── support.rs          Shared plumbing. Decides nothing
│   ├── guards.rs           Every authorization decision. Writes nothing
│   ├── keys.rs             Key CRUD, identity, grants, §6 cascade
│   ├── hooks.rs            Hook definitions, parameters, trash lifecycle
│   ├── executions.rs       Triggering hooks, and reading the records
│   ├── audit.rs            Reads over the audit trail — master-only
│   ├── system.rs           Effective configuration + counters — master-only
│   └── health.rs           Liveness/readiness probes — the only public routes
├── entities/               SeaORM models, one file per table
└── migration/              Ordered schema migrations
```

---

## Top level

### `src/lib.rs` — 186 lines

**Role & scope.** Declares the module tree, assembles the Axum router, and spawns the retention
worker. Holds no business logic and no authorization: it is the wiring diagram.

**Key exports.** `create_app(state: AppState) -> Router`, `spawn_retention_worker(&AppState)`.

**Rationale.** Every route in one place makes the API surface auditable by reading a single function
— which route is public, which is nested behind `auth_middleware`, and in what order layers apply.
Carries `#![warn(missing_docs)]`, which is what makes the rustdoc requirement in `AGENT.MD`
enforceable rather than aspirational.

`api_routes` is `admin_routes.merge(hook_invocation_routes)` rather than one flat router: the two
hook-invocation routes (`POST /hooks/{id}/execute`, `POST /hooks/{id}/test`) are the only `/api/*`
routes that may authorize a keyless caller, so they sit behind `middleware::invocation_auth_middleware`
on their own sub-router while every other `/api/*` route stays behind the always-mandatory-bearer-key
`middleware::auth_middleware`. `webhook_routes` (`/webhook/{identifier}`) shares the same dual-path
middleware, for the same reason a third-party sender is exactly the caller `HMAC_ONLY`/`NONE` exist
for.

> **Note:** `create_app` refers to handlers unqualified as `api::create_hook`. That works because
> `api/mod.rs` re-exports every handler, and it is why the `src/api.rs` → `src/api/` split left this
> file byte-identical.

### `src/main.rs` — 349 lines

**Role & scope.** The binary. Runs migrations, bootstraps the Master key on an empty table, pins the
Master identity, primes proxy resolution, binds the listener, and shuts down gracefully. Must **not**
hold request-handling logic.

**Key exports.** `main`, `bootstrap_master_key`, `prime_trusted_proxies`, `shutdown_signal`.

**Rationale.** Startup ordering here is load-bearing and deliberately not reorderable for style:
migrations must precede bootstrap (the table must exist), bootstrap must precede pinning (there must
be a row to pin), and pinning must precede binding the listener (no request may be served before the
Master identity is fixed). `bootstrap_master_key` is the **only** writer of `is_master = true` in the
codebase, which is what makes regeneration an out-of-band operation: delete the row directly and
restart.

### `src/state.rs` — 80 lines

**Role & scope.** `AppState` — the cheaply-clonable handle every handler receives. Holds the database
pool, runtime config, concurrency limiter, secret cipher, replay guard, and the Master pin. Must
**not** hold logic; it is a bag of shared handles.

**Key exports.** `AppState`, `AppState::new`, `AppState::with_pinned_master`.

**Rationale.** Everything shared is behind `Arc` on purpose. The limiter and the Master pin in
particular *must* be shared rather than copied: two clones with independent concurrency budgets would
not be a budget, and two clones with different Master pins could reach different conclusions about
who the Master is on two requests in the same second.

### `src/master.rs` — 291 lines

**Role & scope.** Establishes *which* key is the Master, once, and enforces that decision at runtime.
Must **not** decide what a Master may *do* — that is `api/guards.rs`.

**Key exports.** `MasterPin` (`pin_at_boot`, `resolve`, `authenticate`, `pinned_to`),
`MasterPinError`.

**Rationale.** Every authorization decision branches on `is_master`, which is a database column — so
an attacker with write access needs one `UPDATE` to become Master. `RBAC_MODEL.md` §5's uniqueness
constraint refuses that statement; this module is the layer *behind* it, for the case where the
constraint itself is dropped.

`authenticate` is the single choke point: it demotes a key whose column claims mastery but whose id
is not the pinned one, **before any handler sees it**. That is the whole design. There are dozens of
`key.is_master` reads across `src/api/`, and a scheme requiring each of them to also compare an id
would be one forgotten call site away from worthless — including every call site added later by
someone who never read this file. Handlers keep reading `key.is_master` and are automatically
correct, because the principal they receive is the *effective* one.

### `src/middleware.rs` — 848 lines

**Role & scope.** Authentication only — establishing *who* is calling. Bearer key lookup, HMAC
signature verification, timestamp freshness, replay rejection, and bound-IP enforcement. Must **not**
make per-resource authorization decisions.

**Key exports.** `auth_middleware` (every administrative `/api/*` route — bearer key always
mandatory), `invocation_auth_middleware` (the three hook-invocation routes — may authorize a keyless
caller per the target hook's `AuthMode`), `ClientIp`, `HMAC_ONLY_DEFAULT_HEADER`.

**Rationale.** Ordering inside this file is a security property, not a style choice:
**authenticate, then authorize.** Checking the source network before the signature let a caller
holding only a leaked bearer key distinguish "wrong network" from "bad signature", handing a network
map to someone who could not authenticate. Timestamp freshness runs *before* the database lookup, so
unauthenticated garbage never buys an indexed query.

This is also where `MasterPin::authenticate` runs, which is why a tampered `is_master` never reaches
a handler.

**Two middleware functions, one shared authentication core.** `auth_middleware` and
`invocation_auth_middleware` both delegate their keyed path to `authenticate_bearer_key` — the whole
of what the pre-existing single function did (steps 3-7 of the ordering above), pulled out so the two
callers cannot drift into two copies of the same security-critical sequence. `invocation_auth_middleware`
additionally branches on whether `X-API-Key` is present at all: absent, it resolves the target hook
from the request path (`hook_identifier_from_path`, a pure function — the router-nest prefix is
already stripped by the time this middleware runs, matching the `OriginalUri` note above) and
authorizes per its `AuthMode`.

**One uniform `401` for every authentication failure on an invocation route** — `invocation_unauthorized`,
returning `{"error": "Unauthorized"}` verbatim, is what both branches of `invocation_auth_middleware`
collapse into: a keyless caller that cannot proceed (no such hook, a hook requiring a key, a `NONE`
hook blocked by `REQUIRE_SIGNED_REQUESTS`, or unexpected signature material on a mode that does not
use one — see `signature_material_present`), *and* a keyed caller whose key does not exist or whose
signature does not verify (`uniformize_keyed_auth_failure`, wrapping `authenticate_bearer_key`'s
errors). A caller holding no credential, a guessed one, or a stolen one it cannot yet prove must learn
nothing beyond "not authenticated" — closing that oracle across both paths at once is why this lives
as one shared function rather than two similar-looking ones. A genuinely *valid* key that merely lacks
`can_execute` is deliberately **not** folded in: `guard_execute` still answers its own `403` with its
own message, since that caller has proven a real credential and "unauthorized" would misdescribe why
it was refused.

### `src/config.rs` — 1,642 lines

**Role & scope.** Turning the environment into typed, validated configuration, plus the trusted-proxy
model and client-IP resolution. Must **not** read the database.

**Key exports.** `RuntimeConfig`, `TrustedProxies`, `ProxySpec`, `resolve_client_ip`,
`resolve_bind_addr`, `normalize_ip`.

**Rationale.** Large, and legitimately so — it is one subject (what the operator asked for) with a
great deal of validation. `resolve_client_ip` lives here rather than in `middleware.rs` because the
X-Forwarded-For chain walk is one of the three behaviours `scripts/verify_convergence.sh` compares
against the peer service; keeping it in a named function in a predictable file is what makes that
check possible.

### `src/crypto.rs` — 828 lines

**Role & scope.** Every cryptographic primitive in the service: HMAC request signing, and encryption
of `api_keys.signing_secret` at rest. Must **not** decide *when* a signature is required, or what a
caller is told when one fails — that is `middleware.rs`.

**Key exports.** Signing: `generate_signing_secret`, `canonical_v1_payload`, `compute_signature`,
`verify_signature`, `verify_signature_with_prefix` (generalized to a caller-supplied prefix, for
`hooks.signature_prefix`), `render_canonical_template`, `DEFAULT_CANONICAL_TEMPLATE`,
`SignatureRejection`, `SIGNATURE_PREFIX`. At rest: `SecretCipher` (`from_env`, `seal`, `open`,
`is_encrypting`), `CryptoError`.

**Rationale.** Both halves protect the same column, from opposite directions: the signing half is
what `api_keys.signing_secret` is *for*, and `SecretCipher` is how it survives being written down.
Holding them together is what makes "where is the crypto?" have one answer.

Everything here is a **total function of its arguments** — no database, no request, no `AppError`.
That purity is the module boundary, and it is what makes byte-level tests like
`every_single_byte_mutation_of_a_valid_signature_is_rejected` practical to write; against a
middleware they would need a router, a pool and a seeded key first. Refusals are reported as
`SignatureRejection`, leaving `middleware::reject_signature` to decide which become `401` and which
become `500`.

This **closes the largest structural divergence** recorded in the previous audit: the peer service
always kept request-signature computation in its own `crypto.rs`, while ours sat in `middleware.rs`
as a private `signature_base`. Both now use the same name in the same file, and
`scripts/verify_convergence.sh` compares `src/crypto.rs::canonical_v1_payload` on both sides rather
than normalizing two names into one.

### `src/replay.rs` — 406 lines

**Role & scope.** Remembering which `CANONICAL_V1` signatures have been used, so each is accepted
exactly once inside its window.

**Key exports.** `ReplayGuard` (`new`, `check_and_record`).

**Rationale.** The anti-replay window and single-use enforcement are two different controls: the
window bounds *how long* a captured request stays useful, single-use bounds *how many times* it may
be used. Only both together are replay protection. A digest is recorded **only after** it verifies —
recording unverified signatures would let anyone who merely observed a request burn it before the
legitimate copy arrived, turning the control into a denial-of-service primitive aimed at the client
it protects.

### `src/executor.rs` — 1,403 lines

**Role & scope.** Everything about running a child process safely: argv construction, environment
isolation, `run_as_user` handling, script-path containment, timeouts, and process-group kill. Must
**not** make authorization decisions — by the time execution starts, the caller has been authorized.

**Key exports.** `execute_hook`, `build_command_plan`, `resolve_parameters`, `validate_script_path`,
`validate_run_as_user`, `effective_run_as_user`, `ensure_executable`, `run_process`,
`is_valid_param_key`.

**Rationale.** Large but coherent — one subject, deeply defended, and splitting it would be churn.
This is the file where a mistake is remote code execution, so the defences are layered: path
containment, `env_clear` with an explicit allowlist, argv rather than shell strings, and `killpg` so
a process that forks cannot outlive its timeout. **This file has no peer equivalent** — the peer
service dispatches HTTP webhooks (`src/webhooks.rs`) rather than executing local scripts, and that
asymmetry is the deepest architectural difference between the two codebases.

### `src/retention.rs` — 150 lines

**Role & scope.** Background sweeps: expired execution history, and trashed hooks past their
retention window.

**Key exports.** `run_retention_worker`, `purge_expired_executions`, `purge_expired_deleted_hooks`.

**Rationale.** The same functions back both the timer and the master-only manual purge endpoint, so
an operator reclaiming space immediately gets exactly the behaviour that would have happened on its
own schedule. The worker takes a shutdown channel so it stops cleanly rather than being killed
mid-sweep.

### `src/db.rs` — 427 lines

**Role & scope.** How the database is *opened*: pool construction, SQLite session pragmas, and the
migration entry point. Must **not** hold queries.

**Key exports.** `connect`, `run_migrations`, `apply_sqlite_pragmas`, `SQLITE_BUSY_TIMEOUT_MS`,
`SQLITE_MAX_CONNECTIONS`.

**Rationale.** One of **three files in `src/` permitted to contain raw SQL**, enforced by
`tests/source_hygiene.rs`. A `PRAGMA` is not a query — it configures how the engine behaves rather
than what it is asked — and SeaORM's builders cannot express one. Backend-gated to SQLite, and no
runtime value is interpolated.

`connect` exists because the pragmas must survive connection recycling: SQLx replays a reopened
connection's *options* but not our `PRAGMA` statements, so `foreign_keys`, `journal_mode`,
`synchronous` and `busy_timeout` are declared through `SqliteConnectOptions` at open time.
`apply_sqlite_pragmas` still runs afterwards and is not redundant — it reads `journal_mode` back, so
the startup log reports what is actually in force rather than what was requested, and it covers pools
this crate did not build (every pool in the test suite).

`SQLITE_MAX_CONNECTIONS = 1` is not a tuning knob: SQLite permits one writer, and a DDL sequence
spread across connections does not survive `m20230106`'s drop-and-re-add of the generated
`master_marker` column.

A pragma that cannot be applied is logged and swallowed rather than aborting startup: the whole test
suite runs on `sqlite::memory:`, which cannot use WAL, and refusing to boot over a performance
setting would trade a real outage for a theoretical slowdown.

> **Correction.** An earlier audit recorded the six foreign keys in `m20230101` as *inert* on SQLite
> because nothing here set `PRAGMA foreign_keys=ON`. That was wrong: SQLx sets it on every SQLite
> connection it opens, so they have always been enforced. Declaring it explicitly is hardening
> against a dependency default changing, not a repair. `tests/referential_integrity.rs` now pins the
> behaviour itself.

### `src/error.rs` — 140 lines

**Role & scope.** The single error type crossing the handler boundary, and its HTTP mapping.

**Key exports.** `AppError` — `Json`, `DbError`, `InvalidInput`, `Unauthorized`, `Forbidden`,
`NotFound`, `Conflict`, `TooManyRequests`, `BodyRejected`, `Internal`.

**Rationale.** One type means the status-code policy is decided in one place and cannot drift per
handler. `BodyRejected` carries the extractor's own status rather than flattening to `400`, which is
what keeps a `413` oversized-body rejection from being reported as a malformed payload.

### `src/extract.rs` — 108 lines

**Role & scope.** The two request-body extractors, and nothing else. `StrictJson` renders a
deserialization refusal in this service's `{"error": …}` envelope instead of Axum's plain-text
rejection; `OptionalStrictJson` additionally treats an **empty body** as `T::default()`, which is
what lets `DELETE /api/keys/{id}` be called with no body at all on the first request and with a §6
resolution map on the resubmission.

**Key exports.** `StrictJson`, `OptionalStrictJson`, `StrictPath`, `StrictQuery`, `StrictBytes` —
one per extractor any handler in this service uses, and handlers use **nothing else**.

**Rationale — why this is a crate-root module and not part of `api/support.rs`.** These are not
helpers. `StrictJson` is the mechanism that turns `#[serde(deny_unknown_fields)]` from an annotation
into an enforced control, and `RBAC_MODEL.md` §5 requires exactly that control: *"Removing the field
from the payload type is required; rejecting it at the handler is not sufficient."* Absence plus
`deny_unknown_fields` is what makes the removal mean something, and this extractor is what carries
the resulting refusal to the caller. `api/support.rs` is by its own charter the module that **decides
nothing** — and deciding whether a request is well-formed enough to reach a handler is a decision,
made before any handler runs. An Axum `FromRequest` implementation is also a framework concern rather
than a domain one, so keeping it under `api/` filed HTTP plumbing inside the tree that models the
service's domain. `simply_ip_vault` places the identical pair in its own `src/extract.rs`; this
placement closes structural divergence **S2** and gives both services one address for "how does a
body become a typed payload here".

**The contract, and why completeness is the whole point.** Every refusal this service produces is
`{"error": "…"}` served as `application/json`. That held for everything a *handler* returned and, until
the extractors were wrapped, for nothing rejected **before** one ran — a malformed body, a mistyped
UUID, a bad query value and an oversized raw body all came back with the right status and a bare
`text/plain` body carrying no `error` field. Those are the most common things a caller gets wrong,
which made them the worst place for the contract to lapse, and because no handler is involved no
handler test could see it. A single bare `Path<Uuid>` left in a handler reopens it for that route, so
the rule is that `src/api/` imports its extractors from here and never from `axum::extract`.

**Invariant worth preserving.** Every extractor passes the rejection's **own status** through rather
than flattening it to `400`. The router-wide `DefaultBodyLimit` surfaces here as a rejection too, so
flattening would silently demote `413 Payload Too Large` into an indistinguishable bad request — and
`PathRejection::MissingPathParams` is a `500` describing a defect in *this service*, which must never
be reported to a caller as their bad request.

---

## `src/api/` — the HTTP layer

Split from a single 3,847-line file. The layout was chosen by measuring which private helpers cross
domain boundaries (17 do); the full audit and rationale are in `AGENT_NOTES.MD`.

`ConflictWithDetails { message, details }` is the one variant that contributes fields beyond `error`:
an object `details` is **merged into** the envelope, producing `{"error":…, "subtree":[…],
"inventory":[…]}` for `RBAC_MODEL.md` §6's pre-flight inventory. It exists so `delete_api_key` can
stay in `Result<_, AppError>` rather than hand-building an `axum::response::Response` — a handler
that leaves that path leaves the one place every refusal is rendered. A non-object `details` is
dropped with an error log rather than replacing the envelope, and a `details` carrying its own
`error` key does not overwrite the message.

### `src/api/mod.rs` — 95 lines

**Role & scope.** Module declarations, router-facing re-exports, and shared policy constants. Must
**not** hold handlers or helpers.

**Key exports.** Every handler, re-exported. `MAX_TIMEOUT_SECONDS`, `MAX_CONCURRENT_JOBS`,
`DEFAULT_PAGE_LIMIT`.

**Rationale.** The re-exports exist so `api::create_hook` resolves exactly as it did before the
split, leaving `src/lib.rs` byte-identical. A refactor that forces every call site to change has a
blast radius nobody can review. The constants sit here rather than in `support.rs` because they are
policy numbers rather than plumbing, read by both the validators that enforce them and the handlers
that document them.

### `src/api/support.rs` — 401 lines

**Role & scope.** Shared plumbing used by three or more handler domains. **Must not decide
anything.** Nothing here returns a refusal that depends on *who* is calling — a helper that starts
doing so belongs in `guards.rs`. The strict JSON extractors used to live here and now sit in
`src/extract.rs`; they were the one thing in this file that decided something.

**Key exports.** `create_audit_log`, `create_audit_log_anonymous` (the keyless-invocation
counterpart — see `hook.rs`/`middleware.rs` above; writes a fixed, `NOT NULL`-satisfying sentinel
rather than relaxing the attribution columns); `resolve_hook`,
`resolve_hook_including_deleted`; `load_parameters`; `format_reference`; `generate_random_key`,
`hash_key`, `generate_key_id`, `generate_signing_secret`, `mint_signing_pair`; `validate_timeout`,
`validate_bound_ips`, `validate_concurrency`; `extract_parameter_map`; `describe_hmac_mode`,
`describe_privilege`.

**Rationale.** This module exists because of a measurement: `create_audit_log` and `resolve_hook` are
each used by five domains, `format_reference` by four, `load_parameters` by three — and none of them
decides anything. Without a support module they would have had to live in `guards.rs`, making
"guards" mean "guards, plus everything else that turned out to be shared" — the monolith problem one
level down. **The peer service has no `support.rs`; its equivalents live in `api/mod.rs`.**

The credential primitives are `pub` because `tests/common/mod.rs` mints keys directly against the
database, hashing a plaintext exactly as the service would — the only way to seed a key whose secret
the test already knows.

### `src/api/guards.rs` — 1,053 lines

**Role & scope.** Every **cross-domain** authorization decision in the API layer. **Must not write
anything.** A guard answers "may this caller do this", returns `Result<_, AppError>`, and mutates no
state. §4's *key-subtree* visibility is the one exception and lives in `api/keys.rs` — see below.

**Key exports.**

| Rule | Guard |
| :--- | :--- |
| R2 conjunction (single evaluation point) | `guard_hook_manage_conjunction` |
| R2, master/owner short-circuit in front of it | `guard_manage` |
| R2 in full for dispatch config, no ownership exception (SHE-1) | `guard_dispatch_configuration` |
| R2 pre-payload standing | `has_permission_admin_standing`, `manages_any_hook` |
| Service policy: `can_manage_keys` ⇒ `hmac_mode = CANONICAL_V1` | `guard_canonical_v1_for_key_management` |
| R1 delegation bound | `guard_delegated_hook_grant` |
| R6 revocation classification | `is_permission_reduction` |
| R4 scope elevation | `guard_master_to_grant_scopes`, `guard_master_to_administer` |
| §3 lifecycle | `guard_lifecycle_authority` |
| §4 hook visibility | `guard_visibility`, `visible_hook_ids`, `verb_denied` |
| §4 execution visibility | `may_read_execution`, `execution_visible_hook_ids` |
| §4 key-subtree visibility | **moved to `api/keys.rs`** — single-consumer exception, `AGENT.MD` §0 |
| §5 master protection | `refuse_master_lifecycle_action`, `guard_master_self_edit_is_bound_ips_only` |
| Privilege elevation | `normalize_run_as_user`, `guard_master_for_privileged_hook` |
| Execute verb | `guard_execute` |
| Trash visibility | `guard_master_for_deleted_view` |

**Rationale.** One module rather than one per domain, **and it must stay that way.**
`RBAC_MODEL.md`'s rules are cross-cutting: R2's conjunction governs hooks, parameters and execution
records alike, and §3's ownership test is consulted from three domains. Splitting guards by caller
would put a single sentence of the specification in three files and invite the copies to drift —
which is precisely the failure the compliance suite exists to catch, and therefore must not be
designed in.

**The single-consumer exception.** §4's key-subtree visibility (`KeyVisibility`,
`descendant_key_ids`, `managed_hook_ids`, `key_visibility`, `load_administrable_key`) moved to
`api/keys.rs` because it satisfies both halves of the rule in `AGENT.MD` §0: exactly one domain calls
it, and the five form a closed cluster calling only each other, so relocating them cannot split a
rule across files. They are module-private there, which makes the single-consumer claim something the
compiler checks. §4's *hook* visibility stayed here — three domains consult it — so one §4 is split
across two files. That is the accepted cost of counting consumers rather than section numbers.

Two ordering rules inside this file are load-bearing:

- `guard_manage` checks **ownership before the conjunction**, because the conjunction answers `404`
  when the caller holds no permission row and an owner need not hold one. Asking the conjunction
  first would hide a hook from the very key answerable for it.
- `guard_hook_manage_conjunction` decides **visibility before the verb**: any row at all makes the
  hook visible (`403` for a missing conjunct), no row makes it invisible (`404`). Filtering on
  `can_manage` first would `404` a hook the caller can demonstrably see via `GET /api/auth/me`.

### `src/api/keys.rs` — 1,335 lines

**Role & scope.** API key lifecycle, caller identity, per-hook grants, the §6 cascade, and §4
**key-subtree** visibility.

**Key exports.** `get_me`, `create_api_key`, `list_api_keys`, `update_api_key`, `delete_api_key`,
`rotate_api_key`, `update_key_hook_permissions`, `revoke_key_hook_permission`; `HookPermissionView`,
`MeResponse`, `ApiKeySummary`, `MinimalApiKeyView`, `collect_subtree_inventory`.

**Module-private** (deliberately not exported): `KeyVisibility`, `descendant_key_ids`,
`managed_hook_ids`, `key_visibility`, `load_administrable_key`.

**Rationale.** `get_me` lives here rather than in an `auth.rs` because it shares both its view type
(`HookPermissionView`) and its loader (`load_hook_permissions`) with the key listing — a separate
module would have put a type in one file and both its consumers in another. "What does this key
hold" is the same question in both places. **The peer service made the same choice independently.**

`delete_api_key` returns `axum::response::Response` rather than a typed body because §6 requires two
different shapes: `204` on success, `409` with a structured inventory when the subtree owns entities
the caller must resolve first.

**The §4 key-visibility cluster lives here**, not in `guards.rs`, under the single-consumer exception
in `AGENT.MD` §0: every call site is in this file, and the five call only each other. All five are
module-private, so a second domain needing one breaks the build and forces an explicit decision
rather than letting the boundary erode. They keep `guards.rs`'s discipline regardless of file —
returning `Result<_, AppError>`, writing nothing, and preserving §4 oracle discipline, where a
`None`/`404` must be indistinguishable from a nonexistent id and is propagated rather than converted
to a `403`.

`create_api_key`/`update_api_key` also own `canonical_template` — a per-key override of the
`CANONICAL_V1` canonical string, added alongside `HmacMode::BodyOnly`'s retirement as the
replacement customization surface. `hmac_mode` stays immutable after creation exactly as before
(still no field on `UpdateApiKeyPayload` at all); `canonical_template` **is** mutable, but only for
a key that is not (and does not become) a `can_manage_keys` holder —
`guards::guard_canonical_v1_for_key_management` refuses either direction (granting the scope to an
already-templated key, or templating an already-scoped one) with `400`.

`ApiKeySummary` also carries `parent_key_id`, for the WebUI's key-lineage column — display only, per
`RBAC_MODEL.md` R3 ("rights are never derived from key lineage"), and deliberately absent from
`MinimalApiKeyView`, whose §4 shared-resource disclosure does not extend to it.

### `src/api/hooks.rs` — 1,063 lines

**Role & scope.** What a hook *is* — its definition, dispatch configuration, parameter contract, and
trash lifecycle. Must **not** hold execution: that is `executions.rs`.

**Key exports.** `create_hook`, `list_hooks`, `get_hook`, `update_hook`, `delete_hook`,
`restore_hook`, `purge_deleted_hooks`; `list_hook_parameters`, `create_hook_parameter`,
`update_hook_parameter`, `delete_hook_parameter`; `HookDetail`, `build_hook_detail`,
`grant_full_hook_permission`.

**Rationale.** `script_path` and `run_as_user` are this service's **dispatch configuration**, which
`RBAC_MODEL.md` places under R2 in full — which is why `update_hook` is gated by `guard_manage` and
not by a bare permission row. Parameter CRUD sits in the same file and behind the same gate because a
parameter is argv for whatever `script_path` names: a defaulted parameter on a hook running `/bin/sh`
supplies `-c` and a command string without the caller ever touching `script_path`.

`auth_mode` and its four supporting fields (`hmac_secret`, `signature_header`, `signature_prefix`,
`canonical_template`) are **not** dispatch configuration under `RBAC_MODEL.md`'s Terminology section —
only `script_path`/`run_as_user` are named there — so they are editable via ordinary `guard_manage`
(ownership included), not `guard_dispatch_configuration`. `validate_and_seal_hmac_secret` is the one
piece of non-trivial validation: it refuses landing a hook in `HMAC_ONLY` with no secret configured,
checked against the *effective* mode and secret (payload's, else the row's existing one) so both
"create as HMAC_ONLY with none" and "switch an existing hook to HMAC_ONLY that never had one" are
caught, not only the first.

### `src/api/executions.rs` — 485 lines

**Role & scope.** Triggering hooks and reading the records that result.

**Key exports.** `execute_hook_endpoint`, `webhook_execute`, `test_hook`; `list_executions`,
`get_execution`, `delete_execution`, `purge_executions`; `ExecutionView`, `run_hook_request`,
`parse_status`, `ExecutionQuery`, `PurgeQuery`.

**Rationale.** Triggering and history are one module because they share `ExecutionView` and nothing
else uses it. The visibility rule enforced here is §4's third scope: an execution record is
**creator-private**, readable by exactly four identities (Master, the acting key, the hook's owner,
or a row carrying `can_view_execution`/`can_manage`), and everything else is `404` — byte-identical
to a record that never existed.

The listing expresses that disjunction as a single indexed `WHERE` rather than filtering after
fetching, which would page wrongly: a `LIMIT 50` applied before a visibility filter returns fewer
than fifty visible rows and hides the rest behind an offset that never advances past them.

`key` is `Option<Extension<api_key::Model>>` on all three trigger handlers, not the mandatory
`Extension` every other handler in this crate takes — `middleware::invocation_auth_middleware` may
authorize a keyless caller through the target hook's `AuthMode`, in which case there is no key row to
extract. `run_hook_request` skips `guard_execute` entirely when `key` is `None` (there is no
permission row to check against; the hook's own `auth_mode` already decided the request was
authorized) and attributes the resulting audit log entry and execution record accordingly
(`api_key_id = NULL`, `create_audit_log_anonymous`'s sentinel name/prefix).

Note `delete_execution` is deliberately **stricter** than reading one — `can_view_execution` buys
visibility, never destruction. An auditor is not a redactor.

### `src/api/audit.rs` — 113 lines

**Role & scope.** Master-only **reads** over `audit_logs`. Must **not** hold the writer.

**Key exports.** `list_audit_logs`, `AuditLogQuery`, `parse_instant`.

**Rationale.** This was the first half of `system.rs`, which grouped the audit log with the settings
endpoint on the grounds that both are master-only. Audience is the weakest thing to organize by —
nearly every administrative endpoint shares it — and the two halves differ in every way that matters
for change: this one reads a growing table and will keep acquiring query surface (filter by acting
key, by target, by time range), while settings reports a struct fixed at startup. Splitting them
also **removes the last naming divergence** from the peer service, which reached `api/audit.rs`
independently.

`AuditLogQuery` grew the predicted time-range and target surface: `client_ip` (substring match, for
the WebUI's Audit Logs tab) and `since`/`until` (RFC 3339, parsed by `parse_instant` into the naive
UTC shape `audit_logs.timestamp` is stored as — `since` is inclusive, `until` is strictly exclusive,
matching the half-open range a paginated "next page starts here" UI expects).

Writing an audit row is `api/support.rs::create_audit_log`, called from every mutating handler. That
asymmetry is deliberate: this module is the *reader* of a table a dozen call sites write to.

### `src/api/system.rs` — 101 lines

**Role & scope.** The effective runtime configuration and instance counters. Master-only.

**Key exports.** `get_settings`, `SettingsResponse`.

**Rationale.** Master-only because `allowed_env_vars` describes what a hook's child process
inherits, which is exactly what an attacker probing for an escape would want. `trusted_proxies` is
surfaced because "is my proxy actually trusted?" is otherwise answerable only by reading the
daemon's environment, and getting it wrong silently changes which address every `bound_ips` check is
evaluated against.

### `src/api/health.rs` — 131 lines

**Role & scope.** Liveness and readiness probes — **the only unauthenticated routes in the
service**. Must disclose nothing an anonymous caller could not already infer.

**Key exports.** `health_check`, `readiness_check`.

**Rationale.** Mounted on the root router outside both nests, so no auth layer is in their path.
That is the mechanism, not a convenience: an orchestrator holds no API key, and a liveness check
that needs one fails exactly when the credential store is what broke.

**Liveness and readiness are deliberately different questions.** `health_check` takes no `State` —
enforced by the compiler, not by a comment — so it cannot be made to fail by the database being down;
an orchestrator uses it to decide whether to *restart*. `readiness_check` reaches the database and a
load balancer uses it to decide whether to *route*. If liveness also checked the database, a
thirty-second database blip would fail liveness on every replica and the orchestrator would restart
all of them — which does not fix a database and does destroy in-flight executions.

The database check is a **typed** SeaORM query — `ApiKey::find().select_only().column(Id).limit(1)`
— bounded to at most one id so an anonymous caller cannot amplify the probe into a table scan. It
carried a raw `SELECT 1` and a third raw-SQL allowlist entry until this pass; that exemption was
withdrawn because it sat in a request-reachable, unauthenticated handler and bought only a saved
round-trip.

`readiness_check` also returns `503` when `master_pin.get().is_none()` — catching a process that
bound its listener before pinning, which would otherwise report itself ready while every master-only
route quietly refused. The `DbErr` is logged and never returned: it renders connection strings and
driver internals, and this endpoint is public.

---

## `src/entities/` — SeaORM models

One file per table, each a `DeriveEntityModel` plus its relations. These are the schema in Rust form;
`SCHEMA.MD` is the prose. Must **not** hold business logic.

| File | Table | Note |
| :--- | :--- | :--- |
| `api_key.rs` | `api_keys` | **`master_marker` is deliberately absent from the model** — it is an engine-generated column, so SeaORM must never emit it in an `INSERT`. `parent_key_id` is the **only** key-to-key relationship; the dormant `owner_key_id` was dropped in `m20260810_090000`. Also defines `HmacMode` — a key's **own** signature mode, unrelated to `hook.rs`'s `AuthMode` below. `HmacMode` now has **one** variant (`CANONICAL_V1`) — `BODY_ONLY` was retired in `m20260819_141730`, superseded by hook-level `HMAC_ONLY`. `canonical_template` (added the same migration) is the per-key customization surface that replaced it |
| `hook.rs` | `hooks` | Carries `owner_key_id` (§3 — the **load-bearing** one, easily confused with the key column that was dropped) and the soft-delete columns. Also defines `AuthMode` (`CANONICAL_V1`/`API_KEY_ONLY`/`HMAC_ONLY`/`NONE`) and the four supporting columns (`hmac_secret`, `signature_header`, `signature_prefix`, `canonical_template`) added in `m20260819_120414` — **inbound** authentication for a request targeting *this hook*. `AuthMode` itself stays off `ApiKey` — `NONE`/`HMAC_ONLY` describe a keyless caller, incoherent as a property of a credential object — but `api_key.rs`'s own `canonical_template` (added later, `m20260819_141730`) is a deliberately separate, narrower field: a per-key template override, not a mode. See `middleware.rs` below |
| `api_key_hook_permission.rs` | `api_key_hook_permissions` | The three verbs: `can_execute`, `can_manage`, `can_view_execution` |
| `hook_parameter.rs` | `hook_parameters` | Declaration order is argv order |
| `execution.rs` | `executions` | `api_key_id` is the acting key — the "creator" in §4's third scope. Defines `ExecutionStatus` |
| `audit_log.rs` | `audit_logs` | Attribution stored as text so it outlives the acting key |
| `mod.rs`, `prelude.rs` | — | Registry and bulk import |

---

## `src/migration/` — ordered schema migrations

Run automatically at startup, in the order listed in `mod.rs`. Migrations are append-only: never edit
one that has shipped.

| Migration | Adds |
| :--- | :--- |
| `m20230101_090000_initial_schema` | All six tables |
| `m20230102_090000_add_run_as_user` | `hooks.run_as_user` |
| `m20230103_090000_add_signing_secret` | `api_keys.key_id`, `api_keys.signing_secret` |
| `m20230104_090000_add_hmac_mode` | `api_keys.hmac_mode` |
| `m20230105_090000_add_hook_soft_delete` | The trash columns on `hooks` |
| `m20230106_090000_master_key_uniqueness` | `api_keys.master_marker` — **§5's engine-derived generated column** |
| `m20230107_090000_key_lineage_and_resource_ownership` | `parent_key_id`, `owner_key_id` (on both `api_keys` and `hooks`), and §7's indexes |
| `m20260809_090000_add_can_view_execution` | The third permission verb |
| `m20260810_090000_drop_api_key_owner_key_id` | **Removes** `api_keys.owner_key_id` and its index — dormant since `m20230107`, read by nothing |
| `m20260819_120414_add_hook_auth_mode` | `hooks.auth_mode` (`NOT NULL DEFAULT 'CANONICAL_V1'`), `hmac_secret`, `signature_header`, `signature_prefix`, `canonical_template` (all nullable) — per-hook inbound authentication, see `entities/hook.rs` above |
| `m20260819_141730_consolidate_hmac_modes` | **Retires** `api_keys.hmac_mode = BODY_ONLY` (rewrites any stored row to `CANONICAL_V1` via a typed `sea_query::Query::update`, not raw SQL) and **adds** `api_keys.canonical_template` — see `entities/api_key.rs` above |

`m20260810` is the only migration so far that **removes** something, and the reasoning is worth
keeping close to the list: `m20230107` added `owner_key_id` to `api_keys` and `hooks` together, on the
symmetric assumption that if a hook has an owner then a key might as well. Only the hook column ever
meant anything — `RBAC_MODEL.md` §3 scopes ownership to managed resources and creator-private
entities, and a key is neither. The key column was write-only for its whole life.
`s7_every_required_index_and_constraint_exists` now asserts its absence *and* the hook column's
presence, so neither the removal nor its limit can drift.

**`m20230106` is the second of the two files permitted to contain raw SQL.** SeaORM's `ColumnDef` has
no generated-column support at all, and §5 requires the marker to be engine-derived rather than
application-maintained. The storage keyword is dialect-dependent — `STORED` for PostgreSQL (which
gained `VIRTUAL` only in 18), `VIRTUAL` for SQLite (which permits only that on an added column) and
MySQL (which accepts either, and avoids a table rewrite this way) — and unit tests in that file pin
all three, because the wrong pairing fails only against a live server the unit suite never starts.

**`m20230107` deliberately declares no foreign keys.** Both available behaviours are wrong here:
`CASCADE` would destroy the resources §6 forbids destroying implicitly, and `SET NULL` would orphan
them exactly when the pre-flight inventory needs to name their owner. The integrity those constraints
would provide is application-level and covered by `s7_adversarial_dangling_lineage_written_behind_the_applications_back`.

---

## Verification surface — which suite covers what

`src/` is only half the tree a future agent needs to navigate. The gates below are what hold every
claim in this document true, and they cover deliberately different things: a property provable
in-process is a Rust test, and a property that is only true of the *running binary* — startup
refusals, signal handling, real child processes — belongs in the e2e suite, because a unit test
cannot tell whether `main` actually honours it.

| Gate | Size | Covers | Cannot cover |
| :--- | :--- | :--- | :--- |
| `cargo test` | **287** across 9 binaries, **2 ignored** | Handler logic through the real router (`oneshot`, no port), RBAC compliance, schema/referential integrity, health probes, source hygiene, request races | Anything about the process: argv, signals, exit codes, real spawned children |
| `cargo test -- --ignored` | **2** | The two tests needing a host tool — `sudo` and `setsid(1)`. They **assert** their precondition rather than skipping, so a host without the tool fails loudly instead of reporting a pass over nothing | Nothing else; it is a deliberate opt-in set |
| `scripts/test_e2e.sh` | **958 checks**, 47 sections | The live daemon over HTTP: hook lifecycle, parameter contracts, real script execution, the RBAC matrix, HMAC signing, timeouts and `killpg`, startup refusals, the §42–§46 robustness set, and the §47 error-envelope contract | Anything needing a second host, a real proxy, or a non-SQLite backend |
| `scripts/verify_convergence.sh` | 19 checks (18 converged, 1 accepted divergence) | Behavioural drift against `example/simply_ip_vault` — three byte-identical functions, shared constants, and `RBAC_MODEL.md` identity | Anything the peer does not also implement |

### E2E robustness sections (§42–§46)

Added because the suite proved the API correct while proving nothing about the daemon under stress.
Each exists for a failure mode nothing else in the tree would notice:

| § | Covers | The failure it exists to catch |
| :--- | :--- | :--- |
| **42** | A hook wrapping a real system binary (`ls -la`) | `run_process` calls `env_clear()`, so **PATH is not inherited**. A hook calling `ls` by bare name works only because `/bin/sh` falls back to a compiled-in default — a property of the shell, not of this service, and one whose loss would break every coreutil-calling hook at once |
| **43** | 10 MiB on stdout **and** stderr | Unbounded buffering. Asserts the `MAX_OUTPUT_BYTES` cap is enforced on *both* streams (~1 MiB each) and that the truncation marker is present — "it did not crash" is also satisfied by a daemon that buffered 20 MiB and got lucky |
| **44** | 20 concurrent executions | `SQLITE_MAX_CONNECTIONS = 1` plus a database-wide write lock. Asserts zero 5xx and zero `database is locked`; 429 is a *correct* outcome (the master key's budget is 10), so the check is "success or deliberate throttling, nothing else" |
| **45** | SIGTERM with a 15 s hook in flight | Three separable halves of graceful shutdown: the listener closes **at once**, in-flight work **runs to completion** (a half-finished deployment script is worse than none), and the process exits **0** rather than 143. Also asserts no orphaned child and that the retention worker was stopped |
| **46** | Two kinds of client disconnect | Leaked tasks and parked workers. A half-open request with an unfulfilled `Content-Length`, plus an upload aborted mid-stream; then asserts the next requests are served *immediately* and that the truncated body created nothing |

### Request races (`tests/concurrency_and_contracts.rs`)

Added after auditing the three sibling services under `example/`, which all test concurrency and this
one did not: before that file there was not a single `tokio::spawn` or `JoinSet` anywhere in
`tests/`. A check-then-act bug is invisible to a sequential test by construction — it needs two
callers interleaving between the check and the act.

| Test | Adapted from | Catches |
| :--- | :--- | :--- |
| `two_concurrent_identical_signed_requests_only_one_succeeds` | `simply_ip_exporter` | A replay ledger that reads then inserts, making "single use" mean "usually single use" |
| `two_concurrent_deletes_of_the_same_hook_do_not_both_report_success` | `simply_ip_exporter` | **Found a real defect** — two `204`s and two `HOOK_DELETE` audit rows for one deletion. Fixed by making the soft delete conditional on the row still being live, matching the hard-delete branch |
| `concurrent_writers_queue_cleanly_and_the_row_count_is_exact` | `simply_ip_vault` | A lost write, a double insert, or a queued writer giving up with `SQLITE_BUSY`. Two phases: disjoint names for throughput, one contested name for the uniqueness race |
| `malformed_input_is_refused_in_the_json_envelope_on_every_extractor` | `simply_ip_exporter` | A refusal a client cannot parse. Asserts status, `Content-Type: application/json`, and a non-empty `error` string across all five extractors |

**Note on the production pool.** That file does *not* test `db::connect`, WAL or `busy_timeout`,
despite those being invisible to every `sqlite::memory:` fixture — because `src/db.rs` already
carries eight file-backed tests in its own `#[cfg(test)]` module. Look there, not in `tests/`, before
concluding the pool is uncovered.

Two mechanics in those sections are load-bearing and easy to undo by accident:

- **Never `wait` without arguments.** The API server is itself a background job, so a bare `wait`
  blocks until the *server* exits — which it does not mid-run. §44 collects its curl PIDs in an
  array and waits on each. Written the idiomatic way, the suite hangs with no output and no timeout.
- **Raw sockets go in a subshell.** A failed `exec` redirection in the main shell of a
  non-interactive bash terminates the script. §46 opens `/dev/tcp` inside `( … )`, as `port_in_use`
  already does; the descriptor dying with the subshell is also exactly the connection cut being
  tested.
- **A skipped section is counted, not merely warned about.** `skip()` increments `SKIP_COUNT`, and
  the summary reports it and downgrades the closing line. A run that skipped two sections must not
  read as identical to one that ran them — the same rule the two `#[ignore]`d Rust tests exist to
  honour.

## Where things are *not*

A quick index for the questions that send people to the wrong file:

| Looking for | It is in | Not in |
| :--- | :--- | :--- |
| "May this caller do X?" | `api/guards.rs` | the handler modules |
| "How much of another *key* may I see?" | `api/keys.rs` (module-private) | `api/guards.rs` — moved, see `AGENT.MD` §0 |
| "How much of a *hook* may I see?" | `api/guards.rs` | `api/hooks.rs` — three domains consult it |
| "Who is this caller?" | `middleware.rs` | `api/guards.rs` |
| "Which key is the Master?" | `master.rs` | `api/guards.rs`, `state.rs` |
| "What may the Master do?" | `api/guards.rs` | `master.rs` |
| HMAC request signing | `crypto.rs` | `middleware.rs` (that decides *when* one is required) |
| The signature error message | `middleware.rs` | `crypto.rs` (that returns `SignatureRejection`) |
| Writing an audit row | `api/support.rs` | `api/audit.rs` (that only *reads* them) |
| Reading audit rows | `api/audit.rs` | `api/system.rs` (that is settings + counters) |
| Client IP from headers | `config.rs` | `middleware.rs` |
| Running a script | `executor.rs` | `api/executions.rs` (that is the HTTP layer) |
| Settings endpoint | `api/system.rs` | `config.rs` (that parses the environment) |
| Health/readiness probes | `api/health.rs` | `api/system.rs` (those are authenticated) |
| Opening the pool | `db.rs::connect` | `main.rs` (it calls through) |
| Raw SQL | `db.rs`, `m20230106`, `api/health.rs` **only** | anywhere else — a test enforces this |
