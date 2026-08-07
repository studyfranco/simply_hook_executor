# Simply Hook Executor - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_hook_executor`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, process execution rules, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.
4. **`example/`**: You can find the code of other similar/linked project inside.

---

## 🎯 Project Overview

`simply_hook_executor` is an enterprise-grade, secure hook execution daemon written in Rust. It acts as an automation bridge listening for webhooks or HTTP API requests (e.g. from `simply_ip_vault` or deployment tools), authenticates callers using API keys or HMAC-SHA256 signatures, validates input parameters, and safely executes local system scripts (Bash, Python, binaries) with strict environment isolation, per-key concurrency throttling, execution timeouts, and comprehensive logging. It features an integrated Vanilla JS dashboard governed by a granular multi-tenant Role-Based Access Control (RBAC) system.

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **ORM (SQL-Agnostic):** SeaORM (2.0+). Defaults to **SQLite** for zero-config local development/testing, but MUST remain strictly **SQL-agnostic** (PostgreSQL-ready). **Never write vendor-specific raw SQL queries.**
- **Frontend:** STRICTLY Vanilla JS, HTML5, and CSS3. **NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only. Dark theme matching `simply_ip_vault`.
- **Quality & Safety:**
  - Zero compiler warnings, zero `clippy` warnings.
  - **Zero `.unwrap()` or `.expect()`** in production code or HTTP handlers. Use structured `AppError` and Axum's `IntoResponse`.
  - **Mandatory `rustdoc`**: All public modules, structs, enums, functions, and Axum handlers MUST be documented using `///` (or `//!` for crates/modules). Enforce `#![warn(missing_docs)]` in `lib.rs`.

---

## 🏛️ Core Architectural Rules

### 1. Security & Network (Zero-Trust)

- **Middleware Protection:** All `/api/*` and `/webhook/*` routes pass through custom authentication middleware (`src/middleware.rs`). There are no unauthenticated API routes; only the static SPA is public.
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
- **Exactly one master exists,** and the guarantee is a **database constraint**, not application logic (`RBAC_MODEL.md` §5). `api_keys` carries a `master_marker` column *generated by the engine* from `is_master`, under a plain unique index — see `SCHEMA.MD` and `m20230106_000001_master_key_uniqueness`. The marker is derived rather than assigned precisely so no writer can bypass it, and a plain unique index on a nullable column is used rather than a partial index because MySQL has no `WHERE` clause on `CREATE INDEX` and the MySQL driver is enabled. A database that somehow already holds two masters fails the migration and refuses to boot: which master is legitimate is an operator's judgement, not a schema change's.
- **Hook Rights:** Managed via junction table `ApiKeyHookPermission` linking keys to `Hook` with explicit flags (`can_execute`, `can_manage`).
- **Least Privilege:** `can_execute` or `can_manage` require valid key mapping unless `is_master`.
- **Auto-Provisioning:** When an API Key creates a new `Hook`, the backend MUST automatically generate full execute/manage permissions for that key on the new hook, **and record it as the hook's `owner_key_id`**. The two are deliberately separate facts: the permission row is operational and delegable to others, the ownership column is lifecycle authority and moves only when master says so.
- **Lineage confers nothing.** `api_keys.parent_key_id` records who created a key, for cascading deletion and visibility scoping only. `RBAC_MODEL.md` R3: "A daughter of the Master key is an ordinary daughter key with no elevated standing." No authorization check may read this column — if one ever needs to, the rule has been broken.

#### Effective permission matrix

`can_read` is **derived, not stored** — the schema carries only `can_execute` and `can_manage`. Read access is granted when a key is `is_master` **or** holds *either* flag on the hook; a key with no mapping at all sees nothing.

| Operation | Required |
| :--- | :--- |
| `POST /api/hooks/{id}/execute`, `POST /webhook/{id}` | `can_execute` |
| `POST /api/hooks/{id}/test` (dry run) | `can_execute` — the preview reveals the fully-resolved command line and child environment, which is execution-shaped knowledge even though nothing is spawned |
| `GET /api/hooks`, `GET /api/hooks/{id}`, `GET .../parameters`, `GET /api/executions*` | derived read: `can_execute` **or** `can_manage` |
| `PUT`/`PATCH`/`DELETE /api/hooks/{id}`, parameter CRUD, `DELETE /api/executions/{id}` | `can_manage` |
| `POST /api/hooks` (create) | global `can_manage_hooks` (creation auto-provisions full rights on the new hook) |
| `POST`/`GET`/`PUT`/`DELETE /api/keys*` | global `can_manage_keys` |
| `GET /api/audit-logs`, `GET /api/settings`, `DELETE /api/executions` (purge) | `is_master` |
| Assigning a non-empty `run_as_user` | `is_master` — checked **immediately after** the endpoint's authorization check and **before any field validation**, so an escalation attempt always surfaces as `403` and can never be masked by a `400` about some other field in the same payload |
| **Granting** `can_manage_keys` or `can_manage_hooks` (create *or* update) | `is_master`. `can_manage_keys` is the right to administer credentials, not to invent authority outranking your own — without this the scope is self-amplifying and therefore identical to `is_master`. **Revoking** a scope stays available to any key manager: removing authority is not an escalation |
| **Setting `is_master`** (create *or* update) | **Nobody, including the master.** Per `RBAC_MODEL.md` §5 the field is not on `CreateApiKeyPayload` or `UpdateApiKeyPayload` at all, and both are `#[serde(deny_unknown_fields)]`, so an `is_master` in either body is a `422` naming the field rather than a silently-dropped no-op. Silence was the wrong failure here: it would return `200` and an ordinary key, leaving the caller believing it had minted a master and leaving nothing in the log for an operator to notice. The only writer is `bootstrap_master_key`, against an empty table |
| `PUT`/`DELETE /api/keys/{id}`, `POST /api/keys/{id}/rotate` where the **target** is `is_master` | **Nobody, including the master itself**, except `bound_ips` (next row). Rotation returns the new plaintext secret, so "only a master may administer a master" collapsed into "the master may rotate itself" the moment exactly one master could exist — one request against a stolen master credential both harvests a fresh secret and locks the operator out. Deletion is barred *regardless of row count*, so the rule does not quietly depend on the uniqueness index for its safety. Regeneration is deliberately out of band: delete the row directly in the database and restart |
| `PUT /api/keys/{id}` setting **only `bound_ips`**, where `{id}` is the master's own id | `is_master`, and the caller must *be* that key. The one editable field, because it is the one an operator has a recurring need to change from inside the running system (the network the master is reachable from moves) and the one that can only ever *reduce* a stolen credential's usefulness. `name`, `max_concurrent_jobs`, `hmac_mode`, and both global scopes are refused individually — `hmac_mode` most sharply, since it could downgrade the master to `BODY_ONLY`, which carries no replay protection at all |
| `POST /api/keys/{id}/permissions` where `{id}` is the **caller's own key**, and the write *grants* a verb | `is_master` — granting rights to yourself is escalation, not administration. A write that only *reduces* the caller's own row is a revocation under R6 and is permitted; see the revoke row below |
| `POST`/`DELETE /api/keys/{id}/permissions*` — administering **any** hook's grants | `is_master`, **or** `can_manage_keys` **AND** a `can_manage = true` row on that specific hook. This is `RBAC_MODEL.md` **R2**: manage is a conjunction, and neither half alone is sufficient. `can_manage_keys` is *never* a global bypass of per-resource RBAC — a holder that were exempt could mint a key, grant it any verb on any hook, and authenticate as it, which is `is_master` in two requests. Conversely a `can_manage` row without the global flag belongs to a Daughter key, which the tier matrix says never manages resources: the row is operational authority over the hook, not the right to decide who else holds it. **Both failures return one message**, so a caller cannot learn which half to go acquire. A caller failing *both* halves is refused before the target key is fetched, so the endpoint cannot be used to enumerate key UUIDs by reading `404` instead of `403` |
| **Revoking** — `DELETE /api/keys/{id}/permissions/{hook}`, or a `POST` that turns no verb on | The R2 conjunction above, and **nothing more** (`RBAC_MODEL.md` **R6**). No per-verb proportionality, and **self-revocation is allowed**, on either route. Removing a permission can never raise anyone's authority: turning a flag off is a request for `false`, and `false` exceeds nothing, so the outcome is always a strict de-escalation of the target regardless of who asks or what they hold. Granting needs a proof of authority because it can manufacture a capability that was withheld; revoking has nothing to prove. **Which route it arrived on is irrelevant** — R6 classifies a reduction through the general update endpoint as a revocation, because `DELETE` and a `POST` writing every verb to `false` reach the same end state, and a rule enforced on only one spelling is routed around rather than obeyed. Classification is by *effect*: a write is a grant when it turns on a verb the target did not already hold, and a reduction otherwise. A mixed write — one verb up, one down — is a grant; the reduction does not pay for the escalation. The remaining exposure is integrity, not escalation (disabling another tenant's automation), which the R2 gate addresses |
| `POST /api/keys/{id}/permissions` granting a **verb the caller does not itself hold** on that hook | `is_master` only. This is `RBAC_MODEL.md` **R1**, applied on top of R2 — **R7** requires both "simultaneously and without exception", so there is no caller below master for whom either is skipped. Managing a hook is authority to administer its grants, not licence to invent a capability an operator withheld: a manager lacking `can_execute` could otherwise route it to a key it already controls and authenticate as that key, obtaining in two requests exactly what was withheld. `can_execute` and `can_manage` are separate columns precisely so that split is expressible, so each verb is checked **independently** against the caller's own row. **Revoking** is always allowed — turning a flag off can never exceed anything — and re-asserting a verb you already hold is a no-op, so an idempotent re-submission still succeeds. <br><br>*Previously `can_manage_keys` was exempt from this rule and from R2 both. That exemption is gone: it made the scope transitively able to execute any non-privileged hook, and "deputy master" is not a tier this model has.* |
| `DELETE /api/hooks/{id}`, and `PUT`/`PATCH` changing a hook's **`name`** | `is_master`, **or** being the hook's `owner_key_id` (`RBAC_MODEL.md` **§3**). Holding `can_manage` — or any operational verb — confers **no** lifecycle authority: "a parent that merely uses a resource must not be able to delete it." `can_manage` remains the right to *operate* the hook (description, `script_path`, timeout, parameter contract); what it no longer carries is the right to make the hook cease to exist. **Renaming is grouped with deletion**, not with the other edits, because this service resolves hooks by name on `/webhook/{identifier}` and in grant payloads — a rename silently breaks every caller pointed at the old one, so it is a lifecycle act wearing an edit's clothes. A hook whose `owner_key_id` is `NULL` (predating ownership) is **master-only**, deliberately the conservative direction: reading "no owner" as "anyone who manages it" would make the un-migrated state more permissive than the migrated one |
| `PUT /api/hooks/{id}` setting **`owner_key_id`** | `is_master` only (§3: "Master may reassign `owner_key_id` on any resource ... at any time"). Not delegable, not even to the current owner — letting an owner hand ownership to an arbitrary key would let it walk away from a resource rather than resolve it, which is the step §6's pre-flight inventory exists to make impossible. The target key must exist: a dangling owner would put the hook permanently beyond §3's non-master path |
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

### 3b. SQLite Concurrency

When the backend is SQLite (the zero-config default), the daemon applies two pragmas at startup —
`journal_mode=WAL` and `busy_timeout=5000` — before migrations run. This is the one place a
backend-specific statement is permitted, and it is a *connection pragma*, not a query: the SQL-agnostic
rule in the Tech Stack section still holds for everything the ORM issues.

- **WAL** lets readers proceed against the last committed snapshot while a writer appends. Without it
  the default rollback journal takes a database-wide exclusive lock for every write, so one hook
  recording its `executions` row blocks every concurrent reader — the opposite of what a daemon whose
  job is parallel execution needs. It is **persistent** (stored in the file header), so setting it
  once covers the whole pool and every later run.
- **`busy_timeout`** covers what WAL does not: WAL still allows only one writer, so simultaneous
  executions can still collide, and without a timeout the loser fails instantly with `SQLITE_BUSY` as
  a spurious `500`. It is **per-connection**; the pool-wide guarantee comes from SQLx's own five-second
  default, which this statement matches and makes explicit.
- Failure to apply either is logged, never fatal. An in-memory database (`sqlite::memory:`, used
  throughout the test suite) legitimately cannot use WAL.

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

### 4. History, Output Capture & Log Retention

- Every execution produces an `Execution` record storing status (`SUCCESS`, `FAILED`, `TIMEOUT`), exit code, full `stdout`, full `stderr`, duration in milliseconds, resolved parameters JSON, and timestamp.
- **Retention Worker:** An asynchronous background task runs two sweeps on the same interval:
  1. `Execution` entries older than `LOG_RETENTION_DAYS` (default: 30 days).
  2. Soft-deleted `Hook` rows trashed more than **92 days** ago, overridable via `DELETED_HOOK_RETENTION_DAYS` (`0` keeps the trash forever), also exposed on demand at `POST /api/system/purge-hooks`. The purge states all three guards explicitly — `is_deleted = true AND deleted_at IS NOT NULL AND deleted_at < threshold` — even though SQL's three-valued logic already makes either of the first two sufficient. This is the one query in the system that destroys audit history, and its safety must not depend on an invariant held elsewhere in the code or on a reader recalling how `NULL` compares.
- The two windows are **separately** governed, and the worker keeps running when either is disabled. `LOG_RETENTION_DAYS=0` means "keep history forever", not "stop maintaining the trash" — an operator shortening log retention to reclaim disk must not silently shrink the undo window for deleted automation as a side effect.
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
- Global fetch wrapper injects and signs the three authentication headers, and intercepts `401/403` responses to return to the login screen.
- Custom dark confirmation modals for deletions (NO native `window.confirm()`).
- High-contrast action buttons and styled custom checkboxes.

### 7. Audit Logging

- Every mutating configuration change (Key CRUD, Hook CRUD, Permission updates) writes an `AuditLog` entry storing `api_key_id`, `api_key_name`, `api_key_prefix`, `client_ip`, `action`, `target_resource`, `details`, and timestamp.

### 8. Database Bootstrapping & Systemd Integration

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG`.
- Migrations run automatically on startup.
- **Master Key Auto-Gen:** If `api_keys` contains no master keys at boot, generate a default Master Key and output it once clearly to `stdout`. This is now the **only** writer of `is_master = true` anywhere in the codebase, and therefore also the only way to regenerate a master: delete the row directly in the database and restart. The banner is the sole source of that key's signing secret, which is why `scripts/test_e2e.sh` scrapes it rather than minting a second master for signing.
- Include a production-ready `simply_hook_executor.service` file for systemd deployment under a dedicated non-root user (`hookrunner`).

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

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*