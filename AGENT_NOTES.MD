# AGENT NOTES

> Living worklog for `simply_hook_executor`. This entry replaces the previous notes, which
> described the `simply_ip_vault` audit sweep that preceded this refactor.

---

## 2026-07-29 — Adaptation from `simply_ip_vault` to `simply_hook_executor`

The `simply_ip_vault` codebase was adapted into a hook execution engine. The transport,
persistence, RBAC, and SPA architecture were kept; the entire domain layer was replaced.

### What was replaced

| Removed | Added |
| :--- | :--- |
| `ip_records`, `ip_groups`, `ip_record_group_memberships`, `webhook_configs`, `api_key_group_permissions` | `hooks`, `hook_parameters`, `api_key_hook_permissions`, `executions` |
| `src/webhooks.rs` (outbound dispatcher) | `src/executor.rs` (execution engine), `src/retention.rs` (log retention worker), `src/config.rs` (runtime config) |
| `POST /api/ban`, `/api/white`, `GET`/`DELETE /api/ips`, group + webhook CRUD | hook CRUD, parameter CRUD, `/execute`, `/test`, `/webhook/{id}`, execution history, `/api/settings` |
| `reqwest` dependency (no outbound HTTP any more) | `libc` dependency (see "process-group kill" below) |

`api_keys.can_manage_webhooks` / `can_create_groups` became `can_manage_hooks`; `max_concurrent_jobs`
was added. `audit_logs.target_address`/`group_names` collapsed into `target_resource`, and
`api_key_name`/`api_key_prefix`/`client_ip` became `NOT NULL` per `SCHEMA.MD`.

### Decisions & interpretations

Each of these resolves a point where `AGENT.MD`/`SCHEMA.MD` left room for more than one reading.

1. **`can_manage_hooks` grants *creation*, not blanket control.** `AGENT.MD` §2 states plainly
   that `can_execute`/`can_manage` "require valid key mapping unless `is_master`", while
   `SCHEMA.MD` describes `can_manage_hooks` as the right to "create and manage hooks". Those
   conflict for an existing hook owned by someone else, and the least-privilege rule wins: the
   global scope authorizes `POST /api/hooks`, and managing an existing hook additionally requires
   a `can_manage` mapping. Auto-provisioning (below) means a key never loses control of what it
   created. See `require_manage` in `src/api.rs`.

2. **Auto-provisioning is unconditional**, including for master keys. `AGENT.MD` says the backend
   MUST create the mapping when "an API Key" creates a hook, with no master exception. The row is
   redundant for a master key (it bypasses RBAC anyway) but harmless, and a literal reading avoids
   a surprising special case.

3. **HMAC signatures are a body-integrity layer, not a standalone auth mode.** Only a SHA-256 hash
   of each key is stored, so the daemon cannot compute an HMAC for a caller it hasn't been given
   the secret by. `X-Signature-256` is therefore verified using the plaintext key presented in
   `X-API-Key` on the same request: it proves the body wasn't altered in transit, on top of the
   key authentication that already happened. `SCHEMA.MD` has no per-hook secret column, which
   confirms `AGENT.MD`'s "or a hook-specific secret" has no schema backing to implement against.
   The body is only buffered when a signature is actually present (1 MiB cap).

4. **Positional argument order is declaration order.** `AGENT.MD` requires positional CLI
   arguments, but `hook_parameters` has no `position` column and the schema is authoritative, so
   the order is `created_at, param_key` — stable, reproducible, and surfaced verbatim by the
   dry-run endpoint so it never has to be guessed. Every resolved parameter is passed *both* as
   `HOOK_PARAM_<UPPERCASED_KEY>` and positionally.

5. **A hook's parameter contract is also its allowlist.** Unknown parameters are rejected with
   `400` rather than ignored: silently dropping an unrecognized key would let a caller believe
   they had influenced an execution that in fact ignored them. `param_key` is constrained to
   `[A-Za-z_][A-Za-z0-9_]*` at declaration time so no unusable environment variable name can ever
   be stored. JSON `null` means "not supplied" (the declared default still applies); arrays and
   objects are rejected, since an env var / argv entry is a flat string.

6. **Process-group kill needs `libc`.** `tokio::process::Child::kill()` signals only the direct
   child, which would leave a script's backgrounded grandchildren running past the timeout —
   contradicting `AGENT.MD`'s "kill the process tree". Children are spawned with
   `process_group(0)` and the timeout path calls `libc::killpg`. `libc` was already in the tree
   transitively via tokio, so this adds no new compilation. Verified by a test that backgrounds a
   grandchild and asserts it never completes.

7. **Signalled exits are recorded as `128 + signum`**, so a `SIGKILL`ed hook records `137` — the
   value `SCHEMA.MD` uses as its own example, and what a shell would report.

8. **Output is capped, drained, and flagged.** stdout/stderr are captured up to `MAX_OUTPUT_BYTES`
   (default 1 MiB) each, but reading *continues* past the cap and discards the excess: stopping
   early would block a chatty hook on a full pipe and misreport it as a timeout. Truncation
   appends an explicit marker so a partial log is never mistaken for a complete one. Capture goes
   through shared buffers rather than task return values so partial output survives a timeout.

9. **A failing script is `200 OK`.** The HTTP status reports whether the *request* was carried
   out; the script's own outcome is the `status`/`exit_code` in the body. A missing or
   non-executable `script_path`, by contrast, is a `400` — nothing ran, so no history row is
   written, and `AGENT.MD`'s test matrix calls for "invalid scripts are rejected".

10. **`/webhook/{identifier}` exists** because `AGENT.MD` §1 requires the auth middleware to cover
    `/webhook/*`. It is a thin alias of `/execute` that resolves the hook by UUID *or* name and
    accepts a flat JSON body, for third-party senders that can only post their own document to a
    fixed URL. Every hook route accepts a name in place of a UUID for the same reason the old
    codebase accepted flexible group identifiers — it avoids an Axum `422` before any handler runs.

11. **`older_than_days=0` is a no-op**, matching `LOG_RETENTION_DAYS=0` ("keep forever") rather
    than meaning "delete everything". The two settings drive the same sweep, and one spelling
    meaning opposite things depending on where it was typed would be a trap.

12. **Concurrency budgets rebuild on change.** Each key's semaphore is keyed by its permit count;
    editing `max_concurrent_jobs` replaces the semaphore, so the new limit applies from that point
    on while already-running jobs finish against the old one. Permits are taken with
    `try_acquire` — over-budget must fail fast with `429`, never queue silently.

### Frontend

The SPA was rebuilt around four tabs (Executions/Dashboard, Hooks Management, API Keys &
Permissions, System Settings), keeping the existing dark theme and the two reusable widgets that
earned their keep (`SearchableSelect`, `PagedCache`). New: stat tiles, a run panel that renders a
hook's parameter fields dynamically and offers both Dry Run and Execute, an execution detail modal
with scrollable stdout/stderr blocks, a hook parameter editor modal, and a settings tab carrying
the runtime configuration plus the audit log. Confirmations still go through the custom dark modal
(no `window.confirm`). Tab visibility is driven by `GET /api/auth/me`, and every action button that
the caller's rights don't cover is disabled rather than left to 403.

`ExecutionStatus` serializes as `SUCCESS`/`FAILED`/`TIMEOUT` (`#[serde(rename_all = "UPPERCASE")]`)
so the wire format matches the stored value and the `?status=` filter — the UI never translates.

### Validation

All green as of this entry:

- `cargo check` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 19 unit + 25 integration tests pass.
- `./scripts/test_e2e.sh` — 183/183 checks pass.

The integration suite covers `AGENT.MD`'s mandatory matrix end to end: 200/201 positives, 401
(missing/invalid key, bad signature), 403 (missing `can_execute`/`can_manage`, cross-tenant reads,
master-only endpoints), 400 (missing required / unknown / non-scalar parameters, malformed JSON,
bad script paths, invalid CIDRs and timeouts), 429 (concurrency budget, synchronized on a marker
file so it can't race), and timeout (`TIMEOUT` + exit `137` + grandchild reaped). Plus the
security properties themselves: shell-injection inertness, environment isolation, dry-run purity.

### Known gaps / possible follow-ups

- `hook_parameters` has no explicit ordering column, so re-ordering positional arguments means
  re-creating parameters. Adding a `position` column would need a `SCHEMA.MD` change first.
  (Appending is safe — see the ordering test below.)
- Executions are recorded only on completion, so there is no "running" state visible in the UI
  while a long hook is in flight; the request simply blocks until it finishes.

---

## 2026-07-29 (later) — Dead code cleanup, configurable binding, expanded coverage

### 1. Dead code & legacy asset cleanup

Audited `src/`, `static/`, `src/migration/`, and `Cargo.toml` for anything left behind by the
`simply_ip_vault` domain. A repo-wide grep for the old vocabulary (`ip_vault`, `banlist`,
`whitelist`, `ip_record`, `ip_group`, `webhook_config`, `firewall`) now returns **zero** hits
outside `target/`.

**CSS** — removed 76 lines of orphaned rules, verified by extracting every class token actually
referenced from `class="..."` attributes, `classList` calls, `querySelector` arguments and
template-literal class strings, then diffing against the stylesheet:
`.api-key-container`, `.main-content`, `.header-input`, `.btn-success`, `.btn-toggle.active`,
`.input-field.input-error`, `.combobox-option.highlighted`, `.message.success`, `.text-accent`,
`.text-danger`, `.gap-4`, `.flex-between`, `.items-center`, `.w-full`, plus the matching
`@media` overrides. The four classes the extractor still reports as "unreferenced"
(`.badge-timeout`, `.toast`, `.toast-success`, `.toast-error`) are composed at runtime
(`` `toast toast-${type}` ``, and a status→class map) and were confirmed live by hand.

`.pagination #page-indicator` targeted an id that no longer exists — the tables were renamed to
`#exec-page-indicator`/`#audit-page-indicator` — so it was silently styling nothing. Replaced with
`.pagination span`, which covers both and needs no edit when a third paginated table appears.

**JS** — removed `SearchableSelect.setValue()`, added speculatively and never wired up.

**HTML** — removed three `id` attributes nothing referenced (`#login-submit`, `#hooks-section`,
`#apikey-section`). The only ids now unreferenced by a literal string are `#tab-executions`,
`#tab-hooks`, `#tab-keys` and `#tab-settings`, which are resolved dynamically from
`data-tab` (`` `tab-${trg.dataset.tab}` ``).

**Rust** — `src/api.rs` mixed `entity::Entity::…` with the prelude aliases, which left
`ApiKeyHookPermission`, `HookParameter` and `AuditLog` as unused re-exports. Converted every call
site to the prelude aliases, so all six exports are live and the file reads consistently.

**`#[allow(dead_code)]` eliminated.** The one instance (`tests/common/mod.rs`) existed to absorb
warnings from helpers used by only some test files. Removing it is safe because the suite lives in
a single integration binary; `cargo clippy --all-targets -- -D warnings` confirms every helper has
a real caller, so an unused fixture is now a real finding instead of a silenced one.

**`Cargo.toml`** — every remaining dependency was confirmed used by grep. Removed the `axum`
dev-dependency, which existed only to enable the `macros` feature for `#[debug_handler]` that
nothing uses. The three SQL drivers on `sea-orm` are kept deliberately (AGENT.MD's SQL-agnostic /
PostgreSQL-ready requirement) and now say so in a comment, so a future audit doesn't strip them.

### 2. Configurable network binding

`BIND_HOST` (or `HOST`, default `0.0.0.0`) and `PORT` (default `3000`) now drive the listen
address via `config::resolve_bind_addr()`.

- **`BIND_HOST` beats `HOST`** when both are set. `HOST` is widely used and some environments set
  it to something unrelated (a hostname, a target triple); an operator who set the explicit name
  should not have it overridden by ambient configuration.
- **Hostnames are rejected, literal IPs only.** Resolving a name can yield several addresses with
  no principled way to choose, and binding the wrong interface is a security problem rather than a
  convenience one. `localhost` therefore falls back to the default *with a warning* instead of
  quietly binding something unintended.
- **Malformed values warn and fall back** rather than aborting startup, matching how the rest of
  `config.rs` treats bad overrides — a typo in a unit file should not take the service down.
- **`PORT=0` is passed through** so the OS can assign an ephemeral port; the bound address is read
  back from the listener (not from the requested address) and logged, so the real port is visible.

The parsing lives in a pure `parse_bind_addr(Option<&str>, Option<&str>)` with the env read in a
thin wrapper — unit tests then cover defaults, overrides, IPv6, trimming and every malformed case
without mutating process-global environment state (which is both racy under parallel tests and
`unsafe` in edition 2024).

`deploy/simply_hook_executor.service`, `Dockerfile`, `docker-compose.yml` and the README were
updated. The unit file documents `BIND_HOST=127.0.0.1` for the reverse-proxy case; the container
files note that `0.0.0.0` must stay inside a container and the *published* port is what to change.

**`scripts/test_e2e.sh`** no longer hard-codes 3000. It honors `$PORT` when set — and fails fast
if that exact port is busy, since silently moving would defeat the point of pinning it — otherwise
it scans 3000→3100 for the first free port. Port probing uses bash's own `/dev/tcp` inside a
subshell, so it needs no `ss`/`lsof`/`fuser` and leaks no descriptor. It also binds `127.0.0.1`
rather than every interface, so a test server is never briefly exposed to the network. A new check
asserts the startup log reports the requested address, making the feature itself covered. All
three paths were exercised: explicit port, auto-scan with 3000 occupied, and fail-fast on a busy
explicit port.

### 3. Extended test coverage

Unit tests 19 → 23, integration tests 25 → 32, E2E checks 183 → 199.

**Retention worker** (previously only the pure purge function was covered):
- `retention_worker_purges_on_its_own_schedule_and_shuts_down_cleanly` — drives the real worker
  through `spawn_retention_worker`, asserts it purges expired rows, that a row *inside* the window
  specifically survives (not merely "one row remains"), that a later sweep picks up newly-expired
  rows, and that dropping the shutdown sender makes it exit promptly.
- `retention_worker_is_disabled_when_retention_days_is_zero` — asserts the worker returns
  immediately *while the shutdown sender is still held*, which is what proves the early return
  rather than a coincidental shutdown, and that a decade-old record survives.
- The purge-function test now also pins the endpoint's `older_than_days=0` (no-op, matching the
  config flag) and negative-value (`400`) semantics.

**HMAC failure** — `hmac_signature_failures_are_rejected_without_executing_anything` presents a
*valid* API key with nine bad signatures (tampered body, body with trailing whitespace, a
signature made with a different valid key's secret, a signature over a different payload, missing
`sha256=` prefix, `sha1=` prefix, non-hex, empty and truncated digests). Each must be `401`, and
the test additionally asserts nothing was spawned (a canary file) and no execution row was
written — i.e. rejection happens before the engine — with a control case proving the hook was
runnable all along.

**Parameter contract edge cases:**
- `non_scalar_parameter_values_are_rejected` — six non-scalar shapes (array, empty array, nested
  object, empty object, array-of-objects, deeply nested) each `400` with the offending key named;
  six scalar flavours (string, int, negative, float, true, false) accepted and stringified.
- `json_null_is_treated_as_an_omitted_parameter` — `null` falls back to the declared default,
  an explicit `""` is distinguishable from `null` and *does* override the default, and `null` on a
  required undefaulted parameter is still a missing-parameter `400`.
- `positional_argument_order_is_deterministic_and_append_only` — parameters declared in an order
  that matches neither alphabetical nor reverse-alphabetical sorting, so a pass can only mean
  declaration order is used; five repeated executions and dry runs must produce byte-identical
  argument vectors (an unstable `ORDER BY` would surface as an intermittent diff); and a parameter
  declared later appends rather than reshuffling, so adding one cannot silently change what an
  existing caller's script receives as `$1..$n`.

**Peak-load throttling** — `peak_load_burst_is_rejected_immediately_rather_than_queued` saturates
a 2-job budget (each job announcing itself via its own marker file, so the burst can't race the
setup), then fires 12 concurrent requests. All 12 must be `429`; the burst must complete in under
3s against occupying jobs that sleep 5s — which is what actually distinguishes *rejected* from
*eventually served*; no burst marker may exist and no history row may be written; and the full
budget must be usable again once the occupying jobs finish.

The E2E suite gained matching black-box checks for null handling, empty-string-vs-null, scalar
coercion, nested-object rejection, and argument-order stability/append-only behavior.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 23 unit + 32 integration tests pass.
- `./scripts/test_e2e.sh` — 199/199 checks pass (also verified on `PORT=3456` and with 3000
  occupied).
