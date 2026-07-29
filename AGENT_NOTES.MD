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

- The listen address is still hard-coded to `0.0.0.0:3000` (inherited; `scripts/test_e2e.sh`
  depends on it and refuses to run if the port is busy).
- `hook_parameters` has no explicit ordering column, so re-ordering positional arguments means
  re-creating parameters. Adding a `position` column would need a `SCHEMA.MD` change first.
- Executions are recorded only on completion, so there is no "running" state visible in the UI
  while a long hook is in flight; the request simply blocks until it finishes.
