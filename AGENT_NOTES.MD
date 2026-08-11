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
   created. See `guard_manage` in `src/api.rs`.

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

---

## 2026-07-29 (later still) — Permission diagnostics & path containment

### Classified spawn/permission errors

`std::io::Error` from the pre-flight check and from `execve` is now classified into a
`ScriptRejection` (`NotFound`, `PermissionDenied`, `NotARegularFile`, `NotExecutable`,
`OutsideAllowedRoots`, `MalformedPath`, `Unusable`) carried by a `ScriptError` alongside a single
operator-facing line in the shape:

```
[ERROR] Cannot execute '<path>': <precise cause>. <what to do about it>
```

Two details worth keeping:

- **`EACCES` names the directory at fault.** Stat'ing a file only needs *search* permission on its
  parents, so an unsearchable directory stats perfectly well — what fails is stat'ing something
  *inside* it. `first_unsearchable_directory` therefore walks the chain root-downward, finds the
  first path that reports `EACCES`, and reports **its parent**. The first version of this walked
  for the first ancestor that failed to stat, which found nothing at all in exactly the scenario it
  existed for; the E2E check for "the diagnostic pinpoints the blocking directory" is what caught it.
- **The mode is reported** (`no execute bit set (mode 0600)`), so an operator can tell 0600 from
  0644 without another round-trip, and the running identity is included (`'hookrunner' (uid=999
  gid=999)`) so they know who to grant it to. The name comes from `USER`/`LOGNAME`, which systemd
  sets from the unit's `User=`; the numeric ids come from `geteuid`/`getegid` and are always
  available.

The same text goes to three places: the HTTP error body, a `tracing` event tagged with
`rejection=<classification>` (WARN for a refusal, ERROR for a spawn failure), and — for failures
that only appear at `execve` time, such as a `noexec` mount or a permission change between
pre-flight and spawn — the execution record's `stderr`.

**Interpretation worth flagging.** The task asked for the diagnostic in "the execution record's
stderr / error message field", but AGENT.MD's test matrix requires an invalid script to be
*rejected* with `400`, and a rejected request never runs. Writing a `FAILED` history row for
something that never executed would corrupt the dashboard's success/failure counts. Resolution:
pre-flight refusals return `400` with the diagnostic in the response's `error` field (and in the
log), while genuinely spawn-time failures — the only ones where a process was actually attempted —
produce a `FAILED` record whose `stderr` holds the identical text.

**ANSI in logs.** Verifying the log assertion surfaced that `tracing_subscriber` was emitting
colour escapes unconditionally, so a redirected log or journald contained
`rejection<ESC>[0m<ESC>[2m=<ESC>[0mNotExecutable` — unreadable, and `grep 'rejection=…'` silently
matched nothing. Now gated on `IsTerminal`.

### Path containment (`ALLOWED_SCRIPT_ROOTS`)

New optional config: a comma-separated list of absolute directories a `script_path` must live
under. Defaults to empty (unrestricted) to stay zero-config and non-breaking, with a startup log
line explaining how to restrict it; the systemd unit and compose file ship with it set, since a
real deployment should.

Validation happens at two moments, and both are needed:

- **Lexical, at definition time** — absolute, no `..`, no interior NUL, and inside a root. The file
  need not exist yet (hooks are routinely declared before the script is deployed), so symlinks
  cannot be resolved here.
- **Physical, at execution time** — `canonicalize()` resolves symlinks and the containment check
  runs again. A symlink planted *inside* an allowed root pointing at `/bin/sh` passes the lexical
  check and is caught here, before anything is spawned. This is the bypass the second check exists
  for, and it has a dedicated test.

Containment uses component-wise `Path::starts_with`, not string prefixes, so `/opt/hooks` never
admits `/opt/hooks-evil`. Relative entries in the variable are dropped with a warning: a boundary
that moves with the working directory is not a boundary.

### Test coverage

Unit 23 → 29, integration 32 → 38, E2E 199 → 236.

New unit tests: root confinement (including the `/opt/hooks-evil` prefix trap and `.` segments),
NUL rejection, an expanded traversal payload table, `classify_io_error` for each errno (asserting
ENOENT is never labelled EACCES, and that the spawn-time variant additionally implicates `noexec`),
and the `ScriptError -> 400` mapping.

New integration tests:
- `non_executable_script_is_refused_with_an_actionable_diagnostic` — `chmod 0600`; asserts the
  prefix, path, cause, actual mode, remedy and uid all appear; that no execution row is written;
  that the dry run reports the *identical* string as `blocking_reason`; and that `chmod +x` makes
  the very same hook succeed, proving the refusal was purely about permissions.
- `missing_script_is_refused_with_an_enoent_diagnostic` — asserts ENOENT wording and explicitly
  that `EACCES` is *absent*, since the two send an operator to completely different places.
- `unsearchable_parent_directory_is_diagnosed_as_eacces` — skips itself when running as root
  (root bypasses search bits, so the scenario cannot be constructed there).
- `a_directory_as_script_path_is_refused`.
- `path_traversal_payloads_are_blocked_at_definition_time` — seven payloads, rejected on **create
  and update**, with a final assertion that the hook still points where it did before.
- `script_paths_are_confined_to_allowed_roots` and
  `a_symlink_escaping_the_allowed_roots_is_blocked_at_execution` — the latter also asserts that a
  symlink staying *inside* the root still works, i.e. this is containment, not a symlink ban.

`invalid_script_paths_are_rejected` was **removed**: every one of its assertions now has a
stronger dedicated home above, and it was the only test still asserting the pre-diagnostic wording.

E2E gained §21 (permission diagnostics and containment), and the suite now boots with
`ALLOWED_SCRIPT_ROOTS` pinned to its throwaway hook directory — so every hook it creates exercises
the containment happy path for free, and the outside-the-root and symlink-escape cases can be
proven without a second server instance. §21 also greps the server log to confirm the refusal was
actually logged with its classification, which is what caught the ANSI bug.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 29 unit + 38 integration tests pass.
- `./scripts/test_e2e.sh` — 236/236 checks pass.

---

## 2026-07-29 (final) — `run_as_user`: privileged execution via sudo

### Schema

`hooks.run_as_user` (nullable string, default `NULL`) added via a **new** migration
(`m20230102_000001_add_run_as_user`) rather than by editing the initial one, so databases created
by an earlier build are upgraded in place instead of silently diverging from the entity. `SCHEMA.MD`
was updated in the same change — the schema document is a mandatory reference, so letting the code
carry a column it does not describe would break the next reader.

`NULL` and empty are treated identically ("run as the daemon user"), normalized to `NULL` on write
so an empty text field from the UI can never be stored as a username of `""`.

### Command construction

```
/usr/bin/sudo -n -u <run_as_user> -- <script_path> <param1> <param2> ...
```

- **`-n`** — non-interactive. Without it, a missing `NOPASSWD` rule would block on a password
  prompt that no one can answer, and the hook would sit there until its timeout `SIGKILL`ed it.
  With it, the refusal is immediate and lands in `stderr` as a normal `FAILED` execution.
- **`--`** — mandatory, per the spec, and load-bearing: it terminates sudo's option parsing so a
  script path or parameter value beginning with `-` is data, not a sudo flag. A test asserts that
  a parameter valued `--login` lands *after* the separator.
- **`/usr/bin/sudo` is hard-coded**, not resolved through `PATH`. `PATH` is an operator-configurable
  passthrough variable, and an elevation path that follows it would be a privilege-escalation
  vector rather than a convenience.

**`run_as_user` validation is the primary guard.** The value lands in argv immediately after `-u`,
so it is validated against the POSIX-portable username shape (`[A-Za-z_][A-Za-z0-9_-]*`, plus a
trailing `$` for Samba machine accounts, capped at 32 chars). This makes an option-shaped value
such as `-i` or `--login` *unrepresentable* rather than relying on sudo's own parsing to be
defensive about it. Enforced on create and on update, and re-checked in the executor.

### Environment behaviour — the honest caveat

`env_clear()` plus explicit `HOOK_PARAM_*` injection is applied to the **sudo** process exactly as
it is to a direct spawn, so the code path is genuinely identical. But modern sudo defaults to
`env_reset`, which strips those variables before `execve`ing the target. That is sudo's behaviour,
not something this daemon can override from the calling side without either
`--preserve-env=<list>` (which *hard-fails* when sudoers lacks the `SETENV` tag, turning a degraded
case into a broken one) or interposing `/usr/bin/env` (which requires sudoers to permit `env`,
effectively "allow anything").

The spec pins the argument vector to `-n -u <user> -- <script>`, so neither was added. Instead:
positional parameters — which always survive — are the reliable channel under sudo, and the
sudoers snippet for `env_keep += "HOOK_PARAM_*"` is documented in the README and the unit file for
operators who want the variables too. Since every parameter is passed **both** ways, a privileged
hook written against `$1..$n` works with no sudoers changes beyond the `NOPASSWD` rule itself.

### Pre-flight interaction

A privileged hook is routinely a root-owned `0700` script the daemon user is *not* meant to be able
to run directly — that is what sudo is for. The existing executable check already asked "does this
file have an execute bit for **someone**" rather than "can *we* execute it", so it needed no
change; the reasoning is now written down next to it, since it is subtle and load-bearing.
Stat'ing and canonicalizing such a file only needs search permission on its parents, which the
daemon does have, so containment checks still work unchanged.

Added `ensure_sudo_available`: without it a missing `sudo` surfaced as a bare `ENOENT` naming
`/usr/bin/sudo`, which is accurate but baffling to an operator staring at their own script path.
`ensure_runnable` now validates elevation **before** touching the filesystem, so a malformed
account name is never reported as a confusing path problem.

### Audit & observability

`run_as_user` is written into `HOOK_CREATE`/`HOOK_UPDATE` audit details ("runs as 'root' via sudo"
/ "runs as the daemon user") and attached to every execution log line. "Which hooks run as another
account, and who made them that way" is answerable from the audit trail alone.

### UI

Create form and edit modal gained a "Run as User (sudo)" field; the edit modal always submits it,
so clearing the box is an explicit "drop elevation" (the API distinguishes a present-but-empty
value from an absent one). The hooks table gained a "Runs As" column rendering a deliberately loud
red `⬆ <user>` tag — privileged hooks are the highest-consequence rows in the UI and must not be
missable — and the dry-run panel repeats it alongside the previewed command.

### Test coverage

Unit 29 → 35, integration 38 → 42, E2E 236 → 267.

- Unit: the exact argument vector for both modes, blank/whitespace `run_as_user` treated as
  unprivileged, whitespace trimming, an option-shaped *parameter* forced after `--`, and a table of
  13 hostile usernames.
- Integration: dry-run preview of the full sudo vector (with the unprivileged form asserted
  side-by-side), CRUD round-trip plus audit assertions, option-injection rejection on both create
  and update, and a real end-to-end sudo execution that asserts *both* legitimate outcomes —
  permitted (stdout captured) or refused (non-zero exit captured in `stderr`, no hang thanks to
  `-n`) — since a test must not assume anything about the host's sudoers.
- E2E §22 mirrors all of it black-box, including that `--` immediately precedes the script path and
  that parameters sit after it.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 35 unit + 43 integration tests pass (including a migration upgrade-path test that
  applies the initial schema alone, then the new migration, exercising ALTER TABLE rather than a
  fresh CREATE).
- `./scripts/test_e2e.sh` — 267/267 checks pass.

### Follow-up worth considering

Creating a privileged hook currently needs only `can_manage_hooks`, the same scope as any other
hook. The OS remains the real gate (sudoers decides what is actually permitted), but a dedicated
`can_elevate` scope — or restricting `run_as_user` to master keys — would be a defensible tightening.
It is not in `SCHEMA.MD`, so it was not invented here.

*(Resolved in the next entry: `run_as_user` is now master-only.)*

---

## 2026-07-29 (later) — Signing secrets, the `run_as_user` master guard, and Test/Launch

### Two divergences from `SCHEMA.MD`, flagged rather than papered over

1. **`can_read` does not exist.** The task described a three-flag per-hook model
   (`can_execute` / `can_read` / `can_manage`), but `SCHEMA.MD`'s `api_key_hook_permissions` table
   defines only `can_execute` and `can_manage`. Rather than invent a column the schema document
   does not sanction, read access is derived: **any** mapping (execute or manage) grants visibility
   of the hook, its parameters, and its execution history — see `guard_visibility`. That yields
   the intended behaviour (an execute-only key can read what it runs; a key with no mapping sees
   nothing) with the columns that actually exist. Adding a real `can_read` flag would need a
   `SCHEMA.MD` change first, and would only matter for a "may read but may neither run nor edit"
   role that nothing currently asks for.
2. **`key_id` / `signing_secret` were not in `api_keys`.** These were added — schema, migration,
   entity — and `SCHEMA.MD` was updated in the same change, as with `run_as_user`.

### Signing secrets cannot be hashed

The task said to store the signing secret "hashed/encrypted". Only one of those is actually
possible: verifying an HMAC means *recomputing* it, which needs the original bytes. A hash would
make signature verification impossible — which is precisely why the previous implementation had to
key signatures on the presented API key and could never support a sender that transmits no bearer
credential.

So the secret is stored **encrypted at rest** (`src/crypto.rs`), XChaCha20-Poly1305 under
`SIGNING_SECRET_KEY`:

- **Encryption is optional but loud.** Unset ⇒ secrets stored verbatim, with a startup `WARN`
  spelling out the consequence. Set-but-malformed ⇒ **hard startup failure**, never a silent
  downgrade: an operator who set the variable believes their secrets are encrypted, and quietly
  writing them in the clear would betray that at exactly the wrong moment.
- **Versioned storage prefixes** (`v1.plain.` / `v1.xchacha20poly1305.`) mean enabling encryption
  on a running deployment does not invalidate previously-issued secrets — old rows stay readable,
  new ones are sealed. A sealed row with no key configured reports "key mismatch", not "corrupt",
  because the fix is to set the variable.
- Even the plaintext mode hex-encodes, so a `grep` of a database dump does not surface secrets.
- `SecretCipher`'s `Debug` is hand-written to redact key material, so `{:?}` of app state cannot
  leak it.

### Authentication model, restated

| Presented | Result |
| :--- | :--- |
| `X-API-Key` | Bearer auth. A signature, if also present, must verify (body integrity on top). |
| `X-Key-Id` + `X-Signature-256` | Signature auth. The key id is *public*, so a valid signature is **mandatory**. |
| `X-Key-Id` alone | `401` — a public identifier proves nothing. |
| neither | `401` |

Unknown key id and bad signature return the same `401`, so the endpoint is not a key-id oracle.
A key with no signing secret (issued before this migration) is told so specifically — that is a
configuration problem the operator fixes by rotating, not a credential to obscure. Rotation
replaces the signing pair as well as the bearer key: a rotation answers "this may be compromised",
and leaving the old signing secret live would keep an attacker able to forge.

**Migration.** `key_id`/`signing_secret` are nullable rather than backfilled. Minting secrets
during an upgrade would create credentials nobody was told about; a placeholder would either break
`key_id` uniqueness or fabricate something that looks usable but is not. `NULL` states the truth,
and multiple `NULL`s coexist under the unique index because SQL treats them as distinct. (An
earlier draft backfilled via `CONCAT`, which SQLite does not have — caught before it shipped.)

### `run_as_user` is now master-only

`normalize_run_as_user` takes the acting key and rejects any non-empty value from a non-master with
the exact message the task specifies. Two deliberate details:

- **Authorization is checked before syntax.** A non-master submitting `-i` gets `403`, not `400`,
  so the field cannot be probed to learn what would be accepted.
- **Clearing elevation stays open** to any hook manager: `""` means "no elevation", which is a
  de-escalation, not an escalation. Omitting the field leaves the current value untouched, so a
  non-master can still edit other fields of a hook a master elevated.

### `/test` now requires `can_execute`

Previously either grant sufficed. It was tightened because a dry run returns the fully-resolved
command line and the child's environment — execution-shaped knowledge, even though nothing spawns.
A manage-only key can still edit the contract; it just cannot preview the resolved result.
`PATCH` was added as a synonym for `PUT` (every `UpdateHookPayload` field is already optional, so
the handler is partial-update either way).

### Frontend

- **One-time credential modal** replaces the old inline reveal, showing all three credentials
  (API key, key id, signing secret) with an explicit "I have copied them" button — deliberate
  friction, since the signing secret is unrecoverable afterwards. Used by both creation and
  rotation. The keys table gained a Key ID column; it shows `has_signing_secret` rather than the
  secret, which no endpoint ever returns again.
- **`run_as_user` is disabled, not hidden,** for non-masters, with the reason in the placeholder
  and tooltip — a hidden control makes users think the feature is missing; a disabled one with an
  explanation tells them who to ask. Re-applied when the edit modal opens, since its inputs persist
  across renders.
- **Test vs Launch.** Test calls `/test` and shows the resolved program, argv and environment,
  captioned "Nothing was executed". It deliberately does **not** claim stdout/stderr/exit code:
  a dry run spawns nothing, so there are none, and fabricating them would misrepresent what ran.
  Launch calls `/execute`, confirms first (with a stronger warning for elevated hooks), and shows
  the real captured output. Hooks whose required parameters have no defaults route to the Run panel
  instead of being launched with a guess. Both buttons are gated on `can_execute`, Edit/Delete/
  Parameters on `can_manage`.

### Test coverage

Unit 35 → 42, integration 43 → 47, E2E 267 → 322.

- `crypto`: round-trip in both modes, fresh nonce per seal, wrong key rejected, tamper detection,
  plaintext-readable-after-upgrade, malformed inputs.
- `only_master_keys_may_assign_run_as_user`: a `can_manage_hooks` key creates standard hooks fine
  but is refused on every elevation attempt (create, `PUT`, `PATCH`), with the exact message; a
  malformed value from a non-master is still `403`; explicit `null`/`""` are allowed; a master can
  elevate the same hook; and the non-master can then edit other fields without disturbing it.
- `granular_hook_permissions_separate_execute_from_manage`: execute-only runs, dry-runs, reads
  definition/parameters/history but cannot modify or delete; manage-only edits but can run
  *neither* `/execute` nor `/test`; an unmapped key is denied everything and sees no history.
- `key_id_and_signature_authenticate_without_a_bearer_key`, plus a rejection table that now
  includes "signature keyed on the bearer key instead of the signing secret".
- `signing_secrets_are_encrypted_at_rest_when_a_key_is_configured`: asserts the stored column is
  sealed, contains the secret nowhere in readable form, still verifies a live signature, and that
  `GET /api/keys` exposes the key id but never the secret.
- E2E §12 covers key-id auth, rotation invalidating the old pair, and the bearer-key-as-signing-key
  mistake; §22 the master guard; §23 Test-vs-Launch including that a dry run leaves no side effect
  and no history row while a launch does both.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 42 unit + 47 integration tests pass.
- `./scripts/test_e2e.sh` — 322/322 checks pass.

---

## 2026-07-30 — HMAC anti-replay flow, doc alignment, RBAC finalization

This round was framed as "document and audit", but three of the behaviours the brief described did
not exist yet. Writing documentation asserting them would have been worse than writing none, so
they were **implemented first, then documented**:

| Described | Was | Now |
| :--- | :--- | :--- |
| Signature over `METHOD + PATH + TIMESTAMP + RAW_BODY` | covered the body only | canonical four-part string |
| `X-Timestamp`, 5-minute anti-replay window | did not exist | enforced, symmetric, configurable |
| SPA signs every request via Web Crypto | SPA never signed | `RequestSigner`, all methods |

### The canonical signature string

```text
<METHOD>\n<PATH_AND_QUERY>\n<TIMESTAMP>\n<RAW_BODY>
```

Three choices in there are load-bearing, and each has a test pinning it:

1. **Newline delimiters.** The brief said "`METHOD + PATH + TIMESTAMP + RAW_BODY`". Literal
   concatenation is ambiguous — `POST` + `/api/x` and `POS` + `T/api/x` hash identically — so a
   captured signature could be replayed across a different method/path split. Delimiting removes
   the class entirely (`delimiters_prevent_component_boundary_shifting`).
2. **`PATH_AND_QUERY`, not just the path.** Signing only the path would leave
   `?older_than_days=0` freely rewritable to `?older_than_days=1000` on an otherwise-valid signed
   request.
3. **`OriginalUri`, not `parts.uri`.** This one was a genuine bug, caught by the first
   end-to-end run: `Router::nest("/api", …)` *strips the prefix* from the URI inner layers see, so
   the server was signing `/hooks/x/execute` while every client signed `/api/hooks/x/execute`. Every
   signed request failed with `401`. The middleware now reads `OriginalUri`, which preserves the
   target the client actually requested. Worth remembering: **any** middleware inside a `nest` that
   cares about the path has this trap.

### Anti-replay

`X-Timestamp` (Unix seconds) must be within `SIGNATURE_MAX_AGE_SECONDS` (default 300) of server
time, checked **before** the HMAC so a stale request never costs a secret decryption and a body
hash. Two deliberate properties:

- **Symmetric window.** A forward-dated timestamp is rejected as firmly as a stale one — otherwise
  a request dated an hour ahead would stay replayable for that entire hour.
- **No coercion.** A signed request with a missing or malformed `X-Timestamp` is `401`, never
  treated as "now". Silently defaulting would disable the whole mechanism for any client that
  simply forgot the header.

`REQUIRE_SIGNED_REQUESTS=true` promotes signing from optional to mandatory across every
authenticated route. It defaults to `false` deliberately: flipping it on by default would break
every existing bearer-only integration on upgrade. This is the migration path to the end state the
brief describes, not a permanent opt-out.

### `run_as_user` guard ordering

Previously the master-only check ran *after* `validate_script_path` and `validate_timeout`. A
non-master submitting `{run_as_user: "root", script_path: "relative.sh"}` therefore got a `400`
about the path — which leaks that the escalation itself was not the objection. The guard now fires
immediately after the endpoint's authorization check and before any field validation, in both
`create_hook` and `update_hook`. Five payloads, each invalid in a *different* additional way, assert
the `403` always wins.

### Frontend signing

`RequestSigner` signs every request `apiFetch` makes — GET, POST, PUT, PATCH, DELETE — with the
`signing_secret` the operator supplies at login. Two honest constraints:

- **`crypto.subtle` requires a secure context.** Over plain HTTP on a LAN address it is simply
  `undefined`. The signer reports itself unavailable, the SPA falls back to bearer-only auth and
  **says so in a toast** rather than silently sending unsigned requests. Deployments running with
  `REQUIRE_SIGNED_REQUESTS` therefore need HTTPS (or localhost) for the dashboard — that is a real
  constraint, not an oversight.
- **The secret lives in `localStorage`**, as specified. That is XSS-reachable; the SPA has no
  inline scripts and escapes all interpolated output, but the exposure is real and the field is
  optional for exactly that reason. It is cleared on logout alongside the API key.

The imported `CryptoKey` is non-extractable, so it cannot be read back out of the browser once
imported.

### Documentation alignment

- **`AGENT.MD`** gained the full protocol (canonical string, header table, the `OriginalUri`
  requirement, constant-time comparison, the 300s window) and an **effective permission matrix**
  mapping every endpoint to the flag it needs.
- **`SCHEMA.MD`** gained the `signing_secret` storage model (sealed vs plaintext prefixes, the
  `VAULT_ENCRYPTION_KEY` alias, why hashing is impossible, why a malformed key aborts startup) and
  an explicit note that **`can_read` is derived, not stored**, with the reasoning for keeping two
  columns rather than three.

### Audit results (task 2)

Verified by inspection and by test, not assumed:

- **Middleware coverage** — `create_app` has exactly three route trees: `/api` and `/webhook`, both
  wrapped in `auth_middleware`, plus the `ServeDir` fallback serving the public SPA. There is no
  unauthenticated API surface.
- **`/test` is side-effect free** — it contains no call to `execute_hook`, `run_process`, or any
  `insert`; it requires `can_execute`; and a test asserts a canary file is never created and
  `execution_count == 0` afterwards, while `/execute` produces both.
- **Per-handler RBAC** — every handler carries an explicit guard: `guard_execute` (execute/test/
  webhook), `guard_visibility` (reads), `guard_manage` (mutations), `is_master` (settings, audit
  logs, purge), and the global scope checks on key/hook creation. Listing endpoints narrow via
  `visible_hook_ids` rather than rejecting.

### Test coverage

Unit 42 → 47, integration 47 → 51, E2E 322 → 342.

New: canonical-base construction and the delimiter-collision case; replay across method, path,
timestamp and query string; the symmetric window at ±299s/±301s and at day-scale; missing and
malformed `X-Timestamp`; signing across GET/POST/PUT/PATCH/DELETE; query-string tampering;
`REQUIRE_SIGNED_REQUESTS` enforcement across `/api/hooks`, `/api/keys`, `/api/settings` and
`/execute`; and the `run_as_user` 403-before-validation ordering.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 47 unit + 51 integration tests pass.
- `./scripts/test_e2e.sh` — 342/342 checks pass.

### A flaky test, root-caused rather than re-rolled

The first full-suite run after adding the replay tests failed once, then passed three times. Chasing
it down: `the_anti_replay_window_rejects_stale_and_future_timestamps` sampled `now` **once** and
then issued five requests that each spawn a real process. By the last iteration several seconds of
wall clock had elapsed, so an offset of `-299` against a 300s window drifted *past* the boundary —
and, symmetrically, `+299` drifted *inside* it. Either direction produces an intermittent failure.

Offsets were widened to ±240 (inside) and ±360 (outside), well clear of the boundary, with the same
fix applied to the E2E script, which had the identical hazard. Exact boundary behaviour (±299/±301)
is asserted in `middleware::tests::timestamps_*`, where `validate_timestamp` is called directly with
no I/O in between and drift is measured in microseconds. That is the right split: integration tests
prove the window is *wired up*, unit tests prove it is *exact*.

Verified with six consecutive runs of the isolated test and three of the full suite.

### Known constraint

`REQUIRE_SIGNED_REQUESTS=true` plus a dashboard served over plain HTTP is a non-working
combination, by construction: the browser will not expose `crypto.subtle` outside a secure context,
so the SPA cannot sign. Terminate TLS in front of the daemon (the unit file already recommends a
reverse proxy) before enabling mandatory signing. Non-browser clients are unaffected.


---

## 2026-07-30 (later) — Per-key HMAC modes, pure-JS crypto fallback, spec lock

### Per-key `hmac_mode`

`api_keys.hmac_mode` (`CANONICAL_V1` | `BODY_ONLY`) selects how a key's signatures are verified.
`BODY_ONLY` exists for one reason: GitHub, Forgejo and GitLab compute HMAC over the raw body alone
and send it as `X-Hub-Signature-256`, and their format cannot be changed. Four decisions shape it:

1. **The default is the strict mode, everywhere.** The column is `NOT NULL DEFAULT 'CANONICAL_V1'`,
   which every supported backend applies to existing rows during the `ALTER TABLE` — so the upgrade
   backfills correctly with no separate `UPDATE` pass and, critically, cannot silently strip replay
   protection from a deployed key. A test stops before this migration, applies it, and asserts the
   resulting mode.
2. **`X-Hub-Signature-256` is honoured only in `BODY_ONLY`.** Accepting it unconditionally would let
   anyone downgrade a strict key to body-only verification by choosing a different header name,
   making the per-key setting advisory rather than enforced. For a `CANONICAL_V1` key the header is
   not merely rejected — it is not read at all, so such a request is treated as *unsigned*.
3. **`BODY_ONLY` relaxes the format, never the requirement.** A key-id request with no signature is
   still `401`; the mode changes what is signed, not whether.
4. **It is audited as a security decision.** Creating or switching to `BODY_ONLY` writes
   "BODY_ONLY — body-only, no replay protection" into the audit trail, and the UI badges it in the
   warning colour. Someone reviewing keys later should not have to know what the value implies.

### Pure-JS HMAC-SHA256 fallback

`crypto.subtle` only exists in a secure context, so a dashboard on a plain-HTTP LAN address could
not sign at all. AGENT.MD forbids external dependencies, so `PureCrypto` is a self-contained
FIPS 180-4 SHA-256 plus RFC 2104 HMAC embedded in `app.js`.

**Hand-written crypto needs verification, not confidence.** There is no JS runtime in this
environment, so it was validated three ways:

- The `K` and `H0` tables were parsed **out of the shipped `app.js`** and checked against the cube
  and square roots of the first 64/8 primes derived from first principles — that validates the
  actual artifact, not a copy of it.
- The round logic was transliterated to Python and checked against `hashlib` on nine SHA-256 vectors
  chosen to straddle every padding boundary (55/56/63/64/65 bytes, plus multi-block), and against
  four RFC 4231 HMAC vectors including the longer-than-block-size key path.
- `PureCrypto.selfTest()` runs **in the browser** before the fallback is ever trusted, reproducing
  RFC 4231 case 2. If it fails, the signer reports itself unavailable and logs loudly rather than
  emitting wrong signatures — a broken hash would otherwise surface as an inexplicable stream of
  401s. The vector embedded in `app.js` was itself checked against `hmac`/`hashlib`.

`crypto.subtle` remains preferred wherever it exists (native, and the imported key is
non-extractable); the pure path is strictly the insecure-context fallback. The SPA also adopts the
key's server-reported `hmac_mode` from `/auth/me`, so a `BODY_ONLY` key signs the body alone rather
than a canonical string the server would not verify.

### Specification lock

- **`SCHEMA.MD`**: `hmac_mode` added to the `api_keys` table with a full `HmacMode` enumeration
  section (signed material, accepted headers, timestamp requirement, replay protection per mode).
  `signing_secret`, `run_as_user` and derived `can_read` were already documented and were verified
  against the code rather than re-asserted.
- **`AGENT.MD`**: the `hmac_mode` table and its four invariants, plus the exact `sudo` invocation
  (`/usr/bin/sudo -n -u <user> --`) with the reasoning for each element — hard-coded path, `-n`,
  the mandatory `--` placement, username validation, master-only assignment, and the `env_keep`
  caveat.

While locking the schema I found and fixed a **markdown defect I had introduced earlier**: the
`signing_secret` storage-model prose had been inserted *inside* the `api_keys` table, orphaning
`bound_ips` and everything after it into a second, header-less table. The prose now follows the
complete table, and a checker validates that no blank line splits any table in either document.

### Test coverage

Unit 47, integration 51 → 55, E2E 342 → 369.

New integration tests: body-only acceptance under both header spellings; a stray `X-Timestamp`
being ignored rather than verified; tampered body and wrong secret still rejected; a canonical
signature refused for a `BODY_ONLY` key and vice versa; `X-Hub-Signature-256` ignored for a
`CANONICAL_V1` key; mode settable at creation and switchable both ways, defaulting to strict;
unknown variants refused at deserialization; and the migration defaulting existing rows.

E2E §24 mirrors this black-box, including a real Forgejo-shaped `X-Hub-Signature-256` invocation
and the downgrade-resistance check.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 47 unit + 55 integration tests pass.
- `./scripts/test_e2e.sh` — 369/369 checks pass.

### Standing caveat

`BODY_ONLY` has no replay protection — that is inherent to the scheme, not an implementation gap.
A captured request stays valid indefinitely. Keys on that mode should be scoped to exactly the hooks
the third-party sender is meant to trigger, and nothing else.


---

## 2026-07-30 (final) — `X-API-Key` standardization and edge-case verification sweep

### One header, one lookup path

`X-Key-Id` is gone. Every request now identifies its key with `X-API-Key`, hashed and matched
against `api_keys.key_hash` — the single key lookup path in the system. Removed from the middleware,
`api.rs` and entity docs, the SPA, `README.md`, `AGENT.MD` and `SCHEMA.MD`.

**What this changes, stated plainly.** The retired header allowed signature-only authentication: a
webhook sender could present a *public* identifier plus a signature and never transmit a bearer
credential. That property is gone — every caller now sends the secret API key. The upside is a
single, obvious authentication path with no second lookup to reason about or keep consistent; the
cost is that a sender's transport must be trusted with the bearer key. Under TLS that is the same
assumption every bearer-token API makes, but it is a real reduction and worth recording.

`api_keys.key_id` is retained as a **public display/correlation identifier** only — useful in the
dashboard and logs, never a credential. A regression check in `§12` of the E2E suite fires the
retired `X-Key-Id` header at the server and asserts it resolves nothing, so the removal cannot
silently regress.

A consequence that rippled through the tests: with the bearer key as the sole credential, an
*unsigned* request from a valid key is now **accepted** (signing is optional unless
`REQUIRE_SIGNED_REQUESTS=true`). Several assertions written for the old model — "an unsigned
request is rejected" — were true only because a key id alone proved nothing. They were rewritten to
pin what the modes actually govern: **how a signature is verified**, not whether the key is a
credential. The `hmac_mode` toggle test now runs against a `REQUIRE_SIGNED_REQUESTS` instance
precisely so the mode is observable; without that it would have passed while proving nothing.

### Constant-time verification — verified, not assumed

No code change was needed, and deliberately so. The chain was traced through the vendored source
rather than taken on faith:

```text
Mac::verify_slice  ->  CtOutput::eq  ->  subtle::ConstantTimeEq::ct_eq
```

`verify_slice` rejects a wrong-length tag first (leaking only the digest width, a public constant)
and then compares all 32 bytes in constant time. This is exactly the `subtle::ConstantTimeEq` the
brief asked for, reached through the RustCrypto `Mac` API. Swapping in `ring` would add a large
dependency for zero security gain; hand-rolling the comparison with `subtle` directly would be more
code with more room for error. The reasoning is now a doc comment on `verify_signature` so a future
"simplification" to `==` is visibly wrong.

**On testing it.** A wall-clock timing assertion was considered and rejected: the HMAC computation
dominates `verify_signature`'s runtime by orders of magnitude, so a byte-by-byte early exit would be
buried in noise. Such a test would pass whether or not the comparison were constant-time — false
assurance, which is worse than none. What was written instead has real detection power:

- **Exhaustive per-byte mutation**: every one of the 32 digest positions, flipped three ways (96
  cases), must be rejected — the deterministic fingerprint of a *full-width* comparison. A
  prefix-only, suffix-only or truncated compare would show up as a specific band of positions that
  wrongly verify.
- **Wrong-length tags** (1, 31, 33 bytes, empty) rejected, so no truncated comparison slips through.
- **Response indistinguishability**: first-byte-wrong, last-byte-wrong, all-zeros and all-ones must
  produce byte-identical status *and* error text. A differing message would itself be an oracle
  regardless of how the bytes were compared.

### Replay differential

`replay_differs_between_hmac_modes` signs an identical payload dated ten minutes back:
`CANONICAL_V1` rejects it (the timestamp is inside the signed material, so it cannot be re-dated and
its own date has aged out), while `BODY_ONLY` accepts it — and accepts three further byte-identical
replays. That is the documented trade-off of the mode, now demonstrated rather than only asserted in
prose.

### Live mode toggle

`hmac_mode_toggle_takes_effect_immediately_without_a_restart` flips a key between modes via `PUT`
and `PATCH` on a single, never-rebuilt app instance and asserts the signature rules invert on the
very next request, in both directions. The middleware re-reads the key row per request, so there is
no cache to invalidate. This test found a genuine gap: `PATCH /api/keys/:id` was not routed at all
(only hooks had it), returning `405`. Added.

### Large payloads

`large_payloads_are_signed_verified_and_executed_within_the_buffer_limit` covers ~512 KB and
just-under-1-MiB bodies end to end, a single byte flipped in the middle of a large body invalidating
the signature (the whole body is covered, not a prefix), and an over-limit body refused with an
explanatory `400` rather than a hang or an OOM. A 64 KiB *parameter* is also round-tripped into the
child environment — held to 64 KiB deliberately, since argv and environment share `ARG_MAX` and each
parameter is passed both ways, so a multi-hundred-KB value would risk `E2BIG`. That is a platform
limit, not a defect here.

**A test-harness bug worth recording.** The first E2E run of this section reported nonsense — a
0-byte body signed and accepted. Cause: `jq --arg` with a 512 KB value exceeds `ARG_MAX`, so jq died
with "Argument list too long" and left an empty file behind, which the script then happily signed.
Fixed by streaming padding through a file and reading it with `jq --rawfile`, plus a guard that
asserts the generated body is actually large before any signature check runs — so a truncated
fixture fails loudly instead of quietly making every downstream assertion meaningless.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 49 unit + 59 integration tests pass (three consecutive clean runs).
- `./scripts/test_e2e.sh` — 382/382 checks pass.

---

## 2026-07-30 (hardening) — XSS sinks, hostile payloads, process-escape limits, body ceiling

Red-team pass over the areas the earlier audits had *not* reached: the rendering layer, argument
interpretation by downstream consumers, the OS boundary around process termination, and memory
exhaustion via request size.

### 1. Frontend XSS audit (`static/app.js`)

**Audit result: no exploitable stored XSS was found.** Every one of the 23 interpolations reaching an
`innerHTML` sink already passed through `escapeHtml()`, which escapes `& < > " '` — complete for both
element-content and quoted-attribute contexts. This is recorded plainly because "we found nothing"
is a result, and overstating it would be worse than useless.

The renderer was nonetheless **restructured**, because escaping-into-markup is a property of the
current text of each template, not of the design. The data flowing through these sinks is the most
attacker-controlled in the system: whoever can execute a hook chooses what the script prints, it is
persisted verbatim in `executions.stdout`, and every operator who later opens that record re-renders
it — a payload lands in a *master* key holder's session. One future edit that drops an `escapeHtml()`
call turns that into account takeover.

What changed:

| Before | After |
| :--- | :--- |
| `outputBlock()` returned an HTML **string** built with `escapeHtml()` | returns a DOM **element**; content is assigned via `pre.textContent` |
| Result panels/modals assembled one big template and assigned `innerHTML` | `renderResultView()` builds a header from trusted markup, then **appends** pre-built nodes |
| `showHookResultModal(title, bodyHtml)` accepted raw markup | takes a descriptor `{headerHtml, noteText, errorText, blocks}` — the modal *cannot* be handed a concatenated string |
| `blocking_reason` interpolated into a `<p>` template | assigned via `message.textContent` |

The invariant is now structural: `headerHtml` is markup this file builds from its own literals plus
already-escaped badge helpers, while everything the server returns arrives as a node or as text and
is assigned, never parsed. A caller cannot accidentally route hook output through the HTML path,
because the only parameter that reaches `innerHTML` is one no server value is ever passed to.

Numeric server fields (`exit_code`, `timeout_seconds`, `duration_ms`) that were previously
interpolated bare are now escaped too. They are `i32`/`u64` server-side and cannot carry markup, so
this is belt-and-braces — but it removes the need for a reader to prove that to themselves.

**Testing constraint, stated honestly.** The task asked for an E2E test asserting the UI does not
render the payload as DOM nodes. This project has no JavaScript runtime and no headless browser, and
`AGENT.MD` forbids frontend dependencies — so nothing here can mount `app.js` and inspect the
resulting node tree. That assertion is therefore split into the two halves that *are* verifiable:

- **API-level** (`hook_output_containing_live_markup_round_trips_verbatim_as_json`,
  `hook_metadata_containing_markup_round_trips_verbatim`, E2E §26): `<img src=x onerror=alert(1)>`
  and `"><script>alert(document.domain)</script>` survive execution, persistence, and re-read
  byte-for-byte, and are served as `application/json`. Verbatim storage is deliberate — a server
  that stripped tags would leave the renderer's escaping untested in production, so the first
  payload that evaded the stripper would land in an unprotected sink.
- **Source-invariant** (`spa_renders_captured_output_through_text_nodes_only`, E2E §26): fails the
  build if `stdout`, `stderr`, `blocking_reason`, `argList`, `envRows`, or `res.command.program`
  ever appears on a line that assigns `innerHTML`, and asserts the three `textContent` assignments
  are still present.

A real DOM assertion would need a browser in CI. That is the honest gap; the guard above catches the
regression this refactor exists to prevent.

### 2. Argument injection — the threat is `getopt`, not `sh`

There is no shell in the execution path, so `; rm -rf /` was never the interesting payload. The real
one is a value shaped like an *option*: `--help`, `-rf`, `--version`, `-u root`, `--preserve-env`.
Those are ordinary strings until something re-parses the argument vector — and for a privileged hook
there *is* such a parser, namely `sudo`.

`cli_flag_shaped_parameters_stay_literal_in_argv_and_environment` runs six payload triples through a
real sub-process and asserts each value arrives in its exact argv slot **and** its `HOOK_PARAM_*`
variable, with no slot absorbed or synthesized, plus a filesystem canary that stays absent.

`hostile_parameters_cannot_escape_the_sudo_argument_boundary` covers the elevation case through the
dry-run endpoint, which reports the vector that would reach `execve` — so the assertion is about the
real argument list rather than a reimplementation of it, and it needs no `sudoers` entry. For each of
nine sudo-meaningful payloads (`-u`, `-u root`, `--user=root`, `-i`, `--login`, `-E`,
`--preserve-env`, `--`, `-s`) it pins:

- `program == /usr/bin/sudo` (hard-coded, never `PATH`-resolved),
- `args[0..4] == ["-n", "-u", "root", "--"]` — the prefix is complete and nothing attacker-supplied
  precedes the separator,
- every supplied value sits at an index strictly greater than the `--` position,
- the vector is exactly 7 entries, so nothing was synthesized.

Note the payload `--` specifically: a second `--` in the data position is inert, because sudo stops
option parsing at the *first* one.

`option_shaped_run_as_user_is_refused_at_definition_time` closes the other half — the `-u` slot
itself. `validate_run_as_user` makes a leading `-` unrepresentable, so a hostile account name is
rejected with `400` at hook definition rather than relying on sudo to be defensive at spawn time.

E2E §27 mirrors all three. A helper `check_stdout_contains` was added: the payloads contain `$`,
backticks and quotes, which would be reinterpreted if spliced into a jq filter string, so they are
bound with `--arg` as data.

**Parameter-ordering determinism (found while writing these).** Positional order is
`ORDER BY created_at, param_key`. Tests that declared `flag, target, extra` were relying on
`created_at` resolving them, since alphabetical order (`extra, flag, target`) disagrees — two rows
landing in the same timestamp tick would have silently permuted argv. Test parameters are now named
`p1_*, p2_*, p3_*` so both orderings agree. This is a test-robustness fix, not a product defect: the
tie-break is documented and deterministic, it simply is not declaration order.

### 3. Process escape — the exact limits of `libc::killpg`

**What `killpg` guarantees.** The child is spawned with `process_group(0)`, making it the leader of a
new group; on timeout `killpg(pgid, SIGKILL)` signals every member of *that* group. This reliably
covers the direct child and any descendant that inherited the group — including one backgrounded with
`&`, and including a double-fork, since `fork(2)` inherits the process group. `child.kill()` and
`child.wait()` then run unconditionally, so the direct child is reaped even when the group signal
found nothing to do.

**What it cannot cover.** A process that calls `setsid(2)` becomes leader of a **new session and a
new process group**. It is, by POSIX definition, no longer a member of the group being signalled, so
`killpg` cannot reach it — not through a bug, but because the identifier being signalled no longer
names it. `a_setsid_child_leaves_the_process_group_and_survives_the_timeout_kill` **asserts the
escape happens**, and E2E §28 does the same. Both run an in-group grandchild and a `setsid`
grandchild under a single execution — same kill, same timing, same machine — and assert the first
dies while the second survives.

Asserting a limitation as a passing test is a deliberate choice. The alternative is a test suite that
is silent about the boundary, which leaves an operator believing in isolation the daemon does not
provide. If a future change adds cgroup or PID-namespace confinement, that test failing is exactly
the signal that the boundary moved, and this section must be rewritten.

**Why this is not fixed here.** Containing a `setsid` escapee requires a kernel-level accounting
boundary the daemon does not create:

| Mechanism | Effect | Cost |
| :--- | :--- | :--- |
| cgroup v2 per execution | complete: `cgroup.kill` terminates every member regardless of session | needs a writable `cgroup2` mount and delegation to the daemon user; systemd-specific setup |
| PID namespace (`unshare`) | complete: killing PID 1 of the namespace reaps everything | needs `CAP_SYS_ADMIN` or user namespaces; interacts badly with `sudo` elevation |
| session-wide `kill(-sid)` | partial and dangerous: would reach unrelated processes in the daemon's own session | unacceptable |

Each is a deployment-shaped change rather than a code change. The honest posture is: **hook timeouts
bound the process group, not the machine.** An operator who runs hooks that deliberately daemonize
should confine the unit with systemd's own `KillMode=control-group` and a per-unit slice.

`timed_out_executions_do_not_leave_zombie_children` additionally asserts that three consecutive
timeouts leave no defunct children *parented to this test process* — scoped to `$PPID` rather than
the machine, so an unrelated zombie on a shared CI host cannot make it flaky.

### 4. Request body ceiling

**Finding: the limit was implicit.** Every handler buffers its whole body before running — the
execute and webhook routes via `Bytes`, the admin routes via `Json<T>` — and the only bound was
Axum's built-in 2 MiB default. `max_concurrent_jobs` throttles concurrent *processes* and did nothing
about concurrent *allocations*, so N simultaneous large POSTs were bounded only by a framework
default that is documented behaviour, not a guarantee.

Mitigation: `MAX_REQUEST_BODY_BYTES` (1 MiB) is now declared in `lib.rs` and applied as an explicit
`DefaultBodyLimit` layered **outside** both nests, so it covers `/api/*`, `/webhook/*`, and the
static fallback alike — the ceiling cannot be sidestepped by aiming at a route that never reaches
the auth middleware. `middleware::MAX_SIGNED_BODY_BYTES` now *is* that same constant rather than an
independently-chosen 1 MiB: two separately-maintained limits would eventually drift into a band of
sizes one layer accepts and the other refuses, which is how parser-differential bugs start.

Behaviour, all covered by tests and E2E §29:

| Request | Result |
| :--- | :--- |
| 10 MiB, authenticated, `Bytes` route (`/execute`, `/webhook/{name}`) | `413 Payload Too Large` |
| 10 MiB, authenticated, `Json<T>` route (`/api/hooks`, `/api/keys`) | `413 Payload Too Large` |
| 10 MiB, missing or unknown key | `401` — the key check precedes the body read, so nothing is buffered |
| >1 MiB **and signed** | `400` with "too large" from the signature buffer (pre-existing, unchanged) |
| just under 1 MiB | accepted, parsed, executed |

The signed path answering `400` rather than `413` is intentional and left alone: the refusal happens
in the middleware while deciding whether it can verify the request at all, which is a different
statement from the extractor's "this body exceeds the route's limit".

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 49 unit + 71 integration pass (was 49 + 59; 12 added).
- `./scripts/test_e2e.sh` — 503/503 checks pass (was 382; §26–§29 added).

### ⚠ Outstanding — NOT addressed by this pass

A prior audit of the RBAC engine (commit `e9c3c5d`, verified by running exploits against the real
router) found five confirmed privilege-escalation paths that remain **open**. They are out of scope
for this task list but must not be lost:

1. **`can_manage_keys` can mint a master key** — `create_api_key` reads `is_master` straight from the
   payload (`api.rs:1551`) while gating only on `is_master || can_manage_keys`. Escalation to master
   in one request, then `run_as_user: root`.
2. **`can_manage_keys` can rotate any key, including a master key**, and the new plaintext is
   returned in the response (`rotate_api_key`) — direct credential theft plus lockout.
3. **`can_manage_keys` can self-grant `can_execute`/`can_manage` on any hook** —
   `update_key_hook_permissions` checks nothing about the caller's rights over the target hook.
4. **`can_manage` on an already-elevated hook allows repointing `script_path` while `run_as_user`
   survives** — the master-only guard fires only when the payload *contains* `run_as_user`. With
   `ALLOWED_SCRIPT_ROOTS` unset (the default) this is arbitrary root execution.
5. **`X-Forwarded-For` is trusted from any peer**, so the `bound_ips` CIDR allowlist is bypassable
   with one header, and `audit_logs.client_ip` is attacker-controlled.

Net effect: **`can_manage_keys` is currently equivalent to `is_master`.** The XSS, argument-injection
and payload-limit work above does not touch any of it.

---

## 2026-07-30 (PrivEsc patch) — Closing the five RBAC escalation findings

Patches the five confirmed privilege-escalation paths carried forward from the previous section.
All five were verified as *exploitable* against the real router before the fix and are now pinned by
regression tests that assert the `403`.

The unifying defect: **`can_manage_keys` was operationally equivalent to `is_master`**, by four
independent routes. A scope meant to say "you may administer credentials" was read by the code as
"you may create authority", which is a different and much larger claim.

### #1 — Minting a master key (`create_api_key`, `update_api_key`)

`is_master` was read straight from the request payload while the only gate was
`is_master || can_manage_keys`. A key manager could mint a master key, authenticate as it, and
assign `run_as_user: root` — three requests from scoped key to arbitrary root execution.

`guard_master_to_grant_scopes` now gates `is_master`, `can_manage_keys` and `can_manage_hooks` on
both create and update. It runs **before any field validation**, matching the existing `run_as_user`
convention: an escalation attempt must surface as `403` and never be masked by a `400` about some
unrelated field in the same payload.

Only *granting* is restricted. Clearing a scope stays available to any key manager — removing
authority is not an escalation, and requiring master to revoke would make an over-provisioned key
harder to contain than it was to create. `UpdateApiKeyPayload` still carries no `is_master` field, so
promotion via update remains impossible by construction as well as by check.

### #2 — Taking over an existing master key (`rotate`, `update`, `delete`)

`rotate_api_key` accepted any key id and returned the new plaintext secret in its response body, so
"rotate the master key" was a single-request credential theft that also locked out the legitimate
holder. `guard_master_to_administer` now gates rotate, update and delete whenever the **target** is
`is_master`. Update is included because `bound_ips` alone would let a key manager strand or widen the
network binding of the system's root credential.

### #3 — Self-granting hook permissions (`update_key_hook_permissions`)

The handler checked that the *target* was not a master key, but never that the caller had any
relationship to the hook being granted. A `can_manage_keys` key could write itself a `can_execute`
row on any hook in the system, including one running as root.

Two gates now apply to non-masters: the target key may not be the caller's own (`id == key.id`), and
the caller must already hold `can_manage` on the hook. Granting rights over a *privileged* hook is
master-only regardless, since those rights are the elevation itself.

`revoke_key_hook_permission` received the same "must manage the hook" rule. Revocation is not an
escalation, so this is a deliberate extension beyond the reported finding: leaving it open would mean
a key manager could strip access to hooks it has no relationship with, and would leave the odd
asymmetry where a grant you could not create is one you could still destroy.

### #4 — Repointing an elevated hook (`update_hook` + all parameter routes)

The `run_as_user` guard fired only when a payload *contained* that field. A payload omitting it left
every other field writable, so a `can_manage` holder could repoint a root hook's `script_path` at a
different binary while the elevation survived the swap. With `ALLOWED_SCRIPT_ROOTS` unset (the
default) that is arbitrary root execution.

`guard_master_for_privileged_hook` now gates **any** mutation of a hook whose `run_as_user` is
non-empty. The scope is wider than "script_path" on purpose — every part of a privileged hook's
definition decides what runs with the borrowed privileges:

| Route | Why it is gated |
| :--- | :--- |
| `PUT`/`PATCH /api/hooks/{id}` | `script_path` names the binary; the timeout bounds it; the name is how operators identify it |
| `POST .../parameters` | a parameter is argv. A defaulted parameter on a root hook pointing at `/bin/sh` supplies `-c` and a command string **without touching `script_path` at all** — this was the sharpest edge of the finding |
| `PUT .../parameters/{id}` | changing a `default_value` rewrites what the elevated command receives |
| `DELETE .../parameters/{id}` | removing a required parameter shifts every positional argument after it |
| `POST /api/keys/{id}/permissions` | distributing rights over a privileged hook distributes the elevation |

**Clearing the elevation is gated too**, which is the one judgement call worth spelling out. The task
text allowed reading it as "a non-master may clear `run_as_user`, then edit freely". That reading is
not exploitable — re-adding elevation is master-only, so the hook cannot be re-armed — but it would
let a non-master silently downgrade an operator's vetted configuration, and it turns the attack into
two requests rather than blocking it. The strict reading ("modifying ANY field requires master") was
implemented. A master clears the elevation; the hook then becomes ordinary and its manager can edit
it again, which the tests assert end to end.

### #5 — Forged `X-Forwarded-For` (`middleware.rs`, `config.rs`)

`X-Forwarded-For` and `X-Real-IP` were parsed from every peer, so the `bound_ips` CIDR allowlist was
bypassable with one header and `audit_logs.client_ip` was attacker-chosen. A stolen LAN-restricted
key worked from anywhere.

New `TRUSTED_PROXIES` config (comma-separated CIDRs **or** bare IPs, which are widened to `/32`
or `/128`). `resolve_client_ip` consults forwarding headers only when the TCP peer matches that list;
otherwise the peer address is authoritative and the headers are ignored outright.

The **ordering is the fix**, not the list: the trust decision is taken from the socket *before* any
header is read. Reading the header first and validating afterwards would still let an untrusted
client choose the address the allowlist sees. Peer normalization happens before the trust match too,
so a dual-stack listener surfacing an IPv4 proxy as `::ffff:10.0.0.9` still matches a `10.0.0.0/8`
entry — otherwise a correct `TRUSTED_PROXIES` value would silently stop applying.

Default is empty (trust nothing). For a directly-exposed daemon that is correct; for a proxied one it
is safe but visible — every key appears to connect from the proxy, which an operator notices at once,
rather than the allowlist silently accepting anything. A malformed entry is dropped with a warning,
which fails in the safe direction: not-trusted.

**`bound_ips` now applies to every key, including `is_master`.** The old `!is_allowed && !is_master`
condition meant the single most valuable credential in the system was also the only one whose network
restriction was decorative — while the dashboard displayed it as enforced. `is_master` bypasses
*RBAC*; a network boundary is not a permission. A master key that should reach the API from anywhere
now says so by leaving `bound_ips` empty rather than by having the check skipped behind its back.

Consequence worth flagging: `BOOTSTRAP_SUBNET` defaulted to `0.0.0.0/0` (IPv4 only) while
`SCHEMA.MD` and the migration both specify `0.0.0.0/0,::/0`. Harmless while master keys bypassed the
check; a first-request lockout on a dual-stack deployment once they no longer do. Corrected to match
the schema.

### Tests

Nine integration tests (`regression_*`, plus `bound_ips_restricts_master_keys_as_well` and
`a_trusted_proxy_can_still_present_the_real_client_address`) and E2E §30. Each is the exploit that
previously *succeeded*, inverted into an assertion that it is refused. They drive the HTTP surface
rather than the guard functions directly: a unit test of `guard_master_to_grant_scopes` would keep
passing if a handler stopped calling it, which is precisely the regression worth catching.

Every one also asserts the **negative space** — that the legitimate capability still works. A gate
that turns `can_manage_keys` into a decoration would pass a test suite that only checks for `403`.
So: a scope-free key is still creatable, revoking a scope still works, a master peer can still
administer a master key, a caller who manages a hook can still delegate it, and an unprivileged hook
is still editable by a `can_manage` holder.

E2E §30 boots a **second daemon instance** on its own port with `TRUSTED_PROXIES` unset, because the
main instance sets it to loopback so §15 can drive `bound_ips` with `X-Forwarded-For`. One process
cannot demonstrate both sides of a startup-time trust decision; two can, and the suite tears the
second one down in `cleanup` alongside the first.

**Two existing test groups asserted the vulnerable behaviour and were inverted, not extended:**
`only_master_keys_may_assign_run_as_user` and E2E §22 both claimed "a non-master may still edit other
fields of an elevated hook" and "dropping elevation is not an escalation". Finding #4 had been
written down as expected behaviour and locked in by a passing test — worth remembering that a green
suite is only as good as the expectations encoded in it.

### Documentation

`AGENT.MD` contained the directive that *produced* finding #5 — "Extract the rightmost IP from
`X-Forwarded-For` or `X-Real-IP`, falling back safely to `ConnectInfo`". That section is rewritten
around the trusted-proxy rule, and the effective-permission matrix gained five rows for the new
master-only operations. `SCHEMA.MD`'s `is_master`, `can_manage_keys`, `can_manage_hooks` and
`bound_ips` descriptions were corrected to state what each flag does and does *not* confer. Leaving
either document as it stood would have instructed the next agent to reintroduce the bug.

`GET /api/settings` (master-only) now reports `trusted_proxies`, and the dashboard renders it: which
peers may speak for a client decides what every `bound_ips` check compares against, and that should
be readable from the UI rather than only from the daemon's environment.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 54 unit + 79 integration pass (was 49 + 71).
- `./scripts/test_e2e.sh` — 553/553 checks pass (was 503).

### Residual risk

- `TRUSTED_PROXIES` is only as tight as the operator makes it. A range wider than the real proxy
  fleet re-opens the bypass for every host inside it; the README says so at the point of use.
- `delete_hook` on a privileged hook is still available to a `can_manage` holder. Destructive, but
  not an escalation: recreating the hook with `run_as_user` requires master, so there is no path back
  up. Left alone deliberately rather than overlooked.
- A non-master key manager can still edit `bound_ips` on *non-master* keys. Lateral within the set of
  keys it already administers, and inherent to what `can_manage_keys` is for.

---

## 2026-08-01 — Proxy parity with `simply_ip_vault`, hook soft delete, SQLite WAL

Four workstreams: bringing proxy validation to parity with the reference implementation in
`example/simply_ip_vault` (and extending it for container platforms), hook soft delete with a 92-day
purge, SQLite concurrency pragmas, and the regression tests for all of it.

### 1. Proxy validation — a real defect found by the cross-check

The audit against `example/simply_ip_vault/src/config.rs` was not a formality. **Our implementation
had a genuine bug the reference did not**, and it would have bitten in exactly the deployment this
round was meant to support.

Our `resolve_client_ip` took the **rightmost** `X-Forwarded-For` hop unconditionally. That is correct
for a single proxy and wrong for a chain. With `client → P1 → P2 → us` the header reads `client, P1`,
so the rightmost entry is **P1 — a proxy, not the client**. Every caller behind two hops would have
been authorized against their proxy's address, and the audit trail would have recorded the
infrastructure instead of the caller.

The reference walks the chain **right to left, skipping addresses that are themselves trusted
proxies**, and takes the first remaining one. That is now our implementation too, verbatim in
behaviour:

- Rightmost-first is what makes the *suffix* unforgeable — each proxy appends the address it actually
  observed, so entries to the left of the last trusted hop are hearsay the client supplied.
- Skipping trusted entries is what makes a chain resolve to the client rather than to a proxy.
- A header naming nothing but trusted proxies says nothing about the client, so the peer stands
  rather than a proxy being reported as the caller.
- `X-Real-IP` is consulted only when `X-Forwarded-For` yields nothing, under the same precondition.

`resolve_client_ip` and `normalize_ip` moved from `middleware.rs` to `config.rs`, matching the
reference's layout so the two files can be diffed directly; the middleware now calls
`crate::config::resolve_client_ip(peer, &headers, &trusted)` exactly as the reference does.

`the_chain_is_walked_right_to_left_past_trusted_hops` and the E2E chain checks in §30 are the
regression guards. Both fail against the old rightmost-only logic.

### 2. Hostname resolution in `TRUSTED_PROXIES` (beyond the reference)

The reference accepts only IPs and CIDRs. On Docker/Traefik the proxy's address is assigned by the
orchestrator and changes on every restart, so it cannot be written into configuration at all — the
operator knows the *service name*, not the address.

`TRUSTED_PROXIES` now accepts three spellings, parsed into a `ProxySpec` enum:

| Spelling | Example | Matched |
| :--- | :--- | :--- |
| CIDR | `172.16.0.0/12` | arithmetically, no lookup |
| Bare address | `127.0.0.1`, `::1` | widened to `/32` / `/128` |
| Hostname | `traefik`, `proxy.internal` | resolved via `tokio::net::lookup_host` |

Design decisions worth recording:

- **Resolution is cached with a 30-second TTL, not resolved once at startup.** A name resolved once
  and cached forever keeps trusting an address the orchestrator has since handed to a different
  container — a stale entry here is a trusted-proxy grant pointing at something arbitrary. Thirty
  seconds bounds that window while keeping DNS out of the request path in the steady state.
- **The no-hostname path costs an `Arc` clone.** `TrustedProxies::resolved()` returns the precomputed
  networks without touching the lock or the resolver when no names are configured, which is every
  deployment that names its proxies by address.
- **An unresolvable name is simply not trusted**, logged at `warn`. Failing closed matters here: a DNS
  outage must never be able to *widen* what the daemon believes, and a container that is down should
  stop being trusted rather than keep a stale grant alive.
- **A malformed entry is not silently reinterpreted as a hostname.** `is_hostname_like` rejects
  anything containing `/` or `:`, and anything made only of digits and dots, so `10.0.0.0/8x` is
  reported as the typo it is instead of becoming a lookup that quietly never matches.

`RuntimeConfig.trusted_proxies` changed type from `Vec<IpNetwork>` to `TrustedProxies`, which carries
the spec plus the shared cache. `PartialEq`/`Debug` are implemented by hand over the *spec* only — two
sets configured identically are equal regardless of when their caches last refreshed.

### 3. Hook soft delete + 92-day purge

**The problem.** `hooks` is the parent of `hook_parameters`, `api_key_hook_permissions`, **and
`executions`**, all `ON DELETE CASCADE`. A single `DELETE /api/hooks/{id}` therefore destroyed the
complete audit record of everything that hook had ever run — irreversibly, from one mistyped
identifier.

New columns (migration `m20230105_000001`): `is_deleted`, `deleted_at`, `deleted_by`.

| Route | Behaviour |
| :--- | :--- |
| `DELETE /api/hooks/{id}` | soft for **everyone**, master included — nothing cascades |
| ordinary read/execute/parameter routes | `404`, identical to a hook that never existed |
| `GET /api/hooks{,/{id}}?include_deleted=true` | trash view, master only |
| `POST /api/hooks/{id}/restore` | master only |
| `DELETE /api/hooks/{id}?hard=true` | master only, cascades |
| `POST /api/system/purge-hooks` | master only, drops trash past 92 days |

Decisions:

- **Soft is the default for master too.** The destructive path is the one that should require saying
  so, not the one you get from a typo. `?hard=true` is master-only because discarding an audit trail
  is not something a scoped `can_manage` grant should be able to do.
- **A trashed hook is a `404`, not a distinguishable state.** Making "deleted" invisible rather than
  special means every route that reads, executes, or edits a hook inherits the right behaviour
  without being individually audited for whether acting on a trashed row is safe.
- **`deleted_by` is text, not an FK.** Attribution must outlive the acting key; an FK would either
  cascade it away or block that key from being deleted. Same reasoning as `audit_logs`' denormalized
  key name and prefix.
- **`hooks.name` stays unique across live and trashed rows** — scoping uniqueness needs a partial
  unique index whose syntax is backend-specific, which `AGENT.MD` forbids. The trade-off is accepted
  and made legible instead: creating a hook whose name a trashed row holds returns `409` naming the
  trashed holder and how to free it. "A hook named X already exists" for a hook the caller just
  deleted and cannot see would be a genuinely baffling error.
- **Execution history of a trashed hook stays visible** in `GET /api/executions`. Preserving it is the
  entire point; hiding it with the hook would defeat the feature.
- **Deleting a privileged hook is master-only**, like every other mutation of one.
- **92 days is not configurable alongside `LOG_RETENTION_DAYS`.** They answer different questions —
  "how much history do we keep?" versus "how long is a mistake reversible?" — and an operator
  shortening log retention to save disk must not silently shrink the undo window for deleted
  automation. This also changed the worker's shutdown contract: it now keeps running when
  `LOG_RETENTION_DAYS=0`, because that means "keep history forever", not "stop maintaining the trash".
  `log_retention_zero_keeps_history_but_still_purges_the_hook_trash` replaces the old test that
  asserted the worker exited.

### 4. SQLite WAL + busy timeout

Applied in `src/db.rs` at startup, **before** migrations (the migration run is itself a long write,
and exactly when a concurrently-starting replica would hit `SQLITE_BUSY`).

Two facts established by reading the vendored SQLx source rather than assuming:

- SQLx's SQLite URL parser accepts only `mode`, `cache`, `immutable`, `vfs` — **not** `journal_mode`
  or `busy_timeout`, so these cannot be smuggled through `DATABASE_URL`.
- SQLx's per-connection `busy_timeout` default is already exactly five seconds.

That matters because the two pragmas have different scopes, and it would be misleading to imply
otherwise:

- **`journal_mode=WAL` is persistent** — recorded in the file header, so one statement covers the
  whole pool and every future run. `wal_and_busy_timeout_are_applied_to_a_file_backed_database`
  asserts it survives reconnection.
- **`busy_timeout` is per-connection.** This statement sets it for the connection that served it; the
  pool-wide guarantee comes from SQLx's default, which this matches and makes explicit rather than
  replaces.

Failures are logged, never fatal: `sqlite::memory:` legitimately reports `journal_mode=memory`, and
the whole test suite runs on it. The pragma call is also the one deliberate exception to the
SQL-agnostic rule, gated on `DatabaseBackend::Sqlite` and documented as such.

**A migration bug this surfaced:** the soft-delete migration originally added all three columns in one
`ALTER TABLE`. `sea-query`'s SQLite backend **panics** on that ("Sqlite doesn't support multiple alter
options") rather than returning an error, so it took down 20+ tests at once. Split into one statement
per column, which is also the only form portable across all three supported backends.

### 5. Tests

| Area | Coverage |
| :--- | :--- |
| Proxy chains | right-to-left peeling, prepended-lie rejection, all-trusted-hops fallback, IPv4-mapped normalization |
| Hostnames | resolution + caching, unresolvable name not trusted, hostname peer trusted end to end, Docker CIDR + hostname coexisting |
| Soft delete | row survives with history and grants intact; every route 404s; trash invisible to non-master |
| Trash management | master view/restore/hard delete; all three refused to a `can_manage` holder |
| Purge | 92-day boundary (91 vs 93 days), overridable window, `0` is a no-op, master-only, negative rejected, background worker sweeps on its own |
| Name reuse | trashed hook holds its name; `409` explains it; freeing the name works |
| WAL | file-backed database reaches WAL and keeps it across reconnection; in-memory is a clean no-op |

E2E §20 was rewritten from "Hook Deletion Cascade" to cover soft delete, the trash, restore, name
retention, and the hard-delete cascade. The main E2E instance now boots with
`TRUSTED_PROXIES=127.0.0.1,localhost` so both spellings — literal and name-resolved — are exercised
against a real DNS lookup rather than a stub.

### Validation

- `cargo check --all-targets` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test` — 60 unit + 90 integration pass (was 54 + 79).
- `./scripts/test_e2e.sh` — 593/593 checks pass (was 554).

### Scope notes

- **`can_manage_groups` has no analogue here.** It belongs to `simply_ip_vault`'s IP-group model;
  this schema has hooks and the `api_key_hook_permission` junction, and the equivalent guards are
  already in place from the previous commit.
- **Tasks 1 (partly) and 2 were already delivered in `2a7e16d`** — the trusted-proxy gate, `bound_ips`
  applying to master keys, and every RBAC guard. Re-verified rather than reimplemented; this round
  added the chain-peeling fix and hostname support on top.
- **No SPA trash UI.** The dashboard's delete button now soft-deletes and the listing hides trashed
  hooks correctly, but there is no screen for viewing or restoring the trash — that was not in scope,
  and the routes are master-only API surface for now. Worth adding.

---

## 2026-08-01 — Read-only comparative security audit vs `simply_ip_vault`

Deliverable: `SECURITY_COMPARISON_REPORT.md`. **No source file was modified**; the only writes this
session were that report and this note. No tests were run.

### What the cross-check found in *our* code (not yet fixed — awaiting arbitration)

- **H-1, ordering (`src/middleware.rs:212–241`).** We evaluate `bound_ips` *before* the signature.
  The reference verifies the HMAC first and documents why: running the network check first lets a
  caller who cannot prove possession of the signing secret learn, from `403` vs `401` alone, whether
  a key it merely guessed is bound to its own network. Free to fix; move the CIDR block below
  `verify_signature`. Note it compounds with H-2 — fixing H-2 alone would make this oracle *newly*
  meaningful rather than mostly moot.
- **H-2, posture (`src/config.rs:385`).** `require_signed_requests` defaults to `false`, so
  `X-API-Key` alone authenticates out of the box. The reference has no such switch and can therefore
  claim "a leaked key is useless without its signing secret". We cannot, by default. Separately,
  `BODY_ONLY` is accepted *inbound* with no timestamp and thus no replay protection at all — the
  reference only ever uses `BODY_ONLY` for *outbound* dispatch.
- **H-3, proportionality (`src/api.rs:2233`).** `update_key_hook_permissions` checks only that the
  caller manages the hook. The reference additionally enforces verb-by-verb: you cannot grant a verb
  you do not hold. A key with `can_manage_keys` + `can_manage` (but not `can_execute`) on a hook can
  mint a key, grant it `can_execute`, and use it. Bounded — `guard_master_for_privileged_hook`
  blocks this entirely for `run_as_user` hooks, and `can_manage` already permits rewriting
  `script_path` — but `can_execute`/`can_manage` are separate columns and an operator will expect
  granting one without the other to mean something.
- **H-4, idempotency (`src/api.rs:343`).** `guard_master_to_grant_scopes` is not baseline-aware:
  it treats any `true` as a grant, so a non-master key manager cannot re-save a key that *already*
  holds `can_manage_hooks` (the dashboard posts every field). The reference passes the target's
  current values as a baseline. Not a vulnerability — the failure is a spurious `403` — but a real
  usability cost with no security benefit, since `requested == held == true` authorizes nothing.

### What the cross-check found in the *reference* (reported, not our code to fix)

- **V-1, high.** The vault signs `uri.path()` and deliberately excludes the query string, on the
  documented premise that query parameters are read-only filters. That premise no longer holds in
  its own code: `DELETE /api/ips/{id}` reads `?hard=true` from the query, and `DELETE /api/ips`
  computes `query_params.merge(body_params)` where the **query wins over the signed body**. So a
  signed request can have `?target_address=…&group_name=…` appended in transit and still verify.
  This is why our `path_and_query` choice is load-bearing rather than stylistic.
- **V-1 interop consequence.** `DEFAULT_HMAC_TEMPLATE` reproduces `canonical_v1_payload`
  byte-for-byte, so a vault `CANONICAL_V1` dispatch is verifiable by our middleware — **only for
  requests with no query string.** Where one is present the two now disagree.
- **V-2, medium.** `VAULT_ENCRYPTION_KEY` SHA-256's any string, so a one-character passphrase yields
  a database that looks encrypted. `open_signing_secret` also returns any unprefixed value verbatim
  *as* the secret. Our `SecretCipher` rejects both cases.

### Where we are ahead, and worth not regressing

- **Hostname hops inside the chain walk.** The reference's `is_literal_network` deliberately skips
  DNS during the walk, so a hop identified only by hostname is treated as a *client* rather than
  skipped. Conservative, but it bites exactly the all-hostname Docker/Traefik deployment that
  hostname support exists to serve. Our merged `Arc<Vec<IpNetwork>>` handles it for free.
- **Body limits.** Ours derives `MAX_SIGNED_BODY_BYTES` *from* `MAX_REQUEST_BODY_BYTES`. The
  reference hard-codes 2 MiB independently of Axum's implicit 2 MiB default — they coincide today by
  accident, and nothing keeps them coincident.
- **Crypto at rest.** XChaCha20's 192-bit random nonce is collision-safe by construction; AES-GCM's
  96-bit nonce needs a birthday argument. Plus length-validated keys, fail-closed prefix parsing,
  cipher built once into `AppState`, and hex-encoded plaintext mode (not greppable in a dump).

### DNS cache trade-off — deliberate divergence, not a defect either way

The reference caches per hostname and caches *nothing* on failure, so a blip costs one request but a
sustained DNS outage fires a lookup per request — request-rate-multiplied amplification against the
resolver. We cache the merged result including partial failure, so a failed name stays untrusted for
up to the 30s TTL (visible as `403`s) but the resolver is hit at most once per TTL. Ours is the
better behaviour under adverse conditions; theirs is more responsive under normal ones. Their
*per-name* structure is the better shape and is worth adopting without adopting their failure
handling.

### Gaps present in both (neither project is ahead)

No replay-nonce cache (identical signed requests replay within the ±300s window); no "last master
key" guard, so two masters can lock each other out with no recovery short of database access;
`TRUSTED_PROXIES=0.0.0.0/0` re-opens full spoofing with only a startup log to notice; a non-master
key manager can widen another non-master key's `bound_ips`; `audit_logs` has no retention sweep.

---

## 2026-08-01 — Convergence pass (shared arbitrated architecture)

Executed in `simply_hook_executor`. Unlike previous rounds this was not "copy the peer" — both
services were told to converge on an arbitrated target that **neither** had fully implemented. I
therefore treated `./example` as a comparison surface, not a template, and in three places this
service is now the conformant side and the peer is the one that must move (see the parity check
below).

### What changed

**1. Fault-tolerant DNS (`src/config.rs`, `src/main.rs`)**

The hostname cache was one merged snapshot on a single 30s clock. It is now **per hostname**, on
two clocks:

- **Positive TTL 30s** — unchanged, and unchanged for the same reason: a container that moves keeps
  its name, so a name cached forever is a trusted-proxy grant pointing at whatever now holds the
  old address.
- **Negative TTL 5s** (`TRUSTED_PROXY_DNS_NEGATIVE_TTL`) — new, and the point of the exercise.
  Without it, one unresolvable entry makes the daemon's *request rate* its *DNS query rate*: every
  inbound request fires a fresh lookup, which is a self-inflicted amplification path that gets worse
  exactly when the resolver is already unhealthy. The write lock is deliberately held across the
  lookups so a burst arriving on an expired entry collapses into a single query rather than one per
  request.

The two windows are asymmetric because their costs are. Over-trusting a stale address is a security
problem, so success expires on the slower-but-still-short clock; an unresolvable name is merely
*untrusted* — the safe direction — so it can be retried aggressively to shorten the outage without
ever widening trust.

`TrustedProxies::prime()` resolves everything unconditionally and returns the failures.
`main::prime_trusted_proxies` calls it at boot, logs an error naming the unresolvable entries, and
schedules **one** re-check after `TRUSTED_PROXY_BOOT_GRACE` (60s) so the log carries a definitive
verdict instead of only the initial pessimistic one. It never aborts. A name that fails at boot is
almost always a sibling container that has not finished starting — this daemon and its reverse proxy
come up in no guaranteed order — and since the entry is already fail-closed, a daemon that keeps
running is strictly more available and no less safe than one that keeps dying.

Distinguishing `resolved` from `networks.is_empty()` matters: a name that resolves to an *empty*
answer is a failure for our purposes and belongs on the negative clock, not held for the full
positive window.

**2. Anti-replay (`src/replay.rs`, new)**

This was the real gap. The timestamp window bounds how *long* a captured request stays useful and
says nothing about how many times it may be used — so anyone able to observe a signed
`POST /api/hooks/{id}/execute` could resend it verbatim and run the hook again, with every existing
check passing. `ReplayGuard` remembers each verified `(api_key_id, digest)` for the length of the
window and refuses a second presentation.

Three decisions worth recording:

- **Record only after verification.** Recording unverified digests would let an observer burn a
  signature before the legitimate client's copy arrived — turning replay protection into a
  denial-of-service primitive aimed at the client it exists to protect. It also means filling the
  map requires producing valid HMACs, i.e. the signing secret, so it is not a memory-exhaustion
  target.
- **Key on raw digest bytes, not header text.** `sha256=AB…` and `sha256=ab…` are the same
  signature; keying on the string would let the same signature be spent twice by re-spelling it.
  `verify_signature` now returns the decoded digest so there is one decode and one representation.
- **Fail closed on a poisoned lock.** A guard that cannot prove a signature is fresh must not claim
  that it is.

`BODY_ONLY` is exempt, selected by `timestamp.is_some()`. That mode carries no timestamp, so there
is no window to be single-use *within*, and per `AGENT.MD` it exists to accept third-party senders
whose format cannot be changed — senders that redeliver on purpose. Tracking them would silently
break GitHub-style redelivery. This is the per-key posture flexibility the brief explicitly keeps
in scope for this service.

**3. Pipeline ordering (`src/middleware.rs`)**

`bound_ips` moved to **after** signature verification. Previously a caller holding only a leaked
`X-API-Key` could tell `403 Client IP not allowed` from `401 Invalid request signature`, and thereby
learn whether a key it had merely found is bound to networks excluding it — a map of the
deployment's topology handed to someone who had proven nothing.

The two findings compound, which is why both were fixed together: with signing optional the oracle
is mostly moot because the bearer key alone authenticates, so tightening the posture *without*
reordering would have made the leak newly meaningful rather than fixing anything.

**4. Memory boundary (`src/lib.rs`)**

`MAX_REQUEST_BODY_BYTES` 1 MiB → **3 MiB**, the converged figure. Already the single constant the
middleware's signing buffer derives from, so there is nothing to keep in sync by hand; the change
was the value plus the rationale for why no per-route override may raise it.

**5. Database & retention (`src/main.rs`, `src/retention.rs`, `src/config.rs`)**

`apply_sqlite_pragmas` already swallowed its own errors, but `main` still called it with `?`, so the
*signature* said "fatal" even though the body never was. Now an explicit `if let Err` with a warning
— the intent is legible at the call site rather than depending on a reader checking the callee.

`DELETED_HOOK_RETENTION_DAYS` is now an environment variable (default 92, `0` = keep forever),
clamped at zero: a negative window would read as "purge everything trashed since the future", and
this is the one query in the system that destroys audit history. It stays **separate** from
`LOG_RETENTION_DAYS` for the reason recorded last round — shortening log retention to reclaim disk
must not silently shrink the undo window for deleted automation.

The purge now states all three guards explicitly (`is_deleted = true AND deleted_at IS NOT NULL AND
deleted_at < threshold`). Two of them are strictly redundant — a live hook has `deleted_at = NULL`
and SQL's three-valued logic already makes `NULL < threshold` evaluate to `NULL` — but making this
query's safety depend on an invariant held elsewhere, or on a reader recalling how `NULL` compares,
is the wrong trade for a few bytes of SQL.

### Crypto audit findings (Task 2) — already compliant, verified rather than changed

Everything in this task was **already** in place, and I confirmed each rather than assuming:

- XChaCha20-Poly1305 with a 192-bit random nonce per operation — `src/crypto.rs`.
- Cipher built once in `main` and held in `AppState.cipher`; no per-request env read. (The peer
  reads `VAULT_ENCRYPTION_KEY` inside `encryption_key()` on every seal and open, i.e. once per
  authenticated request.)
- Fail-closed startup: `SecretCipher::from_env()` returns `Err(InvalidKey)` on anything that is not
  64 hex characters and `main` propagates it. Now covered by
  `a_malformed_key_aborts_startup_instead_of_downgrading_to_plaintext`, which also pins that an
  *empty* value is the documented plaintext fallback rather than a malformed key, and by
  `the_alias_is_honoured_but_validated_just_as_strictly`.
- Constant-time comparison: grepped for `==`/`memcmp`-style comparisons on any signature, secret,
  digest, mac, or token. **None found.** `Mac::verify_slice` is the only signature comparison path.
  The one remaining equality on security-relevant material is `KeyHash.eq(...)` — a database `WHERE`
  on a SHA-256 digest of a 256-bit random key, which is a lookup rather than a secret comparison and
  is preimage-resistant. Left as-is; the peer does the same.

### Test verification — the two headline tests were proven non-vacuous

A passing test that would also pass against the unfixed code is worse than no test. Both headline
regressions were checked by temporarily reintroducing the defect:

- Stubbing `ReplayGuard::check_and_record` to always return `true` →
  `an_intercepted_signed_request_cannot_be_replayed_inside_the_window` fails on the second send.
- Reinstating the CIDR check before the signature →
  `an_unauthenticated_caller_cannot_distinguish_a_bad_key_from_a_bad_source_network` fails with
  `403 != 401`, i.e. it catches exactly the oracle.

Both stubs were reverted immediately.

### Tests that asserted superseded contracts

Three existing tests encoded the *old* behaviour and were rewritten, not extended:

- `an_unresolvable_hostname_is_simply_not_trusted` asserted "with a zero TTL every call
  re-resolves" — which negative caching deliberately breaks. Split into the storm test, the
  expiry test, and a per-domain isolation test.
- `hmac_mode_toggle_takes_effect_immediately_without_a_restart` re-sent the *same* signed request
  three times; every send after the first is now correctly a replay. Each call is now stamped a
  second apart, which keeps the test's actual subject (the mode toggle) intact.
- The payload-limit assertions pinned 1 MiB literals. Now sized from
  `MAX_REQUEST_BODY_BYTES` so the constant cannot move without the test following.

The replay test originally re-read the clock per call, which would have made it pass or fail
depending on whether the two sends straddled a second boundary. Pinned to one captured timestamp.

### Not done, deliberately

- **`SCHEMA.MD` unchanged.** This pass added no columns, tables, or enums. `ReplayGuard` is
  in-memory by design: it must be fast on the hot path, its contents expire within 300s, and
  persisting it would put a write on every authenticated request. The trade-off is that a restart
  clears it — a signature captured immediately before a restart could be replayed immediately
  after, inside its remaining window. Bounded by the window, and the fix (a shared store) would
  cost a round-trip per request; recorded here rather than silently accepted.
- **Signing posture untouched.** `REQUIRE_SIGNED_REQUESTS` still defaults to `false` and the
  per-key `hmac_mode` still offers `BODY_ONLY`. The brief marks this asymmetry intentional and out
  of scope for this service; `AGENT.MD` §1 documents the same. Flagged in the parity check.
- **No SPA trash UI** — still outstanding from the previous round.

### Conflicts with `AGENT.MD`

None. Every change was already consistent with it or is a strictly stronger reading of it, and
`AGENT.MD` was updated to state the new guarantees (two-part anti-replay, authenticate-then-authorize
ordering, §3c the 3 MiB ceiling, per-hostname positive/negative DNS caching plus the boot grace
period, and the configurable hook-retention window). §3b already required non-fatal pragma handling,
so that task was a call-site correction rather than a policy change.

---

## Convergence Parity Check

Side by side against `./example` (`simply_ip_vault`), as of 2026-08-01. Automated by
`scripts/verify_convergence.sh`, which normalizes away plumbing differences and compares what
survives against recorded fingerprints — so an **accepted** divergence stays visible on every run
without failing the check, and a **new** one fails it.

### Pillar 1 — Fault tolerance & production resilience

| Aspect | This service (`simply_hook_executor`) | Peer (`simply_ip_vault`) | Status |
| :--- | :--- | :--- | :--- |
| Hostname support in `TRUSTED_PROXIES` | Yes | Yes | ✅ converged |
| Positive DNS TTL | 30s | 30s | ✅ converged |
| **Negative caching of failures** | **Yes, 5s dedicated TTL** | **No — a failure caches nothing and is retried on every request** | ⚠️ **peer must converge** |
| Cache granularity | Per hostname | Per hostname | ✅ converged |
| Concurrent-lookup collapsing | Yes — write lock held across the lookup | No — each request resolves independently | ⚠️ peer must converge |
| **Boot grace period** | **Yes — error, serve untrusted, re-check at 60s, never abort** | **No boot-time resolution at all; names resolve lazily on first use** | ⚠️ **peer must converge** |
| Unresolvable name is untrusted | Yes | Yes | ✅ converged |
| SQLite pragma failure | **Non-fatal** — logged, startup continues | **Fatal** — propagated with `?` from `main` | ⚠️ **peer must converge** (KNOWN-2) |

The peer's *no negative caching* and *no lookup collapsing* combine into the exact amplification
path this pass was meant to close: under a DNS outage its query rate equals its request rate.

### Pillar 2 — Cryptographic robustness

| Aspect | This service | Peer | Status |
| :--- | :--- | :--- | :--- |
| AEAD at rest | XChaCha20-Poly1305, 192-bit random nonce | AES-GCM-256, 96-bit random nonce | ⚠️ peer must converge |
| Cipher instantiation | Once at startup, held in `AppState` | Per seal/open, re-reads env each call | ⚠️ peer must converge |
| Malformed key at startup | **Hard error** — 64 hex chars required | **Accepts anything** — SHA-256's any passphrase into a key | ⚠️ **peer must converge** |
| Unrecognized stored value | `MalformedCiphertext` error | Returned **verbatim as the secret** | ⚠️ **peer must converge** |
| Plaintext-mode storage | Hex-encoded (`v1.plain.`), not greppable | Stored raw | ⚠️ peer must converge |
| Constant-time MAC comparison | `Mac::verify_slice` | `Mac::verify_slice` | ✅ converged |
| Non-constant-time compares on secrets | None (grepped) | None (grepped) | ✅ converged |
| **Signature covers full URI** | **`path_and_query`** | **`path()` only — query excluded** | ⚠️ **peer must converge** |
| Canonical string construction | `METHOD\nTARGET\nTIMESTAMP\nBODY` | identical | ✅ converged — *verified byte-identical by the script* |
| **Single-use signature enforcement** | **Yes (`src/replay.rs`)** | **No — timestamp window only** | ⚠️ **peer must converge** |
| Anti-replay window | ±300s symmetric, configurable | ±300s symmetric | ✅ converged |

The peer's excluded query string is not theoretical: it serves `DELETE /api/ips/{id}?hard=true`, and
`DELETE /api/ips` merges query parameters **over** the signed body. A signed request can therefore be
rewritten in transit and still verify. Reported in `SECURITY_COMPARISON_REPORT.md` as V-1.

**Interop note.** `canonical_v1_payload` and `signature_base` normalize byte-identical, so a peer
`CANONICAL_V1` dispatch is verifiable by this service's middleware — **but only for requests with no
query string.** Where one is present the two disagree until the peer adopts `path_and_query`.

### Pillar 3 — Strict access control & pipeline ordering

| Aspect | This service | Peer | Status |
| :--- | :--- | :--- | :--- |
| **Authenticate before authorize** | **Yes** — `bound_ips` checked after the signature | Yes | ✅ converged (this service moved) |
| No 401/403 oracle | Enforced, regression-tested | Enforced | ✅ converged |
| `bound_ips` applies to master keys | Yes | Yes | ✅ converged |
| XFF walk: right-to-left, skip trusted | Yes | Yes | ✅ structurally converged |
| **XFF walk skips *hostname* hops** | **Yes** — resolved names are in the list the walk reads | **No** — `is_literal_network` consults only literal CIDRs | ⚠️ **peer must converge** (KNOWN-1) |
| **Router-wide body limit** | **`DefaultBodyLimit::max(3 MiB)`, no per-route override** | **None declared** — inherits Axum's implicit default | ⚠️ **peer must converge** (KNOWN-3) |
| Signature buffer derived from that limit | Yes, same constant | No — independent 2 MiB literal | ⚠️ peer must converge |

KNOWN-1 is the arbitrated spec's "skip exactly the trusted hostname/CIDR hops". The peer's behaviour
is *conservative* (it never trusts an address further left than it should) but it misidentifies the
client in an all-hostname Docker/Traefik deployment — the deployment hostname support exists for.

### Pillar 4 — Retention lifecycle

| Aspect | This service | Peer | Status |
| :--- | :--- | :--- | :--- |
| Soft-deletable resource | `hooks` | `ip_records` | ✅ N/A — different domains, same pattern |
| Retention default | 92 days | 92 days | ✅ converged (verified by value) |
| Configurable via env | `DELETED_HOOK_RETENTION_DAYS` | `IP_RETENTION_DAYS` | ✅ converged in capability |
| Purge guards | `is_deleted = true AND deleted_at IS NOT NULL AND deleted_at < threshold` | `is_deleted = true AND deleted_at < threshold` | ⚠️ peer lacks the explicit `IS NOT NULL` |
| Master-only restore | Yes | Yes | ✅ converged |
| Master-only `?hard=true` | Yes | Yes | ✅ converged |
| Worker survives one window being disabled | Yes | Yes | ✅ converged |

### Pillar 5 — Authentication posture (asymmetric **by design**)

**This asymmetry is intentional and is explicitly out of scope to unify.**

| | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| Role | The more internal, higher-trust service | The externally-reachable webhook receiver |
| HMAC requirement | **Full-URI HMAC + anti-replay, unconditional on every key.** No reduced or no-HMAC mode exists. | **Per-key configurable:** full-HMAC (`CANONICAL_V1`), body-only (`BODY_ONLY`), or bearer-only. |
| Rationale | Its callers are scripts the operator controls (fail2ban, portsentry). Plain bash computes this fine via `openssl dgst -sha256 -hmac`, so there is no operational reason to weaken the path. | It must interoperate with third-party senders (GitHub, Forgejo, GitLab) using their own signing conventions, or none. The flexibility is the feature. |
| Where a key *does* use full HMAC | — | The **same** full-URI canonicalization and the **same** single-use anti-replay apply. Convergence holds inside the mode; only the choice of mode is per-key. |

So the converged rule is not "both services require HMAC" but "**where full-request HMAC is used, it
is identical in both**". `BODY_ONLY` and bearer-only keys on this service are left exactly as
configured, and `REQUIRE_SIGNED_REQUESTS` still defaults to `false` here.

Residual risk, recorded rather than fixed: a `BODY_ONLY` key on this service has **no** replay
protection of any kind, and a bearer-only key has no request integrity at all. Both are documented
in `AGENT.MD` §1 and surfaced in the audit trail by `describe_hmac_mode`, but neither is visible in
the dashboard as a risk marker. Worth adding.

### Running the check

```
scripts/verify_convergence.sh            # 0 = converged (or only known divergences), 1 = drift
scripts/verify_convergence.sh --verbose  # print the normalized text being compared
```

Current: **2 converged, 3 known divergences, 0 drifted, 0 skipped.** Each known divergence is a
row above marked "peer must converge"; when the peer adopts the arbitrated behaviour its fingerprint
will change and the entry should be deleted from both the script and this table rather than
re-recorded.

---

## 2026-08-02 — Post-convergence comparative security audit (read-only)

Re-ran the cross-service comparison against `./example/simply_ip_vault` now that **both** halves of
the convergence pass have landed. Output: `SECURITY_COMPARISON_REPORT.md` (rewritten — the previous
version described this repo at `49d347a`, before `8b70b2c`, and its findings H-1, H-2's body limit,
and "no replay cache" are stale). No source file in `src/` or `./example` was touched; no commit made.

### Reference freshness

`./example/simply_ip_vault` has **no `.git` of its own** — `git -C ./example/… rev-parse HEAD` walks
up and answers with *this* repo's HEAD, and `example/*` is gitignored here, so **no commit hash for
the reference exists on disk**. Closest marker: mtimes of 2026-08-02 11:39–11:46, four to eleven
minutes *after* our own convergence commit `8b70b2c` (11:35:50), plus a "Session 24 — Cross-service
security convergence (`simply_ip_vault` half)" entry in its `AGENT_NOTES.MD` whose claims were spot-
checked against its source and hold. Verdict recorded as **corroborated but not pinned** — not the
stale reference an earlier cross-audit hit.

Caveat worth remembering: **the reference's own parity table is stale about us.** It still describes
this repo as having a 1 MiB body limit, no replay guard, and `bound_ips` before the signature. All
three were closed by `8b70b2c`.

### Result

65 rows compared; 54 equivalent or byte-identical; 1 intentional asymmetry (authentication posture,
not scored); 10 genuine discrepancies, of which 4 are cosmetic. Six worth a future convergence pass:

| # | Finding | Owner |
| :--- | :--- | :--- |
| 1 | Peer's `ReplayGuard` **clears the whole map** at 100k entries (fails open). The map is global across keys, so one key with a valid signing secret can flood it and reopen the replay window for every other key, master included. Ours prunes early and keeps enforcing. | peer |
| 2 | Our `update_key_hook_permissions` checks `guard_manage` on the hook but **not per-verb proportionality** — a `can_manage`-only holder can grant `can_execute` to a second key it controls. Peer's `guard_delegated_group_grant` checks each verb against the caller's own row. | **us** |
| 3 | Peer's `revoke_key_group_permission` has no per-group and no master-target check — any `can_manage_keys` holder can strip any key's access to any group. Our revoke mirrors the grant path via `guard_manage`. | peer |
| 4 | Peer's `SecretCipher::open()` ends in `Ok(stored.to_owned())`, so an unprefixed/corrupted row is used verbatim as the HMAC secret. Ours errors `MalformedCiphertext`. Deliberate AES-migration affordance, but fail-open. | peer |
| 5 | Peer prunes its replay map on *every* `observe` (O(n) per authenticated request); ours sweeps once per `window / 4`. | peer |
| 6 | We validate `X-Timestamp` **after** the API-key DB lookup; the peer validates it before, so a stale timestamp costs it no query. | **us** |

Findings 2 and 6 are the only items on our side and neither is currently exploitable without an
already-privileged key; they are recorded here rather than fixed because this pass was read-only.

### Confirmed converged (spot-checked in source, not taken from either set of notes)

`resolve_client_ip` byte-identical including the hostname-hop skip; `bound_ips` with no master
exemption and placed last in the pipeline on both sides; `path_and_query()` signing with `OriginalUri`
recovery; `Mac::verify_slice` as the only digest comparison in either `src/` (grep-verified, no `==`
on any secret/signature/digest/token); XChaCha20-Poly1305 with a 64-hex-mandatory key that aborts
startup; `DefaultBodyLimit::max(3 MiB)` outside every nest with `MAX_SIGNED_BODY_BYTES` derived from
it; non-fatal SQLite pragmas before migrations; 30s/5s positive/negative DNS TTLs per hostname with a
60s boot grace that never aborts; 92-day purge filtered on all three of `is_deleted`,
`deleted_at IS NOT NULL`, and `deleted_at < threshold`.

---

## 2026-08-02 (session 26) — Per-verb grant proportionality; freshness before the key lookup

The two findings the read-only audit earlier today assigned to *this* side. Both are now closed, so
the only remaining items in that report belong to the peer.

### 1. Per-verb grant proportionality (`src/api.rs`)

`update_key_hook_permissions` asked whether the caller could administer grants on a hook
(`guard_manage`) but never how much of one it could hand out. `can_execute` and `can_manage` are
separate columns in `SCHEMA.MD` precisely so an operator can grant management *without* execution —
and that key could route the missing verb to itself in two requests: mint a second key (it holds
`can_manage_keys`), grant *it* `can_execute` on the hook, authenticate as it, run the hook.

New `guard_delegated_hook_grant` checks **each verb independently** against the caller's own row.
Shape is `wanted && !held`, from which two properties fall out and are tested:

- **Revocation is never blocked** — turning a flag off requests `false`, which cannot exceed
  anything. Removing authority must not need a master.
- **Re-asserting a verb you hold is a no-op**, so an idempotent re-submission still succeeds.

The `can_manage` entry gate moved *inside* the new guard rather than staying a separate
`guard_manage` call, so both questions are answered from **one** permission row. Reading it twice
would let the two answers disagree if a grant were revoked in between. The entry gate's refusal text
is unchanged, deliberately: the two paths must stay indistinguishable to a caller probing them, and
a separate test pins that message so folding the checks together cannot quietly drop one.

Master keys bypass, and `guard_master_for_privileged_hook` still runs afterwards — rights over a
`run_as_user` hook remain master-only even for a caller that legitimately holds both verbs.

### 2. Freshness before the key lookup (`src/middleware.rs`)

`X-Timestamp` was validated after `api_keys` was queried, so every stale capture, broken client
clock and scanner spraying garbage bought an indexed query from a caller that had proven nothing.
New `prevalidate_timestamp_header` runs before the lookup.

**The scope took one correction, and it is the interesting part of this change.** The first
implementation validated the header *whenever present*, on every key. That broke
`body_only_mode_accepts_github_style_webhook_signatures`, which asserts a stray `X-Timestamp` on a
`BODY_ONLY` request is ignored — an existing, deliberate contract, because `AGENT.MD` §1 says that
mode exists for senders whose format cannot be changed. The test was right and the change was wrong:
enforcing a window there would reject a webhook over a header that is not part of its signed
material, and would buy nothing, since `BODY_ONLY` carries no replay protection either way.

The pre-check is therefore scoped to requests carrying `X-Timestamp` **and** `X-Signature-256` —
the shape of a `CANONICAL_V1` request, and the only shape with a window. That is exact rather than
approximate: for a `CANONICAL_V1` key, `X-Signature-256` is the only signature header honoured (the
`X-Hub-Signature-256` downgrade guard sees to that), so every signed request the window applies to
is covered.

**The authoritative check stays in the `CANONICAL_V1` branch and still runs unconditionally.** The
pre-check is an optimization; making it the guarantee would leave the window reachable-but-skipped
if that branch ever accepted a header the pre-check does not inspect. A security property must not
rest on an invariant held two functions apart, and re-parsing an integer is cheap insurance.

`bound_ips` remains last. The ordering is now: client IP → key header present → **timestamp** → key
lookup → signature → replay → `bound_ips`, matching the peer's pipeline exactly.

### Convergence checker re-baselined

`scripts/verify_convergence.sh` was reporting 2 drifted / exit 1 **before** any of today's edits
(verified by stashing them) — the peer's own convergence pass landed after our `8b70b2c` and
invalidated three of its recorded baselines. Two of the rationales had become factually false, which
is worse than a red check:

- **KNOWN-1 retired.** The peer's flat-snapshot restructure retired `is_literal_network`; the chain
  walk is byte-identical now. Fingerprint kept so a *reappearance* of the old shape is drift.
- **KNOWN-2 re-baselined** (`2455903075` → `3743579462`). "Peer aborts startup on pragma failure" is
  no longer true — it converged on non-fatal and went further, returning `()` so the function cannot
  abort by construction, where ours returns a `Result` the caller swallows. Same pragmas, same
  values, same outcome; cosmetic, and worth folding into the next pass that touches `db.rs`.
- **KNOWN-3 retired.** The peer adopted the 3 MiB ceiling and the shared signature-buffer constant.
- **"Signature canonicalization" was a checker bug, not drift.** The normalizer mapped
  `path_and_query` → `TARGET` but left the peer's `target` alone, so identical functions diffed on a
  parameter name. Added the missing rename; both sides now compare equal, which is the truth.

Now 4 converged, 1 known (cosmetic), 0 drifted, exit 0.

### `AGENT.MD` updated

Two directives were extended rather than overridden — both make the document stricter to match the
code, and neither contradicts what was there:

- §1's "Timestamp before HMAC" bullet now states the pre-lookup ordering, its header-shape scope,
  and why the authoritative check stays where it is.
- §2's RBAC matrix gained a row for per-verb proportionality, alongside the existing
  "hook the caller does not `can_manage`" row it builds on.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **176 passed**, 0 failed (75 unit + 101 integration; was 71 + 97) |
| `./scripts/test_e2e.sh` | **632/632**, 0 failed (was 608) |
| `./scripts/verify_convergence.sh` | 4 converged, 1 known, 0 drifted, exit 0 |

New tests: `a_delegated_grant_cannot_exceed_the_verbs_the_caller_holds`,
`granting_on_a_hook_the_caller_does_not_manage_is_still_refused`,
`a_stale_timestamp_is_refused_before_the_api_key_is_looked_up`,
`hoisting_the_window_check_does_not_reach_unsigned_or_body_only_traffic`, four
`prevalidate_timestamp_header` unit tests, and E2E §32 (24 new checks) covering both changes
end-to-end including the "the blocked grant never reached the database" and "the key lookup was
never reached" assertions.

The ordering test asserts on the *message*, not the status: both orderings answer `401`, so only
"does the error name the window or the key lookup?" actually distinguishes them.

---

## 2026-08-02 (session 27) — Dead-code, import, lint-attribute and dependency audit

A maintenance pass that found very little to remove. Recording the *negative* results as carefully
as the changes, because "we looked and there was nothing" is the useful output of an audit like this
— and because the next person to run one should not have to redo the search to learn that.

### What was removed: nothing

Four independent scans, all clean:

- **Unused imports / private dead code.** `cargo clippy --all-targets -- -D warnings` already passes,
  and `unused_imports` and `dead_code` are on by default, so both categories were empty by
  construction. No `use` statement or private item survives unreferenced.
- **Dead `pub` items.** `dead_code` cannot see through `pub` in a library, so this was scanned by
  hand: all 144 `pub` items in `src/` were extracted and counted against a comment-stripped
  concatenation of `src/` + `tests/`. Exactly one had no reference beyond its own definition — see
  below. Everything else resolves to a router wiring, a handler signature, or a test.
- **Dead struct fields and enum variants.** Scanned separately, since the item-level pass misses
  them. Zero hits in either category.
- **Over-broad visibility.** ~40 items are `pub` but referenced only within their own module. All
  are load-bearing: serde payload structs appear in `pub` handler signatures (making them private
  would trip `private_interfaces`), and the migration enums are `pub` by SeaORM convention.

### Lint attributes: none exist

There is no `#[allow(dead_code)]`, `#[allow(unused)]`, or any other lint override anywhere in `src/`
or `tests/`. The only attribute of this family in the tree is `#![warn(missing_docs)]` in `lib.rs`,
which tightens rather than relaxes. `tests/common/mod.rs` documents the deliberate *absence* of
`#![allow(dead_code)]` — an unused helper there is meant to surface as a warning. Nothing to audit,
and nothing to justify keeping.

### Dependencies: all 22 are live, none removed

Every crate in `Cargo.toml` has real references. `#![warn(unused_crate_dependencies)]` was tried and
is **the wrong tool here**: it is per-target, so with one shared `[dependencies]` table it reports
each target's counterpart crates as unused — it flagged `hex`, `sha2` and `hmac`, all of which the
library uses heavily, merely because the binary does not. Its output was discarded in favour of the
reference count.

One dependency needed documenting rather than deleting. **`log` is used exactly once**, at
`src/main.rs:227`, because `ConnectOptions::sqlx_logging_level` takes a `log::LevelFilter` and
naming that type requires a direct dependency. Every diagnostic in this codebase goes through
`tracing`, so `log` reads as a superseded second logging stack and is the one entry a future cleanup
would plausibly delete on sight. A comment in `Cargo.toml` now says why it stays.

### The one dead item: `TrustedProxies::with_ttl`

`src/config.rs` carried a `pub fn with_ttl` with no caller. It is a test-facing builder whose
sibling `with_negative_ttl` is used three times; it was orphaned in session 25, when the negative-TTL
tests replaced the older test that had been its only user.

**Resolved by restoring its purpose rather than deleting it,** because deleting it would have
cemented a real coverage gap. `hostnames_resolve_to_their_addresses_and_are_cached` already asserts
a successful resolution is *reused* inside the window, but nothing asserted it is ever *re-queried*
— and that is the more security-relevant direction. `TRUSTED_PROXY_DNS_TTL` is the window in which a
recreated container keeps its **old** address trusted, an address the orchestrator may already have
reassigned. `AGENT.MD` accepts 30s precisely because it expires; a positive entry that never lapsed
would become a standing grant to whoever inherited the address, clearable only by a restart.

New test `a_successful_resolution_is_re_queried_once_its_positive_ttl_expires` uses `with_ttl` and
mirrors `a_failed_resolution_is_retried_once_its_negative_ttl_expires`, reading the same fresh-`Arc`
signal in the opposite direction. It was mutation-checked rather than assumed: making `is_fresh`
return `true` for resolved entries fails it, and reverting passes it.

Deleting `with_ttl` instead remains a defensible call — it is three lines to remove along with the
test — but it trades a tested window for a smaller surface, which is the wrong direction for a
security-relevant one.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **177 passed**, 0 failed (76 unit + 101 integration; +1 unit) |
| `./scripts/test_e2e.sh` | **632/632**, 0 failed |
| `./scripts/verify_convergence.sh` | 4 converged, 1 known, 0 drifted, exit 0 |

---

## 2026-08-02 (session 28) — WebUI simplified to mandate full-HMAC (`CANONICAL_V1`)

Backend untouched: no file under `src/` changed. The dashboard is a first-party client whose key we
provision ourselves, so it is now held to the strongest posture the backend offers instead of the
most permissive one it accepts.

### What the client used to do

Three signing postures, chosen at runtime:

1. **Unsigned** — no signing secret entered, so `apiFetch` sent `X-API-Key` alone. The login form
   labelled the secret *"(optional)"*, which is what made this the default in practice.
2. **`BODY_ONLY`** — `verifyAuth` read `hmac_mode` off `GET /api/auth/me` and *rebuilt the signer to
   match the server's opinion of the key*. A dashboard logged in with a `BODY_ONLY` key therefore
   signed the body alone, silently giving up the timestamp window and the single-use guard in
   `src/replay.rs`, with no indication in the UI that it had done so.
3. **`CANONICAL_V1`** — the intended path.

### What it does now

One posture. `apiFetch` signs unconditionally and builds the request *inside* the `try`, so a signing
failure throws instead of falling through into an unsigned request. `options.headers` is spread
**before** the three authentication headers, so a caller cannot override them by accident.

`RequestSigner` lost its `hmacMode` parameter and its `BODY_ONLY` branch; `verifyAuth` no longer
adopts the server's mode. Because `GET /api/auth/me` is itself signed, reaching the dashboard now
proves the caller holds the signing secret rather than merely that the key exists.

`init` also discards a stored key with no stored secret — a half-session left by the previous build,
which could not sign and would only produce a `401` the user could not interpret.

### The pure-JS SHA-256 fallback was removed — and that is a real trade

`PureCrypto` was ~130 lines of hand-written FIPS 180-4 SHA-256 + RFC 2104 HMAC, self-tested against
an RFC 4231 vector, used when `crypto.subtle` was absent. It existed for one reason: **Web Crypto is
exposed only in a secure context**, so a dashboard reached at `http://192.168.x.x:3000` has no
`crypto.subtle` at all.

Removing it is the largest single complexity win in the file (231 lines deleted, 110 added) and was
explicitly requested. The cost is stated plainly rather than buried: **a plain-HTTP LAN dashboard no
longer works.** It is not left to fail mysteriously — `SecureContextGate` is checked before anything
else in `init`, the login form is disabled, and the screen says to use HTTPS or `localhost`.

Worth recording for whoever revisits this: `simply_ip_vault` — the higher-trust service — **kept** its
equivalent fallback for exactly this reason. If this daemon is ever deployed behind plain HTTP, the
implementation is recoverable from git history (`git show e1669a5:static/app.js`), and restoring it is
contained: it is one IIFE plus a branch in `RequestSigner.digest`. That is a deployment decision, not
a security one — the pure-JS path produced a byte-identical `CANONICAL_V1` signature.

### What deliberately stayed

`BODY_ONLY` remains a permanent backend feature (`AGENT.MD` §1) for third-party webhook senders whose
signing format we do not control. The dashboard still **provisions** it (the create/edit key
dropdowns) and **displays** it (`hmacModeBadge`, which flags it as the mode without replay
protection). What it no longer does is use it for its own traffic. Consequence to be aware of: a
`BODY_ONLY` key can no longer log into the dashboard, which the login hint now states.

`AGENT.MD` §6 was rewritten — it still described the SPA as authenticating with `X-API-Key` alone.

### `scripts/test_e2e.sh` §33 (16 checks)

There is no JS runtime and no headless browser here (`AGENT.MD` forbids frontend dependencies), so
the posture is pinned by source invariants plus one live round-trip, in the same style as §26.

The guards were **mutation-checked against the previous build** rather than assumed — `git show
HEAD:static/app.js` was run through each pattern, and 8 of 9 fire on it:

| Guard | Fires on the old build? |
| :--- | :--- |
| `this\.hmacMode\b` absent | yes |
| `signatureHeaders` absent | yes |
| `PureCrypto` absent | yes |
| `new RequestSigner(secret, mode)` absent | yes |
| `...(this.apiKey ? …)` absent | yes |
| canonical string in field order | yes |
| `login-signing-secret` is `required` | yes |
| no *"Signing Secret (optional)"* hint | yes |
| `X-Hub-Signature-256` absent | **no — vacuous** |

The last one never fired: the old SPA did not send that header either. It is kept as a forward-looking
guard, not a regression guard, and is recorded as such so nobody mistakes it for proven coverage.

Two patterns are anchored with `\b` for a reason found the hard way — a bare `grep -F hmacMode`
matches `this.hmacModeBadge(...)`, and `=== 'BODY_ONLY'` matches the badge renderer. Both are display
code for *other* keys and must keep working; the first version of these checks failed on exactly that.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **177 passed**, 0 failed (76 unit + 101 integration) |
| `./scripts/test_e2e.sh` | **652/652**, 0 failed (+20) |
| `./scripts/verify_convergence.sh` | 4 converged, 1 known, 0 drifted, exit 0 |

JS syntax was verified structurally (bracket/string/template/comment-aware balance check) rather than
by execution: no `node`, `deno`, `bun` or other JS engine is installed on this machine, and `AGENT.MD`
forbids adding one.

---

## Session 29 — final alignment pass

Six items from the closing audit, in one pass: the WebUI HTTP fallback, a hard-fail on malformed
proxy syntax, RBAC revoke alignment, the replay capacity backoff, a tightened ciphertext assertion,
and property rules in the convergence verifier.

### 1. `PureCrypto` restored as a fallback (`static/app.js`)

Session 28 removed it. That was the wrong trade and this reverses it.

The reasoning last time was that "remove any fallback" plus "use `window.crypto.subtle`" meant one
implementation. But the thing that must be mandatory is the **signature**, not the code path that
computes it — and `crypto.subtle` is exposed only in a secure context, so removing the fallback
silently made every plain-HTTP LAN deployment unusable. That is a deployment constraint being
enforced as if it were an authentication policy. `simply_ip_vault`, the higher-trust service, kept
its equivalent throughout.

What is restored is the same ~130-line IIFE (FIPS 180-4 SHA-256 + RFC 2104 HMAC, no dependencies),
recovered from `git show e1669a5:static/app.js`. What is **not** restored is any relaxation of the
posture: `CANONICAL_V1` signing is still unconditional, there is still no unsigned path, no
bearer-only path, and no per-key mode selection in the browser.

The selection logic is new. `SecureContextGate` became `SigningBackend`:

- `usesWebCrypto` — a getter, so nothing depends on script load order.
- `available` — memoized; `usesWebCrypto || PureCrypto.selfTest()`. The self-test is an RFC 4231
  vector, checked before the fallback is ever trusted with a real credential. An implementation that
  cannot reproduce a published vector must not sign, and failing at the login screen beats emitting
  signatures the server rejects for reasons the operator cannot see.
- The `init()` gate survives, but now fires only when *both* are unusable — a broken build rather
  than an ordinary deployment.

`RequestSigner.digest()` branches on `usesWebCrypto` and renders **both** paths through
`PureCrypto.toHex`. One encoder, so the branch decides only how the MAC is computed and never how it
is spelled.

**Verification without a JS runtime.** There is still no `node`/`deno`/`bun` on this machine and
`AGENT.MD` forbids adding one, so the restored code was checked two ways. Structurally, by a
comment/string/template/regex-aware bracket balance check (also run against the peer's `app.js` as a
known-good control). Behaviourally, by transliterating `PureCrypto` statement-for-statement into
Python and differentially testing it against `hashlib`/`hmac`: 135 SHA-256 lengths spanning every
padding boundary (0, 55, 56, 63, 64, 119, 120, multi-block), 64 HMAC key/message combinations
including keys longer than the 64-byte block (which must be hashed down first), the exact
`CANONICAL_V1` string shape with a UTF-8 body, and the self-test vector. All matched.

### 2. `TRUSTED_PROXIES` syntax is fatal (`src/config.rs`, `src/main.rs`)

Split into two failures that look alike in a config file and are not alike at all — **typo versus
timing**:

| | Syntax error (`10.0.0.0/8x`) | Unresolvable name (`traefik`) |
| :--- | :--- | :--- |
| Fixable by | a human editing configuration | itself, in seconds |
| Cost of serving | operator believes a proxy is trusted while it is not | none; already fail-closed |
| Behaviour | **abort startup** | serve, negative-cache, 60s grace re-check |

The old behaviour dropped a malformed entry with a warning. That is a security boundary configured
one way and enforced another: every request through the untrusted-by-accident proxy is authorized
against the *proxy's* address rather than the client's, so `bound_ips` quietly stops meaning what it
says and `audit_logs.client_ip` records the wrong caller.

- `is_hostname_like` became `hostname_rejection`, returning *why* — the reason is what makes the
  abort actionable. `is_hostname_like` remains as a `#[cfg(test)]` predicate.
- `parse_trusted_proxies` → `Result`; `filter_map` → `map` + `collect::<Result<_,_>>`, so **one bad
  entry condemns the list**. A partially-applied trust boundary is precisely the ambiguity refused.
- `RuntimeConfig::from_env()` → `Result`, propagating only this one class of failure. Every other
  override stays lenient, because every other override has a safe substitute.
- **`main` now reads config before opening the database.** A refused boot applies no migrations and
  mints/prints no bootstrap master key.
- Not `?` in `main`: returning the error would render it through `Debug` and print the struct. It is
  logged through `Display` and the process exits 1, so the required `FATAL: …` text actually appears.

### 3. Revoke-Authority Convergence (`src/api.rs`)

> **Superseded.** This section replaces the "RBAC revoke alignment" writeup that stood here. That
> change added per-verb proportionality and a self-revocation block to `revoke_key_hook_permission`;
> both have been **removed**. What follows is the final decision, not a record of the intermediate
> one.

**The rule: `can_manage` on the hook confers full revoke authority — every verb, every key, including
the caller's own row — on both the `DELETE` path and the `POST`/grant path.**

#### Why the lower bar is correct, not an oversight

Granting and revoking are not mirror images, and building them as if they were was the error.

Granting has to prove authority because it can **manufacture** a capability the caller was never
given: a `can_manage`-only holder writing `can_execute` onto a second key it controls, then
authenticating as that key, obtains in two requests a verb an operator deliberately withheld. That is
escalation, and `guard_delegated_hook_grant` correctly refuses it verb by verb.

Revoking has nothing to prove. Turning a flag off is a request for `false`, and **`false` exceeds
nothing**. Whoever asks and whatever they hold, the outcome is a strict de-escalation of the target
key. There is no state reachable by revocation in which anyone ends up with more authority than they
started with — including the revoker, which the test asserts directly: stripping another key's
`can_execute` does not confer `can_execute` on you.

So the stricter guard was protecting against a category of harm that this operation cannot cause.

#### Why it was actively harmful, not merely redundant

`POST /api/keys/{id}/permissions` can write `can_execute: false` onto an existing row, and `AGENT.MD`
permits it under "revoking is always allowed". `DELETE` reaches the same end state by removing the
row. Two spellings, one operation — so a restriction on only one of them is not a restriction at all,
just a detour. A caller refused by `DELETE` re-issues the request as `POST` and succeeds.

That is worse than having no rule. It presents as a security boundary while enforcing nothing, and it
makes two routes to one outcome disagree about who may take them — which reads as a bug to everyone
who meets it and invites someone to "fix" it by tightening `POST`, spreading the mistake instead of
removing it.

The self-revocation block failed the same way, plus one more: it reasoned by analogy with
self-*granting*, which genuinely is escalation. The analogy does not survive the direction change. Its
only practical effect was that a key could not clean up after itself without finding a master.

#### What still holds

The entry gate — `can_manage` on the hook — is untouched, and it is where the real weight sits.
Revocation needs no authority over the *verbs*, but it still needs authority over the *hook*.
Otherwise any key manager could disable automation belonging to a tenant it has no relationship with.
That is the genuine exposure on this path, and it is an **integrity** concern, never an escalation
one. Naming it precisely matters: the guard exists to stop someone's automation being switched off,
not to stop anyone gaining anything.

This also restores convergence with `simply_ip_vault`, whose group-permission revoke has always
required only the manage verb.

#### The counterpart safeguard: ungoverned hooks

Allowing self-revocation makes a new state reachable — the last manager drops its own grant and **no
permission row references the hook at all**. If a master's view were derived from those rows, the hook
would vanish from the API at the moment it became ungoverned, recoverable only by opening the
database by hand.

Verified that it does not: `visible_hook_ids` returns `None` for a master (no `IN` filter is applied
at all), and `guard_visibility` / `guard_manage` / `guard_execute` each return early before any
row is read. A master's view is authority over the deployment, not a grant within it. **No fix was
needed**, but the property was previously untested, which is how it would have been lost.

`an_ungoverned_hook_stays_visible_and_manageable_by_a_master` now drives the whole path: last manager
self-revokes → ex-manager sees nothing (`GET /api/hooks` empty, direct fetch `403`) → master still
lists it, reads it by UUID *and* by name, executes it, and re-grants on it → the manager sees it
again. Mutation-tested by disabling the `is_master` short-circuit in `visible_hook_ids`, which fails
the test, so it is not vacuous.

#### Addendum — the `can_manage_keys` grant override

A later pass added a **global administrative route** to the grant path, so both directions now read:

| Caller | Grant | Revoke |
| :--- | :--- | :--- |
| `is_master` | unconditional | unconditional |
| `can_manage_keys` | unconditional (non-privileged hooks) | unconditional |
| Local manager (`can_manage` on the hook) | per-verb: may hand out only verbs it holds | unconditional on that hook |
| Neither | refused before any lookup | refused before any lookup |

Three things about it are worth recording precisely, because two of them contradict the brief that
requested the change.

**1. It required making local managers reachable at all.** Both handlers previously opened with
`if !key.is_master && !key.can_manage_keys { return 403 }`. Every non-master caller that reached
`guard_delegated_hook_grant` therefore *already* held `can_manage_keys` — so adding "`can_manage_keys`
bypasses" on its own would have made the per-verb guard unreachable dead code and deleted the
least-privilege rule outright rather than scoping it. The entry gates were widened to
`is_master || can_manage_keys || manages_any_hook(..)` so that "local manager" became a real,
reachable population for the guard to govern. `manages_any_hook` is a coarse indexed pre-check whose
only job is to keep a caller with no standing from distinguishing `404` (key exists) from `403` by
aiming the endpoint at invented UUIDs.

**2. The revoke path was not "already `can_manage_keys` OR per-hook `can_manage`" — it was AND.** A
`can_manage_keys` holder with no row on the hook could not revoke before this change, so the
"regression check" for it was really a new capability. It now takes the same override route as grant,
which is what keeps the two directions agreeing about who may act.

**3. This moves *away* from `simply_ip_vault`, not toward it.** The peer's
`guard_delegated_group_grant` bypasses for `is_master` **only**; `can_manage_keys` is bound by
per-group verb holding exactly like anyone else, and its doc comment names the resulting escalation as
the reason. The peer also applies that same predicate to *revocation* (it passes the grant being
deleted through the grant guard with `action = "revoke"`). So on both counts the peer is now the
stricter of the two services. The claim in the section above that the revoke relaxation "restores
convergence with `simply_ip_vault`" was wrong when written and is corrected here: `simply_hook_executor`
is deliberately the more permissive service on hook-permission administration, and that asymmetry
should be treated as intentional rather than as drift to reconcile.

**What the override costs, stated plainly.** `can_manage_keys` can mint a key, grant it any verb on
any non-privileged hook, and authenticate as it — so the scope is *transitively* able to execute any
non-privileged hook, and per-hook RBAC does not constrain it. It should be read as "deputy master
over non-privileged hooks". Two bounds remain and are tested: `guard_master_for_privileged_hook`
keeps every hook carrying `run_as_user` master-only, and self-granting is still refused, so the
escalation always costs a second credential and leaves two audit entries.

Four existing tests had to be rewritten, and the reason is itself the lesson: each seeded its actor
with `seed_key_manager` (which carries `can_manage_keys`) and then asserted a *per-hook* refusal.
Under the override those actors take the global route, so every one of those assertions became
vacuous — passing for the wrong reason, or failing loudly, which is how they were caught. A
`seed_local_manager` helper now exists specifically so the per-hook rules are tested against the
population that they govern.

#### E2E coverage for the revoke rules

The gap flagged in the previous entry — "the HTTP-level coverage for this rule lives entirely in the
integration suite" — is closed. New §33 (*Revoke authority: can_manage is the whole requirement*), 27
checks against the running daemon:

- a `can_manage`-only holder revokes a verb it does not itself hold, via **`DELETE`** *and* via
  **`POST`** with a reduced set — the two routes asserted permitted for the identical
  actor/target/hook, which is the anti-asymmetry property the whole rule turns on;
- the target is refused execution (`403`) afterwards, so the revocation is real over the wire and not
  merely accepted;
- the revoker does **not** gain the verb it stripped;
- a caller lacking `can_manage` on that hook is refused on both routes, and the blocked revocations
  are shown not to have landed;
- self-revocation succeeds, then the ex-manager can no longer administer the hook, and a master can
  still see and re-govern the now-ungoverned hook.

Self-reduction runs **last** in the section by construction: every earlier check depends on the local
manager still holding `can_manage`, so dropping it earlier would silently invalidate everything after
it. The same ordering rule is why the §33 master-visibility checks sit after the self-revocation
rather than before.

Two pre-existing e2e blocks needed the same treatment as the integration tests — the proportionality
delegator and the Finding #3 key manager were both created with `can_manage_keys` and were therefore
asserting refusals that the override now permits.

#### Tests

| Test | Asserts |
| :--- | :--- |
| `a_can_manage_holder_may_revoke_a_verb_it_does_not_itself_hold` | `204`, the revocation lands, and the revoker gains nothing |
| `a_key_may_revoke_its_own_hook_permissions` | self-revocation succeeds; re-granting to self is still `403` |
| `delete_and_post_revocation_paths_agree_on_who_may_revoke` | identical actor/target/hook, both routes permitted — no asymmetry |
| `an_ungoverned_hook_stays_visible_and_manageable_by_a_master` | list, read, execute, re-grant with zero permission rows |
| `revoking_on_a_hook_the_caller_does_not_manage_is_refused` | *(kept)* the entry gate, the one real control here |
| `a_local_managers_delegated_grant_cannot_exceed_the_verbs_it_holds` | per-verb rule, against a local manager (the population it governs) |
| `granting_on_a_hook_the_caller_does_not_manage_is_still_refused` | per-hook entry gate on the grant path |
| `a_can_manage_keys_holder_may_grant_on_any_hook_without_holding_a_row` | the override: grants and revokes with no row; still barred from privileged hooks and self-grants |
| `a_caller_managing_nothing_is_refused_before_the_target_key_is_looked_up` | no standing ⇒ `403` before the key lookup, so the endpoint is not a UUID oracle |

The first two are the exact inverse of last session's assertions on the same fixtures, so they cannot
pass under the reverted code.

### 4. Replay capacity backoff (`src/replay.rs`)

`CAPACITY_BACKOFF_DIVISOR = 16`, converging on the peer's design. A saturated map whose entries are
all still live previously swept on *every* request — an O(n) retain under the global mutex that
freed nothing, turning memory pressure into a throughput collapse exactly when the daemon is
busiest. `next_prune: Mutex<Instant>` became `schedule: Mutex<PruneSchedule>` holding both due-times
under one lock, so two threads arriving together cannot each decide it is the one that sweeps.
`next_capacity` starts at `now`, not `now + backoff`: the first time the ceiling is reached the
sweep must be immediate.

Also switched `std::time::Instant` → `tokio::time::Instant` (same monotonic source in production;
pausable under test) and added `tokio = { features = ["full", "test-util"] }` to **dev**-dependencies
only. `tracked()` is now `#[cfg(test)]` rather than `pub`.

Three new tests, all `#[tokio::test(start_paused = true)]`, so 250k-entry saturation runs in 0.3s
instead of sleeping out a real window:

| Test | Asserts |
| :--- | :--- |
| `reaching_capacity_sweeps_and_warns_but_never_flushes` | the map grows past the ceiling; pre-existing entries stay enforced |
| `a_saturated_guard_backs_off_instead_of_sweeping_every_request` | the sweep is deferred by `window/16`, and requests inside the backoff do not re-arm it |
| `a_saturated_guard_recovers_once_its_entries_expire` | the map returns to normal size on its own |

`entries_expire_and_are_swept` lost its 1.1s real sleep.

### 5. Ciphertext assertion tightened (`src/crypto.rs`)

`malformed_keys_and_values_are_rejected` now matches `CryptoError::MalformedCiphertext` explicitly
and covers nine inputs (up from four): wrong-width nonce, empty nonce, invalid nonce hex, a foreign
`aesgcm256:` format, and a wrong-case prefix. `is_err()` would have kept passing if the prefix check
were ever loosened into a fall-through that reached the cipher and failed *authentication* instead —
same red/green, materially different code path, and one that accepts formats `open()` must refuse.

### 6. Convergence verifier property rules (`scripts/verify_convergence.sh`)

`assert_absent` / `assert_present`, plus `production_source()` which strips comments and truncates at
the first **column-zero** `#[cfg(test)]` (anchored, so an item-level `#[cfg(test)]` does not blind
the rule to code below it).

Why these are needed alongside the diffs: a function-level diff only fires when the two trees
*disagree*, so a bug introduced in both — by the same person converging them on the same wrong idea —
normalizes identical and reports OK. The peer's `seen.clear()` regression is exactly that shape.

Ten rules, each **mutation-tested** by building a mutated copy of the tree under a scratch directory
(the real repo was never modified) and confirming the rule reports DRIFT:

| Rule | Mutation injected | Caught |
| :--- | :--- | :--- |
| Replay map is never flushed | `retain` → `seen.clear()` | ✅ |
| Replay capacity sweep is throttled | constant renamed away | ✅ |
| Replay digests are not compared as text | `digest.to_lowercase()` added | ✅ |
| Signature comparison is constant-time | `verify_slice` → `==` | ✅ |
| Signature verification uses verify_slice | same | ✅ |
| SQLite pragma failure is never fatal | `panic!` added | ✅ |
| Hooks are never spawned through a shell | `Command::new("/bin/sh")` added | ✅ |
| Canonicalization reads the original URI | `OriginalUri` → `http::Uri` | ✅ |

Two rules (`pragma failure is surfaced to the caller`, `sudo is invoked by absolute path`) are
present-checks on stable text and were not separately mutated.

One false start worth recording: `assert_present` first used `grep -q` in a pipeline. Under
`pipefail`, `-q` exits on the first match, SIGPIPEs the upstream `awk`/`sed`, and the pipeline
reports a **found** pattern as a failed command — so every satisfied rule read as DRIFT. Both helpers
now capture through a substitution instead.

### e2e additions

New §33 (*TRUSTED_PROXIES syntax is fatal, unresolvable names are not*), 7 checks, asserted against
the **real binary** rather than the parser, because "refuses to start" is a property of the process:
exit code 1, both halves of the message verbatim, no database file created, no partial trust boundary
applied — and, for contrast, a well-formed-but-unresolvable name that still serves.

§33 (WebUI) renumbered to §34. `PureCrypto` was removed from its forbidden-pattern loop and is now
asserted **positively**, alongside: Web Crypto still preferred, the RFC 4231 self-test present and
gating, exactly two `PureCrypto.toHex(` call sites, and exactly one hex encoder defined.

Of the 7 new WebUI guards, 6 fire against the pre-restore build. The "exactly one hex encoder" guard
does not — that build also had exactly one — so it is a forward-looking guard against a future second
encoder, not proven coverage. Recorded as such, same as §34's `X-Hub-Signature-256` guard.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **185 passed**, 0 failed (81 unit + 104 integration; was 177) |
| `./scripts/test_e2e.sh` | **665/665**, 0 failed (was 652) |
| `./scripts/verify_convergence.sh` | 14 converged, 1 known, 0 drifted, exit 0 |

Re-run after the Revoke-Authority Convergence revision above (§3), which is the state of the tree as
committed:

| Gate | Result |
| :--- | :--- |
| `cargo check` / `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **187 passed**, 0 failed (81 unit + 106 integration) |
| `./scripts/test_e2e.sh` | **665/665**, 0 failed |
| `./scripts/verify_convergence.sh` | 14 converged, 1 known, 0 drifted, exit 0 |

After the `can_manage_keys` override and the new e2e §33:

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` / `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **189 passed**, 0 failed (81 unit + 108 integration) |
| `./scripts/test_e2e.sh` | **698/698**, 0 failed (+33) |
| `./scripts/verify_convergence.sh` | 14 converged, 1 known, 0 drifted, exit 0 |

The integration count moves 104 → 106: two of last session's revoke tests were rewritten as their
inverse rather than added to, and three new ones landed (`delete_and_post_revocation_paths_agree…`,
`a_key_may_revoke_its_own_hook_permissions`, `an_ungoverned_hook_stays_visible…`). The e2e total is
unchanged because the revoke rules were never asserted at that layer — worth noting as a gap, not a
pass: the HTTP-level coverage for this rule lives entirely in the integration suite.

---

## RBAC_MODEL Gap Analysis

Read-only pass against `RBAC_MODEL.md`. **Every verdict below was checked against `src/` directly**,
not against `AGENT.MD`, this file, or commit history — several of which are now known to describe
behaviour the code does not have. No handler, guard, migration or entity was modified.

Scale, stated up front so the next pass is not surprised by it: of 7 numbered rules and 5
specification sections, **2 comply, 5 are violated, and 8 are not implemented at all**. Three of the
absent items are schema-level (`parent_key_id`, `owner_key_id`, the partial unique index), so this is
a migration-bearing change, not a handler-only one.

### Core Rules

**R1, R2, R5, R6 and R7 RESOLVED in Phase 1** — see "Phase 1 — R1/R2/R4/R6/R7" below. R3 remains
open and is Phase 2's subject. Original verdicts retained for the record.

| Rule | Verdict | Evidence |
| :--- | :--- | :--- |
| **R1 — Non-amplification** | ~~**VIOLATES**~~ → **RESOLVED** | `guard_delegated_hook_grant` (`src/api.rs:461`) opens `if key.is_master \|\| key.can_manage_keys { return Ok(()) }`. The per-verb `wanted && !held` comparison below it is therefore reached only by callers *without* `can_manage_keys`. A `can_manage_keys` holder grants any verb on any non-privileged hook regardless of what it holds. |
| **R2 — Manage is a conjunction** | ~~**VIOLATES**~~ → **RESOLVED** | Same line, plus `revoke_key_hook_permission` (`src/api.rs:2366`): `if !key.is_master && !key.can_manage_keys { guard_manage(..) }`. `can_manage_keys` alone is currently sufficient on **both** paths — the exact global bypass R2 forbids. This is commit `2d62d1b`, and R2 replaces it. |
| **R3 — Parentage confers no authority** | ~~**DOES NOT IMPLEMENT**~~ → **RESOLVED** (Phase 2) | No `parent_key_id` column exists on `api_keys` (`src/entities/api_key.rs`, fields at lines 43–83). Vacuously unviolated: no authority *can* be derived from parentage because parentage is not recorded. Nothing to remove; the column and its cascade/visibility semantics have to be added. |
| **R4 — Only master creates parents** | **COMPLIES** | `guard_master_to_grant_scopes` (`src/api.rs:343`) returns early for master and otherwise refuses any request setting `is_master`, `can_manage_keys` or `can_manage_hooks` to `true`. Enforced on both create and update. Note the naming difference: this service's resource-creation right is `can_manage_hooks`, which the model calls `can_create_hooks`. |
| **R5 — Manage may propagate sideways** | ~~**VIOLATES**~~ → **RESOLVED** | Sideways propagation itself works, but not *bounded by R1 and R2* as R5 requires — the `can_manage_keys` bypass in `guard_delegated_hook_grant` means a parent can grant manage on a resource it holds nothing on. Also unenforceable in the intended form while "parent" is not a modelled tier (see R3). |
| **R6 — Revocation is never escalation** | **COMPLIES** (re-scoped by R2 in Phase 1) | `revoke_key_hook_permission` requires only manage on the hook (`guard_manage`, `src/api.rs:2388`), does not compare verbs, and has no self-revocation block. The "regardless of which endpoint it arrives at" clause holds too: `update_key_hook_permissions` reduces a row through the `wanted && !held` shape, which never fires on a `false`. |
| **R7 — Granting bounded by R1 and R2 together** | ~~**VIOLATES**~~ → **RESOLVED** | Follows directly from R1 and R2 both being violated by the same early return. |

### Ownership and Resource Lifecycle

**RESOLVED in Phase 2.** Original verdicts retained for the record.

| Item | Verdict | Evidence |
| :--- | :--- | :--- |
| `owner_key_id` on every resource | **DOES NOT IMPLEMENT** | Absent from `src/entities/hook.rs` (fields at lines 12–47) and from every migration in `src/migration/`. Ownership is not a concept this service has. |
| Lifecycle restricted to master + owner | **VIOLATES** | `delete_hook` (`src/api.rs:1157`) and `update_hook` authorize on `guard_manage`, so any manage-row holder can delete or rename a hook it does not own. This is precisely the "a parent that merely uses a hook must not be able to delete it" case. |
| Master may reassign `owner_key_id` | **DOES NOT IMPLEMENT** | No owner column, so no reassignment endpoint. |

### Visibility

**RESOLVED in Phase 3.** Original verdicts retained for the record.

| Item | Verdict | Evidence |
| :--- | :--- | :--- |
| Master sees everything | **COMPLIES** | `visible_hook_ids` (`src/api.rs:262`) returns `None` for master, applying no filter; `guard_visibility` short-circuits. Asserted by `an_ungoverned_hook_stays_visible_and_manageable_by_a_master`. |
| Parent sees its own subtree | **DOES NOT IMPLEMENT** | No subtree exists to scope to (R3). `list_api_keys` (`src/api.rs:2063`) returns **every key in the deployment** to any `can_manage_keys` holder, unscoped. |
| Shared-resource keys visible in minimal form only | **VIOLATES** | `ApiKeySummary` (`src/api.rs:1914`) carries `bound_ips`, `is_master`, `can_manage_keys`, `can_manage_hooks`, `max_concurrent_jobs`, `hmac_mode` and the full `hook_permissions` list, and `list_api_keys` hands that to every key manager for every key. This is exactly the keyhole the model forbids: one shared hook exposes another parent's entire configuration. |
| Executors visible to creator + master only | **DOES NOT IMPLEMENT** | This service has no separate Executor/Webhook resource; hooks are the executable resource and are governed by permission rows. Worth an explicit decision in the next pass rather than silent omission. |
| 404 vs 403 oracle discipline | **VIOLATES** | `get_hook` (`src/api.rs:1068`) calls `resolve_hook` first — `404` when the row is absent — then `guard_visibility`, which returns `403`. The two are distinguishable, so a caller can confirm a hook exists without being able to see it. Same shape in `delete_api_key`/`update_api_key`, which `404` on an unknown id before any visibility judgement. **Note the tension with an existing, deliberate control:** `AGENT.MD`'s authenticate-then-authorize rule exists to stop a `403`/`401` oracle on `bound_ips`. That is about *unauthenticated* callers and is unaffected; this is about *authenticated* callers distinguishing absent from invisible. Both can hold, but the next pass should not "fix" one by regressing the other. |

### Master Key Handling

**All four items RESOLVED in Phase 0** — see "Phase 0 — Master Key Integrity" below. Original
verdicts retained for the record.

| Item | Verdict | Evidence |
| :--- | :--- | :--- |
| Exactly one master, DB-enforced | ~~**DOES NOT IMPLEMENT**~~ → **RESOLVED** | No partial unique index anywhere in `src/migration/` — `grep -n "is_master" src/migration/*.rs` returns nothing, so the column carries no constraint at all. Uniqueness is application convention only: `bootstrap_master_key` (`src/main.rs:65`) mints one *if none exists*, and `CreateApiKeyPayload` (`src/api.rs:662`) accepts `is_master: bool`, so **a master can currently create a second master through the API**. |
| Master immutable except own `bound_ips` | ~~**VIOLATES**~~ → **RESOLVED** | `update_api_key` (`src/api.rs:2096`) gates master targets behind `guard_master_to_administer`, but a master editing itself passes, and `UpdateApiKeyPayload` reaches `name`, `bound_ips`, `max_concurrent_jobs` and `hmac_mode`. `rotate_api_key` (`src/api.rs:2187`) is likewise reachable for a master on itself, which the model forbids outright. |
| Master not deletable through the API | ~~**COMPLIES**, incidentally~~ → **RESOLVED** (now unconditional) | `delete_api_key` (`src/api.rs:2170`) refuses `id == key.id` ("Cannot delete yourself"), and `guard_master_to_administer` blocks non-masters from deleting a master. With exactly one master those two combine to make it undeletable — but the guarantee rests on the uniqueness that is *not* enforced (row above). A second master could delete the first. Compliant today, fragile by construction. |
| `is_master` unsettable via any endpoint | ~~**VIOLATES**~~ → **RESOLVED** | `CreateApiKeyPayload` carried `is_master: Option<bool>` and `create_api_key` wrote `Set(payload.is_master.unwrap_or(false))`; `guard_master_to_grant_scopes` returns early for masters, so a master could set it. |

### Key Deletion and Ownership Inventory

**RESOLVED in Phase 4.** Original verdicts retained for the record.

| Item | Verdict | Evidence |
| :--- | :--- | :--- |
| Cascade to daughters | **DOES NOT IMPLEMENT** | No `parent_key_id`, so no subtree. `delete_api_key` removes exactly one row. |
| No implicit data destruction | **VIOLATES** | Deleting a key drops its `api_key_hook_permissions` rows via the schema's cascade. Hooks themselves survive, so no hook is destroyed — but the hook can be left ungoverned with no inventory, no warning, and no record of what was released. |
| Pre-flight ownership inventory | **DOES NOT IMPLEMENT** | No ownership concept and no inventory step; deletion is unconditional. |
| Structured refusal payload | **DOES NOT IMPLEMENT** | Not present. |
| Resolution map, all-or-nothing | **DOES NOT IMPLEMENT** | Not present. |

### Schema and Indexing

| Item | Verdict | Evidence |
| :--- | :--- | :--- |
| Partial unique index on `is_master = true` | ~~**DOES NOT IMPLEMENT**~~ → **RESOLVED** (Phase 0, portable equivalent) | Absent (see above). Also worth flagging for the implementation pass: SQLite and PostgreSQL both support partial indexes, MySQL does not — and `Cargo.toml` enables `sqlx-mysql`. A portable equivalent will be needed, or the SQL-agnostic claim narrows. |
| Index on `parent_key_id`  | ~~**DOES NOT IMPLEMENT**~~ → **RESOLVED** (Phase 2) | Column absent. |
| Index on `owner_key_id`  | ~~**DOES NOT IMPLEMENT**~~ → **RESOLVED** (Phase 2) | Column absent. |
| Index on key-hash lookup column | **COMPLIES** | `key_hash` is `#[sea_orm(unique)]` (`src/entities/api_key.rs:48`) and the initial migration creates a unique index on it — the single authentication lookup path. |
| Indexes on permission-table join columns | **COMPLIES** | `src/migration/m20230101_000001_initial_schema.rs` creates indexes at lines 327/336 and 373/382 covering the junction table's join columns. |

### Where `AGENT.MD` contradicts `RBAC_MODEL.md`

To be reconciled in the implementation pass. `AGENT.MD` currently describes the code accurately; it
is the *model* that has moved, so these are planned changes, not documentation bugs.

1. **The `can_manage_keys` override.** The permission matrix (§2) states grant/revoke may be
   authorized by "`is_master` **or** `can_manage_keys`", and spells out the override at length
   including its cost. R2 abolishes it. **This is the single largest contradiction and the reason for
   the pass.**
2. **Two routes to administering grants.** `AGENT.MD` frames global key administrator and local
   manager as alternatives (`||`); R2 makes them a conjunction (`&&`).
3. **Naming.** `can_manage_hooks` throughout vs the model's `can_create_hooks`. The semantics already
   match ("global right to create hooks"); only the name differs.
4. **No tier vocabulary.** `AGENT.MD` has no notion of Master/Parent/Daughter, and no statement that a
   daughter may never be a resource manager. Its model is flat: global scopes plus per-hook rows.
5. **Lifecycle authority.** `AGENT.MD` assigns `PUT`/`PATCH`/`DELETE /api/hooks/{id}` to `can_manage`;
   the model restricts deleting and renaming to master and owner.
6. **Ownership is absent.** `AGENT.MD` says creation auto-provisions full rights on the new hook,
   which is a *permission row*, not ownership. Nothing survives transfer, and nothing distinguishes
   creator from any other manage-holder afterwards.
7. **Deletion semantics.** `AGENT.MD` documents single-key deletion with no cascade, no inventory and
   no resolution map.
8. **Master key handling.** `AGENT.MD` documents master auto-generation but asserts no uniqueness
   constraint, no immutability, and no regeneration procedure. It also documents master rotation as
   available, which the model forbids.
9. **Oracle discipline.** `AGENT.MD`'s rule is about authenticate-then-authorize for *unauthenticated*
   callers (the `bound_ips` `403`/`401` oracle). It says nothing about invisible-vs-nonexistent for
   authenticated ones. Complementary rather than contradictory — but see the R6/visibility note above
   about not regressing one while implementing the other.

### Sequencing note for the implementation pass

R2 is cheap and self-contained: delete two `|| key.can_manage_keys` bypasses and repair the tests
that depend on them (four integration tests and two e2e blocks were rewritten *to* the override in
`2d62d1b` and will need rewriting back). Everything else — R3, ownership, visibility scoping, the
deletion inventory — is blocked behind two new columns and an index, so it wants a migration first.
Doing R2 alone, immediately, is worth considering: it is the item with a live security consequence,
and it does not depend on any of the schema work.

---

## Phase 0 — Master Key Integrity (`RBAC_MODEL.md` §5)

First phase of the implementation pass that follows the gap analysis above. Scope is §5 and the §7
row that depends on it; nothing about R1/R2/R7, ownership, visibility, or cascade deletion is
touched here.

### Terminology finding, reported before implementing

`RBAC_MODEL.md`'s Terminology table maps **dispatch target** → *Executor* and the resource-creation
right → `can_create_executor`. **Neither exists in this repository.** The tables are `api_keys`,
`hooks`, `hook_parameters`, `api_key_hook_permissions`, `executions`, `audit_logs`; `src/executor.rs`
is the process-spawning engine, a module rather than a persisted entity, and `grep -rn "can_create"
src/` returns nothing.

A `Hook` is behaving as **both** roles the specification separates:

- *Managed resource*: `api_key_hook_permissions` carries `(api_key_id, hook_id, can_execute,
  can_manage)` under a unique index; multiple keys hold rows on one hook.
- *Dispatch target*: the same `hooks` row carries `script_path` and `run_as_user` — the "point it at
  an arbitrary target" power §1 insists is a separate right from key management. There is nowhere
  else for it to live.

The repo's `can_manage_hooks` plays the resource-creation role (`create_hook`, `src/api.rs:877`).

**Consequence for Phases 2–4, unresolved:** creator-privacy has no column to hang on.
`grant_full_hook_permission` gives a creator an ordinary permission row, byte-identical to a
delegated one; there is no `owner_key_id` and no `created_by`. §4's dispatch-target rule ("visible
exclusively to creator and Master") and §4's shared-resource rule ("a parent sees any key holding a
permission row on a resource it manages") give *contradictory* answers for a single `Hook`. This
needs an architectural decision — split the entity, or drop the dispatch-target role for this
service — and Phase 2 should stop for it rather than assume.

### What changed

**1. Database-level master uniqueness — `m20230106_000001_master_key_uniqueness` (new).**

`api_keys` gains `master_marker`, an INTEGER column **generated by the engine** as
`CASE WHEN is_master THEN 1 ELSE NULL END`, under a plain unique index
`idx_api_keys_master_marker`.

Two choices worth recording, both forced:

- *Plain unique index on a nullable column, not a partial index.* The natural spelling is
  `CREATE UNIQUE INDEX … WHERE is_master`. PostgreSQL and SQLite accept it; MySQL has no `WHERE`
  clause on `CREATE INDEX`, and `Cargo.toml` enables `sqlx-mysql`. A partial index would have left
  MySQL deployments silently unprotected while every test (SQLite) passed. §5 anticipates this and
  names the nullable-marker form as the portable equivalent.
- *Generated, not application-maintained.* A marker the application writes could be bypassed by
  writing `is_master = true` and leaving the marker `NULL` — which is exactly the "application logic
  alone" §5 rules out. Deriving it holds against any writer: a future handler, a migration, a
  restored backup, an operator at a SQL prompt.

One dialect split: PostgreSQL generated columns must be `STORED` (it gained `VIRTUAL` only in 18),
SQLite permits only `VIRTUAL` for a column added via `ALTER TABLE`, MySQL takes either. Two unit
tests in the migration pin the pairing, because getting it backwards would fail only against a real
server the suite never starts.

`master_marker` is deliberately **absent from `api_key::Model`**. SeaORM builds explicit column
lists from the entity, so an undeclared column never appears in an `INSERT` — required, since the
engine rejects writes to a generated column.

**2. `is_master` removed from every payload — `src/api.rs`.**

`CreateApiKeyPayload` no longer has the field (`UpdateApiKeyPayload` never did), `create_api_key`
hard-wires `is_master: Set(false)`, and `guard_master_to_grant_scopes` drops the parameter.

Both key payloads are now `#[serde(deny_unknown_fields)]`. **This is the part that matters.** Serde's
default is to ignore unknown fields, so removing the field alone would have returned `200` and a
perfectly ordinary key — leaving the caller believing it had minted a master, and leaving an
operator reading the audit log with no record that anyone tried. Strict deserialization turns it
into `422` naming the field:

```
{"error":"Failed to deserialize the JSON body into the target type: is_master: unknown field
 `is_master`, expected one of `name`, `bound_ips`, `max_concurrent_jobs`, `hmac_mode`,
 `can_manage_keys`, `can_manage_hooks` at line 1 column 12"}
```

**3. `StrictJson` extractor + `AppError::BodyRejected` — `src/api.rs`, `src/error.rs`.**

Axum's own `Json` rejection renders as bare `text/plain`, which would break the `{"error": …}`
envelope every other refusal on these routes uses — a client parsing the refusal would find no
`error` field. Now that a rejected field is a *routine, security-relevant* outcome rather than an
exotic one, it has to read like every other refusal.

The first cut mapped every rejection to `AppError::InvalidInput` and **broke a real control**: the
1 MiB body limit also surfaces as a `Json` rejection, so `oversized_request_bodies_are_rejected_
before_a_handler_runs` went from `413` to `400`. `BodyRejected(StatusCode, String)` passes the
extractor's own status through and normalizes only the response *shape*.

**4. Master lifecycle and mutation guards — `src/api.rs`.**

- `refuse_master_lifecycle_action` — delete and rotate on a master target are refused for **every**
  caller, the master included. The pre-existing `guard_master_to_administer` only stopped *other*
  keys; once exactly one master row can exist, "only a master may administer a master" had collapsed
  into "the master may administer itself", and rotation returns the new plaintext secret in its
  response. One request against a stolen (but IP-bound) master credential both harvested a fresh
  secret and locked the operator out. Deletion is barred *regardless of row count*, deliberately, so
  the rule is two independent controls rather than one leaning on the uniqueness index.
- `guard_master_self_edit_is_bound_ips_only` — the master reaches `bound_ips` and nothing else.
  That exception is narrow on purpose: `bound_ips` is the one field an operator has a recurring need
  to change from inside the running system, and the one that can only ever *reduce* a stolen
  credential's usefulness. `hmac_mode` is the sharpest of the refused fields — it could downgrade
  the master to `BODY_ONLY`, which carries no replay protection at all.

### Breaking changes

| Change | Who is affected | Migration path |
| :--- | :--- | :--- |
| `POST /api/keys` with `is_master` → `422` (was `200` for a master caller, `403` otherwise) | Any tooling that minted master keys through the API | Stop. Delete the master row directly and restart to re-mint; the bootstrap banner is the only source of a master credential. |
| `POST`/`PUT /api/keys*` now reject **any** unknown field → `422` | Clients sending extra/typo'd fields that were previously ignored | Send only documented fields. The refusal names the offending one. |
| `POST /api/keys/{id}/rotate` on the master → `403` for every caller | Operators rotating the master through the API | Out of band: delete the row, restart, capture the new banner. |
| `DELETE /api/keys/{id}` on the master → `403` for every caller | As above | As above. |
| `PUT /api/keys/{id}` on the master with any field but `bound_ips` → `403` | Tooling renaming or re-tuning the master | Only `bound_ips` is editable. |
| Migration aborts startup if two master rows already exist | Deployments in that state | See the operator SQL below. |

### Operator SQL

Before upgrading, check for the one state that blocks the migration:

```sql
-- Must return 0 or 1. Anything higher aborts startup on the next boot.
SELECT COUNT(*) FROM api_keys WHERE is_master = TRUE;

-- If it returns more than 1, list them and pick the one to keep.
SELECT id, name, prefix, key_id, bound_ips, created_at
FROM api_keys WHERE is_master = TRUE ORDER BY created_at;

-- Demote the extras (preferred: keeps the credential usable at a lower tier)...
UPDATE api_keys SET is_master = FALSE, can_manage_keys = TRUE
WHERE is_master = TRUE AND id <> '<id-of-the-master-to-keep>';

-- ...or remove them outright.
DELETE FROM api_keys WHERE is_master = TRUE AND id <> '<id-of-the-master-to-keep>';
```

To regenerate the master after this phase (the API can no longer do it):

```sql
DELETE FROM api_keys WHERE is_master = TRUE;
-- then restart the daemon and capture the bootstrap banner, which prints the
-- plaintext key and signing secret exactly once.
```

### Test and script fallout

- `bound_ips_restricts_master_keys_as_well` seeded **three** master keys into one database. Now one
  database per case, via a local `master_bound_to(allowlist)` helper — the previous shape is not
  merely disallowed, it is a state the service can no longer be in.
- `regression_non_master_cannot_mint_a_master_key` asserted `403` and a guard-authored message. The
  refusal now comes from the deserializer (`422`) and applies to every caller, so it asserts
  `is_client_error()` plus the field name, and gains a check that no credential was minted.
- `regression_non_master_cannot_rotate_update_or_delete_a_master_key` ended with "a master peer may
  still administer it — the gate is 'master only', not 'nobody'". That is now exactly wrong; it
  asserts `403` for master self-rotation and self-deletion instead.
- `scripts/test_e2e.sh` minted a second master **twice**: once as "Signing Master" (for a signing
  pair on master-only routes) and once as "Bound Master" (to prove `bound_ips` binds masters). Both
  are impossible now. The first scrapes the signing secret from the bootstrap banner — the path a
  real operator takes on first boot. The second drives the *real* master through the one field §5
  leaves editable: narrow its own binding to a range excluding the test client, prove the direct
  path is refused, prove the trusted proxy's header gets back in, and restore through that same
  header. No pipes in the scrape: `grep -o | head -1` would SIGPIPE the upstream `grep` under
  `pipefail` and report a successful scrape as a failed command.

### New tests

| Test | Asserts |
| :--- | :--- |
| `even_a_master_cannot_mint_a_second_master` | The master's own attempt is refused and exactly one master row survives |
| `an_update_payload_carrying_is_master_is_refused_rather_than_ignored` | Refused aloud, and the target was not promoted |
| `the_database_rejects_a_second_master_row_with_no_handler_involved` | Direct SeaORM insert fails — **and** three ordinary keys still coexist, so the constraint is on the marker rather than a cap on keys |
| `the_master_may_edit_only_its_own_bound_ips` | `bound_ips` succeeds; five other fields refused one at a time, each refusal naming its field; nothing partially applied |
| `each_backend_gets_the_only_storage_class_it_accepts` (unit) | Postgres `STORED`, SQLite/MySQL `VIRTUAL` |
| `the_marker_is_derived_from_is_master_on_every_backend` (unit) | The marker is `GENERATED ALWAYS AS` over `is_master`, not assignable |
| e2e §36 (20 checks) | The whole §5 contract against the real binary and the real bootstrap master |

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **195 passed** (83 unit + 112 integration), was 189 |
| `./scripts/test_e2e.sh` | **721/721**, 0 failed, exit 0 — was 698 |
| `./scripts/verify_convergence.sh` | 14 converged, 2 known, 0 drifted, exit 0 |

---

## Phase 1 — R1, R2, R4, R6, R7 (conjunction and non-amplification)

Handler-only; no migration. Closes five of the seven core rules. R3 is Phase 2's subject.

### The two errors R2 replaces, in opposite directions

R2 says manage is a conjunction — `can_manage_keys` **AND** a `can_manage = true` row on the
specific hook. The code had two separate routes, and each was one half of the conjunction acting
alone:

- **`can_manage_keys` alone** — the early return added in `2d62d1b`
  (`if key.is_master || key.can_manage_keys { return Ok(()) }`). The reasoning at the time was that a
  deployment-wide credential administrator is not scoped to any one hook. What that did not price in
  is that the same scope can *mint the key it grants to*: hold `can_manage_keys`, create a key, grant
  it `can_execute` on any hook, authenticate as it. That is `is_master` in two requests, and the
  earlier notes recorded it as a "deliberate widening" with `guard_master_for_privileged_hook` as
  the bound — which only ever covered hooks carrying `run_as_user`. R2 names this case in as many
  words: "`can_manage_keys` is never a global bypass of per-resource RBAC."
- **A `can_manage` row alone** — the "local manager" route. The Tiers matrix is explicit that a
  Daughter key (no `can_manage_keys`) *never* manages resources, so a manage row on its own is
  operational authority over the hook, not the right to decide who else holds it. This population
  could previously hand out credentials-adjacent authority with no deployment-wide standing at all.

Both halves now fail with **one message** (`"...You do not have manage access to this hook"`).
Distinguishing them would tell a caller which half to acquire, and the row half doubles as a
statement about which hooks exist and who manages them.

### What changed in `src/api.rs`

| Function | Change |
| :--- | :--- |
| `guard_hook_manage_conjunction` (new) | R2 in one place, returning the caller's own row so R1 can use it without a second lookup |
| `has_permission_admin_standing` (new) | Both halves of R2 as far as they are knowable before the payload is parsed. Must run before `ApiKey::find_by_id`, or the endpoint is a key-UUID oracle |
| `is_permission_reduction` (new) | R6 endpoint-parity classifier — grant vs revocation, decided by effect |
| `guard_delegated_hook_grant` | Master-only early return; R1's per-verb check now sits on top of R2 rather than beside it |
| `update_key_hook_permissions` | Classifies the write, then applies R6 (reduction) or R1+R2 (grant) |
| `revoke_key_hook_permission` | `guard_manage` → `guard_hook_manage_conjunction` |

**R7 is the reason the two are composed rather than alternated.** "Granting is bounded by R1 and R2
together, simultaneously and without exception" — the `2d62d1b` early return skipped *both*, which
is why the per-verb comparison had become unreachable for exactly the population most able to abuse
it.

**R4 was already satisfied** and is unchanged: `guard_master_to_grant_scopes` refuses any
non-master request setting `can_manage_keys` or `can_manage_hooks` to `true`, on create and update
alike. Worth recording that this service's resource-creation right is spelled `can_manage_hooks`;
`RBAC_MODEL.md`'s Terminology table calls it `can_create_executor`, which exists nowhere in `src/`.

### Endpoint parity, and the classifier's one non-obvious case

R6 classifies a reduction arriving at the general update endpoint as a revocation "regardless of
which endpoint it arrives at". `DELETE .../permissions/{hook}` and a `POST` writing every verb to
`false` reach the same end state, so holding them to different standards achieves nothing — the
stricter one is one request away from being routed around.

A write is a **grant** when it turns on a verb the target did not already hold, and a **reduction**
otherwise. The case worth stating explicitly: a *mixed* write — one verb up, one down — is a grant.
Treating "net less authority" as a reduction would let a caller trade away `can_execute` to acquire
`can_manage` without holding it, which is R1 defeated by arithmetic.

This also fixed a live asymmetry: `DELETE` had permitted self-revocation since `357a81b`, while
`POST` refused *any* write targeting the caller's own key — so a key could drop its own grant with a
`DELETE` and was refused for the `POST` that does strictly less. Self-*granting* remains refused.

### Breaking changes

| Change | Who is affected | Migration path |
| :--- | :--- | :--- |
| `POST`/`DELETE /api/keys/{id}/permissions*` now requires `can_manage_keys` **and** a `can_manage` row on that hook | Keys holding `can_manage_keys` but no manage row on the hook they administer | Master grants the missing per-hook `can_manage` row |
| Same, from the other side | Keys holding a `can_manage` row but not `can_manage_keys` (the former "local managers") | Master grants `can_manage_keys` — a tier promotion, and deliberately a decision rather than a default |
| A `POST` reducing the **caller's own** row now succeeds (was `403`) | Nobody adversely; a refusal became a success | None |
| Grants of a verb the caller lacks are refused for `can_manage_keys` holders too (was permitted) | Automation relying on the `2d62d1b` override | The caller must hold the verb it hands out |

### Operator SQL — who is affected

```sql
-- (1) Parents missing the per-hook half: hold can_manage_keys, administer hooks they have no
--     can_manage row for. These keys keep working only on hooks where a row exists.
SELECT k.id, k.name, k.prefix
FROM api_keys k
WHERE k.can_manage_keys = TRUE
  AND k.is_master = FALSE
  AND NOT EXISTS (
      SELECT 1 FROM api_key_hook_permissions p
      WHERE p.api_key_id = k.id AND p.can_manage = TRUE
  );

-- (2) Former "local managers": a can_manage row but no can_manage_keys. These lose grant/revoke
--     authority entirely and need a deliberate promotion, not a repair.
SELECT DISTINCT k.id, k.name, k.prefix
FROM api_keys k
JOIN api_key_hook_permissions p ON p.api_key_id = k.id
WHERE p.can_manage = TRUE
  AND k.can_manage_keys = FALSE
  AND k.is_master = FALSE;

-- (3) For a key in (1), the hooks it can still administer after the change.
SELECT h.id, h.name
FROM hooks h
JOIN api_key_hook_permissions p ON p.hook_id = h.id
WHERE p.api_key_id = '<key-id>' AND p.can_manage = TRUE;
```

### Scope boundary recorded deliberately: `guard_manage` is unchanged

R2 as written governs "managing a specific resource", and the Tiers matrix says a Daughter key never
manages resources. Read at its widest, that would also make **editing a hook's own definition**
(`PUT /api/hooks/{id}`, parameter CRUD — all gated by `guard_manage`) require `can_manage_keys`.

Phase 1 did **not** do that, because the phase brief scopes R2 to the grant and revoke paths
explicitly, and the wider reading has a much larger blast radius: it would revoke hook-editing from
every manage-only key in every deployment, and §9 of the e2e ("the manage-only key can modify the
hook") encodes the current contract.

**This is an open question, not a settled one.** It is recorded here rather than decided silently,
and Phase 5's mutation report must not count R2 as fully covered on the strength of the grant/revoke
tests alone.

### Test changes

- `seed_local_manager` → **`seed_daughter_with_manage_row`**, kept because that population still
  exists and now has to be *refused*; **`seed_parent_manager`** added for the R2-compliant shape
  (`can_manage_keys` + a manage row).
- `a_can_manage_keys_holder_may_grant_on_any_hook_without_holding_a_row` — the `2d62d1b` test —
  replaced by its exact inverse, `r2_a_can_manage_keys_holder_without_a_row_on_the_hook_is_refused`,
  which also supplies the missing half at the end and asserts the same request then succeeds. Paired
  with `r2_a_daughter_holding_only_a_manage_row_may_not_administer_grants` for the other half, which
  additionally asserts the daughter keeps its *operational* rights — R2 governs who administers
  grants, not who may use the hook.
- New: `r6_a_post_that_only_reduces_is_judged_as_a_revocation` (same route, same caller, two
  classifications decided purely by effect) and
  `r6_a_key_may_reduce_its_own_row_through_the_update_endpoint`.
- New unit test `a_write_is_a_reduction_exactly_when_it_turns_no_verb_on`, including the mixed-write
  case.
- e2e §30 finding #3, §32 and §33 all seeded actors deliberately *without* `can_manage_keys` —
  correct under the old rules, vacuous under the new ones. Promoted to parents, with the daughter
  case added to §32 as an explicit refusal.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **199 passed** (84 unit + 115 integration), was 195 |
| `./scripts/test_e2e.sh` | **729/729**, 0 failed — was 721 |
| `./scripts/verify_convergence.sh` | 14 converged, 2 known, 0 drifted |

---

## Phase 2 — Lineage, Ownership & Lifecycle Authority (§3, §7, R3)

Migration `m20230107_000001_key_lineage_and_resource_ownership` plus the §3 lifecycle guard.

### Two columns that look alike and are not

| Column | Meaning | Mutable? | Read by authorization? |
| :--- | :--- | :--- | :--- |
| `api_keys.parent_key_id` | Who **created** this key | No — lineage is a record, not a state | **Never** (R3) |
| `api_keys.owner_key_id` | Who is **answerable** for this key | Master may reassign (§3) | Not yet — see the scope note below |
| `hooks.owner_key_id` | Who is **answerable** for this hook | Master may reassign (§3) | Yes — §3 lifecycle authority |

The distinction earns its keep at deletion time. §6 walks the subtree via `parent_key_id` to find
every key being removed, then collects what those keys *own* via `owner_key_id`. Conflating them
would make a key's creator permanently answerable for resources it had since handed over.

### Backfill: explicit NULL, never a guess

Every pre-existing row gets `NULL` for all three columns. This is a refusal, not a convenient
default.

There is no honest way to reconstruct lineage after the fact — `audit_logs` has `KEY_CREATE`
entries, but they are retention-swept, absent for anything predating auditing, and name the actor by
prefix rather than id. Ownership is worse: **a hook's creator was never recorded anywhere.**
`grant_full_hook_permission` gives the creator an ordinary `can_manage` row, byte-identical to a
delegated one, so "the key holding `can_manage`" is not evidence of authorship and is usually true of
several keys.

Backfilling ownership to the master was the tempting alternative and is worse than NULL: §3
restricts lifecycle to master *and the owner*, so master-everywhere is behaviourally identical to
no-owner while additionally asserting a fact nobody checked. NULL says the true thing — this
predates ownership — and leaves lifecycle authority with master alone until an operator assigns it.

Operators wanting to adopt ownership for existing hooks should do it deliberately:

```sql
-- Review first: which hooks have no owner, and who currently manages each.
SELECT h.id, h.name, h.run_as_user,
       (SELECT COUNT(*) FROM api_key_hook_permissions p
        WHERE p.hook_id = h.id AND p.can_manage = TRUE) AS manager_count
FROM hooks h
WHERE h.owner_key_id IS NULL AND h.is_deleted = FALSE
ORDER BY h.name;

-- Assign one at a time, or scripted from the review above. Never blanket-assign.
UPDATE hooks SET owner_key_id = '<key-id>' WHERE id = '<hook-id>';
```

### No database-level foreign keys, on purpose

All three columns reference `api_keys.id` logically; none carries a DDL `REFERENCES` clause, because
both available behaviours are wrong here:

- `ON DELETE CASCADE` would delete a hook when its owner key is deleted. §6 forbids exactly that:
  "Hooks must never disappear as a side effect of removing a key."
- `ON DELETE SET NULL` would silently orphan resources at the moment of deletion — which is the
  inventory step's whole reason for existing. The caller is meant to be *shown* what it is about to
  strand and made to resolve it.

§6's pre-flight inventory is the referential-integrity mechanism, and it is necessarily
application-level because it is interactive: a database constraint fires before the inventory can
refuse. SQLite also does not enforce foreign keys unless `PRAGMA foreign_keys` is on, so a DDL
constraint would have been decorative on the default backend regardless.

### §3 lifecycle authority

`guard_lifecycle_authority` sits **in front of** `guard_manage`, narrowing rather than replacing
it. `can_manage` remains the right to *operate* a hook — description, `script_path`, timeout,
parameter contract. What it no longer carries is the right to make the hook cease to exist.

**Renaming is grouped with deletion.** This service resolves hooks by name on
`/webhook/{identifier}`, in `hook_name` grant payloads, and in operator runbooks, so a rename
silently breaks every caller pointed at the old one. It changes the resource's identity, not its
content — a lifecycle act wearing an edit's clothes.

**Ownerless hooks are master-only**, which is the conservative direction. Reading "no owner" as
"anyone who manages it" would make the un-migrated state *more* permissive than the migrated one, so
every deployment would silently keep the old behaviour until someone remembered to assign ownership
— a migration that changes nothing until it is noticed.

**Reassignment is master-only and not delegable, not even to the current owner.** An owner able to
hand ownership to an arbitrary key could walk away from a resource rather than resolve it, which is
exactly the step §6's inventory exists to make impossible. The target key must exist: a dangling
owner would put the hook permanently beyond §3's non-master path and make §6's inventory report an
id resolving to nothing.

### R3 — testing a negative

R3 forbids deriving authority from lineage. Nothing derives authority from lineage *today*, so the
test has to be built to catch a violation that does not exist yet:
`r3_a_daughter_of_the_master_holds_no_authority_another_daughter_lacks` creates two keys identical
in every respect except parentage — one by the master, one by an ordinary parent — first asserts
that lineage really was recorded *differently* (or the comparison is vacuous), then asserts six
authority-bearing routes answer identically for both. e2e §37 does the same over the wire.

### Breaking changes

| Change | Who is affected | Migration path |
| :--- | :--- | :--- |
| `DELETE /api/hooks/{id}` now requires master or `owner_key_id` | Keys holding `can_manage` on hooks they did not create | Master assigns ownership, or performs the deletion |
| `PUT /api/hooks/{id}` with `name` now requires master or owner | As above | As above |
| Every pre-existing hook is ownerless, so **all** non-master deletion of them is refused until ownership is assigned | Every deployment upgrading with existing hooks | The `UPDATE hooks SET owner_key_id` above, per hook |

That last row is the one to watch: it is not a corner case, it is every hook in every existing
database. It is stated plainly rather than softened because the alternative — backfilling a guess —
would have made the upgrade quiet and wrong.

### Scope note: `api_keys.owner_key_id` is recorded but not yet enforced

The phase brief asked for `owner_key_id` on `api_keys` as well as `hooks`. It is added, indexed, and
populated at creation, and Phase 4 reports it as `current_owner` for key entities in the §6
inventory. It is **not** yet an authorization input: deleting or updating a key still runs on
`can_manage_keys` plus `guard_master_to_administer`, unchanged.

Applying §3's lifecycle rule to keys themselves — "only master and the owner may delete this key" —
is a coherent extension and a larger behavioural change than this phase's brief covers. Recorded
here so Phase 5's mutation report does not count it as enforced.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **203 passed** (84 unit + 119 integration), was 199 |
| `./scripts/test_e2e.sh` | **754/754**, 0 failed — was 729 |
| `./scripts/verify_convergence.sh` | 14 converged, 2 known, 0 drifted |

---

## Phase 3 — Visibility Scopes & Oracle Discipline (§4)

The largest behavioural change of the five phases, and the one with the widest test fallout:
15 integration tests and 23 e2e checks moved, almost all `403 → 404`.

### The over-disclosure that was there

`GET /api/keys` returned a full `ApiKeySummary` — global flags, `bound_ips`, and **every hook
membership** — for *every key in the deployment*, to any `can_manage_keys` holder. One shared hook
was enough to read another tenant's entire configuration; so was holding the scope and sharing
nothing at all. §4 names this shape exactly: "a single shared resource must never become a keyhole
into another parent's whole configuration."

### Three scopes

| Scope | Who | What they see |
| :--- | :--- | :--- |
| 1 — own subtree | the caller, plus every key transitively below it via `parent_key_id` | the full summary, minus raw secrets |
| 2 — shared resource | any key holding a row on a hook the caller `can_manage` | `id`, `name`, rights **on the shared hooks alone**, `partial: true` |
| 3 — creator-private | executions | the requesting key, and master |

`MinimalApiKeyView` is a **separate type**, not an `ApiKeySummary` with fields blanked out. That is
deliberate: adding a field to the full summary must not silently widen the minimal one. The compiler
has to be told, every time.

`partial: true` is on the minimal view because without it an abridged entry is indistinguishable
from a key that genuinely holds nothing — a client would render "no global scopes" where the truth
is "not shown".

Anything outside all three scopes is **omitted from the listing entirely**, which is the listing
form of oracle discipline: absent and invisible look the same.

This is the one place `parent_key_id` is read, and §4/R3 sanction exactly this use — "solely for
cascading deletion and visibility scoping". `descendant_key_ids` walks breadth-first with a `seen`
set, which is not an optimization: the column carries no FK (see Phase 2), so nothing at the
database level prevents a cycle, and a cycle inside a request handler would spin forever.

### Scope 3, and the terminology gap it sits in

`RBAC_MODEL.md` maps the creator-private scope to a "dispatch target" and names it *Executor*. **No
such entity exists in this service** — the terminology check for Phase 0 established that, and
nothing since has changed it. `executions` is the closest analogue: each row already records
`api_key_id`, the key that requested it, and its `parameters_json`/stdout/stderr are that caller's
data.

So scope 3 is implemented on `executions`, and the consequence is a real narrowing: **a hook's
manager no longer sees runs it did not make.** It sees that the hook exists and what it does; it
does not see the arguments another tenant passed or the output they got back. Hook visibility stays
as a second bound, so history for a hook the caller can no longer see disappears even for its own
runs.

Recorded plainly because it is a judgement call, not a derivation: the Terminology table maps
"resource data (contained records)" to `—` for this service, so neither reading is forced by the
text.

### Oracle discipline, and the line it draws

The rule is that an out-of-scope id must produce what a nonexistent id produces — same status, same
body. Implementing that meant splitting one question into two:

- **No permission row at all** → the hook is outside the caller's visibility scope → `404`.
- **A row exists, but not the verb needed** → the caller can already see the hook → `403`.

Collapsing these, as the code did, made every hook endpoint an existence oracle: `403` for a hook
that exists, `404` for one that does not, from a caller entitled to neither. `verb_denied` is the
helper that makes the split explicit at each call site.

The same split runs through `guard_hook_manage_conjunction`, and it took two attempts to get
right. The first version checked `can_manage` before deciding visibility, so a caller holding
`can_execute` alone got a `404` for a hook it could demonstrably see — a lie it could disprove with
`GET /api/auth/me`. Visibility is decided by whether *any* row exists; only then does the verb
matter.

Name-based resolution is covered too. Hook names are guessable in a way UUIDs are not, so
`GET /api/hooks/{name}` had to be tested for the same indistinguishability.

### The two controls that must both hold

§4 is explicit that oracle discipline "is a distinct control from the authenticate-then-authorize
ordering rule ... Both hold simultaneously; neither may be satisfied by regressing the other."

They govern different populations and pull in opposite directions:

| Control | Population | Rule |
| :--- | :--- | :--- |
| Oracle discipline | **authenticated** callers | invisible must look nonexistent → `404` |
| Authenticate-then-authorize | **unauthenticated** callers | unknown credential is `401`, never `403`, so `403` cannot confirm a guessed key exists |

Making every refusal `404` breaks the second; making every refusal `403` breaks the first. Two tests
name their control in their own titles so the pair cannot be quietly collapsed later:
`s4_an_invisible_hook_is_indistinguishable_from_a_nonexistent_one` and
`s4_unauthenticated_callers_cannot_probe_bound_ips_via_401_vs_403`.

### Consequence worth flagging: delegation is now subtree-shaped

Because `POST /api/keys/{id}/permissions` refuses an invisible target with `404`, a parent can only
grant to keys **in its own subtree**, or ones already sharing a hook it manages. Two keys both
created by master are siblings and invisible to each other.

This follows from §4 rather than being chosen, and it matches how a deployment actually works — a
parent delegates to daughters it created. But it changed a lot of test fixtures, which seeded keys
flat: `set_parent` was added to `tests/common`, and `create_key_as` to the e2e, so an actor that
must administer a target now *creates* it, as it would in practice.

### Breaking changes

| Change | Who is affected | Migration path |
| :--- | :--- | :--- |
| Hook routes return `404` instead of `403` when the caller holds no row | Clients branching on `403` to mean "exists but denied" | Treat `404` as "no access"; the distinction was an information leak |
| `GET /api/keys` no longer returns unrelated keys, and returns shared-resource peers abridged | Dashboards enumerating all keys via a `can_manage_keys` credential | Use the master key, or accept the scoped view. `partial: true` marks abridged entries |
| `PUT`/`DELETE`/`rotate` on a key outside the caller's subtree returns `404` | Tooling administering keys it did not create | The administering key must be the target's parent, or master |
| `GET /api/executions*` returns only the caller's own runs | Dashboards showing per-hook history to hook managers | Master sees all history |

### Operator SQL — who loses visibility

```sql
-- Keys with no recorded parent. Every one of them is invisible to every non-master key, and
-- (per Phase 2's backfill) that is every key predating lineage.
SELECT id, name, prefix, can_manage_keys
FROM api_keys
WHERE parent_key_id IS NULL AND is_master = FALSE;

-- Adopt an existing key into a parent's subtree, deliberately and one at a time. This grants
-- visibility, not authority: R3 forbids deriving any right from lineage.
UPDATE api_keys SET parent_key_id = '<parent-id>' WHERE id = '<child-id>';
```

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **208 passed** (84 unit + 124 integration), was 203 |
| `./scripts/test_e2e.sh` | **791/791**, 0 failed — was 754 |
| `./scripts/verify_convergence.sh` | 14 converged, 2 known, 0 drifted |

---

## Phase 4 — Cascade Deletion & Pre-flight Inventory (§6)

`DELETE /api/keys/{id}` deleted exactly one row. §6 requires it to delete a subtree, and to refuse
until everything that subtree owns has been explicitly accounted for.

### Two-step by design

The first request is a **question**, not a command. If the subtree owns anything the service answers
`409` with the full inventory; the caller resubmits with a resolution for every listed entity.

That shape is forced by §6 pulling in two directions at once: "data is never destroyed implicitly"
rules out deleting the resources along with the keys, and the inventory requirement rules out
leaving them stranded. The only remaining move is to stop and ask.

A subtree owning nothing still deletes in **one** request with no body. The inventory is a gate, not
a toll — a mandatory second round-trip for the ordinary case would be a regression dressed as a
safety feature.

### The refusal payload

```json
{
  "error": "Deletion refused: this key subtree owns 2 entities with no resolution. ...",
  "subtree":   [ { "id": "...", "name": "parent" }, ... ],
  "inventory": [ { "type": "hook", "id": "...", "name": "...", "current_owner": "..." } ]
}
```

`inventory` carries the four fields §6 names. `subtree` is not required by §6 and is included
anyway: the caller asked about one key and is about to remove several, and it should be able to see
that before agreeing rather than after.

### Four ways the resolution map is rejected

| Case | Status | Why |
| :--- | :--- | :--- |
| An inventoried entity has no resolution | `409` + full inventory | §6: partial maps are refused. A partial map is almost always a *stale* one — the caller resolved what it was shown and something arrived in between. Applying it would delete the keys and orphan the late arrival, which is the exact outcome this mechanism exists to prevent |
| A resolution names something the subtree does not own | `400` | Usually a map replayed against a different subtree. Ignoring it would let a caller believe it had resolved something it had not |
| `reassign` to a key **inside** the doomed subtree | `400` | The new owner is about to cease to exist, so it resolves nothing |
| `reassign` to a key that does not exist | `400` | Would leave the hook owned by nothing — §3's non-master path closed off permanently, and §6's inventory reporting an id that resolves to nothing |

All reassignment targets are validated **before** any of them are applied, so a bad target halfway
through the map cannot leave the subtree half-resolved and half-deleted.

### `{"action":"delete"}` is a soft delete

Explicit does not have to mean irreversible. A resolved deletion moves the hook to the trash like
every other deletion in this service: its parameter contract, permission grants and execution
history all survive, and the 92-day purge stays the only thing that destroys them. §6's "data is
never destroyed implicitly" is about *side effects*, and this is an instruction — but an operator
resolving forty hooks at 3am should be able to take one back.

Soft-deleted hooks are also **included in the inventory**. A hook in the trash is still recoverable
and still owned; letting the cascade leave it ownerless would quietly make it master-only forever,
which is a decision nobody made.

### What survives the cascade, and how

- **Permission rows** follow the deleted keys via the initial schema's existing `ON DELETE CASCADE`.
- **Executions** survive: `executions.api_key_id` is `ON DELETE SET NULL`, so a run outlives its
  author and the attribution is nulled rather than cascaded away. That is what makes the audit trail
  worth keeping — a deletion that erased the history of what a key did would be an attractive first
  step for anyone with `can_manage_keys`.
- **Hooks** survive by construction: they cannot reach the cascade unresolved.

### `OptionalStrictJson`

`DELETE` with no body is the common case and must stay that way, so the payload extractor treats an
empty body as `Default`. Emptiness is decided from the **bytes**, not from `Content-Type`, so a
client sending the header without a payload behaves like one sending neither. It reads through
`axum::body::Bytes`, which keeps the request under `DefaultBodyLimit` — the `413` control from Phase
0 still applies here as everywhere else.

### Known gap, recorded rather than papered over

`api_keys.owner_key_id` is **not** inventoried. Keys inside the subtree are being deleted, not
owned-and-stranded, and a key *outside* the subtree owned by one inside it cannot currently arise:
key ownership is set to the creator at creation and there is no route that reassigns it, so owner and
parent are always the same key. If a key-ownership reassignment route is ever added, this walk has to
grow a second arm or it will strand keys the way it currently cannot.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **213 passed** (84 unit + 129 integration), was 208 |
| `./scripts/test_e2e.sh` | **823/823**, 0 failed — was 791 |
| `./scripts/verify_convergence.sh` | 14 converged, 2 known, 0 drifted |

---

## Phase 5 — Compliance Suite & Mutation Validation

`tests/rbac_model_compliance.rs`: 14 tests, every name prefixed with the rule it enforces
(`r1_`…`r7_`, `s3_`…`s7_`). Coverage against the specification is now auditable by running
`cargo test --test rbac_model_compliance -- --list`.

`scripts/verify_convergence.sh` gained `rbac_rule_coverage`, which fails the run if any rule R1–R7
or section §3–§7 has no test carrying its prefix. It reads **test function names only**
(`grep -oE '^async fn ...'`), so a rule mentioned in a doc comment cannot satisfy its own check. It
was mutation-tested by renaming `r5_manage_propagates_…` — the check reported
`[DRIFT] No compliance test for: r5`.

The check proves a rule is not *untested*. It cannot prove a rule is *enforced* — that is what the
mutation results below are for, and the two must not be confused.

### Mutation results

Each enforcement site was disabled in turn, the corresponding compliance test run, and the source
restored with `git checkout -- src/`. A mutation that **FIRED** means the test genuinely pins the
rule; one that **SURVIVED** means the test would pass against unfixed code and proves nothing.

| Rule | Mutation | Outcome |
| :--- | :--- | :--- |
| R1 | per-verb `wanted && !held` comparison always `None` | **FIRED** |
| R2 (per-resource half) | `can_manage_keys` short-circuits to a synthetic full row | **FIRED** |
| R2 (global half) | `!can_manage_keys` check removed from `has_permission_admin_standing` | *survived* |
| R2 (global half) | same check removed from `guard_hook_manage_conjunction` | *survived* |
| R2 (global half) | **both sites at once** | **FIRED** |
| R3 | `guard_execute` grants when the caller's parent is master | **FIRED** |
| R4 | `guard_master_to_grant_scopes` returns `Ok` unconditionally | **FIRED** |
| R5 | granting `can_manage` also sets `can_manage_keys` on the target | **FIRED** |
| R6 | revoke path additionally requires the caller to hold `can_execute` | **FIRED** |
| R7 | R2 gate replaced by a bare row lookup that passes on absence | **FIRED** |
| §3 | `guard_lifecycle_authority` returns `Ok` unconditionally | **FIRED** |
| §4 (minimal view) | shared-resource peers rendered with the full summary | **FIRED** |
| §4 (oracle) | `verb_denied` always returns `403` | **FIRED** |
| §4 (401-vs-403) | unknown API key returns `403` instead of `401` | **FIRED** |
| §5 | `refuse_master_lifecycle_action` returns `Ok` unconditionally | **FIRED** |
| §6 | the unresolved-inventory gate is skipped | **FIRED** |
| §7 | `idx_api_keys_parent_key_id` omitted from the migration | **FIRED** |

**14 of 14 rules covered by a firing mutation.** The two single-site R2 survivors are not a test
weakness and are recorded rather than hidden: the global half is enforced **twice**, at the coarse
standing pre-check and again at the per-hook guard, so disabling either alone leaves the other
holding the line. That is defence in depth working as intended — and it is exactly the situation a
mutation report exists to distinguish from an untested rule, since both look identical from the
outside.

Two mutations changed behaviour in ways worth noting:

- The **§4 oracle** mutation initially *survived*, and that was a real gap. The compliance test
  probed only `GET /api/hooks/{id}`, which fails at `guard_visibility` and never reaches
  `verb_denied` — so the guard that handles execute/modify was unpinned. The test now walks six
  routes, and the mutation fires. Left as written, the oracle would simply have migrated to whichever
  endpoint the test had not visited.
- The **R5** mutation is the only one that had to *add* a violation rather than remove a guard. R5 is
  partly emergent — "manage may propagate sideways ... but this can never elevate a daughter key to
  parent status" is upheld by R4 and by the grant handler never touching global scopes, not by a
  guard of its own. The mutation makes the handler promote its target, which is the violation R5
  names.

### Rules covered but not fully enforced

Recorded here so the table above is not read as a clean bill of health. Both were flagged when they
arose and neither is closed:

1. **R2's wider reading** (Phase 1). R2 governs "managing a specific resource"; the Tiers matrix says
   a Daughter key never manages resources. Enforced on the grant and revoke paths. **Not** enforced on
   `guard_manage`, so a daughter holding a `can_manage` row can still edit a hook's `script_path`,
   timeout and parameter contract. The phase brief scoped R2 to grant/revoke explicitly; widening it
   would revoke hook-editing from every manage-only key in every deployment.
2. **§3 applied to keys** (Phase 2). `api_keys.owner_key_id` is populated, indexed, and reported by
   §6's inventory, but is not an authorization input: key deletion and update still run on
   `can_manage_keys` plus `guard_master_to_administer`.

### Validation

| Gate | Result |
| :--- | :--- |
| `cargo check --all-targets` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` | **227 passed** (84 unit + 129 integration + 14 compliance), was 213 |
| `./scripts/test_e2e.sh` | **823/823**, 0 failed — unchanged |
| `./scripts/verify_convergence.sh` | 15 converged, 2 known, 0 drifted |

---

## Comparative security audit, 2026-08-07 (read-only)

`SECURITY_COMPARISON_REPORT.md` rewritten against the peer's completed Phase 5. No source file
touched. Three things from it belong in this log because they are findings about *this* repository,
not about the comparison:

**1. The `RBAC_MODEL.md` identity check has now run for real, and passes.** The peer carries a copy
(`example/simply_ip_vault/RBAC_MODEL.md`, mtime 2026-08-07 09:47) and `cmp` reports byte-identical.
Every prior note in this file describing that check as pending is now stale. `verify_convergence.sh`
reports `[OK] Canonical RBAC model (byte-identical)` — 16 converged, 1 known, 0 drifted.

**2. Phase 1's recorded open question is a genuine weakness relative to the peer, not just an
unfinished reading.** The note in "Phase 1 — Scope boundary recorded deliberately" said R2's wider
reading over `guard_manage` was an open question. The comparison settles it: `simply_ip_vault`
carries four permission verbs (`can_read`/`can_write`/`can_delete`/`can_manage`) and uses
`can_manage` for **permission-row administration only**, so R2's conjunction governs everything that
verb can do. This service's two-verb model overloads `can_manage` to mean administration *and*
content editing, so the conjunction covers half of it.

The concrete consequence, which the Phase 1 note understated: a Daughter key (no `can_manage_keys`)
holding a `can_manage` row can `PUT /api/hooks/{id}` and change `script_path` — repointing what
binary the daemon executes. `guard_master_for_privileged_hook` bounds this only for hooks carrying
`run_as_user`, and `validate_script_path` bounds it only when `ALLOWED_SCRIPT_ROOTS` is set, which
`src/config.rs` defaults to empty (unrestricted, with a startup warning). Closing it means either
requiring the conjunction in `guard_manage`, or splitting `can_manage` into an administrative and
an operational verb as the peer did. The second is the better fix and the larger one.

**3. This repository is stronger than the peer on §5, for a reason worth keeping.** The peer's
`master_marker` is a plain `VARCHAR(16)` maintained by application code, so `is_master = true` with a
`NULL` marker is a second master the database will accept. Ours is
`GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`, which is why
`the_database_rejects_a_second_master_row_with_no_handler_involved` can insert with `is_master: true`
and never mention the marker. If anyone is ever tempted to "simplify" that migration to a plain
column, this is the reason not to.

**Two smaller items to consider adopting from the peer**, neither urgent:

- Its `§7` mutation makes the master-marker index **non-unique** rather than omitting it. That is the
  realistic regression (a dropped `.unique()` still passes a presence check); ours only tested
  omission. Our `s5_` catches it behaviourally, so coverage exists — the probe is just blunter.
- Its compliance suite is self-contained with its own harness, so a refactor of the functional test
  helpers cannot silently weaken it. Ours shares `tests/common` under `#[allow(dead_code)]`.

**Specification defect, actionable only in concert with the peer.** `RBAC_MODEL.md`'s Terminology
table names `can_create_webhooks` and `can_create_executor` as the resource-creation rights. Neither
string exists in either codebase: the real names are `can_manage_webhooks` and `can_create_groups`
(two rights, where the table allows one) in the peer, and `can_manage_hooks` here. The same table
names an "Executor" entity this service does not have, which is what forced the dispatch-target role
onto `hooks` and scope 3 onto `executions`. Fixing either requires editing both copies together —
a unilateral edit forks the spec and breaks the identity check that just started passing.

---

## Phase 1 — Closing the R2 conjunction gap on resource content

`fix(rbac): enforce R2 conjunction on guard_manage and dispatch configuration`

The audit's finding #2 above, closed. `RBAC_MODEL.md` was amended by the operator before this phase
ran, and the amendment settles two things the audit had recorded as open: the Terminology table now
resolves this service's nouns without inventing entities (*resource data* = Hook parameter,
*creator-private entity* = Execution record, *resource-creation rights* = `can_manage_hooks`), and a
new **Dispatch configuration** paragraph names `script_path` and `run_as_user` explicitly:

> *Where it lives on a shared managed resource, editing it is a management action on that resource
> and is governed by R2 in full — holding an operational verb, or a `can_manage` row without the
> global conjunct, does not authorise changing what the service executes or where it dispatches.*

R2 itself gained a closing sentence: the conjunction "governs every action `can_manage` authorises on
that resource — delegation of permissions, **lifecycle where §3 permits it**, and editing dispatch
configuration held on the resource itself." So this is no longer an inference from the Tiers matrix;
it is the specification's own words, and the fix is mandatory rather than advisable.

### What changed

`guard_manage` was `is_master || row.can_manage`. It is now a master short-circuit in front of
`guard_hook_manage_conjunction` — **one** evaluation point for R2 in the whole service, rather than
two implementations to drift apart. All six call sites inherit the fix without individual edits:

| Call site | Route | Was | Now |
| :--- | :--- | :--- | :--- |
| `update_hook` | `PUT`/`PATCH /api/hooks/{id}` | bare row | conjunction |
| `create_hook_parameter` | `POST /api/hooks/{id}/parameters` | bare row | conjunction |
| `update_hook_parameter` | `PUT /api/hooks/{id}/parameters/{pid}` | bare row | conjunction |
| `delete_hook_parameter` | `DELETE /api/hooks/{id}/parameters/{pid}` | bare row | conjunction |
| `delete_execution` | `DELETE /api/executions/{id}` | bare row | conjunction |
| `delete_hook` | `DELETE /api/hooks/{id}` | bare row, then §3 | conjunction, then §3 |

Status codes are unchanged in shape and still §4-correct, because the conjunction helper already
made the distinction: **no row at all → `404`** (the hook is invisible, so it must answer as a
nonexistent id does), **a row short of a conjunct → `403`**. The caller always knows its own rows via
`GET /api/auth/me`, so the status leaks nothing about itself; what stays hidden is the hook.

### Option 1 chosen: uniform conjunction, no verb split

The peer service solves this differently — it splits `can_manage` (administrative) from
`can_read`/`can_write`/`can_delete` (operational), so its `can_manage` never edits content and the
conjunction lands naturally. That is the better long-term model and it is what the audit recommended.
It is **not** what this phase does.

**Option 1 — uniform enforcement without splitting the verb — was chosen deliberately**, because it
closes a remote-code-execution path today with no schema migration, no change to
`api_key_hook_permissions`, no rewrite of every grant payload, and no coordination with the peer's
column set. A verb split is a data-model change that would have to be designed, migrated, backfilled
with a policy decision about what an existing `can_manage = true` row becomes, and reflected in every
grant route and its R1 per-verb comparison. Shipping that is a phase of its own; shipping *this* is
an edit to one function. The RCE does not wait for the better refactor.

The cost is honest and should be recorded rather than argued away: `can_manage` in this service still
means two things at once, and the conjunction is what compensates. **A verb split remains the correct
follow-up**, and if it happens, `guard_manage` collapses into the operational verb and
`guard_hook_manage_conjunction` keeps the administrative one.

### Sibling guards audited

The instruction was to check for the same omission elsewhere before assuming `guard_manage` was the
only site. Every authorization helper in `src/api.rs` was read. Findings:

| Guard | Verdict | Reasoning |
| :--- | :--- | :--- |
| `guard_manage` | **Was defective — fixed** | The subject of this phase |
| `guard_hook_manage_conjunction` | Correct | Already both halves; now the single R2 site |
| `has_permission_admin_standing` | Correct | Both halves as far as knowable pre-payload |
| `manages_any_hook` | Correct by role | Deliberately the row half only; its caller supplies the global half. Not a guard on its own and never called as one |
| `guard_delegated_hook_grant` | Correct | Enters through `guard_hook_manage_conjunction` |
| `guard_execute` | Correct — **must not** change | R2 governs *managing*. `can_execute` is operational, and a Daughter is entitled to it. Adding the conjunction here would break the Tiers matrix in the opposite direction |
| `guard_visibility` | Correct — **must not** change | Read access is derived from *either* verb; §4 governs it, not R2 |
| `visible_hook_ids` | Correct | The listing form of `guard_visibility`; same reasoning |
| `guard_lifecycle_authority` | Correct | §3 master-or-owner, independent of R2 and now stacked behind it |
| `guard_master_for_privileged_hook` | Correct | Master-only for `run_as_user` hooks; narrower than R2, never a substitute — it does not fire on ordinary hooks, which is exactly why the gap was exploitable |
| `guard_master_to_grant_scopes` | Correct | R4 |
| `guard_master_to_administer` | Correct | R1 non-amplification over key administration |
| `refuse_master_lifecycle_action` | Correct | §5 |
| `guard_master_self_edit_is_bound_ips_only` | Correct | §5 |
| `is_permission_reduction` | Correct | R6, classification by effect |
| `create_hook`'s `can_manage_hooks` check | Correct — **not** an omission | R2 is written about "a `can_manage = true` row for that specific resource"; a resource that does not exist yet can have no row. Creation is governed by the global scope alone, by construction |
| The key-administration routes (`create_api_key`, `list_api_keys`, `update_api_key`, `delete_api_key`, `rotate_api_key`) | Correct | `is_master \|\| can_manage_keys`. These administer *keys*, not a per-resource entity; there is no row for R2 to require. §3 and §4 govern them via `guard_lifecycle_authority` and `key_visibility` |

**No second omission was found.** `guard_manage` was the only guard missing a conjunct.

### Breaking change

**A key holding a `can_manage` row but not `can_manage_keys` loses the ability to edit hooks,
parameters, and execution records.** Under §1 this is the Daughter tier, which "may manage resources:
Never" — so the previous behaviour was the bug and this is the correction. It is nonetheless a
behavioural break for any deployment that leaned on it, and there are two distinct affected shapes:

1. **Delegated managers** — keys granted `can_manage` on someone else's hook.
2. **Self-provisioned creators** — `can_manage_hooks` keys that created a hook, received the
   auto-provisioned full row, and have been editing their own work ever since. These are easy to
   overlook because nobody ever granted them anything. They also lose *deletion* of hooks they own,
   since R2 now gates lifecycle in front of §3.

Operator queries to find them before upgrading:

```sql
-- 1. Every key that would lose hook-management authority: holds a manage row, lacks the global half.
SELECT k.id, k.name, k.prefix, COUNT(p.hook_id) AS manage_rows
FROM api_keys k
JOIN api_key_hook_permissions p ON p.api_key_id = k.id AND p.can_manage = true
WHERE k.is_master = false AND k.can_manage_keys = false
GROUP BY k.id, k.name, k.prefix
ORDER BY manage_rows DESC;

-- 2. Which hooks each of them would stop being able to edit.
SELECT k.name AS key_name, k.prefix, h.name AS hook_name, h.id AS hook_id,
       (h.owner_key_id = k.id) AS is_owner
FROM api_key_hook_permissions p
JOIN api_keys k ON k.id = p.api_key_id
JOIN hooks h   ON h.id = p.hook_id
WHERE p.can_manage = true AND k.is_master = false AND k.can_manage_keys = false
ORDER BY k.name, h.name;

-- 3. The self-provisioned creators specifically — they own the hook and will lose deletion of it
--    too, which the query above flags as is_owner = true. Worth reviewing separately.
SELECT k.id, k.name, k.prefix, COUNT(h.id) AS hooks_owned
FROM api_keys k
JOIN hooks h ON h.owner_key_id = k.id
WHERE k.is_master = false AND k.can_manage_keys = false
GROUP BY k.id, k.name, k.prefix
ORDER BY hooks_owned DESC;
```

**Remediation** is one of three, and it is a policy decision, not a mechanical one:

```sql
-- (a) Promote the key to Parent — restores its previous authority in full. Note this also grants
--     the right to create and administer daughter keys, which is a real widening: do not reach for
--     it by default just because it is the one-line fix.
UPDATE api_keys SET can_manage_keys = true WHERE id = '<key-uuid>';

-- (b) Demote the row to operational-only — the key keeps running the hook, loses editing it.
--     This is the right answer whenever the key was only ever a caller.
UPDATE api_key_hook_permissions SET can_manage = false WHERE api_key_id = '<key-uuid>';

-- (c) Leave it. Editing moves to master or to a Parent, which for most deployments is where the
--     specification wants it.
```

There is no migration for this, deliberately. Any automatic choice would either widen authority
without being asked (a) or silently remove it (b), and the service cannot know which a given
deployment meant.

### Tests

Three new compliance tests under `r2_`, plus fixture corrections across the existing suites.

- **`r2_daughter_cannot_repoint_script_path`** — the named requirement. A Daughter with both verbs on
  an *ordinary* (unelevated) hook is refused `PUT {script_path}`; the row is then re-read to confirm
  the write never landed, since a handler that refuses after writing has refused nothing. It then
  asserts the same key may still *execute* the hook (the conjunction is not a blanket demotion) and
  that a Parent holding the same row may perform the edit (so the refusal is attributable to the
  missing conjunct, not to a broken route).
- **`r2_the_conjunction_governs_content_routes_not_only_delegation`** — walks all five content routes
  behind `guard_manage`, then the positive path for each. Written this way because "governs every
  action" is a claim about a *set* of endpoints, and the §4 mutation survivor in Phase 5 was caused
  precisely by probing one member of a set and generalising.
- **`r2_the_conjunction_is_not_a_substitute_for_section_3_ownership`** — the required deletion case:
  a key holding **both** halves of R2 and not the `owner_key_id` is refused `DELETE` and rename with
  a message naming ownership, while its content edits still succeed. R2 is a gate in front of §3, not
  a replacement for it.

Existing fixtures were corrected rather than weakened. Twelve integration tests and one compliance
test seeded `KeyScopes::plain()` keys with manage rows and asserted they could edit — they were
encoding the defect. Each was re-seeded as a Parent, with a comment recording *why* the tier matters
to that specific test. Two new helpers make the tiers explicit at the call site:
`KeyScopes::parent()` and `KeyScopes::parent_hook_manager()`.

The distinction is load-bearing in the §3 tests especially: with a Daughter, R2 refuses before
ownership is ever consulted, so every §3 assertion would still pass while testing nothing about §3.

### E2E updates

`scripts/test_e2e.sh`: 823 → **841 checks**, all passing. Four existing scenarios were seeded with
Daughter keys and asserted the old looser behaviour:

| Scenario | Change |
| :--- | :--- |
| Granular permission matrix (§ scoped keys) | "Manage-Only Key" is now created with `can_manage_keys` |
| Non-master elevation guard | "Hook Creator No Elevation" gains `can_manage_keys` so the refusals remain attributable to the elevation guard |
| Finding #4 (repointing an elevated hook) | "Hook Editor" gains `can_manage_keys`, same reason |
| §37 ownership and lifecycle | "Hook Owner" and "Hook Operator" both become Parents, or R2 would mask every §3 assertion |

Plus a **new §40** asserting the Daughter side directly on an ordinary hook: refusals across `PUT`,
`PATCH`, parameter creation and lifecycle; confirmation the write never landed; that `can_execute`
still works; and the Parent positive path.

### Mutation verification

`guard_manage` was reverted to its pre-fix body (`is_master || row.can_manage`) and the suite re-run:

| Test | Under mutation | Verdict |
| :--- | :--- | :--- |
| `r2_daughter_cannot_repoint_script_path` | **FAILED** | Catches the regression |
| `r2_the_conjunction_governs_content_routes_not_only_delegation` | **FAILED** | Catches the regression |
| `r2_the_conjunction_is_not_a_substitute_for_section_3_ownership` | passed | **Expected** — §3 is enforced independently by `guard_lifecycle_authority`, so removing R2 does not affect it. Recorded rather than hidden: this test pins §3, and its passing under an R2 mutation is the correct result, not a blind spot |
| `r2_neither_half_of_the_conjunction_suffices_alone` | passed | Expected — it exercises the delegation routes, which never went through `guard_manage` |

The mutation was restored immediately and the full suite re-run green.

### Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **230 passed / 0 failed** (84 unit + 129 integration + 17 compliance) ·
`./scripts/test_e2e.sh` **841 / 841**.

### Deferred, and why

**Execution records are now creator-private under the amended spec** (Terminology: *creator-private
entity* = Execution record), and §4 says such an entity is "visible exclusively to their creator and
Master" and is "never exposed by the shared-resource visibility rule". Today `list_executions` and
`get_execution` gate on `guard_visibility` over the parent hook, so **any** row-holder on a hook
sees every execution of it regardless of who ran it. That is a genuine new divergence created by the
amendment, not by this phase, and closing it is a visibility change with its own §3 question (an
execution has an acting key but no `owner_key_id` column). It is out of scope for a phase whose remit
is R2 and is recorded here as the next candidate.

---

## Phase 2 — Adversarial coverage of infrastructure-level guarantees

`test(rbac): add adversarial-writer coverage for infrastructure-level guarantees`

No production code changed in this phase. It is entirely about what the compliance suite was
*capable of detecting*, which the amended `RBAC_MODEL.md` §5 now states as a requirement:

> *Any test asserting this constraint must attempt an adversarial write — a direct insert setting
> `is_master` with the marker absent or NULL. A test that cooperatively supplies the marker proves
> only that a well-behaved writer behaves well, which is not what this rule is about.*

### Infrastructure guarantees vs. application-logic rules

The split decides which rules need an adversarial test at all, and it is not arbitrary:

**Application-logic rules — R1, R2, R3, R4, R5, R6, R7, §3, §4, §6.** These govern *decisions* that
the application is the only party to. "May this caller grant this verb" has no meaning outside a
request; there is no second writer to defend against, because the rule does not exist below the
handler. An adversarial test here would be incoherent — bypassing the application means bypassing
the rule itself, not evading an enforcement of it. Cooperative HTTP tests are the right and complete
instrument, and these are deliberately **not** required to have `_adversarial_` variants.

**Infrastructure guarantees — §5 (master uniqueness, and the payload-safety clause), §7 (constraints
and indexes).** These are claims about what is true of the *data*, regardless of who is writing. The
whole point of "enforced by a database constraint rather than by application logic alone" is that it
holds when the application is not involved. A test that only ever reaches the table through the
application therefore tests the wrong thing: it would pass identically for a service where the
guarantee lives entirely in a helper and evaporates the moment a migration, a maintenance script, or
a psql session writes a row.

R2 sits interestingly on the line and stays in the first group: it is a decision, but the *dispatch
configuration* it now protects is a fact about a row. It is covered cooperatively, and the row is
re-read after each refusal to confirm the write never landed — which is the part that would catch a
handler that refuses after writing.

### Classification of the compliance suite

| Test | Class | How it reaches the guarantee |
| :--- | :--- | :--- |
| `r1_a_caller_may_only_grant_verbs_it_holds_itself` | Cooperative | HTTP; correct — R1 is a decision |
| `r2_neither_half_of_the_conjunction_suffices_alone` | Cooperative | HTTP |
| `r2_daughter_cannot_repoint_script_path` | Cooperative **+ DB read-back** | Attack over HTTP; the *verification* reads the row directly, so a handler that refused after writing would still fail |
| `r2_the_conjunction_governs_content_routes_not_only_delegation` | Cooperative | HTTP, all five routes |
| `r2_the_conjunction_is_not_a_substitute_for_section_3_ownership` | Cooperative | HTTP |
| `r3_a_daughter_of_the_master_has_no_elevated_standing` | Cooperative **+ direct lineage write** | `set_parent` writes `parent_key_id` behind the API, because no endpoint sets it — the *setup* is adversarial, the assertions are not |
| `r4_only_master_grants_can_manage_keys_or_resource_creation` | Cooperative | HTTP |
| `r5_manage_propagates_sideways_between_parents_but_never_mints_one` | Cooperative | HTTP |
| `r6_revocation_needs_no_proof_and_both_routes_agree` | Cooperative | HTTP |
| `r7_satisfying_one_rule_is_never_a_way_past_the_other` | Cooperative | HTTP |
| `s3_lifecycle_is_the_owners_and_masters_alone` | Cooperative | HTTP |
| `s4_a_shared_resource_is_not_a_keyhole_into_a_whole_configuration` | Cooperative | HTTP |
| `s4_out_of_scope_ids_are_byte_identical_to_nonexistent_ones` | Cooperative | HTTP, byte comparison |
| `s4_the_401_vs_403_ordering_still_holds_for_unauthenticated_callers` | Cooperative | HTTP |
| `s5_exactly_one_master_immutable_and_undeletable` | **Adversarial by accident** | Inserts via `api_key::ActiveModel`. This bypasses the handler, but only because `master_marker` is absent from the model — SeaORM *cannot* emit the column, so the omission is the ORM's doing rather than the test's. It would read as adversarial for a service whose marker *is* on the model and quietly supplied. Kept, and now backed by tests that do not rely on that accident |
| `s6_the_cascade_is_recursive_and_gated_on_a_total_resolution_map` | Cooperative | HTTP |
| `s7_every_required_index_and_constraint_exists` | **Mixed** | Index presence by schema introspection (structural, not adversarial); the `key_hash` uniqueness probe inserts a duplicate through the entity layer, which is adversarial in the same accidental sense as above |
| `s5_adversarial_direct_sql_insert_cannot_mint_a_second_master` | **Adversarial** | Raw SQL `INSERT`/`UPDATE`, no entity layer |
| `s5_adversarial_the_marker_column_refuses_to_be_written` | **Adversarial** | Raw SQL naming `master_marker` explicitly |
| `s5_adversarial_raw_bytes_cannot_smuggle_is_master_onto_a_key` | **Adversarial** | Hand-written `&str` bodies on the wire, no typed struct |
| `s7_adversarial_dangling_lineage_written_behind_the_applications_back` | **Adversarial** | Raw SQL forces the dangling state the API refuses to create |

Before this phase: **0 tests adversarial by construction**, 2 adversarial by accident of the entity
layer. After: **4 by construction**, and the accidental ones are no longer load-bearing.

### The four new tests, and what each would catch

- **`s5_adversarial_direct_sql_insert_cannot_mint_a_second_master`** — the test that separates an
  engine-derived marker from an application-maintained one. It writes raw SQL naming every column
  *except* `master_marker`, exactly as an operator at a psql prompt would, then repeats the attack as
  an `UPDATE` (a generated column recomputes; a constraint that only guards `INSERT` would pass the
  first and fail the second). It also runs the identical statement with `is_master = false` and
  requires it to **succeed** — without that control, a typo in the SQL would make the test pass for
  the wrong reason forever.
- **`s5_adversarial_the_marker_column_refuses_to_be_written`** — the precise bypass §5 describes:
  claim mastery, supply an explicit `NULL` marker, rely on NULLs not colliding in the unique index.
  Also asserts the marker cannot be cleared off the existing master.
- **`s5_adversarial_raw_bytes_cannot_smuggle_is_master_onto_a_key`** — nine hand-written create
  bodies and four update bodies, including key-ordering variants, duplicate keys (last-wins parsing
  is a classic smuggling primitive), truthy-not-true values, nesting, and alternate spellings.
  Expects **422**, not 403: the requirement is that the *deserializer* refuses, so no handler is left
  to reintroduce the path. Closes with a valid body that must still return 200.
- **`s7_adversarial_dangling_lineage_written_behind_the_applications_back`** — §7's new sentence
  ("where a target engine cannot express a constraint in DDL, the application-level equivalent must
  be covered by a test that runs in CI") applied to this repository's deliberate absence of foreign
  keys on `parent_key_id` and `owner_key_id`. Raw SQL forces dangling parents, a lineage cycle, and a
  dangling hook owner; the service must stay upright across authentication, listing, reading, and an
  unrelated cascade. Then it asserts the write-path half: the API refuses to *create* the dangling
  state, which is the job the foreign key would have done.

### Mutation verification

Every new test was proven to fail against a broken constraint, and each mutation was restored
immediately.

| # | Mutation | Expected to fail | Result |
| :--- | :--- | :--- | :--- |
| 1 | `master_marker` reverted to an application-maintained `VARCHAR(16) NULL` with an `UPDATE` backfill — i.e. exactly the peer service's design | both `s5_adversarial_` DB tests | **Both FAILED** ✓. `s5_exactly_one_master_immutable_and_undeletable` also failed, confirming its accidental adversarial character |
| 2 | `#[serde(deny_unknown_fields)]` removed from all three payload types | `s5_adversarial_raw_bytes_...` | **FAILED** ✓ |
| 3 | The `owner_key_id` existence check removed from `update_hook` | `s7_adversarial_...` | **FAILED** ✓ |
| 4 | The `seen` cycle guard removed from `descendant_key_ids` | `s7_adversarial_...` | **SURVIVED** — see below |
| 5 | `s7_adversarial_dangling...` renamed to `s7_dangling...` | `verify_convergence.sh` | **Exit 1**, naming the missing rule ✓ |

**Mutation 4 is an equivalent mutant, not a coverage gap**, and the distinction is worth recording
because the original code comment claims otherwise. `descendant_key_ids` walks children over
`parent_key_id`, which is **single-valued**: a node is enqueued only via its one parent, so each node
enters the frontier at most once, and the only way a cycle re-enters the walk is through the root —
which the walk already filters with `*id != root`. Termination follows from the shape of the data,
not from the `seen` set. No test can kill this mutant because it changes no behaviour. The comment on
`seen` ("a cycle here would spin forever") **overstates**; the guard is genuine defence in depth
against a future second lineage edge or a dropped root filter, and the test now says exactly that
rather than implying it is catching something.

Mutation 5 applies the Phase 5 discipline of mutating the *checker* — a coverage assertion that
cannot fail is worth nothing.

### Convergence checker extension

`adversarial_infrastructure_coverage()` added to `scripts/verify_convergence.sh`, run alongside the
existing rule-coverage check. It requires at least one `<rule>_adversarial_<description>` test for
**§5** and **§7**, plus a separate assertion that some adversarial test puts *raw bytes* on the wire
— because a suite could otherwise satisfy `s5_adversarial_` with the SQL tests alone and leave the
wire format entirely cooperative. R1–R7 are deliberately excluded, for the reason given above: there
is no "behind the application's back" for a rule that only exists inside it.

### Cross-service gap summary (read-only inspection of `./example`)

Read by `grep` only; no file under `example/` was modified. The one file with a newer mtime there is
`RBAC_MODEL.md`, which the operator synced.

Everything below is a **prediction about the peer**, made from its source, and should be verified in
that repository rather than taken as established:

1. **The peer's §5 test is cooperative, and its constraint is bypassable — the two compound.**
   `tests/rbac_model_compliance.rs` seeds its second-master insert with
   `master_marker: Set(Some(simply_ip_vault::api::MASTER_MARKER.to_owned()))` — it hands the
   constraint the very value that makes it fire. Combined with a `master_marker` that is a plain
   `VARCHAR(16)` maintained by application code (`master_marker: Set(None)` on the ordinary key
   path), the peer has a §5 guarantee that a non-cooperating writer walks straight past and a §5
   test that cannot see it. **`s5_adversarial_direct_sql_insert_cannot_mint_a_second_master` would
   fail against the peer today.** This is the same finding the previous audit recorded, but the
   amended §5 now makes it a specification violation rather than a design difference, and this phase
   supplies the test that demonstrates it.

2. **The peer rejects `is_master` at the handler, not at the deserializer.** `is_master:
   Option<bool>` remains a field on its key payload types, refused by `guard_no_master_flag` with a
   `400`. The amended §5 addresses this directly: *"Removing the field from the payload type is
   required; rejecting it at the handler is not sufficient, since a later handler can reintroduce
   the path."* The peer's own reasoning for refusing rather than ignoring is good and worth keeping
   — a caller holding a `200` and a key it wrongly believes is master is a real failure mode — but
   the refusal belongs one layer down. No `deny_unknown_fields` appears anywhere in its `src/api.rs`,
   so unknown fields are silently dropped and the guarantee rests entirely on that one guard being
   called from every present and future key route.

3. **The peer's compliance suite contains no raw SQL at all** (zero occurrences of
   `execute_unprepared` or `execute_raw`), so gap 1 is structural rather than an oversight in one
   test: nothing in that suite is positioned to test a claim about the database as a database.

4. **§7 is likely fine there and is the one place the peer is ahead.** Its initial schema declares
   real `ForeignKey::create()` constraints with `ON DELETE CASCADE`, so the referential integrity
   this repository must uphold in application code is enforced in DDL for the peer. §7's new sentence
   is conditional ("where a target engine cannot express a constraint in DDL") and so does not bind
   it in the same way. Worth confirming the cascade behaviour does not conflict with §6's "data is
   never destroyed implicitly" — a `CASCADE` on an ownership column is exactly the shape this
   repository rejected for that reason.

### Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **234 passed / 0 failed** (84 unit + 129 integration + 21 compliance) ·
`./scripts/test_e2e.sh` **841 / 841** · `./scripts/verify_convergence.sh` exit 0, byte-identity
check active and passing (17 converged, 1 known divergence, 0 drifted).

---

## Security hardening pass — master pinning, ownership rights, `can_view_execution`, frontend audit

`feat(security): pin master, refine owner rights, add can_view_execution & js test validation`

Six independent changes in one pass. Recorded together because three of them interact: ownership
became an editing route, which required ownership to also confer *visibility*, which changed what
the execution endpoints had to answer.

### 1. The Master's identity is pinned at boot (`src/master.rs`, new)

Every authorization decision branches on `api_key::Model::is_master`, read from a column on every
request. An attacker who reaches the database needs one statement to become Master:

```sql
UPDATE api_keys SET is_master = true WHERE id = '<attacker key>';
```

§5's uniqueness constraint refuses that, and this is the layer behind it — a constraint can be
dropped by the same access that would run the `UPDATE`, and it says nothing about the *running
process*, which is where the decisions are actually made.

`MasterPin::pin_at_boot` runs in `main.rs` before the listener binds. It asserts the §5 index is
present, asserts exactly one master row exists, and freezes that id for the process lifetime. All
three failures are fatal and each names its own remedy; a deployment whose master identity is
ambiguous cannot make authorization decisions, and guessing one is not this service's call.

**The enforcement point is `auth_middleware`, and that is the whole design.** A key whose column says
`is_master` but whose id is not the pinned one is *demoted* — `key.is_master` is set to `false` on
the record handed to handlers — before any handler sees it. The alternative, comparing an id at each
decision site, would be one forgotten call site away from worthless: there are dozens of
`key.is_master` reads in `api.rs`, and every one added later would be written by someone who never
read this module. Downstream code keeps reading `key.is_master` and is automatically correct, because
the principal it receives is the *effective* one rather than a copy of the row.

A demotion logs at `error` with a `TAMPER:` prefix. It has exactly one cause and no benign
explanation.

**What this does not claim.** It is not a defence against an attacker who can write the database *and*
restart the service, nor against one who repoints an existing Master row's `key_hash` at a credential
they hold. Nothing at this layer could be. It closes the specific, cheap, otherwise-invisible
escalation of flipping a boolean on a row you already control.

**Test/production parity.** The pin is a `OnceCell`: production primes it explicitly at boot,
everything else resolves it on first authenticated request. Both paths run the same resolution and
neither can replace a stored value. That parity matters more than the timing — a lazily-resolved test
build and a boot-pinned production build would mean the property under test is not the property
deployed. Resolution stores a value **only when exactly one master exists**, so a database with none
or several leaves every key non-master. The failure mode is "nobody is Master", never "the wrong key
is Master".

### 2. Ownership edits; ownership does not delegate

`guard_manage` gained a second route: `is_master` **or** `hook.owner_key_id == key.id` **or** the R2
conjunction. Delegation is untouched — `update_key_hook_permissions` and `revoke_key_hook_permission`
call `guard_hook_manage_conjunction` directly and still require R2 in full.

The previous pass left a model where a `can_manage_hooks` Daughter could create a hook and then never
touch it again, including the hook whose `owner_key_id` names it. That is not what §3 describes: it
makes the owner "the key answerable for this hook" and the only non-Master identity that may delete
or rename it. A caller who may destroy a resource outright but not edit its description is not a
position anyone would design on purpose.

The split that matters is **content versus credentials**. Owning a hook is authority over the hook;
handing out verbs on it is administering who else holds access, which is what R2 governs. A Daughter
owner can now rewrite its own hook's `script_path` and cannot widen anyone's access to it, including
its own.

**Ordering is load-bearing.** The owner check runs *before* the conjunction, because
`guard_hook_manage_conjunction` answers `404` when the caller holds no permission row, and an owner
need not hold one — ownership lives in a column on `hooks`. Asking the conjunction first would hide a
hook from the very key answerable for it.

**Consequential fix.** Adding ownership as an editing route made `guard_visibility` and
`visible_hook_ids` wrong: both filtered on permission rows only, so a hook whose `owner_key_id` had
been reassigned by Master to a key holding no row would have been *editable but unlistable* — `PUT`
succeeding while `GET` answered `404`. Both now treat ownership as conferring visibility.

### 3. `can_view_execution` (migration `m20260809_000001`)

`api_key_hook_permissions` gains a third verb: `BOOLEAN NOT NULL DEFAULT false`. No index — the column
is never searched on, only read from a row already fetched by the `(api_key_id, hook_id)` unique
index, and a boolean with a heavy skew toward `false` is close to the worst possible index candidate.

An execution record is now readable by exactly four identities: Master, the acting key, the hook's
owner, or a row carrying `can_view_execution` or `can_manage`. Everything else is `404`, byte-identical
to a record that never existed.

**Why a third verb rather than reusing one.** `can_execute` would mean every caller entitled to *run*
a hook is entitled to read what every other caller's runs printed — a CI key firing a deployment
would inherit the output of an operator's manual run. `can_manage` would put read-only audit access
behind R2's conjunction, so an auditor could be granted logs only by first being made a Parent with
editing authority over the hook — granting far more than was asked for, which is the shape R1 exists
to prevent. The auditor role (history, no execute, no manage) was simply not expressible before.

`can_manage` is one of the four routes because a key already entitled to rewrite `script_path` and
delete the history outright cannot meaningfully be denied *reading* it; withholding that would be
theatre. The verb itself stays read-only in every direction — `DELETE /api/executions/{id}` remains
behind `guard_manage`, because an auditor is not a redactor.

**Two behaviour changes worth stating plainly**, both widenings relative to what shipped before:

- A `can_manage` holder can now read a hook's history. Previously only the acting key and Master
  could. The e2e §38 checks and one integration test asserted the old rule and were updated.
- A caller keeps its *own* execution records after losing its grant on the hook. The previous
  implementation ANDed hook-visibility onto the creator filter, so revoking a grant also erased the
  key's record of its own past runs. §4 makes an execution visible to its creator, and a creator does
  not stop being one.

The listing expresses the four routes as a single indexed `WHERE` rather than filtering after the
fact, which would page wrongly: a `LIMIT 50` applied before a visibility filter returns fewer than
fifty visible rows and hides the rest behind an offset that never advances past them.

**R1/R6 coverage.** The new verb is wired into `is_permission_reduction` and
`guard_delegated_hook_grant`. Omitting it from either would have been a delegation hole on day one:
a write that *adds* history access while turning another verb off would have classified as a pure
reduction, and reductions skip R1 entirely — so a caller could have traded a verb it held for one it
did not.

### 4. Daughter keys (verified, not changed)

The rule was already enforced by `guard_master_to_grant_scopes` on both the create and update
routes; this pass added the tests that prove it rather than assuming it. A Parent requesting
`can_manage_keys` or `can_manage_hooks` on a key it mints gets `403`, and nothing is written.

**Refused rather than silently forced to `false`**, deliberately. A `200` carrying a key that lacks
what was asked for is the worse failure: the caller walks away believing it provisioned a Parent and
finds out in production. This mirrors the peer service's reasoning about `is_master` on a payload —
a security-relevant field that quietly means nothing is how a deployment ends up misconfigured with
nobody noticing.

### 5. Frontend audit — one live bug, and it was total

**`static/index.html` carried a "Master Access" checkbox whose value `createApiKey` sent as
`is_master`.** That field is on no key payload (§5), and both payload types are
`deny_unknown_fields` — so it was not ignored, it failed the whole request at the deserializer.
**Every key creation from the dashboard returned 422, for as long as the control existed.** Nothing
caught it: the e2e suite creates keys over HTTP with hand-built JSON and never loads the page.

Other changes:

- `can_view_execution` toggle in the hook-rights form; `V` in the per-key badge summary; a `History`
  badge in the hooks table.
- Global scope toggles are Master-only. The create form hides them (a Parent has no decision to make
  — every key it mints is a Daughter); the edit modal disables them but keeps them visible, because a
  Parent may legitimately need to see what the key it is editing already holds. Both **omit the
  fields** for a non-Master rather than sending `false`: the backend refuses a *request* for a scope,
  and re-sending a value a key already holds is still a request, so a Parent renaming a Parent key
  would otherwise have `403`d on a scope it was not trying to change.
- Hook row actions now mirror the server's predicates. `canEditHook` = Master ∨ owner ∨
  (`can_manage_keys` ∧ `can_manage`); `canDeleteHook` = Master ∨ owner. The old gate on `can_manage`
  alone was wrong in both directions — disabled for a Daughter owner who may edit, enabled for a
  Daughter holding a bare row who may not.
- An `Owner` badge, because "why can I edit this?" was otherwise unanswerable from the UI.
- `enforceRBACUI` re-runs after the hook list loads: the Hooks tab is reachable by a key that owns a
  hook and holds no global scope, and ownership is only visible in that response.

### 6. Zero raw SQL, and the two exceptions

**Audit result: `src/api.rs`, `src/retention.rs`, `src/middleware.rs` and `src/executor.rs` contain
no raw SQL at all.** Every statement built from anything a caller sent already went through SeaORM's
typed entities and expression builders. Two files remain, both unreachable from a request:

| File | Construct | Why the builder cannot replace it |
| :--- | :--- | :--- |
| `src/db.rs` | `PRAGMA journal_mode`, `PRAGMA busy_timeout` | A pragma is not a query — it configures how the engine behaves, not what it is asked — and SeaORM has no builder for one. Backend-gated to SQLite, issued once at startup, four of the six occurrences are in `#[cfg(test)]` |
| `m20230106_000001_master_key_uniqueness` | `ALTER TABLE ... GENERATED ALWAYS AS (...)` | `ColumnDef` has no generated-column support at all, and §5 requires the marker to be engine-derived rather than application-maintained. DDL, run once |

Neither interpolates a runtime value; the sole substitution across both is a compile-time `const`.
The property is now enforced by `no_raw_sql_outside_the_documented_exceptions` rather than
asserted once, and a companion test fails if an allowlisted file stops containing raw SQL — an
exemption must not outlive its justification and be silently inherited by whatever lands at that path
next.

**A trap found while testing this.** A `Uuid` is not bound as text on every backend, so a
hand-written `WHERE id = '<uuid>'` can match *nothing* and return `Ok`. Two of the new pinning tests
initially "passed" while tampering with zero rows. Both now mutate through the entity layer, which
still bypasses the application entirely — what those tests need to bypass is the *handler*, not the
ORM. The §5 adversarial tests are unaffected: they insert their own rows as text and their refusal
comes from the `master_marker` index, which does not involve `id`.

### 7. Harness safety

Both scripts assert their working directory before anything else, twice: the basename (catching an
inherited `cd`) and a list of marker files (catching a directory with the right name that is not this
checkout). Verified by running each from `/tmp` and from `example/simply_ip_vault` — both exit 1.

The convergence script needed it most. From the wrong directory its likely outcome was not an error
but a *false green*: missing paths report as skips, and a run of nothing but skips still reaches the
summary; from inside the peer snapshot the byte-identity check would have compared a file to itself.

### Breaking changes

1. **A `can_manage` holder can now read a hook's execution history**, including runs made by other
   keys. This is a widening. Operators who relied on history being creator-only should audit who
   holds `can_manage`:

```sql
-- Keys that gain read access to a hook's history under the new rule.
SELECT k.name AS key_name, k.prefix, h.name AS hook_name
FROM api_key_hook_permissions p
JOIN api_keys k ON k.id = p.api_key_id
JOIN hooks h    ON h.id = p.hook_id
WHERE p.can_manage = true AND k.is_master = false
ORDER BY h.name, k.name;
```

2. **A hook's owner can now edit it without `can_manage_keys`.** This reverses part of the previous
   pass's breaking change, and is a widening for Daughter owners specifically:

```sql
-- Keys that regain editing authority over hooks they own.
SELECT k.name AS key_name, k.prefix, COUNT(h.id) AS hooks_owned
FROM api_keys k
JOIN hooks h ON h.owner_key_id = k.id
WHERE k.is_master = false AND k.can_manage_keys = false
GROUP BY k.id, k.name, k.prefix
ORDER BY hooks_owned DESC;
```

3. **A hot-flipped `is_master` stops working**, which is the point. If any deployment was (somehow)
   relying on a second master row set directly in the database, it will now be treated as an ordinary
   key and the startup log will say so. Find them before upgrading:

```sql
SELECT id, name, prefix, is_master FROM api_keys WHERE is_master = true;
-- Must return exactly one row, or the service refuses to start.
```

4. **`POST /api/keys/{id}/permissions` writes `can_view_execution`.** The field is
   `#[serde(default)]` = `false`, so a client written before this verb existed keeps working and
   grants *less*, never more. Because the endpoint writes the whole row, an omitted field is
   indistinguishable from an explicit `false` — which is correct for "these are the rights" and worth
   knowing if a client re-submits a partial grant.

### Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **255 passed / 0 failed** (88 unit + 133 integration + 23 compliance + 8 source hygiene +
3 doc) · `./scripts/test_e2e.sh` **875 / 875** (was 841) ·
`./scripts/verify_convergence.sh` exit 0.

---

## Architecture pass — `src/api.rs` modularization, UI safety, audit baseline

`refactor(arch): modularize api routes, update ui design, pin master and add source hygiene`

Tasks 1, 3 and 5 of this brief were already satisfied by the previous commit (`9a1c499`) and were
**verified rather than reimplemented** — including the dialect unit test, which already asserts all
three backends:

```
Migration::add_marker_column(Postgres) ends_with "STORED"
Migration::add_marker_column(Sqlite)   ends_with "VIRTUAL"
Migration::add_marker_column(MySql)    ends_with "VIRTUAL"
```

The new work is the audit, the split, and the dialog-safety fix.

### Codebase audit — baseline before this pass

| File | Lines | Assessment |
| :--- | ---: | :--- |
| **`src/api.rs`** | **3,847** | **Monolithic.** Eight distinct responsibilities in one file |
| `src/executor.rs` | 1,389 | Coherent: one subject (spawning and bounding a child process) |
| `src/config.rs` | 1,374 | Coherent: environment parsing and proxy/CIDR resolution |
| `src/middleware.rs` | 704 | Coherent: authentication, one pipeline |
| `src/replay.rs` | 406 | Coherent |
| `src/crypto.rs` | 344 | Coherent |
| `src/main.rs` | 329 | Coherent: bootstrap and shutdown |
| `src/master.rs` | 291 | Coherent |
| `src/db.rs` | 204 | Coherent |
| everything else | ≤160 each | Entities and migrations, one subject each |

Line count alone is not the test — `executor.rs` is 1,389 lines about *one thing* and splitting it
would be churn. `api.rs` was the only file where the count tracked a real responsibility problem.

### Assessment of the proposed layout

The brief's baseline was `keys / hooks / executions / audit / guards / mod`. Before adopting it I
measured which private helpers are used from more than one handler domain, because that — not
intuition about naming — determines whether a shared module is needed. Result: **17 helpers cross
domain boundaries**, with these standing out:

| Helper | Used by |
| :--- | :--- |
| `create_audit_log` | hooks, params, keys, exec-trigger, exec-history |
| `resolve_hook` | hooks, params, keys, exec-trigger, exec-history |
| `format_reference` | hooks, params, keys, exec-trigger |
| `load_parameters` | hooks, params, exec-trigger |
| `guard_manage`, `guard_visibility` | hooks, params, exec-history |
| `guard_master_for_privileged_hook` | hooks, params, keys |
| `HookPermissionView`, `load_hook_permissions` | auth, keys |
| `ExecutionView` | exec-trigger, exec-history |

Three conclusions, and **three deviations from the proposed baseline, each earned by a measurement**:

1. **Added `support.rs`.** `create_audit_log`, `resolve_hook`, `format_reference` and
   `load_parameters` are used by three to five domains each and **decide nothing**. With no support
   module they would have had to live in `guards.rs`, which would make "guards" mean "guards, plus
   everything else that turned out to be shared" — the monolith problem again, one level down. The
   boundary is stated and checkable: *nothing in `support` returns a refusal that depends on who is
   calling.* A helper that starts deciding moves to `guards`.

2. **Folded `auth` into `keys.rs` rather than giving it a module.** `get_me` is ~95 lines and shares
   both its view type (`HookPermissionView`) and its loader (`load_hook_permissions`) with the key
   listing. A separate `auth.rs` would have put a type in one module and both its consumers in
   another. "What does this key hold" is the same question in both places.

3. **Renamed `audit.rs` → `system.rs`.** The module is `list_audit_logs` *and* `get_settings`.
   Settings is not audit, and a file called `audit.rs` whose second half reports runtime
   configuration sends the next reader to the wrong place.

**Confirmed without change:** one `guards.rs` rather than per-domain guards, and `executions.rs`
holding both triggering and history. The first because `RBAC_MODEL.md`'s rules are cross-cutting —
R2's conjunction governs hooks, parameters and execution records alike, and §3's ownership test is
consulted from three domains; splitting guards by caller would put one sentence of the specification
in three files and invite the copies to drift, which is exactly the failure the compliance suite
exists to catch and therefore should not be designed in. The second because `ExecutionView` is shared
by the two halves and by nothing else.

### Result

| Module | Lines | Holds |
| :--- | ---: | :--- |
| `api/mod.rs` | 85 | Module wiring, router-facing re-exports, shared policy constants |
| `api/system.rs` | 144 | Audit log, settings |
| `api/support.rs` | 399 | Shared plumbing, strict JSON extractors. Decides nothing |
| `api/executions.rs` | 436 | Trigger + history |
| `api/hooks.rs` | 892 | Hook CRUD, parameters, trash/restore/purge |
| `api/guards.rs` | 1,030 | Every authorization decision. Writes nothing |
| `api/keys.rs` | 1,102 | Key CRUD, `get_me`, grants, §6 cascade |

3,847 lines in one file → 4,088 across seven (the delta is module headers and import blocks).

**`src/lib.rs` is byte-identical.** Every handler is re-exported from `mod.rs`, so `api::create_hook`
resolves exactly as before and the router never learned this happened. That was a deliberate
constraint: a refactor that forces every call site to change has a blast radius nobody can review.

**Zero behaviour change.** Code moved verbatim; the only edits were visibility widening
(`pub(crate)` on the 17 cross-domain items) and import blocks. Verified by the suite: 252 tests and
875 e2e checks pass unchanged, including all 23 RBAC compliance tests and the adversarial suite.

**One class of defect the mechanical split introduced and the compiler caught:** four doc comments
landed on the wrong side of a line boundary and attached themselves to the *next* item — the
`load_parameters` doc ended up above `normalize_run_as_user`, and so on in a four-way rotation.
Clippy's `empty line after doc comment` found all four. Worth knowing for any future range-based
split: item boundaries are not line boundaries, and a doc comment is part of its item.

### UI: a real safety defect in the confirmation dialog

The confirm modal already used `.btn-danger` for the destructive action and `.btn-secondary` for
Cancel, at opposite edges of the card. What it also did was **auto-focus the destructive button and
bind Enter to confirm**. A user who was typing when the dialog opened, or who hit Enter reflexively,
destroyed data — in the one place where the action cannot be undone.

Fixed: for `danger: true`, focus moves to **Cancel**, and Enter no longer confirms. Escape still
cancels either way, so the safe answer stays the reflexive one, and the destructive path is one Tab
away rather than unreachable. Non-destructive dialogs keep Enter-to-confirm.

That change depends on the user being able to *see* where focus landed, and buttons had **no
`:focus-visible` style at all** — only the browser default, which against these surface colours is
somewhere between faint and invisible. Added an accent ring, with a red variant for `.btn-danger`,
`.btn-logout` and `.btn-batch-delete` so a focused Delete never looks like a focused Cancel.

The dialog also gained `role="alertdialog"`, `aria-modal`, and `aria-labelledby`/`aria-describedby`
pointing at its title and message, so a screen reader announces the question rather than the word
"dialog".

`justify-content: space-between` on `.modal-actions` now carries a comment explaining that it is
deliberate — it drives the safe and destructive choices to opposite edges, and "tidying" it to
`flex-end` would put two buttons a few pixels apart where one deletes data and the other does not.

### Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **252 passed / 0 failed** · `./scripts/test_e2e.sh` **875 / 875** ·
`./scripts/verify_convergence.sh` exit 0.

---

## Structural & functional distribution audit vs `simply_ip_vault`

Read-only comparison of where capabilities live in each codebase, plus the two new mapping documents
(`FILE_MAP.MD`, and a structure section in `README.md`). No file under `src/` was modified.

**Reference state.** `./example/simply_ip_vault` remains a flat snapshot with no git metadata; no
`git` command was run inside it. Comparison is by file listing and symbol grep.

### Size baseline

| | `simply_hook_executor` | `simply_ip_vault` |
| :--- | ---: | ---: |
| `src/` total | 11,247 | ~9,100 |
| Largest file | `executor.rs` 1,389 | `api/keys.rs` 1,372 |
| `api/` total | 4,088 across 7 | 2,523 across 6 |
| `api/guards.rs` | **1,030** | **463** |
| `api/mod.rs` | **85** | **267** |
| `state.rs` | **80** | **330** |

The three bolded pairs are the whole story of the structural divergence, and they are not
independent: our `guards.rs` is large because it absorbed helpers the peer keeps in `keys.rs`, our
`api/mod.rs` is small because we extracted `support.rs`, and our `state.rs` is small because we
extracted `master.rs`.

### Comparative function & responsibility matrix

**Identical alignment** — same concept, same file role:

| Capability | `simply_hook_executor` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Router assembly | `lib.rs::create_app` | `lib.rs::create_app` |
| Entrypoint, migrate → bootstrap → pin → bind | `main.rs` | `main.rs` |
| Graceful shutdown | `main.rs::shutdown_signal` | `main.rs::shutdown_signal` |
| Authentication pipeline | `middleware.rs::auth_middleware` | `middleware.rs::auth_middleware` |
| Master demotion of tampered rows | `middleware.rs` (via `MasterPin::authenticate`) | `middleware.rs` (via `is_effective_master`) |
| Environment config, proxy trust, client IP | `config.rs` | `config.rs` |
| Replay single-use | `replay.rs::ReplayGuard` | `replay.rs::ReplayGuard` |
| Retention worker | `retention.rs` | `retention.rs` |
| Connection pragmas | `db.rs` | `db.rs` |
| Error type → HTTP | `error.rs::AppError` | `error.rs::AppError` |
| Entities, one per table | `entities/` | `entities/` |
| Ordered migrations | `migration/` | `migration/` |
| Key CRUD + identity (`get_me`) | `api/keys.rs` | `api/keys.rs` |
| RBAC guards | `api/guards.rs` | `api/guards.rs` |

`get_me` living with key CRUD rather than in an `auth` module was decided independently in both
codebases, for the same reason: it shares its view types with the key listing.

**Guard correspondence** — same rules, different names. Both files implement `RBAC_MODEL.md`:

| Rule | `simply_hook_executor` | `simply_ip_vault` |
| :--- | :--- | :--- |
| R2 conjunction | `guard_hook_manage_conjunction` | `guard_group_manage` |
| R2 pre-payload standing | `has_permission_admin_standing` | `guard_may_administer_any_group` |
| "holds manage somewhere" | `manages_any_hook` | `holds_any_group_manage` |
| R1 delegation bound | `guard_delegated_hook_grant` | `guard_delegated_group_grant` |
| R6 revocation classification | `is_permission_reduction` | `widens_permissions` *(inverse polarity)* |
| R4 scope elevation | `guard_master_to_grant_scopes` | `guard_scope_elevation` |
| §3 lifecycle | `guard_lifecycle_authority` | `guard_resource_lifecycle` |
| §3 owner lookup / reassignment | inline in `guard_manage` / `update_hook` | `resource_owner` / `resolve_owner_assignment` |
| §5 master as target | `refuse_master_lifecycle_action` | `guard_master_target` |
| §5 master immutability | `guard_master_self_edit_is_bound_ips_only` | `guard_master_immutable` |
| Per-resource permission fetch | `hook_permission` | `caller_group_permission` |

`is_permission_reduction` and `widens_permissions` are the same predicate with opposite polarity —
worth knowing when reading the two side by side, because the call sites negate in opposite places.

**Functional misplacement** — same capability, different host file:

| Capability | `simply_hook_executor` | `simply_ip_vault` | Assessment |
| :--- | :--- | :--- | :--- |
| Shared non-guard helpers (`create_audit_log`, resource resolution, `hash_key`) | `api/support.rs` (named module) | `api/mod.rs` (267 lines, mixed with wiring) | **Ours is clearer.** The peer's `mod.rs` is both the router surface *and* the helper drawer; ours separates them and states a testable boundary ("decides nothing") |
| Master pinning | `master.rs` (dedicated, 291 lines) | `state.rs` (`pin_master_key`, `MasterPinError`, `resolve_master_key_id`) | **Ours is clearer.** Theirs mixes a security control with a handle bag; `state.rs` is 330 lines as a result |
| HMAC request signing | `middleware.rs` (inline) | `crypto.rs` (`canonical_v1_payload`, `compute_signature`, `verify_signature`) | **Theirs is clearer.** They have reusable, separately-testable signature functions; ours are inline in the auth pipeline. This is the one place the peer's layout is better, and it is the top item in the proposal below |
| §4 key-visibility helpers | `api/guards.rs` (`key_visibility`, `descendant_key_ids`, `managed_hook_ids`, `load_administrable_key`) | `api/keys.rs` (`collect_key_subtree`, `groups_the_caller_manages`, `caller_can_administer_key`, `find_administrable_key`) | **Theirs is arguably better placed.** All four of ours are used by `keys.rs` *and nothing else* — see proposal |
| Reference formatting | `api/support.rs::format_reference` | `api/guards.rs::format_key_reference` | **Ours is correct.** Formatting is not a guard; the peer has the misplacement here |
| Strict JSON extractor | `api/support.rs` | `extract.rs` (top-level module) | Cosmetic. Ours also carries `OptionalStrictJson`, which the peer lacks |
| Audit log + settings endpoints | `api/system.rs` (both) | `api/audit.rs` (54 lines, audit only) | **Deliberate divergence.** Our module is audit *and* `/api/settings`; a file called `audit.rs` whose second half reports configuration misleads. The peer's is genuinely audit-only, so its name is right for it |

**Missing module / concept** — present in one codebase only:

| Concept | Where | Why |
| :--- | :--- | :--- |
| `executor.rs` (1,389) | Ours only | We execute local scripts; the peer dispatches HTTP. No equivalent is possible or wanted |
| `webhooks.rs` (519) + `api/webhooks.rs` (580) | Peer only | Outbound dispatch worker and its CRUD. Our dispatch config lives *on* the Hook row, per `RBAC_MODEL.md`'s Terminology section |
| `api/support.rs` | Ours only | Peer's equivalents are in `api/mod.rs` |
| `master.rs` | Ours only | Peer's equivalent is in `state.rs` |
| `extract.rs` | Peer only | Ours is in `api/support.rs` |
| `api/audit.rs` | Peer only | Ours is `api/system.rs`, which is broader |
| `api/records.rs`, `api/groups.rs` | Peer only | Their resource-data model; our `hook_parameters` are governed inside `api/hooks.rs` |
| `api/executions.rs` | Ours only | Executions are our creator-private entity |

### Infrastructure & health handlers

**Neither codebase exposes a healthcheck, readiness probe, or version endpoint.** Verified by
grepping both for `/health`, `/healthz`, `/readyz`, `/ready`, `/version`: zero route registrations in
either. Graceful shutdown is present and *identically placed* in both (`main.rs::shutdown_signal`,
wired via `axum::serve(...).with_graceful_shutdown(...)`), and both retention workers take a shutdown
channel so they stop cleanly rather than being killed mid-sweep.

This is a **symmetric gap, not a divergence.** It is worth recording as a finding in its own right:
neither service can be probed by an orchestrator without an authenticated request, and every route in
both is behind `auth_middleware` by design. Adding one is a deliberate decision with a real
trade-off — an unauthenticated `/healthz` is an unauthenticated route in a service whose stated
posture is that it has none — so it is proposed below rather than assumed.

### Shared utilities & DTOs

| Utility | `simply_hook_executor` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Bearer key hashing (`hash_key`) | `api/support.rs` | `api/mod.rs` |
| Key/secret generation | `api/support.rs` | `api/mod.rs` + `crypto.rs::generate_signing_secret` |
| Secret encryption at rest | `crypto.rs::SecretCipher` | `crypto.rs::SecretCipher` |
| HMAC compute/verify | `middleware.rs` (inline) | `crypto.rs` |
| Error wrapper | `error.rs::AppError` (10 variants) | `error.rs::AppError` (10 variants) |
| DTOs / view types | Co-located with their handlers | Co-located with their handlers |

`AppError` variants are nine-tenths identical. Ours has `TooManyRequests` (concurrency throttling, no
peer equivalent); theirs has `ConflictWithDetails`. Both carry `BodyRejected`, which preserves the
extractor's own status rather than flattening to `400` — independently arrived at in both codebases.

**DTO placement is aligned:** neither service has a shared `dto.rs`. Request payloads and view structs
sit next to the handlers that use them, which is why `HookDetail` is in `hooks.rs` and
`ApiKeySummary` in `keys.rs`.

### Correction to an earlier audit finding

The comparative security audit recorded in this file previously stated that the peer's §5 master
uniqueness was **weaker than ours** because its `master_marker` was an application-maintained
`VARCHAR(16)`, so `is_master = true` with a `NULL` marker was an accepted second master.

**That finding is now stale.** The peer has since added
`m20260808_000009_derive_master_marker`, which replaces the hand-maintained column with an
engine-derived generated column. Its module documentation describes the exact bypass — including a
worked `INSERT` demonstrating two master rows — and fixes it the same way ours does. **The two
services are now aligned on §5**, and the adversarial tests added here would pass against the peer.

This is recorded rather than quietly dropped because the earlier note is still in this file above,
and a reader arriving at it should not act on it.

### Prioritized, non-destructive refactoring proposal

None of this was executed — this session was read-only by instruction. Ordered by value.

**P0 — `PRAGMA foreign_keys=ON` is never set, and six declared foreign keys are inert on SQLite.**
Found by the convergence checker during this audit, not by looking for it. The peer's
`apply_sqlite_pragmas` has grown `foreign_keys=ON` and `synchronous=NORMAL`; ours still sets only
`journal_mode=WAL` and `busy_timeout`. **SQLite ignores foreign keys unless that pragma is set on
each connection**, and `m20230101_000001_initial_schema` declares six:

| Table | Column | Action |
| :--- | :--- | :--- |
| `api_key_hook_permissions` | `api_key_id` | `CASCADE` |
| `api_key_hook_permissions` | `hook_id` | `CASCADE` |
| `hook_parameters` | `hook_id` | `CASCADE` |
| `executions` | `hook_id` | `CASCADE` |
| `executions` | `api_key_id` | `SET NULL` |
| `audit_logs` | `api_key_id` | `SET NULL` |

So on the default backend a hard-deleted hook currently leaves its permission rows, parameter
declarations and execution history behind as orphans rather than cascading, and the same applies to a
deleted key's permission rows. Note this is **distinct from — and does not contradict —** the
deliberate absence of foreign keys on `parent_key_id`/`owner_key_id` in `m20230107`: those were
omitted on purpose because both available behaviours are wrong for §6. These six were *declared* and
are simply not being enforced.

Not fixed here because this session was read-only by instruction, and because it is not a one-line
change: enabling enforcement against an existing database can surface violations that were silently
tolerated while the pragma was off, so it needs a migration-time audit query and probably a cleanup
pass for rows already orphaned. Worth doing early — the cost grows with the amount of orphaned data.

Operator query to size the problem before enabling it:

```sql
-- Orphaned permission rows, parameters, and executions (run per table).
SELECT COUNT(*) FROM api_key_hook_permissions p
  LEFT JOIN hooks h ON h.id = p.hook_id WHERE h.id IS NULL;
SELECT COUNT(*) FROM api_key_hook_permissions p
  LEFT JOIN api_keys k ON k.id = p.api_key_id WHERE k.id IS NULL;
SELECT COUNT(*) FROM hook_parameters hp
  LEFT JOIN hooks h ON h.id = hp.hook_id WHERE h.id IS NULL;
SELECT COUNT(*) FROM executions e
  LEFT JOIN hooks h ON h.id = e.hook_id WHERE h.id IS NULL;
```

`synchronous=NORMAL` is the lesser half of the same divergence and is a durability/throughput
trade-off rather than a correctness one; adopt or decline it deliberately when the above is fixed.

**P1 — Extract HMAC signature computation from `middleware.rs` into `crypto.rs`.**
The only place the peer's layout is clearly better. Move the canonical-string construction and
constant-time verification into named, separately-testable functions
(`canonical_v1_payload`, `compute_signature`, `verify_signature`), leaving `middleware.rs` to
sequence the pipeline. Benefits beyond tidiness: `scripts/verify_convergence.sh` already compares
"Signature canonicalization" between the two services, and comparing two named functions is more
robust than comparing a region of a 704-line middleware. **Risk: low** — pure extraction, no
behaviour change, fully covered by the existing HMAC integration tests. Est. ~150 lines moved.

**P2 — Move the four §4 key-visibility helpers from `api/guards.rs` to `api/keys.rs`.**
`key_visibility`, `descendant_key_ids`, `managed_hook_ids` and `load_administrable_key` are each used
by `keys.rs` **and nothing else** — confirmed by the coupling measurement recorded above, and the peer
places its equivalents in `keys.rs`. This would take `guards.rs` from 1,030 to roughly 870 lines and
leave it holding only genuinely cross-domain rules. **Counter-argument, and the reason this is P2
rather than P1:** they *are* authorization decisions, and `AGENT.MD` states that `guards.rs` holds
every authorization decision. Moving them weakens a rule that is currently absolute and easy to check
in exchange for locality. Recommend either moving all four *and* amending `AGENT.MD` to say
"cross-domain authorization decisions", or leaving them and accepting the size. **Do not do half.**

**P3 — Decide the healthcheck question explicitly.**
Neither service has one. Either add `GET /healthz` (unauthenticated, no body beyond liveness — and
note this makes it the *only* unauthenticated route besides the static SPA, which contradicts the
current stated posture) or record in `AGENT.MD` that its absence is deliberate and that orchestrators
should use a TCP connect probe. Right now it is neither decided nor documented, which is the worst of
the three states. **Risk: low either way; the cost is the decision, not the code.**

**P4 — Consider aligning `format_reference` placement in the peer.**
Peer-side only: their `format_key_reference` sits in `guards.rs` and formats a string. Nothing to do
here; noted so a future cross-repo pass has it on the list.

**Explicitly not proposed:** merging `api/system.rs` back into an `audit.rs` to match the peer. The
divergence is deliberate and the name is more accurate than the peer's would be for our contents.
Also not proposed: splitting `executor.rs`. It is 1,389 lines about one subject, and the line count
tracks depth of defence rather than a responsibility problem.

### Gates

`src/` and `tests/` untouched. One change to `scripts/verify_convergence.sh`: the peer's
`apply_sqlite_pragmas` moved file, so the checker's hardcoded lookup path was corrected and the
fingerprint re-baselined against the drift that correction exposed (see above). No application or
business logic was altered. `git diff RBAC_MODEL.md` empty. `cargo check --all-targets` clean ·
`cargo clippy --all-targets -- -D warnings` clean · `cargo test` **252 passed / 0 failed** ·
`./scripts/test_e2e.sh` **875 / 875** · `./scripts/verify_convergence.sh` exit 0.

### Convergence Parity Check — accepted divergence (re-baselined this session)

`scripts/verify_convergence.sh` went **red during this audit** and that is the headline result of it.
Two separate things had happened since the last run, and the checker caught both:

1. **A stale path became a skip.** The script looked for the peer's `apply_sqlite_pragmas` in
   `src/state.rs`; the peer has since moved it to `src/db.rs` — the file ours has always been in, so
   the two now agree on placement as well as behaviour. The check did not silently pass against a
   function it could no longer find: it refused to report and failed the run, which is the only
   reason the move was noticed. *A skip is not a pass*, and this is what that rule is for.

2. **Fixing the path revealed real drift** — the `foreign_keys=ON` gap recorded as **P0** above.

The fingerprint has been re-baselined to `3377969800` so that *further* drift in this function is
still caught. The recorded rationale says `OPEN (P0)` rather than "cosmetic", deliberately: this is a
tracked defect being watched, not a difference that has been blessed.

---

# Session — P0/P1/P3 remediation: FK enforcement, HMAC extraction, `api/audit.rs`, health probes

Acting on the prioritized proposal recorded in the previous (read-only) session. Four scoped changes
plus the harness realignment they forced.

## P0 — SQLite foreign keys: **the previous finding was wrong, and this corrects it**

The last session recorded, as its headline result, that this service's six declared foreign keys were
**inert** on SQLite because `src/db.rs` set only `journal_mode` and `busy_timeout` and never
`PRAGMA foreign_keys=ON`. The reasoning was sound and the conclusion was false. I checked before
acting on it, and the check is the first thing worth recording:

```
PROBE foreign_keys=1          # file-backed, bare Database::connect
PROBE mem foreign_keys=1      # sqlite::memory:
PROBE orphan insert refused = true
PROBE err = Query Error: error returned from database: (code: 787) FOREIGN KEY constraint failed
```

**SQLx enables foreign keys on every SQLite connection it opens.** The constraints have been enforced
the entire time; cascades have always fired. The audit's error was reasoning from *our* source alone
about a setting a dependency was already applying — the class of mistake where the code you can read
is not the code that decides.

Consequences for the task as scoped:

- **No orphan-cleanup migration was written, and that is the finding, not an omission.** The task
  allowed for one "if necessary". It is not: there was never a window in which enforcement was off,
  so there are no orphans to clean. Writing a migration that deletes rows matching a condition that
  cannot hold would have been a destructive no-op — real risk, zero benefit. An operator who wants to
  confirm this against a specific database can run `PRAGMA foreign_key_check;`, which returns one row
  per violation and nothing for a clean database; that is recorded in `SCHEMA.MD` rather than
  automated, because it is a one-time reassurance and not an invariant needing a sweep.
- **The pragma is now set explicitly anyway.** Not as a repair — as hardening. A defaulted
  security-relevant setting is one a dependency can revise in a point release, and the failure mode of
  that revision is silent: orphans accumulate and nothing errors. Declaring it pins the behaviour to
  this crate's intent.

### What actually changed in `src/db.rs`

`connect()` and `run_migrations()` are new; `apply_sqlite_pragmas` gained `foreign_keys=ON` and
`synchronous=NORMAL`. `main.rs` calls `db::connect` instead of `Database::connect`.

`connect()` exists for a reason the pragma statements cannot cover: **SQLx replays a reopened
connection's options but not our `PRAGMA` statements**, so a connection recycled after an invalidation
would come back without them. Declaring them through `SqliteConnectOptions` is what makes them
survive that. `apply_sqlite_pragmas` is still called and still earns its place — it reads
`journal_mode` back, so the startup log reports what is *in force* rather than what was requested, and
it covers pools this crate did not build (every pool in the test suite).

`SQLITE_MAX_CONNECTIONS = 1` is pinned explicitly. SeaORM's `Database::connect` does this for SQLite;
hand-building a pool from `SqliteConnectOptions` opts out of that default **silently**, and at any
pool size ≥ 2 `m20230106`'s drop-and-re-add of the generated `master_marker` column lands on a
connection whose schema still has the old one. The peer hit exactly this and documented it; taking
their fix without re-deriving the bug was the point of having a peer to read.

Of the four settings, only **`synchronous=NORMAL` is a behaviour change** — the driver default is
`FULL`. The other three were already in force and are now asserted.
`synchronous_normal_is_a_real_change_from_the_driver_default` pins that distinction against a bare
`Database::connect`, so if SQLx ever changed its default the test goes red and says so, rather than
continuing to pass while the code setting it had quietly become redundant.

### `tests/referential_integrity.rs` (6 tests) — the gap that was real either way

The pragma was never the missing piece. **Nothing in the repository asserted that any of the six
foreign keys fired**, and that gap was genuine regardless of who was right about the pragma. The new
suite pins behaviour, not configuration:

| Test | Pins |
| :--- | :--- |
| `deleting_a_hook_cascades_to_permissions_parameters_and_executions` | Three `CASCADE` edges, with a sibling hook present so a cascade that reached too far is caught |
| `deleting_a_key_cascades_grants_but_only_nulls_execution_and_audit_attribution` | The `CASCADE`/`SET NULL` **asymmetry**, including that the denormalized `api_key_name`/`prefix` survive |
| `a_row_referencing_a_nonexistent_parent_is_refused_at_insert` | The constraint in the *other* direction — a row cannot be created dangling |
| `a_parameter_cannot_be_attached_to_a_hook_that_does_not_exist` | The edge a hook purge relies on |
| `purging_a_trashed_hook_leaves_no_orphaned_children` | The **shipped path**: `purge_expired_deleted_hooks` deletes from `hooks` alone and never touches child tables |
| `key_lineage_and_ownership_columns_are_unconstrained_by_design` | An **absence** — see below |

**Mutation-verified.** With `PRAGMA foreign_keys=OFF` injected into `setup_test_db`, five of the six
go red. The sixth stays green, correctly: it asserts that `parent_key_id` and `owner_key_id` carry no
constraint, which is unaffected by the pragma. That split is the evidence the suite tests what it
claims rather than the fixture.

That sixth test asserts an absence, which deserves justification. `m20230107` omits those FKs
deliberately: `CASCADE` would delete a hook when its owner key is deleted — exactly what
`RBAC_MODEL.md` §6 forbids — and `SET NULL` would silently orphan the resource at the moment of
deletion, which is the outcome §6's pre-flight inventory exists to prevent by **refusing** instead.
The test exists so that a future migration "fixing the missing constraint" is met with a red test
explaining why not, rather than shipping and breaking §6.

## P1 — HMAC extraction into `src/crypto.rs`

`signature_base` and `verify_signature` moved out of `middleware.rs` and became
`canonical_v1_payload`, `compute_signature`, `verify_signature`, `SIGNATURE_PREFIX` and
`SignatureRejection`. `generate_signing_secret` moved from `api/support.rs`, and is deliberately
**not** re-exported from `api/mod.rs` — a re-export would recreate the "where do I find the crypto?"
ambiguity the move exists to remove. `mint_signing_pair` calls through to `crypto`.

### Deviation from the task's proposed signatures, and why

The task sketched `canonical_v1_payload(...) -> String`, `compute_signature(secret: &[u8], payload:
&str) -> String`, `verify_signature(...) -> bool`. All three shipped differently:

- **`-> Vec<u8>` rather than `String`** for the payload. A signed body is arbitrary bytes and need not
  be UTF-8 — `BODY_ONLY` exists precisely to accept senders whose format we do not control. A
  `String` return would make signing depend on the payload being decodable.
  `a_body_that_is_not_valid_utf8_still_signs_and_verifies` pins this.
- **`-> Result<Vec<u8>, SignatureRejection>` rather than `-> bool`** for verification. The digest
  bytes are what `ReplayGuard` keys on; returning `bool` would force the middleware to re-decode the
  header, and the *decoded bytes* are what makes `sha256=AB…` and `sha256=ab…` the same single use
  rather than two. `the_same_signature_in_either_hex_case_verifies_to_the_same_digest` pins that.
- **Four rejection variants rather than a boolean.** The existing pipeline returns three distinct
  `401` messages and one `500`, and the task required "without changing the authentication pipeline
  behavior". A `bool` cannot carry that. `SignatureRejection` does, and
  `middleware::reject_signature` — the only new function in `middleware.rs` — maps it back. Note what
  is deliberately *not* distinguished: `Mismatch` covers a tampered payload, a wrong secret and a
  wrong-width tag alike, because telling those apart is exactly the oracle an attacker wants.

`crypto.rs` takes no `AppError`, no database and no request. That purity is the module boundary and
it is testable: `every_single_byte_mutation_of_a_valid_signature_is_rejected` (96 mutations) is
practical here and would need a router, a pool and a seeded key against the middleware.

Ten unit tests moved with the primitive and five were added: the non-UTF-8 body, hex-case
equivalence, the correct-but-untagged digest, the empty secret (which is *valid* HMAC key material —
`KeyUnusable` exists for a case HMAC-SHA256 makes unreachable, and it would be easy to assume "empty
secret" is that case), and secret generation width/uniqueness.

## `src/api/audit.rs` — reversing a previous decision

The last session defended keeping `system.rs` as-is and explicitly listed splitting it as *not
proposed*: "the divergence is deliberate and the name is more accurate than the peer's". **That
defence was of the name, not of the grouping, and it does not survive the question actually being
asked.** `system.rs` grouped the audit log with the settings endpoint because both are master-only —
organizing by *audience*, which is the weakest available axis, since nearly every administrative
endpoint in the service shares it.

The two halves differ in every way that matters for change: `audit.rs` reads a growing table and will
keep acquiring query surface (filter by acting key, by target, by time range), while `system.rs`
reports a struct fixed at startup plus three `COUNT(*)`s. No shared state, no shared types, no reason
to be edited together. Splitting them also removes the last naming divergence from the peer, which
reached `api/audit.rs` independently — corroboration rather than fashion.

Both files gained a header stating what is *not* in them, because the likely error is specific:
**writing** an audit row is `support::create_audit_log`, called from a dozen mutating handlers.
`audit.rs` is the reader of a table many call sites write to, and putting the writer there would drag
an import into every handler module for no gain.

## P3 — health and readiness probes

The previous audit recorded the absence of monitoring endpoints as a **symmetric gap** — neither
service had them — and filed it as P3 because it was "neither decided nor documented". Now decided.

`GET /health` + `/healthz` and `GET /ready` + `/readyz`, mounted on the root router outside both
`nest()` calls so no auth layer is in their path. Three properties are load-bearing:

1. **Unauthenticated by design.** An orchestrator holds no API key, and a liveness check that needs
   one fails exactly when the credential store is what broke.
2. **Liveness must not touch the database.** `health_check` takes no `State` — enforced by the
   compiler, not by a comment. Conflating the two is the classic way to turn a brief dependency
   outage into an outage of your own: if liveness checked the database, a thirty-second blip would
   fail liveness on *every* replica and the orchestrator would restart all of them, which does not fix
   a database and does destroy in-flight executions.
3. **Public means disclosing nothing.** No version, no hostname, no counts, no driver error. `DbErr`
   renders connection strings and driver internals; it is logged at `warn` and never returned. The
   body is asserted to be exactly two fixed fields, so a field added later trips a test and must be
   justified rather than arriving unnoticed on a public endpoint.

`503` rather than `500` for a dead database: nothing about the request failed — the answer *is* "not
ready", and it was produced successfully. `503` is what tells a well-behaved proxy to stop routing
and retry.

**The raw-SQL allowlist gained its third entry, and the guard caught it.** `SELECT 1` tripped
`no_raw_sql_outside_the_two_documented_exceptions` on the first full test run, which is the gate
working. It earns its exemption differently from the other two: those are unreachable from a request
(startup pragmas, DDL), while this one *is* request-reachable and anonymous. Its justification is that
the statement is a literal with no table and nothing to interpolate — a probe that read rows would let
an anonymous caller provoke unbounded work, which is a denial-of-service primitive aimed at the
endpoint that reports health. The test was renamed to `no_raw_sql_outside_the_documented_exceptions`,
since "two" was in the name.

`tests/health_probes.rs` (7 tests) covers the probes at router level, including a **closed pool** so
readiness is not merely indistinguishable from liveness in every test — without it, a version that
ignored its query result and always answered `200` would pass everything else. Two tests guard the
mounting rather than the handlers: a bogus `X-API-Key` is *ignored* (positive evidence no auth layer
is in front, which "works without a header" alone does not prove), and `/api/*` still answers `401`
(the `.merge` that mounted the probes could have taken the auth layer off the API tree). 11 further
checks in `scripts/test_e2e.sh` exercise them against a real server, where the risk is different:
`ServeDir` is live, and whether `/health` reaches the handler or a file on disk is a question about a
real filesystem.

## Harness — convergence went from 17/1-known/1-skipped to **19/0/0**

Three script changes, all consequences of code moving rather than baseline adjustments:

- **`Signature canonicalization`** compared `src/middleware.rs::signature_base` against
  `src/crypto.rs::canonical_v1_payload`. Both sides are now `src/crypto.rs::canonical_v1_payload`, so
  the rule compares like with like instead of relying on `normalize()` to rename one into the other.
  The alias stays in `normalize()` regardless — it costs nothing and keeps the check working against
  an older checkout.
- **`verify_slice` presence** repointed to `src/crypto.rs`. The *absence* rule (no `==` on MACs) now
  runs against **both** files: the primitive moved, but `middleware.rs` is exactly where someone would
  reintroduce a hand-rolled comparison "just to check the header first", and a rule that stopped
  looking there would not notice.
- **`SQLite pragma initialization` — KNOWN-2 retired.** The two functions now compare **equal**, so
  the entry converged rather than being re-baselined again. One cosmetic difference remained after
  the pragmas were added (a braced vs. unbraced `tracing::info!` arm) and was resolved by matching the
  peer, not by accepting a new fingerprint. The stale rationale — which asserted the six FKs were
  inert — is replaced in the script with the correction, so the wrong claim does not survive in the
  one file that gets read during an incident.

**This closes the largest structural divergence between the two codebases.** The previous audit
recorded request-signature computation living in `middleware.rs` here and `crypto.rs` in the peer as
the single biggest layout difference; both are now `crypto.rs`.

## Corrections to the record made this session

Recorded explicitly rather than by quietly editing, because both were stated as findings above and a
reader scrolling up will meet the wrong version first:

1. **"Six foreign keys are inert on SQLite" — false.** SQLx sets `foreign_keys=ON`; they were always
   enforced. Corrected in `AGENT.MD` §3b, `SCHEMA.MD`, `src/db.rs`, `tests/referential_integrity.rs`
   and `scripts/verify_convergence.sh`.
2. **"Splitting `system.rs` is not proposed" — reversed.** The argument defended the *name*
   `system.rs`, which remains right for what that file now holds; it did not defend keeping two
   unrelated subjects in one file.

## Remaining from the previous proposal

**P2 — moving the four §4 key-visibility helpers from `guards.rs` to `keys.rs`** is not done. It is
all-or-nothing (splitting them would put one rule in two files, the failure `guards.rs` is one module
to avoid) and requires amending `AGENT.MD`'s "`guards.rs` holds every authorization decision" rule.
That is a rule change, not a refactor, and it was not in this session's scope.

## Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **275 passed / 0 failed** (98 unit + 133 integration + 23 compliance + 8 hygiene +
7 health + 6 referential integrity) · `./scripts/test_e2e.sh` **886 / 886** ·
`./scripts/verify_convergence.sh` exit 0 — **19 converged, 0 known divergences, 0 drifted, 0
skipped** · `git diff RBAC_MODEL.md` empty.

---

# Session — P2: §4 key-subtree visibility moved to `api/keys.rs`

The last item from the audit's prioritized proposal, and the one deferred twice because it needed a
rule change rather than a refactor. Following `2897b80`.

## What moved

`KeyVisibility`, `descendant_key_ids`, `managed_hook_ids`, `key_visibility` and
`load_administrable_key` moved from `src/api/guards.rs` to `src/api/keys.rs`. `guards.rs` 1,030 →
932 lines; `keys.rs` 1,102 → 1,256.

**`KeyVisibility` moved too, though the task named only the four functions.** It is
`key_visibility`'s return type and has no other use anywhere in the crate. Leaving the enum behind
while its producer and both its consumers moved would have been worse than either placement — a type
in one file whose entire reason to exist is in another.

## Verifying the premise before acting on it

The task asserted these are "exclusively consumed by key handlers". Checked rather than assumed:

```
key_visibility          → guards.rs:786 (self), keys.rs:923
descendant_key_ids      → guards.rs:750 (self), keys.rs:414, keys.rs:622
managed_hook_ids        → guards.rs:755 (self), keys.rs:419
load_administrable_key  → keys.rs:484, keys.rs:692, keys.rs:831
```

Every reference outside `guards.rs` is in `keys.rs`, and every reference *inside* `guards.rs` is one
cluster member calling another (`key_visibility` uses the two id-collectors; `load_administrable_key`
uses `key_visibility`). So the five form a **closed cluster**: nothing outside calls into its
middle, and it calls nothing outside itself. That is what makes the move safe — a group with an
external caller in a third domain could not have moved without splitting a rule.

## They are now module-private, and that is the substance of the change

All five dropped from `pub(crate)`/`pub` to private. This is not tidying: it converts "only the key
domain uses these" from a claim in a comment into **a fact the compiler checks**. If a second domain
ever needs one, the build breaks and forces an explicit decision — widen the visibility and accept it
is cross-domain after all, or move the cluster back — instead of the boundary eroding one `use` at a
time, which is exactly how `guards.rs` would have become a junk drawer.

`KeyVisibility` was `pub` and therefore nominally part of the crate's public API; it is now private.
Nothing outside the crate could meaningfully have used it (it is an internal RBAC classification with
no public constructor), and no test referenced it.

## The rule this needed, and its honest cost

`AGENT.MD` §0 said `guards.rs` holds **every** authorization decision. That sentence had to change,
and the risk in changing it is that "some guards live elsewhere" becomes a licence to scatter them.
So the amendment is a *test*, not a permission — a helper leaves `guards.rs` only when **both** hold:

1. exactly one handler domain calls it, **and**
2. it is part of a closed cluster, so relocating cannot leave one rule split across two files.

Criterion 1 counts consumers because that is checkable. "Feels related to keys" is not a criterion,
deliberately — it is the taste-based split that lets a rule get copied.

**The cost is stated rather than hidden: one section of the specification is now split across two
files.** §4 governs both key-subtree visibility (moved) and hook visibility —
`guard_visibility`, `visible_hook_ids`, `execution_visible_hook_ids` — which stayed, because three
domains consult it. A reader looking for "§4" now finds it in two places. That is accepted because
the split follows consumer count rather than section numbering; grouping by section number would have
moved the hook helpers too, and put one rule in three callers' reach across two files, which is the
drift `guards.rs` exists as one module to prevent. Both module headers say this explicitly, and
`FILE_MAP.MD`'s "Where things are *not*" index now distinguishes the two §4 questions.

## Reversal of an earlier position

The previous session recorded P2 as blocked: *"all-or-nothing … and requires amending `AGENT.MD`'s
'`guards.rs` holds every authorization decision' rule. That is a rule change, not a refactor."* Both
halves were right; neither was a reason not to do it once the rule change was in scope. The
all-or-nothing part is why `KeyVisibility` went along with the four.

## Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **275 passed / 0 failed** · `./scripts/test_e2e.sh` **886 / 886** ·
`./scripts/verify_convergence.sh` exit 0 — 19 converged, 0 known, 0 drifted, 0 skipped ·
`git diff RBAC_MODEL.md` empty.

No test changed. That is the expected outcome for a pure relocation, and it is also the limit of what
the suite can say about this change: the compliance suite tests behaviour, and behaviour is
identical. The claim this commit actually makes — that only one domain consumes these — is checked by
the compiler via the private visibility, not by a test.

---

# Session — drop dormant `api_keys.owner_key_id`, R2 position of record, structural audit

Driven by `SECURITY_COMPARISON_REPORT.md`. **That report audits `b5cf624`, which is seven commits
behind HEAD**, and one of its two findings acted on here has already been fixed in the interim. Both
premises were checked against the running code before anything was written; one held and one did not.

## 1. `api_keys.owner_key_id` dropped — premise held

### Verification first, because two columns share the name

`owner_key_id` exists on **two** tables and only one of them means anything. Dropping the wrong one
would remove §3's entire ownership mechanism, so the distinction was established mechanically rather
than by reading:

| Column | `Column::OwnerKeyId` in queries | Read by | Verdict |
| :--- | :--- | :--- | :--- |
| `hooks.owner_key_id` | 3 sites (`guards.rs` ×2, `keys.rs` ×1) | `guard_manage` route 2, `guard_lifecycle_authority`, `visible_hook_ids`, §6 inventory | **Load-bearing — untouched** |
| `api_keys.owner_key_id` | **0** | Nothing: no guard, no query, no response DTO, no dashboard reference | **Dormant — dropped** |

The key column was written at creation (`create_api_key`, the caller's id) and at bootstrap (NULL),
and never read again. Every `owner_key_id` reference in `guards.rs` and `hooks.rs` is the *hook*
column.

### Why it was dormant, structurally

`RBAC_MODEL.md` §3 scopes ownership to "every managed resource and every creator-private entity", and
§2's glossary makes the managed resource in this service the **Hook**. An API key is neither. Who may
administer a key is decided by §4 visibility (`load_administrable_key`) and R4 — both reading
`parent_key_id` and `can_manage_keys`. There was never a rule for `api_keys.owner_key_id` to
implement, which is exactly why nothing read it. `simply_ip_vault` has never had the column, and this
brings the two schemas to parity.

### The §7 compliance test caught the drop, and was itself wrong

`s7_every_required_index_and_constraint_exists` failed, asserting `idx_api_keys_owner_key_id` must
exist. §7 does say *"Indexes on `parent_key_id`, `owner_key_id`, …"* — so the failure forced the
question of **which** `owner_key_id` §7 means.

It means the one §3 mandates, on managed resources and creator-private entities. In this service that
is `hooks.owner_key_id`, whose index is present and asserted. The test's expectation was over-strict:
it asserted an index on a column the specification never required, because the column happened to
exist. Removing that one row is a **correction to the test, not a relaxation of §7** — and to stop
that being a convenient story, the test now additionally asserts:

- `api_keys.owner_key_id` is **absent** (so a migration registered out of order, or omitted from
  `Migrator::migrations()`, is caught rather than passing silently), and
- `hooks.owner_key_id` is **present** (so the drop cannot be widened to the column that matters).

### Migration

`m20260810_000001_drop_api_key_owner_key_id` drops the index first, then the column — the order is
required on PostgreSQL and MySQL, and SQLite tolerates either, so following only SQLite would have
shipped a migration that fails on the backends nothing tests.

**It is not reversible with data.** `down()` restores the column, its nullability and its index, all
NULL. That is honest rather than lossless, and it costs nothing real: no endpoint could ever set the
column to anything other than the creator id that `parent_key_id` already holds, so nothing
recoverable is lost. Verified by round-trip against a file-backed database:

```
AFTER UP   api_keys.owner_key_id = false   hooks.owner_key_id = true   idx_hooks_owner = true
AFTER DOWN api_keys.owner_key_id = true    idx_api_keys_owner = true
AFTER REUP api_keys.owner_key_id = false
```

## 2. R2 — the position of record

**The task asked for a specific claim to be documented as an accepted risk: that a Daughter key
holding a `can_manage` row can edit a hook's `script_path`. Against HEAD that claim is false, and it
is not documented here, because writing it down would tell every future auditor to stop looking at
something that is actually defended.**

The report is right about `b5cf624`. Commit `79156ce fix(rbac): enforce R2 conjunction on
guard_manage and dispatch configuration` landed afterwards.
`guard_hook_manage_conjunction` now demands **both** `can_manage_keys` and `row.can_manage`, and
`r2_daughter_cannot_repoint_script_path` has guarded it since. Measured against HEAD:

| Caller | Holds | `PUT /api/hooks/{id}` `script_path` |
| :--- | :--- | :--- |
| **A** — Daughter, not owner | `can_manage` row, no `can_manage_keys` | **403** — *the report's scenario; closed* |
| **B** — Daughter, **owner** | owns the hook, no row, no `can_manage_keys` | **200, and the path changes** |
| **C** — Parent | `can_manage_keys` + `can_manage` row | 200 — correct per R2 |

### The real accepted risk is route B, and it is a different thing

`guard_manage` short-circuits on `hook.owner_key_id == Some(key.id)` **before** reaching the
conjunction. So a Daughter that owns a hook may repoint its `script_path` while holding no global
scope at all.

This is intentional — introduced deliberately in `9a1c499` so a `can_manage_hooks` holder can maintain
the hooks it created — and it is a **genuine deviation from the model as written**, not merely an
edge case. §2's Dispatch-configuration clause is explicit that where dispatch config lives on a shared
managed resource, "editing it is a management action on that resource and is **governed by R2 in
full**". §3 grants the owner authority over *lifecycle* — deleting or renaming — and says nothing
about dispatch configuration. Route B therefore exercises an authority §3 does not confer over a field
§2 assigns to R2.

**Accepted, with the reasoning stated rather than assumed:**

- The alternative is worse in practice. Without route B, a `can_manage_hooks` Daughter can create a
  hook and then never touch it again — not even to fix a typo in the path it just wrote. Every
  maintenance action would need a Parent, which pushes deployments toward handing out
  `can_manage_keys` far more widely than R2 intends, weakening the conjunction everywhere to preserve
  it here.
- The blast radius is bounded by ownership, which is not delegable: `hooks.owner_key_id` is set at
  creation and reassignable **only by master** (§3). A Daughter cannot acquire ownership of a hook it
  did not create, so route B never widens beyond what that key already introduced.
- `guard_master_for_privileged_hook` still makes any hook carrying `run_as_user` master-only to
  modify, so route B cannot reach an elevated hook.

**What is *not* claimed:** that `ALLOWED_SCRIPT_ROOTS` mitigates this. It defaults to empty, meaning
unrestricted, and `src/config.rs` logs a warning saying so. In a default deployment the confinement is
absent, and the report was right to say so. The bound here is ownership, not path confinement.

**No guard code was modified for this point, per instruction.** The genuinely correct fix is the one
the report identifies architecturally: split `can_manage` into administrative and content verbs as
`simply_ip_vault` did, so "edit dispatch config" becomes an operational verb the tier matrix governs
directly. That is a schema and API change, recorded here as the standing recommendation rather than
attempted.

## 3. Structural and naming audit vs `simply_ip_vault`

**The peer has moved toward us since the last audit**, which is worth recording because the previous
entry describes a layout that no longer exists on their side.

### Module-level parity — now essentially complete

| Module | Peer | Ours | Status |
| :--- | :--- | :--- | :--- |
| `src/master.rs` | 320 | 291 | **Converged** — peer extracted it from `state.rs`; it used to be ours-only |
| `src/api/support.rs` | 260 | 399 | **Converged** — peer extracted it from `api/mod.rs`; also used to be ours-only |
| `src/api/system.rs` | 97 | 101 | **Converged** — peer added it |
| `src/api/audit.rs` | 54 | 78 | **Converged** — we added it last commit |
| `src/db.rs`, `crypto.rs`, `error.rs`, `config.rs`, `replay.rs`, `retention.rs`, `middleware.rs`, `state.rs` | ✓ | ✓ | Converged |
| `src/api/guards.rs` | ✓ | ✓ | Both a single cross-domain module |
| `src/executor.rs` | — | ours | **Domain difference** — we spawn processes; they dispatch HTTP (`dispatch.rs`, `webhooks.rs`) |
| `src/extract.rs` | theirs | folded into `api/support.rs` | Placement difference, no behavioural gap |
| `src/api/health.rs` | **absent — theirs are in `api/system.rs`** | ours, 102 | Divergent placement, see below |

Every structural finding from the earlier audit is now closed **except** `extract.rs` placement, which
is cosmetic, and the health-probe placement introduced this week on both sides independently.

### The probes: same names, different file, and one thing not copied

Both services added liveness/readiness independently and arrived at **identical handler names** —
`health_check` and `readiness_check` — which is the strongest naming-convergence signal in the two
codebases. Three differences:

1. **Placement.** Theirs sit in `api/system.rs`; ours are in `api/health.rs`. **Keeping ours.** Our
   `system.rs` is authenticated and master-only; putting the only two unauthenticated routes in the
   service inside it would destroy the property that makes that file easy to audit.
2. **`"database": "ok"` vs our `"up"`.** Cosmetic, and the two services never poll each other's
   probes. Not converged; recorded so it is a decision rather than an oversight.
3. **The peer's readiness body includes `"master_pinned": true`** — and it is a **hardcoded literal**,
   not a computed value. **Deliberately not copied.** It discloses internal security posture on an
   endpoint reachable without credentials, and because it is a constant it would be uninformative even
   to an operator. This is the one place our probe is tighter than theirs.

### Naming audit — aligned in shape, divergent in prefix, and **not** mass-renamed

| Concept | Peer | Ours | Assessment |
| :--- | :--- | :--- | :--- |
| Delegation bound | `guard_delegated_group_grant` | `guard_delegated_hook_grant` | **Aligned** — differs only by the domain noun, correctly |
| Liveness / readiness | `health_check`, `readiness_check` | same | **Aligned** |
| R2 conjunction | `guard_group_manage` | `guard_hook_manage_conjunction` | Prefix + explicitness differ |
| §3 lifecycle | `guard_resource_lifecycle` | `guard_lifecycle_authority` | Prefix differs |
| R4 scope elevation | `guard_scope_elevation` | `guard_master_to_grant_scopes` | Prefix differs |
| Master immutability | `guard_master_immutable` | `guard_master_self_edit_is_bound_ips_only` | Ours is more specific |
| Master as target | `guard_master_target` | `refuse_master_lifecycle_action` | Prefix differs |
| Any-manage standing | `holds_any_group_manage` | `manages_any_hook` | Aligned in shape |
| Permission fetch | `caller_group_permission` | `hook_permission` | Aligned in shape |
| R6 classification | `widens_permissions` | `is_permission_reduction` | **Inverse polarity** |

The peer uses a `guard_*` prefix; we use `require_*` for enforcing guards and `is_*`/verb forms for
predicates. **No renames were performed, and the audit's conclusion is that they should not be:**

- The prefix is a convention difference with no behavioural content, and
  `scripts/verify_convergence.sh` does not compare guard names — it compares the three functions where
  a *behavioural* difference would change what each service authenticates.
- Renaming `is_permission_reduction` → `widens_permissions` is **not a rename**: the two predicates
  are logical inverses, so every call site's branch would have to invert. That is a correctness-risky
  edit to R6 enforcement bought purely with cosmetics, and it is the single most likely way to
  introduce a real vulnerability while "aligning naming".
- Our names encode the resource (`hook`) where the peer's encode theirs (`group`). Those *should*
  differ; a shared name would be actively misleading.

Task 3 asked to *verify* naming alignment. The verification result is: aligned where alignment is
meaningful, divergent in prefix convention, and one apparent rename is a semantic change in disguise.
Acting on that would exceed an audit, so it is recorded as a decision to be taken deliberately if the
prefix convention is ever judged worth the churn.

## Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **275 passed / 0 failed** · `./scripts/test_e2e.sh` **886 / 886** ·
`./scripts/verify_convergence.sh` exit 0 — 19 converged, 0 known, 0 drifted, 0 skipped ·
`git diff RBAC_MODEL.md` empty · `SECURITY_COMPARISON_REPORT.md` unmodified.

---

# Session — final read-only parity pass: security + structural convergence reports

Read-only throughout. No file under `src/`, `tests/`, `scripts/` or `static/` was modified, and no
commit was created by the analysis itself. Deliverables: `SECURITY_COMPARISON_REPORT.md` (rewritten),
`STRUCTURAL_CONVERGENCE_REPORT.md` (new), `FILE_MAP.MD` (coverage section + corrected line counts).

## Scope

The workspace holds several Rust projects. Per instruction mid-session — *"Compare only with
simply_ip_vault"* — both reports are strictly two-way: `simply_hook_executor` ↔ `simply_ip_vault`.
Other workspace projects were surveyed only far enough to confirm they were out of scope, and appear
in neither report.

## The finding that changed the methodology

Every prior audit in this repository compared against `example/simply_ip_vault`, a **vendored flat
snapshot**. This pass compared against the **live sibling checkout** at
`../simply_ip_vault` as well, and they are not the same tree:

```
diff -rq example/simply_ip_vault/src ../simply_ip_vault/src
  Only in example/simply_ip_vault/src/api: system.rs
  Only in example/simply_ip_vault/src:     webhooks.rs
```

Both files were **deleted upstream** and linger in our snapshot — it was refreshed with a
non-deleting copy. Every other source file is byte-identical, and `RBAC_MODEL.md` is identical across
all three copies (`cb0b76ab…`), so the convergence gate's results were **not** falsified.

**But two findings in the previous session's structural audit were, and both are retracted:**

| Prior claim | Reality | Cause |
| :--- | :--- | :--- |
| "The peer's probes live in `api/system.rs`; ours in `api/health.rs`. Keeping ours." | The peer has `api/health.rs`; `api/system.rs` **no longer exists**. Placement is **identical** | Read the orphaned snapshot file |
| "The peer exposes a hardcoded `master_pinned: true`; deliberately not copied." | The live peer performs a **real** `master_pin.get().is_none()` check driving the status code, and exposes no such field. **The peer is stricter than us here** | Same |

The orphaned `system.rs` is not referenced by the peer's `api/mod.rs`, so it is dead code even inside
the snapshot — which is exactly why it went unnoticed: it compiles, it greps, and nothing links it.

Recorded as **S1** in the structural report: re-sync with `rsync -a --delete`, and make
`verify_convergence.sh` fail on a peer `.rs` file unreachable from the peer's module tree. This is the
highest-value action from the pass, because it silently degrades every future comparison.

## Checks performed

| # | Check | Method | Result |
| :--- | :--- | :--- | :--- |
| 1 | Snapshot freshness | `diff -rq` snapshot vs live peer `src/` | 2 orphaned files; all others byte-identical |
| 2 | Normative identity | `md5sum RBAC_MODEL.md` × 3 (ours, snapshot, live) | Identical — `cb0b76ab…` |
| 3 | Gate provenance | Read `PEER_ROOT` in `verify_convergence.sh` | Reads the snapshot, not the live tree |
| 4 | F1 — §5 marker | Read peer `m20260808_000009_derive_master_marker` | Generated column + `STORED`/`VIRTUAL` split — **resolved** |
| 5 | F2 — R2 conjunction | Read `guard_hook_manage_conjunction`; live probe of three caller shapes | Daughter+row ⇒ **403**; owner ⇒ 200; Parent+row ⇒ 200 |
| 6 | F3 — dormant key column | `grep` for `api_key::Column::OwnerKeyId` across `src/` | Zero query sites; column dropped in `m20260810_000001` |
| 7 | F4 — master CIDR bypass | Read both `middleware.rs` bound-IP blocks | No `is_master` exemption on either side |
| 8 | F5 — FK enforcement | Prior mutation-verified suite + peer `db.rs` pragma table | Enforced both sides; earlier "inert" claim already retracted |
| 9 | Payload strictness | Enumerated every `…Payload` struct and its attributes, both repos | Both strict on key create/update; peer lacks it on `DeleteKeyPayload` |
| 10 | Error contract | Read both `error.rs` variant lists, status maps, body shapes | Body identical; 3 fixed messages string-identical; 2 non-shared variants |
| 11 | Audit schema | Compared `entities/audit_log.rs` column-by-column | 6/9 match; nullability and target-column shape differ |
| 12 | Master pinning API | Compared `master.rs` public surfaces | **Character-identical** six-method API |
| 13 | Raw-SQL policy | `grep Statement::from_string` across both `src/` | Peer: `db.rs` + migrations only. Ours additionally `api/health.rs` |
| 14 | Module/naming inventory | Enumerated `src/*.rs`, `src/api/*.rs`, guard fn names, middleware fn names, `mod` vs `pub mod` | Recorded in the structural report |
| 15 | FILE_MAP exhaustiveness | Three shape-specific coverage commands (see that file) | 39/39 files documented; 5 stale line counts corrected |

## Verdicts

**Security.** All 7 flaws raised in any prior report across both repositories are resolved. Four open
divergences remain, none a regression: two where the peer is stricter (**D1** our `SELECT 1`
raw-SQL allowlist entry vs their typed query; **D2** their readiness checks the Master pin, ours does
not), and two where this service is (**D3** their audit attribution columns are nullable; **D4** their
`DeleteKeyPayload` lacks `deny_unknown_fields`).

**Structural.** 14/14 crate-root concerns and 7/8 API modules share identical filenames; 11/11
cross-cutting type and function name categories are exact; the HTTP error contract matches on every
shared variant including three message strings. The weakest axis is **observability** — the audit log
schemas differ in three columns' nullability and in target-column naming and arity, so an
ecosystem-wide log consumer cannot assume one schema.

Convergence is **bidirectional and still moving**: in the last cycle the peer extracted `master.rs`,
`db.rs` and `api/support.rs` toward our layout while we moved HMAC into `crypto.rs` and split out
`api/audit.rs` toward theirs, and both added `api/health.rs` in the same week with identical handler
names.

## Actions recorded for later, not taken here

`D1`/`D2` are both cheap changes to *this* service and both make it stricter. They are the natural
next commit; this session was read-only by instruction, so neither was applied.

---

# Session — 64-hex master key, `ConflictWithDetails`, `guard_*` prefix, readiness hardening

Closes **D1** and **D2** from `SECURITY_COMPARISON_REPORT.md` (the two divergences where the peer was
stricter), adopts **S3** and **S5** from `STRUCTURAL_CONVERGENCE_REPORT.md`, and adds fatal
validation of the bootstrap override.

## 1. `INITIAL_MASTER_KEY` — strict 64-hex, fatal when malformed

`config::validate_initial_master_key` returns `Result<Option<String>, InitialMasterKeyError>`:

| Input | Result | Reasoning |
| :--- | :--- | :--- |
| Unset | `Ok(None)` → generate a random key | The documented zero-config path |
| 64 hex chars | `Ok(Some(key))` | Accepted, trimmed |
| Set but empty/whitespace | `Err(Empty)` → **exit 1** | A broken deployment script, not absence |
| Wrong width | `Err(BadLength(n))` → **exit 1** | |
| Non-hex | `Err(NonHex(c, i))` → **exit 1** | |

**Interpretation stated explicitly, because the brief said "fatal if the key is missing".** Absence is
*not* treated as fatal. Making it so would mean the daemon cannot start without an operator-supplied
master key, which contradicts `main.rs`'s own documentation of this variable as test/CI-only and
`README.md`'s zero-config startup. What is treated as fatal is the variable being **set to nothing** —
`INITIAL_MASTER_KEY=$UNSET_VAR` — which is the failure mode "missing" most plausibly means, and where
silently generating a key would hand the operator a daemon whose master credential is not the one
their tooling believes it configured. Both cases are pinned by tests so the reading is visible rather
than inferred.

64 is not arbitrary: `api::generate_random_key` mints 32 bytes hex-encoded, so 64 hex *is* the shape
this service issues. `a_freshly_generated_key_satisfies_the_validator` pins that against the generator
rather than against the literal, so a change to one fails rather than silently diverging.

Validation runs in `main` beside `RuntimeConfig::from_env` — **before the database is opened** —
following that file's existing principle that a boot which can refuse should refuse before leaving
side effects. `bootstrap_master_key` now takes the checked value instead of reading the environment.

**Three e2e harness keys had to change.** `MASTER_KEY`, `STRICT_MASTER` and an inline value in §34
were 42–43-character English phrases. The first run after the change failed 2 checks, which is how the
third one was found. Distinct 64-hex values were chosen so a mix-up between suites stays visible in a
log. New e2e section 33b asserts the abort itself against the real binary — three bad shapes, each
exiting `1` and leaving **no database behind**, plus that the message names `openssl rand -hex 32`.

## 2. `ConflictWithDetails` (S3)

`delete_api_key` previously returned `axum::response::Response` by hand to emit its §6 inventory. It
now returns `Result<impl IntoResponse, AppError>` and raises
`AppError::ConflictWithDetails { message, details }`.

The wire shape is unchanged — `{"error":…, "subtree":[…], "inventory":[…]}` — because `details` is
**merged into** the envelope rather than nested; `s6_the_cascade_is_recursive_and_gated_on_a_total_resolution_map`
asserts a top-level `inventory` array and passed unmodified. `InventoryRefusal` lost its `error`
field and became `InventoryRefusalDetails`, so there is exactly one place the message can come from.

Two edge rules are in `error.rs` rather than left to call sites: a non-object `details` is dropped
with an error log rather than replacing the envelope, and a `details` carrying its own `error` key
does not overwrite the message.

One bug caught in the process: `unresolved` borrows `inventory`, and moving `inventory` into the
details before the last read of `unresolved.len()` failed to compile. The count is now hoisted.

## 3. Naming (S5)

Ten `require_*` guards became `guard_*`, plus `verify_timestamp` → `validate_timestamp` — 210
replacements across `src/`, `tests/` and the docs, applied with word boundaries. `require_signed_requests`
is a config field and was correctly untouched.

`verify_timestamp` lives in `src/middleware.rs` only, not `src/crypto.rs` as the brief suggested.

**`is_permission_reduction` keeps its name, as instructed and for a reason now recorded in `AGENT.MD`:**
the peer's `widens_permissions` is its logical *inverse*, so adopting that name means inverting every
call site's branch — a semantic change to R6 enforcement bought with cosmetics.

## 4. Readiness probe (D1 + D2)

| Change | Before | After |
| :--- | :--- | :--- |
| Database check | literal `SELECT 1` | `ApiKey::find().select_only().column(Id).limit(1)` |
| Raw-SQL allowlist | **3 entries** | **2** — `src/api/health.rs` removed |
| Master pin | not checked | `503` when `master_pin.get().is_none()` |

The allowlist entry was the weaker half of D1: it sat in a handler that is both request-reachable and
*unauthenticated*, which is the worst place in the service to hold an exemption, and bought only a
saved round-trip. `AGENT.MD` now states the standard a third entry must meet — unreachable from a
request — so a handler cannot acquire one again by precedent.

**The pin check exposed a fixture that was modelling an impossible process.** `test_state` leaves the
pin unset, so adding the check turned four health tests red at once. That is the test suite being
right: `main.rs` pins *before* binding the listener, so a process serving traffic has always pinned,
and a fixture that never pins describes a process that would never have accepted the connection. The
health suite now builds a `pinned_state`, and `readiness_reports_unavailable_when_no_master_is_pinned`
covers the unpinned case directly — with the database left **live**, so the `503` is attributable only
to the pin. That case reports `"database":"up"`, because it is.

## 5. Audit trail (verification + one alignment)

Non-nullability **verified, not changed**: `api_key_name`, `api_key_prefix` and `client_ip` are already
`String` (NOT NULL) in `entities/audit_log.rs`. The reasoning is now written down in
`create_audit_log`'s rustdoc, `SCHEMA.MD` and `AGENT.MD` §7 so it survives a future "make it
consistent with the FK" tidy-up — the FK is `SET NULL` on purpose and the snapshot must not be.

One genuine inconsistency found and fixed: of the ~20 `create_audit_log` call sites, every one wrote
the affected entity's **name** except `EXECUTION_DELETE`, which wrote a bare execution UUID. An
execution has no name, so it now takes its parent hook's name — the anchor an operator recognises and
can filter on — and its own id moves into `details`, where the *full* UUID is preserved rather than
truncated. The convention is documented at the writer.

## Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` **285 passed / 0 failed** (107 unit + 133 integration + 23 compliance + 8 hygiene +
8 health + 6 referential integrity) · `./scripts/test_e2e.sh` **893 / 893** ·
`./scripts/verify_convergence.sh` exit 0 — 19 converged, 0 known, 0 drifted, 0 skipped ·
`git diff RBAC_MODEL.md` empty.

Test count moved 275 → 285: nine `initial_master_key_tests` and one readiness test.

---

# 2026-08-11 — Final ecosystem audit: peer refresh, security and structural convergence

**Mode:** strictly read-only over `src/`, `tests/`, `scripts/`, `static/` and `migration/` in **both**
repositories. `RBAC_MODEL.md` untouched (`git diff RBAC_MODEL.md` empty). Only the four documents
below were written.

**Subjects:** this repository @ `4865a82` · `example/simply_ip_vault` @ `6f1c4c7`.

## 0. Task 0 — peer repository update

`example/` holds exactly one project, so the comparison is this repository's root tree against
`example/simply_ip_vault`.

| Step | Command | Outcome |
| :--- | :--- | :--- |
| Enumerate | `ls example/` | `simply_ip_vault` — the only entry |
| Confirm it is a clone | `git rev-parse --is-inside-work-tree`, `git remote -v` | `true`; `origin` = `https://oshino.tomidejetsu.ovh/fallrik/simply_ip_vault.git` |
| Update | `cd example/simply_ip_vault && git pull` | **`Already up to date.`** — `HEAD` `6f1c4c7` before and after |
| Tree state | `git status --short` | Clean |

`example/` is listed in this repository's `.gitignore` (`git ls-files example/` returns nothing), so
the peer clone is not carried in this repository's history — only the reports about it are.

## 1. The previous audit's headline finding is closed

The 2026-08-10 pass found `example/simply_ip_vault` was a **flat vendored snapshot** that had drifted,
still carrying `src/api/system.rs` and `src/webhooks.rs` after both were deleted upstream, and that
this had already produced two false findings. It is now a **git clone with a remote**: refreshable
with `git pull`, and carrying zero files unreachable from the peer's module tree. The recommendation
was implemented.

## 2. What each side fixed for the other

The interesting property of this cycle is that the two open items at the last audit were one on each
side, and each was closed by the repository it was raised *against*:

| Item | Raised by | Against | Closed in |
| :--- | :--- | :--- | :--- |
| `INITIAL_MASTER_KEY` accepted any non-empty string | peer's report | **this repo** | `4865a82` (`config::validate_initial_master_key`) |
| Audit attribution columns nullable | this repo's report (D3) | **the peer** | `6f1c4c7` (`m20260811_000010`) |

The peer went past the brief on its side: `create_audit_log` now takes `&api_key::Model` and `IpAddr`
**by value** rather than as `Option`, so an unattributed write is inexpressible in the type rather
than merely refused by the column. Our writer already had that signature; they are now byte-compatible.

The two readiness items this repository raised against itself (raw-SQL allowlist entry in an
anonymous handler; no master-pin check) also closed in `4865a82`. **11 of 11** historical findings
across both repositories are now resolved.

## 3. Three findings this pass produced

**Drift detection is one-directional (S1/D6).** Both repositories ship `verify_convergence.sh` and
both point it at a peer inside their own `example/`. Only this one has a peer there. Running the
peer's gate:

```
SKIP peer service not found at …/simply_ip_vault/example/simply_hook_executor
exit=0
```

It is **green by absence** — reporting success while comparing nothing. Everything in either report
is a snapshot that only a working gate keeps true, and right now the gate works in one direction.
This is the highest-value item in this pass.

**A documented control that does not exist (D3).** The peer's `ReassignOwnerPayload` carries a doc
comment reasoning that sharing the struct avoids "two things to keep `deny_unknown_fields` in step
across" — and the struct derives only `Deserialize`. No escalation follows (it has one field), but the
comment asserts a guarantee a reader will not find in the code. Reported rather than assumed
harmless, because a comment that names an attribute is exactly what a later reviewer greps for.

**Neither CI pipeline runs any gate (D7/S10).** Both repositories ship precisely two workflows —
`docker-publish.yml` and `update-readme-each-month.yml` — and neither invokes `cargo test`,
`test_e2e.sh` or `verify_convergence.sh`. Every guarantee in both reports currently depends on a human
remembering to run two scripts.

## 4. Two items where the peer is stricter than we are

Recorded so they are not lost between sessions:

- **`no_handler_is_ever_exempted`** — the peer's `source_hygiene.rs` asserts that no raw-SQL
  allowlist entry may begin with `src/api/`, encoding the invariant the allowlist is a proxy for.
  We removed our only such exemption in `4865a82`; nothing currently prevents the next one. Worth
  porting.
- **`no_dml_keyword_is_hand_written_outside_the_exceptions`** — a second, broader scanner alongside
  the raw-SQL one.

## 5. Method

Comparison was mechanical wherever a mechanical check existed, rather than by reading for impression:

| Question | How it was settled |
| :--- | :--- |
| Is the normative document still shared? | `md5sum RBAC_MODEL.md` on both — `cb0b76ab…`, identical |
| Are the three shared functions still identical? | `./scripts/verify_convergence.sh` — 19 converged, 0 drifted |
| Does the peer's gate work? | Ran it. It skips and exits `0` |
| Which payloads are strict? | `grep -rn deny_unknown_fields src/` on both, then read each struct's derive block — the attribute's *line* proves nothing about which struct it sits on |
| Is audit attribution really NOT NULL now? | Read `entities/audit_log.rs` on both plus the peer's new migration — `String`, not `Option<String>`, on both |
| Are the guard prefixes uniform? | Enumerated every `fn` in both `guards.rs`: 10 of 10 `guard_*` here, 6 of 6 there |
| Does this repo's suite still pass? | `cargo test` — **285 passed / 0 failed** across 8 binaries |
| Is `FILE_MAP.MD` still exhaustive? | The three shape-specific commands recorded in the file itself — all three silent |

The peer's suite was **not** executed: it has no build artifacts in this checkout, and compiling it
would be the only mutation this pass made to a tree declared read-only. Peer claims are therefore
sourced from its committed source and its own commit messages, both cited in the reports.

## 6. Written

`SECURITY_COMPARISON_REPORT.md` (replaces the 2026-08-10 edition, retrievable at `7a7ffc7`) ·
`STRUCTURAL_CONVERGENCE_REPORT.md` (replaces the same edition) · this note · `FILE_MAP.MD`
verification date.

---

# 2026-08-11 (second pass) — Independent clean-room audit

**Mode:** strictly read-only over `src/`, `tests/`, `scripts/`, `static/` and `migration/` in **both**
repositories. `RBAC_MODEL.md` untouched. Only the three documents named at the end were written.

**Constraint that shaped this pass:** the brief required a **clean-room** audit — findings derived
from `RBAC_MODEL.md` and current `.rs` source only, with no prior audit report read or relied upon.
Both repositories carry earlier reports and the peer's `git pull` brought in three more; none was
opened. Where the peer's history had to be consulted at all, only `git diff --stat` and
`--name-only` were used, to establish that no `.rs` file had moved.

## 0. Task 0 — peer repository update

| Step | Command | Outcome |
| :--- | :--- | :--- |
| Locate | `ls example/` | `simply_ip_vault` — the only project |
| Update | `cd example/simply_ip_vault && git pull` | **Fast-forward `6f1c4c7` → `c182a7a`** |
| Scope of the update | `git diff --stat 6f1c4c7..c182a7a` | 3 files, all Markdown (the peer's own reports and notes) |
| Source moved? | `git diff --name-only … \| grep -E '^(src\|tests\|scripts\|static)/'` | **None** |
| Tree | `git status --porcelain` | Clean |

Because no `.rs` file changed, the peer source analysed here is the tree as committed at `6f1c4c7`
and unchanged at `c182a7a`.

## 1. Method

Each rule of the specification was traced to enforcing code on both sides, and then attacked. The
negative results are recorded in the report (§1.2 and §1.4) as well as the positive ones — a
clean-room audit that lists only what it found is indistinguishable from one that did not look.

| Question | How it was settled |
| :--- | :--- |
| Is the normative document still shared? | `md5sum RBAC_MODEL.md` on both — `cb0b76ab…`, identical |
| Where is R2 enforced? | Enumerated every `fn` in both `guards.rs`; traced each content route back to its gate |
| Can R2 be reached around? | Followed `update_hook` → `guard_manage` and read all three routes. **It can — see SHE-1** |
| What does an empty `ALLOWED_SCRIPT_ROOTS` mean? | Read `is_within_roots`: `roots.is_empty() \|\| …` — empty allows every path |
| Does the peer have the same gap? | Read `update_webhook`: it re-checks `can_manage_webhooks` **and then** ownership. It does not |
| Is §6 total-map enforcement real on both? | Read both delete paths end to end, including the reassign-into-doomed-subtree refusal |
| Are the subtree walks cycle-safe? | Both carry a visited set and terminate. Only B additionally refuses a caller inside the doomed subtree |
| Which payloads are strict? | `grep -rn deny_unknown_fields` on both, then read each struct's derive block — the attribute's line number proves nothing about which struct it decorates |
| Is R4 complete on the peer? | `MASTER_ONLY_SCOPES` covers all three of its global scopes; both call sites pass all three |
| Do the CI pipelines run any gate? | `grep -rl 'cargo test\|verify_convergence\|test_e2e' .github .forgejo` on both — no matches |

## 2. The finding this pass produced — SHE-1

The specification's *Dispatch configuration* clause says that where dispatch configuration lives on a
shared managed resource — for this service, `script_path` on the Hook row — editing it "is a
management action on that resource and is governed by **R2 in full**".

`guard_manage` admits three routes, and the second is ownership alone:

```rust
if key.is_master { return Ok(()); }
if hook.owner_key_id == Some(key.id) { return Ok(()); }   // ← R2 never consulted
guard_hook_manage_conjunction(db, key, hook.id).await?;
```

`create_hook` sets `owner_key_id` to the creator and auto-provisions `can_execute`, `can_manage` and
`can_view_execution`. So a Daughter granted `can_manage_hooks` creates a hook, and **revoking
`can_manage_hooks` afterwards takes none of that back**: ownership and the permission row survive, so
the key can still repoint that hook at any absolute path and run it. `ALLOWED_SCRIPT_ROOTS` is empty
by default, which permits every path.

What keeps this at Medium rather than higher, stated so the severity is not overread: a hook carrying
`run_as_user` is master-only to modify at all, hooks are never spawned through a shell, and a key
*currently* holding `can_manage_hooks` could set the same path at creation time anyway. The delta is
**persistence after revocation** — plus the second route in, which is Master reassigning
`owner_key_id` to a key holding no `can_manage_keys` at all.

The peer is not exposed: `update_webhook` re-checks the standing scope *and then* ownership, so
revoking `can_manage_webhooks` contains the key immediately. That asymmetry is the substance of the
finding — the same containment question, answered two different ways in two codebases that otherwise
match line for line.

The in-code rationale at `guards.rs:117-128` argues that ownership should confer content authority,
and it is a coherent product position. It is nonetheless a position the specification does not grant,
and `RBAC_MODEL.md:10-11` says the specification wins. Recorded as a finding rather than resolved
here, because this pass is read-only and the resolution is a product decision: either gate the
ownership route on `can_manage_hooks`, or amend the normative document to admit the exception.

## 3. Other findings

- **SHE-2 (Low, this repo)** — no refusal when the caller's own key lies inside the subtree being
  deleted. Reachable only through a `parent_key_id` cycle, which the API cannot create. The peer
  refuses it explicitly; the traversal itself is cycle-safe on both sides.
- **SIV-1 (Low, peer)** — `DeleteKeyPayload` lacks `deny_unknown_fields`. It **fails safe**: a
  dropped map yields the `409` inventory rather than a deletion. Worth noting for whoever fixes it —
  the attribute belongs on `DeleteKeyPayload`, and *cannot* go on the nested `ResolutionEntry`, which
  uses `#[serde(flatten)]`; serde rejects that combination.
- **SIV-2 (Informational, peer)** — `ReassignOwnerPayload`'s doc comment reasons about keeping
  `deny_unknown_fields` in step while the struct derives only `Deserialize`.
- **ECO-1 (Medium, process)** — the peer's `verify_convergence.sh` points at an
  `example/simply_hook_executor` that does not exist in that clone. Ran it: prints `SKIP`, exits `0`.
  Green while comparing nothing, so drift is policed in one direction only.
- **ECO-2 (Medium, process)** — neither CI pipeline runs any gate. This is the one finding the
  specification names outright: §7 requires DDL-inexpressible constraints to be covered by a test
  **that runs in CI**. Both services have written those tests; neither runs them automatically.

## 4. What was attacked and held

Recorded because the negative results are the audit. On this service: minting a second Master through
a payload, through `deny_unknown_fields`, and through direct SQL against the generated marker;
self-granting `can_manage_keys`; granting an unheld verb; trading a held verb for an unheld one in
one write; routing a grant through the update endpoint to dodge R1; probing hook existence and key
UUIDs through `403`/`404`; rotating or deleting the Master; editing a Master field other than
`bound_ips`; orphaning hooks through a key deletion; forging `client_ip` through `X-Forwarded-For`;
bypassing `bound_ips` as Master; assigning `run_as_user` without Master; restoring a trashed
privileged hook. All refused, each at a named line. The peer's equivalents were attacked and held
too, including R4 across all three of its global scopes.

## 5. Written

`SECURITY_COMPARISON_REPORT.md` (overwritten, as instructed) · `STRUCTURAL_CONVERGENCE_REPORT.md`
(rewritten) · this note. `FILE_MAP.MD` re-verified exhaustive against `src/` with the three
shape-specific commands it documents; no entry needed adding.

---

# 2026-08-11 (third pass) — Peer sync automation and S2 (`src/extract.rs`)

Three changes: a mandatory agent directive, an automated peer sync in the convergence gate, and the
structural move that closes divergence **S2**.

## 1. `src/extract.rs` — S2 closed

`StrictJson` and `OptionalStrictJson` moved out of `src/api/support.rs` into a crate-root
`src/extract.rs`, matching where `simply_ip_vault` has always kept the identical pair.

The move is not tidying. `support.rs` states in its own header that it **decides nothing** — and an
extractor decides whether a request is well-formed enough to reach a handler at all, before any
handler runs. `StrictJson` is also the mechanism that turns `#[serde(deny_unknown_fields)]` from an
annotation into an enforced control, and `RBAC_MODEL.md` §5 names that control specifically:
*"Removing the field from the payload type is required; rejecting it at the handler is not
sufficient."* Absence plus `deny_unknown_fields` is what makes the removal mean something, and this
extractor is what carries the resulting refusal out. Filing that under "shared plumbing" understated
it. Third and smallest: an Axum `FromRequest` impl is a framework concern, and `api/` models the
service's *domain*.

| Aspect | Before | After |
| :--- | :--- | :--- |
| Location | `src/api/support.rs` | `src/extract.rs` |
| Import at the call site | `super::support::{OptionalStrictJson, StrictJson, …}` | `crate::extract::{OptionalStrictJson, StrictJson}` |
| Call sites touched | — | 1 file (`src/api/keys.rs`), 3 handlers |
| `api/mod.rs` re-export | Never re-exported them | Unchanged — nothing outside `api` imported them through the facade |
| Behaviour | — | **None.** Bodies moved verbatim; only doc links and the `Json`/`Request` imports were rewritten |

The one substantive edit inside the moved code is the intra-doc link: `[`CreateApiKeyPayload`]`
resolved against `api/` and now reads `[`crate::api::keys::CreateApiKeyPayload`]`. The invariant most
worth not losing in a future edit is recorded at the top of the new module and in `FILE_MAP.MD`:
**both extractors pass the rejection's own status through rather than flattening it to `400`**,
because `DefaultBodyLimit` surfaces here too and flattening would demote `413` into an
indistinguishable bad request.

## 2. Automated peer sync in `scripts/verify_convergence.sh`

`sync_peers()` runs before any comparison, over every `example/*/.git` present — a glob rather than a
hardcoded `simply_ip_vault`, so a second peer needs no edit.

Without it the gate answers a question nobody asked: *"did this repository drift from the peer as it
stood whenever someone last pulled."* A peer three commits behind reports **converged** while the
real trees differ.

That is not hypothetical, and this pass proved it inside a single session. The peer was at `c182a7a`
when the clean-room audit was written and committed. The first run of the new sync step printed:

```
Peer simply_ip_vault updated 2d12bf8 -> f6e8444.
```

— two commits past what the audit had described, one of them touching **14 source files** including
`src/db.rs` and `src/master.rs`. The gate had been green the whole time and would have stayed green.

Design choices, each with a reason:

| Choice | Reason |
| :--- | :--- |
| `--ff-only` | A merge or rebase inside a peer checkout is a local modification to a tree we only read. If it cannot fast-forward, someone committed there and that needs a human, not a strategy |
| Non-fatal on failure | A gate that requires a network is a gate that stops being run. Offline warns and proceeds; the warning names the local `HEAD`, so the run stays reproducible |
| `GIT_TERMINAL_PROMPT=0` | The remotes are HTTPS. Without cached credentials git blocks on an interactive username prompt **forever** — a hanging gate is worse than a failing one |
| `timeout 30` | Bounds the blackholed-route case |
| `SKIP_PEER_SYNC=1` | For a deliberate audit of a pinned revision, where the tree must not move |

**Measured, not assumed.** The offline path was tested against an unroutable remote in a throwaway
repository rather than by editing the peer's remote: DNS failure and connection-refused return in
milliseconds, while a **blackholed** route stalls for the full 30s before the warning prints. That is
the price of not hanging indefinitely, and it is now stated in the script's comment so nobody
mistakes the stall for a wedge.

## 3. `AGENT.MD` — Peer Repository Synchronization

New top-level section, linked from the `example/` entry in the document hierarchy. The directive:
run `git -C example/<peer_repo> pull` **before** reading anything under `example/` or generating any
convergence, parity, or security report, and record the outcome.

The rationale is a failure this repository has actually had: an earlier `example/simply_ip_vault` was
a hand-copied snapshot that kept two files after they were deleted upstream, and an audit written
against it produced **two findings about dead code**, both later retracted. Nothing failed — the
report was simply false, and stayed false until someone diffed the trees by hand.

The section is explicit that the script's automation does **not** discharge the directive: the script
syncs only when invoked, and an agent that opens `example/simply_ip_vault/src/api/guards.rs` directly
has not invoked it.

## 4. Consequence for the reports committed earlier today

`SECURITY_COMPARISON_REPORT.md` and `STRUCTURAL_CONVERGENCE_REPORT.md` name the peer as `c182a7a` in
their headers, which is accurate and reproducible — but the peer is now at `f6e8444`. Both findings
against the peer were re-checked at the new HEAD and **still hold**: `DeleteKeyPayload` still lacks
`deny_unknown_fields` (`keys.rs:651`), `ReassignOwnerPayload` still documents a control it does not
carry (`support.rs:276`), and `update_webhook` still re-checks `can_manage_webhooks` before ownership
(`webhooks.rs:385`), which is the comparison **SHE-1** rests on. The convergence gate is 19/0/0/0
against the new peer source. The reports are behind by a SHA, not by a conclusion — and this is
precisely the drift the directive above exists to make visible rather than to prevent.

## Gates

`cargo check --all-targets` clean · `cargo clippy --all-targets -- -D warnings` exit 0 ·
`cargo test` **285 passed / 0 failed** across 8 binaries — unchanged from before the refactor, which
is the point for a move that was meant to be behaviour-free · `./scripts/verify_convergence.sh`
**19 converged, 0 known, 0 drifted, 0 skipped**, exit 0 · `SKIP_PEER_SYNC=1` path exercised ·
`FILE_MAP.MD` re-verified exhaustive (13 crate-root files now, 40 total) · `git diff RBAC_MODEL.md`
empty.
