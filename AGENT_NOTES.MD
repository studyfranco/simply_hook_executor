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
