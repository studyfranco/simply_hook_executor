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

*(Resolved in the next entry: `run_as_user` is now master-only.)*

---

## 2026-07-29 (later) — Signing secrets, the `run_as_user` master guard, and Test/Launch

### Two divergences from `SCHEMA.MD`, flagged rather than papered over

1. **`can_read` does not exist.** The task described a three-flag per-hook model
   (`can_execute` / `can_read` / `can_manage`), but `SCHEMA.MD`'s `api_key_hook_permissions` table
   defines only `can_execute` and `can_manage`. Rather than invent a column the schema document
   does not sanction, read access is derived: **any** mapping (execute or manage) grants visibility
   of the hook, its parameters, and its execution history — see `require_visibility`. That yields
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
- **Per-handler RBAC** — every handler carries an explicit guard: `require_execute` (execute/test/
  webhook), `require_visibility` (reads), `require_manage` (mutations), `is_master` (settings, audit
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
is asserted in `middleware::tests::timestamps_*`, where `verify_timestamp` is called directly with
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

`require_master_to_grant_scopes` now gates `is_master`, `can_manage_keys` and `can_manage_hooks` on
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
holder. `require_master_to_administer` now gates rotate, update and delete whenever the **target** is
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

`require_master_for_privileged_hook` now gates **any** mutation of a hook whose `run_as_user` is
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
rather than the guard functions directly: a unit test of `require_master_to_grant_scopes` would keep
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
