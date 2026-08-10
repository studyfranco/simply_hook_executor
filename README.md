# simply_hook_executor

Simply efficient. A secure hook execution daemon.

`simply_hook_executor` is a small, self-hosted API and dashboard that turns authenticated HTTP
requests into safely-executed local scripts. It's the automation bridge between "something
happened" (a webhook from `simply_ip_vault`, a CI deploy, a monitoring alert) and "run this
command on this box" — without ever handing an untrusted caller a shell.

- **Backend:** Rust, Axum, SeaORM (SQLite by default, zero config, PostgreSQL-ready).
- **Frontend:** a single-page dashboard in `static/` — vanilla HTML/CSS/JS, no build step, no
  external dependencies.
- **Access control:** every API key can be a full master key, or scoped with fine-grained
  per-hook `execute`/`manage` rights plus a handful of global privileges (manage keys, create
  hooks) and its own concurrency budget.

## Security model

Executing arbitrary local scripts on request is exactly as dangerous as it sounds, so the
execution engine (`src/executor.rs`) is built around four guarantees:

1. **No shell, ever.** The hook's `script_path` goes straight to `tokio::process::Command::new`
   with an argument *vector*. Nothing is ever concatenated into a command string, so a parameter
   value like `; rm -rf / #` reaches the script as one inert argument.
2. **Environment isolation.** Every child starts from a cleared environment (`env_clear()`). Only
   the operator-controlled `ALLOWED_ENV_VARS` allowlist and the hook's own `HOOK_PARAM_*`
   injections survive — a caller cannot set `LD_PRELOAD`, and the daemon's own `DATABASE_URL`
   never reaches a hook.
3. **Bounded runtime.** Each hook carries a timeout. On expiry the child's entire *process group*
   is `SIGKILL`ed, so a script that backgrounds work cannot outlive the request.
4. **Bounded output.** stdout/stderr are captured up to `MAX_OUTPUT_BYTES` each, then
   drained-and-discarded — a runaway hook can neither exhaust memory nor deadlock on a full pipe.

On top of that: API keys are bound to CIDR ranges, request bodies can be HMAC-SHA256 signed,
parameters are validated against a declared contract (unknown keys are rejected, not ignored),
each key has a `max_concurrent_jobs` budget enforced by a semaphore, and every mutating action is
recorded in an audit log.

### Script path containment

A hook's `script_path` is validated twice:

1. **At definition time** — it must be absolute and free of `..` segments (a relative or
   traversing path would resolve against whatever working directory the daemon happens to have),
   and, when `ALLOWED_SCRIPT_ROOTS` is set, must lie inside one of those directories. Containment
   is compared component-wise, so a root of `/opt/hooks` never admits `/opt/hooks-evil`.
2. **At execution time** — the path is canonicalized (resolving symlinks) and re-checked against
   the roots. A symlink planted *inside* an allowed root that points at `/bin/sh` or `/etc/shadow`
   passes the first check and is caught by the second, before anything is spawned.

### Webhook signatures (`key_id` + `signing_secret`)

Every API key carries two further credentials, both returned **once** by `POST /api/keys` (and by
`/rotate`):

| Credential | Secret? | Sent as | Purpose |
| :--- | :--- | :--- | :--- |
| `plaintext_key` | yes | `X-API-Key` | Bearer credential. Only its SHA-256 hash is stored. |
| `key_id` | no | *(not sent)* | Public identifier (`shk_<32 hex>`) for display and log correlation. Not a credential. |
| `signing_secret` | yes | *never sent* | HMAC-SHA256 key. Used to compute `X-Signature-256`. |

Signatures are HMAC-SHA256 over a canonical string of four newline-delimited components:

```text
<METHOD>\n<PATH_AND_QUERY>\n<TIMESTAMP>\n<RAW_BODY>
```

sent alongside `X-Timestamp` (Unix seconds, must be within **300 seconds** of server time):

```bash
BODY='{"target_address":"203.0.113.7"}'
TS=$(date +%s)
PATH_AND_QUERY=/webhook/nftables_ban
SIG=$(printf '%s\n%s\n%s\n%s' POST "$PATH_AND_QUERY" "$TS" "$BODY" \
        | openssl dgst -sha256 -hmac "$SIGNING_SECRET" -r | cut -d' ' -f1)
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
     -H "X-Timestamp: $TS" -H "X-Signature-256: sha256=$SIG" -d "$BODY" \
     "http://localhost:3000$PATH_AND_QUERY"
```

Details that matter when writing a client:

- The **newline delimiters are required** — they stop a signature being replayed across a different
  method/path split.
- **`PATH_AND_QUERY` is the full request target** the client used, `/api` prefix and query string
  included. Altering `?limit=5` to `?limit=1000` invalidates the signature.
- **`RAW_BODY` is the exact bytes sent**; an absent body signs as the empty string.
- The **window is symmetric** — a far-future timestamp is rejected just like a stale one. Tune it
  with `SIGNATURE_MAX_AGE_SECONDS`.
- A signed request **must** carry `X-Timestamp`; a missing or malformed one is a `401`, never
  treated as "now".
- **A signature is single-use.** The window alone bounds how *long* a captured request stays valid,
  not how many times it may be used — so within the window each `CANONICAL_V1` signature is
  accepted exactly once and a resend is refused with `401`. Sign each request; do not cache and
  replay one. (`BODY_ONLY` keys are exempt: they carry no timestamp, and the webhook senders that
  mode exists for redeliver deliberately.)

Every request identifies its key with `X-API-Key` — that is the only key lookup path. A signature
is optional by default and adds request integrity on top of bearer authentication; set
`REQUIRE_SIGNED_REQUESTS=true` to make it mandatory on every authenticated route. A missing key, an
unknown key, and a bad signature all return the same `401`.

The dashboard signs every request it makes using the Web Crypto API, with the signing secret you
optionally supply at login. **`crypto.subtle` only exists in a secure context**, so the dashboard
can only sign over HTTPS or on localhost; over plain HTTP it falls back to bearer-only auth and
says so. Serve the dashboard behind TLS before enabling `REQUIRE_SIGNED_REQUESTS`.

**Storage.** Unlike the API key, the signing secret cannot be hashed — verifying a signature means
recomputing it, which needs the original bytes. It is therefore stored **encrypted at rest** with
XChaCha20-Poly1305:

```bash
SIGNING_SECRET_KEY=$(openssl rand -hex 32)
```

Without `SIGNING_SECRET_KEY` the daemon still runs, but stores signing secrets unencrypted and says
so loudly at startup — anyone able to read the database could then forge signatures. A malformed
key aborts startup rather than silently downgrading. Enabling encryption later is safe: secrets
written before it stay readable, and new ones are sealed from then on.

### Privileged execution (`run_as_user`)

A hook may declare an optional `run_as_user`. When set, the script is invoked through `sudo`
instead of directly:

```
/usr/bin/sudo -n -u <run_as_user> -- /opt/hooks/ban.sh <param1> <param2> ...
```

- `-n` keeps sudo non-interactive: a missing `NOPASSWD` rule fails immediately instead of blocking
  on a password prompt nothing can answer.
- `--` terminates sudo's own option parsing, so a script path or parameter beginning with `-` is
  passed through as data rather than absorbed as a sudo flag.
- `run_as_user` is validated against the POSIX-portable username shape
  (`[A-Za-z_][A-Za-z0-9_-]*`, plus a trailing `$`), which makes an option-shaped value such as
  `-i` or `--login` unrepresentable rather than relying on sudo to be defensive about it.

**Setting `run_as_user` requires a master key.** `can_manage_hooks` is the right to define
automation, not the right to choose which OS account it runs as; a non-master supplying the field
gets `403 Only master API keys can assign run_as_user privileges`, whether on create, `PUT`, or
`PATCH`. Clearing it (sending `""`) is not an escalation and stays open to any hook manager.

**Even for a master, this field requests elevation; it cannot grant it.** `sudoers` remains the
sole authority, so a matching rule is required — scoped as narrowly as the job allows:

```sudoers
hookrunner ALL=(root) NOPASSWD: /opt/hooks/ban.sh
```

**Environment caveat.** Parameters are always passed *positionally* (`$1`, `$2`, …) and that works
regardless of sudo configuration. The `HOOK_PARAM_*` environment variables are set on the `sudo`
process, but modern sudo resets the environment by default, so they only survive into the script
if sudoers is told to keep them:

```sudoers
Defaults:hookrunner env_keep += "HOOK_PARAM_*"
```

If you would rather not touch `env_keep`, write privileged hook scripts against `$1..$n`. The
dry-run endpoint always shows the exact argument vector, so there is no need to guess.

Privileged hooks are called out in the UI with a red `⬆ <user>` tag, logged on every execution
with `run_as_user=`, and recorded in the audit trail at creation and on every change.

### Permission diagnostics

When a script cannot be run, the failure is classified rather than passed through as a bare OS
error, and the same message goes to the HTTP response, the `tracing` log (tagged with a
`rejection=` classification so it is greppable in journald), and — for failures that only surface
at `execve` time — the execution record's `stderr`:

```
[ERROR] Cannot execute '/opt/hooks/ban.sh': the file exists but has no execute bit set (mode 0600).
Run 'chmod +x /opt/hooks/ban.sh' and ensure 'hookrunner' (uid=999 gid=999) owns it or matches its group.

[ERROR] Cannot execute '/opt/hooks/ban.sh': No such file or directory (ENOENT).
The path does not exist. Deploy the script there, or correct the hook's script_path.

[ERROR] Cannot execute '/opt/secret/ban.sh': Permission denied (EACCES).
Running as 'hookrunner' (uid=999 gid=999), which cannot search the directory '/opt/secret'.
Grant traverse permission on it and every parent (chmod +x), or adjust ownership.
```

`EACCES` on a file almost always means a *parent directory* lacks the search bit, so the daemon
walks the path and names the specific directory at fault. A refused script never produces an
execution record — nothing ran, so nothing is logged as having run.

## Features

- Define **hooks**: a name, an absolute `script_path`, a timeout, an optional `run_as_user` for
  `sudo`-elevated execution, and a declared parameter contract (`param_key`, `default_value`,
  `is_required`).
- Execute them via `POST /api/hooks/{id}/execute`, or via `POST /webhook/{name}` for third-party
  senders that post their own flat JSON document to a fixed URL.
- Parameters reach the script **both ways**: as `HOOK_PARAM_<UPPERCASED_KEY>` environment
  variables, and as positional CLI arguments in declaration order (for scripts reading `sys.argv`
  or `$1`).
- **Dry-run** any hook with `POST /api/hooks/{id}/test`: resolves parameters and returns the exact
  program, argument vector, and environment map that *would* be used — without spawning anything.
- Full execution history: status (`SUCCESS`/`FAILED`/`TIMEOUT`), exit code, captured stdout and
  stderr, resolved parameters, and duration, with a background retention worker that purges
  entries older than `LOG_RETENTION_DAYS`.
- Multi-tenant RBAC: keys are scoped to exactly the hooks (and execute/manage rights) they need.
  Creating a hook auto-grants its creator full rights on it.

## Getting Started

### Prerequisites

- A recent stable Rust toolchain (edition 2024).
- No database server to install — SQLite is used out of the box.

### Run it

```bash
cargo run
```

On first boot, `simply_hook_executor`:

1. Connects to the database (creating the SQLite file if needed) and runs all pending migrations
   automatically.
2. Checks whether any API key with master rights exists. If not — which is always true on a brand
   new database, and also true again if every master key is ever deleted later — it generates one
   and prints it **once**, to stdout, in a boxed banner:

   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║  BOOTSTRAP: Master API Key Generated                       ║
   ║  Key:    <64 hex characters>                                ║
   ║  Bound:  0.0.0.0/0                                             ║
   ║  ⚠ This key will NOT be shown again. Store it securely!    ║
   ╚══════════════════════════════════════════════════════════════╝
   ```

   Copy that key immediately — only its SHA-256 hash is stored, so it cannot be recovered later.
   If you lose every master key, delete the corresponding rows from `api_keys` (or the whole
   database, for a fresh start) and restart; a new one will be generated the same way.
3. Starts listening on `0.0.0.0:3000` (configurable — see `BIND_HOST`/`PORT` below) and serves
   the dashboard from `static/` at `/`. The bound address is logged at startup.

Open `http://localhost:3000` and paste the key into the login screen, or drive the API directly
with `curl` (see below).

### Configuration

All configuration is via environment variables (a `.env` file in the working directory is loaded
automatically if present):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite://simply_hook_executor.db?mode=rwc` | SeaORM connection string. |
| `ALLOWED_ENV_VARS` | `PATH,LANG,TERM,SYSTEMROOT` | Comma-separated allowlist of host variables passed through to hook sub-processes. Everything else is cleared. An empty value means total isolation. |
| `SIGNING_SECRET_KEY` (or `VAULT_ENCRYPTION_KEY`) | *(unset — no encryption)* | 64 hex characters (32 bytes) used to encrypt `api_keys.signing_secret` at rest. Strongly recommended: without it, database read access is enough to forge webhook signatures. A malformed value aborts startup rather than silently storing secrets in the clear. `SIGNING_SECRET_KEY` wins if both are set. |
| `SIGNATURE_MAX_AGE_SECONDS` | `300` | Anti-replay window for `X-Timestamp`, applied symmetrically (past *and* future). Also how long a `CANONICAL_V1` signature is remembered as already-used: within this window a signature is accepted exactly once, so an intercepted request cannot be resent. |
| `REQUIRE_SIGNED_REQUESTS` | `false` | When `true`, every authenticated request must carry a valid signature — bearer-only auth is refused. Requires an HTTPS-served dashboard, since the browser cannot sign otherwise. |
| `ALLOWED_SCRIPT_ROOTS` | *(unset — unrestricted)* | Comma-separated absolute directories that a hook's `script_path` must live under. Strongly recommended in production: without it, any key holding `can_manage_hooks` can point a hook at any absolute path. Relative entries are ignored with a warning (a boundary that moves with the working directory is not a boundary). |
| `TRUSTED_PROXIES` | *(unset — trust nothing)* | Comma-separated CIDRs, bare IPs, **or hostnames** (`127.0.0.1,172.16.0.0/12,traefik`) whose `X-Forwarded-For` / `X-Real-IP` headers are believed. **Set this to the reverse proxy actually in front of the daemon, and nothing else.** With it unset the headers are ignored entirely and `bound_ips` is evaluated against the direct TCP peer — correct for a directly-exposed daemon, and safe for a proxied one (every key simply appears to connect from the proxy). A range wider than the real proxy fleet re-opens the bypass for every host inside it. Hostnames are re-resolved every 30s so a restarted container is picked up without a restart here; a name that fails to resolve is simply not trusted, and the failure is itself cached briefly so an unresolvable entry cannot turn request traffic into a DNS storm. A hostname that does not resolve at startup is logged as an error and re-checked once after a minute — the daemon serves throughout, with that entry untrusted, rather than crash-looping. |
| `LOG_RETENTION_DAYS` | `30` | Age beyond which `executions` rows are purged. `0` keeps history forever. |
| `DELETED_HOOK_RETENTION_DAYS` | `92` | Days a soft-deleted hook stays recoverable before the sweep drops it and its history for good. `0` keeps the trash forever. Governed separately from `LOG_RETENTION_DAYS` on purpose: shortening log retention to reclaim disk must not silently shrink the undo window for deleted automation. |
| `RETENTION_SWEEP_SECONDS` | `3600` | Interval between retention sweeps. |
| `MAX_OUTPUT_BYTES` | `1048576` | Per-stream cap on captured stdout/stderr. Excess is discarded (but still drained) and flagged in the stored output. |
| `BIND_HOST` (or `HOST`) | `0.0.0.0` | Interface to listen on. Must be a literal IP (`0.0.0.0`, `127.0.0.1`, `::`, `::1`) — hostnames are not resolved, since picking one of several resolved addresses is a security decision, not a convenience. `BIND_HOST` wins if both are set. |
| `PORT` | `3000` | Listen port. `0` lets the OS assign a free ephemeral port (useful for tests); the actual port is logged at startup. |
| `BOOTSTRAP_SUBNET` | `0.0.0.0/0,::/0` | `bound_ips` assigned to the auto-generated master key. Both families by default: `bound_ips` binds master keys too, so an IPv4-only value would lock you out of a dual-stack deployment on the first request. |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter, e.g. `debug`, `simply_hook_executor=debug`. |

A malformed `BIND_HOST` or `PORT` logs a warning and falls back to the default rather than
aborting startup — a typo in a unit file should not take the service down. Behind a reverse proxy
on the same host, `BIND_HOST=127.0.0.1` keeps the daemon unreachable from outside:

```bash
BIND_HOST=127.0.0.1 PORT=8080 cargo run
```

### Deployment

**systemd** — a production-ready unit is included at
[`deploy/simply_hook_executor.service`](deploy/simply_hook_executor.service). It runs the daemon
as a dedicated non-root `hookrunner` user with a hardened sandbox; the file's header comment has
the full install sequence. Because hook scripts inherit that identity, `hookrunner` defines the
blast radius of everything this daemon can run — grant it only what those scripts genuinely need.

**Docker** — a `Dockerfile` and `docker-compose.yml` are included:

```bash
docker compose up --build
```

This persists the database under `./data`, mounts `./hooks` read-only at `/opt/hooks` (hook
scripts must exist *inside* the container to be executable), and exposes port `3000`.

## API Reference

Every route below requires an `X-API-Key` header; missing or invalid keys get `401`, and keys
whose `bound_ips` CIDRs don't cover the caller's (proxy-aware) source address get `403`. Master
keys bypass all RBAC checks — but **not** the CIDR check: `bound_ips` binds every key, master
included, and an empty value is the only way to say "from anywhere". Any route accepting a hook
`{identifier}` takes either the hook's UUID or its unique name.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/auth/me` | Identity + effective RBAC permissions for the calling key. |
| `POST` / `GET` | `/api/hooks` | Create / list hooks (creation requires `is_master` or `can_manage_hooks`). |
| `GET` | `/api/hooks/{identifier}` | Read one hook. Needs any mapping (`can_execute` or `can_manage`). |
| `PUT` / `PATCH` / `DELETE` | `/api/hooks/{identifier}` | Update one hook, or move it to the trash. Needs `can_manage`. `DELETE` is a **soft** delete: nothing cascades and the row is recoverable for 92 days. `?hard=true` drops it for good (master only). |
| `POST` | `/api/hooks/{identifier}/restore` | Bring a trashed hook back (master only). |
| `POST` | `/api/hooks/{identifier}/execute` | Run the hook and return its recorded outcome. Needs `can_execute`. |
| `POST` | `/api/hooks/{identifier}/test` | Dry run: preview the resolved command without executing. Needs `can_execute` — the preview reveals the resolved command line and child environment. |
| `GET` / `POST` | `/api/hooks/{identifier}/parameters` | List / declare parameters. |
| `PUT` / `DELETE` | `/api/hooks/{identifier}/parameters/{param_id}` | Update / remove a parameter. |
| `POST` | `/webhook/{identifier}` | Webhook-facing alias of `/execute`, for flat third-party payloads. |
| `POST` / `GET` | `/api/keys` | Create / list API keys (requires `is_master` or `can_manage_keys`). |
| `PUT` / `DELETE` | `/api/keys/{id}` | Update / delete an API key. |
| `POST` | `/api/keys/{id}/rotate` | Issue a new secret, invalidating the old one immediately. |
| `POST` | `/api/keys/{id}/permissions` | Grant/update a key's execute/manage rights on a hook. |
| `DELETE` | `/api/keys/{id}/permissions/{hook_identifier}` | Revoke a key's rights on a hook. |
| `GET` | `/api/executions` | Execution history (`?hook=`, `?status=`, `?limit=`, `?offset=`). |
| `GET` / `DELETE` | `/api/executions/{id}` | Read / delete one execution record. |
| `DELETE` | `/api/executions` | Run the retention sweep on demand (`?older_than_days=`, master only). |
| `GET` | `/api/audit-logs` | Audit trail (`?action=`, `?limit=`, `?offset=`; master only). |
| `GET` | `/api/settings` | Runtime configuration and instance counters (master only). |
| `POST` | `/api/system/purge-hooks` | Permanently drop trashed hooks older than 92 days (`?older_than_days=`, master only). |

The two monitoring probes are the exception to the paragraph above — they are **unauthenticated by
design**, because an orchestrator holds no API key and a liveness check that needs one fails exactly
when the credential store is what broke. Both disclose nothing beyond a fixed two-field document.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/health`, `/healthz` | **Liveness.** Always `200`. Touches nothing — a failing database must not make an orchestrator restart a healthy process. |
| `GET` | `/ready`, `/readyz` | **Readiness.** `200` when the pool answers `SELECT 1`, `503` otherwise. This is what a load balancer should poll. |

`POST .../execute` accepts two body shapes: `{"parameters": {...}}` for first-party clients, or a
bare flat object for webhook senders that can only post their own document. An empty body means
"no parameters". A non-zero script exit is still `200 OK` — the request succeeded; the script's
outcome is in the response's `status`/`exit_code`.

### Examples

```bash
# Who am I / what can I do?
curl -H "X-API-Key: <KEY>" http://localhost:3000/api/auth/me

# Define a hook with a parameter contract
curl -X POST -H "X-API-Key: <MASTER_KEY>" -H "Content-Type: application/json" \
  -d '{
        "name": "nftables_ban",
        "script_path": "/usr/local/bin/ban.sh",
        "default_timeout_seconds": 15,
        "parameters": [
          {"param_key": "target_address", "is_required": true},
          {"param_key": "reason", "default_value": "unspecified"}
        ]
      }' \
  http://localhost:3000/api/hooks

# Dry run: see exactly what would be executed, without executing it
curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  -d '{"parameters": {"target_address": "203.0.113.7"}}' \
  http://localhost:3000/api/hooks/nftables_ban/test

# Execute it
curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  -d '{"parameters": {"target_address": "203.0.113.7", "reason": "SSH brute force"}}' \
  http://localhost:3000/api/hooks/nftables_ban/execute

# The same thing as a signed webhook, with a flat payload
BODY='{"target_address":"203.0.113.7"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "<KEY>" -r | cut -d' ' -f1)
curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  -H "X-Signature-256: sha256=$SIG" -d "$BODY" \
  http://localhost:3000/webhook/nftables_ban

# Create a scoped key and grant it execute-only rights on that hook
curl -X POST -H "X-API-Key: <MASTER_KEY>" -H "Content-Type: application/json" \
  -d '{"name": "vault-bot", "bound_ips": "10.0.0.0/8", "max_concurrent_jobs": 3}' \
  http://localhost:3000/api/keys
curl -X POST -H "X-API-Key: <MASTER_KEY>" -H "Content-Type: application/json" \
  -d '{"hook_name": "nftables_ban", "can_execute": true, "can_manage": false}' \
  http://localhost:3000/api/keys/<KEY_ID>/permissions

# Review what ran
curl -H "X-API-Key: <KEY>" "http://localhost:3000/api/executions?hook=nftables_ban&status=FAILED"
```

### Writing a hook script

A hook script receives its parameters twice — pick whichever is more convenient:

```bash
#!/bin/sh
# Positional, in parameter declaration order (see the /test endpoint for the exact order):
target="$1"
reason="$2"

# ...or by name, uppercased and prefixed:
target="$HOOK_PARAM_TARGET_ADDRESS"
reason="$HOOK_PARAM_REASON"

nft add element inet filter blocklist "{ $target }"
echo "banned $target ($reason)"    # captured as stdout on the execution record
```

The script must be executable (`chmod +x`) and referenced by an absolute path. Exit `0` for
`SUCCESS`; any other code is recorded as `FAILED` along with whatever it wrote to stderr.

## Project structure

```
src/
├── lib.rs                  Router assembly, module registry, retention worker spawn
├── main.rs                 Entrypoint: migrate → bootstrap → pin master → bind → shut down
├── state.rs                AppState: db pool, config, limiter, cipher, replay guard, master pin
├── master.rs               Boot-time Master identity pinning, and runtime demotion of tampered rows
├── middleware.rs           Authentication: bearer key, HMAC, replay, bound-IP
├── config.rs               Environment parsing, trusted proxies, client-IP resolution
├── crypto.rs               HMAC request signing, and signing-secret encryption at rest
├── replay.rs               Single-use enforcement for CANONICAL_V1 signatures
├── executor.rs             Script execution: argv, env isolation, timeout, process-group kill
├── retention.rs            Background sweeps: expired history, trashed hooks
├── db.rs                   Pool construction, SQLite session pragmas, migrations
├── error.rs                AppError → HTTP status mapping
├── api/
│   ├── mod.rs              Module wiring, router-facing re-exports, policy constants
│   ├── support.rs          Shared plumbing — audit writes, hook resolution, validation. Decides nothing
│   ├── guards.rs           Every authorization decision (RBAC_MODEL.md R1–R7, §3–§5). Writes nothing
│   ├── keys.rs             Key CRUD, GET /api/auth/me, per-hook grants, cascade deletion
│   ├── hooks.rs            Hook definitions, parameter contracts, trash/restore/purge
│   ├── executions.rs       Triggering hooks, and reading the execution records
│   ├── audit.rs            Reads over the audit trail — master-only
│   ├── system.rs           Effective configuration and instance counters — master-only
│   └── health.rs           Liveness/readiness probes — the only unauthenticated routes
├── entities/               SeaORM models, one file per table
└── migration/              Ordered schema migrations, applied at startup
```

Two boundaries in `src/api/` are rules rather than conventions, and both are stated in `AGENT.MD`:

- **`support.rs` decides nothing.** Nothing in it returns a refusal that depends on *who* is calling.
  A helper that starts deciding moves to `guards.rs`.
- **`guards.rs` writes nothing**, and is one module rather than one per domain. The rules it enforces
  are cross-cutting — R2's conjunction governs hooks, parameters and execution records alike — so
  splitting it by caller would put one sentence of the specification in three files and invite the
  copies to drift.
- **`crypto.rs` holds the primitives; `middleware.rs` holds the policy.** Nothing in `crypto.rs`
  touches the database, the request, or `AppError` — it returns a `SignatureRejection` and lets the
  middleware decide which failures become `401` and which become `500`.

`FILE_MAP.MD` documents every file's role, key exports, and the rationale for its boundaries.

## Development

```bash
cargo check --all-targets            # compile everything, including tests
cargo test                           # unit + integration + compliance + source hygiene
cargo clippy --all-targets -- -D warnings
./scripts/test_e2e.sh                # full black-box HTTP suite against a real server
./scripts/verify_convergence.sh      # security drift check against the peer service
```

Integration tests live in `tests/` and spin up a fresh in-memory SQLite database per test, driving
the real router and spawning real (throwaway) scripts — no external services required. The E2E
script builds and boots an actual server against a throwaway database and exercises the whole API
with `curl` + `jq`. Both scripts refuse to run from anywhere but the repository root.

Beyond the behavioural suites, two files check things the others structurally cannot:

- **`tests/rbac_model_compliance.rs`** — one test per rule of `RBAC_MODEL.md`, named after the rule
  it enforces, so coverage against the specification is auditable by listing test names. Includes
  *adversarial* tests that reach a guarantee without going through the code meant to uphold it (raw
  SQL, raw request bytes), because a cooperative test of a structural claim proves only that a
  well-behaved writer behaves well.
- **`tests/source_hygiene.rs`** — parses `static/app.js` (never compiled by anything else, so a
  syntax error would otherwise ship silently), checks that every `getElementById` resolves, and
  enforces the raw-SQL allowlist across `src/`.
- **`tests/referential_integrity.rs`** — asserts what the schema's six foreign keys actually *do* on
  delete, since SQLite is the one supported engine where declaring a constraint and enforcing it are
  separate decisions. It distinguishes the `CASCADE` edges from the `SET NULL` ones, because deleting
  a key must remove its grants while leaving its audit trail standing.

See `AGENT.MD` for the full architectural/security ruleset this project is built and audited
against, `FILE_MAP.MD` for the file-by-file map, `SCHEMA.MD` for the database schema, and
`AGENT_NOTES.MD` for the running worklog.

## License

GPLv3 — see [LICENSE](LICENSE).
