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

## Features

- Define **hooks**: a name, an absolute `script_path`, a timeout, and a declared parameter
  contract (`param_key`, `default_value`, `is_required`).
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
| `LOG_RETENTION_DAYS` | `30` | Age beyond which `executions` rows are purged. `0` keeps history forever. |
| `RETENTION_SWEEP_SECONDS` | `3600` | Interval between retention sweeps. |
| `MAX_OUTPUT_BYTES` | `1048576` | Per-stream cap on captured stdout/stderr. Excess is discarded (but still drained) and flagged in the stored output. |
| `BIND_HOST` (or `HOST`) | `0.0.0.0` | Interface to listen on. Must be a literal IP (`0.0.0.0`, `127.0.0.1`, `::`, `::1`) — hostnames are not resolved, since picking one of several resolved addresses is a security decision, not a convenience. `BIND_HOST` wins if both are set. |
| `PORT` | `3000` | Listen port. `0` lets the OS assign a free ephemeral port (useful for tests); the actual port is logged at startup. |
| `BOOTSTRAP_SUBNET` | `0.0.0.0/0` | `bound_ips` assigned to the auto-generated master key. |
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
keys bypass all RBAC and CIDR checks. Any route accepting a hook `{identifier}` takes either the
hook's UUID or its unique name.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/auth/me` | Identity + effective RBAC permissions for the calling key. |
| `POST` / `GET` | `/api/hooks` | Create / list hooks (creation requires `is_master` or `can_manage_hooks`). |
| `GET` / `PUT` / `DELETE` | `/api/hooks/{identifier}` | Read / update / delete one hook. |
| `POST` | `/api/hooks/{identifier}/execute` | Run the hook and return its recorded outcome. |
| `POST` | `/api/hooks/{identifier}/test` | Dry run: preview the resolved command without executing. |
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

## Development

```bash
cargo check --all-targets            # compile everything, including tests
cargo test                           # unit + integration tests, run against sqlite::memory:
cargo clippy --all-targets -- -D warnings
./scripts/test_e2e.sh                # full black-box HTTP suite against a real server
```

Integration tests live in `tests/` and spin up a fresh in-memory SQLite database per test, driving
the real router and spawning real (throwaway) scripts — no external services required. The E2E
script builds and boots an actual server against a throwaway database and exercises the whole API
with `curl` + `jq`.

See `AGENT.MD` for the full architectural/security ruleset this project is built and audited
against, `SCHEMA.MD` for the database schema, and `AGENT_NOTES.MD` for the running worklog.

## License

GPLv3 — see [LICENSE](LICENSE).
