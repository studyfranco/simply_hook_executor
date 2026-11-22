---
name: use-hook-executor
description: Operate and configure simply_hook_executor via its CANONICAL_V1 / HMAC_ONLY API, manage hooks, scoped API keys, SSH credentials/targets, dry-run previews, and execution/audit history.
---

# Using `simply_hook_executor`

`simply_hook_executor` is a self-hosted Rust/Axum daemon that turns authenticated HTTP requests and webhooks into runs of operator-configured local scripts or remote SSH commands, backed by SeaORM (SQLite default, PostgreSQL/MySQL-ready).

## 1. Network Placement & Trust Boundary

- **`isolate` bridge (primary):** Attach the daemon to the internal `isolate` network so sibling services (e.g. `https://vault.example.internal:8443`) can trigger hooks and the daemon can reach the host SSH gateway (e.g. `192.0.2.10:22`) or internal SSH targets (e.g. `198.51.100.20`).
- **`ext` reverse-proxy boundary (optional):** Attach `ext` only when an admin reverse proxy terminates TLS for dashboard or external webhook ingress (e.g. `https://hooks.example.com`). Configure `TRUSTED_PROXIES` strictly to the proxy's address/CIDR (e.g. `203.0.113.10/32` or `2001:db8::/32`) so `X-Forwarded-For` / `X-Real-IP` are only believed from trusted peers.
- **Health probes:** `GET /health` (`/healthz`) and `GET /ready` (`/readyz`) are unauthenticated so orchestrators can probe liveness and database readiness.

## 2. Authentication & `CANONICAL_V1` Signing

Every `/api/*` route requires `X-API-Key` except the three hook-invocation routes (`POST /api/hooks/{identifier}/execute`, `POST /api/hooks/{identifier}/test`, `POST /webhook/{identifier}`), which are governed per-hook by `auth_mode`:

| `auth_mode` | Caller credentials | Use case |
| --- | --- | --- |
| `CANONICAL_V1` (default) | `X-API-Key` (and `X-Timestamp` + `X-Signature-256` when `REQUIRE_SIGNED_REQUESTS=true` or key has `can_manage_keys`) | Internal services & admin operations |
| `API_KEY_ONLY` | `X-API-Key` only | Simple internal callers without HMAC |
| `HMAC_ONLY` | Hook-level `hmac_secret` via `signature_header` (default `X-Signature-256`) and `signature_prefix` (default `sha256=`) | Third-party webhooks |
| `NONE` | No key or signature (bound-IP / network isolation only) | Trusted `isolate`-only triggers |

### `CANONICAL_V1` Signature Format

The canonical string is signed with HMAC-SHA256 using the key's **signing secret** (not the bearer `X-API-Key`):

```text
<METHOD>\n<PATH_AND_QUERY>\n<UNIX_TIMESTAMP>\n<RAW_BODY>
```

- `<PATH_AND_QUERY>` is the full request URI including `/api` or `/webhook` prefix and query string (preserved via Axum `OriginalUri`).
- `<UNIX_TIMESTAMP>` is the integer Unix epoch seconds sent in `X-Timestamp` (enforced against `SIGNATURE_MAX_AGE_SECONDS` and single-use replay protection).
- `<RAW_BODY>` is the exact raw HTTP body bytes (empty string `""` for `GET`/`DELETE` with no body).

Example helper in bash:

```bash
BASE_URL="https://hooks.example.com"   # or http://<HOST>:<PORT> on isolate
PATH_AND_QUERY="/api/hooks/deploy-app/test"
TS="$(date +%s)"
BODY='{"parameters":{"env":"staging"}}'
SIG="$(printf '%s\n%s\n%s\n%s' "POST" "$PATH_AND_QUERY" "$TS" "$BODY" \
  | openssl dgst -sha256 -hmac "$SIGNING_SECRET" -r | cut -d' ' -f1)"

curl -sS -X POST "${BASE_URL}${PATH_AND_QUERY}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -H "X-Timestamp: ${TS}" \
  -H "X-Signature-256: ${SIG}" \
  -d "$BODY"
```

## 3. Master vs Scoped RBAC

- **Master key (`is_master: true`):** Full access to all hooks, keys, SSH credentials/targets, `GET /api/settings`, `GET /api/audit-logs`, `DELETE /api/executions` (purge), `POST /api/hooks/{identifier}/restore`, and `POST /api/system/purge-hooks`.
- **Scoped key (`is_master: false`):**
  - Global flags: `can_manage_hooks`, `can_manage_keys` (must always sign with `CANONICAL_V1`), `can_manage_ssh`, `can_view_execution`.
  - Per-hook permissions (`POST /api/keys/{id}/permissions`, `DELETE /api/keys/{id}/permissions/{hook_identifier}`): `can_execute`, `can_manage`.
  - Per-SSH-target permissions (`GET|POST /api/ssh-targets/{id}/permissions`, `DELETE /api/ssh-targets/{id}/permissions/{api_key_id}`): `can_use_in_hook` (target owners and master can attach a target to a hook; non-owners need `can_use_in_hook`).
  - Network & rate guards: `bound_ips` (CIDR allowlist) and `max_concurrent_jobs` (returns `429` when exceeded).

Inspect your active key's identity and capabilities anytime with `GET /api/auth/me`.

## 4. Execution Cookbook (Local Scripts, SSH Hosts, Ansible)

### A. Local Script Hook (`execution_type: "LOCAL"`)

Local execution uses no shell (`tokio::process::Command::new` with `env_clear()`, `ALLOWED_ENV_VARS` passthrough, and `HOOK_PARAM_<KEY>` injection). Scripts must live under `ALLOWED_SCRIPT_ROOTS` when configured.

```bash
curl -sS -X POST "${BASE_URL}/api/hooks" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{
    "name": "reload-edge",
    "script_path": "/opt/hooks/reload-edge.sh",
    "default_timeout_seconds": 30,
    "run_as_user": "ops",
    "args_template": "--target ${target_host}",
    "parameters": [
      { "param_key": "target_host", "is_required": true }
    ]
  }'
```

### B. Remote SSH Host Execution (`execution_type: "SSH"`)

1. **Create credential** (`POST /api/ssh-credentials` with `auth_type: "KEY"` or `"PASSWORD"`).
2. **Fetch & verify host key fingerprint out-of-band** (`POST /api/ssh-targets/fetch-fingerprint` with `{"host":"198.51.100.20","port":22}`).
3. **Create pinned SSH target** (`POST /api/ssh-targets` with `credential_id` and `host_key_fingerprint: "SHA256:..."`). Unpinned targets are refused at connect time.
4. **Verify connectivity** (`POST /api/ssh-targets/{id}/test-connection`).
5. **Create SSH hook** (`POST /api/hooks` with `"execution_type": "SSH"`, `"ssh_target_id": "<TARGET_UUID>"`, `"script_path": "/opt/remote/apply.sh"`).

### C. Ansible Playbook Execution

Wrap `ansible-playbook` in an operator-owned script under `ALLOWED_SCRIPT_ROOTS` (e.g. `/opt/hooks/run-ansible.sh`) that validates inputs and passes `--limit` / `--check` safely:

- Pass parameters via `HOOK_PARAM_*` or explicit `args_template` flags (e.g. `--limit ${host_group} --check ${dry_run}`).
- Use `POST /api/hooks/{identifier}/test` first with `dry_run: "true"` to verify the exact resolved `program`, `args`, `env`, and `run_as_user` before running `POST /api/hooks/{identifier}/execute`.

## 5. Dry-Run & Safety Guardrails

1. **Always dry-run first:** Call `POST /api/hooks/{identifier}/test` before `POST /api/hooks/{identifier}/execute` or `POST /webhook/{identifier}`. It validates parameters, renders `args_template`, checks `is_active` and `executor::ensure_runnable`, and returns the execution plan without spawning a process.
2. **Pin SSH host keys:** Never omit `host_key_fingerprint` on SSH targets; treat any fingerprint mismatch as a hard stop.
3. **Least-privilege keys:** Issue scoped keys with `bound_ips`, `max_concurrent_jobs`, and per-hook `can_execute` rather than sharing the Master key with automation callers.
4. **Inspect outcomes:** Check `GET /api/executions?hook_id=<UUID>` and `GET /api/executions/{id}` for `status`, `exit_code`, `stdout`, `stderr`, and `duration_ms`.
