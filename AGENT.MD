# Simply Hook Executor - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_hook_executor`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, process execution rules, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.

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

- **Middleware Protection:** All `/api/*` and `/webhook/*` routes pass through custom authentication middleware (`src/middleware.rs`).
- **Authentication Modes:**
  - **API Key:** Verified via `X-API-Key` header.
  - **HMAC SHA-256 Signature:** Verified via `X-Signature-256: sha256=<hex_hmac>` calculated over the raw JSON body using the API Key's secret or a hook-specific secret.
- **CIDR Restriction:** API Keys are bound to CIDR network ranges (`bound_ips`, supporting comma-separated IPv4/IPv6 ranges like `127.0.0.1/32, 10.0.0.0/8, ::/0`). Middleware MUST validate the client's IP against these bounds.
- **Resilient IP Extraction:** Do NOT use external IP extraction crates. Extract the rightmost IP from `X-Forwarded-For` or `X-Real-IP`, falling back safely to `axum::extract::ConnectInfo`.

### 2. Granular Multi-Tenant RBAC (M:N)

- **Global Rights:** An `ApiKey` can be `is_master` (bypasses all checks) or hold global booleans (`can_manage_keys`, `can_manage_hooks`).
- **Hook Rights:** Managed via junction table `ApiKeyHookPermission` linking keys to `Hook` with explicit flags (`can_execute`, `can_manage`).
- **Least Privilege:** `can_execute` or `can_manage` require valid key mapping unless `is_master`.
- **Auto-Provisioning:** When an API Key creates a new `Hook`, the backend MUST automatically generate full execute/manage permissions for that key on the new hook.

### 3. Safe Script Execution Engine

- **Strict Injection Prevention:** NEVER evaluate commands inside a shell string (e.g., `sh -c "script.sh $VAR"` is FORBIDDEN). Always use `tokio::process::Command::new(script_path).args(arg_list)`.
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

### 4. History, Output Capture & Log Retention

- Every execution produces an `Execution` record storing status (`SUCCESS`, `FAILED`, `TIMEOUT`), exit code, full `stdout`, full `stderr`, duration in milliseconds, resolved parameters JSON, and timestamp.
- **Log Retention Worker:** An asynchronous background task purges `Execution` entries older than `LOG_RETENTION_DAYS` (default: 30 days) on a periodic schedule.

### 5. Dry-Run / Test Endpoint (`POST /api/hooks/:id/test`)

- Allows testing parameter resolution and previewing the generated command without actually spawning the sub-process.
- Returns a JSON payload showing:
  - Resolved parameters (merged defaults and overrides).
  - List of missing required parameters (if any).
  - Exact binary/script path and argument list that would be executed.
  - Injected environment variables map.

### 6. Frontend Integration & Dynamic UI

- Single Page Application (SPA) served from `static/`.
- Authenticates via `X-API-Key` stored in `localStorage`.
- **Dynamic Scope Rendering:** On startup, `app.js` calls `GET /api/auth/me` and renders/hides tabs and controls (Executions/Dashboard, Hooks Management, API Keys & Permissions, System Settings) based on the returned permissions.
- Global fetch wrapper injects `X-API-Key` and intercepts `401/403` responses to return to the login screen.
- Custom dark confirmation modals for deletions (NO native `window.confirm()`).
- High-contrast action buttons and styled custom checkboxes.

### 7. Audit Logging

- Every mutating configuration change (Key CRUD, Hook CRUD, Permission updates) writes an `AuditLog` entry storing `api_key_id`, `api_key_name`, `api_key_prefix`, `client_ip`, `action`, `target_resource`, `details`, and timestamp.

### 8. Database Bootstrapping & Systemd Integration

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG`.
- Migrations run automatically on startup.
- **Master Key Auto-Gen:** If `api_keys` contains no master keys at boot, generate a default Master Key and output it once clearly to `stdout`.
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