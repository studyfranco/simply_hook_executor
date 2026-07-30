# Simply Hook Executor - Database Schema & SeaORM Specifications

This document defines the official database schema, SeaORM entity models, relationships, and enumeration types for `simply_hook_executor`.

---

## 📊 Entity Relationship Diagram (Conceptual)

```
+-------------------+       +---------------------------+       +-------------------+
|      api_keys     | 1   M | api_key_hook_permissions  | M   1 |       hooks       |
+-------------------+-------+---------------------------+-------+-------------------+
| id (UUID)         |       | api_key_id (UUID)         |       | id (UUID)         |
| name              |       | hook_id (UUID)            |       | name              |
| plaintext_prefix  |       | can_execute (BOOL)        |       | script_path       |
| key_hash          |       | can_manage (BOOL)         |       | default_timeout_s |
| bound_ips         |       +---------------------------+       +-------------------+
| max_concurrent    |                                             | 1
| is_master         |                                             | M
+-------------------+                                           +-------------------+
  | 1                                                           | hook_parameters   |
  |                                                             +-------------------+
  | M                                                           | id (UUID)         |
+-------------------+                                           | hook_id (UUID)    |
|    executions     | M                                         | param_key         |
+-------------------+-------------------------------------------| default_value     |
| id (UUID)         |                                           | is_required       |
| hook_id (UUID)    |                                           +-------------------+
| api_key_id (UUID) |
| status (ENUM)     |
| exit_code         |
| stdout / stderr   |
+-------------------+
```

---

## 📁 Database Tables & Fields

### 1. `api_keys`
Stores authentication keys, global scopes, and network restrictions.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the API Key. |
| `name` | String | NOT NULL | Human-readable label (e.g., "Vault Webhook Client"). |
| `plaintext_prefix`| String | NOT NULL | First 8 characters of plaintext key for display/logs. |
| `key_hash` | String | NOT NULL, UNIQUE | Argon2id or SHA-256 hash of the secret key. |
| `key_id` | String | NULLABLE, UNIQUE | Public, non-secret identifier (`shk_<32 hex>`) for display and log correlation. Safe to log. **Not a credential and not an authentication header** — callers identify themselves with `X-API-Key`, which is the only key lookup path. `NULL` only for keys issued before signing secrets existed; rotate such a key to mint a pair. |
| `signing_secret` | Text | NULLABLE | HMAC-SHA256 signing secret — see the storage model below. Returned in plaintext exactly once, in the `POST /api/keys` (or `/rotate`) response. `NULL` alongside a `NULL` `key_id`. |
| `hmac_mode` | String | NOT NULL, DEFAULT `'CANONICAL_V1'` | Signature verification scheme: `CANONICAL_V1` or `BODY_ONLY`. See the enumeration section below. |
| `bound_ips` | String | NOT NULL, DEFAULT `'0.0.0.0/0,::/0'` | Comma-separated CIDR ranges permitted to use this key. |
| `max_concurrent_jobs`| Integer | NOT NULL, DEFAULT `10` | Maximum simultaneous script executions allowed for this key. |
| `is_master` | Boolean | NOT NULL, DEFAULT `false` | Bypasses all RBAC checks if `true`. |
| `can_manage_keys` | Boolean | NOT NULL, DEFAULT `false` | Global right to manage other API keys. |
| `can_manage_hooks` | Boolean | NOT NULL, DEFAULT `false` | Global right to create and manage hooks. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |
| `updated_at` | DateTime | NOT NULL | Last modification timestamp (UTC). |

#### `signing_secret` storage model

Unlike `key_hash`, this column is **not** a digest, and cannot be: verifying an `X-Signature-256`
header means *recomputing* the HMAC, which requires the original secret bytes. Hashing it would make
signature verification impossible.

It is therefore **encrypted at rest** with XChaCha20-Poly1305 (`src/crypto.rs`):

| Storage mode | Trigger | Column contents |
| :--- | :--- | :--- |
| Sealed | `SIGNING_SECRET_KEY` (or alias `VAULT_ENCRYPTION_KEY`) set to 64 hex chars | `v1.xchacha20poly1305.<nonce_hex>.<ciphertext_hex>` |
| Unencrypted | neither variable set | `v1.plain.<secret_hex>` |

- `SIGNING_SECRET_KEY` wins when both variables are set.
- A **malformed** key aborts startup. It never falls back to plaintext: an operator who set the
  variable believes their secrets are encrypted, and silently writing them in the clear would betray
  that at exactly the wrong moment.
- Running with **no** key is supported (zero-config) but logs a startup warning — database read
  access alone would then be enough to forge signatures for every key.
- The version prefixes make enabling encryption on a live deployment safe: previously-written
  `v1.plain.` rows stay readable, and newly-written secrets are sealed from then on.
- Even the unencrypted mode hex-encodes, so a raw secret is never a substring of the stored column.
- A fresh random nonce is generated per seal, so identical secrets never produce identical
  ciphertexts.

---

### 2. `hooks`
Defines executable script definitions and execution constraints.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the hook. |
| `name` | String | NOT NULL, UNIQUE | Unique hook identifier name (e.g., `nftables_ban`). |
| `description` | String | NULLABLE | Optional summary of what the hook script does. |
| `script_path` | String | NOT NULL | Absolute filesystem path to executable (`/usr/local/bin/ban.sh`). |
| `default_timeout_seconds` | Integer | NOT NULL, DEFAULT `30` | Maximum allowed runtime before `SIGKILL`. |
| `run_as_user` | String | NULLABLE, DEFAULT `NULL` | Target account for privileged execution. `NULL`/empty runs the script directly as the daemon user; a value (e.g. `root`, `postgres`) runs it via `sudo -n -u <user> --`. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |
| `updated_at` | DateTime | NOT NULL | Last modification timestamp (UTC). |

---

### 3. `hook_parameters`
Specifies parameters accepted or required by a hook.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the parameter rule. |
| `hook_id` | UUID / String | NOT NULL, FOREIGN KEY (`hooks.id` ON DELETE CASCADE) | Target hook. |
| `param_key` | String | NOT NULL | Variable name (e.g., `target_address`, `group_name`). |
| `description` | String | NULLABLE | Description of the parameter. |
| `default_value` | String | NULLABLE | Default value used if parameter is omitted in request. |
| `is_required` | Boolean | NOT NULL, DEFAULT `true` | If `true` and no default exists, request fails if omitted. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |

---

### 4. `api_key_hook_permissions`
Junction table managing M:N permissions between API Keys and Hooks.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the permission entry. |
| `api_key_id` | UUID / String | NOT NULL, FOREIGN KEY (`api_keys.id` ON DELETE CASCADE) | Target API key. |
| `hook_id` | UUID / String | NOT NULL, FOREIGN KEY (`hooks.id` ON DELETE CASCADE) | Target hook. |
| `can_execute` | Boolean | NOT NULL, DEFAULT `true` | Permission to invoke `POST /api/hooks/:id/execute`, `POST /api/hooks/:id/test`, and `POST /webhook/:id`. |
| `can_manage` | Boolean | NOT NULL, DEFAULT `false` | Permission to edit or delete this hook configuration, its parameters, and its execution records. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |

*Unique Index:* `(api_key_id, hook_id)`

#### Derived read access (there is no `can_read` column)

This table stores exactly **two** flags. Read access is *derived* rather than stored:

> A key may read a hook's details, its parameter contract, and its execution history if it is
> `is_master`, **or** holds `can_execute = true`, **or** holds `can_manage = true` on that hook.

A key with no mapping for a hook can read nothing about it — `GET /api/hooks/{id}` returns `403`,
and `GET /api/hooks` / `GET /api/executions` simply omit it rather than erroring.

Deriving read access this way keeps the two natural roles coherent with two columns: an executor can
inspect what it runs, and a manager can inspect what it configures. A stored `can_read` flag would
only add expressiveness for a "may read but may neither run nor edit" auditor role, which nothing
currently requires; introducing it would be a schema change, not an implementation detail.

---

### 5. `executions`
Stores complete execution history, output logs, and performance metrics.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique identifier for the execution job. |
| `hook_id` | UUID / String | NOT NULL, FOREIGN KEY (`hooks.id` ON DELETE CASCADE) | Executed hook. |
| `api_key_id` | UUID / String | NULLABLE, FOREIGN KEY (`api_keys.id` ON DELETE SET NULL) | Key that requested execution. |
| `status` | Enum (`ExecutionStatus`) | NOT NULL | Outcome: `SUCCESS`, `FAILED`, `TIMEOUT`. |
| `exit_code` | Integer | NULLABLE | Sub-process exit code (e.g., `0`, `1`, `137`). |
| `stdout` | Text | NOT NULL, DEFAULT `''` | Captured standard output. |
| `stderr` | Text | NOT NULL, DEFAULT `''` | Captured standard error output. |
| `parameters_json`| Text | NOT NULL | JSON string of resolved parameters passed to execution. |
| `duration_ms` | Integer | NOT NULL | Total execution time in milliseconds. |
| `timestamp` | DateTime | NOT NULL | Execution start timestamp (UTC). |

---

### 6. `audit_logs`
System-wide audit trail for configuration changes.

| Field | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID / String | PRIMARY KEY | Unique log entry ID. |
| `api_key_id` | UUID / String | NULLABLE | ID of acting key. |
| `api_key_name` | String | NOT NULL | Denormalized key name for log stability. |
| `api_key_prefix` | String | NOT NULL | Denormalized key prefix. |
| `client_ip` | String | NOT NULL | IP address of caller. |
| `action` | String | NOT NULL | Action name (e.g. `HOOK_CREATE`, `KEY_ROTATE`). |
| `target_resource`| String | NULLABLE | Target resource identifier or name. |
| `details` | String | NULLABLE | Additional details or changed parameters. |
| `timestamp` | DateTime | NOT NULL | Event timestamp (UTC). |

---

## 🔠 Enumeration Types

### `ExecutionStatus`
- `SUCCESS`: Process completed with exit code `0`.
- `FAILED`: Process completed with non-zero exit code or failed to launch.
- `TIMEOUT`: Process exceeded maximum runtime and was terminated.

### `HmacMode`

Stored as a plain string (portable across SQLite/PostgreSQL/MySQL), selected **per API key**.

| Value | Signed material | Accepted headers | `X-Timestamp` | Replay protection |
| :--- | :--- | :--- | :--- | :--- |
| `CANONICAL_V1` *(default)* | `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY` | `X-Signature-256` | **required** | **yes** — 300s window, and the timestamp is inside the signed material so it cannot be re-dated |
| `BODY_ONLY` | `RAW_BODY` | `X-Signature-256` **or** `X-Hub-Signature-256` | not required, ignored if sent | **none** |

- `BODY_ONLY` exists solely for third-party senders (GitHub, Forgejo, GitLab) whose signature format
  cannot be changed. An intercepted request in this mode stays replayable indefinitely, so it should
  be scoped to a key that can execute only the hooks that sender is meant to trigger.
- `X-Hub-Signature-256` is honoured **only** in `BODY_ONLY`. A `CANONICAL_V1` key cannot be
  downgraded to body-only verification by sending the other header name — the per-key mode is
  enforced, not advisory.
- The column defaults to `CANONICAL_V1`, including for rows backfilled by the migration that adds
  it: an upgrade must never silently strip replay protection from an existing key.
- Selecting `BODY_ONLY` at creation or switching to it later is recorded in the audit trail,
  explicitly labelled as removing replay protection.

---

## 🔗 SeaORM Entity Relations

- **`ApiKey` -> `ApiKeyHookPermission`**: HasMany (`api_key_id`)
- **`Hook` -> `ApiKeyHookPermission`**: HasMany (`hook_id`)
- **`Hook` -> `HookParameter`**: HasMany (`hook_id`)
- **`Hook` -> `Execution`**: HasMany (`hook_id`)
- **`ApiKey` -> `Execution`**: HasMany (`api_key_id`)