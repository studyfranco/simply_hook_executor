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
| `bound_ips` | String | NOT NULL, DEFAULT `'0.0.0.0/0,::/0'` | Comma-separated CIDR ranges permitted to use this key. |
| `max_concurrent_jobs`| Integer | NOT NULL, DEFAULT `10` | Maximum simultaneous script executions allowed for this key. |
| `is_master` | Boolean | NOT NULL, DEFAULT `false` | Bypasses all RBAC checks if `true`. |
| `can_manage_keys` | Boolean | NOT NULL, DEFAULT `false` | Global right to manage other API keys. |
| `can_manage_hooks` | Boolean | NOT NULL, DEFAULT `false` | Global right to create and manage hooks. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |
| `updated_at` | DateTime | NOT NULL | Last modification timestamp (UTC). |

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
| `can_execute` | Boolean | NOT NULL, DEFAULT `true` | Permission to invoke `POST /api/hooks/:id/execute`. |
| `can_manage` | Boolean | NOT NULL, DEFAULT `false` | Permission to edit or delete this hook configuration. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |

*Unique Index:* `(api_key_id, hook_id)`

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

---

## 🔗 SeaORM Entity Relations

- **`ApiKey` -> `ApiKeyHookPermission`**: HasMany (`api_key_id`)
- **`Hook` -> `ApiKeyHookPermission`**: HasMany (`hook_id`)
- **`Hook` -> `HookParameter`**: HasMany (`hook_id`)
- **`Hook` -> `Execution`**: HasMany (`hook_id`)
- **`ApiKey` -> `Execution`**: HasMany (`api_key_id`)