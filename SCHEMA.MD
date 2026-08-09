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
| bound_ips         |       | can_view_execution (BOOL) |       | owner_key_id      |
| max_concurrent    |       +---------------------------+       +-------------------+
| is_master         |                                             | 1
| master_marker     |                                             | M
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
| `bound_ips` | String | NOT NULL, DEFAULT `'0.0.0.0/0,::/0'` | Comma-separated CIDR ranges permitted to use this key. Enforced for **every** key including `is_master` (see below); an empty value means "unrestricted". The address compared against it is the TCP peer unless that peer is in `TRUSTED_PROXIES`. |
| `max_concurrent_jobs`| Integer | NOT NULL, DEFAULT `10` | Maximum simultaneous script executions allowed for this key. |
| `is_master` | Boolean | NOT NULL, DEFAULT `false` | Bypasses all **RBAC** checks if `true`. It does **not** bypass the `bound_ips` network check, which is a transport boundary rather than a permission. **Not settable through any API endpoint** — it is absent from every request payload, and at most one row may carry it (see `master_marker` below). Its only writer is the boot-time bootstrap against an empty table. |
| `master_marker` | Integer | **GENERATED**, NULLABLE, UNIQUE (`idx_api_keys_master_marker`) | `1` when `is_master`, `NULL` otherwise — the database-level guarantee that exactly one master exists (`RBAC_MODEL.md` §5). Absent from `api_key::Model` on purpose: SeaORM builds explicit column lists from the entity, so an undeclared column never appears in an `INSERT`, which is required since the engine rejects writes to a generated column. See the note below. |
| `can_manage_keys` | Boolean | NOT NULL, DEFAULT `false` | Global right to manage **other** API keys. Explicitly *not* the right to grant global scopes, to administer a key that is itself `is_master`, or to alter the caller's own hook permissions — all three are master-only, or the scope would be self-amplifying and thus equivalent to `is_master`. |
| `parent_key_id` | UUID / String | NULLABLE, INDEXED (`idx_api_keys_parent_key_id`) | The key that created this one. **Lineage only — never authority** (`RBAC_MODEL.md` R3): it exists for cascading deletion and visibility scoping, and no authorization decision may read it. A daughter of the master is an ordinary daughter. `NULL` for the bootstrap master and for keys predating lineage. |
| `owner_key_id` | UUID / String | NULLABLE, INDEXED (`idx_api_keys_owner_key_id`) | The key answerable for this one. Set to the creator at creation and thereafter free to diverge from lineage: §6's inventory reports it as `current_owner`, while the subtree walk producing that inventory follows `parent_key_id`. |
| `can_manage_hooks` | Boolean | NOT NULL, DEFAULT `false` | Global right to create hooks (creation auto-provisions a full permission row on the new hook and records the creator as its `owner_key_id`). Never confers rights over a hook created by someone else, and never over a hook carrying `run_as_user`. **Nor does it confer the right to edit what it created:** every later edit is governed by `RBAC_MODEL.md` R2, whose global half is `can_manage_keys` — a resource-creation right and a resource-management right are separate powers and neither implies the other (§1). A key that must both define and maintain hooks holds both flags, and both are Master-granted only (R4). |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |
| `updated_at` | DateTime | NOT NULL | Last modification timestamp (UTC). |

#### Master uniqueness (`master_marker`)

`RBAC_MODEL.md` §5 requires that "exactly one Master key exists, enforced by a database constraint
rather than by application logic alone." Two design choices make that portable and unbypassable:

- **A plain unique index on a nullable column, not a partial index.** The natural spelling is
  `CREATE UNIQUE INDEX … ON api_keys (is_master) WHERE is_master`. PostgreSQL and SQLite accept it;
  **MySQL does not** — there is no `WHERE` clause on `CREATE INDEX` — and `Cargo.toml` enables the
  MySQL driver, so a partial index would leave MySQL deployments silently unprotected. SQL's unique
  semantics treat `NULL`s as non-colliding, so a nullable marker under a plain unique index caps
  master rows at one while leaving the number of ordinary keys unbounded.
- **Generated by the engine, not written by the application.** A hand-maintained marker could be
  bypassed by writing `is_master = true` and leaving the marker `NULL` — which is exactly the
  "application logic alone" §5 rules out. Deriving it from `is_master` makes the constraint hold
  against *any* writer: a future handler, a migration, a restored backup, or an operator at a SQL
  prompt.

One dialect split, in `m20230106_000001_master_key_uniqueness`: PostgreSQL generated columns must be
`STORED` (it gained `VIRTUAL` only in 18), while SQLite permits only `VIRTUAL` for a column added
through `ALTER TABLE`. MySQL accepts either and is given `VIRTUAL`. Semantics are identical.

If a database somehow already holds two master rows, creating the index fails and the migration
aborts, taking startup with it. That is deliberate — deciding which master is legitimate is an
operator's judgement. Demote or delete the extra row directly and restart.

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
| `is_deleted` | Boolean | NOT NULL, DEFAULT `false` | Soft-delete flag. A `true` row is in the trash: invisible to every ordinary route and unexecutable, but fully intact. |
| `deleted_at` | DateTime | NULLABLE, DEFAULT `NULL` | When the hook was trashed. The clock the 92-day purge measures from. |
| `deleted_by` | Text | NULLABLE, DEFAULT `NULL` | The `api_keys.id` of whoever trashed it, **as text**. |
| `owner_key_id` | UUID / String | NULLABLE, INDEXED (`idx_hooks_owner_key_id`) | The key answerable for this hook: with master, the **only** identity that may delete or rename it (`RBAC_MODEL.md` §3). Deliberately not derivable from `api_key_hook_permissions` — a creator receives an ordinary `can_manage` row there, byte-identical to a delegated one, so "holds `can_manage`" says nothing about authorship. `NULL` for hooks predating ownership, which leaves lifecycle authority with master alone. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |
| `updated_at` | DateTime | NOT NULL | Last modification timestamp (UTC). |

#### Soft delete

`DELETE /api/hooks/{id}` marks the row rather than dropping it. The reason is the cascade: `hooks` is
the parent of `hook_parameters`, `api_key_hook_permissions`, **and `executions`**, all
`ON DELETE CASCADE`. Dropping one row therefore destroyed the complete audit record of everything
that hook had ever run, irreversibly, from a single mistyped identifier.

| Operation | Effect |
| :--- | :--- |
| `DELETE /api/hooks/{id}` | `is_deleted = true`, `deleted_at = now()`, `deleted_by = caller` — nothing cascades |
| `GET /api/hooks`, `GET /api/hooks/{id}`, execute, `/test`, `/webhook/{id}`, parameter routes | behave as though the row does not exist (`404`) |
| `GET /api/hooks?include_deleted=true`, `GET /api/hooks/{id}?include_deleted=true` | the trash view — **master only** |
| `POST /api/hooks/{id}/restore` | clears all three columns — **master only** |
| `DELETE /api/hooks/{id}?hard=true` | drops the row, cascading everything — **master only** |
| `POST /api/system/purge-hooks` | drops trash older than 92 days — **master only** |

Three details are deliberate:

- **`deleted_by` is text, not a foreign key.** Attribution has to outlive the acting key; a real FK
  would either cascade the attribution away with that key or block it from ever being deleted. This
  matches how `audit_logs` already denormalizes `api_key_name` and `api_key_prefix`.
- **`hooks.name` stays unique across live *and* trashed rows.** Scoping uniqueness to live rows needs
  a partial unique index, whose syntax is backend-specific and therefore forbidden by `AGENT.MD`. A
  trashed hook consequently still holds its name; creating a replacement returns `409` with a message
  naming the trashed holder and how to free it.
- **A soft-deleted hook keeps its execution history visible** in `GET /api/executions`. Preserving
  that history is the entire point of the feature, so hiding it along with the hook would defeat it.

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
| `can_manage` | Boolean | NOT NULL, DEFAULT `false` | **Half** of the permission to edit this hook's configuration, its parameters, and its execution records. Never sufficient alone: `RBAC_MODEL.md` **R2** makes management a conjunction of this row and the *global* `api_keys.can_manage_keys`, because §1's Tiers matrix says a Daughter key (one without that flag) may never manage resources. On its own this row grants read visibility (below) and nothing more; it is a necessary condition, not a grant. The one route around the conjunction is **ownership**: `hooks.owner_key_id` may edit its own hook with no permission row at all. Deleting or renaming still needs ownership (§3). |
| `can_view_execution` | Boolean | NOT NULL, DEFAULT `false` | Permission to read this hook's **execution records** — the runs, their output streams, exit codes, and the parameters each was called with. Deliberately a third verb rather than a facet of the other two. `RBAC_MODEL.md` names the Execution record a *creator-private entity*, so history is **not** covered by the shared-resource visibility rule: a key sees its own runs and every run of a hook it owns without this flag, and needs it only to read runs that are neither. Folding it into `can_execute` would hand every caller entitled to run a hook the output of everyone else's runs; folding it into `can_manage` would put read-only audit access behind R2's conjunction, so an auditor could be granted logs only by first being made a Parent with editing rights. **Read-only in every direction**: it never confers running, editing, or deleting a record. Not indexed — it is never searched on, only read from a row already fetched by the `(api_key_id, hook_id)` unique index. |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC). |

*Unique Index:* `(api_key_id, hook_id)`

#### Derived read access (there is no `can_read` column)

This table stores exactly **two** flags. Read access is *derived* rather than stored:

> A key may read a hook's details, its parameter contract, and its execution history if it is
> `is_master`, **or** holds `can_execute = true`, **or** holds `can_manage = true` on that hook.

A key with no mapping for a hook can read nothing about it — `GET /api/hooks/{id}` returns `404`,
byte-identical to the answer for a hook id that was never issued (`RBAC_MODEL.md` §4 oracle
discipline; a `403` here would confirm the hook exists), and `GET /api/hooks` / `GET /api/executions`
simply omit it rather than erroring.

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