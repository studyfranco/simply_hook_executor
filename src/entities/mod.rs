//! SeaORM entity definitions mirroring the tables described in `SCHEMA.MD`.

/// Re-exports of every entity type, for ergonomic `use crate::entities::prelude::*` imports.
pub mod prelude;

/// The `api_keys` table: authentication tokens, global rights, and CIDR bindings.
pub mod api_key;
/// The `api_key_hook_permissions` M:N junction table between API keys and hooks.
pub mod api_key_hook_permission;
/// The `audit_logs` table: the audit trail of mutating configuration operations.
pub mod audit_log;
/// The `executions` table: hook execution history, captured output, and metrics.
pub mod execution;
/// The `hooks` table: executable script definitions and execution constraints.
pub mod hook;
/// The `hook_parameters` table: the declared parameter contract of each hook.
pub mod hook_parameter;
