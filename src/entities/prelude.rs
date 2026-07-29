//! Convenience re-exports of every entity type in [`crate::entities`].

/// The `api_keys` entity.
pub use super::api_key::Entity as ApiKey;
/// The `api_key_hook_permissions` entity.
pub use super::api_key_hook_permission::Entity as ApiKeyHookPermission;
/// The `audit_logs` entity.
pub use super::audit_log::Entity as AuditLog;
/// The `executions` entity.
pub use super::execution::Entity as Execution;
/// The `hooks` entity.
pub use super::hook::Entity as Hook;
/// The `hook_parameters` entity.
pub use super::hook_parameter::Entity as HookParameter;
