//! The `api_keys` table: authentication tokens, global access rights, concurrency budget, and
//! CIDR network bindings.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single API key: its identity, global RBAC scopes, execution budget, and network binding rule.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Unique identifier for the API key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable key description (e.g. `"Vault Webhook Client"`).
    pub name: String,
    /// SHA-256 hash of the secret API key (the plaintext key is never stored).
    #[sea_orm(unique)]
    pub key_hash: String,
    /// First 8 characters of the plaintext key, kept for display and log correlation.
    pub prefix: String,
    /// Comma-separated CIDR ranges allowed to use this key (e.g. `127.0.0.1/32,::/0`). An empty
    /// value means no CIDR restriction is enforced.
    pub bound_ips: Option<String>,
    /// Maximum number of hook executions this key may have running simultaneously. Enforced by a
    /// `tokio::sync::Semaphore` in [`crate::executor`]; exceeding it yields `429 Too Many Requests`.
    pub max_concurrent_jobs: i32,
    /// Bypasses all RBAC checks (and CIDR binding checks) when `true`.
    pub is_master: bool,
    /// Global privilege to create/edit/delete other API keys.
    pub can_manage_keys: bool,
    /// Global privilege to create new hooks. Managing an *existing* hook additionally requires an
    /// explicit `can_manage` grant in `api_key_hook_permissions` (AGENT.MD least-privilege rule).
    pub can_manage_hooks: bool,
    /// Key generation timestamp.
    pub created_at: DateTime,
    /// Key last-update timestamp.
    pub updated_at: DateTime,
}

/// Relations from `api_keys` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// This key's per-hook permission grants.
    #[sea_orm(has_many = "super::api_key_hook_permission::Entity")]
    ApiKeyHookPermission,
    /// Executions requested by this key.
    #[sea_orm(has_many = "super::execution::Entity")]
    Execution,
    /// Audit log entries attributed to this key.
    #[sea_orm(has_many = "super::audit_log::Entity")]
    AuditLog,
}

impl Related<super::api_key_hook_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyHookPermission.def()
    }
}

impl Related<super::execution::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Execution.def()
    }
}

impl Related<super::audit_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuditLog.def()
    }
}

impl Related<super::hook::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_hook_permission::Relation::Hook.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_hook_permission::Relation::ApiKey.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
