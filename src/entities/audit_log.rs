//! The `audit_logs` table: the security audit trail tracking every mutating configuration change.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single audit trail entry for a mutating operation.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// Unique audit log entry ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The API key that performed the action (`None` once that key is deleted — the FK is
    /// `ON DELETE SET NULL`).
    pub api_key_id: Option<Uuid>,
    /// The acting key's name, denormalized at write time so the audit trail stays legible even
    /// after that key is deleted. Unlike `api_key_id`, it is never nulled out by a cascade — it's
    /// a point-in-time snapshot, not a live join.
    pub api_key_name: String,
    /// The acting key's prefix, denormalized for the same reason as `api_key_name`.
    pub api_key_prefix: String,
    /// The caller's resolved client IP (rightmost `X-Forwarded-For` hop, `X-Real-IP`, or raw TCP
    /// peer address — see [`crate::middleware::auth_middleware`]).
    pub client_ip: String,
    /// Operation type, e.g. `HOOK_CREATE`, `HOOK_UPDATE`, `HOOK_DELETE`, `HOOK_PARAM_CREATE`,
    /// `KEY_CREATE`, `KEY_ROTATE`, `KEY_PERM_UPDATE` (non-exhaustive).
    pub action: String,
    /// The affected resource's name or identifier, when applicable.
    pub target_resource: Option<String>,
    /// Additional context, e.g. the fields that changed.
    pub details: Option<String>,
    /// Event timestamp (UTC).
    pub timestamp: DateTime,
}

/// Relations from `audit_logs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The API key that performed the audited action.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
