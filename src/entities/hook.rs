//! The `hooks` table: executable script definitions and their execution constraints.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single hook: a named, permission-guarded pointer to a local executable.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "hooks")]
pub struct Model {
    /// Unique identifier for the hook.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Unique hook identifier name (e.g. `nftables_ban`). Usable in place of the UUID on the
    /// `/webhook/{identifier}` entry point.
    #[sea_orm(unique)]
    pub name: String,
    /// Optional summary of what the hook script does.
    pub description: Option<String>,
    /// Absolute filesystem path to the executable (e.g. `/usr/local/bin/ban.sh`). Never passed
    /// through a shell — see [`crate::executor`].
    pub script_path: String,
    /// Maximum allowed runtime, in seconds, before the process group is `SIGKILL`ed.
    pub default_timeout_seconds: i32,
    /// Hook creation timestamp.
    pub created_at: DateTime,
    /// Hook last-update timestamp.
    pub updated_at: DateTime,
}

/// Relations from `hooks` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The parameter contract this hook accepts.
    #[sea_orm(has_many = "super::hook_parameter::Entity")]
    HookParameter,
    /// Per-key permission grants covering this hook.
    #[sea_orm(has_many = "super::api_key_hook_permission::Entity")]
    ApiKeyHookPermission,
    /// Recorded executions of this hook.
    #[sea_orm(has_many = "super::execution::Entity")]
    Execution,
}

impl Related<super::hook_parameter::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::HookParameter.def()
    }
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

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_hook_permission::Relation::ApiKey.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_hook_permission::Relation::Hook.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
