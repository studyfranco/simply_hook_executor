//! The `api_key_ssh_target_permissions` M:N junction table: which keys may use which SSH targets
//! in their hooks.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single (API key, SSH target) permission grant.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_key_ssh_target_permissions")]
pub struct Model {
    /// The API key this grant applies to.
    #[sea_orm(primary_key, auto_increment = false)]
    pub api_key_id: Uuid,
    /// The SSH target this grant covers.
    #[sea_orm(primary_key, auto_increment = false)]
    pub ssh_target_id: Uuid,
    /// Permission to use this target in a hook (`execution_type = SSH`).
    pub can_use_in_hook: bool,
    /// Assignment timestamp.
    pub created_at: DateTime,
}

/// Relations from `api_key_ssh_target_permissions` to the entities it joins.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The API key holding this grant.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    ApiKey,
    /// The SSH target this grant covers.
    #[sea_orm(
        belongs_to = "super::ssh_target::Entity",
        from = "Column::SshTargetId",
        to = "super::ssh_target::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    SshTarget,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl Related<super::ssh_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SshTarget.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
