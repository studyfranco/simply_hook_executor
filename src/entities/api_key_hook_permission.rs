//! The `api_key_hook_permissions` M:N junction table: which keys may execute or manage which
//! hooks.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single (API key, hook) permission grant.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_key_hook_permissions")]
pub struct Model {
    /// Unique identifier for the permission grant.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The API key this grant applies to.
    pub api_key_id: Uuid,
    /// The hook this grant applies to.
    pub hook_id: Uuid,
    /// Permission to invoke `POST /api/hooks/{id}/execute` (and the `/webhook/{identifier}` alias).
    pub can_execute: bool,
    /// Permission to edit or delete this hook and its parameter contract.
    pub can_manage: bool,
    /// Permission to read this hook's **execution records** — the runs, their output streams, and
    /// their exit codes.
    ///
    /// Separate from both other verbs on purpose. `RBAC_MODEL.md` names the Execution record as a
    /// creator-private entity, so history is not covered by the shared-resource visibility rule that
    /// governs the hook itself: a key sees its *own* runs and every run of a hook it owns without
    /// this flag, and needs it only to read runs that are neither. Folding that into `can_execute`
    /// would hand every caller entitled to run a hook the output of everyone else's runs; folding it
    /// into `can_manage` would put read-only audit access behind R2's conjunction, so an auditor
    /// could be granted logs only by first being made a Parent with editing rights.
    ///
    /// Defaults to `false`, including for rows that predate the column.
    pub can_view_execution: bool,
    /// Assignment timestamp.
    pub created_at: DateTime,
}

/// Relations from `api_key_hook_permissions` to the entities it joins.
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
    /// The hook this grant covers.
    #[sea_orm(
        belongs_to = "super::hook::Entity",
        from = "Column::HookId",
        to = "super::hook::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Hook,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl Related<super::hook::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Hook.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
