//! The `hook_parameters` table: the declared parameter contract of a hook.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single parameter a hook accepts, with its default and requiredness rule.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "hook_parameters")]
pub struct Model {
    /// Unique identifier for the parameter rule.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The hook this parameter belongs to.
    pub hook_id: Uuid,
    /// Variable name (e.g. `target_address`). Injected into the child process as
    /// `HOOK_PARAM_<UPPERCASED_KEY>`, hence restricted to `[A-Za-z_][A-Za-z0-9_]*` at write time.
    pub param_key: String,
    /// Human-readable description of the parameter.
    pub description: Option<String>,
    /// Value applied when the caller omits this parameter. `None` combined with
    /// `is_required = true` makes omission a `400 Bad Request`.
    pub default_value: Option<String>,
    /// Whether omitting this parameter (with no `default_value`) rejects the request.
    pub is_required: bool,
    /// Parameter creation timestamp. Doubles as the ordering key for positional CLI arguments —
    /// see [`crate::executor::resolve_parameters`].
    pub created_at: DateTime,
}

/// Relations from `hook_parameters` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The hook that declares this parameter.
    #[sea_orm(
        belongs_to = "super::hook::Entity",
        from = "Column::HookId",
        to = "super::hook::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Hook,
}

impl Related<super::hook::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Hook.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
