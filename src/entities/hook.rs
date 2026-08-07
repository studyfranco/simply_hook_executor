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
    /// Target account for privileged execution.
    ///
    /// `None` (or empty) runs the script directly under the daemon's own user. A value runs it
    /// through `sudo -n -u <user> --`, so what is actually permitted remains governed by
    /// `sudoers` — this field can request elevation, never grant it.
    pub run_as_user: Option<String>,
    /// The key answerable for this hook: **the only non-master identity that may delete or rename
    /// it** (`RBAC_MODEL.md` §3).
    ///
    /// Deliberately not derivable from `api_key_hook_permissions`. A creator receives an ordinary
    /// `can_manage` row there, byte-identical to a delegated one, so "holds `can_manage`" says
    /// nothing about authorship and is usually true of several keys. §3 draws the line exactly
    /// here: holding manage rights, or any operational verb, confers no lifecycle authority — "a
    /// parent that merely uses a resource must not be able to delete it."
    ///
    /// `None` for hooks that predate ownership, which leaves lifecycle authority with master alone
    /// until an operator assigns it. Master may reassign it at any time.
    pub owner_key_id: Option<Uuid>,
    /// Whether the hook is in the trash rather than live.
    ///
    /// A soft-deleted hook is invisible to every ordinary route and cannot be executed, but its row,
    /// its parameter contract, its permission grants, and — the reason this exists — its full
    /// execution history all survive. Dropping the row cascades all of that away, so an accidental
    /// `DELETE` used to destroy the audit record of everything the hook had ever run.
    pub is_deleted: bool,
    /// When the hook was moved to the trash, and the clock the 92-day purge measures from.
    pub deleted_at: Option<DateTime>,
    /// The `api_keys.id` of whoever deleted it, as text.
    ///
    /// Deliberately not a foreign key: attribution must outlive the acting key, which an FK would
    /// either cascade away or block from ever being deleted.
    pub deleted_by: Option<String>,
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
