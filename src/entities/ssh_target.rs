//! The `ssh_targets` table: a remote host a [`super::hook::Model`] may dispatch execution to.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A named, reusable remote SSH endpoint: where to connect, which account to authenticate as, which
/// [`super::ssh_credential::Model`] to authenticate with, and — once pinned — the host key
/// fingerprint a connection attempt is verified against.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ssh_targets")]
pub struct Model {
    /// Unique identifier for the target.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Unique, human-readable label (e.g. `prod-web-01`).
    #[sea_orm(unique)]
    pub name: String,
    /// Hostname or IP address to connect to.
    pub host: String,
    /// TCP port to connect to. Defaults to `22`.
    pub port: i32,
    /// The remote account to authenticate as.
    pub username: String,
    /// The credential this target authenticates with. Deleting a credential while a target still
    /// references it is refused (`ON DELETE RESTRICT`).
    pub credential_id: Uuid,
    /// The host key's pinned fingerprint, formatted exactly as `ssh-keygen -lf` prints it
    /// (`SHA256:<base64, unpadded>`).
    ///
    /// `None` until an operator fetches and confirms one via
    /// `POST /api/ssh-targets/{id}/fetch-fingerprint`. A connection attempt against an unpinned
    /// target, or one whose offered host key does not match this value byte-for-byte, is refused —
    /// there is no trust-on-first-use fallback at execution time, since that would make the very
    /// first real hook run against a target the one connection nobody actually verified.
    pub host_key_fingerprint: Option<String>,
    /// Target creation timestamp.
    pub created_at: DateTime,
    /// Target last-update timestamp.
    pub updated_at: DateTime,
}

/// Relations from `ssh_targets` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The credential this target authenticates with.
    #[sea_orm(
        belongs_to = "super::ssh_credential::Entity",
        from = "Column::CredentialId",
        to = "super::ssh_credential::Column::Id",
        on_update = "Cascade",
        on_delete = "Restrict"
    )]
    SshCredential,
    /// Hooks configured to dispatch execution to this target. Deletion is refused
    /// (`ON DELETE RESTRICT`) while any such hook exists.
    #[sea_orm(has_many = "super::hook::Entity")]
    Hook,
}

impl Related<super::ssh_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SshCredential.def()
    }
}

impl Related<super::hook::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Hook.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
