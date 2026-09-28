//! The `ssh_credentials` table: reusable SSH authentication material for [`super::ssh_target`]
//! rows.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// How an [`super::ssh_target::Model`] authenticates using this credential.
///
/// Stored as a plain string rather than a native database enum, matching
/// [`super::hook::AuthMode`], so the schema stays portable across SQLite/PostgreSQL/MySQL without
/// vendor-specific DDL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SshAuthType {
    /// Authenticate with a private key ([`Model::encrypted_private_key`]), optionally protected by
    /// [`Model::encrypted_passphrase`].
    #[sea_orm(string_value = "KEY")]
    Key,
    /// Authenticate with a plain login password ([`Model::encrypted_password`]).
    #[sea_orm(string_value = "PASSWORD")]
    Password,
}

/// A named, reusable set of SSH authentication material. Referenced by one or more
/// [`super::ssh_target::Model`] rows, so a single key pair or password need only be stored (and
/// encrypted) once even when it authenticates against many hosts.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ssh_credentials")]
pub struct Model {
    /// Unique identifier for the credential.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Unique, human-readable label (e.g. `deploy-key-prod`).
    #[sea_orm(unique)]
    pub name: String,
    /// Which secret field(s) below are populated and how a target using this credential
    /// authenticates. See [`SshAuthType`].
    pub auth_type: SshAuthType,
    /// The private key material (PEM or OpenSSH format), sealed at rest with
    /// [`crate::crypto::SecretCipher`]. Populated only when `auth_type = KEY`; decrypted strictly
    /// in-memory, immediately before an SSH connection attempt, and never serialized —
    /// `api::ssh::SshCredentialView` is the only shape this entity is ever exposed through on the
    /// wire, and it omits every field below.
    #[serde(skip_serializing)]
    pub encrypted_private_key: Option<String>,
    /// The private key's passphrase, sealed at rest with [`crate::crypto::SecretCipher`]. `None`
    /// both when `auth_type = PASSWORD` and when `auth_type = KEY` names an unencrypted key. Never
    /// serialized; see [`Self::encrypted_private_key`].
    #[serde(skip_serializing)]
    pub encrypted_passphrase: Option<String>,
    /// The login password, sealed at rest with [`crate::crypto::SecretCipher`]. Populated only when
    /// `auth_type = PASSWORD`. Never serialized; see [`Self::encrypted_private_key`].
    #[serde(skip_serializing)]
    pub encrypted_password: Option<String>,
    /// Credential creation timestamp.
    pub created_at: DateTime,
    /// Credential last-update timestamp.
    pub updated_at: DateTime,
}

/// Relations from `ssh_credentials` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Targets authenticating with this credential. Deletion is refused (`ON DELETE RESTRICT`)
    /// while any such target exists — see the migration's module docs for why.
    #[sea_orm(has_many = "super::ssh_target::Entity")]
    SshTarget,
}

impl Related<super::ssh_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SshTarget.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
