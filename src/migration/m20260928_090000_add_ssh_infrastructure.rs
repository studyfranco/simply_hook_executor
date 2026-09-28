//! Adds remote SSH execution support: two new tables, `ssh_credentials` and `ssh_targets`, and two
//! new columns on `hooks` — `execution_type` and `ssh_target_id`.
//!
//! # Why two tables, not one
//!
//! A credential (a private key, a passphrase, a password) and a target (a host, a port, a login
//! user, a pinned host key) are reused independently in practice — the same key pair routinely
//! authenticates against several hosts, and a single host is routinely reachable under more than
//! one account. Folding them into one table would mean re-entering (and re-encrypting) the same
//! secret for every host it is valid against, and would make "this secret is used by these five
//! targets" unanswerable without a text search. `ssh_targets.credential_id` is the join.
//!
//! # Why `ssh_targets.credential_id` is a real `ON DELETE RESTRICT` foreign key, and
//! `hooks.ssh_target_id` is not
//!
//! Both columns reference another table's `id` logically, and the *policy* both want is identical:
//! deleting a credential/target that is still in use must fail loudly, naming what blocks it, rather
//! than cascading the deletion outward or silently orphaning the referencing row — exactly the
//! `CASCADE` (data loss one step removed from what was actually asked for) and `SET NULL` (a hook
//! whose `execution_type` is still `SSH` but whose `ssh_target_id` reads `NULL`, a configuration this
//! migration's `up()` never produces and no handler should be able to produce either) failure modes
//! `AGENT.MD` §4 ("data is never destroyed implicitly") already rules out elsewhere in this schema.
//!
//! Only one of the two can express that policy as an actual database constraint, though:
//! `ssh_targets` is a brand-new table in *this* migration, so its `credential_id` foreign key is
//! declared inline on `Table::create()`, which every backend accepts. `hooks` is not new — and
//! SQLite's `ALTER TABLE` cannot add a foreign key to an existing table at all (`sea-query`'s SQLite
//! backend rejects it outright, confirmed empirically: the naive `add_column` + `add_foreign_key` two
//! -step this migration attempted first panics with "Sqlite does not support modification of foreign
//! key constraints to existing tables"). `m20230107_090000_key_lineage_and_resource_ownership`
//! already hit this exact shape for `hooks.owner_key_id`/`api_keys.owner_key_id`/`parent_key_id` and
//! settled it the same way this migration now follows: no DDL `REFERENCES` clause on a reference
//! column added to a pre-existing table, application-level enforcement instead
//! (`api::ssh::delete_ssh_target` refuses — `409`, naming the referencing hooks — while any hook
//! still points at the target being deleted). `ssh_targets.credential_id`, needing no such
//! workaround, keeps the real constraint; there is no reason to weaken it to match the column that
//! had no choice.
//!
//! # `hooks.execution_type` / `ssh_target_id`, not a separate join table
//!
//! `RBAC_MODEL.md`'s Dispatch Configuration clause already covers this shape directly: "Where a
//! service directs outbound work at an external target, that configuration may live ... as fields
//! on a shared managed resource (`simply_hook_executor`: `script_path` and `run_as_user` on the
//! Hook row)." SSH execution is the same kind of decision — *where* the service dispatches — so
//! `execution_type`/`ssh_target_id` join `script_path`/`run_as_user` as two more columns on `hooks`
//! rather than becoming a new relation, and are gated identically
//! (`api::guards::guard_dispatch_configuration`) — see `AGENT_NOTES.MD` for the full reasoning
//! behind treating SSH credential/target *management* itself as master-only while leaving
//! *assignment* of an already-vetted target to an already-manageable hook at the ordinary R2
//! conjunction.
//!
//! # Encryption at rest reuses `SecretCipher`, not a second scheme
//!
//! `ssh_credentials.encrypted_private_key`/`encrypted_passphrase`/`encrypted_password` are sealed
//! with the same XChaCha20-Poly1305 `SecretCipher` (`src/crypto.rs`) that already protects
//! `api_keys.signing_secret` and `hooks.hmac_secret` — not a second, AES-256-GCM scheme. Both are
//! modern authenticated ciphers; XChaCha20-Poly1305 additionally uses a 192-bit nonce, which makes
//! random-nonce generation collision-safe without any counter state to persist (AES-GCM's 96-bit
//! nonce is the one place that cipher needs care around reuse). Introducing a second AEAD
//! implementation, a second key-management story, and a second "is this daemon's data encrypted at
//! rest" question for one feature would fragment a property this codebase already has right, for no
//! security benefit.

use sea_orm_migration::prelude::*;

/// Column identifiers for the new `ssh_credentials` table.
#[derive(DeriveIden)]
enum SshCredentials {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Human-readable, unique label (e.g. `"deploy-key-prod"`).
    Name,
    /// `KEY` or `PASSWORD` — see `entities::ssh_credential::SshAuthType`.
    AuthType,
    /// The private key material, sealed with `SecretCipher`. `NULL` unless `auth_type = KEY`.
    EncryptedPrivateKey,
    /// The private key's passphrase, sealed with `SecretCipher`. `NULL` for an unencrypted key, or
    /// when `auth_type = PASSWORD`.
    EncryptedPassphrase,
    /// The login password, sealed with `SecretCipher`. `NULL` unless `auth_type = PASSWORD`.
    EncryptedPassword,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// Column identifiers for the new `ssh_targets` table.
#[derive(DeriveIden)]
enum SshTargets {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Human-readable, unique label (e.g. `"prod-web-01"`).
    Name,
    /// Hostname or IP address to connect to.
    Host,
    /// TCP port. Defaults to the standard SSH port.
    Port,
    /// The remote account to authenticate as.
    Username,
    /// The credential this target authenticates with.
    CredentialId,
    /// The host key's pinned `SHA256:<base64>` fingerprint, in the same format `ssh-keygen -lf`
    /// prints. `NULL` until an operator fetches and confirms one — see
    /// `api::ssh::fetch_ssh_host_fingerprint`. A connection against an unpinned target, or one whose
    /// offered key does not match the pinned fingerprint, is refused; there is no "trust on first
    /// use at execution time" path, since that would make the very first real hook run the one
    /// unverified connection.
    HostKeyFingerprint,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// The subset of the `hooks` table this migration touches.
#[derive(DeriveIden)]
enum Hooks {
    /// The table itself.
    Table,
    /// `LOCAL` (default) or `SSH` — see `entities::hook::HookExecutionType`.
    ExecutionType,
    /// The `ssh_targets` row this hook dispatches to. Carries no DDL `REFERENCES` clause — see this
    /// module's own doc comment on why a column added to a pre-existing table cannot have one under
    /// SQLite — so both invariants are enforced at the application layer instead:
    /// "`NOT NULL` exactly when `execution_type = SSH`" by `api::hooks::validate_ssh_dispatch`, and
    /// "never dangling" by `api::ssh::delete_ssh_target` refusing to delete a still-referenced
    /// target.
    SshTargetId,
}

/// The SSH-infrastructure migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SshCredentials::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SshCredentials::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(SshCredentials::Name).string().not_null().unique_key())
                    .col(ColumnDef::new(SshCredentials::AuthType).string().not_null())
                    .col(ColumnDef::new(SshCredentials::EncryptedPrivateKey).text())
                    .col(ColumnDef::new(SshCredentials::EncryptedPassphrase).text())
                    .col(ColumnDef::new(SshCredentials::EncryptedPassword).text())
                    .col(ColumnDef::new(SshCredentials::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(SshCredentials::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SshTargets::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SshTargets::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(SshTargets::Name).string().not_null().unique_key())
                    .col(ColumnDef::new(SshTargets::Host).string().not_null())
                    .col(ColumnDef::new(SshTargets::Port).integer().not_null().default(22))
                    .col(ColumnDef::new(SshTargets::Username).string().not_null())
                    .col(ColumnDef::new(SshTargets::CredentialId).uuid().not_null())
                    .col(ColumnDef::new(SshTargets::HostKeyFingerprint).string())
                    .col(ColumnDef::new(SshTargets::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(SshTargets::UpdatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ssh_targets-credential_id")
                            .from(SshTargets::Table, SshTargets::CredentialId)
                            .to(SshCredentials::Table, SshCredentials::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-ssh_targets-credential_id")
                    .table(SshTargets::Table)
                    .col(SshTargets::CredentialId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(
                        ColumnDef::new(Hooks::ExecutionType).string().not_null().default("LOCAL"),
                    )
                    .to_owned(),
            )
            .await?;

        // No `.foreign_key(...)` here — see this module's own doc comment on why `hooks.ssh_target_id`
        // cannot carry a DDL `REFERENCES` clause under SQLite, unlike `ssh_targets.credential_id`
        // above (declared inline on that table's own `Table::create()`, which every backend accepts).
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::SshTargetId).uuid())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-hooks-ssh_target_id")
                    .table(Hooks::Table)
                    .col(Hooks::SshTargetId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter().table(Hooks::Table).drop_column(Hooks::SshTargetId).to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter().table(Hooks::Table).drop_column(Hooks::ExecutionType).to_owned(),
            )
            .await?;
        manager.drop_table(Table::drop().table(SshTargets::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SshCredentials::Table).to_owned()).await
    }
}
