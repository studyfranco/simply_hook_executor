//! Unifies variable-length, path, header, and target metadata columns from `VARCHAR`
//! (`.string()`) to `TEXT` (`.text()`).
//!
//! `api_keys.{signing_secret, bound_ips, canonical_template}`, `hooks.{description, deleted_by,
//! hmac_secret, canonical_template, sample_payload_json, args_template, disabled_reason}`,
//! `hook_parameters.{description, default_value}`, `executions.{stdout, stderr, parameters_json}`,
//! `audit_logs.details`, and `ssh_credentials.encrypted_*` already use `.text()`. This migration
//! completes the unification for the remaining unindexed variable-length columns:
//! `hooks.{script_path, run_as_user, signature_header, signature_prefix}` and
//! `ssh_targets.{host, username, host_key_fingerprint}`.
//!
//! # SQLite safety
//!
//! SQLite does not support `ALTER TABLE ... MODIFY COLUMN`, and already stores every `VARCHAR`
//! column with `TEXT` affinity and no 255-character limit. This migration therefore short-circuits
//! cleanly on `DatabaseBackend::Sqlite` while widening columns on PostgreSQL and MySQL.

use super::runner::prelude::*;
use sea_orm::DatabaseBackend;

/// The `hooks` columns widened to `TEXT`.
#[derive(DeriveIden)]
enum Hooks {
    Table,
    ScriptPath,
    RunAsUser,
    SignatureHeader,
    SignaturePrefix,
}

/// The `ssh_targets` columns widened to `TEXT`.
#[derive(DeriveIden)]
enum SshTargets {
    Table,
    Host,
    Username,
    HostKeyFingerprint,
}

/// Variable-length column type unification migration.
pub struct Migration;

migration_name!(Migration);

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .modify_column(ColumnDef::new(Hooks::ScriptPath).text().not_null())
                    .modify_column(ColumnDef::new(Hooks::RunAsUser).text().null())
                    .modify_column(ColumnDef::new(Hooks::SignatureHeader).text().null())
                    .modify_column(ColumnDef::new(Hooks::SignaturePrefix).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SshTargets::Table)
                    .modify_column(ColumnDef::new(SshTargets::Host).text().not_null())
                    .modify_column(ColumnDef::new(SshTargets::Username).text().not_null())
                    .modify_column(ColumnDef::new(SshTargets::HostKeyFingerprint).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(SshTargets::Table)
                    .modify_column(
                        ColumnDef::new(SshTargets::HostKeyFingerprint)
                            .string()
                            .null(),
                    )
                    .modify_column(ColumnDef::new(SshTargets::Username).string().not_null())
                    .modify_column(ColumnDef::new(SshTargets::Host).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .modify_column(ColumnDef::new(Hooks::SignaturePrefix).string().null())
                    .modify_column(ColumnDef::new(Hooks::SignatureHeader).string().null())
                    .modify_column(ColumnDef::new(Hooks::RunAsUser).string().null())
                    .modify_column(ColumnDef::new(Hooks::ScriptPath).string().not_null())
                    .to_owned(),
            )
            .await
    }
}
