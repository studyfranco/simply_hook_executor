//! Adds `hooks.run_as_user`, the optional target account for privileged execution.
//!
//! Written as a separate migration rather than folded into the initial schema so databases
//! already created by an earlier release are upgraded in place instead of silently diverging.

use sea_orm_migration::prelude::*;

/// The subset of the `hooks` table this migration touches.
#[derive(DeriveIden)]
enum Hooks {
    /// The table itself.
    Table,
    /// Target account for `sudo`-elevated execution; `NULL` means "run as the daemon user".
    RunAsUser,
}

/// The `run_as_user` migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    // Nullable with no default: an existing hook keeps running exactly as it did
                    // before this column existed, i.e. unprivileged.
                    .add_column(ColumnDef::new(Hooks::RunAsUser).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .drop_column(Hooks::RunAsUser)
                    .to_owned(),
            )
            .await
    }
}
