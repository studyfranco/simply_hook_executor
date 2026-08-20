//! Adds `hooks.args_template`: an optional argument-vector template, tokenized on whitespace at
//! execution time with each token's `$var`/`${var}` references substituted from resolved parameter
//! values (`executor::build_command_plan`) — never through a shell.
//!
//! Nullable, and stays nullable indefinitely — every hook created before this migration, and every
//! hook that never needs it, keeps the pre-existing behavior: resolved parameters appended
//! positionally, in declaration order, with no templating at all. Every `$var`/`${var}` this
//! references must name a currently-declared parameter — enforced only when the column is actually
//! set (`api::hooks::validate_args_template_matches_parameters`); this migration adds the storage,
//! not the requirement.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum Hooks {
    Table,
    ArgsTemplate,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::ArgsTemplate).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .drop_column(Hooks::ArgsTemplate)
                    .to_owned(),
            )
            .await
    }
}
