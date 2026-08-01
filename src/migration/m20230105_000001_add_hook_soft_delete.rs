//! Adds the soft-delete columns to `hooks`: `is_deleted`, `deleted_at`, and `deleted_by`.
//!
//! Deleting a hook used to drop the row, which cascaded its parameters, its permission grants, and
//! its **entire execution history** — the audit record of everything that hook ever ran. A single
//! mistaken `DELETE` was therefore unrecoverable and silently destroyed forensic data. Soft delete
//! makes removal reversible and keeps the history intact until an operator (or the 92-day sweep)
//! decides otherwise.
//!
//! `is_deleted` is added `NOT NULL` **with a default**, which every supported backend applies to
//! existing rows as part of the `ALTER TABLE`. Existing hooks are therefore backfilled as live with
//! no separate `UPDATE` pass and no window in which the column is nullable.
//!
//! `deleted_by` is text rather than a foreign key to `api_keys.id` on purpose: the whole point of
//! the column is to survive. A real FK would either cascade the attribution away when the acting key
//! is deleted, or block that key from ever being deleted. Storing the id as text keeps a
//! point-in-time record of who did it, matching how `audit_logs` already denormalizes the acting
//! key's name and prefix.

use sea_orm_migration::prelude::*;

/// The subset of the `hooks` table this migration touches.
#[derive(DeriveIden)]
enum Hooks {
    /// The table itself.
    Table,
    /// Whether the hook is in the trash rather than live.
    IsDeleted,
    /// When it was moved there, and the clock the 92-day purge measures from.
    DeletedAt,
    /// The `api_keys.id` of whoever moved it, as text.
    DeletedBy,
}

/// The hook soft-delete migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Adds one column, as its own `ALTER TABLE`.
///
/// SQLite accepts exactly one alteration per statement — batching them panics in `sea-query`'s
/// SQLite backend rather than failing at the database — and the daemon defaults to SQLite. One
/// statement per column is also the only form portable across all three supported backends.
async fn add_column(
    manager: &SchemaManager<'_>,
    column: ColumnDef,
) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Hooks::Table)
                .add_column(column)
                .to_owned(),
        )
        .await
}

/// Drops one column, as its own `ALTER TABLE`, for the same reason.
async fn drop_column(manager: &SchemaManager<'_>, column: Hooks) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Hooks::Table)
                .drop_column(column)
                .to_owned(),
        )
        .await
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        add_column(
            manager,
            ColumnDef::new(Hooks::IsDeleted).boolean().not_null().default(false).to_owned(),
        )
        .await?;
        add_column(manager, ColumnDef::new(Hooks::DeletedAt).date_time().null().to_owned()).await?;
        add_column(manager, ColumnDef::new(Hooks::DeletedBy).text().null().to_owned()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_column(manager, Hooks::DeletedBy).await?;
        drop_column(manager, Hooks::DeletedAt).await?;
        drop_column(manager, Hooks::IsDeleted).await
    }
}
