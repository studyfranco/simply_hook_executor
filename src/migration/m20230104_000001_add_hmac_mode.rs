//! Adds `api_keys.hmac_mode`, selecting how each key's request signatures are verified.
//!
//! Added `NOT NULL` **with a default**, which every supported backend applies to existing rows as
//! part of the `ALTER TABLE`. That gives a correct backfill with no separate `UPDATE` pass and no
//! window in which the column is nullable — and the default is the strict mode, so an existing key
//! keeps full anti-replay protection rather than being silently relaxed by an upgrade.

use sea_orm_migration::prelude::*;

/// The subset of the `api_keys` table this migration touches.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The table itself.
    Table,
    /// Signature verification mode: `CANONICAL_V1` or `BODY_ONLY`.
    HmacMode,
}

/// The `hmac_mode` migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(
                        ColumnDef::new(ApiKeys::HmacMode)
                            .string()
                            .not_null()
                            .default("CANONICAL_V1"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::HmacMode)
                    .to_owned(),
            )
            .await
    }
}
