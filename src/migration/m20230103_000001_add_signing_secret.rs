//! Adds `api_keys.key_id` and `api_keys.signing_secret`, the HMAC webhook signing pair.
//!
//! Both are **nullable**, and deliberately so. A key issued before this migration has no signing
//! secret and never did; inventing one during the upgrade would mint a credential nobody has been
//! told about, and backfilling a placeholder would either break the uniqueness of `key_id` or
//! fabricate a secret that looks usable but is not. `NULL` states the truth — "this key predates
//! signature auth" — and rotating the key issues a real pair.
//!
//! Multiple `NULL`s coexist happily under the unique index: SQL treats them as distinct.

use sea_orm_migration::prelude::*;

/// The subset of the `api_keys` table this migration touches.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The table itself.
    Table,
    /// Public identifier used to select which signing secret verifies a signature.
    KeyId,
    /// HMAC signing secret, encrypted at rest.
    SigningSecret,
}

/// The signing-secret migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::KeyId).string().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::SigningSecret).text().null())
                    .to_owned(),
            )
            .await?;

        // A unique *index* rather than a column constraint: SQLite cannot add a `UNIQUE`
        // constraint to an existing column in place, and an index expresses the same guarantee
        // portably across every backend this project targets.
        manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-key_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::KeyId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(Index::drop().name("idx-api_keys-key_id").table(ApiKeys::Table).to_owned())
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::KeyId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::SigningSecret)
                    .to_owned(),
            )
            .await
    }
}
