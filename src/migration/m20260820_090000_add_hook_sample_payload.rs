//! Adds `hooks.sample_payload_json`: an optional example of the JSON body a real caller sends this
//! hook, used to drive the WebUI's live command preview and the JSON Payload Extractor, and to
//! validate that a hook's declared parameters actually name fields the sample contains.
//!
//! Nullable, and stays nullable indefinitely — every hook created before this migration has no
//! sample to backfill from, and a hook whose caller always sends the same fixed shape may simply
//! never need one. Consistency between `sample_payload_json` and the parameter contract is enforced
//! only when both are present (`api::hooks::validate_sample_payload_matches_parameters`); this
//! migration adds the storage, not the requirement.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum Hooks {
    Table,
    SamplePayloadJson,
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
                    .add_column(ColumnDef::new(Hooks::SamplePayloadJson).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .drop_column(Hooks::SamplePayloadJson)
                    .to_owned(),
            )
            .await
    }
}
