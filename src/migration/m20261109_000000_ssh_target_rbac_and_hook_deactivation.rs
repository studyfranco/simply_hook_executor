//! Adds RBAC permissions for SSH targets (`can_manage_ssh` on `api_keys`, ownership columns on
//! `ssh_credentials` and `ssh_targets`, and the `api_key_ssh_target_permissions` join table) as well
//! as hook deactivation columns (`is_active`, `disabled_reason` on `hooks`).

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
    CanManageSsh,
}

#[derive(DeriveIden)]
enum SshCredentials {
    Table,
    OwnerKeyId,
}

#[derive(DeriveIden)]
enum SshTargets {
    Table,
    Id,
    OwnerKeyId,
}

#[derive(DeriveIden)]
enum Hooks {
    Table,
    IsActive,
    DisabledReason,
}

#[derive(DeriveIden)]
enum ApiKeySshTargetPermissions {
    Table,
    ApiKeyId,
    SshTargetId,
    CanUseInHook,
    CreatedAt,
}

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
                        ColumnDef::new(ApiKeys::CanManageSsh)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SshCredentials::Table)
                    .add_column(ColumnDef::new(SshCredentials::OwnerKeyId).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SshTargets::Table)
                    .add_column(ColumnDef::new(SshTargets::OwnerKeyId).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(
                        ColumnDef::new(Hooks::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::DisabledReason).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ApiKeySshTargetPermissions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ApiKeySshTargetPermissions::ApiKeyId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeySshTargetPermissions::SshTargetId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeySshTargetPermissions::CanUseInHook)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ApiKeySshTargetPermissions::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk_api_key_ssh_target_permissions")
                            .col(ApiKeySshTargetPermissions::ApiKeyId)
                            .col(ApiKeySshTargetPermissions::SshTargetId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-api_key_ssh_target_permissions-api_key_id")
                            .from(
                                ApiKeySshTargetPermissions::Table,
                                ApiKeySshTargetPermissions::ApiKeyId,
                            )
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-api_key_ssh_target_permissions-ssh_target_id")
                            .from(
                                ApiKeySshTargetPermissions::Table,
                                ApiKeySshTargetPermissions::SshTargetId,
                            )
                            .to(SshTargets::Table, SshTargets::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ApiKeySshTargetPermissions::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .drop_column(Hooks::DisabledReason)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .drop_column(Hooks::IsActive)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SshTargets::Table)
                    .drop_column(SshTargets::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SshCredentials::Table)
                    .drop_column(SshCredentials::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::CanManageSsh)
                    .to_owned(),
            )
            .await
    }
}
