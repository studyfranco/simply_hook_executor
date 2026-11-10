//! Adds performance and foreign key indexes across all tables to maximize query execution
//! speed and eliminate sequential scans on foreign keys, lookup columns, and filter fields.
//!
//! Hot paths and foreign key cascades optimized:
//! - Foreign key cascades & reverse joins: `api_key_hook_permissions(hook_id)` and `api_key_ssh_target_permissions(ssh_target_id)`
//! - Owner lookups and pre-flight deletion checks: `ssh_credentials(owner_key_id)` and `ssh_targets(owner_key_id)`
//! - Ordered listings & creation timestamps: `ssh_credentials(created_at)`, `ssh_targets(created_at)`, `api_keys(created_at)`, `hooks(created_at)`
//! - Key lookup by name: `api_keys(name)`
//! - Active hook listings & filtering: composite `hooks(is_deleted, name)` and `hooks(is_active)`
//! - Retention purge sweeps: `hooks(deleted_at)`
//! - Audit log target filtering: `audit_logs(target_resource)`

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Name,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Hooks {
    Table,
    IsDeleted,
    Name,
    DeletedAt,
    IsActive,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ApiKeyHookPermissions {
    Table,
    HookId,
}

#[derive(DeriveIden)]
enum ApiKeySshTargetPermissions {
    Table,
    SshTargetId,
}

#[derive(DeriveIden)]
enum SshCredentials {
    Table,
    OwnerKeyId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SshTargets {
    Table,
    OwnerKeyId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    TargetResource,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // FK index on api_key_hook_permissions (hook_id) for cascade drops and hook-specific grants
        manager
            .create_index(
                Index::create()
                    .name("idx_api_key_hook_permissions_hook_id")
                    .table(ApiKeyHookPermissions::Table)
                    .col(ApiKeyHookPermissions::HookId)
                    .to_owned(),
            )
            .await?;

        // FK index on api_key_ssh_target_permissions (ssh_target_id) for cascade drops and target grants
        manager
            .create_index(
                Index::create()
                    .name("idx_api_key_ssh_target_permissions_ssh_target_id")
                    .table(ApiKeySshTargetPermissions::Table)
                    .col(ApiKeySshTargetPermissions::SshTargetId)
                    .to_owned(),
            )
            .await?;

        // Owner index on ssh_credentials (owner_key_id) for ownership queries and pre-flight deletion checks
        manager
            .create_index(
                Index::create()
                    .name("idx_ssh_credentials_owner_key_id")
                    .table(SshCredentials::Table)
                    .col(SshCredentials::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        // Timestamp index on ssh_credentials (created_at) for ordered listings
        manager
            .create_index(
                Index::create()
                    .name("idx_ssh_credentials_created_at")
                    .table(SshCredentials::Table)
                    .col(SshCredentials::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // Owner index on ssh_targets (owner_key_id) for ownership queries and pre-flight deletion checks
        manager
            .create_index(
                Index::create()
                    .name("idx_ssh_targets_owner_key_id")
                    .table(SshTargets::Table)
                    .col(SshTargets::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        // Timestamp index on ssh_targets (created_at) for ordered listings
        manager
            .create_index(
                Index::create()
                    .name("idx_ssh_targets_created_at")
                    .table(SshTargets::Table)
                    .col(SshTargets::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // Name index on api_keys (name) for key search/filter resolution
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_name")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Name)
                    .to_owned(),
            )
            .await?;

        // Timestamp index on api_keys (created_at) for ordered key listings
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_created_at")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // Composite index on hooks (is_deleted, name) for primary hook listing queries
        manager
            .create_index(
                Index::create()
                    .name("idx_hooks_is_deleted_name")
                    .table(Hooks::Table)
                    .col(Hooks::IsDeleted)
                    .col(Hooks::Name)
                    .to_owned(),
            )
            .await?;

        // Timestamp index on hooks (deleted_at) for trash retention cleanup sweeps
        manager
            .create_index(
                Index::create()
                    .name("idx_hooks_deleted_at")
                    .table(Hooks::Table)
                    .col(Hooks::DeletedAt)
                    .to_owned(),
            )
            .await?;

        // Status index on hooks (is_active) for active/inactive hook filtering
        manager
            .create_index(
                Index::create()
                    .name("idx_hooks_is_active")
                    .table(Hooks::Table)
                    .col(Hooks::IsActive)
                    .to_owned(),
            )
            .await?;

        // Timestamp index on hooks (created_at) for hook chronological ordering
        manager
            .create_index(
                Index::create()
                    .name("idx_hooks_created_at")
                    .table(Hooks::Table)
                    .col(Hooks::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // Target resource index on audit_logs (target_resource) for audit filtering
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_target_resource")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::TargetResource)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_target_resource")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_hooks_created_at")
                    .table(Hooks::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_hooks_is_active")
                    .table(Hooks::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_hooks_deleted_at")
                    .table(Hooks::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_hooks_is_deleted_name")
                    .table(Hooks::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_keys_created_at")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_keys_name")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_ssh_targets_created_at")
                    .table(SshTargets::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_ssh_targets_owner_key_id")
                    .table(SshTargets::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_ssh_credentials_created_at")
                    .table(SshCredentials::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_ssh_credentials_owner_key_id")
                    .table(SshCredentials::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_key_ssh_target_permissions_ssh_target_id")
                    .table(ApiKeySshTargetPermissions::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_key_hook_permissions_hook_id")
                    .table(ApiKeyHookPermissions::Table)
                    .to_owned(),
            )
            .await
    }
}
