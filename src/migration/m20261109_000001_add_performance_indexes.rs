//! Adds composite performance indexes for execution listings and audit log searches.
//!
//! Hot paths in `simply_hook_executor`:
//! - Executions dashboard & API queries: `ORDER BY timestamp DESC` filtered by `hook_id`, `api_key_id`, or `status`.
//! - Audit log queries: `ORDER BY timestamp DESC` filtered by `action` or `api_key_id`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Executions {
    Table,
    HookId,
    ApiKeyId,
    Status,
    Timestamp,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    ApiKeyId,
    Action,
    Timestamp,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Composite index for executions by hook: WHERE hook_id = ? ORDER BY timestamp DESC
        manager
            .create_index(
                Index::create()
                    .name("idx_executions_hook_id_timestamp")
                    .table(Executions::Table)
                    .col(Executions::HookId)
                    .col((Executions::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Composite index for executions by API key: WHERE api_key_id = ? ORDER BY timestamp DESC
        manager
            .create_index(
                Index::create()
                    .name("idx_executions_api_key_id_timestamp")
                    .table(Executions::Table)
                    .col(Executions::ApiKeyId)
                    .col((Executions::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Composite index for executions by status: WHERE status = ? ORDER BY timestamp DESC
        manager
            .create_index(
                Index::create()
                    .name("idx_executions_status_timestamp")
                    .table(Executions::Table)
                    .col(Executions::Status)
                    .col((Executions::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Composite index for audit logs by action: WHERE action = ? ORDER BY timestamp DESC
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_action_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Composite index for audit logs by API key: WHERE api_key_id = ? ORDER BY timestamp DESC
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_api_key_id_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_api_key_id_timestamp")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_action_timestamp")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_executions_status_timestamp")
                    .table(Executions::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_executions_api_key_id_timestamp")
                    .table(Executions::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_executions_hook_id_timestamp")
                    .table(Executions::Table)
                    .to_owned(),
            )
            .await
    }
}
