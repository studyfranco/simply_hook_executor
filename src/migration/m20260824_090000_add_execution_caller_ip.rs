//! Adds `executions.caller_ip`: the resolved client IP of whoever triggered the execution — the
//! same trust-aware resolution already used for `audit_logs.client_ip`
//! (`config::resolve_client_ip`, consulting `X-Forwarded-For`/`X-Real-IP` only when the immediate
//! TCP peer is itself a configured trusted proxy, the raw peer address otherwise).
//!
//! `NOT NULL DEFAULT ''`, not nullable: every request path that can reach `executor::execute_hook`
//! runs behind `invocation_auth_middleware`, which unconditionally resolves and inserts a
//! `ClientIp` extension before any handler sees the request, so every execution recorded from this
//! migration onward always has one. The empty-string default exists only to satisfy the
//! `ALTER TABLE ... ADD COLUMN NOT NULL` requirement against rows that predate this migration and
//! were never able to record one at all.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum Executions {
    Table,
    CallerIp,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Executions::Table)
                    .add_column(ColumnDef::new(Executions::CallerIp).string().not_null().default(""))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Executions::Table)
                    .drop_column(Executions::CallerIp)
                    .to_owned(),
            )
            .await
    }
}
