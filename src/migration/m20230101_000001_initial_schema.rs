//! The initial `simply_hook_executor` schema, exactly as specified in `SCHEMA.MD`.
//!
//! Written entirely through SeaORM's schema builder (no raw SQL) so it applies unchanged to
//! SQLite, PostgreSQL, and MySQL.

use sea_orm_migration::prelude::*;

/// Column identifiers for the `api_keys` table.
#[derive(DeriveIden)]
pub enum ApiKeys {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Human-readable label.
    Name,
    /// SHA-256 hash of the secret key.
    KeyHash,
    /// First 8 plaintext characters, for display.
    Prefix,
    /// Comma-separated CIDR allowlist.
    BoundIps,
    /// Concurrency budget for hook executions.
    MaxConcurrentJobs,
    /// RBAC bypass flag.
    IsMaster,
    /// Global key-management scope.
    CanManageKeys,
    /// Global hook-creation scope.
    CanManageHooks,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// Column identifiers for the `hooks` table.
#[derive(DeriveIden)]
pub enum Hooks {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Unique hook name.
    Name,
    /// Optional summary.
    Description,
    /// Absolute path to the executable.
    ScriptPath,
    /// Timeout before `SIGKILL`, in seconds.
    DefaultTimeoutSeconds,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// Column identifiers for the `hook_parameters` table.
#[derive(DeriveIden)]
pub enum HookParameters {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Owning hook.
    HookId,
    /// Parameter name.
    ParamKey,
    /// Optional description.
    Description,
    /// Value used when the caller omits the parameter.
    DefaultValue,
    /// Whether omission (absent a default) rejects the request.
    IsRequired,
    /// Creation timestamp; also the positional-argument ordering key.
    CreatedAt,
}

/// Column identifiers for the `api_key_hook_permissions` junction table.
#[derive(DeriveIden)]
pub enum ApiKeyHookPermissions {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Granted key.
    ApiKeyId,
    /// Covered hook.
    HookId,
    /// Execute permission.
    CanExecute,
    /// Manage permission.
    CanManage,
    /// Assignment timestamp.
    CreatedAt,
}

/// Column identifiers for the `executions` table.
#[derive(DeriveIden)]
pub enum Executions {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Executed hook.
    HookId,
    /// Requesting key.
    ApiKeyId,
    /// `SUCCESS` / `FAILED` / `TIMEOUT`.
    Status,
    /// Sub-process exit code.
    ExitCode,
    /// Captured standard output.
    Stdout,
    /// Captured standard error.
    Stderr,
    /// Resolved parameters, JSON-encoded.
    ParametersJson,
    /// Wall-clock duration in milliseconds.
    DurationMs,
    /// Execution start timestamp.
    Timestamp,
}

/// Column identifiers for the `audit_logs` table.
#[derive(DeriveIden)]
pub enum AuditLogs {
    /// The table itself.
    Table,
    /// Primary key.
    Id,
    /// Acting key.
    ApiKeyId,
    /// Denormalized acting key name.
    ApiKeyName,
    /// Denormalized acting key prefix.
    ApiKeyPrefix,
    /// Caller address.
    ClientIp,
    /// Action name.
    Action,
    /// Affected resource.
    TargetResource,
    /// Additional context.
    Details,
    /// Event timestamp.
    Timestamp,
}

/// The initial schema migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ── api_keys ────────────────────────────────────────────────────────
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKeys::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(ApiKeys::Name).string().not_null())
                    .col(ColumnDef::new(ApiKeys::KeyHash).string().not_null().unique_key())
                    .col(ColumnDef::new(ApiKeys::Prefix).string().not_null())
                    .col(ColumnDef::new(ApiKeys::BoundIps).text().default("0.0.0.0/0,::/0"))
                    .col(ColumnDef::new(ApiKeys::MaxConcurrentJobs).integer().not_null().default(10))
                    .col(ColumnDef::new(ApiKeys::IsMaster).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CanManageKeys).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CanManageHooks).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(ApiKeys::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-prefix")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Prefix)
                    .to_owned(),
            )
            .await?;

        // ── hooks ───────────────────────────────────────────────────────────
        manager
            .create_table(
                Table::create()
                    .table(Hooks::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Hooks::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Hooks::Name).string().not_null().unique_key())
                    .col(ColumnDef::new(Hooks::Description).text())
                    .col(ColumnDef::new(Hooks::ScriptPath).string().not_null())
                    .col(ColumnDef::new(Hooks::DefaultTimeoutSeconds).integer().not_null().default(30))
                    .col(ColumnDef::new(Hooks::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Hooks::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        // ── hook_parameters ─────────────────────────────────────────────────
        manager
            .create_table(
                Table::create()
                    .table(HookParameters::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(HookParameters::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(HookParameters::HookId).uuid().not_null())
                    .col(ColumnDef::new(HookParameters::ParamKey).string().not_null())
                    .col(ColumnDef::new(HookParameters::Description).text())
                    .col(ColumnDef::new(HookParameters::DefaultValue).text())
                    .col(ColumnDef::new(HookParameters::IsRequired).boolean().not_null().default(true))
                    .col(ColumnDef::new(HookParameters::CreatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-hook_parameters-hook_id")
                            .from(HookParameters::Table, HookParameters::HookId)
                            .to(Hooks::Table, Hooks::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // One parameter contract entry per key name, per hook.
        manager
            .create_index(
                Index::create()
                    .name("idx-hook_parameters-hook_id-param_key")
                    .table(HookParameters::Table)
                    .col(HookParameters::HookId)
                    .col(HookParameters::ParamKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ── api_key_hook_permissions ────────────────────────────────────────
        manager
            .create_table(
                Table::create()
                    .table(ApiKeyHookPermissions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKeyHookPermissions::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(ApiKeyHookPermissions::ApiKeyId).uuid().not_null())
                    .col(ColumnDef::new(ApiKeyHookPermissions::HookId).uuid().not_null())
                    .col(ColumnDef::new(ApiKeyHookPermissions::CanExecute).boolean().not_null().default(true))
                    .col(ColumnDef::new(ApiKeyHookPermissions::CanManage).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeyHookPermissions::CreatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-akhp-api_key_id")
                            .from(ApiKeyHookPermissions::Table, ApiKeyHookPermissions::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-akhp-hook_id")
                            .from(ApiKeyHookPermissions::Table, ApiKeyHookPermissions::HookId)
                            .to(Hooks::Table, Hooks::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-akhp-api_key_id-hook_id")
                    .table(ApiKeyHookPermissions::Table)
                    .col(ApiKeyHookPermissions::ApiKeyId)
                    .col(ApiKeyHookPermissions::HookId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ── executions ──────────────────────────────────────────────────────
        manager
            .create_table(
                Table::create()
                    .table(Executions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Executions::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Executions::HookId).uuid().not_null())
                    .col(ColumnDef::new(Executions::ApiKeyId).uuid())
                    .col(ColumnDef::new(Executions::Status).string().not_null())
                    .col(ColumnDef::new(Executions::ExitCode).integer())
                    .col(ColumnDef::new(Executions::Stdout).text().not_null().default(""))
                    .col(ColumnDef::new(Executions::Stderr).text().not_null().default(""))
                    .col(ColumnDef::new(Executions::ParametersJson).text().not_null().default("{}"))
                    .col(ColumnDef::new(Executions::DurationMs).integer().not_null().default(0))
                    .col(ColumnDef::new(Executions::Timestamp).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-executions-hook_id")
                            .from(Executions::Table, Executions::HookId)
                            .to(Hooks::Table, Hooks::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-executions-api_key_id")
                            .from(Executions::Table, Executions::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        // The retention worker purges by timestamp and the dashboard lists newest-first, so both
        // hot paths are index-backed.
        manager
            .create_index(
                Index::create()
                    .name("idx-executions-timestamp")
                    .table(Executions::Table)
                    .col(Executions::Timestamp)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-executions-hook_id")
                    .table(Executions::Table)
                    .col(Executions::HookId)
                    .to_owned(),
            )
            .await?;

        // ── audit_logs ──────────────────────────────────────────────────────
        manager
            .create_table(
                Table::create()
                    .table(AuditLogs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuditLogs::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(AuditLogs::ApiKeyId).uuid())
                    .col(ColumnDef::new(AuditLogs::ApiKeyName).string().not_null())
                    .col(ColumnDef::new(AuditLogs::ApiKeyPrefix).string().not_null())
                    .col(ColumnDef::new(AuditLogs::ClientIp).string().not_null())
                    .col(ColumnDef::new(AuditLogs::Action).string().not_null())
                    .col(ColumnDef::new(AuditLogs::TargetResource).string())
                    .col(ColumnDef::new(AuditLogs::Details).text())
                    .col(ColumnDef::new(AuditLogs::Timestamp).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-audit_logs-api_key_id")
                            .from(AuditLogs::Table, AuditLogs::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-audit_logs-action")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-audit_logs-timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Timestamp)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(AuditLogs::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Executions::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(ApiKeyHookPermissions::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(HookParameters::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Hooks::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(ApiKeys::Table).to_owned()).await?;
        Ok(())
    }
}
