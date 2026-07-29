//! The `executions` table: the complete history of every hook invocation, its captured output,
//! and its performance metrics.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Outcome of a hook execution, per `SCHEMA.MD`.
///
/// Stored as a plain string rather than a native database enum type so the schema stays portable
/// across SQLite/PostgreSQL/MySQL without vendor-specific DDL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
// JSON uses the same spelling as the stored value, so an API client never has to translate
// between `"Success"` on the wire and `SUCCESS` in the database or in a `?status=` filter.
#[serde(rename_all = "UPPERCASE")]
pub enum ExecutionStatus {
    /// Process completed with exit code `0`.
    #[sea_orm(string_value = "SUCCESS")]
    Success,
    /// Process completed with a non-zero exit code, or failed to launch at all.
    #[sea_orm(string_value = "FAILED")]
    Failed,
    /// Process exceeded its hook's maximum runtime and its process group was `SIGKILL`ed.
    #[sea_orm(string_value = "TIMEOUT")]
    Timeout,
}

/// A single recorded hook execution.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "executions")]
pub struct Model {
    /// Unique identifier for the execution job.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The hook that was executed.
    pub hook_id: Uuid,
    /// The key that requested the execution (`None` once that key is deleted — the FK is
    /// `ON DELETE SET NULL`, so history outlives the credential that created it).
    pub api_key_id: Option<Uuid>,
    /// Execution outcome.
    pub status: ExecutionStatus,
    /// Sub-process exit code, when the process actually reached completion.
    pub exit_code: Option<i32>,
    /// Captured standard output (truncated at `MAX_OUTPUT_BYTES`).
    #[sea_orm(column_type = "Text")]
    pub stdout: String,
    /// Captured standard error (truncated at `MAX_OUTPUT_BYTES`).
    #[sea_orm(column_type = "Text")]
    pub stderr: String,
    /// JSON object of the resolved parameters actually passed to the process.
    #[sea_orm(column_type = "Text")]
    pub parameters_json: String,
    /// Total wall-clock execution time in milliseconds.
    pub duration_ms: i32,
    /// Execution start timestamp (UTC).
    pub timestamp: DateTime,
}

/// Relations from `executions` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The executed hook.
    #[sea_orm(
        belongs_to = "super::hook::Entity",
        from = "Column::HookId",
        to = "super::hook::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Hook,
    /// The API key that requested the execution.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::hook::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Hook.def()
    }
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
