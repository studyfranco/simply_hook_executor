//! Master-only introspection: the audit trail and the effective runtime configuration.
//!
//! Named `system` rather than `audit` because it is not only the audit log — `GET /api/settings`
//! reports the resolved configuration, which is a different subject with the same audience. A file
//! called `audit.rs` whose second half is settings sends the next reader to the wrong place.

use axum::{
    Extension,
    extract::{Json, Query, State},
    response::IntoResponse,
};
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::{
    api_key, audit_log, prelude::*,
};
use crate::error::AppError;
use crate::state::AppState;

use super::DEFAULT_PAGE_LIMIT;

// ─────────────────────────────────────────────────────────────
// Audit logs & system settings
// ─────────────────────────────────────────────────────────────

/// Query parameters for the audit log listing.
#[derive(Deserialize)]
pub struct AuditLogQuery {
    /// Filter by exact action type (e.g. `HOOK_EXECUTE`).
    pub action: Option<String>,
    /// Pagination limit.
    pub limit: Option<u64>,
    /// Pagination offset.
    pub offset: Option<u64>,
}

/// Handles `GET /api/audit-logs`.
///
/// Restricted to master keys: audit entries span every key and hook in the system, so a scoped key
/// reading them would be an RBAC leak regardless of its own grants.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Query(query): Query<AuditLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can view audit logs".to_owned(),
        ));
    }

    let mut q = AuditLog::find().order_by_desc(audit_log::Column::Timestamp);
    if let Some(action) = query.action.as_deref().filter(|a| !a.is_empty()) {
        q = q.filter(audit_log::Column::Action.eq(action));
    }

    let logs = q
        .limit(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;

    Ok(Json(logs))
}

/// The runtime configuration and instance counters shown on the System Settings tab.
#[derive(Serialize)]
pub struct SettingsResponse {
    /// Host environment variables passed through to hook sub-processes.
    pub allowed_env_vars: Vec<String>,
    /// Directories hook scripts are confined to. Empty means any absolute path is permitted.
    pub allowed_script_roots: Vec<String>,
    /// Peers whose forwarding headers are believed. Empty means the TCP peer address is always
    /// authoritative — surfaced because "is my proxy actually trusted?" is otherwise only
    /// answerable by reading the daemon's environment, and getting it wrong silently changes which
    /// address every `bound_ips` check is evaluated against.
    pub trusted_proxies: Vec<String>,
    /// Age, in days, beyond which execution history is purged (`0` = never).
    pub log_retention_days: i64,
    /// Days a soft-deleted hook stays recoverable before the sweep drops it for good (`0` = never).
    pub deleted_hook_retention_days: i64,
    /// Interval between retention sweeps, in seconds.
    pub retention_sweep_seconds: u64,
    /// Per-stream cap on captured output, in bytes.
    pub max_output_bytes: usize,
    /// Anti-replay window applied to `X-Timestamp` on signed requests, in seconds.
    pub signature_max_age_seconds: i64,
    /// Whether every authenticated request must carry a valid signature.
    pub require_signed_requests: bool,
    /// Whether signing secrets are encrypted at rest (i.e. `SIGNING_SECRET_KEY` is configured).
    pub signing_secrets_encrypted: bool,
    /// Total hooks defined.
    pub hook_count: u64,
    /// Total API keys.
    pub api_key_count: u64,
    /// Total execution records currently retained.
    pub execution_count: u64,
}

/// Handles `GET /api/settings`.
///
/// Master-only: `allowed_env_vars` describes what a hook's process inherits, which is exactly the
/// kind of detail an attacker probing for an escape would want.
pub async fn get_settings(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can view system settings".to_owned(),
        ));
    }

    Ok(Json(SettingsResponse {
        allowed_env_vars: state.config.allowed_env_vars.clone(),
        allowed_script_roots: state
            .config
            .allowed_script_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        trusted_proxies: state
            .config
            .trusted_proxies
            .spec()
            .iter()
            .map(ToString::to_string)
            .collect(),
        log_retention_days: state.config.log_retention_days,
        deleted_hook_retention_days: state.config.deleted_hook_retention_days,
        retention_sweep_seconds: state.config.retention_sweep_seconds,
        max_output_bytes: state.config.max_output_bytes,
        signature_max_age_seconds: state.config.signature_max_age_seconds,
        require_signed_requests: state.config.require_signed_requests,
        signing_secrets_encrypted: state.cipher.is_encrypting(),
        hook_count: Hook::find().count(&state.db).await?,
        api_key_count: ApiKey::find().count(&state.db).await?,
        execution_count: Execution::find().count(&state.db).await?,
    }))
}
