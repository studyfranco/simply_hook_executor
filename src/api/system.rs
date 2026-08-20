//! Operational introspection: the effective runtime configuration and instance counters.
//!
//! # What is *not* here
//!
//! The audit trail was the other half of this module until it moved to [`super::audit`]. The two
//! shared an audience — both are master-only — and nothing else: this one reports a configuration
//! struct fixed at startup plus three `COUNT(*)`s, while the audit log is a growing table with
//! query surface still to come. Grouping by audience would eventually pull most of the
//! administrative API into one file.
//!
//! Health and readiness probes are not here either, despite sounding like the same subject. They
//! are unauthenticated and mounted outside the `/api` tree, so they live in [`super::health`] where
//! that difference is visible from the filename rather than buried in a router line.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use sea_orm::{EntityTrait, PaginatorTrait};
use serde::Serialize;

use crate::entities::{api_key, prelude::*};
use crate::error::AppError;
use crate::state::AppState;

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
    /// Whether a hook may be set to `auth_mode = NONE` (public, zero-authentication execution) and
    /// actually be reachable that way. `hook::AuthMode::NoAuth`'s own doc comment is the source of
    /// truth this mirrors: a keyless, unsigned request against a `NONE` hook is accepted only when
    /// `require_signed_requests` is `false`, so this is exactly that flag's negation, surfaced under
    /// the name the question is actually asked in — "can this deployment run public hooks at all" —
    /// rather than making every caller re-derive it from a signing-requirement flag.
    pub keyless_hooks_allowed: bool,
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
        keyless_hooks_allowed: !state.config.require_signed_requests,
        signing_secrets_encrypted: state.cipher.is_encrypting(),
        hook_count: Hook::find().count(&state.db).await?,
        api_key_count: ApiKey::find().count(&state.db).await?,
        execution_count: Execution::find().count(&state.db).await?,
    }))
}
