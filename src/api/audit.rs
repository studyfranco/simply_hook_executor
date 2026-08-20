//! The audit trail: master-only reads over `audit_logs`.
//!
//! # Why this is its own module
//!
//! It was the first half of `system.rs`, which held the audit log and the settings endpoint
//! together on the grounds that both are master-only introspection. That grouping was by
//! *audience*, and audience is the weakest thing to organize by — nearly every administrative
//! endpoint in the service shares it.
//!
//! The two halves differ in every way that matters for change. This one reads a growing table and
//! will keep acquiring query surface: filtering by acting key, by target, by time range, pagination
//! that outgrows limit/offset. `system.rs` reports a configuration struct that is fixed at startup
//! and counts three tables. They have no shared state, no shared types, and no reason to be edited
//! together — and `simply_ip_vault` reached the same split independently, which is corroboration
//! rather than fashion.
//!
//! **Writing** an audit entry is not here. That is [`crate::api::support::create_audit_log`], called
//! from every mutating handler in the service. The asymmetry is deliberate and worth stating plainly
//! because it is the single most likely thing for a reader to get wrong: this module is the *reader*
//! of a table that a dozen other call sites write to, and putting the writer here would drag an
//! import of it into every handler module for no gain.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;

use crate::entities::{api_key, audit_log, prelude::*};
use crate::error::AppError;
use crate::extract::{StrictQuery};
use crate::state::AppState;

use super::DEFAULT_PAGE_LIMIT;
use super::executions::resolve_api_key_filter;
use super::support::parse_instant;

/// Query parameters for the audit log listing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    /// Filter by exact action type (e.g. `HOOK_CREATE`).
    pub action: Option<String>,
    /// Filter by client IP, substring match — an operator narrowing down "everything from this
    /// address" rarely has the exact recorded string at hand (a IPv6 address's zero-compression
    /// form, in particular), so this behaves like the hook-name search filter elsewhere rather than
    /// an exact match.
    pub client_ip: Option<String>,
    /// Restrict to a single acting key, by UUID (exact) or name (substring, case-insensitive) — see
    /// [`resolve_api_key_filter`]. Matched against `audit_logs.api_key_id`, so a key deleted since
    /// the entry was written can only be found by UUID (its name is no longer in `api_keys` to
    /// search), never by the point-in-time `api_key_name` snapshot on the row itself — that
    /// snapshot is for display, not for this filter to also index.
    pub api_key: Option<String>,
    /// Only entries at or after this instant. RFC 3339 (`2026-08-19T00:00:00Z`), the shape
    /// `Date.prototype.toISOString()` produces — the one JavaScript's own `<input
    /// type="datetime-local">` needs a manual round trip through to get, so this exists to be filled
    /// by client code rather than typed by hand.
    pub since: Option<String>,
    /// Only entries strictly before this instant. Same shape as `since`.
    pub until: Option<String>,
    /// Pagination limit.
    pub limit: Option<u64>,
    /// Pagination offset.
    pub offset: Option<u64>,
}

/// Handles `GET /api/audit-logs`.
///
/// Restricted to master keys: audit entries span every key and hook in the system, so a scoped key
/// reading them would be an RBAC leak regardless of its own grants. Note that this is a flat
/// master-only check rather than a §4 visibility filter — there is deliberately no "show me the
/// entries about my own hooks" view, because the entries themselves name keys and targets the
/// caller may not be permitted to know exist.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<AuditLogQuery>,
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
    if let Some(client_ip) = query.client_ip.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(audit_log::Column::ClientIp.contains(client_ip));
    }
    if let Some(api_key_filter) = query.api_key.as_deref().filter(|s| !s.is_empty()) {
        let ids = resolve_api_key_filter(&state.db, api_key_filter).await?;
        q = q.filter(audit_log::Column::ApiKeyId.is_in(ids));
    }
    if let Some(since) = query.since.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(audit_log::Column::Timestamp.gte(parse_instant("since", since)?));
    }
    if let Some(until) = query.until.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(audit_log::Column::Timestamp.lt(parse_instant("until", until)?));
    }

    let logs = q
        .limit(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;

    Ok(Json(logs))
}
