//! Running hooks, and reading what happened.
//!
//! Triggering and history sit in one module because they share the record they produce and read:
//! [`ExecutionView`] is built by both, and the coupling audit found no other consumer of it. The
//! visibility rule enforced here is `RBAC_MODEL.md` §4's third scope — an execution record is
//! *creator-private*, and the four identities that may read one are spelled out in
//! [`super::guards::may_read_execution`].

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use sea_orm::{
    ColumnTrait, Condition, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, execution,
    execution::ExecutionStatus, prelude::*,
};
use crate::error::AppError;
use crate::extract::{StrictBytes, StrictPath, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::AppState;
use crate::executor;

use super::DEFAULT_PAGE_LIMIT;
use super::guards::{
    execution_visible_hook_ids, may_read_execution, guard_execute, guard_manage,
    guard_visibility,
};
use super::support::{create_audit_log, extract_parameter_map, format_reference, load_parameters, resolve_hook};

// ─────────────────────────────────────────────────────────────
// Execution
// ─────────────────────────────────────────────────────────────

/// A recorded execution, as returned to API clients.
#[derive(Serialize)]
pub struct ExecutionView {
    /// Execution ID.
    pub id: Uuid,
    /// Executed hook's ID.
    pub hook_id: Uuid,
    /// Executed hook's name, resolved for display.
    pub hook_name: String,
    /// Requesting key's ID, if it still exists.
    pub api_key_id: Option<Uuid>,
    /// Requesting key's name, resolved for display at read time (not denormalized onto the row).
    /// `None` for a keyless invocation, or one whose key has since been deleted — the two are
    /// distinguished from `api_key_id`, which is `None` in both cases too; a reader wanting to tell
    /// them apart already has to consult `stdout`/the audited hook, since neither table stores that
    /// distinction for executions the way `audit_logs` does with its keyless sentinel.
    pub api_key_name: Option<String>,
    /// Outcome: `SUCCESS`, `FAILED`, or `TIMEOUT`.
    pub status: ExecutionStatus,
    /// Sub-process exit code (`128 + signum` for a signalled process).
    pub exit_code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Resolved parameters actually passed to the process.
    pub parameters: serde_json::Value,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: i32,
    /// Execution start timestamp.
    pub timestamp: chrono::NaiveDateTime,
}

impl ExecutionView {
    /// Combines an execution row with its hook's name and (if any) its acting key's current name.
    fn new(model: execution::Model, hook_name: String, api_key_name: Option<String>) -> Self {
        // Stored as text; rendered back as real JSON so clients don't have to double-parse. A row
        // that somehow holds unparseable text degrades to a JSON string rather than failing the
        // whole response.
        let parameters = serde_json::from_str(&model.parameters_json)
            .unwrap_or(serde_json::Value::String(model.parameters_json.clone()));

        Self {
            id: model.id,
            hook_id: model.hook_id,
            hook_name,
            api_key_id: model.api_key_id,
            api_key_name,
            status: model.status,
            exit_code: model.exit_code,
            stdout: model.stdout,
            stderr: model.stderr,
            parameters,
            duration_ms: model.duration_ms,
            timestamp: model.timestamp,
        }
    }
}

/// Shared implementation behind `POST /api/hooks/{id}/execute` and `POST /webhook/{id}`.
///
/// `key` is `None` exactly when [`crate::middleware::invocation_auth_middleware`] authorized the
/// caller through the target hook's own `auth_mode` (`HMAC_ONLY` or `NONE`) rather than through a
/// bearer key — see that middleware's doc comment. In that case `guard_execute`'s per-key
/// `can_execute` check is skipped entirely: there is no key to hold a permission row, and the
/// hook's `auth_mode` is itself the authorization for a keyless caller.
///
/// Deliberately writes no `audit_logs` entry. `audit_logs` is the administrative/mutation trail
/// (key and hook CRUD, permission grants) — an execution is neither, and already has its own
/// purpose-built, RBAC-scoped record in `executions` (see [`ExecutionView`] and
/// [`super::guards::may_read_execution`]). Writing both would duplicate every run in two tables
/// under two different visibility rules for no reader either table's own design doesn't already
/// serve, and audit.rs's own module doc predicted exactly this scope: "filter by acting key, by
/// target, by time range" is what `executions` already offers, not a second thing `audit_logs`
/// needs to grow to match.
pub(crate) async fn run_hook_request(
    state: AppState,
    key: Option<api_key::Model>,
    identifier: &str,
    body: &[u8],
) -> Result<axum::response::Response, AppError> {
    let hook_model = resolve_hook(&state.db, identifier).await?;
    if let Some(key) = &key {
        guard_execute(&state.db, key, hook_model.id).await?;
    }

    let supplied = extract_parameter_map(body)?;
    let declared = load_parameters(&state.db, hook_model.id).await?;
    let resolved = executor::resolve_parameters(&declared, &supplied)?;

    if !resolved.missing_required.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "Missing required parameter(s): {}",
            resolved.missing_required.join(", ")
        )));
    }

    let record = executor::execute_hook(&state, &hook_model, key.as_ref(), &resolved).await?;
    let api_key_name = key.as_ref().map(|k| k.name.clone());

    // `200 OK` reports that the *request* was carried out; whether the script itself succeeded is
    // the `status`/`exit_code` in the body. A non-zero script exit is a legitimate, fully-recorded
    // outcome, not an HTTP-level failure.
    Ok(Json(ExecutionView::new(record, hook_model.name, api_key_name)).into_response())
}

/// Handles `POST /api/hooks/{identifier}/execute` — runs a hook and returns its recorded outcome.
///
/// The body is taken as raw [`axum::body::Bytes`] rather than a typed `Json<T>` so the two
/// accepted payload shapes (see [`extract_parameter_map`]) both work, and so an empty body is a
/// valid "no parameters" request instead of a deserialization error.
///
/// `key` is `Option` rather than mandatory — see [`run_hook_request`] — because this is one of the
/// two `/api/hooks/{id}` routes (with `test`) that [`crate::middleware::invocation_auth_middleware`]
/// may authorize without one.
pub async fn execute_hook_endpoint(
    State(state): State<AppState>,
    key: Option<Extension<api_key::Model>>,
    StrictPath(identifier): StrictPath<String>,
    StrictBytes(body): StrictBytes,
) -> Result<impl IntoResponse, AppError> {
    run_hook_request(state, key.map(|Extension(k)| k), &identifier, &body).await
}

/// Handles `POST /webhook/{identifier}` — the webhook-facing alias of the execute endpoint, for
/// third-party senders that post their own flat JSON document to a fixed URL.
pub async fn webhook_execute(
    State(state): State<AppState>,
    key: Option<Extension<api_key::Model>>,
    StrictPath(identifier): StrictPath<String>,
    StrictBytes(body): StrictBytes,
) -> Result<impl IntoResponse, AppError> {
    run_hook_request(state, key.map(|Extension(k)| k), &identifier, &body).await
}

/// Dry-run preview returned by `POST /api/hooks/{id}/test`.
#[derive(Serialize)]
pub struct TestHookResponse {
    /// Hook ID.
    pub hook_id: Uuid,
    /// Hook name.
    pub hook_name: String,
    /// Whether an equivalent `/execute` call would actually run (i.e. nothing required is
    /// missing and the script is present and executable).
    pub would_execute: bool,
    /// Why `would_execute` is `false`, when it is.
    pub blocking_reason: Option<String>,
    /// Merged defaults and caller overrides.
    pub resolved_parameters: serde_json::Value,
    /// Required parameters that were neither supplied nor defaulted.
    pub missing_required: Vec<String>,
    /// The exact program, argument vector, and environment that would be used.
    pub command: executor::CommandPlan,
    /// The timeout that would be applied, in seconds.
    pub timeout_seconds: u64,
}

/// Handles `POST /api/hooks/{identifier}/test` — resolves parameters and renders the exact command
/// that *would* run, without spawning anything.
///
/// `key` is `Option`, like [`execute_hook_endpoint`]: [`crate::middleware::invocation_auth_middleware`]
/// may authorize a keyless caller through the target hook's `auth_mode`.
pub async fn test_hook(
    State(state): State<AppState>,
    key: Option<Extension<api_key::Model>>,
    StrictPath(identifier): StrictPath<String>,
    StrictBytes(body): StrictBytes,
) -> Result<impl IntoResponse, AppError> {
    let hook_model = resolve_hook(&state.db, &identifier).await?;
    // `can_execute`, not merely visibility: a dry run reveals the fully-resolved command line and
    // the child's environment, which is execution-shaped knowledge even though nothing is spawned.
    // Skipped for a keyless caller, exactly as in `run_hook_request`: there is no key to hold a
    // permission row, and the hook's own `auth_mode` is what authorized this request.
    if let Some(Extension(key)) = &key {
        guard_execute(&state.db, key, hook_model.id).await?;
    }

    let supplied = extract_parameter_map(&body)?;
    let declared = load_parameters(&state.db, hook_model.id).await?;
    let resolved = executor::resolve_parameters(&declared, &supplied)?;
    let plan = executor::build_command_plan(&hook_model, &resolved, &state.config);

    let blocking_reason = if !resolved.missing_required.is_empty() {
        Some(format!(
            "Missing required parameter(s): {}",
            resolved.missing_required.join(", ")
        ))
    } else {
        // A dry run reports the permission/path diagnostic as data instead of failing: seeing
        // exactly why a hook would be refused is the whole point of the preview.
        executor::ensure_runnable(&hook_model, &state.config)
            .err()
            .map(|diagnosis| diagnosis.detail)
    };

    let resolved_parameters = serde_json::from_str(&resolved.to_json_string())
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));

    Ok(Json(TestHookResponse {
        hook_id: hook_model.id,
        hook_name: hook_model.name.clone(),
        would_execute: blocking_reason.is_none(),
        blocking_reason,
        resolved_parameters,
        missing_required: resolved.missing_required,
        command: plan,
        timeout_seconds: state
            .config
            .timeout_for(hook_model.default_timeout_seconds)
            .as_secs(),
    }))
}

// ─────────────────────────────────────────────────────────────
// Execution history
// ─────────────────────────────────────────────────────────────

/// Query parameters for the execution history listing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionQuery {
    /// Restrict to a single hook, by UUID or name.
    pub hook: Option<String>,
    /// Restrict to a single status (`SUCCESS`, `FAILED`, `TIMEOUT`).
    pub status: Option<String>,
    /// Restrict to a single acting key, by UUID (exact) or name (substring, case-insensitive) —
    /// mirrors `hook`'s own "UUID or name" convention. A keyless execution never matches this
    /// filter, since it has no key to match against.
    pub api_key: Option<String>,
    /// Only executions at or after this instant. RFC 3339, matching `audit::AuditLogQuery::since`.
    pub since: Option<String>,
    /// Only executions strictly before this instant. RFC 3339, matching `audit::AuditLogQuery::until`.
    pub until: Option<String>,
    /// Pagination limit.
    pub limit: Option<u64>,
    /// Pagination offset.
    pub offset: Option<u64>,
}

/// Parses a status filter, rejecting anything outside the enum.
pub(crate) fn parse_status(raw: &str) -> Result<ExecutionStatus, AppError> {
    match raw.to_uppercase().as_str() {
        "SUCCESS" => Ok(ExecutionStatus::Success),
        "FAILED" => Ok(ExecutionStatus::Failed),
        "TIMEOUT" => Ok(ExecutionStatus::Timeout),
        other => Err(AppError::InvalidInput(format!(
            "Invalid status filter '{other}': expected SUCCESS, FAILED, or TIMEOUT"
        ))),
    }
}

/// Resolves an `api_key` filter value to the set of key ids it names: an exact UUID match, or a
/// case-insensitive substring match against `api_keys.name`. Shared with [`super::audit`]'s own
/// `api_key` filter, which resolves the same way for the same reason — a caller narrowing an audit
/// or execution list by key rarely has the exact id at hand.
pub(crate) async fn resolve_api_key_filter(
    db: &sea_orm::DatabaseConnection,
    raw: &str,
) -> Result<Vec<Uuid>, AppError> {
    if let Ok(id) = Uuid::parse_str(raw) {
        return Ok(vec![id]);
    }
    let matches = ApiKey::find().filter(api_key::Column::Name.contains(raw)).all(db).await?;
    Ok(matches.into_iter().map(|k| k.id).collect())
}

/// Handles `GET /api/executions` — newest-first history, scoped to the caller's hooks.
pub async fn list_executions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<ExecutionQuery>,
) -> Result<impl IntoResponse, AppError> {
    let mut q = Execution::find().order_by_desc(execution::Column::Timestamp);

    // §4's third scope, expressed as a filter. The disjunction is exactly [`may_read_execution`]:
    // rows this caller produced, plus every row on a hook it owns or has been granted history access
    // to. Anything else is not merely hidden from the body — it never enters the result set, so the
    // count and the paging are computed over what the caller may see rather than trimmed afterwards.
    //
    // Note the previous implementation also required the *hook* to still be visible, which meant a
    // caller losing its grant on a hook lost the record of its own past runs. That extra bound is
    // gone: §4 makes an execution visible to its creator, and a creator does not stop being one.
    if !key.is_master {
        let mut visibility = Condition::any().add(execution::Column::ApiKeyId.eq(key.id));
        let readable = execution_visible_hook_ids(&state.db, &key).await?;
        if !readable.is_empty() {
            visibility = visibility.add(execution::Column::HookId.is_in(readable));
        }
        q = q.filter(visibility);
    }

    if let Some(identifier) = query.hook.as_deref().filter(|s| !s.is_empty()) {
        let hook_model = resolve_hook(&state.db, identifier).await?;
        guard_visibility(&state.db, &key, &hook_model).await?;
        q = q.filter(execution::Column::HookId.eq(hook_model.id));
    }

    if let Some(status) = query.status.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(execution::Column::Status.eq(parse_status(status)?));
    }
    if let Some(api_key_filter) = query.api_key.as_deref().filter(|s| !s.is_empty()) {
        let ids = resolve_api_key_filter(&state.db, api_key_filter).await?;
        q = q.filter(execution::Column::ApiKeyId.is_in(ids));
    }
    if let Some(since) = query.since.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(execution::Column::Timestamp.gte(crate::api::support::parse_instant("since", since)?));
    }
    if let Some(until) = query.until.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(execution::Column::Timestamp.lt(crate::api::support::parse_instant("until", until)?));
    }

    let rows = q
        .find_also_related(Hook)
        .limit(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;

    // One batch lookup for every acting key named across this page, rather than one query per row —
    // the same shape `guards::execution_visible_hook_ids` already uses for its own IN-list.
    let key_ids: Vec<Uuid> = rows.iter().filter_map(|(model, _)| model.api_key_id).collect();
    let key_names: std::collections::HashMap<Uuid, String> = if key_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        ApiKey::find()
            .filter(api_key::Column::Id.is_in(key_ids))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|k| (k.id, k.name))
            .collect()
    };

    let views = rows
        .into_iter()
        .map(|(model, hook_model)| {
            let hook_name = hook_model.map(|h| h.name).unwrap_or_else(|| "(deleted)".to_owned());
            let api_key_name = model.api_key_id.and_then(|id| key_names.get(&id).cloned());
            ExecutionView::new(model, hook_name, api_key_name)
        })
        .collect::<Vec<_>>();

    Ok(Json(views))
}

/// Handles `GET /api/executions/{id}` — one execution with its full captured output.
pub async fn get_execution(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let model = Execution::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    // §4, third scope. `404` rather than `403` per oracle discipline: a record the caller may not
    // read must be byte-identical to one that was never written, or the endpoint reports how much
    // history exists to someone entitled to none of it.
    if !may_read_execution(&state.db, &key, &model).await? {
        return Err(AppError::NotFound);
    }

    let hook_name = Hook::find_by_id(model.hook_id)
        .one(&state.db)
        .await?
        .map(|h| h.name)
        .unwrap_or_else(|| "(deleted)".to_owned());
    let api_key_name = match model.api_key_id {
        Some(id) => ApiKey::find_by_id(id).one(&state.db).await?.map(|k| k.name),
        None => None,
    };

    Ok(Json(ExecutionView::new(model, hook_name, api_key_name)))
}

/// Handles `DELETE /api/executions/{id}` — removes a single history entry.
pub async fn delete_execution(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let model = Execution::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    // The parent hook is loaded rather than passed by id because authority over an execution record
    // is decided partly by who owns that hook. A row pointing at a hook that no longer exists is
    // unreachable through any supported path — hard deletion drops the history with the hook — so
    // treating it as absent is the honest answer rather than a case to invent a policy for.
    let hook_model =
        Hook::find_by_id(model.hook_id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    // Deleting history is a management action over the hook, not merely an execute-level one.
    // Note this is deliberately *stricter* than reading it: `can_view_execution` buys visibility of
    // the record, never the right to destroy it. An auditor is not a redactor.
    guard_manage(&state.db, &key, &hook_model).await?;

    Execution::delete_by_id(id).exec(&state.db).await?;

    // `target_resource` carries the affected entity's human-readable **name**, matching every other
    // audit row in the service — see [`create_audit_log`]. An execution record has no name of its
    // own, so the hook it belongs to is the anchor an operator recognises and can filter on; the
    // record's own id moves into `details`, where the full UUID is preserved rather than truncated.
    //
    // This previously wrote the bare execution UUID here, which was the one call site in the
    // codebase whose `target_resource` was an identifier rather than a name.
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "EXECUTION_DELETE",
        Some(hook_model.name.clone()),
        Some(format!(
            "Deleted execution record {id} of hook {}",
            format_reference(&hook_model.name, hook_model.id)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Query parameters for the manual history purge.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeQuery {
    /// Age threshold in days. Defaults to the configured `LOG_RETENTION_DAYS`.
    ///
    /// `0` is a deliberate no-op, matching `LOG_RETENTION_DAYS=0` ("keep history forever") rather
    /// than meaning "delete everything" — the two settings drive the same sweep, and having one
    /// spelling mean opposite things depending on where it was typed would be a trap.
    pub older_than_days: Option<i64>,
}

/// Handles `DELETE /api/executions` — runs the retention sweep on demand.
///
/// Master-only: this deletes history across every hook in the system, which no scoped key should
/// be able to do regardless of its per-hook grants.
pub async fn purge_executions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictQuery(query): StrictQuery<PurgeQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can purge execution history".to_owned(),
        ));
    }

    let days = query.older_than_days.unwrap_or(state.config.log_retention_days);
    if days < 0 {
        return Err(AppError::InvalidInput(
            "older_than_days must not be negative".to_owned(),
        ));
    }

    let purged = crate::retention::purge_expired_executions(&state.db, days).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "EXECUTION_PURGE",
        None,
        Some(format!("Purged {purged} execution(s) older than {days} day(s)")),
    )
    .await?;

    Ok(Json(serde_json::json!({ "purged": purged, "older_than_days": days })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_filters_case_insensitively() {
        assert_eq!(parse_status("success").expect("valid"), ExecutionStatus::Success);
        assert_eq!(parse_status("TIMEOUT").expect("valid"), ExecutionStatus::Timeout);
        assert!(parse_status("bogus").is_err());
    }
}
