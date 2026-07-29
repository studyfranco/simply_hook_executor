//! API endpoints and business logic.
//!
//! Every handler in this module runs behind [`crate::middleware::auth_middleware`], so it can rely
//! on an authenticated [`api_key::Model`] and a resolved [`ClientIp`] being present in the request
//! extensions. Authorization, by contrast, is per-handler and explicit — see [`require_execute`]
//! and [`require_manage`].

use axum::{
    Extension,
    extract::{Json, Path, Query, State},
    response::IntoResponse,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use rand::RngExt;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, SqlErr, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_hook_permission, audit_log, execution, execution::ExecutionStatus, hook,
    hook_parameter, prelude::*,
};
use crate::crypto::SecretCipher;
use crate::error::AppError;
use crate::executor;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// Upper bound accepted for `hooks.default_timeout_seconds` (24 hours). A timeout beyond this is
/// almost certainly a units mistake, and accepting it would mean a wedged hook could hold one of
/// the caller's concurrency slots effectively forever.
const MAX_TIMEOUT_SECONDS: i32 = 86_400;

/// Upper bound accepted for `api_keys.max_concurrent_jobs`.
const MAX_CONCURRENT_JOBS: i32 = 1_000;

/// Default page size for the paginated listing endpoints.
const DEFAULT_PAGE_LIMIT: u64 = 50;

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Generates a random 32-byte hex key for API authentication.
pub fn generate_random_key() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Hashes an API key using SHA-256 for secure storage.
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generates a public key identifier (`shk_<32 hex>`).
///
/// Non-secret by design: it travels in the clear as `X-Key-Id` and appears in logs, so it only
/// needs to be unique and unguessable enough not to invite enumeration — never to authenticate.
pub fn generate_key_id() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    format!("shk_{}", hex::encode(bytes))
}

/// Generates a 32-byte HMAC signing secret.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Mints and seals a fresh `(key_id, signing_secret)` pair, returning the plaintext secret.
///
/// The plaintext is handed back exactly once so the caller can put it in the HTTP response; only
/// the sealed form is ever persisted.
fn mint_signing_pair(cipher: &SecretCipher) -> Result<(String, String, String), AppError> {
    let key_id = generate_key_id();
    let signing_secret = generate_signing_secret();
    let sealed = cipher.seal(&signing_secret).map_err(|e| {
        tracing::error!("Failed to seal a signing secret: {e}");
        AppError::Internal
    })?;
    Ok((key_id, signing_secret, sealed))
}

/// Formats a target resource for a human-readable audit log `details` string, e.g.
/// `"'nftables_ban' (65cf11ce...)"` — pairs the name an operator actually recognizes with a
/// truncated id for unambiguous cross-referencing, instead of a bare UUID.
fn format_reference(name: &str, id: Uuid) -> String {
    let id_str = id.to_string();
    format!("'{name}' ({}...)", &id_str[..8])
}

/// Writes an audit log entry.
///
/// The acting key's name and prefix are denormalized into the row so the trail stays legible after
/// that key is deleted: its `api_key_id` FK is `ON DELETE SET NULL`, but these columns are a
/// point-in-time snapshot rather than a live join.
async fn create_audit_log(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    client_ip: std::net::IpAddr,
    action: &str,
    target_resource: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(Some(key.id)),
        api_key_name: Set(key.name.clone()),
        api_key_prefix: Set(key.prefix.clone()),
        client_ip: Set(client_ip.to_string()),
        action: Set(action.to_owned()),
        target_resource: Set(target_resource),
        details: Set(details),
        timestamp: Set(Utc::now().naive_utc()),
    };
    AuditLog::insert(log).exec(db).await?;
    Ok(())
}

/// Resolves a hook from a path segment that may be either its UUID or its unique name.
///
/// Every hook route takes a `String` rather than a strictly-typed `Uuid` for exactly this reason:
/// a caller wiring up `/webhook/nftables_ban` gets a working request instead of Axum rejecting it
/// with a `422` before any handler runs.
async fn resolve_hook(
    db: &sea_orm::DatabaseConnection,
    identifier: &str,
) -> Result<hook::Model, AppError> {
    if let Ok(id) = Uuid::parse_str(identifier)
        && let Some(found) = Hook::find_by_id(id).one(db).await?
    {
        return Ok(found);
    }
    Hook::find()
        .filter(hook::Column::Name.eq(identifier))
        .one(db)
        .await?
        .ok_or(AppError::NotFound)
}

/// Fetches the caller's explicit permission grant for a hook, if any.
async fn hook_permission(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
    hook_id: Uuid,
) -> Result<Option<api_key_hook_permission::Model>, AppError> {
    Ok(ApiKeyHookPermission::find()
        .filter(
            Condition::all()
                .add(api_key_hook_permission::Column::ApiKeyId.eq(key_id))
                .add(api_key_hook_permission::Column::HookId.eq(hook_id)),
        )
        .one(db)
        .await?)
}

/// Authorizes execution of a hook: master keys bypass, everyone else needs an explicit
/// `can_execute` grant (`AGENT.MD` least-privilege rule).
async fn require_execute(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook_id: Uuid,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }
    match hook_permission(db, key.id, hook_id).await? {
        Some(p) if p.can_execute => Ok(()),
        _ => Err(AppError::Forbidden(
            "Permission denied: You do not have execute access to this hook".to_owned(),
        )),
    }
}

/// Authorizes management of an *existing* hook.
///
/// Note the deliberate asymmetry with the global `can_manage_hooks` scope, which authorizes
/// *creating* hooks: per `AGENT.MD`, `can_manage` over an already-existing hook requires a valid
/// key mapping unless the key is master. Since creating a hook auto-provisions full rights on it,
/// a `can_manage_hooks` key always retains control of everything it created — just not of hooks
/// belonging to someone else.
async fn require_manage(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook_id: Uuid,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }
    match hook_permission(db, key.id, hook_id).await? {
        Some(p) if p.can_manage => Ok(()),
        _ => Err(AppError::Forbidden(
            "Permission denied: You do not have manage access to this hook".to_owned(),
        )),
    }
}

/// Authorizes read-only visibility of a hook (either grant suffices).
async fn require_visibility(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook_id: Uuid,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }
    match hook_permission(db, key.id, hook_id).await? {
        Some(p) if p.can_execute || p.can_manage => Ok(()),
        _ => Err(AppError::Forbidden(
            "Permission denied: You have no access mapped to this hook".to_owned(),
        )),
    }
}

/// The set of hook ids the caller may see, or `None` for a master key (meaning "no restriction").
async fn visible_hook_ids(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
) -> Result<Option<Vec<Uuid>>, AppError> {
    if key.is_master {
        return Ok(None);
    }
    let ids = ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key.id))
        .filter(
            Condition::any()
                .add(api_key_hook_permission::Column::CanExecute.eq(true))
                .add(api_key_hook_permission::Column::CanManage.eq(true)),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.hook_id)
        .collect();
    Ok(Some(ids))
}

/// Loads a hook's declared parameters in the canonical order used for positional CLI arguments:
/// declaration order, with the key name as a stable tie-break for rows created in the same
/// timestamp tick.
async fn load_parameters(
    db: &sea_orm::DatabaseConnection,
    hook_id: Uuid,
) -> Result<Vec<hook_parameter::Model>, AppError> {
    Ok(HookParameter::find()
        .filter(hook_parameter::Column::HookId.eq(hook_id))
        .order_by_asc(hook_parameter::Column::CreatedAt)
        .order_by_asc(hook_parameter::Column::ParamKey)
        .all(db)
        .await?)
}

/// Normalizes and validates a submitted `run_as_user`, enforcing the master-only guard.
///
/// Returns `Ok(None)` for an absent or blank value — "no elevation", which any hook manager may
/// set. Requesting an actual account is a privilege-escalation request and is restricted to master
/// keys: `can_manage_hooks` is the right to define automation, not the right to decide which OS
/// account that automation runs as. Note this is a *second* gate in front of `sudoers`, which
/// remains the ultimate authority — it stops a compromised management key from even asking.
///
/// The authorization check runs before syntax validation so a non-master probing the field gets a
/// consistent `403` regardless of whether their candidate value happened to be well-formed.
fn normalize_run_as_user(
    key: &api_key::Model,
    run_as_user: Option<&str>,
) -> Result<Option<String>, AppError> {
    match executor::effective_run_as_user(run_as_user) {
        Some(user) => {
            if !key.is_master {
                tracing::warn!(
                    key = %key.prefix,
                    requested_user = %user,
                    "Non-master key attempted to assign run_as_user"
                );
                return Err(AppError::Forbidden(
                    "Only master API keys can assign run_as_user privileges".to_owned(),
                ));
            }
            executor::validate_run_as_user(user)?;
            Ok(Some(user.to_owned()))
        }
        None => Ok(None),
    }
}

/// Renders a hook's elevation setting for an audit log entry.
///
/// Privileged hooks are the highest-value thing in this system to be able to reconstruct after the
/// fact, so the account is written into the audit trail at creation and on every change.
fn describe_privilege(run_as_user: Option<&str>) -> String {
    match run_as_user {
        Some(user) => format!("runs as '{user}' via sudo"),
        None => "runs as the daemon user".to_owned(),
    }
}

/// Validates a proposed hook timeout.
fn validate_timeout(seconds: i32) -> Result<(), AppError> {
    if seconds <= 0 {
        return Err(AppError::InvalidInput(
            "default_timeout_seconds must be greater than 0".to_owned(),
        ));
    }
    if seconds > MAX_TIMEOUT_SECONDS {
        return Err(AppError::InvalidInput(format!(
            "default_timeout_seconds must not exceed {MAX_TIMEOUT_SECONDS}"
        )));
    }
    Ok(())
}

/// Validates every entry of a comma-separated CIDR list.
fn validate_bound_ips(bound_ips: &str) -> Result<(), AppError> {
    for cidr in bound_ips.split(',') {
        let trimmed = cidr.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _: IpNetwork = trimmed
            .parse()
            .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {trimmed}")))?;
    }
    Ok(())
}

/// Extracts the caller-supplied parameter map from an execute request body.
///
/// Two shapes are accepted, because the callers differ: first-party clients post
/// `{"parameters": {...}}`, while a third-party webhook sender often can only post its own flat
/// JSON document. A top-level `parameters` object wins when present; otherwise the whole body is
/// treated as the parameter map. An empty body means "no parameters".
fn extract_parameter_map(
    body: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, AppError> {
    if body.is_empty() {
        return Ok(serde_json::Map::new());
    }

    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?;

    let object = match value {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => return Ok(serde_json::Map::new()),
        _ => {
            return Err(AppError::InvalidInput(
                "Request body must be a JSON object".to_owned(),
            ));
        }
    };

    match object.get("parameters") {
        Some(serde_json::Value::Object(inner)) => Ok(inner.clone()),
        Some(serde_json::Value::Null) | None => Ok(object),
        Some(_) => Err(AppError::InvalidInput(
            "'parameters' must be a JSON object".to_owned(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────────

/// A single hook permission grant, as reported to the caller.
#[derive(Serialize)]
pub struct HookPermissionView {
    /// Hook ID.
    pub hook_id: Uuid,
    /// Hook name.
    pub hook_name: String,
    /// Whether the key may execute the hook.
    pub can_execute: bool,
    /// Whether the key may edit or delete the hook.
    pub can_manage: bool,
}

/// Identity and permission payload returned to the client.
#[derive(Serialize)]
pub struct MeResponse {
    /// API Key ID.
    pub id: Uuid,
    /// Key name.
    pub name: String,
    /// First 8 characters of the key, for display.
    pub prefix: String,
    /// Public key identifier used for signature auth, if this key has one.
    pub key_id: Option<String>,
    /// Bound CIDRs.
    pub bound_ips: Option<String>,
    /// Simultaneous execution budget.
    pub max_concurrent_jobs: i32,
    /// Master status.
    pub is_master: bool,
    /// Global key management scope.
    pub can_manage_keys: bool,
    /// Global hook creation scope.
    pub can_manage_hooks: bool,
    /// Granular per-hook permissions.
    pub hook_permissions: Vec<HookPermissionView>,
}

/// Builds the per-hook permission views for one key.
async fn load_hook_permissions(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
) -> Result<Vec<HookPermissionView>, AppError> {
    let rows = ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key_id))
        .find_also_related(Hook)
        .all(db)
        .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(perm, hook)| {
            hook.map(|h| HookPermissionView {
                hook_id: perm.hook_id,
                hook_name: h.name,
                can_execute: perm.can_execute,
                can_manage: perm.can_manage,
            })
        })
        .collect())
}

/// Handles `GET /api/auth/me` — the identity and scope payload the SPA renders its tabs from.
pub async fn get_me(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let hook_permissions = load_hook_permissions(&state.db, key.id).await?;

    Ok(Json(MeResponse {
        id: key.id,
        name: key.name,
        prefix: key.prefix,
        key_id: key.key_id,
        bound_ips: key.bound_ips,
        max_concurrent_jobs: key.max_concurrent_jobs,
        is_master: key.is_master,
        can_manage_keys: key.can_manage_keys,
        can_manage_hooks: key.can_manage_hooks,
        hook_permissions,
    }))
}

// ─────────────────────────────────────────────────────────────
// Hooks
// ─────────────────────────────────────────────────────────────

/// A hook parameter declaration, as accepted on hook creation.
#[derive(Deserialize)]
pub struct ParameterInput {
    /// Variable name; must match `[A-Za-z_][A-Za-z0-9_]*`.
    pub param_key: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Value applied when the caller omits this parameter.
    pub default_value: Option<String>,
    /// Whether omission (absent a default) rejects the execution request. Defaults to `true`.
    pub is_required: Option<bool>,
}

/// Payload for creating a hook.
#[derive(Deserialize)]
pub struct CreateHookPayload {
    /// Unique hook name.
    pub name: String,
    /// Optional summary.
    pub description: Option<String>,
    /// Absolute path to the executable.
    pub script_path: String,
    /// Maximum runtime in seconds. Defaults to 30.
    pub default_timeout_seconds: Option<i32>,
    /// Account to run the script as, via `sudo`. Omit (or send `null`/`""`) to run it directly as
    /// the daemon user.
    pub run_as_user: Option<String>,
    /// Optional parameter contract, declared inline so a hook and its parameters can be created
    /// in one request instead of N+1.
    pub parameters: Option<Vec<ParameterInput>>,
}

/// Payload for updating a hook. Every field is optional; omitted fields are left untouched.
#[derive(Deserialize)]
pub struct UpdateHookPayload {
    /// New name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// New script path.
    pub script_path: Option<String>,
    /// New timeout, in seconds.
    pub default_timeout_seconds: Option<i32>,
    /// New `run_as_user`. Send `""` to drop elevation and run as the daemon user again; omitting
    /// the field leaves the current setting untouched.
    pub run_as_user: Option<String>,
}

/// A hook plus its parameter contract and the caller's effective rights over it.
#[derive(Serialize)]
pub struct HookDetail {
    /// Hook ID.
    pub id: Uuid,
    /// Hook name.
    pub name: String,
    /// Optional summary.
    pub description: Option<String>,
    /// Absolute path to the executable.
    pub script_path: String,
    /// Maximum runtime in seconds.
    pub default_timeout_seconds: i32,
    /// Account the script runs as via `sudo`, or `None` when it runs as the daemon user.
    pub run_as_user: Option<String>,
    /// Declared parameters, in the order used for positional CLI arguments.
    pub parameters: Vec<hook_parameter::Model>,
    /// Whether the requesting key may execute this hook.
    pub can_execute: bool,
    /// Whether the requesting key may manage this hook.
    pub can_manage: bool,
    /// Creation timestamp.
    pub created_at: chrono::NaiveDateTime,
    /// Last-update timestamp.
    pub updated_at: chrono::NaiveDateTime,
}

/// Assembles the [`HookDetail`] view for one hook as seen by one key.
async fn build_hook_detail(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    model: hook::Model,
) -> Result<HookDetail, AppError> {
    let parameters = load_parameters(db, model.id).await?;
    let (can_execute, can_manage) = if key.is_master {
        (true, true)
    } else {
        hook_permission(db, key.id, model.id)
            .await?
            .map(|p| (p.can_execute, p.can_manage))
            .unwrap_or((false, false))
    };

    Ok(HookDetail {
        id: model.id,
        name: model.name,
        description: model.description,
        script_path: model.script_path,
        default_timeout_seconds: model.default_timeout_seconds,
        run_as_user: model.run_as_user,
        parameters,
        can_execute,
        can_manage,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

/// Grants a key full rights over a hook, ignoring a pre-existing identical grant.
///
/// `AGENT.MD` requires this on every hook creation ("Auto-Provisioning"), so a key that creates a
/// hook can always execute and manage what it just built without a second round-trip.
async fn grant_full_hook_permission(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
    hook_id: Uuid,
) -> Result<(), AppError> {
    let model = api_key_hook_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        hook_id: Set(hook_id),
        can_execute: Set(true),
        can_manage: Set(true),
        created_at: Set(Utc::now().naive_utc()),
    };
    ApiKeyHookPermission::insert(model)
        .on_conflict(
            OnConflict::columns([
                api_key_hook_permission::Column::ApiKeyId,
                api_key_hook_permission::Column::HookId,
            ])
            .update_columns([
                api_key_hook_permission::Column::CanExecute,
                api_key_hook_permission::Column::CanManage,
            ])
            .to_owned(),
        )
        .exec_without_returning(db)
        .await?;
    Ok(())
}

/// Handles `POST /api/hooks` — declares a new hook (and, optionally, its parameters).
pub async fn create_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<CreateHookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_hooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let name = payload.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::InvalidInput("name is required".to_owned()));
    }

    executor::validate_script_path(&payload.script_path, &state.config.allowed_script_roots)?;
    let timeout = payload.default_timeout_seconds.unwrap_or(30);
    validate_timeout(timeout)?;

    // Normalized to `None` when blank, so an empty text field from the UI stores NULL rather than
    // an empty string that later has to be re-interpreted everywhere.
    let run_as_user = normalize_run_as_user(&key, payload.run_as_user.as_deref())?;

    // Validated before the hook row is written, so a bad parameter can't leave a half-created
    // hook behind.
    let declared = payload.parameters.unwrap_or_default();
    for param in &declared {
        if !executor::is_valid_param_key(&param.param_key) {
            return Err(AppError::InvalidInput(format!(
                "Invalid param_key '{}': must match [A-Za-z_][A-Za-z0-9_]*",
                param.param_key
            )));
        }
    }

    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();
    let model = hook::ActiveModel {
        id: Set(id),
        name: Set(name.clone()),
        description: Set(payload.description.clone()),
        script_path: Set(payload.script_path.clone()),
        default_timeout_seconds: Set(timeout),
        run_as_user: Set(run_as_user.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };

    if let Err(err) = Hook::insert(model).exec(&state.db).await {
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            return Err(AppError::Conflict(format!(
                "A hook named '{name}' already exists"
            )));
        }
        return Err(err.into());
    }

    for param in declared {
        let param_model = hook_parameter::ActiveModel {
            id: Set(Uuid::new_v4()),
            hook_id: Set(id),
            param_key: Set(param.param_key.clone()),
            description: Set(param.description.clone()),
            default_value: Set(param.default_value.clone()),
            is_required: Set(param.is_required.unwrap_or(true)),
            created_at: Set(Utc::now().naive_utc()),
        };
        if let Err(err) = HookParameter::insert(param_model).exec(&state.db).await {
            if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                return Err(AppError::Conflict(format!(
                    "Duplicate parameter '{}' for this hook",
                    param.param_key
                )));
            }
            return Err(err.into());
        }
    }

    grant_full_hook_permission(&state.db, key.id, id).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_CREATE",
        Some(name.clone()),
        Some(format!(
            "Created hook {} -> {} ({})",
            format_reference(&name, id),
            payload.script_path,
            describe_privilege(run_as_user.as_deref())
        )),
    )
    .await?;

    let created = Hook::find_by_id(id).one(&state.db).await?.ok_or(AppError::Internal)?;
    Ok(Json(build_hook_detail(&state.db, &key, created).await?))
}

/// Handles `GET /api/hooks` — lists every hook the caller can see.
pub async fn list_hooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let mut query = Hook::find().order_by_asc(hook::Column::Name);

    if let Some(ids) = visible_hook_ids(&state.db, &key).await? {
        if ids.is_empty() {
            return Ok(Json(Vec::<HookDetail>::new()));
        }
        query = query.filter(hook::Column::Id.is_in(ids));
    }

    let hooks = query.all(&state.db).await?;
    let mut details = Vec::with_capacity(hooks.len());
    for model in hooks {
        details.push(build_hook_detail(&state.db, &key, model).await?);
    }
    Ok(Json(details))
}

/// Handles `GET /api/hooks/{identifier}` — one hook, by UUID or name.
pub async fn get_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(identifier): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_visibility(&state.db, &key, model.id).await?;
    Ok(Json(build_hook_detail(&state.db, &key, model).await?))
}

/// Handles `PUT /api/hooks/{identifier}` — updates a hook's definition in place.
pub async fn update_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(identifier): Path<String>,
    Json(payload): Json<UpdateHookPayload>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_manage(&state.db, &key, model.id).await?;

    if let Some(script_path) = &payload.script_path {
        executor::validate_script_path(script_path, &state.config.allowed_script_roots)?;
    }
    if let Some(timeout) = payload.default_timeout_seconds {
        validate_timeout(timeout)?;
    }

    let hook_id = model.id;
    let mut changes: Vec<String> = Vec::new();
    let mut active: hook::ActiveModel = model.into();

    if let Some(name) = payload.name {
        let trimmed = name.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("name must not be empty".to_owned()));
        }
        changes.push(format!("name={trimmed}"));
        active.name = Set(trimmed);
    }
    if let Some(description) = payload.description {
        changes.push("description".to_owned());
        active.description = Set(Some(description));
    }
    if let Some(script_path) = payload.script_path {
        changes.push(format!("script_path={script_path}"));
        active.script_path = Set(script_path);
    }
    if let Some(timeout) = payload.default_timeout_seconds {
        changes.push(format!("default_timeout_seconds={timeout}"));
        active.default_timeout_seconds = Set(timeout);
    }
    if let Some(raw) = payload.run_as_user {
        // Present-but-blank is a deliberate "drop elevation", distinct from the field being
        // absent, which leaves the current setting alone.
        let normalized = normalize_run_as_user(&key, Some(&raw))?;
        changes.push(describe_privilege(normalized.as_deref()));
        active.run_as_user = Set(normalized);
    }
    active.updated_at = Set(Utc::now().naive_utc());

    let updated = match active.update(&state.db).await {
        Ok(updated) => updated,
        Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            return Err(AppError::Conflict(
                "Another hook already uses that name".to_owned(),
            ));
        }
        Err(err) => return Err(err.into()),
    };

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_UPDATE",
        Some(updated.name.clone()),
        Some(format!(
            "Updated hook {} [{}]",
            format_reference(&updated.name, hook_id),
            changes.join(", ")
        )),
    )
    .await?;

    Ok(Json(build_hook_detail(&state.db, &key, updated).await?))
}

/// Handles `DELETE /api/hooks/{identifier}` — removes a hook, cascading its parameters,
/// permissions, and execution history.
pub async fn delete_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(identifier): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_manage(&state.db, &key, model.id).await?;

    let reference = format_reference(&model.name, model.id);
    let name = model.name.clone();

    let result = Hook::delete_by_id(model.id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_DELETE",
        Some(name),
        Some(format!("Deleted hook {reference}")),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Hook parameters
// ─────────────────────────────────────────────────────────────

/// Payload for updating an existing parameter declaration.
#[derive(Deserialize)]
pub struct UpdateParameterPayload {
    /// New description.
    pub description: Option<String>,
    /// New default value. Send `""` to set an empty default; the field being absent leaves it
    /// untouched.
    pub default_value: Option<String>,
    /// New requiredness flag.
    pub is_required: Option<bool>,
}

/// Handles `GET /api/hooks/{identifier}/parameters`.
pub async fn list_hook_parameters(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(identifier): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_visibility(&state.db, &key, model.id).await?;
    Ok(Json(load_parameters(&state.db, model.id).await?))
}

/// Handles `POST /api/hooks/{identifier}/parameters` — declares one parameter.
pub async fn create_hook_parameter(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(identifier): Path<String>,
    Json(payload): Json<ParameterInput>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_manage(&state.db, &key, model.id).await?;

    if !executor::is_valid_param_key(&payload.param_key) {
        return Err(AppError::InvalidInput(format!(
            "Invalid param_key '{}': must match [A-Za-z_][A-Za-z0-9_]*",
            payload.param_key
        )));
    }

    let param_id = Uuid::new_v4();
    let param = hook_parameter::ActiveModel {
        id: Set(param_id),
        hook_id: Set(model.id),
        param_key: Set(payload.param_key.clone()),
        description: Set(payload.description.clone()),
        default_value: Set(payload.default_value.clone()),
        is_required: Set(payload.is_required.unwrap_or(true)),
        created_at: Set(Utc::now().naive_utc()),
    };

    if let Err(err) = HookParameter::insert(param).exec(&state.db).await {
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            return Err(AppError::Conflict(format!(
                "Parameter '{}' is already declared on this hook",
                payload.param_key
            )));
        }
        return Err(err.into());
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_PARAM_CREATE",
        Some(model.name.clone()),
        Some(format!(
            "Declared parameter '{}' on hook {}",
            payload.param_key,
            format_reference(&model.name, model.id)
        )),
    )
    .await?;

    let created = HookParameter::find_by_id(param_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::Internal)?;
    Ok(Json(created))
}

/// Handles `PUT /api/hooks/{identifier}/parameters/{param_id}`.
pub async fn update_hook_parameter(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path((identifier, param_id)): Path<(String, Uuid)>,
    Json(payload): Json<UpdateParameterPayload>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_manage(&state.db, &key, model.id).await?;

    let param = HookParameter::find_by_id(param_id)
        .one(&state.db)
        .await?
        .filter(|p| p.hook_id == model.id)
        .ok_or(AppError::NotFound)?;

    let param_key = param.param_key.clone();
    let mut active: hook_parameter::ActiveModel = param.into();
    if let Some(description) = payload.description {
        active.description = Set(Some(description));
    }
    if let Some(default_value) = payload.default_value {
        active.default_value = Set(Some(default_value));
    }
    if let Some(is_required) = payload.is_required {
        active.is_required = Set(is_required);
    }
    let updated = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_PARAM_UPDATE",
        Some(model.name.clone()),
        Some(format!(
            "Updated parameter '{param_key}' on hook {}",
            format_reference(&model.name, model.id)
        )),
    )
    .await?;

    Ok(Json(updated))
}

/// Handles `DELETE /api/hooks/{identifier}/parameters/{param_id}`.
pub async fn delete_hook_parameter(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path((identifier, param_id)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    require_manage(&state.db, &key, model.id).await?;

    let param = HookParameter::find_by_id(param_id)
        .one(&state.db)
        .await?
        .filter(|p| p.hook_id == model.id)
        .ok_or(AppError::NotFound)?;
    let param_key = param.param_key.clone();

    HookParameter::delete_by_id(param_id).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_PARAM_DELETE",
        Some(model.name.clone()),
        Some(format!(
            "Removed parameter '{param_key}' from hook {}",
            format_reference(&model.name, model.id)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

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
    /// Combines an execution row with its hook's name.
    fn new(model: execution::Model, hook_name: String) -> Self {
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
async fn run_hook_request(
    state: AppState,
    key: api_key::Model,
    client_ip: std::net::IpAddr,
    identifier: &str,
    body: &[u8],
) -> Result<axum::response::Response, AppError> {
    let hook_model = resolve_hook(&state.db, identifier).await?;
    require_execute(&state.db, &key, hook_model.id).await?;

    let supplied = extract_parameter_map(body)?;
    let declared = load_parameters(&state.db, hook_model.id).await?;
    let resolved = executor::resolve_parameters(&declared, &supplied)?;

    if !resolved.missing_required.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "Missing required parameter(s): {}",
            resolved.missing_required.join(", ")
        )));
    }

    let record = executor::execute_hook(&state, &hook_model, &key, &resolved).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip,
        "HOOK_EXECUTE",
        Some(hook_model.name.clone()),
        Some(format!(
            "Executed hook {} -> {:?} in {}ms",
            format_reference(&hook_model.name, hook_model.id),
            record.status,
            record.duration_ms
        )),
    )
    .await?;

    // `200 OK` reports that the *request* was carried out; whether the script itself succeeded is
    // the `status`/`exit_code` in the body. A non-zero script exit is a legitimate, fully-recorded
    // outcome, not an HTTP-level failure.
    Ok(Json(ExecutionView::new(record, hook_model.name)).into_response())
}

/// Handles `POST /api/hooks/{identifier}/execute` — runs a hook and returns its recorded outcome.
///
/// The body is taken as raw [`axum::body::Bytes`] rather than a typed `Json<T>` so the two
/// accepted payload shapes (see [`extract_parameter_map`]) both work, and so an empty body is a
/// valid "no parameters" request instead of a deserialization error.
pub async fn execute_hook_endpoint(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(identifier): Path<String>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    run_hook_request(state, key, client_ip.0, &identifier, &body).await
}

/// Handles `POST /webhook/{identifier}` — the webhook-facing alias of the execute endpoint, for
/// third-party senders that post their own flat JSON document to a fixed URL.
pub async fn webhook_execute(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(identifier): Path<String>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    run_hook_request(state, key, client_ip.0, &identifier, &body).await
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
pub async fn test_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(identifier): Path<String>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let hook_model = resolve_hook(&state.db, &identifier).await?;
    // `can_execute`, not merely visibility: a dry run reveals the fully-resolved command line and
    // the child's environment, which is execution-shaped knowledge even though nothing is spawned.
    require_execute(&state.db, &key, hook_model.id).await?;

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
pub struct ExecutionQuery {
    /// Restrict to a single hook, by UUID or name.
    pub hook: Option<String>,
    /// Restrict to a single status (`SUCCESS`, `FAILED`, `TIMEOUT`).
    pub status: Option<String>,
    /// Pagination limit.
    pub limit: Option<u64>,
    /// Pagination offset.
    pub offset: Option<u64>,
}

/// Parses a status filter, rejecting anything outside the enum.
fn parse_status(raw: &str) -> Result<ExecutionStatus, AppError> {
    match raw.to_uppercase().as_str() {
        "SUCCESS" => Ok(ExecutionStatus::Success),
        "FAILED" => Ok(ExecutionStatus::Failed),
        "TIMEOUT" => Ok(ExecutionStatus::Timeout),
        other => Err(AppError::InvalidInput(format!(
            "Invalid status filter '{other}': expected SUCCESS, FAILED, or TIMEOUT"
        ))),
    }
}

/// Handles `GET /api/executions` — newest-first history, scoped to the caller's hooks.
pub async fn list_executions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Query(query): Query<ExecutionQuery>,
) -> Result<impl IntoResponse, AppError> {
    let mut q = Execution::find().order_by_desc(execution::Column::Timestamp);

    if let Some(ids) = visible_hook_ids(&state.db, &key).await? {
        if ids.is_empty() {
            return Ok(Json(Vec::<ExecutionView>::new()));
        }
        q = q.filter(execution::Column::HookId.is_in(ids));
    }

    if let Some(identifier) = query.hook.as_deref().filter(|s| !s.is_empty()) {
        let hook_model = resolve_hook(&state.db, identifier).await?;
        require_visibility(&state.db, &key, hook_model.id).await?;
        q = q.filter(execution::Column::HookId.eq(hook_model.id));
    }

    if let Some(status) = query.status.as_deref().filter(|s| !s.is_empty()) {
        q = q.filter(execution::Column::Status.eq(parse_status(status)?));
    }

    let rows = q
        .find_also_related(Hook)
        .limit(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;

    let views = rows
        .into_iter()
        .map(|(model, hook_model)| {
            let name = hook_model.map(|h| h.name).unwrap_or_else(|| "(deleted)".to_owned());
            ExecutionView::new(model, name)
        })
        .collect::<Vec<_>>();

    Ok(Json(views))
}

/// Handles `GET /api/executions/{id}` — one execution with its full captured output.
pub async fn get_execution(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let model = Execution::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    require_visibility(&state.db, &key, model.hook_id).await?;

    let hook_name = Hook::find_by_id(model.hook_id)
        .one(&state.db)
        .await?
        .map(|h| h.name)
        .unwrap_or_else(|| "(deleted)".to_owned());

    Ok(Json(ExecutionView::new(model, hook_name)))
}

/// Handles `DELETE /api/executions/{id}` — removes a single history entry.
pub async fn delete_execution(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let model = Execution::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    // Deleting history is a management action over the hook, not merely an execute-level one.
    require_manage(&state.db, &key, model.hook_id).await?;

    Execution::delete_by_id(id).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "EXECUTION_DELETE",
        Some(id.to_string()),
        None,
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Query parameters for the manual history purge.
#[derive(Deserialize)]
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
    Query(query): Query<PurgeQuery>,
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

// ─────────────────────────────────────────────────────────────
// Admin CRUD — API keys
// ─────────────────────────────────────────────────────────────

/// Payload for creating an API key.
#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    /// Human-readable name.
    pub name: String,
    /// Comma-separated CIDR allowlist.
    pub bound_ips: Option<String>,
    /// Simultaneous execution budget. Defaults to 10.
    pub max_concurrent_jobs: Option<i32>,
    /// Master flag.
    pub is_master: Option<bool>,
    /// Global key-management scope.
    pub can_manage_keys: Option<bool>,
    /// Global hook-creation scope.
    pub can_manage_hooks: Option<bool>,
}

/// Response after creating an API key — the only time the secrets are ever available.
#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    /// Internal UUID.
    pub id: Uuid,
    /// The raw key string. Shown once; only its hash is stored.
    pub plaintext_key: String,
    /// Public key identifier, sent as `X-Key-Id` when authenticating by signature. Not a secret —
    /// it stays retrievable from `GET /api/keys` afterwards.
    pub key_id: String,
    /// The HMAC signing secret. Shown **once**; only its encrypted form is stored, and no endpoint
    /// will ever return it again. Rotating the key is the only way to obtain a new one.
    pub signing_secret: String,
    /// Key name.
    pub name: String,
    /// Bound CIDRs.
    pub bound_ips: Option<String>,
}

/// Public-safe summary of an API key. Deliberately omits `key_hash`: the hash of a live secret has
/// no reason to leave the server, even for a trusted admin UI.
#[derive(Serialize)]
pub struct ApiKeySummary {
    /// Key ID.
    pub id: Uuid,
    /// Key name.
    pub name: String,
    /// First 8 characters of the plaintext key, for display.
    pub prefix: String,
    /// Public key identifier used for signature auth. Safe to display — it is not a credential.
    /// `None` for keys issued before signature auth existed; rotating mints one.
    pub key_id: Option<String>,
    /// Whether a signing secret exists for this key. The secret itself is deliberately absent:
    /// it left the server once, at creation, and no listing will ever hand it back.
    pub has_signing_secret: bool,
    /// Bound CIDRs.
    pub bound_ips: Option<String>,
    /// Simultaneous execution budget.
    pub max_concurrent_jobs: i32,
    /// Master flag.
    pub is_master: bool,
    /// Global key-management scope.
    pub can_manage_keys: bool,
    /// Global hook-creation scope.
    pub can_manage_hooks: bool,
    /// Creation timestamp.
    pub created_at: chrono::NaiveDateTime,
    /// Per-hook permissions held by this key.
    pub hook_permissions: Vec<HookPermissionView>,
}

/// Builds the public-safe summary for a single key, shared by every endpoint that returns key
/// details so the shape stays consistent.
async fn build_api_key_summary(
    db: &sea_orm::DatabaseConnection,
    model: api_key::Model,
) -> Result<ApiKeySummary, AppError> {
    let hook_permissions = load_hook_permissions(db, model.id).await?;
    Ok(ApiKeySummary {
        id: model.id,
        name: model.name,
        prefix: model.prefix,
        key_id: model.key_id,
        has_signing_secret: model.signing_secret.is_some(),
        bound_ips: model.bound_ips,
        max_concurrent_jobs: model.max_concurrent_jobs,
        is_master: model.is_master,
        can_manage_keys: model.can_manage_keys,
        can_manage_hooks: model.can_manage_hooks,
        created_at: model.created_at,
        hook_permissions,
    })
}

/// Validates a proposed concurrency budget.
fn validate_concurrency(jobs: i32) -> Result<(), AppError> {
    if jobs < 1 {
        return Err(AppError::InvalidInput(
            "max_concurrent_jobs must be at least 1".to_owned(),
        ));
    }
    if jobs > MAX_CONCURRENT_JOBS {
        return Err(AppError::InvalidInput(format!(
            "max_concurrent_jobs must not exceed {MAX_CONCURRENT_JOBS}"
        )));
    }
    Ok(())
}

/// Handles `POST /api/keys`.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if let Some(bound_ips) = &payload.bound_ips {
        validate_bound_ips(bound_ips)?;
    }
    let max_concurrent_jobs = payload.max_concurrent_jobs.unwrap_or(10);
    validate_concurrency(max_concurrent_jobs)?;

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let (key_id, signing_secret, sealed_secret) = mint_signing_pair(&state.cipher)?;
    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        name: Set(payload.name.clone()),
        prefix: Set(prefix),
        key_id: Set(Some(key_id.clone())),
        signing_secret: Set(Some(sealed_secret)),
        bound_ips: Set(payload.bound_ips.clone()),
        max_concurrent_jobs: Set(max_concurrent_jobs),
        is_master: Set(payload.is_master.unwrap_or(false)),
        can_manage_keys: Set(payload.can_manage_keys.unwrap_or(false)),
        can_manage_hooks: Set(payload.can_manage_hooks.unwrap_or(false)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    ApiKey::insert(model).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_CREATE",
        Some(payload.name.clone()),
        Some(format!("Created key {}", format_reference(&payload.name, id))),
    )
    .await?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        key_id,
        signing_secret,
        name: payload.name,
        bound_ips: payload.bound_ips,
    }))
}

/// Handles `GET /api/keys`.
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let keys = ApiKey::find().order_by_asc(api_key::Column::CreatedAt).all(&state.db).await?;
    let mut summaries = Vec::with_capacity(keys.len());
    for model in keys {
        summaries.push(build_api_key_summary(&state.db, model).await?);
    }
    Ok(Json(summaries))
}

/// Payload for updating an existing API key. Excludes `is_master`: promoting or demoting master
/// status is deliberately not exposed through a generic update endpoint.
#[derive(Deserialize)]
pub struct UpdateApiKeyPayload {
    /// New name.
    pub name: Option<String>,
    /// New bound CIDRs.
    pub bound_ips: Option<String>,
    /// New concurrency budget.
    pub max_concurrent_jobs: Option<i32>,
    /// New key-management scope.
    pub can_manage_keys: Option<bool>,
    /// New hook-creation scope.
    pub can_manage_hooks: Option<bool>,
}

/// Handles `PUT /api/keys/{id}`.
pub async fn update_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    if let Some(bound_ips) = &payload.bound_ips {
        validate_bound_ips(bound_ips)?;
    }
    if let Some(jobs) = payload.max_concurrent_jobs {
        validate_concurrency(jobs)?;
    }

    let mut active: api_key::ActiveModel = target.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(bound_ips) = payload.bound_ips {
        active.bound_ips = Set(Some(bound_ips));
    }
    if let Some(jobs) = payload.max_concurrent_jobs {
        active.max_concurrent_jobs = Set(jobs);
    }
    if let Some(v) = payload.can_manage_keys {
        active.can_manage_keys = Set(v);
    }
    if let Some(v) = payload.can_manage_hooks {
        active.can_manage_hooks = Set(v);
    }
    active.updated_at = Set(Utc::now().naive_utc());
    let updated = active.update(&state.db).await?;

    // Uses the post-update name: if this call renamed the key, that is what a reader will
    // recognize it by later.
    let reference = format_reference(&updated.name, id);
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_UPDATE",
        Some(updated.name.clone()),
        Some(format!("Updated key {reference}")),
    )
    .await?;

    Ok(Json(build_api_key_summary(&state.db, updated).await?))
}

/// Handles `DELETE /api/keys/{id}`.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }
    if id == key.id {
        return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));
    }

    // Fetched before deleting (rather than relying on rows_affected) so the name is still
    // available for the audit entry below.
    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let reference = format_reference(&target.name, id);
    let name = target.name.clone();

    let result = ApiKey::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_DELETE",
        Some(name),
        Some(format!("Deleted key {reference}")),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Response after rotating an API key's secrets.
#[derive(Serialize)]
pub struct RotateKeyResponse {
    /// Internal UUID.
    pub id: Uuid,
    /// The new plaintext key. Shown only once — only its hash is stored.
    pub plaintext_key: String,
    /// The new public key identifier.
    pub key_id: String,
    /// The new HMAC signing secret. Shown only once.
    pub signing_secret: String,
}

/// Handles `POST /api/keys/{id}/rotate` — issues a new secret, immediately invalidating the old
/// one (its hash is overwritten, not kept alongside).
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let reference = format_reference(&target.name, id);
    let name = target.name.clone();

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    // Rotation replaces the signing pair as well: a rotation is a response to "this credential may
    // be compromised", and leaving the old signing secret in place would keep an attacker able to
    // forge signatures. It is also how a pre-signature-auth key acquires its first pair.
    let (key_id, signing_secret, sealed_secret) = mint_signing_pair(&state.cipher)?;

    let mut active: api_key::ActiveModel = target.into();
    active.key_hash = Set(key_hash);
    active.prefix = Set(prefix);
    active.key_id = Set(Some(key_id.clone()));
    active.signing_secret = Set(Some(sealed_secret));
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_ROTATE",
        Some(name),
        Some(format!("Rotated secret for key {reference}")),
    )
    .await?;

    Ok(Json(RotateKeyResponse {
        id,
        plaintext_key,
        key_id,
        signing_secret,
    }))
}

/// Input for granting a key rights over a hook.
#[derive(Deserialize)]
pub struct HookPermInput {
    /// Target hook, by UUID *or* name (a plain string, so a name here never trips Axum's
    /// deserialization). Provide this or `hook_name`, not both.
    pub hook_id: Option<String>,
    /// Target hook, by name. Equivalent to putting a name in `hook_id`; kept as a separate field
    /// for callers that prefer an explicit one.
    pub hook_name: Option<String>,
    /// Permission to execute the hook.
    pub can_execute: bool,
    /// Permission to manage the hook.
    pub can_manage: bool,
}

/// Handles `POST /api/keys/{id}/permissions` — grants or updates one key's rights over one hook.
pub async fn update_key_hook_permissions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<HookPermInput>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target_key = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if target_key.is_master {
        return Err(AppError::InvalidInput(
            "Cannot configure M:N permissions on a master key".to_owned(),
        ));
    }

    let identifier = match (payload.hook_id.as_deref(), payload.hook_name.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(AppError::InvalidInput(
                "Provide either hook_id or hook_name, not both".to_owned(),
            ));
        }
        (None, None) => {
            return Err(AppError::InvalidInput(
                "Either hook_id or hook_name is required".to_owned(),
            ));
        }
        (Some(v), None) | (None, Some(v)) => v,
    };
    let hook_model = resolve_hook(&state.db, identifier).await?;

    let perm = api_key_hook_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(id),
        hook_id: Set(hook_model.id),
        can_execute: Set(payload.can_execute),
        can_manage: Set(payload.can_manage),
        created_at: Set(Utc::now().naive_utc()),
    };
    ApiKeyHookPermission::insert(perm)
        .on_conflict(
            OnConflict::columns([
                api_key_hook_permission::Column::ApiKeyId,
                api_key_hook_permission::Column::HookId,
            ])
            .update_columns([
                api_key_hook_permission::Column::CanExecute,
                api_key_hook_permission::Column::CanManage,
            ])
            .to_owned(),
        )
        .exec_without_returning(&state.db)
        .await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_PERM_UPDATE",
        Some(hook_model.name.clone()),
        Some(format!(
            "Updated permissions for key {}",
            format_reference(&target_key.name, id)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::OK)
}

/// Handles `DELETE /api/keys/{id}/permissions/{hook_identifier}` — removes a key's grant over one
/// hook. The identifier may be the hook's UUID or its name.
pub async fn revoke_key_hook_permission(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path((id, hook_identifier)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let hook_model = resolve_hook(&state.db, &hook_identifier).await?;

    let result = ApiKeyHookPermission::delete_many()
        .filter(
            Condition::all()
                .add(api_key_hook_permission::Column::ApiKeyId.eq(id))
                .add(api_key_hook_permission::Column::HookId.eq(hook_model.id)),
        )
        .exec(&state.db)
        .await?;

    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_PERM_REVOKE",
        Some(hook_model.name),
        Some(format!(
            "Revoked permissions for key {}",
            format_reference(&target.name, id)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

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
    /// Age, in days, beyond which execution history is purged (`0` = never).
    pub log_retention_days: i64,
    /// Interval between retention sweeps, in seconds.
    pub retention_sweep_seconds: u64,
    /// Per-stream cap on captured output, in bytes.
    pub max_output_bytes: usize,
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
        log_retention_days: state.config.log_retention_days,
        retention_sweep_seconds: state.config.retention_sweep_seconds,
        max_output_bytes: state.config.max_output_bytes,
        hook_count: Hook::find().count(&state.db).await?,
        api_key_count: ApiKey::find().count(&state.db).await?,
        execution_count: Execution::find().count(&state.db).await?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_execute_payload_shapes() {
        let wrapped = br#"{"parameters":{"target":"1.2.3.4"}}"#;
        let flat = br#"{"target":"1.2.3.4"}"#;
        let expected: serde_json::Map<String, serde_json::Value> =
            [("target".to_owned(), serde_json::json!("1.2.3.4"))].into_iter().collect();

        assert_eq!(extract_parameter_map(wrapped).expect("wrapped shape"), expected);
        assert_eq!(extract_parameter_map(flat).expect("flat shape"), expected);
        assert!(extract_parameter_map(b"").expect("empty body").is_empty());
        assert!(extract_parameter_map(b"null").expect("null body").is_empty());
    }

    #[test]
    fn rejects_malformed_execute_payloads() {
        assert!(matches!(
            extract_parameter_map(b"{not json"),
            Err(AppError::InvalidInput(_))
        ));
        assert!(matches!(
            extract_parameter_map(b"[1,2,3]"),
            Err(AppError::InvalidInput(_))
        ));
        assert!(matches!(
            extract_parameter_map(br#"{"parameters":"oops"}"#),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn validates_timeouts_and_concurrency_bounds() {
        assert!(validate_timeout(30).is_ok());
        assert!(validate_timeout(0).is_err());
        assert!(validate_timeout(-5).is_err());
        assert!(validate_timeout(MAX_TIMEOUT_SECONDS + 1).is_err());

        assert!(validate_concurrency(1).is_ok());
        assert!(validate_concurrency(0).is_err());
        assert!(validate_concurrency(MAX_CONCURRENT_JOBS + 1).is_err());
    }

    #[test]
    fn validates_cidr_lists() {
        assert!(validate_bound_ips("0.0.0.0/0,::/0").is_ok());
        assert!(validate_bound_ips("127.0.0.1/32, 10.0.0.0/8").is_ok());
        assert!(validate_bound_ips("").is_ok());
        assert!(validate_bound_ips("not-a-cidr").is_err());
    }

    #[test]
    fn parses_status_filters_case_insensitively() {
        assert_eq!(parse_status("success").expect("valid"), ExecutionStatus::Success);
        assert_eq!(parse_status("TIMEOUT").expect("valid"), ExecutionStatus::Timeout);
        assert!(parse_status("bogus").is_err());
    }
}
