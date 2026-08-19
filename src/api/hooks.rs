//! Hook definitions and their parameter contracts.
//!
//! Covers the full lifecycle of the managed resource itself: creation (with owner assignment and
//! auto-provisioned rights), the definition edits R2 governs, the parameter contract, and the
//! trash/restore/purge path. Running a hook lives in [`super::executions`] — this module decides
//! what a hook *is*, not what happens when one fires.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait,
    QueryFilter, QueryOrder, SqlErr, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_hook_permission, hook, hook::AuthMode, hook_parameter, prelude::*,
};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::AppState;
use crate::executor;

use super::executions::PurgeQuery;
use super::guards::{
    guard_dispatch_configuration, guard_lifecycle_authority, guard_manage,
    guard_master_for_deleted_view, hook_permission, normalize_run_as_user,
    guard_master_for_privileged_hook, guard_visibility, visible_hook_ids,
};
use super::support::{
    create_audit_log, describe_privilege, format_reference, load_parameters,
    resolve_hook, resolve_hook_including_deleted, validate_timeout,
};

// ─────────────────────────────────────────────────────────────
// Hooks
// ─────────────────────────────────────────────────────────────

/// A hook parameter declaration, as accepted on hook creation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// How a keyless caller must authenticate to invoke this hook. Defaults to
    /// [`AuthMode::CanonicalV1`] — every hook keeps requiring a valid `X-API-Key` unless an
    /// operator explicitly opts it into something looser.
    pub auth_mode: Option<AuthMode>,
    /// `HMAC_ONLY`'s signing secret, in plaintext. Required if `auth_mode` is `HMAC_ONLY`; ignored
    /// (but accepted) for any other mode, so a hook can be pre-provisioned with a secret before it
    /// is switched over.
    pub hmac_secret: Option<String>,
    /// Header an `HMAC_ONLY` sender's signature arrives on. Defaults to `X-Signature-256`.
    pub signature_header: Option<String>,
    /// Prefix stripped from an `HMAC_ONLY` signature before hex-decoding it. Defaults to `sha256=`.
    pub signature_prefix: Option<String>,
    /// Override of the `CANONICAL_V1` canonical string template for this hook. Defaults to the
    /// service-wide `{method}\n{path}\n{timestamp}\n{body}`.
    pub canonical_template: Option<String>,
}

/// Payload for updating a hook. Every field is optional; omitted fields are left untouched.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// New owner (`RBAC_MODEL.md` §3: "Master may reassign `owner_key_id` on any resource ... at
    /// any time"). **Master-only**, and the only way ownership ever moves.
    ///
    /// Reassignment is deliberately not delegable, not even to the current owner. Ownership is what
    /// §3 hangs lifecycle authority on and what §6's inventory reports; letting an owner hand it to
    /// an arbitrary key would let it walk away from a resource rather than resolve it, which is the
    /// step §6 exists to make impossible.
    pub owner_key_id: Option<Uuid>,
    /// New `auth_mode`. Omitting the field leaves the current mode untouched. Governed by the same
    /// rights as any other content edit — `RBAC_MODEL.md`'s Terminology section names only
    /// `script_path` and `run_as_user` as this service's dispatch configuration, so `auth_mode` and
    /// its supporting fields below are not subject to `guard_dispatch_configuration`.
    pub auth_mode: Option<AuthMode>,
    /// New `HMAC_ONLY` secret. Send `""` to clear it; omitting the field leaves the current secret
    /// untouched.
    pub hmac_secret: Option<String>,
    /// New signature header for `HMAC_ONLY`. Send `""` to reset to the built-in default
    /// (`X-Signature-256`); omitting the field leaves the current value untouched.
    pub signature_header: Option<String>,
    /// New signature prefix for `HMAC_ONLY`. Send `""` to reset to the built-in default (`sha256=`);
    /// omitting the field leaves the current value untouched.
    pub signature_prefix: Option<String>,
    /// New `CANONICAL_V1` template override. Send `""` to reset to the service-wide default;
    /// omitting the field leaves the current value untouched.
    pub canonical_template: Option<String>,
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
    /// The key answerable for this hook under `RBAC_MODEL.md` §3, or `None` for a hook that
    /// predates ownership (lifecycle authority then rests with master alone).
    pub owner_key_id: Option<Uuid>,
    /// Whether *this caller* may delete or rename the hook — master, or its owner. Distinct from
    /// `can_manage`, which is the right to edit its content.
    pub is_owner: bool,
    /// Whether the hook is in the trash. Only ever `true` in a master's `include_deleted` view.
    pub is_deleted: bool,
    /// When it was trashed, if it was.
    pub deleted_at: Option<chrono::NaiveDateTime>,
    /// The `api_keys.id` of whoever trashed it, if it was.
    pub deleted_by: Option<String>,
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
    /// How a keyless caller must authenticate to invoke this hook.
    pub auth_mode: AuthMode,
    /// Whether an `HMAC_ONLY` secret has been set. The secret itself is never returned — it left
    /// the server once, when it was supplied, and no listing hands it back.
    pub hmac_secret_configured: bool,
    /// Configured signature header for `HMAC_ONLY`, or `None` for the built-in default.
    pub signature_header: Option<String>,
    /// Configured signature prefix for `HMAC_ONLY`, or `None` for the built-in default.
    pub signature_prefix: Option<String>,
    /// Configured `CANONICAL_V1` template override, or `None` for the service-wide default.
    pub canonical_template: Option<String>,
}

/// Assembles the [`HookDetail`] view for one hook as seen by one key.
pub(crate) async fn build_hook_detail(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    model: hook::Model,
) -> Result<HookDetail, AppError> {
    let parameters = load_parameters(db, model.id).await?;
    // §3 authority, reported alongside the operational verbs so a dashboard can grey out "delete"
    // rather than discovering the refusal only after the click.
    let is_owner = key.is_master || model.owner_key_id == Some(key.id);
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
        owner_key_id: model.owner_key_id,
        is_owner,
        is_deleted: model.is_deleted,
        deleted_at: model.deleted_at,
        deleted_by: model.deleted_by,
        parameters,
        can_execute,
        can_manage,
        created_at: model.created_at,
        updated_at: model.updated_at,
        auth_mode: model.auth_mode,
        hmac_secret_configured: model.hmac_secret.is_some(),
        signature_header: model.signature_header,
        signature_prefix: model.signature_prefix,
        canonical_template: model.canonical_template,
    })
}

/// Validates and seals a hook's `HMAC_ONLY` secret for storage, and rejects an `HMAC_ONLY` mode
/// left without one.
///
/// `effective_mode` and `effective_secret` are the values that will actually be on the row once
/// this write lands — the payload's, if it supplied one, otherwise whatever the row already has —
/// so this catches both "create as `HMAC_ONLY` with no secret" and "switch an existing hook to
/// `HMAC_ONLY` without ever having set one", not only the first.
fn validate_and_seal_hmac_secret(
    cipher: &crate::crypto::SecretCipher,
    effective_mode: AuthMode,
    payload_secret: Option<&str>,
    existing_sealed: Option<&str>,
) -> Result<Option<String>, AppError> {
    match payload_secret {
        Some("") => {
            if effective_mode == AuthMode::HmacOnly {
                return Err(AppError::InvalidInput(
                    "hmac_secret cannot be cleared while auth_mode is HMAC_ONLY".to_owned(),
                ));
            }
            Ok(None)
        }
        Some(raw) => cipher
            .seal(raw)
            .map(Some)
            .map_err(|e| {
                tracing::error!("Failed to seal a hook's hmac_secret: {e}");
                AppError::Internal
            }),
        None => {
            if effective_mode == AuthMode::HmacOnly && existing_sealed.is_none() {
                return Err(AppError::InvalidInput(
                    "hmac_secret is required when auth_mode is HMAC_ONLY".to_owned(),
                ));
            }
            Ok(existing_sealed.map(str::to_owned))
        }
    }
}

/// Grants a key full rights over a hook, ignoring a pre-existing identical grant.
///
/// `AGENT.MD` requires this on every hook creation ("Auto-Provisioning"), so a key that creates a
/// hook can always execute and manage what it just built without a second round-trip.
pub(crate) async fn grant_full_hook_permission(
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
        // The creator sees its own hook's history. It would anyway — it owns the hook, and ownership
        // is one of the four routes to execution visibility — but the row should say so rather than
        // leaving the creator's access dependent on the ownership column staying where it is. Master
        // may reassign `owner_key_id` at any time (§3), and a creator that has handed ownership on
        // still holds the grant it was given.
        can_view_execution: Set(true),
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
    StrictJson(payload): StrictJson<CreateHookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_hooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // The escalation guard runs before *any* payload validation. A non-master requesting
    // `run_as_user` must get its `403` regardless of whether the rest of the request happens to be
    // well-formed — otherwise a malformed script_path would mask the real reason for the refusal,
    // and the response would leak which other fields passed validation.
    //
    // Normalized to `None` when blank, so an empty text field from the UI stores NULL rather than
    // an empty string that later has to be re-interpreted everywhere.
    let run_as_user = normalize_run_as_user(&key, payload.run_as_user.as_deref())?;

    let name = payload.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::InvalidInput("name is required".to_owned()));
    }

    executor::validate_script_path(&payload.script_path, &state.config.allowed_script_roots)?;
    let timeout = payload.default_timeout_seconds.unwrap_or(30);
    validate_timeout(timeout)?;

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

    let auth_mode = payload.auth_mode.unwrap_or_default();
    let sealed_hmac_secret = validate_and_seal_hmac_secret(
        &state.cipher,
        auth_mode,
        payload.hmac_secret.as_deref(),
        None,
    )?;
    let signature_header = payload.signature_header.filter(|s| !s.is_empty());
    let signature_prefix = payload.signature_prefix.filter(|s| !s.is_empty());
    let canonical_template = payload.canonical_template.filter(|s| !s.is_empty());

    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();
    let model = hook::ActiveModel {
        id: Set(id),
        name: Set(name.clone()),
        description: Set(payload.description.clone()),
        script_path: Set(payload.script_path.clone()),
        default_timeout_seconds: Set(timeout),
        run_as_user: Set(run_as_user.clone()),
        // The creator owns what it creates. §3 restricts deletion and renaming to master and this
        // key, and the `can_manage` row auto-provisioned below deliberately does not imply it.
        owner_key_id: Set(Some(key.id)),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        auth_mode: Set(auth_mode),
        hmac_secret: Set(sealed_hmac_secret),
        signature_header: Set(signature_header),
        signature_prefix: Set(signature_prefix),
        canonical_template: Set(canonical_template),
    };

    if let Err(err) = Hook::insert(model).exec(&state.db).await {
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            // `hooks.name` stays unique across live *and* trashed rows: a partial unique index is
            // the one way to scope it, and the syntax differs per backend, which `AGENT.MD` forbids.
            // The name is therefore still held by whatever is in the trash — say so explicitly,
            // because "already exists" for a hook the caller just deleted and cannot see is a
            // genuinely baffling error to receive.
            let trashed = Hook::find()
                .filter(hook::Column::Name.eq(name.clone()))
                .filter(hook::Column::IsDeleted.eq(true))
                .one(&state.db)
                .await?;
            return Err(AppError::Conflict(match trashed {
                Some(_) => format!(
                    "A deleted hook named '{name}' still holds that name. Restore it, or purge it \
                     with DELETE /api/hooks/{name}?hard=true, before reusing the name."
                ),
                None => format!("A hook named '{name}' already exists"),
            }));
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

/// Query parameters for the hook listing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListHooksQuery {
    /// Include soft-deleted hooks — the master's trash view. Defaults to `false`.
    pub include_deleted: Option<bool>,
}

/// Handles `GET /api/hooks` — lists every hook the caller can see.
///
/// Soft-deleted hooks are omitted unless a master asks for them with `?include_deleted=true`, so the
/// default view is exactly what an operator expects "the hooks" to mean.
pub async fn list_hooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(params): StrictQuery<ListHooksQuery>,
) -> Result<impl IntoResponse, AppError> {
    let include_deleted = params.include_deleted.unwrap_or(false);
    guard_master_for_deleted_view(&key, include_deleted)?;

    let mut query = Hook::find().order_by_asc(hook::Column::Name);
    if !include_deleted {
        query = query.filter(hook::Column::IsDeleted.eq(false));
    }

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
///
/// A soft-deleted hook is a `404` unless a master asks for it with `?include_deleted=true`, which is
/// how the trash view drills into a row before restoring it.
pub async fn get_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictPath(identifier): StrictPath<String>,
    StrictQuery(params): StrictQuery<ListHooksQuery>,
) -> Result<impl IntoResponse, AppError> {
    let include_deleted = params.include_deleted.unwrap_or(false);
    guard_master_for_deleted_view(&key, include_deleted)?;

    let model = if include_deleted {
        resolve_hook_including_deleted(&state.db, &identifier).await?
    } else {
        resolve_hook(&state.db, &identifier).await?
    };
    guard_visibility(&state.db, &key, &model).await?;
    Ok(Json(build_hook_detail(&state.db, &key, model).await?))
}

/// Handles `PUT /api/hooks/{identifier}` — updates a hook's definition in place.
pub async fn update_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(identifier): StrictPath<String>,
    StrictJson(payload): StrictJson<UpdateHookPayload>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    guard_manage(&state.db, &key, &model).await?;
    // RBAC_MODEL.md's Dispatch configuration clause governs `script_path` and `run_as_user` by R2
    // *in full*, with no ownership exception — a narrower rule than `guard_manage`'s own, which
    // lets the owner through on ownership alone. Checked as its own step, before validation, so an
    // owner whose `can_manage_hooks` was revoked is refused here rather than by a guard further
    // down that happens to also catch it for an unrelated reason.
    if payload.script_path.is_some() || payload.run_as_user.is_some() {
        guard_dispatch_configuration(&state.db, &key, &model).await?;
    }
    // A hook that already runs elevated is master-only to touch *at all*, not merely master-only to
    // elevate. `script_path`, the timeout, and the name all decide what executes with the borrowed
    // privileges, so guarding one field while leaving the rest writable protected nothing.
    guard_master_for_privileged_hook(&key, &model, "modify")?;

    // Checked immediately after authorization and before any field validation, for the same reason
    // as in `create_hook`: an escalation attempt must surface as `403`, never be masked by a `400`
    // about some other field in the same payload.
    let requested_run_as_user = match payload.run_as_user.as_deref() {
        Some(raw) => Some(normalize_run_as_user(&key, Some(raw))?),
        None => None,
    };

    // §3: renaming is a lifecycle action, not an edit. This service resolves hooks by name on
    // `/webhook/{identifier}` and in grant payloads, so a rename silently breaks every caller
    // pointed at the old one — which is a change to the resource's identity, not its content.
    if payload.name.is_some() {
        guard_lifecycle_authority(&key, &model, "rename")?;
    }

    // §3: only master reassigns ownership.
    let requested_owner = match payload.owner_key_id {
        Some(owner) => {
            if !key.is_master {
                tracing::warn!(
                    key = %key.prefix,
                    hook = %model.name,
                    "§3: non-master attempted to reassign hook ownership"
                );
                return Err(AppError::Forbidden(
                    "Only master API keys can reassign a hook's owner".to_owned(),
                ));
            }
            // A dangling owner would put the hook permanently beyond §3's non-master path and make
            // §6's inventory report an id that resolves to nothing.
            if ApiKey::find_by_id(owner).one(&state.db).await?.is_none() {
                return Err(AppError::InvalidInput(
                    "owner_key_id does not name an existing API key".to_owned(),
                ));
            }
            Some(owner)
        }
        None => None,
    };

    if let Some(script_path) = &payload.script_path {
        executor::validate_script_path(script_path, &state.config.allowed_script_roots)?;
    }
    if let Some(timeout) = payload.default_timeout_seconds {
        validate_timeout(timeout)?;
    }

    let effective_auth_mode = payload.auth_mode.unwrap_or(model.auth_mode);
    let sealed_hmac_secret = validate_and_seal_hmac_secret(
        &state.cipher,
        effective_auth_mode,
        payload.hmac_secret.as_deref(),
        model.hmac_secret.as_deref(),
    )?;

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
    if let Some(owner) = requested_owner {
        changes.push(format!("owner_key_id={owner}"));
        active.owner_key_id = Set(Some(owner));
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
    if let Some(normalized) = requested_run_as_user {
        // Present-but-blank is a deliberate "drop elevation", distinct from the field being
        // absent, which leaves the current setting alone.
        changes.push(describe_privilege(normalized.as_deref()));
        active.run_as_user = Set(normalized);
    }
    if let Some(mode) = payload.auth_mode {
        changes.push(format!("auth_mode={mode:?}"));
        active.auth_mode = Set(mode);
    }
    // `hmac_secret` always resolves to a value above (the payload's, the existing one, or `None`
    // after an explicit clear) — but only recorded as *changed* when the payload actually named it,
    // so an untouched secret does not show up in every unrelated edit's audit trail.
    if payload.hmac_secret.is_some() {
        changes.push("hmac_secret".to_owned());
    }
    active.hmac_secret = Set(sealed_hmac_secret);
    if let Some(header) = payload.signature_header {
        changes.push(format!("signature_header={header}"));
        active.signature_header = Set(if header.is_empty() { None } else { Some(header) });
    }
    if let Some(prefix) = payload.signature_prefix {
        changes.push(format!("signature_prefix={prefix}"));
        active.signature_prefix = Set(if prefix.is_empty() { None } else { Some(prefix) });
    }
    if let Some(template) = payload.canonical_template {
        changes.push("canonical_template".to_owned());
        active.canonical_template = Set(if template.is_empty() { None } else { Some(template) });
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

/// Query parameters for `DELETE /api/hooks/{identifier}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteHookQuery {
    /// Drop the row outright instead of moving it to the trash. Master-only.
    pub hard: Option<bool>,
}

/// Handles `DELETE /api/hooks/{identifier}` — moves a hook to the trash, or (master, `?hard=true`)
/// drops it outright.
///
/// The default is a **soft** delete for every caller, master included. Dropping the row cascades the
/// hook's parameters, permission grants, and entire execution history, so the destructive path is
/// the one that has to be asked for explicitly rather than the one you get by mistyping a UUID.
/// `?hard=true` is master-only for the same reason: irreversibly destroying an audit trail is not
/// something a scoped `can_manage` grant should be able to do.
pub async fn delete_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(identifier): StrictPath<String>,
    StrictQuery(query): StrictQuery<DeleteHookQuery>,
) -> Result<impl IntoResponse, AppError> {
    let hard = query.hard.unwrap_or(false);
    // A hard delete may target something already in the trash, which is the normal way an operator
    // empties it; a soft delete only ever applies to a live hook.
    let model = if hard {
        resolve_hook_including_deleted(&state.db, &identifier).await?
    } else {
        resolve_hook(&state.db, &identifier).await?
    };
    guard_manage(&state.db, &key, &model).await?;
    // §3: managing a hook is not authority to make it cease to exist.
    guard_lifecycle_authority(&key, &model, "delete")?;
    // Deleting a privileged hook is a change to a privileged hook like any other.
    guard_master_for_privileged_hook(&key, &model, "delete")?;

    let reference = format_reference(&model.name, model.id);
    let name = model.name.clone();

    if hard {
        if !key.is_master {
            return Err(AppError::Forbidden(
                "Only master API keys can permanently delete a hook; omit ?hard=true to move it \
                 to the trash instead"
                    .to_owned(),
            ));
        }

        let result = Hook::delete_by_id(model.id).exec(&state.db).await?;
        if result.rows_affected == 0 {
            return Err(AppError::NotFound);
        }

        create_audit_log(
            &state.db,
            &key,
            client_ip.0,
            "HOOK_HARD_DELETE",
            Some(name),
            Some(format!(
                "Permanently deleted hook {reference}, discarding its parameters, permissions, and \
                 execution history"
            )),
        )
        .await?;

        return Ok(axum::http::StatusCode::NO_CONTENT);
    }

    // Conditional on the row still being live, and the affected count is checked — the same shape
    // the hard-delete branch above uses, and for the same reason.
    //
    // `resolve_hook` already refuses a trashed hook, so a *sequential* second delete is a `404`
    // before reaching here. What that leaves is the concurrent case: two callers can both resolve a
    // live hook and arrive here, and an unconditional `ActiveModel::update` would let both succeed.
    // The visible damage is not the row — the second write is idempotent — but the audit trail:
    // each caller would go on to write its own `HOOK_DELETE` entry, leaving two records of one
    // deletion and two operators each told they performed it. Filtering on `is_deleted = false`
    // makes the database pick the winner, and the loser takes the same `404` it would have taken a
    // moment later.
    let now = Utc::now().naive_utc();
    let soft_deleted = Hook::update_many()
        .col_expr(hook::Column::IsDeleted, sea_orm::sea_query::Expr::value(true))
        .col_expr(hook::Column::DeletedAt, sea_orm::sea_query::Expr::value(Some(now)))
        // Stored as text so the attribution outlives the acting key.
        .col_expr(
            hook::Column::DeletedBy,
            sea_orm::sea_query::Expr::value(Some(key.id.to_string())),
        )
        .col_expr(hook::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(hook::Column::Id.eq(model.id))
        .filter(hook::Column::IsDeleted.eq(false))
        .exec(&state.db)
        .await?;
    if soft_deleted.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_DELETE",
        Some(name),
        Some(format!(
            "Moved hook {reference} to the trash; it is recoverable until purged after \
             {} days",
            state.config.deleted_hook_retention_days
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Handles `POST /api/hooks/{identifier}/restore` — brings a soft-deleted hook back.
///
/// Master-only. A trashed hook keeps its `script_path` and `run_as_user`, so restoring one puts a
/// previously-removed definition — potentially a privileged one — back into service; that is a
/// decision for the same authority that can create such a hook in the first place.
pub async fn restore_hook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(identifier): StrictPath<String>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master API keys can restore a deleted hook".to_owned(),
        ));
    }

    let model = resolve_hook_including_deleted(&state.db, &identifier).await?;
    if !model.is_deleted {
        return Err(AppError::InvalidInput(format!(
            "Hook '{}' is not deleted",
            model.name
        )));
    }

    let reference = format_reference(&model.name, model.id);
    let name = model.name.clone();
    let hook_id = model.id;

    let mut active: hook::ActiveModel = model.into();
    active.is_deleted = Set(false);
    active.deleted_at = Set(None);
    active.deleted_by = Set(None);
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_RESTORE",
        Some(name),
        Some(format!("Restored hook {reference} from the trash")),
    )
    .await?;

    let restored = Hook::find_by_id(hook_id).one(&state.db).await?.ok_or(AppError::Internal)?;
    Ok(Json(build_hook_detail(&state.db, &key, restored).await?))
}

/// Handles `POST /api/system/purge-hooks` — permanently drops trashed hooks past the retention
/// window.
///
/// Master-only, and irreversible: it discards each purged hook's execution history along with the
/// row. Runs the same sweep as the background worker, so an operator reclaiming space immediately
/// gets exactly the behaviour that would have happened on its own schedule.
pub async fn purge_deleted_hooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictQuery(query): StrictQuery<PurgeQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can purge deleted hooks".to_owned(),
        ));
    }

    let days = query
        .older_than_days
        .unwrap_or(state.config.deleted_hook_retention_days);
    if days < 0 {
        return Err(AppError::InvalidInput(
            "older_than_days must not be negative".to_owned(),
        ));
    }

    let purged = crate::retention::purge_expired_deleted_hooks(&state.db, days).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "HOOK_PURGE",
        None,
        Some(format!(
            "Purged {purged} deleted hook(s) trashed more than {days} day(s) ago"
        )),
    )
    .await?;

    Ok(Json(serde_json::json!({ "purged": purged, "older_than_days": days })))
}

// ─────────────────────────────────────────────────────────────
// Hook parameters
// ─────────────────────────────────────────────────────────────

/// Payload for updating an existing parameter declaration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    StrictPath(identifier): StrictPath<String>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    guard_visibility(&state.db, &key, &model).await?;
    Ok(Json(load_parameters(&state.db, model.id).await?))
}

/// Handles `POST /api/hooks/{identifier}/parameters` — declares one parameter.
pub async fn create_hook_parameter(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(identifier): StrictPath<String>,
    StrictJson(payload): StrictJson<ParameterInput>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    guard_manage(&state.db, &key, &model).await?;
    // A parameter is argv for the elevated command: a defaulted parameter on a root hook running
    // `/bin/sh` supplies `-c` and a command string without the caller ever editing `script_path`.
    guard_master_for_privileged_hook(&key, &model, "declare parameters on")?;

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
    StrictPath((identifier, param_id)): StrictPath<(String, Uuid)>,
    StrictJson(payload): StrictJson<UpdateParameterPayload>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    guard_manage(&state.db, &key, &model).await?;
    // Changing a `default_value` rewrites what the elevated command receives, so this needs the
    // same gate as declaring one.
    guard_master_for_privileged_hook(&key, &model, "modify parameters on")?;

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
    StrictPath((identifier, param_id)): StrictPath<(String, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let model = resolve_hook(&state.db, &identifier).await?;
    guard_manage(&state.db, &key, &model).await?;
    // Removing a required parameter shifts every positional argument after it, which changes the
    // elevated command just as surely as editing one.
    guard_master_for_privileged_hook(&key, &model, "remove parameters from")?;

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
