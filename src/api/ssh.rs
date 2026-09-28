//! Management API for SSH credentials and targets — the operator-facing surface behind
//! [`crate::ssh`]'s runner.
//!
//! # Why every mutation here is master-only
//!
//! `RBAC_MODEL.md` has no scope for "manage remote execution infrastructure" — its granular verbs
//! (`can_manage_hooks`, `can_manage_keys`) are about the resources this service already modeled
//! before SSH existed. An SSH credential is secret material capable of authenticating against
//! infrastructure *outside* this service entirely, and an SSH target names where that authority
//! reaches; delegating either is a materially different decision from delegating "can edit hook
//! definitions", and the RBAC spec (byte-identical across `simply_hook_executor`/`simply_ip_vault`,
//! enforced by `scripts/verify_convergence.sh`) is not a file this feature gets to extend casually.
//! Master-only for every write here is therefore the conservative reading, not a temporary
//! simplification — it mirrors this codebase's existing precedent for `run_as_user` (`AGENT.MD` §3:
//! "only Master API keys can assign a hook a `run_as_user`"), which is the one other place a hook's
//! configuration already reaches for elevated real-world capability.
//!
//! *Reading* the target list is the one exception: `list_ssh_targets`/`get_ssh_target` also accept
//! `can_manage_hooks`, because [`super::hooks`]'s create/edit UI needs to populate a target dropdown
//! for exactly the callers who are otherwise allowed to set a hook's `ssh_target_id` at all. A target
//! carries no secret of its own (`host`, `port`, `username`, a host key fingerprint are not
//! credentials), so widening *read* access here does not leak anything `guard_dispatch_configuration`
//! doesn't already gate on the write side. SSH credentials carry no equivalent exception: even
//! knowing *that* a given credential name exists is master-only.
//!
//! # Why secrets never round-trip
//!
//! [`SshCredentialView`] reports `has_private_key`/`has_passphrase`/`has_password` — booleans, never
//! the sealed columns themselves — the same shape [`super::hooks::HookDetail`]'s
//! `hmac_secret_configured` already established for `hooks.hmac_secret`. A secret is write-only from
//! the API's perspective: supplied once, sealed with [`crate::crypto::SecretCipher`], and from then
//! on only ever read back by [`crate::ssh::SshConnectionSpec::from_target_and_credential`] at
//! connection time — never by a JSON response.
//!
//! # Why credential/target deletion is refused at the application layer here, not by a DDL error
//!
//! `ssh_targets.credential_id` still carries a real `ON DELETE RESTRICT` foreign key (see
//! `migration::m20260928_090000_add_ssh_infrastructure`'s own doc comment), so deleting a
//! still-referenced credential *would* fail regardless — but `delete_ssh_credential` checks first and
//! reports which targets block it by name, rather than surfacing whatever the SQLite driver's
//! constraint-violation error happens to render. `hooks.ssh_target_id` has no DDL constraint at all
//! (the same doc comment explains why SQLite cannot add one to an existing table), so
//! `delete_ssh_target`'s equivalent check is not merely friendlier there — it is the *entire*
//! enforcement mechanism.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use chrono::{NaiveDateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, SqlErr,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::SecretCipher;
use crate::entities::{api_key, hook, prelude::*, ssh_credential, ssh_credential::SshAuthType, ssh_target};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;

use super::support::{create_audit_log, format_reference};

/// Bound on how long a connectivity test or fingerprint fetch may take. Independent of any hook's
/// own `default_timeout_seconds` — neither operation runs a command, so a hook's execution budget
/// has no bearing on it.
const SSH_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Seals `plaintext` for storage, mapping a cipher failure to [`AppError::Internal`] — the same
/// judgment call [`super::hooks::validate_and_seal_hmac_secret`] makes for the identical failure
/// mode: an encryption failure is a server condition, never something the caller's request caused.
fn seal_secret(cipher: &SecretCipher, plaintext: &str) -> Result<String, AppError> {
    cipher.seal(plaintext).map_err(|e| {
        tracing::error!("Failed to seal an SSH credential secret: {e}");
        AppError::Internal
    })
}

/// Resolves one secret field's effective sealed value for an update: a supplied value is sealed
/// fresh, `Some("")` clears it, and `None` (the field was not in the payload) keeps whatever is
/// already stored. Mirrors `super::hooks::validate_and_seal_hmac_secret`'s identical three-way split.
fn effective_sealed_secret(
    cipher: &SecretCipher,
    payload_value: Option<&str>,
    existing_sealed: Option<&str>,
) -> Result<Option<String>, AppError> {
    match payload_value {
        Some("") => Ok(None),
        Some(raw) => seal_secret(cipher, raw).map(Some),
        None => Ok(existing_sealed.map(str::to_owned)),
    }
}

/// Validates a TCP port number.
fn validate_port(port: i32) -> Result<(), AppError> {
    if !(1..=65535).contains(&port) {
        return Err(AppError::InvalidInput("port must be between 1 and 65535".to_owned()));
    }
    Ok(())
}

/// Validates that a host key fingerprint is at least shaped like one: `SHA256:<base64>`, exactly as
/// `ssh-keygen -lf` and [`crate::ssh::fetch_host_key_fingerprint`] both render it. Not a full base64
/// decode — this exists to catch an obviously wrong paste (the wrong hash algorithm's label, stray
/// whitespace, an empty value), not to re-validate what the fetch endpoint already produced
/// correctly.
fn validate_host_key_fingerprint(value: &str) -> Result<(), AppError> {
    let digest = value.strip_prefix("SHA256:").ok_or_else(|| {
        AppError::InvalidInput(
            "host_key_fingerprint must be in the form 'SHA256:<base64>', exactly as ssh-keygen -lf \
             (or this API's own fetch-fingerprint endpoint) prints it"
                .to_owned(),
        )
    })?;
    let looks_like_base64 =
        !digest.is_empty() && digest.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'));
    if !looks_like_base64 {
        return Err(AppError::InvalidInput(
            "host_key_fingerprint's digest (the part after 'SHA256:') must be base64 text"
                .to_owned(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// SSH credentials
// ─────────────────────────────────────────────────────────────

/// Payload for creating an SSH credential.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSshCredentialPayload {
    /// Unique, human-readable label.
    pub name: String,
    /// Which secret field below is required.
    pub auth_type: SshAuthType,
    /// The private key material, in PEM or OpenSSH format. Required when `auth_type` is `KEY`;
    /// ignored (but accepted) otherwise.
    pub private_key: Option<String>,
    /// The private key's passphrase, if it is encrypted. Optional even when `auth_type` is `KEY`;
    /// ignored (but accepted) when it is not.
    pub passphrase: Option<String>,
    /// The login password. Required when `auth_type` is `PASSWORD`; ignored (but accepted)
    /// otherwise.
    pub password: Option<String>,
}

/// Payload for updating an SSH credential. Every field is optional; omitted fields are left
/// untouched. Switching `auth_type` always drops the secret field(s) the *other* mode used, exactly
/// as switching a hook's `execution_type` to `LOCAL` always drops `ssh_target_id` — see
/// `super::hooks::UpdateHookPayload`'s equivalent doc comment.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSshCredentialPayload {
    /// New name.
    pub name: Option<String>,
    /// New `auth_type`.
    pub auth_type: Option<SshAuthType>,
    /// New private key. Send `""` to clear it (refused while the effective `auth_type` is `KEY`).
    pub private_key: Option<String>,
    /// New passphrase. Send `""` to clear it.
    pub passphrase: Option<String>,
    /// New password. Send `""` to clear it (refused while the effective `auth_type` is `PASSWORD`).
    pub password: Option<String>,
}

/// An SSH credential as the API ever shows it: never the secrets themselves, only whether each is
/// set.
#[derive(Serialize)]
pub struct SshCredentialView {
    /// Credential ID.
    pub id: Uuid,
    /// Credential name.
    pub name: String,
    /// Which secret field is in use.
    pub auth_type: SshAuthType,
    /// Whether a private key is stored.
    pub has_private_key: bool,
    /// Whether a passphrase is stored.
    pub has_passphrase: bool,
    /// Whether a password is stored.
    pub has_password: bool,
    /// Creation timestamp.
    pub created_at: NaiveDateTime,
    /// Last-update timestamp.
    pub updated_at: NaiveDateTime,
}

fn build_credential_view(model: ssh_credential::Model) -> SshCredentialView {
    SshCredentialView {
        id: model.id,
        name: model.name,
        auth_type: model.auth_type,
        has_private_key: model.encrypted_private_key.is_some(),
        has_passphrase: model.encrypted_passphrase.is_some(),
        has_password: model.encrypted_password.is_some(),
        created_at: model.created_at,
        updated_at: model.updated_at,
    }
}

/// Handles `POST /api/ssh-credentials`.
pub async fn create_ssh_credential(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateSshCredentialPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can manage SSH credentials".to_owned()));
    }

    let name = payload.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::InvalidInput("name is required".to_owned()));
    }

    // Only the field(s) the chosen mode actually uses are ever sealed and stored — a `password`
    // supplied alongside `auth_type: KEY` is silently ignored, the same "accepted but irrelevant"
    // treatment `super::hooks::CreateHookPayload::hmac_secret` gives a secret sent for a hook that
    // is not `HMAC_ONLY`.
    let (encrypted_private_key, encrypted_passphrase, encrypted_password) = match payload.auth_type {
        SshAuthType::Key => {
            let private_key = payload.private_key.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
                AppError::InvalidInput("private_key is required when auth_type is KEY".to_owned())
            })?;
            let sealed_key = seal_secret(&state.cipher, private_key)?;
            let sealed_passphrase = match payload.passphrase.as_deref().filter(|s| !s.is_empty()) {
                Some(p) => Some(seal_secret(&state.cipher, p)?),
                None => None,
            };
            (Some(sealed_key), sealed_passphrase, None)
        }
        SshAuthType::Password => {
            let password = payload.password.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
                AppError::InvalidInput("password is required when auth_type is PASSWORD".to_owned())
            })?;
            (None, None, Some(seal_secret(&state.cipher, password)?))
        }
    };

    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();
    let model = ssh_credential::ActiveModel {
        id: Set(id),
        name: Set(name.clone()),
        auth_type: Set(payload.auth_type),
        encrypted_private_key: Set(encrypted_private_key),
        encrypted_passphrase: Set(encrypted_passphrase),
        encrypted_password: Set(encrypted_password),
        created_at: Set(now),
        updated_at: Set(now),
    };
    if let Err(err) = SshCredential::insert(model).exec(&state.db).await {
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            return Err(AppError::Conflict(format!("An SSH credential named '{name}' already exists")));
        }
        return Err(err.into());
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "SSH_CREDENTIAL_CREATE",
        Some(name.clone()),
        Some(format!(
            "Created SSH credential {} ({:?})",
            format_reference(&name, id),
            payload.auth_type
        )),
    )
    .await?;

    let created = SshCredential::find_by_id(id).one(&state.db).await?.ok_or(AppError::Internal)?;
    Ok(Json(build_credential_view(created)))
}

/// Handles `GET /api/ssh-credentials`.
pub async fn list_ssh_credentials(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can view SSH credentials".to_owned()));
    }
    let models =
        SshCredential::find().order_by_asc(ssh_credential::Column::Name).all(&state.db).await?;
    Ok(Json(models.into_iter().map(build_credential_view).collect::<Vec<_>>()))
}

/// Handles `GET /api/ssh-credentials/{id}`.
pub async fn get_ssh_credential(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can view SSH credentials".to_owned()));
    }
    let model = SshCredential::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    Ok(Json(build_credential_view(model)))
}

/// Handles `PUT /api/ssh-credentials/{id}`.
pub async fn update_ssh_credential(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateSshCredentialPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can manage SSH credentials".to_owned()));
    }
    let model = SshCredential::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    let effective_auth_type = payload.auth_type.unwrap_or(model.auth_type);
    // Whichever field the *other* mode used is unconditionally cleared, not carried over — the same
    // "the new mode's field must come from this request" rule `api::hooks::update_hook` applies to
    // `ssh_target_id` when `execution_type` flips to `LOCAL`.
    let (encrypted_private_key, encrypted_passphrase, encrypted_password) = match effective_auth_type {
        SshAuthType::Key => (
            effective_sealed_secret(
                &state.cipher,
                payload.private_key.as_deref(),
                model.encrypted_private_key.as_deref(),
            )?,
            effective_sealed_secret(
                &state.cipher,
                payload.passphrase.as_deref(),
                model.encrypted_passphrase.as_deref(),
            )?,
            None,
        ),
        SshAuthType::Password => (
            None,
            None,
            effective_sealed_secret(
                &state.cipher,
                payload.password.as_deref(),
                model.encrypted_password.as_deref(),
            )?,
        ),
    };
    match effective_auth_type {
        SshAuthType::Key if encrypted_private_key.is_none() => {
            return Err(AppError::InvalidInput(
                "private_key cannot be cleared while auth_type is KEY".to_owned(),
            ));
        }
        SshAuthType::Password if encrypted_password.is_none() => {
            return Err(AppError::InvalidInput(
                "password cannot be cleared while auth_type is PASSWORD".to_owned(),
            ));
        }
        _ => {}
    }

    let mut changes: Vec<String> = Vec::new();
    let mut active: ssh_credential::ActiveModel = model.into();
    if let Some(name) = payload.name {
        let trimmed = name.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("name must not be empty".to_owned()));
        }
        changes.push(format!("name={trimmed}"));
        active.name = Set(trimmed);
    }
    if payload.auth_type.is_some() {
        changes.push(format!("auth_type={effective_auth_type:?}"));
    }
    active.auth_type = Set(effective_auth_type);
    active.encrypted_private_key = Set(encrypted_private_key);
    active.encrypted_passphrase = Set(encrypted_passphrase);
    active.encrypted_password = Set(encrypted_password);
    if payload.private_key.is_some() || payload.passphrase.is_some() || payload.password.is_some() {
        changes.push("secret material".to_owned());
    }
    active.updated_at = Set(Utc::now().naive_utc());

    let updated = match active.update(&state.db).await {
        Ok(m) => m,
        Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            return Err(AppError::Conflict("Another SSH credential already uses that name".to_owned()));
        }
        Err(err) => return Err(err.into()),
    };

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "SSH_CREDENTIAL_UPDATE",
        Some(updated.name.clone()),
        Some(format!(
            "Updated SSH credential {} [{}]",
            format_reference(&updated.name, id),
            changes.join(", ")
        )),
    )
    .await?;

    Ok(Json(build_credential_view(updated)))
}

/// Handles `DELETE /api/ssh-credentials/{id}`.
pub async fn delete_ssh_credential(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can manage SSH credentials".to_owned()));
    }
    let model = SshCredential::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    let blocking = SshTarget::find().filter(ssh_target::Column::CredentialId.eq(id)).all(&state.db).await?;
    if !blocking.is_empty() {
        let names: Vec<String> = blocking.iter().map(|t| t.name.clone()).collect();
        return Err(AppError::Conflict(format!(
            "Cannot delete SSH credential '{}': still used by target(s): {}",
            model.name,
            names.join(", ")
        )));
    }

    SshCredential::delete_by_id(id).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "SSH_CREDENTIAL_DELETE",
        Some(model.name.clone()),
        Some(format!("Deleted SSH credential {}", format_reference(&model.name, id))),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// SSH targets
// ─────────────────────────────────────────────────────────────

/// Payload for creating an SSH target.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSshTargetPayload {
    /// Unique, human-readable label.
    pub name: String,
    /// Hostname or IP address.
    pub host: String,
    /// TCP port. Defaults to `22`.
    pub port: Option<i32>,
    /// The remote account to authenticate as.
    pub username: String,
    /// The credential to authenticate with.
    pub credential_id: Uuid,
    /// The pinned host key fingerprint, in `SHA256:<base64>` form — typically the value
    /// `POST /api/ssh-targets/fetch-fingerprint` returned and the operator confirmed out of band.
    /// `None` leaves the target unpinned, which [`crate::ssh::SshConnectionSpec`] refuses to connect
    /// with at all.
    pub host_key_fingerprint: Option<String>,
}

/// Payload for updating an SSH target. Every field is optional; omitted fields are left untouched.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSshTargetPayload {
    /// New name.
    pub name: Option<String>,
    /// New host.
    pub host: Option<String>,
    /// New port.
    pub port: Option<i32>,
    /// New username.
    pub username: Option<String>,
    /// New credential.
    pub credential_id: Option<Uuid>,
    /// New pinned fingerprint. Send `""` to unpin (refuses every future connection until a new one
    /// is set).
    pub host_key_fingerprint: Option<String>,
}

/// An SSH target plus the resolved name of the credential it authenticates with, so a listing needs
/// no follow-up request to render meaningfully.
#[derive(Serialize)]
pub struct SshTargetView {
    /// Target ID.
    pub id: Uuid,
    /// Target name.
    pub name: String,
    /// Hostname or IP address.
    pub host: String,
    /// TCP port.
    pub port: i32,
    /// The remote account authenticated as.
    pub username: String,
    /// The credential this target authenticates with.
    pub credential_id: Uuid,
    /// That credential's name, resolved for display.
    pub credential_name: String,
    /// The pinned host key fingerprint, or `None` if unpinned.
    pub host_key_fingerprint: Option<String>,
    /// Creation timestamp.
    pub created_at: NaiveDateTime,
    /// Last-update timestamp.
    pub updated_at: NaiveDateTime,
}

async fn build_target_view(
    db: &sea_orm::DatabaseConnection,
    model: ssh_target::Model,
) -> Result<SshTargetView, AppError> {
    // `credential_id` cannot dangle in practice (`ON DELETE RESTRICT`), but this reads the row
    // fresh rather than assuming that, so a `None` here degrades to a label instead of a panic if it
    // ever somehow did.
    let credential_name = SshCredential::find_by_id(model.credential_id)
        .one(db)
        .await?
        .map(|c| c.name)
        .unwrap_or_else(|| "(unknown)".to_owned());
    Ok(SshTargetView {
        id: model.id,
        name: model.name,
        host: model.host,
        port: model.port,
        username: model.username,
        credential_id: model.credential_id,
        credential_name,
        host_key_fingerprint: model.host_key_fingerprint,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

/// Handles `POST /api/ssh-targets`.
pub async fn create_ssh_target(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateSshTargetPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can manage SSH targets".to_owned()));
    }

    let name = payload.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::InvalidInput("name is required".to_owned()));
    }
    let host = payload.host.trim().to_owned();
    if host.is_empty() {
        return Err(AppError::InvalidInput("host is required".to_owned()));
    }
    let username = payload.username.trim().to_owned();
    if username.is_empty() {
        return Err(AppError::InvalidInput("username is required".to_owned()));
    }
    let port = payload.port.unwrap_or(22);
    validate_port(port)?;
    if let Some(fingerprint) = &payload.host_key_fingerprint {
        validate_host_key_fingerprint(fingerprint)?;
    }
    if SshCredential::find_by_id(payload.credential_id).one(&state.db).await?.is_none() {
        return Err(AppError::InvalidInput(
            "credential_id does not name an existing SSH credential".to_owned(),
        ));
    }

    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();
    let model = ssh_target::ActiveModel {
        id: Set(id),
        name: Set(name.clone()),
        host: Set(host.clone()),
        port: Set(port),
        username: Set(username.clone()),
        credential_id: Set(payload.credential_id),
        host_key_fingerprint: Set(payload.host_key_fingerprint.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };
    if let Err(err) = SshTarget::insert(model).exec(&state.db).await {
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            return Err(AppError::Conflict(format!("An SSH target named '{name}' already exists")));
        }
        return Err(err.into());
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "SSH_TARGET_CREATE",
        Some(name.clone()),
        Some(format!(
            "Created SSH target {} -> {username}@{host}:{port}",
            format_reference(&name, id)
        )),
    )
    .await?;

    let created = SshTarget::find_by_id(id).one(&state.db).await?.ok_or(AppError::Internal)?;
    Ok(Json(build_target_view(&state.db, created).await?))
}

/// Handles `GET /api/ssh-targets`. Also readable by `can_manage_hooks` — see this module's own doc
/// comment on why.
pub async fn list_ssh_targets(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_hooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }
    let models = SshTarget::find().order_by_asc(ssh_target::Column::Name).all(&state.db).await?;
    let mut views = Vec::with_capacity(models.len());
    for model in models {
        views.push(build_target_view(&state.db, model).await?);
    }
    Ok(Json(views))
}

/// Handles `GET /api/ssh-targets/{id}`. Also readable by `can_manage_hooks` — see this module's own
/// doc comment on why.
pub async fn get_ssh_target(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_hooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }
    let model = SshTarget::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    Ok(Json(build_target_view(&state.db, model).await?))
}

/// Handles `PUT /api/ssh-targets/{id}`.
pub async fn update_ssh_target(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateSshTargetPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can manage SSH targets".to_owned()));
    }
    let model = SshTarget::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    if let Some(port) = payload.port {
        validate_port(port)?;
    }
    if let Some(fingerprint) = payload.host_key_fingerprint.as_deref()
        && !fingerprint.is_empty()
    {
        validate_host_key_fingerprint(fingerprint)?;
    }
    if let Some(credential_id) = payload.credential_id
        && SshCredential::find_by_id(credential_id).one(&state.db).await?.is_none()
    {
        return Err(AppError::InvalidInput(
            "credential_id does not name an existing SSH credential".to_owned(),
        ));
    }

    let mut changes: Vec<String> = Vec::new();
    let mut active: ssh_target::ActiveModel = model.into();
    if let Some(name) = payload.name {
        let trimmed = name.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("name must not be empty".to_owned()));
        }
        changes.push(format!("name={trimmed}"));
        active.name = Set(trimmed);
    }
    if let Some(host) = payload.host {
        let trimmed = host.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("host must not be empty".to_owned()));
        }
        changes.push(format!("host={trimmed}"));
        active.host = Set(trimmed);
    }
    if let Some(port) = payload.port {
        changes.push(format!("port={port}"));
        active.port = Set(port);
    }
    if let Some(username) = payload.username {
        let trimmed = username.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("username must not be empty".to_owned()));
        }
        changes.push(format!("username={trimmed}"));
        active.username = Set(trimmed);
    }
    if let Some(credential_id) = payload.credential_id {
        changes.push(format!("credential_id={credential_id}"));
        active.credential_id = Set(credential_id);
    }
    if let Some(fingerprint) = payload.host_key_fingerprint {
        changes.push("host_key_fingerprint".to_owned());
        active.host_key_fingerprint = Set(if fingerprint.is_empty() { None } else { Some(fingerprint) });
    }
    active.updated_at = Set(Utc::now().naive_utc());

    let updated = match active.update(&state.db).await {
        Ok(m) => m,
        Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            return Err(AppError::Conflict("Another SSH target already uses that name".to_owned()));
        }
        Err(err) => return Err(err.into()),
    };

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "SSH_TARGET_UPDATE",
        Some(updated.name.clone()),
        Some(format!(
            "Updated SSH target {} [{}]",
            format_reference(&updated.name, id),
            changes.join(", ")
        )),
    )
    .await?;

    Ok(Json(build_target_view(&state.db, updated).await?))
}

/// Handles `DELETE /api/ssh-targets/{id}`.
pub async fn delete_ssh_target(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can manage SSH targets".to_owned()));
    }
    let model = SshTarget::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    let blocking = Hook::find().filter(hook::Column::SshTargetId.eq(id)).all(&state.db).await?;
    if !blocking.is_empty() {
        let names: Vec<String> = blocking.iter().map(|h| h.name.clone()).collect();
        return Err(AppError::Conflict(format!(
            "Cannot delete SSH target '{}': still used by hook(s): {}",
            model.name,
            names.join(", ")
        )));
    }

    SshTarget::delete_by_id(id).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "SSH_TARGET_DELETE",
        Some(model.name.clone()),
        Some(format!("Deleted SSH target {}", format_reference(&model.name, id))),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// The result of a connectivity test — always `200`, success or failure alike, matching
/// `super::executions::test_hook`'s established "a probe's outcome is data, not an error" contract.
#[derive(Serialize)]
pub struct TestSshConnectionResponse {
    /// Whether the connection and authentication succeeded.
    pub success: bool,
    /// A human-readable outcome description.
    pub message: String,
}

/// Handles `POST /api/ssh-targets/{id}/test-connection` — connects, verifies the pinned host key,
/// authenticates, and disconnects, without running anything.
pub async fn test_ssh_target_connection(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can test SSH targets".to_owned()));
    }
    let target = SshTarget::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let credential = SshCredential::find_by_id(target.credential_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::Internal)?;

    let spec = match crate::ssh::SshConnectionSpec::from_target_and_credential(
        &state.cipher,
        &target,
        &credential,
    ) {
        Ok(spec) => spec,
        // An unpinned target (`AppError::InvalidInput`) is exactly the kind of "why it can't be
        // tested" fact this endpoint exists to report, not a malformed *request* — the request
        // (a bare target id) was perfectly well-formed.
        Err(AppError::InvalidInput(message)) => {
            return Ok(Json(TestSshConnectionResponse { success: false, message }));
        }
        Err(err) => return Err(err),
    };

    match crate::ssh::test_connection(&spec, SSH_PROBE_TIMEOUT).await {
        Ok(()) => Ok(Json(TestSshConnectionResponse {
            success: true,
            message: "Connected and authenticated successfully".to_owned(),
        })),
        Err(e) => Ok(Json(TestSshConnectionResponse { success: false, message: e.to_string() })),
    }
}

/// Payload for `POST /api/ssh-targets/fetch-fingerprint`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchFingerprintPayload {
    /// Hostname or IP address to connect to.
    pub host: String,
    /// TCP port. Defaults to `22`.
    pub port: Option<i32>,
}

/// The result of a fingerprint fetch — always `200`, matching [`TestSshConnectionResponse`]'s
/// contract.
#[derive(Serialize)]
pub struct FetchFingerprintResponse {
    /// Whether a host key was successfully observed.
    pub success: bool,
    /// The observed fingerprint, `SHA256:<base64>`, when `success` is `true`.
    pub fingerprint: Option<String>,
    /// A human-readable failure description, when `success` is `false`.
    pub message: Option<String>,
}

/// Handles `POST /api/ssh-targets/fetch-fingerprint` — the one step in this deployment's
/// trust-on-first-use model: connects to a bare `host:port` (no target needs to exist yet), records
/// whatever host key it offers, and disconnects without authenticating.
///
/// The returned fingerprint is not stored by this call. The operator is expected to confirm it out
/// of band (the host's own documentation, a provisioning system, a phone call to whoever built it)
/// and then paste it into `host_key_fingerprint` on a create/update — this endpoint answers "what key
/// is this host presenting", not "is this the right key", which nothing server-side can determine on
/// its own.
pub async fn fetch_ssh_host_fingerprint(
    Extension(key): Extension<api_key::Model>,
    StrictJson(payload): StrictJson<FetchFingerprintPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can fetch an SSH host key fingerprint".to_owned(),
        ));
    }
    let host = payload.host.trim().to_owned();
    if host.is_empty() {
        return Err(AppError::InvalidInput("host is required".to_owned()));
    }
    let port = payload.port.unwrap_or(22);
    validate_port(port)?;
    // Infallible after `validate_port`: every value in `1..=65535` fits `u16`.
    let port = u16::try_from(port).unwrap_or(22);

    match crate::ssh::fetch_host_key_fingerprint(&host, port, SSH_PROBE_TIMEOUT).await {
        Ok(fingerprint) => {
            Ok(Json(FetchFingerprintResponse { success: true, fingerprint: Some(fingerprint), message: None }))
        }
        Err(e) => {
            Ok(Json(FetchFingerprintResponse { success: false, fingerprint: None, message: Some(e.to_string()) }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_port_range() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(22).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
        assert!(validate_port(65536).is_err());
        assert!(validate_port(-1).is_err());
    }

    #[test]
    fn validates_host_key_fingerprint_shape() {
        assert!(validate_host_key_fingerprint("SHA256:abcDEF12+/34").is_ok());
        assert!(validate_host_key_fingerprint("MD5:aa:bb:cc").is_err());
        assert!(validate_host_key_fingerprint("SHA256:").is_err());
        assert!(validate_host_key_fingerprint("not-a-fingerprint").is_err());
        assert!(validate_host_key_fingerprint("SHA256:has space").is_err());
    }

    #[test]
    fn effective_secret_seals_clears_or_keeps() {
        let cipher = SecretCipher::Plaintext;
        // Supplied: sealed fresh, and recoverable.
        let sealed = effective_sealed_secret(&cipher, Some("hunter2"), None).unwrap();
        assert_eq!(cipher.open(sealed.as_deref().unwrap()).unwrap(), "hunter2");
        // Empty string: cleared.
        assert_eq!(effective_sealed_secret(&cipher, Some(""), sealed.as_deref()).unwrap(), None);
        // Absent: existing value kept untouched.
        assert_eq!(
            effective_sealed_secret(&cipher, None, sealed.as_deref()).unwrap(),
            sealed
        );
    }
}
