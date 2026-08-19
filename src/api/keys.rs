//! API key lifecycle, identity, and per-hook grants.
//!
//! Holds `GET /api/auth/me` as well as key CRUD, because the coupling audit showed the two share
//! their view types: [`HookPermissionView`] and `load_hook_permissions` are used by the identity
//! response and by the key listing alike, and "what does this key hold" is the same question in
//! both. Splitting them would have put one type in a module and its only two callers in another.
//!
//! Also holds the §6 cascade: deleting a key walks its subtree, inventories everything those keys
//! own, and refuses until the caller resolves each entity explicitly.
//!
//! # Why the §4 key-visibility helpers live here rather than in [`super::guards`]
//!
//! `guards.rs` is one module because `RBAC_MODEL.md`'s rules are cross-cutting and splitting one by
//! caller would put a single sentence of the specification in three files. §4's *key-subtree*
//! visibility is the one part that does not fit that argument: it is consulted by exactly one domain
//! — this one — and `KeyVisibility`, `descendant_key_ids`, `managed_hook_ids`, `key_visibility` and
//! `load_administrable_key` form a closed cluster calling only each other. Moving them therefore
//! cannot scatter a rule; it just puts it where its only consumer is.
//!
//! All five are **module-private**, which is what makes "only this domain uses it" a fact the
//! compiler checks rather than a claim in a comment. If a second domain ever needs one, the build
//! breaks and the choice becomes explicit: widen the visibility and accept that it is cross-domain
//! after all, or move the cluster back. Both are better than it drifting.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait,
    QueryFilter, QueryOrder, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key::HmacMode, api_key_hook_permission, hook, prelude::*,
};
use crate::error::AppError;
use crate::extract::{OptionalStrictJson, StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;


use super::guards::{
    guard_canonical_v1_for_key_management, guard_delegated_hook_grant,
    has_permission_admin_standing, hook_permission, is_permission_reduction,
    refuse_master_lifecycle_action, guard_hook_manage_conjunction,
    guard_master_for_privileged_hook, guard_master_self_edit_is_bound_ips_only,
    guard_master_to_administer, guard_master_to_grant_scopes,
};
use super::support::{
    create_audit_log, describe_hmac_mode, format_reference, generate_random_key, hash_key,
    mint_signing_pair, resolve_hook, validate_bound_ips, validate_concurrency,
};

// ─────────────────────────────────────────────────────────────
// §4 key-subtree visibility
// ─────────────────────────────────────────────────────────────
//
// "How much of *another key* may this caller see" — see the module header for why these are here
// and not in `guards.rs`, and `AGENT.MD` §0 for the boundary it draws.
//
// They are authorization logic and are held to `guards.rs`'s discipline regardless of which file
// they sit in: each returns `Result<_, AppError>`, none writes anything, and the `None`/`404` answer
// is §4's oracle discipline — it must be indistinguishable from what a nonexistent id produces, so
// every caller propagates it unchanged rather than turning it into a `403`.
//
// §4's *hook* visibility deliberately stayed in `guards.rs`: three domains consult it.

/// How much of a key another key is entitled to see (`RBAC_MODEL.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyVisibility {
    /// **Own subtree.** "A parent sees its own key subtree in full, minus raw secrets — its
    /// daughters, their granted rights, and their bound IPs." Also covers the caller itself.
    Full,
    /// **Shared resource, minimal form.** "A parent sees, in minimal form only, any key holding a
    /// permission row on a resource it manages: id, name, and that key's rights on that resource
    /// alone. Global flags, bound IPs, and unrelated resource memberships remain hidden."
    ///
    /// The sentence that gives this scope its shape is the next one: "A single shared resource must
    /// never become a keyhole into another parent's whole configuration."
    Minimal,
}

/// Every key descended from `root`, transitively, **excluding `root` itself**.
///
/// Breadth-first over `parent_key_id`, one indexed query per level rather than one per key. The
/// `seen` set is not an optimization: `parent_key_id` carries no database-level constraint
/// preventing a cycle (see the migration's note on why there is no FK), and a cycle here would spin
/// forever inside a request handler.
async fn descendant_key_ids(
    db: &sea_orm::DatabaseConnection,
    root: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    let mut frontier = vec![root];

    while !frontier.is_empty() {
        let children: Vec<Uuid> = ApiKey::find()
            .filter(api_key::Column::ParentKeyId.is_in(frontier.clone()))
            .all(db)
            .await?
            .into_iter()
            .map(|k| k.id)
            .collect();

        frontier = children.into_iter().filter(|id| *id != root && seen.insert(*id)).collect();
    }

    Ok(seen.into_iter().collect())
}

/// The hooks this key holds a `can_manage` row on — the resources whose *other* holders it is
/// entitled to see in minimal form.
async fn managed_hook_ids(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    Ok(ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key_id))
        .filter(api_key_hook_permission::Column::CanManage.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.hook_id)
        .collect())
}

/// How much of `target` the caller may see, or `None` for "not visible at all".
///
/// `None` is the answer that has to be handled carefully by every caller: under §4's oracle
/// discipline it must produce exactly what a nonexistent id produces, never a `403` that confirms
/// the id is real.
async fn key_visibility(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    target: &api_key::Model,
) -> Result<Option<KeyVisibility>, AppError> {
    // "Master: full visibility over all keys, resources, dispatch targets, and configuration."
    if caller.is_master || caller.id == target.id {
        return Ok(Some(KeyVisibility::Full));
    }

    // Own subtree, transitively. Note this reads `parent_key_id` for *visibility scoping*, which is
    // the one use R3 explicitly sanctions — "`parent_key_id` exists solely for cascading deletion
    // and visibility scoping" — and never to decide whether an action is permitted.
    if descendant_key_ids(db, caller.id).await?.contains(&target.id) {
        return Ok(Some(KeyVisibility::Full));
    }

    // Shared resource: does the target hold a row on any hook the caller manages?
    let managed = managed_hook_ids(db, caller.id).await?;
    if !managed.is_empty() {
        let shares = ApiKeyHookPermission::find()
            .filter(api_key_hook_permission::Column::ApiKeyId.eq(target.id))
            .filter(api_key_hook_permission::Column::HookId.is_in(managed))
            .one(db)
            .await?
            .is_some();
        if shares {
            return Ok(Some(KeyVisibility::Minimal));
        }
    }

    Ok(None)
}

/// Loads a key the caller is entitled to *administer*, or `404`.
///
/// Administering the key entity — updating, deleting, rotating it — needs
/// [`KeyVisibility::Full`]: the caller's own subtree, or master. A key met only through a shared
/// resource is visible in minimal form and is **not** administrable; §4 gives that scope precisely
/// "id, name, and that key's rights on that resource alone", which is a window, not a handle.
///
/// Every refusal is `404`, matching what a key id that does not exist produces. A `403` here would
/// turn `PUT /api/keys/{uuid}` into a key-enumeration oracle for any `can_manage_keys` holder.
async fn load_administrable_key(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    id: Uuid,
) -> Result<api_key::Model, AppError> {
    let target = ApiKey::find_by_id(id).one(db).await?.ok_or(AppError::NotFound)?;
    match key_visibility(db, caller, &target).await? {
        Some(KeyVisibility::Full) => Ok(target),
        _ => {
            tracing::warn!(
                key = %caller.prefix,
                target = %id,
                "§4: key outside the caller's administrable scope; refused as nonexistent"
            );
            Err(AppError::NotFound)
        }
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
    /// Whether the key may read the hook's execution records.
    ///
    /// Reported so a caller can tell why it can or cannot see history without guessing. The
    /// dashboard renders it as a `V` badge alongside `X` and `M`, and the §4 status split depends on
    /// callers being able to read their own rows: a `403` rather than a `404` on a manage route is
    /// only non-leaking because `GET /api/auth/me` already told the caller what it holds.
    pub can_view_execution: bool,
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
    /// Signature verification mode this key's requests are checked under.
    pub hmac_mode: HmacMode,
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
pub(crate) async fn load_hook_permissions(
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
                can_view_execution: perm.can_view_execution,
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
        hmac_mode: key.hmac_mode,
        bound_ips: key.bound_ips,
        max_concurrent_jobs: key.max_concurrent_jobs,
        is_master: key.is_master,
        can_manage_keys: key.can_manage_keys,
        can_manage_hooks: key.can_manage_hooks,
        hook_permissions,
    }))
}


// ─────────────────────────────────────────────────────────────
// Admin CRUD — API keys
// ─────────────────────────────────────────────────────────────

/// Payload for creating an API key.
///
/// Carries **no `is_master` field**, per `RBAC_MODEL.md` §5: master status is not settable through
/// any endpoint, and the only key that ever holds it is the one [`crate::main`] mints at bootstrap
/// against an empty table.
///
/// `deny_unknown_fields` is what turns that omission into an actual refusal rather than a silent
/// one. Serde ignores unknown fields by default, so without it `{"name":"x","is_master":true}`
/// would return `200` and a perfectly ordinary key — leaving the caller believing it had minted a
/// master, and leaving an operator reading the audit log with no record that anyone tried. Strict
/// deserialization makes the attempt an explicit `400` naming the field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyPayload {
    /// Human-readable name.
    pub name: String,
    /// Comma-separated CIDR allowlist.
    pub bound_ips: Option<String>,
    /// Simultaneous execution budget. Defaults to 10.
    pub max_concurrent_jobs: Option<i32>,
    /// Signature verification mode. Defaults to `CANONICAL_V1`; `BODY_ONLY` opts out of replay
    /// protection for third-party webhook senders whose format cannot be changed.
    ///
    /// **Fixed for the key's entire life.** Set here or never; `UpdateApiKeyPayload` carries no
    /// `hmac_mode` field at all, so there is no request that can change it later. A security level a
    /// key can downgrade itself into (or be downgraded into) after the fact is not a fixed level —
    /// this is the guarantee `can_manage_keys` below leans on: once granted to a `CANONICAL_V1` key,
    /// it cannot be left holding that scope while quietly weakened to `BODY_ONLY`.
    pub hmac_mode: Option<HmacMode>,
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
    /// Public key identifier, for display and log correlation. Not a secret, and not a credential:
    /// it stays retrievable from `GET /api/keys` afterwards and is never sent as an auth header.
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
    /// Signature verification mode.
    pub hmac_mode: HmacMode,
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
/// The minimal form §4 permits a parent to see of a key it meets only through a shared resource:
/// "id, name, and that key's rights on that resource alone."
///
/// A separate type rather than an `ApiKeySummary` with fields blanked out, so that adding a field
/// to the full summary cannot silently widen this one. The compiler has to be told, every time.
#[derive(Serialize)]
pub struct MinimalApiKeyView {
    /// Key ID.
    pub id: Uuid,
    /// Key name.
    pub name: String,
    /// This key's rights **on the shared hooks only** — never its other memberships.
    pub hook_permissions: Vec<HookPermissionView>,
    /// Marks the entry as abridged, so a client can tell "no global scopes" from "not shown".
    /// Without it a minimal view is indistinguishable from a key that genuinely holds nothing.
    pub partial: bool,
}

/// One entry in a key listing, at whichever detail §4 entitles the caller to.
#[derive(Serialize)]
#[serde(untagged)]
pub enum ApiKeyView {
    /// Own subtree, or master.
    Full(Box<ApiKeySummary>),
    /// Met only through a shared resource.
    Minimal(MinimalApiKeyView),
}

/// Builds the minimal view, restricting the permission list to the shared hooks.
pub(crate) async fn build_minimal_api_key_view(
    db: &sea_orm::DatabaseConnection,
    model: api_key::Model,
    shared_hook_ids: &[Uuid],
) -> Result<MinimalApiKeyView, AppError> {
    let rows = ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(model.id))
        .filter(api_key_hook_permission::Column::HookId.is_in(shared_hook_ids.to_vec()))
        .find_also_related(Hook)
        .all(db)
        .await?;

    Ok(MinimalApiKeyView {
        id: model.id,
        name: model.name,
        hook_permissions: rows
            .into_iter()
            .filter_map(|(perm, hook)| {
                hook.map(|h| HookPermissionView {
                    hook_id: perm.hook_id,
                    hook_name: h.name,
                    can_execute: perm.can_execute,
                    can_manage: perm.can_manage,
                    // Still §4-minimal: this is the target key's rights *on the shared hook alone*,
                    // which the shared-resource scope explicitly permits ("that key's rights on that
                    // resource alone"). No global flag or unrelated membership is added by it.
                    can_view_execution: perm.can_view_execution,
                })
            })
            .collect(),
        partial: true,
    })
}

pub(crate) async fn build_api_key_summary(
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
        hmac_mode: model.hmac_mode,
        bound_ips: model.bound_ips,
        max_concurrent_jobs: model.max_concurrent_jobs,
        is_master: model.is_master,
        can_manage_keys: model.can_manage_keys,
        can_manage_hooks: model.can_manage_hooks,
        created_at: model.created_at,
        hook_permissions,
    })
}


/// Handles `POST /api/keys`.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // Checked before any field validation, for the same reason `run_as_user` is in the hook
    // handlers: an escalation attempt must surface as `403` rather than be masked by a `400` about
    // some unrelated field in the same payload.
    guard_master_to_grant_scopes(&key, payload.can_manage_keys, payload.can_manage_hooks)?;

    // Computed here, ahead of the other field validation below, so the mandatory-CANONICAL_V1
    // guard can run in the same "authorization before validation" position as the guard above —
    // and so it is set exactly once, since `hmac_mode` is immutable from here on.
    let hmac_mode = payload.hmac_mode.unwrap_or_default();
    guard_canonical_v1_for_key_management(payload.can_manage_keys.unwrap_or(false), hmac_mode)?;

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
        hmac_mode: Set(hmac_mode),
        bound_ips: Set(payload.bound_ips.clone()),
        max_concurrent_jobs: Set(max_concurrent_jobs),
        // Hard-wired, not read from the payload. There is no field to read, and the database's
        // `master_marker` unique index would reject the row even if there were.
        is_master: Set(false),
        // Lineage and ownership both start at the creator. They may diverge later — master can
        // reassign ownership (§3) — but lineage never changes, because §6's cascade has to be able
        // to answer "which keys came from this one" long after custody has moved.
        parent_key_id: Set(Some(key.id)),
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
        Some(format!(
            "Created key {} ({})",
            format_reference(&payload.name, id),
            describe_hmac_mode(hmac_mode)
        )),
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

    // §4. Previously this returned a full `ApiKeySummary` — global flags, `bound_ips`, and every
    // hook membership — for *every key in the deployment* to any `can_manage_keys` holder. One
    // shared hook was enough to read another parent's entire configuration, which is precisely the
    // "keyhole" §4 names.
    let keys = ApiKey::find().order_by_asc(api_key::Column::CreatedAt).all(&state.db).await?;
    // Computed once for the whole listing rather than per key: the alternative is two extra queries
    // per row, and neither answer changes within a single request.
    let subtree = if key.is_master {
        Vec::new()
    } else {
        descendant_key_ids(&state.db, key.id).await?
    };
    let managed = if key.is_master {
        Vec::new()
    } else {
        managed_hook_ids(&state.db, key.id).await?
    };
    let shared_holders: std::collections::HashSet<Uuid> = if managed.is_empty() {
        std::collections::HashSet::new()
    } else {
        ApiKeyHookPermission::find()
            .filter(api_key_hook_permission::Column::HookId.is_in(managed.clone()))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.api_key_id)
            .collect()
    };

    let mut views = Vec::with_capacity(keys.len());
    for model in keys {
        if key.is_master || model.id == key.id || subtree.contains(&model.id) {
            views.push(ApiKeyView::Full(Box::new(
                build_api_key_summary(&state.db, model).await?,
            )));
        } else if shared_holders.contains(&model.id) {
            views.push(ApiKeyView::Minimal(
                build_minimal_api_key_view(&state.db, model, &managed).await?,
            ));
        }
        // Otherwise omitted entirely — a key outside every scope is not listed at all, which is the
        // listing form of oracle discipline: absent and invisible look the same.
    }
    Ok(Json(views))
}

/// Payload for updating an existing API key. Excludes `is_master`: promoting or demoting master
/// status is deliberately not exposed through a generic update endpoint (`RBAC_MODEL.md` §5).
///
/// Strict for the same reason as [`CreateApiKeyPayload`] — an `is_master` here must be refused
/// aloud, not dropped on the floor.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateApiKeyPayload {
    /// New name.
    pub name: Option<String>,
    /// New bound CIDRs.
    pub bound_ips: Option<String>,
    /// New concurrency budget.
    pub max_concurrent_jobs: Option<i32>,
    // No `hmac_mode`, deliberately. It is fixed at creation and immutable for the rest of the key's
    // life — see the module note on `CreateApiKeyPayload`'s `hmac_mode` field for why. Removed from
    // the payload type rather than accepted-and-ignored, for the same reason `is_master` is absent:
    // `deny_unknown_fields` above is what turns an attempt to change it into a `400` naming the
    // field, instead of a silently no-op `200` that leaves the caller believing it took effect.
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
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = load_administrable_key(&state.db, &key, id).await?;

    // Editing a master key is master-only: `bound_ips` alone would otherwise let a key manager
    // widen (or strand) the network binding of the system's root credential.
    guard_master_to_administer(&key, &target, "update")?;
    // ...and even for the master itself, `bound_ips` is the *only* field it reaches.
    guard_master_self_edit_is_bound_ips_only(&key, &target, &payload)?;
    // `UpdateApiKeyPayload` deliberately carries no `is_master` field, so promotion is impossible
    // through this route regardless; the other two global scopes still need the gate.
    guard_master_to_grant_scopes(&key, payload.can_manage_keys, payload.can_manage_hooks)?;

    // The *effective* can_manage_keys after this update, against the target's current — and, since
    // `hmac_mode` is immutable, permanent — signature mode. An omitted `can_manage_keys` in the
    // payload means "leave it as it is", so the target's own current value is the fallback rather
    // than `false`; using `false` here would let this guard be bypassed by simply not mentioning
    // the field on a key that already (illegitimately) held both.
    let effective_can_manage_keys = payload.can_manage_keys.unwrap_or(target.can_manage_keys);
    guard_canonical_v1_for_key_management(effective_can_manage_keys, target.hmac_mode)?;

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

/// One entity a key subtree owns, as reported by the pre-flight inventory (`RBAC_MODEL.md` §6:
/// "type, id, name, and current owner").
#[derive(Serialize)]
pub struct OwnedEntity {
    /// What kind of thing this is. Currently always `"hook"`: hooks are the only owned entity in
    /// this service (see the terminology note in `AGENT_NOTES.MD`). The field is present anyway,
    /// because §6 specifies it and because a second owned type must not change the payload shape.
    #[serde(rename = "type")]
    pub entity_type: &'static str,
    /// The entity's id, and the key a resolution is addressed to.
    pub id: Uuid,
    /// Human-readable name, so an operator can decide without a second lookup.
    pub name: String,
    /// The key inside the doomed subtree that currently owns it.
    pub current_owner: Uuid,
}

/// One key scheduled for deletion by the cascade.
#[derive(Serialize)]
pub struct DoomedKey {
    /// Key id.
    pub id: Uuid,
    /// Key name.
    pub name: String,
}

/// What the caller wants done with one inventoried entity.
///
/// Externally tagged on `action` so the two arms read as `{"action":"delete"}` and
/// `{"action":"reassign","to":"<key-id>"}`. There is deliberately no "leave it" arm: §6 requires
/// every entity to carry an *explicit* resolution, and "do nothing" would silently orphan it —
/// which is the outcome the inventory exists to prevent.
#[derive(Deserialize, Clone, Copy)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityResolution {
    /// Move the entity to the trash. Soft, like every other deletion in this service, so execution
    /// history survives and the 92-day purge remains the only thing that destroys it.
    Delete,
    /// Hand the entity to another key, which must exist and must not itself be in the subtree.
    Reassign {
        /// The new owner.
        to: Uuid,
    },
}

/// Optional body for `DELETE /api/keys/{id}`, carrying the resolution map on resubmission.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeleteApiKeyPayload {
    /// One entry per inventoried entity, keyed by its id. Partial maps are refused.
    #[serde(default)]
    pub resolutions: std::collections::HashMap<Uuid, EntityResolution>,
}

/// The machine-readable half of the refusal §6 specifies, merged into the `409 Conflict` body.
///
/// Carries no `error` field: the human-readable sentence is
/// [`AppError::ConflictWithDetails::message`], which renders it into the same `error` key every
/// other refusal in the service uses. Keeping the message out of this struct is what stops the two
/// from drifting into a body with two summaries, or none.
///
/// These fields land at the **top level** of the response — `{"error":…, "subtree":[…],
/// "inventory":[…]}` — because `AppError` merges an object `details` into the envelope rather than
/// nesting it. That wire shape predates this refactor and is asserted by
/// `s6_deletion_is_refused_until_every_owned_entity_is_resolved`.
#[derive(Serialize)]
pub(crate) struct InventoryRefusalDetails {
    /// Every key the cascade would remove, so the caller sees the true blast radius rather than
    /// just the id it named.
    subtree: Vec<DoomedKey>,
    /// Everything owned by any key in that subtree, each needing an explicit resolution.
    inventory: Vec<OwnedEntity>,
}

/// Walks the subtree rooted at `root` and collects everything any key in it owns.
///
/// §6 is specific that the walk covers "the entire subtree being deleted", not just the named key.
/// A daughter's hooks have to appear, or they are stranded silently — which is the failure the
/// inventory exists to prevent, and the one a naive "what does *this* key own" query produces.
pub(crate) async fn collect_subtree_inventory(
    db: &sea_orm::DatabaseConnection,
    root: Uuid,
) -> Result<(Vec<Uuid>, Vec<DoomedKey>, Vec<OwnedEntity>), AppError> {
    let mut subtree = vec![root];
    subtree.extend(descendant_key_ids(db, root).await?);

    let doomed = ApiKey::find()
        .filter(api_key::Column::Id.is_in(subtree.clone()))
        .order_by_asc(api_key::Column::CreatedAt)
        .all(db)
        .await?
        .into_iter()
        .map(|k| DoomedKey { id: k.id, name: k.name })
        .collect();

    // Soft-deleted hooks are included on purpose. A hook in the trash is still recoverable and
    // still owned; letting the cascade leave it ownerless would quietly make it master-only
    // forever, which is a decision the operator never made.
    let inventory = Hook::find()
        .filter(hook::Column::OwnerKeyId.is_in(subtree.clone()))
        .order_by_asc(hook::Column::Name)
        .all(db)
        .await?
        .into_iter()
        .filter_map(|h| {
            h.owner_key_id.map(|owner| OwnedEntity {
                entity_type: "hook",
                id: h.id,
                name: h.name,
                current_owner: owner,
            })
        })
        .collect();

    Ok((subtree, doomed, inventory))
}

/// Handles `DELETE /api/keys/{id}` — cascading deletion with the §6 pre-flight inventory.
///
/// # Two-step by design
///
/// The first request is a question, not a command. If the subtree owns anything, the service
/// refuses with `409` and the full inventory; the caller resubmits with a resolution for every
/// listed entity. §6 requires that shape because the alternative — deleting and letting the
/// resources fall where they may — violates "data is never destroyed implicitly" in one direction
/// and silently strands resources in the other.
///
/// A subtree owning nothing deletes in one request, as before.
///
/// # Why the resolution map must be total
///
/// "Deletion executes only when every entity in the inventory carries an explicit resolution;
/// partial maps are refused." A partial map is almost always a stale one — the caller resolved the
/// inventory it was shown, and something was created in between. Applying it would delete the keys
/// and orphan whatever arrived late, which is precisely the outcome this whole mechanism exists to
/// make impossible.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    OptionalStrictJson(payload): OptionalStrictJson<DeleteApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {

    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }
    if id == key.id {
        return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));
    }

    // Fetched before deleting (rather than relying on rows_affected) so the name is still
    // available for the audit entry below.
    let target = load_administrable_key(&state.db, &key, id).await?;
    guard_master_to_administer(&key, &target, "delete")?;
    refuse_master_lifecycle_action(&target, "delete")?;
    let reference = format_reference(&target.name, id);
    let name = target.name.clone();

    let (subtree, doomed, inventory) = collect_subtree_inventory(&state.db, id).await?;

    // A resolution naming something not in the inventory is a mistake worth surfacing rather than
    // ignoring: it usually means the caller is replaying a map built against a different subtree.
    let inventoried: std::collections::HashSet<Uuid> = inventory.iter().map(|e| e.id).collect();
    if let Some(stray) = payload.resolutions.keys().find(|k| !inventoried.contains(k)) {
        return Err(AppError::InvalidInput(format!(
            "resolution supplied for '{stray}', which this key subtree does not own"
        )));
    }

    let unresolved: Vec<&OwnedEntity> =
        inventory.iter().filter(|e| !payload.resolutions.contains_key(&e.id)).collect();
    if !unresolved.is_empty() {
        tracing::info!(
            key = %key.prefix,
            target = %target.prefix,
            owned = inventory.len(),
            unresolved = unresolved.len(),
            "§6: key deletion refused pending an ownership resolution map"
        );
        // Read before `inventory` is moved into the details below: `unresolved` borrows it, so the
        // count has to outlive the borrow rather than be taken from it afterwards.
        let unresolved_count = unresolved.len();

        let details = serde_json::to_value(InventoryRefusalDetails {
            subtree: doomed,
            inventory,
        })
        .map_err(|e| {
            // Unreachable in practice — both fields are plain `Serialize` structs of owned data —
            // but serialising is fallible and `AGENT.MD` forbids unwrapping on a request path.
            tracing::error!("Failed to serialise the §6 inventory refusal: {e}");
            AppError::Internal
        })?;

        return Err(AppError::ConflictWithDetails {
            message: format!(
                "Deletion refused: this key subtree owns {} entit{} with no resolution. Resubmit \
                 with a 'resolutions' map naming, for every id below, either \
                 {{\"action\":\"delete\"}} or {{\"action\":\"reassign\",\"to\":\"<key-id>\"}}.",
                unresolved_count,
                if unresolved_count == 1 { "y" } else { "ies" }
            ),
            details,
        });
    }

    // Validate every reassignment *before* applying any of them, so a bad target in the middle of
    // the map cannot leave the subtree half-resolved and half-deleted.
    let doomed_ids: std::collections::HashSet<Uuid> = subtree.iter().copied().collect();
    for (entity_id, resolution) in &payload.resolutions {
        if let EntityResolution::Reassign { to } = resolution {
            if doomed_ids.contains(to) {
                return Err(AppError::InvalidInput(format!(
                    "cannot reassign '{entity_id}' to '{to}': that key is inside the subtree being                      deleted"
                )));
            }
            if ApiKey::find_by_id(*to).one(&state.db).await?.is_none() {
                return Err(AppError::InvalidInput(format!(
                    "cannot reassign '{entity_id}' to '{to}': no such API key"
                )));
            }
        }
    }

    let now = Utc::now().naive_utc();
    let mut deleted_hooks = 0usize;
    let mut reassigned_hooks = 0usize;
    for (entity_id, resolution) in &payload.resolutions {
        let Some(model) = Hook::find_by_id(*entity_id).one(&state.db).await? else {
            continue;
        };
        let mut active: hook::ActiveModel = model.into();
        match resolution {
            EntityResolution::Delete => {
                // Soft, like every other deletion here: the hook's parameters, permission grants
                // and execution history survive, and the 92-day purge stays the only thing that
                // destroys them. §6's "data is never destroyed implicitly" is about side effects,
                // and this is an explicit instruction — but explicit does not have to mean
                // irreversible.
                active.is_deleted = Set(true);
                active.deleted_at = Set(Some(now));
                active.deleted_by = Set(Some(key.id.to_string()));
                deleted_hooks += 1;
            }
            EntityResolution::Reassign { to } => {
                active.owner_key_id = Set(Some(*to));
                reassigned_hooks += 1;
            }
        }
        active.updated_at = Set(now);
        active.update(&state.db).await?;
    }

    // The cascade itself. Permission rows follow via the schema's existing `ON DELETE CASCADE`, and
    // `executions.api_key_id` is `ON DELETE SET NULL`, so run history survives its author — which
    // is what makes the audit trail worth keeping.
    let result =
        ApiKey::delete_many().filter(api_key::Column::Id.is_in(subtree.clone())).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_DELETE",
        Some(name),
        Some(format!(
            "Deleted key {reference} and {} descendant key(s); {reassigned_hooks} hook(s)              reassigned, {deleted_hooks} hook(s) moved to the trash",
            subtree.len().saturating_sub(1)
        )),
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
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = load_administrable_key(&state.db, &key, id).await?;
    // The response hands back the new plaintext secret, so rotating someone else's master key is
    // credential theft with a lockout attached rather than mere administration.
    guard_master_to_administer(&key, &target, "rotate")?;
    refuse_master_lifecycle_action(&target, "rotate")?;
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
#[serde(deny_unknown_fields)]
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
    /// Permission to read the hook's execution records.
    ///
    /// `#[serde(default)]` rather than a required field, and the default is `false`. A client
    /// written before this verb existed sends a body without it and must keep working — and must
    /// keep working by granting *less*, never more. Defaulting to `true` would have meant every
    /// pre-existing integration silently started handing out history access on its next grant.
    ///
    /// Note this makes an omitted field indistinguishable from an explicit `false`, which is correct
    /// for a grant endpoint that writes the whole row: `POST` here is "these are the rights", not
    /// "change these rights".
    #[serde(default)]
    pub can_view_execution: bool,
}

/// Handles `POST /api/keys/{id}/permissions` — grants or updates one key's rights over one hook.
pub async fn update_key_hook_permissions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<HookPermInput>,
) -> Result<impl IntoResponse, AppError> {
    // Both halves of R2, as far as they can be known before the payload is parsed: the global flag,
    // and a manage row on *some* hook. Which hook is not known yet, so
    // `guard_hook_manage_conjunction` re-asks the second half against the resolved hook below.
    // A caller failing this can pass neither, which is what makes refusing here safe rather than
    // merely early — and it must happen before the `find_by_id`, or the endpoint reports `404` for
    // a key id that does not exist and `403` for one that does.
    if !has_permission_admin_standing(&state.db, &key).await? {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // Permission routes accept a *minimally* visible target too, and must: §4's shared-resource
    // scope exists so a parent managing a hook can see who else holds rights on it, and R6 lets it
    // revoke them. Administering the key *entity* still needs full visibility
    // ([`load_administrable_key`]); this is administering one row of a hook it manages.
    let target_key = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if key_visibility(&state.db, &key, &target_key).await?.is_none() {
        return Err(AppError::NotFound);
    }
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

    // **R6 endpoint parity.** A `POST` that only turns verbs *off* reaches the same end state as
    // `DELETE .../permissions/{hook}`, so the model classifies it as a revocation "regardless of
    // which endpoint it arrives at". Holding the two routes to different standards achieves
    // nothing: the stricter one is one request away from being routed around.
    let existing = hook_permission(&state.db, id, hook_model.id).await?;
    let reduction = is_permission_reduction(
        existing.as_ref(),
        payload.can_execute,
        payload.can_manage,
        payload.can_view_execution,
    );

    if key.is_master {
        // Master bypasses both R1 and R2.
    } else if reduction {
        // R6: manage authority on the resource is the whole requirement. The revoker need not hold
        // the verb being removed, and self-revocation is permitted — reducing your own row cannot
        // raise anyone's authority, so there is nothing for it to prove.
        guard_hook_manage_conjunction(&state.db, &key, hook_model.id).await?;
    } else {
        // R7: R1 and R2 together. Self-granting is refused outright rather than left to R1 to
        // reduce to a no-op — the intent is escalation even when the arithmetic happens to fail,
        // and it deserves its own audit line and its own message.
        if id == key.id {
            tracing::warn!(
                key = %key.prefix,
                hook = %hook_model.name,
                "Non-master key attempted to grant itself hook permissions"
            );
            return Err(AppError::Forbidden(
                "Only master API keys can grant themselves hook permissions".to_owned(),
            ));
        }
        guard_delegated_hook_grant(
            &state.db,
            &key,
            &hook_model,
            payload.can_execute,
            payload.can_manage,
            payload.can_view_execution,
        )
        .await?;
    }

    if !key.is_master {
        // Rights over a *privileged* hook are the elevation itself, so distributing them stays
        // master-only even for a caller who legitimately manages the hook and holds both verbs.
        guard_master_for_privileged_hook(&key, &hook_model, "grant permissions on")?;
    }

    let perm = api_key_hook_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(id),
        hook_id: Set(hook_model.id),
        can_execute: Set(payload.can_execute),
        can_manage: Set(payload.can_manage),
        can_view_execution: Set(payload.can_view_execution),
        created_at: Set(Utc::now().naive_utc()),
    };
    ApiKeyHookPermission::insert(perm)
        .on_conflict(
            OnConflict::columns([
                api_key_hook_permission::Column::ApiKeyId,
                api_key_hook_permission::Column::HookId,
            ])
            // Every verb the payload carries must appear here. A column left out of this list is
            // silently unwritable on any *update* — the insert path would set it and the conflict
            // path would leave the old value, so revoking it through this endpoint would appear to
            // succeed and change nothing.
            .update_columns([
                api_key_hook_permission::Column::CanExecute,
                api_key_hook_permission::Column::CanManage,
                api_key_hook_permission::Column::CanViewExecution,
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
    StrictPath((id, hook_identifier)): StrictPath<(Uuid, String)>,
) -> Result<impl IntoResponse, AppError> {
    // Same standing check as the grant path, for the same reason: a caller with no administrative
    // role at all must not be able to probe key UUIDs by reading `404` instead of `403`.
    if !has_permission_admin_standing(&state.db, &key).await? {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let hook_model = resolve_hook(&state.db, &hook_identifier).await?;

    // **R6, scoped by R2.** Manage authority over this hook is the whole requirement — and under R2
    // that authority is the conjunction, the same bar the grant path applies. What R6 removes,
    // relative to granting, is everything *above* that bar:
    //
    // - **No per-verb proportionality.** The revoker need not hold the verb being removed. Turning a
    //   flag off is a request for `false`, and `false` exceeds nothing, so there is no authority to
    //   prove. Granting needs proof because it can manufacture a capability that was withheld.
    // - **Self-revocation is permitted.** Reducing your own row cannot raise anyone's authority.
    //
    // The two routes must agree about who may act. [`update_key_hook_permissions`] classifies an
    // all-`false` write as a revocation and applies exactly this rule, so neither path can be used
    // to route around the other.
    if !key.is_master {
        guard_hook_manage_conjunction(&state.db, &key, hook_model.id).await?;
    }

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
