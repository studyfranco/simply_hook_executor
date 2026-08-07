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
    api_key, api_key::HmacMode, api_key_hook_permission, audit_log, execution,
    execution::ExecutionStatus, hook, hook_parameter, prelude::*,
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

/// A [`Json`] extractor whose deserialization failures come back as [`AppError::InvalidInput`].
///
/// Axum's own `Json` rejection renders as a bare `text/plain` body, which would break the
/// `{"error": "..."}` contract every other failure on these routes honours — a client parsing the
/// refusal would see no `error` field at all. Since the key-administration payloads are
/// `deny_unknown_fields` (see [`CreateApiKeyPayload`]), a rejected field is now a *routine,
/// security-relevant* outcome rather than an exotic one, so it has to read like every other refusal.
///
/// The serde message is passed through verbatim, so a caller that sent `is_master` is told exactly
/// which field was refused rather than being left to guess at a generic "bad request".
///
/// The rejection's own **status** is passed through too, which matters more than it looks: the
/// 1 MiB body limit also arrives here as a `Json` rejection, and mapping every rejection to `400`
/// would quietly demote `413 Payload Too Large` to an indistinguishable bad request. Only the
/// response shape is normalized; the status is the extractor's to decide.
pub struct StrictJson<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for StrictJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                Err(AppError::BodyRejected(rejection.status(), rejection.body_text()))
            }
        }
    }
}

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
/// Non-secret by design: it is shown in the dashboard and appears in logs, so it only needs to be
/// unique — it never authenticates anything. Callers identify themselves with `X-API-Key` alone.
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

/// Resolves a hook from a path segment that may be either its UUID or its unique name, **including
/// soft-deleted ones**.
///
/// Every hook route takes a `String` rather than a strictly-typed `Uuid` for exactly this reason:
/// a caller wiring up `/webhook/nftables_ban` gets a working request instead of Axum rejecting it
/// with a `422` before any handler runs.
///
/// Almost every caller wants [`resolve_hook`] instead. This variant exists for the three trash
/// routes — restore, hard delete, and the master's `include_deleted` view — which by definition need
/// to address a row the rest of the API pretends is gone.
async fn resolve_hook_including_deleted(
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

/// Resolves a **live** hook by UUID or name.
///
/// A soft-deleted hook reports `404`, identically to one that never existed. That equivalence is
/// deliberate: "deleted" is a state the rest of the API does not model, so every route that reads,
/// executes, or edits a hook behaves as though the row is gone. Returning a distinguishable error
/// would mean auditing each of those routes for whether acting on a trashed hook is safe; a `404`
/// makes the answer uniform and unforgettable.
async fn resolve_hook(
    db: &sea_orm::DatabaseConnection,
    identifier: &str,
) -> Result<hook::Model, AppError> {
    let found = resolve_hook_including_deleted(db, identifier).await?;
    if found.is_deleted {
        return Err(AppError::NotFound);
    }
    Ok(found)
}

/// Narrows a hook query to live rows unless the caller asked for the trash and may see it.
///
/// Master-only, because a soft-deleted hook still carries its `script_path` and `run_as_user` — the
/// full definition of something that was privileged enough to want deleting.
fn require_master_for_deleted_view(
    key: &api_key::Model,
    include_deleted: bool,
) -> Result<(), AppError> {
    if include_deleted && !key.is_master {
        return Err(AppError::Forbidden(
            "Only master API keys can view deleted hooks".to_owned(),
        ));
    }
    Ok(())
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

/// Splits "you cannot see this hook" from "you can see it but lack this verb".
///
/// **§4 oracle discipline** turns on exactly this distinction. A caller holding *no* row on a hook
/// is outside its visibility scope, and must receive what a nonexistent hook id produces —
/// `404`, with the same body. A caller that holds a row is inside the scope and is merely short a
/// verb, which is an ordinary `403` and leaks nothing it did not already know.
///
/// Collapsing the two, as the code did before, made every hook endpoint an existence oracle: `403`
/// for a hook that exists, `404` for one that does not, from a caller entitled to neither.
fn verb_denied(held: Option<&api_key_hook_permission::Model>, verb: &str) -> AppError {
    match held {
        Some(_) => AppError::Forbidden(format!(
            "Permission denied: You do not have {verb} access to this hook"
        )),
        None => AppError::NotFound,
    }
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
    let held = hook_permission(db, key.id, hook_id).await?;
    match &held {
        Some(p) if p.can_execute => Ok(()),
        _ => Err(verb_denied(held.as_ref(), "execute")),
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
    let held = hook_permission(db, key.id, hook_id).await?;
    match &held {
        Some(p) if p.can_manage => Ok(()),
        _ => Err(verb_denied(held.as_ref(), "manage")),
    }
}

/// Authorizes read-only visibility of a hook (either grant suffices).
///
/// Every failure here is a `404` under §4: "visible" is precisely the question this asks, so a
/// caller that fails it is outside the scope by definition and must not be able to tell the hook
/// apart from one that never existed.
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
        _ => Err(AppError::NotFound),
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

/// Rejects a non-master caller trying to hand out a global scope.
///
/// `can_manage_keys` is the right to administer *credentials*, not the right to invent authority
/// that outranks your own. Without this gate the scope was self-amplifying: a `can_manage_keys` key
/// could mint a key with `is_master: true`, authenticate as it, and from there assign
/// `run_as_user: root` — so the scope was operationally identical to `is_master`, just less
/// obviously so in the dashboard.
///
/// Only *granting* is restricted. Clearing a scope is left to any key manager: removing authority
/// is not an escalation, and requiring master to revoke would make an over-provisioned key harder
/// to contain than it was to create.
fn require_master_to_grant_scopes(
    key: &api_key::Model,
    can_manage_keys: Option<bool>,
    can_manage_hooks: Option<bool>,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }

    // `is_master` is deliberately absent: it is no longer a field on either payload, so there is
    // nothing here to gate. Refusing it is the deserializer's job now (`deny_unknown_fields`), and
    // it applies to master callers too — which this guard, by design, does not.
    let requested: [(&str, bool); 2] = [
        ("can_manage_keys", can_manage_keys.unwrap_or(false)),
        ("can_manage_hooks", can_manage_hooks.unwrap_or(false)),
    ];
    let Some((scope, _)) = requested.into_iter().find(|(_, wanted)| *wanted) else {
        return Ok(());
    };

    tracing::warn!(
        key = %key.prefix,
        scope,
        "Non-master key attempted to grant a global scope"
    );
    Err(AppError::Forbidden(format!(
        "Only master API keys can grant '{scope}'"
    )))
}

/// Rejects a non-master caller acting on a key that is itself master.
///
/// Rotation returns the new plaintext secret in its response, so "rotate the master key" was a
/// one-request credential theft that also locked out the legitimate holder. Deletion and update are
/// gated for the same reason: the master key is the system's root of trust, and administering it is
/// reserved to a peer.
fn require_master_to_administer(
    key: &api_key::Model,
    target: &api_key::Model,
    action: &str,
) -> Result<(), AppError> {
    if !target.is_master || key.is_master {
        return Ok(());
    }

    tracing::warn!(
        key = %key.prefix,
        target = %target.prefix,
        action,
        "Non-master key attempted to administer a master key"
    );
    Err(AppError::Forbidden(format!(
        "Only master API keys can {action} a master key"
    )))
}

/// Refuses an action against the master key that no caller — **including the master itself** —
/// may perform through the API.
///
/// [`require_master_to_administer`] answers a different question: it stops *other* keys from
/// touching the master. Once the constraint in
/// `m20230106_000001_master_key_uniqueness` guarantees there is exactly one master, "another key
/// administering the master" and "the master administering itself" are the same request, and the
/// second one was still permitted.
///
/// `RBAC_MODEL.md` §5 closes it: the master cannot be deleted or rotated through the API at all.
/// Rotation is the sharper of the two — it returns the new plaintext secret in its response, so a
/// single request against a stolen-but-IP-bound master credential both harvests a fresh secret and
/// invalidates the operator's copy. Deletion is barred "regardless of row count" so that the rule
/// does not silently depend on the uniqueness index for its safety: two independent controls, not
/// one control leaning on another.
///
/// Regeneration remains possible, deliberately out of band: delete the row directly in the
/// database and restart, and [`crate::main`] mints a fresh master against the empty table.
fn refuse_master_lifecycle_action(target: &api_key::Model, action: &str) -> Result<(), AppError> {
    if !target.is_master {
        return Ok(());
    }

    tracing::warn!(
        target = %target.prefix,
        action,
        "Attempt to {action} the master key through the API"
    );
    Err(AppError::Forbidden(format!(
        "The master API key cannot be {action}d through the API; remove its row directly in the \
         database and restart to re-mint it"
    )))
}

/// Restricts an update targeting the master key to its own `bound_ips`, and to the master itself.
///
/// `RBAC_MODEL.md` §5 makes the master immutable through the API "except for its own `bound_ips`".
/// That exception is narrow on purpose. `bound_ips` is the one field an operator has a legitimate,
/// recurring need to change from inside the running system — the network the master is reachable
/// from moves — and it is the one field that can only ever *reduce* the credential's usefulness to
/// an attacker who lacks the operator's network position.
///
/// Every other field fails that test. `name` rewrites what the audit log calls the root of trust;
/// `max_concurrent_jobs` is a resource lever; `hmac_mode` could downgrade the master to
/// `BODY_ONLY`, which carries no replay protection at all. None of them has a reason to be
/// reachable, so none of them is.
///
/// The `key.id != target.id` arm is unreachable while exactly one master row exists, and is
/// written anyway: it is the assertion that keeps §5's "which it alone may edit" true by
/// construction rather than as a side effect of the uniqueness index holding.
fn require_master_self_edit_is_bound_ips_only(
    key: &api_key::Model,
    target: &api_key::Model,
    payload: &UpdateApiKeyPayload,
) -> Result<(), AppError> {
    if !target.is_master {
        return Ok(());
    }

    if key.id != target.id {
        return Err(AppError::Forbidden(
            "Only the master API key itself may edit the master key's bound_ips".to_owned(),
        ));
    }

    let other_fields: [(&str, bool); 4] = [
        ("name", payload.name.is_some()),
        ("max_concurrent_jobs", payload.max_concurrent_jobs.is_some()),
        ("hmac_mode", payload.hmac_mode.is_some()),
        ("can_manage_keys", payload.can_manage_keys.is_some()),
    ];
    let requested = other_fields
        .into_iter()
        .find(|(_, present)| *present)
        .map(|(field, _)| field)
        // Split out so the array stays a fixed-size literal: `can_manage_hooks` is checked on the
        // same footing as the four above.
        .or_else(|| payload.can_manage_hooks.is_some().then_some("can_manage_hooks"));

    let Some(field) = requested else {
        return Ok(());
    };

    tracing::warn!(
        key = %key.prefix,
        field,
        "Attempt to modify a master key field other than bound_ips"
    );
    Err(AppError::Forbidden(format!(
        "The master API key is immutable except for its own 'bound_ips'; '{field}' cannot be \
         changed through the API"
    )))
}

/// Rejects a non-master caller mutating a hook that already runs elevated.
///
/// A hook carrying `run_as_user` is a standing grant of someone else's privileges, and *every* part
/// of its definition decides what runs with them: `script_path` names the binary, the parameter
/// contract supplies its argv, and the timeout bounds it. Guarding only the `run_as_user` field
/// itself — as the previous code did — left a `can_manage` holder able to repoint an existing root
/// hook at a different script, or to declare a defaulted parameter that becomes an argument to it,
/// without ever touching the field that was being protected.
///
/// Clearing the elevation is covered too. It is a modification of a privileged hook like any other,
/// and exempting it would just add a step to the same attack: drop the elevation, repoint the
/// script, and leave an operator's vetted configuration silently downgraded.
fn require_master_for_privileged_hook(
    key: &api_key::Model,
    hook: &hook::Model,
    action: &str,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }
    let Some(user) = executor::effective_run_as_user(hook.run_as_user.as_deref()) else {
        return Ok(());
    };

    tracing::warn!(
        key = %key.prefix,
        hook = %hook.name,
        run_as_user = %user,
        action,
        "Non-master key attempted to modify a privileged hook"
    );
    Err(AppError::Forbidden(format!(
        "Only master API keys can {action} a hook that runs as '{user}'"
    )))
}

/// Whether a key manages *any* hook at all.
///
/// A coarse, indexed pre-check used by the permission endpoints so that a caller with no
/// administrative standing whatsoever is refused **before** a target key or hook is looked up.
/// Without it, those endpoints would let a caller holding nothing learn whether an arbitrary key
/// UUID exists, by reading `404` instead of `403`.
///
/// It deliberately does not say *which* hook — that question needs the resolved hook and is
/// answered by [`require_hook_manage_conjunction`]. This only establishes that the caller holds a
/// manage row somewhere, which is the half of R2 that can be checked without knowing the target.
async fn manages_any_hook(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
) -> Result<bool, AppError> {
    Ok(ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key_id))
        .filter(api_key_hook_permission::Column::CanManage.eq(true))
        .one(db)
        .await?
        .is_some())
}

/// Whether the caller has administrative *standing* on the permission routes at all, checked
/// before any target key or hook is resolved.
///
/// Both halves of R2 are required, so a caller failing this can never pass
/// [`require_hook_manage_conjunction`] for any hook — which is what makes refusing here safe rather
/// than merely early. The refusal must come before the `ApiKey::find_by_id` in either handler, or
/// the endpoint becomes a key-UUID oracle: `404` for an id that does not exist, `403` for one that
/// does.
async fn has_permission_admin_standing(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
) -> Result<bool, AppError> {
    if key.is_master {
        return Ok(true);
    }
    if !key.can_manage_keys {
        return Ok(false);
    }
    manages_any_hook(db, key.id).await
}

/// **R2 — manage is a conjunction.** Authorizes administering one specific hook's grants, and
/// returns the caller's own permission row on it.
///
/// > *Managing a specific resource requires holding both global `can_manage_keys` AND a
/// > `can_manage = true` row for that specific resource. Neither alone is sufficient.
/// > `can_manage_keys` is never a global bypass of per-resource RBAC.*
///
/// Both halves this replaces were wrong in opposite directions, and each was reachable:
///
/// - **`can_manage_keys` alone** (the early return added in `2d62d1b`) made the flag a global
///   bypass. A holder could grant any verb on any hook to any key — including one it had just
///   minted — and then authenticate as that key. That is `is_master` with extra steps, and it is
///   exactly the "global bypass of per-resource RBAC" R2 names.
/// - **A `can_manage` row alone** (the "local manager" route) let a key with no
///   deployment-wide standing hand out credentials-adjacent authority. Under the Tiers matrix a
///   Daughter key — one without `can_manage_keys` — may never manage resources, so a manage row on
///   its own confers operational rights over the hook, not the right to administer who else holds
///   them.
///
/// The two failures return **one message**, deliberately. Distinguishing "you lack the global flag"
/// from "you lack the row on this hook" would tell a caller which half to go acquire, and the row
/// half doubles as a statement about which hooks exist and who manages them.
async fn require_hook_manage_conjunction(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook_id: Uuid,
) -> Result<api_key_hook_permission::Model, AppError> {
    // Callers handle `is_master` before reaching here: master holds no rows and needs none.
    debug_assert!(!key.is_master, "master bypasses R2 and must be short-circuited by the caller");

    // Which half is missing decides the *status*, and §4 is why. A caller with no row at all cannot
    // see this hook, so it must receive what a nonexistent hook id produces. A caller that holds a
    // row can see it and is merely short the global scope — an ordinary `403`.
    //
    // This does not reintroduce the "which half" leak the shared message exists to prevent: a
    // caller always knows its own rows (`GET /api/auth/me` lists them), so the status tells it
    // nothing it could not already read about itself. What stays hidden is the *hook* — a
    // `can_manage_keys` holder probing hooks it has no relationship with gets `404` whether or not
    // they exist.
    // Visibility first, and it is decided by whether *any* row exists — not by whether that row
    // grants `can_manage`. A caller holding `can_execute` alone can see the hook perfectly well, so
    // hiding it behind a `404` would be a lie it can disprove with `GET /api/auth/me`.
    let Some(row) = hook_permission(db, key.id, hook_id).await? else {
        tracing::warn!(
            key = %key.prefix,
            hook_id = %hook_id,
            "R2: no row at all on this hook; refused as invisible per §4"
        );
        return Err(AppError::NotFound);
    };

    let denied = || {
        AppError::Forbidden(
            "Permission denied: You do not have manage access to this hook".to_owned(),
        )
    };

    if !key.can_manage_keys {
        tracing::warn!(
            key = %key.prefix,
            hook_id = %hook_id,
            "R2: key holds a row but not can_manage_keys; manage is a conjunction"
        );
        return Err(denied());
    }
    if !row.can_manage {
        tracing::warn!(
            key = %key.prefix,
            hook_id = %hook_id,
            "R2: key holds can_manage_keys and a row, but the row is not can_manage"
        );
        return Err(denied());
    }

    Ok(row)
}

/// How much of a key another key is entitled to see (`RBAC_MODEL.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyVisibility {
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

/// **§3 — resource lifecycle authority.** Authorizes deleting or renaming a hook.
///
/// > *Resource lifecycle actions — deleting or renaming the entity itself — are restricted
/// > exclusively to Master and the designated `owner_key_id`. Holding manage rights or any
/// > operational verb confers no lifecycle authority: a parent that merely uses a resource must not
/// > be able to delete it.*
///
/// This is a **narrower** gate than [`require_manage`], and it sits in front of it rather than
/// replacing it. `can_manage` remains what it always was — the right to *operate* a hook: edit its
/// description, its script path, its timeout, its parameter contract. What it no longer carries is
/// the right to make the hook cease to exist, or to rename it out from under everything that refers
/// to it by name (`/webhook/{name}`, `hook_name` in a grant payload, an operator's runbook).
///
/// Renaming is grouped with deletion rather than with the other edits for that reason: this
/// service resolves hooks by name on the webhook entry point, so a rename silently breaks every
/// caller pointed at the old one. It is a lifecycle act wearing an edit's clothes.
///
/// An **ownerless** hook — `owner_key_id` NULL, meaning it predates ownership — is master-only.
/// That is the conservative direction: the alternative, treating "no owner" as "anyone who manages
/// it", would make the un-migrated state *more* permissive than the migrated one, so every
/// deployment would silently keep the old behaviour until someone remembered to assign ownership.
fn require_lifecycle_authority(
    key: &api_key::Model,
    hook: &hook::Model,
    action: &str,
) -> Result<(), AppError> {
    if key.is_master || hook.owner_key_id == Some(key.id) {
        return Ok(());
    }

    tracing::warn!(
        key = %key.prefix,
        hook = %hook.name,
        owner = ?hook.owner_key_id,
        action,
        "§3: lifecycle action attempted by a non-owner"
    );
    Err(AppError::Forbidden(format!(
        "Permission denied: only the master key or hook '{}''s owner may {action} it; managing a \
         hook does not confer lifecycle authority over it",
        hook.name
    )))
}

/// Whether a permission write only ever *reduces* the target's rights.
///
/// **R6** classifies a reduction arriving at the general update endpoint as a revocation, "regardless
/// of which endpoint it arrives at". Without this the two routes to the same outcome disagree about
/// who may take them, and the stricter one is simply routed around: `DELETE .../permissions/{hook}`
/// and a `POST` writing every verb to `false` produce an identical end state.
///
/// A verb is being *granted* only when it is requested `true` and is not already held by the
/// target. Everything else — turning a verb off, leaving it as it was, or writing an all-`false`
/// row where none existed — can only ever leave the target with less authority than it started
/// with, and so needs no proof of authority beyond R2.
fn is_permission_reduction(
    existing: Option<&api_key_hook_permission::Model>,
    requested_execute: bool,
    requested_manage: bool,
) -> bool {
    let (had_execute, had_manage) =
        existing.map_or((false, false), |p| (p.can_execute, p.can_manage));
    // Named rather than folded into one expression: "this write grants a verb the target did not
    // have" is the concept R1 is about, and it should be readable as such at the call site of the
    // negation.
    let grants_execute = requested_execute && !had_execute;
    let grants_manage = requested_manage && !had_manage;
    !grants_execute && !grants_manage
}

/// **R1 + R7** — rejects a grant handing out more authority over a hook than the caller holds.
///
/// > *R1 — A caller may only grant rights it currently holds itself. Applies at every tier below
/// > Master.*
/// > *R7 — Granting is bounded by R1 and R2 together, simultaneously and without exception.*
///
/// R2 is the entry gate ([`require_hook_manage_conjunction`]) and R1 is the per-verb bound applied
/// on top of it. "Together, simultaneously and without exception" is the operative phrase: there is
/// no caller below Master for whom one of the two is skipped. The `2d62d1b` early return skipped
/// *both* for any `can_manage_keys` holder, so the per-verb comparison below was unreachable except
/// by a key that did not hold the global flag.
///
/// Without R1, a caller managing one hook could write `can_execute` onto a second key it controls,
/// authenticate as that key, and run the hook — obtaining in two requests a verb an operator
/// deliberately withheld. `SCHEMA.MD` models `can_execute` and `can_manage` as independent columns
/// precisely so that combination is expressible; checking only one of them would make the
/// distinction advisory.
///
/// Two behaviours fall out of the `wanted && !held` shape and are deliberate:
///
/// - **Revocation is never blocked.** Turning a flag *off* is a request for `false`, which can never
///   exceed anything. R6 says so directly, and [`is_permission_reduction`] classifies such a write
///   before this function is reached.
/// - **Re-asserting a verb you hold is a no-op**, so an idempotent re-submission of an existing
///   grant still succeeds rather than failing for a caller that changed nothing.
///
/// The caller's row comes from the R2 check rather than a second lookup: both questions are about
/// the same caller and the same hook, and reading the row twice would invite the two answers to
/// disagree if a grant were revoked in between.
async fn guard_delegated_hook_grant(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook: &hook::Model,
    requested_execute: bool,
    requested_manage: bool,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }

    let held = require_hook_manage_conjunction(db, key, hook.id).await?;

    let overreach = [
        ("can_execute", requested_execute, held.can_execute),
        ("can_manage", requested_manage, held.can_manage),
    ]
    .into_iter()
    .find(|(_, wanted, holds)| *wanted && !*holds);

    if let Some((verb, _, _)) = overreach {
        tracing::warn!(
            key = %key.prefix,
            hook = %hook.name,
            verb,
            "Blocked privilege delegation: key attempted to grant a verb it does not hold itself"
        );
        return Err(AppError::Forbidden(format!(
            "Permission denied: you cannot grant '{verb}' on hook '{}' because you do not hold it \
             yourself",
            hook.name
        )));
    }

    Ok(())
}

/// Renders a key's signature mode for an audit log entry.
///
/// `BODY_ONLY` is called out as replay-vulnerable rather than merely named: choosing it is a
/// security-relevant decision, and the audit trail should say so where an operator will read it.
fn describe_hmac_mode(mode: HmacMode) -> &'static str {
    match mode {
        HmacMode::CanonicalV1 => "signatures: CANONICAL_V1",
        HmacMode::BodyOnly => "signatures: BODY_ONLY — body-only, no replay protection",
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
    /// New owner (`RBAC_MODEL.md` §3: "Master may reassign `owner_key_id` on any resource ... at
    /// any time"). **Master-only**, and the only way ownership ever moves.
    ///
    /// Reassignment is deliberately not delegable, not even to the current owner. Ownership is what
    /// §3 hangs lifecycle authority on and what §6's inventory reports; letting an owner hand it to
    /// an arbitrary key would let it walk away from a resource rather than resolve it, which is the
    /// step §6 exists to make impossible.
    pub owner_key_id: Option<Uuid>,
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
}

/// Assembles the [`HookDetail`] view for one hook as seen by one key.
async fn build_hook_detail(
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
    Query(params): Query<ListHooksQuery>,
) -> Result<impl IntoResponse, AppError> {
    let include_deleted = params.include_deleted.unwrap_or(false);
    require_master_for_deleted_view(&key, include_deleted)?;

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
    Path(identifier): Path<String>,
    Query(params): Query<ListHooksQuery>,
) -> Result<impl IntoResponse, AppError> {
    let include_deleted = params.include_deleted.unwrap_or(false);
    require_master_for_deleted_view(&key, include_deleted)?;

    let model = if include_deleted {
        resolve_hook_including_deleted(&state.db, &identifier).await?
    } else {
        resolve_hook(&state.db, &identifier).await?
    };
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
    // A hook that already runs elevated is master-only to touch *at all*, not merely master-only to
    // elevate. `script_path`, the timeout, and the name all decide what executes with the borrowed
    // privileges, so guarding one field while leaving the rest writable protected nothing.
    require_master_for_privileged_hook(&key, &model, "modify")?;

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
        require_lifecycle_authority(&key, &model, "rename")?;
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
    Path(identifier): Path<String>,
    Query(query): Query<DeleteHookQuery>,
) -> Result<impl IntoResponse, AppError> {
    let hard = query.hard.unwrap_or(false);
    // A hard delete may target something already in the trash, which is the normal way an operator
    // empties it; a soft delete only ever applies to a live hook.
    let model = if hard {
        resolve_hook_including_deleted(&state.db, &identifier).await?
    } else {
        resolve_hook(&state.db, &identifier).await?
    };
    require_manage(&state.db, &key, model.id).await?;
    // §3: managing a hook is not authority to make it cease to exist.
    require_lifecycle_authority(&key, &model, "delete")?;
    // Deleting a privileged hook is a change to a privileged hook like any other.
    require_master_for_privileged_hook(&key, &model, "delete")?;

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

    let mut active: hook::ActiveModel = model.into();
    active.is_deleted = Set(true);
    active.deleted_at = Set(Some(Utc::now().naive_utc()));
    // Stored as text so the attribution outlives the acting key.
    active.deleted_by = Set(Some(key.id.to_string()));
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

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
    Path(identifier): Path<String>,
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
    Query(query): Query<PurgeQuery>,
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
    // A parameter is argv for the elevated command: a defaulted parameter on a root hook running
    // `/bin/sh` supplies `-c` and a command string without the caller ever editing `script_path`.
    require_master_for_privileged_hook(&key, &model, "declare parameters on")?;

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
    // Changing a `default_value` rewrites what the elevated command receives, so this needs the
    // same gate as declaring one.
    require_master_for_privileged_hook(&key, &model, "modify parameters on")?;

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
    // Removing a required parameter shifts every positional argument after it, which changes the
    // elevated command just as surely as editing one.
    require_master_for_privileged_hook(&key, &model, "remove parameters from")?;

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

    // §4, third scope: executions are creator-private. A hook's manager sees *that it is used* —
    // the hook, its definition, its parameter contract — but not the arguments other keys passed to
    // it or the output they got back. The hook-visibility filter below stays as a second bound, so
    // history for a hook the caller can no longer see disappears even for runs it made itself.
    if !key.is_master {
        q = q.filter(execution::Column::ApiKeyId.eq(key.id));

        if let Some(ids) = visible_hook_ids(&state.db, &key).await? {
            if ids.is_empty() {
                return Ok(Json(Vec::<ExecutionView>::new()));
            }
            q = q.filter(execution::Column::HookId.is_in(ids));
        }
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
    // §4, third scope: an execution belongs to the key that requested it. Its `parameters_json`,
    // stdout and stderr are that caller's data — hook membership is not a licence to read another
    // tenant's arguments and output. `404` rather than `403`, per oracle discipline.
    if !key.is_master && model.api_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

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
async fn build_minimal_api_key_view(
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
                })
            })
            .collect(),
        partial: true,
    })
}

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
    StrictJson(payload): StrictJson<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // Checked before any field validation, for the same reason `run_as_user` is in the hook
    // handlers: an escalation attempt must surface as `403` rather than be masked by a `400` about
    // some unrelated field in the same payload.
    require_master_to_grant_scopes(&key, payload.can_manage_keys, payload.can_manage_hooks)?;

    if let Some(bound_ips) = &payload.bound_ips {
        validate_bound_ips(bound_ips)?;
    }
    let max_concurrent_jobs = payload.max_concurrent_jobs.unwrap_or(10);
    validate_concurrency(max_concurrent_jobs)?;

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let (key_id, signing_secret, sealed_secret) = mint_signing_pair(&state.cipher)?;
    let hmac_mode = payload.hmac_mode.unwrap_or_default();
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
        owner_key_id: Set(Some(key.id)),
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
    /// New signature verification mode.
    pub hmac_mode: Option<HmacMode>,
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
    StrictJson(payload): StrictJson<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = load_administrable_key(&state.db, &key, id).await?;

    // Editing a master key is master-only: `bound_ips` alone would otherwise let a key manager
    // widen (or strand) the network binding of the system's root credential.
    require_master_to_administer(&key, &target, "update")?;
    // ...and even for the master itself, `bound_ips` is the *only* field it reaches.
    require_master_self_edit_is_bound_ips_only(&key, &target, &payload)?;
    // `UpdateApiKeyPayload` deliberately carries no `is_master` field, so promotion is impossible
    // through this route regardless; the other two global scopes still need the gate.
    require_master_to_grant_scopes(&key, payload.can_manage_keys, payload.can_manage_hooks)?;

    if let Some(bound_ips) = &payload.bound_ips {
        validate_bound_ips(bound_ips)?;
    }
    if let Some(jobs) = payload.max_concurrent_jobs {
        validate_concurrency(jobs)?;
    }

    // Captured before `payload` is consumed field-by-field below.
    let payload_hmac_mode = payload.hmac_mode;

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
    if let Some(mode) = payload.hmac_mode {
        active.hmac_mode = Set(mode);
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
        Some(match payload_hmac_mode {
            Some(mode) => format!("Updated key {reference} ({})", describe_hmac_mode(mode)),
            None => format!("Updated key {reference}"),
        }),
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
    let target = load_administrable_key(&state.db, &key, id).await?;
    require_master_to_administer(&key, &target, "delete")?;
    refuse_master_lifecycle_action(&target, "delete")?;
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

    let target = load_administrable_key(&state.db, &key, id).await?;
    // The response hands back the new plaintext secret, so rotating someone else's master key is
    // credential theft with a lockout attached rather than mere administration.
    require_master_to_administer(&key, &target, "rotate")?;
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
    // Both halves of R2, as far as they can be known before the payload is parsed: the global flag,
    // and a manage row on *some* hook. Which hook is not known yet, so
    // `require_hook_manage_conjunction` re-asks the second half against the resolved hook below.
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
    let reduction = is_permission_reduction(existing.as_ref(), payload.can_execute, payload.can_manage);

    if key.is_master {
        // Master bypasses both R1 and R2.
    } else if reduction {
        // R6: manage authority on the resource is the whole requirement. The revoker need not hold
        // the verb being removed, and self-revocation is permitted — reducing your own row cannot
        // raise anyone's authority, so there is nothing for it to prove.
        require_hook_manage_conjunction(&state.db, &key, hook_model.id).await?;
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
        )
        .await?;
    }

    if !key.is_master {
        // Rights over a *privileged* hook are the elevation itself, so distributing them stays
        // master-only even for a caller who legitimately manages the hook and holds both verbs.
        require_master_for_privileged_hook(&key, &hook_model, "grant permissions on")?;
    }

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
        require_hook_manage_conjunction(&state.db, &key, hook_model.id).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a permission row carrying just the two verbs; the rest is irrelevant to
    /// [`is_permission_reduction`].
    fn row(can_execute: bool, can_manage: bool) -> api_key_hook_permission::Model {
        api_key_hook_permission::Model {
            id: Uuid::nil(),
            api_key_id: Uuid::nil(),
            hook_id: Uuid::nil(),
            can_execute,
            can_manage,
            created_at: chrono::NaiveDateTime::default(),
        }
    }

    /// **R6 endpoint parity.** The classification that decides whether a `POST` to the permissions
    /// route is judged as a grant (R1 + R2) or as a revocation (R2 alone).
    ///
    /// Getting this backwards in either direction is a real bug: too strict and R6's "regardless of
    /// which endpoint it arrives at" fails, so a caller entitled to revoke is refused on one route
    /// and allowed on the other; too loose and R1 is bypassed by writing a grant that the
    /// classifier mistakes for a reduction.
    #[test]
    fn a_write_is_a_reduction_exactly_when_it_turns_no_verb_on() {
        // Turning a verb on that the target did not have is a grant, in every combination.
        assert!(!is_permission_reduction(None, true, false));
        assert!(!is_permission_reduction(None, false, true));
        assert!(!is_permission_reduction(Some(&row(true, false)), true, true));
        assert!(!is_permission_reduction(Some(&row(false, true)), true, true));

        // Turning verbs off, in any combination, is a reduction.
        assert!(is_permission_reduction(Some(&row(true, true)), false, false));
        assert!(is_permission_reduction(Some(&row(true, true)), true, false));
        assert!(is_permission_reduction(Some(&row(true, true)), false, true));

        // Re-asserting exactly what the target already holds changes nothing, so it cannot be an
        // escalation and must not demand a grant's proof of authority.
        assert!(is_permission_reduction(Some(&row(true, true)), true, true));
        assert!(is_permission_reduction(Some(&row(false, true)), false, true));

        // An all-`false` write where no row exists is the same end state as no row at all.
        assert!(is_permission_reduction(None, false, false));

        // A mixed write — one verb up, one down — is a grant. The reduction of the other verb does
        // not pay for the escalation, and treating "net less authority" as a reduction would let a
        // caller trade `can_execute` for `can_manage` without holding it.
        assert!(!is_permission_reduction(Some(&row(true, false)), false, true));
    }

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
