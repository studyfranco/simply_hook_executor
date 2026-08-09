//! Every authorization decision in the API layer.
//!
//! One module, deliberately, because the rules in `RBAC_MODEL.md` are cross-cutting: R2's
//! conjunction governs hooks, parameters and execution records alike, and §3's ownership test is
//! consulted from three different handler domains. Splitting them by *caller* would put the same
//! sentence of the specification in three files and invite the three copies to drift.
//!
//! The organising principle is that a guard answers "may this caller do this", returns
//! `Result<_, AppError>`, and never writes anything. Helpers that merely fetch or format live in
//! [`super::support`].
//!
//! § and R references throughout are to `RBAC_MODEL.md`, which is normative.

use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::entities::{api_key, api_key_hook_permission, execution, hook, prelude::*};
use crate::error::AppError;

use crate::executor;

use super::keys::UpdateApiKeyPayload;

/// Narrows a hook query to live rows unless the caller asked for the trash and may see it.
///
/// Master-only, because a soft-deleted hook still carries its `script_path` and `run_as_user` — the
/// full definition of something that was privileged enough to want deleting.
pub(crate) fn require_master_for_deleted_view(
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
pub(crate) async fn hook_permission(
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
pub(crate) fn verb_denied(held: Option<&api_key_hook_permission::Model>, verb: &str) -> AppError {
    match held {
        Some(_) => AppError::Forbidden(format!(
            "Permission denied: You do not have {verb} access to this hook"
        )),
        None => AppError::NotFound,
    }
}

/// Authorizes execution of a hook: master keys bypass, everyone else needs an explicit
/// `can_execute` grant (`AGENT.MD` least-privilege rule).
pub(crate) async fn require_execute(
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

/// Authorizes editing the *content* of an existing hook — its definition, its dispatch
/// configuration, its parameter contract, and its execution records.
///
/// Three routes in, and they are not interchangeable:
///
/// 1. **Master.** Bypasses everything.
/// 2. **The hook's owner** (`hooks.owner_key_id`), with no further requirement.
/// 3. **R2 in full** — global `can_manage_keys` *and* a `can_manage = true` row on this hook —
///    for everyone else, via [`require_hook_manage_conjunction`].
///
/// # Why ownership is sufficient on its own
///
/// §3 makes the owner "the key answerable for this hook", and the only non-Master identity that may
/// delete or rename it. A model in which you may destroy a resource outright but may not edit its
/// description is not a model anyone would design on purpose; it is what falls out of applying R2
/// to content without noticing that §3 already grants the owner a strictly larger authority over
/// the same object.
///
/// It also restores a workflow the conjunction had broken. `can_manage_hooks` is a resource-creation
/// right that sits at Daughter tier, so a key holding it could create a hook and then never touch
/// it again — not even the hook it had just written, whose `owner_key_id` names it. Ownership as a
/// third route makes creation coherent: you may maintain what you are answerable for.
///
/// # What ownership is *not* sufficient for
///
/// **Delegation.** Granting or revoking another key's rights on this hook is not reachable through
/// this function at all — those routes call [`require_hook_manage_conjunction`] directly and so
/// still require R2 in full. Owning a hook makes you answerable for it; it does not make you an
/// administrator of credentials, which is what handing out verbs on it amounts to. A Daughter owner
/// can therefore edit its own hook and cannot widen anyone's access to it, including its own.
///
/// # Why the owner check runs before the conjunction
///
/// Ordering is load-bearing for §4. [`require_hook_manage_conjunction`] answers `404` when the
/// caller holds no permission row at all, and an owner need not hold one — ownership lives in a
/// column on `hooks`, not in `api_key_hook_permissions`. Asking the conjunction first would hide a
/// hook from the very key answerable for it.
///
/// # Why this used to accept a bare row, and why that was a remote-code-execution hole
///
/// It previously read `is_master || row.can_manage`, dropping the global half. Under §1's Tiers
/// matrix a Daughter key — one without `can_manage_keys` — "may manage resources: **Never**", so
/// that spelling let precisely the tier the specification forbids manage a hook. The consequence
/// was not abstract: [`update_hook`] is gated by this function, and `script_path` is one of the
/// fields it writes. A Daughter holding a single `can_manage` row could repoint a hook at any
/// binary on the host and then trigger it with the `can_execute` half of the same row.
/// `require_master_for_privileged_hook` bounded that only for hooks already carrying a
/// `run_as_user`, and `ALLOWED_SCRIPT_ROOTS` is empty by default.
///
/// # The asymmetry with `can_manage_hooks`
///
/// Creating a hook still needs only the global `can_manage_hooks` scope, because R2 is written
/// about "a `can_manage = true` row for that specific resource" and a resource that does not yet
/// exist can have no row. Creation rights and management rights remain separate powers — but a
/// creator is recorded as `owner_key_id`, so route 2 above is what lets it keep maintaining its own
/// work without also being made a Parent.
pub(crate) async fn require_manage(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook: &hook::Model,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }
    if hook.owner_key_id == Some(key.id) {
        return Ok(());
    }
    require_hook_manage_conjunction(db, key, hook.id).await?;
    Ok(())
}

/// Authorizes read-only visibility of a hook (either grant suffices).
///
/// Every failure here is a `404` under §4: "visible" is precisely the question this asks, so a
/// caller that fails it is outside the scope by definition and must not be able to tell the hook
/// apart from one that never existed.
pub(crate) async fn require_visibility(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook: &hook::Model,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }
    // Ownership confers visibility on its own. §3 makes the owner answerable for the hook and
    // [`require_manage`] lets it edit one, so a hook invisible to the key that owns it would be
    // editable-but-unreadable — `PUT` succeeding while `GET` answers `404`. Ownership lives in a
    // column on `hooks`, not in `api_key_hook_permissions`, so it has to be asked for separately;
    // master may reassign `owner_key_id` to a key holding no row at all.
    if hook.owner_key_id == Some(key.id) {
        return Ok(());
    }
    match hook_permission(db, key.id, hook.id).await? {
        // Any verb confers the derived read. `can_view_execution` is included because history is
        // unreadable without knowing which hook produced it: an auditor holding only that verb still
        // has to be able to name the hook, or `GET /api/executions?hook=deploy` would answer `404`
        // for a hook whose runs it is entitled to read.
        Some(p) if p.can_execute || p.can_manage || p.can_view_execution => Ok(()),
        _ => Err(AppError::NotFound),
    }
}

/// Whether this caller may read `execution` — `RBAC_MODEL.md` §4's third scope, in full.
///
/// > *Creator-private entities: visible exclusively to their creator and Master. They are never
/// > exposed by the shared-resource rule above.*
///
/// The Terminology table names the **Execution record** as this service's creator-private entity, so
/// holding a verb on a hook is deliberately *not* enough to read what other keys' runs of it printed.
/// An execution carries the arguments a caller passed and the stdout and stderr it got back; that is
/// the caller's data, and a shared hook is not a licence to read it.
///
/// Four routes in, and each answers a different question:
///
/// 1. **Master** — full visibility over everything.
/// 2. **The acting key** (`executions.api_key_id`) — its own run. This is the "creator" §4 names.
/// 3. **The hook's owner** (`hooks.owner_key_id`) — §3 makes the owner answerable for the hook, and
///    being answerable for what a hook does without being able to see what it did is not a coherent
///    position to put an operator in.
/// 4. **An explicit grant** — `can_view_execution`, or `can_manage` on the hook. The latter is
///    included because a key already entitled to rewrite `script_path` and delete the history
///    outright cannot meaningfully be denied *reading* it; withholding that would be theatre.
///
/// Everything else is `404`, never `403`: an execution the caller may not read must be
/// indistinguishable from one that does not exist, or the endpoint becomes an oracle for how often a
/// hook runs and how many records exist.
pub(crate) async fn may_read_execution(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    execution: &execution::Model,
) -> Result<bool, AppError> {
    if key.is_master || execution.api_key_id == Some(key.id) {
        return Ok(true);
    }

    // Loaded rather than passed in: the ownership answer lives on `hooks`, and a hook that has since
    // been hard-deleted leaves history nobody but Master and the acting key can read — which is the
    // conservative direction, and the only one available once the owning row is gone.
    if let Some(hook_model) = Hook::find_by_id(execution.hook_id).one(db).await?
        && hook_model.owner_key_id == Some(key.id)
    {
        return Ok(true);
    }

    Ok(hook_permission(db, key.id, execution.hook_id)
        .await?
        .is_some_and(|p| p.can_view_execution || p.can_manage))
}

/// The hooks whose executions this caller may read *whoever ran them* — ownership plus explicit
/// grants, as routes 3 and 4 of [`may_read_execution`].
///
/// Exists so the listing endpoint can express the same rule as a single indexed `WHERE` rather than
/// by fetching every row and filtering in memory, which would page wrongly: a `LIMIT 50` applied
/// before a visibility filter returns fewer than fifty visible rows and hides the rest behind an
/// offset that never advances past them.
pub(crate) async fn execution_visible_hook_ids(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
) -> Result<Vec<Uuid>, AppError> {
    let owned: Vec<Uuid> = Hook::find()
        .filter(hook::Column::OwnerKeyId.eq(key.id))
        .all(db)
        .await?
        .into_iter()
        .map(|h| h.id)
        .collect();

    let granted: Vec<Uuid> = ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key.id))
        .filter(
            Condition::any()
                .add(api_key_hook_permission::Column::CanViewExecution.eq(true))
                .add(api_key_hook_permission::Column::CanManage.eq(true)),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.hook_id)
        .collect();

    let mut ids = owned;
    ids.extend(granted);
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// The set of hook ids the caller may see, or `None` for a master key (meaning "no restriction").
pub(crate) async fn visible_hook_ids(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
) -> Result<Option<Vec<Uuid>>, AppError> {
    if key.is_master {
        return Ok(None);
    }
    let mut ids: Vec<Uuid> = ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key.id))
        .filter(
            Condition::any()
                .add(api_key_hook_permission::Column::CanExecute.eq(true))
                .add(api_key_hook_permission::Column::CanManage.eq(true))
                .add(api_key_hook_permission::Column::CanViewExecution.eq(true)),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.hook_id)
        .collect();

    // Owned hooks, whether or not a permission row exists — the listing form of the same rule
    // [`require_visibility`] applies to a single hook. Without this a key could edit a hook that
    // never appeared in its own hook list.
    ids.extend(
        Hook::find()
            .filter(hook::Column::OwnerKeyId.eq(key.id))
            .all(db)
            .await?
            .into_iter()
            .map(|h| h.id),
    );

    ids.sort_unstable();
    ids.dedup();
    Ok(Some(ids))
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
pub(crate) fn normalize_run_as_user(
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
pub(crate) fn require_master_to_grant_scopes(
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
pub(crate) fn require_master_to_administer(
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
pub(crate) fn refuse_master_lifecycle_action(target: &api_key::Model, action: &str) -> Result<(), AppError> {
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
pub(crate) fn require_master_self_edit_is_bound_ips_only(
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
pub(crate) fn require_master_for_privileged_hook(
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
pub(crate) async fn manages_any_hook(
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
pub(crate) async fn has_permission_admin_standing(
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

/// **R2 — manage is a conjunction.** The single evaluation point for "may this key manage this
/// hook", and returns the caller's own permission row on it.
///
/// Every manage-level route reaches this function: the grant-administration routes call it
/// directly for the row it returns, and every content route ([`update_hook`], the parameter CRUD,
/// [`delete_hook`], [`delete_execution`]) arrives through [`require_manage`]. There is deliberately
/// no second implementation of R2 to drift from this one.
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
pub(crate) async fn require_hook_manage_conjunction(
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
pub(crate) async fn descendant_key_ids(
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
pub(crate) async fn managed_hook_ids(
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
pub(crate) async fn key_visibility(
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
pub(crate) async fn load_administrable_key(
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
pub(crate) fn require_lifecycle_authority(
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
pub(crate) fn is_permission_reduction(
    existing: Option<&api_key_hook_permission::Model>,
    requested_execute: bool,
    requested_manage: bool,
    requested_view_execution: bool,
) -> bool {
    let (had_execute, had_manage, had_view) = existing
        .map_or((false, false, false), |p| (p.can_execute, p.can_manage, p.can_view_execution));
    // Named rather than folded into one expression: "this write grants a verb the target did not
    // have" is the concept R1 is about, and it should be readable as such at the call site of the
    // negation.
    let grants_execute = requested_execute && !had_execute;
    let grants_manage = requested_manage && !had_manage;
    // `can_view_execution` is a verb like the others here. Omitting it would have made a write that
    // *adds* history access classify as a pure reduction whenever it also turned another verb off,
    // and reductions skip R1 entirely — so a caller could have traded a verb it held for one it did
    // not.
    let grants_view = requested_view_execution && !had_view;
    !grants_execute && !grants_manage && !grants_view
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
pub(crate) async fn guard_delegated_hook_grant(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    hook: &hook::Model,
    requested_execute: bool,
    requested_manage: bool,
    requested_view_execution: bool,
) -> Result<(), AppError> {
    if key.is_master {
        return Ok(());
    }

    let held = require_hook_manage_conjunction(db, key, hook.id).await?;

    // Every verb the permission row carries is compared independently. A verb missing from this
    // array is a verb R1 does not bound, which is how a new column becomes a delegation hole the
    // day it is added — the caller would be free to grant history access it does not hold itself.
    let overreach = [
        ("can_execute", requested_execute, held.can_execute),
        ("can_manage", requested_manage, held.can_manage),
        ("can_view_execution", requested_view_execution, held.can_view_execution),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a permission row carrying just the verbs; the rest is irrelevant to
    /// [`is_permission_reduction`].
    fn row(can_execute: bool, can_manage: bool) -> api_key_hook_permission::Model {
        view_row(can_execute, can_manage, false)
    }

    /// As [`row`], with `can_view_execution` spelled out.
    fn view_row(
        can_execute: bool,
        can_manage: bool,
        can_view_execution: bool,
    ) -> api_key_hook_permission::Model {
        api_key_hook_permission::Model {
            id: Uuid::nil(),
            api_key_id: Uuid::nil(),
            hook_id: Uuid::nil(),
            can_execute,
            can_manage,
            can_view_execution,
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
        assert!(!is_permission_reduction(None, true, false, false));
        assert!(!is_permission_reduction(None, false, true, false));
        assert!(!is_permission_reduction(Some(&row(true, false)), true, true, false));
        assert!(!is_permission_reduction(Some(&row(false, true)), true, true, false));

        // Turning verbs off, in any combination, is a reduction.
        assert!(is_permission_reduction(Some(&row(true, true)), false, false, false));
        assert!(is_permission_reduction(Some(&row(true, true)), true, false, false));
        assert!(is_permission_reduction(Some(&row(true, true)), false, true, false));

        // Re-asserting exactly what the target already holds changes nothing, so it cannot be an
        // escalation and must not demand a grant's proof of authority.
        assert!(is_permission_reduction(Some(&row(true, true)), true, true, false));
        assert!(is_permission_reduction(Some(&row(false, true)), false, true, false));

        // An all-`false` write where no row exists is the same end state as no row at all.
        assert!(is_permission_reduction(None, false, false, false));

        // A mixed write — one verb up, one down — is a grant. The reduction of the other verb does
        // not pay for the escalation, and treating "net less authority" as a reduction would let a
        // caller trade `can_execute` for `can_manage` without holding it.
        assert!(!is_permission_reduction(Some(&row(true, false)), false, true, false));
    }

    /// `can_view_execution` is a verb like the others, and the classifier must treat it as one.
    ///
    /// Written separately because the trade is the interesting case: a write that turns
    /// `can_execute` off while turning history access on has *net* less authority by any naive
    /// count, and is still a grant. Classifying it as a reduction would route it past R1 entirely,
    /// letting a caller hand out execution history it does not itself hold by paying for it with a
    /// verb it does.
    #[test]
    fn granting_history_access_is_a_grant_even_when_another_verb_is_surrendered() {
        // Turning it on where it was not held is a grant.
        assert!(!is_permission_reduction(None, false, false, true));
        assert!(!is_permission_reduction(Some(&view_row(true, true, false)), true, true, true));

        // The trade: execute surrendered, history acquired. Still a grant.
        assert!(!is_permission_reduction(Some(&view_row(true, false, false)), false, false, true));

        // Turning it off is a reduction, and re-asserting it is a no-op.
        assert!(is_permission_reduction(Some(&view_row(false, false, true)), false, false, false));
        assert!(is_permission_reduction(Some(&view_row(false, false, true)), false, false, true));

        // A row that holds only history, asked for only history, is unchanged.
        assert!(is_permission_reduction(Some(&view_row(true, true, true)), true, true, true));
    }
}
