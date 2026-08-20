//! Referential integrity: what the six declared foreign keys actually do when a row is removed.
//!
//! # Why this file exists
//!
//! `m20230101_090000_initial_schema` declares six foreign keys — four `ON DELETE CASCADE`, two
//! `ON DELETE SET NULL` — and until now **nothing in the repository asserted that any of them
//! fired**. On SQLite that is a materially dangerous gap, because SQLite is the one engine where
//! declaring a foreign key and enforcing it are separate decisions: with `PRAGMA foreign_keys=OFF`,
//! the constraints parse, the schema reports them, and the engine ignores them in silence. A
//! deployment in that state accumulates orphaned permission rows, parameters and history with no
//! error anywhere.
//!
//! # The correction this file records
//!
//! An earlier audit entry in `AGENT_NOTES.MD` asserted that this service was in exactly that state,
//! on the reasoning that `src/db.rs` set `journal_mode` and `busy_timeout` and nothing else.
//! **That conclusion was wrong.** SQLx enables foreign keys on every SQLite connection it opens, so
//! the constraints have been enforced the whole time. The pragma is now declared explicitly in
//! [`simply_hook_executor::db::connect`] — not as a repair, but so that a security-relevant setting
//! stops depending on a dependency's default that could be revised in a point release, silently.
//!
//! The tests below are the part that was genuinely missing either way: they pin the *behaviour*,
//! not the pragma. `PRAGMA foreign_keys` reading `1` says a switch is set. These say the engine acts
//! on it, and that it acts differently for `CASCADE` than for `SET NULL` — a distinction the schema
//! makes deliberately and which no other suite would notice collapsing.
//!
//! # Cascades are the schema's backstop, not the application's plan
//!
//! `RBAC_MODEL.md` §6 requires key deletion to run a pre-flight inventory and refuse rather than
//! silently orphan owned resources; `src/api/keys.rs` implements that, and it is the path real
//! traffic takes. These tests deliberately go *around* it, deleting rows directly, because the
//! question here is what the database guarantees when the application layer is bypassed — by a
//! future handler, an operator at a SQL prompt, or a bug.

// `common` is shared by four test binaries and each compiles all of it, so the helpers this one
// does not call are unused *here* while having real callers next door. The crate-wide convention is
// to allow it at the import rather than inside `common`, which keeps `common`'s own no-blanket-allow
// rule intact.
#[allow(dead_code)]
mod common;

use common::*;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter,
};
use simply_hook_executor::entities::{
    api_key_hook_permission, audit_log, execution, hook_parameter, prelude::*,
};
use uuid::Uuid;

/// Records an execution attributed to `key_id`, which is what makes the `SET NULL` edge testable.
///
/// [`common::insert_execution_aged`] leaves `api_key_id` NULL, so it cannot distinguish "the
/// attribution was cleared by the cascade" from "there was never an attribution".
async fn insert_execution_by(db: &DatabaseConnection, hook_id: Uuid, key_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    execution::ActiveModel {
        id: Set(id),
        hook_id: Set(hook_id),
        api_key_id: Set(Some(key_id)),
        status: Set(execution::ExecutionStatus::Success),
        exit_code: Set(Some(0)),
        stdout: Set(String::new()),
        stderr: Set(String::new()),
        parameters_json: Set("{}".to_owned()),
        duration_ms: Set(5),
        timestamp: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .expect("seeding an execution succeeds");
    id
}

/// Writes an audit row attributed to `key_id`, with the name and prefix denormalized as the real
/// writer does.
async fn insert_audit_by(db: &DatabaseConnection, key_id: Uuid, action: &str) -> Uuid {
    let id = Uuid::new_v4();
    audit_log::ActiveModel {
        id: Set(id),
        api_key_id: Set(Some(key_id)),
        api_key_name: Set("Doomed Key".to_owned()),
        api_key_prefix: Set("dead1234".to_owned()),
        client_ip: Set("127.0.0.1".to_owned()),
        action: Set(action.to_owned()),
        target_resource: Set(None),
        details: Set(None),
        timestamp: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .expect("seeding an audit row succeeds");
    id
}

/// Deleting a hook takes its permission grants, parameter contract and execution history with it.
///
/// Three `ON DELETE CASCADE` edges at once, asserted against a *populated* neighbour table in each
/// case: the counts are checked before the delete as well as after, so a test database that never
/// held the rows cannot pass this vacuously.
#[tokio::test]
async fn deleting_a_hook_cascades_to_permissions_parameters_and_executions() {
    let db = setup_test_db().await;
    let (key_id, _) = insert_key(&db, "Grantee", "", KeyScopes::plain()).await;

    let doomed = insert_hook(&db, "doomed", "/bin/true", 30).await;
    let survivor = insert_hook(&db, "survivor", "/bin/true", 30).await;

    grant(&db, key_id, doomed, true, false).await;
    grant(&db, key_id, survivor, true, false).await;
    insert_parameter(&db, doomed, "target", None, true).await;
    insert_parameter(&db, survivor, "target", None, true).await;
    insert_execution_by(&db, doomed, key_id).await;
    insert_execution_by(&db, survivor, key_id).await;

    // Populated first — otherwise "zero rows afterwards" proves nothing.
    assert_eq!(count_perms_for_hook(&db, doomed).await, 1);
    assert_eq!(count_params_for_hook(&db, doomed).await, 1);
    assert_eq!(count_executions_for_hook(&db, doomed).await, 1);

    Hook::delete_by_id(doomed).exec(&db).await.expect("the hook row is removed");

    assert_eq!(count_perms_for_hook(&db, doomed).await, 0, "grants must cascade");
    assert_eq!(count_params_for_hook(&db, doomed).await, 0, "parameters must cascade");
    assert_eq!(count_executions_for_hook(&db, doomed).await, 0, "history must cascade");

    // The cascade is scoped to the deleted row. A cascade that reached the sibling hook would be a
    // far worse bug than one that reached nothing, and only a second hook can detect it.
    assert_eq!(count_perms_for_hook(&db, survivor).await, 1, "an unrelated hook is untouched");
    assert_eq!(count_params_for_hook(&db, survivor).await, 1);
    assert_eq!(count_executions_for_hook(&db, survivor).await, 1);
}

/// Deleting a key cascades its grants but only *nulls* its attribution on history and audit rows.
///
/// The asymmetry is the whole point, and it is a deliberate schema decision rather than an
/// oversight. A grant is meaningless once its holder is gone, so it goes. An execution record and an
/// audit entry are evidence: deleting the key that wrote them must not erase what was done, or
/// deleting your own key would become a way to erase your own trail — the single most valuable thing
/// an attacker could do to an audit log.
#[tokio::test]
async fn deleting_a_key_cascades_grants_but_only_nulls_execution_and_audit_attribution() {
    let db = setup_test_db().await;
    let (doomed_key, _) = insert_key(&db, "Doomed Key", "", KeyScopes::plain()).await;
    let (other_key, _) = insert_key(&db, "Bystander", "", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "target", "/bin/true", 30).await;

    grant(&db, doomed_key, hook_id, true, false).await;
    grant(&db, other_key, hook_id, true, false).await;
    let execution_id = insert_execution_by(&db, hook_id, doomed_key).await;
    let audit_id = insert_audit_by(&db, doomed_key, "HOOK_UPDATE").await;

    assert_eq!(count_perms_for_key(&db, doomed_key).await, 1);

    ApiKey::delete_by_id(doomed_key).exec(&db).await.expect("the key row is removed");

    assert_eq!(count_perms_for_key(&db, doomed_key).await, 0, "grants must cascade");
    assert_eq!(
        count_perms_for_key(&db, other_key).await,
        1,
        "another key's grant on the same hook is untouched"
    );

    // Evidence survives, de-attributed rather than deleted.
    let surviving_execution = Execution::find_by_id(execution_id)
        .one(&db)
        .await
        .expect("querying executions succeeds")
        .expect("the execution record must survive its key's deletion");
    assert_eq!(surviving_execution.api_key_id, None, "attribution is nulled, not the row deleted");
    assert_eq!(surviving_execution.hook_id, hook_id, "and the rest of the record is intact");

    let surviving_audit = AuditLog::find_by_id(audit_id)
        .one(&db)
        .await
        .expect("querying audit logs succeeds")
        .expect("the audit entry must survive its key's deletion");
    assert_eq!(surviving_audit.api_key_id, None);
    assert_eq!(
        (surviving_audit.api_key_name.as_str(), surviving_audit.api_key_prefix.as_str()),
        ("Doomed Key", "dead1234"),
        "the denormalized name and prefix are a point-in-time snapshot and are never nulled — they \
         are what keeps the trail legible after the FK is cleared"
    );
}

/// The constraint runs in the other direction too: a row cannot be *created* dangling.
///
/// Cascade tests alone would still pass on an engine that dropped children on delete but happily
/// accepted a child with no parent. This is the check that says the reference is validated at write
/// time, which is what makes "no orphans exist" an invariant rather than a hope.
#[tokio::test]
async fn a_row_referencing_a_nonexistent_parent_is_refused_at_insert() {
    let db = setup_test_db().await;
    let (real_key, _) = insert_key(&db, "Real", "", KeyScopes::plain()).await;
    let real_hook = insert_hook(&db, "real", "/bin/true", 30).await;

    let ghost = Uuid::new_v4();

    // Both FK columns bad, then each one individually — so a constraint that only checks one of the
    // two cannot pass this.
    for (label, key_id, hook_id) in [
        ("both references dangling", ghost, ghost),
        ("dangling key, real hook", ghost, real_hook),
        ("real key, dangling hook", real_key, ghost),
    ] {
        let row = api_key_hook_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key_id),
            hook_id: Set(hook_id),
            can_execute: Set(true),
            can_manage: Set(false),
            can_view_execution: Set(false),
            created_at: Set(chrono::Utc::now().naive_utc()),
        };
        assert!(
            ApiKeyHookPermission::insert(row).exec(&db).await.is_err(),
            "{label}: SQLite accepts this silently when foreign_keys is off"
        );
    }

    // ...while a fully-referenced row inserts fine, so the loop is not passing because every insert
    // fails for some unrelated reason.
    grant(&db, real_key, real_hook, true, false).await;
    assert_eq!(count_perms_for_hook(&db, real_hook).await, 1);
}

/// A dangling `hook_parameters.hook_id` is refused as well.
///
/// Called out separately from the permission table because it is the edge a hook purge relies on:
/// if parameters could dangle, purging a hook would leave a contract behind that no hook can ever
/// satisfy, and the next hook to reuse that UUID would silently inherit it.
#[tokio::test]
async fn a_parameter_cannot_be_attached_to_a_hook_that_does_not_exist() {
    let db = setup_test_db().await;

    let orphan = hook_parameter::ActiveModel {
        id: Set(Uuid::new_v4()),
        hook_id: Set(Uuid::new_v4()),
        param_key: Set("target".to_owned()),
        description: Set(None),
        default_value: Set(None),
        is_required: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
    };
    assert!(HookParameter::insert(orphan).exec(&db).await.is_err());
}

/// Purging a soft-deleted hook through the real retention path leaves nothing behind.
///
/// The tests above delete rows directly, which proves the constraint. This one proves the
/// *shipped code path* benefits from it: `retention::purge_expired_deleted_hooks` issues a delete
/// against `hooks` alone and never touches the child tables, so if the cascade were not enforced
/// this is precisely where orphans would accumulate in production — silently, on a timer, in a
/// background worker nobody is watching.
#[tokio::test]
async fn purging_a_trashed_hook_leaves_no_orphaned_children() {
    let db = setup_test_db().await;
    let (key_id, _) = insert_key(&db, "Grantee", "", KeyScopes::plain()).await;
    let hook_id = insert_hook_deleted_days_ago(&db, "trashed", "/bin/true", 30, key_id).await;

    grant(&db, key_id, hook_id, true, false).await;
    insert_parameter(&db, hook_id, "target", None, true).await;
    insert_execution_by(&db, hook_id, key_id).await;

    let purged = simply_hook_executor::retention::purge_expired_deleted_hooks(&db, 7)
        .await
        .expect("the purge sweep succeeds");
    assert_eq!(purged, 1, "the trashed hook is old enough to be purged");

    assert_eq!(Hook::find().count(&db).await.expect("count"), 0);
    assert_eq!(count_perms_for_hook(&db, hook_id).await, 0, "no orphaned grants");
    assert_eq!(count_params_for_hook(&db, hook_id).await, 0, "no orphaned parameters");
    assert_eq!(count_executions_for_hook(&db, hook_id).await, 0, "no orphaned history");
}

/// `api_keys.parent_key_id` and `hooks.owner_key_id` carry **no** foreign key, on purpose.
///
/// This test asserts an absence, which deserves justification. `m20230107` documents the reasoning:
/// `ON DELETE CASCADE` on `owner_key_id` would delete a hook when its owner key is deleted — exactly
/// what `RBAC_MODEL.md` §6 forbids — and `ON DELETE SET NULL` would silently orphan the resource at
/// the moment of deletion, which is the outcome §6's pre-flight inventory exists to make impossible
/// by *refusing* instead.
///
/// So the guarantee here is deliberately an application-layer one, and pinning that in a test is
/// what stops a well-meaning future migration from "fixing the missing constraint" and thereby
/// breaking §6. If that migration is ever written, this test is the thing that says why not.
#[tokio::test]
async fn key_lineage_and_ownership_columns_are_unconstrained_by_design() {
    let db = setup_test_db().await;
    let (owner, _) = insert_key(&db, "Owner", "", KeyScopes::parent()).await;
    let (child, _) = insert_key(&db, "Child", "", KeyScopes::plain()).await;
    set_parent(&db, child, owner).await;
    let hook_id = insert_hook_owned_by(&db, "owned", "/bin/true", owner).await;

    // Deleting the owner directly — bypassing the §6 handler, which is the only thing that would
    // have refused — succeeds, and leaves the references dangling rather than cascading.
    ApiKey::delete_by_id(owner).exec(&db).await.expect("no FK blocks this");

    let orphaned_hook = Hook::find_by_id(hook_id)
        .one(&db)
        .await
        .expect("querying hooks succeeds")
        .expect("the hook survives: a CASCADE here would violate RBAC_MODEL.md §6");
    assert_eq!(
        orphaned_hook.owner_key_id,
        Some(owner),
        "and the reference still names the departed key rather than being nulled — §6's inventory \
         is what must prevent reaching this state, not the schema"
    );

    let orphaned_child = ApiKey::find_by_id(child)
        .one(&db)
        .await
        .expect("querying keys succeeds")
        .expect("the child key survives its parent's deletion (R3: lineage confers no authority)");
    assert_eq!(orphaned_child.parent_key_id, Some(owner));
}

// ── Counting helpers ─────────────────────────────────────────────────────────
//
// Local to this file rather than added to `common`: they exist to express "how many children does
// this parent still have", which is a question only referential-integrity tests ask.

async fn count_perms_for_hook(db: &DatabaseConnection, hook_id: Uuid) -> u64 {
    ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::HookId.eq(hook_id))
        .count(db)
        .await
        .expect("counting permissions succeeds")
}

async fn count_perms_for_key(db: &DatabaseConnection, key_id: Uuid) -> u64 {
    ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(key_id))
        .count(db)
        .await
        .expect("counting permissions succeeds")
}

async fn count_params_for_hook(db: &DatabaseConnection, hook_id: Uuid) -> u64 {
    HookParameter::find()
        .filter(hook_parameter::Column::HookId.eq(hook_id))
        .count(db)
        .await
        .expect("counting parameters succeeds")
}

async fn count_executions_for_hook(db: &DatabaseConnection, hook_id: Uuid) -> u64 {
    Execution::find()
        .filter(execution::Column::HookId.eq(hook_id))
        .count(db)
        .await
        .expect("counting executions succeeds")
}
