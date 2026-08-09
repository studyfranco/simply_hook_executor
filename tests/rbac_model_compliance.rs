//! Compliance suite for `RBAC_MODEL.md`, indexed by rule.
//!
//! **Every test name in this file begins with the rule or section it enforces** — `r1_` through
//! `r7_`, `s3_` through `s7_`. That is the entire point of the file existing separately from
//! `hook_executor_integration_tests.rs`: coverage against the specification becomes auditable by
//! reading `cargo test --test rbac_model_compliance -- --list`, rather than by trusting that
//! somebody remembered to write a test when a rule was implemented.
//!
//! `scripts/verify_convergence.sh` enforces the invariant mechanically: it fails if any rule R1–R7
//! or section §3–§7 has no test whose name carries its prefix. A rule can therefore be *unenforced*
//! (that is a finding, recorded in `AGENT_NOTES.MD`) but it can no longer be silently *untested*.
//!
//! These tests are deliberately close to the specification's own wording, and deliberately
//! redundant with the behavioural tests next door. The behavioural suite asks "does this endpoint
//! do the right thing"; this one asks "is this sentence of the model true of the running service".
//! When the two disagree, the model wins.

#[allow(dead_code)]
mod common;

use axum::http::StatusCode;
use common::*;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
};
use sea_orm_migration::SchemaManager;
use serde_json::json;
use simply_hook_executor::{
    create_app,
    entities::{api_key, prelude::ApiKey},
};
use uuid::Uuid;

/// A key holding both halves of R2 on `hook`: `can_manage_keys`, and a `can_manage` row.
async fn parent_managing(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    hook: Uuid,
    can_execute: bool,
) -> (Uuid, String) {
    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (id, plaintext) = insert_key(db, name, "", scopes).await;
    grant(db, id, hook, can_execute, true).await;
    (id, plaintext)
}

// ═════════════════════════════════════════════════════════════
// R1 — Non-amplification
// ═════════════════════════════════════════════════════════════

/// > *A caller may only grant rights it currently holds itself. A holder of a single read-level
/// > verb may grant that verb and nothing more. Applies at every tier below Master.*
#[tokio::test]
async fn r1_a_caller_may_only_grant_verbs_it_holds_itself() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r1.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "r1_hook", &script, 30).await;
    // Manages the hook, deliberately without `can_execute` on it.
    let (parent_id, parent) = parent_managing(&db, "r1-parent", hook, false).await;
    let (daughter_id, _daughter) = insert_key(&db, "r1-daughter", "", KeyScopes::plain()).await;
    set_parent(&db, daughter_id, parent_id).await;

    let over = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{daughter_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(over.status, StatusCode::FORBIDDEN, "R1 violated: {}", over.raw);
    assert!(over.raw.contains("can_execute"), "the refusal names the verb: {}", over.raw);

    // "...may grant that verb and nothing more": the verb it *does* hold still passes.
    let within = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{daughter_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(within.status, StatusCode::OK, "R1 is a bound, not a ban: {}", within.raw);
}

// ═════════════════════════════════════════════════════════════
// R2 — Manage is a conjunction
// ═════════════════════════════════════════════════════════════

/// > *Managing a specific resource requires holding both global `can_manage_keys` AND a
/// > `can_manage = true` row for that specific resource. Neither alone is sufficient.
/// > `can_manage_keys` is never a global bypass of per-resource RBAC.*
#[tokio::test]
async fn r2_neither_half_of_the_conjunction_suffices_alone() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r2.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "r2_hook", &script, 30).await;
    let (target_id, _target) = insert_key(&db, "r2-target", "", KeyScopes::plain()).await;
    grant(&db, target_id, hook, true, false).await;

    let payload = json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false });

    // Half one: the global scope, and a manage row on some *other* hook — enough standing to reach
    // the per-hook decision, and nothing on the hook actually being administered. §4 makes that a
    // `404`: the refusal must not confirm the target hook is real.
    let elsewhere = insert_hook(&db, "r2_elsewhere", &script, 30).await;
    let scope_only = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (scope_id, scope_key) = insert_key(&db, "r2-scope-only", "", scope_only).await;
    grant(&db, scope_id, elsewhere, true, true).await;
    set_parent(&db, target_id, scope_id).await;
    let a = send(
        &app,
        json_request("POST", &format!("/api/keys/{target_id}/permissions"), &scope_key, Some(payload.clone())),
    )
    .await;
    assert_eq!(a.status, StatusCode::NOT_FOUND, "can_manage_keys alone must not suffice: {}", a.raw);

    // Half two: a `can_manage` row, no global scope. This is a Daughter key, which the Tiers matrix
    // says never manages resources.
    let (row_id, row_key) = insert_key(&db, "r2-row-only", "", KeyScopes::plain()).await;
    grant(&db, row_id, hook, true, true).await;
    let b = send(
        &app,
        json_request("POST", &format!("/api/keys/{target_id}/permissions"), &row_key, Some(payload.clone())),
    )
    .await;
    assert!(b.status.is_client_error(), "a manage row alone must not suffice: {}", b.raw);
    let _ = row_id;

    // Both halves: permitted. Without this the two refusals above could be caused by anything.
    grant(&db, scope_id, hook, true, true).await;
    let both = send(
        &app,
        json_request("POST", &format!("/api/keys/{target_id}/permissions"), &scope_key, Some(payload)),
    )
    .await;
    assert_eq!(both.status, StatusCode::OK, "both halves present must be permitted: {}", both.raw);
}

/// > *Where it lives on a shared managed resource, editing it is a management action on that
/// > resource and is governed by R2 in full — holding an operational verb, or a `can_manage` row
/// > without the global conjunct, does not authorise changing what the service executes or where it
/// > dispatches.* (§Terminology, Dispatch configuration)
///
/// The single highest-value assertion in this file. `script_path` is this service's dispatch
/// configuration: it names the binary the daemon runs. A Daughter holding a `can_manage` row could
/// once rewrite it and then trigger the hook with `can_execute` from the same row — arbitrary code
/// execution reachable from a key the Tiers matrix says "may manage resources: **Never**".
///
/// `require_master_for_privileged_hook` was never a defence here: it fires only for a hook that
/// *already* carries a `run_as_user`, and this attack works on an ordinary one. `ALLOWED_SCRIPT_ROOTS`
/// was not one either — it is empty by default, which means unrestricted.
#[tokio::test]
async fn r2_daughter_cannot_repoint_script_path() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let benign = scripts.write_script("r2_benign.sh", "#!/bin/sh\nexit 0\n");
    let attacker = scripts.write_script("r2_attacker.sh", "#!/bin/sh\nid > /tmp/pwned\n");

    let hook = insert_hook(&db, "r2_dispatch_hook", &benign, 30).await;

    // A Daughter: a `can_manage` row and no `can_manage_keys`. This is exactly half of R2, and the
    // half that used to be enough.
    let (daughter_id, daughter) = insert_key(&db, "r2-daughter", "", KeyScopes::plain()).await;
    grant(&db, daughter_id, hook, true, true).await;

    let repoint = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook}"),
            &daughter,
            Some(json!({ "script_path": attacker })),
        ),
    )
    .await;
    assert_eq!(
        repoint.status,
        StatusCode::FORBIDDEN,
        "R2: a Daughter repointed a hook's script_path — this is remote code execution: {}",
        repoint.raw
    );

    // The refusal must be real, not merely a status code: read the row back and confirm the daemon
    // would still run the original binary. A handler that refuses after writing has refused nothing.
    let row = fetch_hook_row(&db, hook).await.expect("hook row survives the refusal");
    assert_eq!(row.script_path, benign, "R2: the write landed despite the 403");

    // The same key may still *run* it — the operational verb is untouched, which is what makes this
    // a conjunction rather than a blanket demotion.
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/hooks/{hook}/execute"), &daughter, None))
            .await
            .status,
        StatusCode::OK,
        "R2 over-applied: can_execute is not what this rule governs"
    );

    // And a Parent holding the same row may repoint it. Without this the refusal above could be
    // caused by anything — a broken payload, an unrelated guard, a typo in the URI.
    let (_parent_id, parent) = parent_managing(&db, "r2-parent", hook, false).await;
    let permitted = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook}"),
            &parent,
            Some(json!({ "script_path": attacker })),
        ),
    )
    .await;
    assert_eq!(
        permitted.status,
        StatusCode::OK,
        "both halves of R2 must still permit the edit: {}",
        permitted.raw
    );
}

/// > *This conjunction governs every action `can_manage` authorises on that resource — delegation of
/// > permissions, lifecycle where §3 permits it, and editing dispatch configuration held on the
/// > resource itself.* (R2)
///
/// R2 was once enforced only on the delegation routes, leaving the *content* routes on a bare
/// `can_manage` row. This walks every one of them, because "governs every action" is a claim about a
/// set of endpoints and a test that probes one member of that set proves nothing about the rest —
/// the same gap that let a mutation survive in the §4 oracle suite.
#[tokio::test]
async fn r2_the_conjunction_governs_content_routes_not_only_delegation() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r2_content.sh", "#!/bin/sh\nexit 0\n");

    // The Parent owns the hook, so the lifecycle route in the positive pass clears §3 as well as R2.
    let (parent_id, parent) = insert_key(&db, "r2-content-parent", "", KeyScopes::parent()).await;
    let hook = insert_hook_owned_by(&db, "r2_content_hook", &script, parent_id).await;
    grant(&db, parent_id, hook, false, true).await;
    let param = insert_parameter(&db, hook, "existing", Some("v"), false).await;

    let (daughter_id, daughter) = insert_key(&db, "r2-content-daughter", "", KeyScopes::plain()).await;
    grant(&db, daughter_id, hook, true, true).await;

    let hook_uri = format!("/api/hooks/{hook}");
    let params_uri = format!("{hook_uri}/parameters");
    let param_uri = format!("{params_uri}/{param}");

    // Every content route behind `require_manage`. A Daughter holds a row on this hook, so it can
    // see the hook — §4 is satisfied by a `403`, and a `404` here would be a lie it could disprove.
    let refusals: [(&str, &str, Option<serde_json::Value>); 5] = [
        ("PUT", &hook_uri, Some(json!({ "description": "seized" }))),
        ("POST", &params_uri, Some(json!({ "param_key": "injected", "default_value": "x" }))),
        ("PUT", &param_uri, Some(json!({ "default_value": "rewritten" }))),
        ("DELETE", &param_uri, None),
        ("DELETE", &hook_uri, None),
    ];
    for (method, uri, body) in refusals {
        let response = send(&app, json_request(method, uri, &daughter, body)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "R2: {method} {uri} accepted a Daughter holding only a can_manage row: {}",
            response.raw
        );
    }

    // The positive path, so the five refusals above cannot be explained by the routes being broken.
    for (method, uri, body) in [
        ("PUT", hook_uri.as_str(), Some(json!({ "description": "managed" }))),
        ("POST", params_uri.as_str(), Some(json!({ "param_key": "declared", "default_value": "x" }))),
        ("PUT", param_uri.as_str(), Some(json!({ "default_value": "rewritten" }))),
    ] {
        let response = send(&app, json_request(method, uri, &parent, body)).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "both halves of R2 must permit {method} {uri}: {}",
            response.raw
        );
    }
    assert_eq!(
        send(&app, json_request("DELETE", &hook_uri, &parent, None)).await.status,
        StatusCode::NO_CONTENT,
        "R2 plus §3 ownership must permit the lifecycle route"
    );
}

/// > *...lifecycle where §3 permits it...* (R2)
///
/// R2 is a gate in *front* of §3, never a substitute for it. The phrase "where §3 permits it" makes
/// the conjunction necessary for a lifecycle action, and §3 independently makes ownership necessary;
/// a caller must clear both. This pins the direction that a careless reading of R2 would break —
/// treating the conjunction as sufficient authority to delete.
#[tokio::test]
async fn r2_the_conjunction_is_not_a_substitute_for_section_3_ownership() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r2_owned.sh", "#!/bin/sh\nexit 0\n");

    let (owner_id, owner) = insert_key(&db, "r2-owner", "", KeyScopes::parent()).await;
    let hook = insert_hook_owned_by(&db, "r2_owned_hook", &script, owner_id).await;
    grant(&db, owner_id, hook, true, true).await;

    // Holds *both* halves of R2 on this hook, and is not its owner.
    let (_intruder_id, intruder) = parent_managing(&db, "r2-intruder", hook, true).await;

    for (method, body, what) in [
        ("DELETE", None, "delete"),
        ("PUT", Some(json!({ "name": "seized" })), "rename"),
    ] {
        let response =
            send(&app, json_request(method, &format!("/api/hooks/{hook}"), &intruder, body)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "§3: a full R2 holder performed a {what} on a hook it does not own: {}",
            response.raw
        );
        assert!(
            response.raw.contains("owner"),
            "the refusal must name ownership, not the conjunction: {}",
            response.raw
        );
    }

    // Content management is untouched — the intruder really does manage this hook, which is what
    // makes the refusals above about §3 rather than about R2 firing a second time.
    assert_eq!(
        send(
            &app,
            json_request(
                "PUT",
                &format!("/api/hooks/{hook}"),
                &intruder,
                Some(json!({ "description": "managed" }))
            )
        )
        .await
        .status,
        StatusCode::OK,
        "§3 over-applied: a manage holder may still edit content"
    );

    // The owner, holding both halves itself, may delete.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &owner, None)).await.status,
        StatusCode::NO_CONTENT,
        "the owner holding R2 in full may run the lifecycle action"
    );
}

// ═════════════════════════════════════════════════════════════
// R3 — Parentage confers no authority
// ═════════════════════════════════════════════════════════════

/// > *`parent_key_id` exists solely for cascading deletion and visibility scoping. A daughter of the
/// > Master key is an ordinary daughter key with no elevated standing. Rights are never derived from
/// > key lineage.*
///
/// A negative rule, so the test constructs the violation it is looking for: two keys identical in
/// every respect except who created them, compared across every authority-bearing route.
#[tokio::test]
async fn r3_a_daughter_of_the_master_has_no_elevated_standing() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r3.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "r3_hook", &script, 30).await;
    let (master_id, _master) = insert_key(&db, "r3-master", "", KeyScopes::master()).await;
    let (parent_id, _parent) = insert_key(&db, "r3-parent", "", KeyScopes::plain()).await;

    let (of_master, key_a) = insert_key(&db, "r3-of-master", "", KeyScopes::plain()).await;
    let (of_parent, key_b) = insert_key(&db, "r3-of-parent", "", KeyScopes::plain()).await;
    set_parent(&db, of_master, master_id).await;
    set_parent(&db, of_parent, parent_id).await;

    // The lineage really differs, or every comparison below is vacuous.
    let a_row = ApiKey::find_by_id(of_master).one(&db).await.expect("query").expect("row");
    let b_row = ApiKey::find_by_id(of_parent).one(&db).await.expect("query").expect("row");
    assert_eq!(a_row.parent_key_id, Some(master_id));
    assert_eq!(b_row.parent_key_id, Some(parent_id));

    for (label, method, path, body) in [
        ("execute a hook", "POST", format!("/api/hooks/{hook}/execute"), Some(json!({}))),
        ("read a hook", "GET", format!("/api/hooks/{hook}"), None),
        ("delete a hook", "DELETE", format!("/api/hooks/{hook}"), None),
        ("list hooks", "GET", "/api/hooks".to_owned(), None),
        ("create a key", "POST", "/api/keys".to_owned(), Some(json!({ "name": "x" }))),
        ("list keys", "GET", "/api/keys".to_owned(), None),
        ("read the audit log", "GET", "/api/audit-logs".to_owned(), None),
        ("read settings", "GET", "/api/settings".to_owned(), None),
        ("list executions", "GET", "/api/executions".to_owned(), None),
    ] {
        let a = send(&app, json_request(method, &path, &key_a, body.clone())).await;
        let b = send(&app, json_request(method, &path, &key_b, body)).await;
        assert_eq!(
            a.status, b.status,
            "R3 violated: being the master's daughter changed '{label}' ({} vs {})",
            a.status, b.status
        );
    }
}

// ═════════════════════════════════════════════════════════════
// R4 — Only Master creates parents
// ═════════════════════════════════════════════════════════════

/// > *Only the Master key may grant `can_manage_keys` or resource-creation rights. A parent key can
/// > never mint another parent key.*
///
/// This service spells the resource-creation right `can_manage_hooks`; `RBAC_MODEL.md`'s
/// Terminology table calls it `can_create_executor`, which exists nowhere in `src/`.
#[tokio::test]
async fn r4_only_master_grants_can_manage_keys_or_resource_creation() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (parent_id, parent) = insert_key(&db, "r4-parent", "", scopes).await;
    let (_master_id, master) = insert_key(&db, "r4-master", "", KeyScopes::master()).await;

    for scope in ["can_manage_keys", "can_manage_hooks"] {
        // At creation.
        let minted = send(
            &app,
            json_request("POST", "/api/keys", &parent, Some(json!({ "name": "spawn", scope: true }))),
        )
        .await;
        assert_eq!(minted.status, StatusCode::FORBIDDEN, "R4 violated at creation for {scope}");

        // ...and by update, which must not become the back door creation just closed.
        let (victim_id, _victim) = insert_key(&db, &format!("r4-victim-{scope}"), "", KeyScopes::plain()).await;
        set_parent(&db, victim_id, parent_id).await;
        let updated = send(
            &app,
            json_request("PUT", &format!("/api/keys/{victim_id}"), &parent, Some(json!({ scope: true }))),
        )
        .await;
        assert_eq!(updated.status, StatusCode::FORBIDDEN, "R4 violated by update for {scope}");

        // Master may.
        let by_master = send(
            &app,
            json_request("POST", "/api/keys", &master, Some(json!({ "name": format!("ok-{scope}"), scope: true }))),
        )
        .await;
        assert_eq!(by_master.status, StatusCode::OK, "master must be able to grant {scope}");
    }
}

// ═════════════════════════════════════════════════════════════
// R5 — Manage may propagate sideways
// ═════════════════════════════════════════════════════════════

/// > *A parent holding manage rights on a resource may grant manage rights on that resource to
/// > another existing parent key (bounded by R1 and R2), but this can never elevate a daughter key
/// > to parent status.*
#[tokio::test]
async fn r5_manage_propagates_sideways_between_parents_but_never_mints_one() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r5.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "r5_hook", &script, 30).await;
    let (giver_id, giver) = parent_managing(&db, "r5-giver", hook, true).await;

    // Another *existing* parent, met through the shared hook rather than through lineage — which is
    // what "sideways" means. It already holds `can_manage_keys`; what it lacks is a manage row.
    let peer_scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (peer_id, peer) = insert_key(&db, "r5-peer", "", peer_scopes).await;
    grant(&db, peer_id, hook, true, false).await;

    let sideways = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{peer_id}/permissions"),
            &giver,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(sideways.status, StatusCode::OK, "R5: manage must propagate sideways: {}", sideways.raw);

    // The peer now holds both halves of R2 and can administer the hook itself.
    let (bystander_id, bystander) = insert_key(&db, "r5-bystander", "", KeyScopes::plain()).await;
    set_parent(&db, bystander_id, peer_id).await;
    let onward = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{bystander_id}/permissions"),
            &peer,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(onward.status, StatusCode::OK, "the propagated manage right is real: {}", onward.raw);

    // "...but this can never elevate a daughter key to parent status." Handing manage on a hook to
    // a key without `can_manage_keys` leaves it a daughter: it gets the row and nothing else.
    let promoted = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{bystander_id}/permissions"),
            &giver,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(promoted.status, StatusCode::OK, "granting the row itself is fine: {}", promoted.raw);
    let bystander_row = ApiKey::find_by_id(bystander_id).one(&db).await.expect("query").expect("row");
    assert!(!bystander_row.can_manage_keys, "R5 violated: a manage grant minted a parent");

    // ...and it still cannot administer grants, because R2 needs the half it does not have.
    let still_daughter = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{giver_id}/permissions"),
            &bystander,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": false })),
        ),
    )
    .await;
    assert!(
        still_daughter.status.is_client_error(),
        "R5/R2 violated: a daughter holding a manage row administered grants: {}",
        still_daughter.raw
    );
}

// ═════════════════════════════════════════════════════════════
// R6 — Revocation is never escalation
// ═════════════════════════════════════════════════════════════

/// > *Removing a permission requires manage rights on the resource only; the revoker need not hold
/// > the verb being removed, and may revoke its own permissions. Reducing an existing permission row
/// > through a general update endpoint is classified as revocation under this rule, regardless of
/// > which endpoint it arrives at.*
#[tokio::test]
async fn r6_revocation_needs_no_proof_and_both_routes_agree() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r6.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "r6_hook", &script, 30).await;
    // Manages the hook, and deliberately cannot execute it.
    let (parent_id, parent) = parent_managing(&db, "r6-parent", hook, false).await;
    let (target_id, _target) = insert_key(&db, "r6-target", "", KeyScopes::plain()).await;
    set_parent(&db, target_id, parent_id).await;
    grant(&db, target_id, hook, true, false).await;

    // Route A — `DELETE`. The revoker does not hold `can_execute` and does not need to.
    let deleted = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{target_id}/permissions/{hook}"), &parent, None),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "R6 violated on DELETE: {}", deleted.raw);

    // Route B — `POST` writing every verb to `false`, which reaches the same end state.
    grant(&db, target_id, hook, true, false).await;
    let zeroed = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{target_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(zeroed.status, StatusCode::OK, "R6 violated on POST: {}", zeroed.raw);

    // Self-revocation, last: it drops the authority everything above depends on.
    let itself = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{parent_id}/permissions/{hook}"), &parent, None),
    )
    .await;
    assert_eq!(itself.status, StatusCode::NO_CONTENT, "R6 violated for self-revocation: {}", itself.raw);
}

// ═════════════════════════════════════════════════════════════
// R7 — Granting is bounded by R1 and R2 together
// ═════════════════════════════════════════════════════════════

/// > *Granting is bounded by R1 and R2 together, simultaneously and without exception.*
///
/// The "simultaneously" is what this test is for. Satisfying one rule must never be a way past the
/// other — which is precisely what the `2d62d1b` early return did, skipping both for any
/// `can_manage_keys` holder.
#[tokio::test]
async fn r7_satisfying_one_rule_is_never_a_way_past_the_other() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("r7.sh", "#!/bin/sh\nexit 0\n");

    // Three hooks, so each half of the bound can be isolated without re-granting anything.
    let full = insert_hook(&db, "r7_full", &script, 30).await;
    let theirs = insert_hook(&db, "r7_theirs", &script, 30).await;
    let manage_only = insert_hook(&db, "r7_manage_only", &script, 30).await;

    let (parent_id, parent) = parent_managing(&db, "r7-parent", full, true).await;
    grant(&db, parent_id, manage_only, false, true).await;
    let (target_id, _target) = insert_key(&db, "r7-target", "", KeyScopes::plain()).await;
    set_parent(&db, target_id, parent_id).await;

    // Control: both rules satisfied on `full`, so the grant lands. If this failed, the two refusals
    // below would prove nothing.
    let ok = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{target_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": full.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "R7 over-applied: {}", ok.raw);

    // R1 satisfied *somewhere* — the caller does hold `can_execute`, on `full` — but R2 is not
    // satisfied *here*. Standing elsewhere must not carry.
    let cross = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{target_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": theirs.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND, "R7: R1 standing elsewhere is not R2 here: {}", cross.raw);

    // R2 satisfied here — a manage row on `manage_only` — but R1 is not: the caller does not hold
    // the verb it is handing out on this hook.
    let over = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{target_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": manage_only.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(over.status, StatusCode::FORBIDDEN, "R7: R2 here is not R1 here: {}", over.raw);
    assert!(over.raw.contains("can_execute"), "and the refusal names the verb: {}", over.raw);
}

// ═════════════════════════════════════════════════════════════
// §3 — Resource lifecycle & ownership
// ═════════════════════════════════════════════════════════════

/// > *Resource lifecycle actions — deleting or renaming the entity itself — are restricted
/// > exclusively to Master and the designated `owner_key_id`. Holding manage rights or any
/// > operational verb confers no lifecycle authority ... Master may reassign `owner_key_id` on any
/// > resource or creator-private entity at any time.*
///
/// Both non-master callers are Parents. R2 says the conjunction governs "lifecycle where §3 permits
/// it", so it sits *in front of* §3 rather than beside it — and a Daughter here would be refused by
/// R2 before §3 was ever consulted, turning every assertion below into a restatement of R2.
#[tokio::test]
async fn s3_lifecycle_is_the_owners_and_masters_alone() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("s3.sh", "#!/bin/sh\nexit 0\n");

    let (owner_id, owner) = insert_key(&db, "s3-owner", "", KeyScopes::parent()).await;
    let (user_id, user) = insert_key(&db, "s3-user", "", KeyScopes::parent()).await;
    let (_master_id, master) = insert_key(&db, "s3-master", "", KeyScopes::master()).await;
    let hook = insert_hook_owned_by(&db, "s3_hook", &script, owner_id).await;
    grant(&db, owner_id, hook, true, true).await;
    grant(&db, user_id, hook, true, true).await;

    // "a parent that merely uses a resource must not be able to delete it" — even holding both verbs.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &user, None)).await.status,
        StatusCode::FORBIDDEN,
        "§3 violated: a manage holder deleted a hook it does not own"
    );
    assert_eq!(
        send(&app, json_request("PUT", &format!("/api/hooks/{hook}"), &user, Some(json!({ "name": "taken" })))).await.status,
        StatusCode::FORBIDDEN,
        "§3 violated: a manage holder renamed a hook it does not own"
    );
    // ...while operational management is untouched.
    assert_eq!(
        send(&app, json_request("PUT", &format!("/api/hooks/{hook}"), &user, Some(json!({ "description": "d" })))).await.status,
        StatusCode::OK,
        "§3 over-applied: manage must still mean manage"
    );

    // "Master may reassign `owner_key_id` ... at any time", and only master.
    assert_eq!(
        send(&app, json_request("PUT", &format!("/api/hooks/{hook}"), &owner, Some(json!({ "owner_key_id": user_id })))).await.status,
        StatusCode::FORBIDDEN,
        "§3 violated: ownership is not delegable by its holder"
    );
    assert_eq!(
        send(&app, json_request("PUT", &format!("/api/hooks/{hook}"), &master, Some(json!({ "owner_key_id": user_id })))).await.status,
        StatusCode::OK,
        "§3 violated: master must be able to reassign ownership"
    );

    // Authority moved with the column.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &owner, None)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &user, None)).await.status,
        StatusCode::NO_CONTENT
    );
}

// ═════════════════════════════════════════════════════════════
// §4 — Visibility & oracle discipline
// ═════════════════════════════════════════════════════════════

/// > *A parent sees, in minimal form only, any key holding a permission row on a resource it
/// > manages: id, name, and that key's rights on that resource alone. Global flags, bound IPs, and
/// > unrelated resource memberships remain hidden.*
#[tokio::test]
async fn s4_a_shared_resource_is_not_a_keyhole_into_a_whole_configuration() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("s4.sh", "#!/bin/sh\nexit 0\n");

    let shared = insert_hook(&db, "s4_shared", &script, 30).await;
    let elsewhere = insert_hook(&db, "s4_elsewhere", &script, 30).await;
    let (_ours_id, ours) = parent_managing(&db, "s4-ours", shared, true).await;

    let their_scopes =
        KeyScopes { can_manage_keys: true, can_manage_hooks: true, max_concurrent_jobs: 9, ..Default::default() };
    let (theirs_id, _theirs) = insert_key(&db, "s4-theirs", "10.1.2.0/24", their_scopes).await;
    grant(&db, theirs_id, shared, true, false).await;
    grant(&db, theirs_id, elsewhere, true, true).await;

    let listing = send(&app, json_request("GET", "/api/keys", &ours, None)).await;
    let entry = listing
        .json
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|e| e["id"].as_str() == Some(&theirs_id.to_string()))
        .expect("§4: a key sharing a managed resource must be visible in minimal form");

    for hidden in ["bound_ips", "can_manage_keys", "can_manage_hooks", "is_master", "prefix", "max_concurrent_jobs"] {
        assert!(entry.get(hidden).is_none(), "§4 violated: '{hidden}' disclosed through a shared resource: {entry}");
    }
    let names: Vec<String> = entry["hook_permissions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p["hook_name"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(names, vec!["s4_shared".to_owned()], "§4 violated: unrelated memberships disclosed");
}

/// > *Any key, resource, or dispatch target outside the caller's visibility scope must return the
/// > identical status and body the service would return if that id did not exist.*
#[tokio::test]
async fn s4_out_of_scope_ids_are_byte_identical_to_nonexistent_ones() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("s4o.sh", "#!/bin/sh\nexit 0\n");

    let real_hook = insert_hook(&db, "s4_real", &script, 30).await;
    let (real_key, _rk) = insert_key(&db, "s4-unrelated", "", KeyScopes::plain()).await;
    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (_caller_id, caller) = insert_key(&db, "s4-caller", "", scopes).await;

    let invented_hook = Uuid::new_v4();
    let invented_key = Uuid::new_v4();

    // Every hook route, not just the read. `GET` fails visibility outright, while execute/modify
    // reach the per-verb guard — two different code paths that must give the same answer, or the
    // oracle simply moves to whichever endpoint was left behind.
    for (method, suffix, body) in [
        ("GET", "", None),
        ("POST", "/execute", Some(json!({}))),
        ("POST", "/test", None),
        ("PUT", "", Some(json!({ "description": "x" }))),
        ("DELETE", "", None),
        ("GET", "/parameters", None),
    ] {
        let a = send(
            &app,
            json_request(method, &format!("/api/hooks/{real_hook}{suffix}"), &caller, body.clone()),
        )
        .await;
        let b = send(
            &app,
            json_request(method, &format!("/api/hooks/{invented_hook}{suffix}"), &caller, body),
        )
        .await;
        assert_eq!(
            a.status,
            StatusCode::NOT_FOUND,
            "§4 violated: {method}{suffix} makes an invisible hook distinguishable ({})",
            a.raw
        );
        assert_eq!(a.status, b.status, "§4 violated: {method}{suffix} status differs");
        assert_eq!(a.raw, b.raw, "§4 violated: {method}{suffix} body differs");
    }

    let c = send(&app, json_request("PUT", &format!("/api/keys/{real_key}"), &caller, Some(json!({ "name": "x" })))).await;
    let d = send(&app, json_request("PUT", &format!("/api/keys/{invented_key}"), &caller, Some(json!({ "name": "x" })))).await;
    assert_eq!(c.status, StatusCode::NOT_FOUND, "§4 violated: an invisible key is distinguishable");
    assert_eq!(c.status, d.status, "§4 violated: status differs");
    assert_eq!(c.raw, d.raw, "§4 violated: body differs");
}

/// > *It is a distinct control from the authenticate-then-authorize ordering rule, which governs
/// > unauthenticated callers probing key bindings via 401-vs-403. Both hold simultaneously; neither
/// > may be satisfied by regressing the other.*
///
/// The companion to [`s4_out_of_scope_ids_are_byte_identical_to_nonexistent_ones`]. Making every
/// refusal `404` would break this test; making every refusal `403` would break that one.
#[tokio::test]
async fn s4_the_401_vs_403_ordering_still_holds_for_unauthenticated_callers() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, bound) = insert_key(&db, "s4-bound", "10.10.10.0/24", KeyScopes::plain()).await;

    let unknown = send(&app, json_request("GET", "/api/hooks", "never-issued", None)).await;
    let none = send(&app, json_request("GET", "/api/hooks", "", None)).await;
    let wrong_network = send(&app, json_request("GET", "/api/hooks", &bound, None)).await;

    assert_eq!(none.status, StatusCode::UNAUTHORIZED, "no credential must be 401");
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED, "an unknown credential must be 401, never 403");
    assert_eq!(wrong_network.status, StatusCode::FORBIDDEN, "a real key outside its bound_ips must be 403");
    assert_ne!(
        unknown.status, wrong_network.status,
        "authenticate-then-authorize violated: 403 can now confirm a guessed key exists"
    );
}

// ═════════════════════════════════════════════════════════════
// §5 — Master key guarantees
// ═════════════════════════════════════════════════════════════

/// > *Exactly one Master key exists, enforced by a database constraint rather than by application
/// > logic alone. `is_master` must not be settable or clearable through any API endpoint ... The
/// > Master key is immutable through the API except for its own `bound_ips` ... cannot be deleted.*
#[tokio::test]
async fn s5_exactly_one_master_immutable_and_undeletable() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master) = insert_key(&db, "s5-master", "", KeyScopes::master()).await;

    // Enforced by the database, not by application logic alone: a direct insert must fail.
    let now = chrono::Utc::now().naive_utc();
    let plaintext = simply_hook_executor::api::generate_random_key();
    let second = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_hook_executor::api::hash_key(&plaintext)),
        name: Set("s5-smuggled".to_owned()),
        prefix: Set(plaintext.chars().take(8).collect()),
        key_id: Set(Some(simply_hook_executor::api::generate_key_id())),
        signing_secret: Set(None),
        hmac_mode: Set(simply_hook_executor::entities::api_key::HmacMode::CanonicalV1),
        bound_ips: Set(Some(String::new())),
        max_concurrent_jobs: Set(10),
        is_master: Set(true),
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        can_manage_keys: Set(true),
        can_manage_hooks: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await;
    assert!(second.is_err(), "§5 violated: the database accepted a second master row");

    // Not settable through any endpoint, by any caller.
    let minted = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "peer", "is_master": true }))),
    )
    .await;
    assert!(minted.status.is_client_error(), "§5 violated: is_master was accepted on create");
    assert_eq!(
        ApiKey::find().filter(api_key::Column::IsMaster.eq(true)).all(&db).await.expect("query").len(),
        1,
        "§5 violated: more than one master exists"
    );

    // Immutable except its own bound_ips.
    assert_eq!(
        send(&app, json_request("PUT", &format!("/api/keys/{master_id}"), &master, Some(json!({ "bound_ips": "127.0.0.0/8" })))).await.status,
        StatusCode::OK,
        "§5 over-applied: the master must be able to edit its own bound_ips"
    );
    for field in ["name", "hmac_mode"] {
        let value = if field == "name" { json!("renamed") } else { json!("BODY_ONLY") };
        assert_eq!(
            send(&app, json_request("PUT", &format!("/api/keys/{master_id}"), &master, Some(json!({ field: value })))).await.status,
            StatusCode::FORBIDDEN,
            "§5 violated: the master's '{field}' was mutable"
        );
    }

    // Neither deletable nor rotatable, by anyone.
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/keys/{master_id}/rotate"), &master, None)).await.status,
        StatusCode::FORBIDDEN,
        "§5 violated: the master rotated itself"
    );
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/keys/{master_id}"), &master, None)).await.status,
        StatusCode::FORBIDDEN,
        "§5 violated: the master deleted itself"
    );
}

// ═════════════════════════════════════════════════════════════
// §6 — Cascade deletion & pre-flight inventory
// ═════════════════════════════════════════════════════════════

/// > *Deleting a key cascades recursively through its entire daughter subtree ... Before any key
/// > deletion, the service walks the entire subtree being deleted and collects every resource and
/// > dispatch target owned by any key within it ... Deletion executes only when every entity in the
/// > inventory carries an explicit resolution; partial maps are refused.*
#[tokio::test]
async fn s6_the_cascade_is_recursive_and_gated_on_a_total_resolution_map() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("s6.sh", "#!/bin/sh\nexit 0\n");

    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (parent_id, _parent) = insert_key(&db, "s6-parent", "", scopes).await;
    let (daughter_id, _daughter) = insert_key(&db, "s6-daughter", "", KeyScopes::plain()).await;
    let (grand_id, _grand) = insert_key(&db, "s6-grand", "", KeyScopes::plain()).await;
    set_parent(&db, daughter_id, parent_id).await;
    set_parent(&db, grand_id, daughter_id).await;
    let deep = insert_hook_owned_by(&db, "s6_deep_hook", &script, grand_id).await;
    let (successor_id, _successor) = insert_key(&db, "s6-successor", "", KeyScopes::plain()).await;
    let (_master_id, master) = insert_key(&db, "s6-master", "", KeyScopes::master()).await;

    // The walk reaches two levels down, or the deep hook is stranded silently.
    let refused = send(&app, json_request("DELETE", &format!("/api/keys/{parent_id}"), &master, None)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "§6 violated: deletion proceeded with an unresolved inventory");
    let inventory = refused.json["inventory"].as_array().cloned().unwrap_or_default();
    assert_eq!(inventory.len(), 1, "§6 violated: the inventory missed a resource: {}", refused.raw);
    assert_eq!(inventory[0]["current_owner"], json!(grand_id.to_string()), "§6: the walk must reach the real owner");
    for field in ["type", "id", "name", "current_owner"] {
        assert!(inventory[0].get(field).is_some(), "§6 violated: inventory entry lacks '{field}'");
    }

    // Partial maps are refused — here, an empty one against a non-empty inventory.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/keys/{parent_id}"), &master, Some(json!({ "resolutions": {} })))).await.status,
        StatusCode::CONFLICT,
        "§6 violated: a partial map executed"
    );

    // A total map executes, and the resource survives rather than being destroyed.
    let done = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": { deep.to_string(): { "action": "reassign", "to": successor_id.to_string() } } })),
        ),
    )
    .await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "§6: a total map must execute: {}", done.raw);

    for id in [parent_id, daughter_id, grand_id] {
        assert!(
            ApiKey::find_by_id(id).one(&db).await.expect("query").is_none(),
            "§6 violated: the cascade did not reach {id}"
        );
    }
    let survivor = fetch_hook_row(&db, deep).await.expect("§6 violated: the hook was destroyed with the key");
    assert_eq!(survivor.owner_key_id, Some(successor_id), "§6: reassignment must move ownership");
    assert!(!survivor.is_deleted, "§6: reassignment is not deletion");
}

// ═════════════════════════════════════════════════════════════
// §7 — Database constraints & indexing
// ═════════════════════════════════════════════════════════════

/// > *A database-level constraint guaranteeing Master uniqueness, per §5. Indexes on
/// > `parent_key_id`, `owner_key_id`, the key-hash lookup column, and the permission-table join
/// > columns — every column the authenticated hot paths search on.*
///
/// Asserted through SeaORM's `SchemaManager` rather than by querying `sqlite_master`, so the check
/// stays backend-agnostic and does not become the vendor-specific SQL `AGENT.MD` forbids.
#[tokio::test]
async fn s7_every_required_index_and_constraint_exists() {
    let db = setup_test_db().await;
    let manager = SchemaManager::new(&db);

    for (table, index) in [
        // §5's master-uniqueness constraint, as the portable generated-column form.
        ("api_keys", "idx_api_keys_master_marker"),
        ("api_keys", "idx_api_keys_parent_key_id"),
        ("api_keys", "idx_api_keys_owner_key_id"),
        ("hooks", "idx_hooks_owner_key_id"),
    ] {
        assert!(
            manager.has_index(table, index).await.expect("index lookup succeeds"),
            "§7 violated: {table}.{index} is missing"
        );
    }

    // The key-hash lookup column and the permission-table join columns predate this work and carry
    // unique indexes from the initial migration. Asserted by *behaviour* rather than by name,
    // because their index names are backend-generated from the UNIQUE constraints: a duplicate must
    // be rejected, which is only possible if the index exists.
    let (_id, _plain) = insert_key(&db, "s7-probe", "", KeyScopes::plain()).await;
    let existing = ApiKey::find().one(&db).await.expect("query").expect("row");
    let now = chrono::Utc::now().naive_utc();
    let clash = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(existing.key_hash.clone()),
        name: Set("s7-clash".to_owned()),
        prefix: Set("clash".to_owned()),
        key_id: Set(Some(simply_hook_executor::api::generate_key_id())),
        signing_secret: Set(None),
        hmac_mode: Set(simply_hook_executor::entities::api_key::HmacMode::CanonicalV1),
        bound_ips: Set(Some(String::new())),
        max_concurrent_jobs: Set(10),
        is_master: Set(false),
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        can_manage_keys: Set(false),
        can_manage_hooks: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await;
    assert!(clash.is_err(), "§7 violated: api_keys.key_hash is not uniquely indexed");
}

// ═════════════════════════════════════════════════════════════
// Adversarial coverage — infrastructure-level guarantees
// ═════════════════════════════════════════════════════════════
//
// Every test below is named `<rule>_adversarial_<description>`, and every one of them reaches the
// guarantee it tests **without going through the code that is supposed to uphold it**: raw SQL
// rather than the entity layer, raw request bytes rather than a typed payload struct.
//
// The distinction is the whole point, and `RBAC_MODEL.md` §5 now states it outright:
//
// > *Any test asserting this constraint must attempt an adversarial write — a direct insert setting
// > `is_master` with the marker absent or NULL. A test that cooperatively supplies the marker proves
// > only that a well-behaved writer behaves well, which is not what this rule is about.*
//
// A cooperative test of a structural claim is close to worthless: it exercises the same helper the
// production path uses, so it passes for a service whose guarantee lives entirely in that helper and
// evaporates the moment anything else writes to the table. These tests are written from the position
// of a caller that has no interest in cooperating — a migration on another branch, a maintenance
// script, an `INSERT` typed at a psql prompt, a curl invocation with a hand-written body.

/// **§5, adversarially.** A direct SQL insert setting `is_master = true` without mentioning the
/// marker column at all.
///
/// > *The uniqueness marker must be derived by the database engine from `is_master` ... An
/// > application-maintained marker does not satisfy this rule. Any writer can set `is_master = true`
/// > and leave the marker NULL, and NULL values do not collide in a unique index, so a second Master
/// > is accepted.*
///
/// This is the test that separates the two designs, and it is deliberately written in raw SQL rather
/// than through `api_key::ActiveModel`. Going through the entity layer would prove less than it
/// appears to: `master_marker` is absent from the model, so SeaORM *cannot* emit it, and the insert
/// would omit the column whether the column were generated or not. Raw SQL removes that alibi — this
/// statement is what a maintenance script or a psql session would type, and nothing in this process
/// gets a say in it.
///
/// A service whose marker is an ordinary column maintained by application code passes every
/// cooperative §5 test and fails this one.
#[tokio::test]
async fn s5_adversarial_direct_sql_insert_cannot_mint_a_second_master() {
    let db = setup_test_db().await;
    let (_master_id, _master) = insert_key(&db, "s5-adv-master", "", KeyScopes::master()).await;

    let smuggled = Uuid::new_v4();
    let plaintext = simply_hook_executor::api::generate_random_key();
    let key_hash = simply_hook_executor::api::hash_key(&plaintext);
    let key_id = simply_hook_executor::api::generate_key_id();
    let now = chrono::Utc::now().naive_utc();

    // Every column named explicitly except `master_marker`, exactly as an operator writing this by
    // hand would — they cannot name a column they do not know exists.
    let insert = format!(
        "INSERT INTO api_keys \
         (id, key_hash, name, prefix, key_id, hmac_mode, bound_ips, max_concurrent_jobs, \
          is_master, can_manage_keys, can_manage_hooks, created_at, updated_at) \
         VALUES ('{smuggled}', '{key_hash}', 's5-adv-smuggled', 'smuggled', '{key_id}', \
                 'CANONICAL_V1', '', 10, true, true, true, '{now}', '{now}')"
    );
    let refused = db.execute_unprepared(&insert).await;
    assert!(
        refused.is_err(),
        "§5 violated: raw SQL minted a second master. The marker is not engine-derived — it is an \
         ordinary column that only the application remembers to populate, which §5 names explicitly \
         as insufficient."
    );

    // The refusal has to be the *uniqueness* constraint, not a typo in the statement above. A
    // malformed INSERT would also return `Err`, and would make this test pass for the wrong reason
    // forever. The same statement with `is_master = false` must succeed.
    let ordinary = Uuid::new_v4();
    let ordinary_hash = simply_hook_executor::api::hash_key(
        &simply_hook_executor::api::generate_random_key(),
    );
    let ordinary_key_id = simply_hook_executor::api::generate_key_id();
    db.execute_unprepared(&format!(
        "INSERT INTO api_keys \
         (id, key_hash, name, prefix, key_id, hmac_mode, bound_ips, max_concurrent_jobs, \
          is_master, can_manage_keys, can_manage_hooks, created_at, updated_at) \
         VALUES ('{ordinary}', '{ordinary_hash}', 's5-adv-ordinary', 'ordinry', \
                 '{ordinary_key_id}', 'CANONICAL_V1', '', 10, false, false, false, '{now}', '{now}')"
    ))
    .await
    .expect(
        "the identical statement with is_master = false must succeed — otherwise the refusal above \
         proves only that this test's SQL is malformed",
    );

    // Promotion by UPDATE is the same attack with an extra step, and a generated column recomputes
    // on update rather than only on insert.
    let promoted = db
        .execute_unprepared(&format!("UPDATE api_keys SET is_master = true WHERE id = '{ordinary}'"))
        .await;
    assert!(
        promoted.is_err(),
        "§5 violated: an UPDATE promoted a second key to master. A generated marker is recomputed \
         on update; this passing would mean the constraint only guards INSERT."
    );

    assert_eq!(
        ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .all(&db)
            .await
            .expect("query")
            .len(),
        1,
        "§5 violated: the database holds more than one master"
    );
}

/// **§5, adversarially.** The marker is not writable, which is what makes it a constraint rather
/// than a convention.
///
/// > *Because the marker is engine-derived it must not be writable: it may not appear as a settable
/// > field on any entity, bootstrap path, fixture, or test helper.*
///
/// An engine-generated column rejects any attempt to supply a value for it, on every supported
/// backend. That refusal *is* the guarantee: it is why no writer anywhere — including a future
/// handler, a fixture, or this test — can set `is_master = true` while quietly parking the marker at
/// `NULL` to dodge the unique index. A plain column would accept both statements below.
#[tokio::test]
async fn s5_adversarial_the_marker_column_refuses_to_be_written() {
    let db = setup_test_db().await;
    let (master_id, _master) = insert_key(&db, "s5-adv-write", "", KeyScopes::master()).await;

    let now = chrono::Utc::now().naive_utc();
    let plaintext = simply_hook_executor::api::generate_random_key();
    let key_hash = simply_hook_executor::api::hash_key(&plaintext);
    let key_id = simply_hook_executor::api::generate_key_id();

    // The precise dodge §5 describes: claim mastery, hand the marker an explicit NULL, and rely on
    // NULLs not colliding in a unique index.
    let with_null_marker = db
        .execute_unprepared(&format!(
            "INSERT INTO api_keys \
             (id, key_hash, name, prefix, key_id, hmac_mode, bound_ips, max_concurrent_jobs, \
              is_master, master_marker, can_manage_keys, can_manage_hooks, created_at, updated_at) \
             VALUES ('{}', '{key_hash}', 's5-adv-null', 'nullmrk', '{key_id}', 'CANONICAL_V1', '', \
                     10, true, NULL, true, true, '{now}', '{now}')",
            Uuid::new_v4()
        ))
        .await;
    assert!(
        with_null_marker.is_err(),
        "§5 violated: a writer supplied its own NULL marker alongside is_master = true and the \
         database accepted it. This is the exact bypass an application-maintained marker permits."
    );

    // And it cannot be cleared off the existing master either.
    let cleared = db
        .execute_unprepared(&format!(
            "UPDATE api_keys SET master_marker = NULL WHERE id = '{master_id}'"
        ))
        .await;
    assert!(
        cleared.is_err(),
        "§5 violated: the marker was cleared by hand, which would free the unique index to accept a \
         second master"
    );
}

/// **§5 payload safety, adversarially.** `is_master` on the wire, as bytes rather than as a struct.
///
/// > *`is_master` must not be settable or clearable through any API endpoint ... Removing the field
/// > from the payload type is required; rejecting it at the handler is not sufficient, since a later
/// > handler can reintroduce the path.*
///
/// Sending `json!({...})` through a typed helper is not a real test of that sentence: the field
/// either exists on the payload struct or it does not, and if it does not, the test is asserting
/// what the compiler already knows. These bodies are hand-written `&str` — the exact bytes a curl
/// invocation would put on the socket, including malformed shapes a `serde_json::Value` could not
/// represent.
///
/// The requirement is that the **deserializer** refuses, which is why the expected status is `422`
/// rather than `403`: nothing in the authorization layer is consulted, so there is no handler left
/// to reintroduce the path. `deny_unknown_fields` plus the absence of the field is what produces it.
#[tokio::test]
async fn s5_adversarial_raw_bytes_cannot_smuggle_is_master_onto_a_key() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master) = insert_key(&db, "s5-adv-payload", "", KeyScopes::master()).await;

    let create_bodies = [
        r#"{"name":"smuggle","is_master":true}"#,
        // Ordering must not matter: a deserializer that stops at the first unknown key would pass
        // the case above and fail this one.
        r#"{"is_master":true,"name":"smuggle"}"#,
        // Duplicate keys — last-wins parsing is a classic smuggling primitive.
        r#"{"name":"smuggle","is_master":false,"is_master":true}"#,
        // Truthy-but-not-true, in case anything downstream coerces.
        r#"{"name":"smuggle","is_master":1}"#,
        r#"{"name":"smuggle","is_master":"true"}"#,
        // Nested, in case a flattened struct is ever introduced.
        r#"{"name":"smuggle","scopes":{"is_master":true}}"#,
        // Alternate spellings, in case a rename attribute is ever added.
        r#"{"name":"smuggle","isMaster":true}"#,
        r#"{"name":"smuggle","IS_MASTER":true}"#,
        // The marker itself, in case it is ever mistakenly exposed.
        r#"{"name":"smuggle","master_marker":1}"#,
    ];
    for body in create_bodies {
        let response =
            send(&app, raw_request("POST", "/api/keys", &master, body.as_bytes().to_vec())).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "§5 violated: POST /api/keys did not refuse {body} at the deserializer: {}",
            response.raw
        );
    }

    // The update route is named by the same sentence and is a separate extractor.
    let update_bodies = [
        r#"{"is_master":true}"#,
        r#"{"name":"renamed","is_master":true}"#,
        // Clearing is forbidden by the same clause as setting.
        r#"{"is_master":false}"#,
        r#"{"master_marker":null}"#,
    ];
    for body in update_bodies {
        let response = send(
            &app,
            raw_request("PUT", &format!("/api/keys/{master_id}"), &master, body.as_bytes().to_vec()),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "§5 violated: PUT /api/keys/{{id}} did not refuse {body} at the deserializer: {}",
            response.raw
        );
    }

    // Nothing landed, and the deployment still has exactly one master.
    assert_eq!(
        ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .all(&db)
            .await
            .expect("query")
            .len(),
        1,
        "§5 violated: a smuggled payload minted a master"
    );

    // A well-formed body on the same route must still succeed, or every assertion above could be
    // explained by the route being broken rather than by the deserializer being strict.
    let legitimate = send(
        &app,
        raw_request("POST", "/api/keys", &master, br#"{"name":"legitimate"}"#.to_vec()),
    )
    .await;
    assert_eq!(
        legitimate.status,
        StatusCode::OK,
        "the strict extractor rejected a valid body: {}",
        legitimate.raw
    );
}

/// **§7, adversarially.** Referential integrity survives without DDL foreign keys.
///
/// > *Where a target engine cannot express a constraint in DDL (for example SQLite's lack of
/// > `ALTER TABLE ADD CONSTRAINT` for foreign keys), the application-level equivalent must be covered
/// > by a test that runs in CI. A constraint that holds only in production is one CI never checks.*
///
/// `parent_key_id` and `owner_key_id` deliberately carry **no** foreign key — see the migration's
/// note: `CASCADE` would destroy the very resources §6 forbids destroying implicitly, and `SET NULL`
/// would orphan them exactly when §6's inventory needs to name their owner. The integrity those
/// constraints would have provided is therefore the application's job, and this is the CI test §7
/// now requires of it.
///
/// Adversarial in the direction that matters: the dangling rows are written **by raw SQL**, so the
/// application layer never gets the chance to prevent them and must instead survive finding them.
#[tokio::test]
async fn s7_adversarial_dangling_lineage_written_behind_the_applications_back() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_master_id, master) = insert_key(&db, "s7-adv-master", "", KeyScopes::master()).await;
    let (orphan_id, orphan) = insert_key(&db, "s7-adv-orphan", "", KeyScopes::plain()).await;

    // A parent that does not exist. No FK stops this, which is the premise of the test.
    let ghost = Uuid::new_v4();
    db.execute_unprepared(&format!(
        "UPDATE api_keys SET parent_key_id = '{ghost}' WHERE id = '{orphan_id}'"
    ))
    .await
    .expect("no foreign key prevents a dangling parent — that is precisely why §7 wants this test");

    // The service must stay upright and answer, rather than 500 on a broken join or spin forever
    // walking a lineage that leads nowhere.
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &orphan, None)).await.status,
        StatusCode::OK,
        "§7: a dangling parent_key_id broke the orphan's own authentication path"
    );
    assert_eq!(
        send(&app, json_request("GET", "/api/keys", &master, None)).await.status,
        StatusCode::OK,
        "§7: a dangling parent_key_id broke the key listing"
    );

    // A lineage *cycle* is the case a foreign key would not have prevented either. Note what this
    // does and does not prove: mutation testing showed that removing the `seen` set from
    // `descendant_key_ids` changes nothing, because `parent_key_id` is single-valued, so the only
    // way a cycle re-enters the frontier is through the root — which the walk already filters out.
    // Termination comes from the structure, not from the guard. This is kept as a shape regression:
    // if the walk ever gains a second lineage edge, or drops the root filter, the guard stops being
    // redundant and this is the test that will be here to notice.
    let (a_id, _a) = insert_key(&db, "s7-adv-cycle-a", "", KeyScopes::plain()).await;
    let (b_id, _b) = insert_key(&db, "s7-adv-cycle-b", "", KeyScopes::plain()).await;
    db.execute_unprepared(&format!(
        "UPDATE api_keys SET parent_key_id = '{b_id}' WHERE id = '{a_id}'"
    ))
    .await
    .expect("cycle half one");
    db.execute_unprepared(&format!(
        "UPDATE api_keys SET parent_key_id = '{a_id}' WHERE id = '{b_id}'"
    ))
    .await
    .expect("cycle half two");

    let listed = send(&app, json_request("GET", "/api/keys", &master, None)).await;
    assert_eq!(listed.status, StatusCode::OK, "§7: a parent_key_id cycle hung or broke the listing");

    // Ownership is the other unconstrained column. A hook owned by a key that never existed must not
    // become undeletable or crash the inventory §6 builds before a cascade.
    let scripts = ScriptDir::new();
    let script = scripts.write_script("s7_adv.sh", "#!/bin/sh\nexit 0\n");
    let hook = insert_hook(&db, "s7_adv_hook", &script, 30).await;
    db.execute_unprepared(&format!(
        "UPDATE hooks SET owner_key_id = '{ghost}' WHERE id = '{hook}'"
    ))
    .await
    .expect("no foreign key prevents a dangling owner either");

    assert_eq!(
        send(&app, json_request("GET", &format!("/api/hooks/{hook}"), &master, None)).await.status,
        StatusCode::OK,
        "§7: a dangling owner_key_id broke reading the hook"
    );
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/keys/{orphan_id}"), &master, None))
            .await
            .status,
        StatusCode::NO_CONTENT,
        "§7: a dangling owner elsewhere in the table broke an unrelated cascade"
    );

    // The application-level equivalent of the FK, on the write path: the API refuses to *create* the
    // dangling state the raw SQL above forced. This is the half a foreign key would have done, and
    // the half that has to be tested because there is no foreign key to do it.
    let dangling = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook}"),
            &master,
            Some(json!({ "owner_key_id": Uuid::new_v4().to_string() })),
        ),
    )
    .await;
    assert_eq!(
        dangling.status,
        StatusCode::BAD_REQUEST,
        "§7: the API accepted an owner_key_id naming no existing key, so nothing enforces \
         referential integrity on this column at all: {}",
        dangling.raw
    );
}
