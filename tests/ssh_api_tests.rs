//! Route-level coverage for `api::ssh` (SSH credential/target management) and the
//! `execution_type`/`ssh_target_id` additions to `api::hooks`: the mandatory matrix from
//! `AGENT.MD` — positive assertions, authentication (401), authorization boundaries (403), input
//! validation (400), and the referential-conflict (409) paths specific to this feature.
//!
//! What this file does **not** cover: actually connecting anywhere. `SshConnectionSpec`/
//! `run_remote_process`/`test_connection`/`fetch_host_key_fingerprint` against a real (in-process)
//! SSH server are `tests/ssh_runner_integration_tests.rs`'s job; this file only ever reaches as far
//! as building request/response shapes and database state.

// Unlike the suite's other integration files, this one is narrowly scoped to the SSH management
// routes and touches only a small slice of `common`'s exhaustive helper surface (the hook-execution,
// signing, and script-fixture helpers exist for the other files) — `#[allow(dead_code)]` here is
// about *this file's* usage, not a claim that any helper in `common` itself is unused across the
// suite as a whole.
#[allow(dead_code)]
mod common;

use axum::http::StatusCode;
use common::*;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::json;
use simply_hook_executor::{
    create_app,
    entities::{ssh_credential, ssh_target},
};
use uuid::Uuid;

/// Inserts a `PASSWORD` SSH credential directly (bypassing the API), returning its id.
async fn insert_password_credential(db: &sea_orm::DatabaseConnection, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    ssh_credential::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        auth_type: Set(ssh_credential::SshAuthType::Password),
        encrypted_private_key: Set(None),
        encrypted_passphrase: Set(None),
        encrypted_password: Set(Some("v1.plain.746573743031".to_owned())),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("seeding an SSH credential succeeds");
    id
}

/// Inserts an SSH target directly (bypassing the API), pinned with a syntactically valid but
/// meaningless fingerprint, returning its id.
async fn insert_target(db: &sea_orm::DatabaseConnection, name: &str, credential_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    ssh_target::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        host: Set("198.51.100.1".to_owned()),
        port: Set(22),
        username: Set("deploy".to_owned()),
        credential_id: Set(credential_id),
        host_key_fingerprint: Set(Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("seeding an SSH target succeeds");
    id
}

// ─────────────────────────────────────────────────────────────
// SSH credentials
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_credential_routes_require_authentication() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let request = with_connect_info(
        axum::http::Request::builder().method("GET").uri("/api/ssh-credentials"),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(send(&app, request).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ssh_credential_crud_is_master_only() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, non_master) = insert_key(&db, "daughter", "0.0.0.0/0", KeyScopes::plain()).await;

    for (method, uri, body) in [
        ("POST", "/api/ssh-credentials", Some(json!({"name": "x", "auth_type": "PASSWORD", "password": "p"}))),
        ("GET", "/api/ssh-credentials", None),
    ] {
        let response = send(&app, json_request(method, uri, &non_master, body)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{method} {uri} should be master-only");
    }
}

#[tokio::test]
async fn creates_a_key_credential_and_never_returns_the_secret() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    let response = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-credentials",
            &master,
            Some(json!({
                "name": "deploy-key",
                "auth_type": "KEY",
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
                "passphrase": "hunter2"
            })),
        ),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("auth_type"), "KEY");
    assert_eq!(response.field("has_private_key"), true);
    assert_eq!(response.field("has_passphrase"), true);
    assert_eq!(response.field("has_password"), false);
    // The raw text must never appear anywhere in the response body — not just absent under the
    // expected field names, in case a bug serialized it under a different one.
    assert!(!response.raw.contains("fake"), "response leaked private key material: {}", response.raw);
    assert!(!response.raw.contains("hunter2"), "response leaked the passphrase: {}", response.raw);
}

#[tokio::test]
async fn key_credential_without_a_private_key_is_rejected() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    let response = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-credentials",
            &master,
            Some(json!({"name": "no-key", "auth_type": "KEY"})),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn duplicate_credential_name_is_a_conflict() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    insert_password_credential(&db, "dup").await;

    let response = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-credentials",
            &master,
            Some(json!({"name": "dup", "auth_type": "PASSWORD", "password": "p"})),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn switching_auth_type_drops_the_other_modes_secret() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "switcher").await;

    let response = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/ssh-credentials/{cred_id}"),
            &master,
            Some(json!({
                "auth_type": "KEY",
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
            })),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("auth_type"), "KEY");
    assert_eq!(response.field("has_private_key"), true);
    assert_eq!(response.field("has_password"), false, "the old PASSWORD secret must not survive the switch");
}

#[tokio::test]
async fn clearing_the_only_secret_a_mode_needs_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "protected").await;

    let response = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/ssh-credentials/{cred_id}"),
            &master,
            Some(json!({"password": ""})),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_a_credential_still_used_by_a_target_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "in-use").await;
    insert_target(&db, "blocker", cred_id).await;

    let response = send(&app, json_request("DELETE", &format!("/api/ssh-credentials/{cred_id}"), &master, None)).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert!(response.string("error").contains("blocker"), "error should name the blocking target: {}", response.raw);
}

#[tokio::test]
async fn deleting_an_unused_credential_succeeds() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "unused").await;

    let response = send(&app, json_request("DELETE", &format!("/api/ssh-credentials/{cred_id}"), &master, None)).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
}

// ─────────────────────────────────────────────────────────────
// SSH targets
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn target_reads_are_open_to_can_manage_hooks_but_writes_are_not() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, hook_manager) = insert_key(&db, "hook-manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;

    let list = send(&app, json_request("GET", "/api/ssh-targets", &hook_manager, None)).await;
    assert_eq!(list.status, StatusCode::OK);

    let create = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &hook_manager,
            Some(json!({
                "name": "nope", "host": "10.0.0.1", "username": "u",
                "credential_id": Uuid::new_v4()
            })),
        ),
    )
    .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn creates_a_target_and_resolves_the_credential_name() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "prod-key").await;

    let response = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &master,
            Some(json!({
                "name": "prod-web-01",
                "host": "203.0.113.5",
                "username": "deploy",
                "credential_id": cred_id,
                "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            })),
        ),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("port"), 22, "port defaults to 22");
    assert_eq!(response.field("credential_name"), "prod-key");
}

#[tokio::test]
async fn target_creation_validates_port_and_credential_existence() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "ok-cred").await;

    let bad_port = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &master,
            Some(json!({"name": "a", "host": "h", "username": "u", "credential_id": cred_id, "port": 70000})),
        ),
    )
    .await;
    assert_eq!(bad_port.status, StatusCode::BAD_REQUEST);

    let missing_credential = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &master,
            Some(json!({"name": "b", "host": "h", "username": "u", "credential_id": Uuid::new_v4()})),
        ),
    )
    .await;
    assert_eq!(missing_credential.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_host_key_fingerprint_is_rejected() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "ok-cred-2").await;

    let response = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &master,
            Some(json!({
                "name": "bad-fp", "host": "h", "username": "u", "credential_id": cred_id,
                "host_key_fingerprint": "not-a-fingerprint"
            })),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fetch_fingerprint_against_an_unreachable_host_reports_failure_as_200() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    // Port 0 as a *connection target* is refused at the OS socket layer near-instantly on every
    // platform, which is what keeps this test fast without needing a real unreachable-but-routed
    // address (slow to fail) or a mock.
    let response = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets/fetch-fingerprint",
            &master,
            Some(json!({"host": "127.0.0.1", "port": 1})),
        ),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK, "a probe's outcome is data, not an HTTP error");
    assert_eq!(response.field("success"), false);
}

#[tokio::test]
async fn deleting_a_target_deactivates_referencing_hooks_instead_of_refusing() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_owner_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "hook-cred").await;
    let target_id = insert_target(&db, "hook-target", cred_id).await;

    let create_hook = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "ssh_hook",
                "script_path": "deploy.sh",
                "execution_type": "SSH",
                "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(create_hook.status, StatusCode::OK, "{}", create_hook.raw);
    let hook_id = create_hook.string("id");

    // Deleting the target must succeed (204 No Content) and cascade deactivation to the hook.
    let response = send(&app, json_request("DELETE", &format!("/api/ssh-targets/{target_id}"), &master, None)).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);

    // Verify hook is now deactivated
    let get_hook = send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &master, None)).await;
    assert_eq!(get_hook.status, StatusCode::OK);
    assert_eq!(get_hook.field("is_active"), false);
    assert!(get_hook.field("ssh_target_id").is_null());
    assert_eq!(
        get_hook.string("disabled_reason"),
        "SSH target 'hook-target' was deleted"
    );

    // Attempting to execute the deactivated hook must fail
    let run = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/execute"),
            &master,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(run.status, StatusCode::BAD_REQUEST);
    assert!(run.string("error").contains("deactivated"));

    // Updating the hook to LOCAL and setting is_active = true reactivates it
    let reactivate = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook_id}"),
            &master,
            Some(json!({
                "execution_type": "LOCAL",
                "script_path": "/bin/true",
                "is_active": true
            })),
        ),
    )
    .await;
    assert_eq!(reactivate.status, StatusCode::OK, "{}", reactivate.raw);
    assert_eq!(reactivate.field("is_active"), true);
    assert!(reactivate.field("disabled_reason").is_null());
}

#[tokio::test]
async fn ssh_manager_can_create_and_manage_own_credentials_and_targets() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_master_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let (_mgr_a_id, mgr_a) = insert_key(&db, "mgr-a", "0.0.0.0/0", KeyScopes::ssh_manager()).await;
    let (_mgr_b_id, mgr_b) = insert_key(&db, "mgr-b", "0.0.0.0/0", KeyScopes::ssh_manager()).await;

    // Manager A creates a credential
    let cred = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-credentials",
            &mgr_a,
            Some(json!({
                "name": "cred-a",
                "auth_type": "PASSWORD",
                "password": "secretpassword"
            })),
        ),
    )
    .await;
    assert_eq!(cred.status, StatusCode::OK, "{}", cred.raw);
    let cred_id = cred.string("id");
    assert_eq!(cred.field("is_owner"), true);

    // Manager A creates a target using that credential
    let target = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &mgr_a,
            Some(json!({
                "name": "target-a",
                "host": "192.168.1.10",
                "username": "admin",
                "credential_id": cred_id
            })),
        ),
    )
    .await;
    assert_eq!(target.status, StatusCode::OK, "{}", target.raw);
    let target_id = target.string("id");
    assert_eq!(target.field("is_owner"), true);
    assert_eq!(target.field("can_use_in_hook"), true);

    // Manager B cannot see target-a without permission
    let b_view = send(&app, json_request("GET", &format!("/api/ssh-targets/{target_id}"), &mgr_b, None)).await;
    assert_eq!(b_view.status, StatusCode::NOT_FOUND);

    // Manager B cannot modify or delete Manager A's target
    let b_update = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/ssh-targets/{target_id}"),
            &mgr_b,
            Some(json!({"name": "hacked"})),
        ),
    )
    .await;
    assert_eq!(b_update.status, StatusCode::FORBIDDEN);

    let b_del = send(&app, json_request("DELETE", &format!("/api/ssh-targets/{target_id}"), &mgr_b, None)).await;
    assert_eq!(b_del.status, StatusCode::FORBIDDEN);

    // Master can see and delete everything
    let master_view = send(&app, json_request("GET", &format!("/api/ssh-targets/{target_id}"), &master, None)).await;
    assert_eq!(master_view.status, StatusCode::OK);
    assert_eq!(master_view.field("is_owner"), true);
    assert_eq!(master_view.field("can_use_in_hook"), true);
}

#[tokio::test]
async fn ssh_target_permissions_and_hook_creation_enforcement() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_master_id, _master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let (owner_id, owner_key) = insert_key(&db, "owner-ssh", "0.0.0.0/0", KeyScopes::ssh_manager()).await;
    let (dev_id, dev_key) = insert_key(&db, "dev-hook", "0.0.0.0/0", KeyScopes::hook_manager()).await;

    // Owner creates credential and target
    let cred = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-credentials",
            &owner_key,
            Some(json!({
                "name": "owner-cred",
                "auth_type": "PASSWORD",
                "password": "pwd"
            })),
        ),
    )
    .await;
    let cred_id = cred.string("id");

    let target = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &owner_key,
            Some(json!({
                "name": "owner-target",
                "host": "10.0.0.5",
                "username": "user",
                "credential_id": cred_id
            })),
        ),
    )
    .await;
    let target_id = target.string("id");

    // Dev tries to create hook referencing Owner's target without permission -> 403 Forbidden
    let unauth_hook = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &dev_key,
            Some(json!({
                "name": "dev-hook",
                "script_path": "run.sh",
                "execution_type": "SSH",
                "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(unauth_hook.status, StatusCode::FORBIDDEN, "{}", unauth_hook.raw);

    // Owner grants permission to Dev
    let grant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/ssh-targets/{target_id}/permissions"),
            &owner_key,
            Some(json!({
                "api_key_id": dev_id,
                "can_use_in_hook": true
            })),
        ),
    )
    .await;
    assert_eq!(grant.status, StatusCode::OK, "{}", grant.raw);

    // List permissions as Owner
    let perms = send(
        &app,
        json_request("GET", &format!("/api/ssh-targets/{target_id}/permissions"), &owner_key, None),
    )
    .await;
    assert_eq!(perms.status, StatusCode::OK, "{}", perms.raw);
    assert_eq!(perms.json.as_array().expect("array").len(), 1);

    // Now Dev can create the hook!
    let auth_hook = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &dev_key,
            Some(json!({
                "name": "dev-hook",
                "script_path": "run.sh",
                "execution_type": "SSH",
                "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(auth_hook.status, StatusCode::OK, "{}", auth_hook.raw);

    // Owner revokes Dev's permission
    let revoke = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/ssh-targets/{target_id}/permissions/{dev_id}"),
            &owner_key,
            None,
        ),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    // Check permissions list is now empty
    let perms_after = send(
        &app,
        json_request("GET", &format!("/api/ssh-targets/{target_id}/permissions"), &owner_key, None),
    )
    .await;
    assert_eq!(perms_after.json.as_array().expect("array").len(), 0);
    let _ = owner_id;
}

// ─────────────────────────────────────────────────────────────
// Hook `execution_type` / `ssh_target_id`
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_hook_requires_a_valid_target() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    let no_target = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({"name": "no_target", "script_path": "run.sh", "execution_type": "SSH"})),
        ),
    )
    .await;
    assert_eq!(no_target.status, StatusCode::BAD_REQUEST);

    let bogus_target = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "bogus_target", "script_path": "run.sh",
                "execution_type": "SSH", "ssh_target_id": Uuid::new_v4()
            })),
        ),
    )
    .await;
    assert_eq!(bogus_target.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn local_hook_rejects_a_relative_script_path_but_ssh_hook_accepts_it() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "loose-cred").await;
    let target_id = insert_target(&db, "loose-target", cred_id).await;

    let local = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({"name": "local_relative", "script_path": "relative.sh"})),
        ),
    )
    .await;
    assert_eq!(local.status, StatusCode::BAD_REQUEST, "LOCAL requires an absolute, root-confined path");

    let remote = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "ssh_relative", "script_path": "relative.sh",
                "execution_type": "SSH", "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(remote.status, StatusCode::OK, "{}", remote.raw);
}

#[tokio::test]
async fn switching_a_hook_back_to_local_clears_its_ssh_target() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
    let cred_id = insert_password_credential(&db, "flip-cred").await;
    let target_id = insert_target(&db, "flip-target", cred_id).await;

    let created = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "flip", "script_path": "remote.sh",
                "execution_type": "SSH", "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let hook_id = created.string("id");

    let updated = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook_id}"),
            &master,
            Some(json!({
                "execution_type": "LOCAL",
                "script_path": "/usr/local/bin/local.sh",
                // Sent deliberately alongside the switch to LOCAL: the server must clear it
                // regardless of this field being present, per `update_hook`'s own contract.
                "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.raw);
    assert_eq!(updated.field("execution_type"), "LOCAL");
    assert!(updated.field("ssh_target_id").is_null(), "ssh_target_id must be cleared: {}", updated.raw);
}

#[tokio::test]
async fn deactivated_ssh_hook_cannot_be_executed_until_reactivated() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    // 1. Create credential and target
    let cred = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-credentials",
            &master,
            Some(json!({
                "name": "deact-cred",
                "auth_type": "PASSWORD",
                "password": "pwd"
            })),
        ),
    )
    .await;
    let cred_id = cred.string("id");

    let target = send(
        &app,
        json_request(
            "POST",
            "/api/ssh-targets",
            &master,
            Some(json!({
                "name": "deact-target",
                "host": "10.0.0.99",
                "username": "deploy",
                "credential_id": cred_id
            })),
        ),
    )
    .await;
    let target_id = target.string("id");

    // 2. Create SSH hook referencing target
    let hook = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "deact-hook",
                "script_path": "deploy.sh",
                "execution_type": "SSH",
                "ssh_target_id": target_id
            })),
        ),
    )
    .await;
    assert_eq!(hook.status, StatusCode::OK);
    let hook_id = hook.string("id");
    assert_eq!(hook.field("is_active"), true);

    // 3. Delete target -> hook must become deactivated
    let del = send(
        &app,
        json_request("DELETE", &format!("/api/ssh-targets/{target_id}"), &master, None),
    )
    .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);

    // Verify hook state is now deactivated
    let inspect = send(
        &app,
        json_request("GET", &format!("/api/hooks/{hook_id}"), &master, None),
    )
    .await;
    assert_eq!(inspect.field("is_active"), false);
    assert!(inspect.field("disabled_reason").as_str().unwrap().contains("SSH target"));

    // 4. Executing the deactivated hook must fail with 400 Bad Request
    let exec = send(
        &app,
        json_request("POST", "/api/hooks/deact-hook/execute", &master, None),
    )
    .await;
    assert_eq!(exec.status, StatusCode::BAD_REQUEST);
    assert!(exec.raw.contains("deactivated"));

    // 5. Updating the hook to LOCAL re-activates it
    let reactivated = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook_id}"),
            &master,
            Some(json!({
                "execution_type": "LOCAL",
                "script_path": "/bin/true",
                "is_active": true
            })),
        ),
    )
    .await;
    assert_eq!(reactivated.status, StatusCode::OK);
    assert_eq!(reactivated.field("is_active"), true);
}
