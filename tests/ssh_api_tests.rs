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
async fn deleting_a_target_still_referenced_by_a_hook_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (owner_id, master) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;
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
    let _ = owner_id;

    let response = send(&app, json_request("DELETE", &format!("/api/ssh-targets/{target_id}"), &master, None)).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert!(response.string("error").contains("ssh_hook"), "error should name the blocking hook: {}", response.raw);
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
