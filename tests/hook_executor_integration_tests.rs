//! Integration tests covering the mandatory matrix from `AGENT.MD`: positive assertions,
//! authentication (401), authorization boundaries (403), input validation (400), concurrency
//! throttling (429), and execution timeouts — plus the security properties the execution engine
//! is responsible for (no shell, cleared environment, process-group kill).

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use hmac::{Hmac, KeyInit, Mac};
use sea_orm::EntityTrait;
use serde_json::json;
use sha2::Sha256;
use simply_hook_executor::{
    config::RuntimeConfig, create_app, entities::prelude::Execution,
    retention::purge_expired_executions, spawn_retention_worker, state::AppState,
};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
// Authentication (401) & network binding (403)
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn missing_or_invalid_api_key_is_rejected() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let request = with_connect_info(axum::http::Request::builder().uri("/api/hooks"))
        .body(axum::body::Body::empty())
        .expect("request builds");
    assert_eq!(send(&app, request).await.status, StatusCode::UNAUTHORIZED);

    let response = send(&app, json_request("GET", "/api/hooks", "not-a-real-key", None)).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bound_cidr_is_enforced_against_the_resolved_client_ip() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, key) = insert_key(&db, "Bound Key", "192.168.1.1/32", KeyScopes::plain()).await;

    // ConnectInfo says 127.0.0.1, which is outside the bound range.
    let response = send(&app, json_request("GET", "/api/hooks", &key, None)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);

    // A matching forwarded hop is accepted.
    let request = with_connect_info(
        axum::http::Request::builder()
            .uri("/api/hooks")
            .header("X-API-Key", &key)
            .header("X-Forwarded-For", "10.0.0.1, 192.168.1.1"),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(send(&app, request).await.status, StatusCode::OK);
}

#[tokio::test]
async fn hmac_signature_is_verified_over_the_raw_body() {
    let dir = ScriptDir::new();
    let script = dir.write_script("signed.sh", "echo signed");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "signed_hook", &script, 30).await;
    grant(&db, key_id, hook_id, true, false).await;

    let body = json!({ "parameters": {} }).to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key");
    mac.update(body.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

    let signed = |sig: &str, payload: &str| {
        with_connect_info(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/api/hooks/{hook_id}/execute"))
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json")
                .header("X-Signature-256", sig),
        )
        .body(axum::body::Body::from(payload.to_owned()))
        .expect("request builds")
    };

    assert_eq!(send(&app, signed(&signature, &body)).await.status, StatusCode::OK);

    // Same signature, altered body: rejected.
    let tampered = json!({ "parameters": { "x": "1" } }).to_string();
    assert_eq!(send(&app, signed(&signature, &tampered)).await.status, StatusCode::UNAUTHORIZED);

    // Malformed signature header: rejected.
    assert_eq!(send(&app, signed("sha256=deadbeef", &body)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hmac_signature_failures_are_rejected_without_executing_anything() {
    let dir = ScriptDir::new();
    let side_effect = dir.path_for("must-not-run");
    let script = dir.write_script("signed_fail.sh", &format!("touch \"{side_effect}\""));

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    // A second valid key: a signature made with *someone else's* valid secret must not pass.
    let (_, other_key) = insert_key(&db, "Other Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "signed_fail", &script, 30).await;
    grant(&db, key_id, hook_id, true, false).await;

    let sign = |secret: &str, payload: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
        mac.update(payload.as_bytes());
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    };

    let request = |sig: &str, payload: &str| {
        with_connect_info(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/api/hooks/{hook_id}/execute"))
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json")
                .header("X-Signature-256", sig),
        )
        .body(axum::body::Body::from(payload.to_owned()))
        .expect("request builds")
    };

    let body = json!({ "parameters": {} }).to_string();
    let valid = sign(&key, &body);

    // Every one of these presents a *valid* API key — only the signature is wrong, so each must
    // still be rejected at the authentication layer.
    let rejected: Vec<(&str, String, String)> = vec![
        ("tampered body", valid.clone(), json!({ "parameters": { "x": "1" } }).to_string()),
        ("body with trailing whitespace", valid.clone(), format!("{body} ")),
        ("signature from another valid key", sign(&other_key, &body), body.clone()),
        ("signature of a different payload", sign(&key, "{}"), body.clone()),
        ("missing sha256= prefix", valid.trim_start_matches("sha256=").to_owned(), body.clone()),
        ("wrong algorithm prefix", format!("sha1={}", &valid[7..]), body.clone()),
        ("non-hex digest", "sha256=zzzz".to_owned(), body.clone()),
        ("empty digest", "sha256=".to_owned(), body.clone()),
        ("truncated digest", format!("sha256={}", &valid[7..20]), body.clone()),
    ];

    for (label, signature, payload) in rejected {
        let response = send(&app, request(&signature, &payload)).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{label} should have been rejected with 401"
        );
    }

    // Rejection happens before the engine is reached: nothing ran, nothing was recorded.
    assert!(!std::path::Path::new(&side_effect).exists(), "a rejected request must not spawn the script");
    assert_eq!(execution_count(&db).await, 0);

    // The control case still works, proving the hook itself was executable all along.
    assert_eq!(send(&app, request(&valid, &body)).await.status, StatusCode::OK);
    assert_eq!(execution_count(&db).await, 1);
}

// ─────────────────────────────────────────────────────────────
// Hook lifecycle & authorization boundaries (403)
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn hook_crud_lifecycle_and_creator_auto_provisioning() {
    let dir = ScriptDir::new();
    let script = dir.write_script("crud.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, manager) = insert_key(&db, "Hook Manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;

    let created = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &manager,
            Some(json!({
                "name": "deploy",
                "script_path": script,
                "default_timeout_seconds": 15,
                "parameters": [{ "param_key": "environment", "default_value": "staging" }]
            })),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let hook_id = created.string("id");

    // AGENT.MD: creating a hook must auto-grant full execute/manage rights on it.
    assert_eq!(created.field("can_execute"), &json!(true));
    assert_eq!(created.field("can_manage"), &json!(true));
    assert_eq!(created.field("parameters").as_array().map(Vec::len), Some(1));

    // Duplicate name -> 409, not a 500.
    let duplicate = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "deploy", "script_path": script }))),
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    // Readable by UUID and by name.
    assert_eq!(send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &manager, None)).await.status, StatusCode::OK);
    let by_name = send(&app, json_request("GET", "/api/hooks/deploy", &manager, None)).await;
    assert_eq!(by_name.status, StatusCode::OK);
    assert_eq!(by_name.string("id"), hook_id);

    let updated = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &manager, Some(json!({ "default_timeout_seconds": 45 }))),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.field("default_timeout_seconds"), &json!(45));

    let deleted = send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &manager, None)).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, json_request("GET", "/api/hooks/deploy", &manager, None)).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn hook_creation_and_management_respect_scopes() {
    let dir = ScriptDir::new();
    let script = dir.write_script("scoped.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (owner_id, _owner) = insert_key(&db, "Owner", "0.0.0.0/0", KeyScopes::hook_manager()).await;
    let (other_id, other) = insert_key(&db, "Other", "0.0.0.0/0", KeyScopes::plain()).await;

    // No can_manage_hooks scope -> cannot create.
    let denied = send(
        &app,
        json_request("POST", "/api/hooks", &other, Some(json!({ "name": "nope", "script_path": script }))),
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let hook_id = insert_hook(&db, "owned", &script, 30).await;
    grant(&db, owner_id, hook_id, true, true).await;
    // Execute-only grant: visible, runnable, but not manageable.
    grant(&db, other_id, hook_id, true, false).await;

    let update = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &other, Some(json!({ "name": "hijacked" }))),
    )
    .await;
    assert_eq!(update.status, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &other, None)).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn hooks_are_only_visible_to_keys_with_a_mapping() {
    let dir = ScriptDir::new();
    let script = dir.write_script("visible.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (mapped_id, mapped) = insert_key(&db, "Mapped", "0.0.0.0/0", KeyScopes::plain()).await;
    let (_, unmapped) = insert_key(&db, "Unmapped", "0.0.0.0/0", KeyScopes::plain()).await;
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    let hook_id = insert_hook(&db, "restricted", &script, 30).await;
    grant(&db, mapped_id, hook_id, true, false).await;

    let visible = send(&app, json_request("GET", "/api/hooks", &mapped, None)).await;
    assert_eq!(visible.json.as_array().map(Vec::len), Some(1));

    let hidden = send(&app, json_request("GET", "/api/hooks", &unmapped, None)).await;
    assert_eq!(hidden.json.as_array().map(Vec::len), Some(0));
    assert_eq!(send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &unmapped, None)).await.status, StatusCode::FORBIDDEN);

    let all = send(&app, json_request("GET", "/api/hooks", &master, None)).await;
    assert_eq!(all.json.as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn executing_without_can_execute_is_forbidden() {
    let dir = ScriptDir::new();
    let script = dir.write_script("guarded.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (manage_only_id, manage_only) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::plain()).await;
    let (_, stranger) = insert_key(&db, "Stranger", "0.0.0.0/0", KeyScopes::plain()).await;

    let hook_id = insert_hook(&db, "guarded", &script, 30).await;
    grant(&db, manage_only_id, hook_id, false, true).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    assert_eq!(send(&app, json_request("POST", &uri, &manage_only, None)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, json_request("POST", &uri, &stranger, None)).await.status, StatusCode::FORBIDDEN);
}

// ─────────────────────────────────────────────────────────────
// Execution engine
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn successful_execution_captures_output_and_records_history() {
    let dir = ScriptDir::new();
    let script = dir.write_script("hello.sh", "echo \"hello $HOOK_PARAM_TARGET\"\necho oops >&2");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "hello", &script, 30).await;
    insert_parameter(&db, hook_id, "target", None, true).await;
    grant(&db, key_id, hook_id, true, true).await;

    let response = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/execute"),
            &key,
            Some(json!({ "parameters": { "target": "world" } })),
        ),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("status"), &json!("SUCCESS"));
    assert_eq!(response.field("exit_code"), &json!(0));
    assert_eq!(response.string("stdout").trim(), "hello world");
    assert_eq!(response.string("stderr").trim(), "oops");
    assert_eq!(response.field("parameters"), &json!({ "target": "world" }));

    // The same record is retrievable from history.
    let history = send(&app, json_request("GET", "/api/executions", &key, None)).await;
    let rows = history.json.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["hook_name"], json!("hello"));

    let detail = send(
        &app,
        json_request("GET", &format!("/api/executions/{}", response.string("id")), &key, None),
    )
    .await;
    assert_eq!(detail.status, StatusCode::OK);
    assert_eq!(detail.string("stdout").trim(), "hello world");
}

#[tokio::test]
async fn non_zero_exit_is_recorded_as_failed() {
    let dir = ScriptDir::new();
    let script = dir.write_script("fail.sh", "echo boom >&2\nexit 3");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "failing", &script, 30).await;
    grant(&db, key_id, hook_id, true, false).await;

    // A failing script is a completed request whose recorded outcome is FAILED — not an HTTP error.
    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("status"), &json!("FAILED"));
    assert_eq!(response.field("exit_code"), &json!(3));
    assert_eq!(response.string("stderr").trim(), "boom");
}

#[tokio::test]
async fn parameters_are_injected_as_env_vars_and_positional_arguments() {
    let dir = ScriptDir::new();
    let script = dir.write_script("args.sh", "echo \"argv:$1|$2\"\necho \"env:$HOOK_PARAM_ALPHA|$HOOK_PARAM_BETA\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "args", &script, 30).await;
    insert_parameter(&db, hook_id, "alpha", None, true).await;
    insert_parameter(&db, hook_id, "beta", Some("default-beta"), true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let response = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/execute"),
            &key,
            Some(json!({ "parameters": { "alpha": "first" } })),
        ),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let stdout = response.string("stdout");
    assert!(stdout.contains("argv:first|default-beta"), "positional args in declaration order: {stdout}");
    assert!(stdout.contains("env:first|default-beta"), "HOOK_PARAM_* injection: {stdout}");
}

#[tokio::test]
async fn parameter_values_are_never_interpreted_by_a_shell() {
    let dir = ScriptDir::new();
    let script = dir.write_script("inject.sh", "echo \"got:[$1]\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "inject", &script, 30).await;
    insert_parameter(&db, hook_id, "payload", None, true).await;
    grant(&db, key_id, hook_id, true, false).await;

    // Classic injection payload: if any layer passed this through a shell, the `id` substitution
    // (or the `;` separator) would execute. Passed as a single argv entry, it stays inert data.
    let malicious = "; id > /tmp/pwned; echo $(whoami)";
    let response = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/execute"),
            &key,
            Some(json!({ "parameters": { "payload": malicious } })),
        ),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.string("stdout").trim(), format!("got:[{malicious}]"));
    assert!(!std::path::Path::new("/tmp/pwned").exists(), "no shell interpretation occurred");
}

#[tokio::test]
async fn child_environment_is_cleared_except_the_allowlist() {
    let dir = ScriptDir::new();
    let script = dir.write_script("env.sh", "env");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "envdump", &script, 30).await;
    insert_parameter(&db, hook_id, "target", None, true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let response = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/execute"),
            &key,
            Some(json!({ "parameters": { "target": "isolated" } })),
        ),
    )
    .await;

    let stdout = response.string("stdout");
    assert!(stdout.contains("PATH="), "the allowlisted PATH is inherited: {stdout}");
    assert!(stdout.contains("HOOK_PARAM_TARGET=isolated"), "parameters are injected: {stdout}");
    // cargo exports a pile of CARGO_* variables into this test process; none may reach the child.
    assert!(!stdout.contains("CARGO"), "non-allowlisted host variables must not leak: {stdout}");
}

#[tokio::test]
async fn timeout_kills_the_whole_process_group_and_records_timeout() {
    let dir = ScriptDir::new();
    let orphan_marker = dir.path_for("orphan-survived");
    // Backgrounds a grandchild that would create a marker file, then blocks. Killing only the
    // direct child would leave that grandchild alive to create the marker two seconds later.
    let script = dir.write_script(
        "slow.sh",
        &format!("(sleep 2; touch \"{orphan_marker}\") &\nsleep 30"),
    );

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "slow", &script, 1).await;
    grant(&db, key_id, hook_id, true, false).await;

    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("status"), &json!("TIMEOUT"));
    // SIGKILL is reported the way a shell would report it.
    assert_eq!(response.field("exit_code"), &json!(137));

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        !std::path::Path::new(&orphan_marker).exists(),
        "the backgrounded grandchild must have been killed with its process group"
    );
}

#[tokio::test]
async fn exceeding_max_concurrent_jobs_returns_429() {
    let dir = ScriptDir::new();
    let marker = dir.path_for("running");
    let script = dir.write_script("busy.sh", "touch \"$HOOK_PARAM_MARKER\"\nsleep 3");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Throttled", "0.0.0.0/0", KeyScopes::plain().with_jobs(1)).await;
    let hook_id = insert_hook(&db, "busy", &script, 30).await;
    insert_parameter(&db, hook_id, "marker", Some(&marker), true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let first = {
        let app = app.clone();
        let key = key.clone();
        let uri = uri.clone();
        tokio::spawn(async move { send(&app, json_request("POST", &uri, &key, None)).await })
    };

    // Wait until the script has demonstrably started, so the second request is guaranteed to
    // contend for the single permit rather than racing the first one's setup.
    let mut started = false;
    for _ in 0..100 {
        if std::path::Path::new(&marker).exists() {
            started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(started, "the first execution never started");

    let second = send(&app, json_request("POST", &uri, &key, None)).await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);

    let first = first.await.expect("the first request task completes");
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.field("status"), &json!("SUCCESS"));

    // The permit is released once the process exits, so the key is usable again.
    let third = send(&app, json_request("POST", &uri, &key, None)).await;
    assert_eq!(third.status, StatusCode::OK);
}

#[tokio::test]
async fn peak_load_burst_is_rejected_immediately_rather_than_queued() {
    let dir = ScriptDir::new();
    // Long enough that a queued (rather than rejected) request would be visibly slow.
    let script = dir.write_script("saturate.sh", "touch \"$HOOK_PARAM_MARKER\"\nsleep 5");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let budget = 2;
    let (key_id, key) = insert_key(&db, "Peak", "0.0.0.0/0", KeyScopes::plain().with_jobs(budget)).await;
    let hook_id = insert_hook(&db, "saturate", &script, 30).await;
    insert_parameter(&db, hook_id, "marker", None, true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");

    // Fill every slot, each job announcing itself through its own marker file.
    let markers: Vec<String> = (0..budget).map(|i| dir.path_for(&format!("slot-{i}"))).collect();
    let occupying: Vec<_> = markers
        .iter()
        .map(|marker| {
            let app = app.clone();
            let key = key.clone();
            let uri = uri.clone();
            let body = json!({ "parameters": { "marker": marker } });
            tokio::spawn(async move { send(&app, json_request("POST", &uri, &key, Some(body))).await })
        })
        .collect();

    let saturated = wait_until(Duration::from_secs(15), async || {
        markers.iter().all(|m| std::path::Path::new(m).exists())
    })
    .await;
    assert!(saturated, "the budget was never fully occupied");

    // Now hammer it well past the budget, all at once.
    let burst_size = 12;
    let started = std::time::Instant::now();
    let burst: Vec<_> = (0..burst_size)
        .map(|i| {
            let app = app.clone();
            let key = key.clone();
            let uri = uri.clone();
            let body = json!({ "parameters": { "marker": dir.path_for(&format!("burst-{i}")) } });
            tokio::spawn(async move { send(&app, json_request("POST", &uri, &key, Some(body))).await })
        })
        .collect();

    let mut rejected = 0;
    for task in burst {
        let response = task.await.expect("burst request task completes");
        assert_eq!(
            response.status,
            StatusCode::TOO_MANY_REQUESTS,
            "every over-budget request must be rejected, not admitted"
        );
        assert!(response.string("error").contains("Concurrency limit"));
        rejected += 1;
    }
    let elapsed = started.elapsed();

    assert_eq!(rejected, burst_size);
    // The occupying jobs sleep 5s. A burst that queued behind them could not have come back this
    // fast, so this is what actually distinguishes "rejected immediately" from "served eventually".
    assert!(
        elapsed < Duration::from_secs(3),
        "the burst should fail fast, but took {elapsed:?}"
    );
    // Nothing over budget was spawned: no burst marker exists.
    for i in 0..burst_size {
        assert!(
            !std::path::Path::new(&dir.path_for(&format!("burst-{i}"))).exists(),
            "a rejected request must not have started a process"
        );
    }
    // ...and no history rows were written for them either.
    assert_eq!(execution_count(&db).await, 0);

    // Once the occupying jobs finish, the full budget is available again.
    for task in occupying {
        let response = task.await.expect("occupying request task completes");
        assert_eq!(response.status, StatusCode::OK);
    }
    assert_eq!(execution_count(&db).await, u64::try_from(budget).expect("small budget"));

    for i in 0..budget {
        let body = json!({ "parameters": { "marker": dir.path_for(&format!("after-{i}")) } });
        let response = send(&app, json_request("POST", &uri, &key, Some(body))).await;
        assert_eq!(response.status, StatusCode::OK, "slot {i} was not released");
    }
}

// ─────────────────────────────────────────────────────────────
// Validation (400)
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn parameter_validation_rejects_missing_unknown_and_malformed_input() {
    let dir = ScriptDir::new();
    let script = dir.write_script("validate.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "validated", &script, 30).await;
    insert_parameter(&db, hook_id, "required_one", None, true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");

    let missing = send(&app, json_request("POST", &uri, &key, Some(json!({ "parameters": {} })))).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(missing.string("error").contains("required_one"));

    let unknown = send(
        &app,
        json_request("POST", &uri, &key, Some(json!({ "parameters": { "required_one": "x", "surprise": "y" } }))),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert!(unknown.string("error").contains("surprise"));

    let malformed = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(&uri)
            .header("X-API-Key", &key)
            .header("Content-Type", "application/json"),
    )
    .body(axum::body::Body::from("{not json"))
    .expect("request builds");
    assert_eq!(send(&app, malformed).await.status, StatusCode::BAD_REQUEST);

    // No execution row was created by any of the rejected requests.
    assert_eq!(execution_count(&db).await, 0);
}

#[tokio::test]
async fn non_scalar_parameter_values_are_rejected() {
    let dir = ScriptDir::new();
    let side_effect = dir.path_for("ran-anyway");
    let script = dir.write_script("scalar.sh", &format!("touch \"{side_effect}\""));

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "scalar_only", &script, 30).await;
    insert_parameter(&db, hook_id, "value", None, true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");

    // An environment variable and an argv entry are both flat strings. Silently JSON-encoding a
    // structure would hand the script something it never asked for, so these are hard errors.
    let non_scalars = [
        ("array", json!(["a", "b"])),
        ("empty array", json!([])),
        ("nested object", json!({ "inner": "value" })),
        ("empty object", json!({})),
        ("array of objects", json!([{ "a": 1 }])),
        ("deeply nested", json!({ "a": { "b": { "c": [1, 2] } } })),
    ];

    for (label, value) in non_scalars {
        let response = send(
            &app,
            json_request("POST", &uri, &key, Some(json!({ "parameters": { "value": value } }))),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{label} must be rejected");
        assert!(
            response.string("error").contains("value"),
            "{label}: the error should name the offending parameter, got {:?}",
            response.string("error")
        );
    }

    // Scalars of every JSON flavour are accepted and stringified.
    let scalars = [
        (json!("text"), "text"),
        (json!(42), "42"),
        (json!(-1), "-1"),
        (json!(3.5), "3.5"),
        (json!(true), "true"),
        (json!(false), "false"),
    ];

    for (value, expected) in scalars {
        let response = send(
            &app,
            json_request("POST", &uri, &key, Some(json!({ "parameters": { "value": value } }))),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{value} should be accepted");
        assert_eq!(response.field("parameters"), &json!({ "value": expected }));
    }

    assert!(std::path::Path::new(&side_effect).exists(), "the accepted runs did execute");
}

#[tokio::test]
async fn json_null_is_treated_as_an_omitted_parameter() {
    let dir = ScriptDir::new();
    let script = dir.write_script("nulls.sh", "echo \"[$1][$2]\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "nulls", &script, 30).await;
    insert_parameter(&db, hook_id, "defaulted", Some("fallback"), true).await;
    insert_parameter(&db, hook_id, "optional", None, false).await;
    grant(&db, key_id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");

    // `null` means "I am not supplying this" — not "supply an empty string" — so the declared
    // default still applies.
    let with_null = send(
        &app,
        json_request(
            "POST",
            &uri,
            &key,
            Some(json!({ "parameters": { "defaulted": null, "optional": null } })),
        ),
    )
    .await;
    assert_eq!(with_null.status, StatusCode::OK);
    assert_eq!(with_null.field("parameters"), &json!({ "defaulted": "fallback" }));
    assert_eq!(with_null.string("stdout").trim(), "[fallback][]");

    // An explicit empty string is distinguishable from `null`: it overrides the default.
    let with_empty = send(
        &app,
        json_request("POST", &uri, &key, Some(json!({ "parameters": { "defaulted": "" } }))),
    )
    .await;
    assert_eq!(with_empty.status, StatusCode::OK);
    assert_eq!(with_empty.field("parameters"), &json!({ "defaulted": "" }));

    // `null` on a required parameter with no default is still a missing parameter.
    let required_id = insert_hook(&db, "nulls_required", &script, 30).await;
    insert_parameter(&db, required_id, "mandatory", None, true).await;
    grant(&db, key_id, required_id, true, false).await;
    let missing = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{required_id}/execute"),
            &key,
            Some(json!({ "parameters": { "mandatory": null } })),
        ),
    )
    .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(missing.string("error").contains("mandatory"));
}

#[tokio::test]
async fn positional_argument_order_is_deterministic_and_append_only() {
    let dir = ScriptDir::new();
    let script = dir.write_script("order.sh", "echo \"$1|$2|$3|$4\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "ordered", &script, 30).await;
    grant(&db, key_id, hook_id, true, true).await;

    // Declared in an order that does NOT match alphabetical or reverse-alphabetical sorting, so a
    // passing assertion can only mean declaration order is what's actually used.
    for (param, default) in [("zulu", "z"), ("alpha", "a"), ("mike", "m")] {
        let created = send(
            &app,
            json_request(
                "POST",
                &format!("/api/hooks/{hook_id}/parameters"),
                &key,
                Some(json!({ "param_key": param, "default_value": default })),
            ),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK);
    }

    let expected = json!(["z", "a", "m"]);
    let preview = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/test"), &key, None)).await;
    assert_eq!(preview.json["command"]["args"], expected, "declaration order, not sorted order");

    // Repeated calls must produce the identical vector — an unstable ORDER BY would show up here
    // as an intermittent difference across runs.
    for attempt in 0..5 {
        let run = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
        assert_eq!(run.status, StatusCode::OK);
        assert_eq!(run.string("stdout").trim(), "z|a|m|", "attempt {attempt} differed");

        let preview = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/test"), &key, None)).await;
        assert_eq!(preview.json["command"]["args"], expected, "attempt {attempt} differed");
    }

    // A parameter declared later appends to the end rather than reshuffling existing positions,
    // so adding one cannot silently change what an existing caller's script receives as $1..$3.
    let added = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/parameters"),
            &key,
            Some(json!({ "param_key": "bravo", "default_value": "b" })),
        ),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK);

    let run = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(run.string("stdout").trim(), "z|a|m|b");

    // Supplied values land in the same positions as their defaults did.
    let run = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/execute"),
            &key,
            Some(json!({ "parameters": { "mike": "M!", "zulu": "Z!" } })),
        ),
    )
    .await;
    assert_eq!(run.string("stdout").trim(), "Z!|a|M!|b");
}

#[tokio::test]
async fn invalid_script_paths_are_rejected() {
    let dir = ScriptDir::new();
    let missing_script = dir.path_for("does-not-exist.sh");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;

    // Relative paths are rejected at definition time.
    let relative = send(
        &app,
        json_request("POST", "/api/hooks", &key, Some(json!({ "name": "rel", "script_path": "relative.sh" }))),
    )
    .await;
    assert_eq!(relative.status, StatusCode::BAD_REQUEST);

    let traversal = send(
        &app,
        json_request("POST", "/api/hooks", &key, Some(json!({ "name": "trav", "script_path": "/usr/../etc/shadow" }))),
    )
    .await;
    assert_eq!(traversal.status, StatusCode::BAD_REQUEST);

    // A path that is well-formed but absent is only detectable at execution time.
    let hook_id = insert_hook(&db, "ghost", &missing_script, 30).await;
    grant(&db, key_id, hook_id, true, false).await;
    let executed = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(executed.status, StatusCode::BAD_REQUEST);
    assert!(executed.string("error").contains("not accessible"));

    // A file with no executable bit is rejected too.
    let non_exec = dir.path_for("plain.txt");
    std::fs::write(&non_exec, "not executable").expect("file is writable");
    let hook_id = insert_hook(&db, "plain", &non_exec, 30).await;
    grant(&db, key_id, hook_id, true, false).await;
    let executed = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(executed.status, StatusCode::BAD_REQUEST);
    assert!(executed.string("error").contains("not executable"));
}

#[tokio::test]
async fn hook_and_key_field_validation_is_enforced() {
    let dir = ScriptDir::new();
    let script = dir.write_script("valid.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    let bad_timeout = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "t", "script_path": script, "default_timeout_seconds": 0 }))),
    )
    .await;
    assert_eq!(bad_timeout.status, StatusCode::BAD_REQUEST);

    let bad_param = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": "p", "script_path": script, "parameters": [{ "param_key": "not-valid" }] })),
        ),
    )
    .await;
    assert_eq!(bad_param.status, StatusCode::BAD_REQUEST);

    let bad_cidr = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "k", "bound_ips": "999.999.999.999/99" }))),
    )
    .await;
    assert_eq!(bad_cidr.status, StatusCode::BAD_REQUEST);

    let bad_jobs = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "k", "bound_ips": "0.0.0.0/0", "max_concurrent_jobs": 0 }))),
    )
    .await;
    assert_eq!(bad_jobs.status, StatusCode::BAD_REQUEST);
}

// ─────────────────────────────────────────────────────────────
// Dry run
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn dry_run_previews_the_command_without_executing() {
    let dir = ScriptDir::new();
    let side_effect = dir.path_for("executed-for-real");
    let script = dir.write_script("dry.sh", &format!("touch \"{side_effect}\""));

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "dry", &script, 42).await;
    insert_parameter(&db, hook_id, "alpha", None, true).await;
    insert_parameter(&db, hook_id, "beta", Some("fallback"), true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let preview = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/test"),
            &key,
            Some(json!({ "parameters": { "alpha": "supplied" } })),
        ),
    )
    .await;

    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(preview.field("would_execute"), &json!(true));
    assert_eq!(preview.field("timeout_seconds"), &json!(42));
    assert_eq!(preview.field("resolved_parameters"), &json!({ "alpha": "supplied", "beta": "fallback" }));
    assert_eq!(preview.json["command"]["program"], json!(script));
    assert_eq!(preview.json["command"]["args"], json!(["supplied", "fallback"]));
    assert_eq!(preview.json["command"]["env"]["HOOK_PARAM_ALPHA"], json!("supplied"));
    assert_eq!(preview.json["command"]["env"]["HOOK_PARAM_BETA"], json!("fallback"));

    assert!(!std::path::Path::new(&side_effect).exists(), "a dry run must not spawn the script");
    assert_eq!(execution_count(&db).await, 0);

    // Missing requirements are reported as data, not as a 400.
    let blocked = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/test"), &key, Some(json!({ "parameters": {} }))),
    )
    .await;
    assert_eq!(blocked.status, StatusCode::OK);
    assert_eq!(blocked.field("would_execute"), &json!(false));
    assert_eq!(blocked.field("missing_required"), &json!(["alpha"]));
}

// ─────────────────────────────────────────────────────────────
// Webhook alias, history scoping, retention
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_alias_executes_by_name_with_a_flat_payload() {
    let dir = ScriptDir::new();
    let script = dir.write_script("webhook.sh", "echo \"banned $HOOK_PARAM_TARGET_ADDRESS\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Vault", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "nftables_ban", &script, 30).await;
    insert_parameter(&db, hook_id, "target_address", None, true).await;
    grant(&db, key_id, hook_id, true, false).await;

    // A third-party sender posts its own flat document to a fixed URL keyed by hook name.
    let response = send(
        &app,
        json_request("POST", "/webhook/nftables_ban", &key, Some(json!({ "target_address": "203.0.113.7" }))),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.string("stdout").trim(), "banned 203.0.113.7");
}

#[tokio::test]
async fn execution_history_is_scoped_and_filterable() {
    let dir = ScriptDir::new();
    let ok_script = dir.write_script("ok.sh", "echo ok");
    let bad_script = dir.write_script("bad.sh", "exit 1");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (alpha_id, alpha) = insert_key(&db, "Alpha", "0.0.0.0/0", KeyScopes::plain()).await;
    let (beta_id, beta) = insert_key(&db, "Beta", "0.0.0.0/0", KeyScopes::plain()).await;
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    let alpha_hook = insert_hook(&db, "alpha_hook", &ok_script, 30).await;
    let beta_hook = insert_hook(&db, "beta_hook", &bad_script, 30).await;
    grant(&db, alpha_id, alpha_hook, true, false).await;
    grant(&db, beta_id, beta_hook, true, false).await;

    send(&app, json_request("POST", &format!("/api/hooks/{alpha_hook}/execute"), &alpha, None)).await;
    send(&app, json_request("POST", &format!("/api/hooks/{beta_hook}/execute"), &beta, None)).await;

    // Each tenant sees only their own hook's history.
    let alpha_view = send(&app, json_request("GET", "/api/executions", &alpha, None)).await;
    let rows = alpha_view.json.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["hook_name"], json!("alpha_hook"));

    // Master sees everything, and the status filter works.
    let all = send(&app, json_request("GET", "/api/executions", &master, None)).await;
    assert_eq!(all.json.as_array().map(Vec::len), Some(2));

    let failed = send(&app, json_request("GET", "/api/executions?status=FAILED", &master, None)).await;
    let rows = failed.json.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["hook_name"], json!("beta_hook"));

    let by_hook = send(&app, json_request("GET", "/api/executions?hook=alpha_hook", &master, None)).await;
    assert_eq!(by_hook.json.as_array().map(Vec::len), Some(1));

    let bad_filter = send(&app, json_request("GET", "/api/executions?status=NOPE", &master, None)).await;
    assert_eq!(bad_filter.status, StatusCode::BAD_REQUEST);

    // Reading another tenant's execution by id is forbidden, not merely filtered out.
    let beta_exec_id = send(&app, json_request("GET", "/api/executions?hook=beta_hook", &master, None))
        .await
        .json[0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let cross_tenant = send(&app, json_request("GET", &format!("/api/executions/{beta_exec_id}"), &alpha, None)).await;
    assert_eq!(cross_tenant.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn retention_purges_only_expired_executions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let hook_id = insert_hook(&db, "aged", "/bin/true", 30).await;

    insert_execution_aged(&db, hook_id, 60).await;
    insert_execution_aged(&db, hook_id, 45).await;
    let recent = insert_execution_aged(&db, hook_id, 1).await;

    let purged = purge_expired_executions(&db, 30).await.expect("purge succeeds");
    assert_eq!(purged, 2);
    assert_eq!(execution_count(&db).await, 1);
    // The survivor is specifically the one inside the window, not merely "one row".
    assert!(
        Execution::find_by_id(recent).one(&db).await.expect("query succeeds").is_some(),
        "the row inside the retention window must survive"
    );

    // A retention window of 0 means "keep forever" and must delete nothing.
    let noop = purge_expired_executions(&db, 0).await.expect("purge succeeds");
    assert_eq!(noop, 0);
    assert_eq!(execution_count(&db).await, 1);

    // The same sweep is available on demand, master-only.
    let (_, scoped) = insert_key(&db, "Scoped", "0.0.0.0/0", KeyScopes::plain()).await;
    assert_eq!(
        send(&app, json_request("DELETE", "/api/executions?older_than_days=1", &scoped, None)).await.status,
        StatusCode::FORBIDDEN
    );

    insert_execution_aged(&db, hook_id, 90).await;
    let response = send(&app, json_request("DELETE", "/api/executions?older_than_days=30", &master, None)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.field("purged"), &json!(1));

    // `older_than_days=0` on the endpoint carries the same "keep forever" meaning as the config
    // flag, rather than the "delete everything" a caller might assume.
    insert_execution_aged(&db, hook_id, 365).await;
    let zero = send(&app, json_request("DELETE", "/api/executions?older_than_days=0", &master, None)).await;
    assert_eq!(zero.status, StatusCode::OK);
    assert_eq!(zero.field("purged"), &json!(0));
    assert_eq!(execution_count(&db).await, 2);

    let negative = send(&app, json_request("DELETE", "/api/executions?older_than_days=-5", &master, None)).await;
    assert_eq!(negative.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn retention_worker_purges_on_its_own_schedule_and_shuts_down_cleanly() {
    let db = setup_test_db().await;
    let hook_id = insert_hook(&db, "worker_aged", "/bin/true", 30).await;

    insert_execution_aged(&db, hook_id, 10).await;
    insert_execution_aged(&db, hook_id, 7).await;
    let survivor = insert_execution_aged(&db, hook_id, 1).await;

    // A 2-day window with a fast sweep interval: the worker's first tick fires immediately, so
    // this does not depend on the interval actually elapsing.
    let state = AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            log_retention_days: 2,
            retention_sweep_seconds: 1,
            ..(*test_config()).clone()
        }),
    );
    let (shutdown_tx, worker) = spawn_retention_worker(&state);

    let purged = wait_until(Duration::from_secs(10), async || execution_count(&db).await == 1).await;
    assert!(purged, "the worker did not purge expired executions");
    assert!(
        Execution::find_by_id(survivor).one(&db).await.expect("query succeeds").is_some(),
        "the worker purged a record inside the retention window"
    );

    // Rows that age past the window while the worker runs are picked up by a later sweep.
    insert_execution_aged(&db, hook_id, 30).await;
    let purged_again = wait_until(Duration::from_secs(10), async || execution_count(&db).await == 1).await;
    assert!(purged_again, "a later sweep did not run");

    // Dropping the sender is the shutdown signal; the worker must then finish promptly rather
    // than being left to be aborted at process exit.
    drop(shutdown_tx);
    let stopped = tokio::time::timeout(Duration::from_secs(5), worker).await;
    assert!(stopped.is_ok(), "the worker did not shut down when its channel closed");
}

#[tokio::test]
async fn retention_worker_is_disabled_when_retention_days_is_zero() {
    let db = setup_test_db().await;
    let hook_id = insert_hook(&db, "kept_forever", "/bin/true", 30).await;
    insert_execution_aged(&db, hook_id, 3650).await;

    let state = AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            log_retention_days: 0,
            retention_sweep_seconds: 1,
            ..(*test_config()).clone()
        }),
    );
    let (shutdown_tx, worker) = spawn_retention_worker(&state);

    // With retention disabled the worker exits immediately — without waiting for the shutdown
    // signal, which is still held here precisely to prove that.
    let stopped = tokio::time::timeout(Duration::from_secs(5), worker).await;
    assert!(stopped.is_ok(), "a disabled worker should return instead of ticking forever");

    // A decade-old record is still there.
    assert_eq!(execution_count(&db).await, 1);
    drop(shutdown_tx);
}

// ─────────────────────────────────────────────────────────────
// Keys, permissions, audit trail, settings
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn key_lifecycle_rotation_and_permission_assignment() {
    let dir = ScriptDir::new();
    let script = dir.write_script("perm.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let hook_id = insert_hook(&db, "shared", &script, 30).await;

    let created = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "worker", "bound_ips": "0.0.0.0/0", "max_concurrent_jobs": 3 }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let worker_id = created.string("id");
    let worker_key = created.string("plaintext_key");

    // No grant yet: execution denied.
    let uri = format!("/api/hooks/{hook_id}/execute");
    assert_eq!(send(&app, json_request("POST", &uri, &worker_key, None)).await.status, StatusCode::FORBIDDEN);

    // Grant by hook name.
    let granted = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{worker_id}/permissions"),
            &master,
            Some(json!({ "hook_name": "shared", "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(granted.status, StatusCode::OK);
    assert_eq!(send(&app, json_request("POST", &uri, &worker_key, None)).await.status, StatusCode::OK);

    // The grant is reported back on /auth/me and in the admin listing.
    let me = send(&app, json_request("GET", "/api/auth/me", &worker_key, None)).await;
    assert_eq!(me.field("max_concurrent_jobs"), &json!(3));
    assert_eq!(me.json["hook_permissions"][0]["hook_name"], json!("shared"));

    // Rotation invalidates the old secret immediately.
    let rotated = send(&app, json_request("POST", &format!("/api/keys/{worker_id}/rotate"), &master, None)).await;
    assert_eq!(rotated.status, StatusCode::OK);
    let new_key = rotated.string("plaintext_key");
    assert_eq!(send(&app, json_request("GET", "/api/auth/me", &worker_key, None)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, json_request("GET", "/api/auth/me", &new_key, None)).await.status, StatusCode::OK);

    // Revocation by hook name removes the grant.
    let revoked = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{worker_id}/permissions/shared"), &master, None),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, json_request("POST", &uri, &new_key, None)).await.status, StatusCode::FORBIDDEN);

    // A scoped key cannot manage keys at all.
    assert_eq!(
        send(&app, json_request("GET", "/api/keys", &new_key, None)).await.status,
        StatusCode::FORBIDDEN
    );

    let deleted = send(&app, json_request("DELETE", &format!("/api/keys/{worker_id}"), &master, None)).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, json_request("GET", "/api/auth/me", &new_key, None)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_trail_records_mutations_and_is_master_only() {
    let dir = ScriptDir::new();
    let script = dir.write_script("audited.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let (scoped_id, scoped) = insert_key(&db, "Scoped", "0.0.0.0/0", KeyScopes::plain()).await;

    let created = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "audited", "script_path": script }))),
    )
    .await;
    let hook_id = created.string("id");
    grant(&db, scoped_id, Uuid::parse_str(&hook_id).expect("valid uuid"), true, false).await;
    send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &scoped, None)).await;

    // Scoped keys cannot read the trail at all.
    assert_eq!(send(&app, json_request("GET", "/api/audit-logs", &scoped, None)).await.status, StatusCode::FORBIDDEN);

    let creates = send(&app, json_request("GET", "/api/audit-logs?action=HOOK_CREATE", &master, None)).await;
    let rows = creates.json.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["api_key_name"], json!("Master"));
    assert_eq!(rows[0]["client_ip"], json!("127.0.0.1"));
    assert_eq!(rows[0]["target_resource"], json!("audited"));

    let executes = send(&app, json_request("GET", "/api/audit-logs?action=HOOK_EXECUTE", &master, None)).await;
    let rows = executes.json.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["api_key_name"], json!("Scoped"));
    assert!(
        rows[0]["details"].as_str().unwrap_or_default().contains("audited"),
        "details name the hook: {}",
        rows[0]["details"]
    );
}

#[tokio::test]
async fn settings_expose_runtime_configuration_to_master_keys_only() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let (_, scoped) = insert_key(&db, "Scoped", "0.0.0.0/0", KeyScopes::plain()).await;

    assert_eq!(send(&app, json_request("GET", "/api/settings", &scoped, None)).await.status, StatusCode::FORBIDDEN);

    let settings = send(&app, json_request("GET", "/api/settings", &master, None)).await;
    assert_eq!(settings.status, StatusCode::OK);
    assert_eq!(settings.field("allowed_env_vars"), &json!(["PATH"]));
    assert_eq!(settings.field("log_retention_days"), &json!(30));
    assert_eq!(settings.field("api_key_count"), &json!(2));
}

#[tokio::test]
async fn hook_parameter_crud_is_guarded_by_manage_rights() {
    let dir = ScriptDir::new();
    let script = dir.write_script("params.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (manager_id, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::plain()).await;
    let (executor_id, executor) = insert_key(&db, "Executor", "0.0.0.0/0", KeyScopes::plain()).await;

    let hook_id = insert_hook(&db, "paramful", &script, 30).await;
    grant(&db, manager_id, hook_id, true, true).await;
    grant(&db, executor_id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/parameters");

    // Execute-only keys may read the contract but not change it.
    assert_eq!(send(&app, json_request("GET", &uri, &executor, None)).await.status, StatusCode::OK);
    assert_eq!(
        send(&app, json_request("POST", &uri, &executor, Some(json!({ "param_key": "sneaky" })))).await.status,
        StatusCode::FORBIDDEN
    );

    let created = send(
        &app,
        json_request("POST", &uri, &manager, Some(json!({ "param_key": "target", "default_value": "1.2.3.4", "is_required": true }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let param_id = created.string("id");

    // Duplicate declaration -> 409.
    let duplicate = send(&app, json_request("POST", &uri, &manager, Some(json!({ "param_key": "target" })))).await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    // Invalid key shape -> 400.
    let invalid = send(&app, json_request("POST", &uri, &manager, Some(json!({ "param_key": "9bad key" })))).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);

    let updated = send(
        &app,
        json_request("PUT", &format!("{uri}/{param_id}"), &manager, Some(json!({ "default_value": "9.9.9.9", "is_required": false }))),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.field("default_value"), &json!("9.9.9.9"));
    assert_eq!(updated.field("is_required"), &json!(false));

    let deleted = send(&app, json_request("DELETE", &format!("{uri}/{param_id}"), &manager, None)).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        send(&app, json_request("GET", &uri, &manager, None)).await.json.as_array().map(Vec::len),
        Some(0)
    );
}
