//! Integration tests covering the mandatory matrix from `AGENT.MD`: positive assertions,
//! authentication (401), authorization boundaries (403), input validation (400), concurrency
//! throttling (429), and execution timeouts — plus the security properties the execution engine
//! is responsible for (no shell, cleared environment, process-group kill).

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
};
use serde_json::json;
use simply_hook_executor::{
    config::RuntimeConfig, create_app,
    entities::{api_key, prelude::ApiKey, prelude::Execution},
    retention::purge_expired_executions, spawn_retention_worker, state::AppState,
};
use uuid::Uuid;

/// Builds a permission set from a raw Unix mode.
#[cfg(unix)]
fn permissions(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

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

/// Builds a GET request carrying an API key and a forwarding header.
fn forwarded_request(uri: &str, key: &str, header: &str, value: &str) -> axum::http::Request<axum::body::Body> {
    with_connect_info(
        axum::http::Request::builder()
            .uri(uri)
            .header("X-API-Key", key)
            .header(header, value),
    )
    .body(axum::body::Body::empty())
    .expect("request builds")
}

#[tokio::test]
async fn bound_cidr_is_enforced_against_the_resolved_client_ip() {
    let db = setup_test_db().await;
    // Behind a trusted proxy: the simulated peer is 127.0.0.1, which is on the trust list, so its
    // forwarding headers are evidence rather than a claim.
    let app = create_app(test_state_with_trusted_proxies(&db, &["127.0.0.1"]));
    let (_, key) = insert_key(&db, "Bound Key", "192.168.1.1/32", KeyScopes::plain()).await;

    // No header at all: the peer is 127.0.0.1, which is outside the bound range.
    let response = send(&app, json_request("GET", "/api/hooks", &key, None)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);

    // A matching forwarded hop is accepted — the rightmost entry is the one the proxy appended.
    let request = forwarded_request("/api/hooks", &key, "X-Forwarded-For", "10.0.0.1, 192.168.1.1");
    assert_eq!(send(&app, request).await.status, StatusCode::OK);

    // X-Real-IP is honoured from a trusted proxy too.
    let request = forwarded_request("/api/hooks", &key, "X-Real-IP", "192.168.1.1");
    assert_eq!(send(&app, request).await.status, StatusCode::OK);

    // A forwarded hop outside the range is still refused: trusting the proxy means believing what
    // it reports, not waiving the allowlist.
    let request = forwarded_request("/api/hooks", &key, "X-Forwarded-For", "192.168.9.9");
    assert_eq!(send(&app, request).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn hmac_signature_is_verified_over_the_raw_body() {
    let dir = ScriptDir::new();
    let script = dir.write_script("signed.sh", "echo signed");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let signer = insert_key_full(&db, "Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "signed_hook", &script, 30).await;
    grant(&db, signer.id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let body = json!({ "parameters": {} }).to_string();
    let timestamp = now_timestamp();
    let signature = sign_request(&signer.signing_secret, "POST", &uri, timestamp, &body);

    let bearer_and_signature = |sig: &str, payload: &str| {
        with_connect_info(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("X-API-Key", &signer.plaintext)
                .header("Content-Type", "application/json")
                .header("X-Timestamp", timestamp.to_string())
                .header("X-Signature-256", sig),
        )
        .body(axum::body::Body::from(payload.to_owned()))
        .expect("request builds")
    };

    // A bearer key plus a correct signature: the signature adds body integrity on top.
    assert_eq!(send(&app, bearer_and_signature(&signature, &body)).await.status, StatusCode::OK);

    // Same signature, altered body: rejected.
    let tampered = json!({ "parameters": { "x": "1" } }).to_string();
    assert_eq!(
        send(&app, bearer_and_signature(&signature, &tampered)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Malformed signature header: rejected.
    assert_eq!(
        send(&app, bearer_and_signature("sha256=deadbeef", &body)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // The signature is keyed on the *signing secret*, not the bearer key: signing with the API key
    // itself must no longer authenticate.
    let wrong_key_material = sign_request(&signer.plaintext, "POST", &uri, timestamp, &body);
    assert_eq!(
        send(&app, bearer_and_signature(&wrong_key_material, &body)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn x_api_key_is_the_only_header_that_resolves_a_key_record() {
    let dir = ScriptDir::new();
    let script = dir.write_script("webhook_signed.sh", "echo \"signed:$HOOK_PARAM_TARGET\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_full(&db, "Webhook Sender", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "webhook_signed", &script, 30).await;
    insert_parameter(&db, hook_id, "target", None, true).await;
    grant(&db, sender.id, hook_id, true, false).await;

    let uri = "/webhook/webhook_signed";
    let body = json!({ "target": "203.0.113.7" }).to_string();

    // A signed request identified by X-API-Key.
    let response = send(
        &app,
        signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &body),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.string("stdout").trim(), "signed:203.0.113.7");

    // A signature made with the wrong secret is rejected even though the bearer key is valid.
    let timestamp = now_timestamp();
    let forged = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &sender.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", sign_request("not-the-secret", "POST", uri, timestamp, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    assert_eq!(send(&app, forged).await.status, StatusCode::UNAUTHORIZED);

    // With the bearer key present and no signature, the key itself is the credential, so the
    // request is accepted. (`REQUIRE_SIGNED_REQUESTS` is what makes signing compulsory; that is
    // covered by its own test.)
    let unsigned = json_request("POST", uri, &sender.plaintext, Some(json!({ "target": "1.2.3.4" })));
    assert_eq!(send(&app, unsigned).await.status, StatusCode::OK);

    // The public key_id is *not* a credential: presenting it in place of the API key — under its
    // old header name or as the API key itself — resolves nothing.
    let via_old_header = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-Key-Id", &sender.key_id)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", sign_request(&sender.signing_secret, "POST", uri, timestamp, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    let response = send(&app, via_old_header).await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "the retired X-Key-Id header must not resolve a key"
    );
    assert!(response.string("error").contains("X-API-Key"));

    let key_id_as_bearer = signed_request("POST", uri, &sender.key_id, &sender.signing_secret, &body);
    assert_eq!(
        send(&app, key_id_as_bearer).await.status,
        StatusCode::UNAUTHORIZED,
        "the public key_id must not authenticate as a bearer key either"
    );

    // A missing key is refused with a message naming the one header that works.
    let anonymous = with_connect_info(
        axum::http::Request::builder().method("POST").uri(uri).header("Content-Type", "application/json"),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    let response = send(&app, anonymous).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.string("error").contains("X-API-Key"));
}

#[tokio::test]
async fn the_anti_replay_window_rejects_stale_and_future_timestamps() {
    let dir = ScriptDir::new();
    let side_effect = dir.path_for("replayed");
    let script = dir.write_script("replay.sh", &format!("touch \"{side_effect}\""));

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_full(&db, "Sender", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "replay_hook", &script, 30).await;
    grant(&db, sender.id, hook_id, true, false).await;

    let uri = "/webhook/replay_hook";
    let body = json!({}).to_string();
    let now = now_timestamp();

    // Offsets are kept well clear of the ±300s boundary in both directions. `now` is sampled once
    // but each iteration below spawns a real process, so by the last request several seconds of
    // wall clock have passed: an offset of -299 would drift past the boundary and a +299 would
    // drift *inside* it, making this test fail intermittently either way. Exact boundary behaviour
    // is asserted in `middleware::tests::timestamps_*`, where there is no I/O to skew it.
    for offset in [0, -240, 240, -120, 120] {
        let response = send(
            &app,
            signed_request_at("POST", uri, &sender.plaintext, &sender.signing_secret, &body, now + offset),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "offset {offset}s should be inside the window");
    }

    // Outside it, in both directions. A stale capture is the replay case; a forward-dated request
    // would otherwise stay replayable for as long as its skew allowed.
    for offset in [-360, -3600, -86_400, 360, 3600] {
        let response = send(
            &app,
            signed_request_at("POST", uri, &sender.plaintext, &sender.signing_secret, &body, now + offset),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "offset {offset}s should be outside the window"
        );
        assert!(
            response.string("error").contains("window"),
            "the error should explain the window: {}",
            response.string("error")
        );
    }

    // A correctly-signed request replayed *later* is refused once its timestamp ages out — which
    // is the whole point of binding the timestamp into the signature.
    let stale = signed_request_at(
        "POST",
        uri,
        &sender.plaintext,
        &sender.signing_secret,
        &body,
        now - 400,
    );
    assert_eq!(send(&app, stale).await.status, StatusCode::UNAUTHORIZED);

    // Only the requests inside the window ran; the rejected ones never reached the engine.
    assert_eq!(execution_count(&db).await, 5);
}

#[tokio::test]
async fn signed_requests_require_a_well_formed_timestamp_header() {
    let dir = ScriptDir::new();
    let script = dir.write_script("ts.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_full(&db, "Sender", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "ts_hook", &script, 30).await;
    grant(&db, sender.id, hook_id, true, false).await;

    let uri = "/webhook/ts_hook";
    let body = json!({}).to_string();
    let now = now_timestamp();

    // A signature with no timestamp at all cannot be replay-checked, so it is refused outright
    // rather than verified against an assumed "now".
    let no_timestamp = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &sender.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Signature-256", sign_request(&sender.signing_secret, "POST", uri, now, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    let response = send(&app, no_timestamp).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.string("error").contains("X-Timestamp"));

    // Malformed timestamps are rejected rather than coerced.
    for malformed in ["", "not-a-number", "1700000000.5", "17e9", "-"] {
        let request = with_connect_info(
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("X-API-Key", &sender.plaintext)
                .header("Content-Type", "application/json")
                .header("X-Timestamp", malformed)
                .header("X-Signature-256", sign_request(&sender.signing_secret, "POST", uri, now, &body)),
        )
        .body(axum::body::Body::from(body.clone()))
        .expect("request builds");
        assert_eq!(
            send(&app, request).await.status,
            StatusCode::UNAUTHORIZED,
            "timestamp {malformed:?} must be rejected"
        );
    }

    assert_eq!(execution_count(&db).await, 0);
}

#[tokio::test]
async fn signatures_cover_every_http_method_and_the_query_string() {
    let dir = ScriptDir::new();
    let script = dir.write_script("methods.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let master = insert_key_full(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let hook_id = insert_hook(&db, "methods_hook", &script, 30).await;

    // GET, POST, PUT, PATCH and DELETE all sign the same way — this mirrors what the SPA does for
    // every request it makes.
    let get = signed_bearer_request("GET", "/api/hooks", &master.plaintext, &master.signing_secret, "");
    assert_eq!(send(&app, get).await.status, StatusCode::OK);

    let post_body = json!({ "name": "signed_created", "script_path": script }).to_string();
    let post = signed_bearer_request("POST", "/api/hooks", &master.plaintext, &master.signing_secret, &post_body);
    let created = send(&app, post).await;
    assert_eq!(created.status, StatusCode::OK);

    let put_uri = format!("/api/hooks/{hook_id}");
    let put_body = json!({ "description": "signed update" }).to_string();
    let put = signed_bearer_request("PUT", &put_uri, &master.plaintext, &master.signing_secret, &put_body);
    assert_eq!(send(&app, put).await.status, StatusCode::OK);

    let patch = signed_bearer_request("PATCH", &put_uri, &master.plaintext, &master.signing_secret, &put_body);
    assert_eq!(send(&app, patch).await.status, StatusCode::OK);

    // A GET whose query string is covered: re-signing for a different query must not validate.
    let listing_uri = "/api/executions?limit=5";
    let listing = signed_bearer_request("GET", listing_uri, &master.plaintext, &master.signing_secret, "");
    assert_eq!(send(&app, listing).await.status, StatusCode::OK);

    let timestamp = now_timestamp();
    let swapped_query = with_connect_info(
        axum::http::Request::builder()
            .method("GET")
            .uri("/api/executions?limit=1000")
            .header("X-API-Key", &master.plaintext)
            .header("X-Timestamp", timestamp.to_string())
            .header(
                "X-Signature-256",
                // Signed for limit=5, sent for limit=1000.
                sign_request(&master.signing_secret, "GET", listing_uri, timestamp, ""),
            ),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(
        send(&app, swapped_query).await.status,
        StatusCode::UNAUTHORIZED,
        "the query string is part of the signed material"
    );

    let delete_uri = format!("/api/hooks/{}", created.string("id"));
    let delete = signed_bearer_request("DELETE", &delete_uri, &master.plaintext, &master.signing_secret, "");
    assert_eq!(send(&app, delete).await.status, StatusCode::NO_CONTENT);

    // A signature minted for the DELETE must not be replayable against a different hook.
    let ts = now_timestamp();
    let cross_route = with_connect_info(
        axum::http::Request::builder()
            .method("DELETE")
            .uri(&put_uri)
            .header("X-API-Key", &master.plaintext)
            .header("X-Timestamp", ts.to_string())
            .header("X-Signature-256", sign_request(&master.signing_secret, "DELETE", &delete_uri, ts, "")),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(send(&app, cross_route).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_signed_requests_makes_the_protocol_mandatory() {
    let dir = ScriptDir::new();
    let script = dir.write_script("mandatory.sh", "echo ok");

    let db = setup_test_db().await;
    let state = AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            require_signed_requests: true,
            ..(*test_config()).clone()
        }),
        test_cipher(),
    );
    let app = create_app(state);
    let master = insert_key_full(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let hook_id = insert_hook(&db, "mandatory_hook", &script, 30).await;

    // A valid bearer key on its own is no longer sufficient.
    let unsigned = send(&app, json_request("GET", "/api/hooks", &master.plaintext, None)).await;
    assert_eq!(unsigned.status, StatusCode::UNAUTHORIZED);
    assert!(unsigned.string("error").contains("must be signed"));

    // The same request, signed, succeeds.
    let signed = signed_bearer_request("GET", "/api/hooks", &master.plaintext, &master.signing_secret, "");
    assert_eq!(send(&app, signed).await.status, StatusCode::OK);

    // Enforcement is global, not per-route: execution and the webhook alias are covered too.
    let exec_uri = format!("/api/hooks/{hook_id}/execute");
    assert_eq!(
        send(&app, json_request("POST", &exec_uri, &master.plaintext, None)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, json_request("GET", "/api/settings", &master.plaintext, None)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, json_request("GET", "/api/keys", &master.plaintext, None)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(execution_count(&db).await, 0);

    let signed_exec = signed_bearer_request("POST", &exec_uri, &master.plaintext, &master.signing_secret, "");
    assert_eq!(send(&app, signed_exec).await.status, StatusCode::OK);
}

#[tokio::test]
async fn body_only_mode_accepts_github_style_webhook_signatures() {
    use simply_hook_executor::entities::api_key::HmacMode;

    let dir = ScriptDir::new();
    let script = dir.write_script("gh.sh", "echo \"pushed:$HOOK_PARAM_REF\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_with_mode(&db, "Forgejo", "0.0.0.0/0", KeyScopes::plain(), HmacMode::BodyOnly).await;
    let hook_id = insert_hook(&db, "on_push", &script, 30).await;
    insert_parameter(&db, hook_id, "ref", Some("refs/heads/main"), true).await;
    grant(&db, sender.id, hook_id, true, false).await;

    let uri = "/webhook/on_push";
    let body = json!({ "ref": "refs/heads/release" }).to_string();

    // Both header spellings are honoured in this mode: GitHub and Forgejo send
    // `X-Hub-Signature-256`, while other senders use `X-Signature-256`.
    for header in ["X-Signature-256", "X-Hub-Signature-256"] {
        let response = send(
            &app,
            body_only_request(uri, &sender.plaintext, &sender.signing_secret, &body, header),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{header} should be accepted in BODY_ONLY mode");
        assert_eq!(response.string("stdout").trim(), "pushed:refs/heads/release");
    }

    // No timestamp is required, and one supplied anyway is simply not part of the signed material.
    let with_stray_timestamp = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &sender.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", "1")
            .header("X-Hub-Signature-256", sign_body_only(&sender.signing_secret, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    assert_eq!(send(&app, with_stray_timestamp).await.status, StatusCode::OK);

    // A tampered body still fails, and so does the wrong secret.
    let tampered = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &sender.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Hub-Signature-256", sign_body_only(&sender.signing_secret, &body)),
    )
    .body(axum::body::Body::from(json!({ "ref": "refs/heads/evil" }).to_string()))
    .expect("request builds");
    assert_eq!(send(&app, tampered).await.status, StatusCode::UNAUTHORIZED);

    let wrong_secret = body_only_request(uri, &sender.plaintext, "not-the-secret", &body, "X-Hub-Signature-256");
    assert_eq!(send(&app, wrong_secret).await.status, StatusCode::UNAUTHORIZED);

    // A canonical-style signature is *not* valid for a BODY_ONLY key: the modes are distinct, not
    // a fallback chain.
    let canonical = signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &body);
    assert_eq!(send(&app, canonical).await.status, StatusCode::UNAUTHORIZED);

    // The bearer key alone still authenticates (signing is optional unless REQUIRE_SIGNED_REQUESTS
    // is on): BODY_ONLY governs how a signature is *verified*, not whether the key is a credential.
    let unsigned = json_request("POST", uri, &sender.plaintext, Some(json!({ "ref": "refs/heads/main" })));
    assert_eq!(send(&app, unsigned).await.status, StatusCode::OK);
}

#[tokio::test]
async fn canonical_mode_ignores_the_hub_signature_header() {
    use simply_hook_executor::entities::api_key::HmacMode;

    let dir = ScriptDir::new();
    let script = dir.write_script("strict.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let strict = insert_key_with_mode(&db, "Strict", "0.0.0.0/0", KeyScopes::plain(), HmacMode::CanonicalV1).await;
    let hook_id = insert_hook(&db, "strict_hook", &script, 30).await;
    grant(&db, strict.id, hook_id, true, false).await;

    let uri = "/webhook/strict_hook";
    let body = json!({}).to_string();

    // A CANONICAL_V1 key must not be downgradeable to body-only verification just by choosing the
    // other header name — otherwise the per-key mode would be advisory rather than enforced.
    let hub_only = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &strict.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Hub-Signature-256", sign_body_only(&strict.signing_secret, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    // For a CANONICAL_V1 key the hub header is not read at all, so this counts as an *unsigned*
    // request — which a valid bearer key still authenticates. The point being pinned is that the
    // hub signature is never accepted as proof: it is ignored, not honoured.
    assert_eq!(send(&app, hub_only).await.status, StatusCode::OK);

    // And with signing made compulsory, the same request is refused outright — proving the hub
    // header contributed nothing.
    let strict_app = create_app(AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig { require_signed_requests: true, ..(*test_config()).clone() }),
        test_cipher(),
    ));
    let hub_only_again = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &strict.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Hub-Signature-256", sign_body_only(&strict.signing_secret, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    let response = send(&strict_app, hub_only_again).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.string("error").contains("must be signed"));

    // A body-only signature sent under the correct header name is still wrong material here.
    let body_only_sig = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &strict.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", now_timestamp().to_string())
            .header("X-Signature-256", sign_body_only(&strict.signing_secret, &body)),
    )
    .body(axum::body::Body::from(body.clone()))
    .expect("request builds");
    assert_eq!(send(&app, body_only_sig).await.status, StatusCode::UNAUTHORIZED);

    // The canonical signature works, confirming the key itself is fine.
    let canonical = signed_request("POST", uri, &strict.plaintext, &strict.signing_secret, &body);
    assert_eq!(send(&app, canonical).await.status, StatusCode::OK);
}

#[tokio::test]
async fn hmac_mode_is_settable_through_the_api_and_defaults_to_canonical() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    // Omitted -> the strict default, never the relaxed one.
    let defaulted = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "defaulted", "bound_ips": "0.0.0.0/0" }))),
    )
    .await;
    assert_eq!(defaulted.status, StatusCode::OK);
    let defaulted_id = defaulted.string("id");

    let listed = send(&app, json_request("GET", "/api/keys", &master, None)).await;
    let rows = listed.json.as_array().cloned().unwrap_or_default();
    let defaulted_row = rows.iter().find(|k| k["id"] == json!(defaulted_id)).expect("the key is listed");
    assert_eq!(defaulted_row["hmac_mode"], json!("CANONICAL_V1"));

    // Explicitly requested at creation.
    let body_only = send(
        &app,
        json_request(
            "POST",
            "/api/keys",
            &master,
            Some(json!({ "name": "webhook_sender", "bound_ips": "0.0.0.0/0", "hmac_mode": "BODY_ONLY" })),
        ),
    )
    .await;
    assert_eq!(body_only.status, StatusCode::OK);
    let body_only_id = body_only.string("id");

    // Choosing the weaker mode is recorded in the audit trail, since it is a security decision.
    let audit = send(&app, json_request("GET", "/api/audit-logs?action=KEY_CREATE&limit=5", &master, None)).await;
    let details = audit.json.as_array().cloned().unwrap_or_default();
    assert!(
        details.iter().any(|e| e["details"].as_str().unwrap_or_default().contains("BODY_ONLY")
            && e["details"].as_str().unwrap_or_default().contains("no replay protection")),
        "creating a BODY_ONLY key must be audited as such: {details:?}"
    );

    // Switchable both ways through the update endpoint.
    let switched = send(
        &app,
        json_request("PUT", &format!("/api/keys/{defaulted_id}"), &master, Some(json!({ "hmac_mode": "BODY_ONLY" }))),
    )
    .await;
    assert_eq!(switched.status, StatusCode::OK);
    assert_eq!(switched.field("hmac_mode"), &json!("BODY_ONLY"));

    let back = send(
        &app,
        json_request("PUT", &format!("/api/keys/{body_only_id}"), &master, Some(json!({ "hmac_mode": "CANONICAL_V1" }))),
    )
    .await;
    assert_eq!(back.status, StatusCode::OK);
    assert_eq!(back.field("hmac_mode"), &json!("CANONICAL_V1"));

    // Omitting the field on an update leaves the mode untouched.
    let untouched = send(
        &app,
        json_request("PUT", &format!("/api/keys/{defaulted_id}"), &master, Some(json!({ "name": "renamed" }))),
    )
    .await;
    assert_eq!(untouched.field("hmac_mode"), &json!("BODY_ONLY"));

    // An unrecognized mode is rejected by deserialization rather than silently defaulting.
    let invalid = send(
        &app,
        json_request(
            "POST",
            "/api/keys",
            &master,
            Some(json!({ "name": "bogus", "bound_ips": "0.0.0.0/0", "hmac_mode": "NO_SUCH_MODE" })),
        ),
    )
    .await;
    assert!(
        invalid.status.is_client_error(),
        "an unknown hmac_mode must not be accepted, got {}",
        invalid.status
    );

    // The key's own identity endpoint reports its mode, which is what the SPA signs with.
    let me = send(&app, json_request("GET", "/api/auth/me", &master, None)).await;
    assert_eq!(me.field("hmac_mode"), &json!("CANONICAL_V1"));
}

#[tokio::test]
async fn hmac_mode_migration_defaults_existing_keys_to_canonical() {
    use sea_orm_migration::MigratorTrait;
    use simply_hook_executor::{entities::api_key::HmacMode, migration::Migrator};

    let db = sea_orm::Database::connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite is available");

    // Stop just before the hmac_mode migration: this is what a database from the previous release
    // looks like.
    Migrator::up(&db, Some(3)).await.expect("earlier migrations apply");
    Migrator::up(&db, None).await.expect("the hmac_mode migration applies to an existing schema");

    // An existing row must come out on the *strict* mode. Defaulting an upgrade to BODY_ONLY would
    // silently strip replay protection from every deployed key.
    let seeded = insert_key_full(&db, "Legacy", "0.0.0.0/0", KeyScopes::plain()).await;
    let stored = simply_hook_executor::entities::prelude::ApiKey::find_by_id(seeded.id)
        .one(&db)
        .await
        .expect("query succeeds")
        .expect("the key exists");
    assert_eq!(stored.hmac_mode, HmacMode::CanonicalV1);

    Migrator::up(&db, None).await.expect("migrations are idempotent");
}

#[tokio::test]
async fn signature_rejection_leaks_no_oracle_about_the_correct_digest() {
    let dir = ScriptDir::new();
    let side_effect = dir.path_for("must-not-run");
    let script = dir.write_script("oracle.sh", &format!("touch \"{side_effect}\""));

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let signer = insert_key_full(&db, "Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "oracle_hook", &script, 30).await;
    grant(&db, signer.id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let body = json!({ "parameters": {} }).to_string();
    let timestamp = now_timestamp();
    let valid = sign_request(&signer.signing_secret, "POST", &uri, timestamp, &body);
    let digest = hex::decode(valid.trim_start_matches("sha256=")).expect("valid hex");

    let attempt = |signature: String| {
        with_connect_info(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("X-API-Key", &signer.plaintext)
                .header("Content-Type", "application/json")
                .header("X-Timestamp", timestamp.to_string())
                .header("X-Signature-256", signature),
        )
        .body(axum::body::Body::from(body.clone()))
        .expect("request builds")
    };

    // Wrong at the very first byte, wrong at the very last byte, and wrong everywhere. If the
    // comparison short-circuited, these would be the cases that differ — so they must be
    // indistinguishable in everything the caller can observe.
    let mut first_byte_wrong = digest.clone();
    first_byte_wrong[0] ^= 0xff;
    let mut last_byte_wrong = digest.clone();
    last_byte_wrong[31] ^= 0xff;

    let variants = [
        ("first byte wrong", hex::encode(&first_byte_wrong)),
        ("last byte wrong", hex::encode(&last_byte_wrong)),
        ("entirely wrong", hex::encode([0u8; 32])),
        ("all ones", hex::encode([0xffu8; 32])),
    ];

    let mut responses = Vec::new();
    for (label, hex_digest) in &variants {
        let response = send(&app, attempt(format!("sha256={hex_digest}"))).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{label} must be rejected");
        responses.push((label, response.status, response.string("error")));
    }

    // Every rejection must be byte-identical in status and message. A differing message — "close
    // but wrong" versus "completely wrong" — would itself be an oracle, regardless of how the
    // bytes were compared.
    let (_, first_status, first_error) = &responses[0];
    for (label, status, error) in &responses {
        assert_eq!(status, first_status, "{label}: status differs from the other rejections");
        assert_eq!(error, first_error, "{label}: error message differs from the other rejections");
    }
    assert_eq!(first_error, "Invalid request signature");

    // No rejected attempt reached the engine.
    assert!(!std::path::Path::new(&side_effect).exists());
    assert_eq!(execution_count(&db).await, 0);

    // The genuine signature still works, proving the setup is otherwise sound.
    assert_eq!(send(&app, attempt(valid)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn replay_differs_between_hmac_modes() {
    use simply_hook_executor::entities::api_key::HmacMode;

    let dir = ScriptDir::new();
    let script = dir.write_script("replay_diff.sh", "echo replayed");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let strict = insert_key_with_mode(&db, "Strict", "0.0.0.0/0", KeyScopes::plain(), HmacMode::CanonicalV1).await;
    let lenient = insert_key_with_mode(&db, "Lenient", "0.0.0.0/0", KeyScopes::plain(), HmacMode::BodyOnly).await;

    let hook_id = insert_hook(&db, "replay_diff", &script, 30).await;
    grant(&db, strict.id, hook_id, true, false).await;
    grant(&db, lenient.id, hook_id, true, false).await;

    let uri = "/webhook/replay_diff";
    let body = json!({}).to_string();
    // Ten minutes in the past — comfortably outside the 300s window in either direction.
    let ten_minutes_ago = now_timestamp() - 600;

    // CANONICAL_V1: the timestamp is part of the signed material, so a captured request cannot be
    // re-dated, and its original date has aged out. This is the anti-replay property.
    let stale_canonical = signed_request_at(
        "POST",
        uri,
        &strict.plaintext,
        &strict.signing_secret,
        &body,
        ten_minutes_ago,
    );
    let response = send(&app, stale_canonical).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.string("error").contains("window"));

    // The same key with a fresh timestamp works, so the rejection above is about age, not the key.
    let fresh_canonical = signed_request("POST", uri, &strict.plaintext, &strict.signing_secret, &body);
    assert_eq!(send(&app, fresh_canonical).await.status, StatusCode::OK);

    // BODY_ONLY: the signature covers the body alone, so age is not expressible and the identical
    // payload stays valid indefinitely. This is the documented trade-off of the mode, demonstrated
    // rather than merely asserted in prose.
    let replayed = body_only_request(uri, &lenient.plaintext, &lenient.signing_secret, &body, "X-Hub-Signature-256");
    assert_eq!(send(&app, replayed).await.status, StatusCode::OK);

    // Replaying the byte-identical request again also succeeds — the actual replay exposure.
    for attempt in 0..3 {
        let again = body_only_request(uri, &lenient.plaintext, &lenient.signing_secret, &body, "X-Hub-Signature-256");
        assert_eq!(
            send(&app, again).await.status,
            StatusCode::OK,
            "BODY_ONLY replay attempt {attempt} should still be accepted"
        );
    }

    // Two accepted canonical runs would be wrong; count what actually executed: 1 fresh canonical
    // + 4 body-only = 5, and zero from the stale canonical attempt.
    assert_eq!(execution_count(&db).await, 5);
}

#[tokio::test]
async fn hmac_mode_toggle_takes_effect_immediately_without_a_restart() {
    use simply_hook_executor::entities::api_key::HmacMode;

    let dir = ScriptDir::new();
    let script = dir.write_script("toggle.sh", "echo toggled");

    let db = setup_test_db().await;
    // One app instance for the whole test: nothing is rebuilt, so anything that takes effect here
    // took effect without a restart.
    //
    // Signing is made mandatory so the mode is *observable*. With signatures optional, a valid
    // bearer key authenticates under either mode and the two would look identical from outside —
    // the test would pass without proving anything.
    let app = create_app(AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig { require_signed_requests: true, ..(*test_config()).clone() }),
        test_cipher(),
    ));
    let master = insert_key_full(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;
    let subject = insert_key_with_mode(&db, "Subject", "0.0.0.0/0", KeyScopes::plain(), HmacMode::CanonicalV1).await;

    let hook_id = insert_hook(&db, "toggle_hook", &script, 30).await;
    grant(&db, subject.id, hook_id, true, false).await;

    let uri = "/webhook/toggle_hook";
    let body = json!({}).to_string();

    // Each call is stamped a second earlier than the last. Every timestamp is comfortably inside
    // the 300s window, but they produce *distinct* signatures — which this test needs, because
    // anti-replay now refuses a second use of the same one. Re-sending an identical signature is a
    // replay whether or not the resender is the original client, and that is the point.
    let canonical = |age_seconds: i64| {
        signed_request_at(
            "POST",
            uri,
            &subject.plaintext,
            &subject.signing_secret,
            &body,
            now_timestamp() - age_seconds,
        )
    };
    let body_only = || body_only_request(uri, &subject.plaintext, &subject.signing_secret, &body, "X-Hub-Signature-256");

    // Starting state: canonical accepted, body-only refused.
    assert_eq!(send(&app, canonical(0)).await.status, StatusCode::OK);
    assert_eq!(send(&app, body_only()).await.status, StatusCode::UNAUTHORIZED);

    // Flip to BODY_ONLY through the API (itself signed, since signing is mandatory here).
    let to_body_only = send(
        &app,
        signed_bearer_request(
            "PUT",
            &format!("/api/keys/{}", subject.id),
            &master.plaintext,
            &master.signing_secret,
            &json!({ "hmac_mode": "BODY_ONLY" }).to_string(),
        ),
    )
    .await;
    assert_eq!(to_body_only.status, StatusCode::OK);
    assert_eq!(to_body_only.field("hmac_mode"), &json!("BODY_ONLY"));

    // The very next request already follows the new rules, in both directions.
    assert_eq!(send(&app, body_only()).await.status, StatusCode::OK, "BODY_ONLY should now be accepted");
    assert_eq!(
        send(&app, canonical(1)).await.status,
        StatusCode::UNAUTHORIZED,
        "canonical signatures should now be refused"
    );

    // Flip back via PATCH, which routes to the same handler.
    let back = send(
        &app,
        signed_bearer_request(
            "PATCH",
            &format!("/api/keys/{}", subject.id),
            &master.plaintext,
            &master.signing_secret,
            &json!({ "hmac_mode": "CANONICAL_V1" }).to_string(),
        ),
    )
    .await;
    assert_eq!(back.status, StatusCode::OK);
    assert_eq!(back.field("hmac_mode"), &json!("CANONICAL_V1"));

    assert_eq!(send(&app, canonical(2)).await.status, StatusCode::OK, "canonical should be accepted again");
    assert_eq!(send(&app, body_only()).await.status, StatusCode::UNAUTHORIZED, "BODY_ONLY should be refused again");

    // The key's own identity endpoint reflects the live mode too, which is what the SPA signs with.
    let me = send(
        &app,
        signed_bearer_request("GET", "/api/auth/me", &subject.plaintext, &subject.signing_secret, ""),
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.field("hmac_mode"), &json!("CANONICAL_V1"));

    // Three accepted executions: the two canonical runs and the one body-only run.
    assert_eq!(execution_count(&db).await, 3);
}

#[tokio::test]
async fn large_payloads_are_signed_verified_and_executed_within_the_buffer_limit() {
    let dir = ScriptDir::new();
    // Reports only lengths, so a multi-hundred-KB payload cannot blow the captured-output cap.
    let script = dir.write_script("large.sh", "echo \"marker=${HOOK_PARAM_MARKER} blob_len=${#HOOK_PARAM_BLOB}\"");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_full(&db, "Bulk", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "large_hook", &script, 30).await;
    insert_parameter(&db, hook_id, "marker", Some("none"), true).await;
    insert_parameter(&db, hook_id, "blob", Some(""), true).await;
    grant(&db, sender.id, hook_id, true, false).await;

    let uri = "/webhook/large_hook";

    // A ~512 KB body whose *parameters* stay small: the padding is a top-level sibling of
    // `parameters`, so it is ignored for parameter resolution but is still fully covered by the
    // signature. That isolates "can we HMAC a large body" from argv/environment size limits.
    let padding = "x".repeat(512 * 1024);
    let large_body = json!({ "parameters": { "marker": "big" }, "padding": padding }).to_string();
    assert!(large_body.len() > 512 * 1024, "the test payload should really be large");

    let response = send(
        &app,
        signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &large_body),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "a ~512 KB signed body should verify and execute");
    assert_eq!(response.field("status"), &json!("SUCCESS"));
    assert!(response.string("stdout").contains("marker=big"));

    // Tampering with one byte deep inside the padding must still invalidate the signature — the
    // whole body is covered, not a prefix of it.
    let mut tampered = large_body.clone();
    let midpoint = tampered.len() / 2;
    tampered.replace_range(midpoint..midpoint + 1, "y");
    let timestamp = now_timestamp();
    let stale_signature = sign_request(&sender.signing_secret, "POST", uri, timestamp, &large_body);
    let tampered_request = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", &sender.plaintext)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", stale_signature),
    )
    .body(axum::body::Body::from(tampered))
    .expect("request builds");
    assert_eq!(
        send(&app, tampered_request).await.status,
        StatusCode::UNAUTHORIZED,
        "a single altered byte in the middle of a large body must invalidate the signature"
    );

    // Just under the buffer bound: still accepted. Sized from the constant rather than a literal,
    // so the converged 3 MiB figure cannot be changed in one place and silently missed here.
    let near_limit_padding = "z".repeat(simply_hook_executor::MAX_REQUEST_BODY_BYTES - 4096);
    let near_limit_body = json!({ "parameters": { "marker": "near" }, "padding": near_limit_padding }).to_string();
    assert!(
        near_limit_body.len() < simply_hook_executor::MAX_REQUEST_BODY_BYTES,
        "must stay under the buffer limit"
    );
    let response = send(
        &app,
        signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &near_limit_body),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "a body just under the limit should be accepted");

    // Over the bound: refused before any hashing or execution, with an explanatory error rather
    // than a hang or an OOM.
    let oversized_padding = "w".repeat(2 * simply_hook_executor::MAX_REQUEST_BODY_BYTES);
    let oversized_body = json!({ "parameters": { "marker": "over" }, "padding": oversized_padding }).to_string();
    let response = send(
        &app,
        signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &oversized_body),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "an oversized body must be refused");
    assert!(response.string("error").contains("too large"));

    // A genuinely large *parameter* also survives the round trip into the child's environment.
    // Kept to 64 KiB: argv plus environment share a per-process limit (ARG_MAX), and each resolved
    // parameter is passed both ways, so a multi-hundred-KB value would risk E2BIG on some systems
    // — a platform limit, not a defect in this daemon.
    let blob = "b".repeat(64 * 1024);
    let blob_body = json!({ "parameters": { "marker": "blob", "blob": blob } }).to_string();
    let response = send(
        &app,
        signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &blob_body),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.string("stdout").contains(&format!("blob_len={}", 64 * 1024)),
        "the full parameter should reach the process environment intact: {}",
        response.string("stdout")
    );

    // Only the accepted requests produced history rows.
    assert_eq!(execution_count(&db).await, 3);
}

#[tokio::test]
async fn signing_secrets_are_encrypted_at_rest_when_a_key_is_configured() {
    use sea_orm::EntityTrait as _;
    use simply_hook_executor::{crypto::SecretCipher, entities::prelude::ApiKey};

    let db = setup_test_db().await;
    let cipher = Arc::new(
        SecretCipher::from_hex_key("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .expect("valid key"),
    );
    let app = create_app(test_state_with_cipher(&db, cipher.clone()));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    let created = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "sealed", "bound_ips": "0.0.0.0/0" }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let signing_secret = created.string("signing_secret");
    let key_id = created.string("key_id");
    let created_api_key = created.string("plaintext_key");
    assert!(key_id.starts_with("shk_"));
    assert!(!signing_secret.is_empty());

    // The stored column must not contain the secret in any readable form.
    let stored = ApiKey::find_by_id(Uuid::parse_str(&created.string("id")).expect("valid uuid"))
        .one(&db)
        .await
        .expect("query succeeds")
        .expect("the key exists")
        .signing_secret
        .expect("a signing secret was stored");
    assert!(!stored.contains(&signing_secret), "the raw secret must not be stored");
    assert!(stored.starts_with("v1.xchacha20poly1305."), "it should be sealed: {stored}");
    assert_eq!(cipher.open(&stored).expect("opens"), signing_secret);

    // And the sealed secret still verifies a real signature end to end.
    let dir = ScriptDir::new();
    let script = dir.write_script("sealed.sh", "echo sealed-ok");
    let hook = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "sealed_hook", "script_path": script }))),
    )
    .await;
    assert_eq!(hook.status, StatusCode::OK);
    send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{}/permissions", created.string("id")),
            &master,
            Some(json!({ "hook_name": "sealed_hook", "can_execute": true, "can_manage": false })),
        ),
    )
    .await;

    let body = json!({}).to_string();
    let response = send(
        &app,
        signed_request("POST", "/webhook/sealed_hook", &created_api_key, &signing_secret, &body),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.string("stdout").trim(), "sealed-ok");

    // The listing exposes the public identifier but never the secret.
    let listed = send(&app, json_request("GET", "/api/keys", &master, None)).await;
    let serialized = listed.json.to_string();
    assert!(serialized.contains(&key_id), "key_id should be listed");
    assert!(!serialized.contains(&signing_secret), "the signing secret must never be listed");
    assert!(!serialized.contains("signing_secret\":\""), "no raw secret field is exposed");
}

#[tokio::test]
async fn hmac_signature_failures_are_rejected_without_executing_anything() {
    let dir = ScriptDir::new();
    let side_effect = dir.path_for("must-not-run");
    let script = dir.write_script("signed_fail.sh", &format!("touch \"{side_effect}\""));

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let signer = insert_key_full(&db, "Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    // A second valid key: a signature made with *someone else's* valid secret must not pass.
    let other = insert_key_full(&db, "Other Signer", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "signed_fail", &script, 30).await;
    grant(&db, signer.id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let body = json!({ "parameters": {} }).to_string();
    let timestamp = now_timestamp();
    let valid = sign_request(&signer.signing_secret, "POST", &uri, timestamp, &body);

    let request = |sig: &str, payload: &str| {
        with_connect_info(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("X-API-Key", &signer.plaintext)
                .header("Content-Type", "application/json")
                .header("X-Timestamp", timestamp.to_string())
                .header("X-Signature-256", sig),
        )
        .body(axum::body::Body::from(payload.to_owned()))
        .expect("request builds")
    };

    // Every one of these presents a *valid* API key — only the signature is wrong, so each must
    // still be rejected at the authentication layer.
    let rejected: Vec<(&str, String, String)> = vec![
        ("tampered body", valid.clone(), json!({ "parameters": { "x": "1" } }).to_string()),
        ("body with trailing whitespace", valid.clone(), format!("{body} ")),
        ("signature from another valid key", sign_request(&other.signing_secret, "POST", &uri, timestamp, &body), body.clone()),
        ("signature of a different payload", sign_request(&signer.signing_secret, "POST", &uri, timestamp, "{}"), body.clone()),
        ("signature keyed on the bearer key instead of the signing secret", sign_request(&signer.plaintext, "POST", &uri, timestamp, &body), body.clone()),
        ("signature computed for a different method", sign_request(&signer.signing_secret, "DELETE", &uri, timestamp, &body), body.clone()),
        ("signature computed for a different path", sign_request(&signer.signing_secret, "POST", "/api/hooks/other/execute", timestamp, &body), body.clone()),
        ("signature computed for a different timestamp", sign_request(&signer.signing_secret, "POST", &uri, timestamp - 60, &body), body.clone()),
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
    // Creation takes `can_manage_hooks`; the edits later in this lifecycle take R2's conjunction,
    // whose global half is `can_manage_keys`. Neither right implies the other, so a key that walks
    // the whole CRUD lifecycle holds both.
    let (_, manager) =
        insert_key(&db, "Hook Manager", "0.0.0.0/0", KeyScopes::parent_hook_manager()).await;

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
    // §4 oracle discipline: an unmapped caller gets exactly what a nonexistent hook id gives, so
    // the listing being empty and the direct fetch failing tell the same story.
    assert_eq!(send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &unmapped, None)).await.status, StatusCode::NOT_FOUND);

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
    // Two different refusals, and the difference is §4's whole point. The manage-only key *can*
    // see the hook — it holds a row — so it is merely short a verb: `403`. The stranger holds
    // nothing, so the hook is outside its visibility scope and must look nonexistent: `404`.
    assert_eq!(send(&app, json_request("POST", &uri, &manage_only, None)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, json_request("POST", &uri, &stranger, None)).await.status, StatusCode::NOT_FOUND);
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
    // A Parent: declaring parameters is a management action, gated by R2's conjunction.
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::parent()).await;
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

// ─────────────────────────────────────────────────────────────
// Privileged execution (run_as_user / sudo)
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn run_as_user_migration_upgrades_an_existing_database() {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set};
    use sea_orm_migration::MigratorTrait;
    use simply_hook_executor::{entities::hook, migration::Migrator};

    let db = sea_orm::Database::connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite is available");

    // Stop at the initial schema: this is what a database created by the previous release looks
    // like, i.e. `hooks` without a `run_as_user` column.
    Migrator::up(&db, Some(1)).await.expect("the initial schema applies");

    // Then apply the rest, exercising the ALTER TABLE upgrade path rather than a fresh CREATE.
    Migrator::up(&db, None).await.expect("the run_as_user migration applies to an existing schema");

    // The new column is present, nullable, and defaults to NULL for pre-existing rows.
    let now = chrono::Utc::now().naive_utc();
    let legacy = hook::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set("legacy".to_owned()),
        description: Set(None),
        script_path: Set("/bin/true".to_owned()),
        default_timeout_seconds: Set(30),
        run_as_user: Set(None),
        owner_key_id: Set(None),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .expect("a hook is insertable after the upgrade");
    assert_eq!(legacy.run_as_user, None, "an unelevated hook keeps running as the daemon user");
    // The soft-delete migration backfills existing rows as live rather than leaving the column
    // nullable, so an upgrade cannot make a hook vanish from the default listing.
    assert!(!legacy.is_deleted, "an upgraded hook is live, not trashed");
    assert_eq!(legacy.deleted_at, None);
    assert_eq!(legacy.deleted_by, None);

    // And the column accepts a value.
    let mut active: hook::ActiveModel = legacy.into();
    active.run_as_user = Set(Some("root".to_owned()));
    let elevated = active.update(&db).await.expect("run_as_user is writable");
    assert_eq!(elevated.run_as_user.as_deref(), Some("root"));

    // Re-running the migrator is a no-op rather than an error, so a restart never fails.
    Migrator::up(&db, None).await.expect("migrations are idempotent");
}

#[tokio::test]
async fn dry_run_previews_the_exact_sudo_command_for_a_privileged_hook() {
    let dir = ScriptDir::new();
    let script = dir.write_script("privileged.sh", "echo elevated");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook_as(&db, "privileged", &script, 30, Some("root")).await;
    insert_parameter(&db, hook_id, "target", None, true).await;
    insert_parameter(&db, hook_id, "reason", Some("routine"), true).await;
    grant(&db, key_id, hook_id, true, false).await;

    let preview = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/test"),
            &key,
            Some(json!({ "parameters": { "target": "203.0.113.7" } })),
        ),
    )
    .await;

    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(preview.json["command"]["program"], json!("/usr/bin/sudo"));
    assert_eq!(preview.json["command"]["run_as_user"], json!("root"));
    // The whole point of the preview: the operator sees the literal argv, sudo flags included.
    assert_eq!(
        preview.json["command"]["args"],
        json!(["-n", "-u", "root", "--", script, "203.0.113.7", "routine"])
    );
    // Parameters still reach the environment exactly as they do for an unprivileged hook.
    assert_eq!(preview.json["command"]["env"]["HOOK_PARAM_TARGET"], json!("203.0.113.7"));
    assert_eq!(preview.json["command"]["env"]["HOOK_PARAM_REASON"], json!("routine"));

    // The unprivileged form of the same hook has no sudo wrapper at all.
    let plain_id = insert_hook_as(&db, "unprivileged", &script, 30, None).await;
    grant(&db, key_id, plain_id, true, false).await;
    let plain = send(&app, json_request("POST", &format!("/api/hooks/{plain_id}/test"), &key, None)).await;
    assert_eq!(plain.json["command"]["program"], json!(script));
    assert_eq!(plain.json["command"]["args"], json!([]));
    assert_eq!(plain.json["command"]["run_as_user"], json!(null));
}

#[tokio::test]
async fn run_as_user_survives_hook_crud_and_is_audited() {
    let dir = ScriptDir::new();
    let script = dir.write_script("crud_priv.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    let created = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": "priv_crud", "script_path": script, "run_as_user": "postgres" })),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.field("run_as_user"), &json!("postgres"));
    let hook_id = created.string("id");

    // It round-trips through the read paths.
    let fetched = send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &master, None)).await;
    assert_eq!(fetched.field("run_as_user"), &json!("postgres"));
    let listed = send(&app, json_request("GET", "/api/hooks", &master, None)).await;
    assert_eq!(listed.json[0]["run_as_user"], json!("postgres"));

    // Creation is audited with the elevation, so "what runs as another account" is answerable
    // from the audit trail alone.
    let audit = send(&app, json_request("GET", "/api/audit-logs?action=HOOK_CREATE&limit=1", &master, None)).await;
    assert!(
        audit.json[0]["details"].as_str().unwrap_or_default().contains("runs as 'postgres' via sudo"),
        "audit details should record the elevation: {}",
        audit.json[0]["details"]
    );

    // Changing the account is recorded too.
    let updated = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &master, Some(json!({ "run_as_user": "root" }))),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.field("run_as_user"), &json!("root"));

    let audit = send(&app, json_request("GET", "/api/audit-logs?action=HOOK_UPDATE&limit=1", &master, None)).await;
    assert!(
        audit.json[0]["details"].as_str().unwrap_or_default().contains("runs as 'root' via sudo"),
        "{}",
        audit.json[0]["details"]
    );

    // An explicit empty string drops elevation; the field being absent would have left it alone.
    let cleared = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &master, Some(json!({ "run_as_user": "" }))),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::OK);
    assert_eq!(cleared.field("run_as_user"), &json!(null));

    let untouched = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &master, Some(json!({ "description": "unrelated" }))),
    )
    .await;
    assert_eq!(untouched.field("run_as_user"), &json!(null));
}

#[tokio::test]
async fn only_master_keys_may_assign_run_as_user() {
    let dir = ScriptDir::new();
    let script = dir.write_script("guarded_priv.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    // A fully-scoped non-master: it may create *and* maintain hooks, it simply may not elevate them.
    let (_, manager) =
        insert_key(&db, "Hook Manager", "0.0.0.0/0", KeyScopes::parent_hook_manager()).await;
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    // Creating a *standard* hook is allowed and must keep working.
    let ordinary = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "ordinary", "script_path": script }))),
    )
    .await;
    assert_eq!(ordinary.status, StatusCode::OK);
    assert_eq!(ordinary.field("run_as_user"), &json!(null));

    // Requesting elevation is not.
    for account in ["root", "postgres", "nobody"] {
        let denied = send(
            &app,
            json_request(
                "POST",
                "/api/hooks",
                &manager,
                Some(json!({ "name": format!("escalate_{account}"), "script_path": script, "run_as_user": account })),
            ),
        )
        .await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN, "run_as_user={account} must be refused");
        assert_eq!(
            denied.string("error"),
            "Only master API keys can assign run_as_user privileges"
        );
    }

    // The refusal is authorization, not validation: a syntactically invalid account from a
    // non-master must still be a 403, so probing the field cannot reveal what would be accepted.
    let probe = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &manager,
            Some(json!({ "name": "probe", "script_path": script, "run_as_user": "-i" })),
        ),
    )
    .await;
    assert_eq!(probe.status, StatusCode::FORBIDDEN);

    // The escalation check must fire *before* any other field is validated. Each of these payloads
    // is invalid in some additional way that would otherwise produce a 400 first; the 403 has to
    // win, or an attacker could distinguish "my run_as_user was accepted" from "it was refused"
    // by observing which complaint came back.
    let masked = [
        ("relative script_path", json!({ "name": "m1", "script_path": "relative.sh", "run_as_user": "root" })),
        ("traversing script_path", json!({ "name": "m2", "script_path": "/opt/../etc/shadow", "run_as_user": "root" })),
        ("invalid timeout", json!({ "name": "m3", "script_path": script, "default_timeout_seconds": 0, "run_as_user": "root" })),
        ("empty name", json!({ "name": "   ", "script_path": script, "run_as_user": "root" })),
        ("bad param_key", json!({ "name": "m4", "script_path": script, "run_as_user": "root", "parameters": [{ "param_key": "9bad" }] })),
    ];
    for (label, payload) in masked {
        let response = send(&app, json_request("POST", "/api/hooks", &manager, Some(payload))).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "{label}: the escalation refusal must precede field validation"
        );
        assert_eq!(
            response.string("error"),
            "Only master API keys can assign run_as_user privileges",
            "{label}: the 403 must not be masked by a 400 about another field"
        );
    }

    // The same ordering holds on update.
    let masked_update = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{}", ordinary.string("id")),
            &manager,
            Some(json!({ "script_path": "relative.sh", "run_as_user": "root" })),
        ),
    )
    .await;
    assert_eq!(masked_update.status, StatusCode::FORBIDDEN);
    assert_eq!(
        masked_update.string("error"),
        "Only master API keys can assign run_as_user privileges"
    );

    // Explicitly *not* elevating is fine for a non-master, in both spellings.
    for null_ish in [json!(null), json!("")] {
        let allowed = send(
            &app,
            json_request(
                "POST",
                "/api/hooks",
                &manager,
                Some(json!({ "name": format!("plain_{null_ish}"), "script_path": script, "run_as_user": null_ish })),
            ),
        )
        .await;
        assert_eq!(allowed.status, StatusCode::OK, "an unelevated hook must still be creatable");
        assert_eq!(allowed.field("run_as_user"), &json!(null));
    }

    // The guard covers updates too — including on a hook the non-master owns outright.
    let owned_id = ordinary.string("id");
    let escalate = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{owned_id}"), &manager, Some(json!({ "run_as_user": "root" }))),
    )
    .await;
    assert_eq!(escalate.status, StatusCode::FORBIDDEN);
    assert_eq!(
        escalate.string("error"),
        "Only master API keys can assign run_as_user privileges"
    );

    // ...and via PATCH, which is routed to the same handler.
    let patched = send(
        &app,
        json_request("PATCH", &format!("/api/hooks/{owned_id}"), &manager, Some(json!({ "run_as_user": "root" }))),
    )
    .await;
    assert_eq!(patched.status, StatusCode::FORBIDDEN);

    // A master can do what the manager could not.
    let elevated = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{owned_id}"), &master, Some(json!({ "run_as_user": "root" }))),
    )
    .await;
    assert_eq!(elevated.status, StatusCode::OK);
    assert_eq!(elevated.field("run_as_user"), &json!("root"));

    // Once the hook is elevated, the non-master creator loses the ability to edit it *at all* —
    // even fields that look harmless, and even though it created the hook and holds full rights on
    // it. This assertion is the inverse of what it was before finding #4: the old expectation was
    // that omitting `run_as_user` left an edit permissible, which is exactly what let a
    // `can_manage` holder repoint a root hook's `script_path` while the elevation survived.
    let unrelated = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{owned_id}"), &manager, Some(json!({ "description": "edited" }))),
    )
    .await;
    assert_eq!(
        unrelated.status,
        StatusCode::FORBIDDEN,
        "a privileged hook is master-only to modify, whichever field the payload names"
    );

    // Nor can it drop the elevation. Permitting that would only add a step to the same attack:
    // clear `run_as_user`, then repoint the script freely.
    let cleared = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{owned_id}"), &manager, Some(json!({ "run_as_user": "" }))),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::FORBIDDEN, "clearing elevation is master-only too");

    // A master clears it, and the hook becomes an ordinary one the manager can edit again.
    let by_master = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{owned_id}"), &master, Some(json!({ "run_as_user": "" }))),
    )
    .await;
    assert_eq!(by_master.status, StatusCode::OK);
    assert_eq!(by_master.field("run_as_user"), &json!(null));

    let now_editable = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{owned_id}"), &manager, Some(json!({ "description": "edited" }))),
    )
    .await;
    assert_eq!(now_editable.status, StatusCode::OK, "an unelevated hook is manageable again");
}

#[tokio::test]
async fn granular_hook_permissions_separate_execute_from_manage() {
    let dir = ScriptDir::new();
    let script = dir.write_script("granular.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (executor_id, executor) = insert_key(&db, "Executor", "0.0.0.0/0", KeyScopes::plain()).await;
    // A Parent, not a plain Daughter: R2 makes management a conjunction, so the manage row granted
    // below is only half of what editing this hook takes. The other half is this flag.
    let (manager_id, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::parent()).await;
    let (_, stranger) = insert_key(&db, "Stranger", "0.0.0.0/0", KeyScopes::plain()).await;

    // Owned by the manager, so the closing assertion exercises the *permission* matrix rather than
    // §3 ownership. The complement — a manage-holder who is not the owner being refused — is
    // covered by `s3_managing_a_hook_does_not_confer_authority_to_delete_it`.
    let hook_id = insert_hook_owned_by(&db, "granular", &script, manager_id).await;
    grant(&db, executor_id, hook_id, true, false).await;
    grant(&db, manager_id, hook_id, false, true).await;

    let execute_uri = format!("/api/hooks/{hook_id}/execute");
    let test_uri = format!("/api/hooks/{hook_id}/test");
    let hook_uri = format!("/api/hooks/{hook_id}");

    // can_execute: may run and dry-run...
    assert_eq!(send(&app, json_request("POST", &execute_uri, &executor, None)).await.status, StatusCode::OK);
    assert_eq!(send(&app, json_request("POST", &test_uri, &executor, None)).await.status, StatusCode::OK);
    // ...may read the definition, its parameters, and its history...
    assert_eq!(send(&app, json_request("GET", &hook_uri, &executor, None)).await.status, StatusCode::OK);
    assert_eq!(
        send(&app, json_request("GET", &format!("{hook_uri}/parameters"), &executor, None)).await.status,
        StatusCode::OK
    );
    let history = send(&app, json_request("GET", "/api/executions", &executor, None)).await;
    assert_eq!(history.status, StatusCode::OK);
    assert_eq!(history.json.as_array().map(Vec::len), Some(1));
    // ...but may not modify or delete it.
    assert_eq!(
        send(&app, json_request("PUT", &hook_uri, &executor, Some(json!({ "name": "hijacked" })))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, json_request("PATCH", &hook_uri, &executor, Some(json!({ "name": "hijacked" })))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(&app, json_request("DELETE", &hook_uri, &executor, None)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        send(&app, json_request("POST", &format!("{hook_uri}/parameters"), &executor, Some(json!({ "param_key": "x" })))).await.status,
        StatusCode::FORBIDDEN
    );

    // can_manage: may edit and read...
    assert_eq!(
        send(&app, json_request("PUT", &hook_uri, &manager, Some(json!({ "description": "managed" })))).await.status,
        StatusCode::OK
    );
    assert_eq!(send(&app, json_request("GET", &hook_uri, &manager, None)).await.status, StatusCode::OK);
    assert_eq!(
        send(&app, json_request("POST", &format!("{hook_uri}/parameters"), &manager, Some(json!({ "param_key": "added", "default_value": "v" })))).await.status,
        StatusCode::OK
    );
    // ...but manage alone does NOT confer the right to run it, in either mode.
    assert_eq!(
        send(&app, json_request("POST", &execute_uri, &manager, None)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, json_request("POST", &test_uri, &manager, None)).await.status,
        StatusCode::FORBIDDEN,
        "a dry run reveals the resolved command line, so it requires execute rights"
    );

    // A key with no mapping at all sees and does nothing.
    for (method, uri) in [
        ("GET", hook_uri.as_str()),
        ("POST", execute_uri.as_str()),
        ("POST", test_uri.as_str()),
        ("PUT", hook_uri.as_str()),
        ("DELETE", hook_uri.as_str()),
    ] {
        let body = if method == "PUT" { Some(json!({ "description": "x" })) } else { None };
        // `404` throughout: the stranger holds no row, so §4 requires every one of these to be
        // indistinguishable from a hook id that was never issued.
        assert_eq!(
            send(&app, json_request(method, uri, &stranger, body)).await.status,
            StatusCode::NOT_FOUND,
            "{method} {uri} must be denied without a mapping"
        );
    }
    assert_eq!(
        send(&app, json_request("GET", "/api/executions", &stranger, None)).await.json.as_array().map(Vec::len),
        Some(0),
        "history is scoped to hooks the key can see"
    );

    // Deletion is the manager's, and it is the last word.
    assert_eq!(send(&app, json_request("DELETE", &hook_uri, &manager, None)).await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn run_as_user_rejects_option_injection_and_malformed_accounts() {
    let dir = ScriptDir::new();
    let script = dir.write_script("reject_priv.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_, master) = insert_key(&db, "Master", "0.0.0.0/0", KeyScopes::master()).await;

    // Each of these would be an argument to sudo's `-u`; a leading dash is the injection case.
    let hostile = [
        "-i", "--login", "-u", "-s", "root user", "root;id", "root&&id", "root|id",
        "1root", "root/../etc", "üser", "root\nother", &"a".repeat(64),
    ];

    for candidate in hostile {
        let response = send(
            &app,
            json_request(
                "POST",
                "/api/hooks",
                &master,
                Some(json!({ "name": "hostile", "script_path": script, "run_as_user": candidate })),
            ),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "run_as_user {candidate:?} must be rejected"
        );
        assert!(
            response.string("error").contains("Invalid run_as_user"),
            "{candidate:?}: unhelpful error {}",
            response.string("error")
        );
    }

    // Nothing was created by any of them.
    let hooks = send(&app, json_request("GET", "/api/hooks", &master, None)).await;
    assert_eq!(hooks.json.as_array().map(Vec::len), Some(0));

    // The same validation guards the update path.
    let created = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "ok", "script_path": script }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let hook_id = created.string("id");

    let rejected = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &master, Some(json!({ "run_as_user": "-i" }))),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);

    let still_unprivileged = send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &master, None)).await;
    assert_eq!(still_unprivileged.field("run_as_user"), &json!(null));
}

/// # Why this is `#[ignore]`d rather than skipped
///
/// It used to run by default and `return` early when `/usr/bin/sudo` was absent — which reports
/// **PASS** while asserting nothing. That is the same failure class as a green audit over a stale
/// tree: a signal that says "covered" over work that never happened, and it is worst on the machine
/// that lacks the dependency, which is exactly where someone would want to know.
///
/// The convention is adapted from `example/simply_ip_sync/tests/live_feed_ingestion_tests.rs`, whose
/// header states the rule directly: an `#[ignore]`d test "panics (failing the test) rather than
/// skipping — a `#[ignore]`d test that silently passes when the [dependency] is unreachable would
/// stop meaning anything the first time someone actually needed it to fail."
///
/// So the precondition below is an **assertion**, not a guard. The default `cargo test` run no
/// longer claims this coverage; `cargo test -- --ignored` runs it and fails loudly on a host without
/// sudo, which is the honest answer to "is this covered here?".
#[tokio::test]
#[ignore = "requires /usr/bin/sudo on the host; run with `cargo test -- --ignored`"]
async fn a_privileged_hook_actually_executes_through_sudo() {
    let dir = ScriptDir::new();
    let script = dir.write_script("via_sudo.sh", "echo ran");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    // Elevating to this test's *own* user keeps the sudoers requirement as small as possible,
    // but the suite still must not depend on any sudo configuration to pass.
    let whoami = std::env::var("USER").unwrap_or_else(|_| "root".to_owned());
    let hook_id = insert_hook_as(&db, "via_sudo", &script, 30, Some(&whoami)).await;
    grant(&db, key_id, hook_id, true, false).await;

    assert!(
        std::path::Path::new("/usr/bin/sudo").exists(),
        "/usr/bin/sudo is not installed, so this test cannot observe what it exists to observe. \
         Asserted rather than skipped: a silent `return` here would report PASS while proving \
         nothing about the sudo boundary"
    );

    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(response.status, StatusCode::OK, "the request itself must complete");

    // Whether sudo *permits* the elevation depends entirely on this machine's sudoers, which a
    // test must not assume. Both outcomes are asserted precisely:
    //   - permitted  -> the script ran and its stdout is captured;
    //   - refused    -> sudo exits non-zero without a password prompt (because of `-n`), which is
    //                   recorded as a normal FAILED execution rather than hanging or crashing.
    let status = response.string("status");
    if status == "SUCCESS" {
        assert_eq!(response.string("stdout").trim(), "ran");
    } else {
        assert_eq!(status, "FAILED");
        let stderr = response.string("stderr");
        assert!(
            stderr.contains("sudo") || stderr.contains("password") || stderr.contains("not allowed"),
            "a sudo refusal should be captured in stderr, got: {stderr:?}"
        );
    }

    // Either way the attempt is recorded, with the hook's elevation intact.
    assert_eq!(execution_count(&db).await, 1);
}

// ─────────────────────────────────────────────────────────────
// Linux permission & path-containment diagnostics
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn non_executable_script_is_refused_with_an_actionable_diagnostic() {
    let dir = ScriptDir::new();
    // Exists, is readable, but carries no execute bit — the classic "forgot chmod +x" deployment.
    let script = dir.write_with_mode("no_exec_bit.sh", "echo should never run", 0o600);

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "no_exec_bit", &script, 30).await;
    grant(&db, key_id, hook_id, true, true).await;

    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let error = response.string("error");
    assert!(error.starts_with("[ERROR] Cannot execute '"), "unexpected shape: {error}");
    assert!(error.contains(&script), "the diagnostic must name the offending path: {error}");
    assert!(error.contains("no execute bit set"), "{error}");
    // The exact mode is reported, so an operator can tell 0600 from 0644 without another round-trip.
    assert!(error.contains("0600"), "the diagnostic must report the actual mode: {error}");
    assert!(error.contains("chmod +x"), "the diagnostic must state the remedy: {error}");
    // ...and who to grant it to.
    assert!(error.contains("uid="), "the diagnostic must identify the running user: {error}");

    // Nothing ran, so nothing is recorded: a refused hook must not pollute execution history.
    assert_eq!(execution_count(&db).await, 0);

    // The dry run reports the identical diagnostic as data rather than as an error.
    let preview = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/test"), &key, None)).await;
    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(preview.field("would_execute"), &json!(false));
    assert_eq!(preview.string("blocking_reason"), error);

    // Granting the bit makes it run, proving the refusal was about permissions and nothing else.
    std::fs::set_permissions(&script, permissions(0o755)).expect("permissions are settable");
    let now_ok = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(now_ok.status, StatusCode::OK);
    assert_eq!(now_ok.field("status"), &json!("SUCCESS"));
}

#[tokio::test]
async fn missing_script_is_refused_with_an_enoent_diagnostic() {
    let dir = ScriptDir::new();
    let missing = dir.path_for("never_deployed.sh");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "never_deployed", &missing, 30).await;
    grant(&db, key_id, hook_id, true, false).await;

    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let error = response.string("error");
    assert!(error.starts_with("[ERROR] Cannot execute '"), "unexpected shape: {error}");
    assert!(error.contains("No such file or directory (ENOENT)"), "{error}");
    assert!(error.contains("Deploy the script"), "the diagnostic must state the remedy: {error}");
    // ENOENT must not be reported as a permission problem — the two send an operator to very
    // different places.
    assert!(!error.contains("EACCES"), "{error}");
    assert_eq!(execution_count(&db).await, 0);
}

#[tokio::test]
async fn a_directory_as_script_path_is_refused() {
    let dir = ScriptDir::new();
    let subdir = dir.make_dir("i_am_a_directory");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "dir_hook", &subdir, 30).await;
    grant(&db, key_id, hook_id, true, false).await;

    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.string("error").contains("not a regular file"), "{}", response.string("error"));
    assert_eq!(execution_count(&db).await, 0);
}

#[tokio::test]
async fn unsearchable_parent_directory_is_diagnosed_as_eacces() {
    let dir = ScriptDir::new();
    let locked = dir.make_dir("locked");
    let script = format!("{locked}/hidden.sh");
    std::fs::write(&script, "#!/bin/sh\necho hidden\n").expect("file is writable");
    std::fs::set_permissions(&script, permissions(0o755)).expect("permissions are settable");
    // Remove the search bit from the parent: the file is fine, but nobody can traverse into it.
    std::fs::set_permissions(&locked, permissions(0o000)).expect("permissions are settable");

    // Root ignores the `x` bit entirely, so this scenario cannot be constructed there.
    if !permissions_are_enforced_for_this_user(&script) {
        eprintln!("skipping: running with permissions that bypass directory search bits (root?)");
        std::fs::set_permissions(&locked, permissions(0o755)).ok();
        return;
    }

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (key_id, key) = insert_key(&db, "Runner", "0.0.0.0/0", KeyScopes::plain()).await;
    let hook_id = insert_hook(&db, "locked_dir", &script, 30).await;
    grant(&db, key_id, hook_id, true, false).await;

    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &key, None)).await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let error = response.string("error");
    assert!(error.contains("Permission denied (EACCES)"), "{error}");
    // The diagnostic must pinpoint the directory at fault, not just the script: an EACCES on a
    // file almost always means a parent lacks the search bit.
    assert!(error.contains(&locked), "the diagnostic must name the blocking directory: {error}");
    assert!(error.contains("uid="), "{error}");
    assert_eq!(execution_count(&db).await, 0);

    // Restore so the directory can be cleaned up on drop.
    std::fs::set_permissions(&locked, permissions(0o755)).expect("permissions are restorable");
}

#[tokio::test]
async fn path_traversal_payloads_are_blocked_at_definition_time() {
    let dir = ScriptDir::new();
    let legit = dir.write_script("legit.sh", "echo ok");

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    // Both rights: the traversal payloads are asserted at creation *and* on update below, and each
    // path sits behind a different gate. A key short of either would produce a 403 that masks the
    // 400 this test is actually about.
    let (_, manager) =
        insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::parent_hook_manager()).await;

    let payloads = [
        "/scripts/../../etc/shadow",
        "/opt/hooks/../../../etc/passwd",
        "../../../bin/sh",
        "../relative_escape.sh",
        "relative.sh",
        "./also_relative.sh",
        "/opt/hooks/./../../etc/shadow",
    ];

    for payload in payloads {
        let response = send(
            &app,
            json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "evil", "script_path": payload }))),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "traversal payload {payload:?} must be rejected at creation"
        );
        let error = response.string("error");
        assert!(
            error.contains("absolute") || error.contains("traversal"),
            "{payload:?}: unhelpful error {error}"
        );
    }

    // No hook was created by any of them.
    let hooks = send(&app, json_request("GET", "/api/hooks", &manager, None)).await;
    assert_eq!(hooks.json.as_array().map(Vec::len), Some(0));

    // The same validation runs on update, so an existing hook cannot be re-pointed at /etc/shadow.
    let created = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "legit", "script_path": legit }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    let hook_id = created.string("id");

    for payload in payloads {
        let response = send(
            &app,
            json_request(
                "PUT",
                &format!("/api/hooks/{hook_id}"),
                &manager,
                Some(json!({ "script_path": payload })),
            ),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "traversal payload {payload:?} must be rejected on update"
        );
    }

    // The hook still points where it did before every rejected update.
    let unchanged = send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &manager, None)).await;
    assert_eq!(unchanged.string("script_path"), legit);
}

#[tokio::test]
async fn script_paths_are_confined_to_allowed_roots() {
    let allowed = ScriptDir::new();
    let forbidden = ScriptDir::new();
    let inside = allowed.write_script("inside.sh", "echo inside");
    let outside = forbidden.write_script("outside.sh", "echo outside");

    let db = setup_test_db().await;
    let app = create_app(test_state_with_roots(&db, vec![allowed.root()]));
    // Both rights: containment is asserted at creation and on re-pointing an existing hook.
    let (_, manager) =
        insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::parent_hook_manager()).await;

    let ok = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "inside", "script_path": inside }))),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    let inside_id = ok.string("id");
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/hooks/{inside_id}/execute"), &manager, None)).await.status,
        StatusCode::OK
    );

    // A perfectly valid absolute path that simply is not inside a vetted root.
    let rejected = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "outside", "script_path": outside }))),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    assert!(
        rejected.string("error").contains("outside the allowed script roots"),
        "{}",
        rejected.string("error")
    );

    // Neither can an existing, contained hook be re-pointed outside.
    let escaped = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{inside_id}"), &manager, Some(json!({ "script_path": outside }))),
    )
    .await;
    assert_eq!(escaped.status, StatusCode::BAD_REQUEST);
}

#[cfg(unix)]
#[tokio::test]
async fn a_symlink_escaping_the_allowed_roots_is_blocked_at_execution() {
    let allowed = ScriptDir::new();
    let forbidden = ScriptDir::new();
    let target = forbidden.write_script("real_target.sh", "echo escaped");
    // The link's own path is inside the allowed root, so it passes the lexical check at
    // definition time — only resolving it reveals the escape.
    let link = allowed.symlink_to("looks_contained.sh", &target);

    let db = setup_test_db().await;
    let app = create_app(test_state_with_roots(&db, vec![allowed.root()]));
    let (_, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;

    let created = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "symlinked", "script_path": link }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "the link's literal path is inside the root");
    let hook_id = created.string("id");

    // Execution canonicalizes first, so the escape is caught before anything is spawned.
    let response = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &manager, None)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let error = response.string("error");
    assert!(error.contains("outside the allowed script roots"), "{error}");
    assert!(error.contains("it resolves to"), "the diagnostic must reveal the real target: {error}");
    assert_eq!(execution_count(&db).await, 0);

    // A symlink that stays inside the root is fine — containment, not a blanket symlink ban.
    let contained_target = allowed.write_script("contained_target.sh", "echo contained");
    let good_link = allowed.symlink_to("good_link.sh", &contained_target);
    let good = send(
        &app,
        json_request("POST", "/api/hooks", &manager, Some(json!({ "name": "good_link", "script_path": good_link }))),
    )
    .await;
    assert_eq!(good.status, StatusCode::OK);
    let good_id = good.string("id");
    let ran = send(&app, json_request("POST", &format!("/api/hooks/{good_id}/execute"), &manager, None)).await;
    assert_eq!(ran.status, StatusCode::OK);
    assert_eq!(ran.string("stdout").trim(), "contained");
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

    // Reading another tenant's execution by id is refused, not merely filtered out — and refused
    // as `404`, so the id cannot be used to confirm that a run happened at all (§4).
    let beta_exec_id = send(&app, json_request("GET", "/api/executions?hook=beta_hook", &master, None))
        .await
        .json[0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let cross_tenant = send(&app, json_request("GET", &format!("/api/executions/{beta_exec_id}"), &alpha, None)).await;
    assert_eq!(cross_tenant.status, StatusCode::NOT_FOUND);
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
        test_cipher(),
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
async fn log_retention_zero_keeps_history_but_still_purges_the_hook_trash() {
    let db = setup_test_db().await;
    let hook_id = insert_hook(&db, "kept_forever", "/bin/true", 30).await;
    insert_execution_aged(&db, hook_id, 3650).await;
    // Trashed well past the 92-day window, so the hook sweep must claim it.
    let (owner_id, _owner) = insert_key(&db, "owner", "", KeyScopes::master()).await;
    let expired = insert_hook_deleted_days_ago(&db, "long_gone", "/bin/true", 200, owner_id).await;

    let state = AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            log_retention_days: 0,
            retention_sweep_seconds: 1,
            ..(*test_config()).clone()
        }),
        test_cipher(),
    );
    let (shutdown_tx, worker) = spawn_retention_worker(&state);

    // `LOG_RETENTION_DAYS=0` means "keep history forever", not "stop maintaining the trash". The
    // worker therefore keeps running — it owns two sweeps, and only one of them is disabled.
    assert!(
        wait_until(Duration::from_secs(5), async || {
            fetch_hook_row(&db, expired).await.is_none()
        })
        .await,
        "the deleted-hook sweep must still run when log retention is disabled"
    );

    // ...while a decade-old execution record is untouched.
    assert_eq!(execution_count(&db).await, 1);

    drop(shutdown_tx);
    let stopped = tokio::time::timeout(Duration::from_secs(5), worker).await;
    assert!(stopped.is_ok(), "the worker still shuts down on signal");
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

    // No grant yet: the hook is outside the worker's visibility scope entirely, so §4 requires the
    // answer a nonexistent hook id gives.
    let uri = format!("/api/hooks/{hook_id}/execute");
    assert_eq!(send(&app, json_request("POST", &uri, &worker_key, None)).await.status, StatusCode::NOT_FOUND);

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
    // The row is gone, so the hook is invisible againrather than merely unusable (§4).
    assert_eq!(send(&app, json_request("POST", &uri, &new_key, None)).await.status, StatusCode::NOT_FOUND);

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
    // A Parent: parameter CRUD is a management action on the hook, so it needs both halves of R2.
    // A parameter is argv for whatever `script_path` names, which is why it sits behind the same
    // gate as the definition rather than behind the operational verb.
    let (manager_id, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::parent()).await;
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

// ─────────────────────────────────────────────────────────────
// Hostile payloads: stored XSS, argument injection, process escape, body limits
// ─────────────────────────────────────────────────────────────

/// The canonical stored-XSS probe: valid HTML, no quoting tricks, fires without user interaction.
const XSS_PAYLOAD: &str = "<img src=x onerror=alert(1)>";

/// A second payload that closes an attribute and a tag first, so a renderer that interpolates into
/// an attribute (rather than into element content) is caught too.
const XSS_BREAKOUT_PAYLOAD: &str = r#""><script>alert(document.domain)</script>"#;

/// Hook output containing live markup must survive the round trip byte-for-byte and be labelled
/// `application/json`.
///
/// Both halves matter. Verbatim storage is what makes the *renderer* solely responsible for safety
/// — if the server silently stripped tags, the UI's escaping would be untested in production and
/// the first payload that evaded the stripper would land in an unprotected sink. The content type
/// is what stops the raw API response from being rendered as a document if an operator opens the
/// URL directly.
#[tokio::test]
async fn hook_output_containing_live_markup_round_trips_verbatim_as_json() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    // Emits the payload on stdout and the breakout variant on stderr, so both streams are covered.
    let script = scripts.write_script(
        "xss.sh",
        &format!("printf '%s' '{XSS_PAYLOAD}'\nprintf '%s' '{XSS_BREAKOUT_PAYLOAD}' >&2"),
    );
    let hook_id = insert_hook(&db, "xss_hook", &script, 30).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let res = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &master, Some(json!({}))),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);

    // Verbatim: not stripped, not entity-encoded, not truncated at the first '<'.
    assert_eq!(res.field("stdout"), &json!(XSS_PAYLOAD));
    assert_eq!(res.field("stderr"), &json!(XSS_BREAKOUT_PAYLOAD));

    // Inert on the wire: a browser told `application/json` will not parse the payload as markup.
    assert_eq!(
        res.content_type.as_deref(),
        Some("application/json"),
        "an endpoint echoing attacker-controlled bytes must never be served as a document"
    );

    // The breakout payload's double quote must be JSON-escaped in the raw body, or the response
    // itself would be malformed JSON — which is how a client could be pushed into a lenient,
    // HTML-ish parse.
    assert!(
        res.raw.contains(r#"\"><script>"#),
        "the quote must be escaped in the serialized body: {}",
        res.raw
    );

    // And it must still be retrievable, unchanged, from the persisted history.
    let execution_id = res.string("id");
    let stored = send(&app, json_request("GET", &format!("/api/executions/{execution_id}"), &master, None)).await;
    assert_eq!(stored.status, StatusCode::OK);
    assert_eq!(stored.field("stdout"), &json!(XSS_PAYLOAD));
    assert_eq!(stored.field("stderr"), &json!(XSS_BREAKOUT_PAYLOAD));
}

/// A hook *name* and *script path* containing markup must also round-trip verbatim, since both are
/// rendered into the hooks table and the audit log.
#[tokio::test]
async fn hook_metadata_containing_markup_round_trips_verbatim() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("meta.sh", "echo ok");
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let hostile_name = format!("hook{XSS_PAYLOAD}");
    let created = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": hostile_name, "script_path": script, "description": XSS_BREAKOUT_PAYLOAD })),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.field("name"), &json!(hostile_name));
    assert_eq!(created.field("description"), &json!(XSS_BREAKOUT_PAYLOAD));

    // The audit trail embeds the name in a human-readable `details` string; it must be stored as
    // written rather than interpreted.
    let logs = send(&app, json_request("GET", "/api/audit-logs?action=HOOK_CREATE", &master, None)).await;
    assert_eq!(logs.status, StatusCode::OK);
    assert!(
        logs.raw.contains("onerror=alert(1)"),
        "the hook name should appear in the audit details verbatim: {}",
        logs.raw
    );
    assert_eq!(logs.content_type.as_deref(), Some("application/json"));
}

/// Guards the SPA invariant that captured output and server error text are *assigned* to the DOM,
/// never parsed as HTML.
///
/// This is a source-level assertion rather than a rendered-DOM one, and the reason is worth stating
/// plainly: the project has no JavaScript runtime and no headless browser (`AGENT.MD` forbids
/// frontend dependencies), so nothing here can mount `static/app.js` and inspect the resulting
/// nodes. What it *can* do is fail the build the moment someone routes hook output back through the
/// HTML-parsing sink, which is the regression this exists to catch. The companion API-level tests
/// above pin the other half: the bytes reaching the renderer really are attacker-controlled.
#[test]
fn spa_renders_captured_output_through_text_nodes_only() {
    let source = std::fs::read_to_string("static/app.js").expect("the SPA source is readable");

    // The single sink every captured stream flows through must assign, not parse.
    assert!(
        source.contains("pre.textContent = content;"),
        "outputBlock must write stream content with textContent"
    );
    assert!(
        source.contains("message.textContent = errorText;"),
        "server-supplied error text must be written with textContent"
    );
    assert!(
        source.contains("caption.textContent = label;"),
        "output labels must be written with textContent"
    );

    // The result modal must take a descriptor, not raw markup — the old `bodyHtml` parameter made
    // it possible to hand it a string built by concatenation.
    assert!(
        !source.contains("bodyHtml"),
        "showHookResultModal must not accept a raw HTML string"
    );

    // No line that assigns innerHTML may mention a field carrying attacker-controlled content.
    // Deliberately field names, not free text: `renderResultView` legitimately assigns trusted
    // header markup, and this check must not forbid that.
    const TAINTED_FIELDS: [&str; 6] = [
        "stdout",
        "stderr",
        "blocking_reason",
        "res.command.program",
        "argList",
        "envRows",
    ];
    for (number, line) in source.lines().enumerate() {
        if !line.contains("innerHTML") {
            continue;
        }
        for field in TAINTED_FIELDS {
            assert!(
                !line.contains(field),
                "static/app.js:{}: '{field}' must not reach innerHTML — use outputBlock()/textContent:\n{}",
                number + 1,
                line.trim()
            );
        }
    }

    // Every remaining innerHTML assignment must be escaped or a self-contained literal. Catching
    // the shape here is what keeps the audit above from silently rotting as new fields are added.
    assert!(
        source.contains("header.innerHTML = headerHtml;"),
        "renderResultView is the one place trusted header markup is parsed"
    );
}

/// Values shaped like CLI options must reach the script as inert positional data.
///
/// The threat is not shell metacharacters — there is no shell — but *argument* interpretation: a
/// value like `--version` or `-rf` is a perfectly ordinary string until something re-parses the
/// argument vector. Passing an explicit `args` vector to `execve` is what makes that impossible,
/// and this pins it end to end rather than trusting the plan builder in isolation.
#[tokio::test]
async fn cli_flag_shaped_parameters_stay_literal_in_argv_and_environment() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let canary = scripts.path_for("argv_canary");
    // Echoes every positional argument inside delimiters, then the matching environment injection.
    // `"$@"` preserves argument boundaries, so a value containing spaces or newlines shows up as
    // one argv entry rather than several.
    let script = scripts.write_script(
        "argv.sh",
        "i=0\nfor a in \"$@\"; do i=$((i+1)); printf 'argv[%s]=<%s>\\n' \"$i\" \"$a\"; done\n\
         printf 'env_flag=<%s>\\n' \"$HOOK_PARAM_P1_FLAG\"\n\
         printf 'env_target=<%s>\\n' \"$HOOK_PARAM_P2_TARGET\"\n\
         printf 'env_extra=<%s>\\n' \"$HOOK_PARAM_P3_EXTRA\"",
    );

    let hook_id = insert_hook(&db, "argv_hook", &script, 30).await;
    // Positional order is `created_at` with `param_key` as the tie-break. Numbering the keys makes
    // alphabetical order already agree with declaration order, so the argv slots asserted below are
    // deterministic even if two rows land in the same timestamp tick.
    insert_parameter(&db, hook_id, "p1_flag", None, true).await;
    insert_parameter(&db, hook_id, "p2_target", None, true).await;
    insert_parameter(&db, hook_id, "p3_extra", None, true).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // Every value here is chosen to be dangerous to a *different* consumer: getopt, rm, sudo, and
    // a shell respectively.
    let touch_canary = format!("; touch {canary}");
    let hostile: [(&str, &str, &str); 6] = [
        ("--help", "--version", "-rf"),
        ("-rf", "/", "--no-preserve-root"),
        ("--", "--login", "-u"),
        ("; rm -rf /", touch_canary.as_str(), "&& id"),
        ("$(id)", "`id`", "${IFS}id"),
        ("-u root", "--user=root", "\n--login"),
    ];

    for (flag, target, extra) in hostile {
        let res = send(
            &app,
            json_request(
                "POST",
                &format!("/api/hooks/{hook_id}/execute"),
                &master,
                Some(json!({ "parameters": { "p1_flag": flag, "p2_target": target, "p3_extra": extra } })),
            ),
        )
        .await;

        assert_eq!(res.status, StatusCode::OK, "hostile payload {flag:?} should execute inertly");
        assert_eq!(res.field("status"), &json!("SUCCESS"), "for {flag:?}");

        let stdout = res.string("stdout");
        // Positional: exactly the bytes supplied, in declaration order, one argv slot each.
        assert!(stdout.contains(&format!("argv[1]=<{flag}>")), "argv[1] for {flag:?} in:\n{stdout}");
        assert!(stdout.contains(&format!("argv[2]=<{target}>")), "argv[2] for {target:?} in:\n{stdout}");
        assert!(stdout.contains(&format!("argv[3]=<{extra}>")), "argv[3] for {extra:?} in:\n{stdout}");
        // Environment: same bytes again, prefixed and uppercased.
        assert!(stdout.contains(&format!("env_flag=<{flag}>")), "env for {flag:?} in:\n{stdout}");
        assert!(stdout.contains(&format!("env_target=<{target}>")), "env for {target:?} in:\n{stdout}");
        assert!(stdout.contains(&format!("env_extra=<{extra}>")), "env for {extra:?} in:\n{stdout}");
        // No argument absorbed another: three declared parameters, three argv slots.
        assert!(!stdout.contains("argv[4]="), "no extra argv entry appeared for {flag:?}:\n{stdout}");
    }

    assert!(
        !std::path::Path::new(&canary).exists(),
        "a payload was interpreted rather than passed as data"
    );
}

/// A hostile parameter cannot escape the `sudo -n -u <user> --` boundary into sudo's own options.
///
/// Verified through the dry-run endpoint, which reports the exact vector that would be handed to
/// `execve` — so the assertion is about the real argument list, not a reimplementation of it, and
/// it needs no `sudoers` entry or elevated test runner to hold.
#[tokio::test]
async fn hostile_parameters_cannot_escape_the_sudo_argument_boundary() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("privileged.sh", "echo ok");
    let hook_id = insert_hook_as(&db, "sudo_hook", &script, 30, Some("root")).await;
    insert_parameter(&db, hook_id, "first", None, true).await;
    insert_parameter(&db, hook_id, "second", None, true).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // Each of these would change *who* the command runs as, or what sudo does, if it were parsed
    // as an option rather than as an argument to the script.
    let escapes = ["-u", "-u root", "--user=root", "-i", "--login", "-E", "--preserve-env", "--", "-s"];

    for payload in escapes {
        let res = send(
            &app,
            json_request(
                "POST",
                &format!("/api/hooks/{hook_id}/test"),
                &master,
                Some(json!({ "parameters": { "first": payload, "second": "-i" } })),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "for {payload:?}");

        let args: Vec<String> = res.json["command"]["args"]
            .as_array()
            .expect("the plan reports an argument vector")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_owned())
            .collect();

        assert_eq!(res.json["command"]["program"], json!("/usr/bin/sudo"), "for {payload:?}");
        assert_eq!(res.json["command"]["run_as_user"], json!("root"), "for {payload:?}");

        // The prefix is fixed and complete: nothing attacker-supplied can appear before `--`.
        assert_eq!(&args[..4], &["-n", "-u", "root", "--"], "sudo prefix intact for {payload:?}");
        assert_eq!(args[4], script, "the script path follows the separator for {payload:?}");

        // Both hostile values land strictly after the separator, where sudo treats them as
        // arguments to the script.
        let separator = args.iter().position(|a| a == "--").expect("separator present");
        for (index, value) in args.iter().enumerate().skip(5) {
            assert!(index > separator, "{value:?} must sit after the separator for {payload:?}");
        }
        assert_eq!(args[5], payload, "the payload is passed through verbatim for {payload:?}");
        assert_eq!(args[6], "-i", "the second payload is passed through verbatim for {payload:?}");
        assert_eq!(args.len(), 7, "no extra arguments were synthesized for {payload:?}");
    }
}

/// A `run_as_user` that is option-shaped is refused at definition time, so the vector above can
/// never be built with a hostile account name in the `-u` slot.
#[tokio::test]
async fn option_shaped_run_as_user_is_refused_at_definition_time() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("elevated.sh", "echo ok");
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    for hostile in ["-i", "--login", "-u", "root -i", "root;id", "--user=root", "-E"] {
        let res = send(
            &app,
            json_request(
                "POST",
                "/api/hooks",
                &master,
                Some(json!({
                    "name": format!("elevated_{}", Uuid::new_v4()),
                    "script_path": script,
                    "run_as_user": hostile
                })),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "run_as_user {hostile:?} must be refused");
    }
}

/// A backgrounded grandchild shares the child's process group, so the timeout's `killpg` reaches it.
#[tokio::test]
async fn timeout_kills_backgrounded_grandchildren_in_the_same_process_group() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let marker = scripts.path_for("group_child_survived");
    // Output is redirected so the grandchild does not hold the captured pipe open past the kill,
    // which would otherwise cost the reader-drain grace period on every run.
    // The grandchild sleeps 3s against a 1s timeout. The margin is load-bearing: with a sleep close
    // to the timeout the `touch` races the kill and can land first, which would read as a
    // containment failure when it is really a test-timing artifact.
    let script = scripts.write_script(
        "group_escape.sh",
        &format!("( sleep 3; touch {marker} ) >/dev/null 2>&1 &\nsleep 30"),
    );

    let hook_id = insert_hook(&db, "group_escape", &script, 1).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let res = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &master, Some(json!({}))),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.field("status"), &json!("TIMEOUT"));
    assert_eq!(res.field("exit_code"), &json!(137), "SIGKILL is recorded as 128+9");

    // Outlive the grandchild's own sleep: if it were still alive it would create the marker.
    tokio::time::sleep(Duration::from_millis(4500)).await;
    assert!(
        !std::path::Path::new(&marker).exists(),
        "a backgrounded grandchild in the same process group must not survive the timeout"
    );
}

/// Documents the exact boundary of `libc::killpg`: a child that calls `setsid` becomes the leader
/// of a *new* process group and is therefore out of reach.
///
/// This test asserts the escape happens. That is deliberate, and it is not an endorsement — it is
/// the honest shape of the guarantee. `killpg(pgid, SIGKILL)` signals one process group; a process
/// that has left that group is, by POSIX definition, no longer a member. Containing it would
/// require a kernel-level accounting boundary the daemon does not create (a cgroup, a PID
/// namespace, or a session-wide sweep), and pretending otherwise in a test would leave an operator
/// believing in an isolation property that does not exist. If a future change adds cgroup
/// confinement, this test failing is precisely the signal that the boundary moved.
/// `#[ignore]`d for the same reason as [`a_privileged_hook_actually_executes_through_sudo`]: it
/// depends on a host tool that is not POSIX, and a silent early `return` reported PASS on hosts
/// lacking it. The precondition is asserted, not guarded — see that test for the convention and
/// where it comes from.
#[tokio::test]
#[ignore = "requires setsid(1) from util-linux; run with `cargo test -- --ignored`"]
async fn a_setsid_child_leaves_the_process_group_and_survives_the_timeout_kill() {
    // `setsid(1)` is util-linux, not POSIX; without it there is nothing to measure.
    let has_setsid = std::process::Command::new("sh")
        .args(["-c", "command -v setsid >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        has_setsid,
        "setsid(1) is not available, so the process-escape boundary cannot be measured here. \
         Asserted rather than skipped, so this reports absence instead of success"
    );

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let escaped = scripts.path_for("setsid_child_survived");
    let contained = scripts.path_for("plain_child_survived");
    // Two grandchildren, identical but for the process group they end up in. Running both in one
    // execution is what makes the comparison airtight: same kill, same timing, same machine.
    // Both sleep well past the 1s timeout so neither can win a race against the kill and produce a
    // misleading result; output is redirected so neither holds the captured pipe open either.
    let script = scripts.write_script(
        "setsid_escape.sh",
        &format!(
            "( sleep 3; touch {contained} ) >/dev/null 2>&1 &\n\
             setsid sh -c 'sleep 3; touch {escaped}' >/dev/null 2>&1 &\n\
             sleep 30"
        ),
    );

    let hook_id = insert_hook(&db, "setsid_escape", &script, 1).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let res = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &master, Some(json!({}))),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.field("status"), &json!("TIMEOUT"));
    assert_eq!(res.field("exit_code"), &json!(137));

    // Both grandchildren sleep 3s; the hook is killed at 1s. Wait well past their wake-up.
    tokio::time::sleep(Duration::from_millis(4500)).await;

    assert!(
        !std::path::Path::new(&contained).exists(),
        "the same-group grandchild must be killed — if this fails, killpg itself regressed"
    );
    assert!(
        std::path::Path::new(&escaped).exists(),
        "a setsid child is expected to escape killpg; if it no longer does, the daemon gained a \
         stronger containment boundary and AGENT_NOTES.MD must be updated to match"
    );
}

/// Nothing a hook leaves behind may become a zombie held open by the daemon.
///
/// The timeout path reaps explicitly (`child.kill().await` then `child.wait().await`), so the
/// direct child is collected even when the group kill found nothing to do. A leaked zombie would
/// accumulate one PID per timed-out execution and eventually exhaust the process table.
#[tokio::test]
async fn timed_out_executions_do_not_leave_zombie_children() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("zombie.sh", "sleep 30");
    let hook_id = insert_hook(&db, "zombie_hook", &script, 1).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    for _ in 0..3 {
        let res = send(
            &app,
            json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &master, Some(json!({}))),
        )
        .await;
        assert_eq!(res.field("status"), &json!("TIMEOUT"));
    }

    // Count this process's own defunct children rather than the machine's: a shared CI host may
    // well have unrelated zombies, and blaming them on this daemon would make the test flaky.
    let pid = std::process::id();
    let zombies = std::process::Command::new("sh")
        .args(["-c", &format!("ps -o stat=,ppid= -A 2>/dev/null | awk '$1 ~ /^Z/ && $2 == {pid}'")])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();

    assert!(zombies.is_empty(), "timed-out hooks left zombie children behind:\n{zombies}");
}

/// A body past [`simply_hook_executor::MAX_REQUEST_BODY_BYTES`] is refused before a handler runs.
///
/// Covers both extractor shapes, because they reject through different code paths: the execute and
/// webhook routes take raw `Bytes`, while the admin routes take `Json<T>`. A limit that held for
/// only one of them would leave the other as an unbounded allocation.
#[tokio::test]
async fn oversized_request_bodies_are_rejected_before_a_handler_runs() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("small.sh", "echo ok");
    let hook_id = insert_hook(&db, "limit_hook", &script, 30).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // 10 MiB, an order of magnitude past the 1 MiB ceiling.
    let oversized = vec![b'a'; 10 * 1024 * 1024];

    for (method, uri) in [
        ("POST", format!("/api/hooks/{hook_id}/execute")),
        ("POST", "/webhook/limit_hook".to_owned()),
        ("POST", "/api/hooks".to_owned()),
        ("POST", "/api/keys".to_owned()),
        ("PUT", format!("/api/hooks/{hook_id}")),
    ] {
        let res = send(&app, raw_request(method, &uri, &master, oversized.clone())).await;
        assert_eq!(
            res.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{method} {uri} must refuse a 10 MiB body"
        );
    }

    // The refusal is the *limit*, not the content: the same route accepts a well-formed body.
    let accepted = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &master, Some(json!({}))),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK);
}

/// An unauthenticated caller cannot use a huge body to force work either: the key check runs first,
/// so the body is never buffered at all.
#[tokio::test]
async fn an_unauthenticated_oversized_body_is_refused_without_being_buffered() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let oversized = vec![b'a'; 10 * 1024 * 1024];

    // No `X-API-Key` at all: the middleware rejects before it ever reads the body.
    let anonymous = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/hooks")
            .header("Content-Type", "application/json"),
    )
    .body(axum::body::Body::from(oversized.clone()))
    .expect("request builds");
    let res = send(&app, anonymous).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    // An unknown key is the same story: still 401, still no buffering.
    let unknown = send(&app, raw_request("POST", "/api/hooks", "not-a-real-key", oversized)).await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
}

/// A body just under the ceiling is still accepted, so the limit is a ceiling rather than an
/// off-by-one that quietly breaks large-but-legitimate webhook payloads.
#[tokio::test]
async fn a_body_just_under_the_ceiling_is_accepted() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("under.sh", "echo ok");
    let hook_id = insert_hook(&db, "under_hook", &script, 30).await;
    insert_parameter(&db, hook_id, "blob", None, true).await;
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // A JSON document a few KiB below the limit. The parameter value itself is held to 64 KiB:
    // argv and the environment share ARG_MAX and each parameter is passed both ways, so a
    // megabyte-scale value would fail with E2BIG for reasons unrelated to the HTTP limit.
    let padding = "b".repeat(64 * 1024);
    let filler = "c".repeat(simply_hook_executor::MAX_REQUEST_BODY_BYTES - (96 * 1024));
    let body = json!({ "parameters": { "blob": padding }, "ignored_padding": filler });
    let encoded = serde_json::to_vec(&body).expect("payload serializes");
    assert!(
        encoded.len() < simply_hook_executor::MAX_REQUEST_BODY_BYTES,
        "the fixture must actually be under the limit, not merely intended to be"
    );

    let res = send(
        &app,
        raw_request("POST", &format!("/api/hooks/{hook_id}/execute"), &master, encoded),
    )
    .await;
    // A top-level `parameters` object wins, so the ~1 MiB of sibling padding is read and parsed but
    // contributes no parameters — which is exactly the proof wanted here: the request was consumed
    // end to end and executed, so the size limit did not intervene just below its own ceiling.
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.field("status"), &json!("SUCCESS"));
    // The declared parameter still made the trip intact alongside all that padding.
    assert_eq!(res.json["parameters"]["blob"], json!(padding));
}

// ─────────────────────────────────────────────────────────────
// Security regressions — the five confirmed privilege-escalation findings
//
// Each test is the exploit that previously *succeeded*, inverted into an assertion that it is now
// refused. They are written against the HTTP surface rather than the guard functions on purpose:
// a unit test of `guard_master_to_grant_scopes` would keep passing if a handler stopped calling
// it, which is precisely the regression worth catching.
// ─────────────────────────────────────────────────────────────

/// Seeds a non-master key holding the `can_manage_keys` scope — the credential every finding in
/// this group started from.
async fn seed_key_manager(db: &sea_orm::DatabaseConnection) -> (Uuid, String) {
    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    insert_key(db, "key-manager", "", scopes).await
}

/// Seeds a **daughter with a manage row**: `can_manage = true` on one hook, and *no* global scopes.
///
/// Under `RBAC_MODEL.md` R2 this key may **not** administer that hook's grants — manage is a
/// conjunction, and this is only half of it. The Tiers matrix is explicit that a Daughter key never
/// manages resources, so a manage row on its own is operational authority over the hook, not the
/// right to decide who else holds it.
///
/// Kept, and renamed from `seed_local_manager`, precisely because that population still exists and
/// still has to be *refused*. Use [`seed_parent_manager`] for a caller that should succeed.
async fn seed_daughter_with_manage_row(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    hook_id: Uuid,
    can_execute: bool,
) -> (Uuid, String) {
    let (id, plaintext) = insert_key(db, name, "", KeyScopes::plain()).await;
    grant(db, id, hook_id, can_execute, true).await;
    (id, plaintext)
}

/// Seeds a **parent manager**: `can_manage_keys` *and* a `can_manage` row on one specific hook —
/// both halves of R2, and therefore the only non-master shape that may administer that hook's
/// grants.
///
/// This is the population the R1 per-verb rule actually governs. Before R2 was enforced, a
/// `can_manage_keys` holder took a global-administrator early return and was bound by neither rule,
/// so a test that seeded one and then asserted a per-verb refusal was asserting nothing. Now the
/// flag is necessary but not sufficient, and this helper is what a passing delegation test needs.
async fn seed_parent_manager(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    hook_id: Uuid,
    can_execute: bool,
) -> (Uuid, String) {
    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    let (id, plaintext) = insert_key(db, name, "", scopes).await;
    grant(db, id, hook_id, can_execute, true).await;
    (id, plaintext)
}

/// Finding #1 — `can_manage_keys` could mint a key with `is_master: true` and become master.
///
/// `RBAC_MODEL.md` §5 widened the rule since: `is_master` is not a field on any payload, so the
/// refusal now comes from the deserializer rather than from an authorization guard, and it applies
/// to *every* caller rather than only to non-masters. That is the point — see
/// [`even_a_master_cannot_mint_a_second_master`].
#[tokio::test]
async fn regression_non_master_cannot_mint_a_master_key() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, manager) = seed_key_manager(&db).await;

    let res = send(
        &app,
        json_request("POST", "/api/keys", &manager, Some(json!({ "name": "escalated", "is_master": true }))),
    )
    .await;
    assert!(res.status.is_client_error(), "minting a master key must be refused");
    assert!(res.string("error").contains("is_master"), "the refusal names the offending scope");
    assert!(
        res.json.get("plaintext_key").is_none(),
        "a refused creation must not have minted a credential"
    );

    // The other two global scopes are self-amplifying in the same way and are gated identically.
    for scope in ["can_manage_keys", "can_manage_hooks"] {
        let res = send(
            &app,
            json_request("POST", "/api/keys", &manager, Some(json!({ "name": "escalated", scope: true }))),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "granting {scope} must be refused");
    }

    // Nothing was created by any of the refused attempts.
    let (_mid, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let keys = send(&app, json_request("GET", "/api/keys", &master, None)).await;
    let names: Vec<&str> = keys.json.as_array().map(|rows| {
        rows.iter().filter_map(|k| k.get("name").and_then(|n| n.as_str())).collect()
    }).unwrap_or_default();
    assert!(!names.contains(&"escalated"), "a refused creation must not persist a row: {names:?}");

    // An ordinary, scope-free key is still creatable — the gate is about escalation, not about
    // disabling the scope the caller legitimately holds.
    let ok = send(
        &app,
        json_request("POST", "/api/keys", &manager, Some(json!({ "name": "ordinary" }))),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.field("name"), &json!("ordinary"));
}

/// Finding #1b — the update route must not become the back door the create route just closed.
#[tokio::test]
async fn regression_non_master_cannot_grant_global_scopes_by_update() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (manager_id, manager) = seed_key_manager(&db).await;
    let (victim_id, _victim) = insert_key(&db, "ordinary", "", KeyScopes::plain()).await;
    // The manager's own daughter, so the refusals below are about R4 rather than about §4 hiding
    // an unrelated key behind a `404`.
    set_parent(&db, victim_id, manager_id).await;

    for scope in ["can_manage_keys", "can_manage_hooks"] {
        let res = send(
            &app,
            json_request("PUT", &format!("/api/keys/{victim_id}"), &manager, Some(json!({ scope: true }))),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "granting {scope} by update must be refused");
    }

    // Revoking a scope is not an escalation and stays available to a key manager.
    let revoke = send(
        &app,
        json_request("PUT", &format!("/api/keys/{victim_id}"), &manager, Some(json!({ "can_manage_hooks": false }))),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::OK, "removing authority is not an escalation");
}

/// Finding #2 — `can_manage_keys` could rotate a master key and read its new plaintext secret.
#[tokio::test]
async fn regression_non_master_cannot_rotate_update_or_delete_a_master_key() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master) = insert_key(&db, "system-master", "", KeyScopes::master()).await;
    let (_id, manager) = seed_key_manager(&db).await;

    // `404` rather than `403` since §4 landed: the master is not in this manager's subtree and does
    // not share a hook with it, so it is outside every visibility scope and must look like an id
    // that was never issued. The refusal is no weaker — it is strictly less informative.
    let rotate = send(&app, json_request("POST", &format!("/api/keys/{master_id}/rotate"), &manager, None)).await;
    assert_eq!(rotate.status, StatusCode::NOT_FOUND, "rotating a master key must be refused");
    assert!(rotate.json.get("plaintext_key").is_none(), "no secret may leak in the refusal body");

    let update = send(
        &app,
        json_request("PUT", &format!("/api/keys/{master_id}"), &manager, Some(json!({ "bound_ips": "0.0.0.0/0" }))),
    )
    .await;
    assert_eq!(update.status, StatusCode::NOT_FOUND, "editing a master key must be refused");

    let delete = send(&app, json_request("DELETE", &format!("/api/keys/{master_id}"), &manager, None)).await;
    assert_eq!(delete.status, StatusCode::NOT_FOUND, "deleting a master key must be refused");

    // The `404`s above are §4 talking, not §5. To prove the master-specific guard still stands on
    // its own, ask again as a caller the master *is* visible to — the master itself, whose refusals
    // are `403` and name the reason.
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/keys/{master_id}/rotate"), &master, None)).await.status,
        StatusCode::FORBIDDEN,
        "§5 still refuses rotation for a caller that can see the master"
    );

    // The master credential still works, so none of the refused calls partially applied.
    let me = send(&app, json_request("GET", "/api/auth/me", &master, None)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.field("is_master"), &json!(true));

    // `RBAC_MODEL.md` §5 closes the last door: rotation of a master key is refused for *every*
    // caller, the master itself included. Previously the gate read "master only", which — now that
    // exactly one master row can exist — meant "the master may rotate itself", and rotation hands
    // back the new plaintext secret in its response. A stolen master credential could therefore
    // mint itself a fresh one and lock the operator out with a single request.
    let by_master = send(&app, json_request("POST", &format!("/api/keys/{master_id}/rotate"), &master, None)).await;
    assert_eq!(by_master.status, StatusCode::FORBIDDEN, "even the master may not rotate itself");
    assert!(by_master.json.get("plaintext_key").is_none(), "no secret may leak in the refusal body");

    let self_delete =
        send(&app, json_request("DELETE", &format!("/api/keys/{master_id}"), &master, None)).await;
    assert_eq!(self_delete.status, StatusCode::FORBIDDEN, "even the master may not delete itself");
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §5 — Master key guarantees
// ─────────────────────────────────────────────────────────────

/// §5: the master cannot mint a second master — and this is the *master's* refusal, not a
/// non-master's.
///
/// The pre-existing guard was `guard_master_to_grant_scopes`, which returns early for master
/// callers. It stopped a `can_manage_keys` holder from escalating, but a master holding a stolen
/// credential could mint a peer master and thereby survive the revocation of the original. §5
/// makes "exactly one" mean exactly one, for everyone.
#[tokio::test]
async fn even_a_master_cannot_mint_a_second_master() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let res = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "peer", "is_master": true }))),
    )
    .await;
    assert!(res.status.is_client_error(), "a master minting a second master must be refused");
    assert!(res.string("error").contains("is_master"), "the refusal names the offending field");

    // Exactly one master row survives, and it is the original.
    let masters = ApiKey::find()
        .filter(api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .expect("querying keys succeeds");
    assert_eq!(masters.len(), 1, "the table still holds exactly one master");
}

/// §5: an update payload carrying `is_master` is refused rather than silently ignored.
///
/// Serde's default is to drop unknown fields, which would have returned `200` and an ordinary key,
/// leaving the caller believing the promotion had taken and the audit log recording a successful
/// update. `deny_unknown_fields` is what makes the refusal audible.
#[tokio::test]
async fn an_update_payload_carrying_is_master_is_refused_rather_than_ignored() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let (victim_id, _victim) = insert_key(&db, "victim", "", KeyScopes::plain()).await;

    let res = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/keys/{victim_id}"),
            &master,
            Some(json!({ "is_master": true })),
        ),
    )
    .await;
    assert!(res.status.is_client_error(), "promotion through update must be refused");
    assert!(res.string("error").contains("is_master"), "the refusal names the offending field");

    let victim = ApiKey::find_by_id(victim_id)
        .one(&db)
        .await
        .expect("querying the key succeeds")
        .expect("the key still exists");
    assert!(!victim.is_master, "the target key was not promoted");
}

/// §5: the *database* refuses a second master, independently of every handler.
///
/// This is the control that has to hold when application logic is wrong, bypassed, or not involved
/// at all — a migration, a restored backup, an operator at a SQL prompt. It writes the row
/// directly through SeaORM, taking the same path `tests/common` uses to seed fixtures, so nothing
/// in `src/api.rs` participates in the refusal.
#[tokio::test]
async fn the_database_rejects_a_second_master_row_with_no_handler_involved() {
    let db = setup_test_db().await;
    let (_id, _master) = insert_key(&db, "the-master", "", KeyScopes::master()).await;

    let plaintext = simply_hook_executor::api::generate_random_key();
    let now = chrono::Utc::now().naive_utc();
    let second = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_hook_executor::api::hash_key(&plaintext)),
        name: Set("smuggled-master".to_owned()),
        prefix: Set(plaintext.chars().take(8).collect()),
        key_id: Set(Some(simply_hook_executor::api::generate_key_id())),
        signing_secret: Set(None),
        hmac_mode: Set(simply_hook_executor::entities::api_key::HmacMode::CanonicalV1),
        bound_ips: Set(Some(String::new())),
        max_concurrent_jobs: Set(10),
        is_master: Set(true),
        parent_key_id: Set(None),
        can_manage_keys: Set(true),
        can_manage_hooks: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await;

    assert!(second.is_err(), "the unique index must refuse a second master row");

    // ...while ordinary keys are entirely unaffected: the constraint is on the *marker*, which is
    // NULL for every non-master, and NULLs do not collide. A constraint that also capped the
    // number of ordinary keys at one would pass the assertion above and be catastrophic.
    for name in ["ordinary-a", "ordinary-b", "ordinary-c"] {
        insert_key(&db, name, "", KeyScopes::plain()).await;
    }
    let total = ApiKey::find().all(&db).await.expect("querying keys succeeds").len();
    assert_eq!(total, 4, "one master plus three ordinary keys coexist");
}

/// §5: the master may edit its own `bound_ips`, and nothing else.
#[tokio::test]
async fn the_master_may_edit_only_its_own_bound_ips() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // The one permitted edit. `127.0.0.0/8` still contains the test client, so the credential
    // stays usable and the assertions below are about authorization, not about lockout.
    let allowed = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/keys/{master_id}"),
            &master,
            Some(json!({ "bound_ips": "127.0.0.0/8,::1/128" })),
        ),
    )
    .await;
    assert_eq!(allowed.status, StatusCode::OK, "the master may narrow its own bound_ips");
    assert_eq!(allowed.string("bound_ips"), "127.0.0.0/8,::1/128");

    // Everything else on the same payload shape is refused, one field at a time so a passing
    // assertion cannot be an artifact of some *other* field in the same body being caught first.
    for (field, value) in [
        ("name", json!("renamed-master")),
        ("max_concurrent_jobs", json!(999)),
        ("hmac_mode", json!("BODY_ONLY")),
        ("can_manage_keys", json!(false)),
        ("can_manage_hooks", json!(false)),
    ] {
        let res = send(
            &app,
            json_request(
                "PUT",
                &format!("/api/keys/{master_id}"),
                &master,
                Some(json!({ field: value })),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "the master's '{field}' must be immutable");
        assert!(res.string("error").contains(field), "the refusal names '{field}'");
    }

    // None of the refusals partially applied.
    let reloaded = ApiKey::find_by_id(master_id)
        .one(&db)
        .await
        .expect("querying the key succeeds")
        .expect("the master still exists");
    assert_eq!(reloaded.name, "master");
    assert_eq!(reloaded.max_concurrent_jobs, 10);
    assert!(reloaded.can_manage_keys && reloaded.can_manage_hooks);
    assert_eq!(reloaded.bound_ips.as_deref(), Some("127.0.0.0/8,::1/128"));
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §6 — cascade deletion and pre-flight inventory
// ─────────────────────────────────────────────────────────────

/// Builds a three-level subtree under `master`: parent → daughter → granddaughter, with a hook
/// owned two levels down. Returns `(parent_id, parent_key, daughter_id, grand_id, deep_hook)`.
///
/// Two levels is the minimum that distinguishes a real subtree walk from "what does this key own".
/// A one-level test passes against a walk that never recurses.
async fn seed_three_level_subtree(
    db: &sea_orm::DatabaseConnection,
    script: &str,
) -> (Uuid, String, Uuid, Uuid, Uuid) {
    let (parent_id, parent) = insert_key(db, "parent", "", KeyScopes {
        can_manage_keys: true,
        max_concurrent_jobs: 10,
        ..Default::default()
    })
    .await;
    let (daughter_id, _daughter) = insert_key(db, "daughter", "", KeyScopes::plain()).await;
    let (grand_id, _grand) = insert_key(db, "granddaughter", "", KeyScopes::plain()).await;
    set_parent(db, daughter_id, parent_id).await;
    set_parent(db, grand_id, daughter_id).await;

    let deep_hook = insert_hook_owned_by(db, "granddaughters_hook", script, grand_id).await;
    (parent_id, parent, daughter_id, grand_id, deep_hook)
}

/// **§6** — the inventory walks the *entire* subtree, not just the key named in the request.
///
/// "Before any key deletion, the service walks the entire subtree being deleted and collects every
/// resource and dispatch target owned by any key within it." A hook owned two levels down must
/// appear, or it is stranded silently — which is the failure a naive "what does *this* key own"
/// query produces and this test exists to catch.
#[tokio::test]
async fn s6_the_inventory_reaches_resources_owned_two_levels_down() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("deep.sh", "#!/bin/sh\nexit 0\n");
    let (parent_id, _parent, daughter_id, grand_id, deep_hook) =
        seed_three_level_subtree(&db, &script).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let refused = send(&app, json_request("DELETE", &format!("/api/keys/{parent_id}"), &master, None)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "deletion is refused, not performed");

    // The inventory names the deep hook, with everything §6 requires.
    let inventory = refused.json["inventory"].as_array().cloned().unwrap_or_default();
    assert_eq!(inventory.len(), 1, "exactly the one owned hook: {}", refused.raw);
    assert_eq!(inventory[0]["type"], json!("hook"));
    assert_eq!(inventory[0]["id"], json!(deep_hook.to_string()));
    assert_eq!(inventory[0]["name"], json!("granddaughters_hook"));
    assert_eq!(
        inventory[0]["current_owner"],
        json!(grand_id.to_string()),
        "and names the owner two levels down, not the key that was asked about"
    );

    // The blast radius is reported too, so the caller sees what it actually asked for.
    let subtree: Vec<String> = refused.json["subtree"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|k| k["id"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(subtree.len(), 3, "parent, daughter, granddaughter");
    for id in [parent_id, daughter_id, grand_id] {
        assert!(subtree.contains(&id.to_string()), "{id} missing from the reported subtree");
    }

    // Nothing happened: the refusal is a question, not a partial execution.
    assert!(ApiKey::find_by_id(parent_id).one(&db).await.expect("query").is_some());
    assert!(ApiKey::find_by_id(grand_id).one(&db).await.expect("query").is_some());
}

/// **§6** — "Deletion executes only when every entity in the inventory carries an explicit
/// resolution; partial maps are refused."
///
/// A partial map is almost always a stale one: the caller resolved the inventory it was shown and
/// something arrived in between. Applying it would delete the keys and orphan the late arrival,
/// which is exactly what the mechanism exists to prevent.
#[tokio::test]
async fn s6_a_partial_resolution_map_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("partial.sh", "#!/bin/sh\nexit 0\n");
    let (parent_id, _parent, daughter_id, _grand_id, deep_hook) =
        seed_three_level_subtree(&db, &script).await;
    let second_hook = insert_hook_owned_by(&db, "daughters_hook", &script, daughter_id).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // Resolve one of the two.
    let partial = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": { deep_hook.to_string(): { "action": "delete" } } })),
        ),
    )
    .await;
    assert_eq!(partial.status, StatusCode::CONFLICT, "a partial map is refused: {}", partial.raw);
    assert!(ApiKey::find_by_id(parent_id).one(&db).await.expect("query").is_some(), "nothing deleted");

    // The still-unresolved entity is the one reported back, so the caller can complete the map
    // rather than re-derive it.
    let inventory = partial.json["inventory"].as_array().cloned().unwrap_or_default();
    assert_eq!(inventory.len(), 2, "the full inventory comes back, not just the gap");

    // A resolution naming something the subtree does not own is a mistake, not a no-op: it usually
    // means the map was built against a different subtree.
    let stray = insert_hook(&db, "unrelated_hook", &script, 30).await;
    let bad = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": {
                deep_hook.to_string(): { "action": "delete" },
                second_hook.to_string(): { "action": "delete" },
                stray.to_string(): { "action": "delete" },
            } })),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "a stray resolution is refused: {}", bad.raw);
    assert!(bad.raw.contains(&stray.to_string()), "and names the offending id");

    // The complete map succeeds.
    let complete = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": {
                deep_hook.to_string(): { "action": "delete" },
                second_hook.to_string(): { "action": "delete" },
            } })),
        ),
    )
    .await;
    assert_eq!(complete.status, StatusCode::NO_CONTENT, "a total map executes: {}", complete.raw);
}

/// **§6** — the cascade removes the whole subtree, and reassignment moves ownership rather than
/// destroying anything.
#[tokio::test]
async fn s6_reassignment_moves_ownership_and_the_cascade_removes_the_subtree() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("reassign.sh", "#!/bin/sh\nexit 0\n");
    let (parent_id, _parent, daughter_id, grand_id, deep_hook) =
        seed_three_level_subtree(&db, &script).await;
    let (successor_id, _successor) = insert_key(&db, "successor", "", KeyScopes::plain()).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // Reassigning *into* the doomed subtree is refused: the new owner is about to cease to exist,
    // so it resolves nothing.
    let into_subtree = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": {
                deep_hook.to_string(): { "action": "reassign", "to": daughter_id.to_string() },
            } })),
        ),
    )
    .await;
    assert_eq!(into_subtree.status, StatusCode::BAD_REQUEST, "{}", into_subtree.raw);
    assert!(into_subtree.raw.contains("inside the subtree"), "{}", into_subtree.raw);

    // A nonexistent successor is refused too — it would leave the hook owned by nothing.
    let nowhere = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": {
                deep_hook.to_string(): { "action": "reassign", "to": Uuid::new_v4().to_string() },
            } })),
        ),
    )
    .await;
    assert_eq!(nowhere.status, StatusCode::BAD_REQUEST, "{}", nowhere.raw);

    // The real thing.
    let done = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": {
                deep_hook.to_string(): { "action": "reassign", "to": successor_id.to_string() },
            } })),
        ),
    )
    .await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{}", done.raw);

    // The entire subtree is gone — recursively, not just the key that was named.
    for id in [parent_id, daughter_id, grand_id] {
        assert!(
            ApiKey::find_by_id(id).one(&db).await.expect("query").is_none(),
            "{id} should have been cascaded away"
        );
    }
    assert!(ApiKey::find_by_id(successor_id).one(&db).await.expect("query").is_some());

    // The hook survives, owned by the successor. §6: "Hooks must never disappear as a side effect
    // of removing a key."
    let survivor = fetch_hook_row(&db, deep_hook).await.expect("the hook must survive");
    assert!(!survivor.is_deleted, "reassignment is not deletion");
    assert_eq!(survivor.owner_key_id, Some(successor_id), "ownership moved to the successor");
}

/// **§6** — "Data is never destroyed implicitly."
///
/// Even when the caller *asks* for deletion, the hook goes to the trash rather than being dropped:
/// its parameters, permission grants, and execution history survive, and the 92-day purge stays the
/// only thing that destroys them. Explicit does not have to mean irreversible.
#[tokio::test]
async fn s6_resolving_by_delete_trashes_the_hook_without_destroying_its_history() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("history.sh", "#!/bin/sh\necho ran\n");

    let (owner_id, owner) = insert_key(&db, "owner", "", KeyScopes::plain()).await;
    let (parent_id, _parent) = insert_key(&db, "parent", "", KeyScopes {
        can_manage_keys: true,
        max_concurrent_jobs: 10,
        ..Default::default()
    })
    .await;
    set_parent(&db, owner_id, parent_id).await;
    let hook = insert_hook_owned_by(&db, "historic_hook", &script, owner_id).await;
    insert_parameter(&db, hook, "p1", Some("v"), false).await;
    grant(&db, owner_id, hook, true, true).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // Give it a run worth preserving.
    let run = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &owner, Some(json!({}))),
    )
    .await;
    assert_eq!(run.status, StatusCode::OK);

    let done = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{parent_id}"),
            &master,
            Some(json!({ "resolutions": { hook.to_string(): { "action": "delete" } } })),
        ),
    )
    .await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{}", done.raw);

    // The hook row survives, flagged.
    let row = fetch_hook_row(&db, hook).await.expect("the row must survive a resolved delete");
    assert!(row.is_deleted, "it went to the trash");

    // ...and so did the history, even though the key that made it is gone.
    let history = Execution::find().all(&db).await.expect("querying executions succeeds");
    assert_eq!(history.len(), 1, "the run survives its author");
    assert_eq!(history[0].api_key_id, None, "attribution is nulled, not cascaded away");

    // Master can still see and restore it — nothing was silently destroyed.
    let trashed = send(&app, json_request("GET", &format!("/api/hooks/{hook}?include_deleted=true"), &master, None)).await;
    assert_eq!(trashed.status, StatusCode::OK, "master can still reach it: {}", trashed.raw);
}

/// **§6** — a subtree owning nothing still deletes in one request.
///
/// The inventory is a gate, not a toll: introducing a mandatory second round-trip for the ordinary
/// case would be a regression dressed as a safety feature.
#[tokio::test]
async fn s6_a_subtree_owning_nothing_deletes_in_a_single_request() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let (parent_id, _parent) = insert_key(&db, "parent", "", KeyScopes {
        can_manage_keys: true,
        max_concurrent_jobs: 10,
        ..Default::default()
    })
    .await;
    let (daughter_id, _daughter) = insert_key(&db, "daughter", "", KeyScopes::plain()).await;
    set_parent(&db, daughter_id, parent_id).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let done = send(&app, json_request("DELETE", &format!("/api/keys/{parent_id}"), &master, None)).await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "no body required: {}", done.raw);
    assert!(ApiKey::find_by_id(parent_id).one(&db).await.expect("query").is_none());
    assert!(
        ApiKey::find_by_id(daughter_id).one(&db).await.expect("query").is_none(),
        "the cascade still ran"
    );
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §4 — visibility scopes and oracle discipline
// ─────────────────────────────────────────────────────────────

/// **§4** — "A single shared resource must never become a keyhole into another parent's whole
/// configuration."
///
/// `GET /api/keys` previously returned a full summary — global flags, `bound_ips`, every hook
/// membership — for *every key in the deployment* to any `can_manage_keys` holder. One shared hook
/// was enough to read a competitor tenant's entire configuration; so was holding the scope and
/// sharing nothing at all.
#[tokio::test]
async fn s4_a_shared_resource_discloses_only_id_name_and_rights_on_that_resource() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("shared.sh", "#!/bin/sh\nexit 0\n");

    let shared = insert_hook(&db, "shared_hook", &script, 30).await;
    let private = insert_hook(&db, "their_private_hook", &script, 30).await;

    // Two unrelated parents, meeting only through `shared`.
    let (ours_id, ours) = seed_parent_manager(&db, "our-parent", shared, true).await;
    let (theirs_id, _theirs) = insert_key(&db, "their-parent", "10.9.8.0/24", KeyScopes {
        can_manage_keys: true,
        can_manage_hooks: true,
        max_concurrent_jobs: 7,
        ..Default::default()
    })
    .await;
    grant(&db, theirs_id, shared, true, false).await;
    grant(&db, theirs_id, private, true, true).await;

    // ...and our own daughter, which we are entitled to see in full.
    let (daughter_id, _daughter) = insert_key(&db, "our-daughter", "127.0.0.1/32", KeyScopes::plain()).await;
    set_parent(&db, daughter_id, ours_id).await;
    grant(&db, daughter_id, shared, true, false).await;

    let listing = send(&app, json_request("GET", "/api/keys", &ours, None)).await;
    assert_eq!(listing.status, StatusCode::OK);
    let entries = listing.json.as_array().cloned().unwrap_or_default();

    let find = |id: Uuid| {
        entries
            .iter()
            .find(|e| e["id"].as_str() == Some(&id.to_string()))
            .cloned()
    };

    // Ourselves and our daughter: full detail.
    let self_view = find(ours_id).expect("the caller sees itself");
    assert_eq!(self_view["bound_ips"], json!(""), "own entry is the full summary");
    let daughter_view = find(daughter_id).expect("the caller sees its own daughter");
    assert_eq!(daughter_view["bound_ips"], json!("127.0.0.1/32"), "own subtree is full detail");
    assert_eq!(daughter_view["can_manage_keys"], json!(false), "including global flags");

    // The other parent: minimal, and *only* because of the shared hook.
    let their_view = find(theirs_id).expect("a key sharing a managed hook is visible in minimal form");
    assert_eq!(their_view["partial"], json!(true), "the entry announces that it is abridged");
    assert!(their_view.get("bound_ips").is_none(), "bound IPs stay hidden: {their_view}");
    assert!(their_view.get("can_manage_keys").is_none(), "global flags stay hidden: {their_view}");
    assert!(their_view.get("can_manage_hooks").is_none(), "...all of them: {their_view}");
    assert!(their_view.get("prefix").is_none(), "and so does the key prefix: {their_view}");
    assert!(their_view.get("max_concurrent_jobs").is_none(), "and the budget: {their_view}");

    // The rights shown are on the shared hook alone — never the unrelated one.
    let names: Vec<String> = their_view["hook_permissions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p["hook_name"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(names, vec!["shared_hook".to_owned()], "unrelated memberships stay hidden");
}

/// **§4** — a key outside every scope is not listed at all. Omission is the listing form of oracle
/// discipline: absent and invisible look the same.
#[tokio::test]
async fn s4_keys_outside_every_scope_are_omitted_from_the_listing() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("scope.sh", "#!/bin/sh\nexit 0\n");

    let mine = insert_hook(&db, "my_hook", &script, 30).await;
    let (ours_id, ours) = seed_parent_manager(&db, "our-parent", mine, true).await;
    let (stranger_id, _stranger) = insert_key(&db, "unrelated", "", KeyScopes::plain()).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let listing = send(&app, json_request("GET", "/api/keys", &ours, None)).await;
    let ids: Vec<String> = listing
        .json
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e["id"].as_str().map(str::to_owned))
        .collect();
    assert!(ids.contains(&ours_id.to_string()), "the caller sees itself");
    assert!(!ids.contains(&stranger_id.to_string()), "an unrelated key is not listed at all");

    // ...and is unreachable by id, with the answer a nonexistent id gives.
    let by_id = send(
        &app,
        json_request("PUT", &format!("/api/keys/{stranger_id}"), &ours, Some(json!({ "name": "x" }))),
    )
    .await;
    let invented = send(
        &app,
        json_request("PUT", &format!("/api/keys/{}", Uuid::new_v4()), &ours, Some(json!({ "name": "x" }))),
    )
    .await;
    assert_eq!(by_id.status, StatusCode::NOT_FOUND, "an invisible key reads as nonexistent");
    assert_eq!(by_id.status, invented.status, "identical status to an id that was never issued");
    assert_eq!(by_id.raw, invented.raw, "and an identical body");

    // Master sees everything, which is what makes the omission a scope rather than a bug.
    let all = send(&app, json_request("GET", "/api/keys", &master, None)).await;
    assert_eq!(all.json.as_array().map(Vec::len), Some(3), "our parent, the stranger, and master");
}

/// **§4 oracle discipline** — an out-of-scope hook is byte-identical to a nonexistent one.
///
/// This is the control for *authenticated* callers distinguishing absent from invisible. Its
/// counterpart, [`s4_unauthenticated_callers_cannot_probe_bound_ips_via_401_vs_403`], covers
/// *unauthenticated* callers probing key bindings. Both must hold; neither may be satisfied by
/// regressing the other.
#[tokio::test]
async fn s4_an_invisible_hook_is_indistinguishable_from_a_nonexistent_one() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("oracle.sh", "#!/bin/sh\nexit 0\n");

    let real = insert_hook(&db, "a_real_hook", &script, 30).await;
    let invented = Uuid::new_v4();
    let (_id, outsider) = insert_key(&db, "outsider", "", KeyScopes::plain()).await;

    for (method, suffix, body) in [
        ("GET", "", None),
        ("POST", "/execute", Some(json!({}))),
        ("POST", "/test", None),
        ("PUT", "", Some(json!({ "description": "x" }))),
        ("DELETE", "", None),
        ("GET", "/parameters", None),
    ] {
        let on_real = send(
            &app,
            json_request(method, &format!("/api/hooks/{real}{suffix}"), &outsider, body.clone()),
        )
        .await;
        let on_invented = send(
            &app,
            json_request(method, &format!("/api/hooks/{invented}{suffix}"), &outsider, body),
        )
        .await;

        assert_eq!(
            on_real.status,
            StatusCode::NOT_FOUND,
            "{method} /api/hooks/{{id}}{suffix} on an invisible hook must read as nonexistent"
        );
        assert_eq!(
            on_real.status, on_invented.status,
            "{method}{suffix}: status differs between invisible and nonexistent"
        );
        assert_eq!(
            on_real.raw, on_invented.raw,
            "{method}{suffix}: body differs between invisible and nonexistent"
        );
    }

    // Resolution by *name* must not leak either — names are guessable in a way UUIDs are not.
    let by_name = send(&app, json_request("GET", "/api/hooks/a_real_hook", &outsider, None)).await;
    let by_absent_name = send(&app, json_request("GET", "/api/hooks/no_such_hook", &outsider, None)).await;
    assert_eq!(by_name.status, by_absent_name.status, "name lookup leaks existence by status");
    assert_eq!(by_name.raw, by_absent_name.raw, "name lookup leaks existence by body");
}

/// **§4, third scope** — an execution record is creator-private, with three named exceptions.
///
/// The Terminology table makes the Execution record this service's creator-private entity, so it is
/// "never exposed by the shared-resource visibility rule": holding a verb on a hook does not, by
/// itself, let you read the arguments other keys passed to it or the output they got back.
///
/// Four identities may read one, and this walks all of them plus the party that may not:
///
/// | Caller | May read | Why |
/// | :--- | :--- | :--- |
/// | Master | yes | Full visibility |
/// | The acting key | yes | It is the "creator" §4 names |
/// | The hook's owner | yes | §3 makes it answerable for what the hook does |
/// | `can_view_execution` holder | yes | The explicit audit grant |
/// | `can_manage` holder | yes | Already entitled to rewrite and delete the history |
/// | `can_execute`-only holder | **no** | Running a hook is not reading everyone else's runs |
///
/// The last row is the one that matters. It is the population a naive "anyone on the hook" rule
/// would expose, and the reason history needed a verb of its own rather than riding on `can_execute`.
#[tokio::test]
async fn s4_execution_records_are_creator_private_with_three_named_exceptions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("private.sh", "#!/bin/sh\necho secret-output\n");

    let (owner_id, owner) = insert_key(&db, "owner", "", KeyScopes::plain()).await;
    let hook = insert_hook_owned_by(&db, "shared_runner", &script, owner_id).await;

    let (runner_id, runner) = insert_key(&db, "runner", "", KeyScopes::plain()).await;
    let (peer_id, peer) = insert_key(&db, "peer-executor", "", KeyScopes::plain()).await;
    let (auditor_id, auditor) = insert_key(&db, "auditor", "", KeyScopes::plain()).await;
    let (manager_id, manager) = insert_key(&db, "manager", "", KeyScopes::parent()).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    grant(&db, runner_id, hook, true, false).await;
    // The critical negative: another key that may *run* the hook, and nothing more.
    grant(&db, peer_id, hook, true, false).await;
    // The auditor holds history access alone — no execute, no manage. That combination was not
    // expressible before `can_view_execution` existed.
    grant_full(&db, auditor_id, hook, false, false, true).await;
    grant(&db, manager_id, hook, false, true).await;

    let run = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &runner, Some(json!({}))),
    )
    .await;
    assert_eq!(run.status, StatusCode::OK);
    let execution_id = run.string("id");
    let uri = format!("/api/executions/{execution_id}");

    for (who, label) in [
        (&runner, "the acting key sees its own run"),
        (&owner, "the hook's owner sees runs of the hook it is answerable for"),
        (&auditor, "a can_view_execution holder sees the history it was granted"),
        (&manager, "a can_manage holder may read what it may already delete"),
        (&master, "master sees everything"),
    ] {
        let listed = send(&app, json_request("GET", "/api/executions", who, None)).await;
        assert_eq!(listed.json.as_array().map(Vec::len), Some(1), "{label}: {}", listed.raw);
        let single = send(&app, json_request("GET", &uri, who, None)).await;
        assert_eq!(single.status, StatusCode::OK, "{label} (by id): {}", single.raw);
    }

    // `can_execute` alone reads nothing, and the refusal is `404` — indistinguishable from an
    // execution id that was never issued, per oracle discipline.
    let listed = send(&app, json_request("GET", "/api/executions", &peer, None)).await;
    assert_eq!(
        listed.json.as_array().map(Vec::len),
        Some(0),
        "running a hook is not licence to read another key's runs: {}",
        listed.raw
    );
    let by_id = send(&app, json_request("GET", &uri, &peer, None)).await;
    assert_eq!(by_id.status, StatusCode::NOT_FOUND, "refused as nonexistent, not as forbidden");
    assert!(!by_id.raw.contains("secret-output"), "no output leaks in the refusal: {}", by_id.raw);
    let invented = send(
        &app,
        json_request("GET", &format!("/api/executions/{}", Uuid::new_v4()), &peer, None),
    )
    .await;
    assert_eq!(by_id.status, invented.status, "an unreadable record leaks existence by status");
    assert_eq!(by_id.raw, invented.raw, "an unreadable record leaks existence by body");

    // Reading is not deleting. The auditor may see the record and may not destroy it — history
    // access is deliberately weaker than `can_manage`, or an auditor would be a redactor.
    assert_eq!(
        send(&app, json_request("DELETE", &uri, &auditor, None)).await.status,
        StatusCode::FORBIDDEN,
        "can_view_execution must not confer deletion"
    );
}

/// **§4, the counterpart control** — authenticate before authorize, so an *unauthenticated* caller
/// cannot probe `bound_ips` by reading `401` against `403`.
///
/// Named to say which control it covers, because the two are easy to confuse and each can be
/// "fixed" by breaking the other. This one governs callers with no valid credential; the oracle
/// discipline in [`s4_an_invisible_hook_is_indistinguishable_from_a_nonexistent_one`] governs
/// callers who have one. Making every refusal a `404` would break this test; making every refusal a
/// `403` would break that one.
#[tokio::test]
async fn s4_unauthenticated_callers_cannot_probe_bound_ips_via_401_vs_403() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    // A real key, bound to a range the test client is not in.
    let (_id, bound) = insert_key(&db, "bound-elsewhere", "10.10.10.0/24", KeyScopes::plain()).await;

    // No credential at all, and a credential that was never issued: both `401`, and identical.
    let absent = send(&app, json_request("GET", "/api/hooks", "", None)).await;
    let invented = send(&app, json_request("GET", "/api/hooks", "not-a-real-key", None)).await;
    assert_eq!(absent.status, StatusCode::UNAUTHORIZED, "no credential is 401");
    assert_eq!(invented.status, StatusCode::UNAUTHORIZED, "an unknown credential is 401");

    // A *real* credential from the wrong network is `403`, not `401`. That difference is only
    // reachable by someone already holding the secret, which is the point: the caller learns
    // nothing it did not supply.
    let wrong_network = send(&app, json_request("GET", "/api/hooks", &bound, None)).await;
    assert_eq!(
        wrong_network.status,
        StatusCode::FORBIDDEN,
        "a valid key from outside its bound_ips is 403: {}",
        wrong_network.raw
    );

    // The ordering is the control: an unknown key from any address is 401, never 403, so `403`
    // cannot be used to confirm that a guessed key string exists.
    assert_ne!(
        invented.status, wrong_network.status,
        "authenticate-then-authorize: an unknown key must not answer like a bound one"
    );
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §3 — ownership and lifecycle authority; R3 — lineage
// ─────────────────────────────────────────────────────────────

/// **§3** — "a parent that merely uses a resource must not be able to delete it."
///
/// The separation this creates did not exist before: `can_manage` was the whole requirement for
/// deletion, so any key an operator gave editing rights to could also make the hook — and, via the
/// 92-day purge, its entire execution history — cease to exist.
#[tokio::test]
async fn s3_managing_a_hook_does_not_confer_authority_to_delete_it() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("owned.sh", "#!/bin/sh\necho ok\n");

    // Both are Parents: this test is about §3 ownership, so both callers must clear R2 first or the
    // refusals below would prove only that the conjunction works — which is a different test.
    let (owner_id, owner) = insert_key(&db, "owner", "", KeyScopes::parent()).await;
    let (manager_id, manager) = insert_key(&db, "manager", "", KeyScopes::parent()).await;
    let hook = insert_hook_owned_by(&db, "owned_hook", &script, owner_id).await;
    grant(&db, owner_id, hook, true, true).await;
    grant(&db, manager_id, hook, true, true).await;

    // The manager holds *both* verbs — this is not a case of insufficient operational rights.
    let edit = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook}"), &manager, Some(json!({ "description": "edited" }))),
    )
    .await;
    assert_eq!(edit.status, StatusCode::OK, "manage still means manage: content edits work");

    let delete = send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &manager, None)).await;
    assert_eq!(delete.status, StatusCode::FORBIDDEN, "but deletion is the owner's: {}", delete.raw);
    assert!(delete.raw.contains("owner"), "the refusal explains why: {}", delete.raw);

    // Renaming is grouped with deletion, not with the edits above: this service resolves hooks by
    // name on `/webhook/{identifier}`, so a rename silently breaks every caller pointed at the old
    // one. It is a lifecycle act wearing an edit's clothes.
    let rename = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook}"), &manager, Some(json!({ "name": "renamed" }))),
    )
    .await;
    assert_eq!(rename.status, StatusCode::FORBIDDEN, "renaming is a lifecycle action");

    // The owner may do both.
    assert_eq!(
        send(&app, json_request("PUT", &format!("/api/hooks/{hook}"), &owner, Some(json!({ "name": "renamed" })))).await.status,
        StatusCode::OK,
        "the owner may rename"
    );
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &owner, None)).await.status,
        StatusCode::NO_CONTENT,
        "and delete"
    );
}

/// **§3** — an ownerless hook is master-only, which is the conservative direction.
///
/// Every hook that predates the ownership column has `owner_key_id` NULL. Reading that as "anyone
/// who manages it may delete it" would make the un-migrated state *more* permissive than the
/// migrated one, so every existing deployment would silently keep the old behaviour until someone
/// remembered to assign ownership — a migration that changes nothing until it is noticed.
#[tokio::test]
async fn s3_a_hook_with_no_owner_is_lifecycle_master_only() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("legacy.sh", "#!/bin/sh\necho ok\n");

    let hook = insert_hook(&db, "ownerless_hook", &script, 30).await;
    let (manager_id, manager) = insert_key(&db, "manager", "", KeyScopes::plain()).await;
    grant(&db, manager_id, hook, true, true).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &manager, None)).await.status,
        StatusCode::FORBIDDEN,
        "no owner means no non-master lifecycle authority"
    );
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &master, None)).await.status,
        StatusCode::NO_CONTENT,
        "master is unaffected by ownership"
    );
}

/// **§3** — "Master may reassign `owner_key_id` on any resource ... at any time", and only master.
#[tokio::test]
async fn s3_only_master_reassigns_ownership() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("reassign.sh", "#!/bin/sh\necho ok\n");

    // Parents both: the point here is that *ownership* moves, so each caller must already clear R2
    // and differ only in whether it holds the column.
    let (owner_id, owner) = insert_key(&db, "owner", "", KeyScopes::parent()).await;
    let (successor_id, successor) = insert_key(&db, "successor", "", KeyScopes::parent()).await;
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let hook = insert_hook_owned_by(&db, "reassigned_hook", &script, owner_id).await;
    grant(&db, owner_id, hook, true, true).await;
    grant(&db, successor_id, hook, true, true).await;

    // The current owner cannot hand ownership on. Letting it would let an owner walk away from a
    // resource rather than resolve it — the step §6's inventory exists to make impossible.
    let by_owner = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook}"), &owner, Some(json!({ "owner_key_id": successor_id }))),
    )
    .await;
    assert_eq!(by_owner.status, StatusCode::FORBIDDEN, "ownership is not delegable by its holder");

    // A dangling owner is refused: it would put the hook permanently beyond §3's non-master path
    // and make §6's inventory report an id resolving to nothing.
    let dangling = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook}"),
            &master,
            Some(json!({ "owner_key_id": Uuid::new_v4() })),
        ),
    )
    .await;
    assert_eq!(dangling.status, StatusCode::BAD_REQUEST, "the new owner must exist");

    let by_master = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook}"), &master, Some(json!({ "owner_key_id": successor_id }))),
    )
    .await;
    assert_eq!(by_master.status, StatusCode::OK, "master reassigns: {}", by_master.raw);

    // Authority moved with the column, in both directions.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &owner, None)).await.status,
        StatusCode::FORBIDDEN,
        "the former owner lost lifecycle authority"
    );
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook}"), &successor, None)).await.status,
        StatusCode::NO_CONTENT,
        "and the new owner gained it"
    );
}

/// **R3** — "A daughter of the Master key is an ordinary daughter key with no elevated standing."
///
/// The rule this pins is a *negative* one, so the test has to be constructed to catch a violation
/// that does not exist yet: `parent_key_id` was added in this phase for cascade and visibility
/// scoping, and the risk is that some future check reads it to decide authority. Two keys are made
/// identical in every respect except parentage — one created by the master, one by an ordinary
/// parent — and every authority-bearing route must answer the same for both.
#[tokio::test]
async fn r3_a_daughter_of_the_master_holds_no_authority_another_daughter_lacks() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("lineage.sh", "#!/bin/sh\necho ok\n");

    let hook = insert_hook(&db, "lineage_hook", &script, 30).await;
    let (master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let (parent_id, parent) = insert_key(&db, "ordinary-parent", "", KeyScopes {
        can_manage_keys: true,
        max_concurrent_jobs: 10,
        ..Default::default()
    })
    .await;

    // Two daughters, differing only in who created them.
    let of_master = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "daughter-of-master" }))),
    )
    .await;
    assert_eq!(of_master.status, StatusCode::OK);
    let of_parent = send(
        &app,
        json_request("POST", "/api/keys", &parent, Some(json!({ "name": "daughter-of-parent" }))),
    )
    .await;
    assert_eq!(of_parent.status, StatusCode::OK);

    // Lineage was recorded, and recorded differently — otherwise the comparison below is vacuous.
    let id_of = |res: &TestResponse| -> Uuid {
        res.json["id"].as_str().expect("id present").parse().expect("id parses")
    };
    let daughter_of_master =
        ApiKey::find_by_id(id_of(&of_master)).one(&db).await.expect("query").expect("row");
    let daughter_of_parent =
        ApiKey::find_by_id(id_of(&of_parent)).one(&db).await.expect("query").expect("row");
    assert_eq!(daughter_of_master.parent_key_id, Some(master_id), "lineage records the master");
    assert_eq!(daughter_of_parent.parent_key_id, Some(parent_id), "and the ordinary parent");

    // Every authority-bearing route answers identically for both.
    let a = of_master.json["plaintext_key"].as_str().expect("key").to_owned();
    let b = of_parent.json["plaintext_key"].as_str().expect("key").to_owned();
    for (label, path, method, body) in [
        ("execute the hook", format!("/api/hooks/{hook}/execute"), "POST", Some(json!({}))),
        ("read the hook", format!("/api/hooks/{hook}"), "GET", None),
        ("delete the hook", format!("/api/hooks/{hook}"), "DELETE", None),
        ("create a key", "/api/keys".to_owned(), "POST", Some(json!({ "name": "x" }))),
        ("read the audit log", "/api/audit-logs".to_owned(), "GET", None),
        ("read settings", "/api/settings".to_owned(), "GET", None),
    ] {
        let from_master_line = send(&app, json_request(method, &path, &a, body.clone())).await;
        let from_parent_line = send(&app, json_request(method, &path, &b, body)).await;
        assert_eq!(
            from_master_line.status, from_parent_line.status,
            "R3: being the master's daughter changed the answer for '{label}'              ({} vs {})",
            from_master_line.status, from_parent_line.status
        );
    }
}

/// Finding #3 — `can_manage_keys` could write itself an execute grant on any hook, including one
/// running as root.
#[tokio::test]
async fn regression_non_master_cannot_self_grant_hook_permissions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("root.sh", "echo ok");
    let privileged = insert_hook_as(&db, "root_hook", &script, 30, Some("root")).await;
    let ordinary = insert_hook(&db, "ordinary_hook", &script, 30).await;
    let (manager_id, manager) = seed_key_manager(&db).await;
    let (victim_id, _victim) = insert_key(&db, "victim", "", KeyScopes::plain()).await;
    // The manager's own daughter, so every refusal below is about the rule under test rather than
    // about §4 hiding an unrelated key behind a `404`.
    set_parent(&db, victim_id, manager_id).await;

    // Self-grant on the privileged hook: the original exploit.
    let self_grant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{manager_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": privileged.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(self_grant.status, StatusCode::FORBIDDEN, "self-granting must be refused");

    // Still refused for an unprivileged hook: the rule is about granting to yourself, not about
    // which hook you picked.
    let self_grant_plain = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{manager_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": ordinary.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(self_grant_plain.status, StatusCode::FORBIDDEN);

    // Granting to somebody else on an *ordinary* hook the caller does not manage is refused too.
    // `2d62d1b` permitted this on the reasoning that `can_manage_keys` is a deployment-wide scope
    // and so is not bounded by any one hook; R2 rejects that reasoning outright, because the scope
    // can also mint the key it grants to. The self-grant block below never contained the exploit on
    // its own — it only made it cost one extra credential.
    let third_party = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": ordinary.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        third_party.status,
        StatusCode::FORBIDDEN,
        "R2: can_manage_keys is not a global bypass, even on an ordinary hook"
    );

    // The same request against the *privileged* hook is still refused, which is the boundary that
    // actually contains the override.
    let third_party_privileged = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": privileged.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        third_party_privileged.status,
        StatusCode::FORBIDDEN,
        "the override must never reach a hook that runs as another user"
    );

    // The grant never landed: the manager still cannot reach the privileged hook.
    let probe = send(&app, json_request("POST", &format!("/api/hooks/{privileged}/test"), &manager, None)).await;
    assert_eq!(probe.status, StatusCode::NOT_FOUND);

    // A caller who *does* manage the hook may still delegate it — the scope keeps working.
    grant(&db, manager_id, ordinary, true, true).await;
    let delegated = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": ordinary.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(delegated.status, StatusCode::OK, "delegating a hook you manage is still allowed");

    // ...but never on a privileged one, even with a legitimate manage grant.
    grant(&db, manager_id, privileged, true, true).await;
    let delegated_privileged = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": privileged.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(delegated_privileged.status, StatusCode::FORBIDDEN);
}

/// Finding #4 — a non-master with `can_manage` on a root hook could repoint its `script_path`, the
/// elevation surviving the swap. With `ALLOWED_SCRIPT_ROOTS` unset that is arbitrary root execution.
#[tokio::test]
async fn regression_non_master_cannot_repoint_a_privileged_hook() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let safe = scripts.write_script("safe.sh", "echo safe");
    let attacker = scripts.write_script("attacker.sh", "echo pwned");
    let hook_id = insert_hook_as(&db, "root_hook", &safe, 30, Some("root")).await;
    // A Parent, so R2 is satisfied and the refusals below can only come from the privileged-hook
    // guard. A Daughter would now be refused one step earlier, which would prove a different rule.
    let (key_id, editor) = insert_key(&db, "hook-editor", "", KeyScopes::parent()).await;
    grant(&db, key_id, hook_id, true, true).await;

    // The original exploit: swap the binary, leave `run_as_user` untouched.
    let repoint = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &editor, Some(json!({ "script_path": attacker }))),
    )
    .await;
    assert_eq!(repoint.status, StatusCode::FORBIDDEN, "repointing a privileged hook must be refused");
    assert!(repoint.string("error").contains("root"), "the refusal names the account: {}", repoint.string("error"));

    // Every other field is gated too — the guard is on the hook's privileged status, not on which
    // field the payload happened to mention.
    for payload in [
        json!({ "name": "renamed" }),
        json!({ "default_timeout_seconds": 600 }),
        json!({ "description": "harmless" }),
        // Including clearing the elevation, which would otherwise just add a step to the attack.
        json!({ "run_as_user": "" }),
    ] {
        let res = send(&app, json_request("PUT", &format!("/api/hooks/{hook_id}"), &editor, Some(payload.clone()))).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "modifying {payload} must be refused");
    }

    // Parameters are argv for the elevated command, so the parameter routes are gated as well —
    // a defaulted parameter is how you feed `-c <command>` to a root hook without touching
    // script_path at all.
    let param_uri = format!("/api/hooks/{hook_id}/parameters");
    let declare = send(
        &app,
        json_request("POST", &param_uri, &editor, Some(json!({ "param_key": "injected", "default_value": "-c" }))),
    )
    .await;
    assert_eq!(declare.status, StatusCode::FORBIDDEN, "declaring a parameter on a root hook must be refused");

    // The hook is untouched: still the safe script, still elevated.
    let (_mid, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let after = send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &master, None)).await;
    assert_eq!(after.field("script_path"), &json!(safe));
    assert_eq!(after.field("run_as_user"), &json!("root"));

    // An *unprivileged* hook is still freely manageable by the same key: the guard is scoped to
    // elevation, and did not just turn `can_manage` into a decoration.
    let plain_id = insert_hook(&db, "plain_hook", &safe, 30).await;
    grant(&db, key_id, plain_id, true, true).await;
    let plain_edit = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{plain_id}"), &editor, Some(json!({ "script_path": attacker }))),
    )
    .await;
    assert_eq!(plain_edit.status, StatusCode::OK);
    assert_eq!(plain_edit.field("script_path"), &json!(attacker));

    // And a master may still administer the privileged hook.
    let by_master = send(
        &app,
        json_request("PUT", &format!("/api/hooks/{hook_id}"), &master, Some(json!({ "script_path": attacker }))),
    )
    .await;
    assert_eq!(by_master.status, StatusCode::OK);
}

/// Finding #5 — a forged `X-Forwarded-For` from an untrusted peer defeated the `bound_ips` CIDR
/// allowlist entirely.
#[tokio::test]
async fn regression_forged_forwarding_headers_cannot_defeat_bound_ips() {
    let db = setup_test_db().await;
    // No trusted proxies: the production default, and the configuration under which the bypass
    // must be impossible.
    let app = create_app(test_state(&db));
    let (_id, scoped) = insert_key(&db, "lan-only", "10.0.0.0/8", KeyScopes::plain()).await;

    // Honest request: the simulated peer is 127.0.0.1, outside the bound range.
    let honest = send(&app, json_request("GET", "/api/auth/me", &scoped, None)).await;
    assert_eq!(honest.status, StatusCode::FORBIDDEN);

    // Every spoofing shape is now inert, because the header is never consulted at all.
    for (header, value) in [
        ("X-Forwarded-For", "10.1.2.3"),
        ("X-Forwarded-For", "203.0.113.9, 10.1.2.3"),
        ("X-Forwarded-For", "10.1.2.3, 10.4.5.6"),
        ("X-Real-IP", "10.1.2.3"),
        ("X-Forwarded-For", "::ffff:10.1.2.3"),
    ] {
        let res = send(&app, forwarded_request("/api/auth/me", &scoped, header, value)).await;
        assert_eq!(
            res.status,
            StatusCode::FORBIDDEN,
            "a forged {header}: {value} must not satisfy the CIDR allowlist"
        );
    }

    // The audit trail must record the real peer, not the claim: a spoofable client_ip would make
    // the trail worse than useless during an incident.
    let (_mid, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let scripts = ScriptDir::new();
    let script = scripts.write_script("noop.sh", "echo ok");
    let created = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "audited", "script_path": script }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);

    let spoofed_audit = send(
        &app,
        forwarded_request("/api/audit-logs", &master, "X-Forwarded-For", "203.0.113.77"),
    )
    .await;
    assert_eq!(spoofed_audit.status, StatusCode::OK);
    assert!(
        !spoofed_audit.raw.contains("203.0.113.77"),
        "a forged address must never be recorded as client_ip: {}",
        spoofed_audit.raw
    );
    assert!(spoofed_audit.raw.contains("127.0.0.1"), "the real TCP peer is what gets recorded");
}

/// A trusted proxy's headers are believed — the fix must not break real reverse-proxy deployments.
#[tokio::test]
async fn a_trusted_proxy_can_still_present_the_real_client_address() {
    let db = setup_test_db().await;
    let app = create_app(test_state_with_trusted_proxies(&db, &["127.0.0.1/32", "10.0.0.0/8"]));
    let (_id, scoped) = insert_key(&db, "lan-only", "192.168.0.0/16", KeyScopes::plain()).await;

    // Without a header the peer itself is used, and 127.0.0.1 is outside the key's range.
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &scoped, None)).await.status,
        StatusCode::FORBIDDEN
    );

    // With one, the rightmost hop is taken as the client.
    let res = send(&app, forwarded_request("/api/auth/me", &scoped, "X-Forwarded-For", "203.0.113.1, 192.168.4.4")).await;
    assert_eq!(res.status, StatusCode::OK);

    // An IPv4-mapped IPv6 hop still matches an IPv4 CIDR.
    let mapped = send(&app, forwarded_request("/api/auth/me", &scoped, "X-Real-IP", "::ffff:192.168.4.4")).await;
    assert_eq!(mapped.status, StatusCode::OK);

    // A garbage header falls back to the peer rather than failing open.
    let garbage = send(&app, forwarded_request("/api/auth/me", &scoped, "X-Forwarded-For", "not-an-ip")).await;
    assert_eq!(garbage.status, StatusCode::FORBIDDEN);
}

/// `bound_ips` now binds master keys too. Previously `is_master` skipped the CIDR check entirely,
/// so the most valuable credential in the system was the only one whose network restriction was
/// decorative — while the dashboard displayed it as enforced.
#[tokio::test]
async fn bound_ips_restricts_master_keys_as_well() {
    // One database per case. `RBAC_MODEL.md` §5 is now enforced by a unique index, so a single
    // database can hold exactly one master row — seeding three side by side is no longer possible
    // and, more to the point, no longer a state the service can ever be in.
    async fn master_bound_to(allowlist: &str) -> StatusCode {
        let db = setup_test_db().await;
        let app = create_app(test_state(&db));
        let (_id, master) = insert_key(&db, "the-master", allowlist, KeyScopes::master()).await;
        send(&app, json_request("GET", "/api/auth/me", &master, None)).await.status
    }

    assert_eq!(
        master_bound_to("10.0.0.0/8").await,
        StatusCode::FORBIDDEN,
        "a bound master key is held to its own allowlist"
    );

    // A master key that should reach the API from anywhere says so by leaving bound_ips empty...
    assert_eq!(master_bound_to("").await, StatusCode::OK);

    // ...or by naming ranges that actually include the caller.
    assert_eq!(master_bound_to("127.0.0.0/8,::1/128").await, StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────
// Hook soft delete, trash management, and the 92-day purge
// ─────────────────────────────────────────────────────────────

/// A non-master `DELETE` must hide the hook without destroying anything.
///
/// The row surviving is the entire point: dropping it cascades the hook's parameters, permission
/// grants, and execution history, so a mistaken delete used to take the audit record of every run
/// with it.
#[tokio::test]
async fn a_non_master_delete_is_soft_and_leaves_the_row_intact() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("soft.sh", "echo ok");
    // A Parent: R2 now gates lifecycle too ("lifecycle where §3 permits it"), so a permitted delete
    // needs the conjunction *and* ownership. This test is about what a permitted delete does.
    let (key_id, editor) = insert_key(&db, "editor", "", KeyScopes::parent()).await;
    // Owned by the deleter: §3 restricts deletion to master and the owner, and this test is about
    // what a *permitted* delete does to the row, not about who may issue one.
    let hook_id = insert_hook_owned_by(&db, "soft_hook", &script, key_id).await;
    insert_parameter(&db, hook_id, "p1", Some("v"), false).await;
    grant(&db, key_id, hook_id, true, true).await;

    // Run it once so there is history worth preserving.
    let run = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/execute"), &editor, Some(json!({}))),
    )
    .await;
    assert_eq!(run.status, StatusCode::OK);

    let deleted = send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &editor, None)).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    // The row is still there, flagged and attributed.
    let row = fetch_hook_row(&db, hook_id).await.expect("the row must survive a soft delete");
    assert!(row.is_deleted, "the hook is flagged as deleted");
    assert!(row.deleted_at.is_some(), "the deletion is timestamped");
    assert_eq!(
        row.deleted_by.as_deref(),
        Some(key_id.to_string().as_str()),
        "the acting key is recorded"
    );
    // Nothing cascaded: the parameter contract and the execution history are untouched.
    assert_eq!(execution_count(&db).await, 1, "history survives a soft delete");

    // ...but the API behaves as though it is gone, for every route.
    assert_eq!(
        send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &editor, None)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, json_request("GET", "/api/hooks", &editor, None)).await.json.as_array().map(Vec::len),
        Some(0),
        "a trashed hook is absent from the listing"
    );
    for (method, uri) in [
        ("POST", format!("/api/hooks/{hook_id}/execute")),
        ("POST", format!("/api/hooks/{hook_id}/test")),
        ("POST", "/webhook/soft_hook".to_owned()),
        ("GET", format!("/api/hooks/{hook_id}/parameters")),
    ] {
        let res = send(&app, json_request(method, &uri, &editor, Some(json!({})))).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{method} {uri} must treat a trashed hook as gone");
    }
    // Above all: it cannot run.
    assert_eq!(execution_count(&db).await, 1, "no execution was recorded for a trashed hook");

    // A non-master cannot see the trash, by name or by flag.
    let peeking = send(&app, json_request("GET", "/api/hooks?include_deleted=true", &editor, None)).await;
    assert_eq!(peeking.status, StatusCode::FORBIDDEN);
}

/// A master can see the trash, restore from it, and empty it.
#[tokio::test]
async fn a_master_can_view_restore_and_hard_delete_a_trashed_hook() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("trash.sh", "echo ok");
    let hook_id = insert_hook(&db, "trash_hook", &script, 30).await;
    let (_mid, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &master, None)).await.status,
        StatusCode::NO_CONTENT
    );

    // Default listing hides it; the trash view shows it, flagged.
    assert_eq!(
        send(&app, json_request("GET", "/api/hooks", &master, None)).await.json.as_array().map(Vec::len),
        Some(0)
    );
    let trash = send(&app, json_request("GET", "/api/hooks?include_deleted=true", &master, None)).await;
    assert_eq!(trash.status, StatusCode::OK);
    let rows = trash.json.as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["is_deleted"], json!(true));
    assert!(rows[0]["deleted_at"].is_string(), "the trash view reports when it was deleted");

    // Restore brings it back into service.
    let restored = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/restore"), &master, None),
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.field("is_deleted"), &json!(false));
    assert_eq!(restored.field("deleted_at"), &json!(null));
    assert_eq!(restored.field("deleted_by"), &json!(null));

    // It is fully live again.
    assert_eq!(
        send(&app, json_request("GET", &format!("/api/hooks/{hook_id}"), &master, None)).await.status,
        StatusCode::OK
    );
    // Restoring something that is not deleted is a 400, not a silent no-op.
    let again = send(&app, json_request("POST", &format!("/api/hooks/{hook_id}/restore"), &master, None)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);

    // Hard delete drops the row for good.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}?hard=true"), &master, None)).await.status,
        StatusCode::NO_CONTENT
    );
    assert!(fetch_hook_row(&db, hook_id).await.is_none(), "a hard delete removes the row");
}

/// Restore and hard delete are master-only; a `can_manage` grant is not enough.
#[tokio::test]
async fn trash_management_is_master_only() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("guard.sh", "echo ok");
    // A Parent, so the soft delete below is permitted and the hard delete is refused for the reason
    // this test is named after rather than for want of the R2 conjunction.
    let (key_id, editor) = insert_key(&db, "editor", "", KeyScopes::parent()).await;
    // Owned by the editor, so the refusals below are about *trash* being master-only rather than
    // about §3 ownership — which is covered separately.
    let hook_id = insert_hook_owned_by(&db, "guard_hook", &script, key_id).await;
    grant(&db, key_id, hook_id, true, true).await;

    // A non-master cannot destroy the row even on a hook it fully manages: hard delete discards an
    // audit trail, which no scoped grant should be able to do.
    let hard = send(
        &app,
        json_request("DELETE", &format!("/api/hooks/{hook_id}?hard=true"), &editor, None),
    )
    .await;
    assert_eq!(hard.status, StatusCode::FORBIDDEN);
    assert!(fetch_hook_row(&db, hook_id).await.is_some(), "the row survives the refused hard delete");

    // Soft delete, then confirm restore is refused too.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &editor, None)).await.status,
        StatusCode::NO_CONTENT
    );
    let restore = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook_id}/restore"), &editor, None),
    )
    .await;
    assert_eq!(restore.status, StatusCode::FORBIDDEN);
    assert!(
        fetch_hook_row(&db, hook_id).await.is_some_and(|h| h.is_deleted),
        "the hook stays in the trash"
    );
}

/// A privileged hook keeps its master-only guard through the delete routes as well.
#[tokio::test]
async fn deleting_a_privileged_hook_stays_master_only() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("root.sh", "echo ok");
    let hook_id = insert_hook_as(&db, "root_hook", &script, 30, Some("root")).await;
    let (key_id, editor) = insert_key(&db, "editor", "", KeyScopes::plain()).await;
    grant(&db, key_id, hook_id, true, true).await;

    let soft = send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &editor, None)).await;
    assert_eq!(soft.status, StatusCode::FORBIDDEN, "even trashing an elevated hook is master-only");
    assert!(fetch_hook_row(&db, hook_id).await.is_some_and(|h| !h.is_deleted));
}

/// A trashed hook still holds its unique name, and the conflict says so.
///
/// `hooks.name` is unique across live and trashed rows alike — a partial unique index is the only
/// way to scope it and its syntax is backend-specific, which `AGENT.MD` forbids. The behaviour is
/// therefore a deliberate trade-off, and the error has to explain itself.
#[tokio::test]
async fn a_trashed_hook_still_holds_its_name_and_says_so() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();

    let script = scripts.write_script("named.sh", "echo ok");
    let hook_id = insert_hook(&db, "taken_name", &script, 30).await;
    let (_mid, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}"), &master, None)).await.status,
        StatusCode::NO_CONTENT
    );

    let conflict = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "taken_name", "script_path": script }))),
    )
    .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    let message = conflict.string("error");
    assert!(
        message.contains("deleted") && message.contains("hard=true"),
        "the conflict must explain that a trashed hook holds the name, and how to free it: {message}"
    );

    // Freeing the name makes the create succeed.
    assert_eq!(
        send(&app, json_request("DELETE", &format!("/api/hooks/{hook_id}?hard=true"), &master, None)).await.status,
        StatusCode::NO_CONTENT
    );
    let created = send(
        &app,
        json_request("POST", "/api/hooks", &master, Some(json!({ "name": "taken_name", "script_path": script }))),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK);
}

/// The 92-day sweep drops expired trash and leaves everything else alone.
#[tokio::test]
async fn the_purge_removes_only_trash_past_the_retention_window() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (owner_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    // One live hook, one freshly trashed, one trashed just inside the window, one just outside.
    let live = insert_hook(&db, "live", "/bin/true", 30).await;
    let fresh = insert_hook_deleted_days_ago(&db, "fresh", "/bin/true", 1, owner_id).await;
    let inside = insert_hook_deleted_days_ago(&db, "inside", "/bin/true", 91, owner_id).await;
    let outside = insert_hook_deleted_days_ago(&db, "outside", "/bin/true", 93, owner_id).await;

    let purged = send(&app, json_request("POST", "/api/system/purge-hooks", &master, None)).await;
    assert_eq!(purged.status, StatusCode::OK);
    assert_eq!(purged.field("purged"), &json!(1), "only the row past 92 days is dropped");
    assert_eq!(purged.field("older_than_days"), &json!(92));

    assert!(fetch_hook_row(&db, outside).await.is_none(), "expired trash is gone");
    assert!(fetch_hook_row(&db, inside).await.is_some(), "trash inside the window survives");
    assert!(fetch_hook_row(&db, fresh).await.is_some(), "recent trash survives");
    assert!(fetch_hook_row(&db, live).await.is_some(), "a live hook is never touched");

    // The threshold is overridable for an operator reclaiming space sooner.
    let aggressive = send(
        &app,
        json_request("POST", "/api/system/purge-hooks?older_than_days=30", &master, None),
    )
    .await;
    assert_eq!(aggressive.status, StatusCode::OK);
    assert_eq!(aggressive.field("purged"), &json!(1), "the 91-day row is now in scope");
    assert!(fetch_hook_row(&db, inside).await.is_none());
    assert!(fetch_hook_row(&db, live).await.is_some(), "a live hook is still never touched");

    // A zero threshold is a no-op rather than "delete everything", matching LOG_RETENTION_DAYS=0.
    let zero = send(
        &app,
        json_request("POST", "/api/system/purge-hooks?older_than_days=0", &master, None),
    )
    .await;
    assert_eq!(zero.field("purged"), &json!(0));
    assert!(fetch_hook_row(&db, fresh).await.is_some());
}

/// The purge endpoint is master-only, and rejects a negative window.
#[tokio::test]
async fn the_purge_endpoint_is_master_only_and_validated() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (owner_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let scopes = KeyScopes { can_manage_hooks: true, max_concurrent_jobs: 10, ..Default::default() };
    let (_id, manager) = insert_key(&db, "manager", "", scopes).await;

    let expired = insert_hook_deleted_days_ago(&db, "expired", "/bin/true", 200, owner_id).await;

    let refused = send(&app, json_request("POST", "/api/system/purge-hooks", &manager, None)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(fetch_hook_row(&db, expired).await.is_some(), "the refused purge changed nothing");

    let negative = send(
        &app,
        json_request("POST", "/api/system/purge-hooks?older_than_days=-1", &master, None),
    )
    .await;
    assert_eq!(negative.status, StatusCode::BAD_REQUEST);
    assert!(fetch_hook_row(&db, expired).await.is_some());
}

/// The background worker runs the hook sweep on its own schedule, not just on demand.
#[tokio::test]
async fn the_retention_worker_purges_expired_trash_on_its_own() {
    let db = setup_test_db().await;
    let (owner_id, _master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let expired = insert_hook_deleted_days_ago(&db, "expired", "/bin/true", 200, owner_id).await;
    let recent = insert_hook_deleted_days_ago(&db, "recent", "/bin/true", 5, owner_id).await;

    let state = AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig { retention_sweep_seconds: 1, ..(*test_config()).clone() }),
        test_cipher(),
    );
    let (shutdown_tx, worker) = spawn_retention_worker(&state);

    assert!(
        wait_until(Duration::from_secs(5), async || {
            fetch_hook_row(&db, expired).await.is_none()
        })
        .await,
        "the worker should purge trash past the 92-day window"
    );
    assert!(fetch_hook_row(&db, recent).await.is_some(), "recent trash is left alone");

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), worker).await;
}

// ─────────────────────────────────────────────────────────────
// Dynamic proxy resolution (Docker / Traefik)
// ─────────────────────────────────────────────────────────────

/// A hostname in `TRUSTED_PROXIES` is resolved, so a container addressed by name can be trusted.
///
/// `localhost` stands in for `traefik` here because it is the one name guaranteed to resolve on any
/// machine without network access; the code path taken is identical.
#[tokio::test]
async fn a_hostname_trusted_proxy_is_resolved_and_honoured() {
    let db = setup_test_db().await;
    // The simulated peer is 127.0.0.1, which is what `localhost` resolves to — so the daemon must
    // believe its forwarding header, exactly as it would for `traefik` on a Docker network.
    let app = create_app(test_state_with_trusted_proxies(&db, &["localhost"]));
    let (_id, scoped) = insert_key(&db, "lan-only", "192.168.0.0/16", KeyScopes::plain()).await;

    // Without a header the peer itself is used, and loopback is outside the key's range.
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &scoped, None)).await.status,
        StatusCode::FORBIDDEN
    );

    let forwarded = send(
        &app,
        forwarded_request("/api/auth/me", &scoped, "X-Forwarded-For", "192.168.4.4"),
    )
    .await;
    assert_eq!(forwarded.status, StatusCode::OK, "a name-resolved proxy's header is believed");
}

/// A Docker bridge CIDR works alongside a hostname, and neither widens the other.
#[tokio::test]
async fn docker_cidrs_and_hostnames_coexist_without_widening_trust() {
    let db = setup_test_db().await;
    // The classic Docker/Traefik shape: the bridge network plus the proxy's service name.
    let app = create_app(test_state_with_trusted_proxies(&db, &["172.16.0.0/12", "traefik"]));
    let (_id, scoped) = insert_key(&db, "lan-only", "10.0.0.0/8", KeyScopes::plain()).await;

    // The test peer is 127.0.0.1: not in the bridge range, and `traefik` does not resolve here.
    // Its forged header must therefore be ignored outright.
    for value in ["10.1.2.3", "10.1.2.3, 10.4.5.6"] {
        let res = send(&app, forwarded_request("/api/auth/me", &scoped, "X-Forwarded-For", value)).await;
        assert_eq!(
            res.status,
            StatusCode::FORBIDDEN,
            "an unresolvable hostname entry must not trust an unrelated peer"
        );
    }
}

/// With a chain of proxies, the client is the rightmost hop that is not itself a trusted proxy.
///
/// This is the case that a naive "take the rightmost entry" reading gets wrong: behind two proxies
/// the last entry *is* a proxy, and reporting it as the client would break `bound_ips` for every
/// caller and fill the audit trail with the infrastructure's own addresses.
#[tokio::test]
async fn a_proxy_chain_resolves_to_the_real_client() {
    let db = setup_test_db().await;
    let app = create_app(test_state_with_trusted_proxies(&db, &["127.0.0.1", "172.16.0.0/12"]));
    let (_id, scoped) = insert_key(&db, "corp", "203.0.113.0/24", KeyScopes::plain()).await;

    // client(203.0.113.50) → P1(172.16.0.9) → us(127.0.0.1). The header's last entry is P1.
    let res = send(
        &app,
        forwarded_request("/api/auth/me", &scoped, "X-Forwarded-For", "203.0.113.50, 172.16.0.9"),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "the trusted hop is peeled to reach the real client");

    // A client prepending a lie cannot displace the suffix the proxies appended.
    let spoofed = send(
        &app,
        forwarded_request(
            "/api/auth/me",
            &scoped,
            "X-Forwarded-For",
            "203.0.113.50, 8.8.8.8, 172.16.0.9",
        ),
    )
    .await;
    assert_eq!(
        spoofed.status,
        StatusCode::FORBIDDEN,
        "the rightmost non-proxy hop is 8.8.8.8, which is outside the key's range"
    );
}

// ─────────────────────────────────────────────────────────────
// Convergence pass: pipeline ordering, anti-replay, full-URI coverage, retention guards
// ─────────────────────────────────────────────────────────────

/// Authenticate-then-authorize: a caller that cannot authenticate must learn nothing about the
/// network binding of the key it is presenting.
///
/// Before the reorder, `bound_ips` was evaluated before the signature, so a caller holding only a
/// leaked `X-API-Key` could tell `403 Client IP not allowed` (the key exists and is bound to
/// networks excluding me) apart from `401` (everything else) — a map of the deployment's topology,
/// handed out to someone who had proven nothing. Both branches must now answer `401`.
#[tokio::test]
async fn an_unauthenticated_caller_cannot_distinguish_a_bad_key_from_a_bad_source_network() {
    let db = setup_test_db().await;
    let app = create_app(test_state_requiring_signatures(&db));

    // Bound to a network the test client (127.0.0.1) is emphatically not in.
    let elsewhere = insert_key_full(&db, "elsewhere", "10.99.0.0/16", KeyScopes::plain()).await;
    // Bound to the caller's own network, so only the signature distinguishes the two.
    let local = insert_key_full(&db, "local", "127.0.0.1/32", KeyScopes::plain()).await;

    // No signature at all, with signing mandatory.
    let unsigned = |key: &str| json_request("GET", "/api/auth/me", key, None);
    assert_eq!(send(&app, unsigned(&elsewhere.plaintext)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, unsigned(&local.plaintext)).await.status, StatusCode::UNAUTHORIZED);

    // A *wrong* signature — the stolen-key case. The out-of-network key must not answer 403 while
    // the in-network one answers 401; that difference is the oracle.
    let wrong_signature = |key: &str| {
        with_connect_info(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .header("X-API-Key", key)
                .header("X-Timestamp", now_timestamp().to_string())
                .header("X-Signature-256", format!("sha256={}", "11".repeat(32))),
        )
        .body(axum::body::Body::empty())
        .expect("request builds")
    };
    let out_of_network = send(&app, wrong_signature(&elsewhere.plaintext)).await;
    let in_network = send(&app, wrong_signature(&local.plaintext)).await;
    assert_eq!(out_of_network.status, StatusCode::UNAUTHORIZED);
    assert_eq!(in_network.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        out_of_network.status, in_network.status,
        "the response must not depend on whether the key's bound_ips admits the caller"
    );

    // And an unknown key is indistinguishable from both.
    assert_eq!(send(&app, wrong_signature("no-such-key")).await.status, StatusCode::UNAUTHORIZED);

    // Authorization still happens — it just happens *after* authentication succeeds.
    let authenticated_but_out_of_network = send(
        &app,
        signed_bearer_request("GET", "/api/auth/me", &elsewhere.plaintext, &elsewhere.signing_secret, ""),
    )
    .await;
    assert_eq!(
        authenticated_but_out_of_network.status,
        StatusCode::FORBIDDEN,
        "once authenticated, the CIDR restriction is enforced and reported honestly"
    );
}

/// Anti-replay: a validly-signed request, captured and resent inside the timestamp window, must be
/// refused. The window alone never provided this — it bounds how long a capture stays useful, not
/// how many times it may be used.
#[tokio::test]
async fn an_intercepted_signed_request_cannot_be_replayed_inside_the_window() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_full(&db, "sender", "", KeyScopes::hook_manager()).await;

    let scripts = ScriptDir::new();
    let script = scripts.write_script("replay.sh", "#!/bin/sh\necho ran\n");
    let hook = insert_hook(&db, "replay_hook", &script, 30).await;
    grant(&db, sender.id, hook, true, true).await;
    let uri = format!("/api/hooks/{hook}/execute");
    let body = json!({ "parameters": {} }).to_string();

    // The timestamp is captured once and reused, so every call rebuilds the *identical* request —
    // same signature, byte for byte. Letting each call re-read the clock would make the test
    // depend on whether the sends happened to straddle a second boundary, and a "replay" with a
    // different timestamp is a different signature and not a replay at all.
    let captured_at = now_timestamp();
    let intercepted = || {
        signed_request_at(
            "POST",
            &uri,
            &sender.plaintext,
            &sender.signing_secret,
            &body,
            captured_at,
        )
    };

    let first = send(&app, intercepted()).await;
    assert_eq!(first.status, StatusCode::OK, "the legitimate request goes through");
    assert_eq!(first.field("status"), &json!("SUCCESS"));

    // Byte-for-byte the same request: same key, same timestamp, same signature, same body.
    let replay = send(&app, intercepted()).await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "a signature that has already been honoured must not be honoured twice"
    );
    assert!(replay.string("error").contains("already been used"));

    // Replaying it repeatedly stays refused rather than sliding through on a later attempt.
    for _ in 0..3 {
        assert_eq!(send(&app, intercepted()).await.status, StatusCode::UNAUTHORIZED);
    }

    // A freshly signed request from the same key still works — the guard rejects reuse, not the key.
    let fresh = send(
        &app,
        signed_request_at(
            "POST",
            &uri,
            &sender.plaintext,
            &sender.signing_secret,
            &body,
            captured_at - 5,
        ),
    )
    .await;
    assert_eq!(fresh.status, StatusCode::OK, "a distinct signature is not a replay");
}

/// `BODY_ONLY` is deliberately exempt: it carries no timestamp, so there is no window to be
/// single-use within, and per `AGENT.MD` it exists to accept third-party senders whose format
/// cannot be changed — senders that redeliver on purpose.
#[tokio::test]
async fn body_only_keys_are_not_subject_to_single_use_enforcement() {
    use simply_hook_executor::entities::api_key::HmacMode;

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender =
        insert_key_with_mode(&db, "github", "", KeyScopes::hook_manager(), HmacMode::BodyOnly).await;

    let scripts = ScriptDir::new();
    let script = scripts.write_script("redeliver.sh", "#!/bin/sh\necho ok\n");
    let hook = insert_hook(&db, "redeliver_hook", &script, 30).await;
    grant(&db, sender.id, hook, true, true).await;
    let uri = format!("/webhook/{hook}");
    let body = json!({}).to_string();

    // A webhook sender's redelivery is the same bytes twice, and must keep working.
    for attempt in 0..3 {
        let response = send(
            &app,
            body_only_request(&uri, &sender.plaintext, &sender.signing_secret, &body, "X-Hub-Signature-256"),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "redelivery {attempt} must be accepted");
    }
}

/// Full-URI coverage: the query string is inside the signed material, so rewriting it in transit
/// invalidates the signature. This is what stops a captured `DELETE /api/hooks/{id}` from being
/// escalated to `?hard=true` — a reversible soft delete turned into permanent destruction of the
/// hook and its entire execution history.
#[tokio::test]
async fn tampering_with_the_query_string_invalidates_the_signature() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let master = insert_key_full(&db, "master", "", KeyScopes::master()).await;

    let scripts = ScriptDir::new();
    let script = scripts.write_script("target.sh", "#!/bin/sh\nexit 0\n");
    let hook = insert_hook(&db, "query_target", &script, 30).await;

    // Signed for the soft-delete path, then replayed with `?hard=true` appended.
    let signed_path = format!("/api/hooks/{hook}");
    let timestamp = now_timestamp();
    let escalated = with_connect_info(
        axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("{signed_path}?hard=true"))
            .header("X-API-Key", &master.plaintext)
            .header("X-Timestamp", timestamp.to_string())
            .header(
                "X-Signature-256",
                sign_request(&master.signing_secret, "DELETE", &signed_path, timestamp, ""),
            ),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");

    assert_eq!(
        send(&app, escalated).await.status,
        StatusCode::UNAUTHORIZED,
        "a signature over the bare path must not authorize the same path with ?hard=true"
    );
    assert!(
        fetch_hook_row(&db, hook).await.is_some(),
        "the hook must survive: the escalated request was never authorized"
    );

    // The reverse direction too — dropping a signed query parameter is equally a rewrite.
    let listing = "/api/hooks?include_deleted=true";
    let timestamp = now_timestamp();
    let stripped = with_connect_info(
        axum::http::Request::builder()
            .method("GET")
            .uri("/api/hooks")
            .header("X-API-Key", &master.plaintext)
            .header("X-Timestamp", timestamp.to_string())
            .header(
                "X-Signature-256",
                sign_request(&master.signing_secret, "GET", listing, timestamp, ""),
            ),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(send(&app, stripped).await.status, StatusCode::UNAUTHORIZED);
}

/// The converged 3 MiB ceiling is one constant governing both the router limit and the middleware's
/// signature buffer. Two independently-chosen numbers would leave a band of sizes accepted by one
/// layer and refused by the other, which is the shape of a parser-differential bug.
#[tokio::test]
async fn the_body_limit_is_three_mib_and_shared_by_the_router_and_the_signature_buffer() {
    assert_eq!(
        simply_hook_executor::MAX_REQUEST_BODY_BYTES,
        3 * 1024 * 1024,
        "the converged limit shared with simply_ip_vault"
    );

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let sender = insert_key_full(&db, "bulk", "", KeyScopes::hook_manager()).await;

    let scripts = ScriptDir::new();
    let script = scripts.write_script("bulk.sh", "#!/bin/sh\necho sized\n");
    let hook = insert_hook(&db, "bulk_hook", &script, 30).await;
    grant(&db, sender.id, hook, true, true).await;
    let uri = format!("/api/hooks/{hook}/execute");

    // Comfortably inside the old 1 MiB bound but well over it: proof the ceiling actually moved,
    // rather than the constant changing while some other layer still enforced the old value.
    let padding = "p".repeat(2 * 1024 * 1024);
    let body = json!({ "parameters": {}, "padding": padding }).to_string();
    assert!(body.len() > 1024 * 1024 && body.len() < simply_hook_executor::MAX_REQUEST_BODY_BYTES);

    let response =
        send(&app, signed_request("POST", &uri, &sender.plaintext, &sender.signing_secret, &body))
            .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "a 2 MiB signed body must be buffered, verified, and executed under the 3 MiB ceiling"
    );

    // Unauthenticated requests are bounded by the same layer, so an anonymous caller cannot force
    // an allocation the authenticated path would have refused.
    let oversized = raw_request(
        "POST",
        &uri,
        "not-a-real-key",
        vec![b'x'; simply_hook_executor::MAX_REQUEST_BODY_BYTES + 4096],
    );
    let status = send(&app, oversized).await.status;
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::UNAUTHORIZED,
        "an oversized unauthenticated body must be refused, got {status}"
    );
}

/// The purge is the one query in the system that destroys audit history, so its guards are asserted
/// directly: a live hook, and a *restored* hook that kept its old `deleted_at`, must both survive a
/// sweep that removes genuinely-trashed rows around them.
#[tokio::test]
async fn the_purge_spares_live_and_restored_hooks_whatever_their_deleted_at_says() {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set};
    use simply_hook_executor::retention::purge_expired_deleted_hooks;

    let db = setup_test_db().await;
    let owner = insert_key_full(&db, "owner", "", KeyScopes::hook_manager()).await;
    let scripts = ScriptDir::new();
    let script = scripts.write_script("keep.sh", "#!/bin/sh\nexit 0\n");

    let live = insert_hook(&db, "still_live", &script, 30).await;
    let trashed = insert_hook_deleted_days_ago(&db, "long_gone", &script, 200, owner.id).await;
    let recent = insert_hook_deleted_days_ago(&db, "recently_binned", &script, 5, owner.id).await;

    // A restored hook: `is_deleted` cleared, but `deleted_at` deliberately left behind, which is
    // exactly the row the `is_deleted = true` guard exists to protect.
    let restored = insert_hook_deleted_days_ago(&db, "brought_back", &script, 300, owner.id).await;
    let model = fetch_hook_row(&db, restored).await.expect("the restored hook exists");
    let mut active: simply_hook_executor::entities::hook::ActiveModel = model.into();
    active.is_deleted = Set(false);
    active.update(&db).await.expect("restore succeeds");

    let removed = purge_expired_deleted_hooks(&db, 92).await.expect("the sweep runs");
    assert_eq!(removed, 1, "only the genuinely expired trashed hook is destroyed");

    assert!(fetch_hook_row(&db, live).await.is_some(), "a live hook is untouched");
    assert!(fetch_hook_row(&db, recent).await.is_some(), "trash inside the window is kept");
    assert!(
        fetch_hook_row(&db, restored).await.is_some(),
        "a restored hook must survive its own stale deleted_at"
    );
    assert!(fetch_hook_row(&db, trashed).await.is_none(), "expired trash is gone");

    // A disabled window keeps everything, so an operator can opt out without stopping the worker.
    let still_there =
        insert_hook_deleted_days_ago(&db, "kept_forever", &script, 999, owner.id).await;
    assert_eq!(purge_expired_deleted_hooks(&db, 0).await.expect("no-op sweep"), 0);
    assert!(fetch_hook_row(&db, still_there).await.is_some());
}

/// The retention window is configurable, and separately from `LOG_RETENTION_DAYS`: shortening log
/// retention to reclaim disk must not silently shrink the undo window for deleted automation.
#[tokio::test]
async fn the_hook_retention_window_is_configurable_and_independent_of_log_retention() {
    use simply_hook_executor::retention::{
        purge_expired_deleted_hooks, DEFAULT_DELETED_HOOK_RETENTION_DAYS,
    };

    assert_eq!(DEFAULT_DELETED_HOOK_RETENTION_DAYS, 92, "the converged default");

    let db = setup_test_db().await;
    let owner = insert_key_full(&db, "owner", "", KeyScopes::hook_manager()).await;
    let scripts = ScriptDir::new();
    let script = scripts.write_script("cfg.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook_deleted_days_ago(&db, "aged_ten_days", &script, 10, owner.id).await;

    // Survives the default window...
    assert_eq!(
        purge_expired_deleted_hooks(&db, DEFAULT_DELETED_HOOK_RETENTION_DAYS).await.expect("sweep"),
        0
    );
    assert!(fetch_hook_row(&db, hook).await.is_some());

    // ...and is removed under a shorter one, which is what makes the setting real.
    assert_eq!(purge_expired_deleted_hooks(&db, 7).await.expect("sweep"), 1);
    assert!(fetch_hook_row(&db, hook).await.is_none());

    // The two windows are carried independently on the config, not derived from one another.
    let config = RuntimeConfig {
        log_retention_days: 0,
        deleted_hook_retention_days: 92,
        ..(*test_config()).clone()
    };
    assert_eq!(config.log_retention_days, 0);
    assert_eq!(config.deleted_hook_retention_days, 92);
}

// ─────────────────────────────────────────────────────────────
// Convergence: per-verb grant proportionality & pre-lookup freshness
// ─────────────────────────────────────────────────────────────

/// A **local manager's** delegated grant may not exceed the verbs it holds on that hook.
///
/// `guard_manage` answers *whether* a caller may administer grants on a hook; it never answered
/// *how much* of it may be handed out. `can_execute` and `can_manage` are separate columns in
/// `SCHEMA.MD`, so an operator can deliberately grant management without execution — and before
/// this guard, that key could route the missing verb to itself through a second key it controls:
/// mint a key, grant it `can_execute`, authenticate as it, run the hook. Two requests, and the
/// withheld capability is in hand.
///
/// Seeded as a **parent manager** — `can_manage_keys` *and* a `can_manage` row — because that is
/// now the only non-master shape R2 admits. Before R2 was enforced a `can_manage_keys` holder took
/// a global-administrator early return that skipped this rule entirely, so seeding one made every
/// assertion below vacuous; seeding a key *without* the flag now fails at R2 instead, which would
/// pass for the wrong reason. Both mistakes are covered separately, by
/// [`r2_a_can_manage_keys_holder_without_a_row_on_the_hook_is_refused`] and
/// [`r2_a_daughter_holding_only_a_manage_row_may_not_administer_grants`].
#[tokio::test]
async fn a_parents_delegated_grant_cannot_exceed_the_verbs_it_holds() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("verbs.sh", "#!/bin/sh\necho ran\n");

    let hook = insert_hook(&db, "delegated_hook", &script, 30).await;
    // Manages the hook, deliberately without execution rights on it.
    let (manager_id, manager) = seed_parent_manager(&db, "parent-manager", hook, false).await;
    let (accomplice_id, accomplice) = insert_key(&db, "accomplice", "", KeyScopes::plain()).await;
    // The accomplice is the manager's own daughter, which is how a real deployment produces a key
    // a parent delegates to. Without the lineage §4 makes the target invisible and the refusal
    // below would be a `404` about visibility rather than the `403` about R1 under test.
    set_parent(&db, accomplice_id, manager_id).await;

    let over_grant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{accomplice_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        over_grant.status,
        StatusCode::FORBIDDEN,
        "granting a verb the caller does not hold must be refused"
    );
    assert!(
        over_grant.raw.contains("can_execute"),
        "the refusal names the verb that was over-granted, not just 'permission denied': {}",
        over_grant.raw
    );

    // The refusal was real: no row was written, so the accomplice still cannot run the hook.
    let attempt = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &accomplice, Some(json!({}))),
    )
    .await;
    // `404`, not `403`: with no row the accomplice cannot see the hook at all (§4).
    assert_eq!(attempt.status, StatusCode::NOT_FOUND, "the blocked grant never landed");

    // Handing out a verb the caller *does* hold still works — this is proportionality, not a ban
    // on delegation.
    let within_bounds = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{accomplice_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(within_bounds.status, StatusCode::OK, "delegating a verb you hold is allowed");

    // Revoking is never an escalation, so turning a flag off is allowed even for the verb the
    // caller lacks: `false` cannot exceed anything.
    let revoke = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{accomplice_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::OK, "revocation must not require holding the verb");

    // On a hook where the caller genuinely holds execution, the identical request succeeds —
    // proving the block was about the caller's own grant and nothing else about the payload.
    let held_fully = insert_hook(&db, "fully_held_hook", &script, 30).await;
    grant(&db, manager_id, held_fully, true, true).await;
    let now_permitted = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{accomplice_id}/permissions"),
            &manager,
            Some(
                json!({ "hook_id": held_fully.to_string(), "can_execute": true, "can_manage": false }),
            ),
        ),
    )
    .await;
    assert_eq!(now_permitted.status, StatusCode::OK, "holding the verb makes the grant legitimate");

    // A master key is exempt, as everywhere else in the RBAC model.
    let (_, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let (bystander_id, _) = insert_key(&db, "bystander", "", KeyScopes::plain()).await;
    let by_master = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{bystander_id}/permissions"),
            &master,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(by_master.status, StatusCode::OK, "master keys bypass proportionality");
}

/// A **local manager** holding no grant on the target hook is still refused.
///
/// The entry gate lives inside `guard_delegated_hook_grant` alongside the per-verb check. Folding
/// two checks into one function is exactly where a condition gets dropped by accident, so the
/// pre-existing rule is pinned separately rather than left implied by the test above.
///
/// The caller manages a *different* hook, which is what gets it past the coarse standing check on
/// the handler and all the way to the real per-hook decision — a caller managing nothing at all is
/// refused earlier and for a different reason, covered separately below.
#[tokio::test]
async fn granting_on_a_hook_the_caller_does_not_manage_is_still_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("unmanaged.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "unmanaged_hook", &script, 30).await;
    let elsewhere = insert_hook(&db, "some_other_hook", &script, 30).await;
    let (manager_id, manager) = seed_parent_manager(&db, "parent-manager", elsewhere, true).await;
    let (victim_id, _) = insert_key(&db, "victim", "", KeyScopes::plain()).await;
    set_parent(&db, victim_id, manager_id).await;

    // No row on the target hook at all.
    let no_grant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": false })),
        ),
    )
    .await;
    // §4: no row on the target hook means the hook is invisible to this caller, so the refusal is
    // the one a nonexistent hook produces. The `403` "manage access" wording is reserved for a
    // caller that *does* hold a row and is short the global half of R2.
    assert_eq!(no_grant.status, StatusCode::NOT_FOUND);
    assert!(
        no_grant.raw.contains("not found") || no_grant.raw.contains("Not Found"),
        "the entry gate is indistinguishable from a nonexistent hook: {}",
        no_grant.raw
    );

    // A row that grants execution but not management is not authority to administer grants either.
    grant(&db, manager_id, hook, true, false).await;
    let execute_only = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    // The caller now holds `can_execute` but not `can_manage` on this hook. It can *see* the hook,
    // so §4 is satisfied and the refusal is R2's — the manage row is what is missing.
    assert_eq!(
        execute_only.status,
        StatusCode::FORBIDDEN,
        "can_execute alone does not authorize delegating anything"
    );
}

/// A caller with no administrative standing anywhere is refused before any lookup happens.
///
/// The handler admits two routes — global key administrator, or manager of *some* hook — and this
/// pins the third case: neither. It matters beyond the `403` itself. The refusal must land before
/// the target key is fetched, or a caller holding nothing could distinguish a real key UUID from an
/// invented one by reading `404` instead of `403`, turning a permission endpoint into a key-
/// enumeration oracle.
#[tokio::test]
async fn a_caller_managing_nothing_is_refused_before_the_target_key_is_looked_up() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("nostanding.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "standing_hook", &script, 30).await;
    let (nobody_id, nobody) = insert_key(&db, "nobody", "", KeyScopes::plain()).await;
    let (victim_id, _) = insert_key(&db, "victim", "", KeyScopes::plain()).await;

    // An execute-only row is not management, so this caller manages nothing.
    grant(&db, nobody_id, hook, true, false).await;

    for (label, target) in [("a real key", victim_id), ("a key that does not exist", Uuid::new_v4())] {
        let refused = send(
            &app,
            json_request(
                "POST",
                &format!("/api/keys/{target}/permissions"),
                &nobody,
                Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
            ),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "{label}: a caller managing nothing must be refused, and indistinguishably"
        );
    }

    // Same on the revoke path, which shares the standing check.
    let revoke = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{victim_id}/permissions/{hook}"), &nobody, None),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::FORBIDDEN, "revoke shares the standing check");
}

/// **R2** — `can_manage_keys` is necessary but never sufficient. It is not a global bypass.
///
/// This test is the exact inverse of the one it replaces. `2d62d1b` made the flag an early return
/// that skipped every per-resource check, on the reasoning that a deployment-wide credential
/// administrator is not scoped to a hook. The consequence, which that reasoning did not price in,
/// is that such a holder could mint a key, grant it any verb on any hook, and authenticate as it —
/// `is_master` reachable in two requests. R2 names this case directly: "`can_manage_keys` is never
/// a global bypass of per-resource RBAC."
#[tokio::test]
async fn r2_a_can_manage_keys_holder_without_a_row_on_the_hook_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("conjunction.sh", "#!/bin/sh\necho ran\n");

    // Ungoverned: no permission row references this hook from anyone, including the admin.
    let hook = insert_hook(&db, "ungoverned_for_grant", &script, 30).await;
    let (admin_id, admin) = seed_key_manager(&db).await;
    let (worker_id, worker) = insert_key(&db, "worker", "", KeyScopes::plain()).await;
    // The admin's own daughter: §4 would otherwise make the target invisible, and every refusal
    // below would be about visibility rather than about R2.
    set_parent(&db, worker_id, admin_id).await;

    let granted = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{worker_id}/permissions"),
            &admin,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(
        granted.status,
        StatusCode::FORBIDDEN,
        "can_manage_keys without a manage row on this hook is only half of R2: {}",
        granted.raw
    );

    // The refusal is real, not merely a status: nothing was written, so the worker cannot run it.
    let ran = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &worker, Some(json!({}))),
    )
    .await;
    assert_eq!(ran.status, StatusCode::NOT_FOUND, "the blocked grant never landed");

    // Revocation takes the same route and is refused identically — the two directions agree about
    // who may act, or the stricter one is simply routed around.
    let revoked = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{worker_id}/permissions/{hook}"), &admin, None),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::FORBIDDEN, "revoke enforces the same conjunction");

    // Supplying the missing half makes both succeed, which is what proves the refusals above were
    // about the conjunction rather than about something incidental to this fixture.
    grant(&db, admin_id, hook, true, true).await;
    let now_granted = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{worker_id}/permissions"),
            &admin,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(now_granted.status, StatusCode::OK, "both halves of R2 present: {}", now_granted.raw);

    let now_revoked = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{worker_id}/permissions/{hook}"), &admin, None),
    )
    .await;
    assert_eq!(now_revoked.status, StatusCode::NO_CONTENT, "and revoke likewise");
}

/// **R2** — the other half, from the other side: a manage row without `can_manage_keys`.
///
/// The Tiers matrix says a Daughter key — one lacking `can_manage_keys` — may *never* manage
/// resources. Its manage row is operational authority over the hook, not the right to decide who
/// else holds it. This population previously had a route of its own ("local managers") and could
/// hand out credentials-adjacent authority with no deployment-wide standing whatsoever.
#[tokio::test]
async fn r2_a_daughter_holding_only_a_manage_row_may_not_administer_grants() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("daughter.sh", "#!/bin/sh\necho ran\n");

    let hook = insert_hook(&db, "daughter_governed_hook", &script, 30).await;
    // Full rights on the hook — both verbs — and still not a manager of its grants.
    let (_daughter_id, daughter) =
        seed_daughter_with_manage_row(&db, "daughter", hook, true).await;
    let (worker_id, worker) = insert_key(&db, "worker", "", KeyScopes::plain()).await;

    let granted = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{worker_id}/permissions"),
            &daughter,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        granted.status,
        StatusCode::FORBIDDEN,
        "a manage row without can_manage_keys is only half of R2: {}",
        granted.raw
    );

    // Note what is *not* being claimed: the daughter keeps its operational rights. R2 governs who
    // administers grants, not who may use the hook.
    let ran = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &daughter, Some(json!({}))),
    )
    .await;
    assert_eq!(ran.status, StatusCode::OK, "the daughter may still run the hook it manages");

    let revoked = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{worker_id}/permissions/{hook}"), &daughter, None),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::FORBIDDEN, "revoke enforces the same conjunction");

    let _ = worker;
}

/// `can_manage` alone confers full revoke authority — no per-verb proportionality.
///
/// Granting has to prove authority because it can manufacture a capability the caller was never
/// given. Revoking cannot: turning a flag off is a request for `false`, and `false` exceeds nothing,
/// so the result is always a strict de-escalation of the target no matter who asks. Requiring the
/// caller to hold each verb it strips bought nothing anyway — `POST` with a reduced permission set
/// reaches the same state and `AGENT.MD` permits it — while making two routes to one outcome
/// disagree about who may take them.
#[tokio::test]
async fn a_can_manage_holder_may_revoke_a_verb_it_does_not_itself_hold() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("revoke_verbs.sh", "#!/bin/sh\necho ran\n");

    let hook = insert_hook(&db, "revoke_hook", &script, 30).await;
    let (manager_id, manager) = seed_key_manager(&db).await;
    let (victim_id, victim) = insert_key(&db, "victim", "", KeyScopes::plain()).await;

    // The caller administers the hook but was deliberately not given execution rights on it.
    grant(&db, manager_id, hook, false, true).await;
    // The victim holds exactly the verb the caller lacks.
    grant(&db, victim_id, hook, true, false).await;

    let revoked = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{victim_id}/permissions/{hook}"), &manager, None),
    )
    .await;
    assert_eq!(
        revoked.status,
        StatusCode::NO_CONTENT,
        "can_manage is the whole requirement for revoking: {}",
        revoked.raw
    );

    // It really landed: the victim can no longer run the hook.
    let now_denied = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &victim, Some(json!({}))),
    )
    .await;
    // `404` rather than `403`: with its row gone the victim is outside the hook's visibility scope,
    // and §4 requires that to be indistinguishable from a hook that never existed.
    assert_eq!(now_denied.status, StatusCode::NOT_FOUND, "the revocation took effect");

    // And the caller gained nothing by it — de-escalating someone else does not escalate you.
    let attempt = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &manager, Some(json!({}))),
    )
    .await;
    assert_eq!(
        attempt.status,
        StatusCode::FORBIDDEN,
        "revoking another key's execute grant must not confer execute on the revoker"
    );
}

/// `DELETE` and `POST`-with-a-reduced-set are two spellings of one operation, so they must agree on
/// who may perform it.
///
/// The asymmetry this pins down is the reason the stricter guard was walked back: for the same
/// actor, target and hook, a caller that can zero a grant through `POST` must also be able to delete
/// it through `DELETE`. Anything else is a rule that a caller routes around rather than obeys.
#[tokio::test]
async fn delete_and_post_revocation_paths_agree_on_who_may_revoke() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("parity.sh", "#!/bin/sh\necho ran\n");

    let hook = insert_hook(&db, "parity_hook", &script, 30).await;
    let (manager_id, manager) = seed_key_manager(&db).await;
    let (victim_id, _) = insert_key(&db, "victim", "", KeyScopes::plain()).await;

    // A caller holding *only* can_manage — the exact actor the old guard singled out.
    grant(&db, manager_id, hook, false, true).await;

    // Route A: zero the grant through the grant endpoint.
    grant(&db, victim_id, hook, true, true).await;
    let via_post = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{victim_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": false })),
        ),
    )
    .await;

    // Route B: delete the row outright, from the identical starting state.
    let db2 = setup_test_db().await;
    let app2 = create_app(test_state(&db2));
    let hook2 = insert_hook(&db2, "parity_hook", &script, 30).await;
    let (manager2_id, manager2) = seed_key_manager(&db2).await;
    let (victim2_id, _) = insert_key(&db2, "victim", "", KeyScopes::plain()).await;
    grant(&db2, manager2_id, hook2, false, true).await;
    grant(&db2, victim2_id, hook2, true, true).await;
    let via_delete = send(
        &app2,
        json_request("DELETE", &format!("/api/keys/{victim2_id}/permissions/{hook2}"), &manager2, None),
    )
    .await;

    // Different status codes (200 vs 204) because they are different verbs; what must match is
    // whether the caller was *allowed*.
    assert!(via_post.status.is_success(), "POST route: {}", via_post.raw);
    assert!(via_delete.status.is_success(), "DELETE route: {}", via_delete.raw);
    assert_eq!(
        via_post.status.is_client_error(),
        via_delete.status.is_client_error(),
        "the two revocation routes must not disagree about who may revoke"
    );
}

/// **R6 endpoint parity** — a reduction arriving at `POST .../permissions` is a revocation.
///
/// > *Reducing an existing permission row through a general update endpoint is classified as
/// > revocation under this rule, regardless of which endpoint it arrives at.*
///
/// The two routes reach the same end state: `DELETE .../permissions/{hook}` and a `POST` writing
/// every verb to `false`. Holding them to different standards achieves nothing — whichever is
/// stricter is one request away from being routed around — so the classifier decides by *effect*,
/// not by URL.
#[tokio::test]
async fn r6_a_post_that_only_reduces_is_judged_as_a_revocation() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("parity.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "parity_hook", &script, 30).await;
    // Manages the hook, deliberately **without** `can_execute` on it. Under R1 this key could never
    // *grant* `can_execute`; under R6 it may freely take it away.
    let (_parent_id, parent) = seed_parent_manager(&db, "parent", hook, false).await;
    let (worker_id, worker) = insert_key(&db, "worker", "", KeyScopes::plain()).await;
    grant(&db, worker_id, hook, true, false).await;

    // Sanity: the verb the parent does not hold is really in place on the target.
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/hooks/{hook}/execute"), &worker, Some(json!({})))).await.status,
        StatusCode::OK
    );

    let reduce = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{worker_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        reduce.status,
        StatusCode::OK,
        "removing a verb needs no proof of holding it: {}",
        reduce.raw
    );
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/hooks/{hook}/execute"), &worker, Some(json!({})))).await.status,
        StatusCode::FORBIDDEN,
        "the reduction actually landed"
    );

    // The complement, on the same route with the same caller: putting the verb *back* is a grant,
    // and R1 refuses it. One route, two classifications, decided purely by effect.
    let restore = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{worker_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        restore.status,
        StatusCode::FORBIDDEN,
        "the same route refuses the same verb in the granting direction"
    );
    assert!(restore.raw.contains("can_execute"), "and names it: {}", restore.raw);
}

/// **R6** — self-reduction through the general update endpoint, the case endpoint parity creates.
///
/// `DELETE` has permitted self-revocation since `357a81b`, but `POST` refused *any* write targeting
/// the caller's own key, reduction included. That asymmetry is exactly what R6's "regardless of
/// which endpoint it arrives at" forbids: the same key could drop its own grant with a `DELETE` and
/// was told no for the `POST` that does strictly less.
#[tokio::test]
async fn r6_a_key_may_reduce_its_own_row_through_the_update_endpoint() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("self_reduce.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "self_reduce_hook", &script, 30).await;
    let (parent_id, parent) = seed_parent_manager(&db, "parent", hook, true).await;

    // Drop `can_execute` from its own row while keeping `can_manage` — a partial self-reduction,
    // which `DELETE` cannot express at all. Ordered last among this key's authority checks, since
    // it reduces the very rights the earlier assertions depend on.
    let reduce = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{parent_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": false, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(reduce.status, StatusCode::OK, "self-reduction is a de-escalation: {}", reduce.raw);

    let execute = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &parent, Some(json!({}))),
    )
    .await;
    assert_eq!(execute.status, StatusCode::FORBIDDEN, "it gave up the verb for real");

    // Taking it back is a grant, and self-granting stays refused — the asymmetry R6 preserves.
    let regrant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{parent_id}/permissions"),
            &parent,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(
        regrant.status,
        StatusCode::FORBIDDEN,
        "giving up authority is free; taking it back is not"
    );
}

/// Self-revocation is allowed: a key may drop its own grant.
///
/// It is a de-escalation like any other. The previous rule refused it by analogy with self-*granting*
/// — which really is escalation — but the analogy does not hold in this direction, and refusing it
/// meant a key could not clean up after itself without finding a master.
#[tokio::test]
async fn a_key_may_revoke_its_own_hook_permissions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("self_revoke.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "self_revoke_hook", &script, 30).await;
    let (manager_id, manager) = seed_key_manager(&db).await;
    grant(&db, manager_id, hook, true, true).await;

    let self_revoke = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{manager_id}/permissions/{hook}"), &manager, None),
    )
    .await;
    assert_eq!(
        self_revoke.status,
        StatusCode::NO_CONTENT,
        "dropping your own grant is a de-escalation, not an escalation: {}",
        self_revoke.raw
    );

    // The key really did give up its access, in both directions.
    let me = send(&app, json_request("GET", "/api/auth/me", &manager, None)).await;
    assert_eq!(me.json["hook_permissions"], json!([]), "the grant is gone from the profile");
    let execute = send(
        &app,
        json_request("POST", &format!("/api/hooks/{hook}/execute"), &manager, Some(json!({}))),
    )
    .await;
    // §4: having no row at all means the hook is invisible, not merely unusable.
    assert_eq!(execute.status, StatusCode::NOT_FOUND, "and the capability with it");

    // Having given it up, it cannot hand it back to itself — self-*granting* is still escalation.
    let regrant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{manager_id}/permissions"),
            &manager,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(
        regrant.status,
        StatusCode::FORBIDDEN,
        "the asymmetry that matters is preserved: giving up authority is free, taking it back is not"
    );
}

/// A caller holding no grant at all cannot revoke.
///
/// This is the check the relaxation did **not** touch, and the one carrying the actual security
/// weight on this path. Revocation needs no proof of authority over the *verbs*, but it still needs
/// authority over the *hook* — otherwise any key manager could disable automation belonging to a
/// tenant it has no relationship with. That is the integrity concern the entry gate exists for.
#[tokio::test]
async fn revoking_on_a_hook_the_caller_does_not_manage_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("unmanaged_revoke.sh", "#!/bin/sh\nexit 0\n");

    let hook = insert_hook(&db, "unmanaged_revoke_hook", &script, 30).await;
    let elsewhere = insert_hook(&db, "a_hook_it_does_manage", &script, 30).await;
    // A local manager: it manages *a* hook (so it has standing) but not the target one. A
    // `can_manage_keys` holder would take the global-administrator route and be allowed, which is
    // the deliberate override — this test is about the population the per-hook rule still governs.
    let (manager_id, manager) = seed_parent_manager(&db, "parent-manager", elsewhere, true).await;
    let (victim_id, _) = insert_key(&db, "victim", "", KeyScopes::plain()).await;
    set_parent(&db, victim_id, manager_id).await;
    grant(&db, victim_id, hook, true, true).await;

    let no_grant = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{victim_id}/permissions/{hook}"),
            &manager,
            None,
        ),
    )
    .await;
    // §4: no row on the target hook makes it invisible, so the refusal is the one a nonexistent
    // hook produces rather than a `403` confirming it is real.
    assert_eq!(no_grant.status, StatusCode::NOT_FOUND);
    assert!(
        !no_grant.raw.contains("manage access"),
        "the refusal must not confirm the hook exists: {}",
        no_grant.raw
    );
}

/// A hook nobody holds a permission row on is still fully visible and manageable by a master.
///
/// This is the counterpart safeguard to allowing self-revocation. Once the last manager can drop its
/// own grant, a hook can reach a state where **no permission row references it at all** — and if
/// master visibility were derived from those rows, the hook would vanish from the API the moment it
/// became ungoverned. Recovering it would then mean opening the database by hand, which is not an
/// administrative interface.
///
/// So the property asserted here is that a master's view never depends on a row existing: it is
/// authority over the deployment, not a grant within it.
#[tokio::test]
async fn an_ungoverned_hook_stays_visible_and_manageable_by_a_master() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("ungoverned.sh", "#!/bin/sh\necho ran\n");

    let hook = insert_hook(&db, "ungoverned_hook", &script, 30).await;
    let (manager_id, manager) = seed_key_manager(&db).await;
    let (_, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    grant(&db, manager_id, hook, true, true).await;

    // The last manager drops its own grant, which this rule now permits. The hook is left with no
    // permission row pointing at it from anyone.
    let self_revoke = send(
        &app,
        json_request("DELETE", &format!("/api/keys/{manager_id}/permissions/{hook}"), &manager, None),
    )
    .await;
    assert_eq!(self_revoke.status, StatusCode::NO_CONTENT, "the last manager revoked itself");

    // Nobody can see it through a grant any more — including the key that used to manage it.
    let orphaned = send(&app, json_request("GET", "/api/hooks", &manager, None)).await;
    assert_eq!(orphaned.json.as_array().map(Vec::len), Some(0), "the ex-manager sees nothing");
    assert_eq!(
        send(&app, json_request("GET", &format!("/api/hooks/{hook}"), &manager, None)).await.status,
        StatusCode::NOT_FOUND,
        "and cannot reach it directly either"
    );

    // The master still lists it...
    let listed = send(&app, json_request("GET", "/api/hooks", &master, None)).await;
    let names: Vec<&str> =
        listed.json.as_array().expect("a list").iter().filter_map(|h| h["name"].as_str()).collect();
    assert!(
        names.contains(&"ungoverned_hook"),
        "an ungoverned hook must not disappear from the master's listing: {names:?}"
    );

    // ...can read it by id and by name...
    for reference in [hook.to_string(), "ungoverned_hook".to_owned()] {
        let detail =
            send(&app, json_request("GET", &format!("/api/hooks/{reference}"), &master, None)).await;
        assert_eq!(detail.status, StatusCode::OK, "master reads {reference} on an ungoverned hook");
        assert_eq!(detail.json["name"], json!("ungoverned_hook"));
    }

    // ...can still execute and manage it, so it is not merely readable...
    assert_eq!(
        send(&app, json_request("POST", &format!("/api/hooks/{hook}/execute"), &master, Some(json!({}))))
            .await
            .status,
        StatusCode::OK,
        "an ungoverned hook is still executable by a master"
    );

    // ...and, decisively, can put it back under governance.
    let regrant = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{manager_id}/permissions"),
            &master,
            Some(json!({ "hook_id": hook.to_string(), "can_execute": true, "can_manage": true })),
        ),
    )
    .await;
    assert_eq!(regrant.status, StatusCode::OK, "a master can re-grant on an ungoverned hook");

    let restored = send(&app, json_request("GET", "/api/hooks", &manager, None)).await;
    assert_eq!(
        restored.json.as_array().map(Vec::len),
        Some(1),
        "the hook is governed again and visible to its manager"
    );
}

/// `X-Timestamp` is validated before the API key is looked up.
///
/// Both orderings answer `401`, so the status alone proves nothing. The *message* does: paired with
/// an unknown key, only the freshness-first ordering can name the window — the other has already
/// failed the key lookup and answers "Invalid API Key". That makes this a genuine assertion about
/// which check ran first, not merely that the request was refused.
#[tokio::test]
async fn a_stale_timestamp_is_refused_before_the_api_key_is_looked_up() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let stale = (now_timestamp() - 3_600).to_string();
    let request = with_connect_info(
        axum::http::Request::builder()
            .method("GET")
            .uri("/api/hooks")
            .header("X-API-Key", "a-key-that-was-never-issued")
            .header("X-Timestamp", &stale)
            .header("X-Signature-256", "sha256=00"),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");

    let response = send(&app, request).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(
        response.raw.contains("window"),
        "the timestamp window must be what rejected this, not the key lookup: {}",
        response.raw
    );
    assert!(
        !response.raw.contains("Invalid API Key"),
        "reaching the key lookup means the ordering regressed: {}",
        response.raw
    );

    // Malformed is handled at the same point, and is likewise not coerced to 'now'.
    for malformed in ["not-a-number", "1700000000.5", ""] {
        let request = with_connect_info(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/hooks")
                .header("X-API-Key", "a-key-that-was-never-issued")
                .header("X-Timestamp", malformed)
                .header("X-Signature-256", "sha256=00"),
        )
        .body(axum::body::Body::empty())
        .expect("request builds");
        let response = send(&app, request).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "a malformed timestamp {malformed:?} must be refused"
        );
        assert!(
            !response.raw.contains("Invalid API Key"),
            "{malformed:?} reached the key lookup: {}",
            response.raw
        );
    }
}

/// Moving the window check earlier must not let it reach traffic it was never meant to judge.
///
/// The pre-check keys off the *shape* of the request — `X-Timestamp` alongside `X-Signature-256` —
/// because the mode that owns the window lives in the row the lookup fetches. That boundary is the
/// whole reason this is safe to hoist, so it is pinned here rather than left as an implementation
/// detail: an unsigned bearer request and a `BODY_ONLY` webhook both carry a stale timestamp
/// through untouched, exactly as they did before, while a signed one is refused.
#[tokio::test]
async fn hoisting_the_window_check_does_not_reach_unsigned_or_body_only_traffic() {
    use simply_hook_executor::entities::api_key::HmacMode;

    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("shape.sh", "#!/bin/sh\necho ok\n");

    let bearer = insert_key_full(&db, "bearer", "", KeyScopes::plain()).await;
    let sender = insert_key_with_mode(&db, "forgejo", "", KeyScopes::plain(), HmacMode::BodyOnly)
        .await;
    let hook = insert_hook(&db, "shaped_hook", &script, 30).await;
    grant(&db, sender.id, hook, true, false).await;

    let ancient = "1";

    // An unsigned bearer request: there is no signed material, so there is nothing for a window to
    // protect and the header is not the daemon's business.
    let unsigned = with_connect_info(
        axum::http::Request::builder()
            .method("GET")
            .uri("/api/hooks")
            .header("X-API-Key", bearer.plaintext.as_str())
            .header("X-Timestamp", ancient),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(
        send(&app, unsigned).await.status,
        StatusCode::OK,
        "an unsigned request's stray timestamp is still ignored"
    );

    // A `BODY_ONLY` webhook, whose sender's format we do not control: the timestamp is not part of
    // its signed material, so rejecting over it would break the integration this mode exists for.
    let body = json!({}).to_string();
    let webhook = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri("/webhook/shaped_hook")
            .header("X-API-Key", sender.plaintext.as_str())
            .header("Content-Type", "application/json")
            .header("X-Timestamp", ancient)
            .header("X-Hub-Signature-256", sign_body_only(&sender.signing_secret, &body)),
    )
    .body(axum::body::Body::from(body))
    .expect("request builds");
    assert_eq!(
        send(&app, webhook).await.status,
        StatusCode::OK,
        "a body-only sender's stray timestamp is still ignored"
    );

    // The canonical shape — both headers — is where the window applies, and it is enforced before
    // the key is ever looked up.
    let signed_shape = with_connect_info(
        axum::http::Request::builder()
            .method("GET")
            .uri("/api/hooks")
            .header("X-API-Key", bearer.plaintext.as_str())
            .header("X-Timestamp", ancient)
            .header("X-Signature-256", "sha256=00"),
    )
    .body(axum::body::Body::empty())
    .expect("request builds");
    assert_eq!(send(&app, signed_shape).await.status, StatusCode::UNAUTHORIZED);
}

// ═════════════════════════════════════════════════════════════
// Master key pinning
// ═════════════════════════════════════════════════════════════

/// **Master pinning** — flipping `is_master` on a row the process did not pin has zero effect.
///
/// The whole authorization model branches on `api_key::Model::is_master`, read from a column on
/// every request. An attacker who reaches the database needs one `UPDATE` to become Master. §5's
/// uniqueness constraint refuses that statement, and this is the second line: even if the constraint
/// were dropped, the *running process* has already decided who the Master is.
///
/// The tamper is applied with raw SQL after the pin is established, which is exactly the shape of
/// the attack — the application is never asked, and never gets a chance to refuse the write.
#[tokio::test]
async fn a_hot_flipped_is_master_row_confers_nothing_on_the_running_process() {
    let db = setup_test_db().await;
    let state = test_state(&db);
    let app = create_app(state.clone());

    let (real_master_id, real_master) = insert_key(&db, "the-master", "", KeyScopes::master()).await;
    let (impostor_id, impostor) = insert_key(&db, "impostor", "", KeyScopes::plain()).await;

    // One authenticated request establishes the pin from a database holding exactly one master.
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &real_master, None)).await.status,
        StatusCode::OK
    );
    assert_eq!(state.master_pin.get(), Some(real_master_id), "the real master was pinned");

    // The tamper. No endpoint can do this — `is_master` is not a field on any payload — so it goes
    // in behind the application's back. Written through the entity layer rather than as a SQL
    // string because a `Uuid` is not bound as text on every backend, so a hand-written
    // `WHERE id = '...'` silently matches nothing and the test would pass without tampering at all.
    // What matters here is bypassing the *application*, which this does completely.
    let promote = |db: sea_orm::DatabaseConnection| async move {
        ApiKey::update_many()
            .col_expr(api_key::Column::IsMaster, sea_orm::sea_query::Expr::value(true))
            .filter(api_key::Column::Id.eq(impostor_id))
            .exec(&db)
            .await
    };

    // §5 first: the constraint refuses a second master outright, and pinning is the layer *behind*
    // it rather than a replacement for it.
    assert!(
        promote(db.clone()).await.is_err(),
        "§5: the database itself must refuse a second master"
    );

    // So take the constraint out of the picture, which is the situation pinning exists for: an
    // attacker who can write the schema as well as the rows.
    db.execute_unprepared("DROP INDEX idx_api_keys_master_marker")
        .await
        .expect("dropping the index models an attacker who reached the schema");
    promote(db.clone()).await.expect("with the constraint gone, the row flips");

    // The database now says two keys are master.
    assert_eq!(
        ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .all(&db)
            .await
            .expect("query")
            .len(),
        2,
        "the tamper landed — this test is worthless if it did not"
    );

    // And it buys nothing. The impostor is refused everywhere master authority is required.
    let me = send(&app, json_request("GET", "/api/auth/me", &impostor, None)).await;
    assert_eq!(me.status, StatusCode::OK, "the impostor is still a valid key");
    assert_eq!(
        me.field("is_master"),
        &json!(false),
        "the impostor must not be *reported* as master either: {}",
        me.raw
    );

    for (method, uri, body) in [
        ("GET", "/api/settings", None),
        ("GET", "/api/audit-logs", None),
        ("POST", "/api/keys", Some(json!({ "name": "minted-by-impostor" }))),
        ("GET", "/api/hooks?include_deleted=true", None),
    ] {
        let response = send(&app, json_request(method, uri, &impostor, body)).await;
        assert_ne!(
            response.status,
            StatusCode::OK,
            "{method} {uri} honoured a hot-flipped is_master: {}",
            response.raw
        );
    }

    // The genuine master is unaffected — pinning must not break the key it pinned.
    assert_eq!(
        send(&app, json_request("GET", "/api/settings", &real_master, None)).await.status,
        StatusCode::OK,
        "the pinned master still works"
    );
}

/// The pin is established once and never re-read, so a *later* database state cannot move it.
#[tokio::test]
async fn the_master_pin_is_resolved_once_and_never_moves() {
    let db = setup_test_db().await;
    let state = test_state(&db);
    let app = create_app(state.clone());

    let (first_id, first) = insert_key(&db, "first-master", "", KeyScopes::master()).await;
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &first, None)).await.status,
        StatusCode::OK
    );
    assert_eq!(state.master_pin.get(), Some(first_id));

    // Delete the pinned master and mint a different one. A process that re-read the database would
    // now follow the new row; a pinned one does not, and requires a restart to notice.
    //
    // Through the entity layer for the same reason as above — a `Uuid` in a hand-written `WHERE`
    // clause is not portably text, and a `DELETE` matching nothing would leave two masters and fail
    // the *next* insert instead of this assertion.
    ApiKey::delete_by_id(first_id)
        .exec(&db)
        .await
        .expect("the master row is deletable directly in the database");
    let (second_id, second) = insert_key(&db, "second-master", "", KeyScopes::master()).await;

    assert_eq!(state.master_pin.get(), Some(first_id), "the pin did not move");
    assert_ne!(second_id, first_id);

    let me = send(&app, json_request("GET", "/api/auth/me", &second, None)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(
        me.field("is_master"),
        &json!(false),
        "a master minted after the pin is not this process's master until it restarts: {}",
        me.raw
    );
}

// ═════════════════════════════════════════════════════════════
// Daughter keys, hook ownership, and delegation
// ═════════════════════════════════════════════════════════════

/// **R4** — a Parent key cannot mint another Parent, nor a hook creator.
///
/// > *Only the Master key may grant `can_manage_keys` or any resource-creation right. A parent key
/// > can never mint another parent key.*
///
/// Refused rather than silently forced to `false`. A `200` carrying a key that lacks what was asked
/// for is the worse failure: the caller walks away believing it provisioned a Parent, and finds out
/// when that key fails in production.
#[tokio::test]
async fn a_parent_key_can_only_mint_daughter_keys() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let (_parent_id, parent) = insert_key(&db, "parent", "", KeyScopes::parent()).await;

    for scope in ["can_manage_keys", "can_manage_hooks"] {
        let refused = send(
            &app,
            json_request("POST", "/api/keys", &parent, Some(json!({ "name": scope, scope: true }))),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "R4: a Parent minted a key holding '{scope}': {}",
            refused.raw
        );
        assert!(refused.raw.contains(scope), "the refusal names the scope: {}", refused.raw);

        // And nothing was created — a refusal that still writes the row is not a refusal.
        let listed = send(&app, json_request("GET", "/api/keys", &master, None)).await;
        assert!(
            !listed.raw.contains(&format!("\"name\":\"{scope}\"")),
            "R4: the refused key was created anyway: {}",
            listed.raw
        );
    }

    // A Daughter is fine, and is what a Parent may mint.
    let daughter = send(
        &app,
        json_request("POST", "/api/keys", &parent, Some(json!({ "name": "ordinary-daughter" }))),
    )
    .await;
    assert_eq!(daughter.status, StatusCode::OK, "a Parent may mint a Daughter: {}", daughter.raw);

    // Escalating an existing key is the same rule on the update route.
    let target_id = daughter.string("id");
    for scope in ["can_manage_keys", "can_manage_hooks"] {
        let refused = send(
            &app,
            json_request("PUT", &format!("/api/keys/{target_id}"), &parent, Some(json!({ scope: true }))),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "R4: a Parent granted '{scope}' by update: {}",
            refused.raw
        );
    }

    // Master may do both, or the refusals above could be explained by the route being broken.
    let promoted = send(
        &app,
        json_request("POST", "/api/keys", &master, Some(json!({ "name": "real-parent", "can_manage_keys": true }))),
    )
    .await;
    assert_eq!(promoted.status, StatusCode::OK, "master may mint a Parent: {}", promoted.raw);
}

/// **§3 + R2** — owning a hook is authority over the hook, not over who else may reach it.
///
/// The two halves are deliberately in one test, because the whole point is that they diverge for the
/// same caller on the same hook. A Daughter that created a hook may rewrite what it executes; it may
/// not hand that capability to anybody else, including itself.
#[tokio::test]
async fn a_hook_owner_may_edit_it_but_may_not_delegate_rights_on_it() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let original = scripts.write_script("owned.sh", "#!/bin/sh\necho original\n");
    let replacement = scripts.write_script("replacement.sh", "#!/bin/sh\necho replaced\n");

    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    // A Daughter with the creation right and nothing else: no `can_manage_keys`, so R2's conjunction
    // is out of reach for it entirely.
    let (owner_id, owner) =
        insert_key(&db, "creator", "", KeyScopes::hook_manager()).await;

    let created = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &owner,
            Some(json!({ "name": "owned_hook", "script_path": original })),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "the daughter may create a hook: {}", created.raw);
    let hook_id = created.string("id");
    assert_eq!(created.field("is_owner"), &json!(true), "the creator is the owner");

    // ── It may maintain what it owns ────────────────────────────────────────
    for (label, body) in [
        ("its description", json!({ "description": "maintained by its owner" })),
        ("its script_path", json!({ "script_path": replacement })),
        ("its timeout", json!({ "default_timeout_seconds": 45 })),
        ("its name", json!({ "name": "renamed_by_owner" })),
    ] {
        let edited = send(
            &app,
            json_request("PUT", &format!("/api/hooks/{hook_id}"), &owner, Some(body)),
        )
        .await;
        assert_eq!(
            edited.status,
            StatusCode::OK,
            "§3: the owner could not edit {label} of its own hook: {}",
            edited.raw
        );
    }

    let param = send(
        &app,
        json_request(
            "POST",
            &format!("/api/hooks/{hook_id}/parameters"),
            &owner,
            Some(json!({ "param_key": "target", "default_value": "x" })),
        ),
    )
    .await;
    assert_eq!(param.status, StatusCode::OK, "the owner declares parameters: {}", param.raw);

    // It can see it, which `visible_hook_ids` has to agree with or the hook would be
    // editable-but-unlistable.
    let listed = send(&app, json_request("GET", "/api/hooks", &owner, None)).await;
    assert!(listed.raw.contains("renamed_by_owner"), "the owner sees its own hook: {}", listed.raw);

    // ── It may not delegate ─────────────────────────────────────────────────
    let (target_id, _target) = insert_key(&db, "someone-else", "", KeyScopes::plain()).await;
    set_parent(&db, target_id, owner_id).await;

    let delegation = send(
        &app,
        json_request(
            "POST",
            &format!("/api/keys/{target_id}/permissions"),
            &owner,
            Some(json!({ "hook_id": hook_id, "can_execute": true, "can_manage": false })),
        ),
    )
    .await;
    assert_eq!(
        delegation.status,
        StatusCode::FORBIDDEN,
        "R2: owning a hook let its owner hand out rights on it without can_manage_keys: {}",
        delegation.raw
    );

    // Revocation is the same rule from the other direction — R6 lowers the bar to "manage rights on
    // the resource", and the owner does not have those in R2's sense.
    grant(&db, target_id, Uuid::parse_str(&hook_id).expect("hook id is a uuid"), true, false).await;
    let revocation = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/keys/{target_id}/permissions/{hook_id}"),
            &owner,
            None,
        ),
    )
    .await;
    assert_eq!(
        revocation.status,
        StatusCode::FORBIDDEN,
        "R2: the owner revoked a grant without holding can_manage_keys: {}",
        revocation.raw
    );

    // Master can do what the owner could not, so the refusals are about the caller and not the route.
    assert_eq!(
        send(
            &app,
            json_request(
                "POST",
                &format!("/api/keys/{target_id}/permissions"),
                &master,
                Some(json!({ "hook_id": hook_id, "can_execute": true, "can_manage": false })),
            ),
        )
        .await
        .status,
        StatusCode::OK,
        "master may delegate on the same hook"
    );
}
