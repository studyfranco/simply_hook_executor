//! Integration tests covering the mandatory matrix from `AGENT.MD`: positive assertions,
//! authentication (401), authorization boundaries (403), input validation (400), concurrency
//! throttling (429), and execution timeouts — plus the security properties the execution engine
//! is responsible for (no shell, cleared environment, process-group kill).

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use sea_orm::EntityTrait;
use serde_json::json;
use simply_hook_executor::{
    config::RuntimeConfig, create_app, entities::prelude::Execution,
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

    let canonical = || signed_request("POST", uri, &subject.plaintext, &subject.signing_secret, &body);
    let body_only = || body_only_request(uri, &subject.plaintext, &subject.signing_secret, &body, "X-Hub-Signature-256");

    // Starting state: canonical accepted, body-only refused.
    assert_eq!(send(&app, canonical()).await.status, StatusCode::OK);
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
        send(&app, canonical()).await.status,
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

    assert_eq!(send(&app, canonical()).await.status, StatusCode::OK, "canonical should be accepted again");
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

    // Just under the 1 MiB buffer bound: still accepted.
    let near_limit_padding = "z".repeat(1024 * 1024 - 4096);
    let near_limit_body = json!({ "parameters": { "marker": "near" }, "padding": near_limit_padding }).to_string();
    assert!(near_limit_body.len() < 1024 * 1024, "must stay under the buffer limit");
    let response = send(
        &app,
        signed_request("POST", uri, &sender.plaintext, &sender.signing_secret, &near_limit_body),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "a body just under the limit should be accepted");

    // Over the bound: refused before any hashing or execution, with an explanatory error rather
    // than a hang or an OOM.
    let oversized_padding = "w".repeat(2 * 1024 * 1024);
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
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .expect("a hook is insertable after the upgrade");
    assert_eq!(legacy.run_as_user, None, "an unelevated hook keeps running as the daemon user");

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
    // A fully-scoped non-master: it may create hooks, it simply may not elevate them.
    let (_, manager) = insert_key(&db, "Hook Manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;
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
    let (manager_id, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::plain()).await;
    let (_, stranger) = insert_key(&db, "Stranger", "0.0.0.0/0", KeyScopes::plain()).await;

    let hook_id = insert_hook(&db, "granular", &script, 30).await;
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
        assert_eq!(
            send(&app, json_request(method, uri, &stranger, body)).await.status,
            StatusCode::FORBIDDEN,
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

#[tokio::test]
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

    if !std::path::Path::new("/usr/bin/sudo").exists() {
        eprintln!("skipping: /usr/bin/sudo is not installed");
        return;
    }

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
    let (_, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;

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
    let (_, manager) = insert_key(&db, "Manager", "0.0.0.0/0", KeyScopes::hook_manager()).await;

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
        test_cipher(),
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
#[tokio::test]
async fn a_setsid_child_leaves_the_process_group_and_survives_the_timeout_kill() {
    // `setsid(1)` is util-linux, not POSIX; without it there is nothing to measure.
    let has_setsid = std::process::Command::new("sh")
        .args(["-c", "command -v setsid >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !has_setsid {
        eprintln!("skipping: setsid(1) is not available on this system");
        return;
    }

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
// a unit test of `require_master_to_grant_scopes` would keep passing if a handler stopped calling
// it, which is precisely the regression worth catching.
// ─────────────────────────────────────────────────────────────

/// Seeds a non-master key holding the `can_manage_keys` scope — the credential every finding in
/// this group started from.
async fn seed_key_manager(db: &sea_orm::DatabaseConnection) -> (Uuid, String) {
    let scopes = KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() };
    insert_key(db, "key-manager", "", scopes).await
}

/// Finding #1 — `can_manage_keys` could mint a key with `is_master: true` and become master.
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
    assert_eq!(res.status, StatusCode::FORBIDDEN, "minting a master key must be refused");
    assert!(res.string("error").contains("is_master"), "the refusal names the offending scope");

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
    let (_id, manager) = seed_key_manager(&db).await;
    let (victim_id, _victim) = insert_key(&db, "ordinary", "", KeyScopes::plain()).await;

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

    let rotate = send(&app, json_request("POST", &format!("/api/keys/{master_id}/rotate"), &manager, None)).await;
    assert_eq!(rotate.status, StatusCode::FORBIDDEN, "rotating a master key must be refused");
    assert!(rotate.json.get("plaintext_key").is_none(), "no secret may leak in the refusal body");

    let update = send(
        &app,
        json_request("PUT", &format!("/api/keys/{master_id}"), &manager, Some(json!({ "bound_ips": "0.0.0.0/0" }))),
    )
    .await;
    assert_eq!(update.status, StatusCode::FORBIDDEN, "editing a master key must be refused");

    let delete = send(&app, json_request("DELETE", &format!("/api/keys/{master_id}"), &manager, None)).await;
    assert_eq!(delete.status, StatusCode::FORBIDDEN, "deleting a master key must be refused");

    // The master credential still works, so none of the refused calls partially applied.
    let me = send(&app, json_request("GET", "/api/auth/me", &master, None)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.field("is_master"), &json!(true));

    // A master peer may still administer it — the gate is "master only", not "nobody".
    let by_master = send(&app, json_request("POST", &format!("/api/keys/{master_id}/rotate"), &master, None)).await;
    assert_eq!(by_master.status, StatusCode::OK);
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

    // Granting to somebody else on a hook the caller does not manage is refused too — otherwise the
    // exploit is one extra key away.
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
    assert_eq!(third_party.status, StatusCode::FORBIDDEN, "granting on an unmanaged hook must be refused");

    // The grant never landed: the manager still cannot reach the privileged hook.
    let probe = send(&app, json_request("POST", &format!("/api/hooks/{privileged}/test"), &manager, None)).await;
    assert_eq!(probe.status, StatusCode::FORBIDDEN);

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
    let (key_id, editor) = insert_key(&db, "hook-editor", "", KeyScopes::plain()).await;
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
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));

    let (_id, bound_master) = insert_key(&db, "bound-master", "10.0.0.0/8", KeyScopes::master()).await;
    let res = send(&app, json_request("GET", "/api/auth/me", &bound_master, None)).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "a bound master key is held to its own allowlist");

    // A master key that should reach the API from anywhere says so by leaving bound_ips empty...
    let (_id, free_master) = insert_key(&db, "free-master", "", KeyScopes::master()).await;
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &free_master, None)).await.status,
        StatusCode::OK
    );

    // ...or by naming ranges that actually include the caller.
    let (_id, local_master) = insert_key(&db, "local-master", "127.0.0.0/8,::1/128", KeyScopes::master()).await;
    assert_eq!(
        send(&app, json_request("GET", "/api/auth/me", &local_master, None)).await.status,
        StatusCode::OK
    );
}
