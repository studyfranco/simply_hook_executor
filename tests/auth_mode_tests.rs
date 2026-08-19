//! Per-hook inbound authentication modes (`Hook.auth_mode`): `CANONICAL_V1` with a custom
//! canonical template, `HMAC_ONLY` with a hook-level secret, `API_KEY_ONLY`, and `NONE`.
//!
//! Every scenario here targets one of the three hook-invocation routes
//! (`POST /api/hooks/{id}/execute`, `POST /api/hooks/{id}/test`, `POST /webhook/{identifier}`),
//! which alone may authorize a caller presenting no `X-API-Key` — see
//! `simply_hook_executor::middleware::invocation_auth_middleware`. Every other route keeps
//! requiring a key exactly as before this feature existed; that is covered by the existing suites,
//! not repeated here.

#[allow(dead_code)]
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use simply_hook_executor::create_app;

/// Builds a request with **no** `X-API-Key` header at all — the shape every keyless scenario here
/// exercises.
fn keyless_request(method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let builder =
        with_connect_info(Request::builder().method(method).uri(uri).header("Content-Type", "application/json"));
    let body = match body {
        Some(value) => Body::from(value.to_string()),
        None => Body::empty(),
    };
    builder.body(body).expect("request builds")
}

/// Builds a keyless request carrying a raw signature on a named header, with a caller-chosen
/// prefix — the shape `HMAC_ONLY` senders (and the tests probing it) use.
fn hmac_only_request(
    method: &str,
    uri: &str,
    body: &str,
    header: &str,
    prefix: &str,
    secret: &str,
) -> Request<Body> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    let signature = format!("{prefix}{}", hex::encode(mac.finalize().into_bytes()));
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("Content-Type", "application/json")
            .header(header, signature),
    )
    .body(Body::from(body.to_owned()))
    .expect("request builds")
}

/// Computes a `CANONICAL_V1`-shaped signature over an arbitrary template, substituting the same
/// four placeholders `crypto::render_canonical_template` does. Used to sign against a hook's custom
/// `canonical_template` without depending on that function being correct — an independent
/// computation is what makes the assertion mean something.
fn sign_with_template(
    secret: &str,
    template: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &str,
) -> String {
    let base = template
        .replace("{method}", method)
        .replace("{path}", path)
        .replace("{timestamp}", timestamp)
        .replace("{body}", body);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(base.as_bytes());
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn signed_request_with_signature(
    method: &str,
    uri: &str,
    api_key: &str,
    timestamp: i64,
    body: &str,
    signature: &str,
) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", signature),
    )
    .body(Body::from(body.to_owned()))
    .expect("request builds")
}

// ─────────────────────────────────────────────────────────────
// 1. CANONICAL_V1 with a custom canonical template
// ─────────────────────────────────────────────────────────────

/// A keyed `CANONICAL_V1` caller signing against a hook's custom `canonical_template` succeeds; the
/// same request signed against the *service-wide default* template fails — proving the override is
/// actually consulted, not merely stored.
#[tokio::test]
async fn canonical_v1_custom_template_is_verified_against_and_the_default_is_refused() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("template_hook.sh", "#!/bin/sh\necho ok\n");

    let (master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let _ = master_id;

    let template = "{method}|{path}|{timestamp}|{body}";
    let create = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "template_hook",
                "script_path": script,
                "canonical_template": template
            })),
        ),
    )
    .await;
    assert_eq!(create.status, StatusCode::OK, "{}", create.raw);
    let hook_id = create.string("id");
    assert_eq!(create.field("auth_mode").as_str(), Some("CANONICAL_V1"));
    assert_eq!(create.field("canonical_template").as_str(), Some(template));

    let caller = insert_key_full(&db, "template-caller", "0.0.0.0/0", KeyScopes::plain()).await;
    grant(&db, caller.id, uuid::Uuid::parse_str(&hook_id).unwrap(), true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let body = "{}";
    let ts = now_timestamp();

    let custom_sig = sign_with_template(&caller.signing_secret, template, "POST", &uri, &ts.to_string(), body);
    let ok = send(&app, signed_request_with_signature("POST", &uri, &caller.plaintext, ts, body, &custom_sig)).await;
    assert_eq!(ok.status, StatusCode::OK, "custom-template signature must verify: {}", ok.raw);

    // The default (newline-joined) template, over the identical request, must NOT verify — proving
    // the hook's override actually replaced it rather than being consulted only cosmetically.
    let default_sig = sign_request(&caller.signing_secret, "POST", &uri, ts, body);
    let refused =
        send(&app, signed_request_with_signature("POST", &uri, &caller.plaintext, ts, body, &default_sig)).await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "a signature over the service-wide default template must be refused once the hook overrides it: {}",
        refused.raw
    );
}

/// A hook that does **not** set `canonical_template` is signed exactly as before this feature
/// existed — the override must never leak backwards onto ordinary hooks.
#[tokio::test]
async fn a_hook_with_no_template_override_still_signs_the_service_wide_default() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("default_template_hook.sh", "#!/bin/sh\necho ok\n");

    let hook_id = insert_hook(&db, "default_template_hook", &script, 30).await;
    let caller = insert_key_full(&db, "default-caller", "0.0.0.0/0", KeyScopes::plain()).await;
    grant(&db, caller.id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let response = send(&app, signed_request("POST", &uri, &caller.plaintext, &caller.signing_secret, "{}")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.raw);
}

// ─────────────────────────────────────────────────────────────
// 2. auth_mode does not exist on ApiKey; canonical_template does, but is admin-locked
// ─────────────────────────────────────────────────────────────

/// `auth_mode` is a hook-level field only; `ApiKey`'s own signature mode stays exactly `hmac_mode`
/// (`CANONICAL_V1` — the only value left, since `BODY_ONLY` was retired). Naming `auth_mode` on a
/// key payload is an unrecognized field under `deny_unknown_fields`, not a silently-accepted no-op.
///
/// `canonical_template`, unlike `auth_mode`, genuinely *is* an `ApiKey` field (added the session
/// this feature shipped, per the reopened design decision — see `entities/api_key.rs`'s doc
/// comment). An ordinary, non-`can_manage_keys` key may set one freely; only a `can_manage_keys`
/// key is refused, which is covered by the dedicated admin-lock test below rather than here.
#[tokio::test]
async fn auth_mode_is_not_recognized_on_api_key_payloads_but_canonical_template_is() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let refused = send(
        &app,
        json_request(
            "POST",
            "/api/keys",
            &master,
            Some(json!({ "name": "x", "auth_mode": "NONE" })),
        ),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "auth_mode is a hook concept, not an ApiKey one: {}",
        refused.raw
    );

    let permitted_template = send(
        &app,
        json_request(
            "POST",
            "/api/keys",
            &master,
            Some(json!({ "name": "y", "canonical_template": "{method}|{path}|{timestamp}|{body}" })),
        ),
    )
    .await;
    assert_eq!(
        permitted_template.status,
        StatusCode::OK,
        "an ordinary (non-admin) key may set canonical_template: {}",
        permitted_template.raw
    );
}

// ─────────────────────────────────────────────────────────────
// 3. can_manage_keys stays mandatory-CANONICAL_V1 on invocation routes too
// ─────────────────────────────────────────────────────────────

/// The mandatory-signing rule for `can_manage_keys` holders (`middleware::authenticate_bearer_key`)
/// is shared between `auth_middleware` and `invocation_auth_middleware`'s keyed branch. This pins
/// that sharing actually holds on a hook-invocation route, with `REQUIRE_SIGNED_REQUESTS=false`
/// globally — an unsigned request from a `can_manage_keys` holder must still be refused here, not
/// only on administrative routes.
#[tokio::test]
async fn a_can_manage_keys_holder_must_sign_even_on_an_invocation_route() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db)); // REQUIRE_SIGNED_REQUESTS = false
    let scripts = ScriptDir::new();
    let script = scripts.write_script("admin_invoke_hook.sh", "#!/bin/sh\necho ok\n");

    let hook_id = insert_hook(&db, "admin_invoke_hook", &script, 30).await;
    let admin = insert_key_full(
        &db,
        "key-admin",
        "0.0.0.0/0",
        KeyScopes { can_manage_keys: true, max_concurrent_jobs: 10, ..Default::default() },
    )
    .await;
    grant(&db, admin.id, hook_id, true, false).await;

    let uri = format!("/api/hooks/{hook_id}/execute");
    let unsigned = send(&app, json_request("POST", &uri, &admin.plaintext, Some(json!({})))).await;
    assert_eq!(
        unsigned.status,
        StatusCode::UNAUTHORIZED,
        "a can_manage_keys holder must sign even here: {}",
        unsigned.raw
    );

    let signed = send(&app, signed_request("POST", &uri, &admin.plaintext, &admin.signing_secret, "{}")).await;
    assert_eq!(signed.status, StatusCode::OK, "{}", signed.raw);
}

// ─────────────────────────────────────────────────────────────
// 4. NONE — REQUIRE_SIGNED_REQUESTS gates it
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn none_mode_is_keyless_reachable_only_when_signing_is_not_globally_mandatory() {
    let db = setup_test_db().await;
    let permissive_app = create_app(test_state(&db)); // REQUIRE_SIGNED_REQUESTS = false
    let scripts = ScriptDir::new();
    let script = scripts.write_script("public_hook.sh", "#!/bin/sh\necho public\n");

    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;
    let create = send(
        &permissive_app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": "public_hook", "script_path": script, "auth_mode": "NONE" })),
        ),
    )
    .await;
    assert_eq!(create.status, StatusCode::OK, "{}", create.raw);
    assert_eq!(create.field("auth_mode").as_str(), Some("NONE"));

    let request = keyless_request("POST", "/api/hooks/public_hook/execute", Some(json!({})));
    let response = send(&permissive_app, request).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "REQUIRE_SIGNED_REQUESTS=false: a NONE hook must accept a keyless caller: {}",
        response.raw
    );

    // Same hook, same database — but a *second* app instance built with signing mandatory
    // globally. NONE must not carve out an exception to that posture.
    let strict_app = create_app(test_state_requiring_signatures(&db));
    let refused = send(&strict_app, keyless_request("POST", "/api/hooks/public_hook/execute", Some(json!({}))))
        .await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "REQUIRE_SIGNED_REQUESTS=true must block a NONE hook's keyless path too: {}",
        refused.raw
    );

    // The refusal is indistinguishable from a keyless request naming a hook that requires a key —
    // no oracle for "this hook exists and is configured NONE, but currently blocked".
    let unrelated_key_required =
        send(&strict_app, keyless_request("POST", "/api/hooks/does_not_exist/execute", Some(json!({})))).await;
    assert_eq!(refused.status, unrelated_key_required.status);
    assert_eq!(refused.raw, unrelated_key_required.raw);
}

// ─────────────────────────────────────────────────────────────
// 5. HMAC_ONLY — hook-level secret, custom header, custom prefix
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn hmac_only_verifies_against_the_hooks_own_secret_header_and_prefix() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("webhook_style_hook.sh", "#!/bin/sh\necho ok\n");
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let create = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "webhook_style_hook",
                "script_path": script,
                "auth_mode": "HMAC_ONLY",
                "hmac_secret": "correct-horse-battery-staple",
                "signature_header": "X-Custom-Signature",
                "signature_prefix": "hmac="
            })),
        ),
    )
    .await;
    assert_eq!(create.status, StatusCode::OK, "{}", create.raw);
    assert_eq!(create.field("auth_mode").as_str(), Some("HMAC_ONLY"));
    assert_eq!(create.field("hmac_secret_configured"), &json!(true));
    assert_eq!(create.field("signature_header").as_str(), Some("X-Custom-Signature"));
    assert_eq!(create.field("signature_prefix").as_str(), Some("hmac="));
    // The secret itself is never echoed back, in any field.
    assert!(!create.raw.contains("correct-horse-battery-staple"));

    let body = json!({}).to_string();
    let uri = "/api/hooks/webhook_style_hook/execute";

    let valid = hmac_only_request(
        "POST",
        uri,
        &body,
        "X-Custom-Signature",
        "hmac=",
        "correct-horse-battery-staple",
    );
    let ok = send(&app, valid).await;
    assert_eq!(ok.status, StatusCode::OK, "a correctly signed HMAC_ONLY request must succeed: {}", ok.raw);

    // Wrong secret.
    let bad_secret = hmac_only_request("POST", uri, &body, "X-Custom-Signature", "hmac=", "wrong-secret");
    let refused = send(&app, bad_secret).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.raw);

    // Correct secret, but on the *default* header instead of the configured one — must not verify,
    // proving the custom header is actually what is consulted.
    let wrong_header = hmac_only_request(
        "POST",
        uri,
        &body,
        "X-Signature-256",
        "hmac=",
        "correct-horse-battery-staple",
    );
    let refused_header = send(&app, wrong_header).await;
    assert_eq!(
        refused_header.status,
        StatusCode::UNAUTHORIZED,
        "a signature on the wrong header must not be found: {}",
        refused_header.raw
    );

    // No signature at all: identical refusal to a hook that simply requires a key — no oracle.
    let bare = keyless_request("POST", uri, Some(json!({})));
    let bare_response = send(&app, bare).await;
    assert_eq!(bare_response.status, StatusCode::UNAUTHORIZED);
}

/// Creating (or updating into) `HMAC_ONLY` with no secret configured is refused outright — an
/// unusable public endpoint is a misconfiguration worth catching at write time, not discovering the
/// first time a legitimate sender's request inexplicably fails to verify.
#[tokio::test]
async fn hmac_only_requires_a_secret_at_creation_and_on_update() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("secretless_hook.sh", "#!/bin/sh\necho ok\n");
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let refused = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": "secretless_hook", "script_path": script, "auth_mode": "HMAC_ONLY" })),
        ),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.raw);

    let ordinary = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": "ordinary_then_switched", "script_path": script })),
        ),
    )
    .await;
    assert_eq!(ordinary.status, StatusCode::OK, "{}", ordinary.raw);
    let hook_id = ordinary.string("id");

    let switch_refused = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook_id}"),
            &master,
            Some(json!({ "auth_mode": "HMAC_ONLY" })),
        ),
    )
    .await;
    assert_eq!(switch_refused.status, StatusCode::BAD_REQUEST, "{}", switch_refused.raw);

    let switch_with_secret = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/hooks/{hook_id}"),
            &master,
            Some(json!({ "auth_mode": "HMAC_ONLY", "hmac_secret": "now-set" })),
        ),
    )
    .await;
    assert_eq!(switch_with_secret.status, StatusCode::OK, "{}", switch_with_secret.raw);
}

// ─────────────────────────────────────────────────────────────
// 6. API_KEY_ONLY vs CANONICAL_V1: keyless refused, keyed always succeeds
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn api_key_only_refuses_keyless_and_accepts_any_permitted_key_exactly_like_canonical_v1() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("api_key_only_hook.sh", "#!/bin/sh\necho ok\n");
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let create = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({
                "name": "api_key_only_hook",
                "script_path": script,
                "auth_mode": "API_KEY_ONLY"
            })),
        ),
    )
    .await;
    assert_eq!(create.status, StatusCode::OK, "{}", create.raw);
    let hook_id = create.string("id");

    let uri = format!("/api/hooks/{hook_id}/execute");

    // Keyless: refused, identically to a CANONICAL_V1 hook's keyless refusal.
    let keyless = send(&app, keyless_request("POST", &uri, Some(json!({})))).await;
    assert_eq!(keyless.status, StatusCode::UNAUTHORIZED, "{}", keyless.raw);

    let canonical_hook_id = insert_hook(&db, "canonical_default_hook", &script, 30).await;
    let canonical_uri = format!("/api/hooks/{canonical_hook_id}/execute");
    let keyless_canonical = send(&app, keyless_request("POST", &canonical_uri, Some(json!({})))).await;
    assert_eq!(keyless.status, keyless_canonical.status);
    assert_eq!(keyless.raw, keyless_canonical.raw, "API_KEY_ONLY and CANONICAL_V1 must refuse a keyless caller identically — neither is a keyless mode");

    // Keyed, unsigned bearer-only request: succeeds — that is the whole point of API_KEY_ONLY, and
    // it is no different from what CANONICAL_V1 already permits when REQUIRE_SIGNED_REQUESTS=false.
    let caller = insert_key_full(&db, "api-key-only-caller", "0.0.0.0/0", KeyScopes::plain()).await;
    grant(&db, caller.id, uuid::Uuid::parse_str(&hook_id).unwrap(), true, false).await;
    let keyed = send(&app, json_request("POST", &uri, &caller.plaintext, Some(json!({})))).await;
    assert_eq!(keyed.status, StatusCode::OK, "{}", keyed.raw);
}

// ─────────────────────────────────────────────────────────────
// 7. Task 2 — uniform 401 on invocation routes (anti-enumeration)
// ─────────────────────────────────────────────────────────────

/// An invalid/unknown key and a bad signature/timestamp both collapse into the **identical** `401`
/// body on a hook-invocation route — the two true authentication failures Task 2 exists to make
/// indistinguishable, so a caller holding a guessed or stolen key string cannot learn from the
/// response alone whether that string names a real key. A genuinely valid key that merely lacks
/// `can_execute` is deliberately **not** folded in: that caller has already proven a real
/// credential, and `guard_execute`'s own `403` still answers with its own message.
#[tokio::test]
async fn unknown_key_and_bad_signature_produce_the_identical_401_on_invocation_routes() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("uniform_hook.sh", "#!/bin/sh\necho ok\n");

    let hook_id = insert_hook(&db, "uniform_hook", &script, 30).await;
    let key = insert_key_full(&db, "uniform-caller", "0.0.0.0/0", KeyScopes::plain()).await;
    grant(&db, key.id, hook_id, true, false).await;
    let uri = format!("/api/hooks/{hook_id}/execute");

    // Case 1: a key that does not exist at all.
    let unknown_key = send(&app, json_request("POST", &uri, "never-issued-key-0123456789", Some(json!({})))).await;
    assert_eq!(unknown_key.status, StatusCode::UNAUTHORIZED);

    // Case 2: a real key, wrong secret (bad signature).
    let ts = now_timestamp();
    let bad_sig = sign_request("not-the-real-secret", "POST", &uri, ts, "{}");
    let bad_signature = send(
        &app,
        signed_request_with_signature("POST", &uri, &key.plaintext, ts, "{}", &bad_sig),
    )
    .await;
    assert_eq!(bad_signature.status, StatusCode::UNAUTHORIZED);

    // Case 2b: a real key, valid secret, but a stale timestamp.
    let stale = send(
        &app,
        signed_request_with_signature(
            "POST",
            &uri,
            &key.plaintext,
            ts,
            "{}",
            &sign_request(&key.signing_secret, "POST", &uri, ts - 3600, "{}"),
        ),
    )
    .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);

    // All three must be byte-identical — status and body alike.
    assert_eq!(unknown_key.raw, bad_signature.raw, "unknown key vs bad signature must be indistinguishable");
    assert_eq!(unknown_key.raw, stale.raw, "unknown key vs stale timestamp must be indistinguishable");
    assert_eq!(unknown_key.field("error"), &json!("Unauthorized"));

    // Contrast: a genuinely *valid* key lacking `can_execute` gets a different, specific `403` —
    // this is authorization, not authentication, and must not be folded into the same oracle.
    // Holds a row on the hook (so it is *visible*, not merely absent) with `can_execute: false` —
    // §4 oracle discipline means a key with no row at all gets `404`, not `403`; the `403` case
    // needs a real, visible permission row that simply lacks the verb.
    let unpermitted = insert_key_full(&db, "no-execute-rights", "0.0.0.0/0", KeyScopes::plain()).await;
    grant(&db, unpermitted.id, hook_id, false, true).await;
    let forbidden = send(&app, json_request("POST", &uri, &unpermitted.plaintext, Some(json!({})))).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN, "{}", forbidden.raw);
    assert_ne!(forbidden.raw, unknown_key.raw, "a real, unpermitted key must not look like a bad credential");
}

/// The same uniformity holds on `POST /api/hooks/{id}/test` and `POST /webhook/{identifier}`, not
/// only on `/execute` — all three invocation routes share the one middleware.
#[tokio::test]
async fn the_uniform_401_covers_test_and_webhook_routes_too() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("uniform_hook2.sh", "#!/bin/sh\necho ok\n");
    let hook_id = insert_hook(&db, "uniform_hook_two", &script, 30).await;

    let test_uri = format!("/api/hooks/{hook_id}/test");
    let unknown_on_test = send(&app, json_request("POST", &test_uri, "not-a-real-key", Some(json!({})))).await;
    assert_eq!(unknown_on_test.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_on_test.field("error"), &json!("Unauthorized"));

    let webhook_uri = "/webhook/uniform_hook_two";
    let unknown_on_webhook = send(&app, json_request("POST", webhook_uri, "also-not-real", Some(json!({})))).await;
    assert_eq!(unknown_on_webhook.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_on_webhook.raw, unknown_on_test.raw);
}

// ─────────────────────────────────────────────────────────────
// 8. Task 3 — unexpected signature material is refused, not ignored
// ─────────────────────────────────────────────────────────────

/// A keyless request carrying signature material against a hook whose `auth_mode` does not use
/// one (`API_KEY_ONLY` or `NONE`) is refused outright, rather than silently succeeding with the
/// header ignored. The `NONE` case is the one where this is actually observable: without the
/// check, a stray or garbage signature on an otherwise-open hook would still be accepted.
#[tokio::test]
async fn unexpected_signature_material_is_refused_on_api_key_only_and_none_hooks() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("unexpected_sig_hook.sh", "#!/bin/sh\necho ok\n");
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    for mode in ["API_KEY_ONLY", "NONE"] {
        let name = format!("unexpected_sig_{}", mode.to_lowercase());
        let create = send(
            &app,
            json_request(
                "POST",
                "/api/hooks",
                &master,
                Some(json!({ "name": name, "script_path": script, "auth_mode": mode })),
            ),
        )
        .await;
        assert_eq!(create.status, StatusCode::OK, "{}", create.raw);

        let uri = format!("/api/hooks/{name}/execute");

        // A stray, garbage signature header — the request is otherwise a plain keyless request.
        let with_garbage_signature = with_connect_info(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Content-Type", "application/json")
                .header("X-Signature-256", "sha256=00"),
        )
        .body(Body::from("{}"))
        .expect("request builds");
        let response = send(&app, with_garbage_signature).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{mode}: unexpected signature material must be refused, not ignored: {}",
            response.raw
        );
        assert_eq!(response.field("error"), &json!("Unauthorized"));
    }
}

/// `NONE` specifically: absent this check, a stray signature on an otherwise fully-open hook would
/// have been silently ignored and the request would have succeeded — this proves the refusal is
/// real, not merely that *some* other reason already blocked the request.
#[tokio::test]
async fn a_none_hook_without_a_stray_signature_still_succeeds() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let scripts = ScriptDir::new();
    let script = scripts.write_script("open_hook.sh", "#!/bin/sh\necho open\n");
    let (_master_id, master) = insert_key(&db, "master", "", KeyScopes::master()).await;

    let create = send(
        &app,
        json_request(
            "POST",
            "/api/hooks",
            &master,
            Some(json!({ "name": "open_hook", "script_path": script, "auth_mode": "NONE" })),
        ),
    )
    .await;
    assert_eq!(create.status, StatusCode::OK, "{}", create.raw);

    let uri = "/api/hooks/open_hook/execute";

    // With a stray signature: refused.
    let with_signature = with_connect_info(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Content-Type", "application/json")
            .header("X-Signature-256", "sha256=00"),
    )
    .body(Body::from("{}"))
    .expect("request builds");
    assert_eq!(send(&app, with_signature).await.status, StatusCode::UNAUTHORIZED);

    // Without one: succeeds, proving the refusal above was really about the stray header.
    let clean = keyless_request("POST", uri, Some(json!({})));
    let response = send(&app, clean).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.raw);
}
