//! The `/health` and `/ready` probes: reachable without a credential, and silent about internals.
//!
//! These are the only unauthenticated routes in the service, so they get their own suite. Two
//! properties are load-bearing and neither is obvious from reading the handlers alone:
//!
//! 1. **No credential is required** — asserted by sending no headers at all, which is what an
//!    orchestrator actually does. A route accidentally moved inside the `/api` nest would still
//!    compile, still return JSON to an authenticated caller, and fail only here.
//! 2. **Nothing leaks** — a public endpoint that named the database, the version, or a row count
//!    would be free reconnaissance. The body is asserted field-by-field rather than merely parsed.

// `common` is shared by four test binaries and each compiles all of it, so the helpers this one
// does not call are unused *here* while having real callers next door. The crate-wide convention is
// to allow it at the import rather than inside `common`, which keeps `common`'s own no-blanket-allow
// rule intact.
#[allow(dead_code)]
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;

/// Builds application state whose Master identity is pinned, as production's is.
///
/// `test_state` deliberately leaves the pin unset — state is routinely built before the master row
/// exists. That is fine for the authenticated suites, which pin lazily on first request, but it is
/// the *wrong* model for readiness: `main.rs` calls `pin_at_boot` **before** binding the listener, so
/// a process serving traffic has always pinned. A fixture that never pins describes a process that
/// would never have accepted the connection.
///
/// The unpinned case is not untested — see
/// [`readiness_reports_unavailable_when_no_master_is_pinned`], which is the whole point of the check.
async fn pinned_state(db: &sea_orm::DatabaseConnection) -> simply_hook_executor::state::AppState {
    let (master_id, _) = insert_key(db, "Master", "", KeyScopes::master()).await;
    test_state(db).with_pinned_master(master_id)
}

/// Builds a request carrying **no** `X-API-Key` and no signature — the shape a probe really sends.
fn anonymous(uri: &str) -> Request<Body> {
    with_connect_info(Request::builder().method("GET").uri(uri))
        .body(Body::empty())
        .expect("building an anonymous request succeeds")
}

/// Both probes answer `200` to a caller holding no credential whatsoever.
///
/// The spellings are checked together because they are one route each in the router and it would be
/// entirely possible to mount `/health` correctly and `/healthz` inside the authenticated tree.
#[tokio::test]
async fn both_probes_answer_without_any_credential() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(pinned_state(&db).await);

    for uri in ["/health", "/healthz", "/ready", "/readyz"] {
        let response = send(&app, anonymous(uri)).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{uri} must be reachable with no API key; an orchestrator has none to send"
        );
    }
}

/// The liveness body is a fixed document and says nothing about runtime state.
#[tokio::test]
async fn liveness_reports_a_constant_document() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(test_state(&db));

    let response = send(&app, anonymous("/health")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.string("status"), "ok");
    assert_eq!(response.string("service"), "simply_hook_executor");

    // Exactly two fields. Asserted as a count rather than by listing absences, so a field added
    // later — a version, a hostname, an uptime — trips this test and has to be justified rather
    // than arriving unnoticed on a public endpoint.
    let object = response.json.as_object().expect("the body is a JSON object");
    assert_eq!(
        object.len(),
        2,
        "the public liveness body gained a field: {object:?} — every field here is disclosed to \
         anonymous callers"
    );
}

/// Readiness reports `up` while the pool is live.
#[tokio::test]
async fn readiness_reports_the_database_as_up_when_it_is() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(pinned_state(&db).await);

    let response = send(&app, anonymous("/ready")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.string("status"), "ready");
    assert_eq!(response.string("database"), "up");
}

/// A dead pool produces `503` and the word `down` — and nothing else.
///
/// This is the test the endpoint exists for, and it is the one that is easy to skip because
/// arranging a broken database is fiddly. Closing the connection is what makes it real: without
/// this, `readiness_check` would be indistinguishable from `health_check` in every test, and a
/// version that ignored its query result entirely and always answered `200` would pass the whole
/// suite above.
#[tokio::test]
async fn readiness_reports_unavailable_when_the_pool_is_gone() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(pinned_state(&db).await);

    // Confirm it is genuinely up first, so the failure below is caused by the close and not by the
    // fixture never having worked.
    assert_eq!(send(&app, anonymous("/ready")).await.status, StatusCode::OK);

    db.close().await.expect("closing the pool succeeds");

    let response = send(&app, anonymous("/ready")).await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a dead database must be 503 — the status that tells a proxy to stop routing here"
    );
    assert_eq!(response.string("status"), "unavailable");
    assert_eq!(response.string("database"), "down");

    // The driver error is logged, never returned. `DbErr` renders connection strings and driver
    // internals, and this endpoint is anonymous.
    let rendered = response.raw.clone();
    for leaked in ["sqlite", "Conn", "pool", "closed", "Error"] {
        assert!(
            !rendered.contains(leaked),
            "the failure body leaked {leaked:?}: {rendered}"
        );
    }
    assert_eq!(
        response.json.as_object().expect("a JSON object").len(),
        2,
        "the failure body must stay two fixed fields"
    );
}

/// Liveness does not depend on the database, which is what separates it from readiness.
///
/// If this ever fails, someone has given `health_check` a `State` extractor and an orchestrator will
/// now restart every replica whenever the database blips — killing in-flight executions to fix a
/// problem that is not in this process. The handler takes no state precisely so that cannot happen;
/// this asserts the consequence rather than the signature.
#[tokio::test]
async fn liveness_still_answers_when_the_database_is_gone() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(pinned_state(&db).await);

    db.close().await.expect("closing the pool succeeds");

    // Readiness has genuinely noticed, so the assertion below is independence rather than a
    // database that never actually went away.
    assert_eq!(send(&app, anonymous("/ready")).await.status, StatusCode::SERVICE_UNAVAILABLE);

    let response = send(&app, anonymous("/health")).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "liveness must not fail because a dependency did; restarting this process would not fix it"
    );
    assert_eq!(response.string("status"), "ok");
}

/// The probes are outside the auth tree, not merely tolerant of a missing key.
///
/// A garbage `X-API-Key` would be rejected with `401` by `auth_middleware`. That it is ignored here
/// is the positive evidence that no auth layer sits in front of these routes — which "no header
/// required" alone does not prove, since a middleware could have been written to skip empty
/// credentials.
#[tokio::test]
async fn a_bogus_api_key_neither_helps_nor_hinders_a_probe() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(pinned_state(&db).await);

    for uri in ["/health", "/ready"] {
        let request = with_connect_info(
            Request::builder().method("GET").uri(uri).header("X-API-Key", "not-a-real-key"),
        )
        .body(Body::empty())
        .expect("building the request succeeds");

        assert_eq!(
            send(&app, request).await.status,
            StatusCode::OK,
            "{uri} must ignore credentials entirely rather than validate them"
        );
    }
}

/// Meanwhile the authenticated tree is untouched: an anonymous `/api/*` call is still `401`.
///
/// The probes are mounted with `.merge` on the root router, and a mistake there — merging the API
/// routes without their layer, say — would show up as authentication silently disappearing.
/// Asserting the probes work proves nothing about that; this does.
#[tokio::test]
async fn adding_the_probes_did_not_open_the_authenticated_tree() {
    let db = setup_test_db().await;
    let app = simply_hook_executor::create_app(test_state(&db));

    for uri in ["/api/hooks", "/api/keys", "/api/settings", "/api/audit-logs"] {
        assert_eq!(
            send(&app, anonymous(uri)).await.status,
            StatusCode::UNAUTHORIZED,
            "{uri} must still demand a credential"
        );
    }
}

/// An unpinned Master identity makes this process **not ready**, even with a healthy database.
///
/// This is the check's entire reason for existing. `main.rs` pins before binding the listener, so in
/// production the `OnceCell` cannot be empty — but that ordering is a convention held by one line. A
/// future edit that bound first would produce a process reporting itself ready while every
/// master-only route quietly refused and every `key.is_master` read fell back to per-request
/// resolution. A load balancer would keep routing to it, which is worse than being plainly down.
///
/// The database is deliberately left **live** here, so the `503` can only be attributable to the pin.
#[tokio::test]
async fn readiness_reports_unavailable_when_no_master_is_pinned() {
    let db = setup_test_db().await;
    // `test_state`, not `pinned_state`: the unpinned fixture is the subject of this test.
    let app = simply_hook_executor::create_app(test_state(&db));

    let response = send(&app, anonymous("/ready")).await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a process that never pinned a Master must not report itself ready: {}",
        response.raw
    );
    assert_eq!(response.string("status"), "unavailable");

    // `up`, because it is: the database answered. Reporting `down` would send an operator to
    // investigate a database that is working perfectly.
    assert_eq!(
        response.string("database"),
        "up",
        "the database is healthy; the failure is this process's own startup ordering"
    );

    // Liveness is unaffected — an unpinned master is not a reason to restart the container, and
    // restarting would not pin it either.
    assert_eq!(send(&app, anonymous("/health")).await.status, StatusCode::OK);
}
