//! Unauthenticated liveness and readiness probes.
//!
//! # The one part of the API that is deliberately public
//!
//! Every other route in this service sits behind [`crate::middleware::auth_middleware`]. These two
//! do not, and that is the whole point: an orchestrator restarting a wedged container, or a load
//! balancer deciding whether to send traffic, has no credential and must not need one. Requiring an
//! API key for a liveness check means the probe fails exactly when the credential store is the thing
//! that broke — the moment the answer matters most.
//!
//! Because they are public, they are held to a rule the authenticated routes are not: **they must
//! disclose nothing an anonymous caller could not already infer.** A probe that leaked a version
//! string, a hostname, a row count, or a database error message would be a free reconnaissance
//! endpoint on the open internet. See [`readiness_check`] for how a failing database is reported
//! without saying anything about it.
//!
//! # Liveness and readiness are different questions
//!
//! Conflating them is the classic way to turn a brief dependency outage into an outage of your own:
//!
//! - [`health_check`] answers *"is this process alive?"* It touches nothing and cannot fail. An
//!   orchestrator uses it to decide whether to **restart** the container.
//! - [`readiness_check`] answers *"can this process serve traffic right now?"* It reaches the
//!   database. A load balancer uses it to decide whether to **route** to the container.
//!
//! If liveness also checked the database, then a database that went away for thirty seconds would
//! make every replica fail liveness, and the orchestrator would kill and restart all of them — which
//! does not fix a database and does destroy any in-flight work. Restarting a process because
//! something *else* is broken is strictly harmful, so liveness stays local by construction.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use sea_orm::{ConnectionTrait, Statement};
use serde_json::json;

use crate::state::AppState;

/// Handles `GET /health` — liveness.
///
/// Always `200 OK`. It takes no [`State`], which is not an oversight but the guarantee: a handler
/// that cannot reach the database cannot be made to fail by the database being down, and the
/// compiler enforces that rather than a comment asking future editors to remember it.
///
/// The body is a fixed two-field document. `service` is the crate name, which is already implied by
/// whatever the caller connected to, and `status` is a constant. Nothing here varies with runtime
/// state, so nothing here can leak it.
pub async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(json!({
            "status": "ok",
            "service": env!("CARGO_PKG_NAME"),
        })),
    )
}

/// Handles `GET /ready` — readiness.
///
/// Issues `SELECT 1` against the pool and answers `200` with `{"status":"ready","database":"up"}`
/// or `503` with `{"status":"unavailable","database":"down"}`.
///
/// # Why `SELECT 1` rather than a real query
///
/// It proves the whole path a request depends on — a connection is obtainable from the pool, the
/// engine responds, and a result decodes — while touching no table, taking no lock, and costing
/// nothing that an anonymous caller could amplify into load. A probe that counted rows would be a
/// free way to make an unauthenticated request do unbounded work, which is a denial-of-service
/// primitive aimed at the endpoint that exists to report health.
///
/// It is also the one query in this codebase written as a literal statement rather than through
/// SeaORM's builder, which is why `tests/source_hygiene.rs` carries an explicit allowlist entry for
/// it. `SELECT 1` is portable across all three supported backends and interpolates nothing, so it
/// raises none of the concerns the raw-SQL ban exists to prevent.
///
/// # The error is logged, never returned
///
/// `DbErr` renders connection strings, host names, and driver internals. Those go to the operator's
/// log at `warn`; the caller gets the word `down`. A load balancer needs one bit, and an anonymous
/// caller has no business learning which database this service failed to reach.
///
/// `503` rather than `500` is deliberate: it is the status that tells a well-behaved proxy to stop
/// routing here and retry, whereas `500` describes a request that failed. Nothing about this request
/// failed — the answer *is* "not ready", and it was produced successfully.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    let backend = state.db.get_database_backend();
    match state
        .db
        .query_one_raw(Statement::from_string(backend, "SELECT 1"))
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            axum::Json(json!({ "status": "ready", "database": "up" })),
        ),
        Err(e) => {
            tracing::warn!("Readiness probe failed: the database is unreachable: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(json!({ "status": "unavailable", "database": "down" })),
            )
        }
    }
}
