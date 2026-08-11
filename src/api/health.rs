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
use sea_orm::{EntityTrait, QuerySelect};
use serde_json::json;

use crate::entities::{api_key, prelude::ApiKey};

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

/// Handles `GET /ready` — readiness. `200` when this process can serve traffic, `503` when it cannot.
///
/// Two things are checked, and both are properties of *this process* rather than of the request.
///
/// # 1. The database answers
///
/// A bounded read of at most one id — **not** `COUNT(*)`, which on a large `api_keys` table would
/// make every probe a table scan and turn the health check itself into load. A probe an anonymous
/// caller can amplify into unbounded work is a denial-of-service primitive aimed at the endpoint
/// that exists to report health.
///
/// The query is built with SeaORM's typed builder rather than a literal `SELECT 1`. An earlier
/// revision used the literal and carried an allowlist entry in `tests/source_hygiene.rs` to permit
/// it. That trade was wrong: it bought one saved round-trip and paid with a standing exception to
/// the raw-SQL ban, in a handler that is both request-reachable and **unauthenticated** — the worst
/// place in the service to hold an exemption. `select_only().column(Id).limit(1)` is portable across
/// all three supported backends and needs no exception at all.
///
/// # 2. The Master identity is pinned
///
/// `main.rs` pins before binding the listener, so in production this is a `OnceCell` read that
/// cannot be `None`. It is asserted anyway because that ordering is a *convention* held by one line:
/// a future edit that bound the listener first would otherwise produce a process reporting itself
/// ready while every master-only route quietly refused, and every `key.is_master` read fell back to
/// per-request resolution. A service in that state is worse than one that is plainly down, because
/// a load balancer would keep routing to it.
///
/// # The response body says as little as possible
///
/// `{"status":"ready","database":"up"}`, or `{"status":"unavailable","database":"up"|"down"}`. A
/// failing probe does **not** name which of the two checks failed beyond the `database` field, and
/// never carries the error: `DbErr` renders connection strings, host names and driver internals, and
/// those go to the operator's log where an operator can read them and an anonymous caller cannot. A
/// load balancer needs one bit.
///
/// Note the unpinned case reports `"database":"up"` — because it is. The database answered; what
/// failed is this process's own startup ordering, and saying `down` would send an operator to
/// investigate a database that is working perfectly.
///
/// `503` rather than `500` is deliberate: it is the status that tells a well-behaved proxy to stop
/// routing here and retry, whereas `500` describes a request that failed. Nothing about this request
/// failed — the answer *is* "not ready", and it was produced successfully.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = ApiKey::find()
        .select_only()
        .column(api_key::Column::Id)
        .limit(1)
        .into_tuple::<uuid::Uuid>()
        .all(&state.db)
        .await
    {
        tracing::error!("Readiness probe failed: the database is unreachable: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": "unavailable", "database": "down" })),
        );
    }

    if state.master_pin.get().is_none() {
        tracing::error!(
            "Readiness probe failed: no Master identity is pinned. This process should not have \
             bound its listener — see main.rs and RBAC_MODEL.md §5."
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": "unavailable", "database": "up" })),
        );
    }

    (
        StatusCode::OK,
        axum::Json(json!({ "status": "ready", "database": "up" })),
    )
}
