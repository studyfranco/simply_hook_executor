#![warn(missing_docs)]
//! Simply Hook Executor — a secure hook execution daemon.
//!
//! Exposes the Axum router ([`create_app`]), the shared application state, the safe script
//! execution engine, and the background log retention worker. The binary in `main.rs` is a thin
//! wrapper around these pieces so integration tests can drive the exact same router.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
};
use tokio::sync::mpsc;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

/// Hard ceiling on the size of any request body this daemon will buffer, in bytes (1 MiB).
///
/// Applied as an explicit [`DefaultBodyLimit`] over the whole router rather than left to Axum's
/// implicit 2 MiB default, for three reasons:
///
/// - **It is a security boundary, so it should be stated.** Every execute/webhook handler takes the
///   body as [`axum::body::Bytes`] and every admin handler as `Json<T>`; both buffer the entire
///   payload in memory before a handler ever runs. Without a bound, `max_concurrent_jobs` limits
///   concurrent *processes* while doing nothing about concurrent *allocations*.
/// - **It must agree with the signature verification buffer.** `middleware::auth_middleware` reads
///   the raw body to recompute the HMAC and refuses anything larger than this same constant. Two
///   independently-chosen limits would mean a band of sizes accepted by one layer and refused by
///   the other, which is exactly the kind of gap that turns into a parser-differential bug.
/// - **The default is version-dependent.** Axum's built-in limit is a documented default, not a
///   guarantee; pinning it here means an upgrade cannot silently widen the exposure.
///
/// A body over the limit is rejected with `413 Payload Too Large` before it is read to completion.
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

pub mod api;
pub mod config;
pub mod crypto;
pub mod entities;
pub mod error;
pub mod executor;
pub mod middleware;
pub mod migration;
pub mod retention;
pub mod state;

use state::AppState;

/// Builds the complete Axum router.
///
/// Both the `/api/*` tree and the `/webhook/*` entry point sit behind
/// [`middleware::auth_middleware`]; only the static SPA served from `static/` is public.
pub fn create_app(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/auth/me", get(api::get_me))
        // Hooks
        .route("/hooks", post(api::create_hook))
        .route("/hooks", get(api::list_hooks))
        .route("/hooks/{identifier}", get(api::get_hook))
        .route("/hooks/{identifier}", put(api::update_hook))
        // PATCH is accepted as a synonym: every field of `UpdateHookPayload` is already optional,
        // so the handler's semantics are partial-update either way.
        .route("/hooks/{identifier}", axum::routing::patch(api::update_hook))
        .route("/hooks/{identifier}", delete(api::delete_hook))
        .route("/hooks/{identifier}/execute", post(api::execute_hook_endpoint))
        .route("/hooks/{identifier}/test", post(api::test_hook))
        // Hook parameters
        .route("/hooks/{identifier}/parameters", get(api::list_hook_parameters))
        .route("/hooks/{identifier}/parameters", post(api::create_hook_parameter))
        .route("/hooks/{identifier}/parameters/{param_id}", put(api::update_hook_parameter))
        .route("/hooks/{identifier}/parameters/{param_id}", delete(api::delete_hook_parameter))
        // API keys
        .route("/keys", post(api::create_api_key))
        .route("/keys", get(api::list_api_keys))
        .route("/keys/{id}", put(api::update_api_key))
        // PATCH as a synonym for PUT, matching the hook routes: every `UpdateApiKeyPayload` field
        // is optional, so the handler is partial-update under either verb.
        .route("/keys/{id}", axum::routing::patch(api::update_api_key))
        .route("/keys/{id}", delete(api::delete_api_key))
        .route("/keys/{id}/rotate", post(api::rotate_api_key))
        .route("/keys/{id}/permissions", post(api::update_key_hook_permissions))
        .route("/keys/{id}/permissions/{hook_identifier}", delete(api::revoke_key_hook_permission))
        // Execution history
        .route("/executions", get(api::list_executions))
        .route("/executions", delete(api::purge_executions))
        .route("/executions/{id}", get(api::get_execution))
        .route("/executions/{id}", delete(api::delete_execution))
        // Observability
        .route("/audit-logs", get(api::list_audit_logs))
        .route("/settings", get(api::get_settings))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Webhook-facing alias of the execute endpoint, for third-party senders posting their own
    // flat JSON to a fixed URL. Authenticated by the same middleware as `/api/*`.
    let webhook_routes = Router::new()
        .route("/{identifier}", post(api::webhook_execute))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    Router::new()
        .fallback_service(ServeDir::new("static"))
        .nest("/api", api_routes)
        .nest("/webhook", webhook_routes)
        // Applied outside the nests so it covers `/api/*`, `/webhook/*`, and the static fallback
        // alike — an unauthenticated POST at the SPA's own path is bounded by the same ceiling as
        // an authenticated one, so the limit cannot be sidestepped by aiming at a route that never
        // reaches the auth middleware.
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Spawns the background log retention worker for `state`.
///
/// Returns the shutdown sender alongside the worker's join handle: dropping the sender asks the
/// worker to stop, and awaiting the handle confirms it has. `main` holds both so graceful
/// shutdown never cuts a sweep off mid-delete.
pub fn spawn_retention_worker(state: &AppState) -> (mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<()>(1);
    let db = state.db.clone();
    let config = state.config.clone();
    let handle = tokio::spawn(async move {
        retention::run_retention_worker(db, config, rx).await;
    });
    (tx, handle)
}
