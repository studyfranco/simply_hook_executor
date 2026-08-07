//! Application errors.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

/// Global application error type.
///
/// Every handler returns `Result<_, AppError>`; the [`IntoResponse`] implementation below is the
/// single place that decides status codes and what detail reaches the client, which is why no
/// handler ever needs `.unwrap()` or a hand-rolled error response.
#[derive(Error, Debug)]
pub enum AppError {
    /// Database error.
    #[error("Database error: {0}")]
    DbError(#[from] sea_orm::DbErr),

    /// Invalid input (malformed payload, failed validation, missing required parameters).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Missing or invalid credentials.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated, but lacking the required permission.
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Resource not found.
    #[error("Not Found")]
    NotFound,

    /// The request conflicts with current state (e.g. a unique-name collision).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// The caller exceeded its `max_concurrent_jobs` execution budget.
    #[error("Too Many Requests: {0}")]
    TooManyRequests(String),

    /// A request body an extractor refused before any handler ran, carrying the extractor's own
    /// status verbatim.
    ///
    /// Exists so wrapping `Json` in a strict extractor cannot silently flatten *unrelated*
    /// rejections into `400`. The body-size limit surfaces as a `Json` rejection too, and
    /// collapsing it would turn a `413 Payload Too Large` — a distinct, separately tested control
    /// — into an indistinguishable "bad request". The status is passed through; only the response
    /// *shape* is normalized to the `{"error": ...}` envelope every other refusal uses.
    #[error("Request rejected: {1}")]
    BodyRejected(StatusCode, String),

    /// Internal server error.
    #[error("Internal Server Error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::DbError(err) => {
                // Logged in full, reported generically: a raw driver error can expose schema and
                // query structure to a caller who has no business seeing either.
                tracing::error!("Database error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error".to_owned())
            }
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_owned()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            AppError::BodyRejected(status, msg) => (status, msg),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal server error occurred".to_owned(),
            ),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
