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

    /// A conflict that carries machine-readable context alongside the message.
    ///
    /// Exists for `RBAC_MODEL.md` §6: deleting a key whose subtree owns resources is refused with an
    /// **inventory** of what would be stranded, because the caller is meant to be shown what it is
    /// about to orphan and made to resolve each entity explicitly. A bare [`AppError::Conflict`]
    /// could carry the sentence but not the list.
    ///
    /// `details` is merged into the response object rather than nested under a `details` key, so the
    /// body stays `{"error": "...", "owned_entities": [...]}` — one flat envelope, matching every
    /// other refusal. A non-object `details` is dropped rather than replacing the envelope; see
    /// [`AppError::into_response`].
    ///
    /// The alternative — a handler returning `axum::response::Response` directly — is what this
    /// replaces. That shape works, but it takes the handler out of `Result<_, AppError>` and so out
    /// of the one place every refusal in the service is rendered, which is precisely where a
    /// response envelope drifts.
    #[error("Conflict: {message}")]
    ConflictWithDetails {
        /// The human-readable refusal, rendered as `error`.
        message: String,
        /// Additional top-level fields merged into the response body. Expected to be a JSON object.
        details: serde_json::Value,
    },

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

fn is_transient_lock_error(err: &sea_orm::DbErr) -> bool {
    if matches!(err, sea_orm::DbErr::ConnectionAcquire(_)) {
        return true;
    }
    let (sea_orm::DbErr::Conn(runtime_err)
    | sea_orm::DbErr::Exec(runtime_err)
    | sea_orm::DbErr::Query(runtime_err)) = err
    else {
        return false;
    };
    let sea_orm::RuntimeErr::SqlxError(sqlx_err) = runtime_err else {
        return false;
    };
    match sqlx_err.as_ref() {
        sea_orm::SqlxError::PoolTimedOut => true,
        sea_orm::SqlxError::Database(db_err) => match db_err.code().as_deref() {
            Some("55P03" | "40001" | "40P01") => true,
            Some(code) => code.parse::<u32>().is_ok_and(|n| matches!(n & 0xFF, 5 | 6)),
            None => false,
        },
        _ => false,
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Handled before the shared envelope because it is the one variant that contributes extra
        // top-level fields. Everything below renders exactly `{"error": ...}`.
        if let AppError::ConflictWithDetails { message, details } = self {
            let mut body = json!({ "error": message });
            if let (Some(envelope), Some(extra)) = (body.as_object_mut(), details.as_object()) {
                for (key, value) in extra {
                    // `error` is the envelope's own field. A `details` object carrying one would
                    // silently rewrite the refusal message, so the envelope wins.
                    if key != "error" {
                        envelope.insert(key.clone(), value.clone());
                    }
                }
            } else {
                // A non-object `details` has nowhere to merge into. Dropping it keeps the envelope
                // well-formed rather than emitting a body whose shape depends on the call site.
                tracing::error!(
                    "ConflictWithDetails carried non-object details; they were dropped: {details}"
                );
            }
            return (StatusCode::CONFLICT, Json(body)).into_response();
        }

        let (status, error_message) = match self {
            AppError::DbError(err) => {
                // Logged in full, reported generically: a raw driver error can expose schema and
                // query structure to a caller who has no business seeing either.
                tracing::error!("Database error: {}", err);
                if is_transient_lock_error(&err) {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Database busy or query timeout, please retry".to_owned(),
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal database error".to_owned(),
                    )
                }
            }
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_owned()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            // Unreachable: returned above, before this match. Kept exhaustive rather than swept
            // into a `_` arm so that a future variant cannot be added without the compiler asking.
            AppError::ConflictWithDetails { message, .. } => (StatusCode::CONFLICT, message),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_writer_lock_maps_to_503() {
        use sea_orm::{
            ConnectionTrait, Database, DeriveIden, SqlxSqliteConnector, TransactionTrait,
            sea_query::{ColumnDef, Query, Table},
            sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions},
        };
        use std::str::FromStr;
        use std::time::Duration;

        #[derive(DeriveIden)]
        enum LockProbe {
            Table,
            Id,
        }

        let directory = tempfile::tempdir().expect("temporary database directory");
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("locked.db").display()
        );
        let first = Database::connect(&url)
            .await
            .expect("first SQLite connection");
        let second_options = SqliteConnectOptions::from_str(&url)
            .expect("parse sqlite URL")
            .busy_timeout(Duration::ZERO);
        let second_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(second_options)
            .await
            .expect("second SQLite pool");
        let second = SqlxSqliteConnector::from_sqlx_sqlite_pool(second_pool);

        let create_table = Table::create()
            .table(LockProbe::Table)
            .col(
                ColumnDef::new(LockProbe::Id)
                    .integer()
                    .not_null()
                    .primary_key(),
            )
            .to_owned();
        first
            .execute(&create_table)
            .await
            .expect("create probe table");

        let transaction = first.begin().await.expect("start writer transaction");
        let insert_one = Query::insert()
            .into_table(LockProbe::Table)
            .columns([LockProbe::Id])
            .values([1.into()])
            .expect("build first insert")
            .to_owned();
        transaction
            .execute(&insert_one)
            .await
            .expect("first connection holds the writer lock");

        let insert_two = Query::insert()
            .into_table(LockProbe::Table)
            .columns([LockProbe::Id])
            .values([2.into()])
            .expect("build second insert")
            .to_owned();
        let error = second
            .execute(&insert_two)
            .await
            .expect_err("second connection is blocked by the writer lock");

        assert_eq!(
            AppError::DbError(error).into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        transaction.rollback().await.expect("release writer lock");
    }

    #[test]
    fn transient_lock_and_pool_errors_map_to_503() {
        let pool_timeout = AppError::DbError(sea_orm::DbErr::Query(
            sea_orm::RuntimeErr::SqlxError(std::sync::Arc::new(sea_orm::SqlxError::PoolTimedOut)),
        ));
        assert_eq!(
            pool_timeout.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let conn_acquire = AppError::DbError(sea_orm::DbErr::ConnectionAcquire(
            sea_orm::ConnAcquireErr::Timeout,
        ));
        assert_eq!(
            conn_acquire.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let generic = AppError::DbError(sea_orm::DbErr::Custom("boom".to_owned()));
        assert_eq!(
            generic.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
