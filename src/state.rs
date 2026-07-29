//! Application state shared by every handler.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::config::RuntimeConfig;
use crate::crypto::SecretCipher;
use crate::executor::ConcurrencyLimiter;

/// Global application state.
///
/// Cheap to clone: the database handle is an internally-refcounted pool, and both the runtime
/// configuration and the concurrency limiter are shared behind [`Arc`]. The limiter in particular
/// *must* be shared rather than copied — it is the single source of truth for how many jobs each
/// API key currently has in flight.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: DatabaseConnection,
    /// Immutable runtime configuration, read from the environment at startup.
    pub config: Arc<RuntimeConfig>,
    /// Per-API-key execution concurrency budgets.
    pub limiter: Arc<ConcurrencyLimiter>,
    /// Protects recoverable secrets (currently `api_keys.signing_secret`) at rest.
    pub cipher: Arc<SecretCipher>,
}

impl AppState {
    /// Builds state around an existing database connection.
    ///
    /// The cipher is an explicit parameter rather than a default so no caller can accidentally
    /// construct state that writes signing secrets in the clear without having said so.
    pub fn new(
        db: DatabaseConnection,
        config: Arc<RuntimeConfig>,
        cipher: Arc<SecretCipher>,
    ) -> Self {
        Self {
            db,
            config,
            limiter: Arc::new(ConcurrencyLimiter::new()),
            cipher,
        }
    }
}
