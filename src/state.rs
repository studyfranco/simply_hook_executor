//! Application state shared by every handler.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::config::RuntimeConfig;
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
}

impl AppState {
    /// Builds state around an existing database connection, reading configuration from the
    /// environment. Used by `main`; tests generally construct [`AppState`] directly so they can
    /// pin a deterministic [`RuntimeConfig`].
    pub fn new(db: DatabaseConnection, config: Arc<RuntimeConfig>) -> Self {
        Self {
            db,
            config,
            limiter: Arc::new(ConcurrencyLimiter::new()),
        }
    }
}
