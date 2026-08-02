//! Application state shared by every handler.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::config::RuntimeConfig;
use crate::crypto::SecretCipher;
use crate::executor::ConcurrencyLimiter;
use crate::replay::ReplayGuard;

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
    /// Enforces single use of `CANONICAL_V1` signatures inside the anti-replay window.
    pub replay_guard: Arc<ReplayGuard>,
}

impl AppState {
    /// Builds state around an existing database connection.
    ///
    /// The cipher is an explicit parameter rather than a default so no caller can accidentally
    /// construct state that writes signing secrets in the clear without having said so.
    ///
    /// The replay guard is built here instead, from the configured window, because there is exactly
    /// one correct value for it and no caller should be choosing another: a guard whose memory is
    /// shorter than the timestamp window would leave a gap where a signature is too new to be
    /// rejected as stale and too old to be remembered as used.
    pub fn new(
        db: DatabaseConnection,
        config: Arc<RuntimeConfig>,
        cipher: Arc<SecretCipher>,
    ) -> Self {
        let replay_guard = Arc::new(ReplayGuard::new(config.signature_max_age_seconds));
        Self {
            db,
            config,
            limiter: Arc::new(ConcurrencyLimiter::new()),
            cipher,
            replay_guard,
        }
    }
}
