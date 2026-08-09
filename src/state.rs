//! Application state shared by every handler.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::config::RuntimeConfig;
use crate::crypto::SecretCipher;
use crate::executor::ConcurrencyLimiter;
use crate::master::MasterPin;
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
    /// The Master key identity, fixed for the life of the process.
    ///
    /// Shared behind [`Arc`] and *not* copied per clone, which is the whole point: every clone of
    /// this state must see the same pinned id, or a request served by one clone could reach a
    /// different conclusion about who the Master is than a request served by another.
    pub master_pin: Arc<MasterPin>,
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
            // Left unresolved here rather than queried, because state is routinely built before the
            // master row exists — `main.rs` migrates and bootstraps around this call, and the test
            // fixtures seed keys afterwards. Production pins it explicitly via
            // [`MasterPin::pin_at_boot`] before the listener binds; anything else resolves it on
            // first authenticated request. Both store the same value and neither can replace it.
            master_pin: Arc::new(MasterPin::new()),
        }
    }

    /// Builds state whose Master identity is fixed to `master_key_id` without a database lookup.
    ///
    /// Exists for tests that need a pin pointing at something *other* than the real Master row, in
    /// order to assert that a key claiming mastery it was not pinned with is refused. That situation
    /// cannot be constructed through the ordinary path by design — resolution only ever pins a row
    /// that genuinely is the sole Master — so it has to be injectable.
    pub fn with_pinned_master(mut self, master_key_id: uuid::Uuid) -> Self {
        self.master_pin = Arc::new(MasterPin::pinned_to(master_key_id));
        self
    }
}
