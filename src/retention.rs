//! Background log retention worker.
//!
//! Execution history grows without bound — every invocation stores its full stdout and stderr —
//! so a periodic sweep purges `executions` rows older than `LOG_RETENTION_DAYS` (default 30).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use tokio::sync::mpsc;

use crate::config::RuntimeConfig;
use crate::entities::execution;

/// Deletes every execution older than `retention_days`, returning how many rows were removed.
///
/// A non-positive `retention_days` disables purging and is a no-op, so an operator can keep
/// history forever by setting `LOG_RETENTION_DAYS=0` without also having to disable the worker.
pub async fn purge_expired_executions(
    db: &DatabaseConnection,
    retention_days: i64,
) -> Result<u64, DbErr> {
    if retention_days <= 0 {
        return Ok(0);
    }

    let threshold = (Utc::now() - chrono::Duration::days(retention_days)).naive_utc();
    let result = execution::Entity::delete_many()
        .filter(execution::Column::Timestamp.lt(threshold))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

/// Runs the retention sweep on a fixed interval until shutdown.
///
/// The worker owns the receiving half of a channel whose sender lives in `main`; dropping that
/// sender is the shutdown signal, so the worker stops cleanly during graceful shutdown instead of
/// being aborted mid-delete. The first tick fires immediately, so a daemon that is restarted more
/// often than the sweep interval still prunes its backlog.
pub async fn run_retention_worker(
    db: DatabaseConnection,
    config: Arc<RuntimeConfig>,
    mut shutdown: mpsc::Receiver<()>,
) {
    if config.log_retention_days <= 0 {
        tracing::info!("Log retention is disabled (LOG_RETENTION_DAYS=0); worker will not run.");
        return;
    }

    tracing::info!(
        retention_days = config.log_retention_days,
        sweep_seconds = config.retention_sweep_seconds,
        "Log retention worker started."
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(config.retention_sweep_seconds));
    // If a sweep ever runs long (a very large backlog on slow storage), skip the ticks it missed
    // rather than firing them back to back the moment it finishes.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match purge_expired_executions(&db, config.log_retention_days).await {
                    Ok(0) => tracing::debug!("Retention sweep: nothing to purge."),
                    Ok(n) => tracing::info!("Retention sweep: purged {n} execution record(s)."),
                    Err(e) => tracing::error!("Retention sweep failed: {e}"),
                }
            }
            _ = shutdown.recv() => break,
        }
    }

    tracing::info!("Log retention worker shut down.");
}
