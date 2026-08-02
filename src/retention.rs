//! Background retention worker.
//!
//! Two sweeps run on the same schedule:
//!
//! - **Execution history**, which grows without bound because every invocation stores its full
//!   stdout and stderr. Purged past `LOG_RETENTION_DAYS` (default 30).
//! - **Soft-deleted hooks**, purged past `DELETED_HOOK_RETENTION_DAYS`
//!   ([`DEFAULT_DELETED_HOOK_RETENTION_DAYS`], 92), which is what stops the trash from being an
//!   unbounded graveyard of dead definitions and their histories.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use tokio::sync::mpsc;

use crate::config::RuntimeConfig;
use crate::entities::{execution, hook};

/// How long a soft-deleted hook stays recoverable before the sweep drops it for good.
///
/// 92 days is a quarter plus a couple of days of slack — long enough that a hook deleted at the
/// start of a quarter is still recoverable during the review at its end, which is the realistic
/// moment someone discovers an automation went missing.
///
/// Overridable through `DELETED_HOOK_RETENTION_DAYS`, but deliberately *not* shared with
/// `LOG_RETENTION_DAYS`. The two answer different questions — "how much history do we keep?" versus
/// "how long is a mistake reversible?" — and an operator shortening log retention to save disk
/// should not silently shrink the undo window for deleted automation as a side effect. See
/// [`crate::config::RuntimeConfig::deleted_hook_retention_days`].
pub const DEFAULT_DELETED_HOOK_RETENTION_DAYS: i64 = 92;

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

/// Permanently drops every soft-deleted hook trashed more than `retention_days` ago, returning how
/// many rows were removed.
///
/// This is the irreversible half of soft delete: the row goes, and its parameters, permission
/// grants, and execution history cascade with it. Rows are matched on `deleted_at` rather than
/// `updated_at` so that the clock measures from the deletion itself — an edit made before the hook
/// was trashed must not extend its stay, and nothing edits a trashed hook anyway.
///
/// A non-positive `retention_days` disables purging and is a no-op, mirroring
/// [`purge_expired_executions`] so an operator can keep the trash forever if they want to.
///
/// All three filters are stated explicitly, and the redundancy is deliberate. A live hook always
/// has `deleted_at = NULL`, and SQL's three-valued logic already makes `NULL < threshold` evaluate
/// to `NULL` rather than true — so in principle either condition alone would be safe. But this is
/// the one query in the system that destroys audit history, and making its safety depend on an
/// invariant held elsewhere in the code (or on a reader recalling how `NULL` compares) is the wrong
/// trade for a few bytes of SQL. `is_deleted = true AND deleted_at IS NOT NULL AND deleted_at <
/// threshold` says what it means without anyone having to reason it out.
pub async fn purge_expired_deleted_hooks(
    db: &DatabaseConnection,
    retention_days: i64,
) -> Result<u64, DbErr> {
    if retention_days <= 0 {
        return Ok(0);
    }

    let threshold = (Utc::now() - chrono::Duration::days(retention_days)).naive_utc();
    let result = hook::Entity::delete_many()
        .filter(hook::Column::IsDeleted.eq(true))
        .filter(hook::Column::DeletedAt.is_not_null())
        .filter(hook::Column::DeletedAt.lt(threshold))
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
    // The worker now owns two sweeps, so it must keep running when only one of them is enabled:
    // `LOG_RETENTION_DAYS=0` means "keep history forever", not "let the trash grow forever too".
    if config.log_retention_days <= 0 {
        tracing::info!(
            "Log retention is disabled (LOG_RETENTION_DAYS=0); the worker will still purge \
             soft-deleted hooks after {} days.",
            config.deleted_hook_retention_days
        );
    }

    tracing::info!(
        retention_days = config.log_retention_days,
        deleted_hook_retention_days = config.deleted_hook_retention_days,
        sweep_seconds = config.retention_sweep_seconds,
        "Retention worker started."
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(config.retention_sweep_seconds));
    // If a sweep ever runs long (a very large backlog on slow storage), skip the ticks it missed
    // rather than firing them back to back the moment it finishes.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match purge_expired_executions(&db, config.log_retention_days).await {
                    Ok(0) => tracing::debug!("Retention sweep: no execution records to purge."),
                    Ok(n) => tracing::info!("Retention sweep: purged {n} execution record(s)."),
                    Err(e) => tracing::error!("Execution retention sweep failed: {e}"),
                }
                // Run regardless of how the execution sweep went: one failing must not silently
                // stop the other, or a transient error would leave the trash growing unnoticed.
                match purge_expired_deleted_hooks(&db, config.deleted_hook_retention_days).await {
                    Ok(0) => tracing::debug!("Retention sweep: no deleted hooks to purge."),
                    Ok(n) => tracing::info!(
                        "Retention sweep: permanently removed {n} hook(s) deleted more than {} \
                         days ago.",
                        config.deleted_hook_retention_days
                    ),
                    Err(e) => tracing::error!("Deleted-hook retention sweep failed: {e}"),
                }
            }
            _ = shutdown.recv() => break,
        }
    }

    tracing::info!("Retention worker shut down.");
}
