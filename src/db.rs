//! Database connection tuning applied once at startup.
//!
//! Everything here is deliberately backend-conditional. `AGENT.MD` requires the data layer to stay
//! SQL-agnostic, and it does: no query in this codebase is vendor-specific. These are connection
//! *pragmas* rather than queries — they configure how the engine behaves, not what it is asked —
//! and they are skipped entirely on any backend that is not SQLite.

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 5_000;

/// Applies SQLite's concurrency pragmas: write-ahead logging and a busy timeout.
///
/// # Why
///
/// The default rollback journal takes a database-wide exclusive lock for the duration of every
/// write, so a single hook execution recording its `executions` row blocks every concurrent reader.
/// That is exactly the wrong shape for this daemon, whose whole job is running jobs in parallel and
/// writing a history row for each. WAL lets readers proceed against the last committed snapshot
/// while a writer appends, which turns the common case — many concurrent executions, one dashboard
/// polling `/api/executions` — from contention into independent work.
///
/// The busy timeout covers what WAL does not: WAL still permits only one *writer* at a time, so two
/// executions finishing simultaneously can collide. Without a timeout the loser fails instantly with
/// `SQLITE_BUSY`, surfacing as a `500` on a request that did nothing wrong. With one it waits and
/// then succeeds.
///
/// # Scope of each setting
///
/// The two differ in an important way, and it is worth being precise rather than implying both are
/// pool-wide:
///
/// - **`journal_mode=WAL` is persistent.** It is recorded in the database file header, so setting it
///   once applies to that database permanently — every future connection, and every future run of
///   the daemon, inherits it. Issuing it on one pooled connection is therefore sufficient.
/// - **`busy_timeout` is per-connection.** This statement sets it for whichever connection served
///   it. The pool-wide guarantee comes from SQLx, which applies its own default of five seconds to
///   every SQLite connection it opens — the same value. This call makes the intent explicit and
///   asserts it holds, rather than being the sole mechanism.
///
/// # Failure handling
///
/// A pragma that cannot be applied is logged and swallowed rather than aborting startup. The most
/// common reason is entirely benign: an in-memory database (`sqlite::memory:`, which the test suite
/// uses throughout) reports `journal_mode=memory` and cannot be switched to WAL, since there is no
/// file to write a log beside. Refusing to boot over a performance setting that did not apply would
/// trade a real outage for a theoretical slowdown.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    // `journal_mode` answers with the mode actually in force, which is the only trustworthy
    // confirmation — SQLite silently declines the switch for in-memory and read-only databases
    // rather than erroring, so assuming success from a clean return would be wrong.
    match db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL;",
        ))
        .await
    {
        Ok(Some(row)) => match row.try_get::<String>("", "journal_mode") {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
                tracing::info!("SQLite journal mode: WAL (concurrent readers during writes).");
            }
            Ok(mode) => {
                // `memory` here is the expected answer for `sqlite::memory:`, not a problem.
                tracing::info!(
                    "SQLite journal mode is '{mode}' rather than WAL; this is normal for in-memory \
                     or read-only databases."
                );
            }
            Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}"),
        },
        Ok(None) => tracing::warn!("PRAGMA journal_mode returned no row; leaving the default."),
        Err(e) => tracing::warn!("Could not enable SQLite WAL mode: {e}. Continuing without it."),
    }

    if let Err(e) = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};"),
        ))
        .await
    {
        tracing::warn!("Could not set the SQLite busy timeout: {e}. Continuing with the default.");
    } else {
        tracing::info!("SQLite busy timeout: {SQLITE_BUSY_TIMEOUT_MS}ms.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    /// A file-backed database is the only place WAL can actually engage, so that is where the
    /// assertion has to be made — an in-memory database would pass a weaker test vacuously.
    #[tokio::test]
    async fn wal_and_busy_timeout_are_applied_to_a_file_backed_database() {
        let dir = std::env::temp_dir().join(format!("shx_wal_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir is creatable");
        let path = dir.join("wal.db");

        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("sqlite file database opens");
        apply_sqlite_pragmas(&db).await.expect("pragmas apply");

        let mode: String = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA journal_mode;",
            ))
            .await
            .expect("query succeeds")
            .expect("a row is returned")
            .try_get("", "journal_mode")
            .expect("the column is a string");
        assert_eq!(mode.to_ascii_lowercase(), "wal", "WAL must be in force on a file database");

        let timeout: i32 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA busy_timeout;",
            ))
            .await
            .expect("query succeeds")
            .expect("a row is returned")
            .try_get("", "timeout")
            .expect("the column is an integer");
        assert_eq!(timeout, SQLITE_BUSY_TIMEOUT_MS as i32);

        // WAL is persistent: a *new* connection to the same file inherits it without re-running the
        // pragma, which is what makes applying it once at startup sufficient for the whole pool.
        drop(db);
        let reopened = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("sqlite file database reopens");
        let inherited: String = reopened
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA journal_mode;",
            ))
            .await
            .expect("query succeeds")
            .expect("a row is returned")
            .try_get("", "journal_mode")
            .expect("the column is a string");
        assert_eq!(inherited.to_ascii_lowercase(), "wal", "WAL survives reconnection");

        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An in-memory database cannot use WAL. That must be a logged no-op, not a startup failure —
    /// the entire test suite runs on `sqlite::memory:`.
    #[tokio::test]
    async fn an_in_memory_database_is_left_alone_without_erroring() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }
}
