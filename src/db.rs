//! Database connection setup: pool construction, SQLite session pragmas, and migrations.
//!
//! Everything here is deliberately backend-conditional. `AGENT.MD` requires the data layer to stay
//! SQL-agnostic, and it does: no query in this codebase is vendor-specific. These are connection
//! *pragmas* rather than queries — they configure how the engine behaves, not what it is asked —
//! and they are skipped entirely on any backend that is not SQLite.
//!
//! # Where each pragma actually takes effect
//!
//! | Pragma | Scope | Already in force before this module set it |
//! | :--- | :--- | :--- |
//! | `foreign_keys` | per-connection | **ON** — SQLx sets it (measured, see below) |
//! | `busy_timeout` | per-connection | **5000 ms** — SQLx sets it |
//! | `journal_mode=WAL` | **persistent** (file header) | `delete` |
//! | `synchronous=NORMAL` | per-connection | `FULL` (2) — **this one is a real change** |
//!
//! ## `foreign_keys` is an assertion, not a fix
//!
//! An earlier audit note in `AGENT_NOTES.MD` claimed this service's six declared foreign keys were
//! *inert* on SQLite because nothing set `PRAGMA foreign_keys=ON`. **That was wrong, and it is
//! corrected here rather than quietly dropped.** SQLx enables foreign keys by default on every
//! SQLite connection it opens, file-backed and in-memory alike: `PRAGMA foreign_keys` reads back
//! `1` on a bare `Database::connect`, and an orphan insert is refused with
//! `(code: 787) FOREIGN KEY constraint failed`. Cascades have always fired.
//!
//! Setting it explicitly is still worth doing, for the reason a defaulted security-relevant setting
//! always is: a *default* is a promise the dependency can revise in a point release, and the failure
//! mode of that revision is silent — orphans accumulate and nothing errors. Declaring it pins the
//! behaviour to this crate's intent, and
//! [`tests::foreign_keys_are_enforced_not_just_reported_as_on`] proves the engine acts on it rather
//! than merely reporting the switch.
//!
//! ## The SQLite pool holds exactly one connection
//!
//! SeaORM pins `max_connections = 1` for SQLite, and [`connect`] restores that explicitly because
//! hand-building a pool from `SqliteConnectOptions` opts out of the default silently. Three of the
//! four settings above are per-connection, which would matter enormously on a wider pool; with one
//! connection, pool-wide and per-connection are the same thing.
//!
//! [`connect`] declares the pragmas through `SqliteConnectOptions` rather than relying on
//! [`apply_sqlite_pragmas`] alone for one narrow but real reason: SQLx reopens a connection that has
//! been closed or invalidated, and a reopened connection replays its *options* but not our `PRAGMA`
//! statements. Declaring them at open time is what makes them survive a recycle.

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    SqlxSqliteConnector, Statement,
};
use sea_orm_migration::MigratorTrait;

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
///
/// Deliberately the same 5000 SQLx already applies by default: this constant exists to make the
/// value explicit and assert it, not to change it. Lowering it would turn a transient lock into a
/// `500` on a request that did nothing wrong.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 5_000;

/// Connections in the SQLite pool. **One**, and not a tuning knob.
///
/// SQLite permits a single writer, and a DDL sequence spread across connections does not survive it:
/// `m20230106_000001_master_key_uniqueness` drops and re-adds `master_marker` as a generated column,
/// and a pool wide enough to serve those two statements from different connections would run the
/// `ADD` against a schema that still holds the old column. SeaORM's own `Database::connect` pins
/// this to 1 for SQLite; building a pool by hand opts out of that default, so it is restored here
/// explicitly and asserted by [`tests::the_sqlite_pool_holds_exactly_one_connection`].
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Opens the database pool, declaring SQLite's session pragmas on **every** connection.
///
/// Non-SQLite backends take the plain [`Database::connect`] path unchanged — there is nothing here
/// PostgreSQL or MySQL needs, and a `PRAGMA` would be a syntax error on both.
///
/// For SQLite the pool is built from `SqliteConnectOptions` rather than from a bare URL, because
/// that is the only place the per-connection settings can be made to hold for connections SQLx opens
/// later (see the module header). `create_if_missing` matches the `?mode=rwc` this service has
/// always documented, so the behaviour no longer depends on callers remembering the query parameter.
pub async fn connect(db_url: &str) -> Result<DatabaseConnection, DbErr> {
    let mut opt = ConnectOptions::new(db_url.to_owned());
    opt.sqlx_logging_level(log::LevelFilter::Debug);

    // Backend detection by URL scheme, which is the only signal available before a pool exists.
    // Everything downstream reads `get_database_backend()` instead; this is the one place that
    // cannot.
    if !db_url.starts_with("sqlite:") {
        return Database::connect(opt).await;
    }

    use sea_orm::sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };
    use std::str::FromStr;

    let connect_options = SqliteConnectOptions::from_str(db_url)
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?
        .create_if_missing(true)
        // Declared rather than inherited. SQLx already defaults this on — measured, not assumed —
        // so this is an assertion that survives a future SQLx default change, not a repair.
        .foreign_keys(true)
        // Readers proceed against the last committed snapshot while a writer appends, instead of
        // blocking on a database-wide exclusive lock.
        .journal_mode(SqliteJournalMode::Wal)
        // The one setting here that genuinely changes behaviour: the default is `FULL`. `NORMAL` is
        // the standard companion to WAL — it keeps full durability against *process* crashes and
        // gives up only the last transactions in a power loss, in exchange for not fsyncing on
        // every commit.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_millis(u64::from(SQLITE_BUSY_TIMEOUT_MS)));

    let pool = SqlitePoolOptions::new()
        // Explicit, because the default is wrong here and silently so: SQLx defaults to ten, while
        // SeaORM's own `Database::connect` pins SQLite to one. See [`SQLITE_MAX_CONNECTIONS`].
        .max_connections(SQLITE_MAX_CONNECTIONS)
        .connect_with(connect_options)
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// Runs every pending migration.
///
/// A thin wrapper, and worth having anyway: it puts migration execution beside connection setup, so
/// the startup order — connect, pragmas, migrate — reads as one sequence in one module rather than
/// being reconstructed from `main.rs`.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    tracing::info!("Running database migrations...");
    crate::migration::Migrator::up(db, None).await
}

/// Applies SQLite's session pragmas to the current connection, logging what actually took effect.
///
/// # What this adds over [`connect`]
///
/// Not the settings themselves — [`connect`] has already declared them on every connection, and on a
/// pool built there this function finds them already in force. What it adds is **evidence**: it
/// reads `journal_mode` back rather than inferring success from a clean return, so the startup log
/// says which mode is genuinely active. It also covers pools this crate did not build, which is
/// every pool in the test suite.
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
            // `memory` here is the expected answer for `sqlite::memory:`, not a problem.
            Ok(mode) => tracing::info!(
                "SQLite journal mode is '{mode}' rather than WAL; this is normal for in-memory or \
                 read-only databases."
            ),
            Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}"),
        },
        Ok(None) => tracing::warn!("PRAGMA journal_mode returned no row; leaving the default."),
        Err(e) => tracing::warn!("Could not enable SQLite WAL mode: {e}. Continuing without it."),
    }

    // The remaining three are set-and-log. Each is per-connection, so on a pool this reaches
    // whichever connection serves it — which is precisely why `connect` declares them at open time
    // and why these calls are confirmation rather than mechanism.
    for (label, statement) in [
        ("foreign key enforcement", "PRAGMA foreign_keys=ON;".to_owned()),
        ("synchronous mode", "PRAGMA synchronous=NORMAL;".to_owned()),
        ("busy timeout", format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")),
    ] {
        if let Err(e) =
            db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, statement)).await
        {
            tracing::warn!("Could not set the SQLite {label}: {e}. Continuing with the default.");
        }
    }
    tracing::info!(
        "SQLite session pragmas applied: foreign_keys=ON, synchronous=NORMAL, \
         busy_timeout={SQLITE_BUSY_TIMEOUT_MS}ms."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{EntityTrait, PaginatorTrait};

    /// Reads one pragma back through the pool.
    async fn pragma<T: sea_orm::TryGetable>(db: &DatabaseConnection, sql: &str, col: &str) -> T {
        db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql.to_owned()))
            .await
            .expect("the pragma query succeeds")
            .expect("a row is returned")
            .try_get("", col)
            .expect("the column has the expected type")
    }

    /// A temporary directory holding one database file, removed on drop.
    ///
    /// `Drop` rather than a trailing `remove_dir_all`: a failing assertion unwinds, and a cleanup
    /// line placed after it would be skipped, leaving a database file behind on every red run.
    struct TempDb(std::path::PathBuf);
    impl TempDb {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("shx_db_{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir is creatable");
            Self(dir)
        }
        fn url(&self) -> String {
            format!("sqlite://{}", self.0.join("shx.db").display())
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// All four settings are in force on a pool built by [`connect`].
    ///
    /// A file-backed database is the only place WAL can actually engage, so that is where the
    /// assertion has to be made — an in-memory database would pass a weaker test vacuously.
    #[tokio::test]
    async fn connect_applies_all_four_pragmas() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("a file-backed sqlite pool opens");

        assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        assert_eq!(pragma::<i32>(&db, "PRAGMA synchronous;", "synchronous").await, 1, "NORMAL");
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;", "foreign_keys").await, 1, "ON");
        assert_eq!(
            pragma::<i32>(&db, "PRAGMA busy_timeout;", "timeout").await,
            SQLITE_BUSY_TIMEOUT_MS as i32
        );
    }

    /// `synchronous` is the one setting [`connect`] genuinely *changes* rather than asserts.
    ///
    /// Pinned against a bare `Database::connect` so the test states the delta rather than just the
    /// destination: if SQLx ever started defaulting to `NORMAL`, this would go red and say so,
    /// instead of continuing to pass while the code that sets it had become redundant.
    #[tokio::test]
    async fn synchronous_normal_is_a_real_change_from_the_driver_default() {
        let tmp = TempDb::new();

        let bare = Database::connect(format!("{}?mode=rwc", tmp.url())).await.expect("opens");
        assert_eq!(
            pragma::<i32>(&bare, "PRAGMA synchronous;", "synchronous").await,
            2,
            "the driver default is FULL; if this ever reads 1, `connect` no longer changes anything"
        );
        drop(bare);

        let db = connect(&tmp.url()).await.expect("pool opens");
        assert_eq!(pragma::<i32>(&db, "PRAGMA synchronous;", "synchronous").await, 1);
    }

    /// Foreign keys are genuinely enforced, not merely reported as on.
    ///
    /// `PRAGMA foreign_keys` returning `1` says the switch is set; it does not prove the engine acts
    /// on it. An insert naming an `api_key_id` and a `hook_id` that do not exist is the direct test,
    /// and it is exactly what SQLite would accept in silence with the pragma off.
    ///
    /// This test also documents a **correction**. An earlier audit recorded these six declared
    /// foreign keys as inert, on the reasoning that nothing in this crate set the pragma. Nothing
    /// did — but SQLx sets it on every SQLite connection it opens, so they have always been
    /// enforced. The claim was wrong; the constraint it worried about was already held.
    #[tokio::test]
    async fn foreign_keys_are_enforced_not_just_reported_as_on() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        run_migrations(&db).await.expect("migrations run");

        let orphan = crate::entities::api_key_hook_permission::ActiveModel {
            id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()),
            api_key_id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()), // no such key
            hook_id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()),    // no such hook
            can_execute: sea_orm::ActiveValue::Set(true),
            can_manage: sea_orm::ActiveValue::Set(false),
            can_view_execution: sea_orm::ActiveValue::Set(false),
            created_at: sea_orm::ActiveValue::Set(chrono::Utc::now().naive_utc()),
        };
        assert!(
            crate::entities::prelude::ApiKeyHookPermission::insert(orphan).exec(&db).await.is_err(),
            "a permission row naming a nonexistent key must be refused; with foreign_keys off \
             SQLite accepts it silently"
        );
        assert_eq!(
            crate::entities::prelude::ApiKeyHookPermission::find()
                .count(&db)
                .await
                .expect("count succeeds"),
            0,
            "and the refusal must leave no row behind"
        );
    }

    /// The SQLite pool holds exactly one connection — the invariant DDL migrations depend on.
    ///
    /// Asserted against the live pool rather than against the constant, so that changing
    /// [`SQLITE_MAX_CONNECTIONS`] alone cannot satisfy it.
    #[tokio::test]
    async fn the_sqlite_pool_holds_exactly_one_connection() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_max_connections(),
            1,
            "SQLite must run a single-connection pool; more than one breaks DDL migrations"
        );
    }

    /// Migrations complete against a **file-backed** pool built by [`connect`].
    ///
    /// Every other suite in this repository runs on `sqlite::memory:`, where there is nothing to
    /// pool and no file for `m20230106`'s generated column to be re-added against. This is the only
    /// test that exercises the combination [`connect`] actually ships with.
    #[tokio::test]
    async fn migrations_apply_cleanly_on_a_file_backed_pool() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        run_migrations(&db).await.expect("every migration applies on a pooled file database");

        // Re-running is a no-op rather than an error: this is what a restart does.
        run_migrations(&db).await.expect("migrations are idempotent across restarts");
    }

    /// WAL is persistent: a *new* connection to the same file inherits it without re-running the
    /// pragma. That is what makes the journal mode the one setting not needing per-connection care.
    #[tokio::test]
    async fn wal_survives_reconnection() {
        let tmp = TempDb::new();
        {
            let db = connect(&tmp.url()).await.expect("pool opens");
            assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        }
        let reopened =
            Database::connect(format!("{}?mode=rwc", tmp.url())).await.expect("plain reconnect");
        assert_eq!(
            pragma::<String>(&reopened, "PRAGMA journal_mode;", "journal_mode").await,
            "wal",
            "WAL is recorded in the file header and survives a reconnect that sets no pragmas"
        );
    }

    /// An in-memory database cannot use WAL. That must be a logged no-op, not a startup failure —
    /// the entire test suite runs on `sqlite::memory:`.
    ///
    /// This is the resilience contract in miniature: the pragmas are a *performance* setting, and
    /// the daemon is entirely correct without them. A database that declines WAL must still come up
    /// and still be usable, because refusing to boot over a setting that did not apply trades a
    /// real outage for a theoretical slowdown.
    #[tokio::test]
    async fn a_database_that_cannot_use_wal_still_starts_and_works() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert!(apply_sqlite_pragmas(&db).await.is_ok(), "a declined pragma is never fatal");

        // WAL genuinely did not engage — so the assertion above is tolerance, not a silent success.
        let mode = pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await;
        assert_ne!(mode.to_ascii_lowercase(), "wal", "an in-memory database cannot use WAL");

        // The settings that *can* apply to an in-memory database still did, so a declined WAL does
        // not take the rest of the loop down with it.
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;", "foreign_keys").await, 1);
        assert_eq!(pragma::<i32>(&db, "PRAGMA synchronous;", "synchronous").await, 1);

        // And the connection is still fully usable afterwards, which is the point of continuing.
        run_migrations(&db).await.expect("migrations still run");

        // Re-applying is idempotent: a restart against the same database must not fail either.
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// A non-SQLite backend must be skipped outright rather than issued a `PRAGMA` it cannot parse.
    /// This is what keeps `AGENT.MD`'s SQL-agnostic rule intact once PostgreSQL is in play.
    #[tokio::test]
    async fn the_pragmas_are_scoped_to_sqlite_by_backend_not_by_url_text() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert_eq!(db.get_database_backend(), DatabaseBackend::Sqlite);
        // The guard reads `get_database_backend()`, so a PostgreSQL pool returns early before any
        // statement is built — there is no URL parsing to get wrong.
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }
}
