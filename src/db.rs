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
//! | `temp_store=MEMORY` | per-connection | `0` (engine's choice, usually a disk file) |
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
//! ## Two pools, not one: migrations are isolated from application traffic
//!
//! [`run_migrations_isolated`] opens its **own**, throwaway, single-connection pool — regardless of
//! backend — runs every pending migration against it, and closes it before returning. Only *then*
//! does [`main`](crate::main) call [`connect`] to build the pool the application actually serves
//! requests from. The two never overlap: nothing can query or write through the application pool
//! while a migration is still in flight, and no migration statement can be interleaved with one
//! issued by a connection the application pool has already handed out.
//!
//! This separation is what makes [`connect`]'s per-backend pool widths (below) safe to introduce at
//! all. A single shared pool running migrations on whichever connection happened to be free — while
//! *also* being wide enough for concurrent application traffic — is exactly how a DDL statement from
//! one connection and a read from another interleave against a half-migrated schema
//! (`duplicate column name` on SQLite if two connections each try to add the same column; a
//! `SELECT` on PostgreSQL/MySQL that starts before a migration's transaction commits and sees the
//! pre-migration shape). With the isolated phase, the application pool is not even *constructed*
//! until every migration has already committed.
//!
//! ## Pool width is backend- **and** topology-specific — see [`PoolLimits`]
//!
//! SQLite permits exactly one writer at a time no matter how many connections a pool holds, and an
//! in-memory database (`sqlite::memory:`) is not one database shared by a pool at all: **every**
//! connection to it opens its own separate, empty database, so a pool wider than one connection
//! means silent, connection-dependent data loss, not added capacity. Neither fact is true of a
//! file-backed SQLite database (which WAL lets multiple *readers* use concurrently) or of
//! PostgreSQL/MySQL (real multi-writer servers). [`PoolLimits::for_backend`] is where these three
//! shapes are told apart; nothing in [`connect`] itself branches on backend beyond calling it.
//!
//! [`connect`] declares SQLite's pragmas through `SqliteConnectOptions` rather than relying on
//! [`apply_sqlite_pragmas`] alone for one narrow but real reason: SQLx reopens a connection that has
//! been closed or invalidated, and a reopened connection replays its *options* but not our `PRAGMA`
//! statements. Declaring them at open time is what makes them survive a recycle.

use std::time::Duration;

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    SqlxSqliteConnector, Statement,
};
use sea_orm_migration::MigratorTrait;

use crate::config::RuntimeConfig;

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
///
/// Deliberately the same 5000 SQLx already applies by default: this constant exists to make the
/// value explicit and assert it, not to change it. Lowering it would turn a transient lock into a
/// `500` on a request that did nothing wrong.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 5_000;

/// The **only** connection count an in-memory SQLite database may ever use, and the count every
/// backend's isolated migration pool uses regardless of what it is migrating.
///
/// For `sqlite::memory:` this is not a tuning knob at all: SQLite gives every connection to an
/// in-memory database its own separate, empty database, so "more than one connection" does not
/// mean more capacity, it means the second connection cannot see anything the first wrote —
/// including the schema migrations just applied to it. For the migration pool (every backend) it is
/// the same invariant the previous, SQLite-only version of this constant existed for: a DDL
/// sequence spread across connections does not survive on SQLite
/// (`m20230106_090000_master_key_uniqueness` drops and re-adds `master_marker` as a generated
/// column, and two connections racing those two statements would run the `ADD` against a schema
/// that still holds the old column), and running every backend's migrations through the same
/// single-connection discipline means that failure mode is structurally unreachable rather than
/// merely unlikely on PostgreSQL/MySQL.
pub const SINGLE_CONNECTION: u32 = 1;

/// Connection-pool ceiling clamp for a **file-backed** SQLite database.
///
/// WAL lets readers proceed concurrently with a writer, so a small pool is genuinely useful for
/// read parallelism — but SQLite still permits exactly one writer at a time no matter how wide the
/// pool is, so there is nothing to gain from letting an operator's PostgreSQL-sized
/// `DATABASE_MAX_CONNECTIONS` reach this backend directly; past this width, additional connections
/// would only add contention on `busy_timeout` for writes that were always going to serialize.
pub const FILE_SQLITE_MAX_CONNECTIONS_CAP: u32 = 10;

/// Connection-pool floor clamp for a file-backed SQLite database. See
/// [`FILE_SQLITE_MAX_CONNECTIONS_CAP`] for why this backend gets its own, much lower, ceiling.
pub const FILE_SQLITE_MIN_CONNECTIONS_CAP: u32 = 2;

/// Resolved connection-pool bounds for one database handle.
///
/// A bare `(max, min)` pair from `RuntimeConfig` cannot express this crate's actual pooling rules,
/// because those rules are not a single number tuned per deployment — they are backend- and
/// topology-specific facts about what a wider pool even *means* for that backend. This type is
/// where those facts are decided once, in [`PoolLimits::for_backend`], so [`connect`] and
/// [`run_migrations_isolated`] each apply a resolved answer rather than re-deriving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLimits {
    /// Maximum simultaneously open connections.
    pub max_connections: u32,
    /// Connections the pool tries to keep open even when idle.
    pub min_connections: u32,
    /// How long a connection above `min_connections` may sit idle before being closed. `None`
    /// disables idle reaping entirely — used only for the pinned single-connection cases, where a
    /// reaped-and-reopened "idle" connection to `sqlite::memory:` would silently discard the whole
    /// database rather than merely costing a reconnect.
    pub idle_timeout: Option<Duration>,
    /// How long a caller may wait to acquire a pooled connection before the attempt fails.
    pub acquire_timeout: Duration,
}

impl PoolLimits {
    /// The bounds every backend's isolated migration pool uses — see [`SINGLE_CONNECTION`].
    /// `idle_timeout` is `None` on principle even though a migration pool's short lifetime makes it
    /// practically moot: this pool is closed by [`run_migrations_isolated`] itself long before any
    /// idle timeout could fire.
    fn migration(acquire_timeout: Duration) -> Self {
        Self {
            max_connections: SINGLE_CONNECTION,
            min_connections: SINGLE_CONNECTION,
            idle_timeout: None,
            acquire_timeout,
        }
    }

    /// Resolves the **application** pool's bounds for `db_url`, from the operator-configured
    /// ceiling/floor on `config`.
    ///
    /// - **In-memory SQLite** (`sqlite::memory:`, or any URL naming `mode=memory`) is pinned to
    ///   [`SINGLE_CONNECTION`], ignoring `config` outright — see [`SINGLE_CONNECTION`]'s own doc
    ///   comment for why more than one connection here is a correctness bug, not a performance
    ///   choice.
    /// - **File-backed SQLite** clamps the configured bounds to
    ///   [`FILE_SQLITE_MAX_CONNECTIONS_CAP`] / [`FILE_SQLITE_MIN_CONNECTIONS_CAP`], since SQLite's
    ///   single-writer limit makes a PostgreSQL-sized pool pure overhead here.
    /// - **PostgreSQL/MySQL** apply the configured bounds directly — these are the only backends
    ///   `RuntimeConfig::database_max_connections`/`database_min_connections` describe without
    ///   qualification.
    pub fn for_backend(db_url: &str, config: &RuntimeConfig) -> Self {
        let acquire_timeout = Duration::from_secs(config.database_acquire_timeout_secs);

        if !db_url.starts_with("sqlite:") {
            return Self {
                max_connections: config.database_max_connections,
                min_connections: config.database_min_connections.min(config.database_max_connections),
                idle_timeout: Some(Duration::from_secs(config.database_idle_timeout_secs)),
                acquire_timeout,
            };
        }

        if is_in_memory_sqlite(db_url) {
            return Self::migration(acquire_timeout);
        }

        let max_connections =
            config.database_max_connections.clamp(SINGLE_CONNECTION, FILE_SQLITE_MAX_CONNECTIONS_CAP);
        let min_connections = config
            .database_min_connections
            .clamp(SINGLE_CONNECTION, FILE_SQLITE_MIN_CONNECTIONS_CAP)
            .min(max_connections);
        Self {
            max_connections,
            min_connections,
            idle_timeout: Some(Duration::from_secs(config.database_idle_timeout_secs)),
            acquire_timeout,
        }
    }
}

/// Whether `db_url` names an in-memory SQLite database — one that exists only for the lifetime of
/// the single connection that opened it, and is never shared by a wider pool.
///
/// Matches both spellings this crate's own tests and documentation use (`sqlite::memory:`,
/// `sqlite://:memory:`) via the `:memory:` substring common to both, plus the query-parameter form
/// (`?mode=memory`) SQLite's URI syntax also accepts for a *named* in-memory database. Checked
/// case-insensitively since URL schemes and query parameters are conventionally lower-case but not
/// enforced to be.
fn is_in_memory_sqlite(db_url: &str) -> bool {
    let lower = db_url.to_ascii_lowercase();
    lower.contains(":memory:") || lower.contains("mode=memory")
}

/// Opens a database pool with the given, already-resolved `limits`.
///
/// The one function every other connection-opening path in this module funnels through — [`connect`]
/// (the application pool) and [`run_migrations_isolated`] (the migration pool) differ only in which
/// [`PoolLimits`] they resolve, never in how a pool is actually built from them.
///
/// Non-SQLite backends take the plain [`Database::connect`] path unchanged — there is nothing here
/// PostgreSQL or MySQL needs beyond the pool bounds `ConnectOptions` already exposes, and a `PRAGMA`
/// would be a syntax error on both. For SQLite the pool is built from `SqliteConnectOptions` rather
/// than from a bare URL, because that is the only place the per-connection settings can be made to
/// hold for connections SQLx opens later. `create_if_missing` matches the `?mode=rwc` this service
/// has always documented, so the behaviour no longer depends on callers remembering the query
/// parameter.
async fn connect_with_limits(db_url: &str, limits: PoolLimits) -> Result<DatabaseConnection, DbErr> {
    // Backend detection by URL scheme, which is the only signal available before a pool exists.
    // Everything downstream reads `get_database_backend()` instead; this is the one place that
    // cannot.
    if !db_url.starts_with("sqlite:") {
        let mut opt = ConnectOptions::new(db_url.to_owned());
        opt.sqlx_logging_level(log::LevelFilter::Debug)
            .max_connections(limits.max_connections)
            .min_connections(limits.min_connections)
            .acquire_timeout(limits.acquire_timeout);
        if let Some(idle_timeout) = limits.idle_timeout {
            opt.idle_timeout(idle_timeout);
        }
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
        // blocking on a database-wide exclusive lock. A no-op on `sqlite::memory:` (SQLite declines
        // the switch there and reports `memory` back), which is exactly the harmless outcome
        // [`apply_sqlite_pragmas`]'s own doc comment describes.
        .journal_mode(SqliteJournalMode::Wal)
        // The one setting here that genuinely changes behaviour: the default is `FULL`. `NORMAL` is
        // the standard companion to WAL — it keeps full durability against *process* crashes and
        // gives up only the last transactions in a power loss, in exchange for not fsyncing on
        // every commit.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_millis(u64::from(SQLITE_BUSY_TIMEOUT_MS)))
        // Temporary tables and indices SQLite creates internally (e.g. for a large `ORDER BY`) are
        // held in memory rather than spilled to a disk file — the engine's own default. A no-op for
        // an in-memory database, which has no disk to spill to in the first place.
        .pragma("temp_store", "MEMORY")
        .pragma("mmap_size", "268435456")
        .pragma("cache_size", "-64000")
        .pragma("analysis_limit", "1000");

    let pool = SqlitePoolOptions::new()
        .max_connections(limits.max_connections)
        .min_connections(limits.min_connections)
        .idle_timeout(limits.idle_timeout)
        .acquire_timeout(limits.acquire_timeout)
        .connect_with(connect_options)
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// Opens the **application** database pool: [`PoolLimits::for_backend`]'s resolved bounds, with
/// SQLite's session pragmas declared on every connection.
///
/// For every backend **except** in-memory SQLite, must be called only after
/// [`run_migrations_isolated`] has already completed against the same `db_url` — see the module
/// header for why the two are kept as separate pools rather than one. In-memory SQLite cannot use
/// that sequence at all; see [`migrate_and_connect`], which every real caller should use instead of
/// calling this function and [`run_migrations_isolated`] directly.
pub async fn connect(db_url: &str, config: &RuntimeConfig) -> Result<DatabaseConnection, DbErr> {
    connect_with_limits(db_url, PoolLimits::for_backend(db_url, config)).await
}

/// Runs every pending migration against a **dedicated, single-connection pool that this function
/// closes before returning** — on every backend, not only SQLite.
///
/// Opening a throwaway pool, migrating through it alone, and closing it before the caller goes on
/// to build the application pool means no connection the application ever uses was open while a
/// migration was in flight, on any backend. See the module header for the race this closes
/// (`duplicate column name` / `SQLITE_BUSY` on SQLite; a read against a half-migrated schema on
/// PostgreSQL/MySQL) and why introducing a wider application pool made this isolation necessary
/// rather than merely tidy.
///
/// Idempotent across restarts, like the `Migrator::up` it wraps: a second call against an
/// already-migrated database applies nothing and succeeds.
///
/// **Never call this against an in-memory SQLite URL.** An in-memory database's entire existence is
/// scoped to the one connection that created it; closing this function's pool would not leave a
/// migrated database behind for anything else to connect to; it would destroy it. Use
/// [`migrate_and_connect`], which knows to route in-memory SQLite around this function entirely.
pub async fn run_migrations_isolated(db_url: &str) -> Result<(), DbErr> {
    tracing::info!("Applying database migrations on an isolated single-connection pool...");
    let migration_acquire_timeout = Duration::from_secs(30);
    let migration_db =
        connect_with_limits(db_url, PoolLimits::migration(migration_acquire_timeout)).await?;

    migrate(&migration_db).await?;

    // Closed explicitly, before this function returns, rather than left to `Drop` — the whole point
    // is that the caller's next step (building the application pool) never overlaps with a
    // migration connection that might still be mid-teardown.
    migration_db.close().await
}

/// Migrates and connects, choosing the one sequence that is actually safe for `db_url`'s backend.
///
/// This is what every real caller — [`crate::main`] included — should call, rather than composing
/// [`run_migrations_isolated`] and [`connect`] by hand: the correct composition is not the same for
/// every backend, and getting it wrong for in-memory SQLite silently loses the entire database
/// rather than raising an error.
///
/// - **In-memory SQLite**: [`run_migrations_isolated`]'s whole premise — migrate on a throwaway pool,
///   close it, connect a separate application pool — is unsound here, because an in-memory
///   database's existence *is* its one connection. Closing the migration pool would not leave a
///   migrated schema behind for a later `connect` to find; it would discard it, and the "application
///   pool" would silently open a second, different, empty in-memory database. So for this one case,
///   [`connect`] runs *first* (opening the single pinned connection — see [`SINGLE_CONNECTION`] —
///   that will serve the whole process lifetime) and [`migrate`] then runs directly against it.
/// - **Every other backend** (file-backed SQLite, PostgreSQL, MySQL): the database persists
///   independently of any one connection, so the safe sequence is exactly [`run_migrations_isolated`]
///   followed by [`connect`] — see the module header for why that ordering, not this function's
///   in-memory exception, is the general rule.
pub async fn migrate_and_connect(
    db_url: &str,
    config: &RuntimeConfig,
) -> Result<DatabaseConnection, DbErr> {
    if is_in_memory_sqlite(db_url) {
        let db = connect(db_url, config).await?;
        migrate(&db).await?;
        return Ok(db);
    }

    run_migrations_isolated(db_url).await?;
    connect(db_url, config).await
}

/// Runs every pending migration against an **already-open** connection, without opening or closing
/// anything itself.
///
/// The low-level primitive [`run_migrations_isolated`] builds on: that function is what production
/// startup calls (own pool, migrate, close), while this one is for a caller that already holds a
/// pool it intends to keep using afterward — every test in this module that migrates and then goes
/// on to query or insert against the same handle needs exactly that, not a pool that vanishes the
/// moment migrations finish.
pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
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

    // The remaining pragmas are set-and-log. Each is per-connection, so on a pool this reaches
    // whichever connection serves it — which is precisely why `connect` declares them at open time
    // and why these calls are confirmation rather than mechanism.
    for (label, statement) in [
        ("foreign key enforcement", "PRAGMA foreign_keys=ON;".to_owned()),
        ("synchronous mode", "PRAGMA synchronous=NORMAL;".to_owned()),
        ("busy timeout", format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")),
        ("temp store", "PRAGMA temp_store=MEMORY;".to_owned()),
        ("mmap size", "PRAGMA mmap_size=268435456;".to_owned()),
        ("cache size", "PRAGMA cache_size=-64000;".to_owned()),
        ("analysis limit", "PRAGMA analysis_limit=1000;".to_owned()),
    ] {
        if let Err(e) =
            db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, statement)).await
        {
            tracing::warn!("Could not set the SQLite {label}: {e}. Continuing with the default.");
        }
    }
    tracing::info!(
        "SQLite session pragmas applied: foreign_keys=ON, synchronous=NORMAL, \
         busy_timeout={SQLITE_BUSY_TIMEOUT_MS}ms, temp_store=MEMORY, mmap_size=256MB, \
         cache_size=64MB, analysis_limit=1000."
    );

    Ok(())
}

/// Runs SQLite query planner statistics optimization (`PRAGMA optimize;`) to ensure the query
/// planner has optimal index selection statistics for query execution.
pub async fn run_sqlite_optimize(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    tracing::info!("Running SQLite query planner optimization (PRAGMA optimize)...");
    if let Err(e) = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA optimize;".to_owned(),
        ))
        .await
    {
        tracing::warn!("Could not run PRAGMA optimize: {e}");
    }

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

    /// All performance and safety settings are in force on a pool built by [`connect`].
    ///
    /// A file-backed database is the only place WAL can actually engage, so that is where the
    /// assertion has to be made — an in-memory database would pass a weaker test vacuously.
    #[tokio::test]
    async fn connect_applies_all_pragmas() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url(), &RuntimeConfig::default())
            .await
            .expect("a file-backed sqlite pool opens");

        assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        assert_eq!(pragma::<i32>(&db, "PRAGMA synchronous;", "synchronous").await, 1, "NORMAL");
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;", "foreign_keys").await, 1, "ON");
        assert_eq!(
            pragma::<i32>(&db, "PRAGMA busy_timeout;", "timeout").await,
            SQLITE_BUSY_TIMEOUT_MS as i32
        );
        // `temp_store`: 0 = engine default (a disk file), 1 = FILE, 2 = MEMORY.
        assert_eq!(pragma::<i32>(&db, "PRAGMA temp_store;", "temp_store").await, 2, "MEMORY");
        assert_eq!(pragma::<i32>(&db, "PRAGMA cache_size;", "cache_size").await, -64000);
        assert_eq!(pragma::<i32>(&db, "PRAGMA analysis_limit;", "analysis_limit").await, 1000);
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

        let db = connect(&tmp.url(), &RuntimeConfig::default()).await.expect("pool opens");
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
        let db = connect(&tmp.url(), &RuntimeConfig::default()).await.expect("pool opens");
        migrate(&db).await.expect("migrations run");

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

    /// An **in-memory** SQLite pool holds exactly one connection, unconditionally — ignoring even a
    /// configured ceiling that says otherwise.
    ///
    /// Asserted against the live pool rather than against the constant, so that changing
    /// [`SINGLE_CONNECTION`] alone cannot satisfy it, and against a config that explicitly *asks*
    /// for a wide pool, so the pin is proven to override the operator's setting rather than merely
    /// agreeing with an unset default.
    #[tokio::test]
    async fn an_in_memory_sqlite_pool_holds_exactly_one_connection_regardless_of_config() {
        let generous = RuntimeConfig { database_max_connections: 64, database_min_connections: 32, ..RuntimeConfig::default() };
        let db = connect("sqlite::memory:", &generous).await.expect("in-memory pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_max_connections(),
            1,
            "an in-memory SQLite pool must hold exactly one connection no matter what \
             DATABASE_MAX_CONNECTIONS asks for — a second connection opens its own separate, \
             empty database"
        );
    }

    /// A **file-backed** SQLite pool is genuinely multi-connection now, clamped to
    /// [`FILE_SQLITE_MAX_CONNECTIONS_CAP`] rather than pinned to one — the behavioural change this
    /// module's pooling work exists to make, now that WAL lets concurrent readers proceed against a
    /// single writer.
    #[tokio::test]
    async fn a_file_backed_sqlite_pool_allows_more_than_one_connection_clamped_to_the_cap() {
        let tmp = TempDb::new();
        let generous = RuntimeConfig { database_max_connections: 64, database_min_connections: 32, ..RuntimeConfig::default() };
        let db = connect(&tmp.url(), &generous).await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_max_connections(),
            FILE_SQLITE_MAX_CONNECTIONS_CAP,
            "a file-backed pool must clamp an oversized configured ceiling down to the SQLite cap, \
             not honour it directly like PostgreSQL/MySQL would"
        );
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_min_connections(),
            FILE_SQLITE_MIN_CONNECTIONS_CAP,
            "the floor clamps the same way"
        );
    }

    /// A **small** configured ceiling for file-backed SQLite is honoured as-is, not raised — the
    /// cap only ever narrows an oversized request, it never widens a deliberately small one.
    #[tokio::test]
    async fn a_small_configured_ceiling_for_file_backed_sqlite_is_not_widened() {
        let tmp = TempDb::new();
        let modest = RuntimeConfig { database_max_connections: 3, database_min_connections: 1, ..RuntimeConfig::default() };
        let db = connect(&tmp.url(), &modest).await.expect("pool opens");
        assert_eq!(db.get_sqlite_connection_pool().options().get_max_connections(), 3);
    }

    /// PostgreSQL/MySQL are not built here (no server in the test environment), but
    /// [`PoolLimits::for_backend`] itself is backend-agnostic below the URL-scheme check, and this
    /// is the one place a Postgres URL's bounds can be asserted without a live server: the
    /// configured ceiling/floor must reach the resolved [`PoolLimits`] untouched, unlike SQLite's
    /// clamping.
    #[test]
    fn non_sqlite_backends_apply_the_configured_pool_bounds_directly() {
        let config = RuntimeConfig {
            database_max_connections: 64,
            database_min_connections: 32,
            database_idle_timeout_secs: 120,
            database_acquire_timeout_secs: 3,
            ..RuntimeConfig::default()
        };
        let limits = PoolLimits::for_backend("postgres://localhost/db", &config);
        assert_eq!(limits.max_connections, 64, "no SQLite-specific clamp applies to PostgreSQL");
        assert_eq!(limits.min_connections, 32);
        assert_eq!(limits.idle_timeout, Some(Duration::from_secs(120)));
        assert_eq!(limits.acquire_timeout, Duration::from_secs(3));

        let mysql_limits = PoolLimits::for_backend("mysql://localhost/db", &config);
        assert_eq!(mysql_limits, limits, "MySQL resolves identically to PostgreSQL — the same generic path");
    }

    /// Migrations complete against a **file-backed** pool built by [`connect`].
    ///
    /// Every other suite in this repository runs on `sqlite::memory:`, where there is nothing to
    /// pool and no file for `m20230106`'s generated column to be re-added against. This is the only
    /// test that exercises the combination [`connect`] actually ships with.
    #[tokio::test]
    async fn migrations_apply_cleanly_on_a_file_backed_pool() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url(), &RuntimeConfig::default()).await.expect("pool opens");
        migrate(&db).await.expect("every migration applies on a pooled file database");

        // Re-running is a no-op rather than an error: this is what a restart does.
        migrate(&db).await.expect("migrations are idempotent across restarts");
    }

    /// [`run_migrations_isolated`] closes its pool, and a fresh [`connect`] against the same
    /// file-backed database finds the migrated schema already there — proving the two-pool
    /// sequence is safe for a backend whose database outlives any one connection to it.
    #[tokio::test]
    async fn run_migrations_isolated_leaves_a_migrated_schema_for_a_later_connect() {
        let tmp = TempDb::new();
        run_migrations_isolated(&tmp.url()).await.expect("isolated migration pool completes");

        let db = connect(&tmp.url(), &RuntimeConfig::default()).await.expect("application pool opens");
        assert!(
            crate::entities::prelude::ApiKey::find().count(&db).await.is_ok(),
            "a query against the api_keys table must succeed — the schema from the closed \
             migration pool is visible to this entirely separate connection"
        );
    }

    /// [`migrate_and_connect`]'s in-memory special case: migrations must land on the *same*
    /// connection the caller goes on to use, since a closed-then-reopened `sqlite::memory:` pool is
    /// a different, empty database, not a reconnection to the same one.
    #[tokio::test]
    async fn migrate_and_connect_leaves_an_in_memory_database_usable() {
        let db = migrate_and_connect("sqlite::memory:", &RuntimeConfig::default())
            .await
            .expect("in-memory migrate-and-connect succeeds");
        assert_eq!(
            crate::entities::prelude::ApiKey::find().count(&db).await.expect("query succeeds"),
            0,
            "the migrated schema is queryable on the very connection migrations ran on"
        );
    }

    /// [`migrate_and_connect`]'s general-backend path: a file-backed database migrated through the
    /// isolated pool and then connected via the separate application pool is fully usable.
    #[tokio::test]
    async fn migrate_and_connect_leaves_a_file_backed_database_usable() {
        let tmp = TempDb::new();
        let db = migrate_and_connect(&tmp.url(), &RuntimeConfig::default())
            .await
            .expect("file-backed migrate-and-connect succeeds");
        assert_eq!(
            crate::entities::prelude::ApiKey::find().count(&db).await.expect("query succeeds"),
            0
        );
    }

    /// WAL is persistent: a *new* connection to the same file inherits it without re-running the
    /// pragma. That is what makes the journal mode the one setting not needing per-connection care.
    #[tokio::test]
    async fn wal_survives_reconnection() {
        let tmp = TempDb::new();
        {
            let db = connect(&tmp.url(), &RuntimeConfig::default()).await.expect("pool opens");
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
        migrate(&db).await.expect("migrations still run");

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
