//! `simply_hook_executor` daemon entry point: database bootstrap, master key provisioning, HTTP
//! server, and graceful shutdown.

use std::net::SocketAddr;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database, DatabaseConnection,
    EntityTrait, QueryFilter,
};
use sea_orm_migration::MigratorTrait;
use simply_hook_executor::{
    api, config, config::RuntimeConfig, create_app, crypto, db, entities, migration,
    spawn_retention_worker, state::AppState,
};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Waits for Ctrl+C or (on Unix) SIGTERM so `axum::serve` can shut down gracefully.
///
/// If signal registration itself fails, that branch is left pending forever instead of firing
/// immediately: an unregisterable signal should never be treated as "shutdown requested now".
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Received shutdown signal.");
}

/// Generates a default Master API Key if the database does not already contain one.
///
/// Checks specifically for the absence of a key with `is_master = true` (not merely "any key
/// exists"): if every master key were deleted while lower-privilege sub-keys remained,
/// administrators could otherwise be permanently locked out.
///
/// If `INITIAL_MASTER_KEY` is set, its exact value is used as the plaintext secret instead of a
/// generated one. This exists purely for deterministic test/CI bootstrap (e.g.
/// `scripts/test_e2e.sh`), where the caller needs to know the master key up front rather than
/// scraping it back out of stdout — it is deliberately **not** a normal deployment option, since a
/// human-chosen secret defeats the point of a random 256-bit key. A warning is logged whenever
/// it's used, so it cannot be enabled in a real deployment without someone noticing.
async fn bootstrap_master_key(
    db: &DatabaseConnection,
    cipher: &crypto::SecretCipher,
) -> Result<(), Box<dyn std::error::Error>> {
    use entities::{api_key, prelude::ApiKey};

    let existing_master = ApiKey::find()
        .filter(api_key::Column::IsMaster.eq(true))
        .one(db)
        .await?;
    if existing_master.is_some() {
        return Ok(());
    }

    let plaintext_key = match std::env::var("INITIAL_MASTER_KEY") {
        Ok(fixed_key) if !fixed_key.is_empty() => {
            tracing::warn!(
                "INITIAL_MASTER_KEY is set: using the provided value as the master key instead \
                 of generating a random one. This is intended for deterministic test/CI bootstrap \
                 only — do not set this in a real deployment."
            );
            fixed_key
        }
        _ => api::generate_random_key(),
    };
    let key_hash = api::hash_key(&plaintext_key);
    // Both families, matching the `api_keys.bound_ips` column default in `SCHEMA.MD`. Listing only
    // `0.0.0.0/0` would have been harmless while master keys bypassed the CIDR check; now that they
    // are held to it, an IPv4-only default would lock an operator out of a dual-stack deployment on
    // the very first request.
    let bound_ip =
        std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0,::/0".to_owned());

    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let now = chrono::Utc::now().naive_utc();

    // The bootstrap key gets a full signing pair too, so webhook signature auth is usable
    // immediately rather than requiring a rotation first.
    let key_id = api::generate_key_id();
    let signing_secret = api::generate_signing_secret();

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(key_hash),
        name: Set("System Master".to_owned()),
        prefix: Set(prefix),
        key_id: Set(Some(key_id.clone())),
        signing_secret: Set(Some(cipher.seal(&signing_secret)?)),
        // The bootstrap key gets the strict mode; relaxing it is a deliberate per-key choice.
        hmac_mode: Set(entities::api_key::HmacMode::CanonicalV1),
        bound_ips: Set(Some(bound_ip.clone())),
        max_concurrent_jobs: Set(10),
        is_master: Set(true),
        // The master has no creator and no owner: it is minted against an empty table. R3 makes
        // that harmless — lineage confers no authority, so a NULL parent is not a missing
        // privilege, and every key the master goes on to create records the master as its parent.
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        can_manage_keys: Set(true),
        can_manage_hooks: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };

    model.insert(db).await?;

    tracing::info!(
        "\n╔══════════════════════════════════════════════════════════════╗\n\
         ║  BOOTSTRAP: Master API Key Generated                       ║\n\
         ║  Key:      {}  ║\n\
         ║  Key ID:   {:52}║\n\
         ║  Secret:   {}  ║\n\
         ║  Bound:    {:52}║\n\
         ║  ⚠ Shown once. Store the key and signing secret securely!  ║\n\
         ╚══════════════════════════════════════════════════════════════╝",
        plaintext_key,
        key_id,
        signing_secret,
        bound_ip
    );

    // tracing's fmt subscriber buffers writes; a reader tailing the redirected log right after
    // this point could otherwise see a truncated or missing banner for a short window.
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    Ok(())
}

/// Resolves every `TRUSTED_PROXIES` hostname at startup, and schedules one re-check if any failed.
///
/// Startup is where a misspelled or not-yet-running proxy should be reported, while an operator is
/// still watching the log — the alternative is discovering it later as inexplicable `403`s from
/// clients whose `bound_ips` were evaluated against the proxy's address instead of their own.
///
/// What it deliberately does **not** do is fail. A name that does not resolve at boot is usually a
/// sibling container that has not finished starting, and this daemon and its reverse proxy come up
/// together with no ordering guarantee. Aborting would convert an ordinary startup race into a
/// crash loop, which is strictly worse than serving: the entry is already fail-closed — an
/// unresolvable name is trusted by nobody — so the running daemon is more available and no less
/// safe. Trust for that one entry is withheld; the service as a whole keeps working.
///
/// After [`config::TRUSTED_PROXY_BOOT_GRACE`] the failed names are tried once more, loudly, so the
/// log carries a definitive verdict rather than only the initial pessimistic one. The steady-state
/// negative cache retries continuously regardless; this exists to make the outcome *legible*.
fn prime_trusted_proxies(trusted_proxies: &config::TrustedProxies) {
    // `RuntimeConfig::from_env` has already reported what is configured (or that nothing is), so
    // there is nothing to add when there are no names to look up.
    if trusted_proxies.is_empty() {
        return;
    }

    let proxies = trusted_proxies.clone();
    tokio::spawn(async move {
        let unresolved = proxies.prime().await;
        if unresolved.is_empty() {
            tracing::info!("All TRUSTED_PROXIES entries resolved.");
            return;
        }

        tracing::error!(
            "TRUSTED_PROXIES {unresolved:?} could not be resolved at startup. Forwarding headers \
             from those hosts are NOT trusted, and requests through them will be matched against \
             the proxy's own address. Serving anyway; re-checking in {}s.",
            config::TRUSTED_PROXY_BOOT_GRACE.as_secs()
        );

        tokio::time::sleep(config::TRUSTED_PROXY_BOOT_GRACE).await;

        let still_unresolved = proxies.prime().await;
        if still_unresolved.is_empty() {
            tracing::info!(
                "TRUSTED_PROXIES {unresolved:?} resolved on re-check; they are trusted from now on."
            );
        } else {
            tracing::error!(
                "TRUSTED_PROXIES {still_unresolved:?} are still unresolvable after the {}s grace \
                 period. Continuing with those entries disabled — check the names and the \
                 daemon's DNS configuration. They are retried automatically as traffic arrives.",
                config::TRUSTED_PROXY_BOOT_GRACE.as_secs()
            );
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // Colour only when stdout is a terminal. Under systemd or any redirect, ANSI escapes would
        // be written verbatim into journald and log files, which makes them ugly to read and — more
        // importantly — breaks `grep 'rejection=PermissionDenied'`, since the codes land between the
        // field name and its value.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    // Read before the database is touched, because this is the step that can refuse to start. A
    // malformed TRUSTED_PROXIES entry is a misconfigured trust boundary (see
    // `config::parse_trusted_proxies`), and aborting *after* running migrations and possibly
    // minting and printing a bootstrap master key would leave side effects behind from a boot that
    // never completed. Every other override in here is lenient and cannot fail.
    // Not `?`: returning the error from `main` would render it through `Debug`, printing the struct
    // rather than the message. The message *is* the operator's entire diagnostic here, so it is
    // logged through `Display` and the process exits deliberately. Nothing is open yet — no
    // database handle, no listener — so there are no destructors worth unwinding for.
    let config = match RuntimeConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        allowed_env_vars = ?config.allowed_env_vars,
        log_retention_days = config.log_retention_days,
        deleted_hook_retention_days = config.deleted_hook_retention_days,
        max_output_bytes = config.max_output_bytes,
        "Runtime configuration loaded."
    );

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://simply_hook_executor.db?mode=rwc".to_owned());

    tracing::info!("Connecting to database...");
    let mut opt = ConnectOptions::new(db_url);
    opt.sqlx_logging_level(log::LevelFilter::Debug);
    let db: DatabaseConnection = Database::connect(opt).await?;

    // Before migrations: the migration run is itself a long write, and is exactly the moment a
    // concurrently-starting replica would otherwise hit SQLITE_BUSY.
    //
    // Explicitly non-fatal, and the `if let` rather than `?` is the point. These are *performance*
    // pragmas: WAL removes reader/writer contention and the busy timeout absorbs writer collisions,
    // but the daemon is entirely correct without either. Refusing to boot over one — on a
    // filesystem that will not support WAL, or an in-memory database that legitimately cannot — is
    // trading a real outage for a theoretical slowdown. The failure is logged loudly instead.
    if let Err(e) = db::apply_sqlite_pragmas(&db).await {
        tracing::warn!(
            "Could not apply the SQLite concurrency pragmas: {e}. Starting anyway — expect \
             reduced write concurrency, but correctness is unaffected."
        );
    }

    tracing::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;

    // Built before the bootstrap key is minted, since that key's signing secret is sealed with it.
    // A malformed SIGNING_SECRET_KEY stops startup here rather than silently degrading to writing
    // signing secrets in the clear.
    let cipher = crypto::SecretCipher::from_env()?;
    if cipher.is_encrypting() {
        tracing::info!("Signing secrets are encrypted at rest (SIGNING_SECRET_KEY is configured).");
    } else {
        tracing::warn!(
            "SIGNING_SECRET_KEY is not set: API key signing secrets are stored unencrypted. \
             Anyone who can read the database can forge webhook signatures. Generate a key with \
             `openssl rand -hex 32` and set SIGNING_SECRET_KEY to enable encryption at rest."
        );
    }

    bootstrap_master_key(&db, &cipher).await?;

    prime_trusted_proxies(&config.trusted_proxies);

    let state = AppState::new(db, config.shared(), std::sync::Arc::new(cipher));
    let (retention_tx, retention_handle) = spawn_retention_worker(&state);

    let app = create_app(state);

    let addr = config::resolve_bind_addr();
    let listener = TcpListener::bind(addr).await?;
    // Reported from the listener rather than from `addr`: with `PORT=0` the OS assigns an
    // ephemeral port, and the requested address would then be a misleading thing to log.
    let bound = listener.local_addr().unwrap_or(addr);
    tracing::info!("Simply Hook Executor API listening on http://{}", bound);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Stopping log retention worker...");
    drop(retention_tx);
    let _ = retention_handle.await;

    tracing::info!("Graceful shutdown complete.");
    Ok(())
}
