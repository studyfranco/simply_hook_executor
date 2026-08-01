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

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://simply_hook_executor.db?mode=rwc".to_owned());

    tracing::info!("Connecting to database...");
    let mut opt = ConnectOptions::new(db_url);
    opt.sqlx_logging_level(log::LevelFilter::Debug);
    let db: DatabaseConnection = Database::connect(opt).await?;

    // Before migrations: the migration run is itself a long write, and is exactly the moment a
    // concurrently-starting replica would otherwise hit SQLITE_BUSY.
    db::apply_sqlite_pragmas(&db).await?;

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

    let config = RuntimeConfig::from_env();
    tracing::info!(
        allowed_env_vars = ?config.allowed_env_vars,
        log_retention_days = config.log_retention_days,
        max_output_bytes = config.max_output_bytes,
        "Runtime configuration loaded."
    );

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
