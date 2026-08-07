//! Shared fixtures for the integration test suite: in-memory databases, key/hook seeding, request
//! construction, and disposable executable scripts.
//!
//! Deliberately has no `#![allow(dead_code)]`: the suite lives in a single integration test
//! binary, so every helper here has a real caller and an unused one is a genuine finding rather
//! than an artifact of per-file compilation.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait};
use sea_orm_migration::MigratorTrait;
use simply_hook_executor::{
    config::{RuntimeConfig, TrustedProxies},
    crypto::SecretCipher,
    entities::{api_key, api_key::HmacMode, api_key_hook_permission, execution, hook, hook_parameter},
    migration,
    state::AppState,
};
use tower::ServiceExt;
use uuid::Uuid;

/// Creates a migrated, isolated in-memory database.
pub async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite is always available");
    migration::Migrator::up(&db, None)
        .await
        .expect("migrations apply to a fresh database");
    db
}

/// The runtime configuration used by every test.
///
/// `PATH` is the only passthrough variable, which pins two things at once: hook scripts can still
/// find `/bin/sh` helpers, and any *other* variable observed inside a child process is a genuine
/// isolation leak rather than test-harness noise.
pub fn test_config() -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        allowed_env_vars: vec!["PATH".to_owned()],
        log_retention_days: 30,
        deleted_hook_retention_days: 92,
        retention_sweep_seconds: 3600,
        max_output_bytes: 64 * 1024,
        signature_max_age_seconds: 300,
        require_signed_requests: false,
        // Unconfined by default: the suite writes throwaway scripts under the system temp dir.
        // Confinement is exercised explicitly via `test_state_with_roots`.
        allowed_script_roots: Vec::new(),
        // No trusted proxies, matching the production default. Every test therefore exercises the
        // secure path — forwarding headers ignored, `bound_ips` evaluated against the TCP peer —
        // and a test that wants headers honoured must opt in via `test_state_with_trusted_proxies`.
        trusted_proxies: TrustedProxies::default(),
    })
}

/// The cipher used by most tests: unencrypted storage, so a seeded signing secret can be written
/// directly. Encryption itself is covered by `crypto`'s own unit tests and by
/// [`test_state_with_cipher`].
pub fn test_cipher() -> Arc<SecretCipher> {
    Arc::new(SecretCipher::Plaintext)
}

/// Builds application state around a database handle.
pub fn test_state(db: &DatabaseConnection) -> AppState {
    AppState::new(db.clone(), test_config(), test_cipher())
}

/// Builds application state where every authenticated route demands a valid signature.
///
/// This is the posture the auth-before-authz ordering matters most under: with signing mandatory, a
/// caller holding only a stolen bearer key genuinely cannot authenticate, so what it can still
/// *learn* from the response code is the whole question.
pub fn test_state_requiring_signatures(db: &DatabaseConnection) -> AppState {
    AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            require_signed_requests: true,
            ..(*test_config()).clone()
        }),
        test_cipher(),
    )
}

/// Builds application state whose hook scripts are confined to `roots`.
pub fn test_state_with_roots(db: &DatabaseConnection, roots: Vec<std::path::PathBuf>) -> AppState {
    AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            allowed_script_roots: roots,
            ..(*test_config()).clone()
        }),
        test_cipher(),
    )
}

/// Builds application state that believes forwarding headers from `proxies`.
///
/// `with_connect_info` simulates a `127.0.0.1` peer, so passing `"127.0.0.1"` here is what puts a
/// test on the "behind a trusted reverse proxy" path. Entries are the raw `TRUSTED_PROXIES`
/// spelling — addresses, CIDRs, or hostnames — so a test can exercise name resolution too.
pub fn test_state_with_trusted_proxies(db: &DatabaseConnection, proxies: &[&str]) -> AppState {
    AppState::new(
        db.clone(),
        Arc::new(RuntimeConfig {
            trusted_proxies: TrustedProxies::from_raw(&proxies.join(","))
                .expect("test fixture proxies are syntactically valid"),
            ..(*test_config()).clone()
        }),
        test_cipher(),
    )
}

/// Builds application state with a specific secret cipher.
pub fn test_state_with_cipher(db: &DatabaseConnection, cipher: Arc<SecretCipher>) -> AppState {
    AppState::new(db.clone(), test_config(), cipher)
}

/// Whether this test process can read a path whose permissions should deny it.
///
/// Running the suite as root defeats every filesystem permission check (root bypasses `x` bits),
/// so tests that depend on a denial must skip rather than fail in that environment.
pub fn permissions_are_enforced_for_this_user(denied_path: &str) -> bool {
    std::fs::metadata(denied_path).is_err()
}

/// The global scopes a seeded key should hold.
#[derive(Clone, Copy, Default)]
pub struct KeyScopes {
    pub is_master: bool,
    pub can_manage_keys: bool,
    pub can_manage_hooks: bool,
    pub max_concurrent_jobs: i32,
}

impl KeyScopes {
    /// A master key.
    pub fn master() -> Self {
        Self { is_master: true, can_manage_keys: true, can_manage_hooks: true, max_concurrent_jobs: 10 }
    }

    /// A scoped key with no global rights.
    pub fn plain() -> Self {
        Self { max_concurrent_jobs: 10, ..Self::default() }
    }

    /// A scoped key allowed to create hooks.
    pub fn hook_manager() -> Self {
        Self { can_manage_hooks: true, max_concurrent_jobs: 10, ..Self::default() }
    }

    /// Overrides the concurrency budget.
    pub fn with_jobs(mut self, jobs: i32) -> Self {
        self.max_concurrent_jobs = jobs;
        self
    }
}

/// Every credential a seeded API key carries.
pub struct SeededKey {
    /// Internal UUID.
    pub id: Uuid,
    /// Bearer credential, sent as `X-API-Key`.
    pub plaintext: String,
    /// Public identifier, for display and log correlation. Never sent as an auth header.
    pub key_id: String,
    /// HMAC signing secret, in plaintext, for computing test signatures.
    pub signing_secret: String,
}

/// Inserts an API key, returning its id and plaintext bearer credential.
///
/// The signing pair is minted too but discarded here; use [`insert_key_full`] when a test needs
/// to compute a signature.
pub async fn insert_key(
    db: &DatabaseConnection,
    name: &str,
    bound_ips: &str,
    scopes: KeyScopes,
) -> (Uuid, String) {
    let seeded = insert_key_full(db, name, bound_ips, scopes).await;
    (seeded.id, seeded.plaintext)
}

/// Inserts an API key and returns its full credential set.
///
/// The signing secret is stored through [`SecretCipher::Plaintext`], matching [`test_cipher`], so
/// the handler under test recovers exactly the value returned here.
pub async fn insert_key_full(
    db: &DatabaseConnection,
    name: &str,
    bound_ips: &str,
    scopes: KeyScopes,
) -> SeededKey {
    insert_key_with_mode(db, name, bound_ips, scopes, HmacMode::CanonicalV1).await
}

/// Inserts an API key pinned to a specific signature verification mode.
pub async fn insert_key_with_mode(
    db: &DatabaseConnection,
    name: &str,
    bound_ips: &str,
    scopes: KeyScopes,
    hmac_mode: HmacMode,
) -> SeededKey {
    let id = Uuid::new_v4();
    let plaintext = simply_hook_executor::api::generate_random_key();
    let key_id = simply_hook_executor::api::generate_key_id();
    let signing_secret = simply_hook_executor::api::generate_signing_secret();
    let now = chrono::Utc::now().naive_utc();

    api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(simply_hook_executor::api::hash_key(&plaintext)),
        name: Set(name.to_owned()),
        prefix: Set(plaintext.chars().take(8).collect()),
        key_id: Set(Some(key_id.clone())),
        signing_secret: Set(Some(
            SecretCipher::Plaintext
                .seal(&signing_secret)
                .expect("sealing a test secret succeeds"),
        )),
        hmac_mode: Set(hmac_mode),
        bound_ips: Set(Some(bound_ips.to_owned())),
        max_concurrent_jobs: Set(scopes.max_concurrent_jobs.max(1)),
        is_master: Set(scopes.is_master),
        // Seeded keys are lineage-less by default: R3 says lineage confers no authority, so a NULL
        // parent must never change how a key behaves. Tests that care about the subtree set it
        // explicitly via [`set_parent`].
        parent_key_id: Set(None),
        owner_key_id: Set(None),
        can_manage_keys: Set(scopes.can_manage_keys),
        can_manage_hooks: Set(scopes.can_manage_hooks),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("seeding an API key succeeds");

    SeededKey { id, plaintext, key_id, signing_secret }
}

/// The current Unix timestamp, as a client would stamp a request.
pub fn now_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Computes an `X-Signature-256` value over the canonical
/// `METHOD \n PATH_AND_QUERY \n TIMESTAMP \n RAW_BODY` string.
pub fn sign_request(signing_secret: &str, method: &str, path: &str, timestamp: i64, body: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(signing_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(format!("{method}\n{path}\n{timestamp}\n{body}").as_bytes());
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Builds a CANONICAL_V1-signed request, stamped at the current time.
///
/// `X-API-Key` is the only identifying header: it is how every caller — dashboard, script, or
/// third-party webhook sender — resolves to a key record.
pub fn signed_request(method: &str, uri: &str, api_key: &str, signing_secret: &str, body: &str) -> Request<Body> {
    signed_request_at(method, uri, api_key, signing_secret, body, now_timestamp())
}

/// As [`signed_request`], but stamped at an explicit time so replay-window behavior is testable.
pub fn signed_request_at(
    method: &str,
    uri: &str,
    api_key: &str,
    signing_secret: &str,
    body: &str,
    timestamp: i64,
) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", sign_request(signing_secret, method, uri, timestamp, body)),
    )
    .body(Body::from(body.to_owned()))
    .expect("request builds")
}

/// Computes a BODY_ONLY signature: HMAC over the raw body alone, with no canonical prefix.
pub fn sign_body_only(signing_secret: &str, body: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(signing_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Builds a request signed the way a GitHub/Forgejo webhook would: body-only signature, no
/// timestamp, and a configurable signature header name.
pub fn body_only_request(
    uri: &str,
    api_key: &str,
    signing_secret: &str,
    body: &str,
    header_name: &str,
) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header(header_name, sign_body_only(signing_secret, body)),
    )
    .body(Body::from(body.to_owned()))
    .expect("request builds")
}

/// Builds a bearer-authenticated request that additionally carries a valid signature.
pub fn signed_bearer_request(
    method: &str,
    uri: &str,
    api_key: &str,
    signing_secret: &str,
    body: &str,
) -> Request<Body> {
    let timestamp = now_timestamp();
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", sign_request(signing_secret, method, uri, timestamp, body)),
    )
    .body(Body::from(body.to_owned()))
    .expect("request builds")
}

/// Inserts an unprivileged hook pointing at `script_path`.
pub async fn insert_hook(
    db: &DatabaseConnection,
    name: &str,
    script_path: &str,
    timeout_seconds: i32,
) -> Uuid {
    insert_hook_as(db, name, script_path, timeout_seconds, None).await
}

/// Inserts a hook, optionally elevated to `run_as_user`. Ownerless — see [`insert_hook_owned_by`].
pub async fn insert_hook_as(
    db: &DatabaseConnection,
    name: &str,
    script_path: &str,
    timeout_seconds: i32,
    run_as_user: Option<&str>,
) -> Uuid {
    insert_hook_full(db, name, script_path, timeout_seconds, run_as_user, None).await
}

/// Inserts a hook owned by `owner`, the shape `RBAC_MODEL.md` §3's lifecycle rules govern.
///
/// The plain [`insert_hook`] family leaves `owner_key_id` NULL, matching a hook that predates
/// ownership: lifecycle authority over it rests with master alone. Tests about *who may delete or
/// rename* need a real owner, and tests about the un-owned fallback need the absence — so the two
/// are separate helpers rather than one with a defaulted argument nobody reads.
pub async fn insert_hook_owned_by(
    db: &DatabaseConnection,
    name: &str,
    script_path: &str,
    owner: Uuid,
) -> Uuid {
    insert_hook_full(db, name, script_path, 30, None, Some(owner)).await
}

/// The full hook seeder the three wrappers above delegate to.
pub async fn insert_hook_full(
    db: &DatabaseConnection,
    name: &str,
    script_path: &str,
    timeout_seconds: i32,
    run_as_user: Option<&str>,
    owner_key_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();

    hook::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        description: Set(None),
        script_path: Set(script_path.to_owned()),
        default_timeout_seconds: Set(timeout_seconds),
        run_as_user: Set(run_as_user.map(str::to_owned)),
        owner_key_id: Set(owner_key_id),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("seeding a hook succeeds");

    id
}

/// Inserts a hook already in the trash, backdated by `deleted_days_ago`.
///
/// Backdating is the only way to exercise the 92-day purge without waiting a quarter:
/// `hooks.deleted_at` is written by the handler at deletion time, so an age has to be seeded
/// directly — the same approach [`insert_execution_aged`] takes for log retention.
pub async fn insert_hook_deleted_days_ago(
    db: &DatabaseConnection,
    name: &str,
    script_path: &str,
    deleted_days_ago: i64,
    deleted_by: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let deleted_at = (chrono::Utc::now() - chrono::Duration::days(deleted_days_ago)).naive_utc();

    hook::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        description: Set(None),
        script_path: Set(script_path.to_owned()),
        default_timeout_seconds: Set(30),
        run_as_user: Set(None),
        owner_key_id: Set(None),
        is_deleted: Set(true),
        deleted_at: Set(Some(deleted_at)),
        deleted_by: Set(Some(deleted_by.to_string())),
        created_at: Set(now),
        updated_at: Set(deleted_at),
    }
    .insert(db)
    .await
    .expect("seeding a deleted hook succeeds");

    id
}

/// Reads a hook row directly, bypassing the API's soft-delete filtering.
///
/// The point of soft delete is that the row survives while the API pretends it does not, so proving
/// that needs a path to the database the handlers do not mediate.
pub async fn fetch_hook_row(db: &DatabaseConnection, id: Uuid) -> Option<hook::Model> {
    hook::Entity::find_by_id(id).one(db).await.expect("querying hooks succeeds")
}

/// Declares a parameter on a hook.
pub async fn insert_parameter(
    db: &DatabaseConnection,
    hook_id: Uuid,
    param_key: &str,
    default_value: Option<&str>,
    is_required: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    hook_parameter::ActiveModel {
        id: Set(id),
        hook_id: Set(hook_id),
        param_key: Set(param_key.to_owned()),
        description: Set(None),
        default_value: Set(default_value.map(str::to_owned)),
        is_required: Set(is_required),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .expect("seeding a hook parameter succeeds");
    id
}

/// Inserts a completed execution record backdated by `age_days`, returning its id.
///
/// Backdating is the only way to exercise retention without waiting: `executions.timestamp` is
/// written by the engine at execution time, so an age has to be seeded directly.
pub async fn insert_execution_aged(
    db: &DatabaseConnection,
    hook_id: Uuid,
    age_days: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    execution::ActiveModel {
        id: Set(id),
        hook_id: Set(hook_id),
        api_key_id: Set(None),
        status: Set(execution::ExecutionStatus::Success),
        exit_code: Set(Some(0)),
        stdout: Set(String::new()),
        stderr: Set(String::new()),
        parameters_json: Set("{}".to_owned()),
        duration_ms: Set(5),
        timestamp: Set((chrono::Utc::now() - chrono::Duration::days(age_days)).naive_utc()),
    }
    .insert(db)
    .await
    .expect("seeding an execution succeeds");
    id
}

/// Counts the execution rows currently stored.
pub async fn execution_count(db: &DatabaseConnection) -> u64 {
    use sea_orm::PaginatorTrait;
    execution::Entity::find()
        .count(db)
        .await
        .expect("counting executions succeeds")
}

/// Polls `condition` until it holds or `timeout` elapses; returns whether it held.
///
/// Used instead of a fixed sleep wherever a background worker or sub-process has to reach some
/// state: it makes the test both faster in the common case and robust on a loaded CI machine.
pub async fn wait_until<F>(timeout: std::time::Duration, mut condition: F) -> bool
where
    F: AsyncFnMut() -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if condition().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    condition().await
}

/// Grants a key rights over a hook.
pub async fn grant(
    db: &DatabaseConnection,
    key_id: Uuid,
    hook_id: Uuid,
    can_execute: bool,
    can_manage: bool,
) {
    api_key_hook_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        hook_id: Set(hook_id),
        can_execute: Set(can_execute),
        can_manage: Set(can_manage),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .expect("seeding a permission grant succeeds");
}

/// Attaches the `ConnectInfo` extension the auth middleware requires, simulating a loopback peer.
pub fn with_connect_info(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        8080,
    ))))
}

/// Builds a JSON request carrying an API key.
pub fn json_request(method: &str, uri: &str, key: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let builder = with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-API-Key", key)
            .header("Content-Type", "application/json"),
    );
    let body = match body {
        Some(value) => Body::from(value.to_string()),
        None => Body::empty(),
    };
    builder.body(body).expect("request builds")
}

/// Builds a request carrying an API key and an arbitrary raw body.
///
/// Distinct from [`json_request`], which takes a `serde_json::Value`: the payload-limit tests need
/// to put megabytes of bytes on the wire without first materializing them as a JSON tree.
pub fn raw_request(method: &str, uri: &str, key: &str, body: Vec<u8>) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-API-Key", key)
            .header("Content-Type", "application/json"),
    )
    .body(Body::from(body))
    .expect("request builds")
}

/// The status, headers, and decoded JSON body of a response.
pub struct TestResponse {
    pub status: StatusCode,
    pub json: serde_json::Value,
    /// The `Content-Type` header, if any.
    ///
    /// Worth asserting on for any endpoint that echoes attacker-controlled bytes back: a JSON
    /// document containing `<script>` is inert only while the browser is told it is JSON. Were a
    /// handler ever to answer `text/html`, navigating straight to the API URL would render it.
    pub content_type: Option<String>,
    /// The undecoded response body, for assertions about the exact bytes on the wire rather than
    /// about the parsed value.
    pub raw: String,
}

impl TestResponse {
    /// Reads a field from the response body, panicking with a useful message when absent.
    pub fn field(&self, key: &str) -> &serde_json::Value {
        self.json
            .get(key)
            .unwrap_or_else(|| panic!("response has no '{key}' field: {}", self.json))
    }

    /// Reads a string field.
    pub fn string(&self, key: &str) -> String {
        self.field(key).as_str().unwrap_or_default().to_owned()
    }
}

/// Sends a request through the router and decodes the response.
///
/// An empty body decodes as JSON `null` rather than erroring, so `204 No Content` responses can be
/// asserted on with the same helper as everything else.
pub async fn send(app: &axum::Router, request: Request<Body>) -> TestResponse {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .expect("response body is readable");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    TestResponse { status, json, content_type, raw }
}

/// A temporary directory holding executable test scripts, removed on drop.
pub struct ScriptDir {
    path: std::path::PathBuf,
}

impl ScriptDir {
    /// Creates a fresh, uniquely-named directory under the system temp dir.
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("simply_hook_executor_test_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("temp directory is creatable");
        Self { path }
    }

    /// Writes an executable `/bin/sh` script and returns its absolute path.
    pub fn write_script(&self, name: &str, body: &str) -> String {
        let path = self.path.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script is writable");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("script is chmod-able");
        }

        path.to_string_lossy().into_owned()
    }

    /// An absolute path inside this directory that no file occupies yet.
    pub fn path_for(&self, name: &str) -> String {
        self.path.join(name).to_string_lossy().into_owned()
    }

    /// This directory's own absolute path — used as an `ALLOWED_SCRIPT_ROOTS` entry.
    pub fn root(&self) -> std::path::PathBuf {
        self.path.clone()
    }

    /// Writes a file with an exact permission mode, returning its absolute path.
    ///
    /// Unlike [`ScriptDir::write_script`] this does not force `0o755`, which is the point: it is
    /// how the suite produces a script that exists and is readable but carries no execute bit.
    pub fn write_with_mode(&self, name: &str, body: &str, mode: u32) -> String {
        let path = self.path.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("file is writable");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("permissions are settable");
        }

        path.to_string_lossy().into_owned()
    }

    /// Creates a sub-directory, returning its absolute path.
    pub fn make_dir(&self, name: &str) -> String {
        let path = self.path.join(name);
        std::fs::create_dir_all(&path).expect("directory is creatable");
        path.to_string_lossy().into_owned()
    }

    /// Symlinks `link_name` inside this directory to `target`, returning the link's path.
    #[cfg(unix)]
    pub fn symlink_to(&self, link_name: &str, target: &str) -> String {
        let link = self.path.join(link_name);
        std::os::unix::fs::symlink(target, &link).expect("symlink is creatable");
        link.to_string_lossy().into_owned()
    }
}

impl Drop for ScriptDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
