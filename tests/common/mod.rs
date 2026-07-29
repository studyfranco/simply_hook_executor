//! Shared fixtures for the integration test suite: in-memory databases, key/hook seeding, request
//! construction, and disposable executable scripts.

// Every integration test file compiles its own copy of this module, so a helper used by only some
// of them would otherwise warn here.
#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use simply_hook_executor::{
    config::RuntimeConfig,
    entities::{api_key, api_key_hook_permission, hook, hook_parameter},
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
        retention_sweep_seconds: 3600,
        max_output_bytes: 64 * 1024,
    })
}

/// Builds application state around a database handle.
pub fn test_state(db: &DatabaseConnection) -> AppState {
    AppState::new(db.clone(), test_config())
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

/// Inserts an API key, returning its id and plaintext secret.
pub async fn insert_key(
    db: &DatabaseConnection,
    name: &str,
    bound_ips: &str,
    scopes: KeyScopes,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_hook_executor::api::generate_random_key();
    let now = chrono::Utc::now().naive_utc();

    api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(simply_hook_executor::api::hash_key(&plaintext)),
        name: Set(name.to_owned()),
        prefix: Set(plaintext.chars().take(8).collect()),
        bound_ips: Set(Some(bound_ips.to_owned())),
        max_concurrent_jobs: Set(scopes.max_concurrent_jobs.max(1)),
        is_master: Set(scopes.is_master),
        can_manage_keys: Set(scopes.can_manage_keys),
        can_manage_hooks: Set(scopes.can_manage_hooks),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("seeding an API key succeeds");

    (id, plaintext)
}

/// Inserts a hook pointing at `script_path`.
pub async fn insert_hook(
    db: &DatabaseConnection,
    name: &str,
    script_path: &str,
    timeout_seconds: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();

    hook::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        description: Set(None),
        script_path: Set(script_path.to_owned()),
        default_timeout_seconds: Set(timeout_seconds),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("seeding a hook succeeds");

    id
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

/// The status and decoded JSON body of a response.
pub struct TestResponse {
    pub status: StatusCode,
    pub json: serde_json::Value,
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
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body is readable");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    TestResponse { status, json }
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
}

impl Drop for ScriptDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
