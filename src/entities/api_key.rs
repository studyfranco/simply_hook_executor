//! The `api_keys` table: authentication tokens, global access rights, concurrency budget, and
//! CIDR network bindings.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// How a key's `X-Signature-256` is verified.
///
/// Stored as a plain string rather than a native database enum so the schema stays portable across
/// SQLite/PostgreSQL/MySQL without vendor-specific DDL.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HmacMode {
    /// Signature covers `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY`, with a mandatory
    /// `X-Timestamp` inside the anti-replay window.
    ///
    /// The default, and the only mode that resists replay: because the timestamp is *inside* the
    /// signed material, a captured request cannot be re-dated, and because the method and target
    /// are too, it cannot be aimed at a different route.
    #[default]
    #[sea_orm(string_value = "CANONICAL_V1")]
    CanonicalV1,
    /// Signature covers the raw body only, accepted from either `X-Signature-256` or
    /// `X-Hub-Signature-256`, with no timestamp required.
    ///
    /// This is the GitHub/Forgejo/GitLab webhook convention, and exists solely for compatibility
    /// with senders whose signature format cannot be changed. It provides **no replay protection**
    /// — an intercepted request stays valid forever — so it must be opted into per key, and only
    /// for keys scoped to the hooks that third party is meant to trigger.
    #[sea_orm(string_value = "BODY_ONLY")]
    BodyOnly,
}

/// A single API key: its identity, global RBAC scopes, execution budget, and network binding rule.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Unique identifier for the API key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable key description (e.g. `"Vault Webhook Client"`).
    pub name: String,
    /// SHA-256 hash of the secret API key (the plaintext key is never stored).
    #[sea_orm(unique)]
    pub key_hash: String,
    /// First 8 characters of the plaintext key, kept for display and log correlation.
    pub prefix: String,
    /// Public, non-secret identifier (`shk_<32 hex>`) used for display and log correlation.
    ///
    /// Deliberately *not* a credential and not an authentication header: callers identify
    /// themselves with `X-API-Key`, which is the single key lookup path. `None` only for keys
    /// issued before signing secrets existed; rotating such a key mints a pair.
    #[sea_orm(unique)]
    pub key_id: Option<String>,
    /// HMAC-SHA256 signing secret, **encrypted at rest** (see [`crate::crypto`]).
    ///
    /// Unlike `key_hash` this cannot be a digest: verifying a signature means recomputing it, so
    /// the original bytes have to be recoverable. Never serialized to a client — it leaves the
    /// server exactly once, in the creation/rotation response, and only as plaintext.
    #[sea_orm(column_type = "Text", nullable)]
    pub signing_secret: Option<String>,
    /// Which signature scheme this key's requests are verified under. See [`HmacMode`].
    pub hmac_mode: HmacMode,
    /// Comma-separated CIDR ranges allowed to use this key (e.g. `127.0.0.1/32,::/0`). An empty
    /// value means no CIDR restriction is enforced.
    pub bound_ips: Option<String>,
    /// Maximum number of hook executions this key may have running simultaneously. Enforced by a
    /// `tokio::sync::Semaphore` in [`crate::executor`]; exceeding it yields `429 Too Many Requests`.
    pub max_concurrent_jobs: i32,
    /// Bypasses all RBAC checks (and CIDR binding checks) when `true`.
    pub is_master: bool,
    /// Global privilege to create/edit/delete other API keys.
    pub can_manage_keys: bool,
    /// Global privilege to create new hooks. Managing an *existing* hook additionally requires an
    /// explicit `can_manage` grant in `api_key_hook_permissions` (AGENT.MD least-privilege rule).
    pub can_manage_hooks: bool,
    /// Key generation timestamp.
    pub created_at: DateTime,
    /// Key last-update timestamp.
    pub updated_at: DateTime,
}

/// Relations from `api_keys` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// This key's per-hook permission grants.
    #[sea_orm(has_many = "super::api_key_hook_permission::Entity")]
    ApiKeyHookPermission,
    /// Executions requested by this key.
    #[sea_orm(has_many = "super::execution::Entity")]
    Execution,
    /// Audit log entries attributed to this key.
    #[sea_orm(has_many = "super::audit_log::Entity")]
    AuditLog,
}

impl Related<super::api_key_hook_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyHookPermission.def()
    }
}

impl Related<super::execution::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Execution.def()
    }
}

impl Related<super::audit_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuditLog.def()
    }
}

impl Related<super::hook::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_hook_permission::Relation::Hook.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_hook_permission::Relation::ApiKey.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
