//! The `api_keys` table: authentication tokens, global access rights, concurrency budget, and
//! CIDR network bindings.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// How a key's `X-Signature-256` is verified.
///
/// **`CANONICAL_V1` is the only value this enum accepts.** `BODY_ONLY` — the GitHub/Forgejo/GitLab
/// raw-body-only convention, with no timestamp and no replay protection — was retired once
/// `hooks.auth_mode = HMAC_ONLY` began serving the exact same third-party-sender use case at the
/// **hook** level, with no bearer key involved at all, which is the shape that kind of sender
/// actually has. `m20260819_141730_consolidate_hmac_modes` rewrote every row still holding the old
/// value to `CANONICAL_V1` before this variant was removed from the type, so no stored row can fail
/// to parse.
///
/// A single-variant enum rather than removing `hmac_mode` outright: the column, and the `From`/
/// `TryFrom` machinery `DeriveActiveEnum` generates for it, are still how the row round-trips through
/// SeaORM, and a future second mode (if one is ever justified) has a type to extend rather than a
/// column to reintroduce. [`Model::canonical_template`] is the customization surface now — a key
/// that needs its `CANONICAL_V1` signature computed over something other than the service-wide
/// default template sets that instead of switching modes.
///
/// Stored as a plain string rather than a native database enum so the schema stays portable across
/// SQLite/PostgreSQL/MySQL without vendor-specific DDL.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HmacMode {
    /// Signature covers `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY` (or [`Model::canonical_template`],
    /// when set), with a mandatory `X-Timestamp` inside the anti-replay window.
    ///
    /// The only mode: because the timestamp is *inside* the signed material, a captured request
    /// cannot be re-dated, and because the method and target are too, it cannot be aimed at a
    /// different route.
    #[default]
    #[sea_orm(string_value = "CANONICAL_V1")]
    CanonicalV1,
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
    /// The key that created this one. **Lineage only — never authority.**
    ///
    /// `RBAC_MODEL.md` R3 is emphatic: "`parent_key_id` exists solely for cascading deletion and
    /// visibility scoping. A daughter of the Master key is an ordinary daughter key with no
    /// elevated standing." No authorization decision may read this field. `None` for the bootstrap
    /// master, which has no creator, and for every key issued before lineage was recorded.
    pub parent_key_id: Option<Uuid>,
    /// Key generation timestamp.
    pub created_at: DateTime,
    /// Key last-update timestamp.
    pub updated_at: DateTime,
    /// Override of the `CANONICAL_V1` canonical string template this key's own signatures are
    /// verified against. `None` means the service-wide default,
    /// `{method}\n{path}\n{timestamp}\n{body}`.
    ///
    /// **Never `Some` while [`Model::can_manage_keys`] is `true`** — enforced by
    /// `guards::guard_canonical_v1_for_key_management` at both creation and update. The credential
    /// that can administer every other one stays on the one canonical string this codebase's
    /// signature verification has actually been reviewed against; every other key is free to
    /// customize it (e.g. for compatibility with an existing signing client that already computes a
    /// different canonical shape).
    pub canonical_template: Option<String>,
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
