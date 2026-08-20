//! The `hooks` table: executable script definitions and their execution constraints.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// How a request that invokes this hook (`execute`, `test`, or the `/webhook/{identifier}` alias)
/// must authenticate, for a caller presenting **no** `X-API-Key`.
///
/// A caller that *does* present a valid `X-API-Key` with `can_execute` on the hook is authenticated
/// and authorized by the key itself — the key's own `hmac_mode` governs whether its signature is
/// required, exactly as for every other route — and this field is not consulted at all for that
/// caller. `auth_mode` only ever *adds* a way in for a keyless caller; it never removes the
/// always-available keyed path.
///
/// Stored as a plain string rather than a native database enum, matching [`super::api_key::HmacMode`],
/// so the schema stays portable across SQLite/PostgreSQL/MySQL without vendor-specific DDL.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthMode {
    /// **The default.** A keyless request is refused with `401`; only a caller presenting a valid,
    /// permitted `X-API-Key` may invoke this hook.
    ///
    /// If [`Model::canonical_template`] is set, a *keyed* `CANONICAL_V1` caller's signature is
    /// verified against that custom template instead of the service-wide default — scoping a
    /// non-standard canonical string to this one hook rather than requiring every key in the
    /// deployment to sign the same way.
    #[default]
    #[sea_orm(string_value = "CANONICAL_V1")]
    CanonicalV1,
    /// A keyless request is refused with `401`, identically to [`Self::CanonicalV1`] from a keyless
    /// caller's perspective. The two modes exist to record different operator intent about what a
    /// *keyed* caller is expected to present — `ApiKeyOnly` documents "a bearer key alone is
    /// sufficient for this integration, it need not also sign" — but neither mode changes how a
    /// keyed request is actually verified, which is governed entirely by the presenting key's own
    /// `hmac_mode` and the deployment's `REQUIRE_SIGNED_REQUESTS` setting.
    #[sea_orm(string_value = "API_KEY_ONLY")]
    ApiKeyOnly,
    /// A keyless request is accepted if it carries a valid signature over the raw body, verified
    /// against [`Model::hmac_secret`] — this hook's own secret, never a key's. No `X-API-Key` and no
    /// timestamp are involved, so there is **no anti-replay protection**: an intercepted request
    /// stays valid forever. This is the GitHub/Forgejo/GitLab third-party webhook shape, and exists
    /// solely to accept senders whose signature format cannot be changed.
    #[sea_orm(string_value = "HMAC_ONLY")]
    HmacOnly,
    /// A keyless, unsigned request is accepted outright — **no authentication of any kind** — but
    /// only when the deployment's `REQUIRE_SIGNED_REQUESTS` is `false`. A deployment that has opted
    /// into mandatory signing globally is refusing exactly this shape of request everywhere else in
    /// the API, and a hook set to `NONE` must not become the one door that setting does not cover.
    /// Rust's `None` is deliberately not this variant's name — `Option::None` is spelled identically
    /// and the collision would be a standing hazard in every match arm that touches both.
    #[sea_orm(string_value = "NONE")]
    #[serde(rename = "NONE")]
    NoAuth,
}

/// A single hook: a named, permission-guarded pointer to a local executable.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "hooks")]
pub struct Model {
    /// Unique identifier for the hook.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Unique hook identifier name (e.g. `nftables_ban`). Usable in place of the UUID on the
    /// `/webhook/{identifier}` entry point.
    #[sea_orm(unique)]
    pub name: String,
    /// Optional summary of what the hook script does.
    pub description: Option<String>,
    /// Absolute filesystem path to the executable (e.g. `/usr/local/bin/ban.sh`). Never passed
    /// through a shell — see [`crate::executor`].
    pub script_path: String,
    /// Maximum allowed runtime, in seconds, before the process group is `SIGKILL`ed.
    pub default_timeout_seconds: i32,
    /// Target account for privileged execution.
    ///
    /// `None` (or empty) runs the script directly under the daemon's own user. A value runs it
    /// through `sudo -n -u <user> --`, so what is actually permitted remains governed by
    /// `sudoers` — this field can request elevation, never grant it.
    pub run_as_user: Option<String>,
    /// The key answerable for this hook: **the only non-master identity that may delete or rename
    /// it** (`RBAC_MODEL.md` §3).
    ///
    /// Deliberately not derivable from `api_key_hook_permissions`. A creator receives an ordinary
    /// `can_manage` row there, byte-identical to a delegated one, so "holds `can_manage`" says
    /// nothing about authorship and is usually true of several keys. §3 draws the line exactly
    /// here: holding manage rights, or any operational verb, confers no lifecycle authority — "a
    /// parent that merely uses a resource must not be able to delete it."
    ///
    /// `None` for hooks that predate ownership, which leaves lifecycle authority with master alone
    /// until an operator assigns it. Master may reassign it at any time.
    pub owner_key_id: Option<Uuid>,
    /// Whether the hook is in the trash rather than live.
    ///
    /// A soft-deleted hook is invisible to every ordinary route and cannot be executed, but its row,
    /// its parameter contract, its permission grants, and — the reason this exists — its full
    /// execution history all survive. Dropping the row cascades all of that away, so an accidental
    /// `DELETE` used to destroy the audit record of everything the hook had ever run.
    pub is_deleted: bool,
    /// When the hook was moved to the trash, and the clock the 92-day purge measures from.
    pub deleted_at: Option<DateTime>,
    /// The `api_keys.id` of whoever deleted it, as text.
    ///
    /// Deliberately not a foreign key: attribution must outlive the acting key, which an FK would
    /// either cascade away or block from ever being deleted.
    pub deleted_by: Option<String>,
    /// Hook creation timestamp.
    pub created_at: DateTime,
    /// Hook last-update timestamp.
    pub updated_at: DateTime,
    /// How a keyless caller must authenticate to invoke this hook. See [`AuthMode`].
    pub auth_mode: AuthMode,
    /// `HMAC_ONLY`'s signing secret, encrypted at rest through the same [`super::api_key::Model`]
    /// mechanism as `signing_secret` — recomputing an HMAC needs the plaintext back, so it cannot be
    /// hashed. `None` for every other [`AuthMode`]. **Never serialized**: unlike a key's plaintext,
    /// which is shown once at creation and never again, this value is meant to be referenced (and
    /// updated) repeatedly by whoever configures the hook, but it must still never leave the server
    /// in a `GET` response — `hook::Model` is serialized directly to API clients, with no separate
    /// safe-view type standing between the entity and the wire, so the field itself carries the
    /// omission.
    #[serde(skip_serializing)]
    pub hmac_secret: Option<String>,
    /// Header an `HMAC_ONLY` sender's signature arrives on. `None` means the built-in default,
    /// `X-Signature-256` — apply the default at the point of use
    /// ([`crate::middleware::HMAC_ONLY_DEFAULT_HEADER`]), not by writing the literal into every row,
    /// so changing the default later does not require a data migration.
    pub signature_header: Option<String>,
    /// Prefix stripped from an `HMAC_ONLY` signature before hex-decoding it. `None` means the
    /// built-in default, `sha256=` ([`crate::crypto::SIGNATURE_PREFIX`]).
    pub signature_prefix: Option<String>,
    /// Override of the `CANONICAL_V1` canonical string template, consulted only when a *keyed*
    /// caller invokes a hook whose [`AuthMode`] is [`AuthMode::CanonicalV1`]. `None` means the
    /// service-wide default, `{method}\n{path}\n{timestamp}\n{body}`
    /// ([`crate::crypto::canonical_v1_payload`]). Recognized placeholders: `{method}`, `{path}`,
    /// `{timestamp}`, `{body}`; substitution is textual, so an unrecognized `{...}` is left in the
    /// signed material verbatim rather than rejected — a template is data the operator controls, not
    /// something this service validates the shape of beyond that.
    pub canonical_template: Option<String>,
    /// An example of the JSON body a real caller sends this hook — free-form, not schema-validated
    /// beyond being well-formed JSON. Drives the WebUI's live command preview and JSON Payload
    /// Extractor, and — only when both this and at least one declared parameter exist — is checked
    /// at creation/update time (`api::hooks::validate_sample_payload_matches_parameters`) so a
    /// parameter contract cannot silently drift from the shape callers actually send.
    pub sample_payload_json: Option<String>,
}

/// Relations from `hooks` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The parameter contract this hook accepts.
    #[sea_orm(has_many = "super::hook_parameter::Entity")]
    HookParameter,
    /// Per-key permission grants covering this hook.
    #[sea_orm(has_many = "super::api_key_hook_permission::Entity")]
    ApiKeyHookPermission,
    /// Recorded executions of this hook.
    #[sea_orm(has_many = "super::execution::Entity")]
    Execution,
}

impl Related<super::hook_parameter::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::HookParameter.def()
    }
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

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_hook_permission::Relation::ApiKey.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_hook_permission::Relation::Hook.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
