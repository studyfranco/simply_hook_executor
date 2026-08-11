//! Shared plumbing every handler module leans on.
//!
//! This module exists because the coupling audit in `AGENT_NOTES.MD` found a specific shape: a
//! handful of helpers are used by *three to five* of the handler domains each — writing an audit
//! row, resolving a hook by id-or-name, loading a parameter contract, formatting a reference for a
//! log line. They are not authorization logic, so putting them in [`super::guards`] would make that
//! module mean "guards, plus everything else that happened to be shared" — the monolith problem
//! again, one level down.
//!
//! Nothing here makes an authorization decision. If a function in this file starts deciding who may
//! do something, it belongs in [`super::guards`] instead.
//!
//! The strict JSON extractors used to live here and now sit in [`crate::extract`]. They were the
//! one thing in this file that decided something — whether a request is well-formed enough to reach
//! a handler at all — and `deny_unknown_fields`, which they enforce, is a `RBAC_MODEL.md` §5
//! control rather than plumbing. See that module's header for the full reasoning.

use chrono::Utc;
use rand::RngExt;
use ipnetwork::IpNetwork;
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::SecretCipher;
use crate::entities::{api_key, api_key::HmacMode, audit_log, hook, hook_parameter, prelude::*};
use crate::error::AppError;

use super::{MAX_CONCURRENT_JOBS, MAX_TIMEOUT_SECONDS};

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Generates a random 32-byte hex key for API authentication.
pub fn generate_random_key() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Hashes an API key using SHA-256 for secure storage.
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generates a public key identifier (`shk_<32 hex>`).
///
/// Non-secret by design: it is shown in the dashboard and appears in logs, so it only needs to be
/// unique — it never authenticates anything. Callers identify themselves with `X-API-Key` alone.
pub fn generate_key_id() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    format!("shk_{}", hex::encode(bytes))
}

/// Mints and seals a fresh `(key_id, signing_secret)` pair, returning the plaintext secret.
///
/// The plaintext is handed back exactly once so the caller can put it in the HTTP response; only
/// the sealed form is ever persisted.
///
/// The secret itself comes from [`crate::crypto::generate_signing_secret`], not from this module.
/// That is a deliberate boundary: `generate_key_id` above mints a *public* identifier and belongs
/// here with the rest of the request plumbing, while the signing secret is the entropy every
/// signature in the system rests on and belongs beside the HMAC that consumes it. This function is
/// where the two meet, which is exactly what it is for.
pub(crate) fn mint_signing_pair(cipher: &SecretCipher) -> Result<(String, String, String), AppError> {
    let key_id = generate_key_id();
    let signing_secret = crate::crypto::generate_signing_secret();
    let sealed = cipher.seal(&signing_secret).map_err(|e| {
        tracing::error!("Failed to seal a signing secret: {e}");
        AppError::Internal
    })?;
    Ok((key_id, signing_secret, sealed))
}

/// Formats a target resource for a human-readable audit log `details` string, e.g.
/// `"'nftables_ban' (65cf11ce...)"` — pairs the name an operator actually recognizes with a
/// truncated id for unambiguous cross-referencing, instead of a bare UUID.
pub(crate) fn format_reference(name: &str, id: Uuid) -> String {
    let id_str = id.to_string();
    format!("'{name}' ({}...)", &id_str[..8])
}

/// Writes an audit log entry.
///
/// # Attribution survives the key
///
/// The acting key's name and prefix are denormalized into the row so the trail stays legible after
/// that key is deleted: its `api_key_id` FK is `ON DELETE SET NULL`, but these columns are a
/// point-in-time snapshot rather than a live join.
///
/// All three attribution columns — `api_key_name`, `api_key_prefix`, `client_ip` — are **NOT NULL**
/// in the schema, and that is load-bearing rather than incidental. A nullable snapshot permits a row
/// that has lost both its foreign key and its denormalized copy, which is an audit entry attributable
/// to nobody. Because they cannot be null, "who did this" is answerable for every row in the table,
/// forever. `simply_ip_vault` declares the same three columns nullable; this is a deliberate
/// divergence in this service's favour, recorded in `SECURITY_COMPARISON_REPORT.md` as **D3**.
///
/// # The `target_resource` convention
///
/// `target_resource` carries the affected entity's **human-readable name** — never a bare UUID. That
/// is what makes `GET /api/audit-logs?action=…` legible to an operator and what makes the column
/// worth filtering on; a truncated or full identifier there is unreadable and duplicates information
/// the `details` string already carries.
///
/// Two shapes are permitted, and both are used deliberately:
///
/// | Situation | `target_resource` | Example |
/// | :--- | :--- | :--- |
/// | A single named entity | `Some(name)` | `Some(hook.name)` |
/// | A bulk operation with no single target | `None` | retention sweeps, `HOOK_PURGE` |
///
/// An entity with no name of its own — an execution record — takes the name of the entity it hangs
/// from, and puts its own id in `details`. Identifiers belong in `details`, formatted with
/// [`format_reference`] so a name and a truncated id appear together.
pub(crate) async fn create_audit_log(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    client_ip: std::net::IpAddr,
    action: &str,
    target_resource: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(Some(key.id)),
        api_key_name: Set(key.name.clone()),
        api_key_prefix: Set(key.prefix.clone()),
        client_ip: Set(client_ip.to_string()),
        action: Set(action.to_owned()),
        target_resource: Set(target_resource),
        details: Set(details),
        timestamp: Set(Utc::now().naive_utc()),
    };
    AuditLog::insert(log).exec(db).await?;
    Ok(())
}

/// Resolves a hook from a path segment that may be either its UUID or its unique name, **including
/// soft-deleted ones**.
///
/// Every hook route takes a `String` rather than a strictly-typed `Uuid` for exactly this reason:
/// a caller wiring up `/webhook/nftables_ban` gets a working request instead of Axum rejecting it
/// with a `422` before any handler runs.
///
/// Almost every caller wants [`resolve_hook`] instead. This variant exists for the three trash
/// routes — restore, hard delete, and the master's `include_deleted` view — which by definition need
/// to address a row the rest of the API pretends is gone.
pub(crate) async fn resolve_hook_including_deleted(
    db: &sea_orm::DatabaseConnection,
    identifier: &str,
) -> Result<hook::Model, AppError> {
    if let Ok(id) = Uuid::parse_str(identifier)
        && let Some(found) = Hook::find_by_id(id).one(db).await?
    {
        return Ok(found);
    }
    Hook::find()
        .filter(hook::Column::Name.eq(identifier))
        .one(db)
        .await?
        .ok_or(AppError::NotFound)
}

/// Resolves a **live** hook by UUID or name.
///
/// A soft-deleted hook reports `404`, identically to one that never existed. That equivalence is
/// deliberate: "deleted" is a state the rest of the API does not model, so every route that reads,
/// executes, or edits a hook behaves as though the row is gone. Returning a distinguishable error
/// would mean auditing each of those routes for whether acting on a trashed hook is safe; a `404`
/// makes the answer uniform and unforgettable.
pub(crate) async fn resolve_hook(
    db: &sea_orm::DatabaseConnection,
    identifier: &str,
) -> Result<hook::Model, AppError> {
    let found = resolve_hook_including_deleted(db, identifier).await?;
    if found.is_deleted {
        return Err(AppError::NotFound);
    }
    Ok(found)
}

/// Loads a hook's declared parameters in the canonical order used for positional CLI arguments:
/// declaration order, with the key name as a stable tie-break for rows created in the same
/// timestamp tick.
pub(crate) async fn load_parameters(
    db: &sea_orm::DatabaseConnection,
    hook_id: Uuid,
) -> Result<Vec<hook_parameter::Model>, AppError> {
    Ok(HookParameter::find()
        .filter(hook_parameter::Column::HookId.eq(hook_id))
        .order_by_asc(hook_parameter::Column::CreatedAt)
        .order_by_asc(hook_parameter::Column::ParamKey)
        .all(db)
        .await?)
}

/// Renders a key's signature mode for an audit log entry.
///
/// `BODY_ONLY` is called out as replay-vulnerable rather than merely named: choosing it is a
/// security-relevant decision, and the audit trail should say so where an operator will read it.
pub(crate) fn describe_hmac_mode(mode: HmacMode) -> &'static str {
    match mode {
        HmacMode::CanonicalV1 => "signatures: CANONICAL_V1",
        HmacMode::BodyOnly => "signatures: BODY_ONLY — body-only, no replay protection",
    }
}

/// Renders a hook's elevation setting for an audit log entry.
///
/// Privileged hooks are the highest-value thing in this system to be able to reconstruct after the
/// fact, so the account is written into the audit trail at creation and on every change.
pub(crate) fn describe_privilege(run_as_user: Option<&str>) -> String {
    match run_as_user {
        Some(user) => format!("runs as '{user}' via sudo"),
        None => "runs as the daemon user".to_owned(),
    }
}

/// Validates a proposed hook timeout.
pub(crate) fn validate_timeout(seconds: i32) -> Result<(), AppError> {
    if seconds <= 0 {
        return Err(AppError::InvalidInput(
            "default_timeout_seconds must be greater than 0".to_owned(),
        ));
    }
    if seconds > MAX_TIMEOUT_SECONDS {
        return Err(AppError::InvalidInput(format!(
            "default_timeout_seconds must not exceed {MAX_TIMEOUT_SECONDS}"
        )));
    }
    Ok(())
}

/// Validates every entry of a comma-separated CIDR list.
pub(crate) fn validate_bound_ips(bound_ips: &str) -> Result<(), AppError> {
    for cidr in bound_ips.split(',') {
        let trimmed = cidr.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _: IpNetwork = trimmed
            .parse()
            .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {trimmed}")))?;
    }
    Ok(())
}

/// Extracts the caller-supplied parameter map from an execute request body.
///
/// Two shapes are accepted, because the callers differ: first-party clients post
/// `{"parameters": {...}}`, while a third-party webhook sender often can only post its own flat
/// JSON document. A top-level `parameters` object wins when present; otherwise the whole body is
/// treated as the parameter map. An empty body means "no parameters".
pub(crate) fn extract_parameter_map(
    body: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, AppError> {
    if body.is_empty() {
        return Ok(serde_json::Map::new());
    }

    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?;

    let object = match value {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => return Ok(serde_json::Map::new()),
        _ => {
            return Err(AppError::InvalidInput(
                "Request body must be a JSON object".to_owned(),
            ));
        }
    };

    match object.get("parameters") {
        Some(serde_json::Value::Object(inner)) => Ok(inner.clone()),
        Some(serde_json::Value::Null) | None => Ok(object),
        Some(_) => Err(AppError::InvalidInput(
            "'parameters' must be a JSON object".to_owned(),
        )),
    }
}

/// Validates a proposed concurrency budget.
pub(crate) fn validate_concurrency(jobs: i32) -> Result<(), AppError> {
    if jobs < 1 {
        return Err(AppError::InvalidInput(
            "max_concurrent_jobs must be at least 1".to_owned(),
        ));
    }
    if jobs > MAX_CONCURRENT_JOBS {
        return Err(AppError::InvalidInput(format!(
            "max_concurrent_jobs must not exceed {MAX_CONCURRENT_JOBS}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_execute_payload_shapes() {
        let wrapped = br#"{"parameters":{"target":"1.2.3.4"}}"#;
        let flat = br#"{"target":"1.2.3.4"}"#;
        let expected: serde_json::Map<String, serde_json::Value> =
            [("target".to_owned(), serde_json::json!("1.2.3.4"))].into_iter().collect();

        assert_eq!(extract_parameter_map(wrapped).expect("wrapped shape"), expected);
        assert_eq!(extract_parameter_map(flat).expect("flat shape"), expected);
        assert!(extract_parameter_map(b"").expect("empty body").is_empty());
        assert!(extract_parameter_map(b"null").expect("null body").is_empty());
    }

    #[test]
    fn rejects_malformed_execute_payloads() {
        assert!(matches!(
            extract_parameter_map(b"{not json"),
            Err(AppError::InvalidInput(_))
        ));
        assert!(matches!(
            extract_parameter_map(b"[1,2,3]"),
            Err(AppError::InvalidInput(_))
        ));
        assert!(matches!(
            extract_parameter_map(br#"{"parameters":"oops"}"#),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn validates_timeouts_and_concurrency_bounds() {
        assert!(validate_timeout(30).is_ok());
        assert!(validate_timeout(0).is_err());
        assert!(validate_timeout(-5).is_err());
        assert!(validate_timeout(MAX_TIMEOUT_SECONDS + 1).is_err());

        assert!(validate_concurrency(1).is_ok());
        assert!(validate_concurrency(0).is_err());
        assert!(validate_concurrency(MAX_CONCURRENT_JOBS + 1).is_err());
    }

    #[test]
    fn validates_cidr_lists() {
        assert!(validate_bound_ips("0.0.0.0/0,::/0").is_ok());
        assert!(validate_bound_ips("127.0.0.1/32, 10.0.0.0/8").is_ok());
        assert!(validate_bound_ips("").is_ok());
        assert!(validate_bound_ips("not-a-cidr").is_err());
    }
}
