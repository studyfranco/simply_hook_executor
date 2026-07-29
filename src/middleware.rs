//! Authentication middleware: API key verification, CIDR binding enforcement, and optional
//! HMAC-SHA256 request signing.

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use hmac::{Hmac, KeyInit, Mac};
use ipnetwork::IpNetwork;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

/// Header carrying the caller's secret key.
const API_KEY_HEADER: &str = "X-API-Key";
/// Header carrying the optional `sha256=<hex>` body signature.
const SIGNATURE_HEADER: &str = "X-Signature-256";
/// Largest request body that will be buffered in order to verify a signature. Signed payloads are
/// small JSON documents; the bound stops an attacker from forcing unbounded buffering just by
/// attaching a signature header.
const MAX_SIGNED_BODY_BYTES: usize = 1024 * 1024;

/// The resolved client IP for the current request (rightmost `X-Forwarded-For` hop, `X-Real-IP`,
/// or raw TCP peer address — see [`auth_middleware`]). Inserted into request extensions so
/// downstream handlers can attribute audit log entries to a real client address without
/// re-deriving it. A dedicated newtype (rather than a bare `Extension<std::net::IpAddr>`) avoids
/// ever silently colliding with some other, unrelated `IpAddr` extension in the future.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub std::net::IpAddr);

/// Normalizes an IPv4-mapped IPv6 address (e.g. `::ffff:192.168.1.1`) down to its plain IPv4 form
/// so it can be matched against IPv4 CIDR ranges in `bound_ips`. Reverse proxies and dual-stack
/// sockets commonly surface IPv4 clients this way, which would otherwise silently fail to match an
/// otherwise-correct IPv4 CIDR and cause a false `403 Forbidden`.
fn normalize_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Extracts the rightmost address from a comma-separated forwarding header, trimmed and parsed.
fn rightmost_ip(header_value: &str) -> Option<std::net::IpAddr> {
    header_value
        .split(',')
        .next_back()
        .map(|s| s.trim())
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
}

/// Verifies an `X-Signature-256: sha256=<hex>` header against the raw request body.
///
/// The HMAC key is the caller's own plaintext API key. Only its SHA-256 hash is stored server
/// side, so the secret used to *verify* has to be the one the caller just presented — meaning the
/// signature is an integrity guarantee over the body (nothing between client and daemon can alter
/// the payload undetected), layered on top of the key authentication that already happened, not a
/// replacement for it.
///
/// Comparison goes through [`Mac::verify_slice`], which is constant-time; comparing hex strings
/// with `==` would leak the correct signature one byte at a time.
fn verify_signature(header_value: &str, secret: &str, body: &[u8]) -> Result<(), AppError> {
    let hex_signature = header_value
        .strip_prefix("sha256=")
        .ok_or_else(|| AppError::Unauthorized("Signature must be formatted as sha256=<hex>".to_owned()))?;

    let expected = hex::decode(hex_signature.trim())
        .map_err(|_| AppError::Unauthorized("Signature is not valid hexadecimal".to_owned()))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("Failed to initialize HMAC verifier: {e}");
        AppError::Internal
    })?;
    mac.update(body);

    mac.verify_slice(&expected)
        .map_err(|_| AppError::Unauthorized("Invalid request signature".to_owned()))
}

/// Enforces API key authentication, CIDR binding, and (when present) body signing for every
/// `/api/*` and `/webhook/*` route.
///
/// On success the authenticated [`crate::entities::api_key::Model`] and the resolved [`ClientIp`]
/// are placed in the request's extensions for handlers to consume.
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // Resilient IP resolution: prefer X-Forwarded-For (rightmost hop), then X-Real-IP, and only
    // fall back to the raw TCP peer address if neither proxy header is present/valid.
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(rightmost_ip)
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.trim())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        })
        .unwrap_or(addr.ip());
    let client_ip = normalize_ip(client_ip);

    let presented_key = req
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized("Missing API Key".to_owned()))?
        .to_owned();

    let mut hasher = Sha256::new();
    hasher.update(presented_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let key_record = ApiKey::find()
        .filter(crate::entities::api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or(AppError::Unauthorized("Invalid API Key".to_owned()))?;

    // Validate the client IP against the bound CIDRs.
    let bound_ips_str = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNetwork> = bound_ips_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            tracing::error!("Invalid CIDR in database: {:?}", key_record.bound_ips);
            AppError::Internal
        })?;

    let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(client_ip));

    if !is_allowed && !key_record.is_master {
        tracing::warn!(
            "Access denied: Client IP {} not in bound networks {:?}",
            client_ip,
            key_record.bound_ips
        );
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    // Signature verification requires the raw body, which means buffering it and rebuilding the
    // request. That only happens when a signature is actually presented — unsigned requests keep
    // streaming through untouched.
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);

    let mut req = if let Some(signature) = signature {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, MAX_SIGNED_BODY_BYTES)
            .await
            .map_err(|_| AppError::InvalidInput("Request body too large to verify".to_owned()))?;

        verify_signature(&signature, &presented_key, &bytes)?;

        Request::from_parts(parts, Body::from(bytes))
    } else {
        req
    };

    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Computes the header value a well-behaved client would send.
    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn accepts_a_correct_signature() {
        let body = br#"{"parameters":{"target":"1.2.3.4"}}"#;
        assert!(verify_signature(&sign("secret", body), "secret", body).is_ok());
    }

    #[test]
    fn rejects_tampered_body_wrong_secret_and_malformed_headers() {
        let body = br#"{"parameters":{"target":"1.2.3.4"}}"#;
        let signature = sign("secret", body);

        let tampered = br#"{"parameters":{"target":"9.9.9.9"}}"#;
        assert!(verify_signature(&signature, "secret", tampered).is_err());
        assert!(verify_signature(&signature, "other-secret", body).is_err());
        assert!(verify_signature("not-prefixed", "secret", body).is_err());
        assert!(verify_signature("sha256=nothex", "secret", body).is_err());
        assert!(verify_signature("sha256=", "secret", body).is_err());
    }

    #[test]
    fn normalizes_ipv4_mapped_addresses() {
        let mapped: std::net::IpAddr = "::ffff:192.168.1.1".parse().expect("valid IPv6 literal");
        assert_eq!(normalize_ip(mapped), "192.168.1.1".parse::<std::net::IpAddr>().expect("valid IPv4"));
    }

    #[test]
    fn takes_the_rightmost_forwarded_hop() {
        assert_eq!(
            rightmost_ip("203.0.113.1, 10.0.0.8, 192.168.1.1"),
            Some("192.168.1.1".parse().expect("valid IPv4"))
        );
        assert_eq!(rightmost_ip("garbage"), None);
    }
}
