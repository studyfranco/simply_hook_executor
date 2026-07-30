//! Authentication middleware: API key verification, CIDR binding enforcement, and optional
//! HMAC-SHA256 request signing.

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use hmac::{Hmac, KeyInit, Mac};
use ipnetwork::IpNetwork;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::entities::api_key::HmacMode;
use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

/// Header carrying the caller's secret key. The single, canonical way a caller identifies itself —
/// every request resolves its key record by hashing this value and matching `api_keys.key_hash`.
const API_KEY_HEADER: &str = "X-API-Key";
/// Header carrying the `sha256=<hex>` request signature.
const SIGNATURE_HEADER: &str = "X-Signature-256";
/// Alternate signature header used by GitHub-style webhook senders. Accepted only in
/// [`HmacMode::BodyOnly`], which is the mode that exists to accommodate them.
const HUB_SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
/// Header carrying the Unix-seconds timestamp a signature was computed at.
const TIMESTAMP_HEADER: &str = "X-Timestamp";
/// Largest request body that will be buffered in order to verify a signature. Signed payloads are
/// small JSON documents; the bound stops an attacker from forcing unbounded buffering just by
/// attaching a signature header.
///
/// Deliberately the *same* constant the router enforces via `DefaultBodyLimit`
/// ([`crate::MAX_REQUEST_BODY_BYTES`]) rather than an independently-chosen number. If this were the
/// larger of the two, a body between the limits would be fully buffered and HMAC'd here only to be
/// rejected by the extractor afterwards — paying the memory cost of a payload the daemon had
/// already decided not to accept.
const MAX_SIGNED_BODY_BYTES: usize = crate::MAX_REQUEST_BODY_BYTES;

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

/// Builds the exact byte string a signature is computed over.
///
/// The canonical form is the four components joined by newlines:
///
/// ```text
/// <METHOD>\n<PATH_AND_QUERY>\n<TIMESTAMP>\n<RAW_BODY>
/// ```
///
/// Three details are load-bearing:
///
/// - **The newline delimiters are not cosmetic.** Plain concatenation is ambiguous — `POST` +
///   `/api/x` and `POS` + `T/api/x` would produce identical input, letting a signature be replayed
///   against a different method/path pair. Delimiting removes that whole class of attack.
/// - **The query string is included.** Signing only the path would leave `?older_than_days=0`
///   freely rewritable to `?older_than_days=1` on an otherwise-valid signed request.
/// - **The raw body is used verbatim**, never a re-serialized form, so the bytes verified are
///   exactly the bytes parsed.
fn signature_base(method: &str, path_and_query: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut base = Vec::with_capacity(method.len() + path_and_query.len() + timestamp.len() + body.len() + 3);
    base.extend_from_slice(method.as_bytes());
    base.push(b'\n');
    base.extend_from_slice(path_and_query.as_bytes());
    base.push(b'\n');
    base.extend_from_slice(timestamp.as_bytes());
    base.push(b'\n');
    base.extend_from_slice(body);
    base
}

/// Rejects a timestamp outside the anti-replay window.
///
/// The check is symmetric: a timestamp too far in the *future* is refused as well as one too far
/// in the past. A forward-dated request would otherwise remain replayable for as long as its skew
/// allows, which is exactly what the window exists to prevent.
fn verify_timestamp(raw: &str, max_age_seconds: i64) -> Result<(), AppError> {
    let presented: i64 = raw.trim().parse().map_err(|_| {
        AppError::Unauthorized(format!("{TIMESTAMP_HEADER} must be a Unix timestamp in seconds"))
    })?;

    let skew = (chrono::Utc::now().timestamp() - presented).abs();
    if skew > max_age_seconds {
        return Err(AppError::Unauthorized(format!(
            "Request timestamp is outside the permitted {max_age_seconds}s window (off by {skew}s); \
             check the client's clock, or re-sign the request"
        )));
    }

    Ok(())
}

/// Verifies an `X-Signature-256: sha256=<hex>` header against the canonical request string.
///
/// The HMAC key is the API key's `signing_secret`, recovered from storage via
/// [`crate::crypto::SecretCipher`]. Because that secret is recoverable (unlike `key_hash`, which is
/// a one-way digest), a caller can authenticate with nothing but a public identifier and a valid
/// signature — the standard webhook-sender pattern, where the sender never transmits a bearer
/// credential at all.
///
/// # Constant-time comparison
///
/// The digest comparison goes through [`Mac::verify_slice`], whose implementation chain was
/// verified against the vendored source rather than assumed:
///
/// ```text
/// Mac::verify_slice  ->  CtOutput::eq  ->  subtle::ConstantTimeEq::ct_eq
/// ```
///
/// `verify_slice` first rejects a tag of the wrong length — that leaks only the digest width, which
/// is a public constant — and then compares all 32 bytes in constant time. Comparing the hex
/// strings with `==` instead would let an attacker recover a valid signature one byte at a time by
/// measuring response latency.
///
/// This is why the function must keep using `verify_slice` and must never be "simplified" to a
/// `==` on the decoded bytes or the hex text. `subtle` is reached through the RustCrypto `Mac` API
/// rather than depended on directly: the API already provides the guarantee, and hand-rolling the
/// comparison would be more code for no benefit.
fn verify_signature(header_value: &str, secret: &str, base: &[u8]) -> Result<(), AppError> {
    let hex_signature = header_value
        .strip_prefix("sha256=")
        .ok_or_else(|| AppError::Unauthorized("Signature must be formatted as sha256=<hex>".to_owned()))?;

    let expected = hex::decode(hex_signature.trim())
        .map_err(|_| AppError::Unauthorized("Signature is not valid hexadecimal".to_owned()))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("Failed to initialize HMAC verifier: {e}");
        AppError::Internal
    })?;
    mac.update(base);

    mac.verify_slice(&expected)
        .map_err(|_| AppError::Unauthorized("Invalid request signature".to_owned()))
}

/// Recovers a key's signing secret from storage, ready to verify a signature against.
///
/// A key with no secret (issued before signature auth existed) cannot verify anything, and is told
/// so specifically — that is a configuration problem the operator can fix by rotating, not a
/// credential problem worth obscuring. A secret that fails to *decrypt*, by contrast, means the
/// daemon's `SIGNING_SECRET_KEY` no longer matches what wrote the row: an operator emergency,
/// logged loudly and reported as a generic server error rather than as "your signature is wrong".
fn recover_signing_secret(
    state: &AppState,
    key_record: &crate::entities::api_key::Model,
) -> Result<String, AppError> {
    let stored = key_record.signing_secret.as_deref().ok_or_else(|| {
        AppError::Unauthorized(
            "This API key has no signing secret; rotate it to obtain one".to_owned(),
        )
    })?;

    state.cipher.open(stored).map_err(|e| {
        tracing::error!(
            key = %key_record.prefix,
            "Failed to decrypt a stored signing secret: {e}"
        );
        AppError::Internal
    })
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

    // One canonical way to name yourself: the bearer API key. It is hashed and matched against
    // `api_keys.key_hash`, which is the only key lookup path in the system.
    let presented_key = headers
        .get(API_KEY_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            AppError::Unauthorized(format!("Missing credentials: provide an {API_KEY_HEADER} header"))
        })?;

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
    // Which signature header applies depends on the key's mode: `X-Hub-Signature-256` is only
    // honoured for BODY_ONLY keys, so a CANONICAL_V1 key cannot be downgraded to the weaker scheme
    // simply by sending the other header name.
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|h| h.to_str().ok())
        .or_else(|| match key_record.hmac_mode {
            HmacMode::BodyOnly => headers.get(HUB_SIGNATURE_HEADER).and_then(|h| h.to_str().ok()),
            HmacMode::CanonicalV1 => None,
        })
        .map(str::to_owned);

    // The bearer key is itself the credential, so a signature is optional by default — when
    // present it must still verify, adding request integrity on top. `REQUIRE_SIGNED_REQUESTS`
    // promotes it to mandatory across every authenticated route.
    let signature_required = state.config.require_signed_requests;

    let mut req = match signature {
        Some(signature) => {
            // CANONICAL_V1 binds the timestamp into the signed material and enforces the replay
            // window. BODY_ONLY signs the body alone, which is what GitHub-style senders produce —
            // it cannot resist replay, and deliberately does not pretend to by demanding a
            // timestamp it would not actually cover.
            let timestamp = match key_record.hmac_mode {
                HmacMode::CanonicalV1 => {
                    let timestamp = headers
                        .get(TIMESTAMP_HEADER)
                        .and_then(|h| h.to_str().ok())
                        .ok_or_else(|| {
                            AppError::Unauthorized(format!(
                                "A signed request must include an {TIMESTAMP_HEADER} header"
                            ))
                        })?
                        .to_owned();

                    // Checked before the HMAC: a stale request is rejected without spending the
                    // work of recovering the secret and hashing the body.
                    verify_timestamp(&timestamp, state.config.signature_max_age_seconds)?;
                    Some(timestamp)
                }
                HmacMode::BodyOnly => None,
            };

            let secret = recover_signing_secret(&state, &key_record)?;

            let (parts, body) = req.into_parts();
            let bytes = axum::body::to_bytes(body, MAX_SIGNED_BODY_BYTES)
                .await
                .map_err(|_| AppError::InvalidInput("Request body too large to verify".to_owned()))?;

            let base = match &timestamp {
                Some(timestamp) => {
                    // The signature covers the method and full request target as well as the
                    // timestamp and body, so a captured signature cannot be replayed against a
                    // different route — a signed `GET /api/hooks` cannot become a
                    // `DELETE /api/hooks/{id}`.
                    //
                    // `OriginalUri` is essential here, not a nicety: `Router::nest("/api", ..)`
                    // strips the prefix from the URI inner layers observe, so `parts.uri` would
                    // read `/hooks/x` while the client signed `/api/hooks/x`. Signing must use the
                    // target the client actually requested, which is what `OriginalUri` preserves.
                    let original_uri = parts
                        .extensions
                        .get::<axum::extract::OriginalUri>()
                        .map(|original| &original.0)
                        .unwrap_or(&parts.uri);
                    let path_and_query = original_uri
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or_else(|| original_uri.path());
                    signature_base(parts.method.as_str(), path_and_query, timestamp, &bytes)
                }
                None => bytes.to_vec(),
            };

            verify_signature(&signature, &secret, &base)?;

            Request::from_parts(parts, Body::from(bytes))
        }
        None if signature_required => {
            return Err(AppError::Unauthorized(match key_record.hmac_mode {
                HmacMode::CanonicalV1 => format!(
                    "This request must be signed: send {SIGNATURE_HEADER} and {TIMESTAMP_HEADER}"
                ),
                HmacMode::BodyOnly => format!(
                    "This request must be signed: send {SIGNATURE_HEADER} or {HUB_SIGNATURE_HEADER}"
                ),
            }));
        }
        None => req,
    };

    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Computes the header value a well-behaved client would send.
    fn sign(secret: &str, base: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(base);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// The canonical base a client would build for a typical signed request.
    fn base(method: &str, path: &str, ts: &str, body: &[u8]) -> Vec<u8> {
        signature_base(method, path, ts, body)
    }

    #[test]
    fn canonical_base_is_newline_delimited() {
        assert_eq!(
            base("POST", "/api/hooks/x/execute", "1700000000", b"{}"),
            b"POST\n/api/hooks/x/execute\n1700000000\n{}".to_vec()
        );
        // An empty body still contributes its delimiter, so "no body" is distinct from a body of
        // "\n" and cannot be substituted for it.
        assert_eq!(base("GET", "/api/hooks", "1700000000", b""), b"GET\n/api/hooks\n1700000000\n".to_vec());
    }

    #[test]
    fn delimiters_prevent_component_boundary_shifting() {
        // Without delimiters, "POST" + "/api/x" and "POS" + "T/api/x" would hash identically and a
        // signature could be replayed across a different method/path split.
        assert_ne!(
            base("POST", "/api/x", "1700000000", b""),
            base("POS", "T/api/x", "1700000000", b"")
        );
    }

    #[test]
    fn accepts_a_correct_signature() {
        let b = base("POST", "/api/hooks/x/execute", "1700000000", br#"{"parameters":{}}"#);
        assert!(verify_signature(&sign("secret", &b), "secret", &b).is_ok());
    }

    #[test]
    fn rejects_tampered_body_wrong_secret_and_malformed_headers() {
        let body = br#"{"parameters":{"target":"1.2.3.4"}}"#;
        let b = base("POST", "/api/hooks/x/execute", "1700000000", body);
        let signature = sign("secret", &b);

        let tampered = base("POST", "/api/hooks/x/execute", "1700000000", br#"{"parameters":{"target":"9.9.9.9"}}"#);
        assert!(verify_signature(&signature, "secret", &tampered).is_err());
        assert!(verify_signature(&signature, "other-secret", &b).is_err());
        assert!(verify_signature("not-prefixed", "secret", &b).is_err());
        assert!(verify_signature("sha256=nothex", "secret", &b).is_err());
        assert!(verify_signature("sha256=", "secret", &b).is_err());
    }

    #[test]
    fn a_signature_cannot_be_replayed_across_method_path_or_timestamp() {
        let body = br#"{}"#;
        let original = base("POST", "/api/hooks/a/test", "1700000000", body);
        let signature = sign("secret", &original);

        // Same body and timestamp, different method: a dry run must not become an execution.
        assert!(verify_signature(&signature, "secret", &base("DELETE", "/api/hooks/a/test", "1700000000", body)).is_err());
        // Same method and timestamp, different path: one hook's signature must not run another's.
        assert!(verify_signature(&signature, "secret", &base("POST", "/api/hooks/b/execute", "1700000000", body)).is_err());
        // Same everything but the timestamp: an old capture cannot be re-dated.
        assert!(verify_signature(&signature, "secret", &base("POST", "/api/hooks/a/test", "1700000900", body)).is_err());
        // The query string is covered too.
        let listing = base("GET", "/api/executions?limit=10", "1700000000", b"");
        let listing_sig = sign("secret", &listing);
        assert!(verify_signature(&listing_sig, "secret", &base("GET", "/api/executions?limit=1000", "1700000000", b"")).is_err());
    }

    #[test]
    fn every_single_byte_mutation_of_a_valid_signature_is_rejected() {
        let b = base("POST", "/api/hooks/x/execute", "1700000000", br#"{"parameters":{}}"#);
        let valid = sign("secret", &b);
        let digest = hex::decode(valid.trim_start_matches("sha256=")).expect("valid hex");
        assert_eq!(digest.len(), 32, "SHA-256 tags are 32 bytes");

        // Flipping any bit at any position must fail. This is the deterministic fingerprint of a
        // full-width comparison: a prefix-only, suffix-only, or truncated compare would let
        // mutations outside the compared region slip through, and would show up here as a specific
        // range of positions that wrongly verify.
        for position in 0..digest.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut mutated = digest.clone();
                mutated[position] ^= mask;
                let signature = format!("sha256={}", hex::encode(&mutated));
                assert!(
                    verify_signature(&signature, "secret", &b).is_err(),
                    "a signature differing at byte {position} (mask {mask:#04x}) must be rejected"
                );
            }
        }

        // ...while the unmutated signature still verifies, so the loop above is not passing simply
        // because everything fails.
        assert!(verify_signature(&valid, "secret", &b).is_ok());
    }

    #[test]
    fn tags_of_the_wrong_length_are_rejected() {
        let b = base("POST", "/api/hooks/x/execute", "1700000000", b"{}");
        let valid = sign("secret", &b);
        let hex_digest = valid.trim_start_matches("sha256=").to_owned();

        // A truncated tag must not verify against a truncated comparison, and an over-long one
        // must not be silently trimmed.
        for wrong in [
            &hex_digest[..62],                      // 31 bytes
            &hex_digest[..2],                       // 1 byte
            "",                                     // empty
            &format!("{hex_digest}00"),             // 33 bytes
        ] {
            assert!(
                verify_signature(&format!("sha256={wrong}"), "secret", &b).is_err(),
                "a {}-char tag must be rejected", wrong.len()
            );
        }
    }

    #[test]
    fn timestamps_inside_the_window_are_accepted() {
        let now = chrono::Utc::now().timestamp();
        assert!(verify_timestamp(&now.to_string(), 300).is_ok());
        assert!(verify_timestamp(&(now - 299).to_string(), 300).is_ok());
        // Symmetric: modest forward skew is tolerated for clients whose clocks run fast.
        assert!(verify_timestamp(&(now + 299).to_string(), 300).is_ok());
        assert!(verify_timestamp(&format!("  {now}  "), 300).is_ok());
    }

    #[test]
    fn timestamps_outside_the_window_are_rejected() {
        let now = chrono::Utc::now().timestamp();

        let stale = verify_timestamp(&(now - 301).to_string(), 300)
            .expect_err("a stale timestamp must be rejected");
        assert!(matches!(stale, AppError::Unauthorized(_)));

        // A forward-dated request would otherwise stay replayable for the length of the skew.
        assert!(verify_timestamp(&(now + 301).to_string(), 300).is_err());
        assert!(verify_timestamp(&(now - 86_400).to_string(), 300).is_err());

        // Malformed values are rejected rather than defaulting to "now".
        for malformed in ["", "not-a-number", "17e9", "1700000000.5", "-"] {
            assert!(verify_timestamp(malformed, 300).is_err(), "{malformed:?} should be rejected");
        }
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
