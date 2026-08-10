//! Authentication middleware: API key verification, CIDR binding enforcement, and optional
//! HMAC-SHA256 request signing.

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use ipnetwork::IpNetwork;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

// Client-address resolution lives in `crate::config` alongside the `TRUSTED_PROXIES` parsing it
// depends on, mirroring the layout of the reference `simply_ip_vault` implementation so the two can
// be diffed against each other.
use crate::config::resolve_client_ip;
// The HMAC itself lives in `crate::crypto`, beside the secret it consumes and the cipher that
// protects that secret at rest. This module decides *when* a signature is required and what a
// caller is told when one fails; it no longer implements the primitive.
use crate::crypto::{SignatureRejection, canonical_v1_payload, verify_signature};
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

/// The resolved client IP for the current request — the rightmost non-proxy `X-Forwarded-For` hop,
/// `X-Real-IP`, or the raw TCP peer address, per [`crate::config::resolve_client_ip`]. Inserted into
/// request extensions so downstream handlers can attribute audit log entries to a real client
/// address without re-deriving it. A dedicated newtype (rather than a bare
/// `Extension<std::net::IpAddr>`) avoids ever silently colliding with some other, unrelated
/// `IpAddr` extension in the future.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub std::net::IpAddr);

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

/// Rejects a stale `X-Timestamp` before the database is consulted, returning the header unchanged.
///
/// # Why this runs before the key lookup
///
/// A timestamp is self-contained: parsing it and comparing it against the server clock needs
/// nothing from `api_keys`. Checking it only after the lookup meant every request carrying a stale
/// or malformed one — a capture replayed hours later, a client with a broken clock, a scanner
/// spraying garbage — first cost an indexed query. Rejecting here makes that traffic free to serve,
/// which is the principle rather than the micro-optimization: the checks that cost us nothing
/// belong in front of the ones that do, so an unauthenticated caller cannot choose how much work
/// we perform on its behalf.
///
/// # Scope: the shape of the request, not the mode of the key
///
/// The window is applied only when [`SIGNATURE_HEADER`] is present alongside the timestamp, which
/// is precisely the shape of a `CANONICAL_V1` request — the only mode that has a window at all.
/// The mode itself lives in the row the lookup fetches, so it cannot be consulted here; the pair of
/// headers is the closest thing to it that is free.
///
/// Widening this to "any request carrying a timestamp" was tried and is wrong. `BODY_ONLY` exists
/// to accept senders whose format cannot be changed (`AGENT.MD` §1), and a stray `X-Timestamp` from
/// one of them is documented as ignored — enforcing a window over it would reject a webhook for a
/// header that is not even part of its signed material, buying nothing, since `BODY_ONLY` carries
/// no replay protection to strengthen either way.
///
/// # This is an optimization, not the guarantee
///
/// The authoritative window check stays in the `CANONICAL_V1` branch below and runs unconditionally
/// there. It would be reachable-but-skipped only if that branch ever accepted a signature header
/// this function does not look at — and a security property must not rest on an invariant held two
/// functions apart. Re-parsing an integer is worth not having that footgun.
///
/// `Ok(None)` means no header was sent. Whether *that* is an error depends on `hmac_mode`, so the
/// judgement stays with the caller. The returned value is the header text **exactly as received**,
/// never a re-serialized integer: it is fed to the HMAC verbatim, so normalizing it (stripping a
/// leading zero, trimming padding) would invalidate a signature the client computed correctly over
/// the bytes it actually sent.
fn prevalidate_timestamp_header(
    headers: &axum::http::HeaderMap,
    max_age_seconds: i64,
) -> Result<Option<String>, AppError> {
    let Some(raw) = headers.get(TIMESTAMP_HEADER).and_then(|h| h.to_str().ok()) else {
        return Ok(None);
    };

    if headers.contains_key(SIGNATURE_HEADER) {
        verify_timestamp(raw, max_age_seconds)?;
    }

    Ok(Some(raw.to_owned()))
}

/// Turns a [`SignatureRejection`] into what the caller is told.
///
/// This is the half of signature verification that is genuinely this module's business:
/// [`crate::crypto::verify_signature`] decides *whether* a signature holds, and this decides what a
/// failure is worth saying out loud.
///
/// The three client-facing variants are named precisely, because a malformed header is a mistake the
/// sender can fix and obscuring it helps nobody — an integrator who forgot the `sha256=` tag would
/// otherwise be told only "invalid signature" and go looking for a key mismatch. What must *not* be
/// distinguished is why a well-formed signature failed: [`SignatureRejection::Mismatch`] covers a
/// tampered body, a wrong secret and a wrong-width tag alike, and it is deliberately a single
/// message.
///
/// [`SignatureRejection::KeyUnusable`] is the odd one out and becomes a `500`. It means this
/// service's own stored secret could not be used as HMAC key material, which is an operator fault;
/// reporting it as `401` would blame the caller for a server defect and hide the real problem.
fn reject_signature(rejection: SignatureRejection, key_prefix: &str) -> AppError {
    match rejection {
        SignatureRejection::MissingPrefix => {
            AppError::Unauthorized("Signature must be formatted as sha256=<hex>".to_owned())
        }
        SignatureRejection::MalformedHex => {
            AppError::Unauthorized("Signature is not valid hexadecimal".to_owned())
        }
        SignatureRejection::Mismatch => {
            AppError::Unauthorized("Invalid request signature".to_owned())
        }
        SignatureRejection::KeyUnusable => {
            tracing::error!(key = %key_prefix, "Stored signing secret is unusable as HMAC key material");
            AppError::Internal
        }
    }
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
/// # Ordering: cheapest first, then authenticate, then authorize
///
/// 1. Resolve the client IP — no I/O beyond a possibly-cached DNS lookup.
/// 2. Require an `X-API-Key` header to exist. No query yet; this is a header read.
/// 3. **Validate `X-Timestamp` on a signed request.** Self-contained, so a stale or malformed
///    timestamp is refused before it can cost a database round-trip.
/// 4. Look up the key by `key_hash` — the first query, and the first step an unauthenticated caller
///    can make us pay for.
/// 5. Verify the HMAC (`CANONICAL_V1` also requires that step 3 found a header).
/// 6. Reject a signature already used inside the window.
/// 7. **Only then** check `bound_ips`.
///
/// Steps 3 and 7 are both load-bearing and neither may drift. Moving step 3 back after the lookup
/// hands an unauthenticated caller a free query per request. Moving step 7 forward lets a caller
/// holding nothing but a leaked `X-API-Key` distinguish `403 Client IP not allowed` from `401`, and
/// so learn whether a key it merely found is bound to networks excluding it — a map of the
/// deployment's topology handed to someone who has proven nothing. Both failures must look identical
/// until the caller has proven it holds the signing secret.
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
    // Forwarding headers are consulted only when the TCP peer is a configured trusted proxy;
    // otherwise the peer address itself is authoritative. See [`crate::config::resolve_client_ip`].
    //
    // `resolved()` is what turns a hostname entry into addresses. It is awaited per request so a
    // container that moved is picked up within the DNS reuse window rather than at the next
    // restart; with no hostnames configured it is a refcount bump and touches neither lock nor
    // resolver.
    let trusted_proxies = state.config.trusted_proxies.resolved().await;
    let client_ip = resolve_client_ip(addr.ip(), &headers, &trusted_proxies);

    // One canonical way to name yourself: the bearer API key. It is hashed and matched against
    // `api_keys.key_hash`, which is the only key lookup path in the system.
    let presented_key = headers
        .get(API_KEY_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            AppError::Unauthorized(format!("Missing credentials: provide an {API_KEY_HEADER} header"))
        })?;

    // Freshness before the database. A stale or malformed timestamp on a signed request is refused
    // here rather than after a query an unauthenticated caller provoked — see
    // [`prevalidate_timestamp_header`]. Its *absence* cannot be judged yet: that depends on the
    // key's `hmac_mode`, which is what the lookup below is for.
    let presented_timestamp =
        prevalidate_timestamp_header(&headers, state.config.signature_max_age_seconds)?;

    let mut hasher = Sha256::new();
    hasher.update(presented_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let mut key_record = ApiKey::find()
        .filter(crate::entities::api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or(AppError::Unauthorized("Invalid API Key".to_owned()))?;

    // The authenticated principal is *derived*, not copied out of the row. A key whose `is_master`
    // column says `true` but which is not the identity this process pinned at boot is demoted here,
    // once, before any handler sees it — so the dozens of `key.is_master` reads downstream stay
    // correct without each having to remember to compare an id. See [`crate::master`] for why the
    // check lives at this choke point rather than at the decision sites.
    state.master_pin.authenticate(&state.db, &mut key_record).await;

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
            // Two things happen here that could not happen before the lookup. First, whether the
            // header had to be present at all — that is what `hmac_mode` decides. Second, the
            // authoritative window check: `prevalidate_timestamp_header` already applied it to
            // every request shaped like this one, but the guarantee lives here, where it cannot be
            // sidestepped by a future change to which signature headers this branch accepts.
            let timestamp = match key_record.hmac_mode {
                HmacMode::CanonicalV1 => {
                    let timestamp = presented_timestamp.ok_or_else(|| {
                        AppError::Unauthorized(format!(
                            "A signed request must include an {TIMESTAMP_HEADER} header"
                        ))
                    })?;
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
                    canonical_v1_payload(parts.method.as_str(), path_and_query, timestamp, &bytes)
                }
                None => bytes.to_vec(),
            };

            let digest = verify_signature(&secret, &base, &signature)
                .map_err(|rejection| reject_signature(rejection, &key_record.prefix))?;

            // Single-use enforcement, and only now that the digest is proven authentic. Recording
            // an unverified signature would let anyone who merely *observed* a request burn it
            // before the legitimate client's copy arrived — turning replay protection into a
            // denial-of-service primitive aimed at the client it exists to protect.
            //
            // `CANONICAL_V1` only, which is what `timestamp.is_some()` selects for. `BODY_ONLY`
            // carries no timestamp and therefore has no window to be single-use within; per
            // `AGENT.MD` that mode exists to accept third-party senders whose format cannot be
            // changed, and those senders redeliver on purpose.
            if timestamp.is_some()
                && !state.replay_guard.check_and_record(key_record.id, &digest)
            {
                tracing::warn!(
                    key = %key_record.prefix,
                    "Rejected replay: this signature was already used inside the {}s window",
                    state.config.signature_max_age_seconds
                );
                return Err(AppError::Unauthorized(
                    "This signature has already been used; sign a fresh request".to_owned(),
                ));
            }

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

    // ── Authorization ────────────────────────────────────────────────────────────────────────
    // Everything above authenticates: it establishes *who* is calling. Only now, with that
    // settled, is the caller's source network checked.
    //
    // The order is load-bearing, not stylistic. Running the network check first meant a caller
    // holding nothing but a leaked `X-API-Key` — no signing secret, so unable to authenticate —
    // could still distinguish `403 Client IP not allowed` from `401 Invalid request signature`,
    // and thereby learn whether a key it had merely found is bound to networks excluding it. That
    // is a map of the deployment's network topology handed to someone who cannot authenticate.
    // Authenticate, then authorize: an unauthenticated caller now gets `401` for every key, and
    // learns nothing from it beyond "not authenticated".
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

    // An empty `bound_ips` means "unrestricted" and is the only way to opt out. A key that names
    // ranges is held to them **whatever its scopes** — `is_master` used to bypass this check, which
    // meant the single most valuable credential in the system was also the only one whose network
    // restriction was decorative while the dashboard displayed it as enforced. A master key that
    // should reach the API from anywhere expresses that by leaving `bound_ips` empty (or listing
    // `0.0.0.0/0,::/0`), not by having the check skipped behind its back.
    let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(client_ip));

    if !is_allowed {
        tracing::warn!(
            key = %key_record.prefix,
            is_master = key_record.is_master,
            "Access denied: client IP {} not in bound networks {:?}",
            client_ip,
            key_record.bound_ips
        );
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Builds a header map carrying an optional timestamp and an optional signature header.
    fn headers_with(
        timestamp: Option<&str>,
        signature_header: Option<&'static str>,
    ) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        if let Some(value) = timestamp {
            headers.insert(TIMESTAMP_HEADER, value.parse().expect("a valid header value"));
        }
        if let Some(name) = signature_header {
            headers.insert(name, "sha256=00".parse().expect("a valid header value"));
        }
        headers
    }

    /// An absent header is not an error *here*: whether it is required depends on the key's
    /// `hmac_mode`, which this function deliberately runs before fetching.
    #[test]
    fn an_absent_timestamp_defers_the_verdict_rather_than_deciding_it() {
        let headers = headers_with(None, Some(SIGNATURE_HEADER));
        assert_eq!(
            prevalidate_timestamp_header(&headers, 300).expect("absence is not a failure"),
            None
        );
    }

    /// The value is returned byte-for-byte, because it is fed to the HMAC verbatim. Normalizing it
    /// here — trimming the padding, dropping a leading zero — would invalidate a signature the
    /// client computed correctly over the bytes it actually sent.
    #[test]
    fn a_valid_timestamp_is_returned_exactly_as_received() {
        let padded = format!("  {}  ", chrono::Utc::now().timestamp());
        let headers = headers_with(Some(&padded), Some(SIGNATURE_HEADER));
        assert_eq!(
            prevalidate_timestamp_header(&headers, 300).expect("inside the window"),
            Some(padded.clone()),
            "the header text must survive validation unchanged"
        );
    }

    /// The point of the reordering: a signed request whose timestamp cannot pass is refused with no
    /// key record in hand, which is to say before the database is touched at all.
    #[test]
    fn a_stale_or_malformed_timestamp_fails_without_a_key_record() {
        let now = chrono::Utc::now().timestamp();

        for rejected in [
            (now - 301).to_string(),
            (now + 301).to_string(),
            (now - 86_400).to_string(),
            "not-a-number".to_owned(),
            "1700000000.5".to_owned(),
            String::new(),
        ] {
            let headers = headers_with(Some(&rejected), Some(SIGNATURE_HEADER));
            let error = prevalidate_timestamp_header(&headers, 300)
                .expect_err("a timestamp outside the window must be refused");
            assert!(
                matches!(error, AppError::Unauthorized(_)),
                "{rejected:?} must be a 401, not a 400: authentication is what failed"
            );
        }
    }

    /// The pre-check is scoped to the shape of a `CANONICAL_V1` request, so it cannot reach into
    /// `BODY_ONLY` traffic — whose senders `AGENT.MD` says we do not get to change, and whose stray
    /// `X-Timestamp` is documented as ignored. A window enforced there would reject a webhook over
    /// a header that is not part of its signed material.
    #[test]
    fn a_stray_timestamp_without_a_canonical_signature_is_carried_not_judged() {
        let ancient = "1";

        for shape in [None, Some(HUB_SIGNATURE_HEADER)] {
            let headers = headers_with(Some(ancient), shape);
            assert_eq!(
                prevalidate_timestamp_header(&headers, 300)
                    .expect("a body-only or unsigned request is not window-checked here"),
                Some(ancient.to_owned()),
                "{shape:?}: the header is passed through untouched"
            );
        }

        // ...whereas the same value alongside `X-Signature-256` is the canonical shape, and is
        // held to the window.
        let canonical = headers_with(Some(ancient), Some(SIGNATURE_HEADER));
        assert!(prevalidate_timestamp_header(&canonical, 300).is_err());
    }
}
