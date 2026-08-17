//! Request-body extractors that refuse in this service's own error shape.
//!
//! # Why these live at the crate root rather than in `api/support.rs`
//!
//! [`StrictJson`] is not a helper. It is the mechanism that turns
//! `#[serde(deny_unknown_fields)]` from an annotation into an enforced control, and
//! `RBAC_MODEL.md` §5 names that control specifically:
//!
//! > *`is_master` must not be settable or clearable through any API endpoint … **Removing the field
//! > from the payload type is required; rejecting it at the handler is not sufficient**, since a
//! > later handler can reintroduce the path.*
//!
//! Absence plus `deny_unknown_fields` is what makes that removal mean something, and this extractor
//! is what carries the resulting serde refusal to the caller as a `400` in the standard envelope
//! rather than as a bare `text/plain` body. That makes it a type-level security boundary, and
//! `api/support.rs` is explicitly the module that **decides nothing** — its own header says a
//! function that starts deciding belongs elsewhere. Extractors decide whether a request is
//! well-formed enough to reach a handler at all, which is a decision, and it is made before any
//! handler runs.
//!
//! It is also the wrong layer twice over: an Axum `FromRequest` implementation is a framework
//! concern, not an API-domain one, so keeping it under `api/` put a piece of HTTP plumbing inside
//! the module tree that models this service's *domain*. `simply_ip_vault` places the identical pair
//! in its own `src/extract.rs`; converging on that placement closes structural divergence **S2**
//! and leaves both services with one obvious address for "how does a body become a typed payload
//! here".
//!
//! # The `Strict*` prefix means one thing: *this extractor refuses in our envelope*
//!
//! There is one of these for every extractor a handler in this service uses — [`StrictJson`],
//! [`OptionalStrictJson`], [`StrictPath`], [`StrictQuery`], [`StrictBytes`] — and handlers use
//! **nothing else**. That completeness is the point rather than a nicety: a single bare `Path<Uuid>`
//! left in a handler is one route where `GET /api/executions/not-a-uuid` answers `400` with
//! `text/plain`, and a client written against the documented envelope reads that as a body with no
//! `error` field at all. The contract is only worth anything if it has no exceptions, so
//! `tests/concurrency_and_contracts.rs` asserts the envelope on every extractor rather than on a
//! representative one.
//!
//! # What every extractor here guarantees
//!
//! - **The refusal is `{"error": "…"}` with `Content-Type: application/json`**, like every other
//!   failure on these routes. A client parsing the envelope never has to special-case the requests
//!   that failed before a handler ran — which are exactly the requests a client most needs a
//!   machine-readable reason for.
//! - **The rejection's own status is passed through**, never flattened to `400`. This matters more
//!   than it looks: the router-wide `DefaultBodyLimit` surfaces here as a rejection too, and
//!   collapsing every rejection to `400` would silently demote `413 Payload Too Large` into an
//!   indistinguishable bad request. Axum's own status is kept for the same reason on every wrapper
//!   below — `PathRejection`, for instance, is a `500` when the *route* declares parameters the
//!   handler does not, which is a bug in this service and must not be reported as the caller's.
//! - **The underlying message is verbatim.** A caller that sent `is_master` is told exactly which
//!   field was refused; one that sent `not-a-uuid` is told which path segment failed to parse.
//!   Wrapping the shape does not mean withholding the reason.
//!
//! # Why wrappers rather than one piece of middleware
//!
//! A middleware sees the response after the fact — a `400` carrying `text/plain` — and would have to
//! guess whether that body is an extractor rejection worth rewriting or a handler's deliberate
//! output. Rewriting by inspection is the kind of rule that silently mangles a future endpoint that
//! legitimately returns text. Wrapping at the extraction point keeps the decision where the
//! information is.

use axum::extract::{FromRequest, FromRequestParts, Json, Path, Query, Request};
use axum::http::request::Parts;

use crate::error::AppError;

/// Renders an Axum rejection into this service's envelope, preserving its status and message.
///
/// A macro rather than a generic function on purpose. Axum exposes `status()` and `body_text()`
/// **inherently** on each rejection type rather than through a shared trait, so a generic version
/// needs a local bridging trait — and a bridging method body of `self.status()` compiles only
/// because inherent methods win name resolution. Remove the inherent method and that same line
/// becomes infinite recursion, silently. Expanding at the call site keeps the calls unambiguous and
/// the hazard non-existent.
macro_rules! envelope {
    ($rejection:expr) => {{
        let rejection = $rejection;
        AppError::BodyRejected(rejection.status(), rejection.body_text())
    }};
}

/// A [`Json`] extractor whose deserialization failures come back as [`AppError`] rather than as
/// Axum's own plain-text rejection.
///
/// Axum's `Json` rejection renders as a bare `text/plain` body, which would break the
/// `{"error": "..."}` contract every other failure on these routes honours — a client parsing the
/// refusal would find no `error` field at all. Since the key-administration payloads carry
/// `#[serde(deny_unknown_fields)]` (see [`crate::api::keys::CreateApiKeyPayload`]), a rejected field
/// is a *routine, security-relevant* outcome rather than an exotic one, so it has to read like every
/// other refusal.
///
/// Both the message and the status are preserved; see the module header for why the status must not
/// be flattened.
pub struct StrictJson<T>(pub T);

impl<T, S> FromRequest<S> for StrictJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(envelope!(rejection)),
        }
    }
}

/// A [`Path`] extractor whose parse failures come back in the standard envelope.
///
/// `GET /api/executions/not-a-uuid` is the case this exists for. Axum rejects it before any handler
/// runs, so **no handler test covers it** — there is no handler involved — and its refusal used to
/// arrive as `text/plain` reading `Invalid URL: Cannot parse \`id\` with value \`not-a-uuid\`…`. A
/// client that parses `{"error": …}` got a body with no `error` field, on a request it had every
/// reason to expect a machine-readable refusal for: a malformed identifier is the single most likely
/// thing a caller gets wrong.
///
/// The status is Axum's, not a hardcoded `400`. `PathRejection::MissingPathParams` is a `500` and
/// means the *route* and the handler disagree about how many parameters exist — a defect in this
/// service, which must not be reported to the caller as their bad request.
pub struct StrictPath<T>(pub T);

impl<T, S> FromRequestParts<S> for StrictPath<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(envelope!(rejection)),
        }
    }
}

/// A [`Query`] extractor whose parse failures come back in the standard envelope.
///
/// `?limit=abc` against a `u64` field is the shape here: Axum refuses it during extraction with
/// `Failed to deserialize query string: limit: invalid digit found in string`, which is a perfectly
/// good message wrapped in the wrong envelope.
///
/// Note this governs only *malformed* query strings — a value that parses but is out of range is a
/// handler's judgement and stays [`AppError::InvalidInput`], which already renders correctly.
pub struct StrictQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for StrictQuery<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(envelope!(rejection)),
        }
    }
}

/// A raw-body extractor whose failures come back in the standard envelope.
///
/// The execute and webhook routes take their body as raw bytes rather than `Json<T>`, because the
/// same endpoint accepts both this service's `{"parameters": {…}}` shape and a third party's
/// arbitrary flat JSON — a typed extractor would have to pick one. That choice also means the
/// **router-wide `DefaultBodyLimit` surfaces on those routes as a `BytesRejection`**, so without
/// this wrapper the `413` on precisely the endpoints most likely to receive a large body was the one
/// refusal that still arrived as plain text.
pub struct StrictBytes(pub axum::body::Bytes);

impl<S> FromRequest<S> for StrictBytes
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::body::Bytes::from_request(req, state).await {
            Ok(bytes) => Ok(Self(bytes)),
            Err(rejection) => Err(envelope!(rejection)),
        }
    }
}

/// A [`StrictJson`] whose body may be absent entirely, yielding `T::default()`.
///
/// `DELETE /api/keys/{id}` needs this: the *first* request carries no body at all — it is a
/// question, and the answer is the `RBAC_MODEL.md` §6 pre-flight inventory — while the resubmission
/// carries the resolution map. Axum's own `Option<Json<T>>` does not cover the case, and demanding
/// an empty `{}` on the first request would make the common "delete a key that owns nothing" call
/// require a body for no reason.
///
/// Emptiness is decided from the *bytes*, not from `Content-Type`, so a client that sends the header
/// without a payload behaves the same as one that sends neither. Reading through
/// [`axum::body::Bytes`] keeps the request under `DefaultBodyLimit`, so the `413` control still
/// applies here as it does everywhere else.
pub struct OptionalStrictJson<T>(pub T);

impl<T, S> FromRequest<S> for OptionalStrictJson<T>
where
    T: serde::de::DeserializeOwned + Default,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::Bytes::from_request(req, state).await.map_err(|rejection| envelope!(rejection))?;

        if bytes.is_empty() {
            return Ok(Self(T::default()));
        }

        serde_json::from_slice(&bytes).map(Self).map_err(|e| {
            AppError::InvalidInput(format!(
                "Failed to deserialize the JSON body into the target type: {e}"
            ))
        })
    }
}
