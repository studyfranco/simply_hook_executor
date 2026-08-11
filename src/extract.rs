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
//! # What both extractors guarantee
//!
//! - **The refusal is `{"error": "…"}`**, like every other failure on these routes. A client
//!   parsing the envelope never has to special-case a body that failed to deserialize.
//! - **The rejection's own status is passed through**, never flattened to `400`. This matters more
//!   than it looks: the router-wide `DefaultBodyLimit` surfaces here as a rejection too, and
//!   collapsing every rejection to `400` would silently demote `413 Payload Too Large` into an
//!   indistinguishable bad request.
//! - **The serde message is verbatim.** A caller that sent `is_master` is told exactly which field
//!   was refused, rather than being left to guess at a generic "bad request".

use axum::extract::{FromRequest, Json, Request};

use crate::error::AppError;

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
            Err(rejection) => Err(AppError::BodyRejected(rejection.status(), rejection.body_text())),
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
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|rejection| AppError::BodyRejected(rejection.status(), rejection.body_text()))?;

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
