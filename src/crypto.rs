//! Cryptographic primitives: HMAC request signing, and encryption at rest for recoverable secrets.
//!
//! # Two subjects, one module, on purpose
//!
//! Both halves exist to protect the same column. `api_keys.key_hash` is a one-way SHA-256 digest,
//! which is exactly right for a credential the server only ever needs to *compare*.
//! `api_keys.signing_secret` is different: verifying an HMAC-SHA256 signature means recomputing it,
//! which requires the original bytes. It therefore cannot be hashed, and storing it verbatim would
//! mean read access to the database — a backup, a stray copy, an SQL injection elsewhere — is enough
//! to forge signatures for every key. So:
//!
//! - [`generate_signing_secret`], [`canonical_v1_payload`], [`compute_signature`] and
//!   [`verify_signature`] are what that secret is *for*.
//! - [`SecretCipher`] is how it survives being written down.
//!
//! # Purity is the boundary
//!
//! Nothing here touches the database, the request, or `AppError`. Every function is a total
//! function of its arguments, which is what makes the signing half unit-testable at the byte level —
//! see [`tests::every_single_byte_mutation_of_a_valid_signature_is_rejected`], which would be
//! impractical to write against a middleware that needs a router, a pool and a seeded key first.
//!
//! Refusals are reported as [`SignatureRejection`] rather than as HTTP errors, so the decision about
//! what a caller is *told* stays in [`crate::middleware`], where the surrounding context (which
//! header was sent, what the key's `hmac_mode` is) is available to phrase it.

// Both `chacha20poly1305::aead` and `hmac` re-export a `KeyInit` trait, and both are needed here —
// `XChaCha20Poly1305::new` comes from one, `Hmac::new_from_slice` from the other. Importing the AEAD
// one under an alias keeps the collision explicit rather than resolving it by which `use` came last.
use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;

// ─────────────────────────────────────────────────────────────
// Request signing
// ─────────────────────────────────────────────────────────────

/// The mandatory algorithm tag on every `X-Signature-256` value.
///
/// Not decoration: it is the one part of the header that says *what the hex means*. A bare digest is
/// a field whose meaning depends on something outside itself, and the day a second algorithm is
/// offered, every stored or transcribed bare digest becomes ambiguous — the compatibility shim
/// needed to disambiguate them being exactly the downgrade surface that makes algorithm confusion
/// possible. Requiring the tag while `sha256` is the only value it can take is what makes adding a
/// second one a non-event.
pub const SIGNATURE_PREFIX: &str = "sha256=";

/// Generates a fresh 32-byte HMAC signing secret, hex-encoded.
///
/// Deliberately the same shape and entropy as [`crate::api::generate_random_key`] — but a wholly
/// independent value: knowing a key's public `X-API-Key` must never reveal its signing secret.
///
/// This lives in `crypto.rs` rather than beside the other credential minters in `api/support.rs`
/// because it is a cryptographic primitive, not request plumbing: it is the sole source of the
/// entropy every signature in the system ultimately rests on. `api/support.rs` re-exports nothing
/// of it — [`crate::api::support::mint_signing_pair`] calls through to here.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the **CANONICAL_V1** byte string that gets signed:
/// `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`.
///
/// The four fields are joined by a single `\n` (LF), with no trailing newline. `method` is expected
/// uppercase. `target` is the request target **including the query string** when one is present.
///
/// Three details are load-bearing:
///
/// - **The newline delimiters are not cosmetic.** Plain concatenation is ambiguous — `POST` +
///   `/api/x` and `POS` + `T/api/x` would produce identical input, letting a signature be replayed
///   against a different method/path pair. A delimiter that cannot appear in a method or a URL
///   target removes that whole class of boundary confusion.
/// - **The query string is included.** Signing only the path would leave `?older_than_days=0`
///   freely rewritable to `?older_than_days=1` on an otherwise-valid signed request.
/// - **The raw body is used verbatim**, never a re-serialized form, so the bytes verified are
///   exactly the bytes parsed.
///
/// Returns `Vec<u8>` rather than `String` because the body is arbitrary bytes and need not be valid
/// UTF-8; signing must not depend on the payload being decodable.
///
/// This is the one function in the file `scripts/verify_convergence.sh` diffs byte-for-byte against
/// `simply_ip_vault`'s copy. A difference here means a signature one service issues is not one the
/// other verifies, so it must not be "tidied" independently on either side.
pub fn canonical_v1_payload(method: &str, target: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(method.len() + target.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(target.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

/// Computes the `X-Signature-256` header value over an already-built payload.
///
/// Returns the **whole header value**, [`SIGNATURE_PREFIX`] included, rather than a bare digest.
/// That makes "produce a signature" and "produce a valid header" the same operation, so a caller
/// cannot build one without the other, and there is no code path in this crate that emits an
/// untagged digest for someone to accidentally send.
///
/// Takes the payload rather than the four canonical components because this service has two signed
/// shapes: `CANONICAL_V1` signs [`canonical_v1_payload`], while `BODY_ONLY` signs the raw body
/// alone. Splitting the payload out is what lets one HMAC implementation serve both, instead of the
/// weaker mode needing its own near-copy.
///
/// `None` only if `secret` cannot be used as HMAC key material at all. That is unreachable in
/// practice — HMAC accepts keys of any length, including empty — but it is reported rather than
/// unwrapped, because `AGENT.MD` forbids panicking on a path an attacker chooses the input to.
pub fn compute_signature(secret: &str, payload: &[u8]) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload);
    Some(format!("{SIGNATURE_PREFIX}{}", hex::encode(mac.finalize().into_bytes())))
}

/// Why a presented signature was refused.
///
/// Four variants rather than a `bool` because the four failures are genuinely different events and
/// the caller phrases them differently: three are client mistakes worth naming precisely, and
/// [`SignatureRejection::KeyUnusable`] is a server fault that must never be reported as a bad
/// signature. Collapsing them would either leak detail into the wrong cases or flatten an operator
/// emergency into "your signature is wrong".
///
/// Note what is deliberately *not* distinguished at the wire level: [`SignatureRejection::Mismatch`]
/// covers a tampered payload, a wrong secret, and a tag of the wrong width alike. Those must look
/// identical to a caller — telling them apart is precisely the oracle an attacker wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureRejection {
    /// The value did not begin with [`SIGNATURE_PREFIX`].
    MissingPrefix,
    /// The prefix was present, but what followed is not hexadecimal.
    MalformedHex,
    /// Well-formed, and does not match the expected digest.
    Mismatch,
    /// The stored secret could not be used as HMAC key material — a server fault, not a caller one.
    KeyUnusable,
}

/// Verifies a caller-supplied `X-Signature-256` value against `payload`.
///
/// # Constant-time comparison
///
/// The digest comparison goes through [`Mac::verify_slice`], whose implementation chain was verified
/// against the vendored source rather than assumed:
///
/// ```text
/// Mac::verify_slice  ->  CtOutput::eq  ->  subtle::ConstantTimeEq::ct_eq
/// ```
///
/// `verify_slice` first rejects a tag of the wrong length — that leaks only the digest width, which
/// is a public constant — and then compares all 32 bytes in constant time. Comparing the hex strings
/// with `==` instead would let an attacker recover a valid signature one byte at a time by measuring
/// response latency. This must therefore never be "simplified" into an equality check on the decoded
/// bytes or the hex text; `scripts/verify_convergence.sh` greps for exactly that regression.
///
/// `subtle` is reached through the RustCrypto `Mac` API rather than depended on directly: the API
/// already provides the guarantee, and hand-rolling the comparison would be more code for no benefit.
///
/// # Return value
///
/// The **raw decoded digest bytes** on success, so [`crate::replay::ReplayGuard`] can key on
/// canonical material without re-parsing the header. That also normalizes spelling by construction:
/// `sha256=AB…` and `sha256=ab…` are the same signature and decode to the same bytes, so they can
/// never be recorded as two distinct single uses.
pub fn verify_signature(
    secret: &str,
    payload: &[u8],
    provided: &str,
) -> Result<Vec<u8>, SignatureRejection> {
    verify_signature_with_prefix(secret, payload, provided, SIGNATURE_PREFIX)
}

/// [`verify_signature`], generalized to a caller-supplied prefix.
///
/// Exists for `hooks.signature_prefix`: an `HMAC_ONLY` hook may configure a prefix other than
/// [`SIGNATURE_PREFIX`] (a third-party sender's own convention), while every other caller in this
/// crate keeps using the fixed one through [`verify_signature`] above. The stripping, decoding and
/// constant-time comparison are otherwise identical — see [`verify_signature`]'s doc comment for why
/// each step is shaped the way it is.
pub fn verify_signature_with_prefix(
    secret: &str,
    payload: &[u8],
    provided: &str,
    prefix: &str,
) -> Result<Vec<u8>, SignatureRejection> {
    // The prefix is required, not merely tolerated: a `None` here ends verification rather than
    // falling back to treating the whole value as hex.
    let hex_digest = provided.trim().strip_prefix(prefix).ok_or(SignatureRejection::MissingPrefix)?;
    let provided_bytes =
        hex::decode(hex_digest.trim()).map_err(|_| SignatureRejection::MalformedHex)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| SignatureRejection::KeyUnusable)?;
    mac.update(payload);
    mac.verify_slice(&provided_bytes)
        .map_err(|_| SignatureRejection::Mismatch)?;

    Ok(provided_bytes)
}

/// The `canonical_template` used when a `CANONICAL_V1` hook leaves the column `NULL`, spelled out
/// as a template string in the same shape [`canonical_v1_payload`] builds directly. The two must
/// stay equivalent: this constant is what [`hooks.canonical_template`] documents itself against, and
/// [`canonical_v1_payload`] is what every route with no hook-level override actually signs.
pub const DEFAULT_CANONICAL_TEMPLATE: &str = "{method}\n{path}\n{timestamp}\n{body}";

/// Renders a hook's custom canonical template, substituting `{method}`, `{path}`, `{timestamp}` and
/// `{body}`.
///
/// Substitution is purely textual — `body` is decoded as UTF-8 on a best-effort basis (invalid bytes
/// become the Unicode replacement character) since a template is necessarily a `String`, and an
/// unrecognized `{placeholder}` is left in the output verbatim rather than rejected. A template is
/// data the hook's operator supplies and is responsible for; this function does not validate its
/// shape beyond performing the substitution, matching [`hooks.canonical_template`]'s documented
/// contract.
///
/// Returns bytes, not `String`, for the same reason [`canonical_v1_payload`] does: the result is
/// HMAC key material, not text to be displayed.
pub fn render_canonical_template(
    template: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_text = String::from_utf8_lossy(body);
    template
        .replace("{method}", method)
        .replace("{path}", path)
        .replace("{timestamp}", timestamp)
        .replace("{body}", &body_text)
        .into_bytes()
}

// ─────────────────────────────────────────────────────────────
// Encryption at rest
// ─────────────────────────────────────────────────────────────

/// Environment variable holding the 32-byte (64 hex character) encryption key.
const KEY_ENV_VAR: &str = "SIGNING_SECRET_KEY";
/// Accepted alias for [`KEY_ENV_VAR`], for deployments that already provision a general-purpose
/// vault key. `SIGNING_SECRET_KEY` wins when both are set.
const KEY_ENV_VAR_ALIAS: &str = "VAULT_ENCRYPTION_KEY";
/// Prefix marking a value stored without encryption.
const PLAINTEXT_PREFIX: &str = "v1.plain.";
/// Prefix marking a value sealed with XChaCha20-Poly1305.
const SEALED_PREFIX: &str = "v1.xchacha20poly1305.";
/// XChaCha20-Poly1305 nonce width, in bytes.
const NONCE_LEN: usize = 24;
/// Required encryption key width, in bytes.
const KEY_LEN: usize = 32;

/// Failure modes for sealing and opening stored secrets.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// `SIGNING_SECRET_KEY` was set but is not 64 hex characters.
    #[error(
        "{KEY_ENV_VAR} must be exactly {} hex characters ({KEY_LEN} bytes); generate one with \
         `openssl rand -hex {KEY_LEN}`",
        KEY_LEN * 2
    )]
    InvalidKey,
    /// The stored value is not in a recognized format.
    #[error("Stored secret is malformed or was written by a newer version")]
    MalformedCiphertext,
    /// The ciphertext failed authentication — wrong key, or the row was tampered with.
    #[error(
        "Stored secret could not be decrypted. This usually means {KEY_ENV_VAR} does not match the \
         key the secret was written with"
    )]
    DecryptionFailed,
    /// The cipher itself failed.
    #[error("Encryption failed")]
    EncryptionFailed,
}

/// How recoverable secrets are protected at rest.
pub enum SecretCipher {
    /// No encryption key configured: secrets are stored verbatim.
    ///
    /// Kept as a supported mode so the daemon still runs with zero configuration, but it means
    /// database confidentiality is the *only* thing protecting signing secrets.
    Plaintext,
    /// Secrets are sealed with XChaCha20-Poly1305 under the configured key.
    Sealed(Box<XChaCha20Poly1305>),
}

impl std::fmt::Debug for SecretCipher {
    /// Never renders key material, so a `{:?}` of application state cannot leak it into a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => f.write_str("SecretCipher::Plaintext"),
            Self::Sealed(_) => f.write_str("SecretCipher::Sealed(<redacted>)"),
        }
    }
}

impl SecretCipher {
    /// Builds the cipher from `SIGNING_SECRET_KEY`.
    ///
    /// A malformed key is a hard error rather than a fallback to plaintext: an operator who set
    /// the variable believes their secrets are encrypted, and silently writing them in the clear
    /// would betray that belief at exactly the wrong moment.
    pub fn from_env() -> Result<Self, CryptoError> {
        let configured = std::env::var(KEY_ENV_VAR)
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .or_else(|| {
                std::env::var(KEY_ENV_VAR_ALIAS)
                    .ok()
                    .filter(|raw| !raw.trim().is_empty())
            });

        match configured {
            Some(raw) => Self::from_hex_key(raw.trim()),
            None => Ok(Self::Plaintext),
        }
    }

    /// Builds a cipher from a hex-encoded 32-byte key.
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        // `TryFrom` rather than the deprecated `from_slice`: the length was already checked
        // above, so this conversion cannot fail.
        let key = Key::try_from(bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let cipher = XChaCha20Poly1305::new(&key);
        Ok(Self::Sealed(Box::new(cipher)))
    }

    /// Whether secrets are actually being encrypted.
    pub fn is_encrypting(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// Encodes a secret for storage.
    pub fn seal(&self, plaintext: &str) -> Result<String, CryptoError> {
        match self {
            Self::Plaintext => Ok(format!("{PLAINTEXT_PREFIX}{}", hex::encode(plaintext))),
            Self::Sealed(cipher) => {
                // A fresh random nonce per secret: XChaCha20's 192-bit nonce makes random
                // generation collision-safe without any counter state to persist.
                let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
                let nonce = XNonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed)?;
                Ok(format!(
                    "{SEALED_PREFIX}{}.{}",
                    hex::encode(nonce_bytes),
                    hex::encode(ciphertext)
                ))
            }
        }
    }

    /// Recovers a secret written by [`SecretCipher::seal`].
    ///
    /// Plaintext rows are readable regardless of the configured mode, so enabling encryption on an
    /// existing deployment does not invalidate keys issued before it; newly-written secrets are
    /// sealed from then on.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        if let Some(encoded) = stored.strip_prefix(PLAINTEXT_PREFIX) {
            let bytes = hex::decode(encoded).map_err(|_| CryptoError::MalformedCiphertext)?;
            return String::from_utf8(bytes).map_err(|_| CryptoError::MalformedCiphertext);
        }

        let body = stored
            .strip_prefix(SEALED_PREFIX)
            .ok_or(CryptoError::MalformedCiphertext)?;
        let (nonce_hex, ciphertext_hex) = body
            .split_once('.')
            .ok_or(CryptoError::MalformedCiphertext)?;

        let nonce_bytes = hex::decode(nonce_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptoError::MalformedCiphertext);
        }
        let ciphertext = hex::decode(ciphertext_hex).map_err(|_| CryptoError::MalformedCiphertext)?;

        let Self::Sealed(cipher) = self else {
            // A sealed row with no key configured: report it as a key mismatch rather than
            // pretending the data is corrupt, since the fix is to set SIGNING_SECRET_KEY.
            return Err(CryptoError::DecryptionFailed);
        };

        let nonce = XNonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| CryptoError::MalformedCiphertext)?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // ── Request signing ──────────────────────────────────────────────────────
    //
    // These moved here wholesale from `src/middleware.rs` when the primitive did. They test the
    // same bytes they always did; what changed is that they no longer need to reach into a private
    // middleware function to do it.

    /// The canonical base a client would build for a typical signed request.
    fn base(method: &str, path: &str, ts: &str, body: &[u8]) -> Vec<u8> {
        canonical_v1_payload(method, path, ts, body)
    }

    /// Computes the header value a well-behaved client would send.
    fn sign(secret: &str, payload: &[u8]) -> String {
        compute_signature(secret, payload).expect("HMAC accepts any key length")
    }

    #[test]
    fn canonical_base_is_newline_delimited() {
        assert_eq!(
            base("POST", "/api/hooks/x/execute", "1700000000", b"{}"),
            b"POST\n/api/hooks/x/execute\n1700000000\n{}".to_vec()
        );
        // An empty body still contributes its delimiter, so "no body" is distinct from a body of
        // "\n" and cannot be substituted for it.
        assert_eq!(
            base("GET", "/api/hooks", "1700000000", b""),
            b"GET\n/api/hooks\n1700000000\n".to_vec()
        );
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

    /// The payload is bytes, not text, and a body that is not valid UTF-8 must sign anyway.
    ///
    /// This is what the `Vec<u8>` return type buys, and it is not hypothetical: `BODY_ONLY` exists
    /// to accept third-party senders whose format this service does not get to choose, and nothing
    /// obliges such a sender to post UTF-8.
    #[test]
    fn a_body_that_is_not_valid_utf8_still_signs_and_verifies() {
        let body = [0xff_u8, 0xfe, 0x00, 0x80];
        let payload = base("POST", "/webhook/x", "1700000000", &body);
        assert!(String::from_utf8(body.to_vec()).is_err(), "the fixture really is not UTF-8");

        let signature = sign("secret", &payload);
        assert!(verify_signature("secret", &payload, &signature).is_ok());
    }

    #[test]
    fn compute_and_verify_are_inverses() {
        let payload = base("POST", "/api/hooks/x/execute", "1700000000", br#"{"parameters":{}}"#);
        let signature = sign("secret", &payload);

        assert!(signature.starts_with(SIGNATURE_PREFIX), "the tag is emitted, never a bare digest");
        let digest = verify_signature("secret", &payload, &signature).expect("it verifies");
        // The decoded digest comes back, which is what `ReplayGuard` keys on.
        assert_eq!(digest, hex::decode(&signature[SIGNATURE_PREFIX.len()..]).expect("hex"));
        assert_eq!(digest.len(), 32, "SHA-256 tags are 32 bytes");
    }

    /// Hex case is not part of the signature's identity.
    ///
    /// `sha256=AB…` and `sha256=ab…` decode to the same bytes and must both verify. This matters
    /// beyond politeness: the replay guard keys on the returned bytes, so if case survived into the
    /// key, one signature spelled two ways would count as two distinct single uses and the
    /// single-use guarantee would be spellable around.
    #[test]
    fn the_same_signature_in_either_hex_case_verifies_to_the_same_digest() {
        let payload = base("POST", "/api/x", "1700000000", b"{}");
        let lower = sign("secret", &payload);
        let upper = format!(
            "{SIGNATURE_PREFIX}{}",
            lower[SIGNATURE_PREFIX.len()..].to_ascii_uppercase()
        );
        assert_ne!(lower, upper, "the two spellings really do differ as text");

        assert_eq!(
            verify_signature("secret", &payload, &lower).expect("lowercase verifies"),
            verify_signature("secret", &payload, &upper).expect("uppercase verifies"),
        );
    }

    #[test]
    fn rejects_tampered_payload_wrong_secret_and_malformed_headers() {
        let body = br#"{"parameters":{"target":"1.2.3.4"}}"#;
        let payload = base("POST", "/api/hooks/x/execute", "1700000000", body);
        let signature = sign("secret", &payload);

        let tampered =
            base("POST", "/api/hooks/x/execute", "1700000000", br#"{"parameters":{"target":"9.9.9.9"}}"#);

        // The *variant* is asserted, not merely `is_err()`. The split between a malformed header
        // and a mismatched digest is what `middleware::reject_signature` turns into two different
        // HTTP answers, so a change that collapsed them would still pass a bare `is_err()`.
        assert_eq!(
            verify_signature("secret", &tampered, &signature),
            Err(SignatureRejection::Mismatch)
        );
        assert_eq!(
            verify_signature("other-secret", &payload, &signature),
            Err(SignatureRejection::Mismatch)
        );
        assert_eq!(
            verify_signature("secret", &payload, "not-prefixed"),
            Err(SignatureRejection::MissingPrefix)
        );
        assert_eq!(
            verify_signature("secret", &payload, "sha256=nothex"),
            Err(SignatureRejection::MalformedHex)
        );
        // An empty tag is well-formed hex of zero length, so it fails on width, not on parsing.
        assert_eq!(
            verify_signature("secret", &payload, "sha256="),
            Err(SignatureRejection::Mismatch)
        );
    }

    /// The `sha256=` tag is mandatory, and a bare digest is refused even when it is the *correct*
    /// digest. That is the whole point: the tag names the algorithm, and accepting untagged hex
    /// would be the compatibility shim that makes algorithm confusion possible later.
    #[test]
    fn a_correct_but_untagged_digest_is_still_refused() {
        let payload = base("POST", "/api/x", "1700000000", b"{}");
        let bare = sign("secret", &payload)[SIGNATURE_PREFIX.len()..].to_owned();
        assert_eq!(
            verify_signature("secret", &payload, &bare),
            Err(SignatureRejection::MissingPrefix)
        );
        // Case-sensitively, too: the prefix is an exact match, not a normalized one.
        assert_eq!(
            verify_signature("secret", &payload, &format!("SHA256={bare}")),
            Err(SignatureRejection::MissingPrefix)
        );
    }

    #[test]
    fn a_signature_cannot_be_replayed_across_method_path_or_timestamp() {
        let body = br#"{}"#;
        let original = base("POST", "/api/hooks/a/test", "1700000000", body);
        let signature = sign("secret", &original);

        // Same body and timestamp, different method: a dry run must not become an execution.
        assert!(
            verify_signature("secret", &base("DELETE", "/api/hooks/a/test", "1700000000", body), &signature)
                .is_err()
        );
        // Same method and timestamp, different path: one hook's signature must not run another's.
        assert!(
            verify_signature("secret", &base("POST", "/api/hooks/b/execute", "1700000000", body), &signature)
                .is_err()
        );
        // Same everything but the timestamp: an old capture cannot be re-dated.
        assert!(
            verify_signature("secret", &base("POST", "/api/hooks/a/test", "1700000900", body), &signature)
                .is_err()
        );
        // The query string is covered too.
        let listing = base("GET", "/api/executions?limit=10", "1700000000", b"");
        let listing_sig = sign("secret", &listing);
        assert!(
            verify_signature(
                "secret",
                &base("GET", "/api/executions?limit=1000", "1700000000", b""),
                &listing_sig
            )
            .is_err()
        );
    }

    #[test]
    fn every_single_byte_mutation_of_a_valid_signature_is_rejected() {
        let payload = base("POST", "/api/hooks/x/execute", "1700000000", br#"{"parameters":{}}"#);
        let valid = sign("secret", &payload);
        let digest = hex::decode(&valid[SIGNATURE_PREFIX.len()..]).expect("valid hex");
        assert_eq!(digest.len(), 32, "SHA-256 tags are 32 bytes");

        // Flipping any bit at any position must fail. This is the deterministic fingerprint of a
        // full-width comparison: a prefix-only, suffix-only, or truncated compare would let
        // mutations outside the compared region slip through, and would show up here as a specific
        // range of positions that wrongly verify.
        for position in 0..digest.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut mutated = digest.clone();
                mutated[position] ^= mask;
                let signature = format!("{SIGNATURE_PREFIX}{}", hex::encode(&mutated));
                assert!(
                    verify_signature("secret", &payload, &signature).is_err(),
                    "a signature differing at byte {position} (mask {mask:#04x}) must be rejected"
                );
            }
        }

        // ...while the unmutated signature still verifies, so the loop above is not passing simply
        // because everything fails.
        assert!(verify_signature("secret", &payload, &valid).is_ok());
    }

    #[test]
    fn tags_of_the_wrong_length_are_rejected() {
        let payload = base("POST", "/api/hooks/x/execute", "1700000000", b"{}");
        let valid = sign("secret", &payload);
        let hex_digest = valid[SIGNATURE_PREFIX.len()..].to_owned();

        // A truncated tag must not verify against a truncated comparison, and an over-long one
        // must not be silently trimmed.
        for wrong in [
            &hex_digest[..62],          // 31 bytes
            &hex_digest[..2],           // 1 byte
            "",                         // empty
            &format!("{hex_digest}00"), // 33 bytes
        ] {
            assert!(
                verify_signature("secret", &payload, &format!("{SIGNATURE_PREFIX}{wrong}")).is_err(),
                "a {}-char tag must be rejected",
                wrong.len()
            );
        }
    }

    /// An empty secret is usable HMAC key material — so a key with an empty signing secret produces
    /// signatures that verify, rather than failing open or panicking.
    ///
    /// Worth pinning because [`SignatureRejection::KeyUnusable`] exists for a case that HMAC-SHA256
    /// makes unreachable, and it would be easy to assume "empty secret" is that case. It is not: the
    /// protection against an empty secret is that one is never *minted*, which is
    /// [`generate_signing_secret`]'s job, not this function's.
    #[test]
    fn an_empty_secret_is_valid_hmac_key_material_and_does_not_fail_open() {
        let payload = base("POST", "/api/x", "1700000000", b"{}");
        let signature = sign("", &payload);
        assert!(verify_signature("", &payload, &signature).is_ok());
        // And it is genuinely a distinct key: a signature made with it does not verify elsewhere.
        assert!(verify_signature("secret", &payload, &signature).is_err());
    }

    /// Minted secrets are 256 bits of fresh entropy, hex-encoded, and never repeat.
    #[test]
    fn generated_signing_secrets_are_full_width_hex_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let secret = generate_signing_secret();
            assert_eq!(secret.len(), 64, "32 bytes, hex-encoded");
            assert!(secret.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            assert!(seen.insert(secret), "a repeated secret means the RNG is not being reseeded");
        }
    }

    // ── Encryption at rest ───────────────────────────────────────────────────

    #[test]
    fn plaintext_mode_round_trips() {
        let cipher = SecretCipher::Plaintext;
        assert!(!cipher.is_encrypting());
        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");
        assert!(sealed.starts_with(PLAINTEXT_PREFIX));
        // Even unencrypted storage is hex-encoded, so the raw secret is never a substring of the
        // stored column — a casual `grep` of a database dump does not surface it.
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "s3cr3t");
    }

    #[test]
    fn sealed_mode_round_trips_and_hides_the_secret() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert!(cipher.is_encrypting());

        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");
        assert!(sealed.starts_with(SEALED_PREFIX));
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "s3cr3t");
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let first = cipher.seal("same-input").expect("sealing succeeds");
        let second = cipher.seal("same-input").expect("sealing succeeds");
        assert_ne!(first, second, "identical plaintexts must not produce identical ciphertexts");
        assert_eq!(cipher.open(&first).expect("opens"), cipher.open(&second).expect("opens"));
    }

    #[test]
    fn a_wrong_key_cannot_open_a_sealed_secret() {
        let writer = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let other = SecretCipher::from_hex_key(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .expect("valid key");

        let sealed = writer.seal("s3cr3t").expect("sealing succeeds");
        assert!(matches!(other.open(&sealed), Err(CryptoError::DecryptionFailed)));
        // Nor can a daemon that lost its key entirely.
        assert!(matches!(SecretCipher::Plaintext.open(&sealed), Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");

        // Flip the final ciphertext nibble; Poly1305 authentication must reject it.
        let mut bytes: Vec<char> = sealed.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = bytes.into_iter().collect();

        assert!(matches!(cipher.open(&tampered), Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn sealed_rows_stay_readable_after_encryption_is_enabled() {
        // A deployment that ran unencrypted, then configured a key, must still be able to read
        // the secrets it issued earlier.
        let legacy = SecretCipher::Plaintext.seal("issued-before").expect("sealing succeeds");
        let upgraded = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert_eq!(upgraded.open(&legacy).expect("opening succeeds"), "issued-before");
    }

    /// `SIGNING_SECRET_KEY` is process-wide state, so the tests that mutate it must not run
    /// concurrently on different libtest threads — `set_var` is `unsafe` precisely because
    /// concurrent mutation is a data race.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Startup must fail closed on a bad key rather than degrade to plaintext.
    ///
    /// This is the property that matters most in this module: an operator who set the variable
    /// believes their signing secrets are encrypted. Silently writing them in the clear because the
    /// value was mistyped would betray that belief at exactly the moment it counted, and would do so
    /// invisibly — the daemon would start, serve, and look entirely healthy.
    #[test]
    fn a_malformed_key_aborts_startup_instead_of_downgrading_to_plaintext() {
        let _guard = ENV_LOCK.lock();

        for bad in ["not-hex", "00ff", "", "   ", &"a".repeat(63), &"a".repeat(65), "zz".repeat(32).as_str()] {
            unsafe { std::env::set_var(KEY_ENV_VAR, bad) };
            let outcome = SecretCipher::from_env();
            match bad.trim() {
                // An empty or whitespace-only value is "unset" rather than "malformed", and is the
                // documented zero-config path — it warns loudly at startup instead.
                "" => assert!(
                    outcome.is_ok_and(|c| !c.is_encrypting()),
                    "an empty {KEY_ENV_VAR} is the documented plaintext fallback"
                ),
                _ => assert!(
                    matches!(outcome, Err(CryptoError::InvalidKey)),
                    "{bad:?} must abort startup, not silently store secrets in the clear"
                ),
            }
        }

        // A well-formed key produces an encrypting cipher, so the loop above is not passing simply
        // because everything fails.
        unsafe { std::env::set_var(KEY_ENV_VAR, TEST_KEY) };
        assert!(SecretCipher::from_env().is_ok_and(|c| c.is_encrypting()));

        unsafe { std::env::remove_var(KEY_ENV_VAR) };
    }

    /// The alias exists for deployments already provisioning a general-purpose vault key, and must
    /// be held to the same standard — an alias that accepted a weaker key would be a way around the
    /// check above.
    #[test]
    fn the_alias_is_honoured_but_validated_just_as_strictly() {
        let _guard = ENV_LOCK.lock();
        unsafe { std::env::remove_var(KEY_ENV_VAR) };

        unsafe { std::env::set_var(KEY_ENV_VAR_ALIAS, TEST_KEY) };
        assert!(SecretCipher::from_env().is_ok_and(|c| c.is_encrypting()));

        unsafe { std::env::set_var(KEY_ENV_VAR_ALIAS, "too-short") };
        assert!(matches!(SecretCipher::from_env(), Err(CryptoError::InvalidKey)));

        // The primary variable wins when both are set, so an unrelated legacy value cannot
        // downgrade a deployment that configured the specific one.
        unsafe { std::env::set_var(KEY_ENV_VAR, TEST_KEY) };
        assert!(SecretCipher::from_env().is_ok_and(|c| c.is_encrypting()));

        unsafe { std::env::remove_var(KEY_ENV_VAR) };
        unsafe { std::env::remove_var(KEY_ENV_VAR_ALIAS) };
    }

    /// Malformed input is rejected *as malformed*, not merely rejected.
    ///
    /// The variant is asserted rather than `is_err()` because the distinction between
    /// [`CryptoError::MalformedCiphertext`] and [`CryptoError::DecryptionFailed`] is the whole
    /// fail-closed contract of [`SecretCipher::open`]. A bare `is_err()` would keep passing if the
    /// prefix check were ever loosened into a fall-through that reached the cipher and failed
    /// authentication instead — the same red test result for a materially different code path, and
    /// one that would accept formats this function is supposed to refuse outright.
    #[test]
    fn malformed_keys_and_values_are_rejected() {
        assert!(matches!(SecretCipher::from_hex_key("not-hex"), Err(CryptoError::InvalidKey)));
        assert!(matches!(SecretCipher::from_hex_key("00ff"), Err(CryptoError::InvalidKey)));

        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        for malformed in [
            "",                                   // no prefix at all
            "garbage",                            // no prefix, non-empty
            "v1.xchacha20poly1305.nodot",         // sealed prefix, missing the nonce/ciphertext split
            "v1.plain.zz",                        // plaintext prefix, invalid hex
            "v1.xchacha20poly1305.zz.00",         // sealed prefix, invalid nonce hex
            "v1.xchacha20poly1305.00ff.00",       // sealed prefix, nonce of the wrong width
            "v1.xchacha20poly1305..00",           // sealed prefix, empty nonce
            "aesgcm256:deadbeef",                 // a format this service never wrote
            "V1.PLAIN.6162",                      // right shape, wrong case: prefixes are exact
        ] {
            assert!(
                matches!(cipher.open(malformed), Err(CryptoError::MalformedCiphertext)),
                "{malformed:?} must be refused as malformed, not merely refused"
            );
        }
    }
}
