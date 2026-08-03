//! Encryption at rest for recoverable secrets.
//!
//! `api_keys.key_hash` is a one-way SHA-256 digest, which is exactly right for a credential the
//! server only ever needs to *compare*. `api_keys.signing_secret` is different: verifying an
//! HMAC-SHA256 signature means recomputing it, which requires the original bytes. It therefore
//! cannot be hashed, and storing it verbatim would mean that read access to the database — a
//! backup, a stray copy, an SQL injection elsewhere — is enough to forge signatures for every key.
//!
//! This module seals such secrets with XChaCha20-Poly1305 under a key supplied out-of-band via
//! `SIGNING_SECRET_KEY`, so the database alone is not sufficient to recover them.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngExt;

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
