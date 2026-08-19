//! Adds per-hook inbound authentication configuration: `hooks.auth_mode` and four supporting
//! fields (`hmac_secret`, `signature_header`, `signature_prefix`, `canonical_template`).
//!
//! # Why this lives on `Hook`, not `ApiKey`
//!
//! `api_keys.hmac_mode` (`CANONICAL_V1`/`BODY_ONLY`) answers "how does *this credential's* own
//! signature verify" and is unchanged by this migration. `hooks.auth_mode` answers a different
//! question — "what does *this endpoint* accept from a caller" — including two shapes a credential
//! cannot express on its own: `HMAC_ONLY` (a signed request carrying no `X-API-Key` at all, verified
//! against a secret that belongs to the hook rather than to any key) and `NONE` (no credential and
//! no signature whatsoever). Putting `auth_mode` on `ApiKey` instead would make `NONE` mean "a key
//! that authenticates as nobody", which is incoherent for a credential object.
//!
//! # Nullable, `NOT NULL`, or both
//!
//! `auth_mode` is `NOT NULL DEFAULT 'CANONICAL_V1'` — every existing hook keeps requiring exactly
//! what it always required (a valid `X-API-Key`, verified per the caller's own `hmac_mode`), with no
//! backfill pass needed. The other four columns are all nullable: they are refinements a hook may or
//! may not set, and `NULL` means "use the built-in default", applied at read time rather than baked
//! into the row (see `AuthMode` and the constants beside it in `src/entities/hook.rs`).
//!
//! `hmac_secret` is encrypted at rest through the same `SecretCipher` that protects
//! `api_keys.signing_secret`, for the same reason: verifying an `HMAC_ONLY` signature means
//! recomputing it, which requires the secret back in plaintext, so it cannot be hashed.

use sea_orm_migration::prelude::*;

/// The subset of the `hooks` table this migration touches.
#[derive(DeriveIden)]
enum Hooks {
    /// The table itself.
    Table,
    /// Inbound authentication mode: `CANONICAL_V1`, `HMAC_ONLY`, `API_KEY_ONLY`, or `NONE`.
    AuthMode,
    /// `HMAC_ONLY`'s signing secret, encrypted at rest. `NULL` for every other mode.
    HmacSecret,
    /// Header an `HMAC_ONLY` sender's signature arrives on. `NULL` means the built-in default,
    /// `X-Signature-256`.
    SignatureHeader,
    /// Prefix stripped from an `HMAC_ONLY` signature before hex-decoding it. `NULL` means the
    /// built-in default, `sha256=`.
    SignaturePrefix,
    /// Override of the `CANONICAL_V1` canonical string template, applied when a keyed caller
    /// invokes a hook whose own `auth_mode` is `CANONICAL_V1`. `NULL` means the service-wide
    /// default, `{method}\n{path}\n{timestamp}\n{body}`.
    CanonicalTemplate,
}

/// The hook-auth-mode migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(
                        ColumnDef::new(Hooks::AuthMode)
                            .string()
                            .not_null()
                            .default("CANONICAL_V1"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::HmacSecret).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::SignatureHeader).string().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::SignaturePrefix).string().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Hooks::Table)
                    .add_column(ColumnDef::new(Hooks::CanonicalTemplate).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            Hooks::CanonicalTemplate,
            Hooks::SignaturePrefix,
            Hooks::SignatureHeader,
            Hooks::HmacSecret,
            Hooks::AuthMode,
        ] {
            manager
                .alter_table(Table::alter().table(Hooks::Table).drop_column(column).to_owned())
                .await?;
        }
        Ok(())
    }
}
