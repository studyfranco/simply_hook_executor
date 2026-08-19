//! Consolidates key-level signature verification onto `CANONICAL_V1` alone.
//!
//! # What this removes, and why it is safe to
//!
//! `api_keys.hmac_mode`'s `BODY_ONLY` value is retired. It existed to accept third-party webhook
//! senders (GitHub/Forgejo/GitLab) whose format cannot be changed — no `X-Timestamp`, an alternate
//! `X-Hub-Signature-256` header, no replay protection — but a **key-level** mode was always an odd
//! fit for that: it required minting and distributing a bearer credential to a sender that, by
//! definition, cannot be taught to sign anything more than a raw body. `hooks.auth_mode = HMAC_ONLY`
//! (added the session before this one) now serves that exact use case at the **hook** level, with no
//! key involved at all — which is the shape a keyless third-party sender actually has. With that
//! route available, `BODY_ONLY` at the key level has no remaining use case that isn't better served
//! there, and removing it collapses key-level signing onto a single, well-understood mode.
//!
//! # What this adds
//!
//! `api_keys.canonical_template`, mirroring `hooks.canonical_template`: a nullable per-key override
//! of the `CANONICAL_V1` canonical string, defaulting (when `NULL`) to the service-wide
//! `{method}\n{path}\n{timestamp}\n{body}`. Unlike the hook-level column, this one is **not** free
//! for every key to set — `guard_canonical_v1_for_key_management` refuses a `can_manage_keys = true`
//! key any value here other than `NULL`, so the credential that can administer every other one stays
//! on the one template this codebase's own signature verification has been reviewed against.
//!
//! # The data fix
//!
//! Removing the `BODY_ONLY` variant from `HmacMode` means any row still storing that string would
//! fail to deserialize into the Rust enum the moment this migration's release starts up — a boot-time
//! crash on the first request touching an affected key, not a graceful degradation. `up()` therefore
//! rewrites every such row to `CANONICAL_V1` *before* the column stops accepting the old value in
//! application code. A key that was `BODY_ONLY` becomes an ordinary `CANONICAL_V1` key requiring
//! `X-Timestamp` from here on; there is no `down()` path that un-does this half, because which rows
//! were `BODY_ONLY` is not recoverable once forgotten, and `down()` restoring the *column* is not the
//! same claim as restoring the *data*.

use sea_orm_migration::prelude::*;

/// The subset of the `api_keys` table this migration touches.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The table itself.
    Table,
    /// Signature verification mode — the column this migration's data fix targets.
    HmacMode,
    /// Override of the `CANONICAL_V1` canonical string template, added here.
    CanonicalTemplate,
}

/// The hmac-mode-consolidation migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Data fix first: no window in which the column holds a value the Rust enum (post-deploy)
        // cannot parse. Built through `sea_query`'s typed statement builder rather than a raw SQL
        // string — `tests/source_hygiene.rs` enforces that every query path does, migrations
        // included, and this one is no exception to write by hand.
        manager
            .execute(
                Query::update()
                    .table(ApiKeys::Table)
                    .value(ApiKeys::HmacMode, "CANONICAL_V1")
                    .and_where(Expr::col(ApiKeys::HmacMode).eq("BODY_ONLY"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::CanonicalTemplate).text().null())
                    .to_owned(),
            )
            .await
    }

    /// Drops `canonical_template`. Does **not** attempt to restore any row to `BODY_ONLY` — see the
    /// module header on why that half of `up()` has no meaningful inverse.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::CanonicalTemplate)
                    .to_owned(),
            )
            .await
    }
}
