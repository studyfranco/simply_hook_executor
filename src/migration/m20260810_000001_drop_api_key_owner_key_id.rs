//! Drops the dormant `api_keys.owner_key_id` column and its index.
//!
//! # What this column was, and why it never did anything
//!
//! `m20230107_000001_key_lineage_and_resource_ownership` added `owner_key_id` to **two** tables at
//! once, on the symmetric-looking reasoning that if a hook has an owner then a key might as well.
//! Only one of the two turned out to mean anything:
//!
//! | Column | Status | Read by |
//! | :--- | :--- | :--- |
//! | `hooks.owner_key_id` | **Load-bearing — untouched by this migration** | `require_manage` (route 2), `require_lifecycle_authority`, `visible_hook_ids`, the §6 inventory |
//! | `api_keys.owner_key_id` | **Dormant — dropped here** | Nothing |
//!
//! The distinction is the whole of this migration's risk, so it was established mechanically rather
//! than by reading: `api_key::Column::OwnerKeyId` appears in **no query anywhere in `src/`**, while
//! `hook::Column::OwnerKeyId` appears in three. The key column was written at creation (the creator's
//! id) and at bootstrap (NULL), and never read again — not by a guard, not by a query, not by a
//! response DTO, not by the dashboard.
//!
//! It was write-only for a structural reason rather than by oversight. `RBAC_MODEL.md` §3 governs
//! **resources**, not principals: it restricts deleting or renaming *a hook* to Master and that
//! hook's owner. A key is not a resource in that sense — who may administer a key is decided by §4
//! visibility (`load_administrable_key`) and R4, both of which read `parent_key_id` and
//! `can_manage_keys`. There was never a rule for `api_keys.owner_key_id` to implement.
//!
//! # Why dropping is better than leaving it
//!
//! A populated column that no rule consults is worse than an absent one. It reads as an
//! authorization input to anyone auditing the schema — the comparative audit spent a row on it
//! precisely because it looks like one — and the standing risk is that some future handler *starts*
//! treating it as one, quietly introducing a second, unspecified ownership notion for keys alongside
//! the lineage `parent_key_id` that §6 actually walks. Removing it makes `parent_key_id` the single
//! answer to "how are keys related", which is what `simply_ip_vault` has always had.
//!
//! # Data loss, stated plainly
//!
//! This drops a populated column and **is not reversible with its contents**. What is lost is the
//! creator id of each key, and only where it has diverged from `parent_key_id` — which it cannot
//! have, because nothing ever wrote a different value: `create_api_key` set both to the caller's id
//! in the same statement, and no endpoint could reassign either. So `down()` restores the column,
//! its nullability and its index, and every row comes back NULL rather than with a creator; that is
//! honest rather than lossless, and it is the most a drop can offer.
//!
//! Operators wanting the values kept can snapshot them before upgrading:
//!
//! ```sql
//! CREATE TABLE api_keys_owner_backup AS
//!     SELECT id, owner_key_id FROM api_keys WHERE owner_key_id IS NOT NULL;
//! ```
//!
//! Nothing reads that table; it exists only so the information is recoverable by hand.

use sea_orm_migration::prelude::*;

/// The `api_keys` column this migration removes.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The table itself.
    Table,
    /// The dormant creator reference being dropped.
    OwnerKeyId,
}

/// Name of the index `m20230107` created over the column, dropped here alongside it.
///
/// Named as a constant because it must match `m20230107`'s spelling exactly: a mismatch would leave
/// an index over a column that no longer exists, which PostgreSQL refuses outright and SQLite drops
/// silently as part of the table rebuild — two different wrong outcomes from one typo.
const OWNER_INDEX: &str = "idx_api_keys_owner_key_id";

/// The drop-dormant-column migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Drops the index first, then the column.
    ///
    /// The order matters on PostgreSQL and MySQL, where dropping a column out from under an index is
    /// an error. SQLite rebuilds the table and would tolerate either order, but a migration that only
    /// works on the backend the tests happen to use is a migration that fails in production.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(Index::drop().name(OWNER_INDEX).table(ApiKeys::Table).to_owned())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::OwnerKeyId)
                    .to_owned(),
            )
            .await
    }

    /// Restores the column and its index — **empty**. See the module header: the values cannot be
    /// recovered, because a drop does not keep them. Rolling back returns a schema, not data.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::OwnerKeyId).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(OWNER_INDEX)
                    .table(ApiKeys::Table)
                    .col(ApiKeys::OwnerKeyId)
                    .to_owned(),
            )
            .await
    }
}
