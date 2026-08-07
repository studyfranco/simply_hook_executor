//! Adds key lineage (`api_keys.parent_key_id`) and resource ownership (`owner_key_id` on
//! `api_keys` and `hooks`), plus the indexes `RBAC_MODEL.md` §7 requires.
//!
//! # Two columns that look alike and are not
//!
//! - **`parent_key_id`** — *who created this key.* Immutable lineage. §3's R3 is emphatic that it
//!   confers **no authority**: "`parent_key_id` exists solely for cascading deletion and visibility
//!   scoping. A daughter of the Master key is an ordinary daughter key with no elevated standing."
//!   Nothing may ever read this column to decide whether a request is allowed.
//! - **`owner_key_id`** — *who is answerable for this entity.* Reassignable by Master (§3), and the
//!   only non-Master identity that may delete or rename the entity. Holding manage rights, or any
//!   operational verb, confers no lifecycle authority: "a parent that merely uses a resource must
//!   not be able to delete it."
//!
//! The distinction matters at deletion time. §6 walks the subtree via `parent_key_id` to find every
//! key being removed, then collects everything those keys *own* via `owner_key_id`. Conflating the
//! two would make a key's creator automatically responsible for resources that had since been
//! handed to somebody else.
//!
//! # Backfill: explicit NULL, never a guess
//!
//! Every existing row gets `NULL` for all three columns, and that is a deliberate refusal rather
//! than a default that happened to be convenient.
//!
//! There is no honest way to reconstruct lineage after the fact. `audit_logs` records `KEY_CREATE`
//! entries, but they are retention-swept, are absent for anything created before auditing covered
//! it, and name the actor by prefix rather than id. Ownership is worse: a hook's creator is not
//! recorded anywhere at all — `grant_full_hook_permission` gives the creator an ordinary permission
//! row, byte-identical to a delegated one, so "the key holding `can_manage`" is not evidence of
//! authorship and may well be several keys.
//!
//! Assigning ownership to the master would have been the tempting alternative. It is worse than
//! NULL: §3 restricts deletion and renaming to Master and the owner, so a backfill naming master
//! everywhere is indistinguishable from no ownership *and* silently asserts a fact nobody checked.
//! NULL says what is true — this predates ownership — and leaves lifecycle authority with Master
//! alone until an operator assigns it deliberately.
//!
//! # No database-level foreign keys, on purpose
//!
//! All three columns reference `api_keys.id` logically, and none carries a DDL `REFERENCES` clause.
//! Both available behaviours are wrong here:
//!
//! - `ON DELETE CASCADE` would delete a hook when its owner key is deleted. §6 forbids exactly
//!   that: "Data is never destroyed implicitly... Hooks must never disappear as a side effect of
//!   removing a key."
//! - `ON DELETE SET NULL` would silently orphan resources at the moment of deletion, which is the
//!   inventory step's whole reason for existing — the caller is meant to be *shown* what it is
//!   about to strand and made to resolve it.
//!
//! §6's pre-flight inventory is the referential-integrity mechanism, and it is necessarily
//! application-level because it is interactive. A database constraint would fire before the
//! inventory could refuse. SQLite also does not enforce foreign keys unless `PRAGMA foreign_keys`
//! is on, so a DDL constraint would have been decorative on the default backend regardless.

use sea_orm_migration::prelude::*;

/// The `api_keys` columns this migration touches.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The table itself.
    Table,
    /// The key that created this one. Lineage only — never authority (R3).
    ParentKeyId,
    /// The key answerable for this one. Reassignable by Master.
    OwnerKeyId,
}

/// The `hooks` columns this migration touches.
#[derive(DeriveIden)]
enum Hooks {
    /// The table itself.
    Table,
    /// The key answerable for this hook: the only non-Master identity that may delete or rename it.
    OwnerKeyId,
}

/// The lineage-and-ownership migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Adds one nullable UUID column to a table, as its own `ALTER TABLE`.
///
/// One statement per column because SQLite accepts exactly one alteration per statement — batching
/// them panics in `sea-query`'s SQLite backend rather than failing at the database — and it is the
/// only form portable across all three supported backends.
async fn add_key_reference<T, C>(
    manager: &SchemaManager<'_>,
    table: T,
    column: C,
) -> Result<(), DbErr>
where
    T: IntoIden + 'static,
    C: IntoIden + 'static,
{
    manager
        .alter_table(
            Table::alter()
                .table(table)
                .add_column(ColumnDef::new(column).uuid().null())
                .to_owned(),
        )
        .await
}

/// Creates one index, named so it is greppable against §7's list.
async fn create_index<T, C>(
    manager: &SchemaManager<'_>,
    name: &str,
    table: T,
    column: C,
) -> Result<(), DbErr>
where
    T: IntoIden + 'static,
    C: IntoIden + 'static,
{
    manager
        .create_index(Index::create().name(name).table(table).col(column).to_owned())
        .await
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        add_key_reference(manager, ApiKeys::Table, ApiKeys::ParentKeyId).await?;
        add_key_reference(manager, ApiKeys::Table, ApiKeys::OwnerKeyId).await?;
        add_key_reference(manager, Hooks::Table, Hooks::OwnerKeyId).await?;

        // §7 — "Indexes on `parent_key_id`, `owner_key_id`, ... every column the authenticated hot
        // paths search on." The subtree walk in §6 recurses on `parent_key_id` once per level, and
        // the inventory scans `hooks.owner_key_id` once per key in the subtree; both are
        // unindexed full scans without these.
        create_index(manager, "idx_api_keys_parent_key_id", ApiKeys::Table, ApiKeys::ParentKeyId)
            .await?;
        create_index(manager, "idx_api_keys_owner_key_id", ApiKeys::Table, ApiKeys::OwnerKeyId)
            .await?;
        create_index(manager, "idx_hooks_owner_key_id", Hooks::Table, Hooks::OwnerKeyId).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, table) in [
            ("idx_hooks_owner_key_id", Hooks::Table.into_iden()),
            ("idx_api_keys_owner_key_id", ApiKeys::Table.into_iden()),
            ("idx_api_keys_parent_key_id", ApiKeys::Table.into_iden()),
        ] {
            manager.drop_index(Index::drop().name(name).table(table).to_owned()).await?;
        }

        for (table, column) in [
            (Hooks::Table.into_iden(), Hooks::OwnerKeyId.into_iden()),
            (ApiKeys::Table.into_iden(), ApiKeys::OwnerKeyId.into_iden()),
            (ApiKeys::Table.into_iden(), ApiKeys::ParentKeyId.into_iden()),
        ] {
            manager
                .alter_table(Table::alter().table(table).drop_column(column).to_owned())
                .await?;
        }

        Ok(())
    }
}
