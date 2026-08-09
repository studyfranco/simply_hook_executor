//! Adds `api_key_hook_permissions.can_view_execution` — the verb that decides who may read a hook's
//! execution history.
//!
//! # The gap this closes
//!
//! `RBAC_MODEL.md`'s Terminology table names the **Execution record** as this service's
//! *creator-private entity*, and §4 is unambiguous about what that means: such an entity is "visible
//! exclusively to their creator and Master" and is "never exposed by the shared-resource visibility
//! rule". Until now `list_executions` and `get_execution` gated on visibility of the *parent hook*,
//! so any key holding any verb on a hook could read every execution of it — including the stdout and
//! stderr of runs triggered by somebody else, with whatever those streams happened to contain.
//!
//! That is precisely the shared-resource rule leaking into a creator-private entity, and §4's
//! closing sentence about a shared resource never becoming "a keyhole into another parent's whole
//! configuration" applies with more force to output streams than to configuration.
//!
//! # Why a new verb rather than reusing `can_execute`
//!
//! Reading somebody else's execution output and being allowed to run the hook are different powers,
//! and the existing verbs cannot express the difference:
//!
//! - `can_execute` would mean every caller entitled to *run* a hook is also entitled to read what
//!   every other caller's runs printed. A CI key that fires a deployment would inherit the output of
//!   an operator's manual run of the same hook.
//! - `can_manage` would put history behind the R2 conjunction, so an auditor could only be given
//!   read access to logs by first being made a Parent with editing authority over the hook — the
//!   exact "grant more than was asked for" shape R1 exists to prevent.
//!
//! So history gets its own verb. A key may now hold `can_view_execution` alone: it sees the hook's
//! runs and can neither trigger nor alter it. That is the auditor role, and it was not previously
//! expressible.
//!
//! # Default `false`, and what that breaks
//!
//! Every existing row gets `false`. This is a **narrowing** backfill and it is deliberate: the
//! alternative — defaulting to `true` for rows that already carry `can_execute` — would encode the
//! very leak this migration exists to close, and would do it silently on upgrade. A key that
//! genuinely needs to read another key's history is granted the verb explicitly.
//!
//! Nothing is lost that §4 says should be visible. A caller still sees, without holding this verb:
//! its own executions (it is their creator), and every execution of a hook it owns. The verb is
//! needed only for the third case — reading runs that are neither yours nor on your own hook.
//!
//! # No index
//!
//! §7 requires indexes on "every column the authenticated hot paths search on". This column is never
//! searched on: the execution query filters by `hook_id` and `api_key_id`, and this flag is read
//! from a permission row already fetched by the existing `(api_key_id, hook_id)` unique index. A
//! boolean with two values and a heavy skew toward `false` is close to the worst possible index
//! candidate — it would cost writes and buy nothing.

use sea_orm_migration::prelude::*;

/// The permission-table identifiers this migration touches.
///
/// Re-declared locally rather than imported from the initial-schema migration so that module can
/// stay private; `DeriveIden` maps the variants to the same snake_case names, so they address the
/// same table and column.
#[derive(DeriveIden)]
enum ApiKeyHookPermissions {
    /// The `api_key_hook_permissions` table.
    Table,
    /// The new verb: may this key read this hook's execution records.
    CanViewExecution,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeyHookPermissions::Table)
                    // `NOT NULL DEFAULT false` rather than nullable: a NULL here would be a third
                    // state with no meaning, and every read site would have to decide what to do
                    // with it. The default is what makes this addable to a populated table without
                    // a separate backfill statement.
                    .add_column(
                        ColumnDef::new(ApiKeyHookPermissions::CanViewExecution)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeyHookPermissions::Table)
                    .drop_column(ApiKeyHookPermissions::CanViewExecution)
                    .to_owned(),
            )
            .await
    }
}
