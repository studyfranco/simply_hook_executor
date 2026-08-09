//! API endpoints and business logic.
//!
//! Every handler here runs behind [`crate::middleware::auth_middleware`], so it can rely on an
//! authenticated [`crate::entities::api_key::Model`] and a resolved [`crate::middleware::ClientIp`]
//! being present in the request extensions. Authorization, by contrast, is per-handler and
//! explicit — see [`guards`].
//!
//! # Layout
//!
//! This was one 3,847-line file until the audit recorded in `AGENT_NOTES.MD`. The split is by
//! *domain*, with two modules that exist because the coupling measurement said they had to:
//!
//! | Module | Holds |
//! | :--- | :--- |
//! | [`support`] | Shared plumbing used by three or more handler domains, plus the strict JSON extractors. Decides nothing |
//! | [`guards`] | Every authorization decision. Writes nothing |
//! | [`keys`] | Key CRUD, `GET /api/auth/me`, per-hook grants, the §6 cascade |
//! | [`hooks`] | Hook definitions, parameter contracts, trash/restore/purge |
//! | [`executions`] | Triggering hooks, and reading the records that result |
//! | [`system`] | Audit log and settings — master-only introspection |
//!
//! **`guards` is one module rather than one per domain on purpose.** The rules in `RBAC_MODEL.md`
//! are cross-cutting: R2's conjunction governs hooks, parameters and execution records alike, and
//! §3's ownership test is consulted from three domains. Splitting guards by caller would put one
//! sentence of the specification in three files and invite the copies to drift — which is precisely
//! the failure the compliance suite exists to catch, so it should not be designed in.
//!
//! **`support` is not a junk drawer**, and the boundary is testable: nothing in it makes an
//! authorization decision or returns a refusal that depends on *who* is calling. A helper that
//! starts deciding belongs in [`guards`].
//!
//! # Re-exports
//!
//! Every handler is re-exported at this level, so `crate::api::create_hook` resolves exactly as it
//! did before the split and `src/lib.rs`'s router is untouched by it. That is deliberate: a
//! refactor that forces every call site to change is a refactor whose blast radius is impossible to
//! review.

pub mod executions;
pub mod guards;
pub mod hooks;
pub mod keys;
pub mod support;
pub mod system;

// ── Router-facing surface ────────────────────────────────────────────────────
//
// Grouped by module rather than alphabetically so a reader can see at a glance which domain owns
// which route. `src/lib.rs` refers to all of these unqualified as `api::name`.

pub use executions::{
    delete_execution, execute_hook_endpoint, get_execution, list_executions, purge_executions,
    test_hook, webhook_execute,
};
pub use hooks::{
    create_hook, create_hook_parameter, delete_hook, delete_hook_parameter, get_hook,
    list_hook_parameters, list_hooks, purge_deleted_hooks, restore_hook, update_hook,
    update_hook_parameter,
};
pub use keys::{
    create_api_key, delete_api_key, get_me, list_api_keys, revoke_key_hook_permission,
    rotate_api_key, update_api_key, update_key_hook_permissions,
};
pub use system::{get_settings, list_audit_logs};

// The credential primitives are public because the test suite mints keys directly against the
// database — `tests/common/mod.rs` hashes a plaintext exactly as the service would, which is the
// only way to seed a key whose secret the test already knows.
pub use support::{generate_key_id, generate_random_key, generate_signing_secret, hash_key};

// ── Shared constants ─────────────────────────────────────────────────────────
//
// Kept at the module root rather than in `support`: they are policy numbers rather than plumbing,
// and both the validators that enforce them and the handlers that document them read them.

/// Upper bound accepted for `hooks.default_timeout_seconds` (24 hours). A timeout beyond this is
/// almost certainly a units mistake, and accepting it would mean a wedged hook could hold one of
/// the caller's concurrency slots effectively forever.
pub(crate) const MAX_TIMEOUT_SECONDS: i32 = 86_400;

/// Upper bound accepted for `api_keys.max_concurrent_jobs`.
pub(crate) const MAX_CONCURRENT_JOBS: i32 = 1_000;

/// Default page size for the paginated listing endpoints.
pub(crate) const DEFAULT_PAGE_LIMIT: u64 = 50;
