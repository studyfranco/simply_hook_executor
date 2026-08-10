# Structural & Formal Convergence Report — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-10
**Mode:** strictly read-only. No source file in either repository was modified.
**Subject A:** `simply_hook_executor` @ `20f2695`
**Subject B:** `simply_ip_vault` — live checkout at `/home/fallrik/Documents/workspaces/simply_ip_vault`
**Companion document:** `SECURITY_COMPARISON_REPORT.md` (behavioural/security parity)

This report assesses **shared architectural DNA**: whether the two services are organised the same
way, name the same things the same way, and answer failures in the same shape. It deliberately does
not re-litigate security controls — those are in the companion document.

---

## 1. Module & file structure

### 1.1 Crate root — `src/*.rs`

| Module | `simply_hook_executor` | `simply_ip_vault` | Status |
| :--- | :--- | :--- | :--- |
| `lib.rs` | ✅ Router assembly, module registry, worker spawn | ✅ Same role | **Identical role** |
| `main.rs` | ✅ Migrate → bootstrap → pin → bind → shut down | ✅ Same sequence | **Identical role** |
| `state.rs` | ✅ `AppState` | ✅ `AppState` | **Identical** |
| `master.rs` | ✅ Boot-time Master pinning | ✅ Same | **Converged** — peer extracted this from `state.rs` after the prior audit |
| `middleware.rs` | ✅ Auth pipeline | ✅ Same | **Identical role** |
| `config.rs` | ✅ Env parsing, proxy trust, client-IP resolution | ✅ Same | **Identical role** |
| `crypto.rs` | ✅ HMAC signing + secrets-at-rest | ✅ Same | **Converged** — this service moved HMAC here to match |
| `db.rs` | ✅ Pool, pragmas, migrations | ✅ Same | **Converged** — peer extracted this from `state.rs` |
| `replay.rs` | ✅ Single-use signature enforcement | ✅ Same | **Identical role** |
| `retention.rs` | ✅ Background sweeps | ✅ Same | **Identical role** |
| `error.rs` | ✅ `AppError` → HTTP | ✅ Same | **Identical role** |
| `entities/` | ✅ SeaORM models, one file per table | ✅ Same | **Identical convention** |
| `migration/` | ✅ Ordered, append-only | ✅ Same | **Identical convention** |
| `extract.rs` | ❌ — folded into `api/support.rs` | ✅ Strict-JSON extractors | **Placement divergence** (§1.3) |
| `executor.rs` | ✅ Process spawn, argv, env isolation, killpg | ❌ | **Domain difference** |
| `dispatch.rs` / `webhooks.rs` | ❌ | ✅ Outbound HTTP dispatch | **Domain difference** |

**14 of 14 shared concerns occupy an identically-named file.** The only differences are the two
domain modules (this service runs local processes; the peer dispatches HTTP) and `extract.rs`.

### 1.2 API layer — `src/api/*.rs`

| Module | `simply_hook_executor` | `simply_ip_vault` | Status |
| :--- | :--- | :--- | :--- |
| `mod.rs` | ✅ Wiring + re-exports + policy constants | ✅ Same | **Identical role** |
| `guards.rs` | ✅ Cross-domain authorization, single module | ✅ Same, single module | **Identical** |
| `support.rs` | ✅ Shared plumbing, decides nothing | ✅ Same | **Converged** — peer extracted from `api/mod.rs` |
| `keys.rs` | ✅ Key CRUD, `/auth/me`, grants, §6 cascade | ✅ Same | **Identical role** |
| `audit.rs` | ✅ Audit-trail reads, master-only | ✅ Same | **Converged** — this service split it out to match |
| `health.rs` | ✅ Liveness/readiness, unauthenticated | ✅ Same | **Converged independently, same week** |
| `system.rs` | ✅ Effective config + counters | ❌ **Removed upstream** | **Divergence** (justified, §1.4) |
| Managed-resource module | `hooks.rs` | `groups.rs` | **Structural analogue** |
| Resource-data module | `executions.rs` | `records.rs` | **Structural analogue** |
| Creator-private module | — (executions carry it) | `webhooks.rs` | **Domain difference** |

**7 of 8 API modules exist on both sides under the same filename.**

### 1.3 The two placement divergences

| Concern | This service | Peer | Assessment |
| :--- | :--- | :--- | :--- |
| Strict-JSON extractors | `api/support.rs` (`StrictJson`, `OptionalStrictJson`) | `src/extract.rs` | **Cosmetic.** Same types, same behaviour, same rejection mapping. Neither placement is wrong: ours groups them with the other request plumbing, theirs promotes them to a crate-root concern |
| Module visibility in `api/mod.rs` | `pub mod` × 8 | `mod` × 8 (**private**, re-exported selectively) | **Peer is tighter.** Ours exposes every API submodule as crate-public API; theirs exposes only the handler re-exports. Ours is a consequence of the historical `src/api.rs` split, where preserving `crate::api::*` paths mattered |

### 1.4 `api/system.rs` — the one true structural divergence

The peer **deleted** `api/system.rs` and with it any settings endpoint. This service retains
`GET /api/settings` (master-only: effective configuration plus three counters).

| Aspect | Detail |
| :--- | :--- |
| Is this drift? | **No.** It is a deliberate product difference: this service's settings response reports `allowed_env_vars` and `allowed_script_roots`, which describe what a spawned hook process inherits. The peer spawns nothing, so its equivalent had little to report |
| Security posture | Both defensible. Ours is master-gated and discloses nothing to an unauthenticated caller; the peer's removal is pure surface reduction |
| Verdict | **Justified divergence.** No action |

---

## 2. Naming conventions

### 2.1 Where naming is already exact

| Concern | Both services use |
| :--- | :--- |
| Auth entry point | `auth_middleware` |
| Master pinning type | `MasterPin` |
| Master pinning API | `new`, `pinned_to`, `get`, `pin_at_boot`, `resolve`, `authenticate` — **all six, same order, same signatures** |
| Canonical signed string | `canonical_v1_payload` |
| Signature helpers | `compute_signature`, `verify_signature`, `generate_signing_secret`, `SIGNATURE_PREFIX` |
| Secrets at rest | `SecretCipher`, `CryptoError`, `seal`, `open`, `is_encrypting` |
| Pool setup | `connect`, `run_migrations`, `apply_sqlite_pragmas`, `SQLITE_BUSY_TIMEOUT_MS`, `SQLITE_MAX_CONNECTIONS` |
| Probes | `health_check`, `readiness_check` |
| Error type | `AppError` |
| Payload suffix | `…Payload` (`CreateApiKeyPayload`, `UpdateApiKeyPayload`) |
| Entity file convention | snake_case singular, one file per table, plus `mod.rs` + `prelude.rs` |
| Migration convention | `m<YYYYMMDD>_<NNNNNN>_<snake_case_description>.rs`, append-only |

`MasterPin`'s six-method surface being character-identical across two independently-written services
is the strongest single indicator of shared DNA in the ecosystem.

### 2.2 Where naming diverges

| Concept | `simply_hook_executor` | `simply_ip_vault` | Assessment |
| :--- | :--- | :--- | :--- |
| R2 conjunction | `require_hook_manage_conjunction` | `guard_group_manage` | Prefix + explicitness |
| §3 lifecycle | `require_lifecycle_authority` | `guard_resource_lifecycle` | Prefix |
| R4 scope elevation | `require_master_to_grant_scopes` | `guard_scope_elevation` | Prefix |
| Master immutability | `require_master_self_edit_is_bound_ips_only` | `guard_master_immutable` | Ours far more specific |
| Master as target | `refuse_master_lifecycle_action` | `guard_master_target` | Prefix |
| Delegation bound | `guard_delegated_hook_grant` | `guard_delegated_group_grant` | ✅ **Aligned** — differs only by domain noun |
| Any-manage standing | `manages_any_hook` | `holds_any_group_manage` | Shape aligned |
| Permission fetch | `hook_permission` | `caller_group_permission` | Shape aligned |
| Timestamp window | `verify_timestamp` | `validate_timestamp` | **Near-miss** — same job, one word apart |
| R6 classification | `is_permission_reduction` | `widens_permissions` | ⚠️ **Inverse polarity**, not a rename |

**Convention summary**

| Dimension | This service | Peer |
| :--- | :--- | :--- |
| Enforcing guard prefix | `require_*` | `guard_*` |
| Predicate prefix | `is_*` / verb (`manages_any_hook`) | verb (`holds_any_group_manage`) / `widens_*` |
| Domain noun in guard names | `hook` | `group` — **correct; these should differ** |

**Assessment.** The prefix split (`require_*` vs `guard_*`) is the ecosystem's one systematic naming
divergence. It is cosmetic — `scripts/verify_convergence.sh` compares behaviour, not identifiers —
and unifying it is **not recommended as a mechanical pass**, because one entry in the table is a trap:
`is_permission_reduction` and `widens_permissions` are logical inverses, so "renaming" one to the
other requires inverting every call site's branch. That is a correctness-risky edit to R6 enforcement
purchased with cosmetics. If the convention is ever unified, that pair must be handled as a semantic
change with its own tests, separately from the other nine.

---

## 3. Error handling & observability

### 3.1 HTTP error contract

| Property | `simply_hook_executor` | `simply_ip_vault` | Unified? |
| :--- | :--- | :--- | :--- |
| Error enum | `AppError` | `AppError` | ✅ |
| Response body | `{"error": "<message>"}` | `{"error": "<message>"}` | ✅ **Identical** |
| `InvalidInput` | `400` | `400` | ✅ |
| `Unauthorized` | `401` | `401` | ✅ |
| `Forbidden` | `403` | `403` | ✅ |
| `NotFound` | `404` + `"Resource not found"` | `404` + `"Resource not found"` | ✅ **Identical string** |
| `Conflict` | `409` | `409` | ✅ |
| `DbError` | `500` + `"Internal database error"` | `500` + `"Internal database error"` | ✅ **Identical string** |
| `Internal` | `500` + `"An internal server error occurred"` | `500` + same string | ✅ **Identical string** |
| `BodyRejected` | carries `(StatusCode, String)` — 400/413/422 preserved | Same shape | ✅ |
| `TooManyRequests` | `429` | ❌ absent | **Domain difference** — raised by `executor.rs` at `max_concurrent_jobs`; the peer spawns nothing |
| `ConflictWithDetails` | ❌ absent | `409` + extra fields merged into the body | **Divergence** — same §6 feature, different mechanism |

**§6 conflict payload — same semantics, different plumbing**

| | This service | Peer |
| :--- | :--- | :--- |
| Mechanism | `delete_api_key` returns `axum::response::Response` directly | `AppError::ConflictWithDetails { message, details }` |
| Wire result | `409` + structured inventory | `409` + structured inventory |
| Assessment | The peer's is the better factoring — it keeps the handler returning `Result<_, AppError>` and puts the shape in one place. **Recommended for adoption**, low risk, no wire change |

### 3.2 Audit logging structure — **not unified**

| Column | `simply_hook_executor` | `simply_ip_vault` | Match |
| :--- | :--- | :--- | :--- |
| `id` | `Uuid` | `Uuid` | ✅ |
| `api_key_id` | `Option<Uuid>` (FK `SET NULL`) | `Option<Uuid>` | ✅ |
| `api_key_name` | **`String` (NOT NULL)** | `Option<String>` | ❌ |
| `api_key_prefix` | **`String` (NOT NULL)** | `Option<String>` | ❌ |
| `client_ip` | **`String` (NOT NULL)** | `Option<String>` | ❌ |
| `action` | `String` | `String` | ✅ |
| Target column(s) | `target_resource: Option<String>` | `target_address: Option<String>` **+** `group_names: Option<String>` | ❌ name and arity |
| `details` | `Option<String>` | `Option<String>` | ✅ |
| `timestamp` | `DateTime` | `DateTime` | ✅ |

**Two substantive differences.**

1. **Nullability.** This service's denormalized attribution columns are `NOT NULL`; the peer's are
   nullable. The denormalized name/prefix exist precisely so the trail survives its key's deletion —
   a nullable column permits a row that has lost both the FK and the snapshot, which is an audit
   entry attributable to nobody. **This service is stronger; recommended for the peer.**
2. **Target shape.** `target_resource` (generic) versus `target_address` + `group_names`
   (domain-specific, two columns). Unifying would mean a migration on one side and a genuine loss of
   queryability on the peer's (`group_names` is separately filterable). **Justified divergence** —
   but it means an ecosystem-wide log pipeline cannot assume one schema.

### 3.3 Writer/reader split

| Aspect | This service | Peer | Unified? |
| :--- | :--- | :--- | :--- |
| Audit **writer** | `api/support.rs::create_audit_log` | `api/support.rs` equivalent | ✅ Same file role |
| Audit **reader** | `api/audit.rs::list_audit_logs` | `api/audit.rs::list_audit_logs` | ✅ Same file, same name |
| Reader access | Master-only, flat check | Master-only | ✅ |

### 3.4 Structured logging & gates

| Aspect | This service | Peer | Unified? |
| :--- | :--- | :--- | :--- |
| Log framework | `tracing` + `EnvFilter`, ANSI only on a TTY | Same | ✅ |
| Convergence harness | `scripts/verify_convergence.sh` | `scripts/verify_convergence.sh` | ✅ Both sides run one |
| E2E harness | `scripts/test_e2e.sh` | `scripts/test_e2e.sh` | ✅ |
| Frontend syntax gate | `tests/source_hygiene.rs` | `tests/frontend_syntax_test.rs` | Same purpose, different filename |
| RBAC compliance suite | `tests/rbac_model_compliance.rs` | `tests/rbac_model_compliance.rs` | ✅ **Identical filename** |
| Schema/integrity suite | `tests/referential_integrity.rs` | `tests/schema_integrity_tests.rs` | Same purpose, different filename |

---

## 4. Convergence scorecard

| Dimension | Score | Basis |
| :--- | :--- | :--- |
| Crate-root module structure | **14 / 14** shared concerns identically named | §1.1 |
| API-layer module structure | **7 / 8** modules identically named | §1.2 |
| Cross-cutting type/function names | **11 / 11** categories exact | §2.1 |
| Guard naming convention | **1 / 10** aligned (prefix split) | §2.2 |
| HTTP error contract | **10 / 10** shared variants identical, incl. message strings | §3.1 |
| Audit log schema | **6 / 9** columns match | §3.2 |
| Normative specification | **byte-identical** | companion report |

---

## 5. Outstanding items

| # | Item | Owner | Severity | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | Vendored peer snapshot at `example/simply_ip_vault` is stale — carries `src/api/system.rs` and `src/webhooks.rs`, both deleted upstream. It is what `verify_convergence.sh` reads | This service | **High (process)** | Re-sync with `rsync -a --delete`; make the gate fail on a `.rs` file unreachable from the peer's module tree. This staleness already produced two incorrect findings in a prior audit |
| **S2** | Audit attribution columns nullable | Peer | Medium | Tighten `api_key_name` / `api_key_prefix` / `client_ip` to `NOT NULL` |
| **S3** | `ConflictWithDetails` factoring | This service | Low | Adopt the peer's error variant for the §6 inventory |
| **S4** | `api/mod.rs` submodules crate-public | This service | Low | Consider `mod` + selective re-export, matching the peer |
| **S5** | Guard prefix convention (`require_*` / `guard_*`) | Both | Low | Unify only as a deliberate decision; **exclude** the `is_permission_reduction` / `widens_permissions` pair, which is a polarity inversion |
| **S6** | `verify_timestamp` / `validate_timestamp` | Both | Trivial | One-word rename if S5 is ever actioned |

---

## 6. Executive verdict

| Question | Verdict |
| :--- | :--- |
| Do the two services share the same foundational DNA? | **Yes, demonstrably.** Fourteen crate-root concerns and seven of eight API modules occupy identically-named files. `MasterPin` exposes a character-identical six-method API on both sides. The canonical signed string is byte-identical under gate enforcement |
| Is the separation of concerns the same? | **Yes.** Both isolate authorization into a single `api/guards.rs`; both keep a non-deciding `api/support.rs`; both keep entities one-file-per-table with `mod.rs` + `prelude.rs`; both keep migrations append-only under an identical filename grammar |
| Is convergence still moving? | **Yes, and bidirectionally.** In the last cycle the peer extracted `master.rs`, `db.rs` and `api/support.rs` toward this service's layout, while this service moved HMAC into `crypto.rs` and split out `api/audit.rs` toward theirs. Both added `api/health.rs` in the same week, independently, with identical handler names |
| Are error responses unified? | **Yes.** Every shared variant maps to the same status code, and the three fixed messages are string-identical. The two non-shared variants are a domain difference and a factoring difference, not drift |
| Is observability unified? | **No — this is the weakest axis.** The audit log schemas differ in three columns' nullability and in target-column naming and arity. Any ecosystem-wide log consumer must special-case per service |
| Overall maturity | **High.** Structure, naming of cross-cutting machinery, and the error contract are converged to a degree that is unusual for independently-developed services. The residue is one process defect (**S1**), one schema divergence worth closing (**S2**), and a cosmetic naming split (**S5**) that is safe to leave |

**Definitive verdict: the two codebases are architecturally convergent and share a common,
deliberately maintained DNA.** No structural divergence found in this pass is unjustified. The single
highest-value action is **S1** — not a code change, but a harness correction: the convergence gate is
currently reading a snapshot that has drifted from the peer it claims to track, which silently
degrades every comparison built on it.
