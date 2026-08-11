# Structural and Formal Convergence Report — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-11
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository. `RBAC_MODEL.md` is untouched.
**Subject A (this repository):** `simply_hook_executor` @ `4865a82`
**Subject B (peer):** `simply_ip_vault` @ `6f1c4c7`, at `example/simply_ip_vault` — a live git clone,
pulled at the start of this pass (`Already up to date.`)

This edition replaces the 2026-08-10 report of `20f2695`, preserved at `7a7ffc7`. Its single unforced
divergence — mixed `require_*` / `guard_*` guard prefixes on this side — has since closed.

**Scope note.** This is a *formal* analysis: it asks whether the two services are built the same way,
not whether they do the same things. They deliberately do not do the same things — one executes
local processes, the other manages IP blocklists and dispatches webhooks — so a divergence is a
finding only when it has no domain justification.

---

## 1. Repository hierarchy

| Path | `simply_hook_executor` | `simply_ip_vault` | Convergence |
| :--- | :--- | :--- | :--- |
| `src/` | ✅ | ✅ | ✅ |
| `src/api/` | ✅ 8 modules | ✅ 8 modules | ✅ Same count, same role split |
| `src/entities/` | ✅ 6 entities + `mod` + `prelude` | ✅ 6 entities + `mod` + `prelude` | ✅ Identical shape |
| `src/migration/` | ✅ 9 migrations + `mod` | ✅ 10 migrations + `mod` | ✅ Same pattern |
| `tests/` | ✅ 5 binaries + `common/` | ✅ 6 binaries, no shared module | ⚠️ Fixture strategy differs (**S3**) |
| `scripts/` | `test_e2e.sh`, `verify_convergence.sh` | `test_e2e.sh`, `verify_convergence.sh` | ✅ Identical names and roles |
| `static/` | `app.js`, `index.html`, `style.css` | `app.js`, `index.html`, `style.css` | ✅ Identical |
| `.github/workflows/` | `docker-publish.yml` | `docker-publish.yml` | ✅ |
| `.forgejo/workflows/` | `update-readme-each-month.yml` | `update-readme-each-month.yml` | ✅ |
| `example/<peer>` | ✅ present, a git clone | ❌ **absent** | ⚠️ Asymmetric (**S1**) |
| `Dockerfile`, `docker-compose.yml` | ✅ | ✅ | ✅ |
| Normative + guidance docs | `RBAC_MODEL.md`, `AGENT.MD`, `SCHEMA.MD`, `FILE_MAP.MD`, `AGENT_NOTES.MD`, `README.md` | Same six | ✅ Identical document set |
| Both comparative reports | ✅ | ✅ | ✅ Both repositories carry both reports |

**Verdict:** the top-level hierarchy is identical bar one asymmetry — only this repository vendors the
peer, so only this repository can run drift detection (**S1**).

---

## 2. Module inventory and separation of concerns

### 2.1 Top-level modules (`src/*.rs`)

| Module | A | B | Role | Convergence |
| :--- | :---: | :---: | :--- | :--- |
| `api` | ✅ | ✅ | HTTP surface | ✅ |
| `config` | ✅ | ✅ | Runtime configuration + validation | ✅ |
| `crypto` | ✅ | ✅ | HMAC canonicalization, signing, AEAD at rest | ✅ |
| `db` | ✅ | ✅ | Connection, pragmas, migrations | ✅ |
| `entities` | ✅ | ✅ | SeaORM models | ✅ |
| `error` | ✅ | ✅ | `AppError` + `IntoResponse` | ✅ |
| `master` | ✅ | ✅ | `MasterPin`, §5 identity | ✅ |
| `middleware` | ✅ | ✅ | Auth, signature, replay, CIDR | ✅ |
| `migration` | ✅ | ✅ | Schema evolution | ✅ |
| `replay` | ✅ | ✅ | Single-use signature ledger | ✅ |
| `retention` | ✅ | ✅ | Soft-delete purge worker | ✅ |
| `state` | ✅ | ✅ | `AppState` | ✅ |
| `executor` | ✅ | — | Spawns hook processes | Domain-only |
| `dispatch` | — | ✅ | Delivers webhook events | Domain-only |
| `extract` | — | ✅ | `StrictJson` / `OptionalStrictJson` | ⚠️ Placement divergence (**S2**) |

**12 of 12 shared modules carry the same name and the same role.** `executor` and `dispatch` are the
domain-specific side-effect engine on each side — role-analogous, correctly named for what they
actually do, and not a convergence defect.

### 2.2 `src/api/` modules

| Module | A | B | Classification |
| :--- | :---: | :---: | :--- |
| `audit.rs` | ✅ | ✅ | **Structural** — audit-log read endpoint |
| `guards.rs` | ✅ | ✅ | **Structural** — all RBAC decisions, one file |
| `health.rs` | ✅ | ✅ | **Structural** — unauthenticated probes |
| `keys.rs` | ✅ | ✅ | **Structural** — credential lifecycle |
| `support.rs` | ✅ | ✅ | **Structural** — shared helpers, audit writer |
| `hooks.rs` / `executions.rs` / `system.rs` | ✅ | — | Domain |
| `groups.rs` / `records.rs` / `webhooks.rs` | — | ✅ | Domain |

**5 of 5 structural modules are identical in name and responsibility, and each side carries exactly
3 domain modules.** Both isolate every RBAC decision in a single `guards.rs` rather than distributing
authorization across handlers — the most important structural property in either codebase, and it
holds on both sides.

### 2.3 Facade style — the one real module-level divergence

| Aspect | `simply_hook_executor` | `simply_ip_vault` |
| :--- | :--- | :--- |
| Submodule visibility | `pub mod audit; pub mod guards; …` | `mod audit; mod guards; …` (**private**) |
| Re-export style | Selective — each handler named individually | Glob — `pub use audit::*;` per module |
| `guards` reachable from outside the crate | **Yes** | **No** |
| Consequence | Integration tests can call guards directly; the facade is advisory | Everything must go through the facade; the glob re-exports whatever is `pub` |

Neither is strictly better. This service is explicit about *what* leaves the module but permissive
about *who* can bypass the facade; the peer is the reverse. Tracked as **S4**.

### 2.4 Module sizes

| Module | A (lines) | B (lines) | Note |
| :--- | ---: | ---: | :--- |
| `api/keys.rs` | 1274 | 1365 | ✅ Comparable — the largest module on both sides |
| `api/guards.rs` | 932 | 457 | Ratio tracks verb count: 4 hook verbs + executions vs. a 4-verb group model |
| `api/support.rs` | 426 | 280 | This side also hosts `StrictJson` (**S2**) |
| `api/health.rs` | 131 | 121 | ✅ Near-identical |
| `api/audit.rs` | 78 | 54 | ✅ |
| `api/mod.rs` | 95 | 69 | ✅ Both are thin facades |
| `crypto.rs` | 781 | 839 | ✅ |
| `master.rs` | 291 | 320 | ✅ |
| `error.rs` | 140 | 107 | Difference is one extra variant and denser comments |
| `state.rs` | 80 | 169 | Peer's `AppState` carries the webhook channel and trusted-proxy set |
| `middleware.rs` | 543 | 319 | This side pre-validates the timestamp header separately |
| **`src/` total** | **10 734** | **9 314** | ✅ Same order of magnitude |

---

## 3. Naming conventions

### 3.1 Security functions

| Concern | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Guard prefix | `guard_*` — **10 of 10** | `guard_*` — **6 of 6** | ✅ **Converged.** The mixed `require_*` / `guard_*` split flagged in the previous report was unified in `4865a82` |
| R2 conjunction | `guard_hook_manage_conjunction` | `guard_group_manage` | ✅ Prefix matches; noun is the domain |
| §3 lifecycle | `guard_lifecycle_authority` | `guard_resource_lifecycle` | ⚠️ Same concept, transposed words (**S5**) |
| §4 pre-gate | `manages_any_hook` | `holds_any_group_manage` | ⚠️ Same concept, different verb (**S5**) |
| Escalation check | `is_permission_reduction` | `widens_permissions` | ⚠️ Logical inverses — deliberately **not** renamed, since a mechanical rename would invert branch conditions |
| Master-target guard | `guard_master_to_administer`, `guard_master_to_grant_scopes` | `guard_master_target`, `guard_scope_elevation` | ⚠️ Same pair of concepts, different naming axis |
| Delegated grant | `guard_delegated_hook_grant` | `guard_delegated_group_grant` | ✅ Identical modulo the domain noun |
| Timestamp validation | `middleware::validate_timestamp` | `middleware::validate_timestamp` | ✅ **Converged** in `4865a82` |
| Client IP resolution | `resolve_client_ip` | `resolve_client_ip` | ✅ Byte-identical body (gate-enforced) |
| Canonical payload | `canonical_v1_payload` | `canonical_v1_payload` | ✅ Byte-identical body (gate-enforced) |
| Pragma application | `apply_sqlite_pragmas` | `apply_sqlite_pragmas` | ✅ Byte-identical body (gate-enforced) |
| Audit writer | `create_audit_log` | `create_audit_log` | ✅ Same name, same argument order |
| Key hashing | `hash_key`, `generate_random_key` | `hash_key`, `generate_random_key` | ✅ |

**The guard-prefix divergence is closed. Every remaining naming difference is a synonym choice, not a
pattern difference** — both sides mark the same set of concepts with the same `guard_` marker, so a
reader who knows one codebase can find the authorization decisions in the other by grep.

### 3.2 `MasterPin` — identical public API

| Symbol | A | B |
| :--- | :---: | :---: |
| `struct MasterPin` | ✅ | ✅ |
| `enum MasterPinError` | ✅ | ✅ |
| `new` / `pinned_to` / `get` | ✅ | ✅ |
| `pin_at_boot` / `resolve` / `authenticate` | ✅ | ✅ |

**8 of 8 symbols match by name and signature** — the strongest single piece of evidence for shared
DNA in either codebase, since none of it is forced by a framework.

### 3.3 Configuration constants

| Constant | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| `MAX_REQUEST_BODY_BYTES` | `3 * 1024 * 1024` | `3 * 1024 * 1024` | ✅ Gate-enforced |
| `SQLITE_BUSY_TIMEOUT_MS` | `5_000` | `5_000` | ✅ |
| `SQLITE_MAX_CONNECTIONS` | `1` | `1` | ✅ |
| `RETENTION_DAYS` | `92` | `92` | ✅ Gate-enforced |
| Master key width | `INITIAL_MASTER_KEY_HEX_LEN = 64` | `MASTER_KEY_HEX_LEN = 64` | ⚠️ Same value, different name (**S6**) |
| Env var name constant | *(literal at the call site)* | `INITIAL_MASTER_KEY_ENV` | ⚠️ Peer's form is better |
| Validation error type | `InitialMasterKeyError` (3 variants) | `InvalidInitialMasterKey { got, detail }` | ⚠️ Divergent shape (**S6**) |

### 3.4 Database models

| Aspect | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| One file per table | ✅ | ✅ | ✅ |
| `prelude.rs` re-export module | ✅ | ✅ | ✅ |
| Table naming | `snake_case` plural — `api_keys`, `hooks`, `executions`, `audit_logs` | `api_keys`, `ip_groups`, `ip_records`, `audit_logs` | ✅ Same convention |
| Join table | `api_key_hook_permission` | `api_key_group_permission` | ✅ `api_key_<resource>_permission` on both |
| Shared `api_key` columns | `id`, `name`, `key_hash`, `prefix`, `signing_secret`, `bound_ips`, `is_master`, `can_manage_keys`, `parent_key_id`, `created_at`, `updated_at` | Identical set | ✅ **11 of 11** |
| Domain verb columns | `can_manage_hooks`, `max_concurrent_jobs`, `hmac_mode`, `key_id` | `can_manage_webhooks`, `can_create_groups` | Domain |
| §3 ownership column | `hooks.owner_key_id` | `ip_groups.owner_key_id`, `webhook_configs.owner_key_id` | ✅ Same name, same role |
| Audit FK behaviour | `on_delete = "SetNull"` | `on_delete = "SetNull"` | ✅ |
| Migration file convention | `mYYYYMMDD_NNNNNN_<slug>.rs` | `mYYYYMMDD_NNNNNN_<slug>.rs` | ✅ Same shape |
| Migration sequence semantics | Per-date reset (`m20230101_000001`, `m20230102_000001`, …) | Globally monotonic (`…_000001` … `…_000010`) | ⚠️ **S7** — the peer's ordering is self-evident from the filename; this side's requires reading the date |

### 3.5 Payload definitions

| Aspect | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Suffix convention | `…Payload` — 6 of 6 | `…Payload` — 9 of 9 | ✅ |
| Create/Update prefixes | `Create…` / `Update…` | `Create…` / `Update…` | ✅ |
| Key payload names | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `DeleteApiKeyPayload` | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `DeleteKeyPayload` | ⚠️ `Delete**Api**KeyPayload` vs `DeleteKeyPayload` — the only asymmetric name in the trio |
| Strict extractor names | `StrictJson`, `OptionalStrictJson` | `StrictJson`, `OptionalStrictJson` | ✅ Identical |
| Strict extractor location | `src/api/support.rs` | `src/extract.rs` | ⚠️ **S2** |
| `deny_unknown_fields` on key create/update | ✅✅ | ✅✅ | ✅ |
| `deny_unknown_fields` on key delete | ✅ | ❌ | ⚠️ Security finding — see `SECURITY_COMPARISON_REPORT.md` **D2** |

---

## 4. Error handling

### 4.1 `AppError` variants and status mapping

| Variant | A | B | HTTP status | Convergence |
| :--- | :---: | :---: | :--- | :--- |
| `DbError(#[from] DbErr)` | ✅ | ✅ | `500` — logged in full, reported as `"Internal database error"` | ✅ |
| `InvalidInput(String)` | ✅ | ✅ | `400` | ✅ |
| `Unauthorized(String)` | ✅ | ✅ | `401` | ✅ |
| `Forbidden(String)` | ✅ | ✅ | `403` | ✅ |
| `NotFound` | ✅ | ✅ | `404` — `"Resource not found"` | ✅ |
| `Conflict(String)` | ✅ | ✅ | `409` | ✅ |
| `ConflictWithDetails { message, details }` | ✅ | ✅ | `409` + merged top-level fields | ✅ **Converged** in `4865a82` |
| `BodyRejected(StatusCode, String)` | ✅ | ✅ | Passed through | ✅ |
| `Internal` | ✅ | ✅ | `500` — `"An internal server error occurred"` | ✅ |
| `TooManyRequests(String)` | ✅ | — | `429` | Domain — this service spawns processes |

**9 of 9 shared variants map to identical status codes with byte-identical default messages.**

### 4.2 Response envelope

| Property | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Base shape | `{"error": "<message>"}` | Identical | ✅ |
| `ConflictWithDetails` merge | Details merged at **top level**, not nested | Identical | ✅ |
| Handled before the flat match | Yes, with the same stated reason | Yes | ✅ |
| Match kept exhaustive despite early return | Yes — no `_` arm | Yes | ✅ Same discipline |
| Collision on the `error` key | **Skipped** — the envelope's message wins | **Overwritten** — `details.error` replaces the message | ⚠️ **S8**, this side stricter |
| Non-object `details` | Logged at `error!`, envelope stays well-formed | Silently dropped by the `if let` | ⚠️ **S8**, this side louder |

`S8` is a robustness divergence rather than a security one: no current call site passes an `error`
key or a non-object `details`. It matters because it is exactly the kind of difference that produces
two different wire shapes from what reads as the same code.

### 4.3 Health and readiness contract

| Property | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Routes | `/health`, `/healthz`, `/ready`, `/readyz` | Same four | ✅ |
| Unauthenticated | ✅ | ✅ | ✅ |
| `health_check` takes no `State` | ✅ — compiler-enforced independence from the DB | ✅ | ✅ |
| Liveness body | `{"status":"ok","service":"<crate>"}` — exactly two fields | Same shape | ✅ |
| Readiness DB probe | Typed SeaORM, bounded to one row | Typed SeaORM, bounded | ✅ **Converged** in `4865a82` |
| Readiness checks the master pin | ✅ | ✅ | ✅ **Converged** in `4865a82` |
| Failure status | `503`, not `500` | `503` | ✅ |
| Driver error in the body | Never — logged only | Never | ✅ |

---

## 5. Observability — audit trail structure

| Column | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| `id: Uuid` | ✅ | ✅ | ✅ |
| `api_key_id: Option<Uuid>` | ✅ | ✅ | ✅ Nullable on both, by design — the FK is `SET NULL` |
| `api_key_name: String` | ✅ **NOT NULL** | ✅ **NOT NULL** | ✅ **Converged** in the peer's `6f1c4c7` |
| `api_key_prefix: String` | ✅ **NOT NULL** | ✅ **NOT NULL** | ✅ Converged |
| `client_ip: String` | ✅ **NOT NULL** | ✅ **NOT NULL** | ✅ Converged |
| `action: String` | ✅ | ✅ | ✅ |
| `details: Option<String>` | ✅ | ✅ | ✅ |
| `timestamp: DateTime` | ✅ | ✅ | ✅ |
| Target reference | `target_resource: Option<String>` | `target_address: Option<String>` + `group_names: Option<String>` | Domain |

**8 of 8 non-domain columns now match in name, type and nullability.** The writer signatures match as
well — `create_audit_log(db, &api_key::Model, IpAddr, action, …, details)`, with the key and address
taken **by value on both sides**, so an unattributed write is not merely constrained at the database
but inexpressible in the type.

| Action-name convention | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Format | `SCREAMING_SNAKE`, `<NOUN>_<VERB>` | Same | ✅ |
| Examples | `HOOK_CREATE`, `KEY_ROTATE`, `KEY_PERM_UPDATE`, `EXECUTION_DELETE` | `IP_ADD`, `KEY_CREATE`, `GROUP_DELETE`, `WEBHOOK_CREATE`, `KEY_PERM_UPDATE` | ✅ |
| Shared credential actions | `KEY_CREATE`, `KEY_DELETE`, `KEY_PERM_UPDATE` | Identical spellings | ✅ |

---

## 6. Verification gates

| Gate | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Unit + integration suite | `cargo test` — **285 tests, 8 binaries** | `cargo test` — 172 test attributes across 6 binaries | ✅ Both substantial |
| RBAC compliance suite | `rbac_model_compliance.rs` — 23 tests | `rbac_model_compliance.rs` — 18 tests | ✅ Same filename, same `rN_` / `sN_` prefix convention |
| Schema / referential integrity | `referential_integrity.rs` — 6 tests | `schema_integrity_tests.rs` — 16 tests | ✅ Same role, different filename |
| Health probes | `health_probes.rs` — 8 tests | Folded into the peer's broader suites | ⚠️ This side isolates them |
| Source hygiene | `source_hygiene.rs` — 8 tests (incl. frontend checks) | `source_hygiene.rs` — 5 tests **+** `frontend_syntax_test.rs` — 3 | ⚠️ Same coverage, different partition |
| `no_handler_is_ever_exempted` | ❌ | ✅ | ⚠️ Peer stricter (**S9**) |
| `no_dml_keyword_is_hand_written…` | ❌ | ✅ | ⚠️ Peer stricter (**S9**) |
| Raw-SQL allowlist size | 2 entries | 2 entries | ✅ |
| E2E script | `test_e2e.sh` — 3710 lines, 893 checks | `test_e2e.sh` — 3027 lines | ✅ Same tool, same role |
| Convergence gate | `verify_convergence.sh` — **19 converged, 0 drifted**, exit `0` | `verify_convergence.sh` — **`SKIP`**, exit `0`, nothing compared | ⚠️ **S1** — inert on the peer side |
| Frontend parser pin | `oxc` pinned with `=` | `oxc` pinned with `=` | ✅ Same reasoning recorded on both |
| CI runs any of the above | ❌ | ❌ | ⚠️ Symmetric gap |

---

## 7. Open structural items

| # | Item | Side | Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | Peer's convergence gate points at a non-existent `example/simply_hook_executor` and exits `0` after printing `SKIP` | Peer | **High (process).** Convergence is policed from one direction only; a divergence introduced on the peer's side passes its own gate | Clone this service into the peer's `example/`, and make a missing peer a non-zero exit rather than a skip |
| **S2** | `StrictJson` lives in `src/api/support.rs` here and `src/extract.rs` there | Both | Low. Same names, same semantics, different address | Prefer the peer's `src/extract.rs`: an Axum extractor is a framework concern, not an API-support helper, and the split keeps `support.rs` to domain helpers |
| **S3** | This repo shares fixtures via `tests/common/mod.rs`; the peer duplicates setup per binary | Both | Low | This side's arrangement is the better one; recommend it to the peer |
| **S4** | `pub mod` + selective re-export here vs. private `mod` + glob re-export there | Both | Low. Neither is unsafe | Ideal is the **intersection**: private `mod` (so the facade cannot be bypassed) **plus** selective `pub use` (so what leaves is explicit). Neither side has both |
| **S5** | Guard nouns diverge — `guard_lifecycle_authority` / `guard_resource_lifecycle`, `manages_any_hook` / `holds_any_group_manage` | Both | Very low | Leave. The `guard_` marker is what carries the convention, and it is uniform |
| **S6** | `INITIAL_MASTER_KEY_HEX_LEN` / `MASTER_KEY_HEX_LEN`; `InitialMasterKeyError` / `InvalidInitialMasterKey`; differing validator signatures | Both | Low | Cosmetic, but this is a control both sides added independently in the same week — worth one coordinated naming pass. The peer's `INITIAL_MASTER_KEY_ENV` constant is the better half and is missing here |
| **S7** | Migration sequence numbers reset per date here, run monotonically there | This repo | Low | Adopt the peer's monotonic numbering for new migrations; renaming existing ones would rewrite applied migration names and is not worth it |
| **S8** | `ConflictWithDetails` merge: this side refuses to let `details` overwrite `error` and logs a non-object `details`; the peer does neither | Peer | Low | Recommend the peer adopt this side's merge, which is 6 lines longer and cannot produce a surprising wire shape |
| **S9** | Peer's `source_hygiene.rs` carries `no_handler_is_ever_exempted` and `no_dml_keyword_is_hand_written_outside_the_exceptions`; this repo has neither | This repo | Medium | **Adopt `no_handler_is_ever_exempted`.** This repo removed its only `src/api/` raw-SQL exemption in `4865a82`; nothing currently prevents the next one |
| **S10** | Neither CI pipeline runs `cargo test`, `test_e2e.sh` or `verify_convergence.sh` | Both | Medium (process) | Add a shared CI job. The gates already exist and already exit non-zero correctly; they are simply never invoked automatically |

---

## 8. Convergence scorecard

| Dimension | Measured | Score |
| :--- | :--- | :--- |
| Top-level module names and roles | 12 of 12 shared modules match | **100%** |
| `api/` structural module names and roles | 5 of 5 match | **100%** |
| Domain module count | 3 each | **Symmetric** |
| `MasterPin` public API | 8 of 8 symbols | **100%** |
| Shared `api_key` columns | 11 of 11 | **100%** |
| Gate-enforced byte-identical functions | 3 of 3 (`resolve_client_ip`, `canonical_v1_payload`, `apply_sqlite_pragmas`) | **100%** |
| Shared configuration constants | 4 of 4 by name and value; 1 of 2 master-key names | **89%** |
| Guard prefix uniformity | 10 of 10 here, 6 of 6 there | **100%** |
| `AppError` variants → status codes | 9 of 9 shared variants, identical bodies | **100%** |
| Error-envelope shape | Identical; one merge-precedence difference | **~95%** |
| Audit-log non-domain columns | 8 of 8 by name, type and nullability | **100%** |
| Audit writer signature | Identical, both by-value | **100%** |
| Health/readiness contract | 8 of 8 properties | **100%** |
| Verification gates present on both sides | 7 of 8 (**S1**: the peer's is inert) | **88%** |
| Repository hierarchy | Identical bar `example/` | **~95%** |

---

## 9. Executive verdict — structural convergence

| Dimension | Verdict |
| :--- | :--- |
| Shared foundational DNA | **Confirmed.** 12 of 12 shared top-level modules and 5 of 5 structural `api/` modules match by name and role; every difference in the module list is one side's domain engine |
| Separation of concerns | **Identical.** Both isolate all RBAC decisions in a single `api/guards.rs`, all schema evolution in `migration/`, all models in `entities/`, and both keep the two unauthenticated probes in their own `api/health.rs` |
| Naming standardization | **Converged.** The one unforced divergence in the previous report — mixed `require_*` / `guard_*` prefixes here — was closed in `4865a82`. What remains is synonym choice, uniform under a shared marker |
| Error handling | **Unified.** 9 of 9 shared variants, identical status codes, identical envelope, identical `ConflictWithDetails` merge strategy — with one precedence difference (**S8**) |
| Observability | **Unified.** 8 of 8 non-domain audit columns match by name, type and nullability; the writer signature is identical and equally strict on both sides |
| Divergences with no domain justification | **10**, all Low or Medium, none a defect in behaviour. Half are naming or placement; the material ones are **S1**, **S9** and **S10** |
| Regressions since the previous report | **None** |

**Convergence level: HIGH — the two services are formally the same codebase wearing two domains.**
A reader who knows one can navigate the other by structure alone: the guards are in the same file,
the errors have the same names and produce the same bodies, the audit trail has the same columns, the
master identity has the same eight-symbol API, and three security-critical functions are enforced
byte-identical by a script.

Three items are worth acting on, and all three are about *keeping* this state rather than reaching
it. **S1**: the peer's convergence gate is inert, so drift is currently detected in one direction
only — this is the highest-value fix in the report, because everything above is a snapshot that only
a working gate keeps true. **S9**: this repository lacks the peer's `no_handler_is_ever_exempted`
test, which encodes the rule its raw-SQL allowlist is a proxy for. **S10**: neither CI pipeline runs
any of the gates, so every guarantee in this document currently depends on a human remembering to
run two scripts.
