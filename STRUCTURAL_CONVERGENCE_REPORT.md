# Structural and Formal Convergence Report — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-11
**Method:** clean-room. Every table below is derived by enumerating the current source trees; no
previous convergence report was read or consulted.
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository. `RBAC_MODEL.md` is untouched.

| Subject | Path | Commit |
| :--- | :--- | :--- |
| **A — this service** | repository root | `edd79fd` |
| **B — peer** | `example/simply_ip_vault` | `c182a7a` (pulled this pass; docs-only change) |

**Framing.** This is a *formal* analysis: it asks whether the two services are built the same way,
not whether they do the same things. They deliberately do not do the same things — A executes local
processes, B manages IP blocklists and dispatches webhooks — so a difference is a **finding** only
when it has no domain justification. Each table classifies accordingly.

---

## 1. Repository hierarchy

| Path | A | B | Convergence |
| :--- | :---: | :---: | :--- |
| `src/` | ✅ | ✅ | ✅ |
| `src/api/` | 8 modules | 8 modules | ✅ Same count |
| `src/entities/` | 6 entities + `mod` + `prelude` | 6 entities + `mod` + `prelude` | ✅ Identical shape |
| `src/migration/` | 9 + `mod` | 10 + `mod` | ✅ Same pattern |
| `tests/` | 5 binaries + `common/mod.rs` | 6 binaries, no shared module | ⚠️ Fixture strategy differs (**S3**) |
| `scripts/` | `test_e2e.sh`, `verify_convergence.sh` | Same two names | ✅ |
| `static/` | `app.js`, `index.html`, `style.css` | Identical three | ✅ |
| `.github/workflows/` | `docker-publish.yml` | `docker-publish.yml` | ✅ |
| `.forgejo/workflows/` | `update-readme-each-month.yml` | `update-readme-each-month.yml` | ✅ |
| `example/<peer>` | ✅ a git clone with an `origin` remote | ❌ **absent** | ⚠️ Asymmetric (**S1**) |
| `Dockerfile`, `docker-compose.yml` | ✅ | ✅ | ✅ |
| Governance docs | `RBAC_MODEL.md`, `AGENT.MD`, `SCHEMA.MD`, `FILE_MAP.MD`, `AGENT_NOTES.MD`, `README.md` | Same six | ✅ Identical set |
| Both comparative reports | ✅ | ✅ | ✅ Both repositories carry both |

The hierarchy is identical but for `example/`. Only A vendors its peer, so only A can run drift
detection — the consequence is developed as **S1**.

---

## 2. Module structure and separation of concerns

### 2.1 Crate-root modules

| Module | A | B | Role | Class |
| :--- | :---: | :---: | :--- | :--- |
| `api` | ✅ | ✅ | HTTP surface | **Shared** |
| `config` | ✅ | ✅ | Runtime configuration and its validation | **Shared** |
| `crypto` | ✅ | ✅ | Canonicalization, HMAC, AEAD at rest | **Shared** |
| `db` | ✅ | ✅ | Connection, pragmas, migration entry point | **Shared** |
| `entities` | ✅ | ✅ | SeaORM models | **Shared** |
| `error` | ✅ | ✅ | `AppError` + `IntoResponse` | **Shared** |
| `master` | ✅ | ✅ | `MasterPin`, §5 identity | **Shared** |
| `middleware` | ✅ | ✅ | Auth, signature, replay, CIDR | **Shared** |
| `migration` | ✅ | ✅ | Schema evolution | **Shared** |
| `replay` | ✅ | ✅ | Single-use signature ledger | **Shared** |
| `retention` | ✅ | ✅ | Soft-delete purge worker | **Shared** |
| `state` | ✅ | ✅ | `AppState` | **Shared** |
| `executor` | ✅ | — | Spawns hook processes | Domain |
| `dispatch` | — | ✅ | Delivers webhook events | Domain |
| `extract` | — | ✅ | `StrictJson` / `OptionalStrictJson` | ⚠️ Placement (**S2**) |

**12 of 12 shared modules carry the same name and the same role.** `executor` and `dispatch` are each
side's side-effect engine — role-analogous, correctly named for what they actually do.

### 2.2 `src/api/` modules

| Module | A | B | Class |
| :--- | :---: | :---: | :--- |
| `audit.rs` | ✅ | ✅ | **Structural** — audit-log read endpoint |
| `guards.rs` | ✅ | ✅ | **Structural** — every RBAC decision, one file |
| `health.rs` | ✅ | ✅ | **Structural** — unauthenticated probes |
| `keys.rs` | ✅ | ✅ | **Structural** — credential lifecycle, §6 cascade |
| `support.rs` | ✅ | ✅ | **Structural** — shared helpers, audit writer |
| `hooks.rs`, `executions.rs`, `system.rs` | ✅ | — | Domain |
| `groups.rs`, `records.rs`, `webhooks.rs` | — | ✅ | Domain |

**5 of 5 structural modules match by name and responsibility, and each side carries exactly 3 domain
modules.** Both isolate every authorization decision in a single `guards.rs` — the single most
important structural property in either codebase, since it is what keeps one rule from being written
in three places.

### 2.3 Facade construction — the one genuine module-level divergence

| Aspect | A | B |
| :--- | :--- | :--- |
| Submodule visibility | `pub mod audit; pub mod guards; …` | `mod audit; mod guards; …` (**private**) |
| Re-export style | **Selective** — each handler named individually | **Glob** — `pub use audit::*;` per module |
| `guards` reachable from outside the crate | **Yes** | **No** |
| What it buys | Explicit about *what* leaves the module | Facade cannot be bypassed |
| What it costs | Facade is advisory; integration tests can reach guards directly | Whatever is `pub` leaves, whether intended or not |

Neither is strictly better; they are opposite halves of the same discipline. Tracked as **S4**.

### 2.4 Module sizes

| Module | A | B | Reading |
| :--- | ---: | ---: | :--- |
| `api/keys.rs` | 1274 | 1365 | ✅ The largest module on both sides — §6 and §4 live here |
| `api/guards.rs` | 932 | 457 | A gates 3 verbs plus execution history and privileged-hook rules; B gates a 4-verb group model |
| `api/support.rs` | 426 | 280 | A also hosts `StrictJson` (**S2**) |
| `api/health.rs` | 131 | 121 | ✅ Near-identical |
| `api/audit.rs` | 78 | 54 | ✅ |
| `api/mod.rs` | 95 | 69 | ✅ Both thin facades |
| `crypto.rs` | 781 | 839 | ✅ |
| `master.rs` | 291 | 320 | ✅ |
| `error.rs` | 140 | 107 | One extra variant on A |
| `middleware.rs` | 543 | 319 | A splits timestamp pre-validation into its own function |
| `state.rs` | 80 | 169 | B's `AppState` carries the webhook channel and trusted-proxy set |
| **`src/` total** | **10 734** | **9 314** | ✅ Same order of magnitude |

---

## 3. Naming conventions

### 3.1 Security functions

| Concern | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| **Guard prefix** | `guard_*` — **10 of 10** | `guard_*` — **6 of 6** | ✅ **Uniform on both** |
| R2 conjunction | `guard_hook_manage_conjunction` | `guard_group_manage` | ✅ Prefix matches, noun is the domain |
| §3 lifecycle | `guard_lifecycle_authority` | `guard_resource_lifecycle` | ⚠️ Transposed words (**S5**) |
| §4 pre-gate | `manages_any_hook` + `has_permission_admin_standing` | `holds_any_group_manage` | ⚠️ Same concept, different verb (**S5**) |
| R4 scope gate | `guard_master_to_grant_scopes` | `guard_scope_elevation` + `MASTER_ONLY_SCOPES` | ⚠️ Different naming axis; B's named constant is the better half |
| Master-target gate | `guard_master_to_administer` | `guard_master_target` | ⚠️ **S5** |
| Master immutability | `refuse_master_lifecycle_action`, `guard_master_self_edit_is_bound_ips_only` | `guard_master_immutable` | ⚠️ A splits one concept in two; B merges |
| R1 delegation | `guard_delegated_hook_grant` | `guard_delegated_group_grant` | ✅ Identical modulo the domain noun |
| R6 classifier | `is_permission_reduction` | `widens_permissions` | ⚠️ **Logical inverses.** Same behaviour, opposite polarity |
| Timestamp validation | `middleware::validate_timestamp` | `middleware::validate_timestamp` | ✅ |
| Client IP resolution | `resolve_client_ip` | `resolve_client_ip` | ✅ **Byte-identical body**, gate-enforced |
| Canonical payload | `canonical_v1_payload` | `canonical_v1_payload` | ✅ **Byte-identical body**, gate-enforced |
| Pragma application | `apply_sqlite_pragmas` | `apply_sqlite_pragmas` | ✅ **Byte-identical body**, gate-enforced |
| Audit writer | `create_audit_log` | `create_audit_log` | ✅ Same name, same argument order |
| Key hashing / minting | `hash_key`, `generate_random_key`, `generate_signing_secret` | Same three | ✅ |
| Subtree walk | `descendant_key_ids` | `collect_key_subtree` | ⚠️ **S5**; both cycle-safe |

**Every security-relevant function on both sides carries the `guard_` marker when it is a gate**, so
a reader who knows one codebase can locate the authorization decisions in the other by grep. The
remaining differences are synonym choice, with one exception worth calling out: `is_permission_reduction`
and `widens_permissions` are logical *inverses*, so the two files read as opposites while behaving
identically. Renaming either mechanically would invert branch conditions — the divergence is stable
and should be left alone rather than "fixed".

### 3.2 `MasterPin` — identical public API

| Symbol | A | B |
| :--- | :---: | :---: |
| `struct MasterPin` | ✅ | ✅ |
| `enum MasterPinError` | ✅ | ✅ |
| `new()` / `pinned_to()` / `get()` | ✅ | ✅ |
| `pin_at_boot()` / `resolve()` / `authenticate()` | ✅ | ✅ |

**8 of 8 symbols match by name and signature.** None of this is forced by a framework, which makes it
the strongest single piece of evidence for shared authorship in either tree.

### 3.3 Configuration constants

| Constant | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| `MAX_REQUEST_BODY_BYTES` | `3 * 1024 * 1024` | `3 * 1024 * 1024` | ✅ Gate-enforced |
| `SQLITE_BUSY_TIMEOUT_MS` | `5_000` | `5_000` | ✅ |
| `SQLITE_MAX_CONNECTIONS` | `1` | `1` | ✅ |
| `RETENTION_DAYS` | `92` | `92` | ✅ Gate-enforced |
| Master-key width | `INITIAL_MASTER_KEY_HEX_LEN = 64` | `MASTER_KEY_HEX_LEN = 64` | ⚠️ Same value, different name (**S6**) |
| Env-var name as a constant | Literal at the call site | `INITIAL_MASTER_KEY_ENV` | ⚠️ B's form is better |
| Validation error type | `InitialMasterKeyError` — 3 variants (`Empty`, `BadLength`, `NonHex`) | `InvalidInitialMasterKey { got, detail }` | ⚠️ **S6** |
| Validator signature | `fn(Option<&str>) -> Result<Option<String>, _>` | `fn(&str) -> Result<(), _>` | ⚠️ **S6** |
| Whitespace handling | Trimmed before validation | Not trimmed | ⚠️ Behavioural, both defensible |
| Set-but-empty | **Fatal** | Treated as unset | ⚠️ A stricter |

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
| Owner recorded for a Master creator | `Some(master.id)` — unconditional | `None` — `resource_owner()` refuses to record a master | ⚠️ Semantic divergence (**S7**) |
| §5 marker | `master_marker`, `GENERATED ALWAYS AS` | `master_marker`, `GENERATED ALWAYS AS` | ✅ Same column name, same expression |
| Audit FK behaviour | `on_delete = "SetNull"` | `on_delete = "SetNull"` | ✅ |
| Migration file convention | `mYYYYMMDD_NNNNNN_<slug>.rs` | `mYYYYMMDD_NNNNNN_<slug>.rs` | ✅ Same shape |
| Migration sequence semantics | Per-date reset (`m20230101_000001`, `m20230102_000001`, …) | Globally monotonic (`…_000001` … `…_000010`) | ⚠️ **S8** — B's order is readable from the filename alone |

### 3.5 Payload definitions

| Aspect | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Suffix convention | `…Payload` — 6 of 6 | `…Payload` — 9 of 9 | ✅ |
| Verb prefixes | `Create…` / `Update…` / `Delete…` | Same | ✅ |
| Key payload trio | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `DeleteApiKeyPayload` | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `DeleteKeyPayload` | ⚠️ B drops `Api` from one of three — the only asymmetric name in the set |
| §6 resolution type | `EntityResolution` enum, `#[serde(tag = "action")]` | `Resolution` enum, `#[serde(flatten)]` on the entry | ✅ Same wire contract |
| Strict extractor names | `StrictJson`, `OptionalStrictJson` | Identical | ✅ |
| Strict extractor location | `src/api/support.rs` | `src/extract.rs` | ⚠️ **S2** |
| `deny_unknown_fields` coverage | 3 of 3 key payloads | 2 of 3 | ⚠️ Security finding — see `SECURITY_COMPARISON_REPORT.md` **SIV-1** |

---

## 4. Error handling

### 4.1 `AppError` variants and status mapping

| Variant | A | B | Status | Default body | Convergence |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `DbError(#[from] DbErr)` | ✅ | ✅ | `500` | `"Internal database error"`, driver error logged only | ✅ |
| `InvalidInput(String)` | ✅ | ✅ | `400` | caller-supplied | ✅ |
| `Unauthorized(String)` | ✅ | ✅ | `401` | caller-supplied | ✅ |
| `Forbidden(String)` | ✅ | ✅ | `403` | caller-supplied | ✅ |
| `NotFound` | ✅ | ✅ | `404` | `"Resource not found"` | ✅ |
| `Conflict(String)` | ✅ | ✅ | `409` | caller-supplied | ✅ |
| `ConflictWithDetails { message, details }` | ✅ | ✅ | `409` | `error` + merged top-level fields | ✅ |
| `BodyRejected(StatusCode, String)` | ✅ | ✅ | passed through | caller-supplied | ✅ |
| `Internal` | ✅ | ✅ | `500` | `"An internal server error occurred"` | ✅ |
| `TooManyRequests(String)` | ✅ | — | `429` | — | Domain — only A spawns processes |

**9 of 9 shared variants map to identical status codes with byte-identical default messages.**

### 4.2 Response envelope

| Property | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Base shape | `{"error": "<message>"}` | Identical | ✅ |
| `ConflictWithDetails` merge depth | **Top level**, not nested | Top level | ✅ Same wire contract |
| Handled ahead of the flat match | Yes, with the same stated reason | Yes | ✅ |
| Match kept exhaustive despite the early return | Yes — no `_` arm on either side | Yes | ✅ Same discipline |
| Collision on the `error` key | **Skipped** — the envelope's message wins | **Overwritten** — `details.error` replaces it | ⚠️ **S9**, A stricter |
| Non-object `details` | Logged at `error!`; envelope stays well-formed | Silently dropped by the `if let` | ⚠️ **S9**, A louder |

`S9` is a robustness divergence, not a security one — no current call site on either side passes an
`error` key or a non-object `details`. It matters because it is precisely the kind of difference that
yields two different wire shapes from code that reads as the same.

### 4.3 Health and readiness contract

| Property | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Routes | `/health`, `/healthz`, `/ready`, `/readyz` | Same four | ✅ |
| Unauthenticated | ✅ | ✅ | ✅ |
| `health_check` takes no `State` | ✅ — compiler-enforced independence from the database | ✅ | ✅ |
| Liveness body | `{"status":"ok","service":"<crate>"}` — exactly two fields | Same shape | ✅ |
| Readiness DB probe | Typed SeaORM builder, bounded to one row | Typed, bounded | ✅ Neither uses raw SQL |
| Readiness checks the master pin | ✅ `503` when unpinned, `database: "up"` | ✅ | ✅ |
| Failure status | `503`, not `500` | `503` | ✅ |
| Driver error in the response body | Never — logged only | Never | ✅ |

---

## 5. Observability — audit trail

| Column | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| `id: Uuid` | ✅ | ✅ | ✅ |
| `api_key_id: Option<Uuid>` | ✅ | ✅ | ✅ Nullable by design — the FK is `SET NULL` |
| `api_key_name: String` | **NOT NULL** | **NOT NULL** | ✅ |
| `api_key_prefix: String` | **NOT NULL** | **NOT NULL** | ✅ |
| `client_ip: String` | **NOT NULL** | **NOT NULL** | ✅ |
| `action: String` | ✅ | ✅ | ✅ |
| `details: Option<String>` | ✅ | ✅ | ✅ |
| `timestamp: DateTime` | ✅ | ✅ | ✅ |
| Target reference | `target_resource: Option<String>` | `target_address` + `group_names` | Domain |

**8 of 8 non-domain columns match by name, type and nullability.** The writer signatures match too —
`create_audit_log(db, &api_key::Model, IpAddr, action, …, details)` — and both take the acting key
and the address **by value rather than as `Option`**, so an unattributed write is not merely refused
by the column but inexpressible in the type. That is the same design decision, reached on both sides.

| Action-name convention | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Format | `SCREAMING_SNAKE`, `<NOUN>_<VERB>` | Same | ✅ |
| Examples | `HOOK_CREATE`, `KEY_ROTATE`, `EXECUTION_DELETE` | `IP_ADD`, `GROUP_DELETE`, `WEBHOOK_CREATE` | ✅ |
| Shared credential actions | `KEY_CREATE`, `KEY_DELETE`, `KEY_PERM_UPDATE` | Identical spellings | ✅ |

---

## 6. Verification gates

| Gate | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Test suite | `cargo test` — **285 passed**, 8 binaries | 172 test attributes across 6 binaries | ✅ Both substantial |
| RBAC compliance suite | `rbac_model_compliance.rs` — 23 tests | `rbac_model_compliance.rs` — 18 tests | ✅ Same filename, same `rN_` / `sN_` prefix convention |
| Schema / referential integrity | `referential_integrity.rs` — 6 | `schema_integrity_tests.rs` — 16 | ✅ Same role, different filename |
| Health probes | `health_probes.rs` — 8 | Folded into broader suites | ⚠️ A isolates them |
| Source hygiene | `source_hygiene.rs` — 8 (frontend checks included) | `source_hygiene.rs` — 5 **+** `frontend_syntax_test.rs` — 3 | ⚠️ Same coverage, different partition |
| `no_handler_is_ever_exempted` | ❌ | ✅ | ⚠️ B stricter (**S10**) |
| `no_dml_keyword_is_hand_written…` | ❌ | ✅ | ⚠️ B stricter (**S10**) |
| Raw-SQL allowlist size | 2 entries, none in `src/api/` | 2 entries, none in `src/api/` | ✅ |
| E2E script | `test_e2e.sh` — 3710 lines | `test_e2e.sh` — 3027 lines | ✅ Same tool, same role |
| Convergence gate | 19 converged, 0 drifted — exit `0` | **`SKIP`** — exit `0`, nothing compared | ⚠️ **S1** |
| `oxc` pinned with `=` | ✅ | ✅ | ✅ Same reasoning recorded on both |
| **Any gate runs in CI** | ❌ | ❌ | ⚠️ Symmetric gap (**S11**) |

---

## 7. Open structural items

| # | Item | Side | Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | B's `verify_convergence.sh` points at `example/simply_hook_executor`, which does not exist in that clone. It prints `SKIP` and exits `0` | B | **High (process).** Drift is policed in one direction only; a divergence introduced on B's side passes B's own gate | Clone A into B's `example/`; make a missing peer a non-zero exit rather than a skip |
| **S2** | `StrictJson` lives in `src/api/support.rs` (A) vs `src/extract.rs` (B) | Both | Low — same names, same semantics | Prefer B's placement: an Axum extractor is a framework concern, not an API-support helper |
| **S3** | A shares fixtures via `tests/common/mod.rs`; B duplicates setup per binary | Both | Low | A's arrangement is the better one; recommend it to B |
| **S4** | `pub mod` + selective re-export (A) vs private `mod` + glob (B) | Both | Low | The ideal is the **intersection** — private `mod` so the facade cannot be bypassed, *plus* selective `pub use` so what leaves is explicit. Neither side has both |
| **S5** | Guard nouns diverge (`guard_lifecycle_authority`/`guard_resource_lifecycle`, `manages_any_hook`/`holds_any_group_manage`, `descendant_key_ids`/`collect_key_subtree`) | Both | Very low | Leave. The `guard_` marker carries the convention and is uniform |
| **S6** | Master-key validation: differing constant name, error type and function signature | Both | Low | Cosmetic, but this control was added independently on both sides — worth one coordinated pass. B's `INITIAL_MASTER_KEY_ENV` constant is the better half and is missing from A |
| **S7** | A records a Master creator as `owner_key_id`; B's `resource_owner()` returns `None` for a master ("a master is not a tenant") | Both | Low, no security impact | B's semantics are cleaner: unowned reads as Master-only anyway, and it keeps an administrative act from looking like a tenancy claim |
| **S8** | Migration sequence numbers reset per date (A) vs globally monotonic (B) | A | Low | Adopt B's numbering for new migrations. Renaming existing ones would rewrite applied migration names and is not worth it |
| **S9** | `ConflictWithDetails` merge: A refuses to let `details` overwrite `error` and logs a non-object `details`; B does neither | B | Low | Recommend B adopt A's merge — six lines longer, and it cannot produce a surprising wire shape |
| **S10** | B's `source_hygiene.rs` carries `no_handler_is_ever_exempted` and `no_dml_keyword_is_hand_written_outside_the_exceptions`; A has neither | A | **Medium** | **Adopt `no_handler_is_ever_exempted`.** It encodes the invariant A's raw-SQL allowlist is a proxy for; nothing currently stops a future `src/api/` exemption |
| **S11** | Neither CI pipeline runs `cargo test`, `test_e2e.sh` or `verify_convergence.sh` | Both | **Medium (process)** | Add one shared workflow. Both sides' gates already exit non-zero correctly; they are simply never invoked automatically |

---

## 8. Convergence scorecard

| Dimension | Measured | Score |
| :--- | :--- | :--- |
| Crate-root module names and roles | 12 of 12 shared modules match | **100%** |
| `api/` structural module names and roles | 5 of 5 match | **100%** |
| Domain module count | 3 each | **Symmetric** |
| `MasterPin` public API | 8 of 8 symbols | **100%** |
| Shared `api_key` columns | 11 of 11 | **100%** |
| Gate-enforced byte-identical functions | 3 of 3 | **100%** |
| Shared configuration constants | 4 of 4 by name and value; 1 of 2 master-key names | **89%** |
| Guard prefix uniformity | 10 of 10 (A), 6 of 6 (B) | **100%** |
| `AppError` variants → status codes | 9 of 9 shared, identical bodies | **100%** |
| Error-envelope shape | Identical; one merge-precedence difference | **~95%** |
| Audit-log non-domain columns | 8 of 8 by name, type and nullability | **100%** |
| Audit writer signature | Identical, both by-value | **100%** |
| Health/readiness contract | 8 of 8 properties | **100%** |
| Payload naming conventions | 15 of 15 follow `<Verb><Noun>Payload` | **100%** |
| Verification gates present and *effective* on both sides | 7 of 8 (**S1**: B's is inert) | **88%** |
| Repository hierarchy | Identical but for `example/` | **~95%** |

---

## 9. Executive verdict — structural convergence

| Dimension | Verdict |
| :--- | :--- |
| Shared foundational DNA | **Confirmed.** 12 of 12 shared crate-root modules and 5 of 5 structural `api/` modules match by name and role. Every difference in the module list is one side's domain engine |
| Separation of concerns | **Identical.** Both isolate all RBAC decisions in a single `api/guards.rs`, all schema evolution in `migration/`, all models in `entities/`, and both keep the two unauthenticated probes in their own `api/health.rs` with `health_check` taking no state |
| Naming standardization | **Converged.** Guard prefixes are uniform on both sides, `MasterPin` matches symbol-for-symbol, payload suffixes are universal, migration filenames share a shape. What remains is synonym choice under a shared marker — plus one stable inverse (`is_permission_reduction` / `widens_permissions`) that should not be "fixed" |
| Error handling | **Unified.** 9 of 9 shared variants, identical status codes, identical envelope, identical `ConflictWithDetails` merge depth — with one precedence difference (**S9**) |
| Observability | **Unified.** 8 of 8 non-domain audit columns match by name, type and nullability; the writer signature is identical and equally unfalsifiable on both sides |
| Divergences with no domain justification | **11**, all Low or Medium, none a behavioural defect. Most are naming or placement; the material ones are **S1**, **S10** and **S11** |

**Convergence level: HIGH — the two services are formally one codebase wearing two domains.** A
reader who knows either can navigate the other by structure alone: the guards are in the same file,
the errors carry the same names and produce the same bodies, the audit trail has the same columns
with the same nullability, the master identity exposes the same eight symbols, and three
security-critical functions are held byte-identical by a script.

Three items deserve action, and all three concern *keeping* this state rather than reaching it.
**S1** — B's convergence gate is inert, so drift is currently detected in one direction only; this is
the highest-value fix in the report, because everything above is a snapshot that only a working gate
keeps true. **S10** — A lacks B's `no_handler_is_ever_exempted` test, which encodes the rule A's
raw-SQL allowlist merely approximates. **S11** — neither CI pipeline runs any gate, so every figure
in this scorecard currently depends on a person remembering to run two scripts.
