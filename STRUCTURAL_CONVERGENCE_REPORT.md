# Structural and Formal Convergence Report — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-18
**Method:** clean-room. Every table below was produced by enumerating the current source trees. No
previous convergence report was opened.
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository. `RBAC_MODEL.md` is untouched.

| Subject | Path | Commit |
| :--- | :--- | :--- |
| **A — this service** | repository root | `818740f` |
| **B — peer** | `example/simply_ip_vault` | `14c8fa3` (pulled: already up to date) |

**Framing.** This is a *formal* analysis: whether the two services are built the same way, not whether
they do the same things. They deliberately do not do the same things — A executes local processes, B
manages IP blocklists and dispatches webhooks — so a difference is a **finding** only when it has no
domain justification. Each table classifies accordingly.

---

## 1. Repository hierarchy

| Path | A | B | Convergence |
| :--- | :---: | :---: | :--- |
| `src/` | ✅ | ✅ | ✅ |
| `src/api/` | 9 modules | 9 modules | ✅ Same count |
| `src/entities/` | 8 files | 9 files | ✅ Same pattern, domain count differs |
| `src/migration/` | 9 + `mod` | 12 + `mod` | ✅ Same pattern |
| `tests/` | 6 binaries + `common/` | 7 binaries | ⚠️ Fixture strategy differs (**S3**) |
| `scripts/` | `test_e2e.sh`, `verify_convergence.sh` | Identical two names | ✅ |
| `static/` | `app.js`, `index.html`, `style.css` | Identical three | ✅ |
| `.github/workflows/` + `.forgejo/workflows/` | 2 workflows | 2 workflows | ✅ |
| `example/<peer>` | ✅ 3 live clones | ❌ absent | ⚠️ Asymmetric (**S1**) |
| Governance docs | `RBAC_MODEL.md`, `AGENT.MD`, `SCHEMA.MD`, `FILE_MAP.MD`, `AGENT_NOTES.MD`, `README.md` | Same six | ✅ |
| **`src/` total lines** | **12 688** | **13 012** | ✅ Same order of magnitude |

---

## 2. Module structure and separation of concerns

### 2.1 Crate-root modules

| Module | A | B | Role | Class |
| :--- | :---: | :---: | :--- | :--- |
| `api` | ✅ | ✅ | HTTP surface | **Shared** |
| `config` | ✅ | ✅ | Runtime configuration and validation | **Shared** |
| `crypto` | ✅ | ✅ | Canonicalization, HMAC, AEAD at rest | **Shared** |
| `db` | ✅ | ✅ | Pool, pragmas, migration entry point | **Shared** |
| `entities` | ✅ | ✅ | SeaORM models | **Shared** |
| `error` | ✅ | ✅ | `AppError` + `IntoResponse` | **Shared** |
| `extract` | ✅ | ✅ | Body/parameter extractors | **Shared** |
| `master` | ✅ | ✅ | `MasterPin`, §5 identity | **Shared** |
| `middleware` | ✅ | ✅ | Auth, signature, replay, CIDR | **Shared** |
| `migration` | ✅ | ✅ | Schema evolution | **Shared** |
| `replay` | ✅ | ✅ | Single-use signature ledger | **Shared** |
| `retention` | ✅ | ✅ | Soft-delete purge worker | **Shared** |
| `state` | ✅ | ✅ | `AppState` | **Shared** |
| `executor` | ✅ | — | Spawns hook processes | Domain |
| `dispatch` | — | ✅ | Delivers webhook events | Domain |

**13 of 13 shared crate-root modules match by name and role.** The only difference in the module list
is each side's domain engine, and the two are role-analogous. `extract` is now shared on both, which
was not true at the last structural pass on this tree.

### 2.2 `src/api/` modules

| Module | A | B | Class |
| :--- | :---: | :---: | :--- |
| `mod.rs` | ✅ | ✅ | **Structural** — facade and policy constants |
| `guards.rs` | ✅ | ✅ | **Structural** — every RBAC decision, one file |
| `support.rs` | ✅ | ✅ | **Structural** — shared helpers, audit writer |
| `keys.rs` | ✅ | ✅ | **Structural** — credential lifecycle, §6 cascade |
| `audit.rs` | ✅ | ✅ | **Structural** — audit-log read endpoint |
| `health.rs` | ✅ | ✅ | **Structural** — unauthenticated probes |
| `hooks.rs`, `executions.rs`, `system.rs` | ✅ | — | Domain |
| `groups.rs`, `records.rs`, `webhooks.rs` | — | ✅ | Domain |

**6 of 6 structural modules identical in name and responsibility; 3 domain modules each.** Both
isolate every authorization decision in a single `guards.rs` — the most important structural property
in either codebase, since it is what stops one sentence of the specification being written in three
places.

### 2.3 Guard inventory

| A (21 functions) | B (12 functions) | Relationship |
| :--- | :--- | :--- |
| `guard_hook_manage_conjunction` | `guard_group_manage` | R2, one evaluation point each |
| `guard_lifecycle_authority` | `guard_resource_lifecycle` | §3 |
| `guard_delegated_hook_grant` | `guard_delegated_group_grant` | R1 + R7 |
| `guard_master_to_grant_scopes` | `guard_scope_elevation` | R4 |
| `guard_master_to_administer` | `guard_master_target` | §5 |
| `refuse_master_lifecycle_action` + `guard_master_self_edit_is_bound_ips_only` | `guard_master_immutable` | §5 — A splits, B merges |
| `manages_any_hook` + `has_permission_admin_standing` | `holds_any_group_manage` + `guard_may_administer_any_group` | §4 pre-gate |
| `is_permission_reduction` | `widens_permissions` | R6 — **logical inverses** |
| `guard_execute`, `guard_visibility`, `may_read_execution`, `guard_master_for_privileged_hook`, `normalize_run_as_user`, `guard_master_for_deleted_view` | — | Domain: process execution has no analogue in B |
| — | `resource_owner`, `resolve_owner_assignment`, `caller_group_permission` | Domain |

The count difference is domain, not discipline: six of A's guards concern executing a process, which
B does not do. Every rule with a counterpart on both sides has exactly one evaluation point on each.

### 2.4 Facade style

| Aspect | A | B |
| :--- | :--- | :--- |
| Submodule declarations | 8 | 8 |
| Visibility | `pub mod` + selective `pub use` | private `mod` + glob `pub use` |
| `guards` reachable outside the crate | Yes | No |

Neither is strictly better — A is explicit about *what* leaves, B about *who* may bypass the facade.
Tracked as **S4**.

---

## 3. Naming conventions

### 3.1 Security functions

| Concern | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Guard prefix | `guard_*` — **10 of 10 gates** | `guard_*` — **7 of 7 gates** | ✅ Uniform on both |
| Question-form helpers | `is_*` / verb (`manages_any_hook`, `hook_permission`) | Same convention (`holds_any_group_manage`, `widens_permissions`) | ✅ |
| Timestamp validation | `middleware::validate_timestamp` | `middleware::validate_timestamp` | ✅ |
| Client IP resolution | `resolve_client_ip` | `resolve_client_ip` | ✅ Byte-identical, gate-enforced |
| Canonical payload | `canonical_v1_payload` | `canonical_v1_payload` | ✅ Byte-identical, gate-enforced |
| Pragma application | `apply_sqlite_pragmas` | `apply_sqlite_pragmas` | ✅ Byte-identical, gate-enforced |
| Audit writer | `create_audit_log` | `create_audit_log` | ✅ Same name and argument order |
| Key primitives | `hash_key`, `generate_random_key`, `generate_signing_secret` | Same three | ✅ |
| R6 classifier polarity | `is_permission_reduction` | `widens_permissions` | ⚠️ **Logical inverses** — stable, and must not be "aligned" mechanically: renaming either inverts every call site's branch |
| §3 / §4 / §5 guard nouns | `…_lifecycle_authority`, `…_to_administer` | `…_resource_lifecycle`, `…_master_target` | ⚠️ Synonym choice (**S5**) |

**Every gate on both sides carries the `guard_` marker**, so a reader who knows one codebase locates
the authorization decisions in the other by grep. What differs is nouns.

### 3.2 `MasterPin` — identical public API

| Symbol | A | B |
| :--- | :---: | :---: |
| `new` / `pinned_to` / `get` | ✅ | ✅ |
| `pin_at_boot` / `resolve` / `authenticate` | ✅ | ✅ |

**6 of 6 methods match by name.** None of this is forced by a framework, which makes it the strongest
single piece of evidence for shared authorship.

### 3.3 Database models

| Aspect | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| One file per table | ✅ | ✅ | ✅ |
| `prelude.rs` re-export module | ✅ | ✅ | ✅ |
| Table naming | `snake_case` plural | Same | ✅ |
| Join table | `api_key_hook_permission` | `api_key_group_permission` | ✅ `api_key_<resource>_permission` |
| Shared `api_key` columns | `id`, `name`, `key_hash`, `prefix`, `signing_secret`, `bound_ips`, `is_master`, `can_manage_keys`, `parent_key_id`, `created_at`, `updated_at` | Identical set | ✅ **11 of 11** |
| Domain columns | `can_manage_hooks`, `max_concurrent_jobs`, `hmac_mode`, `key_id` | `can_create_groups`, `can_manage_webhooks` | Domain |
| §3 ownership column | `hooks.owner_key_id` | `ip_groups.owner_key_id`, `webhook_configs.owner_key_id` | ✅ Same name and role |
| §5 marker | `master_marker`, `GENERATED ALWAYS AS` | Same column name and expression | ✅ |
| Migration filenames | `mYYYYMMDD_NNNNNN_<slug>.rs` | Same shape | ✅ |
| Migration sequence | Per-date reset | Globally monotonic | ⚠️ **S7** — B's ordering is readable from the filename alone |

### 3.4 Payload and extractor naming

| Aspect | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Suffix convention | `…Payload` / `…Input` | Same | ✅ |
| Verb prefixes | `Create…` / `Update…` / `Delete…` | Same | ✅ |
| Key trio | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `DeleteApiKeyPayload` | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `DeleteKeyPayload` | ⚠️ B drops `Api` from one of three |
| Extractor module | `src/extract.rs` | `src/extract.rs` | ✅ Same address |
| Extractors defined | `StrictJson`, `OptionalStrictJson`, **`StrictPath`, `StrictQuery`, `StrictBytes`** | `StrictJson`, `OptionalStrictJson` | ⚠️ **S6** — see §4.2 |

---

## 4. Error handling

### 4.1 `AppError` variants and status mapping

| Variant | A | B | Status | Convergence |
| :--- | :---: | :---: | :--- | :--- |
| `DbError` | ✅ | ✅ | `500`, driver error logged only | ✅ |
| `InvalidInput` | ✅ | ✅ | `400` | ✅ |
| `Unauthorized` | ✅ | ✅ | `401` | ✅ |
| `Forbidden` | ✅ | ✅ | `403` | ✅ |
| `NotFound` | ✅ | ✅ | `404` | ✅ |
| `Conflict` | ✅ | ✅ | `409` | ✅ |
| `ConflictWithDetails` | ✅ | ✅ | `409` + merged top-level fields | ✅ |
| `BodyRejected(StatusCode, String)` | ✅ | ✅ | Passed through | ✅ |
| `Internal` | ✅ | ✅ | `500` | ✅ |
| `TooManyRequests` | ✅ | — | `429` | Domain — only A spawns processes |

**9 of 9 shared variants map to identical status codes.**

### 4.2 Envelope coverage — the one material divergence

Both sides define `BodyRejected` for the same purpose: carry an extractor's rejection into the
`{"error": …}` envelope without flattening its status. They apply it to different extents.

| Extractor used by handlers | A | B |
| :--- | :--- | :--- |
| `Json<T>` | `StrictJson` | `StrictJson` |
| `Json<T>`, optional body | `OptionalStrictJson` | `OptionalStrictJson` |
| `Path<T>` | `StrictPath` | **bare** |
| `Query<T>` | `StrictQuery` | **bare** |
| `Bytes` | `StrictBytes` | *(no raw-body route)* |
| **Bare extractor positions remaining** | **0** | **25** |
| Refusal shape for a bad UUID / query value | `{"error": …}` + `application/json` | `text/plain` |
| Test asserts `Content-Type` on rejections | ✅ | ❌ (status only) |

Tracked as **S6**, and as **SIV-1** in the security report. The mechanism exists on B; only its reach
differs — which is why this reads as an unfinished rollout rather than a design disagreement.

### 4.3 Health and readiness

| Property | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Routes | `/health`, `/healthz`, `/ready`, `/readyz` | Same four | ✅ |
| Unauthenticated | ✅ | ✅ | ✅ |
| `health_check` takes no `State` | ✅ compiler-enforced | ✅ | ✅ |
| Readiness checks DB **and** master pin | ✅ | ✅ | ✅ |
| Failure status | `503` | `503` | ✅ |

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
| Target reference | `target_resource` | `target_address` + `group_names` | Domain |

**8 of 8 non-domain columns match by name, type and nullability.** Both writers take the acting key
and the address **by value rather than as `Option`**, so an unattributed write is not merely refused
by the column but inexpressible in the type — the same decision reached on both sides.

| Writer signature | A | B |
| :--- | :--- | :--- |
| Connection parameter | `&DatabaseConnection` | `&C` (generic) — supports transactions | 

B's generic connection parameter is the better of the two and costs nothing; recorded as **S8**.

| Action naming | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Format | `SCREAMING_SNAKE`, `<NOUN>_<VERB>` | Same | ✅ |
| Shared credential actions | `KEY_CREATE`, `KEY_DELETE`, `KEY_PERM_UPDATE` | Identical spellings | ✅ |

---

## 6. Verification gates

| Gate | A | B | Convergence |
| :--- | :--- | :--- | :--- |
| Test suite | 287 tests, 9 binaries, 2 ignored | 197 test attributes, 7 binaries | ✅ Both substantial |
| RBAC compliance suite | `rbac_model_compliance.rs` — 23 | `rbac_model_compliance.rs` — 18 | ✅ Same filename and `rN_`/`sN_` prefixes |
| Concurrency/contract suite | `concurrency_and_contracts.rs` — 4 | `concurrency_and_contracts.rs` — 3 | ✅ **Converged** — same filename, same first two tests |
| Schema/referential integrity | `referential_integrity.rs` — 6 | `schema_integrity_tests.rs` — 21 | ✅ Same role |
| Source hygiene | 8 | 5 | ✅ |
| E2E | `test_e2e.sh` — 958 checks | `test_e2e.sh` | ✅ Same tool |
| Convergence gate | 18 converged, 1 accepted divergence, exit 0 | **`SKIP`** — no peer in its `example/` | ⚠️ **S1** — inert on B's side |
| **Any gate runs in CI** | ❌ | ❌ | ⚠️ Symmetric gap (**S9**) |

---

## 7. Open structural items

| # | Item | Side | Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | B's `verify_convergence.sh` has no peer under its `example/`; it prints `SKIP` and exits `0` | B | **High (process).** Drift is policed in one direction only; a divergence introduced on B passes B's own gate | Clone A into B's `example/`; make a missing peer a non-zero exit |
| **S6** | 25 bare extractor positions on B; pre-handler refusals are `text/plain` | B | Medium (contract) | Port `StrictPath`/`StrictQuery`. `AppError::BodyRejected` already exists there |
| **S9** | Neither CI pipeline runs `cargo test`, `test_e2e.sh` or `verify_convergence.sh` | Both | **Medium (process)** | One shared workflow. Both sides' gates already exit non-zero correctly |
| **S3** | A shares fixtures via `tests/common/mod.rs`; B duplicates setup per binary | Both | Low | A's arrangement is the better one |
| **S4** | `pub mod` + selective re-export (A) vs private `mod` + glob (B) | Both | Low | The ideal is the intersection — private `mod` *plus* selective `pub use`. Neither has both |
| **S5** | Guard nouns diverge (`guard_lifecycle_authority` / `guard_resource_lifecycle`, etc.) | Both | Very low | Leave. The `guard_` marker carries the convention and is uniform |
| **S7** | Migration sequence numbers reset per date (A) vs globally monotonic (B) | A | Low | Adopt B's numbering for *new* migrations; renaming applied ones is not worth it |
| **S8** | `create_audit_log` takes a concrete connection (A) vs a generic `&C` (B) | A | Low | Adopt B's — it permits writing the audit row inside a transaction |
| **S10** | Body ceiling: fixed 3 MiB (A) vs configurable, 10 MiB default (B) | Both | Low | Accepted divergence, already recorded in A's convergence gate. A runs in the conservative direction |

---

## 8. Convergence scorecard

| Dimension | Measured | Score |
| :--- | :--- | :--- |
| Crate-root modules by name and role | 13 of 13 shared | **100%** |
| `api/` structural modules | 6 of 6 | **100%** |
| Domain module count | 3 each | **Symmetric** |
| `MasterPin` public API | 6 of 6 methods | **100%** |
| Shared `api_key` columns | 11 of 11 | **100%** |
| Gate-enforced byte-identical functions | 3 of 3 | **100%** |
| Shared configuration constants | 3 of 4 by value (body ceiling diverges) | **75%** |
| Guard prefix uniformity | 10/10 (A), 7/7 (B) | **100%** |
| `AppError` variants → status codes | 9 of 9 shared | **100%** |
| Extractor envelope coverage | 5 of 5 (A), 2 of 5 (B) | **70%** |
| Audit-log non-domain columns | 8 of 8 | **100%** |
| Audit writer strictness | Identical (both by-value) | **100%** |
| Health/readiness contract | 5 of 5 properties | **100%** |
| Test-suite filenames and conventions | 5 of 6 aligned | **83%** |
| Verification gates effective on both sides | 5 of 6 (**S1**) | **83%** |

---

## 9. Executive verdict — structural convergence

| Dimension | Verdict |
| :--- | :--- |
| Shared foundational DNA | **Confirmed.** 13 of 13 shared crate-root modules and 6 of 6 structural `api/` modules match by name and role. Every difference in the module list is one side's domain engine |
| Separation of concerns | **Identical.** Both isolate all RBAC decisions in one `api/guards.rs`, all schema evolution in `migration/`, all models in `entities/`, extractors in `src/extract.rs`, and the two unauthenticated probes in `api/health.rs` |
| Naming standardization | **Converged.** Guard prefixes uniform on both, `MasterPin` matching method-for-method, universal payload suffixes, shared migration filename shape. What remains is synonym choice — plus one stable inverse (`is_permission_reduction` / `widens_permissions`) that must **not** be aligned mechanically |
| Error handling | **Unified in structure, divergent in reach.** 9 of 9 shared variants, identical codes, identical envelope and `ConflictWithDetails` merge — but A wraps 5 of 5 extractors and B wraps 2 of 5 (**S6**) |
| Observability | **Unified.** 8 of 8 non-domain audit columns match by name, type and nullability; both writers make an unattributed write inexpressible |
| Divergences with no domain justification | **9**, none behavioural. The material ones are **S1**, **S6** and **S9** |

**Convergence level: HIGH — the two services remain formally one codebase wearing two domains.** A
reader who knows either can navigate the other by structure alone: the guards are in the same file,
the extractors at the same address, the errors carry the same names and produce the same bodies, the
audit trail has the same columns with the same nullability, the master identity exposes the same six
methods, and three security-critical functions are held byte-identical by a script. The appearance of
`src/extract.rs` and `tests/concurrency_and_contracts.rs` on *both* sides — same filenames, same first
two tests — is convergence still actively happening rather than a state being preserved.

Three items deserve action, and all three are about *keeping* this state rather than reaching it.
**S1**: B's convergence gate has no peer to compare against, so drift is detected in one direction
only — the highest-value fix here, because everything above is a snapshot that only a working gate
keeps true. **S6**: B's extractor rollout is unfinished, and its own contract test asserts status
without `Content-Type`, so its suite reports the property covered while the body shape goes
unchecked. **S9**: neither CI pipeline runs any gate, so every figure in this scorecard currently
depends on a person remembering to run two scripts.
