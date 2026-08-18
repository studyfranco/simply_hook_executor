# Ecosystem Structural and Formal Convergence Report

**Date:** 2026-08-18
**Method:** clean-room. Every table was produced by enumerating the current source trees. No previous
convergence report was opened.
**Mode:** read-only over all application code in every repository. `RBAC_MODEL.md` untouched.

| Ref | Project | Path | Commit | Role |
| :--- | :--- | :--- | :--- | :--- |
| **A** | `simply_hook_executor` — *this service* | repository root | `15b8af6` | **Gold standard** |
| **B** | `simply_ip_vault` | `example/simply_ip_vault` | `14c8fa3` | **Gold standard** |
| **C** | `simply_ip_exporter` | `example/simply_ip_exporter` | `80a3b31` | Later adopter |
| **D** | `simply_ip_sync` | `example/simply_ip_sync` | `72cce13` | Later adopter |

**Framing.** A and B are the pair the convergence originated with: they are the two services
`RBAC_MODEL.md` names, and the only two whose shared logic is held byte-identical by a script. C and D
were built afterwards against that pattern. The question for every divergence is therefore not "do
they differ?" but **"is this a domain difference, a deliberate simplification, or drift?"** — and the
tables label which.

They deliberately do different things: A executes local processes, B manages IP blocklists and
dispatches webhooks, C serves aggregated feeds, D synchronises external sources into vaults.

---

## 1. Scale — read the rest of this report against these numbers

| Metric | A | B | C | D |
| ---: | ---: | ---: | ---: | ---: |
| `src/` lines | 12 688 | 13 012 | **4 801** | 7 016 |
| Crate-root modules | 13 | 13 | 18 | 14 |
| `api/` modules | 9 | 9 | **7** | 10 |
| Entities | 8 | 9 | **5** | 11 |
| Migrations | 9 | 12 | **2** | 2 |
| Test binaries | 6 | 7 | **2** | **14** |
| Tests | 182 | 197 | **33** | 108 |

C is roughly a third the size of the gold-standard pair and carries a third of their entity count.
Several divergences below follow from that and are correctly read as *simplification*, not drift —
but not all of them, and §2.2 marks the difference.

---

## 2. Module structure and separation of concerns

### 2.1 Crate-root modules

| Module | A | B | C | D | Class |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `api` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `config` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `crypto` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `db` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `entities` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `error` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `extract` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `master` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `middleware` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `migration` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `replay` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `state` | ✅ | ✅ | ✅ | ✅ | **Universal** |
| `retention` | ✅ | ✅ | ❌ | ❌ | Domain — neither C nor D soft-deletes |
| Domain engine | `executor` | `dispatch` | `feed`, `sync`, `vault_client` | `client`, `scheduler`, `retry` | Domain |
| Domain support | — | — | `cache`, `ipfilter`, `ratelimit` | — | Domain |

**12 modules are universal across all four services, by name and by role.** Every difference is a
domain engine or its support. `extract` being universal is notable: it is the youngest of the twelve
and is already present everywhere.

### 2.2 `src/api/` — where C diverges structurally

| Module | A | B | C | D | Class |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `mod.rs` | ✅ | ✅ | ✅ | ✅ | **Structural** |
| `keys.rs` | ✅ | ✅ | ✅ | ✅ | **Structural** |
| `audit.rs` | ✅ | ✅ | ✅ | ✅ | **Structural** |
| `health.rs` | ✅ | ✅ | ✅ | ✅ | **Structural** |
| `support.rs` | ✅ | ✅ | ✅ | ✅ | **Structural** |
| **`guards.rs`** | ✅ 21 fns | ✅ 12 fns | ❌ **absent** | ✅ 12 fns | **Structural — the defining one** |
| Domain modules | `hooks`, `executions`, `system` | `groups`, `records`, `webhooks` | `auth`, `endpoints` | `sources`, `vaults`, `sync_tasks`, `sync_logs` | Domain |

**5 of 6 structural modules are universal. The sixth — `guards.rs` — is present in A, B and D and
absent in C**, which has `api/auth.rs` containing a single function (`get_me`) and enforces
authorization inline in its handlers.

This is the one structural divergence in the ecosystem that is **not** explained by size. "Every
authorization decision lives in one file" is the property the gold standard exists to demonstrate: it
is what stops one sentence of the specification being written in three places and drifting. C is small
enough today that inline checks are readable — but it is also the service where the security audit
found a privilege flag wired to nothing, which is exactly the class of defect a single guards module
makes visible by making the whole authorization surface one file long.

### 2.3 Guard inventory — the three services that have one

| Rule | A | B | D |
| :--- | :--- | :--- | :--- |
| **R2** conjunction | `guard_hook_manage_conjunction` | `guard_group_manage` | `guard_resource_manage` |
| **R1 + R7** delegation bound | `guard_delegated_hook_grant` | `guard_delegated_group_grant` | `guard_delegated_grant` |
| **R4** scope elevation | `guard_master_to_grant_scopes` | `guard_scope_elevation` | `guard_scope_elevation` |
| **R6** revocation | `is_permission_reduction` | `widens_permissions` | `guard_revocation` |
| **§3** lifecycle | `guard_lifecycle_authority` | `guard_resource_lifecycle` | `guard_resource_lifecycle` |
| **§5** master immutability | `refuse_master_lifecycle_action` + `guard_master_self_edit_is_bound_ips_only` | `guard_master_immutable` | `guard_master_immutable` |
| **§5** rotation | *(inside the master guards)* | *(inside `guard_master_immutable`)* | `guard_rotation_allowed` |
| Resource creation | *(inline `can_manage_hooks` check)* | *(inline)* | `guard_resource_creation` |
| **`guard_*` prefix uniformity** | 10 of 10 gates | 7 of 7 gates | **12 of 12** | 

**Every rule with a counterpart has exactly one evaluation point per service, and every gate on all
three carries the `guard_` marker.** D's naming is the closest to B's — `guard_resource_lifecycle`,
`guard_scope_elevation` and `guard_master_immutable` are B's names exactly — which is what one expects
from a service built later against the pair.

### 2.4 Facade style

| Aspect | A | B | C | D |
| :--- | :--- | :--- | :--- | :--- |
| Submodule visibility | `pub mod` + selective `pub use` | private `mod` + glob | `pub mod` | `pub mod` |
| Guards reachable outside the crate | Yes | No | N/A | Yes |

B is the only service that closes the facade; A, C and D leave submodules public. Neither is unsafe.
The ideal — private `mod` **plus** selective `pub use` — is implemented by nobody.

---

## 3. Naming conventions

### 3.1 Security-critical functions

| Concern | A | B | C | D | Convergence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Gate prefix | `guard_*` | `guard_*` | *(no gates module)* | `guard_*` | ✅ 3 of 3 applicable |
| Client IP resolution | `resolve_client_ip` | `resolve_client_ip` | `resolve_client_ip` | `resolve_client_ip` | ✅ **Universal** |
| Canonical signed string | `canonical_v1_payload` | `canonical_v1_payload` | `canonical_v1_payload` | `canonical_v1_payload` | ✅ **Universal** |
| Pragma application | `apply_sqlite_pragmas` | `apply_sqlite_pragmas` | `apply_sqlite_pragmas` | `apply_sqlite_pragmas` | ✅ **Universal** |
| Audit writer | `create_audit_log` | `create_audit_log` | `create_audit_log` | `create_audit_log` | ✅ **Universal** |
| Key primitives | `hash_key`, `generate_random_key`, `generate_signing_secret` | Same | Same | Same | ✅ **Universal** |
| Master identity | `MasterPin` — 6 methods | 6 methods | 6 methods | 6 methods | ✅ **Universal** |
| R6 classifier polarity | `is_permission_reduction` | `widens_permissions` | — | `guard_revocation` | ⚠️ A and B are **logical inverses** — stable, and must not be aligned mechanically |

**Seven security-critical names are identical in all four services**, and `MasterPin`'s six-method API
matches everywhere. None of that is forced by a framework; it is the clearest evidence of shared
authorship in the ecosystem.

### 3.2 Database models

| Aspect | A | B | C | D |
| :--- | :--- | :--- | :--- | :--- |
| One file per table | ✅ | ✅ | ✅ | ✅ |
| `prelude.rs` re-export | ✅ | ✅ | ✅ | ✅ |
| Table naming | `snake_case` plural | Same | Same | Same |
| Per-resource permission table | `api_key_hook_permission` | `api_key_group_permission` | ❌ none | `api_key_sync_permission` |
| Shared `api_key` columns | 11 | 11 | 10 (no resource-creation right) | 11 |
| §5 marker | `master_marker`, `GENERATED ALWAYS` | Same | Same | Same |
| Migration filename shape | `mYYYYMMDD_NNNNNN_<slug>.rs` | Same | Same | Same |

The `api_key_<resource>_permission` naming holds in all three services that have such a table.

### 3.3 Extractors and payloads

| Aspect | A | B | C | D |
| :--- | :--- | :--- | :--- | :--- |
| Extractor module address | `src/extract.rs` | `src/extract.rs` | `src/extract.rs` | `src/extract.rs` |
| `Strict*` naming | ✅ | ✅ | ✅ | ✅ |
| Wrappers defined | 5 | 2 | 2 | 3 |
| Bare extractor positions left | **0** | 25 | 1 | **0** |
| Payload suffix convention | `…Payload` / `…Input` | Same | Same | Same |

**The `Strict*` convention and the `src/extract.rs` address are universal.** What differs is how far
each rollout got — which reads as staged adoption rather than disagreement, since no service has an
alternative pattern.

---

## 4. Error handling

| Variant | A | B | C | D | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `DbError` | ✅ | ✅ | ✅ | ✅ | `500`, driver error logged only |
| `InvalidInput` | ✅ | ✅ | ✅ | ✅ | `400` |
| `Unauthorized` | ✅ | ✅ | ✅ | ✅ | `401` |
| `Forbidden` | ✅ | ✅ | ✅ | ✅ | `403` |
| `NotFound` | ✅ | ✅ | ✅ | ✅ | `404` |
| `Conflict` | ✅ | ✅ | ✅ | ✅ | `409` |
| `BodyRejected` | ✅ | ✅ | ✅ | ✅ | passed through |
| `Internal` | ✅ | ✅ | ✅ | ✅ | `500` |
| `ConflictWithDetails` | ✅ | ✅ | ❌ | ✅ | `409` + merged fields — C has no §6 cascade to report |
| `TooManyRequests` | ✅ | ❌ | ✅ | ❌ | `429` — only A and C throttle |
| `Json` (`#[from]`) | ✅ | ✅ | ❌ | ❌ | Plumbing |

**8 variants are universal, with identical status codes and identical default messages.** The envelope
is `{"error": "<message>"}` in all four, and `BodyRejected` — the mechanism that carries an extractor
rejection into that envelope without flattening its status — exists everywhere. Only its *reach*
differs (§3.3).

---

## 5. Observability — audit trail

| Column | A | B | C | D |
| :--- | :--- | :--- | :--- | :--- |
| `id: Uuid` | ✅ | ✅ | ✅ | ✅ |
| `api_key_id: Option<Uuid>` | ✅ | ✅ | ✅ | ✅ |
| `api_key_name` | `String` | `String` | `String` | **`Option<String>`** |
| `api_key_prefix` | `String` | `String` | `String` | **`Option<String>`** |
| `client_ip` | `String` | `String` | `String` | **`Option<String>`** |
| `action: String` | ✅ | ✅ | ✅ | ✅ |
| `details: Option<String>` | ✅ | ✅ | ✅ | ✅ |
| `timestamp` | `DateTime` | `DateTime` | `DateTime` | `DateTimeUtc` |
| Target reference | `target_resource` | `target_address` + `group_names` | `target_resource` | `target_resource` |

**`target_resource` is the ecosystem's majority convention (A, C, D);** B splits it into two
domain-specific columns. Attribution is `NOT NULL` in three of four — D's nullability is the security
report's **SYN-1**. All four writers take the acting key and address **by value**, so an unattributed
write is inexpressible in the writer regardless of the column.

| Action naming | A | B | C | D |
| :--- | :--- | :--- | :--- | :--- |
| Format | `SCREAMING_SNAKE`, `<NOUN>_<VERB>` | Same | Same | Same |
| `KEY_CREATE` / `KEY_DELETE` | ✅ | ✅ | ✅ | ✅ |

---

## 6. Verification gates and governance

| Artefact | A | B | C | D |
| :--- | :---: | :---: | :---: | :---: |
| `scripts/test_e2e.sh` | ✅ 958 checks | ✅ | ✅ | ✅ |
| `scripts/verify_convergence.sh` | ✅ 18 converged | ✅ (inert — no peer) | ✅ | ❌ **absent** |
| `RBAC_MODEL.md` | ✅ | ✅ | ✅ (shared, out of scope) | ✅ (restated) |
| `AGENT.MD` / `SCHEMA.MD` / `FILE_MAP.MD` / `AGENT_NOTES.MD` / `README.md` | ✅ | ✅ | ✅ | ✅ |
| Vendored peer checkouts under `example/` | ✅ **3** | ❌ | ❌ | ❌ |
| Any gate runs in CI | ❌ | ❌ | ❌ | ❌ |

**All six governance documents are present in all four repositories** — the strongest single signal
that these are one ecosystem rather than four codebases that resemble each other.

Two asymmetries matter. **A is the only service that vendors its peers**, so it is the only vantage
point from which an ecosystem-wide audit like this one can be run at all — every other service's
convergence gate has nothing to compare against. And **no service runs any gate in CI**, so every
figure in this report depends on a person remembering to run the scripts.

---

## 7. Convergence scorecard

| Dimension | Measure | Score |
| :--- | :--- | :--- |
| Universal crate-root modules | 12 of 12 shared, by name and role | **100%** |
| Universal structural `api/` modules | 5 of 6 (`guards.rs` absent in C) | **83%** |
| `guard_` prefix uniformity, where a gates module exists | A 10/10, B 7/7, D 12/12 | **100%** |
| Security-critical function names identical in all four | 7 of 7 | **100%** |
| `MasterPin` public API | 6 of 6 methods, all four | **100%** |
| §5 engine-derived marker | 4 of 4 | **100%** |
| Cryptographic primitives | 4 of 4 identical | **100%** |
| `AppError` variants with identical status mapping | 8 universal + 3 justified | **100%** of shared |
| Error envelope shape | `{"error": …}` in all four | **100%** |
| Extractor module address and `Strict*` naming | 4 of 4 | **100%** |
| Extractor rollout completeness | A 5/5, D 3/3, C 2/3, B 2/5 | **~70%** |
| Audit non-domain columns | 8 of 8 by name; 3 of 4 by nullability | **94%** |
| Governance documents present | 6 of 6, all four repositories | **100%** |
| Convergence gate present **and effective** | 1 of 4 (**A**) | **25%** |

---

## 8. Executive verdict — structural convergence

| Dimension | Verdict |
| :--- | :--- |
| Shared foundational DNA | **Confirmed across all four.** 12 universal crate-root modules, 5 of 6 universal structural `api/` modules, seven identical security-critical function names, an identical six-method `MasterPin`, and one error envelope |
| A ↔ B (the gold standard) | **Highest convergence in the ecosystem.** 13/13 shared modules, 6/6 structural `api/` modules, 11/11 shared `api_key` columns, 9/9 shared error variants, 3/3 gate-enforced byte-identical functions. `src/extract.rs` and `tests/concurrency_and_contracts.rs` now exist on both sides with the same filenames — convergence still actively happening |
| D against the standard | **High.** Full `guards.rs` with all seven rules, B's exact guard names, the strictest input handling in the ecosystem (10 strict payloads, 0 bare extractors). Two gaps: nullable audit attribution, and no convergence gate |
| C against the standard | **Moderate.** All twelve universal modules, all six governance documents, all four cryptographic primitives — but **no `guards.rs`**, no per-resource permission table, and no `deny_unknown_fields`. Most of that is proportionate to a service a third the size; the missing guards module is the exception |
| Divergences without domain justification | **6**, none behavioural: C's absent guards module, B's unfinished extractor rollout, D's nullable audit columns, D's missing convergence gate, the A/B facade-style split, and the universal absence of CI |

**Ecosystem convergence level: HIGH.** These four services are recognisably one codebase family. A
reader who knows any of them can navigate the others by structure: authorization in `api/guards.rs`,
extractors in `src/extract.rs`, schema evolution in `migration/`, models in `entities/`, the two
unauthenticated probes in `api/health.rs`, and the same six governance documents at the root of each.
Seven security-critical functions carry byte-identical names across all four, and three carry
byte-identical bodies between A and B under a script that fails if they drift.

The convergence is also **still in motion rather than merely preserved**: `src/extract.rs` is the
youngest universal module and is already in all four, and the `Strict*` naming that goes with it is
universal even where the rollout is incomplete. Nobody has invented a competing pattern.

Three items deserve action, and all three are about *keeping* this state rather than reaching it.
**C's missing `guards.rs`** is the only structural divergence not explained by scale, and it is the
service where the security audit found a privilege flag wired to nothing — the class of defect a
single-file authorization surface exists to make visible. **Only A vendors its peers**, so it is the
only vantage point from which ecosystem-wide drift is detectable at all; the other three ship a
convergence gate with nothing to compare against, or none. And **no repository runs any gate in CI**,
which means every number in this report is a snapshot that survives only as long as someone keeps
running two scripts by hand.
