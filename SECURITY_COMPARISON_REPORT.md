# Independent Security Audit — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-18
**Method:** clean-room. Every finding below was derived from `RBAC_MODEL.md` and the current `.rs`
source of both trees. No previous audit report was opened, in either repository.
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository. `RBAC_MODEL.md` is untouched.

| Subject | Path | Commit |
| :--- | :--- | :--- |
| **A — this service** | `./src/`, `./tests/` | `818740f` |
| **B — peer** | `./example/simply_ip_vault/` | `14c8fa3` |

---

## 0. Task 0 — peer repository update

`example/` holds three sibling checkouts. All were pulled before any file was read.

| Project | `git pull --ff-only` | HEAD | In `RBAC_MODEL.md`'s stated scope? |
| :--- | :--- | :--- | :--- |
| `simply_ip_vault` | **Already up to date** | `14c8fa3` | **Yes** — the comparison subject |
| `simply_ip_exporter` | Already up to date | `52651e5` | No |
| `simply_ip_sync` | Already up to date | `c283911` | No |

All three working trees are clean. `simply_ip_vault` is the subject of this report: it is the service
`RBAC_MODEL.md` names alongside this one, and the only one `scripts/verify_convergence.sh` diffs.

### 0.1 A normative-document observation

| Repository | `RBAC_MODEL.md` md5 | Scope line |
| :--- | :--- | :--- |
| `simply_hook_executor` | `cb0b76ab…` | *"`simply_ip_vault` and `simply_hook_executor`"* |
| `simply_ip_vault` | `cb0b76ab…` | Identical |
| `simply_ip_exporter` | `cb0b76ab…` | Identical — **does not name the repository carrying it** |
| `simply_ip_sync` | `792fb269…` | *"Normative specification for this service … `simply_ip_sync` is not in that document's stated scope"* |

`simply_ip_sync` handles being out of scope correctly: it restates the model in its own terminology
and says so explicitly in the header. `simply_ip_exporter` ships the byte-identical shared document
whose Scope line governs two *other* services — so an agent working there is following a
specification that does not claim to apply. **Recommendation:** adopt `simply_ip_sync`'s treatment.
This is document coherence, not a control failure, and it does not affect the audit below.

---

## 1. Zero-knowledge security assessment

Each rule was traced to its enforcing code on both sides, then attacked. Negative results are in
§1.2 and §1.4 — an audit that lists only what it found is indistinguishable from one that did not
look.

### 1.1 Findings against Subject A — `simply_hook_executor`

---

#### **SHE-1 — `MEDIUM` — Ownership bypasses the R2 conjunction on dispatch configuration**

**Rule.** `RBAC_MODEL.md`, *Dispatch configuration*:

> *Where it lives on a shared managed resource, editing it is a management action on that resource and
> is governed by **R2 in full** — holding an operational verb, or a `can_manage` row without the
> global conjunct, does not authorise changing what the service executes or where it dispatches.*

The clause names this service's fields explicitly: `script_path` and `run_as_user` on the Hook row.

**The code.** `src/api/guards.rs` — `guard_manage` returns before R2 is consulted:

```rust
if key.is_master { return Ok(()); }
if hook.owner_key_id == Some(key.id) { return Ok(()); }   // ← R2 never reached
guard_hook_manage_conjunction(db, key, hook.id).await?;
```

`src/api/hooks.rs` — `update_hook` is gated by that function and writes `script_path` from the
payload. `can_manage_keys` is never re-read on this path, and neither is `can_manage_hooks`.

**Reachability, step by step.** Every step is an ordinary API call.

| # | Actor | Action | Effect |
| :--- | :--- | :--- | :--- |
| 1 | Master | Grants a Daughter `can_manage_hooks` | Legitimate — R4 |
| 2 | Daughter | `POST /api/hooks` | `owner_key_id = self`; `grant_full_hook_permission` writes `can_execute`, `can_manage`, `can_view_execution` all `true` |
| 3 | Master | **Revokes `can_manage_hooks`** — the containment action | Scope cleared. **Ownership and the permission row are untouched** |
| 4 | Daughter | `PUT /api/hooks/{id}` with a new `script_path` | **Accepted**, via the ownership route |
| 5 | Daughter | `POST /api/hooks/{id}/execute` | Runs, using the `can_execute` from step 2 |

`allowed_script_roots` defaults to empty, and `executor::is_within_roots` reads empty as *permit
every path*:

```rust
roots.is_empty() || roots.iter().any(|root| candidate.starts_with(root))
```

so step 4 may name any absolute, traversal-free path on the host.

**Impact.** Revoking `can_manage_hooks` does not contain the key. It retains the ability to repoint
every hook it created at an arbitrary binary and run it, indefinitely. A second route reaches the
same place: §3 permits Master to reassign `owner_key_id` to any key, which confers `script_path`
write access on a key holding no `can_manage_keys` at all.

**What bounds it.** Stated so the severity is not overread.

| Mitigation | Effect |
| :--- | :--- |
| `guard_master_for_privileged_hook` | A hook carrying `run_as_user` is **master-only to modify at all** — the escalation cannot cross into another OS account |
| Hooks are never spawned through a shell | Gate-asserted; no metacharacter injection |
| `ALLOWED_SCRIPT_ROOTS` | Closes it entirely when set. Unset by default |
| The tier already holds this power at creation | A key *currently* holding `can_manage_hooks` could set the same path via `POST /api/hooks` |

**Assessment.** Not escalation from nothing — a **containment failure**, and a deviation from a
normative clause that admits no ownership exception. The delta over what the tier can already do is
*persistence after revocation*, plus the reassignment route.

**The peer does not have this gap, and the contrast is the evidence.** `simply_ip_vault`'s
`update_webhook` gates on the standing scope **and then** ownership:

```rust
if !key.is_master && !key.can_manage_webhooks { /* deny */ }        // standing scope, re-checked
if !key.is_master && target.owner_key_id != Some(key.id) { /* 404 */ }  // ownership
```

Revoking `can_manage_webhooks` there contains the key immediately. Two codebases that otherwise
match line for line answer the same containment question two different ways.

---

#### **SHE-2 — `LOW` — No refusal when the caller's own key lies inside the subtree being deleted**

`src/api/keys.rs` refuses `id == key.id`, covering the direct case. It does not check whether the
caller appears among the *descendants* collected by `collect_subtree_inventory`. The peer refuses
exactly that (`if subtree.contains(&key.id)`).

**Reachability.** Only through a cycle in `parent_key_id`, which the API cannot create — every create
path sets the parent to an existing key. It needs a direct database edit or a restore from a corrupt
dump. The traversal itself is safe: `descendant_key_ids` carries a `seen` set and terminates.

**Impact.** In that state the caller deletes its own credential mid-request. No authorization boundary
is crossed; the outcome is lockout, not escalation. Reported as a parity gap.

---

### 1.2 Attacks attempted against Subject A that held

| Attempted | Result | Enforced at |
| :--- | :--- | :--- |
| Mint a second Master via a key payload | **Refused** — `is_master` is not a field on `CreateApiKeyPayload`/`UpdateApiKeyPayload`; both carry `deny_unknown_fields`, so it is a `400` naming the field | `api/keys.rs` |
| Mint a second Master via direct SQL with a NULL marker | **Refused** — `master_marker` is `GENERATED ALWAYS AS (…)` under a unique index | `m20230106_000001` |
| Read `is_master` off a response and write it back | **N/A** — it appears only on `Serialize`-only views (`MeResponse`, `ApiKeySummary`), never on a deserialized type | — |
| Non-master grants a global scope | **Refused** for every non-master, without consulting the target's current value | `guard_master_to_grant_scopes` |
| Grant a verb on a hook the caller does not hold | **Refused** per verb | `guard_delegated_hook_grant` |
| Trade a held verb for an unheld one in one write | **Refused** — classified as a grant, not a reduction | `is_permission_reduction` |
| Reach R2 through the general update endpoint | **Refused** — both routes classify through the same function (R6, final sentence) | `api/keys.rs` |
| Probe which hooks exist via `403`/`404` | **Refused** — no row ⇒ `404`; row but no global conjunct ⇒ `403` | `verb_denied`, `guard_hook_manage_conjunction` |
| Probe key UUIDs on the permission routes | **Refused** — `has_permission_admin_standing` runs before any `find_by_id` | `api/keys.rs` |
| Rotate or delete the Master through the API | **Refused for every caller, including Master**, and not resting on the uniqueness index | `refuse_master_lifecycle_action` |
| Edit a Master field other than `bound_ips` | **Refused**, including by the Master itself | `guard_master_self_edit_is_bound_ips_only` |
| Orphan hooks through a key deletion | **Refused** — §6 inventory, stray-resolution refusal, total-map requirement, reassign-into-doomed-subtree refusal | `api/keys.rs` |
| Bypass `bound_ips` by holding the Master key | **Refused** — no `is_master` exemption in the CIDR check | `middleware.rs` |
| Forge `client_ip` via `X-Forwarded-For` | **Refused** — `TRUSTED_PROXIES` empty by default means "believe no forwarding header" | `config.rs` |
| Assign `run_as_user` without Master | **Refused**, checked before payload validation so the `403` is not masked | `normalize_run_as_user` |

### 1.3 Findings against Subject B — `simply_ip_vault`

---

#### **SIV-1 — `LOW` (contract) — Most refusals produced before a handler runs are not in the error envelope**

Both services document every refusal as `{"error": "<message>"}` served as `application/json`.
Subject B wraps **two** of the five extractors its handlers use:

| Extractor | Subject A | Subject B |
| :--- | :--- | :--- |
| `Json<T>` | `StrictJson` | `StrictJson` |
| `Json<T>`, optional body | `OptionalStrictJson` | `OptionalStrictJson` |
| `Path<T>` | `StrictPath` | **bare `Path<T>`** |
| `Query<T>` | `StrictQuery` | **bare `Query<T>`** |
| `Bytes` | `StrictBytes` | *(no raw-body route)* |
| Bare extractor positions remaining in handlers | **0** | **25** |

Consequence on B: an unparseable UUID path parameter, a mistyped query value, and a malformed body on
any route not using `StrictJson` are refused with the right status and a bare `text/plain` body
carrying no `error` field. Those are the most common things a caller gets wrong.

Two details make this worth reporting rather than filing as cosmetics. First, **the mechanism already
exists** on B — `AppError::BodyRejected(StatusCode, String)` is defined in its `error.rs` and used by
`StrictJson`; it is simply not applied to the other extractors. Second, **B's own test cannot see the
gap**: its `malformed_input_is_refused_on_every_extractor` asserts status only, with zero assertions
on `Content-Type`, so the suite reports the property as covered while the body shape goes unchecked.

No authorization is bypassed and no information leaks, hence `LOW`. It is a client-contract defect.

---

#### **SIV-2 — `LOW` — `DeleteKeyPayload` does not reject unknown fields**

`example/simply_ip_vault/src/api/keys.rs` — `CreateApiKeyPayload`, `UpdateApiKeyPayload`,
`BatchRecordInput` and `BatchRecordsPayload` all carry `#[serde(deny_unknown_fields)]`.
`DeleteKeyPayload`, which carries the §6 resolution map, does not.

**Impact.** A caller misspelling `resolutions` has its map silently dropped. The request then **fails
safe** — an empty map against a non-empty inventory returns the `409` inventory rather than deleting
anything — so this is diagnostic quality on a destructive endpoint, not a bypass.

**Note for whoever fixes it:** the attribute belongs on `DeleteKeyPayload`. It cannot go on the nested
`ResolutionEntry`, which uses `#[serde(flatten)]`; serde rejects that combination.

---

### 1.4 Attacks attempted against Subject B that held

| Attempted | Result |
| :--- | :--- |
| Grant any global scope as a non-master | **Refused** — `MASTER_ONLY_SCOPES` covers all three (`can_manage_keys`, `can_create_groups`, `can_manage_webhooks`) |
| Manage a group's grants with `can_manage` but no `can_manage_keys` | **Refused** — explicit conjunction in `guard_group_manage` |
| Delete a group holding only operational verbs | **Refused** — `guard_resource_lifecycle`; unowned ⇒ Master only |
| Edit a webhook after `can_manage_webhooks` is revoked | **Refused** — the standing scope is re-checked on every edit |
| Read another tenant's webhook via a shared group | **Refused** — creator-private, `404` for non-owners |
| Submit a partial resolution map | **Refused**, with the unresolved set returned |
| Delete a key whose subtree contains the caller | **Refused** — explicit cycle guard |
| Mint a second Master | **Refused** — engine-generated marker, same design as A |

---

## 2. Security parity — control by control

### 2.1 RBAC rules R1–R7

| Rule | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| **R1** non-amplification | `guard_delegated_hook_grant` — per-verb `wanted && !held`, 3 verbs | `guard_delegated_group_grant` — per-verb, 4 verbs | ✅ Same shape |
| **R2** conjunction | `guard_hook_manage_conjunction` — `!can_manage_keys → deny`, then `!row.can_manage → deny` | `guard_group_manage` — `can_manage_keys && perm.can_manage` | ✅ Same predicate |
| R2 evaluation points | **One** | **One** | ✅ No second implementation to drift |
| R2 governs dispatch configuration | ⚠️ **Bypassed by ownership** (**SHE-1**) | ✅ Standing scope re-checked, then ownership | ⚠️ **Divergent** |
| **R3** lineage confers nothing | `parent_key_id` read only for subtree walks and visibility | Same | ✅ |
| **R4** only Master mints parents | `guard_master_to_grant_scopes` — 2 scopes, both covered | `guard_scope_elevation` — 3 scopes, all covered | ✅ Complete on both |
| R4 idempotent re-assertion | Refused for non-master regardless of the target's current value | Permitted when the target already holds it | ⚠️ A stricter; both spec-compliant |
| **R5** sideways propagation | Bounded by R1 + R2; globals unreachable to non-master | Same | ✅ |
| **R6** revocation ≠ escalation | `is_permission_reduction`; both routes agree | `widens_permissions`, same role | ✅ Logical inverses, same behaviour |
| **R7** R1 ∧ R2 simultaneously | R2 is the entry gate, R1 layered on the row it returns | Identical composition | ✅ |

### 2.2 Specification sections §3–§7

| Section | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| **§3** lifecycle = Master ∪ owner | `guard_lifecycle_authority`; rename grouped with delete | `guard_resource_lifecycle` | ✅ |
| §3 unowned ⇒ Master-only | ✅ | ✅ | ✅ |
| §3 owner recorded on create | `owner_key_id = creator`, unconditionally | `resource_owner()` returns `None` for Master — "a master is not a tenant" | ⚠️ Semantic divergence, no security impact |
| §3 Master may reassign | ✅ non-master refused, dangling target refused | ✅ `resolve_owner_assignment` | ✅ |
| **§4** invisible ⇒ `404` | `verb_denied`, `guard_visibility`, `may_read_execution` | `404` on non-owned creator-private entities | ✅ |
| §4 pre-gate before any `find_by_id` | `has_permission_admin_standing` | `holds_any_group_manage` | ✅ Same reasoning |
| §4 authn-before-authz | Key lookup → signature → **then** `bound_ips` | Same | ✅ |
| **§5** engine-derived marker | `GENERATED ALWAYS AS`, unique index | Same construction | ✅ |
| §5 `is_master` absent from payloads | ✅ type-level, both payloads | ✅ type-level, both payloads | ✅ |
| §5 Master immutable but `bound_ips` | `guard_master_self_edit_is_bound_ips_only` | `guard_master_immutable` | ✅ |
| §5 rotation/deletion refused for all | ✅ not resting on the index | ✅ | ✅ |
| §5 runtime pin | `MasterPin` — 6 methods | Identical API | ✅ |
| **§6** recursive cascade | `descendant_key_ids`, cycle-safe | `collect_key_subtree`, cycle-safe | ✅ |
| §6 total map / stray refusal | ✅ both | ✅ both | ✅ |
| §6 reassign into doomed subtree | ✅ refused | ✅ refused | ✅ |
| §6 caller inside subtree | ⚠️ **not checked** (**SHE-2**) | ✅ refused | ⚠️ B stricter |
| **§7** required indexes | Pinned by `s7_…` | Pinned by `s7_…` | ✅ |

### 2.3 Cryptography and session integrity

| Control | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| Credential storage | SHA-256 → `key_hash`, single lookup path | Same | ✅ |
| Signing secret at rest | XChaCha20-Poly1305 | XChaCha20-Poly1305 | ✅ |
| MAC comparison | `Mac::verify_slice` — constant-time | Same primitive | ✅ |
| `==` on MAC/digest | Absent — gate-asserted in `crypto.rs` and `middleware.rs` | Absent, same gate | ✅ |
| Canonical signed string | `canonical_v1_payload` | `canonical_v1_payload` | ✅ Byte-identical, gate-enforced |
| Replay ledger | Never flushed, throttled sweep, digests keyed as raw bytes | Same invariants | ✅ |
| Forwarding-header trust | Empty `TRUSTED_PROXIES` = believe nothing | Same default | ✅ |

### 2.4 Database constraints and isolation

| Control | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| SQLite pragmas | `foreign_keys`, WAL, `synchronous=NORMAL`, `busy_timeout` | Identical set | ✅ Gate-enforced |
| `SQLITE_BUSY_TIMEOUT_MS` | `5_000` | `5_000` | ✅ |
| `SQLITE_MAX_CONNECTIONS` | `1` | `1` | ✅ |
| `RETENTION_DAYS` | `92` | `92` | ✅ |
| Audit FK on key deletion | `ON DELETE SET NULL` | `ON DELETE SET NULL` | ✅ |
| Audit attribution nullability | `api_key_name`, `api_key_prefix`, `client_ip` **NOT NULL** | **NOT NULL** | ✅ |
| Unattributed audit write expressible? | **No** — writer takes `&api_key::Model` and `IpAddr` by value | **No** — same signature | ✅ |
| Request body ceiling | Fixed `3 * 1024 * 1024`, no override | `DEFAULT_MAX_BODY_MIB` (10 MiB), `MAX_BODY_SIZE_MIB` override | ⚠️ A more conservative |

### 2.5 Payload and input strictness

`deny_unknown_fields` is a §5 control on both sides: it is what makes the *absence* of `is_master`
from the key payloads a refusal rather than a silent drop.

| Payload class | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| Key create | ✅ | ✅ | ✅ |
| Key update | ✅ | ✅ | ✅ |
| Key delete (§6 map) | ✅ `DeleteApiKeyPayload` **and** the `EntityResolution` enum | ❌ `DeleteKeyPayload` (**SIV-2**) | ⚠️ A stricter |
| Bulk ingestion payloads | *(no analogue)* | ✅ `BatchRecordInput`, `BatchRecordsPayload` | ⚠️ B stricter where it applies |
| Domain resource payloads | Not strict (4) | Not strict (5) | ✅ Same deliberate policy |
| Error envelope on extractor rejections | **5 of 5 extractors** | **2 of 5** (**SIV-1**) | ⚠️ A stricter |
| Envelope asserted with `Content-Type` in tests | ✅ status + content-type + non-empty `error` | ❌ status only | ⚠️ A stricter |
| Body ceiling applied once, router-wide | ✅ | ✅ | ✅ |

---

## 3. Findings summary

| # | Severity | Subject | Finding | Fix |
| :--- | :--- | :--- | :--- | :--- |
| **SHE-1** | `MEDIUM` | A | Ownership bypasses R2 on `script_path` edits; revoking `can_manage_hooks` does not contain the key | Re-check the standing scope on the ownership route of `guard_manage`, as B's `update_webhook` does. Set `ALLOWED_SCRIPT_ROOTS` as interim defence in depth |
| **SIV-1** | `LOW` | B | 25 bare extractor positions; most pre-handler refusals are `text/plain`, and B's own test asserts status only | Port `StrictPath`/`StrictQuery`; `AppError::BodyRejected` already exists there |
| **SIV-2** | `LOW` | B | `DeleteKeyPayload` lacks `deny_unknown_fields` (fails safe) | One attribute — on `DeleteKeyPayload`, **not** the `flatten`ed `ResolutionEntry` |
| **SHE-2** | `LOW` | A | No refusal when the caller's key is inside the subtree being deleted | Port B's `subtree.contains(&key.id)` |
| **ECO-1** | `INFO` | Ecosystem | `simply_ip_exporter` ships a normative document whose Scope line names two other services | Adopt `simply_ip_sync`'s treatment — restate with an explicit out-of-scope note |

---

## 4. Executive verdict — security

| Dimension | Verdict |
| :--- | :--- |
| Specification coverage | **Complete on both sides.** Every rule R1–R7 and every clause of §3–§7 has identifiable enforcing code in both services |
| Critical vulnerabilities | **None.** No path was found on either side to mint a second Master, self-grant a global scope, bypass R2 for *delegation*, defeat `bound_ips`, forge a signature, or replay one |
| Confirmed findings | **5** — one Medium and one Low against A, two Low against B, one informational |
| Highest-severity finding | **SHE-1**, `MEDIUM`, against **this service**. The specification's dispatch-configuration clause governs `script_path` edits under R2 *in full*; `guard_manage` admits ownership as a third route, so a revoked `can_manage_hooks` does not take back what it granted |
| Cryptographic parity | **Full.** Byte-identical canonicalization, identical AEAD, constant-time comparison, identical replay invariants — gate-enforced |
| Database constraint parity | **Full.** Identical pragmas and pool pinning, engine-derived master marker on both, audit attribution `NOT NULL` and structurally unfalsifiable on both |
| Payload strictness parity | **Substantive**, with each side stricter in one place: A on the §6 delete map and on extractor envelopes, B on bulk-ingestion payloads |
| Oracle discipline | **Full on both.** `404`/`403` split implemented, pre-gates placed before any id lookup |

**Security maturity: HIGH.** Both services enforce the specification comprehensively and in the same
shape, with single evaluation points for the rules that matter and adversarial rather than
cooperative tests behind them. Nothing found here is exploitable by an unprivileged caller.

The one finding with an attack narrative belongs to **this service**, and the peer is the model for
the fix: `simply_ip_vault` re-checks the standing scope on every dispatch-target edit, this service
does not, and the practical consequence is that revocation is not containment. The two findings
against the peer are contract defects rather than control failures — but **SIV-1** carries a lesson
worth naming: the property was already covered by a test that asserted only the status code, so the
suite reported it green while the body shape went unchecked. A test that verifies two of a control's
three observable properties is how a gap survives an audit.
