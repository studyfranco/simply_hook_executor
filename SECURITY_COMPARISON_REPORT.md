# Independent Security Audit — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-11
**Method:** clean-room. Findings below are derived from `RBAC_MODEL.md` and the current `.rs` source
of both services only. No previous audit report was read or consulted, and no finding is carried
forward from one.
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository. `RBAC_MODEL.md` is untouched.

| Subject | Path | Commit |
| :--- | :--- | :--- |
| **A — this service** | `./src/`, `./tests/` | `edd79fd` |
| **B — peer** | `./example/simply_ip_vault/src/`, `.../tests/` | `c182a7a` |

**Normative baseline:** `RBAC_MODEL.md`, verified byte-identical across both repositories
(`md5sum` → `cb0b76abd6c00f28af9bee951f804f7b`).

---

## 0. Task 0 — peer repository update

| Step | Command | Outcome |
| :--- | :--- | :--- |
| Locate peer | `ls example/` | `simply_ip_vault` — the only project present |
| Update | `cd example/simply_ip_vault && git pull` | **Fast-forward `6f1c4c7` → `c182a7a`** |
| Files changed by the pull | `git diff --stat 6f1c4c7..c182a7a` | 3 files, all Markdown |
| Source touched? | `git diff --name-only … \| grep -E '^(src\|tests\|scripts\|static)/'` | **None.** The peer's source tree is unchanged by this update |
| Tree state | `git status --porcelain` | Clean |
| Return | `cd` back to repository root | Done |

The three files the pull brought in are the peer's own audit documents. Per the clean-room
instruction they were **not opened**; only `--stat` and `--name-only` were used, to establish that no
`.rs` file moved.

---

## 1. Zero-knowledge security assessment

Each rule of `RBAC_MODEL.md` was traced to the code that implements it, on both sides, and then
tested for a way around it. Findings are stated with the concrete path that reaches them.

### 1.1 Findings — `simply_hook_executor` (Subject A)

---

#### **SHE-1 — `MEDIUM` — Ownership bypasses the R2 conjunction on dispatch-configuration edits**

**Rule violated.** `RBAC_MODEL.md`, *Dispatch configuration* (Terminology §, final paragraph):

> *Where it lives on a shared managed resource, editing it is a management action on that resource and
> is governed by **R2 in full** — holding an operational verb, or a `can_manage` row without the
> global conjunct, does not authorise changing what the service executes or where it dispatches.*

For this service the specification names `script_path` and `run_as_user` on the Hook row as exactly
that configuration.

**The code.** [`src/api/guards.rs:163-176`](src/api/guards.rs#L163-L176) — `guard_manage` admits three
routes, and the second returns before R2 is ever consulted:

```rust
if key.is_master { return Ok(()); }
if hook.owner_key_id == Some(key.id) { return Ok(()); }   // ← ownership alone
guard_hook_manage_conjunction(db, key, hook.id).await?;
```

[`src/api/hooks.rs:413`](src/api/hooks.rs#L413) — `update_hook` is gated by that function, and
[`hooks.rs:459`](src/api/hooks.rs#L459) writes `script_path` from the payload. `can_manage_keys` is
never re-read on this path.

**Reachability.** Every step is an ordinary API call:

| # | Actor | Action | Result |
| :--- | :--- | :--- | :--- |
| 1 | Master | Grants a Daughter `can_manage_hooks` | Legitimate — R4 |
| 2 | Daughter | `POST /api/hooks` | [`hooks.rs:270`](src/api/hooks.rs#L270) sets `owner_key_id = self`; [`hooks.rs:322`](src/api/hooks.rs#L322) auto-provisions `can_execute`, `can_manage`, `can_view_execution` |
| 3 | Master | Revokes `can_manage_hooks` — the containment action | Row updated. **Ownership and the permission row are untouched** |
| 4 | Daughter | `PUT /api/hooks/{id}` with a new `script_path` | **Accepted** via route 2 |
| 5 | Daughter | `POST /api/hooks/{id}/execute` | Runs, using the `can_execute` from step 2 |

`allowed_script_roots` defaults to **empty**, and
[`executor.rs:471-473`](src/executor.rs#L471-L473) reads empty as *allow every path*:

```rust
roots.is_empty() || roots.iter().any(|root| candidate.starts_with(root))
```

so step 4 may name any absolute, traversal-free path on the host.

**Impact.** Revoking `can_manage_hooks` does not contain the key. It retains the ability to repoint
every hook it ever created at an arbitrary binary and to run it, indefinitely. The same route is
reachable a second way: §3 lets Master reassign `owner_key_id` to any key, which hands that key
`script_path` write access without any `can_manage_keys`.

**What bounds it.** Stated so the severity is not overread:

| Mitigation | Effect |
| :--- | :--- |
| `guard_master_for_privileged_hook` ([`guards.rs:540`](src/api/guards.rs#L540)) | Any hook carrying `run_as_user` is **master-only to modify at all**. The escalation cannot cross into another OS account |
| Hooks are never spawned through a shell | Gate-asserted. No metacharacter injection |
| `ALLOWED_SCRIPT_ROOTS` | Closes it entirely when set. It is unset by default |
| The tier already holds this power at creation | A key *currently* holding `can_manage_hooks` could set the same path in `POST /api/hooks`. The delta is **persistence after revocation**, plus the reassignment route |

**Assessment.** Not a privilege escalation from nothing — it is a **containment failure**, and a
deviation from a normative clause that says "R2 in full" without an ownership exception. The
in-code rationale at [`guards.rs:117-128`](src/api/guards.rs#L117-L128) argues ownership should
confer content authority, which is a coherent product position; it is nonetheless a position the
specification does not currently grant, and `RBAC_MODEL.md:10-11` states the specification wins.

**The peer does not have this gap** — see §1.3.

---

#### **SHE-2 — `LOW` — No refusal when the caller's own key lies inside the subtree being deleted**

**The code.** [`keys.rs:846`](src/api/keys.rs#L846) refuses `id == key.id`, which covers the direct
case. It does not check whether the caller appears among the *descendants* collected at
[`keys.rs:858`](src/api/keys.rs#L858).

**Reachability.** Only through a cycle in `parent_key_id`, which the API cannot create — every
create path sets the parent to an existing key. It requires a direct database edit or a restore from
a corrupted dump. The traversal itself is safe: `descendant_key_ids`
([`keys.rs:92-112`](src/api/keys.rs#L92-L112)) carries a `seen` set and terminates.

**Impact.** In that state the caller deletes its own credential mid-request. No authorization
boundary is crossed; the outcome is lockout, not escalation.

**The peer refuses it explicitly** (`keys.rs:774`), with the reasoning recorded. Reported as a parity
gap, not a vulnerability.

---

### 1.2 Non-findings — attacks attempted against Subject A that failed

Recorded because a clean-room report is only meaningful if the negative results are visible.

| Attempted | Result | Where it is stopped |
| :--- | :--- | :--- |
| Mint a second Master via `is_master` in a key payload | **Refused** — the field does not exist on `CreateApiKeyPayload`/`UpdateApiKeyPayload`, and `deny_unknown_fields` makes its absence a `400` | `keys.rs:312`, `keys.rs:609` |
| Mint a second Master via direct SQL with a NULL marker | **Refused** — `master_marker` is `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a unique index | `m20230106_000001` |
| Parent grants itself `can_manage_keys` | **Refused** for every non-master, without consulting the target's current value | `guard_master_to_grant_scopes`, `guards.rs:378` |
| Parent grants a verb on a hook it does not hold | **Refused** per verb | `guard_delegated_hook_grant`, `guards.rs:806` |
| Trade a held verb for an unheld one in a single write | **Refused** — the write classifies as a grant, not a reduction | `is_permission_reduction`, `guards.rs:756` |
| Reach R2 through the general update endpoint instead of the grant route | **Refused** — both routes classify through the same function (R6, final sentence) | `keys.rs:1124`, `keys.rs:1243` |
| Probe which hooks exist via `403`/`404` | **Refused** — no row ⇒ `404`; row but no global conjunct ⇒ `403` | `verb_denied`, `guard_hook_manage_conjunction` |
| Probe key UUIDs on the permission routes | **Refused** — `has_permission_admin_standing` runs before any `find_by_id` | `keys.rs:1086`, `keys.rs:1224` |
| Rotate or delete the Master through the API | **Refused for every caller, including Master**, and not resting on the uniqueness index | `refuse_master_lifecycle_action`, `guards.rs:452` |
| Edit any Master field other than `bound_ips` | **Refused**, including by the Master itself | `guard_master_self_edit_is_bound_ips_only`, `guards.rs:484` |
| Delete a key and silently orphan its hooks | **Refused** — §6 inventory, total resolution map, and reassignment into the doomed subtree rejected | `keys.rs:858-922` |
| Forge `client_ip` / defeat `bound_ips` via `X-Forwarded-For` | **Refused** — `TRUSTED_PROXIES` is empty by default, meaning "believe no forwarding header" | `config.rs:526-534` |
| Bypass `bound_ips` by holding the Master key | **Refused** — no `is_master` exemption in the CIDR check | `middleware.rs:387` |
| Distinguish "wrong key" from "right key, wrong network" | **Refused** — CIDR is evaluated only after the key resolves and the signature verifies | `middleware.rs:194-198`, `:387` |
| Assign `run_as_user` without Master | **Refused**, and checked before payload validation so the `403` is not masked | `normalize_run_as_user`, `guards.rs:344` |
| Restore a trashed privileged hook | **Refused** — master-only | `hooks.rs:634` |

### 1.3 Findings — `simply_ip_vault` (Subject B)

---

#### **SIV-1 — `LOW` — `DeleteKeyPayload` does not reject unknown fields**

**The code.** `example/simply_ip_vault/src/api/keys.rs:651-657`:

```rust
#[derive(Deserialize, Default)]          // ← no deny_unknown_fields
pub struct DeleteKeyPayload {
    #[serde(default)]
    pub resolutions: Vec<ResolutionEntry>,
}
```

`CreateApiKeyPayload` (`:153`) and `UpdateApiKeyPayload` (`:931`) both carry the attribute; this one
does not.

**Impact.** A caller misspelling the field — `{"resolution": [...]}` — has its map silently dropped.
**The request then fails safe**: `keys.rs:783` sees an empty `resolutions` against a non-empty
inventory and returns the `409` inventory rather than deleting anything. The defect is diagnostic
quality, not a bypass: the caller is told "you sent no resolutions" instead of "that field does not
exist", which is a materially harder debugging session on a destructive endpoint.

**Note on feasibility.** The attribute belongs on `DeleteKeyPayload`, which has no `flatten`. It
could **not** be added to the nested `ResolutionEntry`, which uses `#[serde(flatten)]` — serde
rejects that combination. Worth stating so the fix is not attempted at the wrong level.

---

#### **SIV-2 — `INFORMATIONAL` — `ReassignOwnerPayload` documents a control it does not carry**

`example/simply_ip_vault/src/api/support.rs:270-281`. The doc comment argues the struct is shared
rather than duplicated because "two copies of a payload struct are two things to keep
`deny_unknown_fields` in step across" — and the struct derives only `Deserialize`.

**Impact.** None directly: the payload has one field, `owner_key_id`, and an unknown sibling confers
nothing. It is reported because a comment naming an attribute is what a later reviewer greps for when
asking whether the surface is strict, and this one answers yes when the code says no.

---

### 1.4 Non-findings — attacks attempted against Subject B that failed

| Attempted | Result | Where it is stopped |
| :--- | :--- | :--- |
| Grant any of the three global scopes as a non-master | **Refused** — `MASTER_ONLY_SCOPES` covers `can_manage_keys`, `can_create_groups`, `can_manage_webhooks`; all three checked | `guard_scope_elevation`, `guards.rs:373` |
| Manage a group's grants with `can_manage` but no `can_manage_keys` | **Refused** — explicit conjunction | `guard_group_manage`, `guards.rs:171` |
| Delete a group by holding operational verbs on it | **Refused** — lifecycle is owner-or-Master only; unowned ⇒ Master only | `guard_resource_lifecycle`, `guards.rs:89` |
| Edit a webhook's `target_url` after `can_manage_webhooks` is revoked | **Refused** — the standing scope is re-checked on every edit, *then* ownership | `webhooks.rs:354` **and** `:367` |
| Read another tenant's webhook via a shared group | **Refused** — creator-private, `404` for non-owners | `webhooks.rs:367`, `:568` |
| Submit a partial resolution map | **Refused**, with the unresolved set returned | `keys.rs:812-826` |
| Reassign an orphan-to-be into the doomed subtree | **Refused** | `keys.rs:844-849` |
| Delete a key whose subtree contains the caller | **Refused** — explicit cycle guard | `keys.rs:774` |
| Mint a second Master | **Refused** — engine-generated marker, same design as A | `m20260808_000009` |

---

## 2. Security parity — control by control

### 2.1 RBAC rules R1–R7

| Rule | Subject A — implementation | Subject B — implementation | Parity |
| :--- | :--- | :--- | :--- |
| **R1** non-amplification | `guard_delegated_hook_grant` — per-verb `wanted && !held` over 3 verbs | `guard_delegated_group_grant` — per-verb over 4 verbs | ✅ Same shape |
| **R2** conjunction | `guard_hook_manage_conjunction` — `!can_manage_keys → deny`, then `!row.can_manage → deny` | `guard_group_manage` — `can_manage_keys && perm.can_manage` | ✅ Same predicate |
| R2 evaluation points | **One** | **One** | ✅ No second implementation to drift |
| R2 governs dispatch config | ⚠️ **Bypassed by ownership** (**SHE-1**) | ✅ N/A — dispatch config is a creator-private entity, and its edit path re-checks the standing scope | ⚠️ **Divergent** |
| **R3** lineage confers nothing | No authorization read of `parent_key_id`; used only for subtree walks and visibility | Same | ✅ |
| **R4** only Master mints parents | `guard_master_to_grant_scopes` — 2 scopes | `guard_scope_elevation` — 3 scopes, `MASTER_ONLY_SCOPES` | ✅ Complete on both |
| R4 idempotent re-assertion | **Refused** for non-master regardless of target's current value | **Permitted** when the target already holds it (`held` baseline) | ⚠️ A stricter; both spec-compliant (re-asserting grants nothing) |
| **R5** sideways propagation | Bounded by R1 + R2; global scopes unreachable to non-master | Same | ✅ |
| **R6** revocation ≠ escalation | `is_permission_reduction` classifies before R1 is applied; both routes agree | `widens_permissions`, same role | ✅ Logical inverses, same behaviour |
| **R7** R1 ∧ R2 simultaneously | R2 is the entry gate, R1 layered on the row it returns | Identical composition | ✅ |

### 2.2 Specification sections §3–§7

| Section | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| **§3** lifecycle = Master ∪ owner | `guard_lifecycle_authority`; rename grouped with delete | `guard_resource_lifecycle`; rename folded into the ownership test | ✅ |
| §3 unowned ⇒ Master-only | ✅ | ✅ | ✅ Same conservative direction |
| §3 owner recorded on create | `owner_key_id = creator` **unconditionally**, including Master | `resource_owner()` returns `None` for Master — "a master is not a tenant" | ⚠️ Semantic divergence, no security impact (Master is undeletable, and §3 admits it anyway) |
| §3 Master may reassign | ✅ non-master refused, dangling target refused | ✅ `resolve_owner_assignment`, master refused as owner | ✅ |
| **§4** invisible ⇒ `404` | `verb_denied`, `guard_visibility`, `may_read_execution` | `404` on non-owned creator-private entities | ✅ |
| §4 visible-but-short-a-verb ⇒ `403` | ✅ | ✅ | ✅ |
| §4 pre-gate before any `find_by_id` | `has_permission_admin_standing` | `holds_any_group_manage` — deliberately the weaker half | ✅ Same reasoning |
| §4 creator-private entity | Execution records — 4 routes, `404` otherwise | Webhook configs — owner ∪ Master, `404` otherwise | ✅ |
| §4 authn-before-authz ordering | Key lookup → signature → **then** `bound_ips` | Same | ✅ |
| **§5** engine-derived marker | `GENERATED ALWAYS AS`, unique index, dialect split pinned | Same construction | ✅ |
| §5 marker unwritable | Not a settable field anywhere | Same | ✅ |
| §5 `is_master` absent from payloads | ✅ **type-level**, both payloads | ✅ type-level, both payloads | ✅ |
| §5 Master immutable but `bound_ips` | `guard_master_self_edit_is_bound_ips_only` — 5 fields enumerated | `guard_master_immutable` | ✅ |
| §5 rotation refused for all | ✅ including Master itself | ✅ | ✅ |
| §5 deletion not resting on the index | ✅ stated and separately enforced | ✅ | ✅ |
| §5 adversarial write tested | 3 `s5_adversarial_*` tests | `s5_the_derived_marker_is_unwritable_by_any_client` | ✅ Both attack, neither cooperates |
| §5 runtime pin | `MasterPin` — 6 methods | Identical 6-method API | ✅ |
| **§6** recursive cascade | `descendant_key_ids`, cycle-safe | `collect_key_subtree`, cycle-safe | ✅ |
| §6 inventory returned on refusal | `409` + `ConflictWithDetails` | `409` + `ConflictWithDetails` | ✅ Same variant |
| §6 partial map refused | ✅ | ✅ | ✅ |
| §6 stray resolution refused | ✅ | ✅ + duplicate-entry refusal | ✅ |
| §6 reassign into doomed subtree | ✅ refused | ✅ refused | ✅ |
| §6 caller inside subtree | ⚠️ **not checked** (**SHE-2**) | ✅ refused | ⚠️ B stricter |
| **§7** required indexes | Pinned by `s7_every_required_index_and_constraint_exists` | Pinned by `s7_the_schema_carries_the_required_constraints_and_indexes` | ✅ |
| §7 FK equivalent tested in CI | `referential_integrity.rs` — 6 tests | `schema_integrity_tests.rs` — 16 tests | ⚠️ Both have suites; **neither runs in CI** (**ECO-2**) |

### 2.3 Cryptography and session integrity

| Control | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| Credential storage | SHA-256 → `key_hash`; single lookup path | Same | ✅ |
| Signing secret at rest | XChaCha20-Poly1305, 24-byte random nonce | Identical construction | ✅ |
| MAC comparison | `Mac::verify_slice` — constant-time | Same primitive, same file | ✅ |
| `==` on MAC/digest anywhere | Absent — gate-asserted in `crypto.rs` and `middleware.rs` | Absent, same gate | ✅ |
| Canonical signed string | `canonical_v1_payload` | `canonical_v1_payload` | ✅ **Byte-identical**, gate-enforced |
| Replay ledger | `replay.rs` — never flushed, throttled sweep, digests keyed as raw bytes | Same invariants, same gates | ✅ |
| Forwarding-header trust | `TRUSTED_PROXIES` empty by default = believe nothing | Same default | ✅ |
| Signature max age | Configurable, validated | Configurable, validated | ✅ |

### 2.4 Database constraints and isolation

| Control | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| SQLite pragmas | `foreign_keys=ON`, WAL, `synchronous=NORMAL`, `busy_timeout=5000` | Identical set | ✅ Gate-enforced byte-identical |
| Applied via connect options | Yes — replayed on recycled connections | Yes | ✅ |
| Pool size | `SQLITE_MAX_CONNECTIONS = 1` | Same constant, same value | ✅ |
| Audit FK on key deletion | `ON DELETE SET NULL` | `ON DELETE SET NULL` | ✅ |
| Audit attribution nullability | `api_key_name`, `api_key_prefix`, `client_ip` **NOT NULL** | **NOT NULL** | ✅ |
| Unattributed audit write expressible? | **No** — writer takes `&api_key::Model` and `IpAddr` by value | **No** — identical signature | ✅ |
| Raw SQL outside migrations/pragmas | Banned; 2 allowlist entries, none in `src/api/` | Banned; 2 entries, none in `src/api/` | ✅ |
| Test enforcing "no handler is exempt" | ❌ absent | ✅ `no_handler_is_ever_exempted` | ⚠️ B stricter |

### 2.5 Payload and input strictness

`deny_unknown_fields` is a §5 control on both sides: it is what makes the *absence* of `is_master`
from the key payloads a refusal rather than a silent drop.

| Payload | Subject A | Subject B | Parity |
| :--- | :--- | :--- | :--- |
| Key create | `CreateApiKeyPayload` ✅ | `CreateApiKeyPayload` ✅ | ✅ |
| Key update | `UpdateApiKeyPayload` ✅ | `UpdateApiKeyPayload` ✅ | ✅ |
| Key delete (§6 map) | `DeleteApiKeyPayload` ✅ + `EntityResolution` ✅ | `DeleteKeyPayload` ❌ | ⚠️ **SIV-1** |
| Owner reassignment | Field on `UpdateHookPayload` — not strict | `ReassignOwnerPayload` — not strict (**SIV-2**) | ✅ Same posture |
| Domain resource payloads | 3 payloads, not strict | 5 payloads, not strict | ✅ Same deliberate policy |
| Strict extractor | `StrictJson` / `OptionalStrictJson` | Same names, same semantics | ✅ |
| Body ceiling | `MAX_REQUEST_BODY_BYTES = 3 * 1024 * 1024`, set once router-wide | Identical name and value | ✅ Gate-enforced |
| Dashboard cannot send `is_master` | `the_dashboard_never_sends_is_master_in_a_key_payload` | No equivalent | ⚠️ A stricter |
| Field-level validation | CIDR parse, absolute-path + traversal + NUL checks, timeout bounds, `param_key` regex | CIDR parse, URL scheme allowlist (`http`/`https`), IP/CIDR normalisation | ✅ Equivalent rigour, domain-appropriate |

---

## 3. Ecosystem-level findings

| # | Severity | Finding | Evidence |
| :--- | :--- | :--- | :--- |
| **ECO-1** | `MEDIUM` (process) | **The peer's drift gate is inert.** `simply_ip_vault/scripts/verify_convergence.sh` sets `PEER_ROOT="$PROJECT_ROOT/example/simply_hook_executor"`, a directory that does not exist in that clone. Running it prints `SKIP peer service not found …` and **exits `0`** — reporting success while comparing nothing | Ran it. Exit code `0`, zero comparisons |
| **ECO-2** | `MEDIUM` (process) | **Neither CI pipeline runs any gate.** Both repositories ship exactly two workflows — `.github/workflows/docker-publish.yml` and `.forgejo/workflows/update-readme-each-month.yml` — and neither invokes `cargo test`, `test_e2e.sh` or `verify_convergence.sh`. §7's "a constraint that holds only in production is one CI never checks" is therefore **not satisfied by either service**, despite both having the suites written | `grep -rl 'cargo test\|verify_convergence\|test_e2e' .github .forgejo` → no matches, both sides |

`ECO-2` is the one finding in this report that the specification names directly. Both services have
built the tests §7 requires; neither has wired them to run automatically.

---

## 4. Findings summary

| # | Severity | Subject | Finding | Fix |
| :--- | :--- | :--- | :--- | :--- |
| **SHE-1** | `MEDIUM` | A | Ownership bypasses R2 on `script_path` edits; revoking `can_manage_hooks` does not contain the key | Re-check `can_manage_hooks` (or R2 in full) on the ownership route of `guard_manage`, matching the peer's `update_webhook`. Set `ALLOWED_SCRIPT_ROOTS` as interim defence in depth |
| **ECO-1** | `MEDIUM` | Both | Peer's convergence gate compares nothing and exits `0` | Clone A into the peer's `example/`; make a missing peer non-zero |
| **ECO-2** | `MEDIUM` | Both | No CI job runs any test or gate | Add one shared workflow. The scripts already exit non-zero correctly |
| **SIV-1** | `LOW` | B | `DeleteKeyPayload` lacks `deny_unknown_fields`; a typo'd field is dropped silently (fails safe) | One attribute on `DeleteKeyPayload` — not on the `flatten`ed `ResolutionEntry` |
| **SHE-2** | `LOW` | A | No refusal when the caller's key is inside the subtree being deleted | Port the peer's `subtree.contains(&key.id)` check |
| **SIV-2** | `INFO` | B | `ReassignOwnerPayload` doc cites a control the struct lacks | Add the attribute or correct the comment |

---

## 5. Verification performed

| Check | Command | Result |
| :--- | :--- | :--- |
| Peer freshness | `git pull` in `example/simply_ip_vault` | `6f1c4c7` → **`c182a7a`** (docs only) |
| Normative identity | `md5sum RBAC_MODEL.md` × 2 | Identical — `cb0b76ab…` |
| Subject A suite | `cargo test` | **285 passed / 0 failed**, 8 binaries |
| Subject A convergence gate | `./scripts/verify_convergence.sh` | 19 converged, 0 known, 0 drifted, 0 skipped — exit `0` |
| Subject B convergence gate | `bash scripts/verify_convergence.sh` in the peer | **`SKIP`**, exit `0`, nothing compared (**ECO-1**) |
| CI gate coverage | `grep -rl 'cargo test\|verify_convergence\|test_e2e' .github .forgejo` | No matches on either side (**ECO-2**) |

Subject B's test suite was **not executed**: the peer checkout has no build artifacts, and compiling
it would be the only mutation this read-only pass made. Every claim about B is sourced from its
committed `.rs` files at the line numbers cited.

---

## 6. Executive verdict — security

| Dimension | Verdict |
| :--- | :--- |
| Specification coverage | **Complete on both sides.** Every rule R1–R7 and every clause of §3–§7 has identifiable enforcing code in both services |
| Critical vulnerabilities | **None.** No path was found on either side to mint a second Master, escalate to `can_manage_keys`, bypass the R2 conjunction for *delegation*, defeat `bound_ips`, forge a signature, or replay one |
| Confirmed findings | **6** — one Medium and one Low against A, one Low and one Informational against B, two Medium process gaps shared |
| Highest-severity code finding | **SHE-1**, `MEDIUM`, against **this service**: ownership bypasses R2 on dispatch-configuration edits, so revoking `can_manage_hooks` does not contain the key. The peer's equivalent path re-checks the standing scope and is not exposed |
| Cryptographic parity | **Full.** Byte-identical canonicalization, identical AEAD construction, constant-time comparison, identical replay invariants — all gate-enforced |
| Database constraint parity | **Full.** Identical pragmas, identical pool pinning, engine-derived master marker on both, audit attribution `NOT NULL` and structurally unfalsifiable on both |
| Payload strictness parity | **Substantive**, with one real gap on B (**SIV-1**) that fails safe, and one stricter test on A |
| Oracle discipline | **Full on both.** `404`/`403` split implemented, and pre-gates placed before any id lookup on both sides |

**Security maturity: HIGH.** Both services enforce the specification comprehensively and in the same
shape, with single evaluation points for the rules that matter and adversarial rather than
cooperative tests behind them. Nothing found here is exploitable by an unprivileged caller.

Two things are worth acting on. **SHE-1** is the only finding with a concrete attack narrative, and
it belongs to this service: the specification's dispatch-configuration clause says R2 governs
`script_path` edits *in full*, the code admits ownership as a third route, and the practical
consequence is that a revoked `can_manage_hooks` does not take back what it granted. The peer already
implements the stricter form and is the model to copy. **ECO-2** is the only finding the
specification names outright — §7 requires the DDL-inexpressible constraints to be covered by a test
*that runs in CI*, and on both sides those tests exist but nothing runs them automatically. Until
that is wired, every guarantee in this report is a fact about a tree someone remembered to check by
hand.
