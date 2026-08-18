# Ecosystem Security Audit — `simply_hook_executor` vs. all peers

**Date:** 2026-08-18
**Method:** clean-room. Every finding was derived from `RBAC_MODEL.md` and the current `.rs` source of
the four trees. No previous audit report was opened, in any repository.
**Mode:** read-only over all application code. No file under `src/`, `tests/`, `migration/`,
`scripts/` or `static/` was modified anywhere. `RBAC_MODEL.md` is untouched.

| Ref | Project | Path | Commit |
| :--- | :--- | :--- | :--- |
| **A** | `simply_hook_executor` — *this service* | repository root | `15b8af6` |
| **B** | `simply_ip_vault` | `example/simply_ip_vault` | `14c8fa3` |
| **C** | `simply_ip_exporter` | `example/simply_ip_exporter` | `80a3b31` |
| **D** | `simply_ip_sync` | `example/simply_ip_sync` | `72cce13` |

**A and B are the gold standard.** They are the two services `RBAC_MODEL.md` names, the pair whose
convergence the ecosystem was designed around, and the only two whose shared logic is enforced
byte-identical by a script. C and D are measured against that bar, and where they fall short of it the
question asked is always *does this weaken a control, or is it a domain difference?*

---

## 0. Task 0 — peer repository update

Every checkout under `example/` was pulled before a single source file was read.

| Project | `git pull --ff-only` | Before → after | Tree |
| :--- | :--- | :--- | :--- |
| `simply_ip_vault` | Already up to date | `14c8fa3` | clean |
| `simply_ip_exporter` | **Updated** | `52651e5` → **`80a3b31`** | clean |
| `simply_ip_sync` | **Updated** | `c283911` → **`72cce13`** | clean |

Two of three peers had moved. The pull was not a formality: an audit of the trees as they sat on disk
would have described two revisions that no longer existed.

---

## 1. The normative baseline, and who is inside it

| Project | `RBAC_MODEL.md` md5 | Scope line | Implements the tier/R2 model it carries? |
| :--- | :--- | :--- | :--- |
| **A** | `cb0b76ab…` | *"`simply_ip_vault` and `simply_hook_executor`"* | ✅ Yes |
| **B** | `cb0b76ab…` | Identical | ✅ Yes |
| **C** | `cb0b76ab…` | Identical — **does not name the repository carrying it** | ❌ **No** — see **EXP-1** |
| **D** | `792fb269…` | *"Normative specification for this service … `simply_ip_sync` is not in that document's stated scope"* | ✅ Yes, in its own terminology |

**D handles being outside the shared scope correctly**: it restates the model with its own nouns and
says so in the header. **C ships the byte-identical shared document** whose Scope line governs two
*other* services — and, as §2.1 shows, does not implement the three-tier model that document
specifies. An agent working in C is reading a specification that neither claims to apply to it nor
matches the code in front of it. This is the root of **EXP-1** and **EXP-2** below.

---

## 2. Zero-knowledge security assessment

Each rule was traced to its enforcing code in each tree, then attacked. Negative results are recorded
in §2.5 — an audit that lists only what it found is indistinguishable from one that did not look.

### 2.1 The authorization model actually implemented

| Property | A | B | C | D |
| :--- | :---: | :---: | :---: | :---: |
| Dedicated `api/guards.rs` | ✅ 21 fns | ✅ 12 fns | ❌ **absent** (`api/auth.rs`, 1 fn: `get_me`) | ✅ 12 fns |
| Per-resource permission table | `api_key_hook_permission` | `api_key_group_permission` | ❌ **none** | `api_key_sync_permission` |
| **R2 conjunction implemented** | ✅ `guard_hook_manage_conjunction` | ✅ `guard_group_manage` | ❌ **not representable** | ✅ `guard_resource_manage` |
| **Parent tier functional** (`can_manage_keys` read as an input) | ✅ | ✅ | ❌ **never read** — see **EXP-1** | ✅ |
| R4 — only Master grants global scopes | ✅ `guard_master_to_grant_scopes` | ✅ `guard_scope_elevation` (3 scopes) | ✅ trivially — all key routes are `require_master` | ✅ `guard_scope_elevation` |
| §3 lifecycle = Master ∪ owner | ✅ `guard_lifecycle_authority` | ✅ `guard_resource_lifecycle` | ✅ inline on `endpoints.rs` | ✅ `guard_resource_lifecycle` |
| §5 engine-derived master marker | ✅ | ✅ | ✅ | ✅ |
| §5 `MasterPin` runtime identity | ✅ 6 methods | ✅ 6 methods | ✅ 6 methods | ✅ 6 methods |

**A, B and D implement the specification's three-tier model. C implements a two-tier model** — Master
and everyone else — and carries the columns of the third tier without wiring them to anything.

### 2.2 Findings against **A** — `simply_hook_executor`

---

#### **SHE-1 — `MEDIUM` — Ownership bypasses the R2 conjunction on dispatch configuration**

**Rule.** `RBAC_MODEL.md`, *Dispatch configuration*: where that configuration lives on a shared
managed resource — for this service, `script_path` and `run_as_user` on the Hook row — *"editing it is
a management action on that resource and is governed by **R2 in full**."*

**The code.** `src/api/guards.rs` — `guard_manage` returns before R2 is consulted:

```rust
if key.is_master { return Ok(()); }
if hook.owner_key_id == Some(key.id) { return Ok(()); }   // ← R2 never reached
guard_hook_manage_conjunction(db, key, hook.id).await?;
```

`update_hook` is gated by that function and writes `script_path` from the payload. Neither
`can_manage_keys` nor `can_manage_hooks` is re-read on this path.

**Reachability.** Every step is an ordinary API call.

| # | Actor | Action | Effect |
| :--- | :--- | :--- | :--- |
| 1 | Master | Grants a Daughter `can_manage_hooks` | Legitimate — R4 |
| 2 | Daughter | `POST /api/hooks` | `owner_key_id = self`; `grant_full_hook_permission` sets `can_execute`, `can_manage`, `can_view_execution` all `true` |
| 3 | Master | **Revokes `can_manage_hooks`** — the containment action | Scope cleared. **Ownership and the permission row are untouched** |
| 4 | Daughter | `PUT /api/hooks/{id}` with a new `script_path` | **Accepted**, via the ownership route |
| 5 | Daughter | `POST /api/hooks/{id}/execute` | Runs |

`allowed_script_roots` defaults to empty and `executor::is_within_roots` reads empty as *permit every
path* (`roots.is_empty() || …`), so step 4 may name any absolute, traversal-free path on the host.

**Impact.** Revoking `can_manage_hooks` does not contain the key. A second route reaches the same
place: §3 lets Master reassign `owner_key_id` to any key, conferring `script_path` write access on a
key holding no `can_manage_keys` at all.

**What bounds it.** `guard_master_for_privileged_hook` makes any hook carrying `run_as_user`
master-only to modify at all, so the escalation cannot cross into another OS account; hooks are never
spawned through a shell; `ALLOWED_SCRIPT_ROOTS` closes it when set; and a key *currently* holding the
scope could set the same path at creation. The delta is **persistence after revocation**.

**B, C and D all take the opposite approach on the same question.** Each re-checks the standing scope
before the ownership test:

| Service | Dispatch-target edit path | Standing scope re-checked? |
| :--- | :--- | :---: |
| **A** | `update_hook` → `guard_manage` | ❌ ownership alone suffices |
| **B** | `update_webhook` | ✅ `can_manage_webhooks`, then ownership |
| **C** | `update_endpoint` | ✅ master-or-owner, no standing scope exists to bypass |
| **D** | `guard_resource_manage` | ✅ R2 in full |

A is the only service in the ecosystem where a revoked resource-creation right leaves standing write
access to what the service executes.

---

#### **SHE-2 — `LOW` — No refusal when the caller's own key lies inside the subtree being deleted**

`src/api/keys.rs` refuses `id == key.id` but does not check whether the caller appears among the
*descendants* collected by `collect_subtree_inventory`. B refuses exactly that
(`if subtree.contains(&key.id)`). Reachable only through a `parent_key_id` cycle, which the API cannot
create — it needs a direct database edit. The traversal itself is cycle-safe. Outcome is lockout, not
escalation.

### 2.3 Findings against **C** — `simply_ip_exporter`

---

#### **EXP-1 — `LOW` today, latent escalation — `can_manage_keys` is stored and advertised but never read**

**The code.** All five key-administration routes in `src/api/keys.rs` gate on one helper:

```rust
fn require_master(key: &api_key::Model) -> Result<(), AppError> {
    if key.is_master { Ok(()) } else { Err(AppError::Forbidden("Only the Master key can manage API keys")) }
}
```

`grep can_manage_keys` across `src/` returns only writes and reads-for-display: it is set at creation,
settable on update, returned by `/api/auth/me` and by the key listing. **No code branches on it.**

**Impact today: none — the direction is fail-closed.** A key carrying `can_manage_keys: true` can
manage nothing. That is why this is `LOW`.

**Why it is nonetheless reported.** Two reasons, and the second is the one that matters:

1. **It is a misleading control.** An operator reading `/api/auth/me` sees `can_manage_keys: true` and
   reasonably concludes the key is a key manager. It is not. A security flag that reports authority it
   does not confer is worse than an absent one.
2. **It is a trap for the next commit.** The day somebody wires `can_manage_keys` into a gate — the
   obvious change, since the column exists and the tier is in the specification C ships — *every key
   that already carries `true` silently becomes a Parent*. Those grants were handed out when they
   meant nothing, so no operator ever reviewed one, and no audit entry reads as a privilege decision.
   The escalation would arrive with no event to point at.

**Recommendation:** either implement the tier (matching A/B/D) or drop the column and the payload
field. Carrying an unenforced privilege flag is the worst of the three options.

---

#### **EXP-2 — `LOW` — No `deny_unknown_fields` anywhere; `is_master` is silently ignored rather than refused**

`grep -rc deny_unknown_fields src/` returns **0** for C, against 6 (A), 5 (B) and 10 (D).

`RBAC_MODEL.md` §5 requires that *"removing the field from the payload type is required; rejecting it
at the handler is not sufficient."* **C satisfies that literal requirement** — `is_master` is absent
from `CreateKeyPayload`, and `is_master: Set(false)` is hardcoded at creation. There is **no
escalation path**.

What is missing is the refusal. `POST /api/keys` with `{"name":"x","is_master":true}` returns **`200`
and an ordinary key**: serde ignores the unknown field, the caller believes it minted a Master, and
nothing anywhere records that the attempt was made. A, B and D all treat `deny_unknown_fields` as the
§5 control precisely so that attempt becomes an explicit `400` naming the field — a logged, visible
refusal instead of silence.

---

#### **EXP-3 — `INFO` — `api_keys.owner_key_id` is dormant**

The column is written at key creation and **never read as an authorization input** anywhere in `src/`.
A carried the identical dormant column and dropped it (`m20260810_000001`) precisely because a
populated column that no rule consults invites a future reader to assume it is load-bearing. Same
recommendation.

### 2.4 Findings against **B** and **D**

---

#### **SIV-1 — `LOW` (contract) — B: most refusals produced before a handler runs are not in the error envelope**

| Service | Extractors wrapped | Bare extractor positions left in handlers |
| :--- | :--- | ---: |
| **A** | `StrictJson`, `OptionalStrictJson`, `StrictPath`, `StrictQuery`, `StrictBytes` | **0** |
| **B** | `StrictJson`, `OptionalStrictJson` | **25** |
| **C** | `StrictJson`, `StrictPath` | **1** |
| **D** | `StrictJson`, `StrictPath`, `StrictQuery` | **0** |

On B, an unparseable UUID path parameter, a mistyped query value and a malformed body on any route
not using `StrictJson` are refused with the right status and a bare `text/plain` body carrying no
`error` field. `AppError::BodyRejected` already exists in B's `error.rs` — this is an unfinished
rollout, not a design disagreement. No authorization is bypassed, hence `LOW`.

**Sharper half:** B's own `concurrency_and_contracts.rs` asserts the refusal *status* with **zero**
`Content-Type` assertions, so its suite reports the property covered while the body shape goes
unchecked.

---

#### **SIV-2 — `LOW` — B: `DeleteKeyPayload` does not reject unknown fields**

B's `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `BatchRecordInput` and `BatchRecordsPayload` all
carry the attribute; `DeleteKeyPayload`, which carries the §6 resolution map, does not. A misspelled
`resolutions` is silently dropped — but the request then **fails safe**, returning the `409` inventory
rather than deleting anything. Diagnostic quality on a destructive endpoint. The attribute belongs on
`DeleteKeyPayload`; it **cannot** go on the `flatten`ed `ResolutionEntry`, which serde forbids.

---

#### **SYN-1 — `LOW` — D: audit attribution is nullable at the column**

| Column | A | B | C | **D** |
| :--- | :--- | :--- | :--- | :--- |
| `api_key_name` | `String` | `String` | `String` | **`Option<String>`** |
| `api_key_prefix` | `String` | `String` | `String` | **`Option<String>`** |
| `client_ip` | `String` | `String` | `String` | **`Option<String>`** |

`api_key_id` is `ON DELETE SET NULL` on all four — deliberately, so deleting a credential never erases
what it did. That makes the denormalized name and prefix the *only* attribution that survives the key.
On D the schema permits a row that has lost both.

**Graded `LOW`, not higher, because D's writer cannot currently produce one:** `create_audit_log` takes
`&api_key::Model` and `IpAddr` **by value**, so no call site can pass `None`. The guarantee therefore
rests entirely on that one signature. A, B and C close it at the column, where a migration backfill, a
raw insert, or a second writer added later cannot get around it.

---

#### **SYN-2 — `INFO` — D ships no `verify_convergence.sh`**

A, B and C each carry one. D has `test_e2e.sh` only, so its structural alignment with the ecosystem is
maintained by review rather than by a gate.

### 2.5 Attacks attempted that held

| Attempted | A | B | C | D |
| :--- | :---: | :---: | :---: | :---: |
| Mint a second Master via a key payload | ✅ refused (`400`, field named) | ✅ refused | ⚠️ **ignored, `200`** (**EXP-2**) | ✅ refused |
| Mint a second Master via direct SQL with a NULL marker | ✅ engine-generated marker + unique index | ✅ | ✅ | ✅ |
| Read `is_master` off a response and write it back | ✅ N/A — `Serialize`-only views | ✅ | ✅ | ✅ |
| Non-master grants a global scope | ✅ | ✅ (3 scopes) | ✅ (all routes master-only) | ✅ |
| Grant a verb the caller does not hold | ✅ per-verb | ✅ per-verb | N/A — no verbs | ✅ per-verb |
| Reach R2 through a general update endpoint | ✅ same classifier both routes | ✅ | N/A | ✅ |
| Probe existence via `403`/`404` | ✅ `404` when invisible | ✅ | ✅ | ✅ |
| Rotate or delete the Master through the API | ✅ refused for **all**, incl. Master | ✅ | ✅ | ✅ |
| Edit a Master field other than `bound_ips` | ✅ | ✅ | ✅ | ✅ |
| Bypass `bound_ips` by holding the Master key | ✅ no exemption | ✅ | ✅ | ✅ |
| Forge `client_ip` via `X-Forwarded-For` | ✅ empty `TRUSTED_PROXIES` = trust nothing | ✅ | ✅ | ✅ |
| Replay a captured signature | ✅ single-use ledger, never flushed | ✅ | ✅ | ✅ |

---

## 3. Security parity — control by control

### 3.1 Cryptography

| Control | A | B | C | D |
| :--- | :---: | :---: | :---: | :---: |
| Credential storage — SHA-256 → `key_hash` | ✅ | ✅ | ✅ | ✅ |
| Signing secret at rest — XChaCha20-Poly1305 | ✅ | ✅ | ✅ | ✅ |
| Constant-time MAC compare — `Mac::verify_slice` | ✅ | ✅ | ✅ | ✅ |
| `==` on MAC/digest anywhere | ✅ absent | ✅ absent | ✅ absent | ✅ absent |
| `canonical_v1_payload` | ✅ | ✅ byte-identical (gate) | ✅ | ✅ |
| Replay ledger, never flushed | ✅ | ✅ | ✅ | ✅ |
| `MasterPin` — 6-method API | ✅ | ✅ | ✅ | ✅ |

**Full cryptographic parity across all four.** This is the most uniform layer in the ecosystem, and
the only one with no finding against any project.

### 3.2 Database constraints

| Control | A | B | C | D |
| :--- | :---: | :---: | :---: | :---: |
| §5 marker engine-derived (`GENERATED ALWAYS`) | ✅ | ✅ | ✅ | ✅ |
| SQLite pragmas (`foreign_keys`, WAL, `synchronous`, `busy_timeout`) | ✅ | ✅ | ✅ | ✅ |
| Audit FK `ON DELETE SET NULL` | ✅ | ✅ | ✅ | ✅ |
| Audit attribution `NOT NULL` | ✅ | ✅ | ✅ | ❌ **SYN-1** |
| Unattributed audit write inexpressible in the writer | ✅ by-value | ✅ by-value | ✅ by-value | ✅ by-value |
| Dormant `api_keys.owner_key_id` | ✅ dropped | ✅ never existed | ❌ **EXP-3** | ✅ never existed |

### 3.3 Payload and input strictness

| Control | A | B | C | D |
| :--- | :---: | :---: | :---: | :---: |
| `deny_unknown_fields` occurrences | **6** | 5 | **0** (**EXP-2**) | **10** |
| Key create / update strict | ✅ / ✅ | ✅ / ✅ | ❌ / ❌ | ✅ / ✅ |
| Key delete (§6 map) strict | ✅ | ❌ (**SIV-2**) | N/A | ✅ |
| `is_master` absent from the payload type | ✅ | ✅ | ✅ | ✅ |
| Extractor rejections in the error envelope | **5 of 5** | 2 of 5 (**SIV-1**) | 2 of 3 | **3 of 3** |
| Envelope asserted with `Content-Type` in tests | ✅ | ❌ | — | — |

**D is the strictest input-handling service in the ecosystem** — ten strict payloads and complete
extractor coverage. **C is the least strict**, with none.

---

## 4. Findings summary

| # | Severity | Project | Finding |
| :--- | :--- | :--- | :--- |
| **SHE-1** | `MEDIUM` | **A** | Ownership bypasses R2 on `script_path` edits; revoking `can_manage_hooks` is not containment. The only service in the ecosystem that answers this question this way |
| **EXP-1** | `LOW` (latent) | C | `can_manage_keys` stored and advertised but never read — Parent tier absent. Fail-closed today; wiring it up would silently promote every key already carrying `true` |
| **EXP-2** | `LOW` | C | Zero `deny_unknown_fields`; an `is_master` in a payload is ignored with `200` rather than refused with `400` |
| **SIV-1** | `LOW` | B | 25 bare extractor positions → `text/plain` refusals; B's own test asserts status only |
| **SIV-2** | `LOW` | B | `DeleteKeyPayload` not strict (fails safe) |
| **SYN-1** | `LOW` | D | Audit attribution nullable at the column; the guarantee rests on one writer signature |
| **SHE-2** | `LOW` | **A** | No refusal when the caller's key is inside the subtree being deleted |
| **EXP-3** | `INFO` | C | Dormant `api_keys.owner_key_id` |
| **SYN-2** | `INFO` | D | No `verify_convergence.sh` |
| **ECO-1** | `INFO` | C | Ships the shared `RBAC_MODEL.md` whose Scope names two other services, and does not implement the tier model it specifies |

---

## 5. Executive verdict — security

| Dimension | Verdict |
| :--- | :--- |
| Critical vulnerabilities | **None, in any of the four projects.** No path was found to mint a second Master, self-grant a global scope, bypass R2 for delegation, defeat `bound_ips`, forge a signature, or replay one |
| Cryptographic parity | **Full across all four.** Identical primitives, identical canonicalization, identical replay invariants — the ecosystem's most uniform layer |
| §5 Master guarantees | **Full across all four.** Engine-derived marker, unique index, 6-method `MasterPin`, immutability and undeletability through the API |
| RBAC model parity | **A, B, D implement the specification's three tiers. C implements two** and carries the third tier's columns unwired (**EXP-1**) |
| Payload strictness | **Widest spread in the ecosystem**: D 10, A 6, B 5, **C 0** |
| Highest-severity finding | **SHE-1, `MEDIUM`, against this service** — and the ecosystem is the evidence: B, C and D all re-check the standing scope before ownership on the equivalent path, and A alone does not |
| Findings by project | **A: 2** (1 Medium, 1 Low) · **B: 2** (Low) · **C: 4** (2 Low, 2 Info) · **D: 2** (1 Low, 1 Info) |

**Ecosystem security maturity: HIGH for A, B and D; MODERATE for C.**

A, B and D enforce the specification comprehensively and in the same shape, with a single evaluation
point per rule and adversarial rather than cooperative tests behind them. Nothing found in any of the
four is exploitable by an unprivileged caller.

Two conclusions are worth stating plainly. **First, the finding with the clearest attack narrative
belongs to this service.** The specification governs `script_path` edits under R2 *in full*;
`guard_manage` admits ownership as a third route; and the practical consequence is that revocation
does not take back what it granted. Every other service in the ecosystem re-checks the standing scope
first, which is what makes this a defect rather than a defensible variation.

**Second, C's position is structural rather than accidental.** It has no `guards.rs`, no per-resource
permission table, no `deny_unknown_fields`, and a `can_manage_keys` column wired to nothing — while
shipping the normative document that specifies all of it. None of that is exploitable today, and every
one of those gaps fails closed. But a service carrying the columns of a model it does not implement is
one commit away from implementing it wrongly, and **EXP-1** is the specific shape that would take:
grants handed out when they meant nothing, becoming authority on the day someone reads them. The
recommendation is to decide explicitly — implement the tier, or remove its columns — rather than to
leave the ambiguity in place.
