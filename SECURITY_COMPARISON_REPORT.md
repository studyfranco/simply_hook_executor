# Final Comparative Security Audit — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-10
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository, and no commit was created.
**Subject A (this repo):** `simply_hook_executor` @ `20f2695`
**Subject B (peer):** `simply_ip_vault` — **the live sibling checkout** at
`/home/fallrik/Documents/workspaces/simply_ip_vault`
**Normative document:** `RBAC_MODEL.md`

This edition **replaces** the 2026-08-07 audit of `b5cf624` that previously occupied this file; that
edition is preserved in git history at `0689135`. Every finding below was verified against source at
the paths cited, and every claim inherited from the prior edition was re-tested rather than carried
forward — one of them did not survive (see §1, F2).

---

## 0. Reference provenance — and a correction to how prior audits were conducted

Previous audits in this repository compared against `example/simply_ip_vault`, a **vendored flat
snapshot**. This audit compared against the **live peer checkout** as well, and the two are not the
same tree.

| Probe | Result |
| :--- | :--- |
| `diff -rq example/simply_ip_vault/src ../simply_ip_vault/src` | **2 differences** — both files present in the snapshot only |
| Files stale in snapshot | `src/api/system.rs`, `src/webhooks.rs` — **deleted upstream**, still present locally |
| All other source files | **Byte-identical** — the snapshot is otherwise current |
| `md5sum RBAC_MODEL.md` × 3 (ours, snapshot, live peer) | **`cb0b76ab…` — identical across all three** |
| `verify_convergence.sh` peer source | `$REPO_ROOT/example/simply_ip_vault` — **the snapshot**, not the live tree |

### Impact assessment

| Question | Answer |
| :--- | :--- |
| Did staleness produce a **false green** on the convergence gate? | **No.** The three functions the gate diffs (`resolve_client_ip`, `canonical_v1_payload`, `apply_sqlite_pragmas`) are byte-identical between snapshot and live tree |
| Is the normative-document identity check valid? | **Yes.** `RBAC_MODEL.md` is identical in all three copies |
| Did staleness produce a **false finding**? | **Yes — twice, in this repository's own prior audit.** See below |
| Standing risk | The gate's `grep -r` rules scan `$PEER_ROOT/src` wholesale. An orphaned file deleted upstream can still satisfy a presence check or supply a stale value match |

### Two findings from the previous session that this audit retracts

Both originated from reading the orphaned `example/simply_ip_vault/src/api/system.rs`, which is
**not referenced by the peer's `api/mod.rs`** and is therefore dead code in the snapshot.

| Prior claim (2026-08-10, commit `20f2695` notes) | Actual state of the live peer | Verdict |
| :--- | :--- | :--- |
| "Theirs sit in `api/system.rs`; ours are in `api/health.rs`… Keeping ours." | The peer has `src/api/health.rs`, and `api/system.rs` **no longer exists**. Placement is **identical**, not divergent | **Retracted** |
| "The peer's readiness body includes `"master_pinned": true` — a hardcoded literal… deliberately not copied." | The live peer performs a **real check** (`state.master_pin.get().is_none()`) that drives the *status code*, and exposes no such field | **Retracted — and inverted.** The peer is stricter here than this service |

**Recommendation (process):** refresh `example/simply_ip_vault` with a deleting sync (`rsync -a
--delete`), and have `verify_convergence.sh` fail when the snapshot contains a `.rs` file not
reachable from the peer's module tree.

---

## 1. Resolution of previously identified flaws

Every flaw raised in either repository's prior audit reports, cross-referenced against current
source.

| # | Flaw | Raised in / against | Current state — `simply_hook_executor` | Current state — `simply_ip_vault` | Resolved? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | §5 master marker **application-maintained** — `VARCHAR(16) NULL` written only by bootstrap; a direct `INSERT … is_master=1, master_marker=NULL` was accepted, leaving two masters | Peer's report, against **itself** | N/A — engine-generated since `m20230106` | **RESOLVED.** `m20260808_000009_derive_master_marker` converts it to `INTEGER GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`, with the same `STORED`/`VIRTUAL` dialect split | ✅ **Both** |
| **F2** | R2 conjunction **not applied to content management** — a Daughter holding a `can_manage` row could repoint `script_path` (RCE) | This repo's report, against **itself** | **RESOLVED** in `79156ce`. `require_hook_manage_conjunction` demands `can_manage_keys` **AND** `row.can_manage`. Verified live: that caller now receives **403** | N/A — 4-verb model makes it unreachable; `can_manage` is administrative-only | ✅ **Both** |
| **F3** | §3 applied to keys themselves — `api_keys.owner_key_id` populated, inventoried, **never an authorization input** | This repo's report, against **itself** | **RESOLVED** in `20f2695`. Column dropped (`m20260810_000001`); `s7_…` now asserts its **absence** and the hook column's **presence** | N/A — never had the column | ✅ **Both** |
| **F4** | Master key **bypassed the `bound_ips` CIDR check** — the most valuable credential was the only one whose network restriction was decorative | Historical, both services | **RESOLVED.** `is_allowed` is evaluated with no `is_master` exemption (`src/middleware.rs`) | **RESOLVED.** Same shape | ✅ **Both** |
| **F5** | Six declared foreign keys claimed **inert** on SQLite | This repo's `AGENT_NOTES.MD` (P0) | **RESOLVED AS A FALSE POSITIVE.** SQLx enables `foreign_keys` on every SQLite connection; constraints were always enforced. Pragma now declared explicitly as hardening; `tests/referential_integrity.rs` pins behaviour (mutation-verified) | Already declared all four pragmas | ✅ **Both** |
| **F6** | Readiness probe disclosed a **`version` field** to anonymous callers | Peer's parity audit, against **itself** | N/A — never exposed one | **RESOLVED.** Field removed, with the reasoning recorded in the handler doc | ✅ **Peer** |
| **F7** | Replay map **flushed at capacity**, making every signature in the window replayable | Historical, both | **RESOLVED.** Gate asserts the flush is absent from `src/replay.rs` | **RESOLVED.** Same gate on their side | ✅ **Both** |

**No flaw raised in any prior report remains open in either service.**

---

## 2. Security parity — control-by-control

### 2.1 RBAC enforcement (`RBAC_MODEL.md`)

| Control | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| Normative document | `RBAC_MODEL.md`, md5 `cb0b76ab…` | Identical md5 | ✅ **Byte-identical** |
| **R2 conjunction** | `require_hook_manage_conjunction`: `!key.can_manage_keys → deny`, then `!row.can_manage → deny` | `guard_group_manage`: `caller.can_manage_keys && caller_perm.is_some_and(\|p\| p.can_manage)` | ✅ Same predicate |
| R2 evaluation points | **One** (`require_hook_manage_conjunction`) | **One** (`guard_group_manage`) | ✅ |
| **§5 master uniqueness** | Engine-generated column + unique index | Engine-generated column + unique index | ✅ Converged (peer adopted this design) |
| **§5 runtime pinning** | `MasterPin` — `new`/`pinned_to`/`get`/`pin_at_boot`/`resolve`/`authenticate` | **Identical public API**, same six methods | ✅ |
| Pin enforced at | `middleware.rs` — `master_pin.authenticate(&db, &mut key_record)` | `middleware.rs:312` — identical call | ✅ Same choke point |
| **§4 oracle discipline** | Invisible ⇒ `404`; visible-but-short-a-verb ⇒ `403` | Same split | ✅ |
| **§3 resource ownership** | `hooks.owner_key_id` | `ip_groups.owner_key_id`, `webhook_configs.owner_key_id` | ✅ Equivalent |
| §3 applied to keys | **No** (column dropped) | **No** (never existed) | ✅ Converged |
| **§6 pre-flight inventory** | `collect_subtree_inventory`, `409` + resolution map | Equivalent, via `ConflictWithDetails` | ✅ Same semantics |

### 2.2 Authentication, signing, replay

| Control | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| Credential lookup path | Single — `X-API-Key` → SHA-256 → `key_hash` | Single, same | ✅ |
| Canonical signed string | `crypto::canonical_v1_payload` | `crypto::canonical_v1_payload` | ✅ **Byte-identical** (gate-enforced) |
| Constant-time MAC compare | `Mac::verify_slice` in `src/crypto.rs` | `Mac::verify_slice` in `src/crypto.rs` | ✅ Same file, same primitive |
| `==` on MAC/digest | Absent (gate-asserted, both `crypto.rs` and `middleware.rs`) | Absent | ✅ |
| Replay single-use | `replay.rs`, never flushed, throttled sweep | `replay.rs`, same invariants | ✅ |
| Digest keyed as | Raw decoded bytes (case-insensitive by construction) | Raw decoded bytes | ✅ |
| CIDR check ordering | **After** authentication (no topology oracle) | After authentication | ✅ |
| Master exempt from CIDR | **No** | **No** | ✅ |

### 2.3 Database constraints & isolation

| Control | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| SQLite pragmas | `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000` | Identical set | ✅ (gate-enforced byte-identical) |
| Declared at connect time | Yes — `SqliteConnectOptions` in `db::connect` | Yes | ✅ |
| Pool size pinned | `SQLITE_MAX_CONNECTIONS = 1` | `SQLITE_MAX_CONNECTIONS = 1` | ✅ |
| FK behaviour tested | `tests/referential_integrity.rs` (6 tests, mutation-verified) | `foreign_keys_are_enforced_not_just_enabled` | ✅ Both assert behaviour, not the pragma |
| Pragma failure fatal? | No — logged, startup continues | No | ✅ |

### 2.4 Payload & input strictness

| Payload class | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| **Key create** | `CreateApiKeyPayload` — `deny_unknown_fields` ✅ | `CreateApiKeyPayload` — `deny_unknown_fields` ✅ | ✅ |
| **Key update** | `UpdateApiKeyPayload` — ✅ | `UpdateApiKeyPayload` — ✅ | ✅ |
| **Key delete / §6 resolution** | `DeleteApiKeyPayload` ✅ **and** `EntityResolution` enum ✅ | `DeleteKeyPayload` — **absent** | ⚠️ **This service stricter** |
| Resource payloads (hooks / groups / records / webhooks) | Not strict | Not strict | ✅ Same policy |
| Strict-JSON extractor | `api/support.rs` — `StrictJson`, `OptionalStrictJson` | `src/extract.rs` | ✅ Equivalent, different file |
| Body ceiling | `3 * 1024 * 1024`, router-wide, no per-route override | `3 * 1024 * 1024` | ✅ Identical constant |
| `is_master` acceptable in a key payload? | **No** — absence + `deny_unknown_fields` is the §5 control | **No** — same mechanism, same reasoning in-comment | ✅ |

**Assessment.** Both services apply `deny_unknown_fields` precisely where §5 privilege escalation is
possible — the key create/update payloads — and neither applies it to resource payloads. That is a
**shared, deliberate policy**, not an accident of coverage.

The one gap is the peer's `DeleteKeyPayload`. Under §6 the delete body carries a *resolution map*
naming what to do with each owned entity; a mistyped key in that map is silently ignored rather than
refused, so an operator can believe they resolved an entity they did not. **Recommended for the peer.**

---

## 3. Open divergences

None is a regression; each is a live difference in strictness worth an explicit decision.

| # | Divergence | Stricter side | Detail | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **D1** | Readiness probe raw SQL | **Peer** | This service issues a literal `SELECT 1` and carries a **third raw-SQL allowlist entry** (`src/api/health.rs`) to permit it. The peer uses a typed SeaORM query (`ApiKey::find().select_only().column(Id).limit(1)`) and holds "no raw SQL for DML anywhere in `src/`" with **no** handler exception | **Adopt the peer's form.** The allowlist entry buys one saved query at the cost of an exception in a request-reachable, *anonymous* handler |
| **D2** | Readiness checks the Master pin | **Peer** | Peer returns `503` when `master_pin.get().is_none()`, catching a process that bound its listener before pinning — which would serve while every master-only route quietly refused. This service checks the database only | **Adopt.** Cheap (`OnceLock` read), and it closes an ordering failure that is otherwise invisible |
| **D3** | Audit attribution nullability | **This service** | Ours: `api_key_name`, `api_key_prefix`, `client_ip` are **NOT NULL**. Peer's are all `Option<String>` — attribution can be absent, weakening "the trail outlives the key" | Recommend the peer tighten to NOT NULL |
| **D4** | `DeleteKeyPayload` strictness | **This service** | See §2.4 | Recommend the peer add `deny_unknown_fields` |
| **D5** | Settings endpoint | — | This service exposes master-only `GET /api/settings` (config + counters). The peer **removed** its equivalent along with `api/system.rs` | Justified divergence. Ours is master-gated and discloses nothing publicly; theirs reduced surface area. Either is defensible |
| **D6** | `429 Too Many Requests` | — | This service has `AppError::TooManyRequests`, raised by `executor.rs` when a key is at `max_concurrent_jobs`. The peer has no equivalent because it spawns no processes | Justified — domain difference |

---

## 4. Executive verdict — security

| Dimension | Verdict |
| :--- | :--- |
| Prior flaws resolved | **7 of 7.** No finding from any earlier report in either repository remains open |
| Normative alignment | **Exact.** `RBAC_MODEL.md` byte-identical across all three copies on disk |
| RBAC enforcement parity | **Full.** R2 conjunction, §3 ownership, §4 oracle discipline, §5 uniqueness + pinning, §6 inventory all present and equivalent |
| Cryptographic parity | **Full.** Identical canonical string (gate-enforced), identical constant-time primitive, identical replay invariants |
| Payload strictness parity | **Substantive parity**, with one gap on the peer side (**D4**) |
| Open items | **4**, all minor: two where the peer is stricter (**D1, D2**), two where this service is (**D3, D4**) |
| Regressions | **None** |

**Security maturity: HIGH, and symmetric.** The two services now check each other rather than merely
resembling each other — F1 was found by the peer against itself, F2 and F3 by this service against
itself, and F6 by the peer's own parity pass. Both remaining "this side is weaker" items (**D1**,
**D2**) belong to *this* service and are cheap to close.

The one methodological defect is not in either codebase: the **vendored peer snapshot drifted**, and
it produced two incorrect findings in this repository's previous audit (§0). That is the highest-value
fix identified by this pass, because it silently degrades every future comparison.
