# Final Comparative Security Audit — `simply_hook_executor` ↔ `simply_ip_vault`

**Date:** 2026-08-11
**Mode:** strictly read-only. No file under `src/`, `tests/`, `migration/`, `scripts/` or `static/`
was modified in either repository. `RBAC_MODEL.md` is untouched.
**Subject A (this repository):** `simply_hook_executor` @ `4865a82`
**Subject B (peer):** `simply_ip_vault` @ `6f1c4c7`, at `example/simply_ip_vault` — a **live git
clone**, pulled at the start of this pass (see §0).
**Normative document:** `RBAC_MODEL.md`

This edition **replaces** the 2026-08-10 audit of `20f2695` that previously occupied this file; that
edition is preserved in git history at `7a7ffc7`. Every claim inherited from it was re-verified
against current source rather than carried forward, and four of its open items have since closed —
two on each side.

---

## 0. Method and provenance

### 0.1 Task 0 — peer repository update

`example/` contains exactly one project. The comparison is therefore this repository's root tree
against `example/simply_ip_vault`.

| Step | Command | Outcome |
| :--- | :--- | :--- |
| Enumerate peers | `ls example/` | `simply_ip_vault` — the only entry |
| Confirm it is a clone, not a snapshot | `git rev-parse --is-inside-work-tree` | `true`; `origin` = `https://oshino.tomidejetsu.ovh/fallrik/simply_ip_vault.git` |
| Update | `cd example/simply_ip_vault && git pull` | **`Already up to date.`** — `HEAD` unchanged at `6f1c4c7` before and after |
| Working tree | `git status --short` | Clean — the analysed tree is exactly `6f1c4c7` |

### 0.2 The vendored-snapshot defect from the previous audit is closed

The 2026-08-10 edition's highest-value finding was methodological: `example/simply_ip_vault` was a
**flat vendored copy** that had drifted from upstream, still carrying `src/api/system.rs` and
`src/webhooks.rs` after both were deleted, and it had already produced two false findings.

| Probe | 2026-08-10 | Today |
| :--- | :--- | :--- |
| Nature of `example/simply_ip_vault` | Flat directory copy, no VCS | **Git clone with an `origin` remote** |
| Can it be refreshed deterministically? | No — manual `cp` | **Yes — `git pull`** |
| Orphaned files absent upstream | 2 (`src/api/system.rs`, `src/webhooks.rs`) | **0** — neither path exists |
| `RBAC_MODEL.md` identity (`md5sum`) | Identical | **Identical** — `cb0b76abd6c00f28af9bee951f804f7b` on both |

**Closed.** The recommendation from that audit — replace the snapshot with a syncable source of
truth — was implemented. A residual hardening item remains and is carried below as **D5**.

### 0.3 Drift detection is one-directional — a new finding

Both repositories ship `scripts/verify_convergence.sh`, and both point it at a peer inside their own
`example/`. Only one of the two has a peer there.

| | `simply_hook_executor` | `simply_ip_vault` |
| :--- | :--- | :--- |
| `PEER_ROOT` | `$REPO_ROOT/example/simply_ip_vault` | `$PROJECT_ROOT/example/simply_hook_executor` |
| Does that path exist? | **Yes** | **No** |
| Result of running the gate | `19 converged, 0 known, 0 drifted, 0 skipped` — exit `0` | `SKIP peer service not found …` — exit **`0`** |
| Does it detect drift? | Yes | **No** |

The peer's gate is **green by absence**: it reports success while comparing nothing, so on that side
a divergence introduced today would pass CI silently. This is tracked as **D6**.

---

## 1. Resolution of previously identified flaws

Every flaw raised in either repository's audit history, cross-referenced against current source.

| # | Flaw | Raised in / against | State — `simply_hook_executor` @ `4865a82` | State — `simply_ip_vault` @ `6f1c4c7` | Resolved? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | §5 master marker **application-maintained** — a direct `INSERT … is_master=1, master_marker=NULL` was accepted, leaving two masters | Peer, against itself | Engine-generated since `m20230106_000001` | Engine-generated since `m20260808_000009`; `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` with the same dialect split | ✅ **Both** |
| **F2** | R2 conjunction **not applied to content management** — a Daughter holding a `can_manage` row could repoint `script_path` (RCE) | This repo, against itself | `guard_hook_manage_conjunction`: `!can_manage_keys → deny`, then `!row.can_manage → deny` | Unreachable by construction — `can_manage` is administrative-only in the 4-verb model; `guard_group_manage` still enforces the conjunction | ✅ **Both** |
| **F3** | §3 applied to keys themselves — `api_keys.owner_key_id` populated, inventoried, never an authorization input | This repo, against itself | Column dropped (`m20260810_000001`); `s7_…` asserts its **absence** and the hook column's **presence** | Never had the column | ✅ **Both** |
| **F4** | Master key **bypassed the `bound_ips` CIDR check** | Historical, both | `is_allowed` evaluated with no `is_master` exemption | Same shape | ✅ **Both** |
| **F5** | Six declared foreign keys claimed **inert** on SQLite | This repo's `AGENT_NOTES.MD` (P0) | **False positive, retracted.** SQLx enables `foreign_keys` on every SQLite connection. Pragma now declared explicitly as hardening; `tests/referential_integrity.rs` pins behaviour (mutation-verified) | All four pragmas already declared | ✅ **Both** |
| **F6** | Readiness probe disclosed a **`version` field** to anonymous callers | Peer, against itself | Never exposed one | Removed | ✅ **Both** |
| **F7** | Replay map **flushed at capacity**, making every signature in the window replayable | Historical, both | Gate asserts the flush is absent from `src/replay.rs` | Same gate | ✅ **Both** |
| **F8** | `INITIAL_MASTER_KEY` accepted **any non-empty string** — `INITIAL_MASTER_KEY=changeme` bootstrapped the credential that administers every other credential | Peer's 2026-08-10 audit, **against this repo** | **RESOLVED** in `4865a82`. `config::validate_initial_master_key` enforces 64 hex characters, fatally, before the database is opened. 9 unit tests + e2e §33b against the real binary | Already enforced (`config::validate_initial_master_key`, `MASTER_KEY_HEX_LEN = 64`) | ✅ **Both** |
| **F9** | Audit attribution columns **nullable** — `api_key_id` is `ON DELETE SET NULL`, so a nullable `api_key_name`/`api_key_prefix` allows a row recording an action with no actor | This repo's 2026-08-10 audit, **against the peer** (D3) | Already `NOT NULL` | **RESOLVED** in `6f1c4c7`. `m20260811_000010_audit_attribution_not_null` rebuilds the table; `create_audit_log` now takes `&api_key::Model` and `IpAddr` **by value**, so an unattributed write cannot be expressed | ✅ **Both** |
| **D1 (prior)** | Readiness probe carried a **raw-SQL allowlist exception** in an anonymous, request-reachable handler | This repo's 2026-08-10 audit, against itself | **RESOLVED** in `4865a82`. Typed builder `ApiKey::find().select_only().column(Id).limit(1)`; allowlist reduced 3 → 2 | Never had the exception | ✅ **Both** |
| **D2 (prior)** | Readiness did not check the **Master pin**, so a process that bound before pinning reported itself ready | This repo's 2026-08-10 audit, against itself | **RESOLVED** in `4865a82`. `state.master_pin.get().is_none() → 503`, database reported `up` because it is | Already present | ✅ **Both** |

**Every flaw raised in any prior report against either service is now closed.** The two items still
open at the last audit were one on each side (F8 against this repo, F9 against the peer); each was
fixed by the repository it was raised against, without coordination.

---

## 2. Security parity — control by control

### 2.1 RBAC enforcement (`RBAC_MODEL.md`)

| Control | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| Normative document | `RBAC_MODEL.md`, md5 `cb0b76ab…` | Identical md5 | ✅ **Byte-identical** |
| **R2 conjunction** | `guard_hook_manage_conjunction` — `!key.can_manage_keys → deny`, then `!row.can_manage → deny` | `guard_group_manage` — `caller.can_manage_keys && caller_perm.is_some_and(\|p\| p.can_manage)` | ✅ Same predicate |
| R2 evaluation points | **One** | **One** | ✅ Single choke point on both |
| R2 covers revocation as well as grant | Yes | Yes — explicitly, with the prior grant/revoke split documented as wrong | ✅ |
| **§3 resource ownership** | `hooks.owner_key_id`; `guard_lifecycle_authority` | `ip_groups.owner_key_id`, `webhook_configs.owner_key_id`; `guard_resource_lifecycle` | ✅ Equivalent |
| §3 applied to keys | **No** (column dropped) | **No** (never existed) | ✅ Converged |
| **§4 oracle discipline** | Invisible ⇒ `404`; visible-but-short-a-verb ⇒ `403` | Same split; `holds_any_group_manage` is deliberately the weaker pre-gate so the `403` cannot depend on what exists | ✅ |
| **§5 master uniqueness** | Engine-generated column + unique index | Engine-generated column + unique index | ✅ |
| **§5 runtime pinning** | `MasterPin` — `new` / `pinned_to` / `get` / `pin_at_boot` / `resolve` / `authenticate` | **Identical public API**, same six methods, same `MasterPinError` | ✅ |
| Pin enforced at | `middleware.rs` — `master_pin.authenticate(&db, &mut key)` | `middleware.rs` — identical call | ✅ Same choke point |
| Pin asserted at readiness | Yes (`4865a82`) | Yes | ✅ Converged |
| **§6 pre-flight inventory** | `collect_subtree_inventory` → `AppError::ConflictWithDetails` | `inventory_owned_entities` → `AppError::ConflictWithDetails` | ✅ Same semantics, same error variant |
| §7 compliance suite | `tests/rbac_model_compliance.rs`, **23 tests** | `tests/rbac_model_compliance.rs`, **18 tests** | ✅ Both cover R1–R7 and §3–§7; this repo adds 5 adversarial cases |

### 2.2 Authentication, signing, replay

| Control | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| Credential lookup path | Single — `X-API-Key` → SHA-256 → `key_hash` | Single, same | ✅ |
| Canonical signed string | `crypto::canonical_v1_payload` | `crypto::canonical_v1_payload` | ✅ **Byte-identical** (gate-enforced) |
| Constant-time MAC compare | `Mac::verify_slice` in `src/crypto.rs` | `Mac::verify_slice` in `src/crypto.rs` | ✅ Same file, same primitive |
| `==` on MAC/digest | Absent — gate-asserted in `crypto.rs` **and** `middleware.rs` | Absent, same gate | ✅ |
| Secret-at-rest AEAD | XChaCha20-Poly1305, 24-byte random nonce, `Box<XChaCha20Poly1305>` | Identical construction | ✅ |
| Replay single-use | `replay.rs` — never flushed, throttled sweep, digests keyed as raw bytes | Same invariants, same gate | ✅ |
| CIDR check ordering | **After** authentication — no topology oracle | After authentication | ✅ |
| Master exempt from CIDR | **No** | **No** | ✅ |
| Timestamp validation fn | `middleware::validate_timestamp` | `middleware::validate_timestamp` | ✅ Same name (converged in `4865a82`) |

### 2.3 Database constraints and privilege isolation

| Control | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| SQLite pragmas | `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000` | Identical set | ✅ Gate-enforced byte-identical |
| Declared at connect time | `SqliteConnectOptions` in `db::connect` — replayed on every recycled connection | Same | ✅ |
| Pool size pinned | `SQLITE_MAX_CONNECTIONS = 1` | `SQLITE_MAX_CONNECTIONS = 1` | ✅ Same constant name and value |
| Pragma failure fatal? | No — logged, startup continues; gate asserts it | No, same gate | ✅ |
| FK behaviour tested, not just the pragma | `tests/referential_integrity.rs` — 6 tests, mutation-verified | `schema_integrity_tests.rs` — `foreign_keys_are_enforced_not_just_enabled` + cascade-control tests | ✅ |
| Audit FK on key deletion | `ON DELETE SET NULL` | `ON DELETE SET NULL` | ✅ |
| Audit attribution survives key deletion | `api_key_name`, `api_key_prefix`, `client_ip` **NOT NULL** | **NOT NULL** since `m20260811_000010` | ✅ Converged this cycle |
| Raw SQL outside migrations/pragmas | Forbidden; **2** allowlist entries, neither in `src/api/` | Forbidden; **2** allowlist entries, neither in `src/api/` | ✅ (see D4 for a gate asymmetry) |

### 2.4 Payload and input strictness

`deny_unknown_fields` is a §5 control on both sides: it is what makes the *absence* of `is_master`
from the key payloads mean a refusal rather than a silent drop.

| Payload class | `simply_hook_executor` | `simply_ip_vault` | Parity |
| :--- | :--- | :--- | :--- |
| **Key create** | `CreateApiKeyPayload` — `deny_unknown_fields` ✅ | `CreateApiKeyPayload` — ✅ | ✅ |
| **Key update** | `UpdateApiKeyPayload` — ✅ | `UpdateApiKeyPayload` — ✅ | ✅ |
| **Key delete / §6 resolution map** | `DeleteApiKeyPayload` ✅ **and** the `EntityResolution` enum ✅ | `DeleteKeyPayload` — **absent** | ⚠️ **This service stricter** (**D2**) |
| Owner reassignment | Field on `UpdateHookPayload` — not strict | `ReassignOwnerPayload` — not strict, **though its doc comment claims the attribute** | ⚠️ Symmetric gap, asymmetric documentation (**D3**) |
| Domain resource payloads | `CreateHookPayload`, `UpdateHookPayload`, `UpdateParameterPayload` — not strict | `CreateIpGroupPayload`, `BanWhitePayload`, `PurgeIpsPayload`, `CreateWebhookPayload`, `UpdateWebhookPayload` — not strict | ✅ Same deliberate policy |
| Strict-JSON extractor | `StrictJson`, `OptionalStrictJson` in `src/api/support.rs` | `StrictJson`, `OptionalStrictJson` in `src/extract.rs` | ✅ Same names and semantics, different file (see convergence report) |
| Body ceiling | `MAX_REQUEST_BODY_BYTES = 3 * 1024 * 1024`, router-wide, set exactly once | Identical constant name and value | ✅ Gate-enforced |
| `is_master` acceptable in a key payload? | **No** — absence + `deny_unknown_fields` | **No** — same mechanism, same reasoning in-comment | ✅ |
| Dashboard cannot smuggle it either | `the_dashboard_never_sends_is_master_in_a_key_payload` (source hygiene) | No equivalent test | ⚠️ This service stricter |

### 2.5 Bootstrap credential validation

Both services now refuse a weak `INITIAL_MASTER_KEY`. The refusals differ in three details, none of
which weakens either side, but which are worth stating precisely.

| Aspect | `simply_hook_executor` | `simply_ip_vault` | Assessment |
| :--- | :--- | :--- | :--- |
| Required shape | 64 hex characters | 64 hex characters | ✅ Identical policy |
| Fatal? | Yes — `std::process::exit(1)` before the database is opened | Yes — `Err` from `bootstrap_master_key`, logged before propagation | ✅ Equivalent |
| Checked before any DB write | Yes | Yes | ✅ |
| Variable **unset** | Not an error — a random key is generated and printed once | Not an error — same | ✅ |
| Variable **set but empty** | **Fatal** (`InitialMasterKeyError::Empty`) | **Silently treated as unset** — `Ok(k) if !k.is_empty()` falls through to random generation | ⚠️ This service stricter (**D1**) |
| Surrounding whitespace | Trimmed, then validated — `INITIAL_MASTER_KEY=$(cat key.txt)` works | Not trimmed — a trailing newline is refused | ⚠️ Peer stricter; this service more forgiving |
| Error type | `InitialMasterKeyError` — `Empty` / `BadLength(usize)` / `NonHex(char, usize)` | `InvalidInitialMasterKey { got, detail }` | Divergent naming (see convergence report) |
| Signature | `fn(Option<&str>) -> Result<Option<String>, _>` | `fn(&str) -> Result<(), _>` | Divergent shape |

**`INITIAL_MASTER_KEY=$UNSET_VAR` in a compose file expands to the empty string.** This service
refuses to start; the peer generates a random key and prints it, leaving the operator with a daemon
whose master credential is not the one their tooling believes it configured. The peer's behaviour is
not unsafe — the generated key is strong — but it is silent, and silence is what the whole control
exists to remove.

---

## 3. Open divergences

None is a regression. Each is a live difference in strictness or coverage worth an explicit decision.

| # | Divergence | Stricter side | Detail | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **D1** | `INITIAL_MASTER_KEY` set but empty | **This service** | Refused here; treated as unset by the peer, which then generates a key and continues. See §2.5 | Recommend the peer refuse the empty case explicitly rather than pattern-matching it away |
| **D2** | `DeleteKeyPayload` strictness | **This service** | The §6 delete body carries a *resolution map* naming what to do with each owned entity. Without `deny_unknown_fields` a mistyped key is silently ignored, so an operator can believe they resolved an entity they did not | Recommend the peer add the attribute — one line, and the §6 semantics make it load-bearing |
| **D3** | `ReassignOwnerPayload` documents a control it does not carry | — | Its doc comment reasons that sharing the struct avoids "two things to keep `deny_unknown_fields` in step across", but the struct derives only `Deserialize`. No escalation follows — the payload has a single field — but the comment asserts a guarantee a reader will not find | Recommend the peer either add the attribute or correct the comment |
| **D4** | Hygiene gate breadth | **Peer** | The peer's `source_hygiene.rs` carries two invariants this repo lacks: `no_dml_keyword_is_hand_written_outside_the_exceptions`, and `no_handler_is_ever_exempted` — which asserts no allowlist entry may begin with `src/api/`, encoding the rule the allowlist is a proxy for. Its allowlist also supports whole-directory entries | **Adopt `no_handler_is_ever_exempted`.** This repo removed its only `src/api/` exemption in `4865a82`; nothing currently stops the next one |
| **D5** | Peer clone is not pinned or verified | — | `example/simply_ip_vault` is now a real clone (§0.2), but nothing asserts it is on a known revision or free of local edits. A dirty or detached peer would silently change what the gate compares against | Have `verify_convergence.sh` report the peer's `HEAD` and refuse a dirty peer tree |
| **D6** | Peer's convergence gate is inert | **This service** | `simply_ip_vault`'s gate points at `example/simply_hook_executor`, which does not exist in that clone. It prints `SKIP` and exits `0` — green while comparing nothing (§0.3) | Recommend the peer clone this service into its `example/`, or make a missing peer a non-zero exit |
| **D7** | Neither CI pipeline runs the gates | — | Both repositories ship exactly two workflows (`docker-publish.yml`, `update-readme-each-month.yml`) and **neither** invokes `cargo test`, `test_e2e.sh` or `verify_convergence.sh`. Every gate described in this report is developer-invoked | Symmetric gap. Recommend a shared CI job on both sides — the gates already exist and exit non-zero correctly |
| **D8** | `429 Too Many Requests` | — | This service has `AppError::TooManyRequests`, raised when a key is at `max_concurrent_jobs`. The peer has no equivalent because it spawns no processes | Justified — domain difference |
| **D9** | Settings endpoint | — | This service exposes master-only `GET /api/settings` via `api/system.rs`. The peer removed its equivalent | Justified. Ours is master-gated and discloses nothing publicly; theirs reduced surface area |

---

## 4. Verification performed

| Check | Command | Result |
| :--- | :--- | :--- |
| Peer freshness | `git pull` in `example/simply_ip_vault` | `Already up to date.` @ `6f1c4c7` |
| Normative identity | `md5sum RBAC_MODEL.md` × 2 | Identical — `cb0b76ab…` |
| This service's suite | `cargo test` | **285 passed, 0 failed** across 8 binaries |
| Convergence gate (this side) | `./scripts/verify_convergence.sh` | **19 converged, 0 known, 0 drifted, 0 skipped** — exit `0` |
| Convergence gate (peer side) | `bash scripts/verify_convergence.sh` in the peer | **`SKIP`** — exit `0`, nothing compared (**D6**) |
| Orphaned peer files | `find example/simply_ip_vault/src -name '*.rs'` vs peer module tree | 0 unreachable files |

---

## 5. Executive verdict — security

| Dimension | Verdict |
| :--- | :--- |
| Prior flaws resolved | **11 of 11.** No finding from any earlier report against either service remains open |
| Flaws closed this cycle | **4** — F8 and the two readiness items on this side, F9 on the peer's |
| Normative alignment | **Exact.** `RBAC_MODEL.md` byte-identical across both repositories |
| RBAC enforcement parity | **Full.** R2 conjunction, §3 ownership, §4 oracle discipline, §5 uniqueness and pinning, §6 inventory — all present, all equivalent, all single-choke-point |
| Cryptographic parity | **Full.** Identical canonical string (gate-enforced), identical constant-time primitive, identical AEAD construction, identical replay invariants |
| Database constraint parity | **Full.** Identical pragma set, identical pool pinning, and audit attribution now `NOT NULL` on both |
| Payload strictness parity | **Substantive**, with one real gap on the peer (**D2**) and one documentation defect (**D3**) |
| Open items | **7**, none a vulnerability: 3 where this service is stricter (**D1, D2, D3**), 2 where the peer is (**D4, D6**), 2 shared process gaps (**D5, D7**) |
| Regressions | **None** |

**Security maturity: HIGH, and symmetric.** The defining property of this cycle is that each service
closed the finding the *other* had raised against it, unprompted and in its own idiom — this
repository adopted 64-hex master-key validation, and the peer tightened audit attribution to
`NOT NULL` while going further than the brief by making an unattributed write inexpressible in the
type. That is a working two-way review relationship rather than two codebases that merely resemble
each other.

The remaining items are process rather than product. The two that matter most are **D6** — the
peer's drift gate is green while comparing nothing, so convergence is currently policed from one
side only — and **D7**, that neither repository's CI runs any of the gates this report relies on.
Both are cheap, and until they are closed every guarantee here holds only as long as someone
remembers to run the scripts by hand.
