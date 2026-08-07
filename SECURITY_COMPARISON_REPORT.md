# Comparative Security Audit — `simply_ip_vault` vs `simply_hook_executor`

**Post-convergence pass.** Strictly read-only: no file under `src/`, `tests/`, `migration/`, or
`./example` was modified, and no application code was written.

**Date:** 2026-08-07
**Subject A (reference):** `simply_ip_vault`, at `./example/simply_ip_vault`
**Subject B (this repo):** `simply_hook_executor`, at HEAD `b5cf624`
**Normative document:** `RBAC_MODEL.md`

Both services have now completed a six-phase implementation of `RBAC_MODEL.md`, independently, each
seeing only its own repository plus a read-only snapshot of the peer.

---

## Reference freshness

**Status: CURRENT. Flat file snapshot — no git metadata.**

`./example/simply_ip_vault` contains **no `.git` directory** (neither `example/.git` nor
`example/simply_ip_vault/.git`). It is a flat file copy. No `git` command was run inside it: from
this working tree `git` walks up and reports *this* repository's HEAD, which would be a false
positive dressed as evidence.

Freshness was established from file mtimes and from the reference's own `AGENT_NOTES.MD`:

| Signal | Value |
| :--- | :--- |
| Newest peer file | `AGENT_NOTES.MD`, 2026-08-07 20:23 |
| Peer's newest source | `src/migration/m20260807_000007_add_api_key_master_marker.rs`, 20:21; `src/api.rs`, 20:21 |
| Peer's compliance suite | `tests/rbac_model_compliance.rs`, 20:18 |
| This repo's last commit | `b5cf624`, 2026-08-07 15:51 |
| Peer notes' final section | "Session 36 — RBAC_MODEL Convergence, Phase 5: Compliance Suite & Mutation Validation" |

The snapshot is **newer than this repository's HEAD by roughly four and a half hours** and carries
the peer's completed Phase 5. This is the first audit in this series where the reference reflects a
finished convergence run on both sides, so the comparisons below are between two completed
implementations rather than between one finished and one in progress.

---

## `RBAC_MODEL.md` byte-identity — the check that had never run

**Status: EXECUTED FOR THE FIRST TIME. Result: BYTE-IDENTICAL.**

Every prior audit and both services' Phase 5 notes reported this check as pending, because the peer
carried no copy of the specification. **The peer now has one**
(`example/simply_ip_vault/RBAC_MODEL.md`, 7846 bytes, mtime 2026-08-07 09:47).

```
$ cmp RBAC_MODEL.md example/simply_ip_vault/RBAC_MODEL.md
$ echo $?
0
```

`./scripts/verify_convergence.sh` correspondingly moved off its placeholder for the first time:

```
[OK]    Canonical RBAC model (byte-identical)
[OK]    RBAC rule coverage (12 rules, 14 test(s))

16 converged, 1 known divergence(s), 0 drifted, 0 skipped
```

There are **no substantive divergences to report**, because there are no divergences at all. The
specification is genuinely one document. Note what this does *not* establish: the two services
implement the same text, but the text itself contains defects — see the Task 5 table.

---

## Task 1 — Reference state

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Form on disk | Flat file snapshot at `./example/simply_ip_vault`; no `.git` at any level | Real git repository, HEAD `b5cf624` | Not comparable — the peer is a delivery artifact, not a checkout |
| Pinnable revision | None. `git` inside it resolves to *this* repo and must not be run | `b5cf624` | Peer cannot be pinned; recorded by mtime + notes content instead |
| Latest activity | 2026-08-07 20:23 (`AGENT_NOTES.MD`) | 2026-08-07 15:51 (commit) | Peer is **newer**; its Phase 5 is included |
| Convergence programme state | Phases 0–5 complete ("Session 36") | Phases 0–5 complete (`ceb536e`…`b5cf624`) | Equivalent — both finished |
| Reported gates | 204 tests, 490 e2e, convergence 31 matching / 2 documented / 0 unexplained | 227 tests, 823 e2e, convergence 16 converged / 1 known / 0 drifted | Counts are not comparable across differing harnesses; both self-report green |

---

## Task 2 — Specification identity

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| `RBAC_MODEL.md` present | Yes, 7846 bytes | Yes, 7846 bytes | Equivalent |
| Byte comparison | `cmp` exit 0 — identical | `cmp` exit 0 — identical | **Converged.** First real execution of this check |
| Identity check in convergence script | Present (peer's Pillar 0) | `rbac_model_identity` in `scripts/verify_convergence.sh` | Equivalent; both now report OK rather than "peer copy absent" |
| Was the check ever proven to fail? | Reported verified for the *rule-coverage* gate, by renaming `r5_` | Verified for both: renaming `r5_` produced `[DRIFT] No compliance test for: r5` | Equivalent — both gates shown to fail, not merely to pass |

---

## Task 3 — §5 master uniqueness: the mechanism

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Migration | `m20260807_000007_add_api_key_master_marker` | `m20230106_000001_master_key_uniqueness` | — |
| Marker column type | `VARCHAR(16)` nullable, value `'master'` | `INTEGER` nullable | — |
| **How the marker is produced** | **Application-maintained.** `ColumnDef::new(MasterMarker).string_len(16).null()`; backfilled by `UPDATE`; written by `main.rs:120` and set to `None` by `api.rs:1797` | **Engine-generated.** `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` | **`simply_hook_executor` stronger** — see prose below |
| Marker present on the entity | Yes — `api_key::Model.master_marker: Option<String>`, assignable | No — deliberately undeclared, so SeaORM can never emit it in an `INSERT` | **`simply_hook_executor` stronger**; an assignable marker is a writable marker |
| Is `is_master = true` + `marker = NULL` rejected by the DB? | **No.** Nothing ties the two columns | **Yes.** The marker is derived, so the unique index fires | **`simply_hook_executor` stronger** — this is the §5 threat model |
| Storage mode per backend | N/A (not a generated column) | Postgres `STORED`, SQLite/MySQL `VIRTUAL` | N/A vs pinned |
| Storage mode pinned by tests | N/A | Two unit tests in the migration: `each_backend_gets_the_only_storage_class_it_accepts`, `the_marker_is_derived_from_is_master_on_every_backend` | **`simply_hook_executor` stronger**; the dialect split fails only against a real server, which neither suite starts |
| Pre-existing duplicate masters | Migration aborts with an error **naming the offending ids** and the exact `UPDATE` to run | Migration aborts (index creation fails); recovery SQL is in `AGENT_NOTES.MD`, not in the error | **`simply_ip_vault` stronger** on operator experience |
| Compliance assertion | `s5_…` inserts a second master **with the marker explicitly set** | `s5_…` and `the_database_rejects_a_second_master_row_with_no_handler_involved` insert with `is_master: true` and no marker at all | **`simply_hook_executor` stronger** — see prose |

**Both services satisfy §5's letter; only one satisfies its intent.** §5 requires uniqueness
"enforced by a database constraint rather than by application logic alone." In `simply_ip_vault` the
unique index constrains `master_marker`, and `master_marker` is set by application code. A writer
that sets `is_master = true` and leaves the marker `NULL` produces a second fully functional master —
every guard in `src/api.rs` reads `is_master`, not the marker — and the database accepts the row. The
threat model §5 names explicitly (a restored backup, an operator at a SQL prompt, a future handler)
is therefore not covered. It is not reachable through the peer's API today, because
`bootstrap_master_key` is the only writer of `is_master`; but "no current code path does this" is
exactly the application-logic guarantee §5 was written to replace.

The peer's own §5 compliance test cannot detect this, and shows why: it constructs the second master
with `master_marker: Set(Some(MASTER_MARKER))`. That proves the unique index works. It does not probe
the case where the marker is omitted, which is the only case the derived-column design exists to
close.

In `simply_hook_executor` the marker is computed by the engine from `is_master` on every write, so
the two columns cannot disagree and no writer — application, migration, backup restore, or `psql`
session — can produce a second master. This repository's test inserts with `is_master: true` and
never mentions the marker, and the insert fails.

---

## Task 4 — Terminology resolution

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Managed resource (shared) | `ip_groups` — `api_key_group_permissions` with 4 verbs | `hooks` — `api_key_hook_permissions` with 2 verbs | Equivalent role, different verb granularity |
| Dispatch target (creator-private) | `webhook_configs` — a real, separate entity with `owner_key_id` | **Does not exist.** No table, no entity; `src/executor.rs` is a process-spawning module | **Divergence — resolved on one side only** |
| `can_create_executor` in source | n/a | **0 occurrences** across `src/` | Specification names a right that does not exist |
| One entity holding both roles | No — `ip_groups` and `webhook_configs` are distinct | **Yes.** A `Hook` is shared via permission rows *and* carries `script_path` + `run_as_user`, the dispatch payload | **Divergence.** `RBAC_MODEL.md` says one entity cannot hold both |
| §3 ownership applies to | `ip_groups.owner_key_id` and `webhook_configs.owner_key_id` | `hooks.owner_key_id` only | Equivalent for the managed resource; peer additionally covers its dispatch target |
| §4 scope 3 (creator-private) applies to | `webhook_configs` — `list_webhooks`, detail, update, delete all creator+master | `executions` — chosen as the nearest analogue; a hook's manager no longer sees runs it did not make | **Silently diverged**, but defensibly — see prose |
| §6 inventory covers | IP Groups **and** Webhook Configs | Hooks only | Peer's inventory spans two entity types because it has two |

**The two readings have diverged, and the divergence is honest rather than accidental.** Both claims
in this repository's notes verify against source: `grep -rn "can_create_executor" src/` returns
nothing, there is no executor table in `src/migration/`, and `hooks` genuinely carries both the
permission-row relationship and the dispatch payload.

`simply_ip_vault` had a clean answer available because its webhook configs already existed as a
separate creator-private entity, so §4's dispatch-target rule mapped onto something real.
`simply_hook_executor` had no such entity and picked `executions` for scope 3, which is a judgement
call the specification does not force — its terminology table maps "resource data (contained
records)" to `—` for this service, so neither reading is derivable from the text.

The unresolved part is the dual role. `RBAC_MODEL.md` §4 gives contradictory instructions for a
single `Hook`: the dispatch-target rule says "visible exclusively to their creator and Master", while
the shared-resource rule says every permission-row holder may see it in minimal form. This repository
implements the shared-resource rule for hooks and applies creator-privacy to executions instead. That
is a coherent resolution, but it is *this repository's* resolution, not the specification's, and the
peer never had to make it.

---

## Task 5 — Rights the specification names that do not exist

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Spec's named creation right | `can_create_webhooks` | `can_create_executor` | — |
| Does that exact name exist in source? | **No** — 0 occurrences in `src/` | **No** — 0 occurrences in `src/` | **Specification defect** — the table names two rights, neither of which exists |
| Actual creation right(s) | **Two:** `can_manage_webhooks` (dispatch targets) and `can_create_groups` (managed resources) | **One:** `can_manage_hooks` | **Specification defect** — the table implies exactly one per service |
| Where the mismatch is visible | Peer's own compliance suite says "this service's spelling of `can_create_webhooks`" at `rbac_model_compliance.rs:461` | This repo's notes flag it in Phase 1 and Phase 5 | Both noticed independently; neither could fix it without forking the spec |
| Effect on enforcement | R4 correctly gates both real rights master-only | R4 correctly gates the one real right master-only | Equivalent — behaviour is right, the vocabulary is wrong |

**This is a defect in `RBAC_MODEL.md`, not in either service.** The Terminology table's
resource-creation row is wrong in three separate ways: the vault's right is not called
`can_create_webhooks`, the executor's is not called `can_create_executor`, and the vault has *two*
creation rights where the table allows one. Because the document is enforced byte-identical, neither
service could correct it unilaterally — doing so would fork the specification and fail the identity
check that has only just started passing. It needs a coordinated edit to both copies.

---

## Task 6 — Rules "covered but not fully enforced"

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Gap A — R2 over resource *content* management | **Not present.** `can_manage` is administrative-only; content uses `can_read`/`can_write`/`can_delete`. `guard_group_manage` (the conjunction) is the only consumer of `can_manage`, at 3 call sites, all grant/revoke | **Present.** `require_manage` (`src/api.rs`) is master-OR-`can_manage`-row, with **no** `can_manage_keys`. It gates `update_hook`, all parameter CRUD, and delete — 6 call sites | **`simply_ip_vault` stronger.** See prose — this is the audit's sharpest finding |
| Verb model that causes it | 4 verbs; `can_manage` has one meaning | 2 verbs; `can_manage` means both "administer rows" and "edit content" | Architectural, not an oversight — but the consequence is real |
| Gap B — §3 applied to keys themselves | **Not present** — `api_keys` has `parent_key_id` but **no** `owner_key_id` | Present: `api_keys.owner_key_id` exists, is populated and inventoried, but is not an authorization input | **Equivalent in effect.** Peer has no gap because it has no column; §3 governs resources, not keys |
| Whether the peer looked for these | Gap A: yes, implicitly — its verb model makes it unreachable, and `guard_group_manage`'s doc explicitly reasons about the Daughter tier boundary. Gap B: N/A, no column | Both documented explicitly in `AGENT_NOTES.MD` Phase 5 | Peer's absence of these findings is **structural, not an oversight** |
| Spec-vacuous items disclosed | Yes — "§3's rename clause for groups… no group-rename endpoint exists to restrict" | No equivalent (hook rename exists and is guarded) | Peer discloses a vacuous requirement rather than counting it compliant — good practice |

**Gap A is the one place where this service is genuinely weaker than the peer on a rule in
`RBAC_MODEL.md`, and it deserves stating plainly.**

`RBAC_MODEL.md` §1 says a Daughter key (one without `can_manage_keys`) "may never" manage resources,
and R2 says managing a resource requires the conjunction. In `simply_ip_vault` that holds completely:
`can_manage` means only "administer this group's permission rows", and every one of its three call
sites goes through `guard_group_manage`, which demands both halves. A Daughter editing group
*contents* uses `can_write` — an operational verb the tier matrix does not restrict.

In `simply_hook_executor` `can_manage` is overloaded. R2's conjunction was applied to the
administrative half (grant/revoke) but not to the content half, so **a Daughter key holding a
`can_manage` row can edit a hook's `script_path`** — repointing what code the daemon executes —
without holding `can_manage_keys` at all. `update_hook` at `src/api.rs:1550` calls `require_manage`,
which returns `Ok` on a bare permission row.

Two mitigations bound it, and neither closes it:

- `require_master_for_privileged_hook` makes any hook carrying `run_as_user` master-only to modify.
  Hooks *without* elevation are unprotected.
- `executor::validate_script_path` confines `script_path` to `ALLOWED_SCRIPT_ROOTS`. That variable
  **defaults to empty, meaning unrestricted**, and `src/config.rs:583` logs a warning saying so. In a
  default deployment the confinement is absent.

The severity gap between the two services follows from what the resource *is*: mis-editing an IP
group changes which addresses are blocked; mis-editing a hook changes which binary runs. The same
unenforced clause is worth materially more here.

---

## Task 7 — Remaining implementation choices

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| DDL foreign keys on `parent_key_id` / `owner_key_id` | None. Stated reason: **SQLite has no `ALTER TABLE … ADD CONSTRAINT`**, so the constraint would exist on Postgres/MySQL and silently not on the backend every test runs against | None. Stated reason: both available behaviours are wrong — `CASCADE` destroys resources §6 forbids destroying, `SET NULL` orphans them at exactly the moment the inventory should be showing them | **Equivalent outcome, peer's reasoning is more complete.** Peer names both the portability blocker *and* the semantic one; this repo names only the semantic one |
| Referential integrity substitute | Application-level, **both directions**: validated on assignment, and `delete_api_key` nulls daughters' `parent_key_id` and owned resources' `owner_key_id`. Reads treat a dangling owner as unowned | Application-level on assignment (owner must exist; reassignment target must exist and be outside the doomed subtree). Deletion path resolves owned resources via the §6 inventory rather than nulling | **Equivalent.** Different shapes, both fail closed |
| Unknown-field rejection mechanism | **None.** 0 uses of `deny_unknown_fields`. `is_master` is kept on the payload as a trap field and refused by `guard_no_master_flag` | `deny_unknown_fields` on both key payloads (7 uses total); `is_master` **removed from the struct entirely** | **`simply_hook_executor` stronger** — see prose |
| Status for a forbidden field | `400 Bad Request` | `422 Unprocessable Entity` | Equivalent; both are 4xx and both are deliberate |
| Is the field named in the response? | Yes — message names `'is_master'` explicitly | Yes — serde message names `is_master` *and* lists the accepted fields | Equivalent for the security property |
| §5 letter: "no payload may carry it" | **Violated in form.** `CreateApiKeyPayload.is_master: Option<bool>` exists at `api.rs:1718` | Satisfied — no such field | **`simply_hook_executor` stronger** on the letter; behaviour is equivalent |
| Master rotation refused for all callers | Yes — `guard_master_immutable`, both `/rotate` and `/rotate-secret` | Yes — `refuse_master_lifecycle_action` | Equivalent |
| Master deletion refused for all callers | Yes — same guard | Yes — same guard | Equivalent |
| Does either guarantee rest on uniqueness holding? | No — `guard_master_immutable` keys off `target.is_master` alone | No — barred "regardless of row count", deliberately two independent controls | Equivalent |
| Backfill posture | Everything `NULL`, deliberately; `NULL` reads as "no owner, therefore Master only" | Everything `NULL`, deliberately; ownerless hooks are master-only | Equivalent — both refuse to guess |
| Post-upgrade capability of existing rows | Every pre-migration group/webhook is master-only for lifecycle; recovery via owner-reassignment endpoint | Every pre-migration hook is master-only for lifecycle; recovery via `PUT /api/hooks/{id}` `owner_key_id` (master-only) | Equivalent; both documented with operator SQL |
| Mutation coverage | 12/12 rules fire | 14/14 mutation targets fire across 12 rules | Equivalent |
| Documented surviving mutations | M1a/M1b — the two `can_manage_keys` conjunct sites mask each other; M1c (both) fires. M4 — unreachable fail-closed branch | R2 global half survives at either site alone; fires when both are disabled together | **Equivalent, and independently identical.** Both found the same defence-in-depth masking |
| Mutations that reported false negatives | Three documented: operator-precedence error, string-not-check error, non-compiling mutation. Runner now `cargo check`s first | One documented: §4 oracle mutation initially survived because the test probed only `GET` — a genuine test gap, since fixed to walk six routes | **`simply_ip_vault` more rigorous on harness discipline;** this repo's one survivor was a real coverage gap it then closed |
| §7 schema assertion method | Queries `sqlite_master` directly — SQLite-specific, but catches an index that exists yet is *not unique* | `SchemaManager::has_index` (backend-agnostic) for presence; uniqueness asserted behaviourally in `s5_` | **Equivalent coverage, different trade.** Peer sacrifices portability for a sharper assertion; this repo splits it across two tests |
| §7 mutation applied | Index created **non-unique** | Index **omitted** | **`simply_ip_vault` sharper** — a present-but-non-unique index passes a name check and is the realistic regression |
| §4 minimal-view discriminator | `view: "full" \| "minimal"` — present on every entry | `partial: true` — present only on abridged entries | **`simply_ip_vault` marginally stronger**; a client can branch on `view` without knowing the absent case |
| §4 minimal-view field leakage | Documented wart: `bound_ips` serializes as `null` in the minimal view, ambiguous with genuinely unset | Withheld fields are **absent from the type**, not null | **`simply_hook_executor` stronger** — omission cannot be confused with emptiness |
| Compliance suite harness | Self-contained, own harness, deliberately not sharing the functional suites' helpers | Shares `tests/common` under `#[allow(dead_code)]` | **`simply_ip_vault` stronger** — a refactor of the functional helpers cannot silently weaken the model suite |
| Authentication posture | Mandatory full-URI HMAC + anti-replay on every key | Per-key configurable: `CANONICAL_V1`, `BODY_ONLY`, or unsigned bearer | **Intentional asymmetry — do not unify** |

**On the compliance suites, one asserts what the other assumes in three places.** The peer asserts
the §7 uniqueness constraint *behaviourally within the §7 test* and mutates the index to non-unique;
this repository asserts index presence in `s7_` and uniqueness in `s5_`, and never mutated the index
to non-unique — the omission mutation is the weaker probe, since a `create_index` call that silently
drops `.unique()` is the realistic regression and would pass a presence check. Conversely, this
repository asserts oracle discipline across **six HTTP routes per entity**, where the peer's
`s4_oracle_discipline_…` covers the key and group detail paths; this repo's broader sweep is what
caught its own initially-surviving mutation.

---

## Executive summary

**Aspects compared: 58**, across seven task areas, all verified against source in both repositories.
No file was modified.

**The headline is that the specification identity check ran for the first time and passed.** Both
copies of `RBAC_MODEL.md` are byte-identical (7846 bytes, `cmp` exit 0). Every previous audit
recorded this as pending because the peer carried no copy. It does now, and there is nothing to
reconcile.

**Genuine divergences — three, one of them a real weakness in this service:**

1. **§5 master uniqueness is enforced differently, and only one enforcement is unbypassable.**
   `simply_ip_vault`'s `master_marker` is an ordinary `VARCHAR(16)` maintained by application code;
   nothing in the schema ties it to `is_master`, so a row with `is_master = true` and a `NULL` marker
   is accepted by the database and honoured by every guard. `simply_hook_executor`'s marker is
   `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`, so the two columns cannot
   disagree. §5 requires enforcement "rather than by application logic alone"; the peer's rests on
   application logic for the half that matters. **`simply_hook_executor` is stronger.**

2. **R2 is fully enforced in the peer and partially enforced here.** `simply_ip_vault` splits
   `can_manage` (administrative) from `can_read`/`can_write`/`can_delete` (operational), so R2's
   conjunction governs everything `can_manage` can do. `simply_hook_executor` overloads `can_manage`
   to mean both "administer permission rows" and "edit the hook's definition", and applied the
   conjunction only to the first. A Daughter key holding a `can_manage` row can repoint a hook's
   `script_path` — changing what code the daemon runs — without holding `can_manage_keys`, which is
   the tier boundary §1 draws. `ALLOWED_SCRIPT_ROOTS` defaults to unrestricted, so the confinement
   that would bound it is absent by default. **`simply_hook_executor` is weaker, and this is the only
   rule in `RBAC_MODEL.md` on which it is.**

3. **The dispatch-target role is resolved in the peer and unresolved here.** `simply_ip_vault` has a
   real creator-private entity (`webhook_configs`) for §4's third scope. `simply_hook_executor` has
   none — `can_create_executor` appears nowhere in `src/`, there is no executor table, and a `Hook`
   holds both roles `RBAC_MODEL.md` says one entity cannot. Scope 3 was mapped onto `executions`,
   which is a defensible judgement the specification does not force.

**Specification defects — two, neither fixable by one service alone:**

- The Terminology table names `can_create_webhooks` and `can_create_executor` as the resource-creation
  rights. **Neither string exists in either codebase.** The real names are `can_manage_webhooks` /
  `can_create_groups` (two rights, where the table allows one) and `can_manage_hooks`.
- The same table maps a dispatch target to an "Executor" in `simply_hook_executor`, an entity that
  does not exist, which is what forced divergence 3.

Because the document is enforced byte-identical, correcting either requires a coordinated edit to
both copies; a unilateral fix would fork the specification and break the identity check that has only
just started passing.

**Intentional asymmetries — one, unchanged and out of scope:** the authentication posture.
`simply_ip_vault` mandates full-URI HMAC with anti-replay on every key; `simply_hook_executor`
supports a per-key posture so third-party webhook senders whose signature format cannot be changed
can still be accepted. Recorded, never scored.

**Everything else is equivalent**, including several places the two teams reached identically without
coordinating: NULL-only backfill for lineage and ownership, no DDL foreign keys with
application-level integrity in their place, master rotation and deletion refused for every caller
without leaning on the uniqueness constraint, and — most strikingly — the same defence-in-depth
masking discovered on the `can_manage_keys` conjunction, where mutating either enforcement site alone
survives and mutating both fires. Both documented it as defence in depth rather than as a coverage
gap, and both were right to.

**Stated plainly: `simply_hook_executor` is weaker than `simply_ip_vault` on exactly one rule — R2,
for resource content management — and stronger on §5.** On every other rule in `RBAC_MODEL.md` the
two are equivalent.
