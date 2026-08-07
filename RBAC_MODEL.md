# Canonical RBAC & Authorization Model

**Status:** Normative specification. **Scope:** `simply_ip_vault` and `simply_hook_executor`.

This document is the single source of truth for the authorization and permission model shared by both
services. It is **byte-identical in both repositories**; `scripts/verify_convergence.sh` enforces that.
Where a rule concerns a service-specific noun, the rule is stated generically and both concrete nouns
are named explicitly.

Neither repository's `AGENT.MD` overrides this document. Where an `AGENT.MD` and this specification
disagree, this specification is correct and the `AGENT.MD` is stale.

## Terminology

| Generic term | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| **Managed resource** (shared, permission rows) | IP Group | Hook |
| **Resource data** (contained records) | IP Record | — |
| **Dispatch target** (creator-private) | Webhook Config | Executor |
| **Resource-creation right** | `can_create_webhooks` | `can_create_executor` |
| **Per-resource permission table** | `api_key_group_permissions` | `api_key_hook_permissions` |

A **managed resource** is shared: multiple keys may hold permission rows on it, and it is governed by
the tier and conjunction rules below. A **dispatch target** is creator-private: it is visible only to
its creator and Master, and is never exposed by the shared-resource visibility rule.

---

## 1. Permission Tiers

| Tier | Granted by | May manage resources | Notes |
| :--- | :--- | :--- | :--- |
| **Master** (unique) | Bootstrap only | Yes, everywhere | Full system control; bypasses scoping; sees all entities |
| **Parent** (`can_manage_keys`) | Master only | Yes, where a `can_manage` row is held | May create daughter keys and delegate rights to them |
| **Daughter** (no `can_manage_keys`) | Master or any parent | Never | Rights ⊆ its creator's rights; cannot create keys |

Resource-creation rights (`can_create_webhooks` / `can_create_executor`) sit at the same tier as
`can_manage_keys`, are granted strictly by Master, and are never implied by `can_manage_keys` or by
resource management rights. Managing keys and being able to point a dispatch target at an arbitrary
URL are separate powers.

---

## 2. Core Governance Rules

- **R1 — Non-amplification.** A caller may only grant rights it currently holds itself. A holder of a
  single read-level verb may grant that verb and nothing more. Applies at every tier below Master.
- **R2 — Manage is a conjunction.** Managing a specific resource requires holding both global
  `can_manage_keys` AND a `can_manage = true` row for that specific resource. Neither alone is
  sufficient. `can_manage_keys` is never a global bypass of per-resource RBAC.
- **R3 — Parentage confers no authority.** `parent_key_id` exists solely for cascading deletion and
  visibility scoping. A daughter of the Master key is an ordinary daughter key with no elevated
  standing. Rights are never derived from key lineage.
- **R4 — Only Master creates parents.** Only the Master key may grant `can_manage_keys` or
  resource-creation rights. A parent key can never mint another parent key.
- **R5 — Manage may propagate sideways.** A parent holding manage rights on a resource may grant
  manage rights on that resource to another existing parent key (bounded by R1 and R2), but this can
  never elevate a daughter key to parent status.
- **R6 — Revocation is never escalation.** Removing a permission requires manage rights on the
  resource only; the revoker need not hold the verb being removed, and may revoke its own
  permissions. Reducing an existing permission row through a general update endpoint is classified as
  revocation under this rule, regardless of which endpoint it arrives at.
- **R7 — Granting is bounded by R1 and R2 together**, simultaneously and without exception.

---

## 3. Resource Lifecycle & Ownership

- Every managed resource and every dispatch target (IP Group / Hook, Webhook Config / Executor)
  carries an `owner_key_id`.
- Resource lifecycle actions — deleting or renaming the entity itself — are restricted exclusively to
  Master and the designated `owner_key_id`. Holding manage rights or any operational verb confers no
  lifecycle authority: a parent that merely uses a resource must not be able to delete it.
- Master may reassign `owner_key_id` on any resource or dispatch target at any time.

---

## 4. Visibility & Oracle Discipline

- **Master:** full visibility over all keys, resources, dispatch targets, and configuration.
- **Own subtree:** a parent sees its own key subtree in full, minus raw secrets — its daughters, their
  granted rights, and their bound IPs.
- **Shared resources:** a parent sees, in minimal form only, any key holding a permission row on a
  resource it manages: id, name, and that key's rights on that resource alone. Global flags, bound
  IPs, and unrelated resource memberships remain hidden. A single shared resource must never become a
  keyhole into another parent's whole configuration.
- **Dispatch targets:** visible exclusively to their creator and Master. They are never exposed by the
  shared-resource rule above.
- **Oracle discipline.** Any key, resource, or dispatch target outside the caller's visibility scope
  must return the identical status and body the service would return if that id did not exist. This
  governs *authenticated* callers distinguishing absent from invisible. It is a distinct control from
  the authenticate-then-authorize ordering rule, which governs *unauthenticated* callers probing key
  bindings via 401-vs-403. Both hold simultaneously; neither may be satisfied by regressing the other.

---

## 5. Master Key Guarantees

- Exactly one Master key exists, enforced by a database constraint rather than by application logic
  alone. Where the target engine supports partial unique indexes, use one on `is_master = true`. Where
  it does not, an equivalent portable constraint must be used — for example a nullable
  `master_marker` column carrying a single non-null value, under a plain unique index, since null
  values do not collide.
- `is_master` must not be settable or clearable through any API endpoint. A Master key cannot mint a
  second Master, and no key-creation or key-update payload may carry it.
- The Master key is immutable through the API **except for its own `bound_ips`**, which it alone may
  edit. No other field, permission, or rotation is reachable through the API.
- The Master key cannot be deleted through the API. Regeneration is: delete the row directly in the
  database; the service re-mints at next boot.

---

## 6. Cascade Deletion & Pre-flight Inventory

- Deleting a key cascades recursively through its entire daughter subtree.
- **Data is never destroyed implicitly.** IP Groups, Hooks, IP Records, Webhook Configs, and Executors
  must never disappear as a side effect of removing a key.
- **Pre-flight inventory.** Before any key deletion, the service walks the entire subtree being
  deleted and collects every resource and dispatch target owned by any key within it.
- If that inventory is non-empty, the deletion is refused and returns a structured payload enumerating
  each owned entity with enough detail to decide its fate: type, id, name, and current owner.
- The caller then resubmits with a resolution map assigning every listed entity either deletion or
  reassignment to a named owner key. Deletion executes only when every entity in the inventory carries
  an explicit resolution; partial maps are refused.

---

## 7. Database Constraints & Indexing

- A database-level constraint guaranteeing Master uniqueness, per §5.
- Indexes on `parent_key_id`, `owner_key_id`, the key-hash lookup column, and the permission-table
  join columns — every column the authenticated hot paths search on.