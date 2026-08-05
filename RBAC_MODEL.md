# RBAC Model

Canonical permission model shared by `simply_ip_vault` and `simply_hook_executor`.

This file is the single source of truth for both services and is **byte-identical in both
repositories**. Convergence is measured against this document, not against the other service's
source code. Where the two services differ only in what a thing is called, the rule is stated
generically and both concrete nouns are given.

| Generic term | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| Resource | IP Group | Hook |
| Resource-creation right | `can_create_webhooks` | `can_create_hooks` |
| Outbound integration | Webhook | Executor |

## Tiers Matrix

| Tier | Granted by | May be a resource manager | Notes |
| :--- | :--- | :--- | :--- |
| **Master** (unique) | Bootstrap only | Yes, everywhere | All rights; sees everything |
| **Parent** (`can_manage_keys`) | Master only | Yes, where it holds a manage row | Creates daughter keys |
| **Daughter** (no `can_manage_keys`) | Master or any parent | Never | Rights ⊆ its creator's rights |

Resource-creation rights (`can_create_webhooks` / `can_create_hooks`) sit at the same tier as
`can_manage_keys`, are granted by master only, and are never implied by `can_manage_keys` —
managing keys and being able to create or point resources at arbitrary URLs/scripts are separate
powers.

## Core Rules

- **R1 — Non-amplification:** A caller may only grant rights it holds itself. A `can_execute`-only
  holder can grant `can_execute` and nothing more. Applies at every tier below master.
- **R2 — Manage is a conjunction:** Being a manager of a resource requires `can_manage_keys` AND a
  manage row on that specific resource. Neither alone is sufficient. `can_manage_keys` is never a
  global bypass of per-resource RBAC.
- **R3 — Parentage confers no authority:** `parent_key_id` exists for cascade and visibility scoping
  only. A daughter of the master key is an ordinary daughter with no elevated standing. Never derive
  a right from who created a key.
- **R4 — Only master creates parents:** Only the master may grant `can_manage_keys` or
  resource-creation rights (`can_create_webhooks` / `can_create_hooks`). A parent can never create
  another parent.
- **R5 — Manage may propagate sideways:** A parent holding manage on a resource may grant manage on
  that resource to another existing parent (bounded by R1 and R2), but this can never mint a new
  parent.
- **R6 — Revocation is never escalation:** Removing a permission requires manage on the resource
  only; the caller need not hold the verb being removed, and may revoke its own permissions.
  Reducing an existing permission row through a general update endpoint is a revocation and follows
  this same rule, regardless of which endpoint it arrives at.
- **R7 — Granting is bounded by R1 and R2 together.**

## Ownership and Resource Lifecycle

- Every resource (Group / Hook) carries an `owner_key_id`.
- Resource lifecycle actions (deleting or renaming the resource itself) are restricted to master and
  the owner. Holding manage, or any verb, on a resource does not confer lifecycle authority over it
  — a parent that merely uses a hook must not be able to delete it.
- The master may reassign `owner_key_id` on any resource at any time.

## Visibility

- Master sees everything.
- A parent sees its own subtree in full, minus secrets: its daughters, their rights, their
  bound_ips.
- A parent sees, in minimal form only, any key holding a permission row on a resource it manages:
  id, name, and that key's rights on that resource alone — never its global flags, bound_ips, or
  other resource memberships. A single shared resource must not become a keyhole into another
  parent's whole configuration.
- Webhooks and Executors are visible to their creator and master only. They are not exposed by the
  shared-resource rule above.
- Invisible must be indistinguishable from nonexistent. A request for a resource or key the caller
  cannot see returns the identical status and body it would return if the ID did not exist (404 vs
  403 oracle discipline).

## Master Key Handling

- Exactly one master key exists, enforced by a database constraint (a partial unique index on
  `is_master = true`), not by application logic alone.
- The master key is immutable through the API except for its own `bound_ips`, which it alone may
  edit. No other field, permission, or rotation is reachable through the API.
- The master key cannot be deleted through the API. Regeneration rule: delete the row directly in
  the database, and the service re-mints at next boot.

## Key Deletion and Ownership Inventory

- Deleting a key cascades to its daughter keys, recursively through the whole subtree.
- Data is never destroyed implicitly. Groups, Hooks, IP records, Webhooks, and Executors must never
  disappear as a side effect of removing a key.
- Before any key deletion, a pre-flight inventory walks the entire subtree being deleted and
  collects every resource owned by any key in it.
- If that inventory is non-empty, the deletion is refused and returns a structured payload
  enumerating each owned resource with enough detail to decide its fate (type, id, name, current
  owner).
- The caller then resubmits with a resolution map assigning each listed resource either deletion or
  reassignment to a named owner. The deletion executes only when every resource in the inventory has
  an explicit resolution — partial maps are refused.

## Schema and Indexing

- Partial unique index on `is_master = true`.
- Indexes on `parent_key_id`, `owner_key_id`, the key-hash lookup column, and the permission-table
  join columns.
