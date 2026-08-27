# API Reference — `simply_hook_executor`

Exhaustive catalog of every HTTP endpoint this daemon exposes, generated from a direct audit of
`src/lib.rs` (route table) and every handler under `src/api/`. Companion documents: `AGENT.MD`
(architecture), `SCHEMA.MD` (database), `RBAC_MODEL.md` (the normative authorization spec this
document's guard descriptions summarize — that file wins on any conflict), `FILE_MAP.MD` (file
layout).

## Conventions used throughout this document

- **Method & Path** — the exact route as registered in `src/lib.rs`, including verb aliases.
- **Auth** — which middleware layer guards the route, and what credential it requires. See
  [Authentication model](#authentication-model) below for the shared mechanics.
- **RBAC Guard** — the specific authorization rule the handler applies *after* authentication,
  phrased in `RBAC_MODEL.md`'s own terms (§ and R references are to that document).
- **Query Parameters** / **Request Body** — every field of the corresponding `struct`, with its
  Rust type, optionality, and default. Every query struct and JSON payload in this service derives
  `#[serde(deny_unknown_fields)]`, enforced through the `Strict*` extractors in `src/extract.rs`: an
  unrecognized field is a `400`, not a silently ignored no-op.
- **Response** — the success shape and status, followed by the status codes a caller should expect
  to handle and what triggers each. Every error response — regardless of status — is
  `{"error": "<message>"}` with `Content-Type: application/json` (see
  [Standard error envelope](#standard-error-envelope)), except `AppError::ConflictWithDetails`
  (`DELETE /api/keys/{id}`'s inventory refusal), which merges extra top-level fields into that same
  envelope.

## Base URL structure

Everything under `/api/*` is the administrative surface. `/webhook/{identifier}` is a separate,
top-level mount for third-party senders. Two liveness/readiness paths (each with a Kubernetes-style
alias) and the static single-page dashboard sit outside both. There is no API versioning prefix.

| Prefix | Contents |
| :--- | :--- |
| `/api/*` | Every administrative route — hook/key/permission CRUD, execution history, audit logs, settings. Always behind `auth_middleware`, **except** `/api/hooks/{id}/execute` and `/api/hooks/{id}/test`. |
| `/webhook/{identifier}` | The webhook-facing alias of `POST /api/hooks/{id}/execute`, for third-party senders posting to a fixed URL. |
| `/health`, `/healthz`, `/ready`, `/readyz` | Unauthenticated liveness/readiness probes. |
| `/*` (fallback) | The static SPA (`static/`), served via `ServeDir`. |

## Authentication model

Three middleware postures exist, chosen per route group in `src/lib.rs`:

1. **`auth_middleware`** — every route under `admin_routes`. A valid `X-API-Key` is *always*
   mandatory; there is no keyless path. This is the large majority of `/api/*`.
2. **`invocation_auth_middleware`** — exactly three routes: `POST /api/hooks/{id}/execute`,
   `POST /api/hooks/{id}/test`, and `POST /webhook/{identifier}`. These alone may authorize a caller
   presenting **no** `X-API-Key` at all, governed per-hook by `hook.auth_mode` (see
   [Per-hook `auth_mode`](#per-hook-auth_mode-keyless-invocation) below).
3. **None** — `/health`, `/healthz`, `/ready`, `/readyz`, and the static asset fallback. Deliberately
   public: an orchestrator's liveness/readiness probe has no credential and must not need one.

### Headers

| Header | Required when | Purpose |
| :--- | :--- | :--- |
| `X-API-Key` | Every `/api/*` admin route; a keyed invocation. | Bearer credential. Hashed and matched against `api_keys.key_hash`. |
| `X-Timestamp` | Whenever a signature is presented. Unconditionally mandatory for any key with `hmac_mode = CANONICAL_V1` that is also signing. | Unix timestamp in seconds, bound into the signed material. Must be within `signature_max_age_seconds` (default 300s) of the server's clock in either direction. |
| `X-Signature-256` | Mandatory for every `can_manage_keys` holder, and whenever `REQUIRE_SIGNED_REQUESTS=true` deployment-wide. Optional (but honored if present) for every other keyed request. | `sha256=<hex>` — HMAC-SHA256 over the canonical string (see below), keyed by the caller's `signing_secret`. |

**When is signing mandatory?** `signature_required = REQUIRE_SIGNED_REQUESTS || (key.can_manage_keys && !key.is_master)`.
A `can_manage_keys` holder must always sign, regardless of the global setting — RBAC's highest
non-master scope is never allowed to rely on a bare bearer key. The WebUI dashboard itself signs
*every* request unconditionally, independent of whether the acting key strictly requires it.

**Canonical string** (`CANONICAL_V1`, the only `hmac_mode`): `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY`,
or a hook's/key's own `canonical_template` override when one is configured, in that precedence order
(target hook's template, if its own `auth_mode = CANONICAL_V1` → the signing key's own template →
the service-wide default). `PATH_AND_QUERY` is the *original* request URI the client sent, including
any reverse-proxy prefix — `Router::nest`'s internal prefix-stripping is undone before the string is
built, so signing must be computed against the path the client actually requested.

**Anti-replay.** Every accepted signature is recorded for the duration of `signature_max_age_seconds`;
an identical `(key, digest)` pair presented a second time inside that window is refused with `401`
("This signature has already been used; sign a fresh request") — a *distinct* condition from an
invalid or expired key, not merely a stricter phrasing of the same failure.

### Per-hook `auth_mode` (keyless invocation)

Applies only to the three invocation routes, and only when the caller presents **no** `X-API-Key`.
A keyed caller is authenticated exactly as on any other route regardless of the target hook's mode.

| `auth_mode` | Keyless behavior |
| :--- | :--- |
| `CANONICAL_V1` (default) | Refused — a valid, permitted `X-API-Key` is required. |
| `API_KEY_ONLY` | Refused, identically to `CANONICAL_V1` from a keyless caller's perspective — the two modes only differ in what they document about a *keyed* caller's expectations. |
| `HMAC_ONLY` | Accepted if the request carries a valid HMAC-SHA256 signature over the raw body — verified against the hook's own `hmac_secret` (never a key's) — on the header named by `signature_header` (default `X-Signature-256`), with the value's `signature_prefix` (default `sha256=`) stripped before hex-decoding. **No timestamp, no anti-replay protection** — the GitHub/Forgejo/GitLab third-party-webhook shape. |
| `NONE` | Accepted outright — no authentication of any kind — but only when the deployment's `REQUIRE_SIGNED_REQUESTS` is `false`, and only when the request carries no signature material at all (a stray signature header on a `NONE` hook is refused rather than silently ignored). |

A keyless failure on any of the three invocation routes — no such hook, a hook requiring a key, a
`NONE` hook currently blocked by `REQUIRE_SIGNED_REQUESTS`, or unexpected signature material — always
returns the *same* fixed `401` body (`invocation_unauthorized`), deliberately indistinguishable from
every other keyless failure: distinguishing them would let an uncredentialed caller enumerate which
hook names exist or which are configured for public access.

### Standard error envelope

Every non-2xx response is `{"error": "<message>"}`, `Content-Type: application/json`, produced by
`AppError`'s single `IntoResponse` implementation — no handler hand-rolls an error body.

| Status | `AppError` variant | Meaning |
| :--- | :--- | :--- |
| `400 Bad Request` | `InvalidInput`, or a `Strict*` extractor rejection (malformed JSON, an unrecognized field, a query value that fails to parse, a malformed path segment) | The request is syntactically or semantically invalid. |
| `401 Unauthorized` | `Unauthorized` | Missing/invalid `X-API-Key`, missing/malformed/stale `X-Timestamp`, missing/malformed/invalid signature, or a replayed signature. |
| `403 Forbidden` | `Forbidden` | Authenticated, but lacking the specific permission the action requires. |
| `404 Not Found` | `NotFound` | The resource does not exist, **or** exists but is outside the caller's visibility scope under `RBAC_MODEL.md` §4's oracle discipline — the two are always indistinguishable by design. |
| `409 Conflict` | `Conflict`, `ConflictWithDetails` | A uniqueness collision (duplicate hook/parameter name), or (`DELETE /api/keys/{id}`) an unresolved §6 ownership inventory — see that endpoint's own section. |
| `413 Payload Too Large` | `BodyRejected` (via `DefaultBodyLimit`) | Body exceeds `MAX_REQUEST_BODY_BYTES` (3 MiB), applied router-wide with no per-route override. |
| `429 Too Many Requests` | `TooManyRequests` | The acting key's `max_concurrent_jobs` execution budget is currently exhausted. |
| `500 Internal Server Error` | `Internal`, `DbError` | An unexpected server-side failure. Database errors are logged in full server-side and reported generically — never echoing driver internals to the caller. |

---

## Identity

### `GET /api/auth/me`

The identity and scope payload the SPA renders its tabs from.

- **Auth:** `auth_middleware` — valid `X-API-Key`.
- **RBAC Guard:** none beyond authentication — every key may read its own identity.
- **Query Parameters:** none.
- **Request Body:** none.
- **Response `200 OK`** — `MeResponse`:

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `id` | `Uuid` | API key ID. |
  | `name` | `String` | Key name. |
  | `prefix` | `String` | First 8 characters of the plaintext key, for display. |
  | `key_id` | `Option<String>` | Public signing identifier, if this key has a signing pair. |
  | `hmac_mode` | `HmacMode` (`"CANONICAL_V1"`, the only value) | Signature verification mode. |
  | `canonical_template` | `Option<String>` | Custom canonical-string template override. Always `null` while `can_manage_keys` is `true`. |
  | `bound_ips` | `Option<String>` | Comma-separated CIDR allowlist. |
  | `max_concurrent_jobs` | `i32` | Simultaneous execution budget. |
  | `is_master` | `bool` | Master status. |
  | `can_manage_keys` | `bool` | Global key-management scope. |
  | `can_manage_hooks` | `bool` | Global hook-creation scope. |
  | `hook_permissions` | `Vec<HookPermissionView>` | Per-hook grants (see shape below). |
  | `keyless_hooks_allowed` | `bool` | Whether this deployment can actually reach a `NONE`-mode hook keylessly (`!require_signed_requests`). |

  `HookPermissionView`: `{ hook_id: Uuid, hook_name: String, can_execute: bool, can_manage: bool, can_view_execution: bool }`.

---

## Hooks

### `POST /api/hooks`

Declares a new hook, optionally with its parameter contract, in one request.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `is_master || can_manage_hooks`. `run_as_user` (any non-empty value) is
  **master-only** — checked before any other field validation, so a non-master's escalation attempt
  surfaces as `403` regardless of whether the rest of the payload is well-formed. Creating auto-grants
  the creator full rights (`can_execute`, `can_manage`, `can_view_execution`) on the new hook and sets
  `owner_key_id` to the creator.
- **Query Parameters:** none.
- **Request Body** — `CreateHookPayload`:

  | Field | Type | Required | Default | Description |
  | :--- | :--- | :--- | :--- | :--- |
  | `name` | `String` | yes | — | Unique hook name. Restricted to RFC 3986 `unreserved` characters (`A-Za-z0-9._~-`) — the name doubles as the `/webhook/{name}` path segment. |
  | `description` | `Option<String>` | no | `null` | Free-text summary. |
  | `script_path` | `String` | yes | — | Absolute path to the executable; must resolve inside `ALLOWED_SCRIPT_ROOTS` if configured, and contain no traversal. |
  | `default_timeout_seconds` | `Option<i32>` | no | `30` | Max runtime, `1..=86400`. |
  | `run_as_user` | `Option<String>` | no | `null` | OS account to run as via `sudo`. **Master-only.** |
  | `parameters` | `Option<Vec<ParameterInput>>` | no | `[]` | Inline parameter contract — see shape below. |
  | `auth_mode` | `Option<AuthMode>` | no | `"CANONICAL_V1"` | Keyless-invocation mode — see [Per-hook `auth_mode`](#per-hook-auth_mode-keyless-invocation). |
  | `hmac_secret` | `Option<String>` | required iff `auth_mode = "HMAC_ONLY"` | `null` | Plaintext `HMAC_ONLY` signing secret. Sealed at rest; never returned. |
  | `signature_header` | `Option<String>` | no | `"X-Signature-256"` | Header an `HMAC_ONLY` sender's signature arrives on. |
  | `signature_prefix` | `Option<String>` | no | `"sha256="` | Prefix stripped before hex-decoding an `HMAC_ONLY` signature. |
  | `canonical_template` | `Option<String>` | no | service default | Per-hook `CANONICAL_V1` template override. |
  | `sample_payload_json` | `Option<String>` | no | `null` | Example JSON body. If set alongside declared parameters, every parameter key must appear as a top-level field. |
  | `args_template` | `Option<String>` | no | `null` | Argument-vector template (e.g. `add bad_ip ${target_ip}`). **Not** validated against `parameters` at creation time (deferred to the parameter-CRUD endpoints and to execution time) — see the endpoint's inline rationale. |

  `ParameterInput`: `{ param_key: String (must match [A-Za-z_][A-Za-z0-9_]*), description: Option<String>, default_value: Option<String>, is_required: Option<bool> (default true) }`.

- **Response `200 OK`** — `HookDetail` (see [`HookDetail` shape](#hookdetail-shape) below).
- **Errors:** `400` invalid name/script_path/timeout/param_key/`sample_payload_json`/`args_template`
  shape; `403` non-master requesting `run_as_user` or lacking `can_manage_hooks`; `409` a hook (live
  or trashed) already holds that name.

### `GET /api/hooks`

Lists every hook the caller can see.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** listing is filtered to visible hooks (§4): master sees everything; every other key
  sees hooks it owns or holds any permission row on. Soft-deleted hooks are omitted unless
  `include_deleted=true`, which is **master-only**.
- **Query Parameters** — `ListHooksQuery`: `include_deleted: Option<bool>` (default `false`).
- **Request Body:** none.
- **Response `200 OK`** — `Vec<HookDetail>`.
- **Errors:** `403` a non-master requests `include_deleted=true`.

### `GET /api/hooks/{identifier}`

One hook, by UUID or name.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_visibility` — master, the hook's owner, or any explicit permission row
  (`can_execute`, `can_manage`, or `can_view_execution`) confers read access. Everything else is
  `404` (§4 oracle discipline — never `403`). A soft-deleted hook is `404` unless requested with
  `?include_deleted=true` by a master.
- **Query Parameters** — `ListHooksQuery`: `include_deleted: Option<bool>` (default `false`,
  master-only when `true`).
- **Request Body:** none.
- **Response `200 OK`** — `HookDetail`.
- **Errors:** `404` not found or not visible; `403` a non-master requests `include_deleted=true`.

### `PUT /api/hooks/{identifier}` (alias: `PATCH /api/hooks/{identifier}`)

Updates a hook's definition in place. Every field of `UpdateHookPayload` is optional; an absent
field is left untouched (`PATCH` is accepted as a literal synonym for `PUT` here, since every field
is already optional under either verb).

- **Auth:** `auth_middleware`.
- **RBAC Guard**, applied in order:
  1. `guard_manage` — master, the hook's owner, **or** R2 in full (`can_manage_keys` **and** a
     `can_manage = true` row on this hook).
  2. `guard_dispatch_configuration` — only when `script_path`, `run_as_user`, or `args_template` is
     named: R2 in full, **with no ownership exception** (`RBAC_MODEL.md`'s Dispatch Configuration
     clause). An owner whose `can_manage_hooks`/manage row has lapsed cannot repoint what the hook
     executes even though it may still edit its description.
  3. `guard_master_for_privileged_hook` — a hook already carrying a non-empty `run_as_user` is
     master-only to touch *at all*.
  4. `run_as_user` (a non-empty new value) — **master-only**, checked immediately after the guards
     above and before any other field validation.
  5. `guard_lifecycle_authority` — only when `name` is present (a rename): master or the hook's owner
     only; managing a hook confers no lifecycle authority.
  6. `owner_key_id` — **master-only**; the only way ownership ever moves.
- **Query Parameters:** none.
- **Request Body** — `UpdateHookPayload` (all optional; `""` on a nullable text field clears it,
  field-absent leaves it untouched):

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `name` | `Option<String>` | New name — lifecycle action, same charset restriction as creation. |
  | `description` | `Option<String>` | New description. |
  | `script_path` | `Option<String>` | New script path — dispatch configuration. |
  | `default_timeout_seconds` | `Option<i32>` | New timeout, `1..=86400`. |
  | `run_as_user` | `Option<String>` | New elevation account, or `""` to drop it — dispatch configuration, master-only to set non-empty. |
  | `owner_key_id` | `Option<Uuid>` | New owner — master-only. |
  | `auth_mode` | `Option<AuthMode>` | New keyless-invocation mode. |
  | `hmac_secret` | `Option<String>` | New `HMAC_ONLY` secret, or `""` to clear (refused while `auth_mode = HMAC_ONLY`). |
  | `signature_header` | `Option<String>` | New `HMAC_ONLY` header, or `""` to reset to the default. |
  | `signature_prefix` | `Option<String>` | New `HMAC_ONLY` prefix, or `""` to reset to the default. |
  | `canonical_template` | `Option<String>` | New template override, or `""` to reset to the service default. |
  | `sample_payload_json` | `Option<String>` | New sample, or `""` to clear. Re-validated against the hook's *current* parameter set. |
  | `args_template` | `Option<String>` | New template, or `""` to clear. Re-validated against the hook's *current* parameter set — dispatch configuration. |

- **Response `200 OK`** — `HookDetail`.
- **Errors:** `400` invalid field value or a template now referencing an undeclared parameter; `403`
  any guard failure above; `404` not found/not visible; `409` another hook already uses the requested
  name.

### `DELETE /api/hooks/{identifier}?hard={bool}`

Moves a hook to the trash (default), or — master-only, `?hard=true` — drops it outright, cascading
its parameters, permission grants, and entire execution history.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_manage`, then `guard_lifecycle_authority` (master or owner only — managing
  does not confer deletion authority), then `guard_master_for_privileged_hook`. `?hard=true` is
  additionally and unconditionally **master-only**, checked again inside the handler.
- **Query Parameters** — `DeleteHookQuery`: `hard: Option<bool>` (default `false`).
- **Request Body:** none.
- **Response:** `204 No Content` on success (either mode).
- **Errors:** `403` non-owner/non-master, a privileged hook touched by a non-master, or a non-master
  requesting `?hard=true`; `404` not found/not visible (or, for a soft delete, already trashed by a
  concurrent request).

### `POST /api/hooks/{identifier}/restore`

Brings a soft-deleted hook back, keeping its `script_path` and `run_as_user` (potentially
privileged) intact.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** **master-only**, unconditionally.
- **Query Parameters:** none.
- **Request Body:** none.
- **Response `200 OK`** — `HookDetail`.
- **Errors:** `403` non-master; `400` the hook is not currently deleted; `404` no such hook.

---

## Hook Parameters

### `GET /api/hooks/{identifier}/parameters`

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_visibility` (same as `GET /api/hooks/{identifier}`).
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `Vec<hook_parameter::Model>`, in declaration order (the order used for
  positional CLI arguments): `{ id, hook_id, param_key, description, default_value, is_required, created_at }`.
- **Errors:** `404` not found/not visible.

### `POST /api/hooks/{identifier}/parameters`

Declares one parameter.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_manage`, then `guard_master_for_privileged_hook` — a parameter is argv for
  the elevated command, so declaring one on a privileged hook is master-only.
- **Query Parameters:** none.
- **Request Body** — `ParameterInput` (see shape under `POST /api/hooks`).
- **Response `200 OK`** — the created `hook_parameter::Model`.
- **Errors:** `400` invalid `param_key`; `403` guard failure; `404` not found/not visible; `409`
  parameter already declared on this hook.

### `PUT /api/hooks/{identifier}/parameters/{param_id}`

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_manage`, then `guard_master_for_privileged_hook`.
- **Query Parameters:** none.
- **Request Body** — `UpdateParameterPayload`: `{ description: Option<String>, default_value: Option<String>, is_required: Option<bool> }` — all optional, absent leaves untouched. `param_key` is not editable (it is the row's identity).
- **Response `200 OK`** — the updated `hook_parameter::Model`.
- **Errors:** `403` guard failure; `404` hook or parameter not found (or the parameter does not
  belong to this hook).

### `DELETE /api/hooks/{identifier}/parameters/{param_id}`

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_manage`, then `guard_master_for_privileged_hook`. Additionally refuses
  (`400`) if the hook's `args_template` still references the parameter being removed — the
  load-bearing half of this endpoint's re-validation, since shrinking the declared set is the one
  way a deletion can break that invariant.
- **Query Parameters:** none. **Request Body:** none.
- **Response:** `204 No Content`.
- **Errors:** `400` still referenced by `args_template`; `403` guard failure; `404` hook or parameter
  not found.

---

## Hook Execution

These are the only three routes behind `invocation_auth_middleware` rather than `auth_middleware` —
see [Authentication model](#authentication-model) and [Per-hook `auth_mode`](#per-hook-auth_mode-keyless-invocation).

### `POST /api/hooks/{identifier}/execute`

Runs a hook and returns its recorded outcome.

- **Auth:** `invocation_auth_middleware` — a valid keyed request, **or** a keyless one the target
  hook's `auth_mode` accepts.
- **RBAC Guard:** `guard_execute` for a keyed caller (master, or an explicit `can_execute` grant) —
  skipped entirely for a keyless caller, since the hook's own `auth_mode` is the authorization.
- **Query Parameters:** none.
- **Request Body:** raw bytes, accepted in either of two shapes: `{"parameters": {"key": "value", ...}}`
  (this service's own convention) or a flat `{"key": "value", ...}` document (so a third-party
  webhook sender's native payload works without a wrapper). An empty body is a valid "no parameters"
  request.
- **Response `200 OK`** — `ExecutionView` (the request itself always succeeds if it reaches this far;
  a non-zero script exit is a normal, fully-recorded outcome reported in the body, not an HTTP
  failure):

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `id` | `Uuid` | Execution ID. |
  | `hook_id` | `Uuid` | Executed hook's ID. |
  | `hook_name` | `String` | Executed hook's name. |
  | `api_key_id` | `Option<Uuid>` | Acting key's ID, or `null` for a keyless invocation (or a since-deleted key). |
  | `api_key_name` | `Option<String>` | Acting key's name at read time, or `null`. |
  | `status` | `"SUCCESS" \| "FAILED" \| "TIMEOUT"` | Outcome. |
  | `exit_code` | `Option<i32>` | Sub-process exit code (`128 + signum` if signalled). |
  | `stdout` / `stderr` | `String` | Captured output, truncated at `max_output_bytes` per stream. |
  | `parameters` | `serde_json::Value` | Resolved parameters actually passed to the process. |
  | `duration_ms` | `i32` | Wall-clock duration. |
  | `timestamp` | `NaiveDateTime` | Execution start time. |
  | `caller_ip` | `String` | Resolved client IP (trust-aware: `X-Forwarded-For`/`X-Real-IP` only from a configured trusted proxy, the raw TCP peer otherwise). Empty for a pre-migration record. |

- **Errors:** `400` a required parameter is missing (with no default), or a value fails
  `args_template` substitution; `401` invocation authentication failed (fixed generic body); `403` a
  keyed caller lacks `can_execute`; `404` no such hook; `429` the acting key's concurrency budget is
  exhausted.

### `POST /webhook/{identifier}`

Byte-identical alias of `POST /api/hooks/{identifier}/execute`, mounted at a shorter, fixed URL for
third-party senders (GitHub/Forgejo/GitLab-style webhooks) that cannot be configured with the
`/api/hooks/.../execute` shape. Same auth, same guard, same request/response contract.

### `POST /api/hooks/{identifier}/test`

Dry run: resolves parameters and renders the exact command that *would* run, without spawning
anything or writing an execution record.

- **Auth:** `invocation_auth_middleware` (identical keyed/keyless rules to `execute`).
- **RBAC Guard:** `guard_execute` for a keyed caller (skipped for keyless) — a dry run reveals the
  fully-resolved command line and child environment, which is execution-shaped knowledge even though
  nothing runs.
- **Query Parameters:** none.
- **Request Body:** same two accepted shapes as `execute`.
- **Response `200 OK`** — `TestHookResponse`:

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `hook_id` / `hook_name` | `Uuid` / `String` | Target hook. |
  | `would_execute` | `bool` | Whether an equivalent `/execute` call would actually run. |
  | `blocking_reason` | `Option<String>` | Why not, when `would_execute` is `false`. |
  | `resolved_parameters` | `serde_json::Value` | Merged defaults and caller overrides. |
  | `missing_required` | `Vec<String>` | Required parameters neither supplied nor defaulted. |
  | `command` | `Option<CommandPlan>` | The exact program, argv, and environment that would run. `null` exactly when `blocking_reason` names an `args_template` substitution failure. |
  | `timeout_seconds` | `u64` | The timeout that would apply. |

- **Errors:** `401` invocation authentication failed; `403` a keyed caller lacks `can_execute`;
  `404` no such hook. Never `400` — a would-be-blocking condition is reported as data
  (`blocking_reason`/`would_execute: false`), not a request failure.

---

## Execution History

### `GET /api/executions`

Newest-first execution history, scoped to what the caller may read.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** §4's third scope (creator-private), applied as a query filter rather than a
  post-hoc trim: master sees everything; every other key sees its own runs (`api_key_id` match) plus
  every run on a hook it may read history for (`may_read_execution`'s four routes — owner, an
  explicit `can_view_execution` grant, or `can_manage`). Filtering by `hook` additionally requires
  `guard_visibility` on that specific hook.
- **Query Parameters** — `ExecutionQuery`:

  | Field | Type | Default | Description |
  | :--- | :--- | :--- | :--- |
  | `hook` | `Option<String>` | — | Restrict to one hook, by UUID or name. |
  | `status` | `Option<String>` | — | `SUCCESS` \| `FAILED` \| `TIMEOUT`, case-insensitive. |
  | `api_key` | `Option<String>` | — | Restrict to one acting key, by UUID (exact) or name (substring, case-insensitive). A keyless execution never matches. |
  | `since` / `until` | `Option<String>` | — | RFC 3339 instant bounds (`since` inclusive, `until` exclusive). |
  | `limit` | `Option<u64>` | `50` | Legacy pagination size. Ignored if `page`/`per_page` is present. |
  | `offset` | `Option<u64>` | `0` | Legacy pagination offset. Ignored if `page` is present. |
  | `page` | `Option<u64>` | `1` | 1-indexed page number — takes precedence over `offset`. |
  | `per_page` | `Option<u64>` | `50` | Items per page — takes precedence over `limit`. |

  Every resolved `limit`/`offset` is saturating-clamped to `i64::MAX`, so an extreme or overflow-prone
  `page`×`per_page` product can never panic or misbehave; a page past the real row count returns a
  clean `200` with an empty array rather than a database error.

- **Request Body:** none.
- **Response `200 OK`** — `Vec<ExecutionView>` (see shape under `POST /api/hooks/{identifier}/execute`),
  **plus response headers** carrying pagination metadata (not a body envelope, so every existing
  caller expecting a bare array is unaffected):

  | Header | Description |
  | :--- | :--- |
  | `X-Total-Count` | Total rows matching the filters, across every page. |
  | `X-Page` | The page this response represents (1-indexed). |
  | `X-Per-Page` | Rows per page actually applied. |
  | `X-Total-Pages` | `ceil(X-Total-Count / X-Per-Page)`, minimum `1`. |

- **Errors:** `400` invalid `status` value or malformed `since`/`until`; `404` `hook` names something
  not visible to the caller.

### `GET /api/executions/{id}`

One execution with its full captured output.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `may_read_execution` — master, the acting key, the hook's owner, or an explicit
  `can_view_execution`/`can_manage` grant on the hook. Anything else is `404`, never `403` (§4 oracle
  discipline: a record the caller may not read must be indistinguishable from one that was never
  written).
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `ExecutionView`.
- **Errors:** `404` not found or not visible.

### `DELETE /api/executions/{id}`

Removes a single history entry.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `guard_manage` on the execution's parent hook — deliberately *stricter* than
  reading: `can_view_execution` grants visibility, never the right to destroy the record. An auditor
  is not a redactor.
- **Query Parameters:** none. **Request Body:** none.
- **Response:** `204 No Content`.
- **Errors:** `403` visible but not manageable; `404` no such execution, or its parent hook no longer
  exists.

### `DELETE /api/executions?older_than_days={i64}`

Runs the retention sweep on demand, deleting execution records older than the threshold.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** **master-only** — this deletes history across every hook in the system regardless
  of the caller's own per-hook grants.
- **Query Parameters** — `PurgeQuery`: `older_than_days: Option<i64>` (default: the configured
  `LOG_RETENTION_DAYS`; `0` is a deliberate no-op, "keep forever", matching the config setting's own
  spelling — not "delete everything").
- **Request Body:** none.
- **Response `200 OK`** — `{"purged": <u64>, "older_than_days": <i64>}`.
- **Errors:** `400` `older_than_days` negative; `403` non-master.

---

## API Keys

### `POST /api/keys`

Mints a new API key.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `is_master || can_manage_keys` to call this endpoint at all. Granting
  `can_manage_keys` or `can_manage_hooks: true` in the same request is **master-only**
  (`guard_master_to_grant_scopes`) — checked before any other field validation. `can_manage_keys: true`
  additionally requires `hmac_mode = CANONICAL_V1` (the only value) and no custom `canonical_template`
  (`guard_canonical_v1_for_key_management`), and cannot be combined with `generate_signing_secret: false`
  (a key that administers other keys must always be able to sign).
- **Query Parameters:** none.
- **Request Body** — `CreateApiKeyPayload`:

  | Field | Type | Required | Default | Description |
  | :--- | :--- | :--- | :--- | :--- |
  | `name` | `String` | yes | — | Human-readable name. |
  | `bound_ips` | `Option<String>` | no | `null` | Comma-separated CIDR allowlist. |
  | `max_concurrent_jobs` | `Option<i32>` | no | `10` | `1..=1000`. |
  | `hmac_mode` | `Option<HmacMode>` | no | `"CANONICAL_V1"` | Fixed for the key's entire life — no field on the update payload can ever change it. |
  | `canonical_template` | `Option<String>` | no | service default | Refused if `can_manage_keys` is also requested. |
  | `can_manage_keys` | `Option<bool>` | no | `false` | Global key-management scope. **Master-only to set `true`.** |
  | `can_manage_hooks` | `Option<bool>` | no | `false` | Global hook-creation scope. **Master-only to set `true`.** |
  | `generate_signing_secret` | `Option<bool>` | no | `true` | `false` mints a bearer-only key with no `key_id`/`signing_secret` pair at all. Refused together with `can_manage_keys: true`. |

  **No `is_master` field exists on this payload at all** — master status is never settable through
  any endpoint; the only master key is the one minted at bootstrap against an empty table
  (`RBAC_MODEL.md` §5). Sending it is a `400` naming the field (`deny_unknown_fields`), not a silent
  no-op.

- **Response `200 OK`** — `CreateApiKeyResponse` — **the only time the secrets are ever shown**:

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `id` | `Uuid` | Internal ID. |
  | `plaintext_key` | `String` | The raw `X-API-Key` value. Only its hash is stored. |
  | `key_id` | `Option<String>` | Public signing identifier. `null` if `generate_signing_secret: false`. |
  | `signing_secret` | `Option<String>` | HMAC signing secret, shown once. `null` if `generate_signing_secret: false`. |
  | `name` | `String` | Key name. |
  | `bound_ips` | `Option<String>` | Echoed CIDR allowlist. |

- **Errors:** `400` invalid `bound_ips`/`max_concurrent_jobs`/incompatible `can_manage_keys`+`generate_signing_secret: false`;
  `403` non-master granting a global scope or `hmac_mode`/`canonical_template` incompatible with `can_manage_keys`.

### `GET /api/keys`

Lists keys, at whichever detail level §4 entitles the caller to.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `is_master || can_manage_keys` to call at all. Per-row visibility (§4): master or
  a key's own subtree gets the **full** `ApiKeySummary`; a key met only through a shared managed hook
  gets the **minimal** view (id, name, and rights on that shared hook alone); everything else is
  omitted from the listing entirely.
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `Vec<ApiKeyView>`, an untagged enum rendering as one of two shapes per entry:

  - **Full** (`ApiKeySummary`): `{ id, name, prefix, key_id: Option<String>, has_signing_secret: bool, hmac_mode, canonical_template: Option<String>, bound_ips: Option<String>, max_concurrent_jobs: i32, is_master: bool, can_manage_keys: bool, can_manage_hooks: bool, parent_key_id: Option<Uuid>, created_at, hook_permissions: Vec<HookPermissionView> }`.
  - **Minimal** (`MinimalApiKeyView`): `{ id, name, hook_permissions: Vec<HookPermissionView> (shared hooks only), partial: true }`.

- **Errors:** `403` neither master nor `can_manage_keys`.

### `PUT /api/keys/{id}` (alias: `PATCH /api/keys/{id}`)

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `is_master || can_manage_keys`, and the target must be within the caller's
  **administrable** (full-visibility) scope — a key met only through a shared resource is `404` here,
  not editable. Editing a master key is master-only (`guard_master_to_administer`), and even the
  master editing itself may only touch `bound_ips` (`guard_master_self_edit_is_bound_ips_only`).
  Granting `can_manage_keys`/`can_manage_hooks: true` is master-only, and the *effective*
  `can_manage_keys`+`canonical_template` combination is re-checked against
  `guard_canonical_v1_for_key_management` exactly as at creation.
- **Query Parameters:** none.
- **Request Body** — `UpdateApiKeyPayload` (all optional, absent leaves untouched; **no `hmac_mode`
  field exists at all** — immutable after creation for every key):

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `name` | `Option<String>` | New name. |
  | `bound_ips` | `Option<String>` | New CIDR allowlist. |
  | `max_concurrent_jobs` | `Option<i32>` | New budget, `1..=1000`. |
  | `canonical_template` | `Option<String>` | New override, or `""` to reset. Refused if the *effective* `can_manage_keys` is `true`. |
  | `can_manage_keys` | `Option<bool>` | New global scope. Master-only to set `true`. |
  | `can_manage_hooks` | `Option<bool>` | New global scope. Master-only to set `true`. |

- **Response `200 OK`** — `ApiKeySummary` (full shape, always — this is always the caller's own
  administrable scope).
- **Errors:** `400` invalid field or incompatible `can_manage_keys`/`canonical_template`; `403` guard
  failure; `404` not found or not in the caller's administrable scope.

### `DELETE /api/keys/{id}`

Cascading deletion with a mandatory §6 pre-flight ownership inventory.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `is_master || can_manage_keys`; cannot target self; target must be in the caller's
  administrable scope; master keys are entirely immune (`refuse_master_lifecycle_action` — not even
  the master itself may delete it through the API).
- **Query Parameters:** none.
- **Request Body (optional)** — `DeleteApiKeyPayload`: `{ resolutions: HashMap<Uuid, EntityResolution> }`
  where `EntityResolution` is `{"action":"delete"}` or `{"action":"reassign","to":"<key-id>"}`. Omit
  entirely (or send an empty body) for the first, question-only request.
- **Response, two-step by design:**
  - **`409 Conflict`** (first request, if the subtree owns anything) — `AppError::ConflictWithDetails`,
    merging `subtree: Vec<{id, name}>` (every key the cascade would remove) and
    `inventory: Vec<{type: "hook", id, name, current_owner}>` (everything any key in the subtree owns)
    into the standard `{"error": ...}` envelope. **Partial resolution maps are refused** — every
    inventoried id must appear.
  - **`204 No Content`** — once every inventoried entity carries an explicit resolution (or the
    subtree owns nothing at all). Deletes the key and its entire descendant subtree; permission rows
    cascade, `executions.api_key_id` is set `NULL` (history survives its author).
- **Errors:** `400` a resolution names something outside the subtree's inventory, or a `reassign`
  target that is itself inside the doomed subtree or does not exist; `403` self-deletion, a
  non-administrable target, or a master target; `404` not found/not administrable.

### `POST /api/keys/{id}/rotate`

Issues an entirely new bearer key **and** signing pair, invalidating both old halves at once.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** same as `PUT /api/keys/{id}`'s administrability/master rules, via
  `guard_master_to_administer` + `refuse_master_lifecycle_action`.
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `RotateKeyResponse`: `{ id, plaintext_key, key_id, signing_secret }` — the
  new credentials, shown once.
- **Errors:** `403` non-administrable or master target; `404` not found.

### `POST /api/keys/{id}/regenerate-key`

Issues a new bearer `X-API-Key` only; the signing pair is untouched, so a caller signing with the
existing secret keeps working.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** identical to `rotate`.
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `RegenerateKeyResponse`: `{ id, plaintext_key }`.
- **Errors:** same as `rotate`.

### `POST /api/keys/{id}/regenerate-secret`

Issues a new `key_id` + `signing_secret` pair only; the bearer `X-API-Key` is untouched.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** identical to `rotate`.
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `RegenerateSecretResponse`: `{ id, key_id, signing_secret }`.
- **Errors:** same as `rotate`.

---

## Key–Hook Permissions

### `POST /api/keys/{id}/permissions`

Grants or updates one key's rights over one hook. Writes the **whole row** — an omitted verb is an
explicit `false`, not "leave as is".

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `has_permission_admin_standing` (master, or `can_manage_keys` **and** managing at
  least one hook) to call at all — checked before the target key is even looked up, so a caller with
  no standing cannot probe key UUIDs by reading `404` instead of `403`. The target key needs only §4
  visibility (full **or** minimal), not full administrability. Then, depending on whether the write
  is classified as a reduction (turns no verb on relative to the target's current row — **R6**, applies
  identically to this endpoint and `DELETE .../permissions/{hook}`) or a grant:
  - **Reduction:** `guard_hook_manage_conjunction` (R2: `can_manage_keys` **and** a `can_manage = true`
    row on this hook) — self-revocation is permitted, and the revoker need not hold the verb being
    removed.
  - **Grant:** self-granting is refused outright; otherwise `guard_delegated_hook_grant` (R1 + R2 +
    R7: the same R2 conjunction, **and** the caller may only grant a verb it holds itself).
  - Either way, granting rights on a **privileged** hook (non-empty `run_as_user`) is additionally
    master-only, since distributing rights on it is the elevation itself.
- **Query Parameters:** none.
- **Request Body** — `HookPermInput`:

  | Field | Type | Required | Description |
  | :--- | :--- | :--- | :--- |
  | `hook_id` | `Option<String>` | one of `hook_id`/`hook_name` | Target hook by UUID or name. |
  | `hook_name` | `Option<String>` | one of `hook_id`/`hook_name` | Target hook by name — equivalent to putting a name in `hook_id`. |
  | `can_execute` | `bool` | yes | Grant execute rights. |
  | `can_manage` | `bool` | yes | Grant manage rights. |
  | `can_view_execution` | `bool` | no (`#[serde(default)] = false`) | Grant execution-history read rights. |

- **Response:** `200 OK`, empty body.
- **Errors:** `400` neither/both of `hook_id`/`hook_name` given, or the target is itself a master
  key; `403` no admin standing, self-grant attempt, R1/R2/R7 failure, or a privileged hook touched by
  a non-master; `404` target key not visible, or hook not found.

### `DELETE /api/keys/{id}/permissions/{hook_identifier}`

Removes a key's entire grant over one hook.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** `has_permission_admin_standing`, then `guard_hook_manage_conjunction` (R2) —
  **R6**: no per-verb proportionality (the revoker need not hold any specific verb being removed) and
  self-revocation is permitted, matching the reduction path of the grant endpoint exactly, so neither
  route can be used to route around the other.
- **Query Parameters:** none. **Request Body:** none.
- **Response:** `204 No Content`.
- **Errors:** `403` no admin standing or R2 failure; `404` no such hook, or no grant row exists.

---

## Audit Logs

### `GET /api/audit-logs`

Master-only reads over the administrative/mutation audit trail (`audit_logs`) — every hook and key
CRUD action, permission grant/revoke, and purge, each row attributing `api_key_id`/`api_key_name`/
`api_key_prefix`/`client_ip`/`action`/`target_resource`/`details`/`timestamp`. **Not** written here —
every mutating handler in the service calls `create_audit_log` directly.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** **master-only**, flat — not a §4 visibility filter. Audit entries name keys and
  targets the caller may not be otherwise permitted to know exist, so there is deliberately no "show
  me entries about my own hooks" view.
- **Query Parameters** — `AuditLogQuery`:

  | Field | Type | Default | Description |
  | :--- | :--- | :--- | :--- |
  | `action` | `Option<String>` | — | Exact match (e.g. `HOOK_CREATE`). |
  | `client_ip` | `Option<String>` | — | Substring match against the recorded client IP. |
  | `api_key` | `Option<String>` | — | UUID (exact) or name (substring, case-insensitive) against the *acting* key. A key deleted since the entry was written is only findable by UUID. |
  | `since` / `until` | `Option<String>` | — | RFC 3339 instant bounds. |
  | `limit` | `Option<u64>` | `50` | Pagination size. |
  | `offset` | `Option<u64>` | `0` | Pagination offset. |

  Unlike `GET /api/executions`, this endpoint has no `page`/`per_page` alternative spelling and no
  `X-Total-Count`-style response headers, and its `limit`/`offset` are not saturating-clamped.

- **Request Body:** none.
- **Response `200 OK`** — `Vec<audit_log::Model>`: `{ id, api_key_id: Option<Uuid>, api_key_name, api_key_prefix, client_ip, action, target_resource: Option<String>, details: Option<String>, timestamp }`.
- **Errors:** `400` malformed `since`/`until`; `403` non-master.

---

## System

### `GET /api/settings`

The effective runtime configuration and instance counters, master-only.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** **master-only** — `allowed_env_vars` describes what a hook process inherits, which
  is exactly the reconnaissance an attacker probing for a sandbox escape would want.
- **Query Parameters:** none. **Request Body:** none.
- **Response `200 OK`** — `SettingsResponse`:

  | Field | Type | Description |
  | :--- | :--- | :--- |
  | `allowed_env_vars` | `Vec<String>` | Host env vars passed through to hook sub-processes. |
  | `allowed_script_roots` | `Vec<String>` | Directories `script_path` must resolve inside (empty = unrestricted). |
  | `trusted_proxies` | `Vec<String>` | Peers whose `X-Forwarded-For`/`X-Real-IP` are believed. |
  | `log_retention_days` | `i64` | Execution history purge age (`0` = never). |
  | `deleted_hook_retention_days` | `i64` | Soft-deleted hook purge age (`0` = never). |
  | `retention_sweep_seconds` | `u64` | Interval between background retention sweeps. |
  | `max_output_bytes` | `usize` | Per-stream captured-output cap. |
  | `signature_max_age_seconds` | `i64` | Anti-replay window for `X-Timestamp`. |
  | `require_signed_requests` | `bool` | Whether every authenticated request must be signed. |
  | `keyless_hooks_allowed` | `bool` | `!require_signed_requests` — whether a `NONE`-mode hook is actually reachable keylessly on this deployment. |
  | `signing_secrets_encrypted` | `bool` | Whether `SIGNING_SECRET_KEY` is configured (secrets encrypted at rest). |
  | `hook_count` / `api_key_count` / `execution_count` | `u64` | Live row counts. |

- **Errors:** `403` non-master.

### `POST /api/system/purge-hooks?older_than_days={i64}`

Permanently drops soft-deleted hooks past the retention window — the on-demand form of the
background sweep, discarding each purged hook's entire execution history along with the row.

- **Auth:** `auth_middleware`.
- **RBAC Guard:** **master-only**.
- **Query Parameters** — `PurgeQuery`: `older_than_days: Option<i64>` (default: `DELETED_HOOK_RETENTION_DAYS`).
- **Request Body:** none.
- **Response `200 OK`** — `{"purged": <u64>, "older_than_days": <i64>}`.
- **Errors:** `400` `older_than_days` negative; `403` non-master.

---

## Health & Readiness (unauthenticated)

The only public routes in the service — mounted outside both `auth_middleware` and
`invocation_auth_middleware`, and outside `/api` entirely.

### `GET /health` (alias: `GET /healthz`)

Liveness — *"is this process alive?"* Always `200 OK`, reaches no state (not even `AppState`), so it
cannot be made to fail by a dependency (e.g. the database) being down.

- **Auth:** none.
- **Response `200 OK`** — `{"status": "ok", "service": "simply_hook_executor"}`.

### `GET /ready` (alias: `GET /readyz`)

Readiness — *"can this process serve traffic right now?"* Checks a bounded (`LIMIT 1`, never
`COUNT(*)`) database read and that the Master identity is pinned.

- **Auth:** none.
- **Response `200 OK`** — `{"status": "ready", "database": "up"}`.
- **Response `503 Service Unavailable`** — `{"status": "unavailable", "database": "up" | "down"}`.
  Never carries the underlying error (which could disclose connection strings or driver internals to
  an anonymous caller) — that detail is logged server-side only.

---

## Static Assets

### `GET /*` (fallback)

Serves the single-page dashboard from `static/` (`ServeDir`) for any path not matched by `/api/*`,
`/webhook/*`, or the four probe routes. Unauthenticated, like the probes — the SPA's own JavaScript
performs every subsequent authenticated call itself.

---

## Shared shapes referenced above

### `HookDetail` shape

Returned by every hook-CRUD endpoint (`create_hook`, `list_hooks`, `get_hook`, `update_hook`,
`restore_hook`).

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `Uuid` | Hook ID. |
| `name` | `String` | Hook name. |
| `description` | `Option<String>` | Summary. |
| `script_path` | `String` | Absolute executable path. |
| `default_timeout_seconds` | `i32` | Max runtime. |
| `run_as_user` | `Option<String>` | Elevation account, or `null`. |
| `owner_key_id` | `Option<Uuid>` | §3 lifecycle-authority owner, or `null` for a pre-ownership hook. |
| `is_owner` | `bool` | Whether *this caller* may delete/rename it (master or owner) — distinct from `can_manage`. |
| `is_deleted` | `bool` | Trash status. |
| `deleted_at` | `Option<NaiveDateTime>` | When trashed. |
| `deleted_by` | `Option<String>` | `api_keys.id` (as text) of whoever trashed it. |
| `parameters` | `Vec<hook_parameter::Model>` | Declared parameters, in argv order. |
| `can_execute` / `can_manage` | `bool` | This caller's operational rights. |
| `created_at` / `updated_at` | `NaiveDateTime` | Timestamps. |
| `auth_mode` | `AuthMode` | Keyless-invocation mode. |
| `hmac_secret_configured` | `bool` | Whether an `HMAC_ONLY` secret is set — the secret itself is never returned. |
| `signature_header` / `signature_prefix` | `Option<String>` | `HMAC_ONLY` configuration, or `null` for the built-in default. |
| `canonical_template` | `Option<String>` | Per-hook `CANONICAL_V1` override, or `null`. |
| `sample_payload_json` | `Option<String>` | Example body, or `null`. |
| `args_template` | `Option<String>` | Argument-vector template, or `null`. |
| `webhook_path` | `String` | `/webhook/{percent-encoded name}` — computed fresh from the hook's current name on every response, never stored. A *path*, not a full URL (this server cannot reliably know its own externally-visible scheme/host behind a reverse proxy). |

### Enums

| Enum | Values | Used by |
| :--- | :--- | :--- |
| `AuthMode` | `CANONICAL_V1` (default) \| `API_KEY_ONLY` \| `HMAC_ONLY` \| `NONE` | `hooks.auth_mode` |
| `HmacMode` | `CANONICAL_V1` (the only value; `BODY_ONLY` was retired) | `api_keys.hmac_mode` |
| `ExecutionStatus` | `SUCCESS` \| `FAILED` \| `TIMEOUT` | `executions.status` |

---

## Coverage note

Every `.route(...)` registration in `src/lib.rs`'s `create_app` is represented above, including both
verb aliases (`PUT`/`PATCH` on `/hooks/{identifier}` and `/keys/{id}`) and both probe spellings
(`/health`+`/healthz`, `/ready`+`/readyz`). There are no other route registrations, feature-flagged
routes, or hidden/undocumented endpoints anywhere in `src/`. Verified by direct cross-reference
against every `pub async fn` re-exported from `src/api/mod.rs` and the router table in `src/lib.rs`
— nothing in either is absent from this document.
