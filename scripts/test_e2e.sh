#!/usr/bin/env bash
#
# End-to-end test suite for simply_hook_executor.
#
# Builds the project, boots a fresh instance against a throwaway SQLite database with a
# deterministic bootstrap master key (via INITIAL_MASTER_KEY — no log-scraping), and drives the
# whole HTTP API with curl + jq: hook lifecycle CRUD (including duplicate-name 409 and flexible
# UUID-or-name addressing), hook parameter contracts (defaults, requiredness, unknown-key
# rejection), real script execution with stdout/stderr capture and exit-code recording, the
# dry-run /test preview, environment isolation (env_clear + ALLOWED_ENV_VARS passthrough +
# HOOK_PARAM_* injection), positional CLI arguments, shell-injection safety, the RBAC matrix
# across an execute-only / manage-only / no-access key set, creator auto-provisioning, per-key
# concurrency throttling (429), per-hook timeouts with process-group SIGKILL (137), HMAC-SHA256
# body signing, the /webhook/{name} alias, bound-IP CIDR enforcement, key lifecycle
# (create/update/rotate/delete), execution history filtering/detail/deletion/purge, audit log
# generation + pagination + enrichment, and the master-only settings endpoint. Every request is
# logged with a timestamp, method, full URL, color-coded status, and jq-formatted body.
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq, cargo. Needs port 3000 free (the app's listen address is not configurable).
# Optional: openssl (only for the HMAC signing section; without it that one section is skipped).
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail
# Not using `set -e`: assertions on purpose expect non-2xx responses (400/401/403/404/409/429), so
# a non-zero curl/jq exit inside a check must not abort the whole run.

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# 127.0.0.1 rather than "localhost": avoids any IPv6 (::1) resolution first-try delay against a
# server that only ever binds the IPv4 wildcard address.
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
# Deterministic bootstrap secret: passed to the server as INITIAL_MASTER_KEY so this script never
# needs to scrape the master key back out of the (buffered, redirected) server log.
MASTER_KEY="e2e_master_secret_key_for_testing_123456789"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simply_hook_executor_e2e.XXXXXX")"
DB_PATH="$WORK_DIR/e2e.db"
SERVER_LOG="$WORK_DIR/server.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"
HOOK_DIR="$WORK_DIR/hooks"
SERVER_PID=""

PASS_COUNT=0
FAIL_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────
#
# Every diagnostic/progress function below writes to STDERR, never STDOUT. This is deliberate,
# not cosmetic: helper functions like `create_scoped_key` (further down) need to hand a real
# value back to the caller via plain global variables, and several `check_jq` calls parse
# `$RESP_BODY` via `$(...)` command substitution elsewhere in the script. Command/process
# substitution captures *only* stdout, so if timestamps/status lines/PASS-FAIL/response-body
# output went to stdout too, they'd contaminate any captured value. Keeping stdout pristine and
# routing everything else to stderr is the robust fix — a terminal shows both streams interleaved
# anyway, so a normal run of this script looks identical either way.

ts() { date +"%H:%M:%S.%3N"; }

log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }

log_section() {
    echo "" >&2
    echo -e "$(ts) ${BOLD}${MAGENTA}=== $* ===${RESET}" >&2
}

status_color() {
    case "$1" in
        2??) echo -n "$GREEN" ;;
        400|401|403|404|409|422|429) echo -n "$YELLOW" ;;
        4??) echo -n "$YELLOW" ;;
        5??) echo -n "$RED" ;;
        *) echo -n "$RESET" ;;
    esac
}

# Pretty-prints $RESP_BODY (JSON via jq when possible, indented under the request line above).
print_response_body() {
    if [ -z "$RESP_BODY" ]; then
        echo -e "$(ts)          ${DIM}(empty body)${RESET}" >&2
        return
    fi
    local formatted
    if formatted=$(echo "$RESP_BODY" | jq . 2>/dev/null); then
        while IFS= read -r line; do
            echo -e "$(ts)          ${DIM}${line}${RESET}" >&2
        done <<< "$formatted"
    else
        echo -e "$(ts)          ${DIM}${RESP_BODY}${RESET}" >&2
    fi
}

# Performs an HTTP request and leaves the outcome in $RESP_STATUS / $RESP_BODY. Every call prints
# a timestamped, colored "[STATUS] METHOD /path" line followed by the jq-formatted response body.
# Usage: api_call METHOD PATH [API_KEY] [JSON_BODY] [X_FORWARDED_FOR] [EXTRA_HEADER]
api_call() {
    local method="$1" path="$2" api_key="${3:-}" data="${4:-}" xff="${5:-}" extra="${6:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")
    [ -n "$api_key" ] && args+=(-H "X-API-Key: $api_key")
    [ -n "$xff" ] && args+=(-H "X-Forwarded-For: $xff")
    [ -n "$extra" ] && args+=(-H "$extra")
    if [ -n "$data" ]; then
        args+=(-H "Content-Type: application/json" -d "$data")
    fi
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
}

# Usage: check EXPECTED_STATUS "description"
check() {
    local expected="$1" description="$2"
    if [ "$RESP_STATUS" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    fi
}

# Usage: check_jq '.some.jq.filter' "expected value" "description"
check_jq() {
    local filter="$1" expected="$2" description="$3"
    local actual
    actual=$(echo "$RESP_BODY" | jq -r "$filter" 2>/dev/null)
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

# Usage: check_true "jq boolean expression producing true/false" "description"
check_true() {
    local expr="$1" description="$2"
    local actual
    actual=$(echo "$RESP_BODY" | jq -e "$expr" 2>/dev/null)
    if [ "$actual" == "true" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (jq expr '$expr' was not true)" >&2
    fi
}

# Usage: check_local "actual" "expected" "description" — for assertions about local state
# (files on disk, computed values) rather than an HTTP response.
check_local() {
    local actual="$1" expected="$2" description="$3"
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

# Writes an executable /bin/sh hook script into $HOOK_DIR and echoes its absolute path.
# Usage: SCRIPT_PATH=$(make_hook_script name.sh 'body')
make_hook_script() {
    local name="$1" body="$2"
    local path="$HOOK_DIR/$name"
    printf '#!/bin/sh\n%s\n' "$body" > "$path"
    chmod 755 "$path"
    echo "$path"
}

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "Stopping server (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# ── Preflight ────────────────────────────────────────────────────────────────

log_section "Preflight"

for bin in curl jq cargo; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        err "$bin is required but not found on PATH"
        exit 1
    fi
    log "Found $bin: $(command -v "$bin")"
done

if command -v fuser >/dev/null 2>&1 && fuser 3000/tcp >/dev/null 2>&1; then
    err "Port 3000 is already in use (the app's listen address is not configurable)."
    err "Stop whatever is bound to it and re-run this script."
    exit 1
fi

# openssl is a *soft* dependency: only the HMAC body-signing section needs it to compute a
# signature the way a real client would. Its absence degrades that one section to a warning +
# skip rather than failing the suite.
HAVE_OPENSSL=0
if command -v openssl >/dev/null 2>&1; then
    HAVE_OPENSSL=1
    log "Found openssl: $(command -v openssl) (used for HMAC signature verification)"
else
    warn "openssl not found — HMAC signature verification (§12) will be skipped."
fi

mkdir -p "$HOOK_DIR"

# ── Build & start ────────────────────────────────────────────────────────────

log_section "Build"
log "Running cargo build in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo build --quiet 2>"$WORK_DIR/build.log"); then
    err "Build failed:"
    cat "$WORK_DIR/build.log" >&2
    exit 1
fi
log "Build succeeded."

log_section "Boot"
log "Starting server against a fresh database at $DB_PATH"
log "Using INITIAL_MASTER_KEY for deterministic bootstrap (no log-scraping needed)"
# ALLOWED_ENV_VARS=PATH pins the passthrough allowlist so §7's isolation assertions are exact:
# anything other than PATH and HOOK_PARAM_* showing up in a child's environment is a real leak.
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    ALLOWED_ENV_VARS="PATH" LOG_RETENTION_DAYS=30 \
    "$PROJECT_ROOT/target/debug/simply_hook_executor" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

log "Waiting for the server to become ready (pid $SERVER_PID)..."
READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited during startup. Log:"
        cat "$SERVER_LOG" >&2
        exit 1
    fi
    # Readiness is decided purely by whether the HTTP listener answers on a real API route —
    # never by log content, which may be buffered and lag behind the process actually being ready
    # to serve. `/api/hooks` sits behind auth middleware, so an unauthenticated probe returns 401
    # rather than a connection failure once the server is up.
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/hooks" 2>/dev/null)
    case "$STATUS_CODE" in
        200|401|404)
            READY=1
            break
            ;;
    esac
    sleep 0.5
done
if [ "$READY" -ne 1 ]; then
    err "Server did not become ready in time. Log:"
    cat "$SERVER_LOG" >&2
    exit 1
fi
log "Server is up."

api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "the deterministic INITIAL_MASTER_KEY authenticates"
check_jq ".is_master" "true" "it reports is_master=true"
check_jq ".can_manage_hooks" "true" "the bootstrap master can manage hooks"

# ── 1. Basic authentication ─────────────────────────────────────────────────

log_section "1. Basic Authentication"

api_call GET "/api/auth/me"
check "401" "no X-API-Key header is rejected"

api_call GET "/api/auth/me" "not-a-real-key"
check "401" "an invalid key is rejected"

api_call POST "/api/hooks/anything/execute" "not-a-real-key" '{}'
check "401" "an invalid key cannot reach the execute endpoint"

# ── 2. Hook lifecycle ───────────────────────────────────────────────────────

log_section "2. Hook Lifecycle (Create / Read / Update / Delete)"

ECHO_SCRIPT=$(make_hook_script "echo_hook.sh" 'echo "hello ${HOOK_PARAM_TARGET}"
echo "diagnostics" >&2')

api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"echo_hook\",\"description\":\"Greets a target\",\"script_path\":\"$ECHO_SCRIPT\",\"default_timeout_seconds\":10,\"parameters\":[{\"param_key\":\"target\",\"is_required\":true}]}"
check "200" "create a hook with an inline parameter contract"
ECHO_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".can_execute" "true" "the creating key is auto-granted execute rights"
check_jq ".can_manage" "true" "the creating key is auto-granted manage rights"
check_jq ".parameters | length" "1" "the inline parameter was declared"
log "echo_hook id: $ECHO_HOOK_ID"

api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"echo_hook\",\"script_path\":\"$ECHO_SCRIPT\"}"
check "409" "a duplicate hook name is a conflict, not a 500"

api_call GET "/api/hooks/$ECHO_HOOK_ID" "$MASTER_KEY"
check "200" "fetch the hook by UUID"

api_call GET "/api/hooks/echo_hook" "$MASTER_KEY"
check "200" "fetch the same hook by name"
check_jq ".id" "$ECHO_HOOK_ID" "UUID and name address the same hook"

api_call PUT "/api/hooks/$ECHO_HOOK_ID" "$MASTER_KEY" '{"default_timeout_seconds":20}'
check "200" "update the hook timeout"
check_jq ".default_timeout_seconds" "20" "the new timeout is persisted"

api_call POST "/api/hooks" "$MASTER_KEY" '{"name":"relative","script_path":"not/absolute.sh"}'
check "400" "a relative script_path is rejected"

api_call POST "/api/hooks" "$MASTER_KEY" '{"name":"traversal","script_path":"/usr/../etc/shadow"}'
check "400" "a traversing script_path is rejected"

api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"bad_timeout\",\"script_path\":\"$ECHO_SCRIPT\",\"default_timeout_seconds\":0}"
check "400" "a non-positive timeout is rejected"

# ── 3. Hook parameter contract ──────────────────────────────────────────────

log_section "3. Hook Parameter Contract"

api_call POST "/api/hooks/$ECHO_HOOK_ID/parameters" "$MASTER_KEY" '{"param_key":"greeting","default_value":"hi","is_required":true,"description":"Greeting word"}'
check "200" "declare a second parameter with a default value"
GREETING_PARAM_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$ECHO_HOOK_ID/parameters" "$MASTER_KEY" '{"param_key":"greeting"}'
check "409" "re-declaring the same parameter key is a conflict"

api_call POST "/api/hooks/$ECHO_HOOK_ID/parameters" "$MASTER_KEY" '{"param_key":"9 invalid"}'
check "400" "an unusable param_key is rejected"

api_call GET "/api/hooks/$ECHO_HOOK_ID/parameters" "$MASTER_KEY"
check "200" "list the parameter contract"
check_jq "length" "2" "both parameters are declared"

api_call PUT "/api/hooks/$ECHO_HOOK_ID/parameters/$GREETING_PARAM_ID" "$MASTER_KEY" '{"default_value":"hello"}'
check "200" "update a parameter default"
check_jq ".default_value" "hello" "the new default is persisted"

api_call DELETE "/api/hooks/$ECHO_HOOK_ID/parameters/$GREETING_PARAM_ID" "$MASTER_KEY"
check "204" "remove the parameter"

# ── 4. Execution & output capture ───────────────────────────────────────────

log_section "4. Execution, Output Capture & Exit Codes"

api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"target":"world"}}'
check "200" "execute the hook"
check_jq ".status" "SUCCESS" "a zero exit is recorded as SUCCESS"
check_jq ".exit_code" "0" "the exit code is captured"
check_jq ".stdout | rtrimstr(\"\n\")" "hello world" "stdout is captured with the parameter interpolated"
check_jq ".stderr | rtrimstr(\"\n\")" "diagnostics" "stderr is captured separately"
check_jq ".parameters.target" "world" "the resolved parameters are recorded"
FIRST_EXEC_ID=$(echo "$RESP_BODY" | jq -r '.id')

FAIL_SCRIPT=$(make_hook_script "fail_hook.sh" 'echo "went wrong" >&2
exit 42')
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"fail_hook\",\"script_path\":\"$FAIL_SCRIPT\"}"
check "200" "create a deliberately failing hook"
FAIL_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$FAIL_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "200" "a failing script still completes the request"
check_jq ".status" "FAILED" "a non-zero exit is recorded as FAILED"
check_jq ".exit_code" "42" "the non-zero exit code is preserved"
check_jq ".stderr | rtrimstr(\"\n\")" "went wrong" "the failure message is captured"

MISSING_SCRIPT="$HOOK_DIR/definitely_absent.sh"
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"ghost_hook\",\"script_path\":\"$MISSING_SCRIPT\"}"
check "200" "a hook may be declared before its script is deployed"
GHOST_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$GHOST_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "400" "executing a hook whose script is missing is rejected up front"

# ── 5. Parameter resolution & validation ────────────────────────────────────

log_section "5. Parameter Resolution & Validation"

PARAM_SCRIPT=$(make_hook_script "param_hook.sh" 'echo "argv:$1|$2"
echo "env:${HOOK_PARAM_ALPHA}|${HOOK_PARAM_BETA}"')
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"param_hook\",\"script_path\":\"$PARAM_SCRIPT\",\"parameters\":[{\"param_key\":\"alpha\",\"is_required\":true},{\"param_key\":\"beta\",\"default_value\":\"from-default\",\"is_required\":true}]}"
check "200" "create a hook with a required and a defaulted parameter"
PARAM_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{}}'
check "400" "omitting a required parameter with no default is rejected"
check_true '.error | contains("alpha")' "the error names the missing parameter"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":"supplied","surprise":"nope"}}'
check "400" "an undeclared parameter is rejected rather than silently ignored"
check_true '.error | contains("surprise")' "the error names the unknown parameter"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":"supplied"}}'
check "200" "the declared default fills in for the omitted parameter"
check_true '.stdout | contains("argv:supplied|from-default")' "parameters are passed as positional CLI arguments in declaration order"
check_true '.stdout | contains("env:supplied|from-default")' "parameters are injected as HOOK_PARAM_<KEY> variables"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"alpha":"flat-payload"}'
check "200" "a flat JSON body (no \"parameters\" wrapper) is accepted"
check_true '.stdout | contains("argv:flat-payload|from-default")' "the flat payload resolved the same way"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":["not","a","scalar"]}}'
check "400" "a non-scalar parameter value is rejected"

# ── 6. Shell injection safety ───────────────────────────────────────────────

log_section "6. Shell Injection Safety"

CANARY_FILE="$WORK_DIR/injection_canary"
INJECT_SCRIPT=$(make_hook_script "inject_hook.sh" 'echo "got:[$1]"')
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"inject_hook\",\"script_path\":\"$INJECT_SCRIPT\",\"parameters\":[{\"param_key\":\"payload\",\"is_required\":true}]}"
check "200" "create a hook that echoes its first positional argument"
INJECT_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# If any layer passed this through a shell, the `touch` would run and create the canary file.
INJECTION_PAYLOAD="; touch $CANARY_FILE; echo pwned"
api_call POST "/api/hooks/$INJECT_HOOK_ID/execute" "$MASTER_KEY" \
    "$(jq -nc --arg p "$INJECTION_PAYLOAD" '{parameters:{payload:$p}}')"
check "200" "a shell-metacharacter payload executes as inert data"
check_jq ".stdout | rtrimstr(\"\n\")" "got:[$INJECTION_PAYLOAD]" "the payload reached the script verbatim as one argument"
if [ -e "$CANARY_FILE" ]; then
    check_local "canary created" "canary absent" "no shell interpretation occurred"
else
    check_local "canary absent" "canary absent" "no shell interpretation occurred"
fi

# ── 7. Environment isolation ────────────────────────────────────────────────

log_section "7. Environment Isolation (env_clear + allowlist passthrough)"

ENV_SCRIPT=$(make_hook_script "env_hook.sh" 'env | sort')
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"env_hook\",\"script_path\":\"$ENV_SCRIPT\",\"parameters\":[{\"param_key\":\"secret_value\",\"is_required\":true}]}"
check "200" "create an environment-dumping hook"
ENV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$ENV_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"secret_value":"injected"}}'
check "200" "execute the environment-dumping hook"
check_true '.stdout | contains("PATH=")' "the allowlisted PATH variable is inherited"
check_true '.stdout | contains("HOOK_PARAM_SECRET_VALUE=injected")' "the parameter is injected uppercased and prefixed"
# The server process inherits this script's own environment, which includes DATABASE_URL and
# INITIAL_MASTER_KEY — neither is on the allowlist, so neither may reach a hook.
check_true '.stdout | contains("DATABASE_URL") | not' "the daemon's DATABASE_URL does not leak into hooks"
check_true '.stdout | contains("INITIAL_MASTER_KEY") | not' "the bootstrap secret does not leak into hooks"

# ── 8. Dry run (/test) ──────────────────────────────────────────────────────

log_section "8. Dry-Run Preview"

DRYRUN_CANARY="$WORK_DIR/dryrun_canary"
DRY_SCRIPT=$(make_hook_script "dry_hook.sh" "touch $DRYRUN_CANARY")
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"dry_hook\",\"script_path\":\"$DRY_SCRIPT\",\"default_timeout_seconds\":17,\"parameters\":[{\"param_key\":\"alpha\",\"is_required\":true},{\"param_key\":\"beta\",\"default_value\":\"fallback\",\"is_required\":true}]}"
check "200" "create a hook with an observable side effect"
DRY_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$DRY_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"alpha":"supplied"}}'
check "200" "dry-run the hook"
check_jq ".would_execute" "true" "the preview reports the hook is runnable"
check_jq ".timeout_seconds" "17" "the preview reports the effective timeout"
check_jq ".command.program" "$DRY_SCRIPT" "the preview names the exact program"
check_jq ".command.args | join(\",\")" "supplied,fallback" "the preview lists the exact argument vector"
check_jq ".command.env.HOOK_PARAM_ALPHA" "supplied" "the preview shows the injected environment"
check_jq ".resolved_parameters.beta" "fallback" "the preview shows merged defaults"
if [ -e "$DRYRUN_CANARY" ]; then
    check_local "side effect ran" "no side effect" "a dry run does not spawn the script"
else
    check_local "no side effect" "no side effect" "a dry run does not spawn the script"
fi

api_call POST "/api/hooks/$DRY_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{}}'
check "200" "a dry run with missing parameters still returns a preview"
check_jq ".would_execute" "false" "the preview reports the hook would be blocked"
check_jq ".missing_required | join(\",\")" "alpha" "the preview lists the missing required parameters"

# ── 9. RBAC matrix ──────────────────────────────────────────────────────────

log_section "9. RBAC Matrix (execute-only / manage-only / no-access)"

# Creates a key and leaves its plaintext/id in $CREATED_KEY / $CREATED_ID. Deliberately does NOT
# run in a subshell — those globals need to propagate back to the calling scope.
create_scoped_key() {
    local name="$1" extra="${2:-}"
    api_call POST "/api/keys" "$MASTER_KEY" "{\"name\":\"$name\",\"bound_ips\":\"0.0.0.0/0\"$extra}"
    check "200" "create scoped key '$name'"
    CREATED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    CREATED_ID=$(echo "$RESP_BODY" | jq -r '.id')
}

create_scoped_key "Execute-Only Key"
EXEC_KEY="$CREATED_KEY"; EXEC_ID="$CREATED_ID"
create_scoped_key "Manage-Only Key"
MANAGE_KEY="$CREATED_KEY"; MANAGE_ID="$CREATED_ID"
create_scoped_key "No-Access Key"
NOACCESS_KEY="$CREATED_KEY"; NOACCESS_ID="$CREATED_ID"
create_scoped_key "Hook Creator Key" ',"can_manage_hooks":true'
CREATOR_KEY="$CREATED_KEY"; CREATOR_ID="$CREATED_ID"

api_call POST "/api/keys/$EXEC_ID/permissions" "$MASTER_KEY" "{\"hook_id\":\"$ECHO_HOOK_ID\",\"can_execute\":true,\"can_manage\":false}"
check "200" "grant execute-only rights on echo_hook (by hook_id)"

api_call POST "/api/keys/$MANAGE_ID/permissions" "$MASTER_KEY" '{"hook_name":"echo_hook","can_execute":false,"can_manage":true}'
check "200" "grant manage-only rights on echo_hook (by hook_name)"

api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$EXEC_KEY" '{"parameters":{"target":"scoped"}}'
check "200" "the execute-only key can run the hook"

api_call PUT "/api/hooks/$ECHO_HOOK_ID" "$EXEC_KEY" '{"name":"hijacked"}'
check "403" "the execute-only key cannot modify the hook"

api_call DELETE "/api/hooks/$ECHO_HOOK_ID" "$EXEC_KEY"
check "403" "the execute-only key cannot delete the hook"

api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$MANAGE_KEY" '{"parameters":{"target":"nope"}}'
check "403" "the manage-only key cannot run the hook"

api_call PUT "/api/hooks/$ECHO_HOOK_ID" "$MANAGE_KEY" '{"description":"managed"}'
check "200" "the manage-only key can modify the hook"

api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$NOACCESS_KEY" '{"parameters":{"target":"nope"}}'
check "403" "the no-access key cannot run the hook"

api_call GET "/api/hooks/$ECHO_HOOK_ID" "$NOACCESS_KEY"
check "403" "the no-access key cannot even read the hook definition"

api_call GET "/api/hooks" "$NOACCESS_KEY"
check "200" "listing hooks is allowed for any authenticated key"
check_jq "length" "0" "...but returns nothing without a mapping"

api_call POST "/api/hooks" "$NOACCESS_KEY" "{\"name\":\"unauthorized\",\"script_path\":\"$ECHO_SCRIPT\"}"
check "403" "a key without can_manage_hooks cannot create hooks"

api_call GET "/api/keys" "$NOACCESS_KEY"
check "403" "a key without can_manage_keys cannot list keys"

api_call GET "/api/audit-logs" "$NOACCESS_KEY"
check "403" "audit logs are master-only"

api_call GET "/api/settings" "$NOACCESS_KEY"
check "403" "system settings are master-only"

# ── 10. Auto-provisioning on creation ───────────────────────────────────────

log_section "10. Creator Auto-Provisioning"

CREATOR_SCRIPT=$(make_hook_script "creator_hook.sh" 'echo created-by-scoped-key')
api_call POST "/api/hooks" "$CREATOR_KEY" "{\"name\":\"creator_hook\",\"script_path\":\"$CREATOR_SCRIPT\"}"
check "200" "a can_manage_hooks key creates its own hook"
CREATOR_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/auth/me" "$CREATOR_KEY"
check "200" "read the creator key's own scope"
check_true '[.hook_permissions[] | select(.hook_name == "creator_hook")] | length == 1' \
    "the creator was auto-granted a permission mapping on the new hook"
check_true '[.hook_permissions[] | select(.hook_name == "creator_hook") | .can_execute and .can_manage] | all' \
    "the auto-granted mapping carries both execute and manage"

api_call POST "/api/hooks/$CREATOR_HOOK_ID/execute" "$CREATOR_KEY" '{}'
check "200" "the creator can immediately execute what it created"

api_call PUT "/api/hooks/$ECHO_HOOK_ID" "$CREATOR_KEY" '{"description":"not mine"}'
check "403" "can_manage_hooks does not grant control over someone else's hook"

api_call DELETE "/api/keys/$CREATOR_ID/permissions/creator_hook" "$MASTER_KEY"
check "204" "revoke the creator's mapping by hook name"

api_call POST "/api/hooks/$CREATOR_HOOK_ID/execute" "$CREATOR_KEY" '{}'
check "403" "the revoked key can no longer execute"

# ── 11. Concurrency throttling ──────────────────────────────────────────────

log_section "11. Per-Key Concurrency Throttling (429)"

BUSY_MARKER="$WORK_DIR/busy_started"
BUSY_SCRIPT=$(make_hook_script "busy_hook.sh" 'touch "$HOOK_PARAM_MARKER"
sleep 3')
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"busy_hook\",\"script_path\":\"$BUSY_SCRIPT\",\"default_timeout_seconds\":30,\"parameters\":[{\"param_key\":\"marker\",\"default_value\":\"$BUSY_MARKER\",\"is_required\":true}]}"
check "200" "create a long-running hook"
BUSY_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

create_scoped_key "Throttled Key" ',"max_concurrent_jobs":1'
THROTTLED_KEY="$CREATED_KEY"; THROTTLED_ID="$CREATED_ID"
api_call POST "/api/keys/$THROTTLED_ID/permissions" "$MASTER_KEY" "{\"hook_id\":\"$BUSY_HOOK_ID\",\"can_execute\":true,\"can_manage\":false}"
check "200" "grant the throttled key execute rights"

log "Starting a background execution to occupy the key's single slot..."
curl -s -o "$WORK_DIR/busy_resp" -w "%{http_code}" -X POST \
    -H "X-API-Key: $THROTTLED_KEY" -H "Content-Type: application/json" -d '{}' \
    "$BASE_URL/api/hooks/$BUSY_HOOK_ID/execute" > "$WORK_DIR/busy_status" &
BUSY_REQ_PID=$!

# Wait until the script has demonstrably started, so the second request is guaranteed to contend
# for the single permit rather than racing the first request's own setup.
BUSY_STARTED=0
for _ in $(seq 1 100); do
    if [ -e "$BUSY_MARKER" ]; then
        BUSY_STARTED=1
        break
    fi
    sleep 0.05
done
check_local "$BUSY_STARTED" "1" "the first execution actually started"

api_call POST "/api/hooks/$BUSY_HOOK_ID/execute" "$THROTTLED_KEY" '{}'
check "429" "a second concurrent job exceeds max_concurrent_jobs=1"

api_call POST "/api/hooks/$BUSY_HOOK_ID/execute" "$MASTER_KEY" '{}' "" ""
check "200" "a different key's budget is unaffected by the throttled key"

wait "$BUSY_REQ_PID" 2>/dev/null || true
check_local "$(cat "$WORK_DIR/busy_status" 2>/dev/null)" "200" "the first (long-running) execution completed successfully"

api_call POST "/api/hooks/$BUSY_HOOK_ID/execute" "$THROTTLED_KEY" '{}'
check "200" "the slot is released once the process exits"

# ── 12. HMAC signature verification ─────────────────────────────────────────

log_section "12. HMAC-SHA256 Body Signing"

if [ "$HAVE_OPENSSL" -eq 1 ]; then
    SIGNED_BODY='{"parameters":{"target":"signed"}}'
    SIGNATURE=$(printf '%s' "$SIGNED_BODY" | openssl dgst -sha256 -hmac "$EXEC_KEY" -r | cut -d' ' -f1)

    api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$EXEC_KEY" "$SIGNED_BODY" "" "X-Signature-256: sha256=$SIGNATURE"
    check "200" "a correctly signed body is accepted"
    check_jq ".status" "SUCCESS" "the signed request executed"

    TAMPERED_BODY='{"parameters":{"target":"tampered"}}'
    api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$EXEC_KEY" "$TAMPERED_BODY" "" "X-Signature-256: sha256=$SIGNATURE"
    check "401" "the same signature over an altered body is rejected"

    api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$EXEC_KEY" "$SIGNED_BODY" "" "X-Signature-256: sha256=00ff"
    check "401" "a bogus signature is rejected"

    api_call POST "/api/hooks/$ECHO_HOOK_ID/execute" "$EXEC_KEY" "$SIGNED_BODY" "" "X-Signature-256: notprefixed"
    check "401" "a malformed signature header is rejected"
else
    warn "Skipping §12: openssl is not available to compute an HMAC signature."
fi

# ── 13. Webhook alias ───────────────────────────────────────────────────────

log_section "13. Webhook Alias (/webhook/{name})"

api_call POST "/webhook/echo_hook" "$EXEC_KEY" '{"target":"via-webhook"}'
check "200" "the webhook alias executes a hook by name with a flat payload"
check_jq ".stdout | rtrimstr(\"\n\")" "hello via-webhook" "the flat payload was resolved into parameters"

api_call POST "/webhook/echo_hook" "$NOACCESS_KEY" '{"target":"x"}'
check "403" "the webhook alias enforces the same RBAC as /api"

api_call POST "/webhook/echo_hook"
check "401" "the webhook alias enforces authentication"

api_call POST "/webhook/does_not_exist" "$MASTER_KEY" '{}'
check "404" "an unknown hook name is a 404"

# ── 14. Execution timeout & process-group kill ──────────────────────────────

log_section "14. Execution Timeout (SIGKILL of the whole process group)"

ORPHAN_MARKER="$WORK_DIR/orphan_survived"
# Backgrounds a grandchild that would create a marker file, then blocks. Killing only the direct
# child would leave that grandchild alive to create the marker two seconds later.
SLOW_SCRIPT=$(make_hook_script "slow_hook.sh" "(sleep 2; touch $ORPHAN_MARKER) &
sleep 30")
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"slow_hook\",\"script_path\":\"$SLOW_SCRIPT\",\"default_timeout_seconds\":1}"
check "200" "create a hook with a 1-second timeout"
SLOW_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$SLOW_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "200" "the request returns once the timeout fires"
check_jq ".status" "TIMEOUT" "the execution is recorded as TIMEOUT"
check_jq ".exit_code" "137" "the SIGKILL is reported as 128+9"

log "Waiting to confirm the backgrounded grandchild was killed too..."
sleep 3
if [ -e "$ORPHAN_MARKER" ]; then
    check_local "orphan survived" "orphan killed" "the whole process group was killed, not just the direct child"
else
    check_local "orphan killed" "orphan killed" "the whole process group was killed, not just the direct child"
fi

# ── 15. Bound IP / CIDR restrictions ────────────────────────────────────────

log_section "15. Bound IP / CIDR Restrictions"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"CIDR Locked Key","bound_ips":"10.10.10.0/24"}'
check "200" "create a key bound to 10.10.10.0/24"
CIDR_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$CIDR_KEY"
check "403" "a request from outside the bound range is rejected"

api_call GET "/api/auth/me" "$CIDR_KEY" "" "10.10.10.5"
check "200" "a forwarded address inside the bound range is accepted"

api_call GET "/api/auth/me" "$CIDR_KEY" "" "10.10.11.5"
check "403" "a forwarded address just outside the bound range is rejected"

api_call GET "/api/auth/me" "$CIDR_KEY" "" "10.10.10.5, 203.0.113.9"
check "403" "only the rightmost forwarded hop counts"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Bad CIDR","bound_ips":"not-a-cidr"}'
check "400" "an invalid CIDR is rejected at creation"

# ── 16. Key lifecycle ───────────────────────────────────────────────────────

log_section "16. Key Lifecycle (Update / Rotate / Delete)"

create_scoped_key "Lifecycle Key"
LIFECYCLE_KEY="$CREATED_KEY"; LIFECYCLE_ID="$CREATED_ID"

api_call PUT "/api/keys/$LIFECYCLE_ID" "$MASTER_KEY" '{"name":"Lifecycle Key Renamed","max_concurrent_jobs":7}'
check "200" "update the key's name and concurrency budget"
check_jq ".max_concurrent_jobs" "7" "the new budget is persisted"

api_call GET "/api/auth/me" "$LIFECYCLE_KEY"
check "200" "the key still authenticates after the update"
check_jq ".max_concurrent_jobs" "7" "the updated budget is visible to the key itself"

api_call POST "/api/keys/$LIFECYCLE_ID/rotate" "$MASTER_KEY"
check "200" "rotate the key's secret"
ROTATED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$LIFECYCLE_KEY"
check "401" "the old secret stops working immediately"

api_call GET "/api/auth/me" "$ROTATED_KEY"
check "200" "the new secret works"

api_call DELETE "/api/keys/$LIFECYCLE_ID" "$MASTER_KEY"
check "204" "delete the key"

api_call GET "/api/auth/me" "$ROTATED_KEY"
check "401" "the deleted key no longer authenticates"

# ── 17. Execution history ───────────────────────────────────────────────────

log_section "17. Execution History (Filtering, Detail, Deletion, Purge)"

api_call GET "/api/executions?limit=100" "$MASTER_KEY"
check "200" "master lists the full execution history"
check_true "length > 5" "several executions have accumulated"

api_call GET "/api/executions?status=FAILED&limit=50" "$MASTER_KEY"
check "200" "filter history by status"
check_true 'all(.[]; .status == "FAILED")' "every returned row matches the status filter"

api_call GET "/api/executions?status=TIMEOUT&limit=50" "$MASTER_KEY"
check "200" "filter history for timeouts"
check_true 'length >= 1' "the timed-out execution is recorded"

api_call GET "/api/executions?hook=param_hook&limit=50" "$MASTER_KEY"
check "200" "filter history by hook name"
check_true 'all(.[]; .hook_name == "param_hook")' "every returned row belongs to that hook"

api_call GET "/api/executions?status=NOT_A_STATUS" "$MASTER_KEY"
check "400" "an invalid status filter is rejected"

api_call GET "/api/executions/$FIRST_EXEC_ID" "$MASTER_KEY"
check "200" "fetch a single execution with its captured output"
check_jq ".stdout | rtrimstr(\"\n\")" "hello world" "the detail view carries the full stdout"

api_call GET "/api/executions?limit=50" "$EXEC_KEY"
check "200" "a scoped key lists its own hooks' history"
check_true 'all(.[]; .hook_name == "echo_hook")' "history is scoped to hooks the key can see"

api_call DELETE "/api/executions/$FIRST_EXEC_ID" "$EXEC_KEY"
check "403" "deleting history requires manage rights, not merely execute"

api_call DELETE "/api/executions/$FIRST_EXEC_ID" "$MASTER_KEY"
check "204" "master deletes a single execution record"

api_call GET "/api/executions/$FIRST_EXEC_ID" "$MASTER_KEY"
check "404" "the deleted execution is gone"

api_call DELETE "/api/executions?older_than_days=30" "$NOACCESS_KEY"
check "403" "purging history is master-only"

api_call DELETE "/api/executions?older_than_days=30" "$MASTER_KEY"
check "200" "master runs the retention sweep on demand"
check_jq ".purged" "0" "nothing in a fresh database is older than 30 days"

# ── 18. Audit logs ──────────────────────────────────────────────────────────

log_section "18. Audit Log Generation, Enrichment & Pagination"

api_call GET "/api/audit-logs?action=HOOK_CREATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent HOOK_CREATE entry"
check_jq ".[0].api_key_name" "System Master" "the acting key's name is denormalized into the entry"
check_jq ".[0].client_ip" "127.0.0.1" "the resolved client IP is recorded"

api_call GET "/api/audit-logs?action=HOOK_EXECUTE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent HOOK_EXECUTE entry"
check_true '.[0].details | contains("Executed hook")' "execution requests are audited"

api_call GET "/api/audit-logs?action=KEY_ROTATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_ROTATE entry"
check_true '(.[0].details | contains("Lifecycle Key Renamed")) and (.[0].details | contains("Rotated secret for key"))' \
    "the details string names the key by name, not just its raw UUID"

api_call GET "/api/audit-logs?action=KEY_PERM_UPDATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_PERM_UPDATE entry"
check_true '.[0].details | contains("Updated permissions for key")' "permission changes are audited"

api_call GET "/api/audit-logs?limit=3&offset=0" "$MASTER_KEY"
check "200" "first page of audit logs"
AUDIT_PAGE1=$(echo "$RESP_BODY" | jq -r '.[0].id')
api_call GET "/api/audit-logs?limit=3&offset=3" "$MASTER_KEY"
check "200" "second page of audit logs"
AUDIT_PAGE2=$(echo "$RESP_BODY" | jq -r '.[0].id')
if [ "$AUDIT_PAGE1" != "$AUDIT_PAGE2" ]; then
    check_local "distinct" "distinct" "pagination returns different entries per page"
else
    check_local "identical" "distinct" "pagination returns different entries per page"
fi

# ── 19. System settings ─────────────────────────────────────────────────────

log_section "19. System Settings"

api_call GET "/api/settings" "$MASTER_KEY"
check "200" "master reads the runtime configuration"
check_jq ".allowed_env_vars | join(\",\")" "PATH" "the configured passthrough allowlist is reported"
check_jq ".log_retention_days" "30" "the configured retention window is reported"
check_true '.hook_count >= 8' "the hook counter reflects everything created above"
check_true '.execution_count >= 1' "the execution counter is populated"

# ── 20. Hook deletion cascade ───────────────────────────────────────────────

log_section "20. Hook Deletion Cascade"

api_call GET "/api/executions?hook=param_hook&limit=50" "$MASTER_KEY"
check "200" "param_hook has execution history before deletion"
check_true 'length >= 1' "at least one execution exists for it"

api_call DELETE "/api/hooks/$PARAM_HOOK_ID" "$MASTER_KEY"
check "204" "delete param_hook"

api_call GET "/api/hooks/param_hook" "$MASTER_KEY"
check "404" "the hook is gone"

api_call GET "/api/executions?limit=100" "$MASTER_KEY"
check "200" "history is still readable after the cascade"
check_true 'all(.[]; .hook_name != "param_hook")' "the deleted hook's executions cascaded away"

api_call GET "/api/keys" "$MASTER_KEY"
check "200" "list keys after the cascade"
check_true 'all(.[]; [.hook_permissions[] | select(.hook_name == "param_hook")] | length == 0)' \
    "permission mappings for the deleted hook cascaded away too"

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
