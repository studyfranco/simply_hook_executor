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
# Requires: curl, jq, cargo.
# Optional: openssl (only for the HMAC signing section; without it that one section is skipped).
#
# Port selection: honors $PORT if set (and fails fast if that exact port is busy, since an
# explicit request should not be silently overridden); otherwise starts at 3000 and scans upward
# for the first free port, so concurrent runs and a locally-running instance never collide.
# $BIND_HOST (default 127.0.0.1) picks the interface — the suite binds loopback rather than every
# interface so a test server is never briefly exposed to the network.
#
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail
# Not using `set -e`: assertions on purpose expect non-2xx responses (400/401/403/404/409/429), so
# a non-zero curl/jq exit inside a check must not abort the whole run.

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# 127.0.0.1 rather than "localhost": avoids any IPv6 (::1) resolution first-try delay, and keeps
# the test server off every other interface.
BIND_HOST="${BIND_HOST:-127.0.0.1}"
# Empty unless the caller pinned one; resolved to a concrete port in Preflight below.
REQUESTED_PORT="${PORT:-}"
SERVER_PORT=""
BASE_URL=""
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

# Whether something is already listening on a TCP port, using bash's own /dev/tcp rather than
# ss/lsof/fuser so the check works on any bash without extra tooling. A successful connect means
# the port is taken.
port_in_use() {
    local port="$1"
    # The subshell's exit status is the connect result, and the descriptor it opens dies with it,
    # so nothing leaks into the caller's shell.
    (exec 3<>"/dev/tcp/$BIND_HOST/$port") 2>/dev/null
}

# Resolves $SERVER_PORT: an explicitly requested port is used as-is (and its being busy is a hard
# error — silently moving would defeat the point of pinning it), otherwise the first free port at
# or above 3000 is chosen.
pick_port() {
    if [ -n "$REQUESTED_PORT" ]; then
        if port_in_use "$REQUESTED_PORT"; then
            err "PORT=$REQUESTED_PORT was requested but something is already listening on it."
            exit 1
        fi
        SERVER_PORT="$REQUESTED_PORT"
        log "Using explicitly requested port $SERVER_PORT"
        return
    fi

    local candidate
    for candidate in $(seq 3000 3100); do
        if ! port_in_use "$candidate"; then
            SERVER_PORT="$candidate"
            if [ "$candidate" -ne 3000 ]; then
                log "Port 3000 is busy; using the next free port $SERVER_PORT"
            else
                log "Using default port $SERVER_PORT"
            fi
            return
        fi
    done

    err "No free port found in the range 3000-3100. Set PORT=<port> explicitly."
    exit 1
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

pick_port
BASE_URL="http://$BIND_HOST:$SERVER_PORT"
log "Test server base URL: $BASE_URL"

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
# Resolve to the physical path: it is handed to the server as ALLOWED_SCRIPT_ROOTS, and the
# server compares it against canonicalized script paths. On systems where the temp directory is
# itself a symlink (e.g. /tmp -> /private/tmp), the literal and physical forms differ and every
# containment check would fail for the wrong reason.
HOOK_DIR="$(cd "$HOOK_DIR" && pwd -P)"

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
log "Starting server on $BIND_HOST:$SERVER_PORT against a fresh database at $DB_PATH"
log "Using INITIAL_MASTER_KEY for deterministic bootstrap (no log-scraping needed)"
# ALLOWED_ENV_VARS=PATH pins the passthrough allowlist so §7's isolation assertions are exact:
# anything other than PATH and HOOK_PARAM_* showing up in a child's environment is a real leak.
# ALLOWED_SCRIPT_ROOTS is pinned to the throwaway hook directory, so every hook the suite creates
# exercises the containment check on the happy path, and §21 can prove a path outside it is
# refused without needing a second server instance.
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    ALLOWED_ENV_VARS="PATH" LOG_RETENTION_DAYS=30 \
    ALLOWED_SCRIPT_ROOTS="$HOOK_DIR" \
    BIND_HOST="$BIND_HOST" PORT="$SERVER_PORT" \
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

# The readiness probe above already proves the server bound the requested host:port (nothing else
# is listening there), and this pins the startup log line that reports it.
check_local "$(grep -c "listening on http://$BIND_HOST:$SERVER_PORT" "$SERVER_LOG")" "1" \
    "the server honored BIND_HOST=$BIND_HOST and PORT=$SERVER_PORT"

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
check "400" "a non-scalar array parameter value is rejected"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":{"nested":"object"}}}'
check "400" "a nested-object parameter value is rejected"

# JSON null means "not supplied" rather than "empty string", so the declared default applies.
api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":"given","beta":null}}'
check "200" "a null parameter falls back to its declared default"
check_jq ".parameters.beta" "from-default" "null did not override the default"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":null}}'
check "400" "null on a required parameter with no default is still missing"

# An explicit empty string is distinguishable from null and does override the default.
api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":"given","beta":""}}'
check "200" "an explicit empty string is accepted"
check_jq ".parameters.beta" "" "the empty string overrode the default"

api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"alpha":7,"beta":true}}'
check "200" "numeric and boolean scalars are accepted"
check_true '.stdout | contains("argv:7|true")' "scalars are stringified for argv"

# Positional order must be declaration order, and must not drift between identical calls.
api_call POST "/api/hooks/$PARAM_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"alpha":"one"}}'
check "200" "dry-run the parameter hook"
ORDER_FIRST=$(echo "$RESP_BODY" | jq -r '.command.args | join(",")')
api_call POST "/api/hooks/$PARAM_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"alpha":"one"}}'
check "200" "dry-run it again"
ORDER_SECOND=$(echo "$RESP_BODY" | jq -r '.command.args | join(",")')
check_local "$ORDER_FIRST" "one,from-default" "argument order follows declaration order"
check_local "$ORDER_SECOND" "$ORDER_FIRST" "argument order is stable across identical calls"

# A parameter declared later appends rather than reshuffling existing positions.
api_call POST "/api/hooks/$PARAM_HOOK_ID/parameters" "$MASTER_KEY" '{"param_key":"gamma","default_value":"appended","is_required":true}'
check "200" "declare a third parameter after the fact"
api_call POST "/api/hooks/$PARAM_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"alpha":"one"}}'
check "200" "dry-run after the new declaration"
check_jq ".command.args | join(\",\")" "one,from-default,appended" "the new parameter appended at the end"

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
    CREATED_KEY_ID=$(echo "$RESP_BODY" | jq -r '.key_id')
    CREATED_SIGNING_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
}

create_scoped_key "Execute-Only Key"
EXEC_KEY="$CREATED_KEY"; EXEC_ID="$CREATED_ID"
EXEC_KEY_ID="$CREATED_KEY_ID"; EXEC_SIGNING_SECRET="$CREATED_SIGNING_SECRET"
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
    # The canonical string is METHOD \n PATH_AND_QUERY \n TIMESTAMP \n RAW_BODY, keyed on the
    # key's *signing secret* (never the bearer API key). printf '%b' is not used: the components
    # must be joined with real newlines and nothing else interpreted.
    sign_canonical() {
        local secret="$1" method="$2" path="$3" ts="$4" body="$5"
        printf '%s\n%s\n%s\n%s' "$method" "$path" "$ts" "$body" \
            | openssl dgst -sha256 -hmac "$secret" -r | cut -d' ' -f1
    }

    # Issues a fully-signed request. Usage: signed_call METHOD PATH BODY [AUTH_HEADER...] via globals
    #   $SIGN_SECRET  — signing secret
    #   $SIGN_AUTH    — the identifying header, e.g. "X-API-Key: ..." or "X-Key-Id: ..."
    #   $SIGN_TS      — optional timestamp override (defaults to now)
    signed_call() {
        local method="$1" path="$2" body="${3:-}"
        local ts="${SIGN_TS:-$(date +%s)}"
        local sig; sig=$(sign_canonical "$SIGN_SECRET" "$method" "$path" "$ts" "$body")
        local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method"
                    -H "$SIGN_AUTH" -H "X-Timestamp: $ts" -H "X-Signature-256: sha256=$sig")
        [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
        RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        local color; color=$(status_color "$RESP_STATUS")
        printf "%s ${color}[%s]${RESET} %-6s %s ${DIM}(signed, ts=%s)${RESET}\n" \
            "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" "$ts" >&2
        print_response_body
    }

    # A dedicated master key, so the all-methods checks below can sign master-only routes without
    # scraping the bootstrap banner for its randomly-generated secret.
    create_scoped_key "Signing Master" ',"is_master":true'
    SIGNING_MASTER_KEY="$CREATED_KEY"
    MASTER_SIGNING_SECRET="$CREATED_SIGNING_SECRET"

    SIGN_SECRET="$EXEC_SIGNING_SECRET"
    SIGN_AUTH="X-API-Key: $EXEC_KEY"
    SIGN_TS=""

    SIGNED_BODY='{"parameters":{"target":"signed"}}'
    EXEC_PATH="/api/hooks/$ECHO_HOOK_ID/execute"

    signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "200" "a correctly signed request is accepted alongside a bearer key"
    check_jq ".status" "SUCCESS" "the signed request executed"

    # --- Negative cases, one broken component at a time ---
    NOW=$(date +%s)
    GOOD_SIG=$(sign_canonical "$EXEC_SIGNING_SECRET" "POST" "$EXEC_PATH" "$NOW" "$SIGNED_BODY")

    # Tampered body, valid signature and timestamp.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Timestamp: $NOW" -H "X-Signature-256: sha256=$GOOD_SIG" \
        -d '{"parameters":{"target":"tampered"}}' "$BASE_URL$EXEC_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a signature over an altered body is rejected"

    # Signature computed for a different method.
    WRONG_METHOD_SIG=$(sign_canonical "$EXEC_SIGNING_SECRET" "DELETE" "$EXEC_PATH" "$NOW" "$SIGNED_BODY")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Timestamp: $NOW" -H "X-Signature-256: sha256=$WRONG_METHOD_SIG" \
        -d "$SIGNED_BODY" "$BASE_URL$EXEC_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a signature computed for a different HTTP method is rejected"

    # Signature computed for a different path.
    WRONG_PATH_SIG=$(sign_canonical "$EXEC_SIGNING_SECRET" "POST" "/api/hooks/other/execute" "$NOW" "$SIGNED_BODY")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Timestamp: $NOW" -H "X-Signature-256: sha256=$WRONG_PATH_SIG" \
        -d "$SIGNED_BODY" "$BASE_URL$EXEC_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a signature computed for a different path is rejected"

    # Wrong secret, and the classic mistake of signing with the bearer key.
    SIGN_SECRET="definitely-not-the-secret"; signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "401" "a signature made with the wrong secret is rejected"
    SIGN_SECRET="$EXEC_KEY"; signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "401" "a signature keyed on the API key rather than the signing secret is rejected"
    SIGN_SECRET="$EXEC_SIGNING_SECRET"

    # Malformed signature headers.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Timestamp: $NOW" -H "X-Signature-256: sha256=00ff" \
        -d "$SIGNED_BODY" "$BASE_URL$EXEC_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a bogus signature digest is rejected"

    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Timestamp: $NOW" -H "X-Signature-256: notprefixed" \
        -d "$SIGNED_BODY" "$BASE_URL$EXEC_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a signature header without the sha256= prefix is rejected"

    # --- Anti-replay window ---
    # Offsets stay well clear of the ±300s boundary: $NOW is sampled once but several signed
    # requests (each executing a script) run in between, so a ±299 offset would drift across the
    # boundary and fail intermittently. Exact boundary behaviour is unit-tested instead.
    SIGN_TS=$((NOW - 240)); signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "200" "a timestamp inside the window is accepted"
    SIGN_TS=$((NOW + 240)); signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "200" "modest forward clock skew is tolerated"
    SIGN_TS=$((NOW - 360)); signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "401" "an expired timestamp is rejected (replay window)"
    check_true '.error | contains("window")' "the error names the replay window"
    SIGN_TS=$((NOW - 86400)); signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "401" "a day-old capture is rejected"
    SIGN_TS=$((NOW + 3600)); signed_call POST "$EXEC_PATH" "$SIGNED_BODY"
    check "401" "a far-future timestamp is rejected"
    SIGN_TS=""

    # A signature with no timestamp at all cannot be replay-checked.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Signature-256: sha256=$GOOD_SIG" -d "$SIGNED_BODY" "$BASE_URL$EXEC_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a signed request with no X-Timestamp is rejected"
    check_true '.error | contains("X-Timestamp")' "the error names the missing header"

    # Malformed timestamps are rejected rather than coerced to 'now'.
    for BAD_TS in "not-a-number" "1700000000.5" ""; do
        RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
            -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
            -H "X-Timestamp: $BAD_TS" -H "X-Signature-256: sha256=$GOOD_SIG" \
            -d "$SIGNED_BODY" "$BASE_URL$EXEC_PATH")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        check "401" "a malformed X-Timestamp ('$BAD_TS') is rejected"
    done

    # --- Signing across every HTTP method, as the SPA does ---
    SIGN_AUTH="X-API-Key: $SIGNING_MASTER_KEY"; SIGN_SECRET="$MASTER_SIGNING_SECRET"
    signed_call GET "/api/hooks" ""
    check "200" "a signed GET is accepted"
    signed_call GET "/api/executions?limit=5" ""
    check "200" "a signed GET with a query string is accepted"
    signed_call PUT "/api/hooks/$ECHO_HOOK_ID" '{"description":"signed put"}'
    check "200" "a signed PUT is accepted"
    signed_call PATCH "/api/hooks/$ECHO_HOOK_ID" '{"description":"signed patch"}'
    check "200" "a signed PATCH is accepted"

    # The query string is signed material: re-pointing it invalidates the signature.
    QS_TS=$(date +%s)
    QS_SIG=$(sign_canonical "$MASTER_SIGNING_SECRET" "GET" "/api/executions?limit=5" "$QS_TS" "")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X GET \
        -H "X-API-Key: $SIGNING_MASTER_KEY" -H "X-Timestamp: $QS_TS" -H "X-Signature-256: sha256=$QS_SIG" \
        "$BASE_URL/api/executions?limit=1000")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "altering the query string invalidates the signature"

    SIGN_AUTH="X-API-Key: $EXEC_KEY"; SIGN_SECRET="$EXEC_SIGNING_SECRET"

    # --- Key ID + signature, with no bearer credential at all (the webhook-sender pattern) ---
    curl_signed() {
        local path="$1" key_id="$2" secret="$3" body="$4"
        local ts; ts=$(date +%s)
        local sig; sig=$(sign_canonical "$secret" "POST" "$path" "$ts" "$body")
        RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
            -H "X-Key-Id: $key_id" -H "Content-Type: application/json" \
            -H "X-Timestamp: $ts" -H "X-Signature-256: sha256=$sig" -d "$body" "$BASE_URL$path")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        local color; color=$(status_color "$RESP_STATUS")
        printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "POST" "$BASE_URL$path" >&2
        print_response_body
    }

    curl_signed "/webhook/echo_hook" "$EXEC_KEY_ID" "$EXEC_SIGNING_SECRET" '{"target":"via-key-id"}'
    check "200" "X-Key-Id plus a valid signature authenticates without any API key"
    check_jq ".stdout | rtrimstr(\"\n\")" "hello via-key-id" "the signed webhook executed"

    curl_signed "/webhook/echo_hook" "$EXEC_KEY_ID" "definitely-not-the-secret" '{"target":"forged"}'
    check "401" "a signature made with the wrong secret is rejected"

    curl_signed "/webhook/echo_hook" "shk_00000000000000000000000000000000" "$EXEC_SIGNING_SECRET" '{"target":"x"}'
    check "401" "an unknown key id is rejected"

    # A key id alone is public and must not authenticate anything.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-Key-Id: $EXEC_KEY_ID" -H "Content-Type: application/json" \
        -d '{"target":"unsigned"}' "$BASE_URL/webhook/echo_hook")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a key id without a signature is rejected"
    check_true '.error | contains("X-Signature-256")' "the error explains that a signature is required"

    # Rotation issues a new pair and invalidates the old secret immediately. All three credentials
    # are captured here, before any later call overwrites $RESP_BODY.
    api_call POST "/api/keys/$EXEC_ID/rotate" "$MASTER_KEY"
    check "200" "rotate the execute-only key"
    check_true '.key_id | startswith("shk_")' "rotation returns a new key id"
    check_true '.signing_secret | length == 64' "rotation returns a new 32-byte signing secret"
    ROTATED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    ROTATED_KEY_ID=$(echo "$RESP_BODY" | jq -r '.key_id')
    ROTATED_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')

    curl_signed "/webhook/echo_hook" "$EXEC_KEY_ID" "$EXEC_SIGNING_SECRET" '{"target":"stale"}'
    check "401" "the pre-rotation key id and secret no longer authenticate"

    curl_signed "/webhook/echo_hook" "$ROTATED_KEY_ID" "$ROTATED_SECRET" '{"target":"rotated"}'
    check "200" "the rotated pair authenticates"

    # Later sections keep using this key, so adopt the rotated credentials wholesale.
    EXEC_KEY="$ROTATED_KEY"
    EXEC_KEY_ID="$ROTATED_KEY_ID"
    EXEC_SIGNING_SECRET="$ROTATED_SECRET"
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

# ── 21. Linux permission & path containment diagnostics ─────────────────────

log_section "21. Linux Permission Diagnostics & Path Containment"

# --- Non-executable script (chmod 0600): must fail with an actionable EACCES-class message ---
NOEXEC_SCRIPT="$HOOK_DIR/no_exec_bit.sh"
printf '#!/bin/sh\necho should never run\n' > "$NOEXEC_SCRIPT"
chmod 0600 "$NOEXEC_SCRIPT"

api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"no_exec_bit\",\"script_path\":\"$NOEXEC_SCRIPT\"}"
check "200" "declare a hook pointing at a non-executable file"
NOEXEC_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$NOEXEC_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "400" "executing a non-executable script is refused"
check_true '.error | startswith("[ERROR] Cannot execute ")' "the error uses the standard diagnostic prefix"
check_true '.error | contains("no execute bit set")' "the diagnostic names the actual cause"
check_true '.error | contains("0600")' "the diagnostic reports the file's real mode"
check_true '.error | contains("chmod +x")' "the diagnostic states the remedy"
check_true '.error | contains("uid=")' "the diagnostic identifies the user the daemon runs as"

# The same diagnostic must reach the system log, not just the HTTP caller.
check_local "$(grep -c 'rejection=PermissionDenied\|rejection=NotExecutable' "$SERVER_LOG")" "1" \
    "the refusal is logged once via tracing with its classification"

# The dry run reports it as data instead of failing.
api_call POST "/api/hooks/$NOEXEC_HOOK_ID/test" "$MASTER_KEY" '{}'
check "200" "dry-running a non-executable hook still returns a preview"
check_jq ".would_execute" "false" "the preview reports it would be blocked"
check_true '.blocking_reason | contains("no execute bit set")' "the preview carries the same diagnostic"

# Granting the bit makes it run — proving the refusal was purely about permissions.
chmod +x "$NOEXEC_SCRIPT"
api_call POST "/api/hooks/$NOEXEC_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "200" "the same hook runs once the execute bit is granted"
check_jq ".status" "SUCCESS" "it succeeds after chmod +x"

# --- Missing script: ENOENT, clearly distinguished from a permission problem ---
api_call POST "/api/hooks/$GHOST_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "400" "executing a hook whose script does not exist is refused"
check_true '.error | contains("No such file or directory (ENOENT)")' "the diagnostic reports ENOENT"
check_true '.error | contains("Deploy the script")' "the diagnostic states the remedy"
check_true '(.error | contains("EACCES")) | not' "ENOENT is not mislabelled as a permission error"

# --- A directory is not a script ---
mkdir -p "$HOOK_DIR/i_am_a_directory"
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"dir_hook\",\"script_path\":\"$HOOK_DIR/i_am_a_directory\"}"
check "200" "declare a hook pointing at a directory"
DIR_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
api_call POST "/api/hooks/$DIR_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "400" "executing a directory is refused"
check_true '.error | contains("not a regular file")' "the diagnostic explains why"

# --- Unsearchable parent directory: EACCES naming the blocking directory ---
# Root bypasses directory search bits entirely, so this scenario cannot be built as root.
if [ "$(id -u)" -eq 0 ]; then
    warn "Skipping the unsearchable-directory check: running as root bypasses search bits."
else
    LOCKED_DIR="$HOOK_DIR/locked"
    mkdir -p "$LOCKED_DIR"
    printf '#!/bin/sh\necho hidden\n' > "$LOCKED_DIR/hidden.sh"
    chmod 0755 "$LOCKED_DIR/hidden.sh"
    api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"locked_dir\",\"script_path\":\"$LOCKED_DIR/hidden.sh\"}"
    check "200" "declare a hook inside a directory that is about to be locked"
    LOCKED_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    chmod 0000 "$LOCKED_DIR"
    api_call POST "/api/hooks/$LOCKED_HOOK_ID/execute" "$MASTER_KEY" '{}'
    check "400" "executing a script behind an unsearchable directory is refused"
    check_true '.error | contains("Permission denied (EACCES)")' "the diagnostic reports EACCES"
    check_true ".error | contains(\"$LOCKED_DIR\")" "the diagnostic pinpoints the blocking directory"
    chmod 0755 "$LOCKED_DIR"
fi

# --- Path traversal payloads are blocked at definition time ---
TRAVERSAL_BLOCKED=0
TRAVERSAL_TOTAL=0
for payload in \
    "/scripts/../../etc/shadow" \
    "/opt/hooks/../../../etc/passwd" \
    "../../../bin/sh" \
    "../relative_escape.sh" \
    "relative.sh" \
    "./also_relative.sh" \
    "$HOOK_DIR/../../etc/shadow"
do
    TRAVERSAL_TOTAL=$((TRAVERSAL_TOTAL + 1))
    api_call POST "/api/hooks" "$MASTER_KEY" "$(jq -nc --arg p "$payload" '{name:"traversal_probe",script_path:$p}')"
    if [ "$RESP_STATUS" == "400" ]; then
        TRAVERSAL_BLOCKED=$((TRAVERSAL_BLOCKED + 1))
    else
        err "Traversal payload '$payload' was NOT rejected (status $RESP_STATUS)"
    fi
done
check_local "$TRAVERSAL_BLOCKED" "$TRAVERSAL_TOTAL" "every path traversal payload is blocked at hook creation"

api_call GET "/api/hooks/traversal_probe" "$MASTER_KEY"
check "404" "no hook was created by any traversal payload"

# --- Confinement to ALLOWED_SCRIPT_ROOTS ---
api_call GET "/api/settings" "$MASTER_KEY"
check "200" "settings report the configured script roots"
check_jq ".allowed_script_roots | join(\",\")" "$HOOK_DIR" "the confinement roots are visible to master keys"

api_call POST "/api/hooks" "$MASTER_KEY" '{"name":"outside_root","script_path":"/bin/true"}'
check "400" "an absolute path outside ALLOWED_SCRIPT_ROOTS is refused"
check_true '.error | contains("outside the allowed script roots")' "the diagnostic explains the confinement"

api_call PUT "/api/hooks/$ECHO_HOOK_ID" "$MASTER_KEY" '{"script_path":"/bin/true"}'
check "400" "an existing hook cannot be re-pointed outside the allowed roots"

# --- A symlink whose literal path is contained but whose target escapes ---
ln -sf /bin/true "$HOOK_DIR/looks_contained.sh"
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"symlink_escape\",\"script_path\":\"$HOOK_DIR/looks_contained.sh\"}"
check "200" "a symlink inside the root passes the lexical check at definition time"
SYMLINK_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$SYMLINK_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "400" "...but resolving it at execution time catches the escape"
check_true '.error | contains("outside the allowed script roots")' "the symlink escape is reported as a containment failure"
check_true '.error | contains("it resolves to")' "the diagnostic reveals the real target"

# Nothing above should have produced an execution record.
api_call GET "/api/executions?hook=symlink_escape&limit=10" "$MASTER_KEY"
check "200" "query the escaped hook's history"
check_jq "length" "0" "a refused script never creates an execution record"

# ── 22. Privileged execution (run_as_user / sudo) ───────────────────────────

log_section "22. Privileged Execution (run_as_user via sudo)"

PRIV_SCRIPT=$(make_hook_script "privileged_hook.sh" 'echo "elevated:${HOOK_PARAM_TARGET}"')

api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"privileged_hook\",\"script_path\":\"$PRIV_SCRIPT\",\"run_as_user\":\"root\",\"parameters\":[{\"param_key\":\"target\",\"is_required\":true},{\"param_key\":\"reason\",\"default_value\":\"routine\",\"is_required\":true}]}"
check "200" "create a hook that elevates to root"
PRIV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".run_as_user" "root" "the elevation is stored and returned"

api_call POST "/api/hooks/$PRIV_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"target":"203.0.113.7"}}'
check "200" "dry-run the privileged hook"
check_jq ".command.program" "/usr/bin/sudo" "the program is sudo, not the script"
check_jq ".command.run_as_user" "root" "the preview names the target account"
check_jq ".command.args | join(\" \")" "-n -u root -- $PRIV_SCRIPT 203.0.113.7 routine" \
    "the preview shows the exact sudo argument vector"
# The -- separator must sit immediately before the script path.
check_true '(.command.args | index("--")) as $i | .command.args[$i + 1] == "'"$PRIV_SCRIPT"'"' \
    "the -- separator immediately precedes the script path"
check_true '(.command.args | index("--")) < (.command.args | index("203.0.113.7"))' \
    "parameters are placed after the separator, where sudo cannot parse them as options"
check_jq ".command.env.HOOK_PARAM_TARGET" "203.0.113.7" "HOOK_PARAM_* injection is unchanged under sudo"
check_jq ".command.env.HOOK_PARAM_REASON" "routine" "defaulted parameters are injected too"

# An unprivileged hook must show no sudo wrapper at all. Created here rather than reusing an
# earlier section's hook, so this comparison never depends on what §20's cascade deleted.
PLAIN_SCRIPT=$(make_hook_script "plain_compare.sh" 'echo "plain:$1"')
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"plain_compare\",\"script_path\":\"$PLAIN_SCRIPT\",\"parameters\":[{\"param_key\":\"target\",\"is_required\":true}]}"
check "200" "create an unprivileged hook for comparison"
PLAIN_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".run_as_user" "null" "it reports no elevation"

api_call POST "/api/hooks/$PLAIN_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"target":"one"}}'
check "200" "dry-run the unprivileged hook"
check_jq ".command.program" "$PLAIN_SCRIPT" "the program is the script itself"
check_jq ".command.run_as_user" "null" "no elevation is reported"
check_jq ".command.args | join(\" \")" "one" "only the hook's own parameters are passed"
check_true '(.command.args | index("--")) == null' "no sudo separator appears"

# --- run_as_user validation: option injection into sudo ---
PRIV_BLOCKED=0
PRIV_TOTAL=0
for candidate in "-i" "--login" "-u" "-s" "root user" "root;id" "root|id" "1root" "root/../etc"; do
    PRIV_TOTAL=$((PRIV_TOTAL + 1))
    api_call POST "/api/hooks" "$MASTER_KEY" \
        "$(jq -nc --arg p "$PRIV_SCRIPT" --arg u "$candidate" '{name:"hostile_user",script_path:$p,run_as_user:$u}')"
    if [ "$RESP_STATUS" == "400" ]; then
        PRIV_BLOCKED=$((PRIV_BLOCKED + 1))
    else
        err "run_as_user '$candidate' was NOT rejected (status $RESP_STATUS)"
    fi
done
check_local "$PRIV_BLOCKED" "$PRIV_TOTAL" "every malformed/option-shaped run_as_user is rejected"

api_call GET "/api/hooks/hostile_user" "$MASTER_KEY"
check "404" "no hook was created by any hostile run_as_user"

# --- Elevation can be changed and dropped ---
api_call PUT "/api/hooks/$PRIV_HOOK_ID" "$MASTER_KEY" '{"run_as_user":"postgres"}'
check "200" "change the target account"
check_jq ".run_as_user" "postgres" "the new account is persisted"

api_call PUT "/api/hooks/$PRIV_HOOK_ID" "$MASTER_KEY" '{"run_as_user":"-i"}'
check "400" "an existing hook cannot be re-pointed at an option-shaped account"

api_call PUT "/api/hooks/$PRIV_HOOK_ID" "$MASTER_KEY" '{"description":"unrelated change"}'
check "200" "omitting run_as_user leaves the elevation untouched"
check_jq ".run_as_user" "postgres" "the elevation survived an unrelated update"

api_call PUT "/api/hooks/$PRIV_HOOK_ID" "$MASTER_KEY" '{"run_as_user":""}'
check "200" "an explicit empty string drops elevation"
check_jq ".run_as_user" "null" "the hook runs as the daemon user again"

api_call POST "/api/hooks/$PRIV_HOOK_ID/test" "$MASTER_KEY" '{"parameters":{"target":"203.0.113.7"}}'
check "200" "dry-run after dropping elevation"
check_jq ".command.program" "$PRIV_SCRIPT" "the sudo wrapper is gone"

# --- Master-only guard: a non-master may create hooks but never elevate them ---
create_scoped_key "Hook Creator No Elevation" ',"can_manage_hooks":true'
NOELEV_KEY="$CREATED_KEY"; NOELEV_ID="$CREATED_ID"

NOELEV_SCRIPT=$(make_hook_script "noelev_hook.sh" 'echo ok')
api_call POST "/api/hooks" "$NOELEV_KEY" "{\"name\":\"noelev_ordinary\",\"script_path\":\"$NOELEV_SCRIPT\"}"
check "200" "a can_manage_hooks key can create a standard hook"
check_jq ".run_as_user" "null" "the hook is unelevated"
NOELEV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks" "$NOELEV_KEY" "{\"name\":\"noelev_root\",\"script_path\":\"$NOELEV_SCRIPT\",\"run_as_user\":\"root\"}"
check "403" "the same key is refused when it supplies run_as_user=root"
check_jq ".error" "Only master API keys can assign run_as_user privileges" "the refusal message is exact"

api_call GET "/api/hooks/noelev_root" "$MASTER_KEY"
check "404" "no hook was created by the refused request"

# Authorization, not validation: a malformed account from a non-master is still a 403, so the
# field cannot be probed to learn what would be accepted.
api_call POST "/api/hooks" "$NOELEV_KEY" "{\"name\":\"noelev_probe\",\"script_path\":\"$NOELEV_SCRIPT\",\"run_as_user\":\"-i\"}"
check "403" "a malformed run_as_user from a non-master is refused as forbidden, not invalid"

# Explicit non-elevation is fine.
api_call POST "/api/hooks" "$NOELEV_KEY" "{\"name\":\"noelev_explicit_null\",\"script_path\":\"$NOELEV_SCRIPT\",\"run_as_user\":null}"
check "200" "an explicit null run_as_user is allowed for a non-master"

# The guard covers updates, including on a hook the key owns outright, and via PATCH.
api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"run_as_user":"root"}'
check "403" "a non-master cannot elevate its own hook via PUT"
api_call PATCH "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"run_as_user":"root"}'
check "403" "...nor via PATCH"

api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$MASTER_KEY" '{"run_as_user":"root"}'
check "200" "a master can elevate the same hook"
check_jq ".run_as_user" "root" "the elevation took effect"

api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"description":"unrelated"}'
check "200" "a non-master may still edit other fields of an elevated hook"
check_jq ".run_as_user" "root" "the elevation is preserved by an unrelated edit"

api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"run_as_user":""}'
check "200" "dropping elevation is not an escalation, so a non-master may do it"
check_jq ".run_as_user" "null" "the hook is unelevated again"

# --- The elevation is auditable ---
api_call GET "/api/audit-logs?action=HOOK_CREATE&limit=50" "$MASTER_KEY"
check "200" "fetch hook creation audit entries"
# `test()` with `.` wildcards instead of literal apostrophes: the surrounding jq filter is single
# quoted for bash, so an embedded ' would terminate it.
check_true '[.[] | select(.target_resource == "privileged_hook") | .details | test("runs as .root. via sudo")] | length == 1' \
    "the audit trail records which account a hook was created to run as"
check_true '[.[] | select(.target_resource == "plain_compare") | .details | test("runs as the daemon user")] | length == 1' \
    "an unprivileged hook is audited as running unelevated"

# ── 23. Test (dry-run) vs Launch (execute) endpoints ────────────────────────

log_section "23. Test vs Launch Execution Endpoints"

TL_SIDE_EFFECT="$WORK_DIR/launch_side_effect"
TL_SCRIPT=$(make_hook_script "test_vs_launch.sh" "touch \"$TL_SIDE_EFFECT\"
echo \"launched:\${HOOK_PARAM_MODE}\"
echo \"diagnostics\" >&2
exit 0")
api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"test_vs_launch\",\"script_path\":\"$TL_SCRIPT\",\"parameters\":[{\"param_key\":\"mode\",\"default_value\":\"default-mode\",\"is_required\":true}]}"
check "200" "create a hook with an observable side effect"
TL_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# Test = dry run: resolves and previews, spawns nothing.
api_call POST "/api/hooks/$TL_HOOK_ID/test" "$MASTER_KEY" '{}'
check "200" "Test (dry run) returns a preview"
check_jq ".would_execute" "true" "the preview reports the hook is runnable"
check_jq ".command.program" "$TL_SCRIPT" "the preview names the program"
check_jq ".resolved_parameters.mode" "default-mode" "the preview resolves defaults"
check_true '.stdout == null' "a dry run reports no stdout, because nothing ran"
if [ -e "$TL_SIDE_EFFECT" ]; then
    check_local "side effect ran" "no side effect" "Test must not execute the script"
else
    check_local "no side effect" "no side effect" "Test must not execute the script"
fi

api_call GET "/api/executions?hook=test_vs_launch&limit=10" "$MASTER_KEY"
check "200" "query the hook's history after the dry run"
check_jq "length" "0" "a dry run records no execution"

# Launch = the real thing, with captured output and a history row.
api_call POST "/api/hooks/$TL_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"mode":"production"}}'
check "200" "Launch executes the hook"
check_jq ".status" "SUCCESS" "the execution succeeded"
check_jq ".exit_code" "0" "the exit code is captured"
check_jq ".stdout | rtrimstr(\"\n\")" "launched:production" "stdout is captured"
check_jq ".stderr | rtrimstr(\"\n\")" "diagnostics" "stderr is captured separately"
check_true '.duration_ms >= 0' "a duration is recorded"
if [ -e "$TL_SIDE_EFFECT" ]; then
    check_local "side effect ran" "side effect ran" "Launch really executed the script"
else
    check_local "no side effect" "side effect ran" "Launch really executed the script"
fi

api_call GET "/api/executions?hook=test_vs_launch&limit=10" "$MASTER_KEY"
check "200" "query the hook's history after the launch"
check_jq "length" "1" "exactly one execution was recorded"
check_jq ".[0].status" "SUCCESS" "the recorded status matches"

# Both endpoints require can_execute; can_manage alone is not enough for either.
api_call POST "/api/keys/$MANAGE_ID/permissions" "$MASTER_KEY" "{\"hook_id\":\"$TL_HOOK_ID\",\"can_execute\":false,\"can_manage\":true}"
check "200" "grant a manage-only mapping on the hook"
api_call POST "/api/hooks/$TL_HOOK_ID/test" "$MANAGE_KEY" '{}'
check "403" "manage-only cannot dry-run (the preview reveals the resolved command line)"
api_call POST "/api/hooks/$TL_HOOK_ID/execute" "$MANAGE_KEY" '{}'
check "403" "manage-only cannot launch"

api_call POST "/api/keys/$NOACCESS_ID/permissions" "$MASTER_KEY" "{\"hook_id\":\"$TL_HOOK_ID\",\"can_execute\":true,\"can_manage\":false}"
check "200" "grant an execute-only mapping on the hook"
api_call POST "/api/hooks/$TL_HOOK_ID/test" "$NOACCESS_KEY" '{}'
check "200" "execute-only can dry-run"
api_call POST "/api/hooks/$TL_HOOK_ID/execute" "$NOACCESS_KEY" '{}'
check "200" "execute-only can launch"
api_call PUT "/api/hooks/$TL_HOOK_ID" "$NOACCESS_KEY" '{"description":"nope"}'
check "403" "...but still cannot modify the hook"
api_call DELETE "/api/hooks/$TL_HOOK_ID" "$NOACCESS_KEY"
check "403" "...nor delete it"

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
