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
# generation + pagination + enrichment, the master-only settings endpoint, stored-XSS payload
# round-tripping (plus the SPA's text-node rendering invariant), CLI-flag-shaped argument injection
# against both argv and the sudo boundary, the killpg process-escape boundary (in-group vs setsid),
# and the 3 MiB request body ceiling. Every request is logged with a timestamp, method, full URL,
# color-coded status, and jq-formatted body.
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
# Second, short-lived instance booted by §30 with TRUSTED_PROXIES unset, so the suite can cover
# both sides of the forwarding-header trust decision in one run.
STRICT_SERVER_PID=""
STRICT_BASE_URL=""

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

# Usage: check_stdout_contains "literal substring" "description"
#
# Separate from check_true because the substring is a *literal*, not a jq expression: the hostile
# payloads in §27 contain `$`, backticks, quotes and angle brackets, all of which would be
# reinterpreted if they were spliced into a filter string. `--arg` binds them as data instead.
check_stdout_contains() {
    local needle="$1" description="$2"
    local actual
    actual=$(echo "$RESP_BODY" | jq -e --arg n "$needle" '.stdout | contains($n)' 2>/dev/null)
    if [ "$actual" == "true" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (stdout lacked '$needle')" >&2
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
    if [ -n "$STRICT_SERVER_PID" ] && kill -0 "$STRICT_SERVER_PID" 2>/dev/null; then
        log "Stopping strict-proxy server (pid $STRICT_SERVER_PID)..."
        kill "$STRICT_SERVER_PID" 2>/dev/null || true
        wait "$STRICT_SERVER_PID" 2>/dev/null || true
    fi
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
# TRUSTED_PROXIES names the loopback address the suite connects from, which is what puts this
# instance on the "behind a reverse proxy" path so §15 can drive bound_ips with X-Forwarded-For.
# It is deliberately NOT the default: §30 boots a second instance without it to prove that an
# unconfigured daemon ignores forwarding headers entirely.
#
# Both spellings are configured at once — the literal address and the `localhost` *hostname* that
# resolves to it. That is the Docker/Traefik shape (a proxy named rather than addressed, because the
# orchestrator assigns its IP), and it lets §30 prove name resolution works against a real DNS
# lookup rather than a stub.
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    ALLOWED_ENV_VARS="PATH" LOG_RETENTION_DAYS=30 \
    ALLOWED_SCRIPT_ROOTS="$HOOK_DIR" \
    TRUSTED_PROXIES="$BIND_HOST,localhost" \
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
    #   $SIGN_AUTH    — the identifying header, always "X-API-Key: <key>"
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
        local path="$1" api_key="$2" secret="$3" body="$4"
        local ts; ts=$(date +%s)
        local sig; sig=$(sign_canonical "$secret" "POST" "$path" "$ts" "$body")
        RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
            -H "X-API-Key: $api_key" -H "Content-Type: application/json" \
            -H "X-Timestamp: $ts" -H "X-Signature-256: sha256=$sig" -d "$body" "$BASE_URL$path")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        local color; color=$(status_color "$RESP_STATUS")
        printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "POST" "$BASE_URL$path" >&2
        print_response_body
    }

    curl_signed "/webhook/echo_hook" "$EXEC_KEY" "$EXEC_SIGNING_SECRET" '{"target":"via-signature"}'
    check "200" "a signed webhook request authenticates via X-API-Key"
    check_jq ".stdout | rtrimstr(\"\n\")" "hello via-signature" "the signed webhook executed"

    curl_signed "/webhook/echo_hook" "$EXEC_KEY" "definitely-not-the-secret" '{"target":"forged"}'
    check "401" "a signature made with the wrong secret is rejected"

    # The public key_id is not a credential: it must not resolve a key record.
    curl_signed "/webhook/echo_hook" "$EXEC_KEY_ID" "$EXEC_SIGNING_SECRET" '{"target":"x"}'
    check "401" "the public key_id cannot be used as a bearer key"

    # The retired X-Key-Id header must resolve nothing at all.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-Key-Id: $EXEC_KEY_ID" -H "Content-Type: application/json" \
        -d '{"target":"legacy"}' "$BASE_URL/webhook/echo_hook")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "the retired X-Key-Id header does not authenticate"
    check_true '.error | contains("X-API-Key")' "the error names the one header that works"

    # Rotation issues a new pair and invalidates the old secret immediately. All three credentials
    # are captured here, before any later call overwrites $RESP_BODY.
    api_call POST "/api/keys/$EXEC_ID/rotate" "$MASTER_KEY"
    check "200" "rotate the execute-only key"
    check_true '.key_id | startswith("shk_")' "rotation returns a new key id"
    check_true '.signing_secret | length == 64' "rotation returns a new 32-byte signing secret"
    ROTATED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    ROTATED_KEY_ID=$(echo "$RESP_BODY" | jq -r '.key_id')
    ROTATED_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')

    curl_signed "/webhook/echo_hook" "$EXEC_KEY" "$EXEC_SIGNING_SECRET" '{"target":"stale"}'
    check "401" "the pre-rotation key and secret no longer authenticate"

    curl_signed "/webhook/echo_hook" "$ROTATED_KEY" "$ROTATED_SECRET" '{"target":"rotated"}'
    check "200" "the rotated credentials authenticate"

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
# Which peers may speak for a client decides what every bound_ips check compares against, so an
# operator must be able to read it back rather than infer it from the daemon's environment.
check_jq ".trusted_proxies | join(\",\")" "$BIND_HOST/32,localhost" \
    "both proxy spellings are reported as configured, the hostname unresolved"
check_true '.hook_count >= 8' "the hook counter reflects everything created above"
check_true '.execution_count >= 1' "the execution counter is populated"

# ── 20. Hook deletion cascade ───────────────────────────────────────────────

log_section "20. Hook Soft Delete, Trash & Hard-Delete Cascade"

api_call GET "/api/executions?hook=param_hook&limit=50" "$MASTER_KEY"
check "200" "param_hook has execution history before deletion"
check_true 'length >= 1' "at least one execution exists for it"

# --- Soft delete: hidden, but nothing is destroyed ---
api_call DELETE "/api/hooks/$PARAM_HOOK_ID" "$MASTER_KEY"
check "204" "delete param_hook (soft by default)"

api_call GET "/api/hooks/param_hook" "$MASTER_KEY"
check "404" "the hook reads as gone to every ordinary route"
api_call POST "/api/hooks/$PARAM_HOOK_ID/execute" "$MASTER_KEY" '{}'
check "404" "a trashed hook cannot be executed"
api_call GET "/api/hooks" "$MASTER_KEY"
check_true 'all(.[]; .name != "param_hook")' "it is absent from the default listing"

# The whole point: the history and the permission grants survive.
api_call GET "/api/executions?limit=100" "$MASTER_KEY"
check "200" "history is still readable after a soft delete"
check_true '[.[] | select(.hook_name == "param_hook")] | length >= 1' \
    "the trashed hook's execution history is preserved, not cascaded away"

# --- Master trash view & restore ---
api_call GET "/api/hooks?include_deleted=true" "$MASTER_KEY"
check "200" "master can list the trash"
check_true '[.[] | select(.name == "param_hook" and .is_deleted == true)] | length == 1' \
    "the trashed hook appears in the trash view, flagged"
check_true '[.[] | select(.name == "param_hook") | .deleted_at] | all(. != null)' \
    "the deletion is timestamped"
check_true '[.[] | select(.name == "param_hook") | .deleted_by] | all(. != null)' \
    "the acting key is recorded"

api_call GET "/api/hooks?include_deleted=true" "$EXEC_KEY"
check "403" "a non-master cannot view the trash"
api_call POST "/api/hooks/$PARAM_HOOK_ID/restore" "$EXEC_KEY"
check "403" "a non-master cannot restore"
api_call DELETE "/api/hooks/$PARAM_HOOK_ID?hard=true" "$EXEC_KEY"
check "403" "a non-master cannot hard-delete"

api_call POST "/api/hooks/$PARAM_HOOK_ID/restore" "$MASTER_KEY"
check "200" "master restores the hook"
check_jq ".is_deleted" "false" "it is live again"
check_jq ".deleted_at" "null" "the deletion timestamp is cleared"
api_call GET "/api/hooks/param_hook" "$MASTER_KEY"
check "200" "the restored hook is reachable again"

api_call POST "/api/hooks/$PARAM_HOOK_ID/restore" "$MASTER_KEY"
check "400" "restoring a live hook is a validation error, not a silent no-op"

# --- A trashed hook still holds its unique name ---
api_call DELETE "/api/hooks/$PARAM_HOOK_ID" "$MASTER_KEY"
check "204" "trash it again"
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$PARAM_SCRIPT" '{name:"param_hook",script_path:$p}')"
check "409" "a trashed hook still holds its unique name"
check_true '.error | contains("hard=true")' "the conflict explains how to free the name"

# --- Hard delete: now everything cascades ---
api_call DELETE "/api/hooks/$PARAM_HOOK_ID?hard=true" "$MASTER_KEY"
check "204" "master hard-deletes the trashed hook"

api_call GET "/api/hooks?include_deleted=true" "$MASTER_KEY"
check_true 'all(.[]; .name != "param_hook")' "it is gone from the trash too"

api_call GET "/api/executions?limit=100" "$MASTER_KEY"
check "200" "history is readable after the hard delete"
check_true 'all(.[]; .hook_name != "param_hook")' "the hard delete cascaded its executions away"

api_call GET "/api/keys" "$MASTER_KEY"
check "200" "list keys after the cascade"
check_true 'all(.[]; [.hook_permissions[] | select(.hook_name == "param_hook")] | length == 0)' \
    "permission mappings for the hard-deleted hook cascaded away too"

# --- The 92-day purge endpoint ---
api_call POST "/api/system/purge-hooks" "$EXEC_KEY"
check "403" "the purge endpoint is master-only"
api_call POST "/api/system/purge-hooks?older_than_days=-1" "$MASTER_KEY"
check "400" "a negative window is rejected"
api_call POST "/api/system/purge-hooks" "$MASTER_KEY"
check "200" "master runs the purge sweep"
check_jq ".older_than_days" "92" "it defaults to the 92-day retention window"
check_jq ".purged" "0" "nothing in this run's trash is old enough to purge"

# A freshly-trashed hook is untouched by the default window but caught by a zero-day one... except
# `0` is deliberately a no-op ("keep forever"), matching LOG_RETENTION_DAYS=0.
PURGE_SCRIPT=$(make_hook_script "purge_me.sh" 'echo purge')
api_call POST "/api/hooks" "$MASTER_KEY" "$(jq -nc --arg p "$PURGE_SCRIPT" '{name:"purge_me",script_path:$p}')"
check "200" "create a hook destined for the trash"
PURGE_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
api_call DELETE "/api/hooks/$PURGE_HOOK_ID" "$MASTER_KEY"
check "204" "trash it"
api_call POST "/api/system/purge-hooks?older_than_days=0" "$MASTER_KEY"
check "200" "a zero window runs"
check_jq ".purged" "0" "zero means 'keep forever', not 'delete everything'"
api_call GET "/api/hooks?include_deleted=true" "$MASTER_KEY"
check_true '[.[] | select(.name == "purge_me")] | length == 1' "the freshly-trashed hook survives"

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

# Once elevated, the hook is master-only to touch at all — even for the non-master that created it
# and holds full auto-provisioned rights on it. These three checks are the inverse of what they
# asserted before finding #4: the old expectation was that an edit omitting `run_as_user` stayed
# permissible, which is exactly what let a can_manage holder repoint a root hook's script_path.
api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"description":"unrelated"}'
check "403" "a non-master cannot edit any field of a now-elevated hook"

api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"run_as_user":""}'
check "403" "nor drop the elevation, which would only add a step to the same attack"

api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$MASTER_KEY" '{"run_as_user":""}'
check "200" "a master can drop the elevation"
check_jq ".run_as_user" "null" "the hook is unelevated again"

api_call PUT "/api/hooks/$NOELEV_HOOK_ID" "$NOELEV_KEY" '{"description":"unrelated"}'
check "200" "and the now-ordinary hook is editable by its non-master owner again"

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

# ── 24. Per-key HMAC modes (CANONICAL_V1 vs BODY_ONLY) ──────────────────────

log_section "24. Per-Key HMAC Modes"

if [ "$HAVE_OPENSSL" -eq 1 ]; then
    GH_SCRIPT=$(make_hook_script "gh_push.sh" 'echo "pushed:${HOOK_PARAM_REF}"')
    api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"on_push\",\"script_path\":\"$GH_SCRIPT\",\"parameters\":[{\"param_key\":\"ref\",\"default_value\":\"refs/heads/main\",\"is_required\":true}]}"
    check "200" "create a hook for third-party push webhooks"
    GH_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # A key created without hmac_mode must default to the strict scheme.
    create_scoped_key "Default Mode Key"
    check_jq ".key_id | startswith(\"shk_\")" "true" "the new key has a key id"
    DEFAULT_MODE_ID="$CREATED_ID"
    api_call GET "/api/keys" "$MASTER_KEY"
    check "200" "list keys to inspect modes"
    check_true "[.[] | select(.id == \"$DEFAULT_MODE_ID\") | .hmac_mode == \"CANONICAL_V1\"] | all" \
        "an omitted hmac_mode defaults to CANONICAL_V1"

    # A key explicitly created in BODY_ONLY mode.
    create_scoped_key "Forgejo Webhook Key" ',"hmac_mode":"BODY_ONLY"'
    GH_KEY="$CREATED_KEY"; GH_KEY_ID_VAL="$CREATED_KEY_ID"; GH_SECRET="$CREATED_SIGNING_SECRET"; GH_ID="$CREATED_ID"

    api_call GET "/api/keys" "$MASTER_KEY"
    check "200" "list keys again"
    check_true "[.[] | select(.id == \"$GH_ID\") | .hmac_mode == \"BODY_ONLY\"] | all" \
        "the requested BODY_ONLY mode is stored and reported"

    api_call POST "/api/keys/$GH_ID/permissions" "$MASTER_KEY" "{\"hook_id\":\"$GH_HOOK_ID\",\"can_execute\":true,\"can_manage\":false}"
    check "200" "grant the webhook key execute rights on the hook"

    # Body-only signature, exactly as GitHub/Forgejo compute it: HMAC over the raw body, nothing else.
    GH_BODY='{"ref":"refs/heads/release"}'
    GH_SIG=$(printf '%s' "$GH_BODY" | openssl dgst -sha256 -hmac "$GH_SECRET" -r | cut -d' ' -f1)

    # X-Hub-Signature-256 is the header GitHub and Forgejo actually send.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $GH_KEY" -H "Content-Type: application/json" \
        -H "X-Hub-Signature-256: sha256=$GH_SIG" -d "$GH_BODY" "$BASE_URL/webhook/on_push")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "a GitHub-style X-Hub-Signature-256 body-only signature is accepted"
    check_jq ".stdout | rtrimstr(\"\n\")" "pushed:refs/heads/release" "the third-party webhook executed"

    # The same signature under the other accepted header name.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $GH_KEY" -H "Content-Type: application/json" \
        -H "X-Signature-256: sha256=$GH_SIG" -d "$GH_BODY" "$BASE_URL/webhook/on_push")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "X-Signature-256 is accepted in BODY_ONLY mode too"

    # No X-Timestamp is required in this mode — that is the whole point of it.
    check_true '.status == "SUCCESS"' "the body-only request needed no timestamp"

    # Tampering with the body still fails.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $GH_KEY" -H "Content-Type: application/json" \
        -H "X-Hub-Signature-256: sha256=$GH_SIG" -d '{"ref":"refs/heads/evil"}' "$BASE_URL/webhook/on_push")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a body-only signature over an altered body is rejected"

    # ...as does the wrong secret.
    BAD_SIG=$(printf '%s' "$GH_BODY" | openssl dgst -sha256 -hmac "not-the-secret" -r | cut -d' ' -f1)
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $GH_KEY" -H "Content-Type: application/json" \
        -H "X-Hub-Signature-256: sha256=$BAD_SIG" -d "$GH_BODY" "$BASE_URL/webhook/on_push")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a body-only signature made with the wrong secret is rejected"

    # An unsigned request still authenticates on the bearer key alone — the mode governs how a
    # signature is verified, not whether the key is a credential. (REQUIRE_SIGNED_REQUESTS is what
    # makes signing compulsory.)
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $GH_KEY" -H "Content-Type: application/json" \
        -d "$GH_BODY" "$BASE_URL/webhook/on_push")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "an unsigned request still authenticates on the bearer key"

    # A CANONICAL_V1 key must NOT be downgradeable by sending the hub header instead.
    api_call POST "/api/keys/$EXEC_ID/permissions" "$MASTER_KEY" "{\"hook_id\":\"$GH_HOOK_ID\",\"can_execute\":true,\"can_manage\":false}"
    check "200" "grant the canonical-mode key rights on the same hook"
    # A body-only signature offered to a CANONICAL_V1 key under the *recognised* header must fail:
    # the mode decides what material is signed, and body-only material is not canonical material.
    STRICT_SIG=$(printf '%s' "$GH_BODY" | openssl dgst -sha256 -hmac "$EXEC_SIGNING_SECRET" -r | cut -d' ' -f1)
    STRICT_TS=$(date +%s)
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $EXEC_KEY" -H "Content-Type: application/json" \
        -H "X-Timestamp: $STRICT_TS" -H "X-Signature-256: sha256=$STRICT_SIG" \
        -d "$GH_BODY" "$BASE_URL/webhook/on_push")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a body-only signature is rejected for a CANONICAL_V1 key"

    # Mode is switchable after the fact, and the switch is audited.
    api_call PUT "/api/keys/$DEFAULT_MODE_ID" "$MASTER_KEY" '{"hmac_mode":"BODY_ONLY"}'
    check "200" "switch a key to BODY_ONLY"
    check_jq ".hmac_mode" "BODY_ONLY" "the new mode is returned"
    api_call PUT "/api/keys/$DEFAULT_MODE_ID" "$MASTER_KEY" '{"hmac_mode":"CANONICAL_V1"}'
    check "200" "switch it back to CANONICAL_V1"
    check_jq ".hmac_mode" "CANONICAL_V1" "the strict mode is restored"

    api_call GET "/api/audit-logs?action=KEY_CREATE&limit=20" "$MASTER_KEY"
    check "200" "fetch key-creation audit entries"
    check_true '[.[] | select(.target_resource == "Forgejo Webhook Key") | .details | test("BODY_ONLY.*no replay protection")] | length == 1' \
        "choosing BODY_ONLY is audited as removing replay protection"

    # An unknown variant is refused by deserialization before the handler runs, so this is Axum's
    # own 422 with a plain-text body — not the JSON `{"error": ...}` shape our handlers emit.
    api_call POST "/api/keys" "$MASTER_KEY" '{"name":"bogus_mode","bound_ips":"0.0.0.0/0","hmac_mode":"NO_SUCH_MODE"}'
    check "422" "an unrecognized hmac_mode is rejected rather than silently defaulted"

    api_call GET "/api/keys" "$MASTER_KEY"
    check "200" "list keys after the rejected creation"
    check_true '[.[] | select(.name == "bogus_mode")] | length == 0' "no key was created with an invalid mode"
else
    warn "Skipping §24: openssl is not available to compute body-only signatures."
fi

# ── 25. Large signed payloads & buffer limits ───────────────────────────────

log_section "25. Large Signed Payloads"

if [ "$HAVE_OPENSSL" -eq 1 ]; then
    BIG_SCRIPT=$(make_hook_script "big_payload.sh" 'echo "marker=${HOOK_PARAM_MARKER} blob_len=${#HOOK_PARAM_BLOB}"')
    api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"big_payload\",\"script_path\":\"$BIG_SCRIPT\",\"parameters\":[{\"param_key\":\"marker\",\"default_value\":\"none\",\"is_required\":true},{\"param_key\":\"blob\",\"default_value\":\"\",\"is_required\":true}]}"
    check "200" "create a hook for large-payload testing"
    BIG_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # Signs a file's exact bytes over the canonical string, avoiding any shell-argument size limit
    # by streaming the body from disk for both the HMAC and the request itself.
    signed_file_call() {
        local method="$1" path="$2" file="$3" secret="$4" auth="$5"
        local ts; ts=$(date +%s)
        local canon="$WORK_DIR/canon.bin"
        { printf '%s\n%s\n%s\n' "$method" "$path" "$ts"; cat "$file"; } > "$canon"
        local sig; sig=$(openssl dgst -sha256 -hmac "$secret" -r "$canon" | cut -d' ' -f1)
        RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" \
            -H "$auth" -H "Content-Type: application/json" \
            -H "X-Timestamp: $ts" -H "X-Signature-256: sha256=$sig" \
            --data-binary "@$file" "$BASE_URL$path")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        local color; color=$(status_color "$RESP_STATUS")
        printf "%s ${color}[%s]${RESET} %-6s %s ${DIM}(signed, %s bytes)${RESET}\n" \
            "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" "$(wc -c < "$file")" >&2
        print_response_body
    }

    BIG_PATH="/api/hooks/$BIG_HOOK_ID/execute"
    # These must be a matching pair: $SIGNING_MASTER_KEY is the key whose creation returned
    # $MASTER_SIGNING_SECRET. Pairing it with the bootstrap $MASTER_KEY would sign with the wrong
    # secret and every request would 401.
    BIG_AUTH="X-API-Key: $SIGNING_MASTER_KEY"
    BIG_SECRET="$MASTER_SIGNING_SECRET"

    # ~512 KB body whose parameters stay small: the padding is a sibling of `parameters`, so it is
    # ignored for resolution but fully covered by the signature.
    # Padding is streamed through a file and read with --rawfile: passing half a megabyte as a
    # shell argument exceeds ARG_MAX and jq dies with "Argument list too long", silently leaving an
    # empty body behind.
    head -c 524288 /dev/zero | tr '\0' 'x' > "$WORK_DIR/pad_512k.txt"
    jq -nc --rawfile p "$WORK_DIR/pad_512k.txt" '{parameters:{marker:"big"},padding:$p}' > "$WORK_DIR/big_body.json"
    check_local "$([ "$(wc -c < "$WORK_DIR/big_body.json")" -gt 524288 ] && echo large || echo empty)" "large" \
        "the ~512 KB test body was generated (not truncated by ARG_MAX)"
    signed_file_call POST "$BIG_PATH" "$WORK_DIR/big_body.json" "$BIG_SECRET" "$BIG_AUTH"
    check "200" "a ~512 KB signed payload verifies and executes"
    check_jq ".status" "SUCCESS" "the large-payload execution succeeded"
    check_true '.stdout | contains("marker=big")' "parameters resolved correctly from a large body"

    # One byte flipped deep inside the padding must invalidate the signature: the whole body is
    # covered, not a prefix of it.
    TS_BIG=$(date +%s)
    { printf '%s\n%s\n%s\n' "POST" "$BIG_PATH" "$TS_BIG"; cat "$WORK_DIR/big_body.json"; } > "$WORK_DIR/canon_big.bin"
    SIG_BIG=$(openssl dgst -sha256 -hmac "$BIG_SECRET" -r "$WORK_DIR/canon_big.bin" | cut -d' ' -f1)
    # Rewrite one padding character in the middle of the file.
    python3 - "$WORK_DIR/big_body.json" "$WORK_DIR/big_body_tampered.json" <<'PYEOF' 2>/dev/null || cp "$WORK_DIR/big_body.json" "$WORK_DIR/big_body_tampered.json"
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
mid = len(data) // 2
data[mid] = ord('y') if data[mid] != ord('y') else ord('z')
open(sys.argv[2], 'wb').write(data)
PYEOF
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "$BIG_AUTH" -H "Content-Type: application/json" \
        -H "X-Timestamp: $TS_BIG" -H "X-Signature-256: sha256=$SIG_BIG" \
        --data-binary "@$WORK_DIR/big_body_tampered.json" "$BASE_URL$BIG_PATH")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "one altered byte in the middle of a large body invalidates the signature"

    # Just under the 3 MiB verification buffer: still accepted. 3 MiB is the converged limit
    # shared with simply_ip_vault, and it governs both the router's DefaultBodyLimit and the
    # middleware's signature buffer from a single constant.
    head -c 3100000 /dev/zero | tr '\0' 'z' > "$WORK_DIR/pad_near.txt"
    jq -nc --rawfile p "$WORK_DIR/pad_near.txt" '{parameters:{marker:"near"},padding:$p}' > "$WORK_DIR/near_body.json"
    signed_file_call POST "$BIG_PATH" "$WORK_DIR/near_body.json" "$BIG_SECRET" "$BIG_AUTH"
    check "200" "a payload just under the 3 MiB buffer limit is accepted"

    # Over the bound: refused with an explanatory error rather than a hang or an OOM.
    head -c 6291456 /dev/zero | tr '\0' 'w' > "$WORK_DIR/pad_over.txt"
    jq -nc --rawfile p "$WORK_DIR/pad_over.txt" '{parameters:{marker:"over"},padding:$p}' > "$WORK_DIR/over_body.json"
    signed_file_call POST "$BIG_PATH" "$WORK_DIR/over_body.json" "$BIG_SECRET" "$BIG_AUTH"
    check "400" "a payload over the buffer limit is refused"
    check_true '.error | contains("too large")' "the refusal explains why"

    # A large parameter value survives the trip into the child's environment. Held to 64 KiB:
    # argv and environment share ARG_MAX, and each parameter is passed both ways.
    head -c 65536 /dev/zero | tr '\0' 'b' > "$WORK_DIR/blob.txt"
    jq -nc --rawfile b "$WORK_DIR/blob.txt" '{parameters:{marker:"blob",blob:($b | rtrimstr("\n"))}}' > "$WORK_DIR/blob_body.json"
    signed_file_call POST "$BIG_PATH" "$WORK_DIR/blob_body.json" "$BIG_SECRET" "$BIG_AUTH"
    check "200" "a 64 KiB parameter value is accepted"
    check_true '.stdout | contains("blob_len=65536")' "the full parameter reached the process environment intact"

    api_call GET "/api/executions?hook=big_payload&limit=20" "$MASTER_KEY"
    check "200" "query the large-payload hook's history"
    check_jq "length" "3" "only the accepted payloads produced execution records"
else
    warn "Skipping §25: openssl is not available to sign large payloads."
fi

# ── 26. Stored XSS payloads ─────────────────────────────────────────────────

log_section "26. Stored XSS Payloads (hook output & metadata)"

# The canonical probe: valid HTML, no quoting tricks, fires with no user interaction.
XSS_PAYLOAD='<img src=x onerror=alert(1)>'
# Breaks out of an attribute and a tag first, catching a renderer that interpolates into an
# attribute rather than into element content.
XSS_BREAKOUT='"><script>alert(document.domain)</script>'

XSS_SCRIPT=$(make_hook_script "xss_hook.sh" 'printf "%s" "$1"
printf "%s" "$2" >&2')
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$XSS_SCRIPT" '{name:"xss_hook",script_path:$p,parameters:[{param_key:"p1_out",is_required:true},{param_key:"p2_err",is_required:true}]}')"
check "200" "create a hook that echoes attacker-chosen bytes to both streams"
XSS_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks/$XSS_HOOK_ID/execute" "$MASTER_KEY" \
    "$(jq -nc --arg o "$XSS_PAYLOAD" --arg e "$XSS_BREAKOUT" '{parameters:{p1_out:$o,p2_err:$e}}')"
check "200" "execute the hook with a live-markup payload"
# Verbatim storage is the point: if the server stripped tags, the UI's escaping would be untested
# in production and the first payload that evaded the stripper would land in an unprotected sink.
check_jq ".stdout" "$XSS_PAYLOAD" "the stdout payload is stored and returned byte-for-byte"
check_jq ".stderr" "$XSS_BREAKOUT" "the stderr payload is stored and returned byte-for-byte"
XSS_EXEC_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/executions/$XSS_EXEC_ID" "$MASTER_KEY"
check "200" "re-read the stored execution"
check_jq ".stdout" "$XSS_PAYLOAD" "the payload survives persistence unchanged"

# A JSON document containing <script> is inert only while the browser is told it is JSON. If any
# of these ever answered text/html, opening the API URL directly would render the payload.
XSS_CT=$(curl -s -o /dev/null -w '%{content_type}' -H "X-API-Key: $MASTER_KEY" \
    "$BASE_URL/api/executions/$XSS_EXEC_ID")
check_local "$XSS_CT" "application/json" "the execution endpoint is served as application/json"

# Hook metadata is rendered into the hooks table and the audit log, so it is a sink too.
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$XSS_SCRIPT" --arg n "hook$XSS_PAYLOAD" --arg d "$XSS_BREAKOUT" '{name:$n,script_path:$p,description:$d}')"
check "200" "create a hook whose name and description contain live markup"
check_jq ".name" "hook$XSS_PAYLOAD" "the hook name round-trips verbatim"
check_jq ".description" "$XSS_BREAKOUT" "the hook description round-trips verbatim"

api_call GET "/api/audit-logs?action=HOOK_CREATE" "$MASTER_KEY"
check "200" "read the audit trail"
check_true '[.[] | select(.details | contains("onerror=alert(1)"))] | length > 0' \
    "the markup reaches the audit details verbatim rather than being interpreted"

# The renderer is the layer that must neutralize all of the above. There is no JS runtime or
# headless browser here (AGENT.MD forbids frontend dependencies), so the assertion is on the
# source invariant: captured output must never reach an innerHTML sink.
SPA_JS="$PROJECT_ROOT/static/app.js"
if grep -qF 'pre.textContent = content;' "$SPA_JS"; then
    check_local "textContent" "textContent" "the SPA writes captured stream content with textContent"
else
    check_local "missing" "textContent" "the SPA writes captured stream content with textContent"
fi
if grep -qF 'message.textContent = errorText;' "$SPA_JS"; then
    check_local "textContent" "textContent" "the SPA writes server error text with textContent"
else
    check_local "missing" "textContent" "the SPA writes server error text with textContent"
fi
# No innerHTML assignment may mention a field carrying attacker-controlled content.
TAINTED_HITS=$(grep -n 'innerHTML' "$SPA_JS" | grep -E 'stdout|stderr|blocking_reason|argList|envRows' || true)
if [ -z "$TAINTED_HITS" ]; then
    check_local "none" "none" "no captured-output field reaches innerHTML"
else
    err "innerHTML sinks receiving tainted data:"; echo "$TAINTED_HITS" >&2
    check_local "found" "none" "no captured-output field reaches innerHTML"
fi

# ── 27. Argument injection / hostile CLI flags ──────────────────────────────

log_section "27. Argument Injection (CLI-flag-shaped payloads)"

ARGV_CANARY="$WORK_DIR/argv_canary"
# Echoes each positional argument inside delimiters, then the matching environment injection.
# "$@" preserves argument boundaries, so a value containing spaces or newlines stays one entry.
ARGV_SCRIPT=$(make_hook_script "argv_hook.sh" 'i=0
for a in "$@"; do i=$((i+1)); printf "argv[%s]=<%s>\n" "$i" "$a"; done
printf "env_flag=<%s>\n" "$HOOK_PARAM_P1_FLAG"
printf "env_target=<%s>\n" "$HOOK_PARAM_P2_TARGET"')
# Parameter keys are numbered because positional order is `created_at` with `param_key` as the
# tie-break: naming them so that alphabetical order already matches declaration order makes the
# argv positions deterministic even if two rows land in the same timestamp tick.
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$ARGV_SCRIPT" '{name:"argv_hook",script_path:$p,parameters:[{param_key:"p1_flag",is_required:true},{param_key:"p2_target",is_required:true}]}')"
check "200" "create a hook that reports its argument vector"
ARGV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# Each pair is dangerous to a different consumer: getopt, rm, sudo, a shell.
run_argv_case() {
    local flag="$1" target="$2"
    api_call POST "/api/hooks/$ARGV_HOOK_ID/execute" "$MASTER_KEY" \
        "$(jq -nc --arg f "$flag" --arg t "$target" '{parameters:{p1_flag:$f,p2_target:$t}}')"
    check "200" "hostile payload [$flag] executes inertly"
    check_jq ".status" "SUCCESS" "the process ran and exited cleanly for [$flag]"
    check_stdout_contains "argv[1]=<$flag>" "[$flag] reached argv[1] verbatim"
    check_stdout_contains "argv[2]=<$target>" "[$target] reached argv[2] verbatim"
    check_stdout_contains "env_flag=<$flag>" "[$flag] reached HOOK_PARAM_P1_FLAG verbatim"
    check_stdout_contains "env_target=<$target>" "[$target] reached HOOK_PARAM_P2_TARGET verbatim"
    check_true '.stdout | contains("argv[3]=") | not' "no third argument was synthesized for [$flag]"
}

run_argv_case '--help' '--version'
run_argv_case '-rf' '/'
run_argv_case '--' '--login'
run_argv_case '; rm -rf /' "; touch $ARGV_CANARY"
run_argv_case '$(id)' '`id`'
run_argv_case '-u root' '--user=root'

if [ -e "$ARGV_CANARY" ]; then
    check_local "canary created" "canary absent" "no payload was interpreted as a command"
else
    check_local "canary absent" "canary absent" "no payload was interpreted as a command"
fi

# The sudo boundary: hostile values must land after `--`, where sudo can only treat them as
# arguments to the script. Checked via the dry run, so no sudoers entry is needed.
SUDO_ARGV_SCRIPT=$(make_hook_script "sudo_argv.sh" 'echo ok')
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$SUDO_ARGV_SCRIPT" '{name:"sudo_argv_hook",script_path:$p,run_as_user:"root",parameters:[{param_key:"first",is_required:true}]}')"
check "200" "create a privileged hook taking one parameter"
SUDO_ARGV_ID=$(echo "$RESP_BODY" | jq -r '.id')

for ESCAPE in '-u' '-u root' '--user=root' '-i' '--login' '--preserve-env' '--'; do
    api_call POST "/api/hooks/$SUDO_ARGV_ID/test" "$MASTER_KEY" \
        "$(jq -nc --arg e "$ESCAPE" '{parameters:{first:$e}}')"
    check "200" "dry-run the privileged hook with [$ESCAPE]"
    check_jq ".command.program" "/usr/bin/sudo" "the program is the hard-coded sudo path for [$ESCAPE]"
    check_true '.command.args[0:4] == ["-n","-u","root","--"]' "the sudo prefix is intact for [$ESCAPE]"
    check_true '(.command.args | index("--")) < ((.command.args | length) - 1)' \
        "[$ESCAPE] sits after the -- separator"
    check_jq ".command.args[5]" "$ESCAPE" "[$ESCAPE] is passed through verbatim as script data"
    check_true '.command.args | length == 6' "no extra arguments were synthesized for [$ESCAPE]"
done

# An option-shaped run_as_user is unrepresentable, so the -u slot can never hold one.
for BAD_USER in '-i' '--login' '-u' 'root -i' 'root;id'; do
    api_call POST "/api/hooks" "$MASTER_KEY" \
        "$(jq -nc --arg p "$SUDO_ARGV_SCRIPT" --arg u "$BAD_USER" '{name:"bad_user_hook",script_path:$p,run_as_user:$u}')"
    check "400" "run_as_user [$BAD_USER] is refused at definition time"
done

# ── 28. Process escape (killpg boundary) ────────────────────────────────────

log_section "28. Process Escape Boundary (killpg vs setsid)"

GROUP_MARKER="$WORK_DIR/group_child_survived"
ESCAPED_MARKER="$WORK_DIR/setsid_child_survived"

if command -v setsid >/dev/null 2>&1; then
    # Two grandchildren, identical but for the process group they land in. Running both under one
    # execution makes the comparison airtight: same kill, same timing, same machine. Output is
    # redirected so neither holds the captured pipe open past the kill.
    #
    # Each grandchild sleeps 3s against the hook's 1s timeout. The margin is load-bearing: with a
    # 1s sleep the in-group child races the kill and can land its `touch` first, which reads as a
    # containment failure when it is really a test-timing artifact.
    ESCAPE_SCRIPT=$(make_hook_script "escape_hook.sh" "( sleep 3; touch $GROUP_MARKER ) >/dev/null 2>&1 &
setsid sh -c 'sleep 3; touch $ESCAPED_MARKER' >/dev/null 2>&1 &
sleep 30")
    api_call POST "/api/hooks" "$MASTER_KEY" \
        "$(jq -nc --arg p "$ESCAPE_SCRIPT" '{name:"escape_hook",script_path:$p,default_timeout_seconds:1}')"
    check "200" "create a hook that spawns one in-group and one setsid grandchild"
    ESCAPE_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/hooks/$ESCAPE_HOOK_ID/execute" "$MASTER_KEY" '{}'
    check "200" "the request returns once the timeout fires"
    check_jq ".status" "TIMEOUT" "the execution is recorded as TIMEOUT"
    check_jq ".exit_code" "137" "the SIGKILL is reported as 128+9"

    log "Waiting past both grandchildren's sleep to see which survived..."
    sleep 5

    if [ -e "$GROUP_MARKER" ]; then
        check_local "survived" "killed" "the same-process-group grandchild is killed by killpg"
    else
        check_local "killed" "killed" "the same-process-group grandchild is killed by killpg"
    fi

    # Asserted as an escape on purpose. killpg signals exactly one process group; a process that
    # called setsid has left it and is, by POSIX definition, no longer a member. Containing it
    # would need a cgroup or PID namespace the daemon does not create. See AGENT_NOTES.MD §28.
    if [ -e "$ESCAPED_MARKER" ]; then
        check_local "escaped" "escaped" "a setsid child escapes killpg (documented OS-level limit)"
    else
        check_local "contained" "escaped" "a setsid child escapes killpg (documented OS-level limit)"
        warn "setsid no longer escapes the kill group — containment improved; update AGENT_NOTES.MD §28."
    fi
else
    warn "Skipping §28 setsid checks: setsid(1) is not available."
fi

# ── 29. Request body size limit ─────────────────────────────────────────────

log_section "29. Request Body Size Limit (413)"

# 10 MiB, an order of magnitude past the 1 MiB ceiling. Written to a file and streamed so this
# script never puts it on a command line (ARG_MAX), which is the bug §25 already learned the hard way.
head -c 10485760 /dev/zero | tr '\0' 'a' > "$WORK_DIR/oversized.bin"
OVERSIZED_LEN=$(wc -c < "$WORK_DIR/oversized.bin" | tr -d ' ')
check_local "$OVERSIZED_LEN" "10485760" "the oversized fixture really is 10 MiB"

oversized_call() {
    local method="$1" path="$2" key="${3:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" -H "Content-Type: application/json")
    [ -n "$key" ] && args+=(-H "X-API-Key: $key")
    args+=(--data-binary "@$WORK_DIR/oversized.bin")
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s (10 MiB body)\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
}

# Bytes-extractor routes.
oversized_call POST "/api/hooks/$ARGV_HOOK_ID/execute" "$MASTER_KEY"
check "413" "a 10 MiB body is refused on the execute route"
oversized_call POST "/webhook/argv_hook" "$MASTER_KEY"
check "413" "a 10 MiB body is refused on the webhook route"
# Json<T>-extractor routes reject through a different code path, so both shapes are covered.
oversized_call POST "/api/hooks" "$MASTER_KEY"
check "413" "a 10 MiB body is refused on the hook creation route"
oversized_call POST "/api/keys" "$MASTER_KEY"
check "413" "a 10 MiB body is refused on the key creation route"

# Unauthenticated: the key check runs first, so the body is never buffered at all.
oversized_call POST "/api/hooks" ""
check "401" "an unauthenticated 10 MiB body is refused before it is read"
oversized_call POST "/api/hooks" "not-a-real-key"
check "401" "an unknown-key 10 MiB body is refused before it is read"

# The limit is a ceiling, not a blanket refusal: normal traffic still works afterwards.
api_call POST "/api/hooks/$ARGV_HOOK_ID/execute" "$MASTER_KEY" '{"parameters":{"p1_flag":"ok","p2_target":"fine"}}'
check "200" "an ordinary request still succeeds after the oversized ones"

# ── 30. Security regressions: the five privilege-escalation findings ────────

log_section "30. Security Regressions (PrivEsc findings #1-#5)"

# A non-master key holding only can_manage_keys — the credential findings #1-#3 started from.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Key Manager","can_manage_keys":true}'
check "200" "create a non-master key holding can_manage_keys"
KEYMGR_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
KEYMGR_ID=$(echo "$RESP_BODY" | jq -r '.id')

# ── Finding #1: minting a master key ───────────────────────────────────────
api_call POST "/api/keys" "$KEYMGR_KEY" '{"name":"escalated","is_master":true}'
check "403" "#1 a non-master cannot mint a master key"
check_true '.error | contains("is_master")' "the refusal names the offending scope"

api_call POST "/api/keys" "$KEYMGR_KEY" '{"name":"escalated","can_manage_keys":true}'
check "403" "#1 a non-master cannot grant can_manage_keys"
api_call POST "/api/keys" "$KEYMGR_KEY" '{"name":"escalated","can_manage_hooks":true}'
check "403" "#1 a non-master cannot grant can_manage_hooks"

# The scope it does hold still works for ordinary keys.
api_call POST "/api/keys" "$KEYMGR_KEY" '{"name":"Ordinary Sub-Key"}'
check "200" "#1 a scope-free key is still creatable by a key manager"
ORDINARY_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call PUT "/api/keys/$ORDINARY_ID" "$KEYMGR_KEY" '{"can_manage_hooks":true}'
check "403" "#1 a non-master cannot grant a global scope by update either"
api_call PUT "/api/keys/$ORDINARY_ID" "$KEYMGR_KEY" '{"can_manage_hooks":false}'
check "200" "#1 revoking a scope is not an escalation and stays allowed"

# ── Finding #2: taking over an existing master key ─────────────────────────
api_call GET "/api/keys" "$MASTER_KEY"
check "200" "list keys to locate the bootstrap master"
BOOTSTRAP_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.is_master == true) | .id' | head -1)

api_call POST "/api/keys/$BOOTSTRAP_ID/rotate" "$KEYMGR_KEY"
check "403" "#2 a non-master cannot rotate a master key"
check_true '.plaintext_key == null' "no secret leaks in the refusal body"
api_call PUT "/api/keys/$BOOTSTRAP_ID" "$KEYMGR_KEY" '{"bound_ips":"0.0.0.0/0"}'
check "403" "#2 a non-master cannot edit a master key"
api_call DELETE "/api/keys/$BOOTSTRAP_ID" "$KEYMGR_KEY"
check "403" "#2 a non-master cannot delete a master key"

# The master credential is untouched by any of the refused calls.
api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "#2 the master key still authenticates"
check_jq ".is_master" "true" "#2 the master key is still master"

# ── Finding #3: self-granting hook permissions ─────────────────────────────
PRIV_SCRIPT=$(make_hook_script "privesc_hook.sh" 'echo running')
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$PRIV_SCRIPT" '{name:"privesc_root_hook",script_path:$p,run_as_user:"root"}')"
check "200" "create a root-running hook as master"
PRIVESC_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$PRIV_SCRIPT" '{name:"privesc_plain_hook",script_path:$p}')"
check "200" "create an ordinary hook as master"
PLAIN_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys/$KEYMGR_ID/permissions" "$KEYMGR_KEY" \
    "$(jq -nc --arg h "$PRIVESC_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:true}')"
check "403" "#3 a non-master cannot self-grant rights on a root hook"

api_call POST "/api/keys/$KEYMGR_ID/permissions" "$KEYMGR_KEY" \
    "$(jq -nc --arg h "$PLAIN_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:false}')"
check "403" "#3 self-granting is refused for an ordinary hook too"

api_call POST "/api/keys/$ORDINARY_ID/permissions" "$KEYMGR_KEY" \
    "$(jq -nc --arg h "$PLAIN_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:false}')"
check "403" "#3 granting on a hook the caller does not manage is refused"

# The grant never landed, so the root hook is still out of reach.
api_call POST "/api/hooks/$PRIVESC_HOOK_ID/test" "$KEYMGR_KEY" '{}'
check "403" "#3 the root hook remains unreachable to the key manager"

# ── Finding #4: repointing an elevated hook ────────────────────────────────
create_scoped_key "Hook Editor"
EDITOR_KEY="$CREATED_KEY"; EDITOR_ID="$CREATED_ID"
api_call POST "/api/keys/$EDITOR_ID/permissions" "$MASTER_KEY" \
    "$(jq -nc --arg h "$PRIVESC_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:true}')"
check "200" "grant the editor full rights on the root hook (as master)"

ATTACKER_SCRIPT=$(make_hook_script "attacker_hook.sh" 'echo pwned')
api_call PUT "/api/hooks/$PRIVESC_HOOK_ID" "$EDITOR_KEY" \
    "$(jq -nc --arg p "$ATTACKER_SCRIPT" '{script_path:$p}')"
check "403" "#4 a non-master cannot repoint a root hook's script_path"
check_true '.error | contains("root")' "the refusal names the account the hook runs as"

api_call PUT "/api/hooks/$PRIVESC_HOOK_ID" "$EDITOR_KEY" '{"description":"harmless"}'
check "403" "#4 every field of a privileged hook is gated, not just script_path"
api_call PUT "/api/hooks/$PRIVESC_HOOK_ID" "$EDITOR_KEY" '{"default_timeout_seconds":600}'
check "403" "#4 the timeout is gated too"
api_call PUT "/api/hooks/$PRIVESC_HOOK_ID" "$EDITOR_KEY" '{"run_as_user":""}'
check "403" "#4 clearing the elevation is master-only as well"

# Parameters are argv for the elevated command, so those routes are gated too.
api_call POST "/api/hooks/$PRIVESC_HOOK_ID/parameters" "$EDITOR_KEY" '{"param_key":"injected","default_value":"-c"}'
check "403" "#4 declaring a parameter on a root hook is refused"

# The hook is unchanged.
api_call GET "/api/hooks/$PRIVESC_HOOK_ID" "$MASTER_KEY"
check "200" "#4 re-read the root hook"
check_jq ".script_path" "$PRIV_SCRIPT" "#4 the script path was not repointed"
check_jq ".run_as_user" "root" "#4 the elevation is intact"

# An unprivileged hook is still freely manageable: the guard is scoped to elevation.
api_call POST "/api/keys/$EDITOR_ID/permissions" "$MASTER_KEY" \
    "$(jq -nc --arg h "$PLAIN_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:true}')"
check "200" "grant the editor rights on the ordinary hook"
api_call PUT "/api/hooks/$PLAIN_HOOK_ID" "$EDITOR_KEY" \
    "$(jq -nc --arg p "$ATTACKER_SCRIPT" '{script_path:$p}')"
check "200" "#4 an ordinary hook is still editable by a can_manage holder"

# ── Finding #5: X-Forwarded-For spoofing, on a daemon with no trusted proxies ──
STRICT_PORT=$((SERVER_PORT + 1))
while port_in_use "$STRICT_PORT"; do STRICT_PORT=$((STRICT_PORT + 1)); done
STRICT_DB="$WORK_DIR/strict.db"
STRICT_LOG="$WORK_DIR/strict_server.log"
STRICT_BASE_URL="http://$BIND_HOST:$STRICT_PORT"
STRICT_MASTER="e2e_strict_master_key_for_testing_987654321"

log "Booting a second instance on port $STRICT_PORT with TRUSTED_PROXIES unset..."
DATABASE_URL="sqlite://$STRICT_DB?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$STRICT_MASTER" \
    ALLOWED_ENV_VARS="PATH" ALLOWED_SCRIPT_ROOTS="$HOOK_DIR" \
    BIND_HOST="$BIND_HOST" PORT="$STRICT_PORT" \
    "$PROJECT_ROOT/target/debug/simply_hook_executor" >"$STRICT_LOG" 2>&1 &
STRICT_SERVER_PID=$!

STRICT_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$STRICT_SERVER_PID" 2>/dev/null; then
        err "Strict-proxy server exited during startup. Log:"; cat "$STRICT_LOG" >&2; break
    fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "$STRICT_BASE_URL/api/hooks" 2>/dev/null)
    case "$SC" in 200|401|404) STRICT_READY=1; break ;; esac
    sleep 0.5
done

if [ "$STRICT_READY" != "1" ]; then
    err "Strict-proxy server never became ready; skipping §30 finding #5 checks."
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    check_local "ready" "ready" "#5 the no-trusted-proxy instance is up"

    # Requests to this instance go to a different base URL, so they bypass api_call's $BASE_URL.
    strict_call() {
        local method="$1" path="$2" key="$3" xff="${4:-}" hdr="${5:-}"
        local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" -H "X-API-Key: $key")
        [ -n "$xff" ] && args+=(-H "${hdr:-X-Forwarded-For}: $xff")
        RESP_STATUS=$(curl "${args[@]}" "$STRICT_BASE_URL$path")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        local color; color=$(status_color "$RESP_STATUS")
        printf "%s ${color}[%s]${RESET} %-6s %s%s\n" "$(ts)" "$RESP_STATUS" "$method" \
            "$STRICT_BASE_URL$path" "${xff:+ (${hdr:-X-Forwarded-For}: $xff)}" >&2
        print_response_body
    }

    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $STRICT_MASTER" -H "Content-Type: application/json" \
        -d '{"name":"LAN Only","bound_ips":"10.0.0.0/8"}' "$STRICT_BASE_URL/api/keys")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "#5 create a key bound to 10.0.0.0/8 on the strict instance"
    LAN_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

    # The real peer is 127.0.0.1, outside 10.0.0.0/8.
    strict_call GET "/api/auth/me" "$LAN_KEY"
    check "403" "#5 an honest request from outside the bound range is rejected"

    # Every spoofing shape is inert: the header is never consulted from an untrusted peer.
    strict_call GET "/api/auth/me" "$LAN_KEY" "10.1.2.3"
    check "403" "#5 a forged X-Forwarded-For cannot satisfy the CIDR allowlist"
    strict_call GET "/api/auth/me" "$LAN_KEY" "203.0.113.9, 10.1.2.3"
    check "403" "#5 a forged multi-hop X-Forwarded-For is refused"
    strict_call GET "/api/auth/me" "$LAN_KEY" "::ffff:10.1.2.3"
    check "403" "#5 an IPv4-mapped forged hop is refused"
    strict_call GET "/api/auth/me" "$LAN_KEY" "10.1.2.3" "X-Real-IP"
    check "403" "#5 a forged X-Real-IP is refused"

    # The audit trail records the real peer, never the claim.
    strict_call GET "/api/audit-logs" "$STRICT_MASTER" "203.0.113.77"
    check "200" "#5 read the strict instance's audit trail"
    check_true '[.[] | select(.client_ip == "203.0.113.77")] | length == 0' \
        "#5 a forged address is never recorded as client_ip"
    check_true '[.[] | select(.client_ip == "127.0.0.1")] | length > 0' \
        "#5 the real TCP peer is what gets recorded"

    # A key bound to the real peer works, proving the check is evaluated rather than always denying.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-API-Key: $STRICT_MASTER" -H "Content-Type: application/json" \
        -d "{\"name\":\"Loopback Only\",\"bound_ips\":\"$BIND_HOST/32\"}" "$STRICT_BASE_URL/api/keys")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "#5 create a key bound to the real peer address"
    LOOPBACK_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    strict_call GET "/api/auth/me" "$LOOPBACK_KEY"
    check "200" "#5 a key bound to the true peer is accepted"

    log "Stopping the strict-proxy instance..."
    kill "$STRICT_SERVER_PID" 2>/dev/null || true
    wait "$STRICT_SERVER_PID" 2>/dev/null || true
    STRICT_SERVER_PID=""
fi

# The main instance is booted with TRUSTED_PROXIES set to a *hostname* alias of the bind address
# (see Boot), which is the Docker/Traefik shape: the proxy is named, not addressed, because the
# orchestrator assigns its IP. Everything §15 asserted about CIDR entries must hold identically when
# the entry had to be resolved first.
api_call GET "/api/settings" "$MASTER_KEY"
check "200" "read the resolved proxy configuration"
check_true '.trusted_proxies | length == 2' "both the literal and the hostname entry are reported"
check_true '.trusted_proxies | any(. == "localhost")' "the hostname is kept as written, not flattened to an IP"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Hostname Proxy Key","bound_ips":"198.51.100.0/24"}'
check "200" "create a key bound to a range the loopback peer is outside of"
HOSTPROXY_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$HOSTPROXY_KEY"
check "403" "without a forwarding header the real peer is used, and it is out of range"
api_call GET "/api/auth/me" "$HOSTPROXY_KEY" "" "198.51.100.7"
check "200" "a header from the name-resolved proxy is believed"

# Chain peeling: with client → P1 → us, the rightmost entry is P1, a trusted proxy. Reporting it as
# the client would break bound_ips for every caller behind a second hop.
api_call GET "/api/auth/me" "$HOSTPROXY_KEY" "" "198.51.100.7, 127.0.0.1"
check "200" "a trusted hop is peeled to reach the real client behind it"
api_call GET "/api/auth/me" "$HOSTPROXY_KEY" "" "198.51.100.7, 203.0.113.9"
check "403" "the rightmost non-proxy hop wins, so an untrusted last hop is the client"

# bound_ips now applies to master keys too — previously is_master skipped the check entirely.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Bound Master","is_master":true,"bound_ips":"10.10.10.0/24"}'
check "200" "create a master key bound to a range that excludes the caller"
BOUND_MASTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
api_call GET "/api/auth/me" "$BOUND_MASTER_KEY"
check "403" "a master key is held to its own bound_ips rather than bypassing them"
# ...and honouring the trusted proxy's header brings it back inside the range.
api_call GET "/api/auth/me" "$BOUND_MASTER_KEY" "" "10.10.10.5"
check "200" "the same master key is accepted from inside its bound range"

# ── 31. Convergence: anti-replay, full-URI signing, auth-before-authz ───────

log_section "31. Convergence (anti-replay, full-URI coverage, pipeline ordering)"

if [ "$HAVE_OPENSSL" -eq 1 ]; then
    CONV_SCRIPT=$(make_hook_script "convergence.sh" 'echo "ran=${HOOK_PARAM_TARGET}"')
    api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"convergence_hook\",\"script_path\":\"$CONV_SCRIPT\",\"parameters\":[{\"param_key\":\"target\",\"default_value\":\"none\",\"is_required\":true}]}"
    check "200" "create a hook for the convergence checks"
    CONV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
    CONV_PATH="/api/hooks/$CONV_HOOK_ID/execute"
    CONV_BODY='{"parameters":{"target":"conv"}}'

    # --- Anti-replay: a captured signature is single-use ---
    # The timestamp is pinned so both requests are byte-identical. Re-reading the clock would
    # produce a different signature, which is a different request rather than a replay.
    CONV_TS=$(date +%s)
    CONV_SIG=$(sign_canonical "$MASTER_SIGNING_SECRET" "POST" "$CONV_PATH" "$CONV_TS" "$CONV_BODY")
    replay_call() {
        RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
            -H "X-API-Key: $SIGNING_MASTER_KEY" -H "Content-Type: application/json" \
            -H "X-Timestamp: $CONV_TS" -H "X-Signature-256: sha256=$CONV_SIG" \
            -d "$CONV_BODY" "$BASE_URL$CONV_PATH")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
        local color; color=$(status_color "$RESP_STATUS")
        printf "%s ${color}[%s]${RESET} %-6s %s ${DIM}(replay probe)${RESET}\n" \
            "$(ts)" "$RESP_STATUS" "POST" "$BASE_URL$CONV_PATH" >&2
        print_response_body
    }

    replay_call
    check "200" "the original signed request is accepted"
    check_jq ".status" "SUCCESS" "the original request executed"

    replay_call
    check "401" "an intercepted signature replayed inside the window is rejected"
    check_true '.error | contains("already been used")' "the refusal names signature reuse"

    replay_call
    check "401" "the replay stays rejected on later attempts rather than sliding through"

    # A freshly signed request from the same key still works: reuse is refused, not the key.
    SIGN_SECRET="$MASTER_SIGNING_SECRET"
    SIGN_AUTH="X-API-Key: $SIGNING_MASTER_KEY"
    SIGN_TS=$((CONV_TS - 30))
    signed_call POST "$CONV_PATH" "$CONV_BODY"
    check "200" "a distinct signature from the same key is not a replay"
    SIGN_TS=""

    # --- Full-URI coverage: the query string is inside the signed material ---
    # A signature over the bare path must not authorize the same path with ?hard=true appended,
    # which is what stops a captured soft delete from becoming permanent destruction.
    api_call POST "/api/hooks" "$MASTER_KEY" "{\"name\":\"query_target_hook\",\"script_path\":\"$CONV_SCRIPT\"}"
    check "200" "create a hook to aim the query-tampering probe at"
    QT_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
    QT_PATH="/api/hooks/$QT_HOOK_ID"

    QT_TS=$(date +%s)
    QT_SIG=$(sign_canonical "$MASTER_SIGNING_SECRET" "DELETE" "$QT_PATH" "$QT_TS" "")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X DELETE \
        -H "X-API-Key: $SIGNING_MASTER_KEY" \
        -H "X-Timestamp: $QT_TS" -H "X-Signature-256: sha256=$QT_SIG" \
        "$BASE_URL$QT_PATH?hard=true")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "appending ?hard=true to a signed path invalidates the signature"

    api_call GET "$QT_PATH" "$MASTER_KEY"
    check "200" "the hook survived: the escalated request was never authorized"

    # Stripping a signed query parameter is equally a rewrite.
    QT_TS=$(date +%s)
    QT_SIG=$(sign_canonical "$MASTER_SIGNING_SECRET" "GET" "/api/hooks?include_deleted=true" "$QT_TS" "")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X GET \
        -H "X-API-Key: $SIGNING_MASTER_KEY" \
        -H "X-Timestamp: $QT_TS" -H "X-Signature-256: sha256=$QT_SIG" \
        "$BASE_URL/api/hooks")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "dropping a signed query parameter also invalidates the signature"

    # --- Auth before authz: no 401-vs-403 oracle for an unauthenticated caller ---
    # A key bound to a network this client is not in. With a *bad* signature the response must be
    # 401 — identical to an in-range key with a bad signature — so nothing about the key's network
    # binding leaks to a caller that cannot authenticate.
    api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Oracle Probe","bound_ips":"10.99.0.0/16"}'
    check "200" "create a key bound to a network excluding the caller"
    ORACLE_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

    ORACLE_TS=$(date +%s)
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X GET \
        -H "X-API-Key: $ORACLE_KEY" \
        -H "X-Timestamp: $ORACLE_TS" \
        -H "X-Signature-256: sha256=$(printf '11%.0s' $(seq 1 32))" \
        "$BASE_URL/api/auth/me")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "an out-of-network key with a bad signature answers 401, not 403"

    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X GET \
        -H "X-API-Key: $SIGNING_MASTER_KEY" \
        -H "X-Timestamp: $ORACLE_TS" \
        -H "X-Signature-256: sha256=$(printf '11%.0s' $(seq 1 32))" \
        "$BASE_URL/api/auth/me")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "an in-network key with a bad signature answers 401 too — the codes match"

    # Authorization still applies once authentication succeeds.
    api_call GET "/api/auth/me" "$ORACLE_KEY"
    check "403" "once authenticated, the CIDR restriction is enforced and reported honestly"
else
    warn "Skipping §31: openssl is not available to sign requests."
fi

# ── 32. Per-verb grant proportionality & pre-lookup timestamp validation ────

log_section "32. Grant proportionality and freshness-before-lookup"

# --- Per-verb proportionality on M:N hook permissions ---
# `can_manage` is authority to administer a hook's grants; it is not authority to invent a verb the
# caller was deliberately not given. Before this, a manage-only holder could route `can_execute` to
# itself through a second key it controls: mint, grant, authenticate as the new key, run.
PROP_SCRIPT=$(make_hook_script "proportional.sh" 'echo "prop ran"')
api_call POST "/api/hooks" "$MASTER_KEY" \
    "$(jq -nc --arg p "$PROP_SCRIPT" '{name:"proportional_hook",script_path:$p}')"
check "200" "create a hook for the proportionality checks"
PROP_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

create_scoped_key "Proportionality Delegator" ',"can_manage_keys":true'
DELEGATOR_KEY="$CREATED_KEY"; DELEGATOR_ID="$CREATED_ID"
create_scoped_key "Proportionality Accomplice"
ACCOMPLICE_KEY="$CREATED_KEY"; ACCOMPLICE_ID="$CREATED_ID"

# Manage without execute — the combination `SCHEMA.MD` models as two columns so it is expressible.
api_call POST "/api/keys/$DELEGATOR_ID/permissions" "$MASTER_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:false,can_manage:true}')"
check "200" "grant the delegator manage-without-execute (as master)"

api_call POST "/api/hooks/$PROP_HOOK_ID/execute" "$DELEGATOR_KEY" '{"parameters":{}}'
check "403" "the delegator genuinely cannot execute the hook itself"

api_call POST "/api/keys/$ACCOMPLICE_ID/permissions" "$DELEGATOR_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:false}')"
check "403" "granting can_execute without holding it is refused"
check_true '.error | contains("can_execute")' "the refusal names the over-granted verb"

# The refusal was real, not cosmetic: no row landed, so the accomplice still cannot run it.
api_call POST "/api/hooks/$PROP_HOOK_ID/execute" "$ACCOMPLICE_KEY" '{"parameters":{}}'
check "403" "the blocked grant never reached the database"

# Handing out a verb the caller does hold still works — this is proportionality, not a ban.
api_call POST "/api/keys/$ACCOMPLICE_ID/permissions" "$DELEGATOR_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:false,can_manage:true}')"
check "200" "delegating a verb the caller holds is still allowed"

# Revoking is never an escalation: `false` cannot exceed anything, even for the missing verb.
api_call POST "/api/keys/$ACCOMPLICE_ID/permissions" "$DELEGATOR_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:false,can_manage:false}')"
check "200" "revocation does not require holding the verb being cleared"

# Once the caller holds both verbs, the identical request it was refused now succeeds.
api_call POST "/api/keys/$DELEGATOR_ID/permissions" "$MASTER_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:true}')"
check "200" "master widens the delegator to both verbs"
api_call POST "/api/keys/$ACCOMPLICE_ID/permissions" "$DELEGATOR_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:true,can_manage:false}')"
check "200" "the same grant is legitimate once the caller holds the verb"
api_call POST "/api/hooks/$PROP_HOOK_ID/execute" "$ACCOMPLICE_KEY" '{"parameters":{}}'
check "200" "the delegated execute right actually works"

# The entry gate is unchanged: no grant at all is still refused, in the same words.
create_scoped_key "Proportionality Outsider" ',"can_manage_keys":true'
OUTSIDER_KEY="$CREATED_KEY"
api_call POST "/api/keys/$ACCOMPLICE_ID/permissions" "$OUTSIDER_KEY" \
    "$(jq -nc --arg h "$PROP_HOOK_ID" '{hook_id:$h,can_execute:false,can_manage:false}')"
check "403" "a caller with no grant on the hook cannot administer its permissions"
check_true '.error | contains("manage access")' "the entry gate's message is unchanged"

# --- Freshness is checked before the API key is looked up ---
# Both orderings answer 401, so the status proves nothing on its own. The *message* does: paired
# with an unknown key, only the freshness-first ordering can name the window — the other has
# already failed the key lookup and answers "Invalid API Key".
STALE_TS=$(( $(date +%s) - 3600 ))
RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X GET \
    -H "X-API-Key: a-key-that-was-never-issued" \
    -H "X-Timestamp: $STALE_TS" -H "X-Signature-256: sha256=00" \
    "$BASE_URL/api/hooks")
RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
check "401" "a stale timestamp on an unknown key is rejected"
check_true '.error | contains("window")' "the window rejected it, not the key lookup"
check_true '.error | contains("Invalid API Key") | not' "the key lookup was never reached"

for BAD_TS in "not-a-number" "1700000000.5"; do
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X GET \
        -H "X-API-Key: a-key-that-was-never-issued" \
        -H "X-Timestamp: $BAD_TS" -H "X-Signature-256: sha256=00" \
        "$BASE_URL/api/hooks")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a malformed X-Timestamp ('$BAD_TS') is rejected before the lookup"
    check_true '.error | contains("Invalid API Key") | not' \
        "('$BAD_TS') never reached the key lookup"
done

# The hoist is scoped to the shape that owns a window — `X-Timestamp` *and* `X-Signature-256`.
# An unsigned bearer request carries a stray timestamp through untouched, exactly as before.
api_call GET "/api/auth/me" "$MASTER_KEY" "" "" "X-Timestamp: 1"
check "200" "an unsigned request's stray timestamp is still ignored"

# ── 33. WebUI mandates full-HMAC (CANONICAL_V1) signing ─────────────────────

log_section "33. TRUSTED_PROXIES syntax is fatal, unresolvable names are not"

# The two failures look alike in a config file and are not alike at all — *typo versus timing*.
#
# A syntax error can only be fixed by a human editing configuration, and serving through it means
# the operator believes a proxy is trusted while it is not: every request arriving via that proxy is
# then authorized against the proxy's address instead of the client's, so `bound_ips` quietly stops
# meaning what it says. That is a security boundary configured one way and enforced another, and the
# daemon refuses to start.
#
# An unresolvable hostname is the opposite: `traefik` is well-formed, it just names a container that
# has not finished starting. It is already fail-closed, it corrects itself, and aborting would turn
# an ordinary startup race into a crash loop. The daemon serves.
#
# Asserted against the real binary rather than the parser, because "refuses to start" is a property
# of the process, not of a function — a unit test cannot tell whether `main` actually honours it.
ABORT_DB="$WORK_DIR/abort.db"
ABORT_LOG="$WORK_DIR/abort_server.log"
ABORT_PORT=$((SERVER_PORT + 2))
while port_in_use "$ABORT_PORT"; do ABORT_PORT=$((ABORT_PORT + 1)); done

DATABASE_URL="sqlite://$ABORT_DB?mode=rwc" RUST_LOG=info \
    BIND_HOST="$BIND_HOST" PORT="$ABORT_PORT" TRUSTED_PROXIES="10.0.0.0/8x, 127.0.0.1" \
    timeout 30 "$PROJECT_ROOT/target/debug/simply_hook_executor" >"$ABORT_LOG" 2>&1
ABORT_CODE=$?

check_local "$ABORT_CODE" "1" "a malformed TRUSTED_PROXIES entry aborts startup"

# The message is the operator's whole diagnostic, so its wording is pinned — including the offending
# entry, which is what makes a multi-entry list actionable.
if grep -qF "FATAL: TRUSTED_PROXIES entry '10.0.0.0/8x' is not a valid IP address, CIDR range, or hostname" "$ABORT_LOG"; then
    check_local "stated" "stated" "the abort names the offending entry and the expected spellings"
else
    check_local "missing" "stated" "the abort names the offending entry and the expected spellings"
fi
if grep -qF "Refusing to start with an ambiguous trust boundary." "$ABORT_LOG"; then
    check_local "stated" "stated" "the abort says why an ambiguous trust boundary is refused"
else
    check_local "missing" "stated" "the abort says why an ambiguous trust boundary is refused"
fi

# It aborts *before* touching the database, so a refused boot leaves nothing behind — no migrations
# applied, and no bootstrap master key minted and printed for a daemon that never came up.
if [ ! -f "$ABORT_DB" ]; then
    check_local "clean" "clean" "the refused boot created no database"
else
    check_local "dirty" "clean" "the refused boot created no database"
fi

# The valid entry alongside the bad one is not silently kept: one bad entry condemns the list,
# because a partially-applied trust boundary is precisely the ambiguity being refused.
if grep -qF "Forwarding headers are honoured only from" "$ABORT_LOG"; then
    check_local "applied" "refused" "a partial trust boundary is never applied"
else
    check_local "refused" "refused" "a partial trust boundary is never applied"
fi

# The other half of the split: a well-formed name that does not resolve must NOT abort. The main
# instance is already running with TRUSTED_PROXIES="$BIND_HOST,localhost"; this covers the case the
# grace period exists for.
UNRESOLVED_DB="$WORK_DIR/unresolved.db"
UNRESOLVED_LOG="$WORK_DIR/unresolved_server.log"
UNRESOLVED_PORT=$((ABORT_PORT + 1))
while port_in_use "$UNRESOLVED_PORT"; do UNRESOLVED_PORT=$((UNRESOLVED_PORT + 1)); done

DATABASE_URL="sqlite://$UNRESOLVED_DB?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="e2e_unresolved_master_key_for_testing_5555" \
    BIND_HOST="$BIND_HOST" PORT="$UNRESOLVED_PORT" \
    TRUSTED_PROXIES="no-such-proxy.invalid, 127.0.0.1" \
    "$PROJECT_ROOT/target/debug/simply_hook_executor" >"$UNRESOLVED_LOG" 2>&1 &
UNRESOLVED_PID=$!

UNRESOLVED_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$UNRESOLVED_PID" 2>/dev/null; then break; fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "http://$BIND_HOST:$UNRESOLVED_PORT/api/hooks" 2>/dev/null)
    case "$SC" in 200|401|404) UNRESOLVED_READY=1; break ;; esac
    sleep 0.5
done

check_local "$UNRESOLVED_READY" "1" "an unresolvable but well-formed hostname still serves traffic"

if [ "$UNRESOLVED_READY" = "1" ]; then
    # And it is fail-closed while unresolved: the name contributes nothing, so a forwarding header
    # from an untrusted peer is still ignored. Trust is withheld, not widened, by a DNS failure.
    if grep -qF "could not be resolved at startup" "$UNRESOLVED_LOG"; then
        check_local "reported" "reported" "the unresolved name is reported rather than fatal"
    else
        check_local "silent" "reported" "the unresolved name is reported rather than fatal"
    fi
fi

kill "$UNRESOLVED_PID" 2>/dev/null || true
wait "$UNRESOLVED_PID" 2>/dev/null || true

log_section "34. WebUI full-HMAC enforcement"

# Source invariants again, for the same reason section 26 uses them: there is no JS runtime and no
# headless browser here (`AGENT.MD` forbids frontend dependencies), so the dashboard's signing
# posture cannot be observed by driving it. What can be pinned is that the code has no other path.
SPA_JS="$PROJECT_ROOT/static/app.js"
SPA_HTML="$PROJECT_ROOT/static/index.html"

# One signing implementation, and it is Web Crypto.
if grep -qF 'crypto.subtle.sign(' "$SPA_JS"; then
    check_local "subtle" "subtle" "the SPA signs with crypto.subtle"
else
    check_local "missing" "subtle" "the SPA signs with crypto.subtle"
fi

# Each pattern below marks a *client-side* behaviour that was removed. Deliberately precise rather
# than a bare grep for "BODY_ONLY" or "hmacMode": both strings legitimately survive in the API-keys
# table badge and the key-provisioning dropdowns, which describe the mode of *other* keys — the ones
# an operator issues to webhook senders. What must not come back is this client choosing a signing
# mode for its own traffic, or skipping the signature altogether.
# The patterns are anchored with \b so they cannot collide with the surviving display code:
# `this.hmacModeBadge(...)` renders another key's mode in the API-keys table and must keep working.
#   this.hmacMode\b        — the signer's own mode state, which drove the removed BODY_ONLY branch
#   signatureHeaders       — the "sign if possible, otherwise don't" plumbing in apiFetch
#   X-Hub-Signature-256    — the GitHub-style header a browser must never send
#
# `PureCrypto` is deliberately NOT in this list. It was removed once and restored on purpose: it is
# the pure-JS HMAC used where `crypto.subtle` does not exist, which is every plain-HTTP LAN origin.
# Its presence is asserted positively below. What matters is that it is a *fallback* — the signature
# stays mandatory either way — not that it is absent.
for FORBIDDEN in 'this\.hmacMode\b' 'signatureHeaders' 'X-Hub-Signature-256'; do
    if grep -qE "$FORBIDDEN" "$SPA_JS"; then
        err "static/app.js still references '$FORBIDDEN'"
        check_local "found" "absent" "the SPA has no '$FORBIDDEN' path"
    else
        check_local "absent" "absent" "the SPA has no '$FORBIDDEN' path"
    fi
done

# ── The pure-JS fallback ─────────────────────────────────────────────────────
#
# `crypto.subtle` exists only in a secure context, so a dashboard reached over plain HTTP at a LAN
# address — the normal homelab deployment — cannot use Web Crypto at all. The fallback is what keeps
# the mandatory signature achievable there. These checks pin that it exists, that it is genuinely a
# *fallback* rather than the primary, and that it validates itself before signing anything.
if grep -qF 'const PureCrypto' "$SPA_JS"; then
    check_local "present" "present" "the SPA carries the pure-JS HMAC fallback"
else
    check_local "missing" "present" "the SPA carries the pure-JS HMAC fallback"
fi

# Web Crypto must still win where it exists: it is constant-time, the fallback is not.
if grep -qF 'SigningBackend.usesWebCrypto' "$SPA_JS"; then
    check_local "preferred" "preferred" "Web Crypto is preferred over the fallback"
else
    check_local "unconditional" "preferred" "Web Crypto is preferred over the fallback"
fi

# The fallback gates itself on a published vector before it is trusted with a real credential. This
# is the RFC 4231 case 2 digest; if the implementation is ever broken, the login screen refuses
# rather than the browser emitting signatures the server silently rejects.
if grep -qF '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843' "$SPA_JS"; then
    check_local "vector" "vector" "the fallback self-tests against the RFC 4231 vector"
else
    check_local "missing" "vector" "the fallback self-tests against the RFC 4231 vector"
fi
if grep -qF 'PureCrypto.selfTest()' "$SPA_JS"; then
    check_local "gated" "gated" "the fallback is only used after its self-test passes"
else
    check_local "ungated" "gated" "the fallback is only used after its self-test passes"
fi

# Both signing paths render the digest through one hex encoder, so the branch decides only how the
# MAC is computed and never how it is spelled. Two encoders is how the two paths drift apart — one
# uppercase, one padded differently — while both remain "correct" in isolation.
#
# Matched with the opening paren so the prose reference in the doc comment above the function is not
# counted as a call site.
if [ "$(grep -cF 'PureCrypto.toHex(' "$SPA_JS")" -eq 2 ]; then
    check_local "shared" "shared" "both signing paths call the same hex encoder"
else
    check_local "split" "shared" "both signing paths call the same hex encoder"
fi

# ...and there is only one hex encoder to call: the byte-to-hex idiom appears exactly once, inside
# `PureCrypto.toHex` itself. A second inline copy is how a "small cleanup" reintroduces the split.
if [ "$(grep -cF "toString(16).padStart(2, '0')" "$SPA_JS")" -eq 1 ]; then
    check_local "single" "single" "the SPA defines exactly one hex encoder"
else
    check_local "duplicated" "single" "the SPA defines exactly one hex encoder"
fi

# The fallback must not have reintroduced an unsigned path: signing stays mandatory, and the login
# screen still refuses when *neither* implementation is usable.
if grep -qF 'SigningBackend.available' "$SPA_JS"; then
    check_local "gated" "gated" "login still refuses when no signing backend is usable"
else
    check_local "ungated" "gated" "login still refuses when no signing backend is usable"
fi

# The signer takes a secret and nothing else — a second constructor argument was the mode.
if grep -qE 'new RequestSigner\([^)]*,' "$SPA_JS"; then
    check_local "mode arg" "secret only" "RequestSigner takes only a signing secret"
else
    check_local "secret only" "secret only" "RequestSigner takes only a signing secret"
fi

# The API key header must be unconditional — the old form was `...(this.apiKey ? {...} : {})`.
if grep -qE "\.\.\.\(this\.apiKey \?" "$SPA_JS"; then
    check_local "conditional" "unconditional" "the SPA always sends X-API-Key"
else
    check_local "unconditional" "unconditional" "the SPA always sends X-API-Key"
fi

# All three CANONICAL_V1 headers are produced.
for HEADER in "X-API-Key" "X-Timestamp" "X-Signature-256"; do
    if grep -qF "'$HEADER'" "$SPA_JS"; then
        check_local "present" "present" "the SPA sends $HEADER"
    else
        check_local "missing" "present" "the SPA sends $HEADER"
    fi
done

# The canonical string is METHOD \n PATH_AND_QUERY \n TIMESTAMP \n BODY, matching signature_base().
if grep -qF '${method.toUpperCase()}\n${pathAndQuery}\n${timestamp}\n${body ?? '"''"'}' "$SPA_JS"; then
    check_local "canonical" "canonical" "the SPA builds the CANONICAL_V1 string in field order"
else
    check_local "wrong" "canonical" "the SPA builds the CANONICAL_V1 string in field order"
fi

# The login form demands both halves; an optional secret is what made unsigned sessions possible.
if grep -qE 'id="login-signing-secret"[^>]*required' "$SPA_HTML"; then
    check_local "required" "required" "the login form requires a signing secret"
else
    check_local "optional" "required" "the login form requires a signing secret"
fi
if grep -qiF "Signing Secret (optional)" "$SPA_HTML"; then
    check_local "optional" "mandatory" "the login form no longer advertises an optional secret"
else
    check_local "mandatory" "mandatory" "the login form no longer advertises an optional secret"
fi

# Static assets still serve. The dashboard is the only unauthenticated surface, by design.
RESP_CODE=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" "$BASE_URL/")
check "200" "the dashboard is served"
if grep -qF 'login-signing-secret' "$RESP_BODY_FILE"; then
    check_local "served" "served" "the served HTML carries the mandatory-secret login form"
else
    check_local "stale" "served" "the served HTML carries the mandatory-secret login form"
fi
RESP_CODE=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" "$BASE_URL/app.js")
check "200" "the SPA script is served"
if grep -qF 'crypto.subtle.sign(' "$RESP_BODY_FILE"; then
    check_local "served" "served" "the served script is the signing build"
else
    check_local "stale" "served" "the served script is the signing build"
fi

# End to end: the exact request shape app.js now emits — signed GET on a path the dashboard loads
# first — is accepted by the real server. This is what makes the source invariants above mean
# something rather than merely describing the file to itself.
if [ "$HAVE_OPENSSL" -eq 1 ]; then
    SIGN_AUTH="X-API-Key: $SIGNING_MASTER_KEY"; SIGN_SECRET="$MASTER_SIGNING_SECRET"

    signed_call GET "/api/auth/me" ""
    check "200" "the dashboard's first request authenticates when signed CANONICAL_V1"
    check_true '.hmac_mode != null' "the profile still reports the key's own mode to the UI"

    # ...and the same request unsigned is refused the moment signing is mandatory, which is the
    # posture the WebUI now always presents. (Under the default posture an unsigned bearer request
    # is still accepted — that is the per-key flexibility the backend keeps for webhook senders;
    # what changed is that the browser never takes it.)
    api_call GET "/api/auth/me" "$SIGNING_MASTER_KEY"
    check "200" "the backend still accepts unsigned bearer traffic from non-browser callers"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
