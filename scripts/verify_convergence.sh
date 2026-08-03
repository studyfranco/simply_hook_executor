#!/usr/bin/env bash
#
# verify_convergence.sh — catches security drift between this service and its sibling.
#
# `simply_ip_vault` and `simply_hook_executor` share three pieces of logic that must stay
# behaviourally identical, because a difference in any of them is a difference in what the two
# services consider authenticated:
#
#   1. The X-Forwarded-For chain walk   — who the caller is
#   2. Signature canonicalization       — what a signature covers
#   3. SQLite pragma initialization     — how the store behaves under concurrency
#
# These were converged by hand. Hand-converged code drifts: someone fixes a bug in one repo, the
# other keeps the bug, and nobody notices until the next audit. This script turns that audit into a
# command.
#
# ── How it decides ───────────────────────────────────────────────────────────
#
# Not a byte-for-byte diff. The two services legitimately differ in plumbing — one resolves
# hostnames lazily behind an async `contains`, the other flattens them into a network list — so a
# raw diff would be permanently red and therefore permanently ignored. Each function is first
# normalized: comments and formatting stripped, statements put one per line, and a short list of
# known-equivalent identifiers renamed to a common form.
#
# What survives normalization is behaviour. That is then compared against a *recorded* fingerprint:
#
#   OK      — normalizes identical. Converged.
#   KNOWN   — differs, but exactly as recorded below, with a rationale. Not a failure.
#   DRIFT   — differs in a way nobody has signed off on. Fails.
#
# The KNOWN mechanism is what makes this runnable in CI. An accepted divergence stays visible on
# every run (so it is never forgotten) without turning the check into noise — and if that
# divergence *changes*, the fingerprint stops matching and it becomes DRIFT again.
#
# Every KNOWN entry mirrors a row in the Convergence Parity Check section of AGENT_NOTES.MD.
#
# Usage:
#   scripts/verify_convergence.sh            # report drift
#   scripts/verify_convergence.sh --verbose  # also print the normalized text being compared
#
# Exit codes: 0 = converged (or only known divergences), 1 = drift, 2 = could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEER_ROOT="$REPO_ROOT/example/simply_ip_vault"

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

VERBOSE=0
[ "${1:-}" = "--verbose" ] && VERBOSE=1

DRIFT=0; KNOWN=0; OK=0; SKIPPED=0

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [ ! -d "$PEER_ROOT" ]; then
    echo "${YELLOW}[SKIP]${RESET} Peer service not found at $PEER_ROOT." >&2
    echo "       Mount simply_ip_vault there (read-only) to enable drift detection." >&2
    exit 2
fi

# ── Extraction ───────────────────────────────────────────────────────────────
#
# Pulls one function out of a Rust file: from the line declaring it to the closing brace in column
# zero. Rustfmt guarantees that shape for a top-level item, which is what makes this reliable
# without a parser.
extract_fn() {
    local file="$1" name="$2"
    [ -f "$file" ] || return 1
    awk -v want="$name" '
        !inside && $0 ~ "^(pub )?(async )?fn " want "[(<]" { inside = 1 }
        inside { print }
        inside && /^}/ { exit }
    ' "$file"
}

# ── Normalization ────────────────────────────────────────────────────────────
#
# Removes what can differ without behaviour differing. The renames are deliberately few: each one
# is an assertion that two names mean the same thing, and a rename that is wrong would *hide* real
# drift. `is_literal_network` is pointedly NOT normalized to `is_trusted` — those two genuinely
# differ (see KNOWN-1), and collapsing them would conceal the difference this script exists to
# surface.
normalize() {
    # Squash all whitespace including newlines, then re-break on statement boundaries. This makes
    # the comparison immune to rustfmt line-wrapping, which is the single largest source of
    # cosmetic diffs between the two trees.
    sed -E 's://.*$::' \
    | tr '\n' ' ' \
    | sed -E \
        -e 's/[[:space:]]+/ /g' \
        -e 's/; /;\n/g' \
        -e 's/\{ /{\n/g' \
        -e 's/\} /}\n/g' \
    | sed -E \
        -e 's/^ //; s/ $//' \
        -e '/^$/d' \
        -e 's/\bpub (async )?fn/fn/' \
        -e 's/\basync fn/fn/' \
        -e 's/\.await\b//g' \
        `# the canonical-string builder, named for its module in each service` \
        -e 's/\bcanonical_v1_payload\b/SIGNATURE_BASE/g' \
        -e 's/\bsignature_base\b/SIGNATURE_BASE/g' \
        `# its accumulator and target parameter are named differently, not built differently` \
        -e 's/\bmessage\b/BUF/g' \
        -e 's/\bbase\b/BUF/g' \
        -e 's/\bpath_and_query\b/TARGET/g' \
        -e 's/\btarget\b/TARGET/g' \
        -e 's/\bpath\b/TARGET/g' \
        `# SeaORM API era, not behaviour: both issue the same statement` \
        -e 's/\bexecute_unprepared\b/EXEC/g' \
        -e 's/\bexecute_raw\b/EXEC/g' \
        -e 's/\bquery_one_raw\b/QUERY/g' \
        -e 's/\bquery_one\b/QUERY/g' \
        -e 's/sea_orm:://g'
}

fingerprint() {
    cksum | cut -d' ' -f1
}

# ── One comparison ───────────────────────────────────────────────────────────
#
#   compare <label> <our_file> <our_fn> <peer_file> <peer_fn> <known_fp> <rationale>
#
# `known_fp` of "-" means "no divergence is accepted here; any difference is drift".
compare() {
    local label="$1" our_file="$2" our_fn="$3" peer_file="$4" peer_fn="$5"
    local known_fp="$6" rationale="$7"

    local ours="$WORK_DIR/ours.txt" theirs="$WORK_DIR/theirs.txt"
    extract_fn "$REPO_ROOT/$our_file" "$our_fn" | normalize > "$ours"
    extract_fn "$PEER_ROOT/$peer_file" "$peer_fn" | normalize > "$theirs"

    if [ ! -s "$ours" ] || [ ! -s "$theirs" ]; then
        echo "${YELLOW}[SKIP]${RESET}  ${BOLD}$label${RESET}"
        [ -s "$ours" ]   || echo "         could not extract ${our_fn}() from $our_file"
        [ -s "$theirs" ] || echo "         could not extract ${peer_fn}() from $peer_file"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if diff -q "$ours" "$theirs" >/dev/null 2>&1; then
        echo "${GREEN}[OK]${RESET}    ${BOLD}$label${RESET} ${DIM}(converged)${RESET}"
        [ "$VERBOSE" -eq 1 ] && sed 's/^/         /' "$ours"
        OK=$((OK + 1))
        return
    fi

    local actual_fp
    actual_fp=$(diff -u "$ours" "$theirs" | tail -n +3 | fingerprint)

    if [ "$actual_fp" = "$known_fp" ]; then
        echo "${YELLOW}[KNOWN]${RESET} ${BOLD}$label${RESET} ${DIM}(fp $actual_fp)${RESET}"
        echo "         ${DIM}$rationale${RESET}"
        [ "$VERBOSE" -eq 1 ] && diff -u "$ours" "$theirs" | tail -n +3 | sed 's/^/         /'
        KNOWN=$((KNOWN + 1))
        return
    fi

    echo "${RED}[DRIFT]${RESET} ${BOLD}$label${RESET} ${DIM}(fp $actual_fp, expected ${known_fp})${RESET}"
    [ -n "$rationale" ] && echo "         ${DIM}previously accepted: $rationale${RESET}"
    echo "         ${DIM}--- this service: $our_file::$our_fn${RESET}"
    echo "         ${DIM}+++ peer:         $peer_file::$peer_fn${RESET}"
    diff -u "$ours" "$theirs" | tail -n +3 | sed 's/^/         /'
    DRIFT=$((DRIFT + 1))
}

# ── Shared constants ─────────────────────────────────────────────────────────
#
# Not functions, but just as load-bearing: a body limit that differs between the services means one
# accepts a payload the other refuses — a parser differential across a two-service pipeline.
compare_value() {
    local label="$1" our_pattern="$2" peer_pattern="$3" known="$4" rationale="$5"

    local ours theirs
    ours=$(grep -rhoE "$our_pattern" "$REPO_ROOT/src" 2>/dev/null | head -1)
    theirs=$(grep -rhoE "$peer_pattern" "$PEER_ROOT/src" 2>/dev/null | head -1)

    if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
        echo "${GREEN}[OK]${RESET}    ${BOLD}$label${RESET} ${DIM}($ours)${RESET}"
        OK=$((OK + 1))
        return
    fi

    if [ "$known" = "missing-in-peer" ] && [ -n "$ours" ] && [ -z "$theirs" ]; then
        echo "${YELLOW}[KNOWN]${RESET} ${BOLD}$label${RESET} ${DIM}(this service: $ours; peer: absent)${RESET}"
        echo "         ${DIM}$rationale${RESET}"
        KNOWN=$((KNOWN + 1))
        return
    fi

    echo "${RED}[DRIFT]${RESET} ${BOLD}$label${RESET}"
    echo "         this service: ${ours:-<absent>}"
    echo "         peer:         ${theirs:-<absent>}"
    DRIFT=$((DRIFT + 1))
}

# ── Structural properties ────────────────────────────────────────────────────
#
# The two checks above compare *this* service against the peer. These compare it against a rule.
#
# Both are needed, and for different reasons. A function-level diff only fires when the two trees
# disagree, so a bug introduced in *both* — by the same person converging them on the same wrong
# idea — normalizes identical and reports OK. That is not hypothetical: the peer's replay guard
# once called `seen.clear()` at capacity, which made every signature accepted in the window
# replayable at once, and a diff against a repo doing the same thing would have said "converged".
#
# So a handful of properties are asserted directly, as text that must NOT appear. They are chosen to
# be things that are (a) always a bug in this codebase, (b) greppable without a parser, and (c) the
# specific shapes real regressions have taken here. `assert_present` covers the inverse: a guard
# whose absence is the bug.
#
#   assert_absent  <label> <file> <pattern> <why>
#   assert_present <label> <file> <pattern> <why>
#
# `pattern` is an ERE passed to `grep -E`, matched against the file's *production* source only:
#
#   - Comments are stripped, so a rule named in prose — as several are, in the very doc comments
#     explaining why the thing is wrong — does not trip its own check.
#   - Everything from the first column-zero `#[cfg(test)]` onward is dropped. Test modules are full
#     of `.expect()` and hand-built fixtures that are entirely correct there, and including them
#     would make the rules either noisy or unwritable. The attribute is anchored to column zero so
#     an *item*-level `#[cfg(test)]` (an indented test-only helper) does not truncate the module
#     early and blind the rule to the code below it.
production_source() {
    awk '/^#\[cfg\(test\)\]/ { exit } { print }' "$1" | sed -E 's://.*$::'
}

assert_absent() {
    local label="$1" file="$2" pattern="$3" why="$4"
    local path="$REPO_ROOT/$file"

    if [ ! -f "$path" ]; then
        echo "${YELLOW}[SKIP]${RESET}  ${BOLD}$label${RESET}"
        echo "         $file does not exist — update the paths in this script."
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    # `grep -n` rather than `grep -q`, and via a substitution rather than a bare pipeline: `-q`
    # exits on the first match, which SIGPIPEs the upstream `awk`/`sed` and — under `pipefail` —
    # reports a *found* pattern as a failed command.
    local hits
    hits=$(production_source "$path" | grep -nE "$pattern" || true)

    if [ -z "$hits" ]; then
        echo "${GREEN}[OK]${RESET}    ${BOLD}$label${RESET} ${DIM}(absent from $file)${RESET}"
        OK=$((OK + 1))
        return
    fi

    echo "${RED}[DRIFT]${RESET} ${BOLD}$label${RESET}"
    echo "         ${DIM}$why${RESET}"
    echo "         ${DIM}found in $file:${RESET}"
    echo "$hits" | sed 's/^/         /'
    DRIFT=$((DRIFT + 1))
}

assert_present() {
    local label="$1" file="$2" pattern="$3" why="$4"
    local path="$REPO_ROOT/$file"

    if [ ! -f "$path" ]; then
        echo "${YELLOW}[SKIP]${RESET}  ${BOLD}$label${RESET}"
        echo "         $file does not exist — update the paths in this script."
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    local count
    count=$(production_source "$path" | grep -cE "$pattern" || true)

    if [ "${count:-0}" -gt 0 ]; then
        echo "${GREEN}[OK]${RESET}    ${BOLD}$label${RESET} ${DIM}($count match(es) in $file)${RESET}"
        OK=$((OK + 1))
        return
    fi

    echo "${RED}[DRIFT]${RESET} ${BOLD}$label${RESET}"
    echo "         ${DIM}$why${RESET}"
    echo "         ${DIM}expected /$pattern/ in $file${RESET}"
    DRIFT=$((DRIFT + 1))
}

echo "${CYAN}${BOLD}Convergence check${RESET} — this service vs ${DIM}$PEER_ROOT${RESET}"
echo

# KNOWN-1 is retired. The peer restructured its resolution into a flat snapshot, which retired
# `is_literal_network` and with it the hostname hop it used to report as the client. The walk is
# now byte-identical on both sides and this entry is expected to stay converged; the fingerprint is
# kept only so a *reappearance* of the old shape is reported as drift rather than silently accepted.
compare "X-Forwarded-For chain walk" \
    "src/config.rs" "resolve_client_ip" \
    "src/config.rs" "resolve_client_ip" \
    "3481781178" \
    "Retired: peer converged on skipping resolved hostname hops. Any match here is a regression."

# No divergence is accepted in the signed material. A difference here means a signature one service
# issues is not one the other verifies.
compare "Signature canonicalization" \
    "src/middleware.rs" "signature_base" \
    "src/crypto.rs" "canonical_v1_payload" \
    "-" \
    ""

# KNOWN-2, re-baselined. The original rationale ("peer aborts startup on pragma failure") is no
# longer true: the peer converged on non-fatal and went one better, returning `()` so the function
# is *structurally* incapable of aborting, where ours returns a `Result` its caller logs and
# swallows. Same two pragmas, same values, same outcome; what differs now is the return type and
# the log wording. Recorded rather than reconciled because adopting `()` would be a signature change
# for no behavioural gain — worth doing on the next pass that touches this file, not on its own.
compare "SQLite pragma initialization" \
    "src/db.rs" "apply_sqlite_pragmas" \
    "src/state.rs" "apply_sqlite_pragmas" \
    "3743579462" \
    "Peer returns (); ours returns Result and the caller swallows it. Both non-fatal — cosmetic."

# KNOWN-3 is retired: the peer adopted the 3 MiB ceiling and now derives its signature buffer from
# the same constant. Both sides declare it explicitly, so this compares equal by value.
compare_value "Request body ceiling" \
    '3 \* 1024 \* 1024' '3 \* 1024 \* 1024' \
    "missing-in-peer" \
    "Retired: peer adopted the 3 MiB DefaultBodyLimit and the shared constant."

# Both services keep a 92-day soft-delete window; only the resource differs (hooks vs ip_records),
# so the constants are compared by value rather than by name.
compare_value "Soft-delete retention default (days)" \
    'RETENTION_DAYS: i64 = ([0-9]+)' 'RETENTION_DAYS: i64 = ([0-9]+)' \
    "-" \
    ""

echo

# ── Property rules ───────────────────────────────────────────────────────────

# The regression that motivated this whole section. Flushing the replay map to honour the ceiling
# makes every signature accepted in the current window replayable at once, and because the guard is
# process-global, one key's burst disables replay protection for every other key. Growing past the
# ceiling is the correct trade: over-retention costs memory, under-retention costs the property.
assert_absent "Replay map is never flushed" \
    "src/replay.rs" \
    '\bseen(\.lock\(\)[^;]*)?\.clear\(\)|\*seen = HashMap::new' \
    "Clearing the map at capacity makes every signature in the current window replayable."

# The capacity branch must stay throttled. Without a backoff, a saturated map whose entries are all
# still live retains on every request — an O(n) scan under the global mutex that frees nothing,
# turning memory pressure into a throughput collapse exactly when the daemon is busiest.
assert_present "Replay capacity sweep is throttled" \
    "src/replay.rs" \
    'CAPACITY_BACKOFF_DIVISOR' \
    "A capacity sweep with no floor on its frequency reinstates the per-request O(n) scan."

# Digests are compared as bytes through a HashMap key, never by string equality on the header text.
# `SHA256=AB…` and `sha256=ab…` are the same signature spelled differently, and a string compare
# would let the second be presented as a fresh single use of the first.
assert_absent "Replay digests are not compared as text" \
    "src/replay.rs" \
    'digest\.to_lowercase|digest *== *|to_str\(\).*digest' \
    "Digests must be keyed as raw bytes; comparing header text lets one signature be spelled two ways."

# MAC comparison goes through `Mac::verify_slice`, which is constant-time. A `==` on the decoded
# digest or the hex string leaks the expected signature a byte at a time under timing observation.
assert_absent "Signature comparison is constant-time" \
    "src/middleware.rs" \
    'expected_?[Ss]ig[a-z_]* *== |signature *== *expected|\.eq\(&?expected_signature\)' \
    "Comparing MACs with == leaks the signature byte by byte; use Mac::verify_slice."
assert_present "Signature verification uses verify_slice" \
    "src/middleware.rs" \
    'verify_slice' \
    "The constant-time comparison is what makes the HMAC check safe to expose to an attacker."

# The SQLite pragmas are a performance optimization, not a correctness requirement. Aborting startup
# over one trades a real outage — on a filesystem that cannot do WAL, or the in-memory database the
# whole test suite uses — for a theoretical slowdown.
assert_absent "SQLite pragma failure is never fatal" \
    "src/db.rs" \
    'panic!|unwrap\(\)|expect\(|process::exit' \
    "A pragma failure must be logged and survived, not aborted on."
assert_present "SQLite pragma failure is surfaced to the caller" \
    "src/db.rs" \
    'Result<' \
    "The caller must be able to log the failure; a silently swallowed pragma is not observable."

# AGENT.MD's hardest rule about the execution engine: a shell string is command injection by
# construction. Arguments go through `Command::args`, never through `sh -c`.
assert_absent "Hooks are never spawned through a shell" \
    "src/executor.rs" \
    'Command::new\("(sh|bash|/bin/sh|/bin/bash)"\)|arg\("-c"\)' \
    "Evaluating a command inside a shell string is injection by construction (AGENT.MD §3)."

# The elevation path must not follow PATH. `sudo` is hard-coded at its absolute location precisely
# because PATH is an operator-configurable passthrough.
assert_present "sudo is invoked by absolute path" \
    "src/executor.rs" \
    '"/usr/bin/sudo"' \
    "Resolving sudo through PATH would make the elevation path itself an escalation vector."

# The signature covers the target the *client* requested. `Router::nest` strips the prefix from the
# URI inner layers observe, so reading `parts.uri` would sign a different string than the client did
# — and would leave the query string freely rewritable on an otherwise-valid signed request.
assert_present "Canonicalization reads the original URI" \
    "src/middleware.rs" \
    'OriginalUri' \
    "parts.uri has the /api prefix stripped by nest(); signing it omits what the client signed."

echo
echo "${DIM}$OK converged, $KNOWN known divergence(s), $DRIFT drifted, $SKIPPED skipped${RESET}"

if [ "$SKIPPED" -gt 0 ]; then
    echo "${YELLOW}A skip is not a pass${RESET} — a symbol was renamed or moved. Update the paths in this script."
    exit 1
fi

if [ "$DRIFT" -gt 0 ]; then
    echo "${RED}${BOLD}Drift detected.${RESET}"
    echo "Reconcile it, or — if intentional — record it in the Convergence Parity Check"
    echo "section of AGENT_NOTES.MD and add its fingerprint to this script."
    exit 1
fi

echo "${GREEN}${BOLD}Converged.${RESET}"
[ "$KNOWN" -gt 0 ] && echo "${DIM}($KNOWN accepted divergence(s) — see AGENT_NOTES.MD)${RESET}"
exit 0
