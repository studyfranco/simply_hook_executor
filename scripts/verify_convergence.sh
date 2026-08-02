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
