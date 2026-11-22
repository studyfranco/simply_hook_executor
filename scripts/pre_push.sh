#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test | awk '
    { print }
    /^test result: / {
        summaries++
        if ($0 !~ /; 0 failed; 0 ignored;/) {
            invalid = 1
        }
    }
    END {
        if (!summaries || invalid) {
            print "Cargo tests must report zero failures and zero ignored tests in every suite." > "/dev/stderr"
            exit 1
        }
    }
'
cargo audit --deny warnings
bash -n scripts/test_e2e.sh
