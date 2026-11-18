#!/bin/bash
# Builds the binaries and runs the integration tests that need macOS code
# signing and audit tokens.
#
# The tests are #[ignore]d by default so `cargo test` stays portable; this
# script supplies the environment they need.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "integration tests need macOS" >&2
    exit 1
fi

echo "== building"
cargo build --bins --quiet

WORKDIR="$(mktemp -d /tmp/syncd-it.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

BIN="$PWD/target/debug"
RT_HELPER="$BIN/syncd-helper"
RT_PROBE="$BIN/probe"

for f in "$RT_HELPER" "$RT_PROBE"; do
    [[ -x "$f" ]] || { echo "missing $f" >&2; exit 1; }
done

echo "== binaries"
printf '  %-24s %s\n' helper "$(codesign -dvvv "$RT_HELPER" 2>&1 | awk '/^CandidateCDHash /{print $2}')"
printf '  %-24s %s\n' probe  "$(codesign -dvvv "$RT_PROBE"  2>&1 | awk '/^CandidateCDHash /{print $2}')"

echo "== integration tests"
RT_HELPER="$RT_HELPER" RT_PROBE="$RT_PROBE" RT_WORKDIR="$WORKDIR" \
    cargo test -p syncd-redteam --test integration -- --ignored --test-threads=1 --nocapture

echo
echo "== attack matrix (pure logic, no helper process)"
cargo run -q -p syncd-redteam --bin redteam
