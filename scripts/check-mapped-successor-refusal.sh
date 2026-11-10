#!/bin/bash
# The preload's mapped-successor feature must fail to compile with exactly
# one error, the named dh-axoec refusal (preload/src/lib.rs), until dh-axoec
# lands on Reverie main. Any other error, or a success, fails this check.
#
# usage: scripts/check-mapped-successor-refusal.sh
#   CARGO_TARGET_DIR is honoured; the check is for the musl target the
#   private runtime image is built for.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
want='literoot-preload: the mapped-successor feature needs dh-axoec, whose Reverie mapped-entry API is not on Reverie main yet'
out=$(mktemp)
trap 'rm -f "$out"' EXIT
RUSTFLAGS="-C target-feature=-crt-static" cargo check --offline \
    --manifest-path preload/Cargo.toml --target x86_64-unknown-linux-musl \
    --features mapped-successor >"$out" 2>&1
rc=$?
errors=$(grep -E '^error(\[E[0-9]+\])?: ' "$out" | grep -v '^error: could not compile ')
if [ "$rc" -eq 0 ]; then
    echo "FAIL: mapped-successor compiled; drop the dh-axoec refusal only with dh-axoec on main" >&2
    exit 1
fi
if [ "$errors" != "error: $want" ]; then
    echo "FAIL: expected exactly the dh-axoec refusal, got:" >&2
    printf '%s\n' "$errors" >&2
    exit 1
fi
echo "ok: mapped-successor refuses by name (dh-axoec)"
