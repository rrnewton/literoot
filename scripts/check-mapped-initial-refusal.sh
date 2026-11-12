#!/bin/bash
# The preload's mapped-initial feature must fail to compile with exactly one
# error, the named dh-tc7os refusal (preload/src/lib.rs), until dh-tc7os
# defines literoot's first generation in Reverie's factory. Any other error,
# or a success, fails this check.
#
# usage: scripts/check-mapped-initial-refusal.sh
#   CARGO_TARGET_DIR is honoured; the check is for the musl target the
#   private runtime image is built for.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
want='literoot-preload: the mapped-initial entry needs dh-tc7os (the factory'"'"'s literoot first generation is not defined on Reverie main)'
out=$(mktemp)
trap 'rm -f "$out"' EXIT
RUSTFLAGS="-C target-feature=-crt-static" cargo check --offline \
    --manifest-path preload/Cargo.toml --target x86_64-unknown-linux-musl \
    --features mapped-initial >"$out" 2>&1
rc=$?
errors=$(grep -E '^error(\[E[0-9]+\])?: ' "$out" | grep -v '^error: could not compile ')
if [ "$rc" -eq 0 ]; then
    echo "FAIL: mapped-initial compiled; drop the dh-tc7os refusal only with dh-tc7os on main" >&2
    exit 1
fi
if [ "$errors" != "error: $want" ]; then
    echo "FAIL: expected exactly the dh-tc7os refusal, got:" >&2
    printf '%s\n' "$errors" >&2
    exit 1
fi
echo "ok: mapped-initial refuses by name (dh-tc7os)"
