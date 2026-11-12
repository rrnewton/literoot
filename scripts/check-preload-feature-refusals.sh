#!/bin/bash
# Two preload feature combinations must fail to compile with exactly their
# named refusals (preload/src/lib.rs), and nothing else:
#   - inguest-trap with liteinst (the default): two global allocators;
#   - watched-initial with successor: the TrapHost first image cannot also be
#     the liteinst successor image. successor implies liteinst, so this
#     combination also carries the allocator refusal.
# Any other error, or a success, fails this check.
#
# usage: scripts/check-preload-feature-refusals.sh
#   CARGO_TARGET_DIR is honoured.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
alloc='error: literoot-preload: inguest-trap and liteinst each install a global allocator; build inguest-trap with --no-default-features'
watched='error: literoot-preload: watched-initial is the TrapHost first image and cannot also be the liteinst successor image'
out=$(mktemp)
trap 'rm -f "$out"' EXIT
fail=0
refuses() { # <description> <expected sorted error lines> <cargo feature arguments...>
    local description=$1 want=$2 rc errors
    shift 2
    cargo check --offline --manifest-path preload/Cargo.toml "$@" >"$out" 2>&1
    rc=$?
    errors=$(grep -E '^error(\[E[0-9]+\])?: ' "$out" | grep -v '^error: could not compile ' | LC_ALL=C sort)
    if [ "$rc" -eq 0 ]; then
        echo "FAIL: $description compiled ($*)" >&2
        fail=1
    elif [ "$errors" != "$want" ]; then
        echo "FAIL: $description ($*): expected exactly" >&2
        printf '%s\n' "$want" >&2
        echo "got:" >&2
        printf '%s\n' "$errors" >&2
        fail=1
    else
        echo "ok: $description refuses by name ($*)"
    fi
}
refuses "inguest-trap with liteinst" "$alloc" --features inguest-trap
refuses "watched-initial with successor" "$(printf '%s\n%s\n' "$alloc" "$watched" | LC_ALL=C sort)" \
    --no-default-features --features watched-initial,successor
[ "$fail" -eq 0 ] || exit 1
