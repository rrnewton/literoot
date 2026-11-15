#!/bin/bash
# The staging feature must not bring the liteinst backend into a TrapHost
# build: exec-stage alone, inguest-trap with exec-stage, and watched-initial
# (each with --no-default-features) must resolve reverie-rpc-transport and no
# reverie-liteinst, liteinst or reverie-ptrace in the normal dependency graph.
# A build with both global allocators cannot link, so this is what lets the
# watched first image stage its exec snapshot.
#
# With --row, it checks instead the one preload build a bench row uses
# (bench/preload-identity.sh, check T1):
#   --row trap      --no-default-features --features inguest-trap must
#                   resolve reverie-inguest and none of reverie-liteinst,
#                   liteinst or reverie-ptrace;
#   --row liteinst  the default features must resolve reverie-liteinst.
# --target TRIPLE resolves the graph for that target (default: the host).
#
# usage: scripts/check-preload-feature-tree.sh [--row trap|liteinst [--target TRIPLE]]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# crates_of FEATURE-ARGS...: the sorted crate names of the preload's normal
# dependency graph, or a failure with cargo's output on stderr.
crates_of() {
    local tree
    if ! tree=$(cargo tree --offline --locked --manifest-path preload/Cargo.toml -e normal \
        --prefix none "$@" 2>&1); then
        printf '%s\n' "$tree" >&2
        return 1
    fi
    awk '{print $1}' <<<"$tree" | LC_ALL=C sort -u
}

if [ $# -gt 0 ]; then
    row="" target=()
    while [ $# -gt 0 ]; do
        [ $# -ge 2 ] || { echo "usage: $0 [--row trap|liteinst [--target TRIPLE]]" >&2; exit 2; }
        case "$1" in
            --row) row=$2 ;;
            --target) target=(--target "$2") ;;
            *) echo "usage: $0 [--row trap|liteinst [--target TRIPLE]]" >&2; exit 2 ;;
        esac
        shift 2
    done
    case "$row" in
        trap) features=(--no-default-features --features inguest-trap) ;;
        liteinst) features=() ;;
        *) echo "usage: $0 [--row trap|liteinst [--target TRIPLE]]" >&2; exit 2 ;;
    esac
    crates=$(crates_of "${features[@]}" "${target[@]}") || {
        echo "FAIL: --row $row: cargo tree failed" >&2
        exit 1
    }
    if [ "$row" = trap ]; then
        grep -qx 'reverie-inguest' <<<"$crates" || { echo "FAIL: --row trap does not resolve reverie-inguest" >&2; exit 1; }
        found=$(grep -xE 'reverie-liteinst|liteinst|reverie-ptrace' <<<"$crates" | tr '\n' ' ')
        [ -z "$found" ] || { echo "FAIL: --row trap resolves $found" >&2; exit 1; }
        echo "ok: --row trap resolves reverie-inguest and no liteinst or ptrace backend"
    else
        grep -qx 'reverie-liteinst' <<<"$crates" || { echo "FAIL: --row liteinst does not resolve reverie-liteinst" >&2; exit 1; }
        echo "ok: --row liteinst resolves reverie-liteinst"
    fi
    exit 0
fi

fail=0
for features in exec-stage inguest-trap,exec-stage watched-initial; do
    if ! crates=$(crates_of --no-default-features --features "$features"); then
        echo "FAIL: cargo tree failed for --features $features" >&2
        fail=1
        continue
    fi
    if ! grep -qx 'reverie-rpc-transport' <<<"$crates"; then
        echo "FAIL: --features $features does not resolve reverie-rpc-transport" >&2
        fail=1
    fi
    found=$(grep -xE 'reverie-liteinst|liteinst|reverie-ptrace' <<<"$crates" | tr '\n' ' ')
    if [ -n "$found" ]; then
        echo "FAIL: --features $features resolves $found" >&2
        fail=1
    else
        echo "ok: --features $features resolves reverie-rpc-transport and no liteinst backend"
    fi
done
[ "$fail" -eq 0 ] || exit 1
