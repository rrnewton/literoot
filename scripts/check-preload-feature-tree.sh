#!/bin/bash
# The staging feature must not bring the liteinst backend into a TrapHost
# build: exec-stage alone, inguest-trap with exec-stage, and watched-initial
# (each with --no-default-features) must resolve reverie-rpc-transport and no
# reverie-liteinst, liteinst or reverie-ptrace in the normal dependency graph.
# A build with both global allocators cannot link, so this is what lets the
# watched first image stage its exec snapshot.
#
# usage: scripts/check-preload-feature-tree.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
fail=0
for features in exec-stage inguest-trap,exec-stage watched-initial; do
    if ! tree=$(cargo tree --offline --locked --manifest-path preload/Cargo.toml -e normal \
        --prefix none --no-default-features --features "$features" 2>&1); then
        echo "FAIL: cargo tree failed for --features $features:" >&2
        printf '%s\n' "$tree" >&2
        fail=1
        continue
    fi
    crates=$(awk '{print $1}' <<<"$tree" | LC_ALL=C sort -u)
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
