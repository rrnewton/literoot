#!/bin/bash
# The LD_PRELOAD build of the preload must keep its .init_array constructor,
# LITEROOT_INIT (preload/src/lib.rs): without it the guest runs without
# literoot and nothing says so. Only the musl mapped-successor archive leaves
# it out (private-static/dry-run.sh checks that side).
#
# usage: scripts/check-preload-constructor.sh <libliteroot_preload.so>
#
# Passes when the library has a LITEROOT_INIT symbol whose address lies inside
# its .init_array section and a dynamic relocation fills that slot at load.
set -uo pipefail
if [ $# -ne 1 ] || [ -z "$1" ]; then
    sed -n '2,10p' "$0"
    exit 64
fi
lib=$1
[ -f "$lib" ] || { echo "FAIL: no library at $lib" >&2; exit 1; }
symbols=$(nm "$lib" 2>/dev/null) || { echo "FAIL: nm could not read $lib" >&2; exit 1; }
sections=$(readelf -SW "$lib" 2>/dev/null) || { echo "FAIL: readelf could not read $lib" >&2; exit 1; }
relocations=$(readelf -rW "$lib" 2>/dev/null) || { echo "FAIL: readelf -r could not read $lib" >&2; exit 1; }
matches=$(grep -E '^[0-9a-f]+ [dDbBrR] \S*LITEROOT_INIT$' <<<"$symbols")
count=$(grep -c . <<<"$matches")
if [ -z "$matches" ] || [ "$count" -ne 1 ]; then
    echo "FAIL: expected one LITEROOT_INIT data symbol in $lib, found ${count:-0}" >&2
    exit 1
fi
addr=$((16#$(awk '{print $1}' <<<"$matches")))
read -r start size < <(awk '$0 ~ /\] \.init_array / { for (i = 1; i <= NF; i++) if ($i == ".init_array") { print $(i + 2), $(i + 4); exit } }' <<<"$sections")
if [ -z "${start:-}" ] || [ -z "${size:-}" ]; then
    echo "FAIL: $lib has no .init_array section" >&2
    exit 1
fi
start=$((16#$start)); size=$((16#$size))
if [ "$addr" -lt "$start" ] || [ "$addr" -ge $((start + size)) ]; then
    printf 'FAIL: LITEROOT_INIT at %#x is outside .init_array [%#x, %#x)\n' "$addr" "$start" $((start + size)) >&2
    exit 1
fi
printf -v hex '%x' "$addr"
if ! grep -Eq "^0*${hex} " <<<"$relocations"; then
    printf 'FAIL: no dynamic relocation fills the LITEROOT_INIT slot at %#x\n' "$addr" >&2
    exit 1
fi
printf 'ok: LITEROOT_INIT at %#x is in .init_array [%#x, %#x) and relocated at load\n' "$addr" "$start" $((start + size))
