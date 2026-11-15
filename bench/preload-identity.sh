#!/bin/bash
# Identity of one preload a bench row names: is it the build the row's kind
# claims? run.sh calls it for every literoot-liteinst and literoot-trap row
# before round 0. All three checks are required:
#
#   T1 graph    SOURCE's preload, with the kind's features, resolves the
#               kind's backend: scripts/check-preload-feature-tree.sh --row.
#   T2 build    PRELOAD's sha256 is SHA256, the value recorded when it was
#               built, and BUILD_LOG (that build's cargo -v output) compiled
#               reverie-inguest once and reverie-liteinst once for liteinst,
#               never for trap. Lines are counted, never printed.
#   T3 symbols  PRELOAD defines symbols of reverie_inguest, and of
#               reverie_liteinst for liteinst, none for trap. nm runs
#               without -C and the check counts the length-prefixed crate
#               names (15reverie_inguest, 16reverie_liteinst), which both
#               legacy (_ZN) and v0 (_R) mangling spell out, so it does not
#               depend on nm's demangler: nm 2.35 leaves v0 names raw.
#
# These replace a text search for "reverie-liteinst": reverie-inguest's own
# strings carry that name, so the text is in both preloads and told neither
# apart. A check that cannot be made (no nm, no symbol table, no cargo) is
# UNAVAILABLE, never a pass.
#
# usage: bench/preload-identity.sh KIND PRELOAD SHA256 BUILD_LOG SOURCE [TARGET]
#   KIND is trap or liteinst; SOURCE is the literoot checkout PRELOAD was
#   built from; TARGET is the target triple it was built for (default: host).
# exit: 0 identity holds; 1 it does not; 3 UNAVAILABLE; 2 usage.
# One line per check goes to stdout; the reason for a failure goes to stderr.
set -uo pipefail

usage() { echo "usage: $0 trap|liteinst PRELOAD SHA256 BUILD_LOG SOURCE [TARGET]" >&2; exit 2; }
[ $# -eq 5 ] || [ $# -eq 6 ] || usage
kind=$1 preload=$2 sha=$3 log=$4 src=$5 target=${6:-}
case "$kind" in
    trap) want_lite=0 ;;
    liteinst) want_lite=1 ;;
    *) usage ;;
esac
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "$0: SHA256 must be 64 lowercase hex digits" >&2; exit 2; }
[ -f "$preload" ] && [ -f "$log" ] || { echo "$0: PRELOAD and BUILD_LOG must be files" >&2; exit 2; }
[ -x "$src/scripts/check-preload-feature-tree.sh" ] || { echo "$0: $src has no scripts/check-preload-feature-tree.sh" >&2; exit 2; }

fail() { echo "$kind $preload: $*" >&2; exit 1; }
unavailable() { echo "$kind $preload: UNAVAILABLE: $*" >&2; exit 3; }

# T1
targs=(--row "$kind")
[ -z "$target" ] || targs+=(--target "$target")
command -v cargo > /dev/null || unavailable "T1 needs cargo"
t1=$("$src/scripts/check-preload-feature-tree.sh" "${targs[@]}" 2>&1) || fail "T1: $t1"
echo "T1 ok: $t1"

# T2
got=$(sha256sum "$preload" | cut -d' ' -f1)
[ "$got" = "$sha" ] || fail "T2: sha256 $got is not the recorded $sha"
n_in=$(grep -cE '^[[:space:]]*Compiling reverie-inguest v' "$log")
n_lite=$(grep -cE '^[[:space:]]*Compiling reverie-liteinst v' "$log")
[ "$n_in" -eq 1 ] || fail "T2: the build log compiled reverie-inguest $n_in times, not once"
[ "$n_lite" -eq "$want_lite" ] || fail "T2: the build log compiled reverie-liteinst $n_lite times, not $want_lite"
echo "T2 ok: sha256 matches; build log compiled reverie-inguest 1, reverie-liteinst $n_lite"

# T3
command -v nm > /dev/null || unavailable "T3 needs nm"
# nm reports a stripped file on stderr ("no symbols") with nothing on stdout.
syms=$(nm --defined-only "$preload" 2> /dev/null) || unavailable "T3: nm failed on $preload"
[ -n "$syms" ] || unavailable "T3: no symbol table (stripped)"
s_in=$(grep -cF '15reverie_inguest' <<<"$syms")
s_lite=$(grep -cF '16reverie_liteinst' <<<"$syms")
[ "$s_in" -gt 0 ] || fail "T3: no reverie_inguest symbol"
if [ "$kind" = trap ]; then
    [ "$s_lite" -eq 0 ] || fail "T3: $s_lite reverie_liteinst symbols in a trap preload"
else
    [ "$s_lite" -gt 0 ] || fail "T3: no reverie_liteinst symbol in a liteinst preload"
fi
echo "T3 ok: reverie_inguest symbols $s_in, reverie_liteinst symbols $s_lite"
