#!/bin/bash
# Red twins for bench/preload-identity.sh and run.sh's use of it, on two
# real preload builds of this checkout: the trap build
# (--no-default-features --features inguest-trap) and the default
# (liteinst) build, each with the cargo -v log of its own build.
#
#   - each preload passes for its own kind, and the trap preload passes even
#     though it contains the text "reverie-liteinst" (the old check's false
#     positive);
#   - a swapped preload is caught in both directions (the old liteinst check
#     passed a trap preload);
#   - each check fails on a case only it can see: T1 on a source whose trap
#     graph resolves reverie-liteinst, T2 on a wrong sha256 and on a log that
#     compiled reverie-liteinst, T3 on a liteinst preload given with the
#     trap log, and a stripped copy is UNAVAILABLE (exit 3);
#   - run.sh stops on a row whose preload fails, and on a row with no
#     --preload-ids line, and gets past the identity check for a good row.
#
# usage: scripts/check-bench-preload-identity.sh TRAP_SO TRAP_LOG LITE_SO LITE_LOG SCRATCH [TARGET]
#   SCRATCH must be an empty directory; the fixtures are written there.
set -uo pipefail
[ $# -eq 5 ] || [ $# -eq 6 ] || {
    echo "usage: $0 TRAP_SO TRAP_LOG LITE_SO LITE_LOG SCRATCH [TARGET]" >&2
    exit 2
}
trap_so=$1 trap_log=$2 lite_so=$3 lite_log=$4 scratch=$5 target=${6:-}
src=$(cd "$(dirname "$0")/.." && pwd -P) || exit 2
id=$src/bench/preload-identity.sh
[ -d "$scratch" ] && [ -z "$(ls -A "$scratch")" ] || { echo "$0: SCRATCH must be an empty directory" >&2; exit 2; }
for f in "$trap_so" "$trap_log" "$lite_so" "$lite_log"; do
    [ -f "$f" ] || { echo "$0: $f is not a file" >&2; exit 2; }
done
trap_sha=$(sha256sum "$trap_so" | cut -d' ' -f1)
lite_sha=$(sha256sum "$lite_so" | cut -d' ' -f1)
tgt=()
[ -z "$target" ] || tgt=("$target")

fail=0
# row NAME WANT-RC WANT-TEXT CMD...: the command must exit WANT-RC and, if
# WANT-TEXT is not empty, print it (stdout or stderr).
row() {
    local name=$1 want=$2 text=$3 out rc
    shift 3
    out=$("$@" 2>&1); rc=$?
    if [ "$rc" -ne "$want" ]; then
        echo "FAIL $name: exit $rc, wanted $want: $(head -c 300 <<<"$out")"
        fail=1
    elif [ -n "$text" ] && ! grep -qF -- "$text" <<<"$out"; then
        echo "FAIL $name: exit $rc but no \"$text\": $(head -c 300 <<<"$out")"
        fail=1
    else
        echo "ok   $name"
    fi
}

# The old check's premise: both preloads contain the text.
if grep -qaF reverie-liteinst "$trap_so" && grep -qaF reverie-liteinst "$lite_so"; then
    echo "ok   both preloads contain the text reverie-liteinst"
else
    echo "FAIL the trap and liteinst preloads should both contain the text reverie-liteinst"
    fail=1
fi

row R1-trap-own-kind 0 "T3 ok" "$id" trap "$trap_so" "$trap_sha" "$trap_log" "$src" "${tgt[@]}"
row R2-liteinst-own-kind 0 "T3 ok" "$id" liteinst "$lite_so" "$lite_sha" "$lite_log" "$src" "${tgt[@]}"
row R3-liteinst-preload-as-trap 1 "" "$id" trap "$lite_so" "$lite_sha" "$lite_log" "$src" "${tgt[@]}"
row R4-trap-preload-as-liteinst 1 "" "$id" liteinst "$trap_so" "$trap_sha" "$trap_log" "$src" "${tgt[@]}"
row R5-T2-wrong-sha 1 "T2: sha256" "$id" trap "$trap_so" "$lite_sha" "$trap_log" "$src" "${tgt[@]}"
row R6-T2-log-compiled-liteinst 1 "T2: the build log compiled reverie-liteinst" \
    "$id" trap "$trap_so" "$trap_sha" "$lite_log" "$src" "${tgt[@]}"
row R7-T3-liteinst-symbols 1 "T3:" "$id" trap "$lite_so" "$lite_sha" "$trap_log" "$src" "${tgt[@]}"

# T1: a copy of this checkout whose inguest-trap feature also pulls
# reverie-liteinst (the lock already holds it, so cargo tree stays offline).
mkdir "$scratch/src-t1" || exit 2
(cd "$src" && tar --exclude=./target --exclude=./.git -cf - .) | tar -x -C "$scratch/src-t1" || exit 2
sed -i 's/^inguest-trap = \["dep:reverie-inguest"\]$/inguest-trap = ["dep:reverie-inguest", "dep:reverie-liteinst"]/' \
    "$scratch/src-t1/preload/Cargo.toml" || exit 2
grep -qx 'inguest-trap = \["dep:reverie-inguest", "dep:reverie-liteinst"\]' "$scratch/src-t1/preload/Cargo.toml" \
    || { echo "FAIL R8 fixture: the inguest-trap feature line was not found"; exit 1; }
row R8-T1-graph-resolves-liteinst 1 "T1:" "$id" trap "$trap_so" "$trap_sha" "$trap_log" "$scratch/src-t1" "${tgt[@]}"

# T3 UNAVAILABLE: a stripped copy, given with its own sha so T2 passes.
cp "$trap_so" "$scratch/stripped.so" && strip --strip-all "$scratch/stripped.so" || exit 2
strip_sha=$(sha256sum "$scratch/stripped.so" | cut -d' ' -f1)
row R9-T3-stripped-unavailable 3 "UNAVAILABLE" "$id" trap "$scratch/stripped.so" "$strip_sha" "$trap_log" "$src" "${tgt[@]}"

# run.sh: a trap row and a liteinst row behind a host-mode native row and a
# rootfs workload without {RUN}. run.sh checks runners before that workload
# rule, so a row that passes its identity check stops at the {RUN} rule
# (nothing runs), and a row that fails stops at its identity check.
mkdir "$scratch/rootfs" "$scratch/bin-host" || exit 2
printf '#!/bin/sh\nexit 0\n' > "$scratch/bin-host/timeit" && chmod +x "$scratch/bin-host/timeit" || exit 2
# A stand-in literoot binary: run.sh requires the inguest-trap text in a
# trap row's binary; it is never executed here.
printf '#!/bin/sh\n# --no-default-features --features inguest-trap\nexit 9\n' > "$scratch/literoot" \
    && chmod +x "$scratch/literoot" || exit 2
printf 'w1\tr\t1\t5\t-\t{BIN}/x\n' > "$scratch/workloads.tsv"
ids() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$src" "$target" > "$scratch/ids-$4.tsv"; }
runners() {
    printf 'native\thost\tnative\t-\t\n%s\ttranslate\tliteroot-%s\tLITEROOT_PRELOAD=%s\t%s --refusal-log {REFUSAL_LOG} --backend %s -r {ROOT}\n' \
        "$1" "$1" "$2" "$scratch/literoot" "$1" > "$scratch/runners-$3.tsv"
}
runsh() {
    bash "$src/bench/run.sh" --runners "$scratch/runners-$1.tsv" --workloads "$scratch/workloads.tsv" \
        --out "$scratch/out-$1" --seed 1 --bin-host "$scratch/bin-host" --rootfs "r=$scratch/rootfs" "${@:2}"
}
runners trap "$trap_so" good
ids "$trap_so" "$trap_sha" "$trap_log" good
row R10-runsh-trap-row-passes 2 "rootfs workloads must start their binaries with {RUN}" \
    runsh good --preload-ids "$scratch/ids-good.tsv"
runners liteinst "$trap_so" swapped
ids "$trap_so" "$trap_sha" "$trap_log" swapped
row R11-runsh-swapped-preload-stops 2 "is not a liteinst preload by bench/preload-identity.sh" \
    runsh swapped --preload-ids "$scratch/ids-swapped.tsv"
runners trap "$trap_so" noids
row R12-runsh-no-ids-line-stops 2 "has no --preload-ids line" runsh noids
for o in good swapped noids; do
    [ ! -e "$scratch/out-$o" ] || { echo "FAIL run.sh created $scratch/out-$o"; fail=1; }
done

# summarize.sh: an exit 125 with a recorded literoot refusal is named for the
# refusal, a bare 125 names both of its causes, and neither is called a
# timeout failure.
sm=$scratch/summarize
mkdir "$sm" || exit 2
printf 'workload\troot\trounds\trunner\tkind\n' > "$sm/expected.tsv"
printf 'round\torder\tquiet_rc\tload1_start\tload1_end\tflagged\n0\t-\t-\t0\t0\tunchecked\n1\t-\t-\t0\t0\tunchecked\n' > "$sm/rounds.tsv"
printf 'workload\trunner\tround\trc\twall_ns\tutime_ns\tstime_ns\tmaxrss_kb\tcheck\tflagged\tns_per_op\tstderr_bytes\trefused\twork\tstderr_head\n' > "$sm/per-run.tsv"
for r in native:native lr-refused:literoot-liteinst lr-bare:literoot-liteinst; do
    printf 'w1\thost\t1\t%s\t%s\n' "${r%%:*}" "${r#*:}" >> "$sm/expected.tsv"
done
for round in 0 1; do
    printf 'w1\tnative\t%s\t0\t1000\t1\t1\t0\tok\tno\t-\t0\t-\tw\t\n' "$round" >> "$sm/per-run.tsv"
    printf 'w1\tlr-refused\t%s\t125\t1000\t1\t1\t0\trc\tno\t-\t1\tend:7;launcher_other*1\tw\tx\n' "$round" >> "$sm/per-run.tsv"
    printf 'w1\tlr-bare\t%s\t125\t1000\t1\t1\t0\trc\tno\t-\t1\tnolog\tw\tx\n' "$round" >> "$sm/per-run.tsv"
done
touch "$sm/COMPLETE"
row R13-summarize-runs 0 "" bash "$src/bench/summarize.sh" "$sm" native native
if grep -qF 'rc=125 (literoot refused)' "$sm/summary.md" \
    && grep -qF 'rc=125 (timeout(1) could not run the command, or the command exited 125)' "$sm/summary.md" \
    && ! grep -qF 'timeout failed' "$sm/summary.md"; then
    echo "ok   R13-summarize-rc125-labels"
else
    echo "FAIL R13-summarize-rc125-labels: $(grep -F 'rc=125' "$sm/summary.md" | head -c 300)"
    fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS" || { echo "FAILED"; exit 1; }
