#!/bin/bash
# Run one upstream proot test-suite row and count it.
#
# usage: scripts/proot-suite-row.sh [--per-name] <suite-src> <out-dir> <label> <proot-cmd...>
#
#   <suite-src>  checkout of proot-me/proot (pinned: 25dc6a3, v5.5.0)
#   <out-dir>    receives <label>.log, <label>.verdicts, <label>.counts
#   <proot-cmd>  the PROOT the suite invokes, e.g.
#                /path/literoot --backend liteinst
#
# Each row runs in a fresh copy of the suite (<out-dir>/suite-<label>)
# so rows never share build products or rootfs state. make exits 2 when
# any case fails; that is a measurement, not a harness failure.
#
# Counting: raw = every "CHECK <name> <verdict>" line; unique = one
# verdict per name, FAILED if any line failed, else ok if any line
# passed, else skipped.
#
# --per-name (literoot only): each test file runs as its own make target
# (check-<file>), with its own refusal side log: the proot-cmd's first
# word must be the literoot binary, and the driver inserts
# `--refusal-log <out-dir>/sidelogs-<label>/<file>.log` right after it,
# before any other option. The driver never creates the log. A name
# whose log is missing, fails `literoot --check-refusal-log`, or whose
# run breached the free-space floor (LITEROOT_SIDELOG_MIN_FREE_KB on the
# log's filesystem, default 1048576, checked before and after) is "not
# measured". A name whose valid log records any refusal is reported as
# "<verdict>-with-refusal <keys>" and is counted in no pass number. A
# skipped name is a refusal (literoot exits 125 on launcher errors) and
# is reported with its keys, or as unkeyed. Output: <label>.pername (one
# line per test file) and <label>.counts. LITEROOT_PERNAME_ONLY="<file>
# ..." runs only the named test files (for bite proofs); the counts then
# cover only those files.
set -uo pipefail
per_name=
if [ "${1:-}" = --per-name ]; then
    per_name=1
    shift
fi
if [ $# -lt 4 ]; then
    sed -n '2,33p' "$0"
    exit 64
fi
src=$1 out=$2 label=$3
shift 3
mkdir -p "$out"
copy="$out/suite-$label"
rm -rf "$copy"
cp -a "$src" "$copy"
log="$out/$label.log"
if [ -n "$per_name" ]; then
    literoot=$1
    shift
    logs="$out/sidelogs-$label"
    rm -rf "$logs"
    mkdir -p "$logs"
    floor=${LITEROOT_SIDELOG_MIN_FREE_KB:-1048576}
    free_kb() { df -Pk "$logs" | awk 'NR == 2 { print $4 }'; }
    : >"$log"
    : >"$out/$label.pername"
    for f in $(cd "$copy/test" && ls test-*.sh test-*.c 2>/dev/null); do
        if [ -n "${LITEROOT_PERNAME_ONLY:-}" ]; then
            case " $LITEROOT_PERNAME_ONLY " in
                *" $f "*) ;;
                *) continue ;;
            esac
        fi
        side="$logs/$f.log"
        before=$(free_kb)
        name_log="$logs/$f.make.log"
        env -u TMPDIR CARE=/bin/false make -C "$copy/test" \
            PROOT="$literoot --refusal-log $side $*" CARE=/bin/false "check-$f" >"$name_log" 2>&1
        after=$(free_kb)
        cat "$name_log" >>"$log"
        verdict=$(awk '$1 == "CHECK" { v = $3
                if (v == "FAILED" || cur == "FAILED") cur = "FAILED"
                else if (v == "ok" || cur == "ok") cur = "ok"
                else cur = "skipped" }
            END { print (cur == "" ? "none" : cur) }' "$name_log")
        if [ "$before" -lt "$floor" ] || [ "$after" -lt "$floor" ]; then
            status="not-measured free-space"
        elif [ ! -e "$side" ]; then
            status="not-measured no-side-log"
        elif ! keys=$("$literoot" --check-refusal-log "$side" 2>"$side.check"); then
            # Still not measured; the reason and any keys in the log are
            # reported for step 3's regression accounting, never counted.
            seen=$(sed -n 's/^literoot: refused //p' "$side" | tr ' ' '_' | sort -u | tr '\n' ' ')
            status="not-measured invalid-side-log ($(sed 's/^literoot: refusal log not valid: //' "$side.check" | head -1 | tr ' ' '_')) keys: ${seen:-none}"
        elif [ -n "$keys" ]; then
            status="$verdict-with-refusal $(printf '%s' "$keys" | sed 's/^refused //' | tr ' ' '_' | sort -u | tr '\n' ' ')"
        elif [ "$verdict" = skipped ]; then
            status="skipped-unkeyed"
        else
            status="$verdict"
        fi
        printf '%s %s\n' "$f" "$status" >>"$out/$label.pername"
    done
    rc=0
    {
        printf 'row %s per-name\n' "$label"
        for k in ok FAILED skipped-unkeyed none; do
            printf '%s %d\n' "$k" "$(awk -v k="$k" '$2 == k' "$out/$label.pername" | wc -l)"
        done
        printf 'with-refusal %d\n' "$(grep -c -- '-with-refusal ' "$out/$label.pername")"
        printf 'not-measured %d\n' "$(grep -c ' not-measured ' "$out/$label.pername")"
        printf 'files %d\n' "$(wc -l <"$out/$label.pername")"
    } | tee "$out/$label.counts"
    rm -rf "$copy"
    exit 0
fi
env -u TMPDIR CARE=/bin/false make -C "$copy/test" PROOT="$*" CARE=/bin/false check >"$log" 2>&1
rc=$?
awk '$1 == "CHECK" { print $2, $3 }' "$log" | sort >"$out/$label.raw"
awk '
    { name = $1; v = $2; cur = (name in seen) ? seen[name] : ""
      if (v == "FAILED" || cur == "FAILED") seen[name] = "FAILED"
      else if (v == "ok" || cur == "ok") seen[name] = "ok"
      else seen[name] = "skipped" }
    END { for (n in seen) print n, seen[n] }' "$out/$label.raw" | sort >"$out/$label.verdicts"
count() { awk -v v="$1" '$2 == v' "$2" | wc -l; }
{
    printf 'row %s make_rc %s\n' "$label" "$rc"
    printf 'raw    ok %d FAILED %d skipped %d total %d\n' \
        "$(count ok "$out/$label.raw")" "$(count FAILED "$out/$label.raw")" \
        "$(count skipped "$out/$label.raw")" "$(wc -l <"$out/$label.raw")"
    printf 'unique ok %d FAILED %d skipped %d total %d\n' \
        "$(count ok "$out/$label.verdicts")" "$(count FAILED "$out/$label.verdicts")" \
        "$(count skipped "$out/$label.verdicts")" "$(wc -l <"$out/$label.verdicts")"
} | tee "$out/$label.counts"
rm -rf "$copy"
