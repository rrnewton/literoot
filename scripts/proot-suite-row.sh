#!/bin/bash
# Run one upstream proot test-suite row and count it.
#
# usage: scripts/proot-suite-row.sh <suite-src> <out-dir> <label> <proot-cmd...>
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
set -uo pipefail
if [ $# -lt 4 ]; then
    sed -n '2,20p' "$0"
    exit 64
fi
src=$1 out=$2 label=$3
shift 3
mkdir -p "$out"
copy="$out/suite-$label"
rm -rf "$copy"
cp -a "$src" "$copy"
log="$out/$label.log"
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
