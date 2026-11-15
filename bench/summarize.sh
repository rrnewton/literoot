#!/bin/bash
# Summarize a bench/run.sh output directory.
#
# usage: bench/summarize.sh <run-dir> <native> <proot>
#
# <native> and <proot> name the reference runners for the ratio columns,
# either one runner for every workload or ROOT:RUNNER,ROOT:RUNNER to pick
# one per workload root (for example host:native-plain,alpine:native-bwrap).
# Every name must be a runner of the run.
#
# Reads per-run.tsv, expected.tsv, rounds.tsv and COMPLETE from <run-dir>
# and writes <run-dir>/summary.tsv and <run-dir>/summary.md, refusing if
# either exists. For every expected (workload, runner) pair, in the
# workloads file's order, and for two sets of rounds, "all" and "quiet"
# (rounds the quiet check did not flag):
#   status    OK; FAILED (any failed run of the pair, in any round, flagged
#             or not, the warmup round 0 included: it fails both sets);
#             INCOMPLETE (the run has no COMPLETE marker, or the pair lacks
#             its warmup run or ran a number of measured rounds other than
#             its ROUNDS); WORK-DIFFERS (the OK runs of the workload did not
#             all print the same stdout once ns_per_op is removed, for
#             example a different library count); UNCHECKED (the quiet set of a run made without
#             --quiet-cmd); NO-DATA (no run in the set).
#   n, failures (and how many of them in round 0), runs with stderr output;
#   failure classes: each distinct check (rc, output, nowall, nolog, route,
#   refused) with the literoot refusals of those runs, and its count;
#   for OK rows only: median, first and third quartile (linear
#   interpolation), min and max of wall time in microseconds, and the
#   median's ratio to the reference runners' OK medians for the workload;
#   and, for cells that print ns_per_op, the same median, quartiles and
#   ratios of that in-process per-operation time.
# summarize exits 1 only when the run has no COMPLETE marker (or on an
# error); a complete run with FAILED or other non-OK rows exits 0, so read
# the status column, not the exit code.
# Wall time covers the whole runner process: its startup and exit as well
# as the workload. ns_per_op covers only the measured loop.
set -uo pipefail
die() { echo "summarize: $*" >&2; exit 2; }
dir=${1:?usage: summarize.sh <run-dir> <native> <proot>}
native=${2:?native runner}
proot=${3:?proot runner}
for f in per-run.tsv expected.tsv rounds.tsv; do
  [ -f "$dir/$f" ] || die "no $dir/$f"
done
for f in summary.tsv summary.md summary.tsv.tmp summary.md.tmp; do
  [ ! -e "$dir/$f" ] || die "$dir/$f exists; summarize writes only new files"
done
complete=0
[ -f "$dir/COMPLETE" ] && complete=1
# The quiet set means something only if the quiet check ran every round.
quiet_checked=$(awk -F'\t' 'NR > 1 { rows++; if ($3 == "-") un++ } END { print (rows > 0 && !un) ? 1 : 0 }' \
  "$dir/rounds.tsv") || die "cannot read rounds.tsv"

awk -F'\t' -v native="$native" -v proot="$proot" -v complete="$complete" -v quiet_checked="$quiet_checked" \
  -v md="$dir/summary.md.tmp" '
function q(arr, n, f,    pos, lo, hi) {
  pos = 1 + (n - 1) * f; lo = int(pos); hi = (lo < n) ? lo + 1 : lo
  return arr[lo] + (pos - lo) * (arr[hi] - arr[lo])
}
function sortn(arr, n,    i, j, t) {
  for (i = 2; i <= n; i++) { t = arr[i]; for (j = i - 1; j >= 1 && arr[j] > t; j--) arr[j + 1] = arr[j]; arr[j + 1] = t }
}
# ref(spec, root): the reference runner for a workload root, "" if none.
function ref(spec, root,    parts, n, i, kv) {
  if (index(spec, ":") == 0) return spec
  n = split(spec, parts, ",")
  for (i = 1; i <= n; i++) { split(parts[i], kv, ":"); if (kv[1] == root) return kv[2] }
  return ""
}
function checkspec(spec, what,    parts, n, i, kv) {
  if (index(spec, ":") == 0) { if (!(spec in runner)) bad = bad what " runner " spec " is not in the run; "; return }
  n = split(spec, parts, ",")
  for (i = 1; i <= n; i++) {
    split(parts[i], kv, ":")
    if (!(kv[1] in rootseen)) bad = bad what " root " kv[1] " is not in the run; "
    if (!(kv[2] in runner)) bad = bad what " runner " kv[2] " is not in the run; "
  }
}
# rcname(rc, refused): a name for a nonzero exit. timeout(1) exits 125 when
# it cannot run its command, but it also passes on the exit 125 of the
# command itself, and 125 is the exit literoot gives a refused launch. A run
# whose refusal.log recorded a "literoot: refused" line (a TOKEN*N word in
# the refused column) is named for the refusal; 125 alone names both causes.
function rcname(rc, refused) {
  if (rc == 124) return " (timeout)"
  if (rc == 125 && refused ~ /(^|;)[^;:]+[*][0-9]+(;|$)/) return " (literoot refused)"
  if (rc == 125) return " (timeout(1) could not run the command, or the command exited 125)"
  if (rc == 126) return " (cannot execute)"
  if (rc == 127) return " (not found or exec failed)"
  if (rc > 128) return " (signal " (rc - 128) ")"
  return ""
}
# classes(key): "check[refusals] xN; ..." for the failed runs of a pair.
function classes(key,    parts, n, i, out) {
  n = split(substr(fcls[key], 2), parts, SUBSEP); out = ""
  for (i = 1; i <= n; i++) out = out (i > 1 ? "; " : "") parts[i] " x" fcnt[key, parts[i]]
  return out
}
function stats(key, set, src, cnt,    n, i, v) {
  n = cnt[key, set]
  delete v
  for (i = 1; i <= n; i++) v[i] = src[key, set, i]
  sortn(v, n)
  if (n == 0) return 0
  S_med = q(v, n, 0.5); S_q1 = q(v, n, 0.25); S_q3 = q(v, n, 0.75); S_min = v[1]; S_max = v[n]
  return n
}
FILENAME ~ /expected\.tsv$/ {
  if (FNR == 1) next
  key = $1 SUBSEP $4
  order[++nk] = key; rounds[key] = $3; wroot[$1] = $2; runner[$4] = 1; rootseen[$2] = 1; rkind[$4] = $5
  expected[key] = 1
  next
}
FNR == 1 { next }
{
  key = $1 SUBSEP $2
  if (!(key in expected)) { unexpected = unexpected $1 "/" $2 " "; next }
  if ($12 + 0 > 0) { errruns[key]++; if (!(key in errfirst)) errfirst[key] = "runs/" $1 "/" $2 "/" $3 "/stderr.txt" }
  if ($3 == 0) warm[key] = 1; else meas[key]++
  if ($9 != "ok") {
    # A failure of any class in any round, flagged or not and the warmup
    # included, fails the pair in both sets: correctness does not depend
    # on host load.
    fail[key]++; if ($3 == 0) wfail[key]++
    cls = ($9 == "rc") ? "rc=" $4 rcname($4, $13) : $9
    if ($13 != "-" && $13 != "") cls = cls "[" $13 "]"
    if (!((key, cls) in fcnt)) { fcls[key] = fcls[key] SUBSEP cls; fhead[key, cls] = $15 }
    fcnt[key, cls]++
    next
  }
  # Every OK run of a workload must have done the same work (stdout without
  # its timing), whichever runner ran it.
  if (!(($1, $14) in wseen)) { wseen[$1, $14] = "runs/" $1 "/" $2 "/" $3; wlist[$1] = wlist[$1] SUBSEP $14; nwd[$1]++ }
  wcnt[$1, $14]++
  if ($3 == 0) next
  for (set = 1; set <= 2; set++) {
    if (set == 2 && $10 == "yes") continue
    wall[key, set, ++nw[key, set]] = $5 / 1000
    if ($11 != "-") op[key, set, ++no[key, set]] = $11
  }
}
END {
  if (unexpected != "") { print "summarize: per-run.tsv has pairs not in expected.tsv: " unexpected > "/dev/stderr"; exit 3 }
  bad = ""; checkspec(native, "native"); checkspec(proot, "proot")
  for (rt in rootseen) {
    if (ref(native, rt) == "") bad = bad "no native runner for root " rt "; "
    if (ref(proot, rt) == "") bad = bad "no proot runner for root " rt "; "
  }
  if (bad != "") { print "summarize: " bad > "/dev/stderr"; exit 3 }
  for (k = 1; k <= nk; k++) {
    key = order[k]; split(key, kp, SUBSEP)
    for (set = 1; set <= 2; set++) {
      if (fail[key]) st = "FAILED"
      else if (!complete || !warm[key] || meas[key] != rounds[key]) st = "INCOMPLETE"
      else if (nwd[kp[1]] > 1) st = "WORK-DIFFERS"
      else if (set == 2 && !quiet_checked) st = "UNCHECKED"
      else if (!nw[key, set]) st = "NO-DATA"
      else st = "OK"
      status[key, set] = st
      if (st == "OK") {
        stats(key, set, wall, nw); med[key, set] = S_med; q1[key, set] = S_q1; q3[key, set] = S_q3
        mn[key, set] = S_min; mx[key, set] = S_max
        if (stats(key, set, op, no)) { omed[key, set] = S_med; oq1[key, set] = S_q1; oq3[key, set] = S_q3 }
      }
    }
  }
  print "workload\troot\trunner\tset\tstatus\trounds\tn\tfailures\twarmup_failures\tstderr_runs\tmedian_us\tq1_us\tq3_us\tmin_us\tmax_us\tvs_native\tvs_proot\top_n\top_median_ns\top_q1_ns\top_q3_ns\top_vs_native\top_vs_proot\tfailure_classes\tkind"
  if (complete) print "Run: COMPLETE." > md
  else print "Run: INCOMPLETE. There is no COMPLETE marker, so no row is timed." > md
  if (quiet_checked) print "Quiet check: ran before every round." > md
  else print "Quiet check: not run (or not every round), so the quiet set is UNCHECKED." > md
  print "" > md
  print "| workload | runner (kind) | root | set | status | n/rounds | failures (round 0) | runs with stderr | median µs | Q1-Q3 µs | min-max µs | ×native | ×proot | ns/op median | ns/op Q1-Q3 | ns/op ×native | ns/op ×proot | failure classes |" > md
  print "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|" > md
  for (k = 1; k <= nk; k++) {
    key = order[k]; split(key, kp, SUBSEP); w = kp[1]; r = kp[2]; root = wroot[w]
    nref = ref(native, root) ; pref = ref(proot, root)
    for (set = 1; set <= 2; set++) {
      label = (set == 1) ? "all" : "quiet"; st = status[key, set]
      n = nw[key, set] + 0; f = fail[key] + 0; wf = wfail[key] + 0; e = errruns[key] + 0
      if (st != "OK") {
        printf "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t\t\t\t\t\t\t\t\t\t\t\t\t\t%s\t%s\n", w, root, r, label, st, rounds[key], n, f, wf, e, classes(key), rkind[r]
        printf "| %s | %s (%s) | %s | %s | %s | %d/%d | %d (%d) | %d | | | | | | | | | | %s |\n", w, r, rkind[r], root, label, st, n, rounds[key], f, wf, e, classes(key) > md
        continue
      }
      nk2 = w SUBSEP nref; pk2 = w SUBSEP pref
      rn = (status[nk2, set] == "OK" && med[nk2, set] > 0) ? sprintf("%.2f", med[key, set] / med[nk2, set]) : ""
      rp = (status[pk2, set] == "OK" && med[pk2, set] > 0) ? sprintf("%.2f", med[key, set] / med[pk2, set]) : ""
      on = no[key, set] + 0; os = ""; oqs = ""; orn = ""; orp = ""
      if (on) {
        os = sprintf("%.0f", omed[key, set]); oqs = sprintf("%.0f\t%.0f", oq1[key, set], oq3[key, set])
        if (omed[nk2, set] > 0) orn = sprintf("%.2f", omed[key, set] / omed[nk2, set])
        if (omed[pk2, set] > 0) orp = sprintf("%.2f", omed[key, set] / omed[pk2, set])
      } else oqs = "\t"
      printf "%s\t%s\t%s\t%s\tOK\t%d\t%d\t%d\t%d\t%d\t%.1f\t%.1f\t%.1f\t%.1f\t%.1f\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t\t%s\n", \
        w, root, r, label, rounds[key], n, f, wf, e, med[key, set], q1[key, set], q3[key, set], mn[key, set], mx[key, set], \
        rn, rp, on, os, oqs, orn, orp, rkind[r]
      printf "| %s | %s (%s) | %s | %s | OK | %d/%d | %d (%d) | %d | %.1f | %.1f-%.1f | %.1f-%.1f | %s | %s | %s | %s | %s | %s | |\n", \
        w, r, rkind[r], root, label, n, rounds[key], f, wf, e, med[key, set], q1[key, set], q3[key, set], mn[key, set], mx[key, set], \
        rn, rp, os, (on ? sprintf("%.0f-%.0f", oq1[key, set], oq3[key, set]) : ""), orn, orp > md
    }
  }
  first = 1
  for (k = 1; k <= nk; k++) {
    key = order[k]
    if (!fcls[key]) continue
    if (first) { print "" > md; print "Failure classes, with the first stderr line of the first such run:" > md; first = 0 }
    split(key, kp, SUBSEP); nc = split(substr(fcls[key], 2), cl, SUBSEP)
    for (i = 1; i <= nc; i++) printf "- %s / %s: %s x%d: %s\n", kp[1], kp[2], cl[i], fcnt[key, cl[i]], fhead[key, cl[i]] > md
  }
  first = 1
  for (w in nwd) {
    if (nwd[w] < 2) continue
    if (first) { print "" > md; print "Workloads whose runs did different work (distinct stdout digests, with one run each):" > md; first = 0 }
    nc = split(substr(wlist[w], 2), cl, SUBSEP)
    for (i = 1; i <= nc; i++) printf "- %s: %s x%d, e.g. %s\n", w, cl[i], wcnt[w, cl[i]], wseen[w, cl[i]] > md
  }
  first = 1
  for (k = 1; k <= nk; k++) {
    key = order[k]
    if (!errruns[key]) continue
    if (first) { print "" > md; print "Runs with stderr output (read them before trusting a row):" > md; first = 0 }
    split(key, kp, SUBSEP)
    printf "- %s / %s: %d runs; first: %s\n", kp[1], kp[2], errruns[key], errfirst[key] > md
  }
}' "$dir/expected.tsv" "$dir/per-run.tsv" > "$dir/summary.tsv.tmp"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "summarize: awk failed (rc $rc); the partial output is in $dir/summary.tsv.tmp and summary.md.tmp" >&2
  exit 1
fi
mv -n "$dir/summary.tsv.tmp" "$dir/summary.tsv" && mv -n "$dir/summary.md.tmp" "$dir/summary.md" \
  && [ ! -e "$dir/summary.tsv.tmp" ] && [ ! -e "$dir/summary.md.tmp" ] || die "could not move the outputs into place"
echo "summarize: wrote $dir/summary.tsv and $dir/summary.md"
[ "$complete" -eq 1 ] || { echo "summarize: the run is INCOMPLETE" >&2; exit 1; }
