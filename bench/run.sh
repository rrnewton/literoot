#!/bin/bash
# Interleaved benchmark runner: every (workload, runner) pair once per
# round, in a per-round shuffled order, each run timed by bench/timeit.
#
# usage: bench/run.sh --runners FILE --workloads FILE --out DIR --seed N
#                     --bin-host DIR [--rootfs NAME=DIR]... [--assets DIR]
#                     [--quiet-cmd CMD] [--preload-ids FILE]
#
# --runners FILE    tab-separated: NAME  MODE  KIND  ENV  PREFIX
#                   MODE is "translate" (the runner maps guest paths; the
#                   workload sees rootfs paths) or "host" (no mapping; the
#                   workload is given host paths into the rootfs).
#                   KIND says what the row claims to measure, and run.sh
#                   checks the claim before round 0 (see "Runner kinds").
#                   ENV is "-" or space-separated NAME=VALUE words (values
#                   without spaces) given to this runner only.
#                   PREFIX is the words put before the workload command;
#                   {ROOT} becomes the workload's rootfs directory and
#                   {REFUSAL_LOG} a new refusal.log path in the run's own
#                   directory. An empty PREFIX runs the command directly.
# --workloads FILE  tab-separated: ID  ROOT  ROUNDS  TIMEOUT  EXPECT  COMMAND
#                   ROOT is "host" (rootfs /) or a NAME given by --rootfs.
#                   ROUNDS (at least 1) is how many measured rounds the
#                   workload gets. TIMEOUT (at least 1) is seconds per run.
#                   EXPECT is a string the run's stdout must contain, or
#                   "=TEXT" for a stdout of exactly TEXT and a newline, or
#                   "-" for no check; rc must be 0 in every case.
#                   COMMAND may use {P} (host path prefix of the rootfs, or
#                   empty), {BIN} (where the bench binaries are, as the
#                   workload sees them: /bench-bin under a translating
#                   runner, <rootfs>/bench-bin under a host-mode runner,
#                   --bin-host for a host workload) and {RUN} (empty, or,
#                   for a rootfs workload under a host-mode runner, the
#                   rootfs's musl loader with its library path, so every
#                   runner executes the same rootfs binaries; rootfs
#                   workloads must start their binaries with {RUN}{BIN}).
#                   Host workloads may also use {ASSETS} (--assets),
#                   {BENCH} (this directory) and {RUNDIR} (a new empty
#                   directory for this one run).
# --out DIR         must not exist. Receives runs/ID/RUNNER/ROUND/
#                   {cmd.txt,stdout.txt,stderr.txt,time.json[,refusal.log,work/]},
#                   per-run.tsv, rounds.tsv, expected.tsv, the record files
#                   listed under "Record", and COMPLETE, written last and
#                   only when every round ran and every row was written.
#                   Round 0 is the unmeasured warmup; its failures count.
#                   per-run.tsv's work column digests each run's stdout with
#                   the ns_per_op timing removed, so summarize.sh can check
#                   that every runner did the same work.
# --seed N          the shuffle seed. It is recorded, with awk's version:
#                   the order follows from the seed on the same awk.
# --assets DIR      inputs for {ASSETS}; DIR/SHA256SUMS must list every
#                   file and is checked with sha256sum -c before round 0.
# --quiet-cmd CMD   evaluated by the shell before each round (it is the
#                   operator's command); a nonzero exit flags the round
#                   (it still runs). Without it, every round is recorded
#                   as "unchecked", never as quiet. The 1-minute load
#                   average is recorded at the start and end of every round.
# --preload-ids FILE  tab-separated: PRELOAD  SHA256  BUILD_LOG  SOURCE  [TARGET]
#                   one line per preload a liteinst or trap row names (its
#                   LITEROOT_PRELOAD), all paths absolute: the sha256 recorded
#                   when it was built, that build's cargo -v log, the literoot
#                   checkout it was built from, and the target triple if not
#                   the host. Required when there is a liteinst or trap row.
#
# Runner kinds:
#   native, other     no check, but a name starting with literoot or proot
#                     is refused under these kinds.
#   proot             PROOT_NO_SECCOMP must not be in ENV (the comparison
#                     is proot's default seccomp mode).
#   proot-noseccomp   ENV must set PROOT_NO_SECCOMP=1.
#   literoot-liteinst, literoot-trap, literoot-ptrace
#                     PREFIX's first word is the literoot binary (an
#                     absolute path) and PREFIX has "--backend liteinst",
#                     "trap" or "ptrace" to match. liteinst and trap rows
#                     must set LITEROOT_PRELOAD=<absolute path> in ENV, so
#                     each row names its own preload. A trap row needs a
#                     literoot built with the inguest-trap feature (without
#                     it, --backend trap silently runs the liteinst preload
#                     with site patching off): the binary must contain the
#                     text only that feature compiles in (an identity check
#                     on embedded text, made to catch a swapped file). Each
#                     liteinst and trap row's preload must pass
#                     bench/preload-identity.sh for its kind, with its line
#                     from --preload-ids: the preload graph (T1), the
#                     recorded sha256 and build log (T2) and the linked
#                     symbols (T3). A failed or UNAVAILABLE check stops the
#                     run. (A search for the text "reverie-liteinst" told
#                     the two preloads apart before; reverie-inguest's own
#                     strings carry that name, so both preloads have it.)
#                     proot and literoot rows may not start with "env".
#                     Every literoot row passes --refusal-log {REFUSAL_LOG}.
#                     After each run, the log must exist, name the one route
#                     the kind implies ("preload" for liteinst and trap,
#                     "ptrace" for ptrace: it tells in-guest from ptrace, not
#                     liteinst from trap), end every "begin <pid>" with
#                     "end <pid> ok" (else check "logend"), and any "literoot: refused"
#                     line is recorded in per-run.tsv's refused column. A
#                     run that exits 0 with a refusal is a failure (check
#                     "refused"): the backend did not do all of the work.
#
# Environment: every run starts from an empty environment plus PATH,
# HOME and LC_ALL=C (recorded in env-base.txt) and the runner's ENV, so a
# variable exported by the caller (LITEROOT_PRELOAD, PROOT_NO_SECCOMP,
# LD_PRELOAD...) cannot change what a row measures.
#
# Record (all under --out): argv.txt, seed.txt, tools.txt (bash, awk,
# uname), env-base.txt, env-caller.txt (the NAMES and LENGTHS of the
# caller's LITEROOT_*, REVERIE_*, PROOT_*, LD_* and PATH variables, never
# their values; runs do not see them), runners.tsv, workloads.tsv and
# their sha256, bench.sha256 (this directory's files, the dlopen list
# included), runner-ids.tsv
# (each runner's resolved binary and preload with sha256), bin-host.sha256,
# rootfs-<NAME>-bench-bin.sha256, assets.SHA256SUMS, and with
# --preload-ids, preload-ids.tsv and preload-identity.txt (each check's line).
#
# run.sh does not set CPU, memory, nice or I/O limits or an outer time
# limit; run it inside one bounded unit that applies the same treatment
# to every runner.
#
# Lines starting with '#' and blank lines are skipped in both files.
# Commands come from the two files and are evaluated as shell words, so
# both files must be trusted. Paths from the command line may hold only
# letters, digits and . _ / + -, so they read the same in every context.
set -uo pipefail

die() { echo "run.sh: $*" >&2; exit 2; }

ARGV=("$@")
RUNNERS="" WORKLOADS="" OUT="" SEED="" BIN_HOST="" QUIET_CMD="" ASSETS="" PRELOAD_IDS=""
declare -A ROOTFS=()
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || die "$1 needs a value"
  case "$1" in
    --runners) RUNNERS=$2 ;;
    --workloads) WORKLOADS=$2 ;;
    --out) OUT=$2 ;;
    --seed) SEED=$2 ;;
    --bin-host) BIN_HOST=$2 ;;
    --rootfs) [[ "$2" =~ ^[A-Za-z0-9_-]+=/ ]] || die "--rootfs takes NAME=/absolute/dir"
              ROOTFS[${2%%=*}]=${2#*=} ;;
    --assets) ASSETS=$2 ;;
    --quiet-cmd) QUIET_CMD=$2 ;;
    --preload-ids) PRELOAD_IDS=$2 ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done
[ -f "$RUNNERS" ] && [ -f "$WORKLOADS" ] || die "--runners and --workloads must be files"
[ -n "$OUT" ] && [ ! -e "$OUT" ] || die "--out must name a directory that does not exist"
[[ "$SEED" =~ ^[0-9]{1,9}$ ]] || die "--seed must be a number of at most 9 digits"
BENCH=$(cd "$(dirname "$0")" && pwd -P) || die "cannot resolve the bench directory"
[[ "$BIN_HOST" == /* ]] && [ -x "$BIN_HOST/timeit" ] || die "--bin-host must be an absolute directory holding timeit"
[ -z "$ASSETS" ] || { [[ "$ASSETS" == /* ]] && [ -f "$ASSETS/SHA256SUMS" ]; } \
  || die "--assets must be an absolute directory with a SHA256SUMS file"
# Paths are substituted into command text, some of it inside quotes, so
# they are limited to characters that need no quoting anywhere.
for v in "$OUT" "$BIN_HOST" "$ASSETS" "$BENCH" "${ROOTFS[@]}"; do
  [[ "$v" =~ ^[A-Za-z0-9._/+-]*$ ]] || die "path $v: use only letters, digits and . _ / + -"
done
# --preload-ids: one identity line per preload path.
declare -A ID_SHA=() ID_LOG=() ID_SRC=() ID_TGT=()
if [ -n "$PRELOAD_IDS" ]; then
  [ -f "$PRELOAD_IDS" ] || die "--preload-ids must be a file"
  while IFS=$'\t' read -r ipl isha ilog isrc itgt || [ -n "$ipl" ]; do
    [ -z "$ipl" ] || [ "${ipl:0:1}" = "#" ] && continue
    for v in "$ipl" "$ilog" "$isrc"; do
      [[ "$v" == /* && "$v" =~ ^[A-Za-z0-9._/+-]*$ ]] || die "--preload-ids: $v must be an absolute path of letters, digits and . _ / + -"
    done
    [[ "$isha" =~ ^[0-9a-f]{64}$ ]] || die "--preload-ids: $ipl: bad sha256"
    [[ "$itgt" =~ ^[A-Za-z0-9._-]*$ ]] || die "--preload-ids: $ipl: bad target"
    [ -z "${ID_SHA[$ipl]:-}" ] || die "--preload-ids: $ipl listed twice"
    ID_SHA[$ipl]=$isha ID_LOG[$ipl]=$ilog ID_SRC[$ipl]=$isrc ID_TGT[$ipl]=$itgt
  done < "$PRELOAD_IDS"
fi
declare -a ID_OUT=()
# The escape checks rely on these fixtures existing only inside a rootfs.
for f in /bench-marker /bench-link /bench-tree; do
  if [ -e "$f" ] || [ -L "$f" ]; then die "$f exists on the host; the escape checks need it absent"; fi
done

declare -a R_NAME R_MODE R_KIND R_ENV R_PREFIX W_ID W_ROOT W_ROUNDS W_TIMEOUT W_EXPECT W_CMD
while IFS=$'\t' read -r name mode kind envw prefix || [ -n "$name" ]; do
  [ -z "$name" ] || [ "${name:0:1}" = "#" ] && continue
  [ "$mode" = translate ] || [ "$mode" = host ] || die "runner $name: bad mode $mode"
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "runner $name: bad name"
  R_NAME+=("$name"); R_MODE+=("$mode"); R_KIND+=("$kind"); R_ENV+=("$envw"); R_PREFIX+=("$prefix")
done < "$RUNNERS"
while IFS=$'\t' read -r id root rounds timeout expect cmd || [ -n "$id" ]; do
  [ -z "$id" ] || [ "${id:0:1}" = "#" ] && continue
  [[ "$id" =~ ^[A-Za-z0-9._-]+$ ]] || die "workload $id: bad id"
  [ "$root" = host ] || [ -n "${ROOTFS[$root]:-}" ] || die "workload $id: unknown rootfs $root"
  [[ "$rounds" =~ ^[0-9]+$ && "$timeout" =~ ^[0-9]+$ ]] || die "workload $id: bad rounds or timeout"
  [ "$timeout" -ge 1 ] || die "workload $id: TIMEOUT must be at least 1 (0 would disable it)"
  [ -n "$cmd" ] && [ -n "$expect" ] || die "workload $id: empty EXPECT or COMMAND"
  [ "$rounds" -ge 1 ] || die "workload $id: ROUNDS must be at least 1"
  if [ "$root" != host ] && [[ "$cmd" == *"{ASSETS}"* || "$cmd" == *"{RUNDIR}"* || "$cmd" == *"{BENCH}"* ]]; then
    die "workload $id: {ASSETS}, {RUNDIR} and {BENCH} are for host workloads only"
  fi
  [[ "$cmd" != *"{ASSETS}"* ]] || [ -n "$ASSETS" ] || die "workload $id uses {ASSETS}; give --assets"
  W_ID+=("$id"); W_ROOT+=("$root"); W_ROUNDS+=("$rounds"); W_TIMEOUT+=("$timeout")
  W_EXPECT+=("$expect"); W_CMD+=("$cmd")
done < "$WORKLOADS"
[ ${#R_NAME[@]} -gt 0 ] && [ ${#W_ID[@]} -gt 0 ] || die "no runners or no workloads"
[ "$(printf '%s\n' "${R_NAME[@]}" | sort | uniq -d)" = "" ] || die "duplicate runner names"
[ "$(printf '%s\n' "${W_ID[@]}" | sort | uniq -d)" = "" ] || die "duplicate workload ids"

BASE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE_ENV=("PATH=$BASE_PATH" "HOME=${HOME:-/}" "LC_ALL=C")
TRAP_MARK='--no-default-features --features inguest-trap'

# env_get NAME WORDS: the value NAME has in a runner's ENV words.
env_get() {
  local -a ws; local w
  read -ra ws <<< "$2"
  for w in "${ws[@]}"; do [ "${w%%=*}" = "$1" ] && { printf '%s' "${w#*=}"; return 0; }; done
  return 1
}

# Check every runner's claim before anything runs.
declare -a R_ENVV R_BIN R_PRELOAD
for r in "${!R_NAME[@]}"; do
  name=${R_NAME[$r]} kind=${R_KIND[$r]} envw=${R_ENV[$r]} prefix=${R_PREFIX[$r]}
  [ "$envw" = - ] && envw=""
  read -ra ews <<< "$envw"
  for w in "${ews[@]}"; do
    [[ "$w" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]] || die "runner $name: bad ENV word $w"
  done
  R_ENVV[$r]=$envw
  read -r first _ <<< "$prefix"
  bin=""
  [ -z "$first" ] || bin=$(PATH=$BASE_PATH command -v -- "$first") || die "runner $name: $first not found"
  R_BIN[$r]=$bin
  preload=$(env_get LITEROOT_PRELOAD "$envw") || preload=""
  R_PRELOAD[$r]=$preload
  case "$kind" in
    proot*|literoot-*)
      [ "$first" != env ] || die "runner $name: kind $kind takes its environment from ENV, not an env prefix" ;;
  esac
  case "$kind" in
    native|other)
      case "$name" in
        literoot*|proot*) die "runner $name: a literoot or proot name needs its literoot or proot kind" ;;
      esac ;;
    proot)
      ! env_get PROOT_NO_SECCOMP "$envw" > /dev/null || die "runner $name: kind proot with PROOT_NO_SECCOMP" ;;
    proot-noseccomp)
      [ "$(env_get PROOT_NO_SECCOMP "$envw")" = 1 ] || die "runner $name: proot-noseccomp needs PROOT_NO_SECCOMP=1" ;;
    literoot-liteinst|literoot-trap|literoot-ptrace)
      backend=${kind#literoot-}
      [[ "$first" == /* ]] && [ -x "$first" ] || die "runner $name: the literoot binary must be an absolute path"
      [[ " $prefix " == *" --backend $backend "* ]] || die "runner $name: kind $kind needs --backend $backend"
      [[ " $prefix " == *" --refusal-log {REFUSAL_LOG} "* ]] || die "runner $name: kind $kind needs --refusal-log {REFUSAL_LOG}"
      if [ "$backend" != ptrace ]; then
        [[ "$preload" == /* ]] && [ -f "$preload" ] || die "runner $name: set LITEROOT_PRELOAD=<absolute path> in ENV"
      fi
      if [ "$backend" = trap ]; then
        grep -qaF -- "$TRAP_MARK" "$first" || die "runner $name: $first is not an inguest-trap build"
      fi
      if [ "$backend" != ptrace ]; then
        [ -n "${ID_SHA[$preload]:-}" ] || die "runner $name: $preload has no --preload-ids line"
        idout=$("$BENCH/preload-identity.sh" "$backend" "$preload" "${ID_SHA[$preload]}" \
          "${ID_LOG[$preload]}" "${ID_SRC[$preload]}" ${ID_TGT[$preload]:+"${ID_TGT[$preload]}"} 2>&1) \
          || die "runner $name: $preload is not a $backend preload by bench/preload-identity.sh: $idout"
        ID_OUT+=("runner $name ($backend, $preload):" "$idout")
      fi ;;
    *) die "runner $name: unknown kind $kind" ;;
  esac
done

if [ -n "$ASSETS" ]; then
  (cd "$ASSETS" && sha256sum -c --quiet SHA256SUMS) || die "--assets: sha256sum -c failed"
  # The pinned values in this directory must be the ones checked.
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] || grep -qxF -- "$line" "$ASSETS/SHA256SUMS" \
      || die "--assets: SHA256SUMS lacks the pinned line: $line"
  done < "$BENCH/assets.sha256"
fi

# A host-mode runner runs a rootfs workload's binaries through the
# rootfs's own musl loader ({RUN}), so it executes the same binaries as
# the translating runners.
declare -A LOADER=()
for name in "${!ROOTFS[@]}"; do
  shopt -s nullglob
  lds=("${ROOTFS[$name]}"/lib/ld-musl-*.so.1)
  shopt -u nullglob
  [ ${#lds[@]} -le 1 ] || die "rootfs $name: more than one lib/ld-musl-*.so.1"
  [ ${#lds[@]} -eq 0 ] || LOADER[$name]=${lds[0]}
done
for w in "${!W_ID[@]}"; do
  root=${W_ROOT[$w]}
  [ "$root" != host ] || continue
  for r in "${!R_NAME[@]}"; do
    [ "${R_MODE[$r]}" = host ] || continue
    [[ "${W_CMD[$w]}" == *"{RUN}"* ]] || die "workload ${W_ID[$w]}: rootfs workloads must start their binaries with {RUN}"
    [ -n "${LOADER[$root]:-}" ] || die "rootfs $root has no lib/ld-musl-*.so.1 for host-mode runner ${R_NAME[$r]}"
  done
done

MAX=0
for r in "${W_ROUNDS[@]}"; do [ "$r" -gt "$MAX" ] && MAX=$r; done

mkdir "$OUT" || die "cannot create $OUT"
mkdir "$OUT/runs" || die "cannot create $OUT/runs"
# wr FILE FORMAT ARGS...: append one record, or stop without COMPLETE.
wr() { local f=$1; shift; printf "$@" >> "$f" || die "write to $f failed"; }

{
  printf '%q ' "$0" "${ARGV[@]}"; echo
} > "$OUT/argv.txt" || die "write failed"
echo "$SEED" > "$OUT/seed.txt" || die "write failed"
{ echo "bash $BASH_VERSION"; awk --version 2>/dev/null | head -1 || awk -W version 2>&1 | head -1; uname -srvmo
  # Workload commands run under /bin/sh; its read loop costs differ by shell.
  echo "/bin/sh -> $(readlink -f /bin/sh)"; } > "$OUT/tools.txt" || die "write failed"
printf '%s\n' "${BASE_ENV[@]}" > "$OUT/env-base.txt" || die "write failed"
# Names and lengths only, never values, and never traced: runs use env -i,
# so the caller's values cannot affect a measurement, and a value could be
# a credential. The subshell turns xtrace off, since under set -x (bash -x,
# or an inherited SHELLOPTS=xtrace) the assignment would print the value.
( set +x
  for n in $(compgen -e | LC_ALL=C sort); do
    case "$n" in
      LITEROOT_*|REVERIE_*|PROOT_*|LD_*|PATH) v=${!n}; printf '%s len=%d\n' "$n" "${#v}" ;;
    esac
  done ) > "$OUT/env-caller.txt" || die "write failed"
cp "$RUNNERS" "$OUT/runners.tsv" && cp "$WORKLOADS" "$OUT/workloads.tsv" || die "cannot copy the input files"
if [ -n "$PRELOAD_IDS" ]; then
  cp "$PRELOAD_IDS" "$OUT/preload-ids.tsv" || die "cannot copy --preload-ids"
  printf '%s\n' "${ID_OUT[@]}" > "$OUT/preload-identity.txt" || die "write failed"
fi
(cd "$OUT" && sha256sum runners.tsv workloads.tsv > inputs.sha256) || die "write failed"
(cd "$BENCH" && find . -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum) > "$OUT/bench.sha256" \
  || die "cannot hash $BENCH"
(cd "$BIN_HOST" && find . -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum) > "$OUT/bin-host.sha256" \
  || die "cannot hash --bin-host"
for name in "${!ROOTFS[@]}"; do
  d=${ROOTFS[$name]}/bench-bin
  if [ -d "$d" ]; then
    (cd "$d" && find . -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum) > "$OUT/rootfs-$name-bench-bin.sha256" \
      || die "cannot hash $d"
  fi
done
[ -z "$ASSETS" ] || cp "$ASSETS/SHA256SUMS" "$OUT/assets.SHA256SUMS" || die "cannot copy assets SHA256SUMS"
printf 'runner\tmode\tkind\tenv\tbinary\tbinary_sha256\tpreload\tpreload_sha256\n' > "$OUT/runner-ids.tsv"
for r in "${!R_NAME[@]}"; do
  bs=-; ps=-
  [ -z "${R_BIN[$r]}" ] || bs=$(sha256sum "${R_BIN[$r]}" | cut -d' ' -f1)
  [ -z "${R_PRELOAD[$r]}" ] || ps=$(sha256sum "${R_PRELOAD[$r]}" | cut -d' ' -f1)
  wr "$OUT/runner-ids.tsv" '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${R_NAME[$r]}" "${R_MODE[$r]}" "${R_KIND[$r]}" \
    "${R_ENVV[$r]:--}" "${R_BIN[$r]:--}" "$bs" "${R_PRELOAD[$r]:--}" "$ps"
done
printf 'workload\troot\trounds\trunner\tkind\n' > "$OUT/expected.tsv"
for w in "${!W_ID[@]}"; do
  for r in "${!R_NAME[@]}"; do
    wr "$OUT/expected.tsv" '%s\t%s\t%s\t%s\t%s\n' "${W_ID[$w]}" "${W_ROOT[$w]}" "${W_ROUNDS[$w]}" "${R_NAME[$r]}" "${R_KIND[$r]}"
  done
done
printf 'workload\trunner\tround\trc\twall_ns\tutime_ns\tstime_ns\tmaxrss_kb\tcheck\tflagged\tns_per_op\tstderr_bytes\trefused\twork\tstderr_head\n' \
  > "$OUT/per-run.tsv"
printf 'round\torder\tquiet_rc\tload1_start\tload1_end\tflagged\n' > "$OUT/rounds.tsv"
echo "run.sh: ${#R_NAME[@]} runners, ${#W_ID[@]} workloads, rounds 0..$MAX" | tee "$OUT/plan.txt"

load1() { cut -d' ' -f1 /proc/loadavg; }

# expect_ok EXPECT FILE: "-" accepts any stdout, "=TEXT" requires stdout to
# be exactly TEXT and a newline, anything else must occur in stdout.
expect_ok() {
  case "$1" in
    -) return 0 ;;
    =*) [ "$(cat "$2"; echo .)" = "${1#=}"$'\n'. ] ;;
    *) grep -qF -- "$1" "$2" ;;
  esac
}

# run_one W R ROUND FLAGGED
run_one() {
  local w=$1 r=$2 round=$3 flagged=$4
  local root=${W_ROOT[$w]} rootdir=/ p="" bin=$BIN_HOST run=""
  if [ "$root" != host ]; then
    rootdir=${ROOTFS[$root]}
    if [ "${R_MODE[$r]}" = translate ]; then
      bin=/bench-bin
    else
      p=$rootdir bin=$rootdir/bench-bin
      run="${LOADER[$root]} --library-path $rootdir/lib:$rootdir/usr/lib "
    fi
  fi
  local dir="$OUT/runs/${W_ID[$w]}/${R_NAME[$r]}/$round"
  mkdir -p "$dir" || die "cannot create $dir"
  local qroot qp qbin qassets qrun
  printf -v qroot '%q' "$rootdir"; printf -v qbin '%q' "$bin"; printf -v qassets '%q' "$ASSETS"
  if [ -n "$p" ]; then printf -v qp '%q' "$p"; else qp=""; fi
  local cmd=${W_CMD[$w]}
  if [[ "$cmd" == *"{RUNDIR}"* ]]; then
    mkdir "$dir/work" || die "cannot create $dir/work"
    printf -v qrun '%q' "$dir/work"
    cmd=${cmd//\{RUNDIR\}/$qrun}
  fi
  local qlog
  printf -v qlog '%q' "$dir/refusal.log"
  local prefix=${R_PREFIX[$r]//\{ROOT\}/$qroot}
  prefix=${prefix//\{REFUSAL_LOG\}/$qlog}
  cmd=${cmd//\{P\}/$qp}
  cmd=${cmd//\{BIN\}/$qbin}
  cmd=${cmd//\{ASSETS\}/$qassets}
  cmd=${cmd//\{BENCH\}/$BENCH}
  cmd=${cmd//\{RUN\}/$run}
  printf '%s\n' "env -i ${BASE_ENV[*]} ${R_ENVV[$r]} timeout ${W_TIMEOUT[$w]} $prefix $cmd" > "$dir/cmd.txt" \
    || die "write to $dir failed"
  local -a argv ev
  eval "argv=(timeout ${W_TIMEOUT[$w]} $prefix $cmd)"
  read -ra ev <<< "${R_ENVV[$r]}"
  env -i "${BASE_ENV[@]}" "${ev[@]}" "$BIN_HOST/timeit" "$dir/time.json" "${argv[@]}" \
    > "$dir/stdout.txt" 2> "$dir/stderr.txt" < /dev/null
  local rc=$? wall="" ut="" st="" rss=""
  if [ -s "$dir/time.json" ]; then
    wall=$(sed -n 's/.*"wall_ns":\([0-9]*\).*/\1/p' "$dir/time.json")
    ut=$(sed -n 's/.*"utime_ns":\([0-9]*\).*/\1/p' "$dir/time.json")
    st=$(sed -n 's/.*"stime_ns":\([0-9]*\).*/\1/p' "$dir/time.json")
    rss=$(sed -n 's/.*"maxrss_kb":\([0-9]*\).*/\1/p' "$dir/time.json")
  fi
  local check=ok
  if [ "$rc" -ne 0 ]; then
    check=rc
  elif ! expect_ok "${W_EXPECT[$w]}" "$dir/stdout.txt"; then
    check=output
  elif ! [[ "$wall" =~ ^[0-9]+$ ]]; then
    check=nowall
  fi
  local refused=-
  case "${R_KIND[$r]}" in
    literoot-*)
      local want=preload routes toks
      [ "${R_KIND[$r]}" = literoot-ptrace ] && want=ptrace
      if [ ! -f "$dir/refusal.log" ]; then
        refused=nolog
        [ "$check" != ok ] || check=nolog
      else
        routes=$(sed -n 's/^literoot: route //p' "$dir/refusal.log" | sort -u | paste -sd, -)
        toks=$(sed -n 's/^literoot: refused //p' "$dir/refusal.log" | tr ' ' '_' | sort | uniq -c \
          | awk '{ printf "%s%s*%s", sep, $2, $1; sep = ";" }')
        if [ "$routes" != "$want" ]; then
          refused="route:${routes:-none}"
          [ "$check" != ok ] || check=route
        fi
        # Every launcher that began must have ended "ok" (a launch or
        # reporter error is written as "end <pid> error <token>").
        local pids pid bad=""
        pids=$(sed -n 's/^literoot: begin \([0-9][0-9]*\)$/\1/p' "$dir/refusal.log")
        [ -n "$pids" ] || bad="nobegin"
        for pid in $pids; do
          grep -qx "literoot: end $pid ok" "$dir/refusal.log" || bad="end:$pid"
        done
        if [ -n "$bad" ]; then
          [ "$refused" = - ] && refused=$bad || refused="$refused;$bad"
          [ "$check" != ok ] || check=logend
        fi
        if [ -n "$toks" ]; then
          [ "$refused" = - ] && refused=$toks || refused="$refused;$toks"
          [ "$check" != ok ] || check=refused
        fi
      fi ;;
  esac
  local op
  op=$(sed -n 's/.*ns_per_op=\([0-9][0-9]*\).*/\1/p' "$dir/stdout.txt" | head -1)
  # The work a run did: its stdout without the timing, digested, so runs
  # of one workload can be compared across runners.
  local work head
  work=$(sed 's/ns_per_op=[0-9]*//g' "$dir/stdout.txt" | sha256sum | cut -c1-16)
  head=$(head -n1 "$dir/stderr.txt" | tr '\t\r' '  ' | cut -c1-120)
  wr "$OUT/per-run.tsv" '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${W_ID[$w]}" "${R_NAME[$r]}" "$round" \
    "$rc" "$wall" "$ut" "$st" "$rss" "$check" "$flagged" "${op:--}" "$(stat -c %s "$dir/stderr.txt")" "$refused" \
    "$work" "${head:--}"
}

runs=0
for round in $(seq 0 "$MAX"); do
  # The pairs due this round (every pair in the warmup round 0), shuffled.
  pairs=()
  for w in "${!W_ID[@]}"; do
    [ "$round" -eq 0 ] || [ "$round" -le "${W_ROUNDS[$w]}" ] || continue
    for r in "${!R_NAME[@]}"; do pairs+=("$w:$r"); done
  done
  [ ${#pairs[@]} -gt 0 ] || continue
  order=$(printf '%s\n' "${pairs[@]}" | awk -v s=$((SEED * 1000 + round)) \
    'BEGIN { srand(s) } { printf "%.12f\t%s\n", rand(), $0 }' | sort -n | cut -f2 | tr '\n' ' ')
  read -ra order_w <<< "$order"
  [ ${#order_w[@]} -eq ${#pairs[@]} ] || die "round $round: the shuffle gave ${#order_w[@]} pairs for ${#pairs[@]}"
  quiet_rc=- flagged=unchecked
  if [ -n "$QUIET_CMD" ]; then
    eval "$QUIET_CMD" > "$OUT/quiet-$round.txt" 2>&1
    quiet_rc=$?
    flagged=no
    [ "$quiet_rc" -eq 0 ] || flagged=yes
  fi
  start=$(load1)
  for pair in $order; do
    run_one "${pair%%:*}" "${pair#*:}" "$round" "$flagged"
    runs=$((runs + 1))
  done
  wr "$OUT/rounds.tsv" '%s\t%s\t%s\t%s\t%s\t%s\n' "$round" "$order" "$quiet_rc" "$start" "$(load1)" "$flagged"
done
rows=$(($(wc -l < "$OUT/per-run.tsv") - 1))
[ "$rows" -eq "$runs" ] || die "per-run.tsv has $rows rows for $runs runs"
printf 'COMPLETE runs=%s\n' "$runs" > "$OUT/COMPLETE" || die "cannot write COMPLETE"
echo "run.sh: done; $runs runs in $OUT"
