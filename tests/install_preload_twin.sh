#!/bin/sh
# tests/install_preload_twin.sh - acceptance twin for the literoot install fix.
# Usage: tests/install_preload_twin.sh <work-root> <checkout> <head-sha> <fixture-rootfs>
# Fixture: rootfs with a dynamically linked /bin/cat and /bin/true; /proc is
# bound by -R, never assumed. umask 022 (a common user default) is set once,
# after the checkout checks; every leg inherits it, so a cache that relies on
# the umask for privacy fails T1-modes. Signals NOTHING: no kill/pkill/timeout/pid
# arithmetic, foreground children only; the EXIT cleanup sends no signal.
# NO STUB PRINTS PASS: every leg below is implemented end-to-end in this
# script or delegated to a named Rust test invoked with --exact under a
# valid identifier and checked for exactly 1 test run and passed.
# A leg that cannot be induced FAILS loudly; nothing is skipped to green.
set -u
WORKROOT=${1:-}; CHECKOUT=${2:-}; HEADSHA=${3:-}; ROOTFS=${4:-}
[ -n "$WORKROOT" ] && [ -n "$CHECKOUT" ] && [ -n "$HEADSHA" ] && [ -n "$ROOTFS" ] || { echo "FAIL: usage" >&2; exit 2; }
[ ! -e "$CHECKOUT/target" ] || { echo "FAIL: checkout target exists" >&2; exit 1; }
# HEADSHA must be the checkout HEAD and the tree clean: --path legs
# build the working tree while --git builds HEADSHA; different bytes = fail.
ACTUALHEAD=$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null) || { echo "FAIL: cannot read checkout HEAD" >&2; exit 1; }
[ "$ACTUALHEAD" = "$HEADSHA" ] || { echo "FAIL: HEADSHA differs from checkout HEAD" >&2; exit 1; }
[ -z "$(git -C "$CHECKOUT" status --porcelain 2>/dev/null)" ] || { echo "FAIL: dirty checkout" >&2; exit 1; }
umask 022
WORK=$(mktemp -d "$WORKROOT/twin.XXXXXX") || exit 1
WORK=$(readlink -f "$WORK") || { echo "FAIL: work dir canonical path" >&2; exit 1; }
[ -n "$WORK" ] && [ -d "$WORK" ] || { echo "FAIL: work dir" >&2; exit 1; }
# Fixture precondition: a plain work root. Under a setgid one the
# cache directories inherit S_ISGID unless the implementation clears it, so
# T1-modes could FAIL on the fixture rather than the code; refuse up front.
[ ! -g "$WORK" ] || { echo "FAIL: setgid work dir; use a work root without the setgid bit" >&2; exit 1; }
KEEP=0
cleanup() { if [ "$KEEP" = "0" ]; then rm -rf "$WORK"; else echo "logs kept: $WORK" >&2; fi; }
trap cleanup EXIT
export XDG_CACHE_HOME="$WORK/cache"; mkdir -p "$XDG_CACHE_HOME"
export LITEROOT_PRELOAD=; unset LITEROOT_PRELOAD || true
FAILED=0
LEGFAIL=0
bad() { echo "FAIL: $1" >&2; FAILED=1; LEGFAIL=1; KEEP=1; }
legpass() { if [ "$LEGFAIL" = "0" ]; then echo "PASS: $1"; else echo "FAIL: $1 (see above)" >&2; fi; LEGFAIL=0; }
# check_positive BIN LOG OUT EXPECTED_CANON: valid log, zero refused lines,
# exactly one whole-line route preload, no ptrace, maps full pathname field
# equals EXPECTED_CANON. Prints no PASS; caller decides (no premature PASS).
check_positive() {
  "$1" --check-refusal-log "$2" >"$WORK/chk.txt" 2>&1 || { bad "positive log invalid ($2)"; sed -n '1,20p' "$WORK/chk.txt" >&2; return 1; }
  if grep -q 'refused' "$WORK/chk.txt"; then bad "positive refused lines ($2)"; return 1; fi
  [ "$(grep -cx 'literoot: route preload' "$2" || true)" = "1" ] || { bad "positive route count ($2)"; return 1; }
  if grep -q 'route ptrace' "$2"; then bad "positive ptrace route ($2)"; return 1; fi
  awk '{print $NF}' "$3" | grep -qxF "$4" || { bad "positive maps path missing: $4"; return 1; }
  return 0
}
# check_refusal BIN LOG LOGLINE ERRLINE OUT: nonzero already checked. Own log
# valid, validator lists exactly one refused line equal to LOGLINE, stderr
# carries ERRLINE whole-line, no ptrace, guest produced NO output (preflight
# refusals only; the reporter legs N07/N08 use their own oracle).
check_refusal() {
  "$1" --check-refusal-log "$2" >"$WORK/chk.txt" 2>&1 || { bad "refusal log invalid ($2)"; sed -n '1,20p' "$WORK/chk.txt" >&2; return 1; }
  STRIPPED=$(printf '%s' "$3" | sed 's/^literoot: //')
  [ "$(grep -c '^refused' "$WORK/chk.txt" || true)" = "1" ] || { bad "validator refused count ($2)"; return 1; }
  grep -qxF "$STRIPPED" "$WORK/chk.txt" || { bad "validator refused line: $STRIPPED"; return 1; }
  grep -qxF "$3" "$2" || { bad "exact log record missing: $3"; return 1; }
  grep -qxF "$4" "$5" || { bad "exact stderr refusal missing: $4"; return 1; }
  if grep -q 'route ptrace' "$2"; then bad "refusal ptrace fallback ($2)"; return 1; fi
  if grep -q 'route preload' "$2"; then bad "preflight false preload route ($2)"; return 1; fi
  [ ! -s "$6" ] || { bad "preflight guest produced output ($2)"; return 1; }
  return 0
}
# run_rust_test bin|test NAME: in-binary seams via --bin literoot with full
# path preload_materialize::tests::NAME; T6 via --test preload_cache_tamper.
# --exact valid identifier; exactly 1 ran and passed; own target and build dirs.
run_rust_test() {
  if [ "$1" = "bin" ]; then
    CARGO_BUILD_BUILD_DIR="$WORK/build-unit" cargo test --manifest-path "$CHECKOUT/Cargo.toml" --target-dir "$WORK/target-unit" \
      --bin literoot -- --exact "preload_materialize::tests::$2" >"$WORK/unit-$2.txt" 2>&1
  else
    CARGO_BUILD_BUILD_DIR="$WORK/build-unit" cargo test --manifest-path "$CHECKOUT/Cargo.toml" --target-dir "$WORK/target-unit" \
      --test preload_cache_tamper -- --exact "$2" >"$WORK/unit-$2.txt" 2>&1
  fi
  rc=$?
  [ "$rc" = "0" ] || { bad "rust $2 exit $rc"; sed -n '1,30p' "$WORK/unit-$2.txt" >&2; return 1; }
  grep -q 'test result: ok. 1 passed; 0 failed' "$WORK/unit-$2.txt" || { bad "rust $2 not exactly 1 passing test"; sed -n '1,30p' "$WORK/unit-$2.txt" >&2; return 1; }
  return 0
}
witness_run() { # $1=leg $2=root-suffix $3=log : initial cat only, -R binds /proc
  "$WORK/root-$2/bin/literoot" -R "$ROOTFS" --backend "${WITNESS_BACKEND:-liteinst}" --refusal-log "$3" \
    -- /bin/cat /proc/self/maps >"$WORK/out-$1.txt" 2>"$WORK/err-$1.txt"; return $?
}
# receipt_for LEG: exactly one build receipt under this leg's build dir;
# prints "digest flavour target artifact-path". Count != 1 fails (no head).
receipt_for() {
  N=$(find "$WORK/build-$1" -path '*preload-embed/*.receipt' -type f 2>/dev/null | wc -l)
  [ "$N" = "1" ] || return 1
  REC=$(find "$WORK/build-$1" -path '*preload-embed/*.receipt' -type f 2>/dev/null)
  echo "receipt=$REC"
  cat "$REC"
}
install_leg() { # $1=leg $2=path|git $3=extra cargo args $4=expected flavour
  LEGFAIL=0
  rm -rf "$WORK/root-$1" "$WORK/target-$1" "$WORK/build-$1"; mkdir -p "$WORK/root-$1"
  if [ "$2" = "git" ]; then
    CARGO_BUILD_BUILD_DIR="$WORK/build-$1" cargo install --git "file://$CHECKOUT" --rev "$HEADSHA" \
      --root "$WORK/root-$1" --locked --target-dir "$WORK/target-$1" $3 >"$WORK/cargo-$1.txt" 2>&1 \
      || { bad "$1 install"; sed -n '1,30p' "$WORK/cargo-$1.txt" >&2; legpass "$1"; return 1; }
  else
    CARGO_BUILD_BUILD_DIR="$WORK/build-$1" cargo install --path "$CHECKOUT" \
      --root "$WORK/root-$1" --locked --target-dir "$WORK/target-$1" $3 \
      >"$WORK/cargo-$1.txt" 2>&1 || { bad "$1 install"; sed -n '1,30p' "$WORK/cargo-$1.txt" >&2; legpass "$1"; return 1; }
  fi
  [ -x "$WORK/root-$1/bin/literoot" ] || { bad "$1 no binary"; legpass "$1"; return 1; }
  witness_run "$1" "$1" "$WORK/log-$1.txt"; rc=$?
  [ "$rc" = "0" ] || { bad "$1 witness exit $rc"; sed -n '1,20p' "$WORK/err-$1.txt" >&2; legpass "$1"; return 1; }
  RECTXT=$(receipt_for "$1") || { bad "$1 receipt missing/ambiguous"; legpass "$1"; return 1; }
  echo "$RECTXT" > "$WORK/receipt-$1.txt"
  EXP=$(echo "$RECTXT" | sed -n 's/^digest=//p'); ART=$(echo "$RECTXT" | sed -n 's/^artifact=//p')
  FLV=$(echo "$RECTXT" | sed -n 's/^flavour=//p'); TGT=$(echo "$RECTXT" | sed -n 's/^target=//p')
  [ "$(echo "$RECTXT" | grep -c '^digest=')" = "1" ] && [ "$(echo "$RECTXT" | grep -c '^flavour=')" = "1" ] && [ "$(echo "$RECTXT" | grep -c '^target=')" = "1" ] && [ "$(echo "$RECTXT" | grep -c '^artifact=')" = "1" ] || { bad "$1 receipt fields not unique"; legpass "$1"; return 1; }
  HOSTTGT=$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')
  [ -n "$EXP" ] && [ -n "$ART" ] && [ -f "$ART" ] || { bad "$1 receipt fields/artifact"; legpass "$1"; return 1; }
  case "$EXP" in *[!0-9a-f]*|'') bad "$1 digest not hex"; legpass "$1"; return 1;; esac
  [ "${#EXP}" = "64" ] || { bad "$1 digest length"; legpass "$1"; return 1; }
  [ "$FLV" = "$4" ] || { bad "$1 flavour $FLV expected $4"; legpass "$1"; return 1; }
  [ -n "$TGT" ] && [ "$TGT" = "$HOSTTGT" ] || { bad "$1 target mismatch"; legpass "$1"; return 1; }
  RECPATH=$(echo "$RECTXT" | sed -n 's/^receipt=//p')
  CANONBUILD=$(readlink -f "$WORK/build-$1" 2>/dev/null || echo "")
  case "$(readlink -f "$RECPATH" 2>/dev/null || echo "")" in "$CANONBUILD"/*) : ;; *) bad "$1 receipt outside leg build dir"; legpass "$1"; return 1;; esac
  [ "$ART" = "$(dirname "$RECPATH")/$4/libliteroot_preload.so" ] || { bad "$1 artifact not beside receipt"; legpass "$1"; return 1; }
  [ "$(sha256sum "$ART" | cut -d' ' -f1)" = "$EXP" ] || { bad "$1 artifact hash differs from receipt"; legpass "$1"; return 1; }
  echo "$EXP" > "$WORK/receipt-$1.sha"
  SO="$XDG_CACHE_HOME/literoot/$EXP/libliteroot_preload.so"
  [ -f "$SO" ] || { bad "$1 pinned cache file missing"; legpass "$1"; return 1; }
  [ "$(sha256sum "$SO" | cut -d' ' -f1)" = "$EXP" ] || { bad "$1 cache digest differs"; legpass "$1"; return 1; }
  CANON=$(readlink -f "$SO") || { bad "$1 canonicalize cache path"; legpass "$1"; return 1; }
  check_positive "$WORK/root-$1/bin/literoot" "$WORK/log-$1.txt" "$WORK/out-$1.txt" "$CANON" || { legpass "$1"; return 1; }
  legpass "$1"; return 0
}
install_leg T1 path "" liteinst || true
# T1-modes: our cache is private under umask 022: literoot/
# and literoot/<sha>/ are 0700, the published file is 0500.
LEGFAIL=0
EXPM=$(cat "$WORK/receipt-T1.sha" 2>/dev/null || echo "")
if [ -z "$EXPM" ]; then bad "T1-modes no T1 receipt digest"; else
  [ "$(stat -c %a "$XDG_CACHE_HOME/literoot" 2>/dev/null)" = "700" ] || bad "T1-modes literoot/ is not 0700"
  [ "$(stat -c %a "$XDG_CACHE_HOME/literoot/$EXPM" 2>/dev/null)" = "700" ] || bad "T1-modes literoot/<sha>/ is not 0700"
  [ "$(stat -c %a "$XDG_CACHE_HOME/literoot/$EXPM/libliteroot_preload.so" 2>/dev/null)" = "500" ] || bad "T1-modes cache file is not 0500"
fi
legpass "T1-modes"
install_leg T1g git "" liteinst || true
# T2: exported offline config + closed-port proxies, fresh dirs; provenance is
# this leg's own receipt (checked inside install_leg), never cache existence.
# The caller's state of the five variables T2 sets (set, set but empty, or
# unset) is saved first and restored after T2, so later legs (N10's
# networked install) keep the caller's own network settings.
T2_VARS="CARGO_NET_OFFLINE http_proxy https_proxy HTTPS_PROXY CARGO_HTTP_PROXY"
t2_save() { for v in $T2_VARS; do if eval "[ -n \"\${$v+x}\" ]"; then eval "T2_SET_$v=1 T2_VAL_$v=\"\${$v}\""; else eval "T2_SET_$v=0 T2_VAL_$v="; fi; done; }
t2_restore() { for v in $T2_VARS; do if eval "[ \"\$T2_SET_$v\" = 1 ]"; then eval "export $v=\"\$T2_VAL_$v\""; else unset "$v" || true; fi; done; }
# The five variables as a child process sees them, read with printenv (not
# with the save/restore code): "set <sha256 of the value>" or "unset" per
# name; an empty value is set.
t2_env_state() { for v in $T2_VARS; do if printenv "$v" >/dev/null 2>&1; then printf '%s set %s\n' "$v" "$(printenv "$v" | sha256sum | cut -d' ' -f1)"; else printf '%s unset\n' "$v"; fi; done; }
T2_ENV_BEFORE=$(t2_env_state)
t2_save
export CARGO_NET_OFFLINE=true
export http_proxy="http://127.0.0.1:9" https_proxy="http://127.0.0.1:9" HTTPS_PROXY="http://127.0.0.1:9" CARGO_HTTP_PROXY="http://127.0.0.1:9"
install_leg T2 path "--offline" liteinst || true
t2_restore
# T2-env: after T2 each of the five variables is exactly as the caller had
# it, as a child sees it; and the same save/restore pair keeps each of the
# three states (set, set but empty, unset), shown on chosen values in a
# subshell.
LEGFAIL=0
[ "$(t2_env_state)" = "$T2_ENV_BEFORE" ] || bad "T2-env caller variables not restored after T2"
( export CARGO_NET_OFFLINE=caller http_proxy= HTTPS_PROXY='a b$c*'; unset https_proxy CARGO_HTTP_PROXY || true
  before=$(t2_env_state)
  t2_save; export CARGO_NET_OFFLINE=x http_proxy=x https_proxy=x HTTPS_PROXY=x CARGO_HTTP_PROXY=x; t2_restore
  [ "$(t2_env_state)" = "$before" ] ) || bad "T2-env set, empty and unset round trip"
legpass "T2-env"
# T3b managed cache: corrupt THIS binary's (T1) entry; locked repair must run.
LEGFAIL=0
EXP=$(cat "$WORK/receipt-T1.sha" 2>/dev/null || echo "")
SO="$XDG_CACHE_HOME/literoot/$EXP/libliteroot_preload.so"
if [ -z "$EXP" ] || [ ! -f "$SO" ]; then bad "T3b no pinned cache entry"; else
  [ "$(sha256sum "$SO" | cut -d' ' -f1)" = "$EXP" ] || bad "T3b pre-mutation digest wrong"
  chmod u+w "$SO" || bad "T3b chmod"
  python3 -I -c "import sys; d=bytearray(open(sys.argv[1],'rb').read()); d[256]^=0xFF; open(sys.argv[1],'wb').write(d)" "$SO" || bad "T3b mutation command"
  [ "$(sha256sum "$SO" | cut -d' ' -f1)" != "$EXP" ] || bad "T3b mutation no-op"
  witness_run T3b T1 "$WORK/log-T3b.txt"; rc=$?
  [ "$rc" = "0" ] || bad "T3b witness exit $rc"
  # Detection record: the materializer prints this whole line on stderr when
  # it publishes a damaged entry again; read from this run's own stderr file.
  grep -qxF "literoot: preload rematerialized" "$WORK/err-T3b.txt" || bad "T3b detection record missing"
  [ "$(sha256sum "$SO" | cut -d' ' -f1)" = "$EXP" ] || bad "T3b cache not rematerialized to embedded digest"
  CANON=$(readlink -f "$SO" 2>/dev/null || echo "")
  # Witness of THIS run (out-T3b), binary T1: never T1's earlier output.
  check_positive "$WORK/root-T1/bin/literoot" "$WORK/log-T3b.txt" "$WORK/out-T3b.txt" "$CANON" || true
fi
legpass "T3b"
# T3c user-supplied files via LITEROOT_PRELOAD. Every case: own log, no ptrace,
# file intact.
USR="$WORK/user-preload.so"
ART1=$(sed -n 's/^artifact=//p' "$WORK/receipt-T1.txt" 2>/dev/null || echo "")
if [ -z "$ART1" ] || [ ! -f "$ART1" ]; then bad "T3c no T1 artifact"; legpass "T3c"; else
  BIN1="$WORK/root-T1/bin/literoot"
  # T3c1 stamp field mismatch: walk PT_NOTE by name/type, flip inside
  # protocol_version only; assert exact stderr line plus field text.
  LEGFAIL=0; cp "$ART1" "$USR" || bad "T3c1 copy"
  python3 -I - "$USR" <<'PYEOF' || bad "T3c1 stamp edit"
import struct,sys
p=sys.argv[1]; d=bytearray(open(p,'rb').read())
assert d[:4]==b'\x7fELF', "not ELF"
e_phoff=struct.unpack_from('<Q',d,0x20)[0]; e_phentsize=struct.unpack_from('<H',d,0x36)[0]; e_phnum=struct.unpack_from('<H',d,0x38)[0]
hit=False
for i in range(e_phnum):
    off=e_phoff+i*e_phentsize; p_type=struct.unpack_from('<I',d,off)[0]
    if p_type!=4: continue
    p_offset=struct.unpack_from('<Q',d,off+8)[0]; p_filesz=struct.unpack_from('<Q',d,off+32)[0]
    pos=p_offset; end=p_offset+p_filesz
    while pos+12<=end:
        namesz,descsz,ntype=struct.unpack_from('<III',d,pos)
        name=bytes(d[pos+12:pos+12+namesz]).rstrip(b'\x00')
        desc_off=pos+12+((namesz+3)&~3)
        if name==b'literoot' and ntype==0x4c4954:
            # descriptor: magic(9) stamp_version u32 protocol u32 flavour u32
            proto_off=desc_off+9+4
            old=d[proto_off]; d[proto_off]=old^0xFF
            assert d[proto_off]!=old
            hit=True; break
        pos=desc_off+((descsz+3)&~3)
    if hit: break
assert hit, "literoot note/protocol field not found"
open(p,'wb').write(d)
PYEOF
  B4=$(sha256sum "$USR" | cut -d' ' -f1)
  export LITEROOT_PRELOAD="$USR"
  witness_run T3c1 T1 "$WORK/log-T3c1.txt"; rc=$?
  [ "$rc" != "0" ] || bad "T3c1 run unexpectedly succeeded"
  check_refusal "$BIN1" "$WORK/log-T3c1.txt" "literoot: refused launcher preload_stamp" "literoot: preload stamp mismatch: rebuild the preload" "$WORK/err-T3c1.txt" "$WORK/out-T3c1.txt" || true
  grep -q 'protocol_version' "$WORK/err-T3c1.txt" || bad "T3c1 field name missing on stderr"
  [ "$(sha256sum "$USR" | cut -d' ' -f1)" = "$B4" ] || bad "T3c1 user file modified"
  unset LITEROOT_PRELOAD || true
  legpass "T3c1"
  # T3c-missing: note removed; same refusal, file intact, own log.
  LEGFAIL=0; cp "$ART1" "$USR" || bad "T3cm copy"
  command -v objcopy >/dev/null 2>&1 || bad "T3cm objcopy absent (induction unavailable)"
  if command -v objcopy >/dev/null 2>&1; then objcopy --remove-section .note.literoot.preload "$USR" || bad "T3cm remove-section"; fi
  B4=$(sha256sum "$USR" | cut -d' ' -f1)
  export LITEROOT_PRELOAD="$USR"
  witness_run T3cm T1 "$WORK/log-T3cm.txt"; rc=$?
  [ "$rc" != "0" ] || bad "T3cm run unexpectedly succeeded"
  check_refusal "$BIN1" "$WORK/log-T3cm.txt" "literoot: refused launcher preload_stamp" "literoot: preload stamp mismatch: rebuild the preload" "$WORK/err-T3cm.txt" "$WORK/out-T3cm.txt" || true
  [ "$(sha256sum "$USR" | cut -d' ' -f1)" = "$B4" ] || bad "T3cm user file modified"
  unset LITEROOT_PRELOAD || true
  legpass "T3c-missing"
fi
if [ -n "$ART1" ] && [ -f "$ART1" ]; then
  BIN1="$WORK/root-T1/bin/literoot"; USRCANON=$(readlink -f "$USR" 2>/dev/null || echo "$USR")
  # A user file is admitted by its stamp alone; no digest pin applies to it.
  # T3c5a unpinned compatible success. Full
  # positive oracle with the USER file canonical path, never rc-only.
  LEGFAIL=0; cp "$ART1" "$USR" || bad "T3c5a copy"; export LITEROOT_PRELOAD="$USR"
  UB4=$(sha256sum "$USR" 2>/dev/null | cut -d' ' -f1); [ -n "$UB4" ] || bad "T3c5a before-hash"
  witness_run T3c5a T1 "$WORK/log-T3c5a.txt"; rc=$?
  [ "$rc" = "0" ] || bad "T3c5a witness exit $rc"
  check_positive "$BIN1" "$WORK/log-T3c5a.txt" "$WORK/out-T3c5a.txt" "$USRCANON" || true
  UAF=$(sha256sum "$USR" 2>/dev/null | cut -d' ' -f1); [ -n "$UAF" ] && [ "$UAF" = "$UB4" ] || bad "T3c5a user file modified"
  unset LITEROOT_PRELOAD || true
  legpass "T3c5a"
fi
# T-TRAP: default build --backend trap uses the liteinst blob (dispatch, not
# backend word); full positive oracle on the T1 cache path.
LEGFAIL=0
"$WORK/root-T1/bin/literoot" -R "$ROOTFS" --backend trap --refusal-log "$WORK/log-TTRAP.txt" \
  -- /bin/cat /proc/self/maps >"$WORK/out-TTRAP.txt" 2>"$WORK/err-TTRAP.txt"; rc=$?
[ "$rc" = "0" ] || bad "TTRAP witness exit $rc"
EXPT1=$(cat "$WORK/receipt-T1.sha" 2>/dev/null || echo "")
CANONT1=$(readlink -f "$XDG_CACHE_HOME/literoot/$EXPT1/libliteroot_preload.so" 2>/dev/null || echo "")
check_positive "$WORK/root-T1/bin/literoot" "$WORK/log-TTRAP.txt" "$WORK/out-TTRAP.txt" "$CANONT1" || true
legpass "TTRAP"
# TTRAPU: user override in the compatible trap pairing (stamp admission).
LEGFAIL=0; cp "$ART1" "$USR" 2>/dev/null || cp "$(sed -n 's/^artifact=//p' "$WORK/receipt-T1.txt" 2>/dev/null)" "$USR" || bad "TTRAPU copy"
export LITEROOT_PRELOAD="$USR"
UB4=$(sha256sum "$USR" 2>/dev/null | cut -d' ' -f1); [ -n "$UB4" ] || bad "TTRAPU before-hash"
"$WORK/root-T1/bin/literoot" -R "$ROOTFS" --backend trap --refusal-log "$WORK/log-TTRAPU.txt" -- /bin/cat /proc/self/maps >"$WORK/out-TTRAPU.txt" 2>"$WORK/err-TTRAPU.txt"; rc=$?
[ "$rc" = "0" ] || bad "TTRAPU witness exit $rc"
check_positive "$WORK/root-T1/bin/literoot" "$WORK/log-TTRAPU.txt" "$WORK/out-TTRAPU.txt" "$(readlink -f "$USR" 2>/dev/null || echo "$USR")" || true
UAF=$(sha256sum "$USR" 2>/dev/null | cut -d' ' -f1); [ -n "$UAF" ] && [ "$UAF" = "$UB4" ] || bad "TTRAPU user file modified"
unset LITEROOT_PRELOAD || true
legpass "TTRAPU"
# CTL ptrace control: must run with a valid log, and the maps detector must
# not find the preload in a ptrace run.
LEGFAIL=0
"$WORK/root-T1/bin/literoot" -R "$ROOTFS" --backend ptrace --refusal-log "$WORK/log-ctl.txt" \
  -- /bin/cat /proc/self/maps >"$WORK/out-ctl.txt" 2>"$WORK/err-ctl.txt"; rc=$?
[ "$rc" = "0" ] || bad "CTL exit $rc"
[ -s "$WORK/out-ctl.txt" ] || bad "CTL empty maps output"
"$WORK/root-T1/bin/literoot" --check-refusal-log "$WORK/log-ctl.txt" >"$WORK/chk.txt" 2>&1 || { bad "CTL log invalid"; sed -n '1,20p' "$WORK/chk.txt" >&2; }
[ "$(grep -cx 'literoot: route ptrace' "$WORK/log-ctl.txt" || true)" = "1" ] || bad "CTL route count"
CANONSO=$(readlink -f "$SO" 2>/dev/null || echo "$SO")
if awk '{print $NF}' "$WORK/out-ctl.txt" | grep -qxF "$CANONSO"; then bad "CTL detector accepted ptrace"; fi
legpass "CTL"
# N02 writable half end-to-end: XDG and HOME mode 0500 refuse by name.
LEGFAIL=0
mkdir -p "$WORK/nowrite/cache" "$WORK/nowrite/home"; chmod 0500 "$WORK/nowrite/cache" "$WORK/nowrite/home"
SAVEXDG="$XDG_CACHE_HOME"; SAVEHOME_SET=0; [ -n "${HOME+x}" ] && SAVEHOME_SET=1; SAVEHOME="${HOME:-}"; export XDG_CACHE_HOME="$WORK/nowrite/cache"; export HOME="$WORK/nowrite/home"
witness_run N02 T1 "$WORK/log-N02.txt"; rc=$?
export XDG_CACHE_HOME="$SAVEXDG"; if [ "$SAVEHOME_SET" = "1" ]; then export HOME="$SAVEHOME"; else unset HOME || true; fi
[ "$rc" != "0" ] || bad "N02 run unexpectedly succeeded"
check_refusal "$WORK/root-T1/bin/literoot" "$WORK/log-N02.txt" "literoot: refused launcher cache_dir" "literoot: no writable private cache directory for the in-guest preload" "$WORK/err-N02.txt" "$WORK/out-N02.txt" || true
chmod 0700 "$WORK/nowrite/cache" "$WORK/nowrite/home" || true
legpass "N02"
# Delegated unit seams (valid identifiers; --exact; exactly 1 passed).
# N01 embedded digest, N03 cache write, N04 persistent mismatch, N06 final-file
# probe, N02 noexec half, N16 flavour mismatch, the cache lock, a cache
# directory with a setgid or sticky bit, a symlinked or non-regular final
# path, a final file whose mode is not 0500, and T6 freshness/invalidation.
# Absence FAILS loudly.
for tst in n01_embedded_digest_refuses n03_cache_write_refuses n04_persistent_mismatch_refuses n06_final_probe_refuses n02_noexec_probe_refuses n16_flavour_mismatch_refuses lock_materialize_concurrent special_bits_dir_refuses symlinked_final_path_refuses non_regular_final_path_refuses widened_mode_republishes; do
  LEGFAIL=0; run_rust_test bin "$tst" || true; legpass "UNIT-$tst"
done
for tst in t6_semantic_change_changes_digest t6_touch_only_reruns_build_script t6_lockfile_rev_changes_version; do
  LEGFAIL=0; run_rust_test test "$tst" || true; legpass "UNIT-$tst"
done
# N07/N08 reporter-off fixture: real preload, valid stamp, never reports.
LEGFAIL=0
FIXDIR="$WORK/fixture-reporter"; mkdir -p "$FIXDIR"
CARGO_BUILD_BUILD_DIR="$FIXDIR/build" cargo build --locked --manifest-path "$CHECKOUT/preload/Cargo.toml" \
  --features reporter-off --release --target-dir "$FIXDIR/target" >"$WORK/fixture-build.txt" 2>&1 \
  || bad "N07 fixture build (FAIL: N07)"
FIXSO=$(find "$FIXDIR/target" -name 'libliteroot_preload.so' -type f 2>/dev/null | head -n 1)
NFIX=$(find "$FIXDIR/target" -name 'libliteroot_preload.so' -type f 2>/dev/null | wc -l)
[ "$NFIX" = "1" ] && [ -n "$FIXSO" ] && [ -f "$FIXSO" ] || bad "N07 fixture artifact count $NFIX"
if [ "$LEGFAIL" = "0" ]; then
  FIXB4=$(sha256sum "$FIXSO" 2>/dev/null | cut -d' ' -f1); [ -n "$FIXB4" ] || bad "N07 fixture baseline hash"
  export LITEROOT_PRELOAD="$FIXSO"
  witness_run N07 T1 "$WORK/log-N07.txt"; rc=$?
  [ "$rc" != "0" ] || bad "N07 run unexpectedly succeeded"
  grep -qxF "literoot: in-guest preload did not report" "$WORK/err-N07.txt" || bad "N07 stderr refusal missing"
  # Expected-error oracle: the validator must reject the log with
  # exit 1, no stdout and exactly its reporter-error message; any other
  # rejection FAILS. The exact-log check below binds the message to the pid.
  "$WORK/root-T1/bin/literoot" --check-refusal-log "$WORK/log-N07.txt" >"$WORK/chk-N07.out" 2>"$WORK/chk-N07.err"; crc=$?
  [ "$crc" = "1" ] || bad "N07 validator exit $crc, expected 1 (reporter-error rejection)"
  grep -Eqx 'literoot: end [0-9]+ error reporter' "$WORK/log-N07.txt" || bad "N07 reporter-error termination missing"
  [ "$(grep -cx 'literoot: route preload' "$WORK/log-N07.txt" || true)" = "1" ] || bad "N07 route count"
  FIXCANON=$(readlink -f "$FIXSO" 2>/dev/null || echo "")
  awk '{print $NF}' "$WORK/out-N07.txt" | grep -qxF "$FIXCANON" || bad "N07 fixture not mapped"
  # Exact lifecycle oracle: the log bytes are exactly these three LF-terminated
  # ASCII records, nothing before, between or after them (no refused line, no
  # second route, no record after the end); the validator's stdout is empty and
  # its stderr is exactly its reporter-error message for that same pid.
  # Whenever an initial-stack cap record is written (aarch64 only, and only
  # when the initial-loader cap applies), this exact check FAILS, never passes.
  python3 -I - "$WORK/log-N07.txt" "$WORK/chk-N07.out" "$WORK/chk-N07.err" <<'PYEOF' || bad "N07 exact reporter-error log"
import re,sys
log=open(sys.argv[1],'rb').read()
m=re.fullmatch(rb'literoot: begin ([1-9][0-9]*)\nliteroot: route preload\nliteroot: end \1 error reporter\n',log)
if m is None: sys.exit('N07 log is not exactly: begin P, route preload, end P error reporter')
if open(sys.argv[2],'rb').read()!=b'': sys.exit('N07 validator printed refused lines')
want=b'literoot: refusal log not valid: launcher '+m.group(1)+b' ended with error reporter\n'
if open(sys.argv[3],'rb').read()!=want: sys.exit('N07 validator rejection is not the reporter-error message')
PYEOF
  if grep -q 'route ptrace' "$WORK/log-N07.txt"; then bad "N07 ptrace fallback"; fi
  FIXA7=$(sha256sum "$FIXSO" 2>/dev/null | cut -d' ' -f1); [ -n "$FIXA7" ] && [ "$FIXA7" = "$FIXB4" ] || bad "N07 fixture file changed"
  legpass "N07"
  LEGFAIL=0
  # N08: same fixture, log option omitted; hard outcome via stderr + exit.
  "$WORK/root-T1/bin/literoot" -R "$ROOTFS" --backend liteinst \
    -- /bin/cat /proc/self/maps >"$WORK/out-N08.txt" 2>"$WORK/err-N08.txt"; rc=$?
  [ "$rc" != "0" ] || bad "N08 run unexpectedly succeeded"
  grep -qxF "literoot: in-guest preload did not report" "$WORK/err-N08.txt" || bad "N08 stderr refusal missing"
  awk '{print $NF}' "$WORK/out-N08.txt" | grep -qxF "$FIXCANON" || bad "N08 fixture not mapped"
  unset LITEROOT_PRELOAD || true
fi
[ "$(sha256sum "$FIXSO" 2>/dev/null | cut -d' ' -f1)" = "${FIXB4:-}" ] && [ -n "${FIXB4:-}" ] || bad "N07/N08 fixture file changed"
legpass "N08"
# N09 separator: space and colon cache paths refuse by name (own logs).
for variant in space colon; do
  LEGFAIL=0
  if [ "$variant" = "space" ]; then BADX="$WORK/bad cache"; else BADX="$WORK/bad:cache"; fi
  mkdir -p "$BADX" || bad "N09 mkdir"
  SAVEXDG="$XDG_CACHE_HOME"; export XDG_CACHE_HOME="$BADX"
  witness_run "N09$variant" T1 "$WORK/log-N09$variant.txt"; rc=$?
  export XDG_CACHE_HOME="$SAVEXDG"
  [ "$rc" != "0" ] || bad "N09-$variant run unexpectedly succeeded"
  check_refusal "$WORK/root-T1/bin/literoot" "$WORK/log-N09$variant.txt" "literoot: refused launcher preload_separator" "literoot: preload path contains a separator" "$WORK/err-N09$variant.txt" "$WORK/out-N09$variant.txt" || true
  legpass "N09-$variant"
done
# N10 not-built: ptrace-only install (no receipt/witness expected) refuses.
LEGFAIL=0
rm -rf "$WORK/root-N10" "$WORK/target-N10" "$WORK/build-N10"; mkdir -p "$WORK/root-N10"
CARGO_BUILD_BUILD_DIR="$WORK/build-N10" cargo install --path "$CHECKOUT" \
  --root "$WORK/root-N10" --locked --target-dir "$WORK/target-N10" \
  --no-default-features --features run >"$WORK/cargo-N10.txt" 2>&1 \
  || { bad "N10 install"; sed -n '1,30p' "$WORK/cargo-N10.txt" >&2; }
[ -x "$WORK/root-N10/bin/literoot" ] || bad "N10 no binary"
"$WORK/root-N10/bin/literoot" -R "$ROOTFS" --backend liteinst --refusal-log "$WORK/log-N10.txt" \
  -- /bin/cat /proc/self/maps >"$WORK/out-N10.txt" 2>"$WORK/err-N10.txt"; rc=$?
[ "$rc" != "0" ] || bad "N10 run unexpectedly succeeded"
check_refusal "$WORK/root-N10/bin/literoot" "$WORK/log-N10.txt" "literoot: refused launcher not_built" "literoot: in-guest not built into this binary" "$WORK/err-N10.txt" "$WORK/out-N10.txt" || true
legpass "N10"
# N11 override missing/unreadable: never falls through to the blob.
for variant in missing unreadable; do
  LEGFAIL=0
  if [ "$variant" = "missing" ]; then export LITEROOT_PRELOAD="$WORK/no-such-preload.so"; else cp "$ART1" "$WORK/noread.so" || bad "N11 copy"; N11B4=$(sha256sum "$WORK/noread.so" 2>/dev/null | cut -d' ' -f1) || bad "N11 before-hash failed"; [ -n "$N11B4" ] || bad "N11 before-hash empty"; chmod 000 "$WORK/noread.so" || bad "N11 chmod"; export LITEROOT_PRELOAD="$WORK/noread.so"; fi
  witness_run "N11$variant" T1 "$WORK/log-N11$variant.txt"; rc=$?
  [ "$rc" != "0" ] || bad "N11-$variant run unexpectedly succeeded"
  check_refusal "$WORK/root-T1/bin/literoot" "$WORK/log-N11$variant.txt" "literoot: refused launcher preload_missing" "literoot: LITEROOT_PRELOAD names no readable file" "$WORK/err-N11$variant.txt" "$WORK/out-N11$variant.txt" || true
  if [ "$variant" = "missing" ]; then [ ! -e "$WORK/no-such-preload.so" ] || bad "N11 missing path appeared"; else chmod 0600 "$WORK/noread.so" || bad "N11 restore readability"; N11A=$(sha256sum "$WORK/noread.so" 2>/dev/null | cut -d' ' -f1) || bad "N11 after-hash failed"; [ -n "$N11A" ] && [ "$N11A" = "$N11B4" ] || bad "N11 unreadable file changed"; fi
  unset LITEROOT_PRELOAD || true
  [ "$variant" = "unreadable" ] && chmod 0600 "$WORK/noread.so" || true
  legpass "N11-$variant"
done
# TTH: a TrapHost-flavour install. A trap-only build (no default features,
# inguest-trap) embeds the traphost preload: this leg's own receipt must say
# traphost, and --backend trap must run that blob from the cache under the
# full positive oracle. It runs last, so every leg above keeps the T1 cache
# path in SO.
WITNESS_BACKEND=trap
install_leg TTH path "--no-default-features --features inguest-trap" traphost || true
WITNESS_BACKEND=liteinst
if [ "$FAILED" = "1" ]; then echo "RESULT: FAIL" >&2; exit 1; fi
echo "ALL PASS"
