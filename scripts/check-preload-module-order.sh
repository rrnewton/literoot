#!/bin/bash
# The preload's module declarations (preload/src/lib.rs) must be in rustfmt's
# order, so a module added or moved later lands in place.
#
# The check takes "rustfmt's order" literally: it feeds lib.rs to rustfmt on
# standard input, takes the formatted text from standard output, and compares
# the sequence of `mod NAME;` declarations before and after. Any difference
# in order fails the check. Nothing is parsed out of hunks or line runs, so no
# attribute, comment or neighbouring change can split or merge what rustfmt
# reorders together.
#
# Child modules are not read, and nothing stands in for them: rustfmt formats
# lib.rs alone, on standard input, where it does not open declared child
# files. This checks declaration order in lib.rs only; the children's syntax
# is the compiler's to check. The check writes only inside its own temporary
# directory, so a path attribute cannot make it write anywhere else, and it
# removes that directory on every exit, including a kill or a closed pipe.
#
# A rustfmt failure (a parse error, a missing toolchain, anything on stderr or
# no output) is refused, never read as "no declarations". So is a formatted
# text whose declarations are not the same names as the input's; that is also
# how a `mod NAME;` sharing its line with an attribute or another item ends
# up, since only rustfmt's output has it on a line of its own.
#
# rustfmt runs at the crate's edition (2021) with an explicit empty config:
# literoot has no rustfmt.toml, and without --config-path rustfmt would read a
# rustfmt.toml from any parent directory. The rustfmt version and style
# edition are printed on every run.
#
# usage: scripts/check-preload-module-order.sh [lib.rs]
#        scripts/check-preload-module-order.sh --self-test
#        scripts/check-preload-module-order.sh --help
# exit: 0 in order; 1 rustfmt reorders the declarations; 2 refused (rustfmt
#       does not run or fails, no declarations, names differ, bad usage).
set -uo pipefail
case ${1:-} in -* | '') ;; /*) target_arg=$1 ;; *) target_arg=$PWD/$1 ;; esac
cd "$(dirname "$0")/.." || exit 2
self=$PWD/scripts/check-preload-module-order.sh

# The temporary directories of check and self_test; removed on any exit,
# including one forced by a signal.
scratch= work=
cleanup() {
    if [ -n "$scratch" ]; then rm -rf -- "$scratch"; fi
    if [ -n "$work" ]; then rm -rf -- "$work"; fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
usage: scripts/check-preload-module-order.sh [lib.rs] | --self-test | --help
Checks that the `mod NAME;` declarations in lib.rs (default
preload/src/lib.rs) are in rustfmt's order (edition 2021, empty config).
Child modules are not read: rustfmt formats lib.rs alone, on standard input.
This checks declaration order in lib.rs only.
exit: 0 in order; 1 rustfmt reorders the declarations; 2 refused (rustfmt
does not run or fails, no declarations, names differ, bad usage).
EOF
}

# The names of `mod NAME;` declarations, in order, one per line.
declarations() {
    sed -n -E 's/^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+(r#)?([A-Za-z0-9_]+)[[:space:]]*;.*$/\4/p' "$1"
}

check() { # <lib.rs>
    local lib=$1 version rc before after hunks
    [ -f "$lib" ] || { echo "REFUSED: no file $lib" >&2; return 2; }
    if ! version=$(rustfmt --version 2>&1); then
        echo "REFUSED: rustfmt does not run: $version" >&2
        return 2
    fi
    echo "using $version, style edition 2021 (--edition 2021, empty config)"
    scratch=$(mktemp -d) || return 2
    : >"$scratch/rustfmt.toml"
    rustfmt --edition 2021 --emit stdout --config-path "$scratch/rustfmt.toml" <"$lib" >"$scratch/formatted.rs" 2>"$scratch/err"
    rc=$?
    if [ "$rc" -ne 0 ] || [ -s "$scratch/err" ] || [ ! -s "$scratch/formatted.rs" ]; then
        echo "REFUSED: rustfmt failed (exit $rc), so the order was not checked:" >&2
        cat "$scratch/err" >&2
        rm -rf -- "${scratch:?}"
        return 2
    fi
    declarations "$lib" >"$scratch/before"
    declarations "$scratch/formatted.rs" >"$scratch/after"
    # Informational: the line numbers rustfmt would change anywhere in lib.rs.
    hunks=$(rustfmt --edition 2021 --check --color never --config-path "$scratch/rustfmt.toml" <"$lib" 2>/dev/null |
        sed -n -E 's/^Diff in <stdin>:([0-9]+):$/\1/p' | tr '\n' ' ')
    echo "lib.rs rustfmt hunks: $(wc -w <<<"$hunks") (${hunks:-none})"
    before=$(wc -l <"$scratch/before")
    if [ "$before" -eq 0 ]; then
        echo "REFUSED: no module declarations in $lib" >&2
        rm -rf -- "${scratch:?}"
        return 2
    fi
    if ! cmp -s <(sort "$scratch/before") <(sort "$scratch/after"); then
        echo "REFUSED: the formatted text does not declare the same modules, so the order cannot be compared" >&2
        echo "(a \`mod NAME;\` sharing its line with an attribute or another item is recognised only after rustfmt splits it):" >&2
        diff <(sort "$scratch/before") <(sort "$scratch/after") >&2
        rm -rf -- "${scratch:?}"
        return 2
    fi
    if cmp -s "$scratch/before" "$scratch/after"; then
        echo "ok: the $before module declarations are in rustfmt's order"
        rm -rf -- "${scratch:?}"
        return 0
    fi
    echo "FAIL: rustfmt reorders the module declarations (lib.rs order, then rustfmt's):" >&2
    paste -d ' ' <(nl -ba -w2 -s' ' "$scratch/before") <(sed 's/^/-> /' "$scratch/after") >&2
    rm -rf -- "${scratch:?}"
    return 1
}

# self_test: each case edits a copy of the current lib.rs, optionally writes
# a child file next to the copy, runs the check (optionally with an
# environment setting) and compares its exit status with the expected one,
# and optionally requires an output line matching a pattern.
# same_bytes <expected> <file>: true only if the two files are byte for byte
# equal (no newline or whitespace normalization).
same_bytes() {
    cmp -s -- "$1" "$2"
}

self_test() {
    local fail=0 count=0 lib=preload/src/lib.rs got
    work=$(mktemp -d) || return 2
    # standin <dir> <commands>: a stand-in for rustfmt in $work/<dir>, to put
    # first on PATH. It reports a version, prints nothing for --check, and
    # runs <commands> to format standard input.
    standin() {
        mkdir -p "$work/$1"
        printf '#!/bin/sh\ncase "$*" in\n*--version*) echo "rustfmt 0.0.0 (stand-in for the self-test)" ;;\n*--check*) ;;\n*) %s ;;\nesac\n' "$2" >"$work/$1/rustfmt"
        chmod +x "$work/$1/rustfmt"
    }
    standin standin-fail 'cat; exit 1'
    standin standin-warn 'cat; echo "warning: stand-in warning" >&2'
    standin standin-slow 'sleep "$STANDIN_SLEEP"; exec cat'
    # case_run <name> <expected exit> <python edit of s> [child file name] [env assignment] [required output line ERE]
    case_run() {
        count=$((count + 1))
        mkdir -p "$work/$1/preload/src"
        python3 - "$lib" "$work/$1/preload/src/lib.rs" "$3" <<'PY' || { echo "self-test $1: edit failed" >&2; fail=1; return; }
import sys
s = open(sys.argv[1]).read()
exec(sys.argv[3])
open(sys.argv[2], 'w').write(s)
PY
        # A child file the check must never read: a parse error.
        [ -z "${4:-}" ] || printf 'fn broken( {\n' >"$work/$1/preload/src/$4"
        if [ -n "${5:-}" ]; then
            env "$5" "$self" "$work/$1/preload/src/lib.rs" </dev/null >"$work/$1.out" 2>&1
        else
            "$self" "$work/$1/preload/src/lib.rs" </dev/null >"$work/$1.out" 2>&1
        fi
        local got=$?
        if [ "$got" -ne "$2" ]; then
            echo "self-test $1: FAIL, exit $got, expected $2" >&2
            sed 's/^/    /' "$work/$1.out" >&2
            fail=1
        elif [ -n "${6:-}" ] && ! grep -qE -- "$6" "$work/$1.out"; then
            echo "self-test $1: FAIL, exit $got, but no output line matches $6" >&2
            sed 's/^/    /' "$work/$1.out" >&2
            fail=1
        else
            echo "self-test $1: ok (exit $got)"
        fi
    }
    swap='
a = "mod refusal_log;\nmod reporting;\n"; assert s.count(a) == 1
s = s.replace(a, "mod reporting;\nmod refusal_log;\n", 1)'
    # The shipped file. Its output must name the rustfmt that made the verdict:
    # literoot pins no toolchain, so this line is the only record of it.
    case_run current 0 'pass' '' '' '^using rustfmt [0-9]'
    # Two adjacent declarations swapped.
    case_run swapped 1 "$swap"
    # The first declaration moved above its predecessor, with a change on the
    # line just before the declarations too.
    case_run merged-across-edge 1 '
a = "#[path = \"../../src/arch.rs\"]\nmod arch;\nmod exec_stage;\n"; assert s.count(a) == 1
s = s.replace(a, "mod exec_stage;\n#[path = \"../../src/arch.rs\"]\nmod arch;\n", 1)
i = s.index("mod exec_stage;\n"); j = s.rindex(");\n", 0, i); s = s[:j] + " ) ;\n" + s[j + 3:]'
    # A formatting change right after the declarations, nothing in them.
    case_run neighbour-after 0 '
a = "use std::ffi::CStr;\n"; assert s.count(a) == 1
s = s.replace(a, "use   std::ffi::CStr;\n", 1)'
    # The two use lines right after the declarations swapped.
    case_run uses-swapped-after 0 '
a = "use std::ffi::CStr;\nuse std::mem::MaybeUninit;\n"; assert s.count(a) == 1
s = s.replace(a, "use std::mem::MaybeUninit;\nuse std::ffi::CStr;\n", 1)'
    # Extra spacing inside a declaration: formatting only, order unchanged.
    case_run spacing-only 0 '
a = "mod reporting;\n"; assert s.count(a) == 1
s = s.replace(a, "mod   reporting ;\n", 1)'
    # A test module declared out of line at the end of the file.
    case_run trailing-test-module 0 's += "\n#[cfg(test)]\nmod zz_more_tests;\n"'
    # A use line splits the declarations into two groups, and the second is
    # out of order.
    case_run second-group-out-of-order 1 '
a = "mod reporting;\n#[path = \"../../src/rootfs_tool.rs\"]\nmod rootfs_tool;\n"; assert s.count(a) == 1
s = s.replace(a, "mod reporting;\nuse std::ffi::CStr as _;\n#[path = \"../../src/rootfs_tool.rs\"]\nmod rootfs_tool;\n", 1)
b = "#[path = \"../../src/translate.rs\"]\nmod translate;\n"; assert s.count(b) == 1
s = s.replace(b, "", 1)
c = "use std::ffi::CStr as _;\n"; s = s.replace(c, c + b, 1)'
    # A multiline attribute on one declaration, with its neighbour moved
    # before it: one rustfmt group, out of order.
    case_run multiline-attribute-out-of-order 1 '
a = "#[path = \"../../src/refusal_log.rs\"]\nmod refusal_log;\nmod reporting;\n"; assert s.count(a) == 1
s = s.replace(a, "mod reporting;\n#[cfg(\n    any(unix, windows)\n)]\n#[path = \"../../src/refusal_log.rs\"]\nmod refusal_log;\n", 1)'
    # A path attribute pointing outside the tree at an existing file: the
    # check must leave that file byte for byte as it was, compared with cmp
    # against a copy made beforehand.
    printf 'CANARY: must stay byte-identical\n' >"$work/canary.rs"
    cp "$work/canary.rs" "$work/canary.expected"
    case_run path-escape 0 '
a = "#[path = \"../../src/arch.rs\"]\nmod arch;\n"; assert s.count(a) == 1
s = s.replace(a, "#[path = \"../../../canary.rs\"]\nmod arch;\n", 1)'
    if same_bytes "$work/canary.expected" "$work/canary.rs"; then
        echo "self-test path-escape canary: ok (unchanged)"
    else
        echo "self-test path-escape canary: FAIL, the file outside the tree changed" >&2
        fail=1
    fi
    # The canary comparison itself: a trailing newline added or removed is a
    # change, and must be reported as one.
    printf 'CANARY: must stay byte-identical\n\n' >"$work/canary.added-newline"
    printf 'CANARY: must stay byte-identical' >"$work/canary.removed-newline"
    for f in added-newline removed-newline; do
        if same_bytes "$work/canary.expected" "$work/canary.$f"; then
            echo "self-test canary comparison, $f: FAIL, the change was not detected" >&2
            fail=1
        else
            echo "self-test canary comparison, $f: ok (detected)"
        fi
    done
    # A parse error in lib.rs, alone and with the declarations out of order.
    case_run syntax-error 2 's += "\nfn broken( {\n"'
    case_run syntax-error-and-swapped 2 "$swap"'
s += "\nfn broken( {\n"'
    # rustfmt's toolchain missing (the rustup proxy is still on PATH), with
    # the declarations out of order.
    case_run toolchain-missing-and-swapped 2 "$swap" '' RUSTUP_TOOLCHAIN=literoot-missing-toolchain
    # A parse error in a child file, which the check never reads: the order
    # verdict is unaffected in both directions.
    case_run broken-child-and-swapped 1 "$swap" reporting.rs
    case_run broken-child-in-order 0 'pass' reporting.rs
    # No module declarations at all.
    case_run no-declarations 2 '
import re
s = re.sub(r"(?m)^mod [a-z0-9_]+;$", "", s)'
    # rustfmt failing, or warning, while still printing the whole file: the
    # names alone would match, so only the outcome check refuses these.
    case_run rustfmt-fails-with-full-output 2 'pass' '' "PATH=$work/standin-fail:$PATH"
    case_run rustfmt-warns-with-full-output 2 'pass' '' "PATH=$work/standin-warn:$PATH"
    # A declaration sharing its line with an attribute: refused, saying why.
    case_run same-line-attribute 2 '
a = "mod reporting;\n"; assert s.count(a) == 1
s = s.replace(a, "#[allow(dead_code)] mod reporting;\n", 1)' '' '' 'sharing its line'
    # The usage text states that child modules are not read.
    count=$((count + 1))
    local help
    help=$("$self" --help)
    if [ $? -eq 0 ] && grep -qF 'This checks declaration order in lib.rs only.' <<<"$help"; then
        echo "self-test usage-text: ok"
    else
        echo "self-test usage-text: FAIL, --help does not say that only lib.rs is checked" >&2
        fail=1
    fi
    # A run that is killed, or whose output pipe closes, must not leave its
    # temporary directory. The slow stand-in for rustfmt holds the check
    # mid-run; each run gets its own empty TMPDIR to inspect.
    mkdir -p "$work/tmp-term" "$work/tmp-pipe"
    count=$((count + 1))
    env PATH="$work/standin-slow:$PATH" TMPDIR="$work/tmp-term" STANDIN_SLEEP=30 \
        timeout -s TERM 1 "$self" "$work/current/preload/src/lib.rs" </dev/null >"$work/term.out" 2>&1
    got=$?
    if [ "$got" -eq 124 ] && [ -z "$(ls -A "$work/tmp-term")" ]; then
        echo "self-test cleanup-on-kill: ok (killed, nothing left)"
    else
        echo "self-test cleanup-on-kill: FAIL, exit $got (124 expected), left: $(ls -A "$work/tmp-term" | tr '\n' ' ')" >&2
        fail=1
    fi
    count=$((count + 1))
    env PATH="$work/standin-slow:$PATH" TMPDIR="$work/tmp-pipe" STANDIN_SLEEP=1 \
        "$self" "$work/current/preload/src/lib.rs" </dev/null 2>/dev/null | head -n 1 >"$work/pipe.out"
    if grep -q '^using ' "$work/pipe.out" && [ -z "$(ls -A "$work/tmp-pipe")" ]; then
        echo "self-test cleanup-on-closed-pipe: ok (nothing left)"
    else
        echo "self-test cleanup-on-closed-pipe: FAIL, first line: $(cat "$work/pipe.out"); left: $(ls -A "$work/tmp-pipe" | tr '\n' ' ')" >&2
        fail=1
    fi
    rm -rf -- "${work:?}"
    [ "$fail" -eq 0 ] && echo "self-test: all $count cases ok"
    return $fail
}

case ${1:-} in
--self-test) [ $# -eq 1 ] || { usage >&2; exit 2; }; self_test; exit $? ;;
--help) [ $# -eq 1 ] || { usage >&2; exit 2; }; usage; exit 0 ;;
-*) usage >&2; exit 2 ;;
esac
[ $# -le 1 ] || { usage >&2; exit 2; }
check "${target_arg:-$PWD/preload/src/lib.rs}"
