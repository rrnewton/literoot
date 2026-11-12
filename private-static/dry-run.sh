#!/bin/bash
# Dry run of literoot's private runtime build, up to the static archive.
#
# usage: private-static/dry-run.sh <target-dir> [--link]
#
# Builds the preload's mapped-successor image archive (literoot-preload,
# crate-type staticlib, x86_64-unknown-linux-musl) the way Reverie's
# factory expects to find it (reverie-liteinst-artifact
# selected_initializers.rs, MappedConsumer::Literoot: package
# literoot-preload, feature mapped-successor-image, entry source
# preload/src/mapped_entry.rs), with Hermit's private-static codegen
# (hermit-install/private-static/owned/prepare.py CODEGEN) plus v0 symbol
# mangling, which the factory's symbol discovery reads. Then checks the
# archive's symbols with nm:
#   - literoot_mapped_successor_entry, a global text symbol;
#   - literoot_mapped_successor_entry_observed_int3, the observation label;
#   - literoot_mapped_layout, the HLMLAY01 descriptor, in read-only data;
#   - literoot_preload::mapped_entry::{terminal, observe_initializer_return}
#     as v0 names, one module level under the crate root;
#   - the private runtime's 16 C allocator names and its strong __init_tls,
#     each defined (T) exactly once: Reverie's private-libc-exports, which
#     mapped-successor-image enables (Reverie 52fcfde3,
#     https://github.com/rrnewton/reverie/pull/1500, private libc exports
#     gated on a feature);
#   - no literoot_mapped_initial_entry (the first generation is later work);
#   - no LITEROOT_INIT, the preload's .init_array constructor, which the
#     musl mapped-successor build leaves out (preload/src/lib.rs;
#     scripts/check-preload-constructor.sh checks the LD_PRELOAD build keeps it).
# Linking and publishing a literoot image through the factory is NOT done
# here: it refuses by name until later work (Reverie's factory has no literoot
# first generation, and nothing supervises a literoot image yet). --link
# asks for that step and gets the refusal (exit 3).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
if [ $# -lt 1 ] || [ -z "$1" ]; then
    sed -n '2,32p' "$0"
    exit 64
fi
target=$1
link=${2:-}
codegen='-C relocation-model=pic -C code-model=small -C target-feature=+crt-static -C link-self-contained=yes -C symbol-mangling-version=v0'
if ! CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$codegen" cargo rustc --locked --offline \
    --manifest-path preload/Cargo.toml --lib --target x86_64-unknown-linux-musl --release \
    --features mapped-successor-image --crate-type staticlib --target-dir "$target"; then
    echo "FAIL: the mapped-successor-image archive did not build" >&2
    exit 1
fi
archive=$target/x86_64-unknown-linux-musl/release/libliteroot_preload.a
[ -f "$archive" ] || { echo "FAIL: no archive at $archive" >&2; exit 1; }
symbols=$(nm "$archive" 2>/dev/null) || { echo "FAIL: nm could not read $archive" >&2; exit 1; }
fail=0
need() { # <description> <extended regex over "type name">
    if grep -Eq -- "$2" <<<"$symbols"; then
        echo "ok: $1"
    else
        echo "FAIL: $1 (no match for $2)" >&2
        fail=1
    fi
}
need "successor entry is a global text symbol" ' T literoot_mapped_successor_entry$'
need "observation label is present" ' [TtNn] literoot_mapped_successor_entry_observed_int3$'
need "HLMLAY01 descriptor is in read-only data" ' [Rr] literoot_mapped_layout$'
need "terminal has its v0 name" ' [Tt] _RNvNtCs[0-9A-Za-z]+_16literoot_preload12mapped_entry8terminal$'
need "observer has its v0 name" ' [Tt] _RNvNtCs[0-9A-Za-z]+_16literoot_preload12mapped_entry26observe_initializer_return$'
# The private runtime's own definitions, by archive member: musl's libc
# objects may define some of these names too, and musl's __init_tls is weak.
members=$(nm -A "$archive" 2>/dev/null) || { echo "FAIL: nm -A could not read $archive" >&2; exit 1; }
for name in malloc __libc_malloc __libc_malloc_impl calloc __libc_calloc free __libc_free \
    realloc __libc_realloc reallocarray aligned_alloc memalign valloc posix_memalign \
    malloc_usable_size __malloc_allzerop __init_tls; do
    defined=$(grep -Ec -- ":reverie_inguest-[^:]*:[0-9a-f]* T $name\$" <<<"$members")
    if [ "$defined" -eq 1 ]; then
        echo "ok: reverie_inguest defines $name once (private-libc-exports)"
    else
        echo "FAIL: reverie_inguest defines $name $defined times, not once; the image needs private-libc-exports" >&2
        fail=1
    fi
done
if grep -q 'LITEROOT_INIT' <<<"$symbols"; then
    echo "FAIL: the preload's .init_array constructor (LITEROOT_INIT) is in the private image archive" >&2
    fail=1
else
    echo "ok: no preload constructor (LITEROOT_INIT) in the archive"
fi
if grep -q 'literoot_mapped_initial_entry' <<<"$symbols"; then
    echo "FAIL: literoot_mapped_initial_entry is present; the first generation is dh-tc7os work" >&2
    fail=1
else
    echo "ok: no first-generation entry (dh-tc7os)"
fi
[ "$fail" -eq 0 ] || exit 1
echo "dry run ok: $archive"
if [ "$link" = --link ]; then
    echo "refused: linking and publishing a literoot private runtime image needs dh-tc7os (Reverie's factory has no literoot first generation, and no supervisor transfers a literoot image yet)" >&2
    exit 3
fi
