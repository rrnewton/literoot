#!/bin/sh
# Lay out the micro-cell fixtures inside a rootfs directory.
#
# usage: bench/mktree.sh <rootfs-dir> [files]
#
# Creates, under <rootfs-dir>:
#   bench-tree/f00000 .. f<files-1>  each exactly 4096 bytes (default 2000 files),
#                                    lines of "literoot bench fixture block"
#   bench-marker                     a file that exists only inside the rootfs,
#                                    holding "literoot bench marker" and a newline
#   bench-link -> bench-marker       a symlink for the readlink cell
# Refuses if any of them already exists. The content is fixed, so two
# trees made from the same arguments are byte-identical.
set -eu
root=${1:?usage: mktree.sh <rootfs-dir> [files]}
files=${2:-2000}
case "$files" in
  ''|*[!0-9]*) echo "mktree: files must be a number" >&2; exit 2 ;;
esac
[ "$files" -ge 1 ] && [ "$files" -le 99999 ] || { echo "mktree: files must be 1..99999" >&2; exit 2; }
[ -d "$root" ] || { echo "mktree: $root is not a directory" >&2; exit 2; }
# The fixtures must exist only inside a rootfs: the escape checks rely on it.
[ "$(cd "$root" && pwd -P)" != / ] || { echo "mktree: refusing the host root /" >&2; exit 2; }
for p in bench-tree bench-marker bench-link; do
  if [ -e "$root/$p" ] || [ -L "$root/$p" ]; then
    echo "mktree: $root/$p exists" >&2
    exit 2
  fi
done
mkdir "$root/bench-tree"
i=0
while [ "$i" -lt "$files" ]; do
  yes 'literoot bench fixture block' | head -c 4096 > "$root/bench-tree/$(printf 'f%05d' "$i")"
  i=$((i + 1))
done
printf 'literoot bench marker\n' > "$root/bench-marker"
ln -s bench-marker "$root/bench-link"
echo "mktree: $files files in $root/bench-tree"
