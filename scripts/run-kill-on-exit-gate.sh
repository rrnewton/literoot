#!/usr/bin/env bash
# Kill-on-exit gate (owner: museport / literoot lane). Runs
# the kill_on_exit suite once: ptrace kill semantics plus
# the in-guest named-refusal arm. The busy-daemon test
# loops internally (10 launcher runs). The strict unpaced
# fork-hop test (12 runs, each exactly 7) is quarantined
# with #[ignore] as a known failure on the Reverie
# fork-hop ESRCH race (plus a SIGTRAP-1541 class),
# https://github.com/rrnewton/reverie/issues/1377 —
# reproduce with --include-ignored (standalone --ignored
# did not reproduce); it is never weakened to accept the
# named rc2 refusal. No trap preload is built
# here: in-guest --kill-on-exit refuses before spawn by
# design, so the default-feature test binary covers the
# refusal case.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
cargo test -p literoot --test kill_on_exit
