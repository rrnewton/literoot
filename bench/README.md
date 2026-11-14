# bench: startup- and syscall-heavy timing for literoot

A small harness that times the same workloads under several runners,
such as native, bubblewrap, upstream proot, and literoot's backends,
and reports medians with their spread. Correctness is asserted in the
same run: a run whose exit status or output is wrong counts as a
failure, the warmup round included. It is never counted as a time.

## Pieces

| file | what it is |
|---|---|
| `timeit.c` | runs one command and writes its wall time (CLOCK_MONOTONIC) and its user/system time and peak RSS to a JSON file |
| `statloop.c` | `stat` one path N times; prints the in-process time per call; can check the file's content once after the loop |
| `opsloop.c` | `openat`/`close` or `readlink` one path N times; readlink must return the expected target; prints the time per call |
| `threadstat.c` | `stat` from T threads; aim it at a file that exists only in the rootfs, so a thread that escapes the rootfs fails instead of looking fast |
| `walker.c` | open, read 4 KiB and close every file of a tree, from T threads; each read must start with the fixture text, and the total bytes must match |
| `dlopen_many.c` | `dlopen` (RTLD_NOW) every library in a list file |
| `tick.c` | appends one byte to a counter file; the child of the fork+exec cell, so its children can be counted without tracing |
| `bench.h` | argument parsing, the monotonic clock and the fixture content check shared by the programs |
| `dlopen-list.txt` | the pinned library list of the dlopen cell (30 sonames common on glibc distributions) |
| `mktree.sh` | lays out the micro-cell fixtures in a rootfs: `bench-tree/` (4096-byte files), `bench-marker`, `bench-link` |
| `run.sh` | the interleaved runner: each round runs every (workload, runner) pair once, in an order shuffled from a recorded seed, after one warmup round that is checked but not timed |
| `summarize.sh` | per (workload, runner): status, n, failures and their classes, median, IQR, min, max, ratios to a native and a proot runner, and the same for the per-call time where a cell prints one; over all rounds and over rounds the quiet check did not flag |
| `runners.example.tsv`, `workloads.tsv`, `workloads-build.tsv` | example configurations; their formats are described in the header of `run.sh` |
| `assets.sha256` | the pinned sha256 of the lua source tarball the build workload uses |

## Build

```
cc -O2 -Wall -Wextra -Werror -o timeit timeit.c
cc -O2 -Wall -Wextra -Werror -o statloop statloop.c
cc -O2 -Wall -Wextra -Werror -o opsloop opsloop.c
cc -O2 -Wall -Wextra -Werror -pthread -o threadstat threadstat.c
cc -O2 -Wall -Wextra -Werror -pthread -o walker walker.c
cc -O2 -Wall -Wextra -Werror -o dlopen_many dlopen_many.c -ldl
cc -O2 -Wall -Wextra -Werror -o tick tick.c
```

Build the binaries twice: for the host, and dynamically for the rootfs's
libc (for example a musl toolchain for an Alpine rootfs). Copy the
second set to `<rootfs>/bench-bin`. The in-guest backends refuse static
initial executables, so the rootfs set must be dynamic.

`--bin-host` also holds `stat-list.txt`, the file list of the stat-heavy
shell cell, made once per host and then kept:

```
for f in /usr/bin/*; do [ -e "$f" ] && echo "$f"; done > <host-bin-dir>/stat-list.txt
```

run.sh records the sha256 of every file in `--bin-host` and in each
`<rootfs>/bench-bin`, so the list a table used is on record.

## Run

```
bench/mktree.sh <alpine-rootfs>
bench/run.sh --runners runners.tsv --workloads bench/workloads.tsv \
  --out <new-dir> --seed <n> --bin-host <host-bin-dir> --rootfs alpine=<alpine-rootfs> \
  --quiet-cmd '<command that exits 0 when the host is quiet>'
bench/summarize.sh <new-dir> host:native-plain,alpine:native-bwrap proot
```

The build workload runs separately, with `--workloads
bench/workloads-build.tsv --assets <dir>`, where `<dir>` holds
`lua-5.4.8.tar.gz` and a `SHA256SUMS` with the line from
`bench/assets.sha256`. Each of its runs extracts a clean tree into a
new directory of its own and builds it with `make -j4`; the extraction
is inside the timed region (a small part of a full build). It prints
the number of compiler invocations, which should equal native's.

Write `runners.tsv` with absolute paths. Every runner has a KIND, which
run.sh checks before round 0:

- Each in-guest row names its own literoot binary and its own preload
  (`LITEROOT_PRELOAD=` in the ENV column). Without that, one preload
  exported by the caller would serve every row.
- The trap row must use a literoot and a preload built with the
  `inguest-trap` feature. A literoot built without it runs
  `--backend trap` as the liteinst preload with site patching off,
  silently.
- Every literoot row passes `--refusal-log {REFUSAL_LOG}`. Each run's log
  must name the route the kind implies (in-guest or ptrace; it does not
  tell liteinst from trap, which rests on the build checks above), must
  end every launcher it began with "ok", and every refusal in it is
  recorded with the run.
- A `proot` row runs proot's default seccomp mode; `PROOT_NO_SECCOMP=1`
  is a separate `proot-noseccomp` row.

Every run starts from an empty environment plus PATH, HOME, LC_ALL=C and
the runner's ENV, so nothing exported by the caller changes a row; the
caller's related variables are recorded for disclosure only, by name and
length. The ENV column's values are recorded verbatim (runners.tsv,
runner-ids.tsv and every run's cmd.txt), so never put a credential in a
runners file. Keep the
host quiet, and treat every runner the same: run.sh itself sets no CPU,
memory, nice or I/O limits and no outer time limit, so run it inside one
bounded unit (cgroup, nice and I/O priority) that covers every runner. Without `--quiet-cmd`, no round is called quiet: the
quiet set is reported as UNCHECKED.

The micro-cell fixtures must not exist on the host itself (`/bench-marker`,
`/bench-link`, `/bench-tree`): run.sh refuses to start if they do, and
mktree.sh refuses the host root.

## Reading the results

- **Status.** Only OK rows carry numbers.
  - FAILED: any run of the pair failed, in any round, flagged or not, the
    warmup included. It fails both sets: correctness does not depend on
    host load. The failure classes name
    the check (`rc=N` with timeout, not-found or signal spelled out,
    `output`, `nowall`, `nolog`, `route`, `logend`, `refused`) and any literoot
    refusals of those runs; summary.md adds the first stderr line of the
    first such run. A literoot run
    that exits 0 after a refusal is a failure: the backend did not do
    all of the work.
  - INCOMPLETE: the run has no COMPLETE marker, or the pair lacks its
    warmup run or ran other than its ROUNDS. A run that was stopped part
    way never reads as clean.
  - WORK-DIFFERS: the OK runs of the workload did not all do the same
    work (see "Same work" below).
  - UNCHECKED: the quiet set of a run made without a quiet check.
  - NO-DATA: no run in the set.
- summary.tsv and summary.md show each runner's KIND. summarize exits 1
  only for a run without its COMPLETE marker; a complete run with FAILED
  rows exits 0, so read the status column.
- **Wall time and per-call time.** Wall time covers the whole runner
  process: its startup (for example proot's tracer setup, or literoot's
  runtime and preload) and exit as well as the workload. The micro cells
  also print `ns_per_op`, timed inside the loop; summarize reports it
  beside wall time. Compare per-call figures with earlier per-call
  measurements, not wall times.
- **The native baseline.** Every runner of an Alpine cell executes the
  same rootfs (musl) binaries: a `host`-mode runner starts them through
  the rootfs's musl loader. The two native runners still differ in the
  path they walk. A `host`-mode runner uses the long host path into the
  rootfs, which is what proot and literoot walk after translation. A
  bubblewrap runner uses the short in-rootfs path. summarize takes a
  native runner per root (`host:...,alpine:...`); say which one a table
  uses.
- **Calibration.** `startup-min` and `startup-min-alpine` do almost
  nothing. Their wall time is the timer, `timeout` and runner startup
  that every other cell's wall time includes; read the other cells
  against them.
- **Same work.** Every OK run of a workload must print the same stdout
  once its timing is removed (for example the same library count, child
  count or list length); otherwise all its rows read WORK-DIFFERS and the
  differing outputs are listed.
- **Warm cache.** The warmup round loads the trees, libraries and modules
  for every runner, so all numbers are warm-cache numbers, never
  cold-disk ones.
- **Threaded cells** fail when worker threads run outside the rootfs, or
  when a backend refuses thread creation. A backend that refuses
  `pthread_create` makes threadstat exit 2 with "threadstat:
  pthread_create failed" on stderr (musl reports the refused clone as
  EAGAIN). literoot records "refused unsupported thread_creation" in that
  run's refusal log, so the failure class names it.
- **Substitutes and limits in the workloads.**
  - `shell-exec` runs `tick` as its child, which also counts the
    children: the run passes only with exactly 500 bytes in its counter.
  - `shell-stat` walks the host's recorded `stat-list.txt` and requires
    every entry to exist (`[ -e ]`); it prints the list length (`t=`).
    Its loop runs under the host's `/bin/sh`, whose `read` costs differ
    (dash reads the list a byte at a time); tools.txt records which shell
    `/bin/sh` is, and two hosts' rows compare only with the same shell.
  - The python cells print a sentinel and must print nothing else.
  - `dlopen-many` requires all 30 listed libraries to load (`listed=30`,
    and dlopen_many exits nonzero unless loaded equals listed).
  - The micro cells check the marker's or each tree file's content, so a
    path that reached a same-named file outside the rootfs fails, and
    run.sh refuses to start while such host paths exist.
  - walker creates its threads even for one thread.
- **maxrss and CPU time** come from `wait4` on the `timeout` process: the
  peak RSS of the largest single process in the reaped tree (not a sum),
  and the CPU time of waited-for descendants. A runner whose tracer is a
  separate process (proot) can drop out of the maximum while an
  in-process runtime (literoot) is always counted. Do not compare memory
  across runners without saying so.

Do not average across workloads. A path-heavy cell and a CPU-bound cell
answer different questions.
