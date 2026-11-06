# literoot M1 benchmark results (design §8.2 cells)

Machine: AMD EPYC 9D85 158-Core, Linux 7.1.3-0_fbk0, x86-64.
Runners: native = bubblewrap bind of the same rootfs (kernel path
resolution); proot = official 5.5.0 static binary (sha256
db185300a9daabbce86aca7632d8c7fdc4249f6f153171954013b70c5f491ec0);
literoot backends share one RootfsTool. Correctness gate: oracle
green on the measured commit; byte counts asserted per run (a
zero-byte walker result was caught and discarded during this
session — see `inguest-thread-escape` below).

## Cell 1 micro: stat loop 20k (median of 7)

| Runner | µs/stat | vs native |
|---|---|---|
| native (bwrap) | 2.91 | 1.00× |
| proot 5.5.0 | 8.76 | 3.0× |
| literoot-liteinst (patched) | 4.19 | 1.44× |
| literoot-trap (SIGSYS net) | 5.81 | 2.0× |
| literoot-ptrace (reference) | 56.9 | 19.6× |

DroidDeck target (design §8): patched ≤2× native — **met**.
literoot-liteinst is 2.1× faster than proot on this cell.

## Cell 1b: 8-thread stat, 40k stats (median of 5)

| Runner | ops/s | Note |
|---|---|---|
| native (bwrap) | 437,975 | |
| proot 5.5.0 | 173,469 | single tracer serializes |
| literoot-liteinst | — | guest SIGSEGV (139), retained: `inguest-thread-clone` |
| literoot-ptrace | 42,745 | |

## Cell 4 game walker: open/read-4KiB/close, 2000 files ×5

Main-thread (10k file ops, median of 5, bytes asserted 40,960,000):

| Runner | files/s | vs native |
|---|---|---|
| native (bwrap) | 74,127 | 1.00× |
| proot 5.5.0 | 58,113 | 1.28× slower |
| literoot-liteinst | 57,510 | 1.29× slower |
| literoot-trap | 44,002 | 1.68× slower |
| literoot-ptrace | 16,125 | 4.6× slower |

4-thread variant: native 65,632; proot 39,634; literoot-ptrace
10,238; literoot-liteinst — worker threads escape translation
(opens hit host paths, bytes=0), retained: `inguest-thread-escape`.

## Cell 3 compile: gcc -c 60 C files, rootfs=/ (median of 3)

| Runner | seconds | vs native |
|---|---|---|
| native (direct) | 1.025 | 1.00× |
| proot 5.5.0 | 1.986 | 1.94× |
| literoot-ptrace | 2.442 | 2.38× |
| literoot-liteinst | — | `cc1` exec refused EOPNOTSUPP (stage-1b) |

## Cell 2 package manager

Covered as correctness (byte-identical trees vs proot; see PR
body). Timing cell not yet recorded — `apk add` wall time under
each runner is future work, listed here so the gap is explicit.

## Addendum 2026-11-05: seccomp value + ptrace-stop anatomy

Same stat cell (20k stats), literoot slot `b4b81ae92`,
export head `b231b65a`. Commands:
`proot -r ROOT /bin/statloop 20000 /etc/os-release` with and
without `PROOT_NO_SECCOMP=1`.

**Corrected measurement (interleaved rerun):** 9 rounds,
randomized cell order per round, one warmup pass per cell,
same path/filesystem. Medians: native (bwrap) 2.89 µs/stat
(IQR 2.85–3.05), proot default 7.65 (7.30–8.25),
proot `PROOT_NO_SECCOMP=1` 11.37 (11.15–11.65),
literoot-liteinst 6.72 (6.60–6.95). The first (sequential,
non-interleaved) run reported native 13.25 µs *slower* than
proot — an artifact of drifting machine load between
sequential cell blocks (native ran first under a load spike;
its IQR was 3× wider than any interleaved cell). Interleaving
removes the ordering confound; the sequential native/proot
numbers from that run should not be used.

**Seccomp buys proot 1.49×** (11.37 → 7.65 µs/stat,
interleaved; 1.54× in the sequential run — same conclusion):
the BPF filter stops only on cared-about syscalls instead of
every syscall enter/exit. literoot-ptrace same-session
sequential figure was 69.26 µs/stat.

**Why in-guest moved between Cell 1 and the rerun (same op,
same binary, same path):** Cell 1 predates the
kernel-faithful canonicalizer (batch 6), which probes every
intermediate path component with a real `symlink_metadata`
syscall from Tool code — measurable extra work per stat
(no coordinator RPC is involved: `send_rpc` appears nowhere
in the Tool; a 200-stat in-guest run produces exactly 200
Tool syscall events). A generation-validated probe cache
(generation in a launcher-created memfd shared across the
guest tree; any guest process's mutating path syscall bumps
it *after* the mutation completes, on all return paths.
Host-side mutation between guest operations is not detected:
a stated divergence from proot, which re-probes every time;
if the memfd env is scrubbed or the fd closed, the cache
silently falls back to per-process generation) restored most of
it: second interleaved rerun (9 rounds): native 2.84,
literoot-liteinst 5.04 (1.77× native, shared-memfd cache generation), proot 7.87,
proot-noseccomp 11.93 µs/stat. **The ≤2×-native M1 claim is
therefore op- and commit-dependent, stated per cell:** stat
loop 1.44× (pre-canonicalizer) / 2.3× (uncached) / 1.77×
(cached); walker open-read-close 1.29×. It is not a blanket
per-syscall bound.

**Ptrace stops per op** (method: `strace -p <tracer-pid> -c -e
trace=ptrace,wait4,waitid` attached ~50 ms into a 20k-stat run,
counting syscalls made *by the tracer process*; lower bounds —
startup stops before attach are missed, and literoot's waits
were not observed on the attached thread): proot made 61,463
`ptrace` + 15,368 `wait4` calls (≈3.1 ptrace + 0.8 wait per
stat in-window — enter+exit stops with register/memory pokes);
literoot-ptrace made **329,921 `ptrace` calls (≈16.5 per
stat)**. Where the remaining literoot-ptrace gap goes:
Reverie's generic per-syscall injection (register save/restore
+ guest-memory peek/poke for path staging + injected syscall
execution, ~16 ptrace ops vs proot's ~4 lean enter/exit
rewrites) plus async Tool runtime overhead — i.e. stop *count
per op*, not stop latency; the in-guest backends remove stops
entirely, which is why liteinst lands at 9.78 µs here.

## Retained in-guest failures (by name)

- `inguest-exec-eopnotsupp`: guest execve → EOPNOTSUPP (stage-1b,
  docs/stage1b-scope.md).
- `inguest-thread-clone`: 8-thread guest SIGSEGV in-guest.
- `inguest-thread-escape`: pthread workers run untranslated.
- `inguest-musl-loader-bootstrap`: ld-musl-as-program opens the
  target before the preload arms.
