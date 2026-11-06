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

## Retained in-guest failures (by name)

- `inguest-exec-eopnotsupp`: guest execve → EOPNOTSUPP (stage-1b,
  docs/stage1b-scope.md).
- `inguest-thread-clone`: 8-thread guest SIGSEGV in-guest.
- `inguest-thread-escape`: pthread workers run untranslated.
- `inguest-musl-loader-bootstrap`: ld-musl-as-program opens the
  target before the preload arms.
