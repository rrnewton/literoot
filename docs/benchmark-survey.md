# proot benchmark and syscall survey for a literoot design note

Survey 2026-11-06, host `M1 dev host (x86-64 Linux)`. Every fetch succeeded, so nothing is reported blocked. Source read: `proot-me/proot` `v5.5.0`, `25dc6a3134891f98a79f57ce1c2c1b23ff15cad1`, 2026-10-02. [Verified: https://github.com/proot-me/proot/releases/tag/v5.5.0]

## 1. Path-translating syscalls and slow paths (upstream `v5.5.0`)

A `ptrace` tracer rewrites path args at syscall-enter and path results at exit; unlisted syscalls hit `default: nothing to do` and pass through untranslated. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]
Seccomp acceleration BPF-returns `SECCOMP_RET_TRACE` only for cared-about syscalls and `SECCOMP_RET_ALLOW` otherwise; `PROOT_NO_SECCOMP=1` stops on every syscall. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/seccomp.c]
Enter translation (`src/syscall/enter.c`, 84 distinct `PR_*` incl. control cases): [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]

- Single-path follow (`REGULAR` arg 1): `access acct chmod chown chown32 chroot creat getxattr listxattr mknod oldstat removexattr setxattr stat stat64 statfs statfs64 swapoff swapon truncate truncate64 umount umount2 uselib utime utimes`, plus `open` without nofollow flags. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]
- Single-path nofollow (`SYMLINK` arg 1): `lchown lchown32 lgetxattr llistxattr lremovexattr lsetxattr lstat lstat64 mkdir oldlstat readlink rmdir unlink`; `open`/`openat` use this under `O_NOFOLLOW` or `O_CREAT|O_EXCL`. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]
- `dirfd`-relative: `faccessat faccessat2 fchmodat fchmodat2 fchownat fstatat64 futimesat mkdirat mknodat name_to_handle_at newfstatat openat readlinkat statx unlinkat utimensat utimensat_time64` (`AT_SYMLINK_NOFOLLOW/FOLLOW` selects mode). [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]
- Two-path: `link rename linkat renameat renameat2 symlink symlinkat pivot_root inotify_add_watch`, plus `mount` (source only if starting `/`/`.`, plus target). For `symlink*` only the link path is translated, not the target string. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]
- Socket paths: `bind connect` at enter; `accept accept4 getpeername getsockname` (+ legacy `socketcall`) save size at enter, detranslate `sockaddr_un` at exit. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]
- Emulated/special (`PR_void` or custom): `getcwd` (virtual cwd at exit), `chdir fchdir` (virtual cwd only), selected `prctl`, plus `execve ptrace wait4 waitpid brk`. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]

Exit fixups (`src/syscall/exit.c`): `readlink readlinkat` (detranslate; full buffer triggers tracer re-`readlink`), `getcwd`, `rename*` cwd-prefix update, socket calls, `execve brk uname prctl wait*`. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/exit.c]
`-0` (`fake_id0`) additionally exit-filters the `stat` family and `getuid/geteuid/getgid/getegid` to rewrite ids, adding exit cost to `-0` stat-heavy runs. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/extension/fake_id0/fake_id0.c]
Gaps: `getdents/getdents64` have no core translation (CARE extension only; `glue.c` TODO to emulate parent `getdents`), and `openat2`/`execveat` are absent from `sysnums.list` (435 entries), so they fall through untranslated. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/sysnums.list]
Kernel-resident path resolution that never issues a traced path syscall (e.g. `io_uring` path ops) is therefore an escape class literoot must enumerate. [Unverified — inference from pass-through default]

Slow paths in cost order:

1. Single-tracer stop/rewrite at enter (+ exit where applicable) serializes traced syscalls across all tracee threads. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/seccomp.c]
2. `canonicalize()` (`src/path/canon.c`) `lstat`s the host path *per component*, `readlink`s + recurses per symlink (`MAXSYMLINKS` bound): one guest `open/stat` = O(components+symlinks) tracer host syscalls before the real syscall. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/path/canon.c]
3. Non-`AT_FDCWD` `dirfd` resolved per `*at` call via `readlink(/proc/<pid>/fd/<fd>)` in `translate_path()`. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/path/path.c]
4. `execve`/auxv rewriting (incl. corrected-`/proc/self/auxv` temp file) dominates fork/exec-heavy work: shells, builds, package managers. [Verified: https://github.com/proot-me/proot/blob/v5.5.0/src/syscall/enter.c]

## 2. Published benchmarks (do not average: CPU-bound ≈ free, path-bound = worst case)

| Study (date, host) | Numbers | Label |
|---|---|---|
| Gomes et al. udocker, 2018-06-05, x86_64 HPC (Altamira/CESGA/INCD) | Compile (host ≈923 s): P2 PRoot-no-seccomp ≈+30%, P1 PRoot+seccomp ≈+5%, Docker ≈native, VirtualBox ≈+15%. CPU sampling (host ≈31,187 s): all ≤2.5% slower. Gromacs GPU+8thr: P1 ≤+22%, F3 fakechroot ≈native; DisVis GPU: within 1–2%. (P=PRoot, F=`LD_PRELOAD`, R1=runC-userns, S1=Singularity.) | [Verified: https://arxiv.org/abs/1711.01758] |
| Termux #29944, 2026-05-29, Gentoo x86_64 Ryzen 9 5950X, proot-distro 5.1.1 / proot 5.1.107.72 | byte-unixbench n=3: outside 11861/12114/11991 vs inside 6746/6811/6466; "44% lower than docker/chroot". Desktop via `termux-docker`, not a phone. | [Verified: https://github.com/termux/termux-packages/discussions/29944] |
| MakersPet, 2026-10, Pixel 7 Android 17, Termux+Ubuntu 24.04 proot+seccomp | `getpid/write` 0.2→0.2 µs; `clock_gettime` 0.04→0.2 µs (5×); UDP 5→70 µs (14×); `open+close` 1.6→105 µs (64×); `PROOT_NO_SECCOMP=1`: 80–1,900 µs/call. ROS2 480p30: 145% core (proot 34%) 2-proc vs 42% (proot 12%) 1-proc. | [Verified: https://makerspet.com/blog/oomwoo-smartphone-ros2-termux/] |
| gVisor Perf Guide, GCE n1-standard-4 Broadwell, Debian 9 k4.19 | ptrace platform throughout; "highest structural costs by far", prefer Systrap. Values are chart-only, none quoted here. | [Verified: https://gvisor.dev/docs/architecture_guide/performance/] |
| Ant gVisor prod., 2021-12-02, Xeon E5-2650 v2, `getpid` | Native 62 ns, KPTI 236 ns, KVM 830 ns, ptrace 6,249 ns (~100× native). Sentry emulates *all* syscalls: upper-bound analogue, not proot-equivalent. | [Verified: https://gvisor.dev/blog/2021/12/02/running-gvisor-in-production-at-scale-in-ant/] |
| Evans bwrap notes, 2022-06-28, laptop (startup only) | `ls`: native ≈3 ms, `bwrap` ≈8 ms, Docker/Podman ≈279–378 ms. Namespaces cost setup, not per-syscall time. | [Verified: https://jvns.ca/blog/2022/06/28/some-notes-on-bubblewrap/] |

`chroot`/userns/`bwrap` repoint kernel lookup once at setup; steady-state path resolution stays in-kernel at native latency (`bwrap` = userns sandbox builder). [Verified: https://github.com/containers/bubblewrap/blob/main/README.md]
No single-host proot-vs-`bwrap` syscall microbenchmark was found; any "N×" claim is unmeasured until literoot runs it. [Unverified — absence in sources searched 2026-11-06]
Undated round claims ("~5%", "3–8% CPU", "20–30% I/O", "10–50 µs/syscall") lack host/workload/raw data and contradict both 64× `open` and ≤2.5% CPU-bound above: do not use as targets. [Unverified]

## 3. Termux `proot-distro`

Enters an OCI rootfs via `proot -0` + `/dev /proc /sys` binds (`LD_PRELOAD` cleared vs Termux `execve` hook) to run glibc distros (Alpine/Arch/Debian/Fedora/Ubuntu/Void…) unrooted on Android. [Verified: https://wiki.termux.com/wiki/PRoot]
On-device binary is the Android-patched fork `termux/proot`, so upstream `v5.5.0` coverage is a baseline, not on-device proof. [Verified: https://github.com/termux/proot]
README: filesystem-heavy work (compiles, package managers) "noticeably slower"; no real root/init/cgroups/namespaces/nesting. [Verified: https://github.com/termux/proot-distro/blob/master/README.md]
Only on-phone quantification found is the Pixel 7 row above (incl. "never `PROOT_NO_SECCOMP=1`"); the 44% UNIXbench figure is x86 desktop and must not be cited as phone speed. [Verified: https://makerspet.com/blog/oomwoo-smartphone-ros2-termux/]

## 4. DroidDeck baseline → literoot targets

Secondary summary only (BestHub distillation; `Droid-Deck/DroidDeck`, Snapdragon 8/Adreno 730+, updated 2026-10-13, no harness): path call 15–60 µs vs ≈0.5 µs native, single-tracer cap, in-process preload for safe paths cut `stat` 25→0.6 µs, `open` 25→0.9 µs, 8-thread `stat` 89k→3.6M/s, ≤57% proot-heavy speedup (v0.4.0), Steam cold ≈31→6 s. Its "7.5–9.5k traps/s" conflicts with 89k stats/s unless units differ: check primary repo before quoting. [Unverified — secondary, inconsistent: https://www.besthub.dev/articles/droiddeck-native-steamos-on-snapdragon-handhelds-run-windows-games-via-proton-d3f831052cda]
Arithmetic on supplied pair: 41.7× latency, 40.4× throughput; added cost ≈24.4 µs (98% of 25 µs); pre-fix ≈11k/s/thread vs post-fix 450k/s/thread at 8 threads → serialization-bound, not just CPU-bound. [Unverified — derived from secondary inputs]

Targets (re-measure on literoot hardware before promoting to requirements):

- Safe-path `stat/open` total ≤1.5 µs (≤1 µs added over ≈0.5 µs native), i.e. match 0.6/0.9 µs, not merely beat 25 µs. [Unverified — derived target]
- ≥3M stats/s at 8 threads with per-thread scaling reported; no single-tracer lock. [Unverified — derived target]
- Macro: ≤2.5% CPU-bound, ≤5% compile-like (seccomp-P1 point); native/`bwrap` parity = stretch. [Verified basis: https://arxiv.org/abs/1711.01758]
- One `ptrace` stop + O(components) tracer `lstat/readlink` per path call cannot meet the first two by tuning alone: avoid/shard/in-process the trap for the common case, and close or reject `openat2/execveat/io_uring/getdents`. [Unverified — design inference]
