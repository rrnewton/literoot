# literoot design: a fast drop-in proot replacement

Status: DESIGN + M1 POC BRIEF, 2026-11-05.
This note is the contract for the POC branch and the M1–M3 milestones. Claims
about existing code are labelled **Verified-current** (read in pinned code),
**Partial**, **Design-only**, or **Unmeasured**. Nothing here claims an
aarch64 or Android result that has not been run.

## 1. What literoot is

One static binary, `literoot`, CLI-compatible with proot for the common
container use case: run programs as if `<rootfs>` were `/`, with bind mounts
emulated by path translation, fake-root identity, and no privilege, no user
namespaces, no setuid helper, and — unlike classic proot — no per-syscall
ptrace stop in the fast path.

Motivating workload: PC games on Horizon OS (Quest-class devices) via the
DroidDeck / Quest Deck runtime (Wine/FEX/DXVK/VKD3D/Turnip), plus the general
Termux/proot-distro use case. Games issue tens of thousands of small file
operations (asset open/stat/read bursts, shader-cache probes); proot's two
ptrace stops per path syscall (≈25 µs/stat measured in DroidDeck baselines
vs ≈0.6 µs native; 8-thread throughput 89k/s vs 3.6M/s — see §8) dominate
load times. literoot targets near-native path-syscall cost by rewriting
paths in-guest.

Milestones (explicit, in order):

| Milestone | Target | Proves |
|---|---|---|
| M1 | x86-64 Linux | Path-translation correctness + differential oracle vs real proot; in-guest fast path on the one arch liteinst supports today |
| M2 | aarch64 Linux | Port of the in-guest interception to aarch64 (new work, §7); same oracle |
| M3 | aarch64 Android app sandbox | Unprivileged app UID under the app's seccomp filter, no userns, possible execmem ban; seccomp-blocked syscall emulation (§5) |

M1 deliberately does **not** prove M2/M3. Reverie-liteinst is x86-64-only
today (**Verified-current**: liteinst patches x86-64 bytes by instruction
punning/WordPatch++; see the architecture note §1.1). The aarch64 port is
planned explicitly in §7, not assumed.

## 2. CLI compatibility scope

proot reference: `proot [options] [--] [command [args...]]`. literoot
accepts the same spelling so `proot-distro`-style scripts work unchanged.

In scope for M1 POC (must work): `-r/--rootfs <dir>` (a.k.a. `-r`),
`-b/--bind <host>[:<guest>]` (repeatable), `-w/--cwd <guest-cwd>` (default
`/` or `$PROOT_CWD`), `-0/--root-id` (fake uid/gid 0), `-c/--cwd` alias,
`-q` ignored-for-compat (QEMU passthrough is **out** initially — see
below), `--help/--version`, `--` terminator, and the `PROOT_*` environment
variables proot honours for the same functions
(`PROOT_ROOTFS`, `PROOT_CWD`, `PROOT_BINDINGS`-equivalent handling where
applicable; unknown `PROOT_*` are passed through to the guest untouched).

Cheap, include if free: `-k/--kernel-release <string>` (uname/release
spoofing — one struct rewrite in `uname`, `newuname`); `-R` (proot's
"rootfs + common bindings" shorthand: `-r` plus recommended binds
`/dev`, `/proc`, `/sys`, `$HOME`, …) — implement `-R` as `-r` plus the
documented default binding set so `literoot -R <dir>` matches proot.

Explicitly out of initial scope (named refusals, never silent no-ops):

- **QEMU / foreign-arch passthrough** (`-q qemu-…`). Running a different
  guest ISA is an emulator problem, not a path-translation problem. If
  `-q` is given, literoot refuses by name
  (`literoot: -q/qemu passthrough not supported yet`) rather than ignoring
  it. Revisit only as "exec qemu-user under literoot" composition later.
- **proot extensions** (`--extension`, seccomp acceleration extensions,
  `PROOT_EXTENSION_*`): refuse by name. literoot has one mechanism story
  (§3); loading proot's ptrace extensions is meaningless.
- **`--link2symlink`, `--mount-hiding-slash`** and other obscure proot
  toggles: parse-and-refuse by name until a real workload needs them.
  `--link2symlink` (hardlink→symlink emulation for filesystems without
  hardlinks) is the most likely early addition; it is a small change in
  the `linkat` handler and is listed as M1-stretch, not POC-blocking.
- **Network/uid namespaces**: proot never had them; literoot does not add
  them. Fake-root (`-0`) is identity *spoofing* only (§4.4).

Defaulting rule copied from proot: with no command, literoot execs the
rootfs's `/bin/sh` (resolved through the translated root). Exit status is
always the guest's exit status; literoot's own setup failures exit 125
with a named message (proot convention).

## 3. Mechanism

### 3.1 The three layers

```
literoot (launcher, out-of-guest)          guest process(es)
┌────────────────────────────┐   exec    ┌───────────────────────────────┐
│ parse CLI, build bind table│──────────▶│ literoot in-guest Tool        │
│ canonicalize rootfs/binds  │  + state  │ (Reverie Tool, replicated —   │
│ pick mechanism (§3.3)      │  handoff  │  per-process, no RPC §6)      │
└────────────────────────────┘           │  • patched path syscalls →    │
                                          │    local rewrite + inject     │
                                          │  • unpatched raw syscalls →   │
                                          │    seccomp/SUD trap → same    │
                                          │    rewrite                    │
                                          │  • non-path syscalls → native │
                                          └───────────────────────────────┘
```

1. **Path patching (fast path, B3).** Path-taking syscall sites
   (`openat`, `newfstatat`, `access`, `execve`, … §4.1) are patched
   ahead of time / at load with liteinst instruction punning so control
   reaches the in-guest Tool, which canonicalizes the path against the
   replicated bind table and issues the real syscall with the translated
   path (`inject`). Cost target: one string scan + one syscall, no
   context switch — i.e. native + O(path length).
2. **Trap safety net (correctness floor).** A seccomp filter
   (`SECCOMP_RET_TRAP` → in-guest `SIGSYS` handler) or, where available,
   Syscall User Dispatch catches path-taking syscalls from *unpatched*
   code: raw `syscall` instructions in static binaries, JIT output,
   Go/musl direct syscalls, `dlopen`'d code censused after patching.
   The trap handler runs the identical translation function. The net is
   what makes patching an optimization instead of a soundness
   requirement: **miss a site and you get slower, never wrong.**
   **Verified-current** caveat: SUD (`PR_SET_SYSCALL_USER_DISPATCH`) is
   absent from Reverie's in-guest runtime today (architecture note
   §1.0/§1.5); M1 ships the seccomp-trap net and treats SUD as an
   optimization to adopt when it is wired. Signal-masking constraints
   on the trap path are §5.2 — they are the reason patching, not
   trapping, must be the primary mechanism on Android.
3. **Everything else native.** `read`/`write`/`futex`/`mmap`/… never
   enter literoot. This is the entire performance thesis: classic proot
   (even with seccomp acceleration) still stops on every path syscall;
   literoot stops on none.

**Fallbacks, by named refusal only** (the architecture note §3 rule:
never silently downgrade). If in-guest arming fails for a guest image
(unpatchable site census, no writable trampoline arena, execmem ban
without a pre-patched fallback — §5.3), literoot either (a) refuses the
run with the exact missing fact, or (b) when explicitly passed
`--backend ptrace`, runs the *same* Tool under Reverie's ptrace backend
as a slow reference. There is no implicit "fall back to ptrace and hope
nobody notices": that would hide exactly the bugs M1 exists to find.
The ptrace mode is also the differential-oracle harness (§9): same Tool,
two mechanisms, byte-identical observable behaviour required.

### 3.2 Activation (first-instruction control)

The guest must never execute a path syscall before interception is
armed. Options, from the first-instruction design of record
(**Verified-current** status in architecture note §1.3): A-stop (ptrace
exec-stop, loader maps + arms the Tool runtime, then hands to the
guest `ld.so`) is the production path on desktop Linux; `LD_PRELOAD`
late activation has a declared unmonitored window (misses `ld.so`
itself and early constructors) and is acceptable only as an explicit
`--activation preload` debug mode; a custom userspace exec loader
(A-exec, zero ptrace) is **Design-only** today. literoot's M1 uses
A-stop via the existing Reverie launcher; M3 (Android, where the app
cannot rely on ptracing its children the same way and SELinux may
forbid it) is designed around pre-patched images + trap net (§5.3) —
the activation choice is per-platform, the Tool semantics are not.

### 3.3 Mechanism selection (never silently downgrade)

At launch literoot selects exactly one combination and prints it with
`-v`: `{patched+trap-net | trap-only | ptrace} × {A-stop | preload}`.
Selection inputs: host facts (CPUID-faulting irrelevant here; seccomp
availability; execmem allowed?; SUD available?) and guest facts
(patchable census? static/dynamic? PT_INTERP?). If the requested
combination's requirements are unmet, the run refuses with the missing
fact named. `--backend` pins the choice; default is "best correct
combination" with the choice reported, never hidden.

## 4. Path translation: the Tool

### 4.1 Syscalls that translate

The Tool subscribes to the path-taking set (x86-64 names; aarch64
equivalents in §7): `open`, `openat`, `openat2`, `creat`, `access`,
`faccessat`, `faccessat2`, `stat`, `lstat`, `newfstatat`, `statx`,
`readlink`, `readlinkat`, `mkdir`, `mkdirat`, `rmdir`, `unlink`,
`unlinkat`, `rename`, `renameat`, `renameat2`, `link`, `linkat`,
`symlink`, `symlinkat`, `mknod`, `mknodat`, `chmod`, `fchmodat`,
`chown`, `lchown`, `fchownat`, `utime`, `utimes`, `utimensat`,
`truncate` (path form), `chdir`, `chroot` (emulated: re-root, never
real), `mount`/`umount2` (fake-root success or `EPERM`, matching
proot), `execve`, `execveat`, `name_to_handle_at`/`open_by_handle_at`
(reverse-translation sensitive; M1 returns `EOPNOTSUPP` by name unless
the oracle shows a workload needs them), `inotify_add_watch`,
`fanotify_mark`, socket `bind`/`connect` with `sockaddr_un` paths,
and `io_uring` path ops (§4.6). Reverse-translation syscalls:
`getcwd`, `readlink` on `/proc/self/exe|/proc/self/cwd|/proc/self/fd/N`,
`getdents64` is *not* rewritten (dirents are names, not paths — but
see §4.5 for the `/proc` exceptions).

Each handler does the same three steps: (1) read the guest path
string/buffer, (2) `translate(guest_path, dirfd, cwd)` → host path,
(3) inject the syscall with a Tool-owned copy of the translated path
(never mutate guest memory in place — the guest may reuse the buffer,
and another thread may be reading it).

### 4.2 Translation algorithm

`translate` is pure and allocation-light (small-string fast path, no
heap traffic for paths under the common 256-byte case):

1. Resolve the base: absolute path → root; `AT_FDCWD` relative →
   replicated cwd (§6); `dirfd`-relative → the dirfd's recorded guest
   path (§4.3).
2. Lexically normalize `.`/`..` **inside the guest namespace**,
   clamping `..` at the guest root (proot semantics: `/../etc` is
   `/etc` in the rootfs, never an escape to the host).
3. Longest-prefix match against the immutable bind table ( guest
   prefix → host prefix), defaulting to `<rootfs> + guest_path`.
4. Symlink resolution: let the kernel resolve symlinks in the
   *translated* path, with one correction — an absolute symlink inside
   the rootfs (e.g. `lib -> /usr/lib`) must restart resolution inside
   the rootfs, not on the host. Implement by resolving component-wise
   in the Tool for any path containing a symlink whose target is
   absolute (detected via `readlink` on the translated prefix), or by
   opening with the translated path and, on the absolute-symlink case,
   re-translating. M1 implements component-wise resolution only when
   a prefix is a symlink (fast path: single translated syscall;
   slow path: per-component `readlink`/`openat` walk). This matches
   proot's observable behaviour, including `ELOOP` after 40 hops.

### 4.3 fd-relative calls

Every `*at` syscall with a real `dirfd` needs the *guest* meaning of
that fd. The Tool keeps a per-process fd table (§6) recording, for
each fd it has seen opened, the guest path it denotes. Fds inherited
across `execve` or received via `SCM_RIGHTS` have no record: recover
the guest path lazily via `readlink /proc/self/fd/N` and
reverse-translation (§4.5), caching the result. `O_PATH` fds, socket
fds, and pipes record "not a path" and any `*at` use returns the
kernel's own error unchanged (inject untranslated).

### 4.4 Fake root (`-0`) and identity

`-0` spoofs: `getuid/geteuid/getgid/getegid` → 0, `setuid/setgid/…`
family → success without effect (also required for Android, §5.1),
`stat` family `st_uid/st_gid` shown as 0 for files owned by the real
user (proot's exact rule: files owned by others keep their ids),
`chown` family → success. Without `-0`, identity syscalls pass
through natively on desktop Linux (but are still emulated on Android
where seccomp blocks them, §5.1 — behaviour must match real proot on
each platform; the oracle is per-platform).

### 4.5 Reverse mapping: `getcwd`, `readlink`, `/proc/self/*`

Anything that *returns* a path must return the guest path, not the
host path, or shells and build systems leak `<rootfs>` prefixes into
outputs (the differential oracle checks this byte-for-byte, §9):
`getcwd` returns the replicated cwd; `readlink` results that point
inside the rootfs/binds are reverse-translated (longest host-prefix
match → guest prefix); reads of `/proc/self/exe`, `/proc/self/cwd`,
`/proc/self/fd/*`, `/proc/self/maps`, `/proc/self/cmdline` are either
served from replicated state or post-processed. **M1 scope:**
`getcwd` + `readlink` + `/proc/self/fd` reverse map are required;
`/proc/self/maps` path scrubbing is best-effort (noted, oracle-listed
as known-partial; proot itself is imperfect here — the oracle records
proot's actual output, not an ideal).

### 4.6 `io_uring` path ops

`IORING_OP_OPENAT/OPENAT2/STATX` (and `UNLINK`, `RENAME`, `MKDIR`,
`SYMLINK`, `LINK`) carry paths in SQEs that the kernel consumes
asynchronously — in-guest rewriting must happen at `io_uring_enter`
submission time by scanning the SQ ring, copying and translating path
buffers into Tool-owned memory, and patching SQE pointers. M1:
intercept `io_uring_setup` to record ring geometry and
`io_uring_enter` to rewrite pending path SQEs. On Android `io_uring`
itself is seccomp-blocked (§5.1): M3 emulates the subset glibc/apps
use or fails `io_uring_setup` with the error that makes callers fall
back to plain syscalls (which are then translated normally) —
whichever the DroidDeck workloads require, decided by measurement,
not assumption.

### 4.7 `execve` re-arm (the hard part)

`execve` must: translate the target path; re-arm interception in the
new image **before its first instruction**; rewrite `PT_INTERP` so a
rootfs binary with `PT_INTERP=/lib64/ld-linux…` loads the *rootfs's*
`ld.so` (translate the interp path); handle `#!` scripts (kernel
re-exec with the interpreter path — translate that too); preserve the
fd table for non-`O_CLOEXEC` fds and the cwd; rebuild per-process
Tool state from the handoff (§6). **Verified-current** gap: in the
A-stop production path, `execve` successors are the weak point of
today's in-guest backend (architecture note §1.5). M1's POC proves
`sh → ls/cat` exec chains or reports the refusal by name — it does
not paper over a missing re-arm with a ptrace detour (that is the
explicit `--backend ptrace` mode's job, §3.1).

### 4.8 Fork, vfork, threads, signals

- `fork`/`clone` (no `CLONE_VM`): child inherits a copy of Tool state
  (§6); patch census is already in the shared-until-write text — no
  re-patching needed. `vfork`: parent suspended until exec/exit; the
  Tool must not allocate or lock in the child before exec (async
  constraints documented per handler).
- Threads (`CLONE_VM`): Tool per-thread state is minimal (scratch
  buffers); cwd/fd table are process-shared with lock-free reads of
  the immutable bind table and a sharded fd table. Path translation
  takes no global lock on the fast path (the DroidDeck 8-thread
  number is the requirement driving this, §8).
- Signals: patched handlers must be signal-safe (no malloc locks on
  the hot path; preallocated scratch); the trap-net handler's
  masked-signal hazard is §5.2. Guest signal dispositions are never
  stolen: liteinst refuses to replace a pre-existing `SIGTRAP`
  handler (**Verified-current**), and literoot inherits that refusal
  by name.

### 4.9 Named path refusals and known differences from Linux

literoot answers a path call natively whenever it can. When it cannot give the native answer with confidence, it
refuses the call by name. It returns an errno and writes one side-log line, so a refused call is never silent. This
section lists every such refusal and every known difference from Linux. A process's side log lists what it hit.

#### 4.9.1 Path refusal kinds

Each `refused path` refusal returns EACCES and writes `literoot: refused path <kind>`. One kind of the same wire
family, `synthetic_file_unavailable`, is not a refusal: the call is answered by the kernel's own file, and its line is
`literoot: answered path synthetic_file_unavailable` (the line text is not part of the wire identity, §4.9.6).

| Kind | Trigger | literoot | Native | Why |
| --- | --- | --- | --- | --- |
| `base_uninspectable` | literoot could not inspect the base: a stat or readlink error, or non-absolute /proc text (the decide unit `tests::decide_refuses_every_uninspectable_base`), or the Tool's climb in cred-ns-dotdot (a real binary) | EACCES | depends on the input. For cred-ns-dotdot, ENOENT. | without the base's identity no guest name can be checked. cred-ns-dotdot fails closed by ruling 4, a known difference. |
| `base_outside_root` | a live base directory with no guest name | EACCES | the lookup's answer | the base is outside every guest route |
| `proc_link_outside_root` | the guest's own cwd or `fd/<n>` is a directory outside the guest root, so the reverse mapping gives none. A dead or unnamed directory gives this kind too. | EACCES | the host path's answer | the host path must not reach the guest. A held non-directory behind `fd/<n>` is not refused: it goes to the kernel untranslated and gets the native ENOTDIR. |
| `proc_link_other_process` | never written. Another process's procfs entries (its magic links, cmdline, environ, maps and the rest) are the kernel's, as under proot (§4.9.8), per the owner directive of 2026-11-14; earlier drafts of this change refused them. The kind keeps its wire tag, unused. | — | — | literoot assumes non-hostile programs |
| `base_moved` | the base's /proc name does not lead back to it (moved, or held in another mount namespace), or the base changed during the search check | EACCES | the lookup's answer | the dev+ino check failed, so the name is not proven |
| `no_guest_route` | the final follow reached a relative link with no guest route | EACCES | the link's resolution | no guest-side name exists for the result |
| `probe_unsupported` | triggers 1-6 below | EACCES, nothing injected | the call's own answer | literoot has no trustworthy probe for this call |
| `synthetic_file_unavailable` (answered, not refused) | a cmdline literoot answers itself (its own process's, or a shared-record row's, §4.9.5) cannot be made. In-guest: the probe gate is closed (a guest filter installed or being installed in the process, which its children inherit, a flagged record, or the thread's dispatch ON or unreadable), memfd_create fails or admission refuses it, the Tool-side write fails or the calling thread's descriptor is not the empty memfd (the memfd is closed first), or openat2's argument probe proves nothing. On ptrace: the tracer itself is not dumpable, the guest left the tracer's mount namespace, the tracer's argument check gives any answer but EBADF, EINVAL, E2BIG or EAGAIN, the tracer's memfd cannot be made, or the guest's rewritten call fails with anything but EMFILE, ENFILE, ENOMEM or a restart code, or opens another object | the kernel's own cmdline file, which on every backend holds the argv literoot exec'd: `[rootfs interpreter, program, args…]` for a dynamically linked program or a script | the process's command line | nothing is refused: the guest gets the kernel's file, and the line says the synthesized answer was unavailable |

`probe_unsupported` triggers:
1. **setxattr or lsetxattr with a dead name, or a failed search check, in a dead base.** literoot's syscall table
   (Reverie's syscalls 0.6.18, last number 461) cannot name setxattrat. So the call is refused on every kernel,
   6.13 and later included, where setxattrat exists. It is refused by name, before argument validation. Native
   answers the argument errors first (EINVAL, ERANGE, E2BIG, EFAULT), then ENOENT or EACCES. A ".." climb that lands
   on a live directory is translated normally (fix 3's route).
2. **An untrusted probe result.** A probe or the search check returned ENOSYS, EPERM, a success (nothing is closed),
   or anything outside its expected set. EINTR and the ERESTART* codes are outside every expected set, and there is
   never a second injection.
3. **A guest seccomp filter.** The process installed or inherited a guest seccomp filter during the run, or an install
   is in flight (§4.9.4). This trigger is best-effort (§4.9.4, detector).
4. **A socket not positively identified as AF_UNIX** in the guest's current network namespace, given a relative AF_UNIX
   path in a dead cwd. That is a non-AF_UNIX socket, or an AF_UNIX socket from another network namespace. Natively the
   first kind answers a family errno (for example EINVAL or EAFNOSUPPORT); the second would have been answered by a
   path lookup. Both are refused by name. Natively an unbound UDP socket is autobound before the error for
   addrlen >= 16 (IPv4) or >= 24 (IPv6) (MEASURED, M9). For shorter lengths it is autobound only when no cgroup on the
   host has a connect4/6 BPF program attached (SOURCE-ONLY, INFERRED; not observable here). literoot never autobinds
   it. Reproducing each family's exact native errno is a follow-up, not part of fix 4.
5. **The descriptor changed** between the Tool's domain read and the probe.
6. **Syscall user dispatch ON.** A path call that needs a literoot probe, made on a thread with syscall user dispatch on
   (any mode but OFF), is refused with nothing injected. Native would answer it. On ptrace the mode is read from the
   kernel (PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG, Linux v6.4 or later). If that read fails with EIO, EINVAL or ENOSYS,
   tracking of the thread's own prctl calls is used instead, with the once-per-run line
   `literoot: sud config read unavailable errno=<e>`. Any other error fails closed. On trap and liteinst the mode always
   comes from tracking. Tracking counts only an exact 0 as success. Under §4.9.5 the in-guest ordinary route can reach
   only OFF, so in-guest this trigger is pinned by a unit only. Counted: `sud_refused` out of `probes`.

The same line is also written, outside the numbered triggers, for:
- a Tool-side fdinfo or fd read error other than ENOENT;
- an unreadable /proc status at a probe;
- a filter-count deficit or an unreadable count (§4.9.4, detector).

#### 4.9.2 Answers recorded for a dead base, and launcher tokens

- `literoot: answered path dead_base_name` and `literoot: answered path dead_base_search` record NATIVE answers, not
  refusals. They are listed here so a reader knows the records exist. For example, the 0600 dead base reached with
  "../x" gets the native EACCES and is recorded as `dead_base_search`. The order is the argument probe, then EACCES
  (search check), then EISDIR, then ENOENT, as natively.
- `literoot: refused launcher interp_not_guest`: on the walked-loader route, where the preload cannot arm, the in-guest
  launch is refused by name.
- In-guest exec and threads (stage 1b) are refused by name (EOPNOTSUPP); they work in ptrace mode only.
- https://github.com/rrnewton/literoot/issues/4: fix 4 closes the WALK part (a planted rootfs `proc/<x>` link). A
  rootfs `/proc` that is itself a symlink is an ordinary guest symlink: without `-b /proc` it resolves inside the guest
  root (an absolute `/proc` target loops to ELOOP, as natively in a chroot), and with `-b /proc` the bind is terminal
  and the rootfs entry is not read. No procfs check runs at startup. The rest of the issue stays open there.
- Evidence label, not a difference: the execve RLIMIT_NPROC EAGAIN cell is "source equivalence, not measured" (the same
  kernel function with the same task state; the state cannot be produced unprivileged).

#### 4.9.3 Limits of the probes

- **Hook arguments.** Pre-lookup security hooks (LSM socket/inode hooks, BPF cgroup sock_addr programs) see the PROBE's
  arguments ("x" with dirfd -1, or sun_path "/"; T3 bind's "/" with addrlen 4 and T4's 2-byte address), not the
  guest's. Under any LSM or cgroup BPF hook, no probe can create, connect, write or exec.
- **Two "not proven" cells:** connect-EINVAL (an LSM that denies with EINVAL itself) and bind-EADDRINUSE (an LSM that
  denies with EADDRINUSE itself). Any other probe result is outside the expected set (trigger 2).
- **Connect differences.** (a) The UNIX_CONNECT BPF hook does not run: natively it sees "x" and could rewrite it to a
  live listener. literoot's T4 fails before the hook, so the answer is ENOENT or EACCES and nothing connects.
  (b) Stream/seqpacket connect's new-socket allocation (unix_create1, sock_wmalloc) is not reproduced: natively ENFILE
  or ENOMEM is possible before the lookup, never under literoot. (c) A PASSCRED/PASSPIDFD socket is not autobound by a
  failed dead-base connect: natively it is autobound (M7: length 8), while under literoot its length stays 2. literoot
  does less than native, never more. If a reproduced autobind is ever added, it goes through security_socket_bind.
- **O_PATH fds** given to bind or connect: EBADF, as natively (read from fdinfo flags).
- **fd-reuse windows.** These are bounded limits, not native parity. The domain read's A→B→A swap and the base
  re-read's A→B→A sit beside fix 3's closed-fd window and the fd-number reuse window on `/proc/self/fd/<n>/…`. A
  transient fd change gives the conservative refusal (trigger 5). In the undetectable A→B→A case it gives an errno from
  another object. In the domain-read window, T4 on a swapped-in socket never does more than the native call racing the
  same swap.
- **An untrusted probe success never closes anything.** If the kernel ever really allocated an fd (impossible by the
  source), the cost is one leaked fd, never a closed guest fd. openat2's argument probe (its open_how against
  descriptor -1 after a failed walk) follows the same rule.
- **openat2's argument probe needs an open gate.** It runs only with the probe gate open (no guest filter installed,
  pending or flagged, and the thread's dispatch mode OFF) and under admission, like every other probe. Under a closed
  gate an openat2 whose walk fails and whose open_how the kernel would refuse first (EINVAL, E2BIG, EFAULT, EMFILE)
  answers the walk's errno (ELOOP or EACCES). The call fails either way.
- **Pre-lookup EPERM.** A native LSM EPERM before the lookup is answered as a refusal too: conservative, and named.

#### 4.9.4 Guest seccomp filters

- **(i) The named refusal and its denominator.** A process that installed or inherited a guest seccomp filter gets
  trigger 3 for every later probe. Per process, literoot counts installs, installs_refused, translated, refused and
  unseen_best_effort. Each process writes one `literoot: guest seccomp filter summary ...` line when it exits, and gates5
  sums these per backend. The line `literoot: guest seccomp filter install attempted` is written before each install
  is forwarded.
- **(ii) An install made while a probe is in flight is refused.** A guest seccomp filter install made while a literoot
  probe of the same thread group is in flight is refused with EOPNOTSUPP and
  `literoot: refused seccomp_install probes_in_flight in_flight=<k>`, on every backend. The refusal depends on the ORDER
  of the two events, not on time. It is counted per process (installs, installs_refused) and summed per backend by
  gates5. On trap and liteinst it cannot fire while Reverie's in-guest thread admission is off: each guest process has
  one thread, so no probe can overlap an install.
- **(iii) Filters from before the run** are invisible. Probes they deny give `probe_unsupported`, and a probe's ENOSYS or
  EPERM is never trusted. A filter that FAKES a plausible errno (for example EBADF for T1) cannot be detected.
- **(iv) Detector.** On trap and liteinst the Tool compares the process's Seccomp_filters count with the expected count:
  the count read before arming, plus 1 for Reverie's install, plus every install made since. This catches a filter
  installed through Reverie's trusted gate. An excess sets the filter flag and is counted as `unseen_best_effort`.
  A deficit or an unreadable count is refused. The first check runs before the process's first translated call, and a
  result latches: the expected count is never rebased to an observation. The detector is best-effort: a guest that
  jumps to a trusted gate can defeat it. The count is the procfs view, labelled "untranslated" and not
  "host-authentic": a chroot or a substituted /proc can change it. Filters and dispatch set before the run are
  disclosed limits. Plain `-r` without /proc still runs. On those backends the launcher writes, once each, as soon as it knows the backend:
  `literoot: scope detector best-effort; defeatable by a guest that jumps to a trusted gate` and
  `literoot: scope constructor-checks best-effort; defeatable by code that runs before the preload's constructor (LD_PRELOAD window)`.
- **(v) literoot's own syscalls under guest filters** are tracked in https://github.com/rrnewton/literoot/issues/7. A
  filter the guest installs also judges every syscall literoot injects: the translated path calls, their staging and
  the Tool's `prctl(PR_SET_NAME)`. On trap and liteinst it also judges every Tool-side syscall of the in-process Tool:
  the fdinfo and fd reads, the re-reads, and the refusal and summary RPC to the launcher. So a filter can refuse, fake
  or kill a call the guest did not literally make. Fix 4 guards only its own probes, through (i)-(iv). Done when: cBPF
  evaluation of the probe and of the original call, for probes AND the pre-existing injections.

#### 4.9.5 Trusted gate and syscall user dispatch

- **Containment.** literoot is not a security boundary; it assumes non-hostile programs (owner directive 2026-11-14).
  In particular, in-guest backends (trap, liteinst) do not contain a guest that jumps to a trusted gate. Reverie's in-guest filter ALLOWs the
  exact trusted-gate instruction addresses by design. A guest that jumps there makes kernel calls (clone, seccomp,
  unshare, …) that neither Reverie nor literoot observes, including a dispatch setter, after which a fix-4 probe may be
  decided by the guest's dispatch. See https://github.com/rrnewton/literoot/issues/7.
- **Syscall user dispatch on in-guest backends.** In-guest backends (trap, liteinst) refuse any
  prctl(PR_SET_SYSCALL_USER_DISPATCH) that would turn dispatch on: EOPNOTSUPP and the side-log line
  `literoot: refused guest syscall_user_dispatch`. Turning it off is allowed. An ordinary-route
  ptrace(PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG) keeps literoot's in-guest ptrace refusal (EPERM) and writes the same
  line; the line count does not split the two setters. Reason: the in-guest runtime owns SIGSYS (a guest's own SIGSYS
  handler is refused with EPERM), and a guest with dispatch on and a BLOCK selector is killed by SIGSYS with no message
  (measured on trap, liteinst and the TrapHost build). After an ON made through the trusted gate with a BLOCK selector,
  the in-guest runtime's own calls are dispatched, and the process dies by SIGSYS with no message (the same mechanism).
  Programs that need syscall user dispatch, for example Wine, need the ptrace backend, where it works natively. No Wine
  smoke run; the synthetic sud_probe stands in for it. R2 and run 2's evidence are recorded in
  https://github.com/rrnewton/literoot/issues/7.
- **Pre-existing injections under the guest's dispatch.** literoot's pre-existing injected calls (translated path
  calls, their staging, the Tool's prctl(PR_SET_NAME)), and on trap and liteinst every Tool-side syscall of the
  in-process Tool, are also decided by a guest's syscall user dispatch, and can raise SIGSYS or kill the guest. Fix 4
  does not change this. Tracked in https://github.com/rrnewton/literoot/issues/7, done when no injected call runs while
  the injecting thread has dispatch on, or such a call is refused by name.
- **Tracking limits** (wherever tracking is the source: ptrace before v6.4, trap and liteinst): a filter from before the
  run that fakes a 0 for an OFF call leaves the thread ON while tracking records OFF (the (iii) class). A tracer
  outside literoot can set a guest task's mode with PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG. On ptrace, Reverie holds
  every guest task's tracer slot. In-guest, an outside tracer is not seen.
- **The preload's OFF call** (LD_PRELOAD route, before arming):
  - x86_64: EINVAL counts as "dispatch absent" only on a release below 5.11 with no release-altering persona bit. A
    distro backport with an old release string is a backport risk. An x86 7.3+ kernel built with
    CONFIG_SYSCALL_USER_DISPATCH=n answers EINVAL legitimately and gets the named failure. Tracked follow-up: accept "absent" when
    the kernel's own config, where readable (/proc/config.gz or /boot/config-<release>), says the option is not set.
  - arm64: EINVAL counts as "dispatch absent" with no release bound. Through v7.3-rc6 only x86 selects it. If a future
    arm64 kernel gains dispatch, a host policy's EINVAL there would be misread as absent. Tracked follow-up: bound this acceptance
    once arm64 selects GENERIC_ENTRY and syscall user dispatch.
  - A uname or personality faked by code that runs before the constructor is the LD_PRELOAD-window case below.
- **LD_PRELOAD route only: code before the preload's constructor.** IFUNC resolvers, DT_PREINIT_ARRAY and the
  initializers glibc orders before the constructor all run before Reverie's filter. The preload clears dispatch for the
  initial thread and refuses to arm with more than one thread (`Threads: 1` from the same status read as the filter
  count). Both checks are best-effort and can be defeated by code that runs before the preload's constructor
  (literoot is not a security boundary; it assumes non-hostile programs). A
  pre-constructor SIGSYS handler is outside the guarantee: its exit_group is itself dispatched, so the
  process dies by SIGSYS, which fails closed. A filter installed in that window is outside the guarantee too: it is
  inside the baseline, so the detector does not see it. The mapped-successor route has no such window.
- **Own views and other processes.** literoot answers the guest's OWN procfs views of its command line and
  executable: an open of its own `cmdline` (by pid, by any of its thread ids, `self`, `thread-self` or
  `task/<tid>`, spelled or through a final symlink, from a dirfd or a cwd under /proc) gives its guest-side argv
  from literoot's records, not the launcher's, and an open or execve of its own `exe` reaches its guest exe. Its own
  `root` is the guest root, and its own `cwd` and `fd/<n>` continue from the directory's guest path when it has one
  that leads back to the same directory (the own links have this identity check too: §4.9.8). Readlink
  of its own links answers by owner, whatever the naming: `root` reads `/` (before this change, the host rootfs path),
  and `cwd`, `fd/<n>` and `map_files/<k>` read their guest paths. Every other per-process entry of its own
  (environ, maps, smaps, …) is the kernel's: it shows host values (launcher variables such as LD_PRELOAD with host
  paths, the host paths of mapped files). A guest process literoot does not own but that has a row in literoot's
  shared record (a guest's child on the in-guest backends, where no tracer can confirm it) is a guest process too:
  its `root`, `cwd` and directory `fd/<n>` continue and read as the guest's, readlink, open and execve of its `exe`
  reach the row's exe, and an open of its `cmdline` gives the row's argv, so ps inside the guest shows guest argv
  for it. A row that is gone, or that has no argv (or no exe), gets the kernel's file; another argv (a bare-pid
  cache, the caller's own) never answers for it. On ptrace such a child is traced, so it is owned; an open of its
  `exe` answers from its row too. Another (host) process's entries are the kernel's, as under
  proot: literoot assumes non-hostile programs (owner directive 2026-11-14; before it, they were refused as
  `proc_link_other_process`). One exception keeps a walk correct: a name continued past, or a final follow of, its
  `root`, `cwd` or a directory `fd/<n>` continues from that directory's guest path when it has a verified one, and
  otherwise goes to the kernel with the links in its rest counted against the walk's budget (§4.9.8). The full
  table is §4.9.8.
- **Synthetic command lines.** A cmdline literoot answers itself (its own process's, or a shared-record row's) is a
  memfd named `literoot-cmdline` holding the argv, mode 0444, made for that one open.
  On ptrace the tracer makes it, fills it, makes it 0444 and seals it
  (F_SEAL_WRITE, SHRINK, GROW and SEAL), and the guest's own call is rewritten to reopen it through
  `/proc/<tracer pid>/task/<tracer tid>/fd/<n>` (the tracer thread's own descriptor table), with O_NOFOLLOW cleared
  (the guest named a regular file) and, for openat2, the RESOLVE_BENEATH, IN_ROOT, NO_XDEV, NO_MAGICLINKS,
  NO_SYMLINKS and CACHED bits cleared in a staged 24-byte copy of open_how. The guest's own call is the only call
  injected; what is written into the guest is its arguments, staged in the thread's scratch page (the rewritten
  name and, for openat2, the open_how). A thread with no page yet takes one from the pool, or maps a new pool first
  (an injected mmap the guest's filters see; Known limits). Staging is a tracer write into the guest, which ptrace
  allows only over a guest the tracer may attach to: a non-dumpable guest cannot be staged into unless the tracer is
  privileged (true of every translated call, not only this one). First the tracer runs the kernel's argument checks
  on a copy of the guest's arguments against descriptor -1, which opens nothing. For openat2 that copy has the
  guest's layout (the same offset in a page; a page the guest cannot read is inaccessible in the copy), so the
  kernel's own checks run in its order: the size against 24 and the page size, the range's end against the top of
  user memory, the extension word by word (E2BIG at the first nonzero word, EFAULT at an unreadable one), then the
  24 bytes. EBADF means valid, and EINVAL, E2BIG, EAGAIN and EFAULT are the guest's answer. A success at descriptor
  -1 can only be made up by a filter of the tracer's: the kernel's file answers, and nothing is closed. Then the answers the flags alone
  decide for an existing regular file, in the kernel's order: EEXIST for O_CREAT|O_EXCL, ENOTDIR for O_DIRECTORY,
  EACCES for a write mode or O_TRUNC (unless the tracer runs as root); under O_PATH only ENOTDIR. The route needs a
  dumpable tracer (PR_GET_DUMPABLE) and a guest in the tracer's mount namespace (literoot records every successful
  unshare(CLONE_NEWNS), setns and namespace-moving clone, and assumes a move when it cannot tell); otherwise the
  kernel's file answers. A descriptor the tracer can inspect must name the memfd, or it is closed and the kernel's
  file answers; the tracer's own descriptor closes when the call returns, or is held across a restart code until
  that thread's next such call or its exit.
  In-guest it is an injected memfd_create, with MFD_CLOEXEC
  exactly when the guest's open asked for O_CLOEXEC, behind the probe gate and under admission (§4.9.3), then filled
  from the Tool's side at offset 0, so the guest's descriptor reads it from the start. The write goes through the
  calling thread's own descriptor table, which differs from its thread group leader's after unshare(CLONE_FILES) or
  close_range(CLOSE_RANGE_UNSHARE): pidfd_open(tid, PIDFD_THREAD) and pidfd_getfd (a thread pidfd reads that
  thread's table) and pwrite on the duplicate, or, when either call fails, a write through a fresh open of
  `/proc/<tid>/fd/<n>`. Before any write the file must be the one that descriptor names (same device and inode), a
  regular file, and empty; otherwise nothing is written. Then its mode is set to 0444. No file or directory is made
  anywhere, so no host directory is needed and nothing is left behind. When it cannot be made (the probe gate is
  closed, memfd_create
  fails or admission refuses it, or the write or its check fails, in which case the memfd is closed first), the
  kernel's own cmdline file answers and the side log says `literoot: answered path synthetic_file_unavailable`.
  That file holds the argv literoot exec'd, on every backend: `[rootfs interpreter, program, args…]` for a
  dynamically linked program or a script (§4.7), which is not what the program was started with. Known differences
  from the kernel's file, on both routes: readlink of the descriptor shows `/memfd:literoot-cmdline (deleted)`;
  st_size is the length (natively 0); st_mode is 0444 like the kernel's, but it is a memfd's inode. In-guest only:
  F_GETFL shows O_RDWR, and the memfd is unsealed, so any guest can write to or truncate it through that descriptor
  (write(2) and ftruncate(2) check the descriptor, and the 0444 mode only governs a reopen), where the kernel's
  cmdline descriptor cannot be written; and the guest's open flags other than O_CLOEXEC are not applied (O_DIRECTORY,
  O_WRONLY, openat2's RESOLVE_* bits). In-guest, openat2's open_how is checked first, through the probe below the gate
  (§4.9.3): only the kernel's EBADF for a lookup on descriptor -1 lets the memfd answer, its pre-lookup errors
  (EINVAL, E2BIG, EFAULT, EMFILE) are the guest's, and any other result, or a closed gate, leaves the open to the
  kernel (the fallback line). So for openat2 the two routes differ: where the in-guest probe proves nothing the
  kernel's file (the exec'd argv above) answers where ptrace synthesizes the guest's argv; an EAGAIN (RESOLVE_CACHED
  with O_CREAT, O_TRUNC or O_TMPFILE) is the guest's answer on both, but in-guest it comes from the kernel's own open,
  after the fallback line; and with no free descriptor, ptrace answers the flag-decided EEXIST, ENOTDIR or EACCES
  before the guest's EMFILE, where the kernel and the in-guest probe answer EMFILE first. The two errno lists above
  (EINVAL, E2BIG, EAGAIN and EFAULT through the tracer; EINVAL, E2BIG, EFAULT and EMFILE in-guest) are what each
  argument probe answers directly, not a limit on what either route's final open returns. Both in-guest choices, this
  probe and the memfd route with its writable, unsealed descriptor and unapplied open flags, are known in-guest
  differences, and the C4 gate (tests/c4_backend_branches.rs) names them with these reasons rather than keying a
  refusal: neither refuses anything. In-guest the
  injection runs in the calling guest thread, and the Tool's own pidfd and write calls run in the same process; that
  route is checked in the source and measured only by the shared-record consumer rows.

#### 4.9.6 Wire identity

- The launcher reads the preload library's `.literoot_wire_id` record before it spawns anything. The preload checks
  the identity that the launcher appends to its tool selector before it arms. Both carry LITEROOT_WIRE_DIGEST, one
  SHA-256 over the config layout and the refusal schema.
- **Swap limit.** The check reads the file at `<path>`, and the guest's loader opens it later. A file swapped in
  between is not a build-mismatch case. If it happens anyway, the second barrier stops an old preload before arming,
  with the old preload's own message.
- **Disclosed plan delta (C5d).** The digest pin runs in the launcher's default-features test build. That build needs
  `reverie-inguest` as a dev-dependency (Cargo.toml:78; same rev and features as the normal dependency), beside the
  `reverie-rpc-transport` that C5d names, because the module that computes the digest also places the coordinator
  descriptor. Cargo.lock is unchanged by it. Review accepted it as disclosed.
- **Disclosed plan delta (C5d recording seam).** C5d's preload-side mismatch unit must show that a refused identity
  connects nothing and decodes nothing. To make that observable, the two preload constructors' steps after the
  bootstrap (the UTF-8 check, the identity check, then the selector's arming and the install) now run through one
  shared function, `wire_id::arm_with`. Its closure is the only holder of the coordinator socket and the only path to
  the install that decodes the config. The unit `preload_rejects_config_only_mismatch` passes a recording closure: a
  config-only mismatch is refused with 0 calls, and this build's identity reaches it exactly once. A source tripwire
  pins both constructors to that step. The messages and the order of checks are unchanged. The production change is
  that factoring, with no new API surface beyond the function itself.

#### 4.9.7 Exit-summary identity

- Exit summaries (`guest seccomp filter summary`, `probe summary`) identify a process by `receipt_id`, a number the
  launcher assigns to that process's one exit-summary emission. It is unique within the run by construction. It orders
  receipt only, not creation, and it is compared for equality only. The plan had specified a "run-unique creation
  sequence number". That cannot be produced
  in-guest without a new response RPC.
- The alternative, the kernel pair (pid, starttime from /proc/<pid>/stat field 22), was rejected for two reasons:
  - it is not unique: a pid can be reused within one clock tick (clone3 set_tid or ns_last_pid in a user+pid
    namespace), and pid namespaces repeat numbers;
  - it is not host-authentic: the read follows the process's mount namespace and root, so a substituted or private
    procfs can supply different content, and starttime carries the reader's time-namespace offset.
- Each summary also carries `kernel_id`, the pidfs inode. It is collected by the tracer on ptrace only (Linux 6.9+)
  and is always 0 in-guest (0 = uncollected). It is kernel metadata, not authenticated, and not the identity. On ptrace,
  a nonzero kernel_id shared by two identified receipts raises the warning `suspected_duplicate`. The warning never
  merges records or excludes them from sums. In-guest, a duplicate emission is visible only through gates5's roster,
  which flags both a missing emission (`expected_absent`) and an extra one (`expected_surplus`).
- A route that rebuilt a Tool for a live process without ExecState would emit twice. No route does so today: ExecState
  v3 carries the record across exec, and one emitter writes it. On ptrace (6.9+) such a double emission shows as
  `suspected_duplicate`. Before 6.9, and in-guest, only the roster shows it.
- A process that never emits (killed without exit callbacks, or alive at the end of the run, on any backend) has no
  summary. The reader cannot see it, and gates5 counts it against its roster as expected and absent.


#### 4.9.8 Per-process procfs entries: own views

literoot assumes non-hostile programs (owner directive 2026-11-14). It decides only a guest process's views of its
command line, executable, root, cwd and directory descriptors (its own, and a guest child's from its row); every
other procfs entry is the kernel's, and so is every entry of a host process, as under proot, except where a walk
continues past or follows a host process's directory link (below).

Every open of these entries is decided by one shared route, `self_link_route`, on all three open arms (openat,
open, openat2) and execve, on every backend (the Tool code is the same; backends differ only in which processes
are owned or have a shared-record row). It judges the final host entry of the spelled path, and, for an open that
follows a final symlink, the entry the guest-view walk resolves to (§4.9.5). The tool view turns `self` into the
caller's tgid and `thread-self` into `<tgid>/task/<tid>`, and a thread id in `/proc/<tid>` is taken as its thread
group, so every naming below reaches the same classifiers: magic links by `classify_rel` (src/translate.rs), the
cmdline file by `proc_cmdline_pid` (src/rootfs_tool.rs), both with the `<N>/` and `<N>/task/<T>/` forms.

Owner classes, judged by thread group: **own** is the caller's process (on ptrace, any process literoot traces).
**row** is a process literoot does not own that has a shared-record row: a guest's child on the in-guest backends.
**other** is any other process (a host process). Every process is judged under the caller's root: a guest child
that emulates a chroot of its own (`root_override`) is not represented, a disclosed limit. The equal-root case
is the one pinned.

| Entry | own: every naming | row: `/proc/<N>/X`, `/proc/<N>/task/<T>/X` | other |
| --- | --- | --- | --- |
| `cmdline` | the caller's guest argv, in a memfd (§4.9.5) | the row's argv, in a memfd | the kernel's |
| `exe` | the guest exe (open and execve follow it; readlink); an open without following (O_NOFOLLOW, O_PATH, O_CREAT\|O_EXCL) is the kernel's link | the row's exe (open and execve follow it; readlink); without following, the kernel's link | the kernel's |
| `root` | the guest root; a name under it is the guest's; readlink `/` | as own | continued past or followed: the directory's verified guest path, else the kernel's (the links after it counted); readlink the kernel's |
| `cwd`, `fd/<n>` | the kernel's on open; a name under a directory continues from its verified guest path (`proc_link_outside_root` when it has none, §4.9.1); readlink the guest path | as own | as `root` |
| every other entry | the kernel's | the kernel's | the kernel's |

A directory's **verified guest path** (`GuestProcLinks::verified_reverse`): the link's target, read by the Tool,
is absolute and not deleted, has the link's device and inode, maps back into the guest (`RootConfig::reverse`),
and that guest name, translated again, reaches the same device and inode (a deeper bind can shadow the name). A
host process's link that fails this, or that the Tool cannot read (another uid, or not dumpable), goes to the
kernel as is, and the links in the rest of the name count against the walk's 40-link budget
(`translate::count_raw_tail`); the walk then gives no guest route, so chdir records the kernel's cwd (reversed, or
UNNAMED_CWD) and execve records the file it reached.

Own namings: `/proc/<pid>/X`, `/proc/<pid>/task/<tid>/X`, `/proc/self/X`, `/proc/thread-self/X`,
`/proc/self/task/<tid>/X`, `/proc/<tid>/X` and `/proc/<tid>/task/<tid>/X`, each spelled, through a symlink or a
chain of them, from a dirfd on `/proc` or `/proc/<pid>`, or relative to a cwd under /proc. A row's or an own
`cmdline` that cannot be made falls back to the kernel's file (`answered path synthetic_file_unavailable`). A row
that is gone, or has no argv or exe, gets the kernel's file.

Unit rows: `own_views::own_views_on_every_naming` (every own naming, plain, through a symlink, from both dirfds and
from a cwd, on openat, openat2 and open, on the ptrace and the in-guest configurations, on a guest root that is not
the host's, so the guest exe and root differ from the kernel's), `own_views::other_process_is_native` (another
process's exe, cwd, root, cmdline, environ and maps on open, and its exe, cwd, root and fd/0 on readlink, all equal
to a native call), `own_views::own_numeric_readlink_is_reversed`, `own_views::own_exe_nofollow_is_the_link`,
`own_views::own_fd_map_files_and_traversal`, `own_views::row_root_cwd_fd_are_the_guests`,
`own_views::truncated_thread_self_readlink_reads_the_callers_table` and `own_views::thread_self_fd_is_the_callers_table`
(a thread with a descriptor table of its own), `own_views::guest_only_task_dir_and_parent_stay_in_procfs`,
`own_views::planted_rootfs_proc_link_loops_in_the_guest`, `own_views::own_root_reroots_charge_the_link_budget`,
`own_views::directory_bound_at_self_root_is_ordinary`, the `route_units` (a relative final link after a ".." out of a
deleted directory), the `raw_walk_units`
(another process's directory link), the a1 units (rows) and the p1b units (symlinks). `task/<T>/map_files` does
not exist in the kernel's thread directory, so it is ENOENT natively and through literoot.

Known limits:
- **A command line literoot cannot synthesize shows the exec'd argv.** On the in-guest backends, a process whose
  probe gate is closed reads `[rootfs interpreter, program, args…]` (for a dynamically linked program or a script)
  for its own cmdline and for its guest children's: a process with a seccomp filter installed or being installed,
  and every descendant of it (the record's filter state is inherited at fork), a flagged record, or a thread with
  syscall user dispatch ON. On ptrace none of these matter (§4.9.5); the same fallback happens only when the tracer
  is not dumpable or the guest left its mount namespace. The side log says `answered path
  synthetic_file_unavailable` each time.
- **The readlink-to-call window.** literoot reads a host process's directory link, then the guest's call runs. If
  that process moves in between, the call lands where it was when literoot read the link, as if the call had run a
  moment earlier. Afterwards the guest's cwd and exe records hold still.
- **The tail count is conservative.** After a host process's link goes to the kernel, literoot counts the links in
  the rest of the name by walking the kernel's objects from that link (by descriptor, in that process's mount
  namespace). It stops counting, with no error, at procfs (magic links, self, thread-self), at a component it cannot
  open, stat or read, or at a non-directory: over-counting would turn a native success into ELOOP. So a guest that
  can search a directory the Tool cannot (other credentials or namespace capabilities) can follow more than 40
  links in all, up to 40 more inside that rest. A final link the kernel follows because of a trailing slash or
  "/." is counted with the rest, once.
- **An execve whose file has no name.** An execve through a host process's link records the file it reached: its
  guest name when one leads back to it, else its host path (opens of /proc/self/exe then open that host file,
  readlink gives it, and its row publishes no exe). When the Tool cannot name the file at all (another mount
  namespace, a deleted file, a file it cannot reach), the record is the spelling, and a later open of
  /proc/self/exe walks it again.
- **A new thread can need an injected mmap.** A thread's first staging takes a 4096-byte slot from its image's pool
  (16 slots, mapped by the post-exec handler of a successful execve) or an exited thread's slot. Four cases map a new
  pool first, in the task that stages: the 17th thread of an image alive at once with no slot free (and so on every
  16th after it); in a process forked without an exec (its pool is not carried across the fork), its first new
  thread, and then every 16th; the first staging of a `CLONE_VM` process that is not a vfork; and on ptrace a vfork
  or posix_spawn child whose caller has no slot while none is free (a caller with no slot takes a free one before
  the clone, so the child shares it; with none free the child maps a pool in the shared address space that the
  caller's process does not reuse, 64 KiB on each such spawn). The call is
  `mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`, which the guest did not make. On
  ptrace it is injected into that thread, so every seccomp filter attached to the thread (one the guest installed,
  or one it inherited), the process's RLIMIT_AS and its memory cgroup judge it; a filter that refuses it fails that
  thread's path call, and one that kills kills the thread. In-guest (trap, liteinst) the runtime issues it through
  Reverie's trusted gate, which Reverie's own filter allows by address, and every other filter on the thread (one
  the guest installed, or one from before the run) judges it, as for every injected call (§4.9.4 (v)); in-guest a
  process has one thread today (thread admission is off), so only the post-exec pool is mapped there. The
  post-exec mapping itself predates this change (it was one page) and is the same class.
- **A pending execve's identity.** On ptrace a process's exe and argv are its successor's from just before the
  execve is injected (they are recorded first, for the new image) until the call returns: a sibling thread that
  reads /proc/self/exe or cmdline in that window sees the successor's. A failed execve restores the prior ones.
  Natively the old values hold until the exec's point of no return.
- **Checks no unit pins.** Two checks have no unit that fails without them: openat2's access_ok range check at its
  call site (its arithmetic has a unit; a dispatch case needs the last user page mapped, which another mapping can
  hold) and the pool mapping's image guard (not reachable on the pinned Reverie). Two test gaps remain: an
  unreadable status read at a probe is pinned at the admission record but not through a handler, and no unit
  freezes the refusal wire tags 0-17 as golden bytes.
- **openat2's open_how check on arm64.** The tracer's copy models access_ok with the top of user memory at 2^48,
  or 2^52 when a mapping above 2^48 succeeds; a kernel built for 52-bit addresses on 48-bit hardware, and the
  tagged-address ABI (a tagged open_how pointer), are not modelled: such a range can answer EFAULT where the kernel
  checks the extension first.
- **A walk refusal is logged before an argument error.** In-guest, an openat2 whose walk is refused by name, and
  whose open_how the kernel would refuse first, answers the kernel's EINVAL, but the refusal line was already
  written.
- **A traced child's exe without a row.** On ptrace, readlink of an owned child's `exe` with no row falls back to a
  record keyed by bare pid (a fork child can read its launch program's, a reused pid a stale value); an open of it
  is then the kernel's link, which names the loader. An exec that reached a file with no guest
  name leaves no such record and publishes an empty row exe: readlink then gives the kernel's link.
- **Other processes' entries are the kernel's**, per the owner directive of 2026-11-14 (earlier drafts of this
  change refused another process's magic links, exe, cwd, root, fd and map_files, in its walk, and its cmdline,
  environ, maps and similar files). A guest sees what the kernel shows: host command lines, host paths, the host
  environment of same-uid processes.
- **Own environ, maps, smaps and the rest show host values**: launcher variables such as LD_PRELOAD with host paths,
  the shared-record and probe descriptors, and the host paths of mapped files. Rewriting them is outside fix 4
  (§4.5).
- **RESOLVE_* is passed through, and RESOLVE_IN_ROOT re-roots.** openat2's open_how goes to the kernel unchanged,
  with literoot's absolute host path. Under RESOLVE_IN_ROOT the kernel resolves an absolute name from the dirfd (or
  the cwd for AT_FDCWD): path_init skips the root jump for LOOKUP_IN_ROOT and roots the walk at the dirfd
  (fs/namei.c:2714-2715 and :2767 at v7.1.3). So the kernel can open a different entry from the one literoot
  judged. The concrete case: with `-r /` (the default rootfs), D a descriptor on `/proc`, and P another process,
  `openat2(D, "/P/environ", {resolve = RESOLVE_IN_ROOT})` is judged as the ordinary `/P/environ` and opens
  `/proc/P/environ`; the same holds for a dirfd on `/proc/P` with `"/environ"`, and for AT_FDCWD after
  `chdir("/proc/P")`. Under RESOLVE_BENEATH the kernel refuses every absolute name with EXDEV (nd_jump_root,
  fs/namei.c:1129-1130), and literoot injects an absolute host path, so every translated RESOLVE_BENEATH openat2,
  relative names included, gives EXDEV where natively it can succeed. A cmdline literoot
  synthesizes on ptrace is the exception: those bits are cleared in its rewritten call (§4.9.5). Emulating both in
  literoot's walk (and injecting with AT_FDCWD and the flags cleared) is (2b)'s work.
- **A bind at a /proc magic path matches its spelling.** A bind at `/proc/self/root` (or another magic path) applies
  to that spelling, a guest-path prefix as in proot: the walk then classifies the bound directory, an ordinary one.
  `/proc/<own pid>/root` does not match it and is still procfs's link.
- **An unresolvable `-w` starts in "/".** When the launcher's `-w` names no directory (missing, not a directory, or
  more than 40 links on its walk), the guest starts in "/" without a message. proot makes the same choice, with a
  warning.
- **A call with two errors can answer the walk's.** literoot translates a name before the kernel sees the call, so a
  call with both an invalid argument and a name the walk refuses (more than 40 links, or a named refusal) answers the
  walk's errno where the kernel would answer the argument's first. openat2 is the exception while its probe gate is
  open: EINVAL, E2BIG, EFAULT and EMFILE come first through its argument probe (§4.9.3); ENFILE and ENOMEM, which the
  kernel can also return before the lookup, are not among them. The call fails either way.
- **The cwd after a rename.** literoot keeps the cwd as a guest path and rewrites it when this process renames one of
  its ancestors (the old prefix becomes the new one, as in proot). Two cases are not followed: another process renames
  an ancestor of this process's cwd, or this process exchanges two directories (renameat2 RENAME_EXCHANGE) and its
  cwd is under the exchange's second name. Later relative names then resolve from the old guest path, which can name
  another directory's entries. getcwd stays the kernel's, de-translated.
- **getcwd with a small buffer.** getcwd runs in the kernel with the guest's buffer, and its answer is then
  de-translated, so a buffer too small for the HOST path gives ERANGE even when the guest path would fit.
- **AF_UNIX names.** bind and connect give the kernel the walk's host path, so getsockname returns the canonical guest
  path of what was bound (every link, "..", alias and `/proc/self/fd/<n>` spelling resolved), not the name the guest
  used, as in proot. A host path longer than 107 bytes answers by its parent, as Linux's walk of the guest's short
  name would (`overlong_sockname_errno`): a missing or non-directory parent gives that walk's errno, and so does a
  connect's missing final name. A symlink parent, a ".." tail, a bind into a directory, or a connect to a name that
  exists keeps ENAMETOOLONG, where Linux may create, connect, or answer ENOENT, ENOTDIR or ECONNREFUSED; proot binds
  such a name to a short temporary path instead.
- **Descriptors literoot makes in the guest's table.** Two in-guest routes reach a descriptor they create in the
  guest's table by its number: the filter-count read (an open, reads and a close of /proc/self/status, §4.9.4) and
  the cmdline memfd (memfd_create, then literoot's write and identity check, and a close when either fails, §4.9.5).
  Another thread of the same guest that closes or replaces that number meanwhile (close_range, closefrom, dup2 onto
  it) makes literoot read, or close, its replacement; an empty regular file opened writable at that number also
  passes the memfd's identity check and then holds the argv, mode 0444. Natively such a thread already breaks its
  sibling threads' descriptors; literoot assumes non-hostile programs.

## 5. Android constraints (M3), in the owner's priority order

The Android app sandbox is not "Linux but smaller": the app runs as an
unprivileged app UID under a pre-installed seccomp filter, with no
user namespaces, and SELinux policy that varies by device/Android
version. literoot on Android is therefore **two** products in one:
path translation (as on desktop) *and* emulation of syscalls the
sandbox forbids. The emulation half is listed first because a guest
glibc that dies on a blocked syscall never reaches a path syscall.

### 5.1 Emulate seccomp-blocked syscalls, not just path rewrite

Blocked or restricted in the app sandbox (varies by Android version;
each needs a per-version fact table at M3, this list is the design
envelope): `rseq` (return success/no-op or emulate registration so
glibc's rseq fast paths stay correct — a half-emulated rseq is worse
than none: prefer failing with the errno that makes glibc disable
rseq, verified against the guest glibc version), `set_robust_list`
(no-op success; robust futexes degrade to non-robust — record as a
known semantic delta), `faccessat2` (emulate via `faccessat` +
flag handling), `openat2` (emulate via `openat` after validating the
`open_how` resolve flags can be honoured in the Tool's own
resolution — `RESOLVE_BENEATH`/`IN_ROOT` map naturally onto §4.2's
clamping), the `set*id` family (`setuid/setgid/setreuid/setresuid/
setgroups`, … → fake-root semantics §4.4), `futex_waitv` (emulate
with a `futex` wait loop or fail `ENOSYS` so callers fall back —
measure which the game stack needs), `io_uring` (§4.6),
`landlock_*` (fail `EOPNOTSUPP`; guests that *require* landlock are
out of scope, guests that probe-and-continue work), `clone3` on
pre-Android-15 (emulate via `clone` with the flag subset `clone`
supports; refuse by name flags it cannot express, e.g. some
`CLONE_CLEAR_SIGHAND` combinations need care).

Design rule: every emulation is a Tool handler with the same shape
as a path handler (intercept → emulate/fallback → inject), tested by
the same oracle style (§9) against behaviour on an unfiltered Linux.
No emulation may silently succeed with wrong semantics: where exact
semantics are impossible (`set_robust_list`), the delta is named in
`-v` output and in this document.

### 5.2 The glibc signal-blocking hazard (why patching is primary)

glibc blocks signals around several blocked-syscall call sites
(internal `INTERNAL_SYSCALL` wrappers, cancellation points). A
seccomp `RET_TRAP`/`SIGSYS` (or SUD `SIGSYS`) raised while `SIGSYS`
is blocked in the thread's mask does not deliver to the handler — the
process dies or wedges. Consequence for literoot:

- Any syscall that must be emulated on Android **must be patched
  ahead of time / at load** (§3.1 layer 1), so control reaches the
  Tool by an ordinary call/branch, not by signal delivery.
- The trap net remains only as a correctness floor for *path*
  syscalls from unpatched code, and the masked-signal plan is: the
  in-guest runtime keeps its trap handler re-entrant and, where the
  platform allows, uses an alternate signal stack + a dedicated
  unblocked "waiter" arrangement validated per Android version. If a
  guest image cannot be patched *and* its blocked-syscall sites run
  with `SIGSYS` masked, literoot refuses that image by name on M3
  rather than risking a wedged game. This is the sharpest M3 risk
  and it is called out here, not discovered later.

### 5.3 Possible execmem ban: file-backed / pre-patched code

SELinux may forbid `execmem`/`execmod` for app domains (no anonymous
executable pages, no making data pages executable, W^X enforced).
liteinst's trampoline arenas today use memfd RW/RX aliases and do
**not** provide strict W^X (**Verified-current**, architecture note
§1.1) — that can be exactly what the policy bans. M3 plan:

- Preferred: **offline/pre-patched images** (liteinst B5 emission,
  **Partial** today): patch the guest ELF (and its `ld.so`) into a
  file-backed copy on app-private storage at install/first-run, then
  execute the patched file. No runtime code generation, no JIT
  pages; patched text is file-backed and `mmap`'d `PROT_EXEC` from a
  regular file, which app policy generally allows (it is how the
  app's own `.so`s load). Trampolines live in a pre-built
  file-backed region shipped inside the literoot binary.
- If even `execmod` on app-private files is denied on a target
  device, the fallback is trap-only mode (§3.3) with the §5.2
  refusal rules. literoot never attempts to defeat SELinux; it
  selects a mechanism the policy admits or refuses by name.

### 5.4 Remaining Android facts to pin at M3 (not guessed here)

Exact blocked-syscall list per Android version/API level; whether
`process_vm_readv`/ptrace of own children is permitted (affects
A-stop viability); `memfd_create` availability under the app filter;
max `PATH`/bind counts for the game runtime. Each becomes a row in a
device-fact table with provenance (device, build, command) before
any M3 performance claim.

## 6. State model: replicated, zero coordinator RPC

The Tool runs *in* every guest process. There is no central literoot
daemon and **no RPC on the hot path** (or any path: after launch, the
launcher only waits and forwards the exit status/signals).

| State | Kind | Lifecycle |
|---|---|---|
| Rootfs path, bind table (guest→host prefixes, longest-match) | Immutable after launch | Built by launcher, handed to first guest, inherited verbatim on `fork`, re-handed on `execve` (Tool-region handoff) |
| Fake uid/gid, kernel-release string, mechanism/options | Immutable | Same as above |
| cwd (guest path) | Per-process mutable | Initialised from `-w`, updated by translated `chdir`, copied on `fork`, preserved on `execve` |
| fd → guest-path table | Per-process mutable | Recorded on `open*`/`dup*`/`socket`, dropped on `close`, `O_CLOEXEC` entries dropped on `execve`, lazy `/proc/self/fd` recovery for unknown fds (§4.3) |
| io_uring ring records | Per-process mutable | Created at `io_uring_setup`, dropped at ring fd close |
| Scratch path buffers | Per-thread | One 4096-byte slot per thread. The post-exec handler of a successful `execve` maps a pool of 16 slots in one injected anonymous mmap of 64 KiB: the exec'ing thread takes the first, and new threads take the others, or an exited thread's slot of the same image, zeroed before use; a new thread maps another 16-slot pool (one mmap) only when none is free. A `fork` child keeps the caller's copy, a `vfork` child shares the suspended caller's, a thread or other `CLONE_VM` child gets its own; a staged write never runs past the slot. On a 64 KiB kernel the 16 slots share one kernel page with no guard page between them, so the explicit length checks are what bound every staged write. Image numbers are unique in the process (one counter), so a slot of another image is never reused. Earlier the code kept ONE slot per process despite this row, so one thread's staging could overwrite another's before the kernel read it (reachable on ptrace) |

Handoff mechanism: the launcher stages the immutable blob in the
Tool region before first instruction (A-stop) or via an inherited
memfd whose fd number is passed in a reserved environment variable
(preload/debug mode). `execve` re-arm re-stages the same blob plus
the serialized cwd/fd table. Because every process holds a full
copy, fork-heavy workloads (shell pipelines, package managers) pay
no coordination cost and cannot deadlock against a central server —
the failure mode "tracer died, all guests wedged" does not exist.

Consistency note: replicated cwd/fd state is per-process by
construction, exactly like the kernel's. Two processes never share
mutable Tool state, so no cross-process coherence protocol exists
(or is needed). The one shared truth — the bind table — never
changes after launch (proot has no runtime re-bind either).

## 7. aarch64 port plan (M2) — explicit, not assumed

What exists: liteinst's patching kernel is x86-64 (instruction
punning relies on variable-length x86 encodings, **Verified-current**).
What aarch64 needs, as its own work package:

1. **Site patching on fixed-width ISA.** aarch64 `svc #0` sites are
   4-byte aligned instructions; patching uses `b`/`bl` detours to
   nearby trampolines (±128 MiB) or literal-pool far branches, with
   the atomicity story resting on aligned 4-byte stores +
   `IC IVAU`/`DSB ISH` cache maintenance instead of x86 punning.
   This is *simpler* in encoding, *different* in cache coherence —
   a liteinst-aarch64 backend, not a recompile.
2. **Trap net first.** seccomp `RET_TRAP` and SUD are arch-portable;
   M2 can reach correctness trap-only, then add patching for speed —
   the reverse order of M1, reusing the identical Tool.
3. **Syscall table.** aarch64 (asm-generic) numbering and the
   `*at`-only surface (no `open`/`stat` legacy forms) — the Tool's
   subscription list is per-arch data, translation logic shared.
4. **Loader/activation.** A-stop mechanics are `ptrace`-generic but
   the Tool-region mapping and `ld.so` handoff need aarch64
   bring-up; BTI/PAC (pointer authentication) interact with
   trampolines (`RETAA` vs `RET`) and must be handled per-binary
   (`GNU_PROPERTY` notes) — refuse by name what cannot be armed.
5. **Oracle.** §9 runs unmodified on aarch64 Linux (real proot
   exists there; it is proot's home turf via Termux).

Estimate class: M2 is a backend port (weeks), not a Tool rewrite —
*provided* M1 keeps all arch knowledge behind the subscription
table and the patcher trait. That separation is an M1 requirement,
enforced by keeping `translate()` arch-free.

## 8. Benchmarks: existing evidence and our gap suite

### 8.1 What is already known (cited; full survey appendix lands with POC)

- **DroidDeck baseline (owner-supplied, the numbers literoot must
  beat):** proot `stat` ≈25 µs vs native ≈0.6 µs (≈40×); 8-thread
  file-op throughput 89k ops/s (proot) vs 3.6M ops/s (native) (
  ≈40×, and the gap *widens* with threads because one tracer
  serializes all guests). These two cells define M1's headline
  targets: patched-mode `stat` within 2× of native; 8-thread
  scaling within 2× of native (replicated state §6 is what makes
  the second achievable at all — proot's single tracer cannot).
- **Upstream proot (proot-me/PRoot):** ships a test suite (`test/`,
  &&-chained shell cases) and documented known-issue overheads; the
  community's standard report is "extracting a distro tarball /
  `apt update` under proot-distro is several× slower than native".
  Controlled published head-to-heads (proot vs chroot vs userns/
  `bwrap` vs udocker vs gVisor-ptrace) consistently rank: native ≈
  chroot ≈ bwrap < gVisor-ptrace ≪ proot for syscall-dense loads,
  because only proot stops per path syscall. Exact figures with
  URLs/dates are in the survey appendix (research in flight; no
  number enters literoot's own results tables without provenance).
- **liteinst anchors (Verified-current, liteinst checkpoint):**
  patch-apply median ≈0.49 µs (aligned) / ≈4.15 µs (crossing),
  N=20,000; no-op trampoline hot-loop overhead 12–22% at
  ~420M calls/s baselines. Whole-program literoot-vs-proot:
  **Unmeasured** until §8.2 runs. The trap-net cost (seccomp
  `SIGSYS` round trip) is expected in the low-µs range — still an
  order of magnitude under a ptrace stop (≈31 µs cited literature
  value for ptrace per intercepted syscall) — to be measured, not
  assumed.

### 8.2 Gap suite (ours; correctness first, then these cells)

Run each cell under: native (chroot into same rootfs where
privilege allows, else host-root equivalent), real proot, literoot
patched+trap, literoot trap-only, literoot ptrace. Report ratios to
native *and* to real proot, median/IQR, N≥30 for micro cells,
machine + kernel recorded with every table.

1. Micro: `stat`/`openat`/`readlink` loops (1M iterations, 1 and 8
   threads) — directly comparable to the DroidDeck baselines.
2. Package-manager install inside a rootfs (`apt-get update &&
   apt-get install -y <fixed set>` or Alpine `apk add`), wall time
   + syscall counts.
3. Compile workload: build a fixed small C project (e.g. sqlite
   amalgamation single-file + 100-file synthetic tree) in-rootfs.
4. Game-like: many-small-reads walker (open/read 4KiB/close over a
   10k-file asset tree, 1/4/8 threads), plus a shader-cache probe
   pattern (stat-heavy, mostly-miss).

No performance claim ships without the correctness oracle green on
the same commit (§9), and no cell is dropped silently — a cell that
cannot run is reported as such with the reason.

## 9. Correctness oracle (built alongside, never after)

Three comparators, in increasing strength:

1. **Upstream proot tests:** the proot-me/PRoot `test/` suite run
   under literoot (subset that does not require `-q`/extensions §2;
   excluded cases listed by name with reason).
2. **Differential vs real proot:** identical command lines under
   `proot -r …` and `literoot -r …` on twin copies of one rootfs;
   compare stdout, stderr, exit code **byte-for-byte**, and the
   resulting file tree (names, modes, contents' hashes, symlink
   targets). The maintained harness is `tests/oracle.rs` (+ shell
   driver `tests/oracle.sh`); failures are retained **by test name**
   and the comparator is never loosened (no normalizing away
   prefixes, timings are the only excluded channel — outputs
   containing PIDs/timestamps are avoided by workload choice, not
   scrubbed after the fact).
3. **Self-differential (mechanism swap):** same Tool under
   literoot-ptrace vs literoot-patched vs literoot-trap-only must
   agree byte-for-byte. This catches patching soundness bugs that
   comparator 2 would attribute to "proot quirk".

Real proot is not installed on the M1 dev host today (`which proot`
empty, **Verified-current** 2026-11-05); comparator 2 therefore
starts as "literoot vs native-in-rootfs-via-chroot/bwrap + vs
literoot-ptrace" and gains the real-proot column when a proot binary
is staged. That gap is stated in every results table until closed.

## 10. Dependencies: unreleased pieces vs published 0.2.x

**Verified-current pins (2026-11-05):**

| Crate | What literoot needs | Published | POC pin |
|---|---|---|---|
| `liteinst` (ex-`liteinst2`) | patcher/planner/trampoline/scanner + guard-signal runtime; quiescent + emission later (M3 pre-patch) | crates.io `liteinst` **0.2.0** (+ subcrates 0.2.0/0.2.1); `liteinst2` 0.2.1 is a deprecation pointer | git rev `d64dc833418a4c265803645653b8f597d0f25060` via Reverie (below) |
| `reverie` (`reverie-core` 0.5.4), `reverie-inguest`, `reverie-liteinst` | Tool/Guest traits, in-guest runtime, `LiteinstBackend` | **Not on crates.io as a usable set** (name-reservation placeholders only) | git `reverie` @ `ac71ee9c844def23714c22f0a37f92bb1e838817` (then-current head); `liteinst2` @ `46e6e8f3cc6a5cfce0e4b1bf4d7aec93a0e0f336` available locally |
| `reverie-liteinst` → liteinst edge | the binding itself | — | pins liteinst2 git `d64dc83` (2026-10-10), **1,971 commits behind** liteinst 0.2.0 — "liteinst can do X" ≠ "a Reverie tool gets X" |

**Unreleased pieces literoot needs (exact list):**

1. `reverie-liteinst` **ported to liteinst 0.2.x** (crates.io
   `liteinst` 0.2.0 API): currently only the Oct `d64dc83` pin is
   wired (narrow imports: trampoline hook context, patcher jump
   plans, guard-signal runtime, scanner). Future release must
   consume `liteinst = "0.2"` and expose quiescent publication +
   offline emission to Tools (M3 pre-patch, §5.3).
2. **SUD safety net in `reverie-inguest`** (`PR_SET_SYSCALL_USER_DISPATCH`
   as a selectable trap mechanism alongside seccomp `SIGSYS`):
   absent today (only in liteinst's standalone C launchers).
   Future release must offer it as a backend option; M1 ships
   without it.
3. **`execve` successor re-arm (stage 1b)** in the A-stop in-guest
   path: exec currently the weak/refused point (§4.7). Future
   release must re-arm a Tool across `execve` before first
   instruction, including `PT_INTERP` handling hooks the Tool can
   translate.
4. **Reverie-level loader / Tool-requirement + selection API**
   (architecture note §3/§4.3): today backend choice is hard-wired
   by the embedding binary. literoot embeds its own selection (§3.3)
   for the POC; a future Reverie release should provide the shared
   requirement/selection contract so literoot is a client, not a
   fork, of that logic.
5. **Page-gate (B4) as a selectable Reverie mode** — *not* needed
   by the M1 POC; needed only if JIT-heavy guests must avoid census
   patching. Listed so its absence is a decision, not a surprise.

POC dependency rule: pin **git revs** (above) so the POC builds
today; flip each edge to a crates.io version as the corresponding
release lands, one edge per commit, oracle green at each flip. The
POC branch's `Cargo.lock` is committed — "builds on my machine" is not
a reproducibility story.

## 11. Packaging: one static binary

- Single `literoot` executable (musl static on Linux; `lto=thin`,
  one codegen unit) with the in-guest runtime **embedded**
  (`include_bytes!` of the Tool-region image / preload `cdylib` as
  the activation mode requires) — no sidecar files, no
  `LD_LIBRARY_PATH`, copy-to-device-and-run (the Android/Termux
  distribution constraint). Embedded artifacts are extracted to a
  memfd (desktop) or app-private file (Android §5.3) at launch.
- No runtime network, config-file, or plugin surface. All
  configuration is CLI + `PROOT_*` env (§2).
- Version output includes the git/rev pins of liteinst/reverie it
  was built against (`literoot --version --pins`) so bug reports
  carry their own provenance.
- Size budget to be measured at POC (target: single-digit MiB;
  report actual, don't promise).

## 12. M1 POC scope and exit criteria

The POC began as a standalone tree before it was maintained in
this repository. POC = minimum `-r/-b/-w` +
Tool (§4.1 core subset: `openat/newfstatat/access/readlinkat/
execve/chdir/getcwd` + fd table) + seccomp-trap net + oracle
harness (§9 comparators 1-subset + 3, comparator 2 vs
native/ptrace until real proot is staged).

Exit criteria (all on one commit, oracle output retained):
`literoot -r <rootfs> /bin/sh -c 'ls /; cat /etc/os-release'`
byte-identical to the reference run; one package-manager operation
in-rootfs completes with identical resulting tree; `stat` micro
cell (§8.2.1) measured with medians/IQR/N and machine recorded.
Anything failing is reported by name — a POC that hides its
failures has no value as an M1 gate.

## 13. Wine/FEX coexistence (the game runtime)

Literoot's motivating stack (Wine/FEX/DXVK/VKD3D/Turnip under
DroidDeck/Quest Deck) means literoot never runs alone in the
guest: Wine and FEX both install their own interception
machinery. Rules, in force from M1 (not retrofitted at M3):

### 13.1 Syscall User Dispatch: Wine owns it; literoot does not use it

Wine (wow64/new-wow64 and the unix-call dispatch path) uses
Syscall User Dispatch (`PR_SET_SYSCALL_USER_DISPATCH`) to trap
raw Windows `syscall` instructions from PE code. **A thread has
exactly one SUD configuration** (one dispatch range + selector);
a second `prctl` replaces the first. Decision: **literoot must
not depend on SUD in any configuration where Wine may run.**
literoot's mechanisms are patching (primary) + seccomp
`RET_TRAP` (safety net) — neither consumes the SUD slot. If a
future literoot mode wants SUD on non-Wine guests, it must (a)
detect an existing SUD config at arm time and refuse by name
rather than overwrite it, and (b) never install SUD after Wine's
preloader has run in that process. Chaining two SUD consumers is
not possible without cooperation from Wine itself; we do not
plan to ask for it. (Verified-current: Reverie's in-guest
runtime has no SUD today, §10 item 2 — adding it must respect
this section.)

### 13.2 Signal ownership: never swallow a foreign SIGSYS

Wine installs handlers for SIGSEGV/SIGILL (PE exception
dispatch) and, with SUD, SIGSYS. literoot's trap net also uses
SIGSYS (seccomp `RET_TRAP`). Chaining rules:

- literoot's SIGSYS handler claims **only** traps whose
  `siginfo` proves literoot provenance (`si_code == SYS_SECCOMP`
  and the syscall number/address falls in literoot's subscribed
  set as raised through its filter). Anything else is forwarded
  to the previously installed handler (or default disposition)
  with the original `siginfo`/`ucontext` untouched — never
  swallowed, never "handled" as a path syscall.
- Disposition ownership: literoot saves and chains the prior
  SIGSYS disposition at arm time; on `execve` the successor's
  dispositions reset per kernel rules and literoot re-arms
  (stage-1b, docs/stage1b-scope.md) *without* assuming Wine's
  handlers survived — Wine re-installs its own during its
  startup, in whatever order the two arming paths interleave,
  so literoot must re-read the current disposition at every
  (re-)arm, never cache across exec.
- Thread creation: new threads inherit dispositions; literoot
  per-thread arming must not reset a disposition another
  runtime installed between thread creation and arming. The
  masked-signal hazard (§5.2) compounds here: Wine blocks
  signals around its unix calls, so a literoot trap raised in
  that window defers — acceptable for the *net* (correctness
  floor), never for an emulated blocked syscall (patched,
  §5.2).
- SIGSEGV/SIGILL are never literoot's: the in-guest patching
  runtime's own guard-signal use (liteinst SIGTRAP router)
  already refuses to replace a pre-existing handler
  (§4.8); the same refusal-by-name applies to any disposition
  literoot would need to own outright.

### 13.3 Wine preloader reservations vs in-guest runtime placement

`wine-preloader` reserves large low address ranges (the PE load
area, e.g. 0x00000000–0x7fff0000 style reservations and the
top-down/ASLR-sensitive regions Wine probes) *before* `ld.so`
runs, then hands a pre-shaped address space to the Wine loader.
Consequences for literoot's in-guest runtime (ToolRegion,
trampoline arenas, scratch):

- Never assume fixed addresses: the in-guest runtime must
  allocate its regions with hint-free `mmap` and tolerate
  landing anywhere the preloader left free; a fixed ToolRegion
  window that collides with a Wine reservation must relocate
  or refuse by name, never `MAP_FIXED` over a reservation.
- Arm-order: when the guest program *is* wine-preloader, the
  preload constructor runs inside the manually loaded Wine
  `ld.so` image — placement negotiation happens against an
  address space the preloader already shaped; census/patching
  must treat preloader-reserved-but-unmapped ranges as
  off-limits, not as free holes.
- File-backed placement (M3, §5.3) does not change this: the
  constraint is addresses, not backings.

### 13.4 Under FEX: intercept the emulator's host syscalls only

On aarch64, FEX JIT-translates x86-64 guest code; translated
blocks live in FEX's code cache and issue *host* (aarch64)
syscalls from FEX's own syscall-emulation thunks. Rules:

- literoot intercepts **FEX's host aarch64 syscalls** (its
  openat/statx/... thunks and runtime), i.e. FEX is "the
  program" from literoot's perspective. Path arguments at that
  layer are already the host-side paths Wine/FEX computed —
  exactly the layer where rootfs translation belongs.
- **Never patch JIT-translated code**: translated blocks are
  ephemeral, self-modifying from literoot's viewpoint, and
  owned by FEX's cache invalidation. literoot's census must
  classify FEX code-cache mappings as census-exempt (trap net
  covers stray raw syscalls if any escape the thunks) — the
  same classification §3.1 already gives JIT output generally,
  made explicit here because with FEX *most* guest code is JIT.
- If FEX itself uses SUD or seccomp for its own purposes on the
  host threads, §13.1/§13.2 apply unchanged (FEX owns its SUD
  slot; literoot chains SIGSYS).

### 13.5 Smoke evidence

**UNMEASURED.** No Wine on the M1 dev host (`which wine`
empty); the x86-64 smoke (wine + tiny Win32 console program
under literoot-ptrace vs native wine, stdout/exit compared) is
blocked on a Wine install being authorized/staged — named here
as the blocker, per instructions no large packages installed
unasked. First smoke target when unblocked: `wine cmd /c echo`
class builtin-free PE (avoids net/registry writes), ptrace
backend first (in-guest additionally gated on stage-1b exec).

## 14. Open questions (for project review)

1. Name: `literoot`, pending a name check; crates.io and repository
   writes go through project review (this work makes none).
2. Placeholder `Cargo.toml`/stub line: prepared per §10 conventions;
   confirm exact owner-specified wording before any publish.
3. `-R` default binding set: copy proot's documented set verbatim,
   or curate for the game runtime? (POC copies proot's.)
4. M2 test hardware: which aarch64 Linux host is the oracle target?


