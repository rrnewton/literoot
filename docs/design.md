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
| Scratch path buffers | Per-thread | Preallocated, reused; no allocator on the hot path |

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
| `reverie` (`reverie-core` 0.5.4), `reverie-inguest`, `reverie-liteinst` | Tool/Guest traits, in-guest runtime, `LiteinstBackend` | **Not on crates.io as a usable set** (name-reservation placeholders only) | git `reverie` @ `ac71ee9c844def23714c22f0a37f92bb1e838817` (slot head); `liteinst2` @ `46e6e8f3cc6a5cfce0e4b1bf4d7aec93a0e0f336` available locally |
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

The POC began as a standalone tree, before the `rrnewton/literoot`
repository existed. POC = minimum `-r/-b/-w` +
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


