# Stage-1b scope: in-guest execve successor re-arm (consumer-side)

Status: DESIGN-ONLY scope from literoot (the consumer), 2026-11-05.
No reverie-inguest code is proposed here line-by-line; this pins
the interface literoot needs, the gate, failure modes, witnesses,
and touch estimate so an implementation lane can start cold.
Pinned tree: reverie @ ac71ee9. Nobody was assigned to this item
as of 2026-11-05.

## 1. Exact interface literoot needs

Today (verified): guest `execve/execveat` in-guest returns typed
`EOPNOTSUPP` (`UnsupportedOperation::Exec`,
reverie-inguest/src/guest/host.rs ~3834); thread/vfork clone
likewise (`ThreadCreation`, ~3783). An inactive experimental seam
exists: feature `exec-native-injection`
(reverie-inguest/Cargo.toml:57 → exec-private-successor →
exec-private-init + coordinator-rpc; modules
src/guest/native_exec{,_arguments,_fds,_mappings}.rs), admitted
only when an installer installed a native exec route; the default
preload path does not.

Literoot needs, as Tool-visible behaviour (no new Tool methods
required in the minimum):

1. **Successor arming.** When the Tool injects/handles an
   `Execve` and the kernel exec succeeds, the *new image* runs
   with the same Tool armed before its first userspace
   instruction that can issue a subscribed syscall — equivalently:
   `handle_syscall_event` keeps firing in the successor, and
   `handle_post_exec` (or its in-guest equivalent) observes the
   transition. Tool per-process state semantics: state the Tool
   chooses to carry must have a defined channel (minimum viable:
   fresh `Tool::default()` + same GlobalTool Config, matching
   today's fork behaviour; literoot rebuilds cwd/fd state from
   Config + /proc lazily, so this suffices — richer state handoff
   is explicitly NOT required).
2. **PT_INTERP behaviour.** The successor's interpreter load must
   itself be mediated (the Tool sees the loader's path syscalls),
   for both routes literoot uses: (a) kernel-loaded PT_INTERP
   (normal exec), and (b) literoot's explicit loader-as-program
   exec (musl rootfses). Route (b) today additionally hits
   `inguest-musl-loader-bootstrap`: ld.so opens the target before
   the preload constructor arms. Acceptable minimum: (a) works
   fully; (b) either works or refuses by name at launch (not a
   mid-run ENOENT).
3. **Thread clone.** `clone(CLONE_THREAD|VM...)` children run
   with the Tool armed (shared per-process Tool, per-thread
   ThreadState), or refuse by name *cleanly* (typed EOPNOTSUPP to
   the guest — today an 8-thread guest SIGSEGVs and pthread
   workers escape translation entirely; both measured in
   docs/benchmark-results-m1.md). Correct-and-slow beats
   silently-untranslated: any thread the backend cannot arm must
   not run unmediated syscalls.
4. **Failure atomicity.** A failed exec (ENOENT/EACCES/ENOEXEC
   from the kernel) returns the genuine errno with the Tool
   still armed in the *old* image (literoot's shebang/ENOEXEC
   handling depends on distinguishing this from refusal).

## 2. Feature gate (off Hermit's build path)

Reuse the existing gate shape: ship behind
`exec-native-injection` (reverie-inguest) forwarded as
`reverie-liteinst/exec-native-injection` (Cargo.toml:38 exists).
Requirements: default features unchanged on every crate
(reverie-inguest default = ["preload-constructor"],
reverie-liteinst default = []); Hermit does not enable the
feature, so its build graph and behaviour are untouched; the
launcher admits successor exec only when the feature was
compiled in AND the embedder opted in at runtime (env or builder
flag), otherwise today's typed refusal remains.

## 3. Failure modes to handle (each: refuse by name, never wedge)

- Successor image is static / has no PT_INTERP slot for preload
  re-entry → named refusal at exec time (guest gets EOPNOTSUPP,
  old image intact).
- Successor is setuid/setgid (kernel strips LD_PRELOAD) → named
  refusal; never run unarmed.
- Execveat with AT_EMPTY_PATH / memfd images → support or named
  refusal (literoot minimum: plain path execve).
- Thread created while another thread is mid-exec → serialize or
  named refusal; no half-armed thread.
- Coordinator socket lost across exec → successor must rebind or
  the run fails closed with the launcher reporting the break.
- vfork: parent-suspended semantics with Tool state shared until
  exec — minimum: keep today's plain-fork COW treatment, named
  as a semantic delta if observable.

## 4. Test witnesses (acceptance)

1. In-guest sh chain: `literoot --backend liteinst -r <glibc
   rootfs> /bin/sh -c 'cat /etc/os-release; ls /'` byte-identical
   to the ptrace run (today: EOPNOTSUPP, exit 126/127).
2. In-guest package manager: Alpine `apk add --no-network`
   (zlib+libmagic+file) under `--backend liteinst` with stdout +
   resulting tree byte-identical to the proot/ptrace runs
   (musl route (b) — if (b) is refused-by-name per §1.2, witness
   becomes the glibc-fixture equivalent plus the named refusal).
3. Thread witness: 8-thread statloop in-guest completes with
   correct count (today SIGSEGV) — or typed refusal, no crash,
   no untranslated escape (walker bytes assertion catches it).
4. Regression: existing reverie-inguest/reverie-liteinst test
   suites green with the feature OFF (default) and ON; Hermit
   build untouched (feature off in its graph).

## 5. Touch estimate (reverie-inguest, from pinned tree)

- `src/guest/host.rs` (5,595 lines): exec/clone admission around
  the two refusal sites (~3783 thread, ~3834 exec) + successor
  lifecycle hooks. Largest risk concentration.
- `src/guest/native_exec*.rs` (existing seam: arguments/fds/
  mappings collectors): wire from "installer-only inactive" to
  an admitted route, or supersede — implementer's call, but reuse
  the collectors; do not fork a second exec path.
- `src/launcher/mod.rs` (2,457 lines): successor bootstrap
  (Config/tool_data re-delivery, coordinator rebind).
- `reverie-liteinst/src/tool_host.rs` (1,244 lines): successor
  install entry (Tool re-construction in new image).
- Cargo.toml features only (no default changes).
Estimate class: 1–2k lines touched/added plus tests; the
unknown is successor arming order vs ld.so, not volume.

## 6. Recommended lane

**The gate/launcher side** (the preferred owner): the work is
preload/launcher-side Reverie mechanics, and spike context on the
gate/launcher seam transfers directly. The literoot side supplies the
consumer witnesses above (literoot oracle + apk + statloop8 are
ready-made acceptance tests) and reviews from the Tool side.
If the gate side is saturated, the literoot side can take it — preload-side
knowledge is fresh — at the cost of pausing literoot M1 tail
(suite widening).
