# L5 record: W6a ptrace re-bootstrap coverage of the 11 coexistence failures

Status: RECORD ONLY (2026-11-06, museport/W1). No implementation.
Implementation stays deferred until W6a S-B (stage-1b in-guest
successor arming, docs/stage1b-scope.md) lands. "Covered" below means:
once the backend no longer occupies the guest's single ptrace slot,
the kernel alone provides what the test exercises — assuming the
guest tracer process itself is armed per stage1b-scope §1.1/§1.3
(fork/clone + exec successor arming). The 11 names are the
guest-ptrace/gdb/strace coexistence class in
docs/proot-suite-results.md plus test-execve-sysexit-seccomp.

## Covered by W6a (kernel ptrace suffices once freed)

- `test-ptrace-traceme-basic` — TRACEME + parent wait; pure kernel.
- `test-ptrace-setoptions` — PTRACE_SETOPTIONS over a TRACEME child
  (strace-4.8 extract); option acceptance is the kernel's.
- `test-nested-ptrace` — guest ptrace helpers tracing children
  (incl. fork-wait tracees) under `-r`; needs only a free tracer slot
  per level.
- `test-gdb-ptrace` — ptrace-API helper binaries (peek/poke/signal
  delivery), no text patching by the guest; kernel-served once freed.
- `test-trace-without-parent-wait` — tracer exits without wait;
  detach/reparent semantics are the kernel's.
- `test-strace-fork-wait` — guest `strace [-f]` over fork-wait;
  verdict is exit status only (no output comparison), so it is
  covered. Caveat recorded: syscalls the in-guest backend patches do
  not generate ptrace syscall-stops, so a guest strace observes a
  subset — invisible to this test, material to any output-comparing
  successor test.

## Partially covered (needs validation beyond freeing ptrace)

- `test-gdb-breakpoint-run` — guest gdb sets INT3 breakpoints in
  tracee text. Covered for breakpoints outside liteinst-patched
  windows; a breakpoint on/near a patched syscall site interacts
  with WordPatch publication and needs an explicit witness before
  claiming coverage.

## Not covered by the W6a minimum (needs work beyond S-B scope)

- `test-ptrace-exec-trap`, `test-ptrace-sigtrap-execve` — both
  byte-compare (`cmp`) the guest tracer's output native vs under the
  backend, across tracer-behavior variants. The exec stop RIP and
  stop sequence must match native exactly; successor arming routes
  (kernel PT_INTERP vs loader-as-program, stage1b-scope §1.2) change
  the executed image and stop sequence, so byte-equality is not
  implied by freeing ptrace. Needs exec-stop fidelity work beyond
  the S2 minimum.
- `test-strace-execve-count` — asserts exactly one successful
  `execve` line for `true`. Successor arming/loader execs visible to
  a guest strace can change the count; not guaranteed by W6a.
- `test-execve-sysexit-seccomp` — not a ptrace-coexistence test at
  all (proot `-k` kompat/auxv behaviour; in-suite flake that passes
  in isolated runs). W6a neither covers nor affects it; it stays
  classified separately.

## Summary

Covered: 6 (traceme-basic, setoptions, nested-ptrace, gdb-ptrace,
trace-without-parent-wait, strace-fork-wait). Partial: 1
(gdb-breakpoint-run). Not covered by the W6a minimum: 3
(ptrace-exec-trap, ptrace-sigtrap-execve, strace-execve-count).
Not applicable: 1 (execve-sysexit-seccomp).
