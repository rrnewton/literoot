# Upstream proot test-suite results (M1, x86-64)

Suite: proot-me/proot v5.5.0 `test/` (94 shell + 38 C, 25dc6a3), GNUmakefile, CARE=/bin/false. EPYC 9D85, kernel 7.1.3. Unique names; no comparator loosening.

| Runner | ok | FAILED | skipped |
|---|---|---|---|
| proot 5.5.0 | 117 | 10 | 5 |
| literoot b0 | 43 | 79 | 13 |
| b1 | 49 | 74 | 12 |
| b2 | 56 | 68 | 11 |
| b3 | 60 | 64 | 11 |
| b4 | 62 | 62 | 11 |
| b5 | 64 | 60 | 11 |
| b6 canonicalize | 69 | 54 | 11 |
| b7 | 72 | 51 | 11 |
| b8 | 75 | 48 | 11 |
| b9 | 80 | 43 | 11 |
| b10 | 81 | 43 | 11 |
| b11 | 83 | 39 | 11 |
| b12 | 86 | 36 | 11 |
| b13 | 88 | 34 | 10 |
| b14 shared gen | 90 | 32 | 10 |
| b15 auxv/cmdline | 93 | 29 | 10 |
| b16 SIGTERM | 94 | 28 | 10 |
| b17 bound-splice | 98 | 24 | 10 |


## Failing under BOTH

- `test-care-archive-formats`
- `test-care-env-auth-vars`
- `test-care-env-special-chars`
- `test-care-hwcap-auxv`
- `test-care-reexec-exit-code`
- `test-care-symlinked-cwd`
- `test-care-via-symlinked-proot`
- `test-socket01`
- `test-socket02`
- `test-socket03`

## Failing only under literoot (retained by name)

- `test-execve-eacces-enoexec`
- `test-execve-sysexit-seccomp`
- `test-foreign-binary-emulation`
- `test-foreign-binary-proc-self-exe`
- `test-gdb-breakpoint-run`
- `test-gdb-ptrace`
- `test-nested-ptrace`
- `test-ptrace-exec-trap`
- `test-ptrace-setoptions`
- `test-ptrace-sigtrap-execve`
- `test-ptrace-traceme-basic`
- `test-strace-execve-count`
- `test-strace-fork-wait`
- `test-trace-without-parent-wait`

## Passing under literoot

- `test-asymmetric-bind-cwd-readlink`
- `test-asymmetric-binding-root`
- `test-bind-chdir-getcwd`
- `test-bind-cwd-bash-pwd`
- `test-bind-file-over-etc`
- `test-bind-longer-path-pwd`
- `test-bind-ls-la`
- `test-bind-order-independence`
- `test-bind-proc-self-mounts`
- `test-bind-single-file`
- `test-bind-symlink-swap`
- `test-bind-write-same-path`
- `test-brk-syscall`
- `test-bug-138`
- `test-chdir-no-exec-permission`
- `test-chdir-thread-fork`
- `test-chroot01`
- `test-constructor-runs-once`
- `test-cwd-recreated-same-path`
- `test-cwd-removed-dir`
- `test-cwd-rename-rmdir`
- `test-cwd-shell-pwd-var`
- `test-dont-pollute-rootfs`
- `test-exec-proc-self-exe`
- `test-exec-proc-self-exe-null-argv`
- `test-faccessat-nofollow-ignored`
- `test-fake-id-auxv-chroot`
- `test-fake-id0-permissions`
- `test-fchownat-symlink`
- `test-fork-pipe-sigkill-stress`
- `test-fork-stress-loop`
- `test-fork-vfork-execve`
- `test-fork-wait-exit-status`
- `test-getresid-native`
- `test-getresuid-getresgid-syscalls`
- `test-kernel-release-truncation`
- `test-kernel-release-uts-fields`
- `test-kill-tracer-pid`
- `test-kompat-rm-recursive`
- `test-ldd-passthrough`
- `test-lstat-trailing-slash-symlink`
- `test-lutimes-symlink`
- `test-make-under-proot`
- `test-mkdir-rmdir-symlink-errors`
- `test-mkdir-rmdir-trailing-slash`
- `test-mknod-requires-fake-root`
- `test-msgmerge-no-hang`
- `test-nested-shebang`
- `test-open-trailing-slash-enotdir`
- `test-openat-fd-edge-cases`
- `test-option-override-last-wins`
- `test-path-env-lookup`
- `test-path-lookup-directory-shadow`
- `test-path-search`
- `test-path-symlink-exec-argv`
- `test-path-traversal-conformance`
- `test-pipe2-nonblock`
- `test-proc-cmdline-script-argv`
- `test-proc-comm-name-truncation`
- `test-proc-fd-dir-traversal`
- `test-proc-fd-dotdot-root`
- `test-proc-self-cmdline-read`
- `test-proc-self-exe-readlink`
- `test-proc-self-fd-stdin`
- `test-proc-self-readlink-edge-cases`
- `test-proc-self-root-readlink`
- `test-proc-toplevel-symlink`
- `test-proot-tmp-dir-env`
- `test-pwd-dash-w`
- `test-pwd-physical-smoke`
- `test-pwd-preserves-host-cwd`
- `test-readdir-bind-parent-traversal`
- `test-readdir-nested-bindings`
- `test-readdir-symlinked-dir`
- `test-readlink-abs-rel-symlink`
- `test-readlink-bind-detranslate`
- `test-readlink-deepest-binding`
- `test-readlink-getcwd-raw-syscall`
- `test-readlink-getcwd-shared-buffer`
- `test-readlink-proc-self-exe-raw-syscall`
- `test-readlinkat-empty-pathname`
- `test-relative-exec-w-bin`
- `test-rlimit-stack-brk`
- `test-rmdir-dot-path`
- `test-rootfs-arg-validation`
- `test-rootfs-exec`
- `test-rootfs-shebang-exec`
- `test-setcap-fake-id`
- `test-setuid-thread-vs-process`
- `test-shebang-length-limit`
- `test-sigtrap-self-raise`
- `test-stat-fake-ids`
- `test-symlink-create-dangling`
- `test-symlink-script-argv0`
- `test-symlink-self-referential`
- `test-sysexit`
- `test-unix-socket-bind-getsockname`
- `test-unix-socket-path-length`

## Skipped under literoot only

- `test-kill-on-exit-flag`
- `test-ld-library-path-foreign`
- `test-nested-proot-no-subreconf`
- `test-nested-proot-options`
- `test-python-extension-getdents`

Classification of the remaining 14: guest-ptrace/gdb/strace coexistence (11) is inherent to the ptrace backend (single tracer) and resolves only post stage-1b in-guest; foreign-binary (2) needs qemu (design out-of-scope); test-execve-sysexit-seccomp passes manually and in isolated make runs (in-suite flake); test-execve-eacces-enoexec is an upstream test bug (reclassified 2026-11-06, see below; retained by name).

## Reclassification: test-execve-eacces-enoexec (2026-11-06, museport/W1)

The upstream test declares `extern char *environ[];` (array, not
pointer-to-pointer), so both execve calls receive the address of the
`environ` variable as `envp`. Whether the kernel's envp walk then faults
depends on static-glibc copy-relocation/layout: with gcc 11.5 / glibc
2.34 (devbig030) the second execve returns EFAULT **natively, with no
tracer**, at -O0/-O1/-O2 and any environment size; correcting the
declaration to `extern char **environ;` makes the verbatim test pass
both natively and under literoot-ptrace. Frame-independent asm repros
(direct syscalls; stack-local and .data argv variants) show errno
sequence (EACCES then ENOEXEC), red zone, and 512 bytes below rsp fully
preserved across both failed execves under the Reverie ptrace backend,
identical to native — no backend guest-state corruption was found. The
earlier native-pass/literoot-fail split was the same latent UB surfacing
under a different toolchain. The name stays in the failing list (the
pinned upstream suite is the comparator and is not edited); the
corrected-declaration build of the same source is the W4
failed-exec-atomicity oracle candidate for stage-1b (it passes on
ptrace today, so S2 inherits a real gate). Docs/execve-eacces-evidence.md
retains the original characterization for history.

## Local reproduction baseline (devbig030) and run rules

Reproduced 2026-11-06 (EPYC 9D85, kernel 7.1.3, literoot @ PR#1 head
031dc11, reverie @ ac71ee9c): **97 ok / 25 FAILED / 10 skipped** — the
b17 set plus `test-unix-socket-bind-getsockname`. Two host-environment
deltas, both proven environmental, must not be re-derived as bugs:

- Run the suite with `TMPDIR` **unset for the guest** (host-side build
  `TMPDIR` must not leak into `make check`): a long host TMPDIR breaks
  `test-readlinkat-empty-pathname` (it builds its link path from
  `getenv("TMPDIR")`).
- Keep the suite rootfs at a **short host path**: translated AF_UNIX
  socket paths must fit `sun_path` (107 bytes);
  `test-unix-socket-bind-getsockname` fails with ENAMETOOLONG when
  `<rootfs>/test-nnnnnnnn-socket` exceeds it (110 bytes at this slot's
  depth).

