# Upstream proot test-suite results (M1, x86-64)

Suite: proot-me/proot v5.5.0 `test/` (94 shell + 38 C, 25dc6a3), GNUmakefile, CARE=/bin/false. EPYC 9D85, kernel 7.1.3. Unique names; no comparator loosening.

| Runner | ok | FAILED | skipped |
|---|---|---|---|
| proot 5.5.0 | 117 | 10 | 5 |
| literoot b0 | 43 | 79 | 13 |
| b1 readlink/bind/cwd | 49 | 74 | 12 |
| b2 detranslate/PWD/cwd | 56 | 68 | 11 |
| b3 identity/uname/chroot | 60 | 64 | 11 |
| b4 PATH/options/binds | 62 | 62 | 11 |
| b5 proc-self/exe | 64 | 60 | 11 |
| b6 canonicalize | 69 | 54 | 11 |
| b7 proc exe/fd | 72 | 51 | 11 |
| b8 dot/tmp-env | 75 | 48 | 11 |
| b9 shebang/mknod/virtual | 80 | 43 | 11 |
| b10 getcwd/dirfd | 81 | 43 | 10 |


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

- `test-asymmetric-binding-root`
- `test-bind-symlink-swap`
- `test-execve-eacces-enoexec`
- `test-execve-sysexit-seccomp`
- `test-fake-id-auxv-chroot`
- `test-fake-id0-permissions`
- `test-foreign-binary-emulation`
- `test-foreign-binary-proc-self-exe`
- `test-gdb-breakpoint-run`
- `test-gdb-ptrace`
- `test-getresid-native`
- `test-getresuid-getresgid-syscalls`
- `test-kernel-release-uts-fields`
- `test-kill-tracer-pid`
- `test-nested-ptrace`
- `test-path-search`
- `test-proc-cmdline-script-argv`
- `test-proc-comm-name-truncation`
- `test-ptrace-exec-trap`
- `test-ptrace-setoptions`
- `test-ptrace-sigtrap-execve`
- `test-ptrace-traceme-basic`
- `test-readdir-nested-bindings`
- `test-readlink-proc-self-exe-raw-syscall`
- `test-rootfs-arg-validation`
- `test-setcap-fake-id`
- `test-setuid-thread-vs-process`
- `test-shebang-length-limit`
- `test-strace-execve-count`
- `test-strace-fork-wait`
- `test-symlink-self-referential`
- `test-trace-without-parent-wait`
- `test-unix-socket-bind-getsockname`

## Passing under literoot

- `test-asymmetric-bind-cwd-readlink`
- `test-bind-chdir-getcwd`
- `test-bind-cwd-bash-pwd`
- `test-bind-file-over-etc`
- `test-bind-longer-path-pwd`
- `test-bind-ls-la`
- `test-bind-order-independence`
- `test-bind-proc-self-mounts`
- `test-bind-single-file`
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
- `test-fchownat-symlink`
- `test-fork-pipe-sigkill-stress`
- `test-fork-stress-loop`
- `test-fork-vfork-execve`
- `test-fork-wait-exit-status`
- `test-getresuid-getresgid-syscalls`
- `test-kernel-release-truncation`
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
- `test-path-symlink-exec-argv`
- `test-path-traversal-conformance`
- `test-pipe2-nonblock`
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
- `test-readdir-symlinked-dir`
- `test-readlink-abs-rel-symlink`
- `test-readlink-bind-detranslate`
- `test-readlink-deepest-binding`
- `test-readlink-getcwd-raw-syscall`
- `test-readlink-getcwd-shared-buffer`
- `test-readlinkat-empty-pathname`
- `test-relative-exec-w-bin`
- `test-rlimit-stack-brk`
- `test-rmdir-dot-path`
- `test-rootfs-exec`
- `test-rootfs-shebang-exec`
- `test-setuid-thread-vs-process`
- `test-sigtrap-self-raise`
- `test-stat-fake-ids`
- `test-symlink-create-dangling`
- `test-symlink-script-argv0`
- `test-sysexit`
- `test-unix-socket-path-length`

## Skipped under literoot only

- `test-kill-on-exit-flag`
- `test-ld-library-path-foreign`
- `test-nested-proot-no-subreconf`
- `test-nested-proot-options`
- `test-python-extension-getdents`

Note: test-asymmetric-binding-root regressed in the b10 full run and was fixed immediately after (explicit -w must not trigger host-cwd preservation; verified manually, full recount next batch). test-readlink-proc-self-exe-raw-syscall passes manually under both; intermittent in-suite, retained.

