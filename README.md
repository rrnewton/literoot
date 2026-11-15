# literoot

A fast, drop-in replacement for [proot](https://proot-me.github.io/): run a
Linux root filesystem without privileges, user namespaces, or setuid helpers.

classic proot uses `ptrace` and pays a tracer stop for every path-taking
syscall. literoot instead runs its path-translation logic *inside* the guest
(Reverie + liteinst in-guest interception with a seccomp/Syscall User Dispatch
safety net for unpatched call sites), so non-path syscalls run natively and
path syscalls cost a local rewrite instead of two context switches.

**Status: early development (0.0.1). Not yet usable.** This release reserves
the name and tracks the design. Milestones: M1 x86-64 Linux correctness with a
differential oracle against real proot; M2 aarch64 Linux; M3 aarch64 Android
app sandbox (seccomp-constrained, no user namespaces).

Known issue: in non-fake-root mode the rootfs is not an isolation boundary.
Some path system calls can reach host files that the invoking user can already
access. Do not rely on literoot to confine untrusted programs. A fix is in
progress.

Install with `cargo install --path <checkout>` or `cargo install --git <repo>`.
The build also builds literoot's in-guest preload and embeds it in the
binary, so the in-guest backends need no second build step. Installing from
crates.io is not supported. At launch literoot writes the preload to a
private cache, `$XDG_CACHE_HOME/literoot/<sha256>/` (else
`~/.cache/literoot/<sha256>/`), and checks its SHA-256 again just before it
hands the file's path to the launcher; the guest loads the file later, by
that path. Other users cannot write there; a process of the same user could
still replace the file between that check and the load. When the
in-guest preload cannot be used, literoot refuses by name; it never falls back
to ptrace. `LITEROOT_PRELOAD=<file>` runs a separately built preload instead,
admitted only when its stamp matches this literoot.

See [docs/design.md](docs/design.md) for the full design: CLI compatibility
scope, interception mechanism, Android syscall-emulation requirements, state
model, dependency pins, and the correctness/performance test plan.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
