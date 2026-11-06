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

See [docs/design.md](docs/design.md) for the full design: CLI compatibility
scope, interception mechanism, Android syscall-emulation requirements, state
model, dependency pins, and the correctness/performance test plan.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
