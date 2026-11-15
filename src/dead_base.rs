//! The dead-base answer: what a path call gets when its relative name
//! starts in a deleted directory (docs/design.md §4.9).
//!
//! The kernel answers such a call in a fixed order: its own argument checks
//! before any lookup, then the search permission of every directory the
//! walk passes (may_lookup), then ENOENT in the deleted directory
//! (IS_DEADDIR). literoot reproduces the first part by asking the kernel: it
//! injects a PROBE, the guest's own call with every dirfd -1 and every name
//! the staged "x" (or "y"), which fails EBADF at path_init before any lookup
//! in every root and namespace, or reports the argument error first. The
//! second part is the guest's own search check, `faccessat2` on the base.
//! The third is local.
//!
//! This module is the pure half: the one probe table, the probe builder,
//! the classification of a probe's result, and the search check's name.
//! The dispatch that injects them is `RootfsTool::dead_base_gate`.

use std::path::Path;
use std::path::PathBuf;

use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie::syscalls::SyscallArgs;

/// Where a probe argument comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgSrc {
    /// The guest call's own argument `n`.
    Arg(u8),
    /// -1: the dirfd that fails path_init with EBADF.
    NoBase,
    /// The staged single name: 0 is "x", 1 is "y".
    Name(u8),
    /// A constant.
    Const(u64),
}

use ArgSrc::Arg;
use ArgSrc::Const;
use ArgSrc::Name;
use ArgSrc::NoBase;

/// How a dead-base call's argument checks are reproduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// T1: the `*at` call `nr` built from `args`.
    T1 { nr: Sysno, args: [ArgSrc; 6] },
    /// T3: the guest's bind with sun_path "/" and addrlen 4.
    Bind,
    /// T4: the guest's connect with `{AF_UNIX}` and addrlen 2.
    Connect,
    /// L: no argument check runs before the lookup; nothing is injected.
    Local,
    /// No probe can be issued: setxattrat has no number in literoot's
    /// syscall table (Reverie's syscalls 0.6.18 ends at 461). The argument
    /// checks are skipped; a dead NAME or a failed search check is refused
    /// by name.
    Unavailable,
}

/// One relative name of a call: its dirfd argument (None: the cwd) and its
/// path argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    pub dirfd: Option<u8>,
    pub path: u8,
}

/// Whose ids the search check uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchIds {
    /// The effective ids (AT_EACCESS): every caller but the access family.
    Effective,
    /// The real ids: access and faccessat, which switch to them before
    /// their own lookup (do_faccessat, fs/open.c:478-493 at v6.18.55).
    Real,
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub slots: &'static [Slot],
    pub probe: Probe,
    /// The errnos the kernel answers before the lookup for this call: a
    /// probe that returns one of them returns it as the call's answer.
    pub pre_lookup: &'static [Errno],
    pub ids: SearchIds,
}

const CWD0: &[Slot] = &[Slot { dirfd: None, path: 0 }];
#[cfg(target_arch = "x86_64")]
const CWD1: &[Slot] = &[Slot { dirfd: None, path: 1 }];
const AT01: &[Slot] = &[Slot { dirfd: Some(0), path: 1 }];
const AT12: &[Slot] = &[Slot { dirfd: Some(1), path: 2 }];
#[cfg(target_arch = "x86_64")]
const CWD01: &[Slot] = &[Slot { dirfd: None, path: 0 }, Slot { dirfd: None, path: 1 }];
const AT0123: &[Slot] = &[Slot { dirfd: Some(0), path: 1 }, Slot { dirfd: Some(2), path: 3 }];

const NONE: &[Errno] = &[];
const EINVAL: &[Errno] = &[Errno::EINVAL];
const OPEN: &[Errno] = &[Errno::EINVAL, Errno::EMFILE];
const OPENAT2: &[Errno] = &[Errno::EINVAL, Errno::E2BIG, Errno::EFAULT, Errno::EMFILE];
const SYMLINK: &[Errno] = &[Errno::EFAULT, Errno::ENAMETOOLONG];
const EXEC: &[Errno] = &[Errno::EAGAIN];
// utimensat copies the times before the path (fs/utimes.c).
const UTIMENS: &[Errno] = &[Errno::EINVAL, Errno::EFAULT];

#[cfg(target_arch = "x86_64")]
const AT_SYMLINK_NOFOLLOW: u64 = libc::AT_SYMLINK_NOFOLLOW as u64;
#[cfg(target_arch = "x86_64")]
const AT_REMOVEDIR: u64 = libc::AT_REMOVEDIR as u64;

const fn t1(nr: Sysno, args: [ArgSrc; 6]) -> Probe {
    Probe::T1 { nr, args }
}

const fn row(slots: &'static [Slot], probe: Probe, pre_lookup: &'static [Errno]) -> Entry {
    Entry {
        slots,
        probe,
        pre_lookup,
        ids: SearchIds::Effective,
    }
}

/// The one table: every call literoot translates with a relative name, and
/// how its dead-base answer is built. No T1 entry keeps a guest dirfd or a
/// guest name, and no entry holds an absolute path: none can resolve
/// against the guest's cwd, root or mount namespace.
pub(crate) fn dead_base_probe(nr: Sysno) -> Option<Entry> {
    use Sysno as S;
    let z = Const(0);
    Some(match nr {
        #[cfg(target_arch = "x86_64")]
        S::open => row(CWD0, t1(S::openat, [NoBase, Name(0), Arg(1), Arg(2), z, z]), OPEN),
        S::openat => row(AT01, t1(S::openat, [NoBase, Name(0), Arg(2), Arg(3), z, z]), OPEN),
        S::openat2 => row(AT01, t1(S::openat2, [NoBase, Name(0), Arg(2), Arg(3), z, z]), OPENAT2),
        #[cfg(target_arch = "x86_64")]
        S::access => Entry {
            ids: SearchIds::Real,
            ..row(CWD0, t1(S::faccessat, [NoBase, Name(0), Arg(1), z, z, z]), EINVAL)
        },
        S::faccessat => Entry {
            ids: SearchIds::Real,
            ..row(AT01, t1(S::faccessat, [NoBase, Name(0), Arg(2), z, z, z]), EINVAL)
        },
        #[cfg(target_arch = "x86_64")]
        S::chmod => row(CWD0, t1(S::fchmodat, [NoBase, Name(0), Arg(1), z, z, z]), NONE),
        S::fchmodat => row(AT01, t1(S::fchmodat, [NoBase, Name(0), Arg(2), z, z, z]), NONE),
        #[cfg(target_arch = "x86_64")]
        S::chown => row(CWD0, t1(S::fchownat, [NoBase, Name(0), Arg(1), Arg(2), z, z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::lchown => row(
            CWD0,
            t1(S::fchownat, [NoBase, Name(0), Arg(1), Arg(2), Const(AT_SYMLINK_NOFOLLOW), z]),
            EINVAL,
        ),
        S::fchownat => row(AT01, t1(S::fchownat, [NoBase, Name(0), Arg(2), Arg(3), Arg(4), z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::stat => row(CWD0, t1(S::newfstatat, [NoBase, Name(0), Arg(1), z, z, z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::lstat => row(
            CWD0,
            t1(S::newfstatat, [NoBase, Name(0), Arg(1), Const(AT_SYMLINK_NOFOLLOW), z, z]),
            EINVAL,
        ),
        #[cfg(target_arch = "x86_64")]
        S::newfstatat => row(AT01, t1(S::newfstatat, [NoBase, Name(0), Arg(2), Arg(3), z, z]), EINVAL),
        // aarch64's name for newfstatat.
        #[cfg(target_arch = "aarch64")]
        S::fstatat => row(AT01, t1(S::fstatat, [NoBase, Name(0), Arg(2), Arg(3), z, z]), EINVAL),
        S::statx => row(AT01, t1(S::statx, [NoBase, Name(0), Arg(2), Arg(3), Arg(4), z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::mkdir => row(CWD0, t1(S::mkdirat, [NoBase, Name(0), Arg(1), z, z, z]), NONE),
        S::mkdirat => row(AT01, t1(S::mkdirat, [NoBase, Name(0), Arg(2), z, z, z]), NONE),
        S::mknodat => row(AT01, t1(S::mknodat, [NoBase, Name(0), Arg(2), Arg(3), z, z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::unlink => row(CWD0, t1(S::unlinkat, [NoBase, Name(0), z, z, z, z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::rmdir => row(CWD0, t1(S::unlinkat, [NoBase, Name(0), Const(AT_REMOVEDIR), z, z, z]), EINVAL),
        S::unlinkat => row(AT01, t1(S::unlinkat, [NoBase, Name(0), Arg(2), z, z, z]), EINVAL),
        #[cfg(target_arch = "x86_64")]
        S::rename => row(CWD01, t1(S::renameat2, [NoBase, Name(0), NoBase, Name(1), z, z]), EINVAL),
        S::renameat => row(AT0123, t1(S::renameat2, [NoBase, Name(0), NoBase, Name(1), z, z]), EINVAL),
        S::renameat2 => row(
            AT0123,
            t1(S::renameat2, [NoBase, Name(0), NoBase, Name(1), Arg(4), z]),
            EINVAL,
        ),
        #[cfg(target_arch = "x86_64")]
        S::link => row(CWD01, t1(S::linkat, [NoBase, Name(0), NoBase, Name(1), z, z]), EINVAL),
        S::linkat => row(AT0123, t1(S::linkat, [NoBase, Name(0), NoBase, Name(1), Arg(4), z]), EINVAL),
        // The target is not a path the kernel resolves: it is kept.
        #[cfg(target_arch = "x86_64")]
        S::symlink => row(CWD1, t1(S::symlinkat, [Arg(0), NoBase, Name(0), z, z, z]), SYMLINK),
        S::symlinkat => row(AT12, t1(S::symlinkat, [Arg(0), NoBase, Name(0), z, z, z]), SYMLINK),
        #[cfg(target_arch = "x86_64")]
        S::readlink => row(CWD0, t1(S::readlinkat, [NoBase, Name(0), Arg(1), Arg(2), z, z]), EINVAL),
        S::readlinkat => row(AT01, t1(S::readlinkat, [NoBase, Name(0), Arg(2), Arg(3), z, z]), EINVAL),
        S::name_to_handle_at => row(
            AT01,
            t1(S::name_to_handle_at, [NoBase, Name(0), Arg(2), Arg(3), Arg(4), z]),
            EINVAL,
        ),
        S::utimensat => row(AT01, t1(S::utimensat, [NoBase, Name(0), Arg(2), Arg(3), z, z]), UTIMENS),
        S::execve => row(CWD0, t1(S::execveat, [NoBase, Name(0), Arg(1), Arg(2), z, z]), EXEC),
        S::setxattr | S::lsetxattr => row(CWD0, Probe::Unavailable, NONE),
        S::statfs | S::chdir | S::chroot => row(CWD0, Probe::Local, NONE),
        S::bind => row(&[], Probe::Bind, NONE),
        S::connect => row(&[], Probe::Connect, NONE),
        _ => return None,
    })
}

/// The T1 probe for `raw`, the guest call's arguments, with the staged names
/// at `names[0]` ("x") and `names[1]` ("y").
pub(crate) fn build_t1(nr: Sysno, args: &[ArgSrc; 6], raw: &SyscallArgs, names: [usize; 2]) -> Syscall {
    let guest = [raw.arg0, raw.arg1, raw.arg2, raw.arg3, raw.arg4, raw.arg5];
    let value = |src: ArgSrc| -> usize {
        match src {
            Arg(n) => guest[n as usize],
            NoBase => -1i64 as usize,
            Name(n) => names[n as usize],
            Const(v) => v as usize,
        }
    };
    let a = args.map(value);
    Syscall::Other(nr, SyscallArgs::new(a[0], a[1], a[2], a[3], a[4], a[5]))
}

/// What a probe's result means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// The probe reached the lookup: the search check and the local steps
    /// decide.
    LookupReached,
    /// An argument error the kernel answers before the lookup: the call's
    /// answer.
    Answer(Errno),
    /// Anything outside the probe's expected set (ENOSYS, EPERM, a success,
    /// an unlisted errno): literoot has no trustworthy answer (K7 trigger 2).
    Unsupported,
}

#[cfg(test)]
thread_local! {
    /// Test observer: the dead-base probe steps on this thread, in order
    /// (`reread` from the socket descriptor re-read, `classify` from
    /// [`classify`]; a unit adds its own `probe` at the injection).
    pub(crate) static PROBE_TRACE: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Record one step in [`PROBE_TRACE`] (test builds only).
#[cfg(test)]
pub(crate) fn trace(step: &'static str) {
    PROBE_TRACE.with(|t| t.borrow_mut().push(step));
}

/// Classify a probe result. The positive signal is EBADF for T1, EADDRINUSE
/// for T3 and EINVAL for T4. A success is never trusted, and nothing it
/// might have returned is closed.
pub(crate) fn classify(probe: Probe, pre_lookup: &[Errno], result: Result<i64, Errno>) -> ProbeOutcome {
    #[cfg(test)]
    trace("classify");
    let signal = match probe {
        Probe::T1 { .. } => Errno::EBADF,
        Probe::Bind => Errno::EADDRINUSE,
        Probe::Connect => Errno::EINVAL,
        Probe::Local | Probe::Unavailable => return ProbeOutcome::LookupReached,
    };
    match result {
        Err(e) if e == signal => ProbeOutcome::LookupReached,
        Err(e) if e == Errno::ENOSYS || e == Errno::EPERM => ProbeOutcome::Unsupported,
        Err(e) if pre_lookup.contains(&e) => ProbeOutcome::Answer(e),
        _ => ProbeOutcome::Unsupported,
    }
}

/// The name the guest's search check walks from its base (E1): the guest's
/// own leading run of "." and ".." components, verbatim. When that run is
/// the whole name, its last component is dropped: link_path_walk checks
/// may_lookup before every component, the last included, but never on the
/// target of the last one. Empty means the base itself (AT_EMPTY_PATH).
pub(crate) fn search_name(path: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    let parts: Vec<&[u8]> = path
        .as_os_str()
        .as_bytes()
        .split(|&b| b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    let run = parts
        .iter()
        .take_while(|p| **p == b"." || **p == b"..")
        .count();
    let keep = if run == parts.len() { run.saturating_sub(1) } else { run };
    let mut out = PathBuf::new();
    for p in &parts[..keep] {
        out.push(std::ffi::OsStr::from_bytes(p));
    }
    out
}

/// The flags of the guest's search check.
pub(crate) fn search_flags(ids: SearchIds, name: &Path) -> i32 {
    let mut flags = match ids {
        SearchIds::Effective => libc::AT_EACCESS,
        SearchIds::Real => 0,
    };
    if name.as_os_str().is_empty() {
        flags |= libc::AT_EMPTY_PATH;
    }
    flags
}

/// open_last_lookups' EISDIR: an open with O_CREAT of a single component
/// spelled with a trailing slash. The kernel answers it before the
/// deleted directory's ENOENT.
pub(crate) fn create_with_trailing_slash(path: &Path, open_flags: u64) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_os_str().as_bytes();
    let name = bytes.split(|&b| b == b'/').filter(|p| !p.is_empty()).count() == 1;
    open_flags & libc::O_CREAT as u64 != 0 && name && bytes.ends_with(b"/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every sysno the table names.
    fn all_rows() -> Vec<(Sysno, Entry)> {
        Sysno::iter()
            .filter_map(|nr| dead_base_probe(nr).map(|e| (nr, e)))
            .collect()
    }

    #[test]
    fn dead_base_probe_namespace_independent() {
        let rows = all_rows();
        // The exact row count of each arch. Both arches share 24 rows;
        // x86_64 adds its 15 x86_64-only calls (open, access, chmod,
        // chown, lchown, stat, lstat, newfstatat, mkdir, unlink, rmdir,
        // rename, link, symlink, readlink), and aarch64 adds fstatat, its
        // name for newfstatat. A dropped or added row on either arch fails
        // here.
        #[cfg(target_arch = "x86_64")]
        const ROWS: usize = 39;
        #[cfg(target_arch = "aarch64")]
        const ROWS: usize = 25;
        let names: Vec<Sysno> = rows.iter().map(|(nr, _)| *nr).collect();
        assert_eq!(rows.len(), ROWS, "{names:?}");
        for (nr, entry) in rows {
            match entry.probe {
                Probe::T1 { args, .. } => {
                    // Every slot's dirfd and name is replaced: no guest dirfd
                    // and no guest path reaches the probe.
                    for slot in entry.slots {
                        if let Some(d) = slot.dirfd {
                            assert!(!args.contains(&Arg(d)), "{nr:?} keeps a guest dirfd");
                        }
                        assert!(!args.contains(&Arg(slot.path)), "{nr:?} keeps a guest name");
                    }
                    // Each staged name follows a -1 dirfd.
                    for (i, a) in args.iter().enumerate() {
                        if let Name(_) = a {
                            assert!(i > 0 && args[i - 1] == NoBase, "{nr:?} name without dirfd -1");
                        }
                    }
                }
                Probe::Local => {
                    assert!(matches!(nr, Sysno::statfs | Sysno::chdir | Sysno::chroot), "{nr:?}");
                }
                Probe::Unavailable => {
                    assert!(matches!(nr, Sysno::setxattr | Sysno::lsetxattr), "{nr:?}");
                }
                Probe::Bind | Probe::Connect => {}
            }
        }
        assert_eq!(dead_base_probe(Sysno::execve).map(|e| e.probe), Some(t1(Sysno::execveat, [NoBase, Name(0), Arg(1), Arg(2), Const(0), Const(0)])));
    }

    #[test]
    fn build_t1_places_minus_one_and_the_staged_names() {
        let raw = SyscallArgs::new(7, 0x1000, 8, 0x2000, 3, 0);
        let entry = dead_base_probe(Sysno::renameat2).unwrap();
        let Probe::T1 { nr, args } = entry.probe else { panic!() };
        let built = build_t1(nr, &args, &raw, [0xa0, 0xb0]);
        let (n, a) = reverie::syscalls::SyscallInfo::into_parts(built);
        assert_eq!(n, Sysno::renameat2);
        assert_eq!(
            [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4],
            [usize::MAX, 0xa0, usize::MAX, 0xb0, 3]
        );
    }

    #[test]
    fn classify_trusts_only_the_signal_and_the_listed_errnos() {
        let t1 = dead_base_probe(Sysno::openat).unwrap();
        let c = |r| classify(t1.probe, t1.pre_lookup, r);
        assert_eq!(c(Err(Errno::EBADF)), ProbeOutcome::LookupReached);
        assert_eq!(c(Err(Errno::EINVAL)), ProbeOutcome::Answer(Errno::EINVAL));
        assert_eq!(c(Err(Errno::EPERM)), ProbeOutcome::Unsupported);
        assert_eq!(c(Err(Errno::ENOSYS)), ProbeOutcome::Unsupported);
        assert_eq!(c(Err(Errno::ENOENT)), ProbeOutcome::Unsupported);
        assert_eq!(c(Ok(0)), ProbeOutcome::Unsupported);
        assert_eq!(c(Ok(5)), ProbeOutcome::Unsupported);
        assert_eq!(classify(Probe::Bind, NONE, Err(Errno::EADDRINUSE)), ProbeOutcome::LookupReached);
        assert_eq!(classify(Probe::Bind, NONE, Err(Errno::EACCES)), ProbeOutcome::Unsupported);
        assert_eq!(classify(Probe::Connect, NONE, Err(Errno::EINVAL)), ProbeOutcome::LookupReached);
        assert_eq!(classify(Probe::Connect, NONE, Err(Errno::EACCES)), ProbeOutcome::Unsupported);
    }

    #[test]
    fn search_name_is_the_leading_dot_run() {
        for (path, want) in [
            ("x", ""),
            ("../../x", "../.."),
            ("..", ""),
            ("../..", ".."),
            ("../..//", ".."),
            ("../a/x", ".."),
            ("./x", "."),
            ("../.", ".."),
            ("a/../x", ""),
        ] {
            assert_eq!(search_name(Path::new(path)), Path::new(want), "{path}");
        }
        assert_eq!(search_flags(SearchIds::Effective, Path::new("")), libc::AT_EACCESS | libc::AT_EMPTY_PATH);
        assert_eq!(search_flags(SearchIds::Real, Path::new("..")), 0);
    }

    #[test]
    fn eisdir_only_for_a_created_single_name_with_a_slash() {
        let creat = libc::O_CREAT as u64;
        assert!(create_with_trailing_slash(Path::new("x/"), creat));
        assert!(!create_with_trailing_slash(Path::new("x"), creat));
        assert!(!create_with_trailing_slash(Path::new("x/"), 0));
        assert!(!create_with_trailing_slash(Path::new("../x/"), creat));
    }

    /// Tracked follow-up: the table cannot name setxattrat today, which is why
    /// setxattr and lsetxattr in a dead base are refused. When the pinned
    /// syscalls crate gains it, this fails, and the probe must be restored.
    #[test]
    fn sysno_has_no_setxattrat() {
        assert!(Sysno::iter().all(|nr| nr.name() != "setxattrat"));
    }

    /// C5a.7: the syscall table Reverie resolves (syscalls 0.6.18,
    /// `Sysno::new` an exact match over the x86_64 table) names no x32
    /// number, so an x32 prctl (0x4000_009d) or ptrace (0x4000_0209) call is
    /// never decoded as its x86_64 twin.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sysno_has_no_x32_numbers() {
        assert_eq!(Sysno::new(0x4000_009d), None, "x32 prctl");
        assert_eq!(Sysno::new(0x4000_0209), None, "x32 ptrace");
        assert!(Sysno::iter().all(|nr| nr.id() & 0x4000_0000 == 0));
    }

    /// The files under `dir` with one of `exts`, recursively.
    fn files_under(dir: &std::path::Path, exts: &[&str]) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("read {}: {e}", d.display())) {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|x| x.to_str()).is_some_and(|x| exts.contains(&x)) {
                    found.push(path);
                }
            }
        }
        found.sort();
        found
    }

    /// The Reverie checkout literoot builds against (the rev in Cargo.lock,
    /// in Cargo's git checkouts), and the repository root. A checkout that
    /// cannot be found fails by name; it is never skipped.
    fn reverie_checkout() -> (std::path::PathBuf, std::path::PathBuf) {
        use std::path::Path;
        use std::path::PathBuf;
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = if manifest.ends_with("preload") { manifest.parent().unwrap() } else { manifest };
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let rev = lock
            .lines()
            .find_map(|l| l.strip_prefix("source = \"git+https://github.com/facebookexperimental/reverie?rev="))
            .and_then(|l| l.split('#').nth(1))
            .map(|r| r.trim_end_matches('"').to_string())
            .expect("the Reverie rev in Cargo.lock");
        let home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
            .expect("CARGO_HOME or HOME");
        let checkouts = home.join("git/checkouts");
        let checkout = std::fs::read_dir(&checkouts)
            .unwrap_or_else(|e| panic!("read {}: {e}", checkouts.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path().join(&rev[..7]))
            .find(|p| p.join("reverie-inguest/src/guest/host.rs").is_file())
            .unwrap_or_else(|| panic!("no Reverie checkout of {rev} under {}", checkouts.display()));
        (checkout, root.to_path_buf())
    }

    /// C3.5's static witness: no dispatch setter (prctl option 59,
    /// PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_*; ptrace 0x4210,
    /// PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG) is spelled in the in-guest
    /// crates literoot runs (reverie-inguest, reverie-liteinst,
    /// reverie-liteinst-preload, reverie-loader) or in literoot's own
    /// non-test sources, outside the allow-list: Reverie's test fixture,
    /// literoot's constants and the two matchers that refuse or classify a
    /// guest call (never issue one), and the preload's single pre-arming
    /// OFF call. That call's function runs before either install call in
    /// the preload constructor (source order), so no setter is issued once
    /// the filter exists.
    #[test]
    fn sud_setter_static_witness() {
        let setter = |line: &str| {
            ["PR_SET_SYSCALL_USER_DISPATCH", "PR_SYS_DISPATCH", "PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG", "0x4210"]
                .iter()
                .any(|t| line.contains(t))
                || (line.contains("prctl") && line.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == "59"))
        };
        let (reverie, root) = reverie_checkout();
        let mut hits = Vec::new();
        let mut sentinels = 0;
        for krate in ["reverie-inguest", "reverie-liteinst", "reverie-liteinst-preload", "reverie-loader"] {
            for path in files_under(&reverie.join(krate), &["rs", "c", "h", "S", "inc"]) {
                let text = std::fs::read_to_string(&path).unwrap();
                let rel = path.strip_prefix(&reverie).unwrap().display().to_string();
                for line in text.lines().filter(|l| setter(l)) {
                    hits.push(format!("{rel}: {}", line.trim()));
                }
            }
        }
        for dir in ["src", "preload/src"] {
            for path in files_under(&root.join(dir), &["rs"]) {
                let rel = path.strip_prefix(&root).unwrap().display().to_string();
                if rel == "src/rootfs_tool_seams.rs" {
                    continue; // a #[cfg(test)] module file
                }
                let text = crate::test_source::without_test_items(&std::fs::read_to_string(&path).unwrap());
                // The strip keeps production code that follows a test item
                // and drops a test module to its end: a production line
                // late in the file is kept, the file's last test fn is gone.
                if let Some((kept, gone)) = match rel.as_str() {
                    "src/dead_base.rs" => Some(("pub fn tracked_dispatch_after(", "fn unknown_count_refuses_that_probe_only(")),
                    "src/side_log.rs" => Some(("pub fn take_from_args(", "fn the_option_is_taken_before_any_other_and_only_once(")),
                    "preload/src/prearm.rs" => Some(("pub fn take_sud_absent(", "fn decide_off_by_arch_release_and_persona(")),
                    _ => None,
                } {
                    assert!(text.contains(kept), "{rel}: production after a test item was stripped");
                    assert!(!text.contains(gone), "{rel}: test code was scanned as production");
                    sentinels += 1;
                }
                for line in text.lines().filter(|l| setter(l) && !l.trim_start().starts_with("//")) {
                    hits.push(format!("{rel}: {}", line.trim()));
                }
            }
        }
        assert_eq!(sentinels, 3, "each stripped file's production sentinel was checked");
        // The allow-list, exact: every entry is hit exactly once, so an entry
        // that no longer matches (or a scan that stopped reaching it) fails.
        // The fixture lines are Reverie's, at the rev Cargo.lock pins.
        const FIXTURE: &str = "reverie-inguest/tests/fixtures/aarch64_trap_probe.c: ";
        let allowed: Vec<String> = [
            "#ifndef PR_SET_SYSCALL_USER_DISPATCH",
            "#define PR_SET_SYSCALL_USER_DISPATCH 59",
            "#define PR_SYS_DISPATCH_OFF 0",
            "#define PR_SYS_DISPATCH_ON 1",
            "/* PR_SYS_DISPATCH_ON is EXCLUSIVE (range = always-allowed dispatcher).",
            "#ifndef PR_SYS_DISPATCH_INCLUSIVE_ON",
            "#define PR_SYS_DISPATCH_INCLUSIVE_ON 2",
            "return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_INCLUSIVE_ON,",
            "prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0);",
        ]
        .iter()
        .map(|l| format!("{FIXTURE}{l}"))
        .chain(
            [
                "src/dead_base.rs: pub const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;",
                "src/dead_base.rs: pub const PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG: u64 = 0x4210;",
                "src/dead_base.rs: (nr == Sysno::prctl && args[0] as u32 as i32 == PR_SET_SYSCALL_USER_DISPATCH).then_some(args[1])",
                "src/dead_base.rs: request == PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG",
                "preload/src/prearm.rs: const PR_SET_SYSCALL_USER_DISPATCH: u64 = 59;",
                "preload/src/prearm.rs: let off = unsafe { raw(libc::SYS_prctl, [PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0, 0]) };",
            ]
            .iter()
            .map(|l| l.to_string()),
        )
        .collect();
        let outside: Vec<_> = hits.iter().filter(|h| !allowed.contains(h)).collect();
        assert!(outside.is_empty(), "dispatch setters outside the allow-list: {outside:#?}");
        for entry in &allowed {
            assert_eq!(hits.iter().filter(|h| *h == entry).count(), 1, "allow-list entry not hit exactly once: {entry}");
        }
        let off = "preload/src/prearm.rs: let off = unsafe { raw(libc::SYS_prctl, [PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0, 0]) };";
        assert_eq!(hits.iter().filter(|h| h.as_str() == off).count(), 1, "one pre-arming OFF call");
        let lib = crate::test_source::without_test_items(&std::fs::read_to_string(root.join("preload/src/lib.rs")).unwrap());
        let check = lib.find("prearm::check_before_arming()").expect("the pre-arming checks");
        for install in ["install_tool_with::<", "install_tool_from_bootstrap::<"] {
            let at = lib.find(install).unwrap_or_else(|| panic!("{install}"));
            assert!(check < at, "the OFF call's function runs before {install}");
        }
        let prearm = crate::test_source::without_test_items(&std::fs::read_to_string(root.join("preload/src/prearm.rs")).unwrap());
        let body = &prearm[prearm.find("pub fn check_before_arming()").expect("check_before_arming")..];
        let body = &body[..body.find("\n}\n").expect("its end")];
        assert!(body.contains("[PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0, 0]"), "the OFF call is in it");
    }

    /// B3 (P3-b): the dormant in-guest thread admission stays dormant.
    /// literoot's own sources (src/ and the preload crate) never call
    /// Reverie's `set_thread_admission`, and the Reverie checkout literoot
    /// builds against (the rev in Cargo.lock, in Cargo's git checkouts) still
    /// starts every host with `admit_threads: false`. A checkout that cannot
    /// be found fails by name; it is never skipped.
    #[test]
    fn thread_admission_never_enabled() {
        use std::path::Path;
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = if manifest.ends_with("preload") { manifest.parent().unwrap() } else { manifest };
        let needle = concat!("set_thread", "_admission(");
        let mut stack = vec![root.join("src"), root.join("preload/src")];
        let mut scanned = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    assert!(!text.contains(needle), "{} calls set_thread_admission", path.display());
                    scanned += 1;
                }
            }
        }
        assert!(scanned > 20, "only {scanned} source files scanned");
        let host = reverie_checkout().0.join("reverie-inguest/src/guest/host.rs");
        let text = std::fs::read_to_string(&host).unwrap();
        assert!(
            text.contains("install_gate: SpinMutex::new(()),\n            admit_threads: false,\n"),
            "{}: the host's default is no longer admit_threads: false",
            host.display()
        );
        let setter = concat!("pub fn set_thread", "_admission(&mut self, enabled: bool)");
        assert!(text.contains(setter), "{}", host.display());
        // The other host's default, and no call that
        // turns admission on outside host.rs's test module, in the in-guest
        // and liteinst runtimes.
        let checkout = reverie_checkout().0;
        let linux = checkout.join("reverie-inguest/src/guest/host_linux.rs");
        let linux_text = std::fs::read_to_string(&linux).unwrap();
        assert!(linux_text.contains("admit_threads: false,"), "{}: its default", linux.display());
        let mut files = Vec::new();
        for crate_dir in ["reverie-inguest/src", "reverie-liteinst/src"] {
            let mut stack = vec![checkout.join(crate_dir)];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|x| x == "rs") {
                        let text = std::fs::read_to_string(&path).unwrap();
                        files.push((path, text));
                    }
                }
            }
        }
        assert!(files.len() > 20, "only {} Reverie files scanned", files.len());
        assert_eq!(admission_enabled_outside_tests(&files), Vec::<String>::new());
    }

    /// Where `files` turn thread admission on outside a test: a call of the
    /// host's admission setter, or an `admit_threads` field set true, anywhere but
    /// guest/host.rs after its first `#[cfg(test)]` module. Each as
    /// "path:line".
    fn admission_enabled_outside_tests(files: &[(std::path::PathBuf, String)]) -> Vec<String> {
        let call = concat!(".set_thread", "_admission(");
        let on = concat!("admit_threads", ": true");
        let mut out = Vec::new();
        for (path, text) in files {
            let tests_from = if path.ends_with("guest/host.rs") {
                text.find("#[cfg(test)]\nmod ").unwrap_or(text.len())
            } else {
                text.len()
            };
            for needle in [call, on] {
                for (at, _) in text.match_indices(needle) {
                    if at < tests_from {
                        let line = text[..at].matches('\n').count() + 1;
                        out.push(format!("{}:{line}", path.display()));
                    }
                }
            }
        }
        out
    }

    /// The scan above flags a call or a `true` default outside the test
    /// module, and accepts them inside it.
    #[test]
    fn admission_scan_flags_non_test_uses() {
        let host = std::path::PathBuf::from("r/reverie-inguest/src/guest/host.rs");
        let other = std::path::PathBuf::from("r/reverie-liteinst/src/lib.rs");
        let call = concat!("host.set_thread", "_admission(true);");
        let on = concat!("admit_threads", ": true,");
        let tests = format!("fn a() {{}}\n#[cfg(test)]\nmod tests {{\n    {call}\n    {on}\n}}\n");
        assert!(admission_enabled_outside_tests(&[(host.clone(), tests.clone())]).is_empty(), "inside the test module");
        let early = format!("fn a() {{ {call} }}\n{tests}");
        assert_eq!(admission_enabled_outside_tests(&[(host.clone(), early)]), vec![format!("{}:1", host.display())]);
        let default_on = format!("struct S;\nfn b() {{ S {{ {on} }} }}\n");
        assert_eq!(admission_enabled_outside_tests(&[(other.clone(), default_on)]), vec![format!("{}:2", other.display())]);
        assert_eq!(admission_enabled_outside_tests(&[(other.clone(), tests)]).len(), 2, "another file has no test module exemption");
    }
}

/// Whether a guest call installs a seccomp filter (S.3), its arguments read
/// at the kernel's widths, as Reverie's in-guest policy reads them (R
/// reverie-inguest guest/host.rs:3614-3619): seccomp's operation is an
/// unsigned int and prctl's option an int; prctl's mode is an unsigned long.
pub fn installs_seccomp_filter(nr: Sysno, args: [u64; 6]) -> bool {
    (nr == Sysno::seccomp && args[0] as u32 == libc::SECCOMP_SET_MODE_FILTER)
        || (nr == Sysno::prctl
            && args[0] as u32 as i32 == libc::PR_SET_SECCOMP
            && args[1] == u64::from(libc::SECCOMP_MODE_FILTER))
}

/// prctl's PR_SET_SYSCALL_USER_DISPATCH option (include/uapi/linux/prctl.h).
pub const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;
/// ptrace's PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG and
/// PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG (include/uapi/linux/ptrace.h).
pub const PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG: u64 = 0x4210;
pub const PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG: u64 = 0x4211;

/// The mode of a guest prctl(PR_SET_SYSCALL_USER_DISPATCH, mode, ...), or
/// None for any other call. The option is the low 32 bits of arg0, as the
/// kernel declares `int option`; the mode is the whole `unsigned long`
/// arg1 (kernel/sys.c, kernel/entry/syscall_user_dispatch.c).
pub fn dispatch_setter_mode(nr: Sysno, args: [u64; 6]) -> Option<u64> {
    (nr == Sysno::prctl && args[0] as u32 as i32 == PR_SET_SYSCALL_USER_DISPATCH).then_some(args[1])
}

/// Whether a ptrace request word is PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG:
/// the request is a whole `long`, so `0x1_0000_4210` is not it (C5.7). The
/// opposite of prctl's low-32-bit option rule; each follows its syscall's
/// declared type.
pub fn is_ptrace_dispatch_setter(request: u64) -> bool {
    request == PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG
}

/// Whether a dispatch setter with `mode` is refused (R1): any mode other
/// than OFF, where the config refuses guest dispatch (in-guest backends).
/// A refused call is answered before anything is injected.
pub fn refuses_dispatch_setter(refuse_guest_dispatch: bool, mode: u64) -> bool {
    refuse_guest_dispatch && mode != 0
}

/// The tracked dispatch mode (true = ON) after a forwarded
/// prctl(PR_SET_SYSCALL_USER_DISPATCH, `mode`) whose result is `result`
/// (None when unknown: cancelled). Only an exact 0 is a success (C2.2): 0
/// with mode OFF sets OFF, 0 with any other mode sets ON; a negative errno
/// leaves the state; any other value (157 is a dispatched injection's
/// rollback, which leaves the prctl number) or an unknown result sets ON.
pub fn tracked_dispatch_after(was_on: bool, mode: u64, result: Option<i64>) -> bool {
    match result {
        Some(0) => mode != 0,
        Some(r) if r < 0 => was_on,
        _ => true,
    }
}

/// The decimal value of the `name:` line of a /proc status text: blanks,
/// then digits to the end of the line. None when the line is missing,
/// repeated, empty or out of range. Allocates nothing (the preload's
/// constructor calls it before arming).
pub fn status_field(buf: &[u8], name: &[u8]) -> Option<u64> {
    let mut found = None;
    for line in buf.split(|&b| b == b'\n') {
        let Some(rest) = line.strip_prefix(name).and_then(|r| r.strip_prefix(b":")) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        let digits = rest.trim_ascii_start();
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut v: u64 = 0;
        for &d in digits {
            v = v.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
        }
        found = Some(v);
    }
    found
}

/// The filter-count detector's verdict (C3.6, baseline delta (A)):
/// the observed `Seccomp_filters` against the expected count. Best-effort,
/// defeatable by a guest that jumps to a trusted gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterCount {
    Match,
    /// More filters than expected: one literoot did not see installed.
    Excess,
    /// Fewer (impossible natively: filters are never removed).
    Deficit,
    /// The expected or the observed count is unknown.
    Unknown,
}

/// Compare an observed filter count with the expected one.
pub fn filter_count_verdict(expected: Option<u32>, observed: Option<u32>) -> FilterCount {
    match (expected, observed) {
        (Some(e), Some(o)) if o == e => FilterCount::Match,
        (Some(e), Some(o)) if o > e => FilterCount::Excess,
        (Some(_), Some(_)) => FilterCount::Deficit,
        _ => FilterCount::Unknown,
    }
}

/// How a process record came to be flagged: the summary's `flag=` field.
/// Its own successful install wins over inheritance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FlagState {
    #[default]
    None,
    Installed,
    Inherited,
}

impl FlagState {
    /// The summary token.
    pub fn token(self) -> &'static str {
        match self {
            FlagState::None => "none",
            FlagState::Installed => "installed",
            FlagState::Inherited => "inherited",
        }
    }
}

/// Every [`FlagState`], for the fingerprint corpus and the parser.
#[allow(dead_code)] // The corpus and the kind-list units are its callers.
pub const FLAG_STATES: [FlagState; 3] = flag_states();

/// Every [`FlagState`], through an exhaustive match with no wildcard: a new
/// variant does not compile until it is listed here, and so in the corpus.
const fn flag_states() -> [FlagState; 3] {
    const fn listed(f: FlagState) -> usize {
        match f {
            FlagState::None => 0,
            FlagState::Installed => 1,
            FlagState::Inherited => 2,
        }
    }
    let all = [FlagState::None, FlagState::Installed, FlagState::Inherited];
    assert!(listed(all[0]) == 0 && listed(all[1]) == 1 && listed(all[2]) == 2);
    all
}

/// Probe admission for one thread group (S.3): a probe is injected only
/// while no guest seccomp filter is installed or being installed, and an
/// install that meets a probe in flight is refused at once. Nothing ever
/// waits, and the lock is never held across an injection.
#[derive(Debug, Default, Clone)]
pub(crate) struct Admission {
    /// A guest filter was installed (or inherited, or may have been).
    pub guest_filter: bool,
    /// Installs being injected now.
    pub install_pending: u32,
    /// The injecting thread of each admitted probe whose result has not
    /// come back. A probe whose future is dropped keeps its entry until
    /// that thread exits: later installs are refused by name, never a probe
    /// run under a new filter.
    pub in_flight: Vec<i32>,
    /// How the record was flagged (the summary's `flag=`).
    pub flag: FlagState,
    /// Install attempts (the summary's `installs`).
    pub installs: u64,
    /// Installs refused because a probe was in flight (`installs_refused`).
    pub installs_refused: u64,
    /// Path calls that entered translation after the flag was set,
    /// including the refused ones (`translated`).
    pub translated: u64,
    /// Probe refusals this section made (the summary's `refused`).
    pub refused: u64,
    /// Refusals by the best-effort filter-count detector
    /// (`unseen_best_effort`; defeatable by a guest that jumps to a trusted
    /// gate).
    pub unseen_best_effort: u64,
    /// Dead-base routes that reached the probe gate, refused or not (the
    /// probe summary's `probes`).
    pub probes: u64,
    /// Of those, the ones refused because syscall user dispatch was on.
    pub sud_refused: u64,
    /// Of those, the ones whose dispatch mode came from prctl tracking.
    pub sud_fallback: u64,
    /// The process that owns this record. In-guest a fork child's address
    /// space holds a copy of its parent's record; [`Admission::adopt`]
    /// replaces such a copy before any use.
    pub owner: Option<i32>,
    /// The pidfs inode, read once when the record first mattered (0 when
    /// unavailable): kernel metadata, not authenticated, not the identity;
    /// tracer-collected on ptrace only; 0 = uncollected.
    pub kernel_id: Option<u64>,
    /// The exit summaries were emitted (exactly one emission per process).
    pub summary_emitted: bool,
    /// Guest installs S.3 forwarded that succeeded in this image (or whose
    /// result is unknown): added to the image's baseline for the expected
    /// filter count. Carried to a fork child, reset by exec (C5.8).
    pub filter_addend: u32,
    /// The detector found the count other than expected (or the
    /// first-callback check could not read it): every later probe of this
    /// record is refused. Never cleared, and the expected count is never
    /// rebased to an observation. An unreadable count at a probe refuses
    /// that probe only (C4.4).
    pub filter_latched: bool,
    /// The record's first-callback count check ran (or was skipped because
    /// the record is flagged: no injection under a guest filter).
    pub first_check_done: bool,
}

/// What a process-creating clone stages for its child's record: the
/// conservative flag and the expected-count addend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewGroup {
    pub flag: bool,
    pub filter_addend: u32,
}

/// An admitted probe. Only [`Admission::release`], or its thread's exit
/// ([`Admission::release_thread`]), gives the count back.
#[must_use]
pub(crate) struct Ticket(i32);

/// An install that passed the gate and is being injected.
#[must_use]
pub(crate) struct InstallTicket(());

impl Admission {
    /// Admitted probes whose result has not come back.
    pub fn probes_in_flight(&self) -> u32 {
        self.in_flight.len() as u32
    }

    /// Admit one probe injected by thread `tid`, or refuse it (K7 trigger 3).
    pub fn admit(&mut self, tid: i32) -> Option<Ticket> {
        if self.closed() {
            self.refused += 1;
            return None;
        }
        self.in_flight.push(tid);
        Some(Ticket(tid))
    }

    /// The probe's result came back.
    pub fn release(&mut self, ticket: Ticket) {
        let Ticket(tid) = ticket;
        if let Some(i) = self.in_flight.iter().position(|&t| t == tid) {
            self.in_flight.swap_remove(i);
        }
    }

    /// Thread `tid` exited or died: its probes can no longer inject.
    pub fn release_thread(&mut self, tid: i32) {
        self.in_flight.retain(|&t| t != tid);
    }

    /// Whether a probe would be refused now (checked at the top of the
    /// dead-base route, before any Tool-side read).
    pub fn closed(&self) -> bool {
        self.guest_filter || self.install_pending > 0 || self.filter_latched
    }

    /// Install step 1: count the attempt; refuse it at once, with the
    /// number of probes in flight, if any is (review (ii): never wait);
    /// otherwise hold the gate closed until [`Admission::finish_install`].
    pub fn begin_install(&mut self) -> Result<InstallTicket, u32> {
        self.installs += 1;
        let in_flight = self.probes_in_flight();
        if in_flight > 0 {
            self.installs_refused += 1;
            return Err(in_flight);
        }
        self.install_pending += 1;
        Ok(InstallTicket(()))
    }

    /// Install steps 4-5. `result` is the injection's result, or None when
    /// it is unknown (cancelled after the injection may have run): a
    /// success (>= 0, a NEW_LISTENER fd or a TSYNC thread id included) and
    /// an unknown result set the flag; a negative errno installed nothing.
    pub fn finish_install(&mut self, ticket: InstallTicket, result: Option<i64>) {
        let InstallTicket(()) = ticket;
        if result.is_none_or(|r| r >= 0) {
            self.guest_filter = true;
            self.flag = FlagState::Installed;
            self.filter_addend = self.filter_addend.saturating_add(1);
        }
        self.install_pending -= 1;
    }

    /// The installer was cancelled before its injection could run.
    pub fn abandon_install(&mut self, ticket: InstallTicket) {
        let InstallTicket(()) = ticket;
        self.install_pending -= 1;
    }

    /// The flag a new thread group created now starts with: set if a filter
    /// is installed, or may be by an install in flight.
    pub fn inherited_flag(&self) -> bool {
        self.guest_filter || self.install_pending > 0
    }

    /// A new thread group's record, created with the parent's
    /// [`Admission::inherited_flag`]: fresh counters, no probes or
    /// installs in flight.
    pub fn for_new_group(inherited: bool) -> Self {
        Self {
            guest_filter: inherited,
            flag: if inherited { FlagState::Inherited } else { FlagState::None },
            ..Self::default()
        }
    }

    /// A new group's record from its parent's clone: the flag and the
    /// parent's addend (the child inherits the parent's filters, so its
    /// expected count is the parent's; a fork adds no install).
    pub fn for_child(group: NewGroup) -> Self {
        Self {
            filter_addend: group.filter_addend,
            ..Self::for_new_group(group.flag)
        }
    }

    /// What a process-creating clone stages for the child's record.
    pub fn new_group(&self) -> NewGroup {
        NewGroup {
            flag: self.inherited_flag(),
            filter_addend: self.filter_addend,
        }
    }

    /// The detector's check of an observed filter count against the
    /// image's `baseline` plus this record's addend. False refuses the
    /// probe: a latched record, an excess (an unseen filter: the record is
    /// flagged and counted in `unseen_best_effort`), a deficit (latched,
    /// counted in `refused`), or an unknown count: an unreadable or
    /// unparsable status, or no `Seccomp_filters:` line, refuses that probe
    /// only, counted in `refused` (C4.4: "At a probe: an unreadable or
    /// unparsable `/proc/thread-self/status`, or one with no
    /// `Seccomp_filters:` line, refuses that probe by name").
    pub fn filter_count_admits(&mut self, baseline: Option<u32>, observed: Option<u32>) -> bool {
        if self.filter_latched {
            self.refused += 1;
            return false;
        }
        let expected = baseline.and_then(|b| b.checked_add(self.filter_addend));
        match filter_count_verdict(expected, observed) {
            FilterCount::Match => true,
            FilterCount::Excess => {
                self.filter_latched = true;
                self.guest_filter = true;
                if self.flag == FlagState::None {
                    self.flag = FlagState::Installed;
                }
                self.unseen_best_effort += 1;
                false
            }
            FilterCount::Deficit => {
                self.filter_latched = true;
                self.refused += 1;
                false
            }
            FilterCount::Unknown => {
                self.refused += 1;
                false
            }
        }
    }

    /// The first-callback check (baseline delta (A)): its verdict latches
    /// before any guest call is translated, so the first call's probe is
    /// refused too. Counts nothing itself: the refusals count when probes
    /// meet the latch.
    pub fn first_callback_check(&mut self, baseline: Option<u32>, observed: Option<u32>) {
        self.first_check_done = true;
        let expected = baseline.and_then(|b| b.checked_add(self.filter_addend));
        match filter_count_verdict(expected, observed) {
            FilterCount::Match => {}
            FilterCount::Excess => {
                self.filter_latched = true;
                self.guest_filter = true;
                if self.flag == FlagState::None {
                    self.flag = FlagState::Installed;
                }
                self.unseen_best_effort += 1;
            }
            FilterCount::Deficit | FilterCount::Unknown => self.filter_latched = true,
        }
    }

    /// A path call entered translation (the summary's `translated` counts
    /// the ones after the flag was set).
    pub fn note_translation(&mut self) {
        if self.guest_filter {
            self.translated += 1;
        }
    }

    /// Make this the record of process `pid`. A record owned by another
    /// process is a fork child's copy of its parent's (in-guest the child's
    /// address space is a copy): it becomes a new group's record, with the
    /// conservative flag the copy implies, so the child never reports its
    /// parent's counts or waits on its parent's probes.
    pub fn adopt(&mut self, pid: i32) {
        match self.owner {
            Some(owner) if owner == pid => {}
            Some(_) => {
                *self = Self::for_child(self.new_group());
                self.owner = Some(pid);
            }
            None => self.owner = Some(pid),
        }
    }

    /// The probe gate (S.3, C1): a dead-base route reached it (`probes`).
    /// True, a refusal, when a guest filter is installed or being installed
    /// (trigger 3, `refused`), or when the probing thread's dispatch mode is
    /// ON or could not be read (`dispatch` None; trigger 6, `sud_refused`).
    /// `fallback`: the mode came from prctl tracking (`sud_fallback`).
    pub fn probe_gate(&mut self, dispatch: Option<bool>, fallback: bool) -> bool {
        self.probes += 1;
        if fallback {
            self.sud_fallback += 1;
        }
        let filtered = self.closed();
        if filtered {
            self.refused += 1;
        }
        let dispatch_on = dispatch != Some(false);
        if dispatch_on {
            self.sud_refused += 1;
        }
        filtered || dispatch_on
    }

    /// Whether the seccomp summary is due at exit: installs, or a flag.
    pub fn seccomp_summary_due(&self) -> bool {
        self.installs > 0 || self.guest_filter || self.flag != FlagState::None
    }

    /// Whether the probe summary is due at exit: probes.
    pub fn probe_summary_due(&self) -> bool {
        self.probes > 0
    }

    /// Mark the exit emission done; false if it already was (a second exit
    /// path emits nothing).
    pub fn begin_emission(&mut self) -> bool {
        !std::mem::replace(&mut self.summary_emitted, true)
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    /// A record owned by another process (a fork child's copy) is
    /// replaced with a new group's, keeping only the conservative flag.
    #[test]
    fn copied_record_is_replaced_on_pid_mismatch() {
        let mut a = Admission::default();
        a.adopt(10);
        let probe = a.admit(10).unwrap();
        a.probes = 4;
        a.adopt(10);
        assert_eq!((a.probes_in_flight(), a.probes), (1, 4), "own record kept");
        // A copy taken with a probe in flight and no filter: unflagged.
        let mut copy = a.clone();
        copy.adopt(20);
        assert_eq!(copy.owner, Some(20));
        assert!(!copy.guest_filter && copy.flag == FlagState::None);
        assert_eq!((copy.probes_in_flight(), copy.probes), (0, 0));
        a.release(probe);
        // A copy taken with an install pending: flagged as inherited.
        let install = a.begin_install().unwrap();
        let mut copy = a.clone();
        copy.adopt(21);
        assert!(copy.guest_filter && copy.flag == FlagState::Inherited);
        assert_eq!((copy.install_pending, copy.installs), (0, 0));
        assert!(!copy.summary_emitted);
        a.finish_install(install, Some(-1));
    }

    #[test]
    fn emitted_record_does_not_emit_again() {
        let mut a = Admission::default();
        assert!(a.begin_emission());
        assert!(!a.begin_emission());
        // A new group's record emits on its own.
        assert!(Admission::for_new_group(true).begin_emission());
    }

    /// prctl matches the option's low 32 bits and the whole mode; ptrace
    /// matches the whole request word.
    #[test]
    fn option_and_request_word_rules() {
        let at = |option: u64, mode: u64| dispatch_setter_mode(Sysno::prctl, [option, mode, 0, 0, 0, 0]);
        assert_eq!(at(59, 1), Some(1));
        assert_eq!(at(0x1_0000_003b, 1), Some(1));
        assert_eq!(at(59, 0x1_0000_0000), Some(0x1_0000_0000));
        assert_eq!(at(59, u64::MAX), Some(u64::MAX));
        for other in [58, 60, 0x1_0000_003a] {
            assert_eq!(at(other, 1), None, "{other:#x}");
        }
        assert_eq!(dispatch_setter_mode(Sysno::ptrace, [59, 1, 0, 0, 0, 0]), None);
        assert!(is_ptrace_dispatch_setter(0x4210));
        assert!(!is_ptrace_dispatch_setter(0x1_0000_4210));
        assert!(!is_ptrace_dispatch_setter(0x4211));
    }

    /// R1's refusal set: every non-OFF mode where the config refuses guest
    /// dispatch; never OFF, and nothing on the ptrace backend.
    #[test]
    fn sud_setter_refusal() {
        for mode in [1, 2, 3, 0x1_0000_0000, u64::MAX] {
            assert!(refuses_dispatch_setter(true, mode), "{mode:#x}");
            assert!(!refuses_dispatch_setter(false, mode), "{mode:#x}");
        }
        assert!(!refuses_dispatch_setter(true, 0));
        // The low-32 option match reaches the refusal.
        let mode = dispatch_setter_mode(Sysno::prctl, [0x1_0000_003b, 1, 0, 0, 0, 0]).unwrap();
        assert!(refuses_dispatch_setter(true, mode));
    }

    /// Trigger 6 refuses while the tracked mode is ON (and when it cannot be
    /// read), counted apart from trigger 3; OFF admits.
    #[test]
    fn trigger6_refuses_when_tracked_on() {
        let mut a = Admission::default();
        assert!(!a.probe_gate(Some(false), true));
        assert!(a.probe_gate(Some(true), true));
        assert!(a.probe_gate(None, false));
        assert_eq!((a.probes, a.sud_refused, a.sud_fallback, a.refused), (3, 2, 2, 0));
        // Both triggers at once count in both.
        let t = a.begin_install().unwrap();
        assert!(a.probe_gate(Some(true), false));
        assert_eq!((a.probes, a.sud_refused, a.refused), (4, 3, 1));
        a.abandon_install(t);
        assert!(!a.probe_gate(Some(false), false));
        assert!(a.sud_refused <= a.probes && a.sud_fallback <= a.probes);
    }

    /// C4.4 (#99, the review's condition for the correction): an unreadable count at
    /// a probe refuses that probe only, and the next readable Match admits;
    /// `refused` counts the refusal. Excess and Deficit still latch (Excess
    /// also flags), and the first-callback Unknown still latches.
    #[test]
    fn unknown_count_refuses_that_probe_only() {
        let mut a = Admission::default();
        assert!(!a.filter_count_admits(Some(2), None), "unknown: refused");
        assert_eq!((a.refused, a.filter_latched), (1, false));
        assert!(a.filter_count_admits(Some(2), Some(2)), "then Match admits");
        assert_eq!(a.refused, 1);
        assert!(!a.filter_count_admits(None, Some(2)), "no baseline: unknown again");
        assert_eq!((a.refused, a.filter_latched), (2, false));
        let mut excess = Admission::default();
        assert!(!excess.filter_count_admits(Some(2), Some(3)));
        assert!(excess.filter_latched && excess.guest_filter);
        assert!(!excess.filter_count_admits(Some(2), Some(2)), "latched");
        let mut deficit = Admission::default();
        assert!(!deficit.filter_count_admits(Some(2), Some(1)));
        assert!(deficit.filter_latched && !deficit.guest_filter);
        assert!(!deficit.filter_count_admits(Some(2), Some(2)), "latched");
        assert_eq!(deficit.refused, 2);
        let mut first = Admission::default();
        first.first_callback_check(Some(2), None);
        assert!(first.filter_latched, "the first-callback Unknown latches");
        assert!(!first.filter_count_admits(Some(2), Some(2)));
    }

    #[test]
    fn tracking_nonzero_success_is_on() {
        for was in [false, true] {
            assert!(!tracked_dispatch_after(was, 0, Some(0)));
            assert!(tracked_dispatch_after(was, 1, Some(0)));
            assert_eq!(tracked_dispatch_after(was, 0, Some(-22)), was);
            assert!(tracked_dispatch_after(was, 0, Some(157)));
            assert!(tracked_dispatch_after(was, 0, None));
        }
    }

    #[test]
    fn install_predicate_reads_kernel_widths() {
        let filter = u64::from(libc::SECCOMP_SET_MODE_FILTER);
        let mode = u64::from(libc::SECCOMP_MODE_FILTER);
        let set = libc::PR_SET_SECCOMP as u64;
        assert!(installs_seccomp_filter(Sysno::seccomp, [filter, 0, 0, 0, 0, 0]));
        // seccomp's op is an unsigned int: high bits are ignored.
        assert!(installs_seccomp_filter(Sysno::seccomp, [filter | 1 << 32, 0, 0, 0, 0, 0]));
        assert!(!installs_seccomp_filter(Sysno::seccomp, [0, 0, 0, 0, 0, 0]));
        assert!(installs_seccomp_filter(Sysno::prctl, [set, mode, 0, 0, 0, 0]));
        // prctl's option is an int, its mode an unsigned long.
        assert!(installs_seccomp_filter(Sysno::prctl, [set | 1 << 32, mode, 0, 0, 0, 0]));
        assert!(!installs_seccomp_filter(Sysno::prctl, [set, mode | 1 << 32, 0, 0, 0, 0]));
        assert!(!installs_seccomp_filter(Sysno::prctl, [set, 1, 0, 0, 0, 0]));
        assert!(!installs_seccomp_filter(Sysno::openat, [filter, mode, 0, 0, 0, 0]));
    }

    #[test]
    fn admission_refuses_under_a_filter_or_a_pending_install() {
        let mut a = Admission::default();
        let t = a.admit(1).expect("open");
        assert_eq!(a.probes_in_flight(), 1);
        a.release(t);
        assert_eq!(a.probes_in_flight(), 0);
        a.install_pending = 1;
        assert!(a.closed() && a.admit(1).is_none());
        a.install_pending = 0;
        a.guest_filter = true;
        assert!(a.admit(1).is_none());
        assert_eq!(a.refused, 2);
    }

    #[test]
    fn a_dropped_ticket_keeps_the_count_until_its_thread_exits() {
        let mut a = Admission::default();
        drop(a.admit(7));
        let kept = a.admit(8).expect("open");
        assert_eq!(a.probes_in_flight(), 2);
        assert_eq!(a.begin_install().err(), Some(2));
        a.release_thread(7);
        a.release(kept);
        assert_eq!(a.probes_in_flight(), 0);
    }

    #[test]
    fn install_refused_while_probe_admitted() {
        let mut a = Admission::default();
        let probe = a.admit(1).expect("open");
        assert_eq!(a.begin_install().err(), Some(1));
        assert_eq!((a.installs, a.installs_refused), (1, 1));
        assert!(!a.guest_filter, "a refused install installs nothing");
        a.release(probe);
        let install = a.begin_install().expect("no probe in flight");
        assert!(a.admit(1).is_none(), "probes are refused while it is pending");
        a.finish_install(install, Some(0));
        assert!(a.guest_filter && a.flag == FlagState::Installed);
        assert!(a.admit(1).is_none(), "and after it took effect");
    }

    #[test]
    fn failed_install_readmits() {
        let mut a = Admission::default();
        let install = a.begin_install().unwrap();
        a.finish_install(install, Some(-(libc::EINVAL as i64)));
        assert!(!a.guest_filter && a.flag == FlagState::None);
        let t = a.admit(1).expect("readmitted");
        a.release(t);
    }

    #[test]
    fn installer_cancelled_releases_pending() {
        let mut a = Admission::default();
        let before = a.begin_install().unwrap();
        a.abandon_install(before);
        assert!(!a.closed(), "cancelled before the injection: flag unchanged");
        let after = a.begin_install().unwrap();
        a.finish_install(after, None);
        assert!(a.guest_filter, "cancelled after it may have run: flagged");
        assert_eq!(a.install_pending, 0);
    }

    #[test]
    fn success_values_all_flag() {
        for r in [0, 5, 1234] {
            let mut a = Admission::default();
            let t = a.begin_install().unwrap();
            a.finish_install(t, Some(r));
            assert!(a.guest_filter, "result {r}");
        }
    }

    #[test]
    fn a_new_group_starts_fresh_with_the_conservative_flag() {
        let mut parent = Admission::default();
        let _held = parent.admit(1).unwrap();
        parent.translated = 3;
        assert!(!parent.inherited_flag());
        let pending = Admission { install_pending: 1, ..Admission::default() };
        let child = Admission::for_new_group(pending.inherited_flag());
        assert!(child.guest_filter && child.flag == FlagState::Inherited);
        assert_eq!((child.probes_in_flight(), child.install_pending), (0, 0));
        assert_eq!((child.installs, child.translated, child.refused), (0, 0, 0));
        let clean = Admission::for_new_group(parent.inherited_flag());
        assert!(!clean.guest_filter && clean.flag == FlagState::None);
    }

    /// C4.4: after an exec the new image reads its own baseline, which
    /// includes the old image's filters and the new in-process install
    /// (P' + 1), and the record exec keeps carries no per-image part (no
    /// addend, no latch): the new image's first check matches and its first
    /// probe is admitted. Against the old baseline the same count would be
    /// an excess.
    #[test]
    fn count_baseline_reread_after_exec() {
        let mut old = Admission::default();
        old.first_callback_check(Some(2), Some(2));
        assert!(old.filter_count_admits(Some(2), Some(2)));
        old.probes = 3;
        // Exec: the old image's filters stay (count 2), the new image's
        // Reverie install adds one; the record keeps only its lifetime part.
        let new_baseline = 2 + 1;
        let mut new = crate::exec_state::LifetimeRecord::of(&old).admission();
        assert_eq!((new.filter_addend, new.filter_latched, new.first_check_done), (0, false, false));
        assert_eq!(new.probes, 3, "exec keeps the counters");
        new.first_callback_check(Some(new_baseline), Some(3));
        assert!(!new.filter_latched);
        assert!(new.filter_count_admits(Some(new_baseline), Some(3)), "the first probe is admitted");
        let mut stale = crate::exec_state::LifetimeRecord::of(&old).admission();
        stale.first_callback_check(Some(2), Some(3));
        assert!(stale.filter_latched && stale.unseen_best_effort == 1, "the old baseline would refuse");
    }

    #[test]
    fn translated_counts_only_after_the_flag() {
        let mut a = Admission::default();
        a.note_translation();
        a.guest_filter = true;
        a.note_translation();
        a.note_translation();
        assert_eq!(a.translated, 2);
    }
}
