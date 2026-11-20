//! The constructor's checks before arming (LD_PRELOAD route), made with raw
//! syscall instructions in this library's own code before Reverie's handler
//! and filter exist, so nothing interposes or traps them. They are
//! untranslated, not host-authentic: they run in the process's own root and
//! mount namespace, and a filter from before the run, or code that ran
//! before this constructor, can still affect them (docs/design.md §4.9).
//!
//! - One read of the thread's status gives `Threads:`, which must be 1
//!   (dispatch is per thread, and Reverie's TSYNC copies a filter, not an
//!   OFF mode), and `Seccomp_filters:`, P, the filter count before
//!   Reverie's own install: the expected count after it is P + 1.
//! - The syscall user dispatch OFF call for the initial thread clears any
//!   mode early code left ON; its EINVAL is decided by architecture and,
//!   on x86_64, kernel release (`decide_off`) and, from 7.3, the running
//!   kernel's /boot/config-<release>, an ADVISORY source.
//!
//! Nothing here allocates: the guest's allocator may be interposed in this
//! window. Every failure is a named one, through the constructor's `fail`.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF).
const PR_SET_SYSCALL_USER_DISPATCH: u64 = 59;
/// The personality bit that makes uname report 2.6.<60 + x> (UNAME26,
/// include/uapi/linux/personality.h): the only one that alters the release
/// at v7.1.3 (kernel/sys.c, override_release).
const UNAME26: u64 = 0x0020000;

/// A raw syscall from this library's own instruction.
///
/// # Safety
/// The caller passes arguments valid for syscall `nr`.
#[cfg(target_arch = "x86_64")]
unsafe fn raw(nr: i64, a: [u64; 6]) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a[0],
            in("rsi") a[1],
            in("rdx") a[2],
            in("r10") a[3],
            in("r8") a[4],
            in("r9") a[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// A raw syscall from this library's own instruction.
///
/// # Safety
/// The caller passes arguments valid for syscall `nr`.
#[cfg(target_arch = "aarch64")]
unsafe fn raw(nr: i64, a: [u64; 6]) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a[0] => ret,
            in("x1") a[1],
            in("x2") a[2],
            in("x3") a[3],
            in("x4") a[4],
            in("x5") a[5],
            options(nostack),
        );
    }
    ret
}

/// The architecture the decision is made for: compile-time
/// `cfg(target_arch)`, never uname, whose machine field PER_LINUX32 rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // A build constructs its own target's variant; the units construct all three.
pub enum Arch {
    X86_64,
    Aarch64,
    /// Any other architecture (C5a.2 branch (c)): an EINVAL is a named
    /// failure. The preload has no OFF call for one, so such a build stops
    /// at the `compile_error!` below rather than running unchecked.
    Other,
}

#[cfg(target_arch = "x86_64")]
const ARCH: Arch = Arch::X86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: Arch = Arch::Aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "literoot-preload supports only x86_64 and aarch64: it has no syscall user dispatch OFF call for this \
     architecture (C5a.2 branch (c))"
);

/// What one status read says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFacts {
    pub threads: u64,
    pub filters: u32,
}

/// `Threads:` and `Seccomp_filters:` from one status text, or the reason
/// they cannot be read.
pub fn parse_status(buf: &[u8]) -> Result<StatusFacts, &'static str> {
    use crate::dead_base::status_field;
    let threads = status_field(buf, b"Threads").ok_or("cannot read Threads: no readable Threads: line")?;
    let filters = status_field(buf, b"Seccomp_filters")
        .ok_or("cannot read Threads: no readable Seccomp_filters: line")?;
    let filters = u32::try_from(filters).map_err(|_| "cannot read Threads: Seccomp_filters out of range")?;
    Ok(StatusFacts { threads, filters })
}

/// Read /proc/self/status into `buf` to its end with raw open, read and
/// close: the length read, or the reason it failed (including a status
/// larger than the buffer, never a truncated read).
fn read_status(buf: &mut [u8]) -> Result<usize, &'static str> {
    const PATH: &[u8] = b"/proc/self/status\0";
    let fd = unsafe {
        raw(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return Err("cannot read Threads: cannot open /proc/self/status");
    }
    let mut len = 0;
    let result = loop {
        if len == buf.len() {
            break Err("cannot read Threads: /proc/self/status is larger than the preload's buffer");
        }
        let n = unsafe {
            raw(
                libc::SYS_read,
                [fd as u64, buf[len..].as_mut_ptr() as u64, (buf.len() - len) as u64, 0, 0, 0],
            )
        };
        match n {
            0 => break Ok(len),
            n if n > 0 => len += n as usize,
            n if n == -i64::from(libc::EINTR) => {}
            _ => break Err("cannot read Threads: cannot read /proc/self/status"),
        }
    };
    unsafe { raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    result
}

/// `<major>.<minor>` at the start of a kernel release string.
pub fn parse_release(release: &[u8]) -> Option<(u32, u32)> {
    fn number(part: Option<&[u8]>) -> Option<u32> {
        let part = part.filter(|p| !p.is_empty())?;
        let mut v: u32 = 0;
        for &d in part {
            v = v.checked_mul(10)?.checked_add(u32::from(d - b'0'))?;
        }
        Some(v)
    }
    let mut parts = release.split(|&b| !b.is_ascii_digit());
    let major = number(parts.next())?;
    // The separator after the major number must be a dot.
    let after = release.get(release.iter().position(|b| !b.is_ascii_digit())?)?;
    if *after != b'.' {
        return None;
    }
    let minor = number(parts.next())?;
    Some((major, minor))
}

/// What the running kernel's installed config says about
/// CONFIG_SYSCALL_USER_DISPATCH, from its two canonical Kconfig lines only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAnswer {
    /// `# CONFIG_SYSCALL_USER_DISPATCH is not set`, exactly once, and no `=y`.
    NotSet,
    /// `CONFIG_SYSCALL_USER_DISPATCH=y`, exactly once, and no "not set".
    Set,
    /// Unreadable, absent, in any other form, or both forms, or either twice.
    Unknown,
}

const SUD_NOT_SET: &[u8] = b"# CONFIG_SYSCALL_USER_DISPATCH is not set";
const SUD_SET: &[u8] = b"CONFIG_SYSCALL_USER_DISPATCH=y";
/// A line longer than this cannot be either form; it is skipped whole.
const CONFIG_CARRY: usize = 128;
/// The largest config file admitted, and the most bytes read from one.
const CONFIG_MAX: u64 = 1 << 20;

/// A streaming, allocation-free matcher of whole config lines: bytes are
/// fed in chunks of any size, and a line split across chunks is carried.
struct ConfigScan {
    line: [u8; CONFIG_CARRY],
    len: usize,
    long: bool,
    not_set: u32,
    set: u32,
}

impl ConfigScan {
    const fn new() -> Self {
        Self { line: [0; CONFIG_CARRY], len: 0, long: false, not_set: 0, set: 0 }
    }

    fn end_line(&mut self) {
        if !self.long {
            let line = &self.line[..self.len];
            if line == SUD_NOT_SET {
                self.not_set = self.not_set.saturating_add(1);
            } else if line == SUD_SET {
                self.set = self.set.saturating_add(1);
            }
        }
        self.len = 0;
        self.long = false;
    }

    fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if b == b'\n' {
                self.end_line();
            } else if self.len < CONFIG_CARRY {
                self.line[self.len] = b;
                self.len += 1;
            } else {
                self.long = true;
            }
        }
    }

    /// The answer; a last line without its newline still counts.
    fn finish(mut self) -> ConfigAnswer {
        if self.len > 0 || self.long {
            self.end_line();
        }
        match (self.not_set, self.set) {
            (1, 0) => ConfigAnswer::NotSet,
            (0, 1) => ConfigAnswer::Set,
            _ => ConfigAnswer::Unknown,
        }
    }
}

const BOOT_CONFIG_PREFIX: &[u8] = b"/boot/config-";

/// `/boot/config-<release>`, NUL-terminated, in `out`: its length without
/// the NUL, or None for an empty release, one longer than uname's field
/// (64 bytes), or one holding '/' or NUL.
fn boot_config_path(release: &[u8], out: &mut [u8; 80]) -> Option<usize> {
    if release.is_empty() || release.len() > 64 || release.iter().any(|&b| b == b'/' || b == 0) {
        return None;
    }
    let n = BOOT_CONFIG_PREFIX.len() + release.len();
    out[..BOOT_CONFIG_PREFIX.len()].copy_from_slice(BOOT_CONFIG_PREFIX);
    out[BOOT_CONFIG_PREFIX.len()..n].copy_from_slice(release);
    out[n] = 0;
    Some(n)
}

/// The release field of `uts` up to its NUL.
fn release_bytes(uts: &libc::utsname) -> Option<&[u8]> {
    let field: &[u8] =
        unsafe { std::slice::from_raw_parts(uts.release.as_ptr().cast::<u8>(), uts.release.len()) };
    let end = field.iter().position(|&b| b == 0)?;
    Some(&field[..end])
}

/// `/boot/config-<release>`'s answer: an ADVISORY source (a rebuild with the
/// same release string, or a container's own /boot, can disagree with the
/// running kernel). Any failure is Unknown.
fn read_boot_config(release: &[u8]) -> ConfigAnswer {
    let mut path = [0u8; 80];
    match boot_config_path(release, &mut path) {
        Some(n) => read_config_file(&path[..=n]),
        None => ConfigAnswer::Unknown,
    }
}

/// The answer of the config file at `path_nul` (NUL-terminated). Raw
/// syscalls and stack buffers only, nothing allocated: O_NOFOLLOW;
/// O_NONBLOCK so a FIFO or device at the path cannot block the open;
/// O_NOCTTY so a terminal at the path cannot become the controlling
/// terminal of a session leader that has none; a regular file of at most
/// CONFIG_MAX bytes; read in 4 KiB chunks through [`ConfigScan`]. Any
/// failure, or a path without its NUL, is Unknown.
fn read_config_file(path_nul: &[u8]) -> ConfigAnswer {
    if path_nul.last() != Some(&0) {
        return ConfigAnswer::Unknown;
    }
    let fd = unsafe {
        raw(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                path_nul.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return ConfigAnswer::Unknown;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    const EMPTY: &[u8] = b"\0";
    let stat_rc = unsafe {
        raw(
            libc::SYS_newfstatat,
            [fd as u64, EMPTY.as_ptr() as u64, &mut st as *mut libc::stat as u64, libc::AT_EMPTY_PATH as u64, 0, 0],
        )
    };
    let answer = if stat_rc != 0
        || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
        || st.st_size as u64 > CONFIG_MAX
    {
        ConfigAnswer::Unknown
    } else {
        let mut scan = ConfigScan::new();
        let mut buf = [0u8; 4096];
        let mut total: u64 = 0;
        loop {
            let n = unsafe { raw(libc::SYS_read, [fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0]) };
            if n == 0 {
                break scan.finish();
            }
            if n == -i64::from(libc::EINTR) {
                continue;
            }
            if n < 0 {
                break ConfigAnswer::Unknown;
            }
            total += n as u64;
            if total > CONFIG_MAX {
                break ConfigAnswer::Unknown;
            }
            scan.feed(&buf[..n as usize]);
        }
    };
    unsafe { raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    answer
}

/// The OFF call's outcome that lets startup go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffOutcome {
    /// The mode is OFF.
    Off,
    /// EINVAL with independent evidence that the kernel has no syscall
    /// user dispatch: startup goes on, noted (`literoot: note sud_absent`).
    Absent,
    /// EINVAL on x86_64 >= 7.3 where /boot/config-<release> says the option
    /// is not set: ADVISORY evidence (/boot may be stale). Startup goes on,
    /// noted as `literoot: note sud_absent_boot_config_advisory`.
    AbsentAdvisory,
}

/// Decide the OFF call's result `result` (a value or a negative errno) on
/// `arch` (C5a.2). `release` and `persona` are read only on the x86_64
/// EINVAL path: the release's `<major>.<minor>`, and the raw personality
/// (None when either cannot be read). `config` is read only there and only
/// for a release of 7.3 or later: the running kernel's
/// /boot/config-<release> answer.
pub fn decide_off(
    arch: Arch,
    result: i64,
    release: impl FnOnce() -> Option<(u32, u32)>,
    persona: impl FnOnce() -> Option<u64>,
    config: impl FnOnce() -> ConfigAnswer,
) -> Result<OffOutcome, &'static str> {
    if result == 0 {
        return Ok(OffOutcome::Off);
    }
    if result != -i64::from(libc::EINVAL) {
        return Err("cannot turn syscall user dispatch off: the OFF call failed");
    }
    match arch {
        // arm64 selects GENERIC_ENTRY nowhere through v7.3-rc6, so the
        // prctl is the -EINVAL stub (include/linux/syscall_user_dispatch.h).
        // No release bound, as ruled. Tracked follow-up: bound this
        // acceptance once arm64 selects GENERIC_ENTRY and syscall user
        // dispatch.
        Arch::Aarch64 => Ok(OffOutcome::Absent),
        // Branch (c): nothing says whether the prctl exists there.
        Arch::Other => Err("cannot turn syscall user dispatch off: EINVAL on an architecture literoot \
                            does not know; cannot tell whether syscall user dispatch exists"),
        Arch::X86_64 => {
            let persona = persona().ok_or(
                "cannot read the personality; cannot tell whether syscall user dispatch exists",
            )?;
            if persona & UNAME26 != 0 {
                return Err(
                    "kernel release unknown (UNAME26 personality); cannot tell whether \
                     syscall user dispatch exists",
                );
            }
            let (major, minor) = release().ok_or(
                "kernel release unparsable; cannot tell whether syscall user dispatch exists",
            )?;
            // Syscall user dispatch first appears in v5.11-rc1. From v7.3-rc1
            // it is CONFIG_SYSCALL_USER_DISPATCH (default y; only x86 selects
            // it), so a 7.3+ kernel built without it also answers EINVAL;
            // below 7.3 x86 always has it (GENERIC_ENTRY), so EINVAL there is
            // a denial. From 7.3 the running kernel's /boot/config-<release>
            // decides, as an ADVISORY source. Tracked next slice:
            // /proc/config.gz (authoritative) ahead of it.
            if (major, minor) < (5, 11) {
                Ok(OffOutcome::Absent)
            } else if (major, minor) < (7, 3) {
                Err("cannot turn syscall user dispatch off: EINVAL on a kernel that has it \
                     (a security policy may deny it, or the kernel was built without it)")
            } else {
                match config() {
                    ConfigAnswer::NotSet => Ok(OffOutcome::AbsentAdvisory),
                    ConfigAnswer::Set => Err("cannot turn syscall user dispatch off: EINVAL, and \
                                              /boot/config-<release> (advisory) says the kernel has it: \
                                              a policy may have denied the OFF call"),
                    ConfigAnswer::Unknown => Err("cannot turn syscall user dispatch off: EINVAL on a \
                                                  kernel that has it (a security policy may deny it, \
                                                  or the kernel was built without it); \
                                                  /boot/config-<release> did not say"),
                }
            }
        }
    }
}

/// Set when the OFF call found syscall user dispatch absent; the reporter
/// takes it into its first report.
static SUD_ABSENT: AtomicBool = AtomicBool::new(false);

/// Whether the absence note is still to be reported (taking clears it).
pub fn take_sud_absent() -> bool {
    SUD_ABSENT.swap(false, Ordering::AcqRel)
}

/// Set when the OFF call found syscall user dispatch absent on the ADVISORY
/// word of /boot/config-<release> (x86_64 >= 7.3); the reporter takes it into
/// its first report as `literoot: note sud_absent_boot_config_advisory`, so a
/// stale /boot's false Absent is in the side log, never silent.
static SUD_ABSENT_ADVISORY: AtomicBool = AtomicBool::new(false);

/// Whether the advisory absence note is still to be reported (taking clears it).
pub fn take_sud_absent_advisory() -> bool {
    SUD_ABSENT_ADVISORY.swap(false, Ordering::AcqRel)
}

/// The constructor's checks before arming: the status read, `Threads: 1`,
/// the OFF call and its decision. Returns the filter count expected once
/// Reverie's single in-process install has run (P + 1), or the named
/// reason startup must stop. The `Threads: 1` check and the OFF call are
/// best-effort; defeatable by code that runs before the preload's
/// constructor (LD_PRELOAD window).
pub fn check_before_arming() -> Result<u32, &'static str> {
    let mut buf = [0u8; 8192];
    let len = read_status(&mut buf)?;
    let facts = parse_status(&buf[..len])?;
    // Best-effort; defeatable by code that runs before the preload's
    // constructor (LD_PRELOAD window).
    if facts.threads != 1 {
        return Err("more than one thread before arming: syscall user dispatch cannot be \
                    cleared for the others");
    }
    // The OFF call: best-effort; defeatable by code that runs before the
    // preload's constructor (LD_PRELOAD window).
    let off = unsafe { raw(libc::SYS_prctl, [PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0, 0]) };
    // One uname read serves both the release decision and the config path.
    let uts = std::cell::RefCell::new(None::<libc::utsname>);
    let release = || {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { raw(libc::SYS_uname, [&mut u as *mut libc::utsname as u64, 0, 0, 0, 0, 0]) } != 0 {
            return None;
        }
        let parsed = parse_release(release_bytes(&u)?);
        *uts.borrow_mut() = Some(u);
        parsed
    };
    let persona = || {
        let p = unsafe { raw(libc::SYS_personality, [0xffff_ffff, 0, 0, 0, 0, 0]) };
        (p >= 0).then_some(p as u64)
    };
    let config = || match uts.borrow().as_ref().and_then(release_bytes) {
        Some(r) => read_boot_config(r),
        None => ConfigAnswer::Unknown,
    };
    match decide_off(ARCH, off, release, persona, config)? {
        OffOutcome::Off => {}
        OffOutcome::Absent => SUD_ABSENT.store(true, Ordering::Release),
        OffOutcome::AbsentAdvisory => SUD_ABSENT_ADVISORY.store(true, Ordering::Release),
    }
    facts
        .filters
        .checked_add(1)
        .ok_or("Seccomp_filters out of range")
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &[u8] = b"Name:\tx\nThreads:\t1\nSeccomp:\t0\nSeccomp_filters:\t0\nCpus_allowed:\tff\n";

    #[test]
    fn status_gives_threads_and_filters_from_one_read() {
        assert_eq!(parse_status(STATUS), Ok(StatusFacts { threads: 1, filters: 0 }));
        let two = b"Threads:\t3\nSeccomp_filters:\t2\n";
        assert_eq!(parse_status(two), Ok(StatusFacts { threads: 3, filters: 2 }));
        for bad in [
            &b"Seccomp_filters:\t0\n"[..],
            b"Threads:\t1\n",
            b"Threads:\t1\nSeccomp_filters:\t\n",
            b"Threads:\t1\nSeccomp_filters:\tx\n",
            b"Threads:\t1\nSeccomp_filters:\t4294967296\n",
            b"Threads:\t1\nThreads:\t1\nSeccomp_filters:\t0\n",
            b"Threads:\t99999999999999999999\nSeccomp_filters:\t0\n",
        ] {
            assert!(parse_status(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    /// C4.4, constructor: an unreadable or unparsable status ends the
    /// process through the named `fail(...)` path with "cannot read
    /// Threads", before arming. Every reason check_before_arming can give
    /// for the status read or parse carries it.
    #[test]
    fn unreadable_status_is_a_named_constructor_failure() {
        for bad in [&b""[..], b"Threads:\t1\n", b"Seccomp_filters:\t0\n", b"Threads:\tx\nSeccomp_filters:\t0\n"] {
            let reason = parse_status(bad).unwrap_err();
            assert!(reason.starts_with("cannot read Threads: "), "{reason}");
        }
        // Production only, each function bounded by its own closing line, so
        // this unit's own text can never satisfy its checks.
        let source = crate::test_source::without_test_items(include_str!("prearm.rs"));
        assert!(!source.contains("fn unreadable_status_is_a_named_constructor_failure("), "the tests dropped");
        let read = &source[source.find("fn read_status(").expect("read_status")..];
        let read = &read[..read.find("\n}\n").expect("its end")];
        let errs: Vec<&str> = read.match_indices("Err(\"").map(|(i, _)| &read[i + 5..]).collect();
        assert_eq!(errs.len(), 3, "open, size and read failures");
        for e in errs {
            assert!(e.starts_with("cannot read Threads: "), "{}", &e[..e.find('"').unwrap()]);
        }
        let check = &source[source.find("pub fn check_before_arming()").expect("check_before_arming")..];
        let check = &check[..check.find("\n}\n").expect("its end")];
        assert!(check.contains("let len = read_status(&mut buf)?;") && check.contains("parse_status(&buf[..len])?;"));
    }

    #[test]
    fn release_major_minor() {
        assert_eq!(parse_release(b"7.1.3-0_fbk0"), Some((7, 1)));
        assert_eq!(parse_release(b"5.10.0"), Some((5, 10)));
        assert_eq!(parse_release(b"2.6.61"), Some((2, 6)));
        for bad in [&b""[..], b"x.1", b"7", b"7-1", b"7.", b"99999999999.1"] {
            assert_eq!(parse_release(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    fn never<T>() -> Option<T> {
        panic!("read where the decision must not read it")
    }

    fn never_config() -> ConfigAnswer {
        panic!("config read where the decision must not read it")
    }

    #[test]
    fn decide_off_by_arch_release_and_persona() {
        let einval = -i64::from(libc::EINVAL);
        for arch in [Arch::X86_64, Arch::Aarch64, Arch::Other] {
            assert_eq!(decide_off(arch, 0, never, never, never_config), Ok(OffOutcome::Off));
            assert!(decide_off(arch, -i64::from(libc::ENOSYS), never, never, never_config).is_err());
            assert!(decide_off(arch, -i64::from(libc::EPERM), never, never, never_config).is_err());
            assert!(decide_off(arch, 1, never, never, never_config).is_err());
        }
        // arm64: absent with no release bound, and nothing read.
        assert_eq!(decide_off(Arch::Aarch64, einval, never, never, never_config), Ok(OffOutcome::Absent));
        // Any other arch (branch (c)): a named failure, nothing read.
        assert!(decide_off(Arch::Other, einval, never, never, never_config)
            .unwrap_err()
            .contains("an architecture literoot does not know"));
        // x86_64: below 5.11 absent; 5.11 to 7.2, UNAME26, an unreadable
        // persona or release: named failures, the config never read.
        let x86 = |release: Option<(u32, u32)>, persona: Option<u64>| {
            decide_off(Arch::X86_64, einval, || release, || persona, never_config)
        };
        assert_eq!(x86(Some((5, 10)), Some(0)), Ok(OffOutcome::Absent));
        assert!(x86(Some((5, 11)), Some(0)).is_err());
        assert!(x86(Some((7, 1)), Some(0)).is_err());
        assert!(x86(Some((7, 2)), Some(0)).is_err());
        assert!(x86(Some((2, 6)), Some(UNAME26)).unwrap_err().contains("UNAME26"));
        assert!(x86(Some((7, 3)), Some(UNAME26)).unwrap_err().contains("UNAME26"));
        assert!(x86(Some((5, 10)), None).is_err());
        assert!(x86(None, Some(0)).unwrap_err().contains("unparsable"));
        assert!(x86(Some((7, 3)), None).is_err());
        // x86_64 >= 7.3: /boot/config-<release> decides, advisory.
        let x86c = |release: (u32, u32), answer: ConfigAnswer| {
            decide_off(Arch::X86_64, einval, || Some(release), || Some(0), || answer)
        };
        assert_eq!(x86c((7, 3), ConfigAnswer::NotSet), Ok(OffOutcome::AbsentAdvisory));
        assert_eq!(x86c((8, 0), ConfigAnswer::NotSet), Ok(OffOutcome::AbsentAdvisory));
        assert!(x86c((7, 3), ConfigAnswer::Set).unwrap_err().contains("says the kernel has it"));
        assert!(x86c((7, 3), ConfigAnswer::Unknown).unwrap_err().contains("did not say"));
    }

    fn scan(chunks: &[&[u8]]) -> ConfigAnswer {
        let mut s = ConfigScan::new();
        for chunk in chunks {
            s.feed(chunk);
        }
        s.finish()
    }

    #[test]
    fn config_scan_reads_only_the_two_canonical_whole_lines() {
        let not_set = b"# CONFIG_SYSCALL_USER_DISPATCH is not set";
        let set = b"CONFIG_SYSCALL_USER_DISPATCH=y";
        for (form, want) in [(&not_set[..], ConfigAnswer::NotSet), (&set[..], ConfigAnswer::Set)] {
            let mut start = form.to_vec();
            start.extend_from_slice(b"\nCONFIG_X=y\n");
            let mut middle = b"CONFIG_A=y\n".to_vec();
            middle.extend_from_slice(form);
            middle.extend_from_slice(b"\nCONFIG_B=m\n");
            let mut end = b"CONFIG_A=y\n".to_vec();
            end.extend_from_slice(form);
            for text in [start, middle, end] {
                assert_eq!(scan(&[&text[..]]), want, "{:?}", String::from_utf8_lossy(&text));
            }
        }
        let mut both = not_set.to_vec();
        both.push(b'\n');
        both.extend_from_slice(set);
        let mut twice = set.to_vec();
        twice.push(b'\n');
        twice.extend_from_slice(set);
        let mut not_set_twice = not_set.to_vec();
        not_set_twice.push(b'\n');
        not_set_twice.extend_from_slice(not_set);
        let mut long = vec![b'x'; 160];
        long.extend_from_slice(not_set);
        for text in [
            both,
            twice,
            not_set_twice,
            long,
            b"CONFIG_SYSCALL_USER_DISPATCH=y\r\n".to_vec(),
            b"".to_vec(),
            b"CONFIG_A=y\n".to_vec(),
            b"CONFIG_SYSCALL_USER_DISPATCH=m\n".to_vec(),
            b"CONFIG_SYSCALL_USER_DISPATCH=n\n".to_vec(),
            b" CONFIG_SYSCALL_USER_DISPATCH=y\n".to_vec(),
            b"CONFIG_SYSCALL_USER_DISPATCH=y \n".to_vec(),
            b"# CONFIG_SYSCALL_USER_DISPATCH is not set \n".to_vec(),
        ] {
            assert_eq!(scan(&[&text[..]]), ConfigAnswer::Unknown, "{:?}", String::from_utf8_lossy(&text));
        }
        // A line longer than the carry is skipped whole, and the next line is
        // still read: `long` resets at the newline.
        let mut long_then = vec![b'x'; 200];
        long_then.push(b'\n');
        long_then.extend_from_slice(not_set);
        long_then.push(b'\n');
        assert_eq!(scan(&[&long_then[..]]), ConfigAnswer::NotSet);
    }

    #[test]
    fn config_scan_carries_a_line_split_at_any_offset() {
        for (form, want) in [
            (&b"# CONFIG_SYSCALL_USER_DISPATCH is not set"[..], ConfigAnswer::NotSet),
            (&b"CONFIG_SYSCALL_USER_DISPATCH=y"[..], ConfigAnswer::Set),
        ] {
            let mut text = b"A=1\n".to_vec();
            text.extend_from_slice(form);
            text.extend_from_slice(b"\nB=2\n");
            for k in 0..=text.len() {
                assert_eq!(scan(&[&text[..k], &text[k..]]), want, "split at {k}");
            }
            // One byte per chunk.
            let bytes: Vec<&[u8]> = text.chunks(1).collect();
            assert_eq!(scan(&bytes), want, "1-byte chunks");
        }
    }

    #[test]
    fn boot_config_path_bounds() {
        let mut out = [0xffu8; 80];
        let release = [b'7'; 64];
        assert_eq!(boot_config_path(&release, &mut out), Some(77));
        assert_eq!(&out[..13], b"/boot/config-");
        assert_eq!(&out[13..77], &release[..]);
        assert_eq!(out[77], 0);
        for bad in [&[b'7'; 65][..], b"", b"a/b", b"a\0b"] {
            assert_eq!(boot_config_path(bad, &mut out), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    /// A NUL-terminated copy of `path`, as read_config_file takes it.
    fn nul(path: &std::path::Path) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt;
        let mut v = path.as_os_str().as_bytes().to_vec();
        v.push(0);
        v
    }

    /// read_config_file on `path_nul` in a thread, bounded at 5 s, so a
    /// blocking open fails this test by name instead of hanging the build.
    fn read_bounded(path_nul: &[u8]) -> Option<ConfigAnswer> {
        let (tx, rx) = std::sync::mpsc::channel();
        let path = path_nul.to_vec();
        std::thread::spawn(move || {
            let _ = tx.send(read_config_file(&path));
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).ok()
    }

    /// Removes a test directory when dropped, on success or on a panic.
    struct RemoveOnDrop(std::path::PathBuf);

    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn read_config_file_reads_regular_files_only() {
        use std::io::Write as _;
        // Unique beyond the PID (two PID namespaces can share TMPDIR), made
        // exclusively, and removed on drop, so a failing run leaves nothing.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("prearm-config-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).expect("create the test dir exclusively");
        let _cleanup = RemoveOnDrop(dir.clone());
        let line = b"# CONFIG_SYSCALL_USER_DISPATCH is not set\n";
        let not_set = dir.join("not-set");
        let mut text = b"CONFIG_A=y\n".to_vec();
        text.extend_from_slice(line);
        text.extend_from_slice(b"CONFIG_B=m\n");
        std::fs::write(&not_set, &text).unwrap();
        let set = dir.join("set");
        std::fs::write(&set, b"CONFIG_A=y\nCONFIG_SYSCALL_USER_DISPATCH=y\n").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&not_set, &link).unwrap();
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let big = dir.join("big");
        {
            let mut f = std::fs::File::create(&big).unwrap();
            f.write_all(&vec![b'x'; CONFIG_MAX as usize]).unwrap();
            f.write_all(b"\n").unwrap();
            f.write_all(line).unwrap();
        }
        assert_eq!(read_config_file(&nul(&not_set)), ConfigAnswer::NotSet, "the positive control");
        assert_eq!(read_config_file(&nul(&set)), ConfigAnswer::Set);
        assert_eq!(read_config_file(&nul(&link)), ConfigAnswer::Unknown, "a symlink (O_NOFOLLOW)");
        assert_eq!(read_config_file(&nul(&sub)), ConfigAnswer::Unknown, "a directory");
        assert_eq!(read_config_file(&nul(&dir.join("missing"))), ConfigAnswer::Unknown, "a missing path");
        assert_eq!(read_config_file(&nul(&big)), ConfigAnswer::Unknown, "a file over CONFIG_MAX");
        let mut no_nul = nul(&not_set);
        no_nul.pop();
        assert_eq!(read_config_file(&no_nul), ConfigAnswer::Unknown, "a path without its NUL");

        // An empty FIFO with no writer: the open must not block (O_NONBLOCK).
        let fifo = nul(&dir.join("fifo"));
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr().cast(), 0o600) }, 0, "mkfifo");
        match read_bounded(&fifo) {
            Some(answer) => assert_eq!(answer, ConfigAnswer::Unknown, "an empty FIFO"),
            None => {
                // Release the blocked open with a writer, then fail by name.
                let w = unsafe { libc::open(fifo.as_ptr().cast(), libc::O_WRONLY | libc::O_NONBLOCK) };
                if w >= 0 {
                    unsafe { libc::close(w) };
                }
                panic!("read_config_file gave no answer within 5 s on an empty FIFO: a blocking open (no O_NONBLOCK) or a stalled host");
            }
        }

        // A FIFO holding the not-set line with EOF pending: refused by its
        // type, never read. A kept reader holds the buffer after the writer
        // closes.
        let fifo_data = nul(&dir.join("fifo-data"));
        assert_eq!(unsafe { libc::mkfifo(fifo_data.as_ptr().cast(), 0o600) }, 0, "mkfifo");
        let keep = unsafe { libc::open(fifo_data.as_ptr().cast(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(keep >= 0, "open the kept reader");
        let keep = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(keep) };
        let w = unsafe { libc::open(fifo_data.as_ptr().cast(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(w >= 0, "open the writer");
        assert_eq!(unsafe { libc::write(w, line.as_ptr().cast(), line.len()) }, line.len() as isize);
        unsafe { libc::close(w) };
        let answer = read_bounded(&fifo_data);
        drop(keep);
        assert_eq!(
            answer,
            Some(ConfigAnswer::Unknown),
            "a FIFO is not a regular file, even with the canonical line in it"
        );
    }
}
