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
//!   on x86_64, kernel release (`decide_off`).
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

/// The OFF call's outcome that lets startup go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffOutcome {
    /// The mode is OFF.
    Off,
    /// EINVAL with independent evidence that the kernel has no syscall
    /// user dispatch: startup goes on, noted (`literoot: note sud_absent`).
    Absent,
}

/// Decide the OFF call's result `result` (a value or a negative errno) on
/// `arch` (C5a.2). `release` and `persona` are read only on the x86_64
/// EINVAL path: the release's `<major>.<minor>`, and the raw personality
/// (None when either cannot be read).
pub fn decide_off(
    arch: Arch,
    result: i64,
    release: impl FnOnce() -> Option<(u32, u32)>,
    persona: impl FnOnce() -> Option<u64>,
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
            // Syscall user dispatch first appears in v5.11-rc1. A 7.3+
            // kernel built with CONFIG_SYSCALL_USER_DISPATCH=n also answers
            // EINVAL here and gets the named failure. Tracked follow-up:
            // accept "absent" when the kernel's own config, where readable
            // (/proc/config.gz or /boot/config-<release>), says the option
            // is not set.
            if (major, minor) < (5, 11) {
                Ok(OffOutcome::Absent)
            } else {
                Err("cannot turn syscall user dispatch off: EINVAL on a kernel that has it \
                     (a security policy may deny it, or the kernel was built without it)")
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
    let release = || {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { raw(libc::SYS_uname, [&mut uts as *mut libc::utsname as u64, 0, 0, 0, 0, 0]) } != 0 {
            return None;
        }
        let release: &[u8] = unsafe {
            std::slice::from_raw_parts(uts.release.as_ptr().cast::<u8>(), uts.release.len())
        };
        let end = release.iter().position(|&b| b == 0)?;
        parse_release(&release[..end])
    };
    let persona = || {
        let p = unsafe { raw(libc::SYS_personality, [0xffff_ffff, 0, 0, 0, 0, 0]) };
        (p >= 0).then_some(p as u64)
    };
    if decide_off(ARCH, off, release, persona)? == OffOutcome::Absent {
        SUD_ABSENT.store(true, Ordering::Release);
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

    #[test]
    fn decide_off_by_arch_release_and_persona() {
        let einval = -i64::from(libc::EINVAL);
        for arch in [Arch::X86_64, Arch::Aarch64, Arch::Other] {
            assert_eq!(decide_off(arch, 0, never, never), Ok(OffOutcome::Off));
            assert!(decide_off(arch, -i64::from(libc::ENOSYS), never, never).is_err());
            assert!(decide_off(arch, -i64::from(libc::EPERM), never, never).is_err());
            assert!(decide_off(arch, 1, never, never).is_err());
        }
        // arm64: absent with no release bound, and nothing read.
        assert_eq!(decide_off(Arch::Aarch64, einval, never, never), Ok(OffOutcome::Absent));
        // Any other arch (branch (c)): a named failure, nothing read.
        assert!(decide_off(Arch::Other, einval, never, never)
            .unwrap_err()
            .contains("an architecture literoot does not know"));
        // x86_64: below 5.11 absent; 5.11 and later, UNAME26, an unreadable
        // persona or release: named failures.
        let x86 = |release: Option<(u32, u32)>, persona: Option<u64>| {
            decide_off(Arch::X86_64, einval, || release, || persona)
        };
        assert_eq!(x86(Some((5, 10)), Some(0)), Ok(OffOutcome::Absent));
        assert!(x86(Some((5, 11)), Some(0)).is_err());
        assert!(x86(Some((7, 1)), Some(0)).is_err());
        assert!(x86(Some((2, 6)), Some(UNAME26)).unwrap_err().contains("UNAME26"));
        assert!(x86(Some((5, 10)), None).is_err());
        assert!(x86(None, Some(0)).unwrap_err().contains("unparsable"));
    }
}
