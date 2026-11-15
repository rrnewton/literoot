//! The two launcher-created memfds an in-guest image shares with the
//! rest of its guest tree: the probe-cache generation
//! (`translate::PROBE_GEN_ID_ENV`) and the cross-process facts record
//! (`shared_record::SHARED_RECORD_ID_ENV`).
//!
//! Each image holds its copy of each at a number the in-guest runtime
//! keeps the guest away from, as it does its own descriptors: the copy is
//! moved into the runtime's range and recorded there
//! (`reverie_inguest::guest::protect::place_runtime_fd_and` and
//! `record_runtime_fd`). A guest call that names the number then fails as
//! on a number the guest does not have (EBADF), a `close_range` over it
//! spares it, and a `dup2`, `dup3` or `F_DUPFD` that would take it gets
//! the number (see the limits below). Before this, a guest could fcntl,
//! read, write, mmap, truncate, close or send (SCM_RIGHTS) both memfds by
//! number, at the low numbers the launcher handed down.
//!
//! The copies stay inheritable. The placement makes the new number
//! close-on-exec; `place` clears that inside the placement, before
//! recording, so an exec keeps both memfds, as their creation intends
//! ("descendants and guest execs must inherit").
//!
//! - Image start (`adopt_at_image_start`, from the preload initializer
//!   once the bootstrap is taken, before the runtime is installed and
//!   before any guest instruction): find each inherited copy by the file
//!   identity the launcher put in the environment (the launcher's number
//!   in a first image, the predecessor's placed number after an exec),
//!   adopt it, and place it.
//! - Fork child (`replace_in_fork_child`, from the Tool's `new`, the
//!   first Tool code Reverie runs in a fork child, and again, as a no-op,
//!   from `handle_thread_start`): the child inherited its parent's copies
//!   at numbers recorded under the parent's pid, which the runtime closes
//!   in a child (`close_inherited_runtime_fds`). So the child reopens each
//!   copy by path, closes the inherited records itself, and places the
//!   reopened copies under its own pid. Only plain forks create a child
//!   in-guest; see the comment on the Tool's clone arms.
//!
//!   The reopens go through the runtime's own syscall gate, before any
//!   libc call in the child. Under LiteInst a libc syscall from a site
//!   the guest's own calls have already had patched enters the runtime's
//!   hook, which reads the RCB clock first; a fork child's first clock
//!   read closes the inherited records (Reverie 6281d616,
//!   `reverie-inguest/src/guest/installed_tool.rs` `dispatch_saved_syscall`,
//!   and `clock.rs` `rcb_clock`). A libc reopen would therefore close the
//!   very copy it reopens. The gate's syscall instruction is allowed by
//!   the runtime's filter and never traps (`trap.rs` `raw_syscall6`), so
//!   no site there is ever patched. tests/runtime_memfds.rs
//!   `liteinst_clock_read_before_the_reopen_fails_loudly` is the twin of a
//!   mutant, applied as a patch by the test runner and absent from this
//!   tree, that reads the clock before the reopens: under it the tree must
//!   lose both memfds in every fork child and say so on stderr.
//!
//! A failure leaves that memfd absent in that process, never an
//! unprotected copy: the shared record falls back to the callers'
//! process-local state, and the probe generation keeps a mapping the
//! process already has (losing only exec inheritance) or falls back to
//! the process-local counter. Every build prints one line on stderr for
//! each failure, so a lost memfd is never silent.
//!
//! Limits, stated rather than fixed:
//! - Reverie's own reserved descriptors are sockets or anonymous inodes,
//!   which the kernel refuses to reopen by path (ENXIO); literoot's placed
//!   memfds are regular files and remain reachable through
//!   /proc/self/fd/<n> and /proc/<pid>/fd/<n>. The fork-child path here
//!   relies on that reopen itself, as the shared record does for every
//!   operation.
//! - A guest `dup2`, `dup3` or `F_DUPFD` that takes a placed number makes
//!   Reverie close the copy and forget it (`relocate_runtime_fd` moves
//!   only the runtime's counter, coordinator connection and Tool output
//!   socket). That process then fails closed: the shared record's identity
//!   check refuses the guest's file at the number and the callers fall
//!   back, and the probe generation keeps its mapping. There is no copy
//!   left to look for; a rescan by identity could only find a copy the
//!   guest reopened by path, which is the guest's descriptor, not one to
//!   adopt.
//! - The identity handoff protects against number reuse. It is not
//!   authentication: a guest can name any file it holds, which desyncs
//!   only its own tree.

use std::sync::atomic::{AtomicI32, Ordering};

use reverie_inguest::guest::protect;
use reverie_inguest::trap::raw_syscall6;

use crate::shared_record::{self, SharedRecordFile, SHARED_RECORD_ID_ENV};
use crate::translate::{self, FdIdentity, PROBE_GEN_ID_ENV};

/// The pid that placed this process's copies, or 0 when this image placed
/// nothing. A thread start in another pid is a fork child holding its
/// parent's copies.
static PLACED_BY: AtomicI32 = AtomicI32::new(0);

/// This process's pid through the runtime's gate, the pid the runtime
/// keys its records by.
fn raw_pid() -> i32 {
    // SAFETY: getpid takes no arguments and changes nothing.
    unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) as i32 }
}

/// One stderr line for a memfd this process cannot hold, in every build.
fn report(what: &str, error: &dyn std::fmt::Display) {
    eprintln!("literoot: {what} unavailable in this process: {error}");
}

fn close(fd: i32) {
    // SAFETY: closes a descriptor this module owns and no one else uses.
    unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
}

/// Moves `fd` into the runtime's range, keeps the new number inheritable
/// across exec, and records it as the runtime's. Returns the new number.
/// On `Err` the placement has already closed the number it held
/// (`place_runtime_fd_and`), so no copy remains.
fn place(fd: i32) -> std::io::Result<i32> {
    protect::place_runtime_fd_and(fd, |placed| {
        // Inside the placement's signal-blocked window every syscall goes
        // through the runtime's gate, never libc (`block_all_signals`).
        // The flag is cleared before the record: once recorded, the
        // runtime refuses this process's own calls naming the number.
        // SAFETY: F_SETFD changes only this descriptor's flags.
        let cleared = unsafe {
            raw_syscall6(
                libc::SYS_fcntl,
                [placed as u64, libc::F_SETFD as u64, 0, 0, 0, 0],
            )
        };
        if cleared < 0 {
            return Err(std::io::Error::from_raw_os_error(-cleared as i32));
        }
        protect::record_runtime_fd(placed)
    })
}

/// The inherited copy of the memfd that the environment variable `name`
/// identifies, with that identity; `None` when there is no variable or no
/// read-write copy, or the listing failed.
fn inherited(name: &str, what: &str) -> Option<(i32, FdIdentity)> {
    let identity = FdIdentity::decode(&std::env::var(name).ok()?)?;
    match translate::find_read_write_descriptor(identity) {
        Ok(found) => found.map(|fd| (fd, identity)),
        Err(error) => {
            report(what, &error);
            None
        }
    }
}

/// Adopt and place this image's inherited copies, and register the
/// fork-child re-placement. Called once per image from the preload
/// initializer, after the bootstrap is taken and before the runtime is
/// installed: nothing traps yet, and no guest instruction has run.
pub(crate) fn adopt_at_image_start() {
    PLACED_BY.store(raw_pid(), Ordering::Release);
    if let Some((fd, identity)) = inherited(PROBE_GEN_ID_ENV, "probe generation") {
        if translate::adopt_shared_gen(fd, identity) {
            match place(fd) {
                Ok(placed) => translate::set_shared_gen_fd(placed),
                Err(error) => {
                    translate::set_shared_gen_fd(-1);
                    report("probe generation", &error);
                }
            }
        } else {
            close(fd);
            report("probe generation", &"the counter cannot be mapped");
        }
    }
    if let Some((fd, _)) = inherited(SHARED_RECORD_ID_ENV, "shared record") {
        match SharedRecordFile::from_fd(fd) {
            Some(store) => match place(fd) {
                Ok(placed) => {
                    store.set_fd(placed);
                    let _ = shared_record::init_shared_record_file(store);
                }
                Err(error) => report("shared record", &error),
            },
            None => {
                close(fd);
                report("shared record", &"the inherited copy is not a valid store");
            }
        }
    }
    shared_record::set_fork_child_hook(replace_in_fork_child);
}

/// `/proc/self/fd/<fd>` as a NUL-terminated path in `buf`, without
/// allocating. Returns the path's length without the NUL.
fn proc_fd_path(fd: i32, buf: &mut [u8; 32]) -> usize {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut digits = [0u8; 10];
    let mut n = fd.max(0) as u32;
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut at = PREFIX.len();
    for i in (0..len).rev() {
        buf[at] = digits[i];
        at += 1;
    }
    buf[at] = 0;
    at
}

/// A new descriptor on the file open at `fd`, opened through
/// `/proc/self/fd/<fd>` by the runtime's gate: no libc call, no
/// allocation. A path open names no descriptor, so the runtime does not
/// refuse it. The caller checks the new descriptor's identity.
fn reopen_raw(fd: i32) -> std::io::Result<i32> {
    let mut path = [0u8; 32];
    proc_fd_path(fd, &mut path);
    // SAFETY: opens a NUL-terminated path in a live stack buffer; the new
    // descriptor is owned by the caller.
    let copy = unsafe {
        raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as i64 as u64,
                path.as_ptr() as u64,
                (libc::O_RDWR | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if copy < 0 {
        return Err(std::io::Error::from_raw_os_error(-copy as i32));
    }
    Ok(copy as i32)
}

/// Keeps `copy` when `same_file` accepts it, and closes it otherwise.
fn checked(
    copy: std::io::Result<i32>,
    same_file: impl FnOnce(i32) -> bool,
) -> std::io::Result<i32> {
    let copy = copy?;
    if same_file(copy) {
        return Ok(copy);
    }
    close(copy);
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the inherited number holds another file",
    ))
}

/// Re-place a fork child's copies under its own pid. A no-op in the
/// process that placed them (its own Tool construction and thread
/// starts, and every call after the first in a child), and for a lineage
/// that placed nothing. Everything before the two reopens is memory or
/// the runtime's gate, so no libc call can close the inherited copies
/// first (module docs). The inherited records are closed before the new
/// copies are placed, so the record stays bounded (the memfds and the
/// counter) on every build, whenever the runtime first reads its clock in
/// the child.
fn replace_in_fork_child() {
    let pid = raw_pid();
    let placer = PLACED_BY.load(Ordering::Acquire);
    if placer == 0 || placer == pid {
        return;
    }
    PLACED_BY.store(pid, Ordering::Release);
    let probe = translate::shared_gen_descriptor();
    let store = shared_record::shared_record_file().filter(|store| store.fd() >= 0);
    if probe.is_none() && store.is_none() {
        return;
    }
    // MUTANT (clock first; never in the tree): this fork child's first RCB
    // clock read runs before the reopens, as if Reverie had moved one ahead
    // of the Tool's construction. It closes the inherited copies.
    let _ = reverie_inguest::guest::clock::read_guest_rcb_clock();
    // Both copies first, through the runtime's gate.
    let probe_copy = probe.map(|(fd, _)| reopen_raw(fd));
    let store_copy = store.map(|store| reopen_raw(store.fd()));
    // Libc may run from here on: the copies just opened are not recorded,
    // so a clock read that closes the inherited records leaves them.
    let probe_copy = probe.zip(probe_copy).map(|((_, identity), copy)| {
        checked(copy, |copy| FdIdentity::of_fd(copy).ok() == Some(identity))
    });
    let store_copy = store
        .zip(store_copy)
        .map(|(store, copy)| checked(copy, |copy| store.is_store_file(copy)));
    if let Err(error) = protect::close_inherited_runtime_fds() {
        report("the inherited runtime descriptors' close", &error);
    }
    if let Some(copy) = probe_copy {
        match copy.and_then(place) {
            Ok(placed) => translate::set_shared_gen_fd(placed),
            Err(error) => {
                translate::set_shared_gen_fd(-1);
                report("probe generation", &error);
            }
        }
    }
    if let (Some(store), Some(copy)) = (store, store_copy) {
        match copy.and_then(place) {
            Ok(placed) => store.set_fd(placed),
            Err(error) => {
                store.set_fd(-1);
                report("shared record", &error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The exec half of inheritance. A guest exec is refused in-guest at
    //! the pinned Reverie (no native exec route or exec watch in the
    //! default builds), so it cannot run end to end under literoot. These
    //! tests run the real placement in a test process, then exec a child
    //! image of the test binary, which must find each copy by identity at
    //! the placed number and adopt it as `adopt_at_image_start` would.
    use super::*;

    const CHILD_ENV: &str = "LITEROOT_RUNTIME_MEMFDS_TEST_CHILD";

    fn memfd(name: &std::ffi::CStr) -> i32 {
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        fd
    }

    fn is_open(fd: i32) -> bool {
        unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
    }

    /// Runs this test binary again on exactly `test`, as a child image
    /// with `envs`, and returns its stdout and whether it succeeded.
    fn exec_child(test: &str, envs: &[(&str, String)]) -> (String, bool) {
        let exe = std::env::current_exe().expect("test binary path");
        let mut command = std::process::Command::new(exe);
        command
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1");
        for (key, value) in envs {
            command.env(key, value);
        }
        let out = command.output().expect("run the child image");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.success(),
        )
    }

    #[test]
    fn proc_fd_path_writes_the_number_and_a_nul() {
        for (fd, want) in [
            (0, "/proc/self/fd/0"),
            (7, "/proc/self/fd/7"),
            (1000, "/proc/self/fd/1000"),
            (i32::MAX, "/proc/self/fd/2147483647"),
        ] {
            let mut buf = [0xffu8; 32];
            let len = proc_fd_path(fd, &mut buf);
            assert_eq!(&buf[..len], want.as_bytes());
            assert_eq!(buf[len], 0);
        }
    }

    /// The fork child's reopen: through the runtime's gate, the same file,
    /// close-on-exec until placed; a closed number is ENOENT, which is what
    /// a reopen after the runtime closed the inherited copy would see.
    #[test]
    fn raw_reopen_opens_the_same_file_and_refuses_a_closed_number() {
        let fd = memfd(c"literoot-raw-reopen-test");
        let copy = reopen_raw(fd).expect("reopen an open memfd");
        assert_ne!(copy, fd);
        assert_eq!(
            FdIdentity::of_fd(copy).unwrap(),
            FdIdentity::of_fd(fd).unwrap()
        );
        let flags = unsafe { libc::fcntl(copy, libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        unsafe { libc::close(copy) };
        // A high number no other test uses, closed again at once.
        let gone = 901;
        assert_eq!(unsafe { libc::dup2(fd, gone) }, gone);
        unsafe { libc::close(gone) };
        let err = reopen_raw(gone).expect_err("a closed number");
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
        unsafe { libc::close(fd) };
    }

    #[test]
    fn placed_copy_is_recorded_inheritable_and_moved_off_the_low_number() {
        if std::env::var_os(CHILD_ENV).is_some() {
            return;
        }
        // Start from a number no parallel test's lowest-free open can
        // take, so "closed after the move" cannot be another file.
        let created = memfd(c"literoot-place-test");
        let fd = unsafe { libc::fcntl(created, libc::F_DUPFD, 777) };
        assert!(fd >= 777);
        unsafe { libc::close(created) };
        let identity = FdIdentity::of_fd(fd).unwrap();
        let placed = place(fd).expect("place");
        assert_ne!(placed, fd);
        // The runtime's band: at or above RUNTIME_FD_MIN, or the eight
        // numbers below a soft RLIMIT_NOFILE that leaves none there.
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
        let band = protect::RUNTIME_FD_MIN.min(limit.rlim_cur.min(i32::MAX as u64) as i32 - 8);
        assert!(placed >= band, "placed at {placed}, below the band at {band}");
        assert!(!is_open(fd), "the low number was closed");
        assert_eq!(FdIdentity::of_fd(placed).unwrap(), identity);
        assert_eq!(unsafe { libc::fcntl(placed, libc::F_GETFD) }, 0, "inheritable");
        assert!(protect::is_runtime_owned_fd(placed), "recorded");
    }

    #[test]
    fn exec_child_finds_and_adopts_placed_probe_generation() {
        if std::env::var_os(CHILD_ENV).is_some() {
            // The child image: the placed copy came through exec at the
            // same number and is found by identity alone.
            let identity =
                FdIdentity::decode(&std::env::var(PROBE_GEN_ID_ENV).unwrap()).unwrap();
            let expected: i32 = std::env::var("LITEROOT_TEST_PLACED").unwrap().parse().unwrap();
            let found = translate::find_read_write_descriptor(identity).unwrap();
            assert_eq!(found, Some(expected));
            assert!(translate::adopt_shared_gen(expected, identity));
            println!("child-generation={}", translate::probe_gen());
            return;
        }
        // The counter is written through the file, not through this
        // process's mapping: another test may already have mapped a
        // different generation memfd into this test process.
        let fd = translate::create_shared_gen_fd();
        assert!(fd >= 0);
        let identity = FdIdentity::of_fd(fd).unwrap();
        let generation: u64 = 7_000_000_007;
        let bytes = generation.to_ne_bytes();
        assert_eq!(
            unsafe { libc::pwrite(fd, bytes.as_ptr().cast(), bytes.len(), 0) },
            8
        );
        let placed = place(fd).expect("place");
        let (stdout, ok) = exec_child(
            "runtime_memfds::tests::exec_child_finds_and_adopts_placed_probe_generation",
            &[
                (PROBE_GEN_ID_ENV, identity.encode()),
                ("LITEROOT_TEST_PLACED", placed.to_string()),
            ],
        );
        assert!(ok, "child failed: {stdout}");
        assert!(
            stdout.contains(&format!("child-generation={generation}")),
            "child did not read the shared generation {generation}: {stdout}"
        );
    }

    #[test]
    fn exec_child_finds_and_adopts_placed_shared_record() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let identity =
                FdIdentity::decode(&std::env::var(SHARED_RECORD_ID_ENV).unwrap()).unwrap();
            let expected: i32 = std::env::var("LITEROOT_TEST_PLACED").unwrap().parse().unwrap();
            let found = translate::find_read_write_descriptor(identity).unwrap();
            assert_eq!(found, Some(expected));
            let store = SharedRecordFile::from_fd(expected).expect("adopt");
            let uts = store.uts().expect("read");
            println!("child-nodename={}", String::from_utf8_lossy(&uts.0.unwrap()));
            return;
        }
        let store = SharedRecordFile::create().expect("create");
        store
            .set_uts_nodename(Some(b"exec-parent".to_vec()))
            .expect("write");
        let identity = FdIdentity::of_fd(store.fd()).unwrap();
        let placed = place(store.fd()).expect("place");
        store.set_fd(placed);
        let (stdout, ok) = exec_child(
            "runtime_memfds::tests::exec_child_finds_and_adopts_placed_shared_record",
            &[
                (SHARED_RECORD_ID_ENV, identity.encode()),
                ("LITEROOT_TEST_PLACED", placed.to_string()),
            ],
        );
        assert!(ok, "child failed: {stdout}");
        assert!(
            stdout.contains("child-nodename=exec-parent"),
            "child did not read the shared record: {stdout}"
        );
    }
}
