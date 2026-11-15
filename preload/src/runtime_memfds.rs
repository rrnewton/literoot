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
//! - Fork child (`replace_in_fork_child`, from the Tool's
//!   `handle_thread_start`, which Reverie runs in the child before the
//!   callback that forked returns): the child inherited its parent's
//!   copies at numbers recorded under the parent's pid, which the runtime
//!   closes in a child (`close_inherited_runtime_fds`). So the child
//!   reopens each copy by path, closes the inherited records itself, and
//!   places the reopened copies under its own pid. Only plain forks create
//!   a child in-guest; see the comment on the Tool's clone arms.
//!
//! A failure leaves that memfd absent in that process, never an
//! unprotected copy: the shared record falls back to the callers'
//! process-local state, and the probe generation keeps a mapping the
//! process already has (losing only exec inheritance) or falls back to
//! the process-local counter. With `LITEROOT_DEBUG` set, each failure
//! prints one line.
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

fn report(what: &str, error: &dyn std::fmt::Display) {
    if std::env::var_os("LITEROOT_DEBUG").is_some() {
        eprintln!("literoot: {what} unavailable in this process: {error}");
    }
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

/// A new descriptor on the file open at `fd`, opened through
/// `/proc/self/fd/<fd>`, kept only when `same_file` accepts it. A Tool
/// call that names a recorded number is refused like the guest's
/// (`forward_nested_tool_syscall`); a path open names no descriptor.
fn reopen(fd: i32, same_file: impl FnOnce(i32) -> bool) -> std::io::Result<i32> {
    let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}"))
        .expect("a descriptor path has no NUL");
    // SAFETY: opens a path; the new descriptor is owned here.
    let copy = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !same_file(copy) {
        close(copy);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the inherited number holds another file",
        ));
    }
    Ok(copy)
}

/// Re-place a fork child's copies under its own pid. A no-op for a thread
/// start in the process that placed them, and for a lineage that placed
/// nothing. The parent's copies are reopened first and the inherited
/// records closed before the new copies are placed, so the record stays
/// bounded (the memfds and the counter) on every build, whenever the
/// runtime first reads its clock in the child.
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
    let probe_copy = probe.map(|(fd, identity)| {
        reopen(fd, |copy| FdIdentity::of_fd(copy).ok() == Some(identity))
    });
    let store_copy = store.map(|store| reopen(store.fd(), |copy| store.is_store_file(copy)));
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
