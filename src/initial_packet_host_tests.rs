//! Host tests of `initial_packet` that need the root crate: the
//! `CONFIG_JSON` pin (serde_json is not in the preload) and the production
//! connector under a soft `RLIMIT_NOFILE` each test sets itself, in a forked
//! child, so no outcome depends on the runner's limit.

use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use crate::initial_packet::*;

#[test]
fn config_json_is_serdes_declaration_order_string() {
    let json = serde_json::to_string(&canonical_config()).unwrap();
    assert_eq!(json, CONFIG_JSON);
    assert!(!json.contains("null"), "{json}");
    assert!(!json.contains("[]"), "{json}");
}

fn limits() -> (u64, u64) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid out-pointer.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    (limit.rlim_cur, limit.rlim_max)
}

/// Runs `body` in a forked child whose soft `RLIMIT_NOFILE` is `soft`, and
/// requires it to exit 0. The child starts no thread and ends with `_exit`.
fn in_child(soft: u64, body: impl FnOnce() -> Result<(), String>) {
    let (_, hard) = limits();
    assert!(
        hard >= soft,
        "this test needs a hard RLIMIT_NOFILE of at least {soft}; the runner's is {hard}"
    );
    // SAFETY: the child runs `body` on this thread only and leaves with _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let run = || -> Result<(), String> {
            let limit = libc::rlimit {
                rlim_cur: soft,
                rlim_max: hard,
            };
            // SAFETY: valid in-pointer; this child alone changes its limit.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                return Err(format!(
                    "setrlimit {soft}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            body()
        };
        let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
            Ok(Ok(())) => 0,
            Ok(Err(e)) => {
                eprintln!("initial_packet host test child: {e}");
                1
            }
            Err(_) => 2,
        };
        // SAFETY: leave the forked child without running the harness's exit.
        unsafe { libc::_exit(code) };
    }
    // Bounded: the child can deadlock if a sibling test thread held one of
    // std's locks (env, stderr) at the fork, so give it 60 s, then kill it
    // and fail rather than hang the run.
    let mut status = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let reaped = loop {
        // SAFETY: polls the child forked above.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r != 0 || std::time::Instant::now() >= deadline {
            break r;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    if reaped == 0 {
        // SAFETY: kills and reaps this test's own child.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
    }
    remove_sockets_of(pid);
    assert_eq!(reaped, pid, "child did not exit within 60 s");
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child failed: status {status:#x}"
    );
}

/// Removes the socket files [`listener`] made in the child `pid`.
fn remove_sockets_of(pid: libc::pid_t) {
    let prefix = format!("lr-ip-{pid}-");
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

fn listener(name: &str) -> Result<(UnixListener, PathBuf), String> {
    let path = std::env::temp_dir().join(format!("lr-ip-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    Ok((l, path))
}

/// The number the next lowest-free allocation takes.
fn lowest_free() -> i32 {
    // SAFETY: open and close a descriptor this function owns.
    unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        libc::close(fd);
        fd
    }
}

fn hold(range: std::ops::RangeInclusive<i32>) -> Result<(), String> {
    // SAFETY: dup2 of a descriptor this child opened onto free numbers.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        for n in range {
            if n != null && libc::dup2(null, n) != n {
                return Err(format!(
                    "dup2 onto {n}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    Ok(())
}

fn cloexec(fd: i32) -> bool {
    // SAFETY: F_GETFD reads flags only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    flags >= 0 && flags & libc::FD_CLOEXEC != 0
}

fn is_open(fd: i32) -> bool {
    // SAFETY: F_GETFD reads flags only.
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

fn check(ok: bool, what: String) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what) }
}

#[test]
fn coordinator_fd_goes_to_the_runtime_range() {
    let (_, hard) = limits();
    assert!(
        hard >= 1026,
        "needs a hard RLIMIT_NOFILE of at least 1026 to leave a number at 1025; the runner's is {hard}"
    );
    in_child(hard.min(2048), || {
        let (_l, path) = listener("range")?;
        let before = lowest_free();
        let stream = connect_coordinator(&path).map_err(|e| format!("{e:?}"))?;
        let fd = stream.as_raw_fd();
        check(fd >= 1025, format!("placed at {fd}"))?;
        check(cloexec(fd), format!("{fd} lacks FD_CLOEXEC"))?;
        check(
            lowest_free() == before,
            "the connect-time number stayed open".into(),
        )
    });
}

#[test]
fn coordinator_fd_under_soft_nofile_1024_goes_below_the_limit() {
    in_child(1024, || {
        check(
            reverie_inguest::guest::protect::runtime_fd_minimums().nth(1)
                == Some(top_band_floor(1024)),
            "top_band_floor(1024) is not Reverie's fallback floor".into(),
        )?;
        let (_l, path) = listener("soft1024")?;
        let before = lowest_free();
        let stream = connect_coordinator(&path).map_err(|e| format!("{e:?}"))?;
        let fd = stream.as_raw_fd();
        check((1016..=1023).contains(&fd), format!("placed at {fd}"))?;
        check(cloexec(fd), format!("{fd} lacks FD_CLOEXEC"))?;
        check(
            lowest_free() == before,
            "the connect-time number stayed open".into(),
        )
    });
}

#[test]
fn coordinator_fd_in_a_lower_block_is_refused() {
    in_child(1024, || {
        let (_l, path) = listener("lowerblock")?;
        hold(1016..=1023)?;
        let before = lowest_free();
        match connect_coordinator(&path) {
            Err(ConnectError::FdMove { errno: 0, placed }) => {
                check(
                    (1008..1016).contains(&placed),
                    format!("placed at {placed}"),
                )?;
                check(
                    !is_open(placed),
                    format!("refused connection left open at {placed}"),
                )?;
                check(lowest_free() == before, "a descriptor leaked".into())
            }
            other => Err(format!("expected FdMove in a lower block, got {other:?}")),
        }
    });
}

#[test]
fn coordinator_fd_move_refuses_with_no_free_number() {
    in_child(16, || {
        check(
            reverie_inguest::guest::protect::runtime_fd_minimums().nth(1)
                == Some(top_band_floor(16)),
            "top_band_floor(16) is not Reverie's fallback floor".into(),
        )?;
        // The listener moves to 14 and 3..=13 are held, so connect's socket
        // takes 15, the last number, and no number in any block is free.
        let (l, path) = listener("full")?;
        // SAFETY: duplicates the listener this child owns onto a free number.
        check(
            unsafe { libc::dup2(l.as_raw_fd(), 14) } == 14,
            "dup2 listener".into(),
        )?;
        drop(l);
        hold(3..=13)?;
        match connect_coordinator(&path) {
            Err(ConnectError::FdMove {
                errno: 0,
                placed: 15,
            }) => check(!is_open(15), "refused connection left open at 15".into()),
            other => Err(format!(
                "expected FdMove with the socket left at 15, got {other:?}"
            )),
        }
    });
}

/// Condition 1 (rl-lt, coord7): the placement records nothing, so Reverie's
/// installation is the single reservation, of the placed number. Installation
/// reserves `rpc.raw_fd()` after `from_live_client` (reverie-liteinst
/// tool_host.rs:1598), which is this same stream; that call runs only in a
/// mapped image (G2), so here the two halves literoot owns are checked: no
/// reservation exists after placement, and a second reservation of the
/// placed number is refused.
#[test]
fn placement_leaves_the_single_reservation_to_installation() {
    let (_, hard) = limits();
    in_child(hard.min(2048), || {
        let (_l, path) = listener("reserve")?;
        let stream = connect_coordinator(&path).map_err(|e| format!("{e:?}"))?;
        let fd = stream.as_raw_fd();
        reverie_inguest::guest::protect::reserve_coordinator_fd(fd)
            .map_err(|e| format!("the placement had already reserved: {e}"))?;
        match reverie_inguest::guest::protect::reserve_coordinator_fd(fd) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            other => Err(format!("a second reservation was not refused: {other:?}")),
        }
    });
}
