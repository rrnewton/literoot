//! Red witnesses W10, W10x, W11 and W12 of the static-initial plan
//! (revision 5 of the static-initial plan):
//! a static initial guest under the in-guest trap backend makes one
//! call that the in-guest runtime refuses, keeps running, and the
//! refusal is named in literoot's side log.
//!
//! RED TODAY, on purpose. Two links are missing: the static launch
//! (M2; today A6 refuses a static target before spawn) and link g2
//! (the in-guest drain, the coordinator-RPC refusal message, and the
//! side log that `--refusal-log <path>` names). Each witness is
//! therefore `#[ignore]`d as a known failure. Its body stays strict:
//! it never accepts the A6 refusal or a missing key line. Run them
//! with `--ignored`.
//!
//! The side-log line format is the plan's: `literoot: refused <key>
//! <detail>`, one line per refused kind per drain. A witness asserts
//! that its key line is present, never where it falls (plan N1).
//!
//! The ptrace controls run the same guests, modes and libcs under
//! the ptrace backend, where every call is allowed. They prove the
//! guests, so each witness isolates the in-guest refusal.

mod common;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use common::fixture_or_skip;
use common::literoot_bin;
use common::resolve_preload;
use common::run_bounded;

const GLIBC_GUEST: &str = "/bin/witness-glibc";
const MUSL_GUEST: &str = "/bin/witness-musl";

/// The two static guests, built into a scratch rootfs (`bin`, `tmp`), and
/// a side-log directory beside it. The side logs stay outside the rootfs,
/// so the guest can neither see nor write them.
struct Rootfs {
    scratch: PathBuf,
    dir: PathBuf,
    logs: PathBuf,
}

impl Drop for Rootfs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// Build both guests into a fresh rootfs. `None` is a skip, never a pass.
fn rootfs(label: &str) -> Option<Rootfs> {
    let scratch = std::env::temp_dir().join(format!(
        "literoot-static-witness-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    let dir = scratch.join("root");
    let logs = scratch.join("logs");
    for sub in [dir.join("bin"), dir.join("tmp"), logs.clone()] {
        std::fs::create_dir_all(sub).unwrap();
    }
    let rootfs = Rootfs { scratch, dir, logs };
    let guests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guests");
    let glibc = Command::new("cc")
        .args(["-O2", "-static", "-pthread", "-o"])
        .arg(rootfs.dir.join("bin/witness-glibc"))
        .arg(guests.join("static_witness.c"))
        .output()
        .expect("cc is required to build the glibc witness");
    if !fixture_or_skip(&glibc, "static glibc witness") {
        return None;
    }
    // No Rust runtime (no_std, no_main): std would install SIGSEGV and
    // SIGBUS handlers and an alternate stack before main, and those
    // refusals would reach the side log ahead of the witness call.
    let musl = Command::new("rustc")
        .args([
            "--edition=2021",
            "--target=x86_64-unknown-linux-musl",
            "-Cpanic=abort",
            "-Ctarget-feature=+crt-static",
            "-Crelocation-model=static",
            "-Copt-level=2",
            "-o",
        ])
        .arg(rootfs.dir.join("bin/witness-musl"))
        .arg(guests.join("static_witness_musl.rs"))
        .output()
        .expect("rustc is required to build the musl witness");
    if !fixture_or_skip(&musl, "static musl witness") {
        return None;
    }
    Some(rootfs)
}

/// One witness call: a guest, its mode, the stdout line it prints when
/// the call is refused, and the side-log lines the refusal must leave.
struct Case {
    guest: &'static str,
    mode: &'static str,
    refused: &'static str,
    allowed: &'static str,
    keys: &'static [&'static str],
}

// W10: expected call per libc (plan N4). glibc's fork() is
// clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD), a process
// clone; musl's fork() on x86-64 is SYS_fork; a raw syscall(SYS_fork)
// is fork on both.
const W10: &[Case] = &[
    Case {
        guest: GLIBC_GUEST,
        mode: "fork",
        refused: "fork-refused errno=",
        allowed: "fork-ok",
        keys: &["literoot: refused fork_policy clone_process"],
    },
    Case {
        guest: GLIBC_GUEST,
        mode: "raw-fork",
        refused: "raw-fork-refused errno=",
        allowed: "raw-fork-ok",
        keys: &["literoot: refused fork_policy fork"],
    },
    Case {
        guest: MUSL_GUEST,
        mode: "fork",
        refused: "fork-refused errno=",
        allowed: "fork-ok",
        keys: &["literoot: refused fork_policy fork"],
    },
    Case {
        guest: MUSL_GUEST,
        mode: "raw-fork",
        refused: "raw-fork-refused errno=",
        allowed: "raw-fork-ok",
        keys: &["literoot: refused fork_policy fork"],
    },
];

// W10x: the exit drain (plan N1, P7). After fork() the guest's only
// syscalls are a raw write and syscall(SYS_exit_group): no subscribed
// call drains first, so only on_exit_process / on_exit_thread can
// write the key line.
const W10X: &[Case] = &[Case {
    guest: GLIBC_GUEST,
    mode: "fork-then-exit",
    refused: "fork-refused errno=",
    allowed: "fork-ok",
    keys: &["literoot: refused fork_policy clone_process"],
}];

// W11: a handler for SIGUSR1 (10), and an alternate stack (plan N5).
const W11: &[Case] = &[
    Case {
        guest: GLIBC_GUEST,
        mode: "sigaction",
        refused: "sigaction-refused errno=",
        allowed: "sigaction-ok",
        keys: &["literoot: refused signal_action 10"],
    },
    Case {
        guest: GLIBC_GUEST,
        mode: "sigaltstack",
        refused: "sigaltstack-refused errno=",
        allowed: "sigaltstack-ok",
        keys: &["literoot: refused alternate_stack"],
    },
];

// W12 (review C1 b): thread creation is refused by the fork-like policy
// before any thread admission. Static glibc 2.34 installs a SIGRT_1 (33)
// handler, then calls clone3, whose flags are not read; musl calls
// clone with CLONE_THREAD.
const W12: &[Case] = &[
    Case {
        guest: GLIBC_GUEST,
        mode: "thread",
        refused: "thread-refused errno=",
        allowed: "thread-ok",
        keys: &[
            "literoot: refused signal_action 33",
            "literoot: refused fork_policy clone3",
        ],
    },
    Case {
        guest: MUSL_GUEST,
        mode: "thread",
        refused: "thread-refused errno=",
        allowed: "thread-ok",
        keys: &["literoot: refused fork_policy clone_thread"],
    },
];

fn launch(rootfs: &Rootfs, backend: &str, case: &Case, side_log: Option<&Path>) -> Output {
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", backend]);
    if let Some(log) = side_log {
        cmd.arg("--refusal-log").arg(log);
    }
    cmd.arg("-r").arg(&rootfs.dir).args([case.guest, case.mode]);
    if backend != "ptrace" {
        cmd.env("LITEROOT_PRELOAD", resolve_preload());
    }
    run_bounded(cmd, &format!("{backend} {} {}", case.guest, case.mode))
}

fn stdout_lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Run every case under the in-guest trap backend with its own side
/// log, and return a description of each case that is not as the plan
/// requires: exit 7 (the guest continued), the refused line on stdout,
/// and every key line present in the side log.
fn refusals_named(label: &str, cases: &[Case]) -> Vec<String> {
    let preload = resolve_preload();
    assert!(
        preload.exists(),
        "the witnesses require the preload built: \
         cargo build --release --manifest-path preload/Cargo.toml"
    );
    let rootfs = rootfs(label).expect("both witness guests must build for a witness");
    let mut wrong = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let log = rootfs.logs.join(format!("side-log-{i}"));
        let out = launch(&rootfs, "trap", case, Some(&log));
        let side = std::fs::read_to_string(&log).unwrap_or_default();
        let lines: Vec<&str> = side.lines().collect();
        let printed = stdout_lines(&out);
        let continued = out.status.code() == Some(7);
        let refused = printed.iter().any(|l| l.starts_with(case.refused));
        let missing: Vec<&str> = case
            .keys
            .iter()
            .copied()
            .filter(|key| !lines.contains(key))
            .collect();
        if !continued || !refused || !missing.is_empty() {
            wrong.push(format!(
                "{} {}: exit {:?} (want 7), stdout {printed:?} (want a line \
                 starting {:?}), side log missing {missing:?}; side log {side:?}; \
                 stderr {:?}",
                case.guest,
                case.mode,
                out.status.code(),
                case.refused,
                String::from_utf8_lossy(&out.stderr),
            ));
        }
    }
    wrong
}

/// Control: under ptrace every witness call is allowed, so each case
/// exits 7 with its `-ok` line. Proves the guests and their modes.
#[test]
fn static_witness_guests_ptrace_control() {
    let Some(rootfs) = rootfs("ptrace-control") else {
        return;
    };
    let mut wrong = Vec::new();
    for case in [W10, W10X, W11, W12].into_iter().flatten() {
        let out = launch(&rootfs, "ptrace", case, None);
        let printed = stdout_lines(&out);
        if out.status.code() != Some(7) || printed != [case.allowed] {
            wrong.push(format!(
                "{} {}: exit {:?}, stdout {printed:?} (want 7, [{:?}]); stderr {:?}",
                case.guest,
                case.mode,
                out.status.code(),
                case.allowed,
                String::from_utf8_lossy(&out.stderr),
            ));
        }
    }
    assert!(wrong.is_empty(), "ptrace control:\n{}", wrong.join("\n"));
}

#[test]
#[ignore = "red witness: needs the static launch (M2) and link g2 (side log)"]
fn w10_refused_fork_is_named_and_the_guest_continues() {
    let wrong = refusals_named("w10", W10);
    assert!(wrong.is_empty(), "W10:\n{}", wrong.join("\n"));
}

#[test]
#[ignore = "red witness: needs the static launch (M2) and link g2 (exit drain)"]
fn w10x_the_exit_drain_names_a_refused_fork() {
    let wrong = refusals_named("w10x", W10X);
    assert!(wrong.is_empty(), "W10x:\n{}", wrong.join("\n"));
}

#[test]
#[ignore = "red witness: needs the static launch (M2) and link g2 (side log)"]
fn w11_refused_handler_and_alternate_stack_are_named() {
    let wrong = refusals_named("w11", W11);
    assert!(wrong.is_empty(), "W11:\n{}", wrong.join("\n"));
}

#[test]
#[ignore = "red witness: needs the static launch (M2) and link g2 (side log)"]
fn w12_refused_thread_creation_is_named_by_the_fork_policy() {
    let wrong = refusals_named("w12", W12);
    assert!(wrong.is_empty(), "W12:\n{}", wrong.join("\n"));
}
