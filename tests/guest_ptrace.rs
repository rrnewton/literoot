//! Guest ptrace must fail fast, never hang.
//!
//! The guest mirrors upstream test-ptrace-setoptions: a
//! child PTRACE_TRACEME + SIGSTOP, the parent waits, calls
//! PTRACE_SETOPTIONS, then PTRACE_SYSCALLs expecting
//! syscall stops. Under the in-guest trap backend the
//! child's syscalls are seccomp-trapped (SIGSYS) for the
//! Tool; a guest tracer that continues the child with the
//! SIGSYS suppressed makes the child re-trap forever and
//! the parent spins in wait — measured as a >60 s hang
//! with both guest processes running. Literoot therefore
//! refuses the guest ptrace syscall itself (EPERM, the
//! same errno the kernel gives a tracee that is already
//! traced under the ptrace backend): TRACEME fails in the
//! child, the parent reports it, and both exit promptly.
//!
//! Both arms are bounded by a harness timeout that kills
//! the whole process group, so a regression to the hang
//! fails this test instead of stalling the gate. The trap
//! arm skips with a notice when the preload has not been
//! built (same convention as inguest_exec_translation):
//!   cargo build --release --manifest-path preload/Cargo.toml
//! In that environment only the ptrace arm distinguishes
//! nothing (the kernel already refuses); the trap arm is
//! the discriminating one where the preload exists.

use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

const GUEST_C: &str = r#"
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
int main(void) {
    bool does_work = false;
    int status;
    pid_t pid;
    switch (pid = fork()) {
    case -1:
        perror("fork");
        exit(EXIT_FAILURE);
    case 0:
        status = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (status < 0) {
            perror("ptrace(PTRACE_TRACEME)");
            exit(EXIT_FAILURE);
        }
        kill(getpid(), SIGSTOP);
        exit(EXIT_SUCCESS);
    default:
        break;
    }
    for (int iter = 0; iter < 200; iter++) {
        pid = wait(&status);
        if (pid < 0) {
            perror("wait");
            exit(EXIT_FAILURE);
        } else if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0)
                break;
            fprintf(stderr, "WEXITSTATUS != 0\n");
            exit(EXIT_FAILURE);
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "WIFSIGNALED\n");
            exit(EXIT_FAILURE);
        } else if (!WIFSTOPPED(status)) {
            fprintf(stderr, "!WIFSTOPPED\n");
            exit(EXIT_FAILURE);
        } else if (WSTOPSIG(status) == SIGSTOP) {
            status = ptrace(PTRACE_SETOPTIONS, pid, 0,
                            PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
            if (status < 0) {
                perror("ptrace(PTRACE_SETOPTIONS)");
                exit(EXIT_FAILURE);
            }
        } else if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            does_work = true;
        }
        status = ptrace(PTRACE_SYSCALL, pid, 0, 0);
        if (status < 0) {
            perror("ptrace(PTRACE_SYSCALL)");
            exit(EXIT_FAILURE);
        }
    }
    exit(does_work ? EXIT_SUCCESS : EXIT_FAILURE);
}
"#;

fn kill_pgroup(child: &mut Child) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(-(child.id() as i32), 9);
    }
    let _ = child.kill();
}

/// Run literoot with a hard timeout: on expiry kill the
/// whole process group (launcher + guests) and fail.
fn run_bounded(mut cmd: Command, what: &str) -> Output {
    use std::os::unix::process::CommandExt as _;
    cmd.process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn literoot");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait literoot") {
            Some(_) => return child.wait_with_output().expect("collect literoot output"),
            None if Instant::now() >= deadline => {
                kill_pgroup(&mut child);
                let out = child.wait_with_output().expect("collect killed output");
                panic!(
                    "{what}: guest ptrace hang: literoot did not finish within 10 s: {out:?}"
                );
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn build_guest(dir: &std::path::Path) -> Option<PathBuf> {
    std::fs::write(dir.join("setoptions.c"), GUEST_C).unwrap();
    let bin = dir.join("setoptions");
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(dir.join("setoptions.c"))
        .output()
        .expect("cc is required to build the setoptions guest");
    if !cc.status.success() {
        eprintln!("guest-ptrace: cc unavailable — skipping: {cc:?}");
        return None;
    }
    Some(bin)
}

fn assert_fast_traceme_refusal(out: &Output, backend: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "{backend}: guest ptrace must be refused, not succeed: {out:?}"
    );
    assert!(
        stderr.contains("ptrace(PTRACE_TRACEME): Operation not permitted"),
        "{backend}: refusal must surface as TRACEME EPERM, got: {stderr:?}"
    );
}

#[test]
fn guest_ptrace_refused_fast_ptrace_backend() {
    let dir = std::env::temp_dir().join(format!("literoot-guestptrace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(bin) = build_guest(&dir) else { return };
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", "ptrace"]).arg(&bin);
    let out = run_bounded(cmd, "ptrace backend");
    let _ = std::fs::remove_dir_all(&dir);
    assert_fast_traceme_refusal(&out, "ptrace");
}

#[test]
fn guest_ptrace_refused_fast_trap_backend() {
    let preload = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("preload/target/release/libliteroot_preload.so");
    if !preload.exists() {
        eprintln!("guest-ptrace: preload not built — skipping trap arm");
        return;
    }
    let dir = std::env::temp_dir().join(format!("literoot-guestptrace-trap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["bin", "lib64", "src"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let Some(bin) = build_guest(&dir.join("src")) else { return };
    std::fs::copy(&bin, dir.join("bin/setoptions")).unwrap();
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        let src = PathBuf::from(format!("/lib64/{lib}"));
        if src.exists() {
            std::fs::copy(&src, dir.join("lib64").join(lib)).unwrap();
        }
    }
    let root = dir.to_string_lossy().to_string();
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", "trap", "-r", &root, "/bin/setoptions"])
        .env("LITEROOT_PRELOAD", &preload);
    let out = run_bounded(cmd, "trap backend");
    let _ = std::fs::remove_dir_all(&dir);
    assert_fast_traceme_refusal(&out, "trap");
}
