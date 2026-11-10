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
//! refuses guest ptrace on in-guest backends (EPERM):
//! TRACEME fails in the child, the parent reports it, and
//! both exit promptly. On the ptrace backend guest
//! ptrace passes through to the kernel (TRACEME still
//! gets EPERM there from literoot's own tracer slot, but
//! outside-pid operations are kernel-served — pinned by
//! the scope tests below).
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

// Resolution follows tool.rs's convention: $LITEROOT_PRELOAD wins,
// then $CARGO_TARGET_DIR/release, then the preload-local target.
fn resolve_preload() -> PathBuf {
    if let Ok(p) = std::env::var("LITEROOT_PRELOAD") {
        return PathBuf::from(p);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        let td = PathBuf::from(td);
        let td = if td.is_absolute() { td } else { root.join(td) };
        let cand = td.join("release/libliteroot_preload.so");
        if cand.exists() {
            return cand;
        }
    }
    root.join("preload/target/release/libliteroot_preload.so")
}

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

const GUEST_C: &str = r#"
#include <errno.h>
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
    case 0: {
        /* Ignore the TRACEME result and proceed to the
           self-stop regardless (upstream gdb-ptrace-test
           shape). This is the guest that hung before the
           self-stop swallow: with TRACEME refused it would
           stop untraced with nobody to continue it. No
           intercepted syscall may run between ptrace and
           kill (getpid inside kill() is unsubscribed and
           does not clear the swallow), so errno is saved
           across the kill and reported after. */
        status = ptrace(PTRACE_TRACEME, 0, 0, 0);
        int traceme_errno = errno;
        kill(getpid(), SIGSTOP);
        if (status < 0) {
            errno = traceme_errno;
            perror("ptrace(PTRACE_TRACEME)");
        }
        exit(EXIT_SUCCESS);
    }
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
    build_guest_src(dir, GUEST_C, "setoptions")
}

fn build_guest_src(dir: &std::path::Path, src: &str, name: &str) -> Option<PathBuf> {
    std::fs::write(dir.join(format!("{name}.c")), src).unwrap();
    let bin = dir.join(name);
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(dir.join(format!("{name}.c")))
        .output()
        .expect("cc is required to build the guest");
    if !cc.status.success() {
        eprintln!("guest-ptrace: cc unavailable — skipping: {cc:?}");
        return None;
    }
    Some(bin)
}

/// Scope probe: ptrace on a pid that cannot exist. The
/// kernel answers ESRCH; a Tool that refuses guest ptrace
/// answers EPERM. Exit codes pin which one served it:
/// 42 = ESRCH (kernel passthrough), 43 = EPERM (refused).
const SCOPE_GUEST_C: &str = r#"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
int main(void) {
    errno = 0;
    long r = ptrace(PTRACE_ATTACH, INT_MAX, 0, 0);
    int e = errno;
    if (r == 0) return 44;
    errno = e;
    perror("ptrace(PTRACE_ATTACH)");
    if (e == ESRCH) return 42;
    if (e == EPERM) return 43;
    return 44;
}
"#;

/// Run a guest binary under the trap backend in a scratch
/// rootfs. `None` (with a loud notice, or a panic when
/// LITEROOT_REQUIRE_PRELOAD is set) when the preload has
/// not been built: in that case the trap arm did NOT run
/// and must not be read as a pass of it. Note the default
/// build's "trap" backend is the liteinst preload with
/// site patching off; the TrapHost flavour shares the
/// same RootfsTool refusal and is covered by the row
/// binaries in the lane evidence.
fn run_trap_guest(src_bin: &std::path::Path, guest_name: &str) -> Option<Output> {
    run_trap_guest_with(src_bin, guest_name, &[], &[])
}

fn run_trap_guest_with(
    src_bin: &std::path::Path,
    guest_name: &str,
    launcher_args: &[&str],
    envs: &[(&str, &str)],
) -> Option<Output> {
    let preload = resolve_preload();
    if !preload.exists() {
        assert!(
            std::env::var_os("LITEROOT_REQUIRE_PRELOAD").is_none(),
            "guest-ptrace: LITEROOT_REQUIRE_PRELOAD is set but the preload is not built"
        );
        eprintln!("guest-ptrace: SKIP (not a pass): preload not built, trap arm not run");
        return None;
    }
    let dir = std::env::temp_dir()
        .join(format!("literoot-guestptrace-trap-{}-{guest_name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["bin", "lib64"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::copy(src_bin, dir.join("bin").join(guest_name)).unwrap();
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        let src = PathBuf::from(format!("/lib64/{lib}"));
        if src.exists() {
            std::fs::copy(&src, dir.join("lib64").join(lib)).unwrap();
        }
    }
    let root = dir.to_string_lossy().to_string();
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", "trap", "-r", &root])
        .args(launcher_args)
        .arg(format!("/bin/{guest_name}"))
        .envs(envs.iter().copied())
        .env("LITEROOT_PRELOAD", &preload);
    let out = run_bounded(cmd, "trap backend");
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
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
    let dir = std::env::temp_dir().join(format!("literoot-guestptrace-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(bin) = build_guest(&dir) else { return };
    let out = run_trap_guest(&bin, "setoptions");
    let _ = std::fs::remove_dir_all(&dir);
    let Some(out) = out else { return };
    assert_fast_traceme_refusal(&out, "trap");
}

/// Scope pin, ptrace backend: guest ptrace passes through
/// to the kernel, so ATTACH on a pid that cannot exist
/// gets the kernel's ESRCH (guest exit 42), not a Tool
/// EPERM. Refusing every request on this backend (the
/// pre-koe10 behaviour) fails this test.
#[test]
fn guest_ptrace_scope_ptrace_backend_kernel_served() {
    let dir = std::env::temp_dir().join(format!("literoot-guestptrace-scope-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(bin) = build_guest_src(&dir, SCOPE_GUEST_C, "scope") else { return };
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", "ptrace"]).arg(&bin);
    let out = run_bounded(cmd, "ptrace backend scope");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(42),
        "ptrace backend must pass guest ptrace to the kernel (ESRCH): {out:?}"
    );
}

/// Scope pin, trap backend: every guest ptrace request is
/// refused by the Tool with EPERM (guest exit 43), not
/// just TRACEME. Refusing only TRACEME (mutant m4) lets
/// the kernel answer ESRCH here and fails this test.
#[test]
fn guest_ptrace_scope_trap_backend_refused() {
    let dir = std::env::temp_dir().join(format!("literoot-guestptrace-scope-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(bin) = build_guest_src(&dir, SCOPE_GUEST_C, "scope") else { return };
    let out = run_trap_guest(&bin, "scope");
    let _ = std::fs::remove_dir_all(&dir);
    let Some(out) = out else { return };
    assert_eq!(
        out.status.code(),
        Some(43),
        "trap backend must refuse every guest ptrace request (EPERM): {out:?}"
    );
}

/// Swallow-window guest: child ignores the TRACEME
/// result, runs an *intercepted* syscall (getuid is
/// subscribed), then self-SIGSTOPs. The parent
/// waitpid(WUNTRACED) must observe the stop: the swallow
/// armed by the refused TRACEME was cleared by the
/// getuid dispatch. Exit 0 = stop honoured; exit 1 =
/// child exited without stopping (stop swallowed).
const GETUID_BETWEEN_GUEST_C: &str = r#"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        (void)ptrace(PTRACE_TRACEME, 0, 0, 0);
        (void)getuid();
        kill(getpid(), SIGSTOP);
        _exit(42);
    }
    int status;
    pid_t w = waitpid(pid, &status, WUNTRACED);
    if (w < 0) { perror("waitpid"); return 1; }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        fprintf(stderr, "STOP-HONOURED\n");
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        return 0;
    }
    fprintf(stderr, "STOP-SWALLOWED status=%d\n", status);
    return 1;
}
"#;

/// The self-SIGSTOP swallow must last only until the next
/// intercepted syscall or exec. With an intercepted
/// getuid() between the refused TRACEME and the self-stop,
/// the stop must be honoured. The persistent window
/// (mutant m7: swallow armed until it fires) swallows
/// this stop, the child exits 42, and this test fails.
#[test]
fn guest_ptrace_swallow_cleared_by_intercepted_syscall() {
    let dir = std::env::temp_dir()
        .join(format!("literoot-guestptrace-between-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(bin) = build_guest_src(&dir, GETUID_BETWEEN_GUEST_C, "between") else { return };
    let out = run_trap_guest(&bin, "between");
    let _ = std::fs::remove_dir_all(&dir);
    let Some(out) = out else { return };
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stderr.contains("STOP-HONOURED"),
        "self-stop after an intercepted syscall must be honoured, not swallowed: {out:?}"
    );
}

/// Gate pin: in-guest kompat must not execute because there
/// post-exec is not at the exec stop. Output alone cannot
/// catch an accidentally open gate on this host, so assert
/// the production debug line.
#[test]
fn kompat_auxv_skipped_in_guest_under_trap() {
    let true_bin = PathBuf::from("/bin/true");
    let Some(out) = run_trap_guest_with(
        &true_bin,
        "true",
        &["-k", "6.6.6"],
        &[("LITEROOT_DEBUG", "1")],
    ) else {
        return;
    };
    assert!(out.status.success(), "trap /bin/true must run: {out:?}");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(
        text.contains("literoot-tool: kompat auxv skipped: post-exec not at exec stop"),
        "in-guest kompat gate must report skipped post-exec handling: {text:?}"
    );
}
