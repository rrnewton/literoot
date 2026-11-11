//! The refusal side log (`--refusal-log <path>`) on the dynamic preload
//! route: plan revision 6, pin C5 (entry drain) and C2 (validity).
//!
//! The entry-drain witness: the guest makes one refused call (a SIGUSR1
//! handler), then one subscribed raw getuid, then blocks reading fd 0,
//! which the witness holds open. While the guest is blocked, the key
//! line must already be in the side log: the reporter drained at the
//! getuid callback, not only at exit. The witness then releases the
//! guest, which exits 7, and the whole log must be valid, with a
//! `begin`/`end ... ok` pair. It runs under each counted in-guest row
//! (liteinst and trap). The negative control, under each of them too, runs
//! `/bin/true`, which makes no refused call: its log is valid with no
//! refusal. The ptrace control runs the same guest: nothing is refused
//! there, and its log is valid with no refusal.

mod common;

use std::io::BufRead as _;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use common::fixture_or_skip;
use common::literoot_bin;
use common::resolve_preload;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The guest, built dynamic into a fresh scratch directory with a `logs`
/// directory beside it. `None` is a skip, never a pass.
fn scratch(label: &str) -> Option<(Scratch, PathBuf)> {
    let dir = std::env::temp_dir().join(format!(
        "literoot-refusal-log-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    let scratch = Scratch(dir);
    let guest = scratch.0.join("entry-drain");
    let built = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&guest)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guests/entry_drain.c"))
        .output()
        .expect("cc is required to build the entry-drain guest");
    if !fixture_or_skip(&built, "entry-drain guest") {
        return None;
    }
    Some((scratch, guest))
}

/// What one run showed: the side log as read while the guest was
/// blocked, the guest's stdout, its exit status, and the final log.
struct Run {
    while_blocked: String,
    stdout: Vec<String>,
    code: Option<i32>,
    log: PathBuf,
}

fn run(backend: &str, guest: &Path, log: &Path) -> Run {
    use std::os::unix::process::CommandExt as _;
    let marker = log.with_extension("blocked");
    let _ = std::fs::remove_file(&marker);
    let mut cmd = Command::new(literoot_bin());
    cmd.arg("--refusal-log")
        .arg(log)
        .args(["--backend", backend])
        .arg(guest)
        .arg(&marker)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if backend != "ptrace" {
        cmd.env("LITEROOT_PRELOAD", resolve_preload());
    }
    let mut child = cmd.spawn().expect("spawn literoot");
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut printed = Vec::new();
    // The guest creates the marker just before it blocks on fd 0. Its
    // stdout cannot say so: the liteinst launcher relays the guest's
    // stdout only after the guest exits.
    let blocked = loop {
        if marker.exists() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // The guest is blocked reading fd 0: read the log now, then release it.
    let while_blocked = std::fs::read_to_string(log).unwrap_or_default();
    drop(stdin);
    let code = loop {
        if let Some(status) = child.try_wait().expect("try_wait literoot") {
            break status.code();
        }
        if Instant::now() >= deadline {
            extern "C" {
                fn kill(pid: i32, sig: i32) -> i32;
            }
            unsafe {
                kill(-(child.id() as i32), 9);
            }
            let _ = child.wait();
            panic!("{backend}: literoot did not finish within 10 s; stdout {printed:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // The reader thread ends at EOF, after literoot exits.
    printed.extend(received.iter());
    assert!(
        blocked,
        "{backend}: the guest never reached its blocking read: {printed:?}"
    );
    Run {
        while_blocked,
        stdout: printed,
        code,
        log: log.to_owned(),
    }
}

/// `literoot --check-refusal-log`: Ok(refusal lines) for a valid log.
fn check(log: &Path) -> Result<Vec<String>, String> {
    let out = Command::new(literoot_bin())
        .arg("--check-refusal-log")
        .arg(log)
        .output()
        .expect("run literoot --check-refusal-log");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn require_preload() {
    assert!(
        resolve_preload().exists(),
        "this test requires the preload built: \
         cargo build --release --manifest-path preload/Cargo.toml"
    );
}

#[test]
fn the_entry_drain_names_a_refusal_while_the_guest_runs() {
    entry_drain("liteinst");
}

#[test]
fn the_entry_drain_names_a_refusal_while_the_guest_runs_under_trap() {
    entry_drain("trap");
}

fn entry_drain(backend: &str) {
    require_preload();
    let Some((scratch, guest)) = scratch(&format!("entry-{backend}")) else {
        return;
    };
    let run = run(backend, &guest, &scratch.0.join("logs/side"));
    let key = "literoot: refused signal_action 10";
    assert!(
        run.while_blocked.lines().any(|l| l == key),
        "while the guest was blocked the side log lacked {key:?}: {:?}",
        run.while_blocked
    );
    assert!(
        !run.while_blocked.contains(" end "),
        "the launcher ended its log while the guest was still blocked: {:?}",
        run.while_blocked
    );
    assert_eq!(
        run.code,
        Some(7),
        "the guest continued: stdout {:?}",
        run.stdout
    );
    assert!(
        run.stdout
            .iter()
            .any(|l| l.starts_with("sigaction-refused errno=")),
        "{:?}",
        run.stdout
    );
    let refused = check(&run.log).expect("the final side log is valid");
    assert!(
        refused.iter().any(|l| l == "refused signal_action 10"),
        "{refused:?}"
    );
}

/// C5's negative control, per counted in-guest row: a guest that makes no
/// refused call leaves a valid log with no `refused` line, so an
/// implementation that writes every key every time is caught.
fn no_refusal(backend: &str) {
    require_preload();
    let Some((scratch, _guest)) = scratch(&format!("none-{backend}")) else {
        return;
    };
    let log = scratch.0.join("logs/side");
    let status = Command::new(literoot_bin())
        .arg("--refusal-log")
        .arg(&log)
        .args(["--backend", backend, "/bin/true"])
        .env("LITEROOT_PRELOAD", resolve_preload())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    assert_eq!(status.code(), Some(0), "{backend}: /bin/true");
    assert_eq!(check(&log), Ok(Vec::new()), "{backend}");
}

#[test]
fn a_run_with_no_refused_call_leaves_a_valid_log_without_refusals() {
    no_refusal("liteinst");
}

#[test]
fn a_run_with_no_refused_call_leaves_a_valid_log_without_refusals_under_trap() {
    no_refusal("trap");
}

#[test]
fn the_ptrace_control_refuses_nothing_and_its_log_is_valid() {
    let Some((scratch, guest)) = scratch("ptrace") else {
        return;
    };
    let run = run("ptrace", &guest, &scratch.0.join("logs/side"));
    assert_eq!(run.code, Some(7), "stdout {:?}", run.stdout);
    assert_eq!(run.stdout, ["sigaction-ok", "blocked"]);
    assert_eq!(check(&run.log), Ok(Vec::new()));
    let text = std::fs::read_to_string(&run.log).unwrap();
    assert!(
        text.lines().any(|l| l == "literoot: route ptrace"),
        "{text:?}"
    );
}

/// C1: a second `--refusal-log` in one argv is refused by name in the
/// first log, and the second path is never created; C4: `-q` is a keyed
/// launcher refusal. Both logs stay valid, so the refusal is counted.
#[test]
fn launcher_refusals_are_keyed_in_the_first_log() {
    let Some((scratch, _guest)) = scratch("launcher") else {
        return;
    };
    let first = scratch.0.join("logs/first");
    let second = scratch.0.join("logs/second");
    let status = Command::new(literoot_bin())
        .arg("--refusal-log")
        .arg(&first)
        .arg("--refusal-log")
        .arg(&second)
        .arg("/bin/true")
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    assert_eq!(status.code(), Some(125));
    assert_eq!(
        check(&first),
        Ok(vec!["refused launcher refusal_log_repeated".to_owned()])
    );
    assert!(!second.exists(), "the second log was created");

    let q = scratch.0.join("logs/q");
    let status = Command::new(literoot_bin())
        .arg("--refusal-log")
        .arg(&q)
        .args(["-q", "qemu-x86_64", "/bin/true"])
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    assert_eq!(status.code(), Some(125));
    assert_eq!(
        check(&q),
        Ok(vec!["refused launcher qemu_passthrough".to_owned()])
    );
}

/// C1: a nested literoot (a guest running literoot with the same option)
/// opens the same path and writes its own `begin`/`end` pair under its own
/// pid; the log stays valid with both pairs matched.
#[test]
fn a_nested_literoot_writes_its_own_pair() {
    let Some((scratch, _guest)) = scratch("nested") else {
        return;
    };
    let log = scratch.0.join("logs/side");
    let _ = Command::new(literoot_bin())
        .arg("--refusal-log")
        .arg(&log)
        .args(["--backend", "ptrace"])
        .arg(literoot_bin())
        .arg("--refusal-log")
        .arg(&log)
        .args(["--backend", "ptrace", "/bin/true"])
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    let text = std::fs::read_to_string(&log).unwrap();
    let begins: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("literoot: begin "))
        .collect();
    assert_eq!(begins.len(), 2, "{text:?}");
    assert_ne!(
        begins[0], begins[1],
        "both pairs carry the same pid: {text:?}"
    );
    assert!(check(&log).is_ok(), "{text:?}");
}

/// The `kompat_auxv` key (coord7's ruling on the C3 grammar, 2026-11-10):
/// under `-k`, the in-guest backends skip proot kompat's auxv adjustment,
/// which the ptrace backend applies at the exec stop, and say so exactly
/// once per exec; ptrace writes no such line, and nor does a run without
/// `-k`.
fn kompat_lines(backend: &str, release: Option<&str>) -> usize {
    let Some((scratch, _guest)) = scratch(&format!("kompat-{backend}-{}", release.is_some())) else {
        return usize::MAX;
    };
    let log = scratch.0.join("logs/side");
    let mut cmd = Command::new(literoot_bin());
    cmd.arg("--refusal-log").arg(&log).args(["--backend", backend]);
    if let Some(release) = release {
        cmd.args(["-k", release]);
    }
    let status = cmd
        .arg("/bin/true")
        .env("LITEROOT_PRELOAD", resolve_preload())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    assert_eq!(status.code(), Some(0), "{backend} -k {release:?}: /bin/true");
    let refused = check(&log).expect("the side log is valid");
    refused
        .iter()
        .filter(|l| *l == "refused guest kompat_auxv")
        .count()
}

#[test]
fn kompat_auxv_is_keyed_once_in_guest_and_never_under_ptrace_or_without_k() {
    require_preload();
    for backend in ["liteinst", "trap"] {
        assert_eq!(kompat_lines(backend, Some("5.4.0")), 1, "{backend} with -k");
        assert_eq!(kompat_lines(backend, None), 0, "{backend} without -k");
    }
    assert_eq!(kompat_lines("ptrace", Some("5.4.0")), 0, "ptrace with -k");
}

/// The number of `refused <key>` lines a `/bin/true` run under `options`
/// leaves in its valid side log.
fn key_lines(label: &str, backend: &str, options: &[&str], key: &str) -> usize {
    let Some((scratch, _guest)) = scratch(&format!("{label}-{backend}")) else {
        return usize::MAX;
    };
    let log = scratch.0.join("logs/side");
    let status = Command::new(literoot_bin())
        .arg("--refusal-log")
        .arg(&log)
        .args(["--backend", backend])
        .args(options)
        .arg("/bin/true")
        .env("LITEROOT_PRELOAD", resolve_preload())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    assert_eq!(status.code(), Some(0), "{backend} {options:?}: /bin/true");
    let refused = check(&log).expect("the side log is valid");
    refused.iter().filter(|l| *l == key).count()
}

/// The `fake_id_auxv` key (coord7's ruling on the C3 grammar, 2026-11-10,
/// review of g2 38e83d31, finding 1): under `-0` or `-i`, the in-guest
/// backends skip the fake-identity auxv patch that the ptrace backend
/// applies at the exec stop, and say so exactly once per exec; ptrace
/// writes no such line, and nor does a run without a fake identity.
#[test]
fn fake_id_auxv_is_keyed_once_in_guest_and_never_under_ptrace_or_without_fake_ids() {
    require_preload();
    let key = "refused guest fake_id_auxv";
    for backend in ["liteinst", "trap"] {
        assert_eq!(key_lines("fake0", backend, &["-0"], key), 1, "{backend} -0");
        assert_eq!(key_lines("fakei", backend, &["-i", "123:456"], key), 1, "{backend} -i");
        assert_eq!(key_lines("fakenone", backend, &[], key), 0, "{backend} without");
    }
    assert_eq!(key_lines("fake0", "ptrace", &["-0"], key), 0, "ptrace -0");
    assert_eq!(key_lines("fakei", "ptrace", &["-i", "123:456"], key), 0, "ptrace -i");
}

/// TRACEME, then a self-SIGSTOP, then exit 0: the shape the in-guest Tool
/// refuses (guest ptrace, EPERM) and then swallows (the self-stop).
const SELF_STOP_C: &str = r#"
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return 3;
    return WEXITSTATUS(status);
}
"#;

/// The `guest ptrace` and `guest self_stop` keys reach the side log on the
/// in-guest backends (review of g2 38e83d31, finding 2). There is no ptrace
/// arm: there the self-SIGSTOP really stops the child, as natively.
#[test]
fn guest_ptrace_and_self_stop_are_keyed_in_guest() {
    require_preload();
    let Some((scratch, _guest)) = scratch("selfstop") else {
        return;
    };
    let src = scratch.0.join("self_stop.c");
    let bin = scratch.0.join("self-stop");
    std::fs::write(&src, SELF_STOP_C).unwrap();
    let built = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc is required to build the self-stop guest");
    if !fixture_or_skip(&built, "self-stop guest") {
        return;
    }
    for backend in ["liteinst", "trap"] {
        let log = scratch.0.join(format!("logs/{backend}"));
        let status = Command::new(literoot_bin())
            .arg("--refusal-log")
            .arg(&log)
            .args(["--backend", backend])
            .arg(&bin)
            .env("LITEROOT_PRELOAD", resolve_preload())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run literoot");
        assert_eq!(status.code(), Some(0), "{backend}: the guest exits 0");
        let refused = check(&log).expect("the side log is valid");
        let has = |key: &str| refused.iter().any(|l| l == key);
        assert!(has("refused guest ptrace"), "{backend}: {refused:?}");
        assert!(has("refused guest self_stop"), "{backend}: {refused:?}");
    }
}

/// C4's closed list (main.rs `CliError::ProotAlsoRaises`) and the not-runnable
/// exemption: these launcher errors, which real proot also raises for the
/// same argv, leave a valid log with no `refused` line; any other launcher
/// error is keyed, here `launcher other` (review of g2 38e83d31, finding 3).
#[test]
fn only_the_closed_list_and_not_runnable_commands_go_unkeyed() {
    let Some((scratch, _guest)) = scratch("closed") else {
        return;
    };
    let run = |label: &str, args: &[&str]| -> (Option<i32>, Result<Vec<String>, String>) {
        let log = scratch.0.join(format!("logs/{label}"));
        let status = Command::new(literoot_bin())
            .arg("--refusal-log")
            .arg(&log)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run literoot");
        (status.code(), check(&log))
    };
    let unkeyed: &[(&str, &[&str])] = &[
        ("v-without-level", &["-v"]),
        ("rootfs-missing", &["-r", "/nonexistent-literoot-rootfs", "/bin/true"]),
        ("bind-over-root", &["-r", "/", "-b", "/etc:/", "/bin/true"]),
        ("command-missing", &["/no/such/literoot-command"]),
        ("command-is-a-directory", &["/etc"]),
    ];
    for (label, args) in unkeyed {
        assert_eq!(run(label, args), (Some(125), Ok(Vec::new())), "{label}: {args:?}");
    }
    assert_eq!(
        run("bogus-option", &["--bogus", "/bin/true"]),
        (Some(125), Ok(vec!["refused launcher other".to_owned()]))
    );
}

const EXECVEAT_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    char *argv[] = {"true", 0};
    char *envp[] = {0};
    syscall(SYS_execveat, AT_FDCWD, "/bin/true", argv, envp, 0);
    return errno == EOPNOTSUPP ? 95 : 3;
}
"#;

/// A raw execveat is keyed `refused exec` on the in-guest backends, and the
/// guest continues past it with EOPNOTSUPP (review of g2 38e83d31 by
/// rev5338-cx, finding P1-1: unsubscribed, the in-guest runtime refused it
/// with no record). The ptrace control execs `/bin/true` and refuses nothing.
#[test]
fn a_raw_execveat_is_keyed_in_guest_and_runs_under_ptrace() {
    require_preload();
    let Some((scratch, _guest)) = scratch("execveat") else {
        return;
    };
    let src = scratch.0.join("execveat.c");
    let bin = scratch.0.join("execveat");
    std::fs::write(&src, EXECVEAT_C).unwrap();
    let built = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc is required to build the execveat guest");
    if !fixture_or_skip(&built, "execveat guest") {
        return;
    }
    for (backend, code, keyed) in [("liteinst", 95, true), ("trap", 95, true), ("ptrace", 0, false)] {
        let log = scratch.0.join(format!("logs/{backend}"));
        let status = Command::new(literoot_bin())
            .arg("--refusal-log")
            .arg(&log)
            .args(["--backend", backend])
            .arg(&bin)
            .env("LITEROOT_PRELOAD", resolve_preload())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run literoot");
        assert_eq!(status.code(), Some(code), "{backend}");
        let refused = check(&log).expect("the side log is valid");
        let want: &[&str] = if keyed { &["refused exec"] } else { &[] };
        assert_eq!(refused, want, "{backend}");
    }
}

/// A preload that predates the side log runs the guest but reports nothing:
/// the pin parent 2dbd5c52 installs the bare Tool under the same Reverie
/// pin, configuration and selector. The launcher must end its log
/// `error reporter` and say why on stderr, so no test name counts a run
/// whose refusals could not be seen (review of g2 38e83d31 by rev5338-cx,
/// finding P1-2). `LITEROOT_STALE_PRELOAD` names such a preload; unset,
/// this is a skip, never a pass, and under LITEROOT_REQUIRE_FIXTURES a
/// failure.
#[test]
fn a_preload_without_the_reporter_ends_the_log_in_error() {
    let Some(stale) = std::env::var_os("LITEROOT_STALE_PRELOAD") else {
        assert!(
            std::env::var_os("LITEROOT_REQUIRE_FIXTURES").is_none(),
            "LITEROOT_STALE_PRELOAD is unset under LITEROOT_REQUIRE_FIXTURES"
        );
        eprintln!("stale preload: SKIP (not a pass): LITEROOT_STALE_PRELOAD is unset");
        return;
    };
    let Some((scratch, _guest)) = scratch("stale") else {
        return;
    };
    for backend in ["liteinst", "trap"] {
        let log = scratch.0.join(format!("logs/{backend}"));
        let out = Command::new(literoot_bin())
            .arg("--refusal-log")
            .arg(&log)
            .args(["--backend", backend, "/bin/true"])
            .env("LITEROOT_PRELOAD", &stale)
            .stdin(Stdio::null())
            .output()
            .expect("run literoot");
        assert_eq!(out.status.code(), Some(0), "{backend}: the guest still runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("sent no refusal report"), "{backend}: {stderr}");
        let invalid = check(&log).expect_err("the side log must not be valid");
        assert!(invalid.contains("error reporter"), "{backend}: {invalid}");
    }
}

/// An unwritable `PROOT_TMP_DIR` is a launcher refusal outside C4's closed
/// list, so it is keyed `launcher other` (review of g2 38e83d31 by
/// rev5338-cx, finding P2-5); the exit status stays proot's 125.
#[test]
fn an_unwritable_proot_tmp_dir_is_keyed() {
    let Some((scratch, _guest)) = scratch("tmpdir") else {
        return;
    };
    let log = scratch.0.join("logs/side");
    let status = Command::new(literoot_bin())
        .arg("--refusal-log")
        .arg(&log)
        .arg("/bin/true")
        .env("PROOT_TMP_DIR", "/nonexistent-literoot-tmp-dir")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run literoot");
    assert_eq!(status.code(), Some(125));
    assert_eq!(check(&log), Ok(vec!["refused launcher other".to_owned()]));
}

/// C1: a failed side-log write exits nonzero, including on the help and
/// version exits, which leave from argument parsing (review of g2 38e83d31
/// by rev5338-cx, P3). Every write to /dev/full fails.
#[test]
fn a_failed_log_write_exits_nonzero_from_help_and_version_too() {
    for args in [&["--help"][..], &["--version"], &["-r", "/", "/bin/true"]] {
        let out = Command::new(literoot_bin())
            .args(["--refusal-log", "/dev/full"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run literoot");
        assert_eq!(out.status.code(), Some(3), "{args:?}: {out:?}");
    }
}

/// Loaded into the literoot launcher (not the guest): `statx` fails with EIO
/// for any path holding the marker, and goes to libc's for every other path.
/// Rust's std calls `statx` through libc so that LD_PRELOAD can interpose it.
const STATX_EIO_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *buf) {
    static int (*real)(int, const char *, int, unsigned int, struct statx *);
    if (path && strstr(path, "literoot-eio-marker")) {
        errno = EIO;
        return -1;
    }
    if (!real) real = (int (*)(int, const char *, int, unsigned int, struct statx *))dlsym(RTLD_NEXT, "statx");
    return real(dirfd, path, flags, mask, buf);
}
"#;

/// An unexpected error while looking up the guest command is a keyed
/// launcher refusal, through the PATH search as on the command path; a
/// candidate that is simply missing stays unkeyed, as real proot also fails
/// there (review of g2 98d28848 by rev5338-cx, F2). EIO comes from a statx
/// shim in the launcher, so the witness runs through the real search,
/// caller and log finalization.
#[test]
fn an_unexpected_command_lookup_error_is_keyed_on_path_search_and_command_path() {
    let Some((scratch, _guest)) = scratch("lookup-eio") else {
        return;
    };
    let src = scratch.0.join("statx_eio.c");
    let shim = scratch.0.join("statx_eio.so");
    std::fs::write(&src, STATX_EIO_C).unwrap();
    let built = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&shim)
        .arg(&src)
        .arg("-ldl")
        .output()
        .expect("cc is required to build the statx shim");
    if !fixture_or_skip(&built, "statx shim") {
        return;
    }
    let run = |label: &str, path: &str, command: &[&str]| -> (Option<i32>, Result<Vec<String>, String>, String) {
        let log = scratch.0.join(format!("logs/{label}"));
        let out = Command::new(literoot_bin())
            .arg("--refusal-log")
            .arg(&log)
            .args(command)
            .env("PATH", path)
            .env("LD_PRELOAD", &shim)
            .stdin(Stdio::null())
            .output()
            .expect("run literoot");
        (out.status.code(), check(&log), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let keyed = Ok(vec!["refused launcher other".to_owned()]);
    let (code, refused, stderr) = run("path-eio", "/literoot-eio-marker", &["literoot-no-such-prog"]);
    assert_eq!((code, &refused), (Some(125), &keyed), "PATH search: {stderr}");
    assert!(stderr.contains("Input/output error"), "{stderr}");
    let (code, refused, stderr) = run("path-missing", "/nonexistent-literoot-dir", &["literoot-no-such-prog"]);
    assert_eq!((code, refused), (Some(125), Ok(Vec::new())), "missing on PATH: {stderr}");
    let (code, refused, stderr) = run("command-eio", "/usr/bin:/bin", &["/literoot-eio-marker/prog"]);
    assert_eq!((code, &refused), (Some(125), &keyed), "command path: {stderr}");
    // The key follows where the error came from, not its text: command names
    // that spell the start of a closed-list argument error are still keyed
    // (review of g2 8b480bd0 by rev-g2d2-cx; a text match on
    // "literoot: rootfs " exempted the first).
    for (label, path, command) in [
        ("named-rootfs-path", "/literoot-eio-marker", &["rootfs helper"][..]),
        ("named-rootfs-command", "/usr/bin:/bin", &["rootfs helper/../literoot-eio-marker"][..]),
        ("named-v-path", "/literoot-eio-marker", &["--", "-v requires a level argument"][..]),
    ] {
        let (code, refused, stderr) = run(label, path, command);
        assert_eq!((code, &refused), (Some(125), &keyed), "{label}: {stderr}");
        assert!(stderr.contains("Input/output error"), "{label}: {stderr}");
    }
}
