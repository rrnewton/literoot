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
