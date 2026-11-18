//! `LITEROOT_STATS` / `LITEROOT_EXIT_RECORD` / `LITEROOT_CGROUP`: one JSON
//! line per run. Off by default; none of the variables reaches the guest.
//!
//! The trap and liteinst tests need the preload (as backend_smoke): they
//! panic unless it is built, or skip explicitly with
//! LITEROOT_ALLOW_SKIP_PRELOAD=1. The cgroup tests need a cgroup v2
//! directory delegated to this user, with no controller enabled in its
//! subtree, on the cgroup v2 file system mounted at /sys/fs/cgroup, named
//! by LITEROOT_TEST_CGROUP; they panic without it unless
//! LITEROOT_ALLOW_SKIP_CGROUP=1 skips them explicitly. A run refuses a
//! root whose subtree holds any process, so only one run per root at a
//! time: the cgroup tests take turns (one static mutex), and the test
//! runner itself must run outside LITEROOT_TEST_CGROUP.

#![cfg(feature = "tool")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

// Same resolution as backend_smoke.rs.
#[allow(dead_code)]
fn preload_or_skip() -> Option<PathBuf> {
    let preload = if let Ok(p) = std::env::var("LITEROOT_PRELOAD") {
        PathBuf::from(p)
    } else {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let from_target = std::env::var("CARGO_TARGET_DIR").ok().map(|td| {
            let td = PathBuf::from(td);
            let td = if td.is_absolute() { td } else { root.join(td) };
            td.join("release/libliteroot_preload.so")
        });
        match from_target {
            Some(cand) if cand.exists() => cand,
            _ => root.join("preload/target/release/libliteroot_preload.so"),
        }
    };
    if preload.exists() {
        return Some(preload);
    }
    if std::env::var("LITEROOT_ALLOW_SKIP_PRELOAD").as_deref() == Ok("1") {
        eprintln!("run_stats: preload not built — skipping (opt-in)");
        return None;
    }
    panic!(
        "run_stats: preload not built at {} — build it or set \
         LITEROOT_ALLOW_SKIP_PRELOAD=1 to skip explicitly",
        preload.display()
    );
}

/// The delegated cgroup directory for the cgroup tests.
#[allow(dead_code)]
fn cgroup_or_skip() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("LITEROOT_TEST_CGROUP").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    if std::env::var("LITEROOT_ALLOW_SKIP_CGROUP").as_deref() == Ok("1") {
        eprintln!("run_stats: no delegated cgroup — skipping (opt-in)");
        return None;
    }
    panic!(
        "run_stats: set LITEROOT_TEST_CGROUP to a delegated cgroup v2 directory, \
         or LITEROOT_ALLOW_SKIP_CGROUP=1 to skip explicitly"
    );
}

/// The cgroup tests share LITEROOT_TEST_CGROUP, where one run's
/// `lr-<pid>` makes another's admission refuse: they take turns.
#[allow(dead_code)]
static CGROUP_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// This test's turn at the delegated cgroup (a test that panicked while
/// holding it does not stop the next one).
#[allow(dead_code)]
fn cgroup_turn() -> std::sync::MutexGuard<'static, ()> {
    CGROUP_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A fresh directory under the test temp dir.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One launcher run: `literoot --refusal-log <dir>/refusal.log --backend
/// <backend> -r / <argv>` with the given variables (only these; the
/// three record variables are removed otherwise).
struct Run<'a> {
    backend: &'a str,
    vars: Vec<(&'a str, PathBuf)>,
    argv: &'a [&'a str],
}

impl Run<'_> {
    /// The exit status and the refusal log's lines. Output is not
    /// printed, so nothing from the environment can reach the test log.
    fn go(&self, dir: &Path) -> (i32, Vec<String>) {
        let (status, lines, _) = self.go_with_stderr(dir);
        (status, lines)
    }

    /// As `go`, plus literoot's stderr, for checks against fixed text only
    /// (never printed).
    fn go_with_stderr(&self, dir: &Path) -> (i32, Vec<String>, String) {
        let log = dir.join("refusal.log");
        let _ = std::fs::remove_file(&log);
        let mut cmd = Command::new(literoot_bin());
        cmd.arg("--refusal-log").arg(&log);
        cmd.args(["--backend", self.backend, "-r", "/"])
            .args(self.argv);
        for v in ["LITEROOT_STATS", "LITEROOT_EXIT_RECORD", "LITEROOT_CGROUP"] {
            cmd.env_remove(v);
        }
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn literoot");
        let lines = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (out.status.code().unwrap_or(-1), lines, stderr)
    }
}

fn preload_var(preload: Option<&Path>) -> Vec<(&'static str, PathBuf)> {
    preload
        .map(|p| vec![("LITEROOT_PRELOAD", p.to_owned())])
        .unwrap_or_default()
}

/// The single record in a stats file.
fn one_record(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("record file written");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one record per run");
    serde_json::from_str(lines[0]).expect("record is JSON")
}

fn count(record: &serde_json::Value, pointer: &str) -> u64 {
    record
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("{pointer} is not a count in the record"))
}

/// The pid of the log's single `begin` line, which is the record's pid.
fn begin_pid(log: &[String]) -> u64 {
    let pids: Vec<u64> = log
        .iter()
        .filter_map(|l| l.strip_prefix("literoot: begin ")?.parse().ok())
        .collect();
    assert_eq!(pids.len(), 1, "one begin line");
    pids[0]
}

fn assert_common(record: &serde_json::Value, backend: &str, mode: &str, log: &[String]) {
    assert_eq!(record["schema"], "literoot-stats-v1");
    assert_eq!(record["mode"], mode);
    assert_eq!(record["backend"], backend);
    assert_eq!(record["exit_code"], 0);
    assert_eq!(count(record, "/pid"), begin_pid(log));
    assert!(count(record, "/backend_wall_ns") > 0);
    for side in ["rusage_self", "rusage_children"] {
        for key in [
            "user_us",
            "sys_us",
            "maxrss_kb",
            "voluntary_ctxt_switches",
            "involuntary_ctxt_switches",
        ] {
            assert!(
                record[side][key].is_i64(),
                "{side}.{key} missing from the record"
            );
        }
    }
    assert!(log
        .iter()
        .any(|l| l.ends_with(" ok") && l.starts_with("literoot: end ")));
    if mode == "counting" {
        assert_eq!(count(record, "/dispatch/schema_version"), 1);
    }
}

#[cfg(feature = "run")]
const PTRACE_KEYS: [&str; 12] = [
    "tracees_started",
    "stop_events",
    "exited_tracees",
    "seccomp_stops",
    "signal_stops",
    "exec_stops",
    "fork_stops",
    "vfork_stops",
    "clone_stops",
    "vfork_done_stops",
    "injected_trap_stops",
    "internal_seccomp_stops",
];

/// Ptrace counts by kind, with a guest that forks twice and execs twice,
/// so swapped accessors of different kinds read wrong. (Two fields with
/// equal values, such as two that stay 0, cannot be told apart by any
/// guest.)
#[cfg(feature = "run")]
#[test]
fn ptrace_record_counts_stops_by_kind() {
    let dir = scratch("stats-ptrace");
    let stats = dir.join("stats.jsonl");
    let run = Run {
        backend: "ptrace",
        vars: vec![("LITEROOT_STATS", stats.clone())],
        argv: &["/bin/sh", "-c", "/bin/true; /bin/true; exit 0"],
    };
    let (status, log) = run.go(&dir);
    assert_eq!(status, 0);
    let record = one_record(&stats);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "ptrace", "counting", &log);
    let keys: Vec<&String> = record["ptrace"].as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 12, "exactly the 12 snapshot fields");
    for k in PTRACE_KEYS {
        count(&record, &format!("/ptrace/{k}"));
    }
    let stops = count(&record, "/ptrace/stop_events");
    let seccomp = count(&record, "/ptrace/seccomp_stops");
    assert!(seccomp > 0);
    assert!(stops >= seccomp, "every seccomp stop is a stop event");
    assert!(
        count(&record, "/ptrace/tracees_started") >= 3,
        "sh and two children"
    );
    assert!(count(&record, "/ptrace/exited_tracees") >= 3);
    assert!(
        count(&record, "/ptrace/exec_stops") >= 2,
        "two children exec /bin/true"
    );
    let forks = count(&record, "/ptrace/fork_stops")
        + count(&record, "/ptrace/vfork_stops")
        + count(&record, "/ptrace/clone_stops");
    assert!(forks >= 2, "sh creates two children");
    assert_eq!(
        count(&record, "/dispatch/counters/ptrace_seccomp_stops"),
        seccomp
    );
    assert_eq!(count(&record, "/dispatch/counters/signal_traps"), 0);
    assert_eq!(count(&record, "/dispatch/counters/patched_direct_calls"), 0);
    assert_eq!(record["cgroup"]["guest_cpu_state"], "UNAVAILABLE");
}

/// The exit-only record: no backend counting at all.
#[cfg(feature = "run")]
#[test]
fn exit_record_has_wall_and_rusage_only() {
    let dir = scratch("stats-exit");
    let rec = dir.join("exit.jsonl");
    let run = Run {
        backend: "ptrace",
        vars: vec![("LITEROOT_EXIT_RECORD", rec.clone())],
        argv: &["/bin/true"],
    };
    let (status, log) = run.go(&dir);
    assert_eq!(status, 0);
    let record = one_record(&rec);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "ptrace", "exit", &log);
    assert!(record["dispatch"].is_null());
    assert!(record["ptrace"].is_null());
    assert!(record["backend_detail"].is_null());
}

/// R1: a record that cannot be written is its own outcome: exit 5 and
/// `end <pid> error stats_record`, never a launcher refusal.
#[cfg(feature = "run")]
#[test]
fn unwritable_record_ends_with_its_own_status_and_token() {
    let dir = scratch("stats-unwritable");
    let run = Run {
        backend: "ptrace",
        vars: vec![(
            "LITEROOT_STATS",
            PathBuf::from("/nonexistent-literoot-dir/s.jsonl"),
        )],
        argv: &["/bin/true"],
    };
    let (status, log, stderr) = run.go_with_stderr(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(status, 5, "STATS_RECORD_EXIT");
    // Checked, not printed.
    assert!(
        stderr.contains("LITEROOT_STATS: cannot append"),
        "the record failure's fixed text is missing from stderr"
    );
    let pid = begin_pid(&log);
    assert!(
        log.contains(&format!("literoot: end {pid} error stats_record")),
        "{log:?}"
    );
    assert!(
        !log.iter().any(|l| l.starts_with("literoot: refused")),
        "{log:?}"
    );
}

/// None of the three variables reaches the guest, on any backend (a
/// status check, so no value is ever printed).
fn variables_never_reach_the_guest(backend: &str, preload: Option<&Path>) {
    let dir = scratch(&format!("stats-env-{backend}"));
    let mut vars = preload_var(preload);
    vars.push(("LITEROOT_STATS", dir.join("s.jsonl")));
    vars.push(("LITEROOT_EXIT_RECORD", dir.join("e.jsonl")));
    // Empty requests no cgroup, but a leaked empty value still shows.
    vars.push(("LITEROOT_CGROUP", PathBuf::new()));
    let probe = [
        "/bin/sh",
        "-c",
        "test -z \"${LITEROOT_STATS+x}${LITEROOT_EXIT_RECORD+x}${LITEROOT_CGROUP+x}\"",
    ];
    let run = Run {
        backend,
        vars,
        argv: &probe,
    };
    let (status, _) = run.go(&dir);
    assert_eq!(status, 0, "{backend}: a record variable reached the guest");
    assert_eq!(one_record(&dir.join("s.jsonl"))["exit_code"], 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(feature = "run")]
#[test]
fn variables_never_reach_the_guest_ptrace() {
    variables_never_reach_the_guest("ptrace", None);
}

/// The zero-ptrace trap route. `/bin/cat /dev/null` makes a subscribed
/// syscall (openat) after arming, so the positive count does not rest on
/// exit_group alone.
#[cfg(feature = "inguest-trap")]
#[test]
fn trap_record_has_no_ptrace_stops() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = scratch("stats-trap");
    let stats = dir.join("stats.jsonl");
    let mut vars = preload_var(Some(&preload));
    vars.push(("LITEROOT_STATS", stats.clone()));
    let run = Run {
        backend: "trap",
        vars,
        argv: &["/bin/cat", "/dev/null"],
    };
    let (status, log) = run.go(&dir);
    assert_eq!(status, 0);
    let record = one_record(&stats);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "trap", "counting", &log);
    assert!(record["ptrace"].is_null());
    assert_eq!(count(&record, "/dispatch/counters/ptrace_seccomp_stops"), 0);
    assert_eq!(count(&record, "/dispatch/counters/ptrace_sigtrap_stops"), 0);
    assert!(count(&record, "/dispatch/counters/signal_traps") > 0);
    variables_never_reach_the_guest("trap", Some(&preload));
}

/// Patched-site liteinst (x86_64 only today): no ptrace stops, and
/// deliveries by patched call or SIGSYS, with a subscribed syscall.
#[cfg(all(target_arch = "x86_64", feature = "in-guest"))]
#[test]
fn liteinst_record_has_no_ptrace_stops() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = scratch("stats-liteinst");
    let stats = dir.join("stats.jsonl");
    let mut vars = preload_var(Some(&preload));
    vars.push(("LITEROOT_STATS", stats.clone()));
    let run = Run {
        backend: "liteinst",
        vars,
        argv: &["/bin/cat", "/dev/null"],
    };
    let (status, log) = run.go(&dir);
    assert_eq!(status, 0);
    let record = one_record(&stats);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "liteinst", "counting", &log);
    assert!(record["ptrace"].is_null());
    assert_eq!(count(&record, "/dispatch/counters/ptrace_seccomp_stops"), 0);
    let delivered = count(&record, "/dispatch/counters/patched_direct_calls")
        + count(&record, "/dispatch/counters/signal_traps");
    assert!(delivered > 0);
    variables_never_reach_the_guest("liteinst", Some(&preload));
}

/// One run in the cgroup under `root` with an exit record: the status,
/// the record, and the refusal log. The run's cgroup must be gone after.
fn cgroup_run(
    backend: &str,
    preload: Option<&Path>,
    root: &Path,
    argv: &[&str],
) -> (i32, serde_json::Value, Vec<String>) {
    let dir = scratch(&format!("stats-cg-{backend}"));
    let rec = dir.join("exit.jsonl");
    let mut vars = preload_var(preload);
    vars.push(("LITEROOT_EXIT_RECORD", rec.clone()));
    vars.push(("LITEROOT_CGROUP", root.to_owned()));
    let run = Run {
        backend,
        vars,
        argv,
    };
    let (status, log) = run.go(&dir);
    let record = one_record(&rec);
    std::fs::remove_dir_all(&dir).unwrap();
    let pid = begin_pid(&log);
    assert!(
        !root.join(format!("lr-{pid}")).exists(),
        "the run's cgroup was removed"
    );
    (status, record, log)
}

fn int(record: &serde_json::Value, pointer: &str) -> i64 {
    record
        .pointer(pointer)
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| panic!("{pointer} is not an integer in the record"))
}

/// A COMPLETE split: its arithmetic holds, it captured the guest (the
/// CPU of the reaped children, a lower bound on the guest's, is at most
/// the interval's upper bound, and since `/bin/cat` leaves no orphan it is
/// no more than 1 ms under the lower bound), its interval
/// is narrow (two getrusage calls wide), and the launcher's samples are
/// real (it used CPU inside the cgroup, and its final SELF is at least
/// the last sample).
fn cgroup_split(backend: &str, preload: Option<&Path>, root: &Path) {
    let (status, record, log) = cgroup_run(backend, preload, root, &["/bin/cat", "/dev/null"]);
    assert_eq!(status, 0, "{log:?}");
    assert_common(&record, backend, "exit", &log);
    let cg = &record["cgroup"];
    assert_eq!(cg["guest_cpu_state"], "COMPLETE", "{cg}");
    assert_eq!(cg["procs_left"], 0);
    let usage = int(&record, "/cgroup/usage_usec");
    let lo = int(&record, "/cgroup/launcher_in_cgroup_us/0");
    let hi = int(&record, "/cgroup/launcher_in_cgroup_us/1");
    assert!(0 < lo && lo <= hi && hi <= usage, "{cg}");
    let (glo, ghi) = (
        int(&record, "/cgroup/guest_cpu_us/0"),
        int(&record, "/cgroup/guest_cpu_us/1"),
    );
    assert_eq!((glo, ghi), (usage - hi, usage - lo));
    assert!(ghi - glo <= 5_000, "a narrow interval: {cg}");
    let children = int(&record, "/cgroup/children_since_move_us");
    assert!(
        glo - 1_000 <= children && children <= ghi,
        "children within the guest interval: {cg}"
    );
    let d = int(&record, "/cgroup/self_at_read_us/1");
    let self_total = int(&record, "/rusage_self/user_us") + int(&record, "/rusage_self/sys_us");
    assert!(
        self_total >= d,
        "the final SELF is at least the last sample: {cg}"
    );
    // With the cgroup set, still nothing reaches the guest.
    let probe = [
        "/bin/sh",
        "-c",
        "test -z \"${LITEROOT_STATS+x}${LITEROOT_EXIT_RECORD+x}${LITEROOT_CGROUP+x}\"",
    ];
    let (status, _, log) = cgroup_run(backend, preload, root, &probe);
    assert_eq!(
        status, 0,
        "{backend}: a record variable reached the guest: {log:?}"
    );
}

/// A shell loop that uses some CPU and makes no syscall.
const BURN: &str = "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done";

/// A guest that moves itself out of the run's cgroup takes its later CPU
/// with it: never COMPLETE, and no guest number.
fn cgroup_escape_is_not_complete(backend: &str, preload: Option<&Path>, root: &Path) {
    let script = format!("echo $$ > {}/cgroup.procs && {BURN}", root.display());
    let (status, record, log) = cgroup_run(backend, preload, root, &["/bin/sh", "-c", &script]);
    assert_eq!(status, 0, "{log:?}");
    let cg = &record["cgroup"];
    assert_eq!(cg["guest_cpu_state"], "INCONSISTENT", "{cg}");
    assert!(cg["guest_cpu_us"].is_null());
}

/// A guest that moves into a child cgroup of its own stays measured
/// (cpu.stat is hierarchical), and cleanup removes the child too.
#[cfg(feature = "run")]
fn cgroup_descendant_is_measured(backend: &str, preload: Option<&Path>, root: &Path) {
    let script = format!(
        "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); \
         mkdir \"$cg/sub\" && echo $$ > \"$cg/sub/cgroup.procs\" && {BURN}"
    );
    let (status, record, log) = cgroup_run(backend, preload, root, &["/bin/sh", "-c", &script]);
    assert_eq!(status, 0, "{log:?}");
    let cg = &record["cgroup"];
    assert_eq!(cg["guest_cpu_state"], "COMPLETE", "{cg}");
    let children = int(&record, "/cgroup/children_since_move_us");
    assert!(children <= int(&record, "/cgroup/guest_cpu_us/1"), "{cg}");
    assert!(children >= 1_000, "the loop's CPU was reaped: {cg}");
}

/// A cgroup setup that fails refuses the run before the guest starts: the
/// stats status 5, the launcher token, and no trace of the guest.
#[cfg(feature = "run")]
fn refused_before_launch(vars: Vec<(&str, PathBuf)>, dir: &Path) {
    let marker = dir.join("guest-ran");
    let script = format!("echo ran > {}", marker.display());
    let run = Run {
        backend: "ptrace",
        vars,
        argv: &["/bin/sh", "-c", &script],
    };
    let (status, log) = run.go(dir);
    assert_eq!(status, 5, "{log:?}");
    assert!(
        log.contains(&"literoot: refused launcher stats_cgroup".to_owned()),
        "{log:?}"
    );
    assert!(!marker.exists(), "the guest did not start");
}

#[cfg(feature = "run")]
#[test]
fn ptrace_cgroup_split_and_refusals() {
    let Some(root) = cgroup_or_skip() else {
        return;
    };
    let _turn = cgroup_turn();
    cgroup_split("ptrace", None, &root);
    cgroup_escape_is_not_complete("ptrace", None, &root);
    cgroup_descendant_is_measured("ptrace", None, &root);
    let dir = scratch("stats-cg-refuse");
    // LITEROOT_CGROUP without a record.
    refused_before_launch(vec![("LITEROOT_CGROUP", root.clone())], &dir);
    // A writable directory that is not a cgroup.
    let plain = dir.join("plain");
    std::fs::create_dir(&plain).unwrap();
    refused_before_launch(
        vec![
            ("LITEROOT_EXIT_RECORD", dir.join("e.jsonl")),
            ("LITEROOT_CGROUP", plain.clone()),
        ],
        &dir,
    );
    assert_eq!(
        std::fs::read_dir(&plain).unwrap().count(),
        0,
        "nothing was created in it"
    );
    // A directory that does not exist.
    refused_before_launch(
        vec![
            ("LITEROOT_EXIT_RECORD", dir.join("e.jsonl")),
            (
                "LITEROOT_CGROUP",
                PathBuf::from("/nonexistent-literoot-cgroup"),
            ),
        ],
        &dir,
    );
    assert!(!dir.join("e.jsonl").exists(), "no record for a refused run");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(feature = "inguest-trap")]
#[test]
fn trap_cgroup_split() {
    let (Some(root), Some(preload)) = (cgroup_or_skip(), preload_or_skip()) else {
        return;
    };
    let _turn = cgroup_turn();
    cgroup_split("trap", Some(&preload), &root);
    cgroup_escape_is_not_complete("trap", Some(&preload), &root);
}
