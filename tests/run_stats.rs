//! `LITEROOT_STATS` / `LITEROOT_EXIT_RECORD` / `LITEROOT_CGROUP`: one JSON
//! line per run. Off by default; none of the variables reaches the guest.
//!
//! The trap and liteinst tests need the preload (as backend_smoke): they
//! panic unless it is built, or skip explicitly with
//! LITEROOT_ALLOW_SKIP_PRELOAD=1. The cgroup tests need a cgroup v2
//! directory delegated to this user, named by LITEROOT_TEST_CGROUP; they
//! panic without it unless LITEROOT_ALLOW_SKIP_CGROUP=1 skips them
//! explicitly.

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
        cmd.args(["--backend", self.backend, "-r", "/"]).args(self.argv);
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
            assert!(record[side][key].is_i64(), "{side}.{key} missing from the record");
        }
    }
    assert!(log.iter().any(|l| l.ends_with(" ok") && l.starts_with("literoot: end ")));
}

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
    assert!(count(&record, "/ptrace/tracees_started") >= 3, "sh and two children");
    assert!(count(&record, "/ptrace/exited_tracees") >= 3);
    assert!(count(&record, "/ptrace/exec_stops") >= 2, "two children exec /bin/true");
    let forks = count(&record, "/ptrace/fork_stops")
        + count(&record, "/ptrace/vfork_stops")
        + count(&record, "/ptrace/clone_stops");
    assert!(forks >= 2, "sh creates two children");
    assert_eq!(count(&record, "/dispatch/counters/ptrace_seccomp_stops"), seccomp);
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
    assert!(log.contains(&format!("literoot: end {pid} error stats_record")), "{log:?}");
    assert!(!log.iter().any(|l| l.starts_with("literoot: refused")), "{log:?}");
}

/// None of the three variables reaches the guest, on any backend (a
/// status check, so no value is ever printed).
fn variables_never_reach_the_guest(backend: &str, preload: Option<&Path>) {
    let dir = scratch(&format!("stats-env-{backend}"));
    let mut vars = preload_var(preload);
    vars.push(("LITEROOT_STATS", dir.join("s.jsonl")));
    vars.push(("LITEROOT_EXIT_RECORD", dir.join("e.jsonl")));
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

/// The run's own cgroup: a COMPLETE split whose arithmetic holds, and the
/// cgroup is gone afterwards.
fn cgroup_split(backend: &str, preload: Option<&Path>, root: &Path) {
    let dir = scratch(&format!("stats-cg-{backend}"));
    let rec = dir.join("exit.jsonl");
    let mut vars = preload_var(preload);
    vars.push(("LITEROOT_EXIT_RECORD", rec.clone()));
    vars.push(("LITEROOT_CGROUP", root.to_owned()));
    let run = Run {
        backend,
        vars,
        argv: &["/bin/cat", "/dev/null"],
    };
    let (status, log) = run.go(&dir);
    assert_eq!(status, 0, "{log:?}");
    let record = one_record(&rec);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, backend, "exit", &log);
    let cg = &record["cgroup"];
    assert_eq!(cg["guest_cpu_state"], "COMPLETE");
    assert_eq!(cg["procs_left"], 0);
    let n = |p: &str| record.pointer(p).and_then(serde_json::Value::as_i64).unwrap();
    let usage = n("/cgroup/usage_usec");
    let lo = n("/cgroup/launcher_in_cgroup_us/0");
    let hi = n("/cgroup/launcher_in_cgroup_us/1");
    assert!(0 <= lo && lo <= hi && hi <= usage, "{cg}");
    assert_eq!(n("/cgroup/guest_cpu_us/0"), usage - hi);
    assert_eq!(n("/cgroup/guest_cpu_us/1"), usage - lo);
    let pid = begin_pid(&log);
    assert!(!root.join(format!("lr-{pid}")).exists(), "the run's cgroup was removed");
}

#[cfg(feature = "run")]
#[test]
fn ptrace_cgroup_split_and_refusals() {
    let Some(root) = cgroup_or_skip() else {
        return;
    };
    cgroup_split("ptrace", None, &root);
    // LITEROOT_CGROUP without a record: refused by name, before launch.
    let dir = scratch("stats-cg-refuse");
    let run = Run {
        backend: "ptrace",
        vars: vec![("LITEROOT_CGROUP", root.clone())],
        argv: &["/bin/true"],
    };
    let (status, log) = run.go(&dir);
    assert_eq!(status, 125);
    assert!(log.contains(&"literoot: refused launcher stats_cgroup".to_owned()), "{log:?}");
    // A directory that is not a delegated cgroup: refused the same way.
    let run = Run {
        backend: "ptrace",
        vars: vec![
            ("LITEROOT_EXIT_RECORD", dir.join("e.jsonl")),
            ("LITEROOT_CGROUP", PathBuf::from("/nonexistent-literoot-cgroup")),
        ],
        argv: &["/bin/true"],
    };
    let (status, log) = run.go(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(status, 125);
    assert!(log.contains(&"literoot: refused launcher stats_cgroup".to_owned()), "{log:?}");
}

#[cfg(feature = "inguest-trap")]
#[test]
fn trap_cgroup_split() {
    let (Some(root), Some(preload)) = (cgroup_or_skip(), preload_or_skip()) else {
        return;
    };
    cgroup_split("trap", Some(&preload), &root);
}
