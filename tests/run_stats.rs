//! `LITEROOT_STATS=<path>`: one JSON line per run with the backend's
//! own counts. Off by default; the variable never reaches the guest.
//!
//! The trap and liteinst tests need the preload (as backend_smoke):
//! they panic unless it is built, or skip explicitly with
//! LITEROOT_ALLOW_SKIP_PRELOAD=1.

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

/// A fresh directory under the test temp dir.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `literoot --backend <backend> -r / <argv>`, with the stats
/// file when one is given, and returns the exit status.
fn run(backend: &str, stats: Option<&Path>, preload: Option<&Path>, argv: &[&str]) -> i32 {
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", backend, "-r", "/"]).args(argv);
    cmd.env_remove("LITEROOT_STATS");
    if let Some(stats) = stats {
        cmd.env("LITEROOT_STATS", stats);
    }
    if let Some(preload) = preload {
        cmd.env("LITEROOT_PRELOAD", preload);
    }
    // Status only: output is not printed, so nothing from the
    // environment can reach the test log.
    let out = cmd.output().expect("spawn literoot");
    out.status.code().unwrap_or(-1)
}

/// The single record in a stats file.
fn one_record(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("stats file written");
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

fn assert_common(record: &serde_json::Value, backend: &str) {
    assert_eq!(record["schema"], "literoot-stats-v1");
    assert_eq!(record["backend"], backend);
    assert_eq!(record["exit_code"], 0);
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
    assert_eq!(count(record, "/dispatch/schema_version"), 1);
}

#[cfg(feature = "run")]
#[test]
fn ptrace_record_counts_stops_by_kind() {
    let dir = scratch("stats-ptrace");
    let stats = dir.join("stats.jsonl");
    assert_eq!(run("ptrace", Some(&stats), None, &["/bin/true"]), 0);
    let record = one_record(&stats);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "ptrace");
    let stops = count(&record, "/ptrace/stop_events");
    let seccomp = count(&record, "/ptrace/seccomp_stops");
    assert!(seccomp > 0, "a dynamic /bin/true makes intercepted syscalls");
    assert!(stops >= seccomp, "every seccomp stop is a stop event");
    // The shared projection agrees with the snapshot and names no
    // in-guest route.
    assert_eq!(count(&record, "/dispatch/counters/ptrace_seccomp_stops"), seccomp);
    assert_eq!(count(&record, "/dispatch/counters/signal_traps"), 0);
    assert_eq!(count(&record, "/dispatch/counters/patched_direct_calls"), 0);
}

#[cfg(feature = "run")]
#[test]
fn unset_stats_writes_nothing_and_never_reaches_the_guest() {
    let dir = scratch("stats-unset");
    let stats = dir.join("stats.jsonl");
    // Unset: no record anywhere we named.
    assert_eq!(run("ptrace", None, None, &["/bin/true"]), 0);
    assert!(!stats.exists());
    // Set: the guest still does not see the variable (a status
    // check, so no value is ever printed).
    let probe = ["/bin/sh", "-c", "test -z \"${LITEROOT_STATS+x}\""];
    assert_eq!(run("ptrace", Some(&stats), None, &probe), 0);
    assert_eq!(one_record(&stats)["exit_code"], 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(feature = "run")]
#[test]
fn unwritable_stats_path_fails_the_run() {
    let status = run(
        "ptrace",
        Some(Path::new("/nonexistent-literoot-dir/stats.jsonl")),
        None,
        &["/bin/true"],
    );
    assert_ne!(status, 0, "a requested record that cannot be written fails");
}

/// The zero-ptrace trap route: every ptrace count is zero by
/// structure and the deliveries are in-guest SIGSYS traps.
#[cfg(feature = "inguest-trap")]
#[test]
fn trap_record_has_no_ptrace_stops() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = scratch("stats-trap");
    let stats = dir.join("stats.jsonl");
    assert_eq!(run("trap", Some(&stats), Some(&preload), &["/bin/true"]), 0);
    let record = one_record(&stats);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "trap");
    assert!(record["ptrace"].is_null());
    assert_eq!(count(&record, "/dispatch/counters/ptrace_seccomp_stops"), 0);
    assert_eq!(count(&record, "/dispatch/counters/ptrace_sigtrap_stops"), 0);
    assert!(count(&record, "/dispatch/counters/signal_traps") > 0);
}

/// Patched-site liteinst (x86_64 only today): no ptrace stops, and
/// deliveries by patched call or SIGSYS.
#[cfg(all(target_arch = "x86_64", feature = "in-guest"))]
#[test]
fn liteinst_record_has_no_ptrace_stops() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = scratch("stats-liteinst");
    let stats = dir.join("stats.jsonl");
    assert_eq!(run("liteinst", Some(&stats), Some(&preload), &["/bin/true"]), 0);
    let record = one_record(&stats);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_common(&record, "liteinst");
    assert!(record["ptrace"].is_null());
    assert_eq!(count(&record, "/dispatch/counters/ptrace_seccomp_stops"), 0);
    let delivered = count(&record, "/dispatch/counters/patched_direct_calls")
        + count(&record, "/dispatch/counters/signal_traps");
    assert!(delivered > 0);
}
