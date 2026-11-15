//! End-of-run statistics (`LITEROOT_STATS=<path>`), off by default.
//!
//! When the variable names a file, the launcher asks the selected
//! Reverie backend for its existing statistics snapshot and appends
//! one JSON line to that file after the guest finishes:
//!
//! - the backend-neutral `reverie::DispatchStats` record (how each
//!   intercepted event was delivered: seccomp `SIGSYS`, patched call,
//!   ptrace seccomp or `SIGTRAP` stop, ...), and the backend's own
//!   snapshot as its display text;
//! - for ptrace, every lifecycle stop count of
//!   `reverie_ptrace::PtraceBackendStatsSnapshot` by name;
//! - the launcher's wall time from backend start to guest exit;
//! - `getrusage(RUSAGE_SELF)` (the launcher or tracer, all threads)
//!   and `getrusage(RUSAGE_CHILDREN)` (descendants that were reaped
//!   up to the root guest): user and system time, max RSS, voluntary
//!   and involuntary context switches.
//!
//! Literoot counts nothing itself; Reverie counts only when asked
//! (`BackendStatsRequest`), so with the variable unset every backend
//! runs exactly the calls it runs without this module. The variable
//! is removed from the guest's environment either way. The in-guest
//! backends still name their statistics socket to the guest, so a
//! counting run's guest environment differs from a timing run's: use
//! counting runs for counts and timing runs for time.
//!
//! A requested record that cannot be written fails the run rather
//! than leaving a silent gap.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

/// Environment variable naming the statistics file.
pub(crate) const STATS_ENV: &str = "LITEROOT_STATS";

/// Version of the JSON line below; bump it when a field changes meaning.
const SCHEMA: &str = "literoot-stats-v1";

/// A statistics request, decided once before the backend starts.
pub(crate) struct RunStats {
    path: Option<PathBuf>,
    start: Instant,
}

impl RunStats {
    /// Reads [`STATS_ENV`] and keeps it out of the guest's environment.
    pub(crate) fn from_env(cmd: &mut reverie::process::Command) -> Self {
        cmd.env_remove(STATS_ENV);
        let path = std::env::var_os(STATS_ENV).filter(|v| !v.is_empty());
        Self::new(path.map(PathBuf::from))
    }

    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            start: Instant::now(),
        }
    }

    /// The request to hand to the backend.
    pub(crate) fn request(&self) -> reverie::BackendStatsRequest {
        reverie::BackendStatsRequest::new(self.path.is_some())
    }

    /// Whether a record was requested.
    pub(crate) fn enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Appends the record for a finished run; a no-op when not requested.
    ///
    /// `snapshot` is the backend's statistics snapshot; `ptrace` carries
    /// the ptrace stop counts by name when the backend is ptrace.
    pub(crate) fn finish<S: reverie::BackendStatsSnapshot>(
        &self,
        backend: &str,
        exit_code: u8,
        snapshot: Option<&S>,
        ptrace: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let line = record(
            backend,
            exit_code,
            self.start.elapsed().as_nanos(),
            snapshot.map(|s| (s.dispatch_stats(), s.to_string())),
            ptrace,
            rusage(libc::RUSAGE_SELF)?,
            rusage(libc::RUSAGE_CHILDREN)?,
        );
        let mut text =
            serde_json::to_string(&line).map_err(|e| format!("{STATS_ENV}: {e}"))?;
        text.push('\n');
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .map_err(|e| format!("{STATS_ENV}: cannot append to {}: {e}", path.display()))
    }
}

/// The ptrace stop counts, by the snapshot's own accessor names.
#[cfg(feature = "run")]
pub(crate) fn ptrace_counts(s: &reverie_ptrace::PtraceBackendStatsSnapshot) -> serde_json::Value {
    serde_json::json!({
        "tracees_started": s.tracees_started(),
        "stop_events": s.stop_events(),
        "exited_tracees": s.exited_tracees(),
        "seccomp_stops": s.seccomp_stops(),
        "signal_stops": s.signal_stops(),
        "exec_stops": s.exec_stops(),
        "fork_stops": s.fork_stops(),
        "vfork_stops": s.vfork_stops(),
        "clone_stops": s.clone_stops(),
        "vfork_done_stops": s.vfork_done_stops(),
        "injected_trap_stops": s.injected_trap_stops(),
        "internal_seccomp_stops": s.internal_seccomp_stops(),
    })
}

fn record(
    backend: &str,
    exit_code: u8,
    wall_ns: u128,
    snapshot: Option<(Option<reverie::DispatchStats>, String)>,
    ptrace: Option<serde_json::Value>,
    self_usage: serde_json::Value,
    children_usage: serde_json::Value,
) -> serde_json::Value {
    let (dispatch, detail) = match snapshot {
        Some((dispatch, detail)) => (dispatch, Some(detail)),
        None => (None, None),
    };
    serde_json::json!({
        "schema": SCHEMA,
        "backend": backend,
        "exit_code": exit_code,
        "backend_wall_ns": wall_ns as u64,
        "dispatch": dispatch,
        "ptrace": ptrace,
        "backend_detail": detail,
        "rusage_self": self_usage,
        "rusage_children": children_usage,
    })
}

fn rusage(who: libc::c_int) -> Result<serde_json::Value, String> {
    // SAFETY: getrusage writes only into the zeroed struct we own.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(who, &mut usage) } != 0 {
        return Err(format!(
            "{STATS_ENV}: getrusage: {}",
            std::io::Error::last_os_error()
        ));
    }
    // time_t and suseconds_t are both i64 on 64-bit Linux.
    let micros = |t: libc::timeval| t.tv_sec * 1_000_000 + t.tv_usec;
    Ok(serde_json::json!({
        "user_us": micros(usage.ru_utime),
        "sys_us": micros(usage.ru_stime),
        "maxrss_kb": usage.ru_maxrss,
        "voluntary_ctxt_switches": usage.ru_nvcsw,
        "involuntary_ctxt_switches": usage.ru_nivcsw,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_requests_nothing_and_finish_writes_nothing() {
        let stats = RunStats::new(None);
        assert!(!stats.enabled());
        assert_eq!(stats.request(), reverie::BackendStatsRequest::DISABLED);
        stats
            .finish::<NoSnapshot>(backend(), 0, None, None)
            .expect("disabled finish is a no-op");
    }

    #[test]
    fn requested_record_is_one_json_line_with_every_field() {
        let dir = std::env::temp_dir().join(format!("literoot-stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stats.jsonl");
        let stats = RunStats::new(Some(path.clone()));
        assert_eq!(stats.request(), reverie::BackendStatsRequest::ENABLED);
        stats
            .finish(
                backend(),
                3,
                Some(&NoSnapshot),
                Some(serde_json::json!({"stop_events": 7})),
            )
            .unwrap();
        stats.finish::<NoSnapshot>(backend(), 0, None, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{text}");
        let first = &lines[0];
        assert_eq!(first["schema"], SCHEMA);
        assert_eq!(first["backend"], "test");
        assert_eq!(first["exit_code"], 3);
        assert_eq!(first["ptrace"]["stop_events"], 7);
        assert_eq!(first["backend_detail"], "no-snapshot");
        assert!(first["dispatch"].is_null());
        for side in ["rusage_self", "rusage_children"] {
            for key in [
                "user_us",
                "sys_us",
                "maxrss_kb",
                "voluntary_ctxt_switches",
                "involuntary_ctxt_switches",
            ] {
                assert!(first[side][key].is_i64(), "{side}.{key} in {text}");
            }
        }
        assert!(lines[1]["backend_detail"].is_null());
    }

    #[test]
    fn unwritable_requested_record_fails_the_run() {
        let stats = RunStats::new(Some(PathBuf::from("/nonexistent-dir/stats.jsonl")));
        let error = stats.finish::<NoSnapshot>(backend(), 0, None, None).unwrap_err();
        assert!(error.contains("cannot append"), "{error}");
    }

    fn backend() -> &'static str {
        "test"
    }

    struct NoSnapshot;

    impl std::fmt::Display for NoSnapshot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("no-snapshot")
        }
    }

    impl reverie::BackendStatsSnapshot for NoSnapshot {
        const BACKEND_NAME: &'static str = "test";

        fn dispatch_stats(&self) -> Option<reverie::DispatchStats> {
            None
        }
    }
}
