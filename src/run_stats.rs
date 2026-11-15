//! End-of-run records, both off by default:
//!
//! - `LITEROOT_STATS=<path>` (counting runs): the launcher asks the
//!   selected Reverie backend for its existing statistics snapshot and
//!   appends one JSON line to that file after the guest finishes, with
//!   every field below (`"mode": "counting"`);
//! - `LITEROOT_EXIT_RECORD=<path>` (timing runs): no backend counting at
//!   all (the backend gets a disabled request and runs exactly as without
//!   this module); one line with the wall time and getrusage below, written
//!   once at exit (`"mode": "exit"`, the count fields null). The line
//!   carries the launcher's pid, which its refusal log's `begin` line
//!   names, so a harness that appends every run to one file can attribute
//!   each line to its run.
//!
//! When both are set, `LITEROOT_STATS` wins. With either one,
//! `LITEROOT_CGROUP=<dir>` (a cgroup v2 directory delegated to this user)
//! gives the run its own cgroup, `<dir>/lr-<pid>`, so the record can split
//! CPU between the launcher and the guest with matching boundaries (see
//! `cgroup` below). The fields:
//!
//! - the backend-neutral `reverie::DispatchStats` record (how each
//!   intercepted event was delivered: seccomp `SIGSYS`, patched call,
//!   ptrace seccomp or `SIGTRAP` stop, ...), and the backend's own
//!   snapshot as its display text;
//! - for ptrace, every count of `reverie_ptrace::PtraceBackendStatsSnapshot`
//!   by its accessor's name. `stop_events` counts the tracer's top-level
//!   run-loop stops only: the PTRACE_SYSCALL stops taken while the tracer
//!   injects a syscall are not counted (reverie-ptrace stats.rs:142-145),
//!   so ptrace stops removed by an in-guest backend, computed from it, are
//!   a LOWER BOUND. The counts overlap rather than partition: seccomp_stops
//!   includes internal_seccomp_stops and signal_stops includes
//!   injected_trap_stops;
//! - `backend_wall_ns`: from `run_backend`'s entry, before the probe
//!   memfd, shared record, runtime and preload are set up, to just before
//!   this record is built: after backend cleanup, the in-guest report
//!   collection and output replay, or the ptrace snapshot. It is the
//!   launcher's interval in a counting run, not a timing result;
//! - `getrusage(RUSAGE_SELF)` (the launcher or tracer, all threads, from
//!   the process's start, sampled here, so the launcher's tail after this
//!   point is not in it) and `getrusage(RUSAGE_CHILDREN)` (descendants
//!   reaped through the root guest; an orphan reparented away is not in
//!   it): user and system time, max RSS, voluntary and involuntary context
//!   switches. `rusage_children` is a PARTIAL value: it covers only the
//!   children this launcher waited for (and what they waited for), and its
//!   `maxrss_kb` is the largest single reaped descendant, not a sum;
//! - `cgroup`. Without `LITEROOT_CGROUP` no cgroup code runs at all and
//!   this field says only `"guest_cpu_state": "UNAVAILABLE"` with its
//!   reason (on a host without delegation, for example). With it, before
//!   the backend starts, the launcher creates `<dir>/lr-<pid>` (it must not exist),
//!   moves itself in and reads `cgroup.procs` back, which must hold only its
//!   own pid; the guest then starts inside it, so the cgroup holds this run
//!   and nothing else. At exit, before the record, it waits up to 10 s for
//!   every other process to leave, then reads its own CPU, the cgroup's
//!   `cpu.stat`, and its own CPU again. With `a`/`b` its CPU just before and
//!   after the move and `c`/`d` around the `cpu.stat` read:
//!   launcher in cgroup in [c - b, d - a]; guest = usage - launcher, so
//!   guest in [usage - (d - a), usage - (c - b)]. The launcher's work after
//!   the read (the record, leaving, exit) is in neither term. If another
//!   process is still there after the wait, `guest_cpu_state` is
//!   INCOMPLETE and `guest_cpu_us` is null, never a partial number. Then it
//!   moves itself, and any process still there, back to `<dir>` and removes
//!   `lr-<pid>`; a step that fails ends the run as a record failure, loudly.
//!   A setup failure refuses the run before the guest starts. The guest can
//!   see the cgroup path in `/proc/self/cgroup`: a known guest-visible
//!   difference of measurement mode only, never a default.
//!
//! Literoot counts nothing itself; Reverie counts only when asked
//! (`BackendStatsRequest`), so with the three variables unset every backend
//! runs exactly the calls it runs without this module. The variables are
//! removed from the guest's environment either way. Literoot's Tool has 139
//! syscall injection sites (`.inject(` in rootfs_tool.rs); every injection
//! that runs takes ptrace stops `stop_events` does not count.
//!
//! With `LITEROOT_STATS` set, the in-guest backends start their statistics
//! server and carry its endpoint to the guest's runtime through the private
//! bootstrap (not the environment), and every guest process reports over
//! it at exit: that counting and IPC cost is why counting runs and timing
//! runs stay separate. `LITEROOT_EXIT_RECORD` adds no backend work.
//!
//! A requested record that cannot be written ends the run with
//! [`STATS_RECORD_EXIT`] and the side log's `end <pid> error stats_record`,
//! never as a launcher refusal and never as a silent gap.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Environment variable naming the counting record's file.
pub(crate) const STATS_ENV: &str = "LITEROOT_STATS";

/// Environment variable naming the exit-only record's file.
pub(crate) const EXIT_ENV: &str = "LITEROOT_EXIT_RECORD";

/// Environment variable naming the delegated cgroup directory under which
/// a run with a record gets its own cgroup.
pub(crate) const CGROUP_ENV: &str = "LITEROOT_CGROUP";

/// Version of the JSON line below; bump it when a field changes meaning.
const SCHEMA: &str = "literoot-stats-v1";

/// Exit status of a run whose guest finished but whose requested record
/// could not be written: neither 0 nor the launcher's 2, 3 or 125. The
/// side log's `end` token (`stats_record`) is the authority; a guest can
/// exit with any status.
pub(crate) const STATS_RECORD_EXIT: u8 = 5;

static RECORD_FAILED: AtomicBool = AtomicBool::new(false);

/// Whether a requested record could not be written in this process.
pub(crate) fn record_failed() -> bool {
    RECORD_FAILED.load(Ordering::SeqCst)
}

/// A record request, decided once before the backend starts.
pub(crate) struct RunStats {
    path: Option<PathBuf>,
    counting: bool,
    cgroup: Option<RunCgroup>,
    start: Instant,
}

impl RunStats {
    /// Reads [`STATS_ENV`], [`EXIT_ENV`] and [`CGROUP_ENV`], keeps all
    /// three out of the guest's environment, and enters the run's own
    /// cgroup when one is asked for. `CGROUP_ENV` without a record is
    /// refused, as is any cgroup step that fails.
    pub(crate) fn from_env(cmd: &mut reverie::process::Command) -> Result<Self, String> {
        cmd.env_remove(STATS_ENV);
        cmd.env_remove(EXIT_ENV);
        cmd.env_remove(CGROUP_ENV);
        let mut stats =
            Self::from_values(std::env::var_os(STATS_ENV), std::env::var_os(EXIT_ENV));
        if let Some(root) = std::env::var_os(CGROUP_ENV).filter(|v| !v.is_empty()) {
            if stats.path.is_none() {
                return Err(format!("{CGROUP_ENV}: set without {STATS_ENV} or {EXIT_ENV}"));
            }
            stats.cgroup = Some(RunCgroup::enter(PathBuf::from(root))?);
        }
        Ok(stats)
    }

    /// The decision for the two values: unset or empty requests nothing;
    /// a counting path wins over an exit-only path.
    fn from_values(stats: Option<OsString>, exit: Option<OsString>) -> Self {
        let set = |v: Option<OsString>| v.filter(|v| !v.is_empty());
        match (set(stats), set(exit)) {
            (Some(path), _) => Self::new(Some(PathBuf::from(path)), true),
            (None, Some(path)) => Self::new(Some(PathBuf::from(path)), false),
            (None, None) => Self::new(None, false),
        }
    }

    fn new(path: Option<PathBuf>, counting: bool) -> Self {
        Self {
            path,
            counting,
            cgroup: None,
            start: Instant::now(),
        }
    }

    /// The request to hand to the backend: enabled only for counting.
    pub(crate) fn request(&self) -> reverie::BackendStatsRequest {
        reverie::BackendStatsRequest::new(self.counting)
    }

    /// Whether backend counting was requested (the `*_and_stats` calls).
    pub(crate) fn counting(&self) -> bool {
        self.counting
    }

    /// The run's exit status once the guest has finished: `exit_code`
    /// after appending the record (or when none was requested), else
    /// [`STATS_RECORD_EXIT`], with the reason on stderr and the failure
    /// noted for the side log's `end` line.
    pub(crate) fn conclude<S: reverie::BackendStatsSnapshot>(
        &self,
        backend: &str,
        exit_code: u8,
        snapshot: Option<&S>,
        ptrace: Option<serde_json::Value>,
    ) -> u8 {
        let written = self.finish(backend, exit_code, snapshot, ptrace);
        let left = self.cgroup.as_ref().map_or(Ok(()), RunCgroup::leave);
        match written.and(left) {
            Ok(()) => exit_code,
            Err(e) => {
                eprintln!("literoot: {e}");
                RECORD_FAILED.store(true, Ordering::SeqCst);
                STATS_RECORD_EXIT
            }
        }
    }

    /// Appends the record for a finished run; a no-op when not requested.
    ///
    /// `snapshot` is the backend's statistics snapshot; `ptrace` carries
    /// the ptrace stop counts by name when the backend is ptrace.
    fn finish<S: reverie::BackendStatsSnapshot>(
        &self,
        backend: &str,
        exit_code: u8,
        snapshot: Option<&S>,
        ptrace: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        // No cgroup: the record says the split is unavailable, explicitly.
        let cgroup = match &self.cgroup {
            Some(cg) => cg.read()?,
            None => serde_json::json!({
                "guest_cpu_state": "UNAVAILABLE",
                "reason": "LITEROOT_CGROUP unset: guest split unavailable",
            }),
        };
        let line = record(
            if self.counting { "counting" } else { "exit" },
            backend,
            exit_code,
            self.start.elapsed().as_nanos(),
            snapshot.map(|s| (s.dispatch_stats(), s.to_string())),
            ptrace,
            rusage(libc::RUSAGE_SELF)?,
            rusage(libc::RUSAGE_CHILDREN)?,
            cgroup,
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
    mode: &str,
    backend: &str,
    exit_code: u8,
    wall_ns: u128,
    snapshot: Option<(Option<reverie::DispatchStats>, String)>,
    ptrace: Option<serde_json::Value>,
    self_usage: serde_json::Value,
    children_usage: serde_json::Value,
    cgroup: serde_json::Value,
) -> serde_json::Value {
    let (dispatch, detail) = match snapshot {
        Some((dispatch, detail)) => (dispatch, Some(detail)),
        None => (None, None),
    };
    serde_json::json!({
        "schema": SCHEMA,
        "mode": mode,
        "pid": std::process::id(),
        "backend": backend,
        "exit_code": exit_code,
        "backend_wall_ns": wall_ns as u64,
        "dispatch": dispatch,
        "ptrace": ptrace,
        "backend_detail": detail,
        "rusage_self": self_usage,
        "rusage_children": children_usage,
        "cgroup": cgroup,
    })
}

/// This run's own cgroup, `<root>/lr-<pid>` (see the module docs).
struct RunCgroup {
    root: PathBuf,
    dir: PathBuf,
    /// This process's CPU (µs) just before and just after the move.
    moved: (i64, i64),
    left: std::cell::Cell<bool>,
}

impl RunCgroup {
    fn enter(root: PathBuf) -> Result<Self, String> {
        let pid = std::process::id();
        let dir = root.join(format!("lr-{pid}"));
        std::fs::create_dir(&dir)
            .map_err(|e| format!("{CGROUP_ENV}: cannot create lr-{pid}: {e}"))?;
        let mut cg = Self {
            root,
            dir,
            moved: (0, 0),
            left: std::cell::Cell::new(true),
        };
        let a = self_cpu_us()?;
        std::fs::write(cg.dir.join("cgroup.procs"), format!("{pid}\n"))
            .map_err(|e| format!("{CGROUP_ENV}: cannot enter lr-{pid}: {e}"))?;
        cg.left.set(false);
        let b = self_cpu_us()?;
        cg.moved = (a, b);
        let procs = read_procs(&cg.dir)?;
        if procs != [pid] {
            return Err(format!(
                "{CGROUP_ENV}: lr-{pid} holds {} process(es) after the move, not only this one",
                procs.len()
            ));
        }
        Ok(cg)
    }

    /// The split at exit; the guest must have left (10 s at most).
    fn read(&self) -> Result<serde_json::Value, String> {
        self.read_waiting(100)
    }

    /// [`Self::read`], polling `cgroup.procs` at most `polls` times, 100 ms apart.
    fn read_waiting(&self, polls: u32) -> Result<serde_json::Value, String> {
        let pid = std::process::id();
        let mut others = 0;
        for _ in 0..polls {
            others = read_procs(&self.dir)?.iter().filter(|&&p| p != pid).count();
            if others == 0 || polls == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let c = self_cpu_us()?;
        let stat = std::fs::read_to_string(self.dir.join("cpu.stat"))
            .map_err(|e| format!("{CGROUP_ENV}: cannot read cpu.stat: {e}"))?;
        let d = self_cpu_us()?;
        let field = |name: &str| -> Result<i64, String> {
            stat.lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
                .ok_or_else(|| format!("{CGROUP_ENV}: cpu.stat has no {name}"))
        };
        let usage = field("usage_usec")?;
        let (a, b) = self.moved;
        // A guest process still running has CPU still to come: the split
        // is then INCOMPLETE and carries no guest number at all.
        let (state, guest) = if others == 0 {
            ("COMPLETE", serde_json::json!([usage - (d - a), usage - (c - b)]))
        } else {
            ("INCOMPLETE", serde_json::Value::Null)
        };
        Ok(serde_json::json!({
            "usage_usec": usage,
            "user_usec": field("user_usec")?,
            "system_usec": field("system_usec")?,
            "procs_left": others,
            "self_at_move_us": [a, b],
            "self_at_read_us": [c, d],
            "launcher_in_cgroup_us": [c - b, d - a],
            "guest_cpu_state": state,
            "guest_cpu_us": guest,
        }))
    }

    /// Move back to the root and remove the run's cgroup (once).
    fn leave(&self) -> Result<(), String> {
        if self.left.replace(true) {
            return Ok(());
        }
        let pid = std::process::id();
        std::fs::write(self.root.join("cgroup.procs"), format!("{pid}\n"))
            .map_err(|e| format!("{CGROUP_ENV}: cannot leave lr-{pid}: {e}"))?;
        // A process the 10 s wait did not see leave is moved to the root
        // first, so the cgroup itself is never left behind.
        for p in read_procs(&self.dir)? {
            std::fs::write(self.root.join("cgroup.procs"), format!("{p}\n"))
                .map_err(|e| format!("{CGROUP_ENV}: cannot move pid {p} out of lr-{pid}: {e}"))?;
        }
        std::fs::remove_dir(&self.dir)
            .map_err(|e| format!("{CGROUP_ENV}: cannot remove lr-{pid}: {e}"))
    }
}

impl Drop for RunCgroup {
    /// A run that ends without a record (a launch error) still leaves and
    /// removes its cgroup when it can; a failure here is reported by the
    /// error that ended the run.
    fn drop(&mut self) {
        let _ = self.leave();
        if self.left.get() && self.dir.exists() {
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}

fn read_procs(dir: &std::path::Path) -> Result<Vec<u32>, String> {
    let text = std::fs::read_to_string(dir.join("cgroup.procs"))
        .map_err(|e| format!("{CGROUP_ENV}: cannot read cgroup.procs: {e}"))?;
    text.split_whitespace()
        .map(|p| p.parse().map_err(|_| format!("{CGROUP_ENV}: bad cgroup.procs entry")))
        .collect()
}

/// This process's user plus system CPU, in microseconds.
fn self_cpu_us() -> Result<i64, String> {
    let usage = rusage(libc::RUSAGE_SELF)?;
    Ok(usage["user_us"].as_i64().unwrap_or(0) + usage["sys_us"].as_i64().unwrap_or(0))
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
        let stats = RunStats::new(None, false);
        assert!(!stats.counting());
        assert_eq!(stats.request(), reverie::BackendStatsRequest::DISABLED);
        stats
            .finish::<NoSnapshot>(backend(), 0, None, None)
            .expect("disabled finish is a no-op");
    }

    #[test]
    fn decision_from_the_two_values() {
        let none = RunStats::from_values(None, None);
        assert!(none.path.is_none() && !none.counting());
        let empty = RunStats::from_values(Some("".into()), Some("".into()));
        assert!(empty.path.is_none() && !empty.counting());
        let exit = RunStats::from_values(None, Some("/x/exit.jsonl".into()));
        assert_eq!(exit.path, Some(PathBuf::from("/x/exit.jsonl")));
        assert!(!exit.counting());
        assert_eq!(exit.request(), reverie::BackendStatsRequest::DISABLED);
        let both = RunStats::from_values(Some("/x/s.jsonl".into()), Some("/x/e.jsonl".into()));
        assert_eq!(both.path, Some(PathBuf::from("/x/s.jsonl")));
        assert!(both.counting());
        assert_eq!(both.request(), reverie::BackendStatsRequest::ENABLED);
    }

    #[test]
    fn records_are_json_lines_with_every_field_and_mode() {
        let dir = std::env::temp_dir().join(format!("literoot-stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stats.jsonl");
        let counting = RunStats::new(Some(path.clone()), true);
        counting
            .finish(
                backend(),
                3,
                Some(&NoSnapshot),
                Some(serde_json::json!({"stop_events": 7})),
            )
            .unwrap();
        RunStats::new(Some(path.clone()), false)
            .finish::<NoSnapshot>(backend(), 0, None, None)
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{text}");
        let first = &lines[0];
        assert_eq!(first["schema"], SCHEMA);
        assert_eq!(first["mode"], "counting");
        assert_eq!(first["pid"], std::process::id());
        assert_eq!(first["backend"], "test");
        assert_eq!(first["exit_code"], 3);
        assert_eq!(first["ptrace"]["stop_events"], 7);
        assert_eq!(first["backend_detail"], "no-snapshot");
        assert!(first["dispatch"].is_null());
        for line in &lines {
            for side in ["rusage_self", "rusage_children"] {
                for key in [
                    "user_us",
                    "sys_us",
                    "maxrss_kb",
                    "voluntary_ctxt_switches",
                    "involuntary_ctxt_switches",
                ] {
                    assert!(line[side][key].is_i64(), "{side}.{key} in {text}");
                }
            }
        }
        assert_eq!(lines[1]["mode"], "exit");
        assert!(lines[1]["backend_detail"].is_null() && lines[1]["ptrace"].is_null());
    }

    #[test]
    fn unwritable_requested_record_concludes_with_its_own_status() {
        let stats = RunStats::new(Some(PathBuf::from("/nonexistent-dir/stats.jsonl")), true);
        let error = stats.finish::<NoSnapshot>(backend(), 0, None, None).unwrap_err();
        assert!(error.contains("cannot append"), "{error}");
        assert!(!record_failed());
        assert_eq!(stats.conclude::<NoSnapshot>(backend(), 0, None, None), STATS_RECORD_EXIT);
        assert!(record_failed());
        // A written (or unrequested) record keeps the guest's status.
        let none = RunStats::new(None, false);
        assert_eq!(none.conclude::<NoSnapshot>(backend(), 9, None, None), 9);
    }

    /// The split's arithmetic and states on a plain directory standing in
    /// for a cgroup (the kernel's own cgroup is exercised by
    /// tests/run_stats.rs under a delegated directory).
    #[test]
    fn cgroup_split_on_a_stand_in_tree() {
        let root = std::env::temp_dir().join(format!("literoot-cg-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let cg = RunCgroup::enter(root.clone()).expect("enter a stand-in");
        let pid = std::process::id();
        let dir = root.join(format!("lr-{pid}"));
        assert_eq!(read_procs(&dir).unwrap(), vec![pid]);
        assert!(RunCgroup::enter(root.clone()).is_err(), "lr-<pid> must not exist");
        let stat = "usage_usec 1000000\nuser_usec 600000\nsystem_usec 400000\n";
        std::fs::write(dir.join("cpu.stat"), stat).unwrap();
        let split = cg.read_waiting(1).unwrap();
        assert_eq!(split["guest_cpu_state"], "COMPLETE");
        let (a, b) = cg.moved;
        let read = &split["self_at_read_us"];
        let (c, d) = (read[0].as_i64().unwrap(), read[1].as_i64().unwrap());
        assert!(a <= b && b <= c && c <= d);
        assert_eq!(split["launcher_in_cgroup_us"], serde_json::json!([c - b, d - a]));
        let guest = serde_json::json!([1_000_000 - (d - a), 1_000_000 - (c - b)]);
        assert_eq!(split["guest_cpu_us"], guest);
        // Another process still there: INCOMPLETE, and no guest number.
        std::fs::write(dir.join("cgroup.procs"), format!("{pid}\n4194999\n")).unwrap();
        let split = cg.read_waiting(1).unwrap();
        assert_eq!(split["guest_cpu_state"], "INCOMPLETE");
        assert_eq!(split["procs_left"], 1);
        assert!(split["guest_cpu_us"].is_null());
        // A plain directory with files cannot be removed: loud, not silent.
        let error = cg.leave().unwrap_err();
        assert!(error.contains("cannot remove"), "{error}");
        assert!(cg.leave().is_ok(), "leave runs once");
        drop(cg);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn without_a_cgroup_the_split_is_unavailable() {
        let stats = RunStats::new(None, false);
        assert!(stats.cgroup.is_none());
        let dir = std::env::temp_dir().join(format!("literoot-un-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.jsonl");
        RunStats::new(Some(path.clone()), false)
            .finish::<NoSnapshot>(backend(), 0, None, None)
            .unwrap();
        let line: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(line["cgroup"]["guest_cpu_state"], "UNAVAILABLE");
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
