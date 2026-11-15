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
//! - `backend_wall_ns`: from `run_backend`'s entry (after the run's cgroup
//!   is entered), before the probe memfd, shared record, runtime and
//!   preload are set up, to the start of the record: after backend
//!   cleanup, the in-guest report collection and output replay, or the
//!   ptrace snapshot, and before the cgroup's exit wait and read. It is the
//!   launcher's interval, not a timing result; the clock is read only when
//!   a record is requested;
//! - `getrusage(RUSAGE_SELF)` (the launcher or tracer, all threads, from
//!   the process's start, sampled when the line is built) and
//!   `getrusage(RUSAGE_CHILDREN)` (descendants reaped through the root
//!   guest; an orphan reparented away is not in it): user and system time,
//!   max RSS, voluntary and involuntary context switches. `rusage_children`
//!   is a PARTIAL value: it covers only the children this launcher waited
//!   for (and what they waited for), and its `maxrss_kb` is the largest
//!   single reaped descendant, not a sum;
//! - `cgroup`. Without `LITEROOT_CGROUP` no cgroup code runs at all and
//!   this field says only `"guest_cpu_state": "UNAVAILABLE"` with its
//!   reason (on a host without delegation, for example). With it, before
//!   the backend starts, the launcher checks that `<dir>` is on a cgroup v2
//!   file system (statfs) and that its subtree holds no process (a
//!   dedicated parent, with nothing left from an earlier run), creates
//!   `<dir>/lr-<pid>` (it must not exist),
//!   checks that the kernel gave it a `cpu.stat` with `usage_usec`, writes
//!   its pid to the existing `cgroup.procs` (never creating one), and
//!   requires that `cgroup.procs` then holds only its pid and that
//!   `/proc/<pid>/cgroup` names `lr-<pid>`. Any of these failing refuses
//!   the run before the guest starts. The guest then starts inside, so the
//!   cgroup holds this run and nothing else.
//!
//!   At exit it waits, until a 10 s monotonic deadline, for every other
//!   process to leave the cgroup's whole subtree (its own `cgroup.procs`
//!   and every descendant cgroup's), then reads its own CPU, the cgroup's
//!   `cpu.stat` (hierarchical) and its own CPU again. With `a`/`b` its CPU
//!   just before and after the move and `c`/`d` around the `cpu.stat`
//!   read: launcher in cgroup in [c - b, d - a]; guest = usage - launcher,
//!   so guest in [usage - (d - a), usage - (c - b)]. The launcher's work
//!   after the read is in neither term. `guest_cpu_state` is:
//!   - COMPLETE: no other process anywhere in the subtree, and the CPU of
//!     the children reaped since the move (every one was born in the
//!     cgroup, so a lower bound on the guest's CPU) is at most the guest
//!     interval's upper bound: an interval that its own lower bound
//!     contradicts is never published, with no allowance;
//!   - INCOMPLETE: a process was still in the subtree after the wait;
//!   - INCONSISTENT: the reaped children used more CPU than the cgroup can
//!     account for, so guest CPU left the cgroup (a process that moved
//!     itself out) or the cgroup missed the guest;
//!   - CLEANUP_FAILED or READ_FAILED: the steps below failed.
//!
//!   Only COMPLETE carries a guest number; every other state has
//!   `guest_cpu_us` null, never a partial number. Limit: a process that
//!   moved itself out of the cgroup and was never reaped through the
//!   launcher is invisible to both checks; a measurement harness must show
//!   that its workloads write no cgroup files.
//!
//!   Then the launcher moves itself, and any process still in the subtree,
//!   back to `<dir>` (a process is moved only while `/proc/<p>/cgroup`
//!   still names this subtree, so an exited process's reused pid is never
//!   moved; the move needs write access to a common ancestor, which bounds
//!   the remaining race, a pid freed and reused between that check and the
//!   write, to the cgroups this user may write: its delegated systemd
//!   subtree), removes the
//!   subtree's cgroups, and checks they are gone. Cleanup counts as done
//!   only once the directory is verified absent; any failure is reported
//!   and ends the run as a stats failure. The guest can see the cgroup
//!   path in `/proc/self/cgroup`: a known guest-visible difference of
//!   measurement mode only, never a default.
//!
//! Literoot counts nothing itself; Reverie counts only when asked
//! (`BackendStatsRequest`), so with the three variables unset every backend
//! runs exactly the calls it runs without this module; what remains is
//! once-per-run launcher work before the backend starts (three removals
//! from the guest's environment and three reads of the launcher's). The
//! variables are removed from the guest's environment either way.
//! Literoot's Tool has 139 syscall injection sites (`.inject(` in
//! rootfs_tool.rs); every injection that runs takes ptrace stops
//! `stop_events` does not count.
//!
//! With `LITEROOT_STATS` set, the in-guest backends start their statistics
//! server and carry its endpoint to the guest's runtime through the private
//! bootstrap (not the environment), and every guest process reports over
//! it at exit: that counting and IPC cost is why counting runs and timing
//! runs stay separate. `LITEROOT_EXIT_RECORD` adds no backend work.
//!
//! Every failure of this module exits [`STATS_RECORD_EXIT`]: a record that
//! cannot be written, and a cgroup read or cleanup that fails, end the side
//! log with `end <pid> error stats_record` (that token outranks the others);
//! a cgroup setup failure is refused before the guest starts with the
//! launcher token `stats_cgroup`. Never a silent gap.

use std::cell::Cell;
use std::ffi::{CString, OsString};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Environment variable naming the counting record's file.
pub(crate) const STATS_ENV: &str = "LITEROOT_STATS";

/// Environment variable naming the exit-only record's file.
pub(crate) const EXIT_ENV: &str = "LITEROOT_EXIT_RECORD";

/// Environment variable naming the delegated cgroup directory under which
/// a run with a record gets its own cgroup.
pub(crate) const CGROUP_ENV: &str = "LITEROOT_CGROUP";

/// Version of the JSON line below; bump it when a field changes meaning.
const SCHEMA: &str = "literoot-stats-v1";

/// Exit status of every failure of this module: neither 0 nor the
/// launcher's 2, 3 or 125. The side log's tokens (`stats_record`,
/// `stats_cgroup`) are the authority; a guest can exit with any status.
pub(crate) const STATS_RECORD_EXIT: u8 = 5;

/// statfs `f_type` of a cgroup v2 file system (linux/magic.h).
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// How long the exit read waits for the guest to leave the cgroup.
const EXIT_WAIT: Duration = Duration::from_secs(10);

/// How long cleanup keeps moving processes that remain or appear.
const CLEANUP_WAIT: Duration = Duration::from_secs(2);

static RECORD_FAILED: AtomicBool = AtomicBool::new(false);

/// Whether a requested record, or the run's cgroup, failed in this process.
pub(crate) fn record_failed() -> bool {
    RECORD_FAILED.load(Ordering::SeqCst)
}

/// A record request, decided once before the backend starts.
pub(crate) struct RunStats {
    path: Option<PathBuf>,
    counting: bool,
    cgroup: Option<RunCgroup>,
    /// Read only when a record is requested.
    start: Option<Instant>,
}

impl RunStats {
    /// Reads [`STATS_ENV`], [`EXIT_ENV`] and [`CGROUP_ENV`], keeps all
    /// three out of the guest's environment, and enters the run's own
    /// cgroup when one is asked for. `CGROUP_ENV` without a record is
    /// refused, as is any cgroup setup step that fails.
    pub(crate) fn from_env(cmd: &mut reverie::process::Command) -> Result<Self, String> {
        cmd.env_remove(STATS_ENV);
        cmd.env_remove(EXIT_ENV);
        cmd.env_remove(CGROUP_ENV);
        let mut stats = Self::from_values(std::env::var_os(STATS_ENV), std::env::var_os(EXIT_ENV));
        if let Some(root) = std::env::var_os(CGROUP_ENV).filter(|v| !v.is_empty()) {
            if stats.path.is_none() {
                return Err(format!(
                    "{CGROUP_ENV}: set without {STATS_ENV} or {EXIT_ENV}"
                ));
            }
            stats.cgroup = Some(RunCgroup::enter(PathBuf::from(root))?);
            // The interval starts inside the cgroup.
            stats.start = Some(Instant::now());
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
        let start = path.as_ref().map(|_| Instant::now());
        Self {
            path,
            counting,
            cgroup: None,
            start,
        }
    }

    /// The variable that requested the record, for its messages.
    fn var(&self) -> &'static str {
        if self.counting {
            STATS_ENV
        } else {
            EXIT_ENV
        }
    }

    /// The request to hand to the backend: enabled only for counting.
    #[cfg_attr(not(feature = "run"), allow(dead_code))]
    pub(crate) fn request(&self) -> reverie::BackendStatsRequest {
        reverie::BackendStatsRequest::new(self.counting)
    }

    /// Whether backend counting was requested (the `*_and_stats` calls).
    #[cfg_attr(
        not(any(feature = "in-guest", feature = "inguest-trap")),
        allow(dead_code)
    )]
    pub(crate) fn counting(&self) -> bool {
        self.counting
    }

    /// The run's exit status once the guest has finished: `exit_code` when
    /// the cgroup (if any) was read and removed and the record (if any)
    /// appended, else [`STATS_RECORD_EXIT`], with every reason on stderr
    /// and the failure noted for the side log's `end` line.
    pub(crate) fn conclude<S: reverie::BackendStatsSnapshot>(
        &self,
        backend: &str,
        exit_code: u8,
        snapshot: Option<&S>,
        ptrace: Option<serde_json::Value>,
    ) -> u8 {
        // The interval ends here, before the cgroup's exit wait and read.
        let wall_ns = self.start.map(|s| s.elapsed().as_nanos());
        let mut errors = Vec::new();
        let cgroup = self.cgroup.as_ref().map(|cg| cg.conclude(&mut errors));
        if let Err(e) = self.append(backend, exit_code, wall_ns, snapshot, ptrace, cgroup) {
            errors.push(e);
        }
        if errors.is_empty() {
            return exit_code;
        }
        for e in &errors {
            eprintln!("literoot: {e}");
        }
        RECORD_FAILED.store(true, Ordering::SeqCst);
        STATS_RECORD_EXIT
    }

    /// The error that ends a run on a launcher error (no record): the
    /// run's cgroup is cleaned up first. A cleanup failure is added to the
    /// error's text and counts as a stats failure (status 5 and the
    /// `stats_record` end token); the error keeps its own launcher token,
    /// since the guest may already have run.
    pub(crate) fn abandon(&self, error: String) -> String {
        match self.cgroup.as_ref().map_or(Ok(()), RunCgroup::leave) {
            Ok(()) => error,
            Err(cleanup) => {
                RECORD_FAILED.store(true, Ordering::SeqCst);
                format!("{error} (then {cleanup})")
            }
        }
    }

    /// Appends the record for a finished run; a no-op when not requested.
    ///
    /// `snapshot` is the backend's statistics snapshot; `ptrace` carries
    /// the ptrace stop counts by name when the backend is ptrace; `cgroup`
    /// is the run's cgroup block, or `None` without one.
    fn append<S: reverie::BackendStatsSnapshot>(
        &self,
        backend: &str,
        exit_code: u8,
        wall_ns: Option<u128>,
        snapshot: Option<&S>,
        ptrace: Option<serde_json::Value>,
        cgroup: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let var = self.var();
        // No cgroup: the record says the split is unavailable, explicitly.
        let cgroup = cgroup.unwrap_or_else(|| {
            serde_json::json!({
                "guest_cpu_state": "UNAVAILABLE",
                "reason": "LITEROOT_CGROUP unset: guest split unavailable",
            })
        });
        let (dispatch, detail) = match snapshot {
            Some(s) => (s.dispatch_stats(), Some(s.to_string())),
            None => (None, None),
        };
        let mode = if self.counting { "counting" } else { "exit" };
        let line = serde_json::json!({
            "schema": SCHEMA,
            "mode": mode,
            "pid": std::process::id(),
            "backend": backend,
            "exit_code": exit_code,
            "backend_wall_ns": wall_ns.unwrap_or(0) as u64,
            "dispatch": dispatch,
            "ptrace": ptrace,
            "backend_detail": detail,
            "rusage_self": rusage(libc::RUSAGE_SELF, var)?,
            "rusage_children": rusage(libc::RUSAGE_CHILDREN, var)?,
            "cgroup": cgroup,
        });
        let mut text = serde_json::to_string(&line).map_err(|e| format!("{var}: {e}"))?;
        text.push('\n');
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .map_err(|e| format!("{var}: cannot append to {}: {e}", path.display()))
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

/// The guest split decided from one read (see the module docs).
struct Split {
    state: &'static str,
    guest: Option<(i64, i64)>,
    reason: Option<&'static str>,
}

/// `usage` is the cgroup's `usage_usec`; `moved` and `read` this process's
/// CPU around the move and around the read; `others` the processes other
/// than the launcher left in the subtree; `children` the CPU of the
/// children reaped since the move.
fn split(usage: i64, moved: (i64, i64), read: (i64, i64), others: usize, children: i64) -> Split {
    let ((a, b), (c, d)) = (moved, read);
    if others > 0 {
        return Split {
            state: "INCOMPLETE",
            guest: None,
            reason: Some("a guest process was still in the run's cgroup subtree after the wait"),
        };
    }
    let (lo, hi) = (usage - (d - a), usage - (c - b));
    if children > hi {
        return Split {
            state: "INCONSISTENT",
            guest: None,
            reason: Some("reaped children used more CPU than the cgroup's guest upper bound"),
        };
    }
    Split {
        state: "COMPLETE",
        guest: Some((lo, hi)),
        reason: None,
    }
}

/// This run's own cgroup, `<root>/lr-<pid>` (see the module docs).
struct RunCgroup {
    root: PathBuf,
    dir: PathBuf,
    /// `<root's name>/lr-<pid>`: the end of this cgroup's path as
    /// `/proc/<pid>/cgroup` names it.
    tail: String,
    /// This process's CPU (µs) just before and just after the move.
    moved: (i64, i64),
    /// CPU (µs) of the children reaped before the move.
    children_at_move: i64,
    /// This process is in the cgroup.
    inside: Cell<bool>,
    /// The cgroup's directory has not been verified removed.
    exists: Cell<bool>,
}

impl RunCgroup {
    fn enter(root: PathBuf) -> Result<Self, String> {
        let pid = std::process::id();
        require_cgroup2(&root)?;
        let strays = subtree_procs(&root)?.len();
        if strays > 0 {
            return Err(format!(
                "{CGROUP_ENV}: {} holds {strays} process(es); it must be a dedicated parent",
                root.display()
            ));
        }
        let name = format!("lr-{pid}");
        let Some(root_name) = root.file_name() else {
            return Err(format!(
                "{CGROUP_ENV}: {} has no final component",
                root.display()
            ));
        };
        let tail = format!("{}/{name}", root_name.to_string_lossy());
        let dir = root.join(&name);
        std::fs::create_dir(&dir)
            .map_err(|e| format!("{CGROUP_ENV}: cannot create {name}: {e}"))?;
        let mut cg = Self {
            root,
            dir,
            tail,
            moved: (0, 0),
            children_at_move: 0,
            inside: Cell::new(false),
            exists: Cell::new(true),
        };
        match cg.admit(pid) {
            Ok(()) => Ok(cg),
            Err(e) => Err(match cg.leave() {
                Ok(()) => e,
                Err(cleanup) => format!("{e}; {cleanup}"),
            }),
        }
    }

    /// Checks the new cgroup and moves this process into it.
    fn admit(&mut self, pid: u32) -> Result<(), String> {
        require_cgroup2(&self.dir)?;
        field(&cpu_stat(&self.dir)?, "usage_usec")?;
        let a = self_cpu_us()?;
        write_pid(&self.dir, pid)
            .map_err(|e| format!("{CGROUP_ENV}: cannot enter {}: {e}", self.tail))?;
        self.inside.set(true);
        let b = self_cpu_us()?;
        self.moved = (a, b);
        self.children_at_move = children_cpu_us()?;
        let procs = read_procs(&self.dir)?;
        if procs != [pid] {
            return Err(format!(
                "{CGROUP_ENV}: {} holds {} process(es) after the move, not only this one",
                self.tail,
                procs.len()
            ));
        }
        if !own_cgroup()?.ends_with(&format!("/{}", self.tail)) {
            return Err(format!(
                "{CGROUP_ENV}: /proc/self/cgroup does not name {}",
                self.tail
            ));
        }
        Ok(())
    }

    /// Reads the split, then cleans up; a failure of either is pushed to
    /// `errors` and leaves no guest number.
    fn conclude(&self, errors: &mut Vec<String>) -> serde_json::Value {
        let read = self.read();
        let left = self.leave();
        match (read, left) {
            (Ok(v), Ok(())) => v,
            (Ok(mut v), Err(cleanup)) => {
                errors.push(cleanup);
                v["guest_cpu_state"] = "CLEANUP_FAILED".into();
                v["guest_cpu_us"] = serde_json::Value::Null;
                v
            }
            (Err(e), left) => {
                errors.push(e);
                if let Err(cleanup) = left {
                    errors.push(cleanup);
                }
                serde_json::json!({"guest_cpu_state": "READ_FAILED", "guest_cpu_us": null})
            }
        }
    }

    /// The split at exit, after waiting (until [`EXIT_WAIT`]) for the
    /// guest to leave the subtree.
    fn read(&self) -> Result<serde_json::Value, String> {
        self.read_until(Instant::now() + EXIT_WAIT)
    }

    /// [`Self::read`], waiting until `deadline`.
    fn read_until(&self, deadline: Instant) -> Result<serde_json::Value, String> {
        let pid = std::process::id();
        let others = loop {
            let others = subtree_procs(&self.dir)?
                .iter()
                .filter(|(_, p)| *p != pid)
                .count();
            let now = Instant::now();
            if others == 0 || now >= deadline {
                break others;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(100)));
        };
        let c = self_cpu_us()?;
        let stat = cpu_stat(&self.dir)?;
        let d = self_cpu_us()?;
        let children = children_cpu_us()? - self.children_at_move;
        let usage = field(&stat, "usage_usec")?;
        let (a, b) = self.moved;
        let s = split(usage, self.moved, (c, d), others, children);
        Ok(serde_json::json!({
            "usage_usec": usage,
            "user_usec": field(&stat, "user_usec")?,
            "system_usec": field(&stat, "system_usec")?,
            "procs_left": others,
            "self_at_move_us": [a, b],
            "self_at_read_us": [c, d],
            "launcher_in_cgroup_us": [c - b, d - a],
            "children_since_move_us": children,
            "guest_cpu_state": s.state,
            "guest_cpu_us": s.guest.map(|(lo, hi)| serde_json::json!([lo, hi])),
            "reason": s.reason,
        }))
    }

    /// Moves this process, then anything still in the subtree, to the
    /// root, and removes the subtree. Each step is marked done only once
    /// verified, so a failure stays a failure and a retry redoes the rest.
    fn leave(&self) -> Result<(), String> {
        if self.inside.get() {
            write_pid(&self.root, std::process::id())
                .map_err(|e| format!("{CGROUP_ENV}: cannot leave {}: {e}", self.tail))?;
            if own_cgroup()?.ends_with(&format!("/{}", self.tail)) {
                return Err(format!(
                    "{CGROUP_ENV}: still in {} after leaving",
                    self.tail
                ));
            }
            self.inside.set(false);
        }
        if self.exists.get() {
            self.evacuate()?;
            remove_tree(&self.dir)?;
            if self.dir.exists() {
                return Err(format!(
                    "{CGROUP_ENV}: {} still exists after removal",
                    self.tail
                ));
            }
            self.exists.set(false);
        }
        Ok(())
    }

    /// Moves every process left in the subtree to the root, until none is
    /// left or [`CLEANUP_WAIT`] passes.
    fn evacuate(&self) -> Result<(), String> {
        let deadline = Instant::now() + CLEANUP_WAIT;
        loop {
            let left = subtree_procs(&self.dir)?;
            if left.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{CGROUP_ENV}: {} process(es) still in {} after {} s of cleanup",
                    left.len(),
                    self.tail,
                    CLEANUP_WAIT.as_secs()
                ));
            }
            for (dir, p) in left {
                self.move_out(&dir, p)?;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Moves pid `p` from `dir` (in the subtree) to the root, only while
    /// `/proc/<p>/cgroup` still names `dir`: an exited process (whose pid
    /// may be reused) or one that moved itself is left alone. A pid freed
    /// and reused between that check and the write is the remaining race;
    /// the kernel lets the write move only a process in a cgroup this user
    /// may write (its delegated systemd subtree).
    fn move_out(&self, dir: &Path, p: u32) -> Result<(), String> {
        let rest = dir.strip_prefix(&self.dir).unwrap_or(Path::new(""));
        let want = if rest.as_os_str().is_empty() {
            format!("/{}", self.tail)
        } else {
            format!("/{}/{}", self.tail, rest.display())
        };
        match proc_cgroup(p) {
            Ok(path) if path.ends_with(&want) => {}
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
            Err(e) => return Err(format!("{CGROUP_ENV}: cannot read /proc/{p}/cgroup: {e}")),
        }
        match write_pid(&self.root, p) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            Err(e) => Err(format!(
                "{CGROUP_ENV}: cannot move pid {p} out of {}: {e}",
                self.tail
            )),
        }
    }
}

impl Drop for RunCgroup {
    /// Every path concludes or abandons explicitly, so this finds work only
    /// when that cleanup failed (it then tries once more) or after a panic;
    /// a failure here is reported loudly and counts as a stats failure.
    fn drop(&mut self) {
        if self.inside.get() || self.exists.get() {
            if let Err(e) = self.leave() {
                eprintln!("literoot: {e} (cgroup cleanup at drop)");
                RECORD_FAILED.store(true, Ordering::SeqCst);
            }
        }
    }
}

/// Refuses a path that is not on a cgroup v2 file system.
fn require_cgroup2(path: &Path) -> Result<(), String> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{CGROUP_ENV}: {} contains a NUL byte", path.display()))?;
    // SAFETY: `c` is a valid C string; statfs writes only into the zeroed
    // struct we own.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("{CGROUP_ENV}: statfs {}: {e}", path.display()));
    }
    // f_type's integer type differs between libc targets.
    #[allow(clippy::unnecessary_cast)]
    let magic = st.f_type as u64;
    if magic != CGROUP2_SUPER_MAGIC {
        return Err(format!(
            "{CGROUP_ENV}: {} is not a cgroup v2 directory",
            path.display()
        ));
    }
    Ok(())
}

/// Writes `pid` to `dir`'s existing `cgroup.procs` (never creating it).
fn write_pid(dir: &Path, pid: u32) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("cgroup.procs"))?
        .write_all(format!("{pid}\n").as_bytes())
}

fn read_procs(dir: &Path) -> Result<Vec<u32>, String> {
    let text = std::fs::read_to_string(dir.join("cgroup.procs")).map_err(|e| {
        format!(
            "{CGROUP_ENV}: cannot read {}/cgroup.procs: {e}",
            dir.display()
        )
    })?;
    text.split_whitespace()
        .map(|p| {
            p.parse()
                .map_err(|_| format!("{CGROUP_ENV}: bad cgroup.procs entry"))
        })
        .collect()
}

/// Every process in `dir`'s cgroup and its descendant cgroups.
fn subtree_procs(dir: &Path) -> Result<Vec<(PathBuf, u32)>, String> {
    let mut all: Vec<(PathBuf, u32)> = read_procs(dir)?
        .into_iter()
        .map(|p| (dir.to_owned(), p))
        .collect();
    for sub in child_cgroups(dir)? {
        match subtree_procs(&sub) {
            Ok(procs) => all.extend(procs),
            // A guest may remove its own child cgroup while it is read.
            Err(_) if !sub.exists() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(all)
}

/// The child cgroups of `dir` (its subdirectories).
fn child_cgroups(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let fail = |e: std::io::Error| format!("{CGROUP_ENV}: cannot list {}: {e}", dir.display());
    let mut subs = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        if entry.file_type().map_err(fail)?.is_dir() {
            subs.push(entry.path());
        }
    }
    Ok(subs)
}

/// Removes `dir`'s cgroup and its descendants, deepest first.
fn remove_tree(dir: &Path) -> Result<(), String> {
    for sub in child_cgroups(dir)? {
        match remove_tree(&sub) {
            Ok(()) => {}
            // Gone already (a guest removed its own child cgroup).
            Err(_) if !sub.exists() => {}
            Err(e) => return Err(e),
        }
    }
    std::fs::remove_dir(dir)
        .map_err(|e| format!("{CGROUP_ENV}: cannot remove {}: {e}", dir.display()))
}

fn cpu_stat(dir: &Path) -> Result<String, String> {
    std::fs::read_to_string(dir.join("cpu.stat"))
        .map_err(|e| format!("{CGROUP_ENV}: cannot read {}/cpu.stat: {e}", dir.display()))
}

fn field(stat: &str, name: &str) -> Result<i64, String> {
    stat.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
        .ok_or_else(|| format!("{CGROUP_ENV}: cpu.stat has no {name}"))
}

/// The cgroup v2 path in `/proc/<pid>/cgroup` (its `0::` line).
fn proc_cgroup(pid: u32) -> std::io::Result<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| std::io::Error::other("no cgroup v2 line"))
}

fn own_cgroup() -> Result<String, String> {
    proc_cgroup(std::process::id())
        .map_err(|e| format!("{CGROUP_ENV}: cannot read /proc/self/cgroup: {e}"))
}

/// This process's user plus system CPU, in microseconds.
fn self_cpu_us() -> Result<i64, String> {
    cpu_us(&rusage(libc::RUSAGE_SELF, CGROUP_ENV)?)
}

/// The reaped children's user plus system CPU, in microseconds.
fn children_cpu_us() -> Result<i64, String> {
    cpu_us(&rusage(libc::RUSAGE_CHILDREN, CGROUP_ENV)?)
}

fn cpu_us(usage: &serde_json::Value) -> Result<i64, String> {
    match (usage["user_us"].as_i64(), usage["sys_us"].as_i64()) {
        (Some(user), Some(sys)) => Ok(user + sys),
        _ => Err(format!("{CGROUP_ENV}: getrusage gave no CPU time")),
    }
}

/// getrusage for `who`; `var` names the variable whose work failed.
fn rusage(who: libc::c_int, var: &str) -> Result<serde_json::Value, String> {
    // SAFETY: getrusage writes only into the zeroed struct we own.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(who, &mut usage) } != 0 {
        return Err(format!(
            "{var}: getrusage: {}",
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

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("literoot-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unset_requests_nothing_reads_no_clock_and_appends_nothing() {
        let stats = RunStats::new(None, false);
        assert!(!stats.counting());
        assert!(stats.start.is_none(), "no record, no clock read");
        assert_eq!(stats.request(), reverie::BackendStatsRequest::DISABLED);
        stats
            .append::<NoSnapshot>(backend(), 0, None, None, None, None)
            .expect("disabled append is a no-op");
    }

    #[test]
    fn decision_from_the_two_values() {
        let none = RunStats::from_values(None, None);
        assert!(none.path.is_none() && !none.counting() && none.start.is_none());
        let empty = RunStats::from_values(Some("".into()), Some("".into()));
        assert!(empty.path.is_none() && !empty.counting() && empty.start.is_none());
        let exit = RunStats::from_values(None, Some("/x/exit.jsonl".into()));
        assert_eq!(exit.path, Some(PathBuf::from("/x/exit.jsonl")));
        assert!(!exit.counting() && exit.start.is_some());
        assert_eq!(exit.request(), reverie::BackendStatsRequest::DISABLED);
        let both = RunStats::from_values(Some("/x/s.jsonl".into()), Some("/x/e.jsonl".into()));
        assert_eq!(both.path, Some(PathBuf::from("/x/s.jsonl")));
        assert!(both.counting());
        assert_eq!(both.request(), reverie::BackendStatsRequest::ENABLED);
    }

    #[test]
    fn records_are_json_lines_with_every_field_and_mode() {
        let dir = scratch("stats-lines");
        let path = dir.join("stats.jsonl");
        let counting = RunStats::new(Some(path.clone()), true);
        counting
            .append(
                backend(),
                3,
                Some(11),
                Some(&NoSnapshot),
                Some(serde_json::json!({"stop_events": 7})),
                None,
            )
            .unwrap();
        RunStats::new(Some(path.clone()), false)
            .append::<NoSnapshot>(backend(), 0, Some(12), None, None, None)
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
        assert_eq!(first["backend_wall_ns"], 11);
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
            assert_eq!(line["cgroup"]["guest_cpu_state"], "UNAVAILABLE");
        }
        assert_eq!(lines[1]["mode"], "exit");
        assert!(lines[1]["backend_detail"].is_null() && lines[1]["ptrace"].is_null());
    }

    #[test]
    fn an_unwritable_record_names_its_variable_and_concludes_with_its_status() {
        let stats = RunStats::new(Some(PathBuf::from("/nonexistent-dir/stats.jsonl")), true);
        let error = stats
            .append::<NoSnapshot>(backend(), 0, None, None, None, None)
            .unwrap_err();
        assert!(
            error.starts_with("LITEROOT_STATS: cannot append"),
            "{error}"
        );
        let exit = RunStats::new(Some(PathBuf::from("/nonexistent-dir/exit.jsonl")), false);
        let error = exit
            .append::<NoSnapshot>(backend(), 0, None, None, None, None)
            .unwrap_err();
        assert!(
            error.starts_with("LITEROOT_EXIT_RECORD: cannot append"),
            "{error}"
        );
        assert!(!record_failed());
        assert_eq!(
            stats.conclude::<NoSnapshot>(backend(), 0, None, None),
            STATS_RECORD_EXIT
        );
        assert!(record_failed());
        // A written (or unrequested) record keeps the guest's status.
        let none = RunStats::new(None, false);
        assert_eq!(none.conclude::<NoSnapshot>(backend(), 9, None, None), 9);
    }

    #[test]
    fn the_split_states() {
        // a=1, b=2 around the move; c=12, d=13 around the read.
        let (moved, read) = ((1, 2), (12, 13));
        let complete = split(1_000, moved, read, 0, 900);
        assert_eq!(complete.state, "COMPLETE");
        assert_eq!(complete.guest, Some((1_000 - 12, 1_000 - 10)));
        assert!(complete.reason.is_none());
        // The children's CPU is a lower bound on the guest's: at the upper
        // bound passes, one microsecond more contradicts the interval.
        assert_eq!(split(1_000, moved, read, 0, 990).state, "COMPLETE");
        let escaped = split(1_000, moved, read, 0, 991);
        assert_eq!(escaped.state, "INCONSISTENT");
        assert!(escaped.guest.is_none() && escaped.reason.is_some());
        // Children far above [988, 990] are never COMPLETE.
        assert_eq!(split(1_000, moved, read, 0, 1_990).state, "INCONSISTENT");
        // A cgroup that captured nothing of a guest that used CPU.
        assert_eq!(split(11, moved, read, 0, 50_000).state, "INCONSISTENT");
        let left = split(1_000, moved, read, 1, 0);
        assert_eq!(left.state, "INCOMPLETE");
        assert!(left.guest.is_none() && left.reason.is_some());
    }

    /// The real reader on a stand-in tree (plain files where the kernel's
    /// would be) with a short deadline: a process left in the cgroup, or in
    /// a child cgroup, at the read gives INCOMPLETE and no number.
    #[test]
    fn the_reader_sees_a_leftover_anywhere_in_the_subtree() {
        let root = scratch("cg-reader");
        let dir = root.join("lr-stand-in");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let stat = "usage_usec 1000000\nuser_usec 600000\nsystem_usec 400000\n";
        std::fs::write(dir.join("cpu.stat"), stat).unwrap();
        let pid = std::process::id();
        let cg = RunCgroup {
            root: root.clone(),
            dir: dir.clone(),
            tail: "cg-reader/lr-stand-in".into(),
            moved: (0, 0),
            children_at_move: children_cpu_us().unwrap(),
            inside: Cell::new(false),
            exists: Cell::new(false),
        };
        let short = || Instant::now() + Duration::from_millis(200);
        // Only this process: COMPLETE.
        std::fs::write(dir.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        std::fs::write(dir.join("sub/cgroup.procs"), "").unwrap();
        let seen = cg.read_until(short()).unwrap();
        assert_eq!(seen["guest_cpu_state"], "COMPLETE", "{seen}");
        // Another process in the cgroup itself.
        std::fs::write(dir.join("cgroup.procs"), format!("{pid}\n4194999\n")).unwrap();
        let seen = cg.read_until(short()).unwrap();
        assert_eq!(seen["guest_cpu_state"], "INCOMPLETE", "{seen}");
        assert_eq!(seen["procs_left"], 1);
        assert!(seen["guest_cpu_us"].is_null());
        // Another process only in a child cgroup.
        std::fs::write(dir.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        std::fs::write(dir.join("sub/cgroup.procs"), "4194998\n").unwrap();
        let seen = cg.read_until(short()).unwrap();
        assert_eq!(seen["guest_cpu_state"], "INCOMPLETE", "{seen}");
        assert!(seen["guest_cpu_us"].is_null());
        drop(cg);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_plain_directory_is_refused_before_anything_is_created() {
        let root = scratch("cg-plain");
        let error = RunCgroup::enter(root.clone())
            .err()
            .expect("a plain directory is refused");
        assert!(error.contains("is not a cgroup v2 directory"), "{error}");
        let lr = root.join(format!("lr-{}", std::process::id()));
        assert!(!lr.exists(), "nothing was created");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn failed_cleanup_stays_failed() {
        // A stand-in that cannot be removed (a plain file inside).
        let root = scratch("cg-cleanup");
        let dir = root.join("lr-stand-in");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("cgroup.procs"), "").unwrap();
        let cg = RunCgroup {
            root: root.clone(),
            dir: dir.clone(),
            tail: "cg-cleanup/lr-stand-in".into(),
            moved: (0, 0),
            children_at_move: 0,
            inside: Cell::new(false),
            exists: Cell::new(true),
        };
        let first = cg.leave().unwrap_err();
        assert!(first.contains("cannot remove"), "{first}");
        let second = cg.leave().unwrap_err();
        assert!(
            second.contains("cannot remove"),
            "a retry does the work again: {second}"
        );
        assert!(cg.exists.get(), "not marked removed");
        // Hand the stand-in back to the test, so drop has nothing to do.
        cg.exists.set(false);
        drop(cg);
        std::fs::remove_dir_all(&root).unwrap();
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
