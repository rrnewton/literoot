//! Backend-neutral path-rewriting Reverie Tool (design §4).
//!
//! The same `RootfsTool` runs under Reverie's ptrace backend (M1 POC
//! reference + differential-oracle harness) and, unchanged, under
//! the in-guest liteinst backend (fast path) once preload packaging
//! lands — mechanism swap must not change observable behaviour
//! (design §9 comparator 3). State is replicated per process with
//! zero coordinator RPC (design §6): GlobalTool only carries the
//! immutable launch config; cwd/fd state lives in each Tool.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::GlobalRPC;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::MemoryAccess as _;
use reverie::syscalls::PathPtr;
use reverie::syscalls::ReadAddr;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo as _;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

use crate::exec_state::{ExecState, ExecStateError};
use crate::fake_creds::Ids;
use crate::shared_record::{
    shared_record_file, ProcessId, ProcessRecord, RefusalCategory, StoreError, MAX_UTS_BYTES,
};
use crate::translate::{Bind, RootConfig};

/// Serializable launch config (GlobalTool::Config).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiterootConfig {
    pub rootfs: String,
    pub binds: Vec<(String, String, bool)>, // (guest, host, no_follow)
    pub cwd: String,
    pub fake_root: bool,
    pub fake_uid: Option<u32>,
    pub fake_gid: Option<u32>,
    pub kernel_release: Option<String>,
    /// Identity-only in effect (the launcher checked the `-i` ids
    /// against its own real ids).
    #[serde(default)]
    pub identity_only: bool,
    /// --kill-on-exit: kill the whole guest tree when the
    /// initial guest process exits (proot semantics).
    #[serde(default)]
    pub kill_on_exit: bool,
    /// PROOT_FORCE_KOMPAT was set on the launcher: in
    /// post-exec auxv adjustment, move AT_RANDOM to the
    /// last vector (proot kompat forced-mode observable).
    #[serde(default)]
    pub kompat_force: bool,
    /// handle_post_exec runs at the exec stop with the
    /// guest stack pointer still at argc (ptrace backend).
    /// False on in-guest backends, where post-exec runs at
    /// the root thread's first trapped syscall and the
    /// initial-stack auxv walk must not run at all for the
    /// kompat rewrite (it could rewrite live stack words;
    /// measured dormant on this host, where the computed
    /// auxv start is unmapped and nothing is written).
    #[serde(default)]
    pub post_exec_at_exec_stop: bool,
    /// Refuse guest ptrace with EPERM (in-guest backends
    /// only, set by the launcher). Under the ptrace
    /// backend this is false and guest ptrace passes
    /// through to the kernel, which serves it subject to
    /// literoot's own tracer slot (TRACEME/tree targets
    /// EPERM, outside-pid SEIZE etc. work).
    #[serde(default)]
    pub refuse_guest_ptrace: bool,
    /// Refuse a guest call that would turn syscall user dispatch on
    /// (prctl(PR_SET_SYSCALL_USER_DISPATCH) with a mode other than OFF)
    /// with EOPNOTSUPP (in-guest backends only, set by the launcher on the
    /// same line as `refuse_guest_ptrace`). Under the ptrace backend this
    /// is false: dispatch works natively there and the Tool reads the mode.
    #[serde(default)]
    pub refuse_guest_dispatch: bool,
    /// Guest path of the initial program (argv-resolved).
    pub initial_exe: String,
    /// Full initial argv as spelled on the literoot command
    /// line (for /proc/self/cmdline synthesis).
    pub initial_argv: Vec<String>,
    /// Original stack limit to restore after the launcher capped
    /// its own soft limit for the initial loader-as-main exec.
    #[serde(default)]
    pub initial_stack_limit: Option<(u64, u64)>,
}

impl LiterootConfig {
    /// Whether the Tool runs inside the guest process (trap, liteinst): the
    /// launcher sets `refuse_guest_ptrace` exactly for those backends
    /// (tool.rs, the in-guest config).
    pub(crate) fn tool_in_guest(&self) -> bool {
        self.refuse_guest_ptrace
    }

    pub(crate) fn to_root_config(&self) -> RootConfig {
        let mut c = RootConfig::new(
            PathBuf::from(&self.rootfs),
            self.binds
                .iter()
                .map(|(g, h, nf)| Bind {
                    guest: PathBuf::from(g),
                    host: PathBuf::from(h),
                    no_follow: *nf,
                })
                .collect(),
        );
        c.fake_root = self.fake_root;
        c.fake_ids = match (self.fake_uid, self.fake_gid) {
            (Some(u), Some(g)) => Some((u, g)),
            _ => None,
        };
        c.kernel_release = self.kernel_release.clone();
        c.identity_only = self.identity_only;
        c
    }
}

/// Process-tree global state: just the immutable config (no hot-path
/// RPC is ever sent; see design §6).
#[derive(Debug, Default)]
pub struct LiterootGlobal {
    config: std::sync::OnceLock<RootConfig>,
}

/// A refusal reported to the launcher's side log (`crate::refusal_log`),
/// which writes one line per refusal, of its closed grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// A nested exec refused in-guest (`UnsupportedOperation::Exec`).
    Exec,
    /// A fork-like call refused while process forks are not allowed.
    ForkPolicy(ForkKind),
    /// A signal handler refused; the kernel signal number, 1..=64.
    SignalAction(u8),
    /// An alternate signal stack refused.
    AlternateStack,
    /// Another unsupported operation the in-guest host refused.
    Unsupported(UnsupportedKind),
    /// A refusal literoot's own Tool makes.
    Guest(GuestKind),
    /// A path refusal by name (`refused path <kind>`), one per refused call.
    Path(crate::translate::PathRefusal),
    /// Not a refusal: a native answer literoot gave for a path in a deleted
    /// directory (`answered path <kind>`), one per call.
    Answered(PathAnswer),
    /// Not a refusal: a note of something the guest did (`note ...`, or the
    /// install-attempt line).
    Note(Note),
    /// Not a refusal: one of a process's exit summaries, sent only in its
    /// exit drain. The launcher adds the batch's receipt ID when it writes it.
    Summary(Summary),
    /// A guest seccomp filter install refused at once because probes of the
    /// same thread group were in flight (S.3): their number.
    InstallRefused { in_flight: u32 },
}

/// The notes [`Refusal::Note`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Note {
    /// A guest seccomp filter install is about to be injected (written
    /// before the injection, so it records the attempt, not its result).
    FilterInstallAttempted,
    /// The constructor's dispatch OFF call answered EINVAL where that is
    /// independent evidence that the kernel has no syscall user dispatch.
    SudAbsent,
}

/// A process's exit summaries. `pid` is the pid as the Tool sees it (local
/// to the process's pid namespace in-guest), a diagnostic. `kernel_id` is
/// the pidfs inode (Linux 6.9+, else 0): kernel metadata, not
/// authenticated, not the identity; tracer-collected on ptrace only; 0 =
/// uncollected. The identity is the receipt ID the launcher assigns to the
/// whole exit batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Summary {
    /// `guest seccomp filter summary`, for a process with installs or a set
    /// flag.
    Seccomp {
        pid: i32,
        /// Kernel metadata, not authenticated, not the identity;
        /// tracer-collected on ptrace only; 0 = uncollected.
        kernel_id: u64,
        flag: crate::dead_base::FlagState,
        installs: u64,
        installs_refused: u64,
        translated: u64,
        refused: u64,
        /// The best-effort filter-count detector's refusals; defeatable by a
        /// guest that jumps to a trusted gate.
        unseen_best_effort: u64,
    },
    /// `probe summary`, for a process with probes.
    Probe {
        pid: i32,
        /// Kernel metadata, not authenticated, not the identity;
        /// tracer-collected on ptrace only; 0 = uncollected.
        kernel_id: u64,
        probes: u64,
        sud_refused: u64,
        sud_fallback: u64,
    },
}

impl Summary {
    /// The side-log line, with the batch's receipt ID.
    pub fn line(self, receipt: crate::refusal_log::ReceiptId) -> String {
        match self {
            Summary::Seccomp {
                pid,
                kernel_id,
                flag,
                installs,
                installs_refused,
                translated,
                refused,
                unseen_best_effort,
            } => format!(
                "literoot: guest seccomp filter summary pid={pid} receipt_id={receipt} \
                 kernel_id={kernel_id} flag={} installs={installs} \
                 installs_refused={installs_refused} translated={translated} refused={refused} \
                 unseen_best_effort={unseen_best_effort}",
                flag.token()
            ),
            Summary::Probe {
                pid,
                kernel_id,
                probes,
                sud_refused,
                sud_fallback,
            } => format!(
                "literoot: probe summary pid={pid} receipt_id={receipt} kernel_id={kernel_id} \
                 probes={probes} sud_refused={sud_refused} sud_fallback={sud_fallback}"
            ),
        }
    }
}

// PathRefusal lives in translate.rs, which the translation-only build
// compiles without serde, so its wire form is written here, where every
// build that sends it has serde: its index in PATH_REFUSALS, as a u32, the
// same value as a derived unit variant's index.
impl Serialize for crate::translate::PathRefusal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let index = crate::translate::PATH_REFUSALS
            .iter()
            .position(|k| k == self)
            .expect("PATH_REFUSALS lists every PathRefusal");
        serializer.serialize_u32(index as u32)
    }
}

impl<'de> Deserialize<'de> for crate::translate::PathRefusal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let index = u32::deserialize(deserializer)?;
        crate::translate::PATH_REFUSALS
            .get(index as usize)
            .copied()
            .ok_or_else(|| serde::de::Error::custom(format!("no path refusal kind {index}")))
    }
}

/// The native answers `answered path <kind>` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathAnswer {
    /// ENOENT for a name in a deleted directory.
    DeadBaseName,
    /// EACCES from the guest's own search check of a deleted base.
    DeadBaseSearch,
}

impl PathAnswer {
    /// The side-log token.
    pub fn token(self) -> &'static str {
        match self {
            PathAnswer::DeadBaseName => "dead_base_name",
            PathAnswer::DeadBaseSearch => "dead_base_search",
        }
    }
}

/// The fork-like kinds of the runtime's record: `clone` split by
/// `CLONE_THREAD` only, `clone3` unsplit (its flags are not read).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkKind {
    CloneThread,
    CloneProcess,
    Clone3,
    Fork,
    Vfork,
}

/// The in-guest host's `UnsupportedOperation` refusals other than `Exec`
/// that the side-log grammar names; every other variant, including any
/// added later (the enum is non-exhaustive), is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsupportedKind {
    NativeExec,
    ThreadCreation,
    Other,
}

impl UnsupportedKind {
    fn token(self) -> &'static str {
        match self {
            UnsupportedKind::NativeExec => "native_exec",
            UnsupportedKind::ThreadCreation => "thread_creation",
            UnsupportedKind::Other => "other",
        }
    }
}

/// Refusals literoot's own Tool makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestKind {
    /// Guest `ptrace` refused with EPERM (in-guest backends).
    Ptrace,
    /// A self-SIGSTOP after a refused `PTRACE_TRACEME`, swallowed.
    SelfStop,
    SharedRecordPublish,
    NodenameWrite,
    DomainnameWrite,
    /// proot kompat's auxv adjustment under `-k`, which the ptrace backend
    /// applies at the exec stop, is not implemented in-guest.
    KompatAuxv,
    /// The fake-identity auxv patch under `-0`/`-i` (AT_UID, AT_EUID, AT_GID,
    /// AT_EGID), which the ptrace backend applies at the exec stop, is not
    /// implemented in-guest.
    FakeIdAuxv,
    /// A guest call that would turn syscall user dispatch on, refused: the
    /// prctl with EOPNOTSUPP, or the ptrace(PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG)
    /// that in-guest backends refuse with EPERM. One kind for both.
    SyscallUserDispatch,
}

impl Refusal {
    /// The side-log line of a refusal written on its own. A summary gets a
    /// receipt of its own; a batch uses [`Refusal::line_in_batch`].
    pub fn line(self) -> String {
        self.line_in_batch(&mut None)
    }

    /// The side-log line of one refusal of a batch: every summary of the
    /// batch carries the one receipt ID, issued at the batch's first
    /// summary.
    pub fn line_in_batch(self, receipt: &mut Option<crate::refusal_log::ReceiptId>) -> String {
        let kind = |k: ForkKind| match k {
            ForkKind::CloneThread => "clone_thread",
            ForkKind::CloneProcess => "clone_process",
            ForkKind::Clone3 => "clone3",
            ForkKind::Fork => "fork",
            ForkKind::Vfork => "vfork",
        };
        match self {
            Refusal::Exec => "literoot: refused exec".into(),
            Refusal::ForkPolicy(k) => format!("literoot: refused fork_policy {}", kind(k)),
            Refusal::SignalAction(n @ 1..=64) => format!("literoot: refused signal_action {n}"),
            Refusal::SignalAction(_) => "literoot: refused unsupported other".into(),
            Refusal::AlternateStack => "literoot: refused alternate_stack".into(),
            Refusal::Unsupported(k) => format!("literoot: refused unsupported {}", k.token()),
            Refusal::Guest(k) => format!(
                "literoot: refused guest {}",
                match k {
                    GuestKind::Ptrace => "ptrace",
                    GuestKind::SelfStop => "self_stop",
                    GuestKind::SharedRecordPublish => "shared_record_publish",
                    GuestKind::NodenameWrite => "nodename_write",
                    GuestKind::DomainnameWrite => "domainname_write",
                    GuestKind::KompatAuxv => "kompat_auxv",
                    GuestKind::FakeIdAuxv => "fake_id_auxv",
                    GuestKind::SyscallUserDispatch => "syscall_user_dispatch",
                }
            ),
            // Not a refusal: the kernel's own cmdline file answered
            // (§4.9.1). The line text is not part of the wire.
            Refusal::Path(k @ crate::translate::PathRefusal::SyntheticFileUnavailable) => {
                format!("literoot: answered path {}", k.token())
            }
            Refusal::Path(k) => format!("literoot: refused path {}", k.token()),
            Refusal::Answered(k) => format!("literoot: answered path {}", k.token()),
            Refusal::Note(Note::FilterInstallAttempted) => {
                "literoot: guest seccomp filter install attempted".into()
            }
            Refusal::Note(Note::SudAbsent) => "literoot: note sud_absent".into(),
            Refusal::Summary(s) => {
                s.line(*receipt.get_or_insert_with(crate::refusal_log::next_summary_receipt))
            }
            Refusal::InstallRefused { in_flight } => {
                format!("literoot: refused seccomp_install probes_in_flight in_flight={in_flight}")
            }
        }
    }
}

/// The coordinator request: the refusals one drain found, in the order
/// drained. The launcher writes them before it answers. Each preload
/// process sends its first one even when it is empty: that report is the
/// reporting-capability acknowledgement (see [`REPORTER_ACKNOWLEDGED`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refused(pub Vec<Refusal>);

/// Set in the launcher when any preload process has reported. A preload
/// built before the refusal side log installs the bare Tool, which sends
/// no request at all, so an in-guest run that ends with this unset ran
/// without a reporter and its log cannot show its refusals.
pub static REPORTER_ACKNOWLEDGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Refusals the Tool made in this process and has not yet reported: one
/// bit per [`GuestKind`]. The in-guest wiring takes them at its next drain.
pub(crate) static PENDING_GUEST_REFUSALS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

pub(crate) const GUEST_KINDS: [GuestKind; 8] = [
    GuestKind::Ptrace,
    GuestKind::SelfStop,
    GuestKind::SharedRecordPublish,
    GuestKind::NodenameWrite,
    GuestKind::DomainnameWrite,
    GuestKind::KompatAuxv,
    GuestKind::FakeIdAuxv,
    GuestKind::SyscallUserDispatch,
];

/// Path refusals and answers the Tool made in this process and has not yet
/// reported, in order: unlike the guest kinds, every occurrence is a line.
/// The in-guest wiring takes them at its next drain. Process-wide: a test
/// that reads or drains it (or [`PENDING_GUEST_REFUSALS`]) must hold the
/// seam units' serial lock, or the units' report checks become flaky.
pub(crate) static PENDING_PATH_REPORTS: Mutex<Vec<Refusal>> = Mutex::new(Vec::new());

/// Note one path refusal or answer: written at once where the side log is
/// open here (the ptrace backend), queued for the drain in a guest process.
fn note_path_report(report: Refusal) {
    if crate::refusal_log::is_open() {
        crate::refusal_log::write_line(&report.line());
    } else {
        PENDING_PATH_REPORTS.lock().unwrap().push(report);
    }
}

/// The kernel's `struct ptrace_sud_config` (include/uapi/linux/ptrace.h).
#[repr(C)]
#[derive(Default)]
struct PtraceSudConfig {
    mode: u64,
    selector: u64,
    offset: u64,
    len: u64,
}

#[cfg(test)]
thread_local! {
    /// Test seam: when set, [`RootfsTool::shared_process_record`] looks the
    /// pid up in these rows on the calling thread instead of the store.
    pub(crate) static SHARED_ROW_SEAM: std::cell::RefCell<Option<Vec<ProcessRecord>>> =
        const { std::cell::RefCell::new(None) };
    /// With the row seam set: how many more lookups find a row (None: all
    /// of them), so a unit can make a row vanish between two lookups.
    pub(crate) static SHARED_ROW_SEAM_LOOKUPS: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test seams for [`RootfsTool::open_argv_memfd`]'s Tool-side write on
    /// the calling thread: skip the pidfd route (so the /proc/<tid>/fd
    /// route writes), and make the write fail (so the memfd is closed and
    /// the kernel's file answers).
    pub(crate) static MEMFD_PIDFD_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static MEMFD_WRITE_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The route that last wrote a memfd on this thread, so a unit can tell
    /// a pidfd write from a fall back to /proc/<tid>/fd.
    pub(crate) static MEMFD_ROUTE: std::cell::Cell<Option<MemfdRoute>> = const { std::cell::Cell::new(None) };
    /// The ptrace cmdline route reports itself unusable (a non-dumpable
    /// tracer).
    pub(crate) static TRACER_ROUTE_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A magic link's identity check fails, as when its process moves
    /// between the readlink and the stat.
    pub(crate) static LINK_IDENTITY_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A magic link's readlink answers this path instead, as when the text
    /// names another object than the link (a moved or shadowed directory):
    /// the identity check must refuse it.
    pub(crate) static LINK_TARGET_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    /// The tracer cannot inspect the guest's descriptors, as for a
    /// non-dumpable guest (such a guest still reads
    /// the synthesized argv).
    pub(crate) static GUEST_FDS_UNREADABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// [`LayoutCopy::new`]'s mprotect fails and leaves the page as it was,
    /// as when a filter on the tracer answers it EPERM.
    pub(crate) static LAYOUT_COPY_PROTECT_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// How many [`LayoutCopy`] mappings made on this thread are still
    /// mapped, so a unit can tell that a refused copy was unmapped.
    pub(crate) static LAYOUT_COPY_LIVE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The route [`write_guest_fd`] wrote through (test record).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemfdRoute {
    Pidfd,
    Procfs,
}

#[cfg(test)]
thread_local! {
    /// Test seam: when set, [`read_dispatch_config`] answers this on the
    /// calling thread instead of asking the kernel.
    pub(crate) static DISPATCH_READ_SEAM: std::cell::Cell<Option<Result<bool, i32>>> =
        const { std::cell::Cell::new(None) };
}

/// PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG on tracee `tid`, from the
/// tracer: whether its mode is ON, or the errno.
fn read_dispatch_config(tid: i32) -> Result<bool, i32> {
    #[cfg(test)]
    if let Some(answer) = DISPATCH_READ_SEAM.with(|s| s.get()) {
        return answer;
    }
    let mut config = PtraceSudConfig::default();
    let r = unsafe {
        libc::syscall(
            libc::SYS_ptrace,
            crate::dead_base::PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG as libc::c_long,
            tid as libc::c_long,
            std::mem::size_of::<PtraceSudConfig>() as libc::c_long,
            &mut config as *mut PtraceSudConfig,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(config.mode != 0)
    }
}

/// Set by the first [`note_dispatch_fallback`] of the run.
static DISPATCH_FALLBACK_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Write `literoot: sud config read unavailable errno=<name>` once per run,
/// at the first probe whose mode falls back to tracking (ptrace backend).
fn note_dispatch_fallback(errno: i32) {
    if !DISPATCH_FALLBACK_NOTED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        crate::refusal_log::write_line(&dispatch_fallback_line(errno));
    }
}

/// The fallback line for `errno`, one of the three that fall back.
fn dispatch_fallback_line(errno: i32) -> String {
    let name = match errno {
        libc::EIO => "EIO",
        libc::EINVAL => "EINVAL",
        _ => "ENOSYS",
    };
    format!("literoot: sud config read unavailable errno={name}")
}

/// The filter count expected right after arming in this image: set by the
/// preload constructor to P + 1 before Reverie's single in-process install
/// (P read before it), or 1 on the mapped route, where the image controller
/// verifies Reverie's one filter (that route is not wired yet). Unset
/// (u32::MAX), it is unknown, and the detector refuses probes. A fork child
/// inherits it with the address space; exec starts a new image.
static FILTER_BASELINE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);

/// Set this image's filter-count baseline (the expected count after arming).
#[allow(dead_code)] // The preload constructor is its caller.
pub(crate) fn set_filter_baseline(expected: u32) {
    FILTER_BASELINE.store(expected, std::sync::atomic::Ordering::Release);
}

/// This image's filter-count baseline, if set.
fn filter_baseline() -> Option<u32> {
    let n = FILTER_BASELINE.load(std::sync::atomic::Ordering::Acquire);
    (n != u32::MAX).then_some(n)
}

/// The pidfs inode of process `pid`, through a pidfd the caller (the
/// ptrace tracer) opens and closes itself: None before Linux 6.9, where a
/// pidfd is an anonymous inode that names no process, or on any failure.
fn pidfs_inode(pid: i32) -> Option<u64> {
    // include/uapi/linux/magic.h
    const PID_FS_MAGIC: i64 = 0x5049_4446;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    if fd < 0 {
        return None;
    }
    let fd = fd as libc::c_int;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let on_pidfs = unsafe { libc::fstatfs(fd, &mut fs) } == 0 && fs.f_type as i64 == PID_FS_MAGIC;
    let ino = (on_pidfs && unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino as u64);
    unsafe { libc::close(fd) };
    ino
}

/// Report a note at once, before the call it precedes: written directly
/// where the side log is open here (the ptrace backend), sent to the
/// launcher from a guest process, where a queued note would be lost with
/// the process if that call kills it.
async fn note_now<T: Guest<RootfsTool>>(guest: &T, note: Note) {
    if crate::refusal_log::is_open() {
        crate::refusal_log::write_line(&Refusal::Note(note).line());
    } else if guest.config().tool_in_guest() { // note_now: sends the note itself
        guest.send_rpc(Refused(vec![Refusal::Note(note)])).await;
    }
}

/// An install between its gate and its result (S.3). Dropped
/// without [`PendingInstall::finish`] (the installer's handler was
/// cancelled: a sibling's exec, exit_group, SIGKILL), it gives
/// install_pending back, and sets the flag if the injection may have run.
struct PendingInstall<'a> {
    state: &'a Mutex<ProcState>,
    pid: i32,
    ticket: Option<crate::dead_base::InstallTicket>,
    injecting: bool,
}

impl PendingInstall<'_> {
    /// The injection's result: a value, or a negative errno.
    fn finish(mut self, result: i64) {
        if let Some(ticket) = self.ticket.take() {
            let mut st = self.state.lock().unwrap();
            st.admission(self.pid).finish_install(ticket, Some(result));
        }
    }
}

impl Drop for PendingInstall<'_> {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        // No panic here: a poisoned lock still holds the record.
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let admission = st.admission(self.pid);
        if self.injecting {
            admission.finish_install(ticket, None);
        } else {
            admission.abandon_install(ticket);
        }
    }
}

/// Note the refusal a failed walk makes by name, if it is one.
fn note_walk_error(e: &crate::translate::WalkError) {
    if let crate::translate::WalkError::Refused(kind) = e {
        note_path_report(Refusal::Path(*kind));
    }
}

/// Note a refusal the Tool made. Where the Tool runs in the launcher
/// process (the ptrace backend) the side log is open here and the line is
/// written at once; in a guest process it waits for the wiring's drain.
fn note_guest_refusal(kind: GuestKind) {
    if crate::refusal_log::is_open() {
        crate::refusal_log::write_line(&Refusal::Guest(kind).line());
    } else {
        let bit = 1 << GUEST_KINDS.iter().position(|&k| k == kind).unwrap();
        PENDING_GUEST_REFUSALS.fetch_or(bit, std::sync::atomic::Ordering::AcqRel);
    }
}

#[reverie::global_tool]
impl GlobalTool for LiterootGlobal {
    type Request = Refused;
    type Response = ();
    type Config = LiterootConfig;

    async fn init_global_state(cfg: &Self::Config) -> Self {
        set_config(cfg.clone());
        let g = Self::default();
        let _ = g.config.set(cfg.to_root_config());
        g
    }

    async fn receive_rpc(&self, _from: Pid, msg: Refused) {
        REPORTER_ACKNOWLEDGED.store(true, std::sync::atomic::Ordering::SeqCst);
        // One receipt per batch: an exit drain's summaries are one
        // process's emission.
        let mut receipt = None;
        for refusal in msg.0 {
            crate::refusal_log::write_line(&refusal.line_in_batch(&mut receipt));
        }
    }
}

/// A per-dispatch translation memo key: (the translating thread, dirfd,
/// guest path, final symlink followed). The thread scopes it to one
/// dispatch: a thread runs one dispatch at a time, and its entries are
/// dropped when its next dispatch starts and when it exits. Keyed by thread,
/// not by a process-wide counter, because the value depends on the thread
/// (its descriptor table, its /proc/<pid>/task/<tid> paths), and on ptrace
/// another thread's dispatch can run while this one waits on an injection
/// (https://github.com/rrnewton/literoot/issues/9).
type MemoKey = (i32, i32, PathBuf, bool);
/// A translation: the host path, the symlinks its walk followed, the guest
/// route it came through (None when the name went to the kernel as is),
/// and whether it went through another process's directory link.
type Walked = (PathBuf, u32, Option<PathBuf>, OtherLink);

/// Whether a walk went through another process's directory link (`root`,
/// `cwd`, a directory `fd/<n>`), and how.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OtherLink {
    /// No such link.
    #[default]
    None,
    /// Continued from the directory's verified guest path: the route names
    /// where the walk landed.
    Spliced,
    /// Handed to the kernel with the rest of the path: the route past it
    /// names no stable guest directory.
    Raw,
}

/// Per-process replicated state (design §6).
/// Fields are `pub(crate)` so `crate::exec_state` can snapshot and
/// restore the exec-continuity subset (B4) without a second copy
/// of the layout living in two modules.
#[derive(Debug)]
pub(crate) struct ProcState {
    pub(crate) cwd: PathBuf,
    /// Fd-number state per kernel fd table (see `FdTable`). Threads
    /// share MAIN_FILES until one of them gets its own table.
    pub(crate) tables: HashMap<FilesId, FdTable>,
    /// Last id handed out by `split_files`.
    pub(crate) next_files: FilesId,
    /// Directory listing state per open file description (see
    /// `DirStream`); fd tables refer to it by id, so two tables holding
    /// one description share its position.
    pub(crate) streams: HashMap<StreamId, DirStream>,
    /// Last id handed out for a stream.
    pub(crate) next_stream: StreamId,
    /// False until the initial (launcher-issued) execve has passed:
    /// its path is already a host path and must not be translated.
    pub(crate) bootstrapped: bool,
    /// Emulated chroot: host directory acting as the new root.
    pub(crate) root_override: Option<PathBuf>,
    /// The current image's number, for the scratch pages: each thread
    /// stages in a page of its own ([`RootfsThreadState::scratch`]),
    /// tagged with the image it was mapped in. Exec draws a new one, so a
    /// page of the old image is never reused. Numbers come from one
    /// process-wide counter ([`next_scratch_image`]), so no two images
    /// share one: on ptrace a fork child's fresh state would otherwise
    /// count from 0 again and match the tag of the page it inherited.
    pub(crate) scratch_image: u64,
    /// Scratch pages of this image's exited threads, for the next new
    /// thread (zeroed before reuse): thread churn reuses pages rather
    /// than mapping one per thread ever created. Cleared at exec.
    pub(crate) free_scratch: Vec<usize>,
    /// Guest path of the current program image (for
    /// /proc/self/exe de-translation; seeded from Config).
    pub(crate) exe_guest: PathBuf,
    /// `exe_guest` is a HOST path: the file an execve reached through
    /// another process's directory link has no guest name.
    /// An open of the own exe opens that file as is,
    /// readlink answers it, and the shared row publishes no exe.
    pub(crate) exe_host: bool,
    /// As-exec'd argv of the current image (cmdline synthesis).
    pub(crate) argv: Vec<Vec<u8>>,
    /// Stateful fake identity (r/e/s uid+gid) under -0/-i:
    /// setres* must be observable via getres* afterwards.
    pub(crate) fake: Option<[u32; 6]>,
    /// Fake filesystem uid and gid, once a set*id call under
    /// identity-only sets them; until then, and after an exec (where
    /// the kernel resets them), the fake effective ids.
    pub(crate) fake_fs: Option<(u32, u32)>,
    /// Dispatch counter, bumped at every dispatch: keys `config_memo` (a
    /// value no thread changes) and `gate_closed_at`.
    pub(crate) dispatch_seq: u64,
    /// Per-dispatch translations (stat-gap fix: one syscall dispatch
    /// translates the same (dirfd, path) through several helpers), with the
    /// symlinks each walk followed and the guest route it came through,
    /// each keyed by its thread ([`MemoKey`]). Never lives across a thread's
    /// dispatches, so no cross-syscall staleness is possible.
    pub(crate) translate_memo: Vec<(MemoKey, Result<Walked, crate::translate::WalkError>)>,
    /// The (thread, dirfd) bases whose ".." climb out of a deleted
    /// directory the guest's own search check passed in that thread's
    /// current dispatch (E1): only those climbs translate. Keyed by thread
    /// as [`MemoKey`] is (https://github.com/rrnewton/literoot/issues/9).
    pub(crate) searched_bases: Vec<(i32, i32)>,
    /// The dispatch whose dead-base gate was found closed at the top of the
    /// route (S.3 placement), with the dispatch mode it read: the arm's own
    /// dead-base refusal counts it once (`probes`, `refused`, `sud_refused`).
    /// One slot per process, keyed by the shared `dispatch_seq`: when sibling
    /// threads dispatch at once, a closed-gate count can be lost or land on
    /// another thread's dispatch. Only these diagnostic counters can be
    /// wrong; the refusal itself never depends on the slot. (The memo and
    /// the searched bases, once the same class, are keyed by thread.)
    pub(crate) gate_closed_at: Option<GateClosed>,
    /// Probe admission for this thread group (S.3).
    pub(crate) admission: crate::dead_base::Admission,
    /// RootConfig built for the current dispatch (same keying: a
    /// RootConfig rebuild re-canonicalizes every bind prefix, which
    /// probes the host filesystem; several helpers per dispatch ask
    /// for the config).
    pub(crate) config_memo: Option<(u64, Option<PathBuf>, RootConfig)>,
    /// Original `(soft, hard)` RLIMIT_STACK values to restore in
    /// `handle_post_exec` after a through-interpreter exec ran with
    /// a temporarily finite soft limit. This is process state, not
    /// thread state: resource limits are per process, and an exec
    /// from any thread de-threads into the same leader Tool state.
    pub(crate) pending_stack_limit: Option<(u64, u64)>,
    /// Whether the launch config's one-shot initial stack-limit
    /// restore has been consumed by this process.
    pub(crate) initial_stack_limit_consumed: bool,
    /// This process has been registered for --kill-on-exit
    /// in the pid registry (creation-time registration).
    pub(crate) kill_registered: bool,
}

/// Which kernel fd table a task of this process uses. Every thread starts
/// on MAIN_FILES (a fork child's tables start from its parent's); a thread
/// leaves it for a copy on unshare(CLONE_FILES),
/// close_range(CLOSE_RANGE_UNSHARE), or a thread clone without CLONE_FILES,
/// as the kernel copies the table then.
pub(crate) type FilesId = u32;
pub(crate) const MAIN_FILES: FilesId = 0;

/// Which directory stream (open file description) an fd number holds.
pub(crate) type StreamId = u64;

/// The fd-number state of one kernel fd table. A number means something
/// only in its own table: a record another table invalidates stays valid
/// here. Listing progress is not per number but per open file description
/// (`DirStream`), shared by every table that still holds it.
#[derive(Debug, Clone, Default)]
pub(crate) struct FdTable {
    /// fd → guest path it denotes (for *at resolution, §4.3).
    pub(crate) fds: HashMap<i32, PathBuf>,
    /// Fds opened on virtual bind-prefix dirs: fd → guest dir.
    pub(crate) virtual_fds: HashMap<i32, PathBuf>,
    /// fd → the directory stream of the description it holds.
    pub(crate) streams: HashMap<i32, StreamId>,
}

impl FdTable {
    /// Forget the per-fd state of a number that now holds another file (or
    /// none): its virtual-directory record and its stream belong to the file
    /// the number held before. Other tables keep theirs; the stream itself
    /// goes when no table holds it (`ProcState::forget`). Returns the stream
    /// the number held.
    pub(crate) fn forget(&mut self, fd: i32) -> Option<StreamId> {
        self.virtual_fds.remove(&fd);
        self.streams.remove(&fd)
    }
}

/// Listing state of one open directory description. Linux keeps the
/// position in the open file, which a table copy shares (dup_fd,
/// fs/file.c), so literoot's synthetic part of a listing is shared the
/// same way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DirStream {
    /// Virtual bind-prefix dir: its entries were emitted.
    pub(crate) emitted: bool,
    /// Real dir with bind children: synthetic dirents still to serve after
    /// kernel EOF; `Some` (maybe empty) once kernel EOF was reached.
    pub(crate) pending: Option<Vec<u8>>,
    /// Names the kernel already returned (dedupe).
    pub(crate) seen: Option<std::collections::HashSet<String>>,
    /// (dev, ino) of the directory this listing state was built for: a dup
    /// of another directory onto the number makes it stale.
    pub(crate) obj: Option<(u64, u64)>,
}

impl ProcState {
    /// Exec's new image for the scratch pages: the number advances, so a
    /// page of the old image (a thread exec killed holds one) is never
    /// queued, and the queued ones, unmapped now, are dropped.
    pub(crate) fn new_scratch_image(&mut self) {
        self.scratch_image = next_scratch_image();
        self.free_scratch.clear();
    }

    /// This process's S.3 record, made its own first (a fork child's copy
    /// of its parent's record is replaced: `Admission::adopt`).
    pub(crate) fn admission(&mut self, pid: i32) -> &mut crate::dead_base::Admission {
        self.admission.adopt(pid);
        &mut self.admission
    }

    /// A new thread group starts here (its first thread's start carried
    /// the flag its parent's clone staged): its record replaces whatever
    /// this state held, whatever the pid.
    pub(crate) fn start_new_group(&mut self, pid: i32, group: crate::dead_base::NewGroup) {
        self.admission = crate::dead_base::Admission::for_child(group);
        self.admission.adopt(pid);
    }

    /// The fd-number state of table `files` (empty if it has none yet).
    pub(crate) fn fdt(&self, files: FilesId) -> &FdTable {
        static EMPTY: std::sync::LazyLock<FdTable> = std::sync::LazyLock::new(FdTable::default);
        self.tables.get(&files).unwrap_or(&EMPTY)
    }

    pub(crate) fn fdt_mut(&mut self, files: FilesId) -> &mut FdTable {
        self.tables.entry(files).or_default()
    }

    /// The stream number `fd` of table `files` holds, if it has one.
    pub(crate) fn stream(&self, files: FilesId, fd: i32) -> Option<&DirStream> {
        self.fdt(files)
            .streams
            .get(&fd)
            .and_then(|id| self.streams.get(id))
    }

    /// The stream number `fd` of table `files` holds, created empty (and
    /// held by this table only) if it has none.
    pub(crate) fn stream_mut(&mut self, files: FilesId, fd: i32) -> &mut DirStream {
        let id = match self.fdt(files).streams.get(&fd) {
            Some(id) if self.streams.contains_key(id) => *id,
            _ => {
                self.next_stream += 1;
                let id = self.next_stream;
                self.fdt_mut(files).streams.insert(fd, id);
                id
            }
        };
        self.streams.entry(id).or_default()
    }

    /// Forget number `fd` of table `files` (see `FdTable::forget`), and the
    /// stream it held once no table holds that stream any more. Only a
    /// number that held a stream costs a scan of the tables.
    pub(crate) fn forget(&mut self, files: FilesId, fd: i32) {
        let Some(id) = self.fdt_mut(files).forget(fd) else {
            return;
        };
        if !self
            .tables
            .values()
            .any(|t| t.streams.values().any(|s| *s == id))
        {
            self.streams.remove(&id);
        }
    }

    /// A task left table `from` for a private copy of it. The copy starts
    /// with the same records, and with the same streams: the kernel's copy
    /// holds the same open files, whose positions stay shared. Every number
    /// the table knows gets its stream first, so a listing started after
    /// the split is shared too, and a stream without an identity takes the
    /// object the number holds now (`identity`, read while the task is
    /// stopped): a later dup onto the number in one table must not lend its
    /// object to the stream the other tables hold. A number whose stream was
    /// built for another object than it holds now (a dup onto it that
    /// literoot did not see) leaves that stream to its other holders first,
    /// so both tables share a fresh one for the object it holds.
    pub(crate) fn split_files(
        &mut self,
        from: FilesId,
        identity: impl Fn(i32) -> Option<(u64, u64)>,
    ) -> FilesId {
        let t = self.fdt(from);
        let known: Vec<i32> = t.fds.keys().chain(t.virtual_fds.keys()).copied().collect();
        for fd in known {
            let now = identity(fd);
            let held = self.stream(from, fd).and_then(|s| s.obj);
            if held.is_some() && now.is_some() && held != now {
                self.forget(from, fd);
            }
            let s = self.stream_mut(from, fd);
            if s.obj.is_none() {
                s.obj = now;
            }
        }
        self.next_files += 1;
        let copy = self.fdt(from).clone();
        self.tables.insert(self.next_files, copy);
        self.next_files
    }
}

/// The calling task's fd table.
fn files_of<T: Guest<RootfsTool>>(guest: &T) -> FilesId {
    guest.thread_state().files
}

/// The literoot Tool: one instance per guest process.
#[derive(Debug)]
pub struct RootfsTool {
    state: Mutex<ProcState>,
}

// Tool requires Default; real config arrives via GlobalState, cwd
// is seeded from Config in `new_tool`-equivalent first use. For the
// POC the launcher passes cwd inside Config and each process reads
// it lazily (see `proc_cwd`).
impl Default for RootfsTool {
    fn default() -> Self {
        Self {
            state: Mutex::new(ProcState {
                cwd: PathBuf::from("/__literoot_unset__"),
                tables: HashMap::new(),
                next_files: MAIN_FILES,
                streams: HashMap::new(),
                next_stream: 0,
                bootstrapped: false,
                root_override: None,
                scratch_image: next_scratch_image(),
                free_scratch: Vec::new(),
                exe_guest: PathBuf::new(),
                exe_host: false,
                fake: None,
                fake_fs: None,
                dispatch_seq: 0,
                translate_memo: Vec::new(),
                searched_bases: Vec::new(),
                gate_closed_at: None,
                admission: Default::default(),
                config_memo: None,
                kill_registered: false,
                argv: Vec::new(),
                pending_stack_limit: None,
                initial_stack_limit_consumed: false,
            }),
        }
    }
}

/// Per-thread carrier for one pending exec snapshot (B4). Its
/// only job is to hold the snapshot taken just before the final
/// exec inject until `handle_post_exec` (same Tool under ptrace,
/// sealed successor state on the native route) consumes it.
/// `None` on every non-exec path, so the common case is inert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsThreadState {
    pub pending: Option<ExecState>,
    /// The fd table this thread uses (`FilesId`).
    #[serde(default)]
    pub files: FilesId,
    /// Staged by a clone handler for the task it creates: the parent's
    /// table (CLONE_FILES), a fresh copy (a thread without CLONE_FILES),
    /// or MAIN_FILES of a new process. Cleared after the inject.
    #[serde(default)]
    pub child_files: Option<FilesId>,
    /// Staged by a process-creating clone handler: what the new thread
    /// group's S.3 record starts with (`Admission::new_group`: the
    /// conservative flag and the expected-count addend). Staged for every
    /// process-creating clone, independent of the fork seed, so it is never
    /// lost. Cleared after the inject.
    #[serde(default)]
    pub child_group: Option<crate::dead_base::NewGroup>,
    /// A new thread group's first thread: what its record starts with,
    /// applied at its start (the lifecycle signal of a new group).
    #[serde(default)]
    pub new_group: Option<crate::dead_base::NewGroup>,
    /// Staged by a clone handler whose child would share this process's
    /// address space, and so its S.3 record, in-guest
    /// ([`shares_record_in_guest`]). Cleared after the inject.
    #[serde(default)]
    pub child_shares_record: bool,
    /// This thread's tracked syscall-user-dispatch mode (true = ON), from
    /// its own prctl calls (C1.1, C2.2). A new thread starts OFF, as the
    /// kernel clears it (kernel/fork.c), and exec resets it.
    #[serde(default)]
    pub sud_on: bool,
    /// This thread's scratch page, where it stages the paths, names and
    /// arguments of its injections. One per thread: a page shared by the
    /// process's threads let one thread's staging overwrite another's
    /// before that one's call read it. None until first used.
    #[serde(default)]
    pub scratch: Option<ScratchPage>,
    /// Staged by a clone handler for the task it creates: the caller's
    /// page for a new process that cannot run while the caller stages
    /// (fork's copy is the child's own; a vfork caller is suspended until
    /// the child execs or exits), else none, as for a thread or a
    /// CLONE_VM process. Cleared after the inject.
    #[serde(default)]
    pub child_scratch: Option<ScratchPage>,
    /// Armed by this thread's refused PTRACE_TRACEME until its next
    /// intercepted (subscribed) syscall dispatch or exec: guests that
    /// ignore the TRACEME result and immediately self-SIGSTOP would stop
    /// untraced with nobody to continue them, so the Kill arm swallows that
    /// one self-stop. Taken (cleared) at this thread's every dispatch entry
    /// and on exec. Per thread, so another thread's dispatch never takes it
    /// (https://github.com/rrnewton/literoot/issues/9). It is NOT cleared by
    /// unsubscribed syscalls (read/write/getpid/... never reach this Tool),
    /// so a later legitimate self-stop after only unsubscribed syscalls is
    /// still swallowed: the accepted leftover window, a known limitation.
    #[serde(default)]
    pub swallow_self_stop: bool,
}

/// A thread's scratch slot (4096 bytes of an injected anonymous mmap) and
/// the image it was mapped in ([`ProcState::scratch_image`]). On a 64 KiB
/// kernel the 16 slots of one mmap share one kernel page with no guard page
/// between them, so the explicit length checks are what bound every staged
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchPage {
    pub addr: usize,
    pub image: u64,
}

// A wrapping Tool with the same thread state forwards its guest to
// `RootfsTool` through `Guest::into_guest`, which asks for these.
impl AsRef<RootfsThreadState> for RootfsThreadState {
    fn as_ref(&self) -> &RootfsThreadState {
        self
    }
}

impl AsMut<RootfsThreadState> for RootfsThreadState {
    fn as_mut(&mut self) -> &mut RootfsThreadState {
        self
    }
}

fn refusal_label(category: RefusalCategory) -> &'static str {
    match category {
        RefusalCategory::Publish => "publish",
        RefusalCategory::UtsNodename => "UTS nodename write",
        RefusalCategory::UtsDomainname => "UTS domainname write",
    }
}

/// Per-category refusal counts for this Tool-host process.
/// The first refusal and every hundredth are reported; all
/// intermediate refusals are counted and suppressed. Rows
/// are not reaped yet, so unconditional reporting would
/// otherwise print on every fork/exec after the store fills.
struct RefusalReporter {
    publish: std::sync::atomic::AtomicU64,
    nodename: std::sync::atomic::AtomicU64,
    domainname: std::sync::atomic::AtomicU64,
}

impl RefusalReporter {
    const fn new() -> Self {
        Self {
            publish: std::sync::atomic::AtomicU64::new(0),
            nodename: std::sync::atomic::AtomicU64::new(0),
            domainname: std::sync::atomic::AtomicU64::new(0),
        }
    }

    // `is_multiple_of` needs Rust 1.87; the package MSRV is 1.85.
    #[allow(clippy::manual_is_multiple_of)]
    fn message_for_count(category: RefusalCategory, count: u64, detail: &str) -> Option<String> {
        if count == 1 {
            Some(format!(
                "literoot: shared record {} refused: {detail}",
                refusal_label(category)
            ))
        } else if count % 100 == 0 {
            Some(format!(
                "literoot: shared record {} refused: {detail} \
                 ({count} refusals so far; intermediate reports suppressed)",
                refusal_label(category)
            ))
        } else {
            None
        }
    }

    fn message(&self, category: RefusalCategory, detail: &str) -> Option<String> {
        let counter = match category {
            RefusalCategory::Publish => &self.publish,
            RefusalCategory::UtsNodename => &self.nodename,
            RefusalCategory::UtsDomainname => &self.domainname,
        };
        let count = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        Self::message_for_count(category, count, detail)
    }
}

static SHARED_RECORD_REFUSALS: RefusalReporter = RefusalReporter::new();

fn report_shared_record_refusal(
    category: RefusalCategory,
    err: &StoreError,
    detail: String,
) {
    // Cap refusals are counted in the frame header under
    // the exclusive lock the refusing write already held,
    // and that session count arrives with the error. The
    // per-process limiter is only the fallback for errors
    // with no persisted count (above all the 5 s lock
    // timeout); in-guest it therefore prints at most once
    // per program image for those.
    note_guest_refusal(match category {
        RefusalCategory::Publish => GuestKind::SharedRecordPublish,
        RefusalCategory::UtsNodename => GuestKind::NodenameWrite,
        RefusalCategory::UtsDomainname => GuestKind::DomainnameWrite,
    });
    let message = match err.refusal_count() {
        Some(count) => RefusalReporter::message_for_count(category, count, &detail),
        None => SHARED_RECORD_REFUSALS.message(category, &detail),
    };
    if let Some(message) = message {
        eprintln!("{message}");
    }
}

impl RootfsTool {
    /// This process's exit summaries (S.3, C3): the seccomp summary for a
    /// process with installs or a set flag, the probe summary for one with
    /// probes. Exactly one emission per process: empty once taken. The
    /// caller sends them in one batch, which the launcher gives one receipt
    /// ID; on the ptrace backend [`RootfsTool::on_exit_process`] writes
    /// them itself.
    pub fn take_exit_summaries(&self, pid: i32) -> Vec<Refusal> {
        let mut st = self.state.lock().unwrap();
        let a = st.admission(pid);
        let (seccomp, probe) = (a.seccomp_summary_due(), a.probe_summary_due());
        if !(seccomp || probe) || !a.begin_emission() {
            return Vec::new();
        }
        let kernel_id = a.kernel_id.unwrap_or(0);
        let mut out = Vec::new();
        if seccomp {
            out.push(Refusal::Summary(Summary::Seccomp {
                pid,
                kernel_id,
                flag: a.flag,
                installs: a.installs,
                installs_refused: a.installs_refused,
                translated: a.translated,
                refused: a.refused,
                unseen_best_effort: a.unseen_best_effort,
            }));
        }
        if probe {
            out.push(Refusal::Summary(Summary::Probe {
                pid,
                kernel_id,
                probes: a.probes,
                sud_refused: a.sud_refused,
                sud_fallback: a.sud_fallback,
            }));
        }
        out
    }

    /// Reconstruct a Tool from a predecessor snapshot. The
    /// successor consumer seam (B4 step 3) builds on this; B4-1
    /// ships it behind unit tests only — no successor transport
    /// calls it yet.
    #[allow(dead_code)]
    pub fn from_exec_state(
        state: ExecState,
        cfg: &RootConfig,
    ) -> Result<Self, ExecStateError> {
        let tool = Self::default();
        {
            let mut st = tool.state.lock().unwrap();
            state.apply_to(&mut st, cfg)?;
            // Exec keeps the S.3 record; only a successor
            // applies it, never a fork restore.
            st.admission = state.record.admission();
        }
        Ok(tool)
    }

    /// Snapshot continuity state into the pending slot, called
    /// immediately before each final exec inject (direct,
    /// `exec_via_interp`, `exec_script`), after the handler has
    /// written the successor's `exe_guest`/argv, and before
    /// process-creating clone-family injects (step 4). Capture
    /// failure (over the size cap) refuses the syscall by name
    /// before injection rather than completing it degraded.
    fn stage_snapshot<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
        let snapshot = {
            let st = self.state.lock().unwrap();
            ExecState::capture(&st, files_of(guest), guest.config())
        };
        // Prove the canonical bytes fit the cap now, while refusal
        // is still possible, then stage them into the host birth
        // mailbox on the mapped successor route. The synchronous
        // ack must complete before the caller injects exec; any
        // staging refusal refuses this syscall before injection.
        // On routes without a recorded coordinator endpoint this
        // is inert and the pending slot remains the carrier.
        let encoded = snapshot.encode().map_err(|e| match e {
            ExecStateError::TooLarge => reverie::syscalls::Errno::E2BIG,
            _ => reverie::syscalls::Errno::EIO,
        })?;
        crate::exec_stage::stage_snapshot(encoded)?;
        guest.thread_state_mut().pending = Some(snapshot);
        Ok(())
    }

    /// The argv the `/proc/self/cmdline` path materializes for
    /// this process: replicated argv if present, else the launch
    /// `initial_argv`. Locks and drops state before returning.
    fn current_argv(&self, cfg: &LiterootConfig) -> Vec<Vec<u8>> {
        let argv = self.state.lock().unwrap().argv.clone();
        if argv.is_empty() {
            cfg.initial_argv
                .iter()
                .map(|arg| arg.clone().into_bytes())
                .collect()
        } else {
            argv
        }
    }

    /// Start-time-qualified identity for a guest pid, learned
    /// from the host `/proc` stat for that exact process. A
    /// missing/unparseable stat is absence: callers retain
    /// today's bare-pid process-local maps rather than mint a
    /// row that could alias a reused pid.
    fn guest_process_id(pid: i32) -> Option<ProcessId> {
        let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
        parse_process_start_time(&stat, pid)
    }

    /// Publish this process's current exe/argv row after a
    /// successful exec or a fork-seed restore. Best effort by
    /// design: no shared store (or an unavailable/corrupt one)
    /// leaves every existing process-local behavior intact.
    fn publish_self_shared<T: Guest<Self>>(&self, guest: &T) {
        let Some(store) = shared_record_file() else {
            return;
        };
        let Some(id) = Self::guest_process_id(guest.pid().as_raw()) else {
            return;
        };
        let raw_exe = self.exe_guest(guest);
        // An exe with no guest name publishes none: other processes then
        // read the kernel's link.
        let exe_guest = if self.state.lock().unwrap().exe_host {
            Vec::new()
        } else {
            self.canonical_exe(guest, &raw_exe).as_os_str().as_bytes().to_vec()
        };
        let row = ProcessRecord {
            id,
            exe_guest,
            argv: self.current_argv(guest.config()),
        };
        if let Err(err) = store.publish(row) {
            report_shared_record_refusal(
                RefusalCategory::Publish,
                &err,
                format!("for pid {}: {err}", id.pid),
            );
        }
    }

    fn shared_process_record(pid: i32) -> Option<ProcessRecord> {
        #[cfg(test)]
        if let Some(rows) = SHARED_ROW_SEAM.with(|s| s.borrow().clone()) {
            let left = SHARED_ROW_SEAM_LOOKUPS.with(|n| n.get());
            if let Some(n) = left {
                if n == 0 {
                    return None;
                }
                SHARED_ROW_SEAM_LOOKUPS.with(|c| c.set(Some(n - 1)));
            }
            return rows.into_iter().find(|row| row.id.pid == pid);
        }
        let id = Self::guest_process_id(pid)?;
        shared_record_file()?.lookup(id).ok().flatten()
    }

    fn set_shared_uts_nodename(name: Vec<u8>) {
        if let Some(store) = shared_record_file() {
            if let Err(err) = store.set_uts_nodename(Some(name)) {
                report_shared_record_refusal(
                    RefusalCategory::UtsNodename,
                    &err,
                    err.to_string(),
                );
            }
        }
    }

    fn set_shared_uts_domainname(name: Vec<u8>) {
        if let Some(store) = shared_record_file() {
            if let Err(err) = store.set_uts_domainname(Some(name)) {
                report_shared_record_refusal(
                    RefusalCategory::UtsDomainname,
                    &err,
                    err.to_string(),
                );
            }
        }
    }

    /// A clone's mount-namespace record: a new
    /// process left the tracer's mount namespace with CLONE_NEWNS, or
    /// inherits its parent's having left it. A thread cloned with
    /// CLONE_NEWNS (the kernel refuses it with CLONE_FS) has a namespace of
    /// its own; the record is per process, so the caller's process counts
    /// as moved, conservatively, as an unshare does.
    fn note_child_mount_ns<T: Guest<Self>>(&self, guest: &T, flags: u64, ret: &Result<i64, reverie::syscalls::Errno>) {
        let Ok(child) = ret else { return };
        if *child <= 0 {
            return;
        }
        let new_ns = flags & libc::CLONE_NEWNS as u64 != 0;
        if !clone_is_process(flags) {
            if new_ns {
                note_mount_ns_moved(guest.pid().as_raw());
            }
        } else if new_ns || mount_ns_moved(guest.pid().as_raw()) {
            note_mount_ns_moved(*child as i32);
        }
    }

    /// Stage a fork seed for a process-creating clone. The
    /// accessor-produced current exe/argv are computed *before*
    /// the capture state lock below (`exe_guest` locks state
    /// internally, as does `current_argv`), so the codec never
    /// re-resolves them against config or the current cwd.
    fn stage_fork_snapshot<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
        let current_exe = self.exe_guest(guest);
        let current_argv = self.current_argv(guest.config());
        let snapshot = {
            let st = self.state.lock().unwrap();
            match fork_seed_if_bootstrapped(
                &st,
                files_of(guest),
                guest.config(),
                &current_exe,
                &current_argv,
            ) {
                Some(seed) => seed?,
                None => {
                    // Named seed refusal, not a guest clone
                    // failure: the clone proceeds unstaged
                    // rather than applying a seed whose restore
                    // would force bootstrapped.
                    eprintln!("literoot: fork seed refused: parent not bootstrapped");
                    return Ok(());
                }
            }
        };
        // Same fit proof as the exec staging path: refuse before
        // injection rather than completing the clone degraded.
        snapshot.encode().map_err(|e| match e {
            ExecStateError::TooLarge => reverie::syscalls::Errno::E2BIG,
            _ => reverie::syscalls::Errno::EIO,
        })?;
        guest.thread_state_mut().pending = Some(snapshot);
        Ok(())
    }

    /// Drop a staged snapshot after a failed exec inject. A
    /// successful inject never returns, so every return path past
    /// staging is a failure; the next exec re-stages from live
    /// state, so clearing here is belt-and-braces made explicit.
    fn clear_exec_snapshot<T: Guest<Self>>(&self, guest: &mut T) {
        guest.thread_state_mut().pending = None;
    }

    /// Serve the whole pending synthetic records of `fd` (table `files`)
    /// that fit the guest's getdents64 buffer. None when nothing is pending,
    /// or when the next record does not fit the buffer at all (it is
    /// dropped): the kernel answers then.
    fn serve_pending<T: Guest<Self>>(
        &self,
        guest: &mut T,
        files: FilesId,
        fd: i32,
        gd: &reverie::syscalls::Getdents64,
    ) -> Option<i64> {
        use reverie::syscalls::MemoryAccess as _;
        let mut st = self.state.lock().unwrap();
        let id = *st.fdt(files).streams.get(&fd)?;
        let pend = st.streams.get_mut(&id)?.pending.as_mut()?;
        if pend.is_empty() {
            return None;
        }
        let mut take = 0usize;
        while take + 19 <= pend.len() {
            let reclen = u16::from_ne_bytes([pend[take + 16], pend[take + 17]]) as usize;
            if reclen < 19 || take + reclen > gd.count() as usize {
                break;
            }
            take += reclen;
        }
        if take == 0 {
            pend.clear();
            return None;
        }
        let chunk: Vec<u8> = pend.drain(..take).collect();
        drop(st);
        let dirent = gd.dirent()?;
        let addr: reverie::syscalls::AddrMut<u8> = unsafe { std::mem::transmute_copy(&dirent) };
        let _ = guest.memory().write(addr, &chunk);
        Some(chunk.len() as i64)
    }

    /// Stage the fd table of the task a clone with `flags` creates: a new
    /// process starts on MAIN_FILES (its tables come from the fork seed), a
    /// thread with CLONE_FILES shares the caller's table, and a thread
    /// without it gets a copy, as the kernel copies the table.
    fn stage_child_files<T: Guest<Self>>(&self, guest: &mut T, flags: u64) {
        let own = files_of(guest);
        let in_guest = guest.config().tool_in_guest(); // shared-record tripwire
        guest.thread_state_mut().child_shares_record = shares_record_in_guest(in_guest, flags);
        // A vfork child shares the caller's page. A caller without one takes
        // a free page first: otherwise the child, on ptrace a new process
        // with a fresh Tool and no free pages, maps a whole pool in the
        // shared address space on every spawn, which the caller's process
        // never reuses. With no page free (or a failed zeroing) the caller
        // stays without one and the child maps its own, as before.
        let vm_vfork = (libc::CLONE_VM | libc::CLONE_VFORK) as u64;
        if clone_is_process(flags) && flags & vm_vfork == vm_vfork && guest.thread_state().scratch.is_none() {
            let _ = self.take_free_page(guest);
        }
        let page = guest.thread_state().scratch;
        guest.thread_state_mut().child_scratch = child_scratch(flags, page);
        let child = if clone_is_process(flags) {
            let pid = guest.pid().as_raw();
            let group = self.state.lock().unwrap().admission(pid).new_group();
            guest.thread_state_mut().child_group = Some(group);
            MAIN_FILES
        } else if flags & libc::CLONE_FILES as u64 != 0 {
            own
        } else {
            self.state
                .lock()
                .unwrap()
                .split_files(own, |fd| fd_identity(guest, fd))
        };
        guest.thread_state_mut().child_files = Some(child);
    }

    /// After a clone inject: drop the staged id, and the copy made for a
    /// thread that was never created.
    fn end_child_files<T: Guest<Self>>(&self, guest: &mut T, created: bool) {
        guest.thread_state_mut().child_group = None;
        guest.thread_state_mut().child_scratch = None;
        if std::mem::take(&mut guest.thread_state_mut().child_shares_record) && created {
            // The tripwire of `shares_record_in_guest`: Reverie created a
            // child that shares this record. Stop rather than run on.
            eprintln!(
                "literoot: fatal: an in-guest clone created a process sharing literoot's \
                 process record (CLONE_VM without CLONE_THREAD)"
            );
            std::process::abort();
        }
        let Some(child) = guest.thread_state_mut().child_files.take() else {
            return;
        };
        if !created && child != MAIN_FILES && child != files_of(guest) {
            self.state.lock().unwrap().tables.remove(&child);
        }
    }

    /// Read the guest's stack resource limit.
    #[cfg(target_arch = "aarch64")]
    async fn get_stack_limit<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(u64, u64), reverie::syscalls::Errno> {
        use reverie::Stack as _;

        let mut stack = guest.stack().await;
        let old_ptr = stack.reserve::<libc::rlimit64>();
        let _guard = stack.commit()?;
        let call = reverie::syscalls::Prlimit64::new()
            .with_pid(0)
            .with_resource(RLIMIT_STACK)
            .with_new_rlim(None)
            .with_old_rlim(Some(old_ptr));
        guest.inject(call).await?;
        let addr: reverie::syscalls::Addr<u8> =
            unsafe { reverie::syscalls::Addr::from_raw_unchecked(old_ptr.as_raw()) };
        let mut bytes = [0u8; 16];
        guest.memory().read(addr, &mut bytes)?;
        Ok((
            u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        ))
    }

    /// Replace the guest's stack resource limit without reading it.
    async fn set_stack_limit<T: Guest<Self>>(
        &self,
        guest: &mut T,
        (rlim_cur, rlim_max): (u64, u64),
    ) -> Result<(), reverie::syscalls::Errno> {
        use reverie::Stack as _;

        let mut stack = guest.stack().await;
        let new_ptr = stack.push(libc::rlimit64 { rlim_cur, rlim_max });
        let _guard = stack.commit()?;
        let call = reverie::syscalls::Prlimit64::new()
            .with_pid(0)
            .with_resource(RLIMIT_STACK)
            .with_new_rlim(Some(new_ptr))
            .with_old_rlim(None);
        guest.inject(call).await?;
        Ok(())
    }

    /// Temporarily make an unlimited stack limit finite for one
    /// through-interpreter exec. On AArch64, `RLIM_INFINITY` selects
    /// the kernel's legacy bottom-up mmap layout; an ET_DYN loader
    /// image then starts at TASK_UNMAPPED_BASE with [vvar] directly
    /// above its last segment, so no heap can grow from its break.
    /// `RLIM_INFINITY - 1` is the least finite deviation: the kernel
    /// clamps its stack gap to MAX_GAP (STACK_TOP / 6 * 5; about
    /// 213 TiB with the measured host's 48-bit stack top), and the
    /// exact original limit is restored in `handle_post_exec` before
    /// the new image runs. This handles only the stack-limit trigger;
    /// `ADDR_COMPAT_LAYOUT` and `vm.legacy_va_layout=1` select the
    /// same layout on generic arm64 and x86 kernel paths and remain
    /// unhandled. X86 is unaffected by this stack-limit trigger, so
    /// the cap is a no-op there.
    ///
    /// The record lives in process-level Tool state because resource
    /// limits are per process and a successful exec de-threads into
    /// the leader. The window is still process-wide: another thread
    /// that forks, reads, or sets RLIMIT_STACK between the cap and
    /// restore can observe or overwrite the temporary value. A fork
    /// in that window inherits the capped limit without a record in
    /// its own fresh Tool state.
    async fn begin_interp_exec_stack_limit<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
        #[cfg(target_arch = "aarch64")]
        {
            let old = self.get_stack_limit(guest).await?;
            if old.0 == libc::RLIM64_INFINITY {
                self.state.lock().unwrap().pending_stack_limit = Some(old);
                if let Err(error) = self
                    .set_stack_limit(guest, (libc::RLIM64_INFINITY - 1, old.1))
                    .await
                {
                    self.state.lock().unwrap().pending_stack_limit = None;
                    return Err(error);
                }
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        let _ = guest;
        Ok(())
    }

    /// Restore a stack limit capped by
    /// `begin_interp_exec_stack_limit`, if one is pending.
    async fn restore_pending_stack_limit<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
        let limits = {
            let mut st = self.state.lock().unwrap();
            if st.pending_stack_limit.is_none() && !st.initial_stack_limit_consumed {
                st.initial_stack_limit_consumed = true;
                st.pending_stack_limit = guest.config().initial_stack_limit;
            }
            st.pending_stack_limit
        };
        let Some(limits) = limits else {
            return Ok(());
        };
        self.set_stack_limit(guest, limits).await?;
        self.state.lock().unwrap().pending_stack_limit = None;
        Ok(())
    }

    /// What an execve handler writes before its injection: the exe record,
    /// its host flag, the argv, and this pid's entries in the bare-pid maps.
    fn exec_identity<T: Guest<Self>>(&self, guest: &T) -> ExecIdentity {
        let pid = guest.pid().as_raw();
        let st = self.state.lock().unwrap();
        ExecIdentity {
            exe_guest: st.exe_guest.clone(),
            exe_host: st.exe_host,
            argv: st.argv.clone(),
            pid_exe: pid_exe_map().lock().unwrap().get(&pid).cloned(),
            pid_argv: pid_argv_map().lock().unwrap().get(&pid).cloned(),
        }
    }

    /// Put back what [`Self::exec_identity`] took, after a failed exec.
    fn restore_exec_identity<T: Guest<Self>>(&self, guest: &T, prior: ExecIdentity) {
        let pid = guest.pid().as_raw();
        match prior.pid_exe {
            Some(exe) => pid_exe_map().lock().unwrap().insert(pid, exe),
            None => pid_exe_map().lock().unwrap().remove(&pid),
        };
        match prior.pid_argv {
            Some(argv) => pid_argv_map().lock().unwrap().insert(pid, argv),
            None => pid_argv_map().lock().unwrap().remove(&pid),
        };
        let mut st = self.state.lock().unwrap();
        st.exe_guest = prior.exe_guest;
        st.exe_host = prior.exe_host;
        st.argv = prior.argv;
    }

    /// Invalidate a mailbox-staged exec snapshot after a failed
    /// inject, then drop the local pending copy. If the host
    /// invalidation cannot be delivered, the pending copy is
    /// restored and the failure replaces the inject result:
    /// the caller must not treat the mailbox as clear.
    fn invalidate_exec_snapshot<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
        let Some(snapshot) = guest.thread_state_mut().pending.take() else {
            return Ok(());
        };
        match crate::exec_stage::invalidate_snapshot() {
            Ok(()) => Ok(()),
            Err(error) => {
                guest.thread_state_mut().pending = Some(snapshot);
                Err(error)
            }
        }
    }

    /// Apply a pending snapshot staged by the predecessor image
    /// (exec) or parent process (fork), if any. Validation runs
    /// against the launch config (not a config already folded
    /// with an override). A bad snapshot is a fatal admission
    /// error — never fall back to launch-config seeding, which is
    /// exactly the state loss B4 exists to remove. Returns
    /// whether a snapshot was consumed.
    fn consume_pending<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<bool, reverie::syscalls::Errno> {
        let Some(state) = guest.thread_state_mut().pending.take() else {
            return Ok(false);
        };
        let cfg = guest.config().to_root_config();
        {
            let mut st = self.state.lock().unwrap();
            state
                .apply_to(&mut st, &cfg)
                .map_err(|_| reverie::syscalls::Errno::EINVAL)?;
        }
        // apply_to leaves one table, MAIN_FILES, holding the snapshot's.
        guest.thread_state_mut().files = MAIN_FILES;
        // Backward compatibility for the ptrace-era guard: a
        // restored process is never the initial image.
        LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(true)
    }
}

/// Parse Linux `/proc/<pid>/stat` field 22 (`starttime`).
/// The comm field may contain spaces and parentheses, so the
/// numeric tail is taken after the final `)`: its first token
/// is field 3, making start time index 19 in that tail.
fn parse_process_start_time(stat: &[u8], pid: i32) -> Option<ProcessId> {
    // Keep this on raw bytes: the kernel comm is a truncated
    // filename and can split a non-ASCII character, so the
    // whole stat line is not guaranteed to be valid UTF-8.
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    let prefix = &stat[..close];
    let tail = &stat[close + 1..];
    let raw_pid_token = prefix
        .split(|byte| byte.is_ascii_whitespace())
        .find(|token| !token.is_empty())?;
    let raw_pid: i32 = std::str::from_utf8(raw_pid_token).ok()?.parse().ok()?;
    if raw_pid != pid {
        return None;
    }
    let start_token = tail
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
        .nth(19)?;
    let start_time: u64 = std::str::from_utf8(start_token).ok()?.parse().ok()?;
    ProcessId::new(pid, start_time).ok()
}

/// The empty-current-exe return branch of `RootfsTool::exe_guest`,
/// extracted so the accessor and its tests share exactly one
/// implementation. `launch_cwd` is the guest config's launch cwd;
/// empty means "/" exactly as `seed_cwd` defines it.
fn initial_exe_guest(initial_exe: &str, launch_cwd: &str, cfg: &RootConfig) -> PathBuf {
    if initial_exe.is_empty() {
        return PathBuf::from("/proc/self/exe");
    }
    let p = PathBuf::from(initial_exe);
    if p.is_absolute() {
        return p;
    }
    let seed_cwd = if launch_cwd.is_empty() {
        Path::new("/")
    } else {
        Path::new(launch_cwd)
    };
    let host = cfg.translate(&p, seed_cwd, None);
    cfg.reverse(&host).unwrap_or(p)
}

/// Build a fork seed from accessor-produced current exe/argv.
/// Refuses by name (`EINVAL`) for a not-yet-bootstrapped
/// parent: `apply_to` would force `bootstrapped = true` in the
/// child and silently skip its launcher-exec transition,
/// because `ExecState` does not carry that bit.
fn fork_seed(
    st: &ProcState,
    files: FilesId,
    cfg: &LiterootConfig,
    current_exe: &Path,
    current_argv: &[Vec<u8>],
) -> Result<ExecState, reverie::syscalls::Errno> {
    if !st.bootstrapped {
        return Err(reverie::syscalls::Errno::EINVAL);
    }
    Ok(ExecState::capture_fork_seed(
        st,
        files,
        cfg,
        current_exe,
        current_argv,
    ))
}

/// The production staging gate: `None` means do not stage a
/// seed for this clone (the caller logs the named refusal and
/// lets the clone proceed unstaged). Guest-free so the exact
/// decision production uses is unit-testable.
fn fork_seed_if_bootstrapped(
    st: &ProcState,
    files: FilesId,
    cfg: &LiterootConfig,
    current_exe: &Path,
    current_argv: &[Vec<u8>],
) -> Option<Result<ExecState, reverie::syscalls::Errno>> {
    if !st.bootstrapped {
        return None;
    }
    Some(fork_seed(st, files, cfg, current_exe, current_argv))
}

/// B4 step 4 staging decision: snapshot for a new *process*, never
/// for a new thread in the same thread group. Unreadable clone3
/// args read back as empty flags (CloneFamily::flags), which
/// stages — safe, because that clone fails in the kernel and the
/// handler clears the snapshot on return.
fn clone_is_process(flags: u64) -> bool {
    flags & (libc::CLONE_THREAD as u64) == 0
}

/// Whether a clone with `flags` creates a new process that shares the
/// caller's address space (CLONE_VM without CLONE_THREAD; vfork) while the
/// Tool runs in the guest: that child would share this process's S.3 record
/// rather than hold a copy, and `Admission::adopt` relies on a copy.
/// Reverie's in-guest host forwards only plain forks and refuses every
/// other clone, clone3 and vfork (R reverie-inguest guest/host.rs:5282-5298),
/// so none is ever created; the clone handlers make a created one a named
/// fatal error (`end_child_files`), never a shared record.
fn shares_record_in_guest(in_guest: bool, flags: u64) -> bool {
    in_guest && clone_is_process(flags) && flags & libc::CLONE_VM as u64 != 0
}

/// The scratch page the task a clone with `flags` starts with, given the
/// caller's `page`. A new process without CLONE_VM keeps it: fork copies
/// the mapping, so the child's copy is its own. A vfork child
/// (CLONE_VM | CLONE_VFORK) shares it: the caller is suspended until the
/// child execs or exits, with nothing staged (its clone handler stages no
/// slot), and the child writes every slot before reading it. A thread or
/// any other CLONE_VM process gets none and maps or reuses its own, as two
/// tasks that run at once must never stage in one page.
fn child_scratch(flags: u64, page: Option<ScratchPage>) -> Option<ScratchPage> {
    let vm = flags & libc::CLONE_VM as u64 != 0;
    let vfork = flags & libc::CLONE_VFORK as u64 != 0;
    if clone_is_process(flags) && (!vm || vfork) {
        page
    } else {
        None
    }
}

// Reverie's ptrace guest-stack arena is ~896 bytes total; stage at
// most 768 bytes of translated path (POC limit — the in-guest
// backend uses Tool-region scratch instead, design §6).
const PATH_BUF: usize = 768;

/// close_range(2) flags (include/uapi/linux/close_range.h), defined here
/// because not every libc target carries them.
const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// `prlimit64`'s resource number for the stack limit, as the syscall
/// builder's `u32`: glibc's libc defines it as `u32`, musl's as `i32`.
#[allow(clippy::unnecessary_cast)]
const RLIMIT_STACK: u32 = libc::RLIMIT_STACK as u32;


#[cfg(target_arch = "x86_64")]
fn guest_stack_pointer(regs: &libc::user_regs_struct) -> u64 {
    regs.rsp
}
#[cfg(not(target_arch = "x86_64"))]
fn guest_stack_pointer(regs: &libc::user_regs_struct) -> u64 {
    regs.sp
}

#[reverie::tool]
impl Tool for RootfsTool {
    type GlobalState = LiterootGlobal;
    type ThreadState = RootfsThreadState;

    fn new(pid: Pid, cfg: &LiterootConfig) -> Self {
        // Creation-time registration (fork event under ptrace,
        // process construction in-guest): a fork child that only
        // sleeps/writes/exits may make no subscribed syscall
        // before the root exits, so first-syscall registration
        // alone would miss it.
        if cfg.kill_on_exit {
            register_guest_pid(pid.as_raw());
        }
        Default::default()
    }

    async fn on_exit_process<G: GlobalRPC<LiterootGlobal>>(
        self,
        pid: Pid,
        _global_state: &G,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        // The exit summaries, where the side log is open here (the ptrace
        // backend): one receipt for this process's emission. A guest
        // process's reporter takes them into its exit drain instead.
        if crate::refusal_log::is_open() {
            let mut receipt = None;
            for summary in self.take_exit_summaries(pid.as_raw()) {
                crate::refusal_log::write_line(&summary.line_in_batch(&mut receipt));
            }
        }
        // Preserve the root guest's real exit status for the
        // launcher: if it later terminates a wedged tracer
        // session (kill-on-exit grace expiry), wait() surfaces
        // the termination cause instead of this status.
        if pid.as_raw() == FIRST_GUEST_PID.load(std::sync::atomic::Ordering::SeqCst) {
            let raw = exit_status.into_raw();
            // Test hook (kill_on_exit delayed-status test):
            // defer the record on a side thread so the
            // launcher's sweep gate is exercised against a
            // late status. Debug builds only: in release
            // builds the variable is never read, so it
            // cannot silently disable kill-on-exit.
            #[cfg(debug_assertions)]
            if let Ok(ms) = std::env::var("LITEROOT_TEST_DELAY_ROOT_STATUS_MS") {
                if let Ok(ms) = ms.parse::<u64>() {
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(ms));
                        ROOT_EXIT_RAW.store(raw, std::sync::atomic::Ordering::SeqCst);
                    });
                    return Ok(());
                }
            }
            ROOT_EXIT_RAW.store(raw, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    fn subscriptions(_cfg: &LiterootConfig) -> Subscription {
        let mut subs = Subscription::none();
        subs.syscalls([
            Sysno::openat,
            Sysno::readlinkat,
            Sysno::fchdir,
            Sysno::execve,
            Sysno::chdir,
            Sysno::getcwd,
            Sysno::unlinkat,
            Sysno::mkdirat,
            Sysno::faccessat,
            Sysno::renameat,
            Sysno::renameat2,
            Sysno::linkat,
            Sysno::symlinkat,
            Sysno::mknodat,
            Sysno::fchownat,
            Sysno::fchown,
            Sysno::fchmodat,
            Sysno::statfs,
            Sysno::utimensat,
            Sysno::statx,
            Sysno::uname,
            Sysno::getuid,
            Sysno::geteuid,
            Sysno::getgid,
            Sysno::getegid,
            Sysno::getresuid,
            Sysno::getresgid,
            Sysno::setuid,
            Sysno::setgid,
            Sysno::setreuid,
            Sysno::setregid,
            Sysno::setresuid,
            Sysno::setresgid,
            Sysno::setfsuid,
            Sysno::setfsgid,
            Sysno::setgroups,
            Sysno::sethostname,
            Sysno::setdomainname,
            Sysno::chroot,
            Sysno::getdents64,
            Sysno::openat2,
            Sysno::name_to_handle_at,
            Sysno::open_by_handle_at,
            Sysno::ptrace,
            Sysno::kill,
            Sysno::capset,
            Sysno::setxattr,
            Sysno::lsetxattr,
            Sysno::fsetxattr,
            Sysno::bind,
            Sysno::connect,
            Sysno::getsockname,
            // B4 step 4: snapshot-and-tail-inject only (no
            // semantic change to the syscall itself).
            Sysno::clone,
            Sysno::clone3,
            // Fd-table ownership (FilesId): both can give the caller its
            // own copy of the table. unshare and setns can also move the
            // caller out of the tracer's mount namespace, which the ptrace
            // cmdline route depends on.
            Sysno::unshare,
            Sysno::close_range,
            Sysno::setns,
            // S.3: a guest seccomp filter install is tracked and admitted
            // (`seccomp_install`); every other call of either is forwarded
            // unchanged.
            Sysno::seccomp,
            Sysno::prctl,
        ]);
        // Legacy non-*at syscalls exist only in the x86-64 table; the
        // aarch64 generic table carries the *at forms subscribed above
        // (plus fstatat for stat/lstat/newfstatat).
        #[cfg(target_arch = "x86_64")]
        subs.syscalls([
            Sysno::open,
            Sysno::stat,
            Sysno::lstat,
            Sysno::access,
            Sysno::newfstatat,
            Sysno::readlink,
            Sysno::rename,
            Sysno::link,
            Sysno::symlink,
            Sysno::rmdir,
            Sysno::unlink,
            Sysno::mkdir,
            Sysno::chmod,
            Sysno::chown,
            Sysno::lchown,
            Sysno::fork,
            Sysno::vfork,
        ]);
        #[cfg(target_arch = "aarch64")]
        subs.syscalls([Sysno::fstatat]);
        subs
    }

    fn init_thread_state(
        &self,
        _child: reverie::Tid,
        parent: Option<(reverie::Tid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        // B4 step 4: the child inherits exactly the snapshot the
        // parent staged for this process-creating clone (the
        // handler stages only then, and clears its own copy after
        // inject; init runs inside that inject, so ordering is
        // stage -> clone-to-child -> parent clear). Unstaged
        // parents and process-tree roots clone nothing.
        match parent {
            Some((_, parent)) => RootfsThreadState {
                pending: parent.pending.clone(),
                files: parent.child_files.unwrap_or(parent.files),
                child_files: None,
                child_group: None,
                new_group: parent.child_group,
                child_shares_record: false,
                sud_on: false,
                scratch: parent.child_scratch,
                child_scratch: None,
                swallow_self_stop: false,
            },
            None => RootfsThreadState::default(),
        }
    }

    async fn handle_thread_start<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), Error> {
        // In-guest creation seam for --kill-on-exit: the initial
        // thread of every new process starts here, including fork
        // children whose Tool construction path may not call
        // Tool::new.
        self.note_process_for_kill_on_exit(guest);
        // Adopt and identity-check the shared descriptor at the
        // first lifecycle hook, before ordinary guest execution
        // gets an opportunity to close/replace the number.
        let _ = shared_record_file();
        // Fork-child restore: apply the inherited snapshot to the
        // child's fresh Tool before ordinary execution. Threads
        // (never staged) take the None fast path, unchanged.
        let restored = self.consume_pending(guest)?;
        if restored {
            self.publish_self_shared(guest);
        }
        // A new thread group's record (S.3): fresh counters, and the flag
        // and addend its parent's clone staged. The staged value arrives
        // through init_thread_state (`new_group`) or, in-guest, as the
        // memory copy of the forking thread's own state (`child_group`),
        // which is cleared here. It is the lifecycle signal: the visible
        // pid can equal the copied record's owner (pid 1 of a new pid
        // namespace).
        let staged = {
            let ts = guest.thread_state_mut();
            ts.new_group.take().or(ts.child_group.take())
        };
        if let Some(group) = staged {
            let pid = guest.pid().as_raw();
            self.state.lock().unwrap().start_new_group(pid, group);
            self.note_kernel_id(guest);
        }
        self.first_callback_check(guest).await;
        Ok(())
    }

    async fn on_exit_thread<G: GlobalRPC<LiterootGlobal>>(
        &self,
        tid: reverie::Tid,
        _global_state: &G,
        thread_state: RootfsThreadState,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let mut st = self.state.lock().unwrap();
        // An exited thread's admitted probes can no longer inject (S.3).
        st.admission.release_thread(tid.as_raw());
        // Its translations and searched bases (keyed by thread) go with it.
        st.translate_memo.retain(|((t, ..), _)| *t != tid.as_raw());
        st.searched_bases.retain(|(t, _)| *t != tid.as_raw());
        // Its scratch page, for the next new thread: only a page of this
        // image (a thread that exec killed held a page of the old one, now
        // unmapped), and never twice (a vfork child shares its caller's
        // page, but a vfork child is another process, with its own state).
        if let Some(page) = thread_state.scratch {
            if page.image == st.scratch_image && !st.free_scratch.contains(&page.addr) {
                st.free_scratch.push(page.addr);
            }
        }
        drop(st);
        // A tracer memfd held for a restarted cmdline open of it is done.
        release_held_tracer_fd(tid.as_raw());
        Ok(())
    }

    async fn handle_post_exec<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
        // This restore is part of the exec itself, not optional
        // post-exec work: it must run even under LITEROOT_NO_POSTEXEC.
        self.restore_pending_stack_limit(guest).await?;
        if std::env::var_os("LITEROOT_NO_POSTEXEC").is_some() {
            return Ok(());
        }
        // B4 restore: a pending snapshot (staged by the
        // predecessor image at its final inject) is applied before
        // anything else observes state, so the scratch realloc,
        // fake set-id transition, comm restore and auxv patch
        // below compose on top of predecessor state.
        self.consume_pending(guest)?;
        // The initial launcher exec has passed in this process;
        // later forks may stage seeds whose restore forces this
        // same post-bootstrap state in the child.
        {
            let mut st = self.state.lock().unwrap();
            st.bootstrapped = true;
            // New image: every previous scratch mapping is gone.
            st.new_scratch_image();
            // The kernel resets the filesystem ids to the effective ids.
            st.fake_fs = None;
        }
        // Exec resets the thread's syscall user dispatch mode.
        guest.thread_state_mut().sud_on = false;
        guest.thread_state_mut().scratch = None;
        // A pending self-stop swallow does not survive exec.
        guest.thread_state_mut().swallow_self_stop = false;
        // Pre-allocate the exec'ing thread's scratch page here, with the
        // pool for this image's new threads: injecting an mmap between a
        // guest's two execve calls was measured to make the second fail
        // EFAULT, and a new thread then maps nothing until the pool is used
        // up.
        let _ = self.map_scratch(guest).await;
        self.publish_self_shared(guest);
        // Setuid/setgid exec under fake identity: euid/suid take
        // the file owner's fake id (owner == real caller maps to
        // 0 by proot's fake-id rule; test-getresid-native).
        if self.fake_ids(guest).is_some() {
            use std::os::unix::fs::MetadataExt as _;
            let exe = self.own_exe_route(guest, libc::AT_FDCWD);
            // Best-effort, as before the link budget: a tree changed
            // after the exec (now past 40 links) skips the mapping.
            let host = self.translate_follow(guest, libc::AT_FDCWD, &exe);
            if let Some(md) = host.ok().and_then(|host| std::fs::metadata(host).ok()) {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = md.permissions().mode();
                let real_uid = unsafe { libc::getuid() };
                let real_gid = unsafe { libc::getgid() };
                let fake_cfg = self.fake_ids(guest);
                let mut st = self.state.lock().unwrap();
                let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                {
                    if mode & 0o4000 != 0 {
                        let mapped = if md.uid() == real_uid { 0 } else { md.uid() };
                        f[1] = mapped;
                        f[2] = mapped;
                    }
                    if mode & 0o2000 != 0 {
                        let mapped = if md.gid() == real_gid { 0 } else { md.gid() };
                        f[4] = mapped;
                        f[5] = mapped;
                    }
                }
            }
        }
        // Our interp/shebang exec routes make the kernel comm
        // name the loader/interpreter; restore the program's
        // basename (test-proc-comm-name-truncation). Best-effort:
        // failure leaves the kernel name.
        use reverie::Stack as _;
        let exe = self.exe_guest(guest);
        let base = exe
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if base.is_empty() {
            return Ok(());
        }
        let mut cell = [0u8; 16];
        let bytes = base.as_bytes();
        let n = bytes.len().min(15);
        cell[..n].copy_from_slice(&bytes[..n]);
        // Stage via scratch page, NOT the guest stack: at
        // post-exec the stack top holds argv/env strings that
        // a later execve must copy intact (measured EFAULT).
        if let Ok(addr) = self.scratch_write(guest, &cell).await {
            let prctl = reverie::syscalls::Prctl::new()
                .with_option(libc::PR_SET_NAME)
                .with_arg2(addr as u64);
            let _ = guest.inject(prctl).await;
        }
        // Auxv patching: fake AT_UID/EUID/GID/EGID under fake
        // identity; zero AT_HWCAP when -k requests it (proot's
        // UTS form carries hwcap as field 7; a plain release
        // string leaves it alone). On the ptrace backend
        // only (post_exec_at_exec_stop), with any -k spoof
        // also apply proot kompat's auxv adjustment: discard
        // AT_SYSINFO/AT_SYSINFO_EHDR (under Reverie ptrace
        // the EHDR points at Reverie's canonical vDSO, whose
        // fixed version note still bypasses the spoof), and
        // in forced mode move AT_RANDOM to the last vector.
        // In-guest this walk must not run for kompat: there
        // handle_post_exec runs at the first trapped syscall
        // with live stack frames below the pointer, so
        // in-guest kompat auxv adjustment is not implemented.
        let fake = self.fake_ids(guest);
        let zero_hwcap = guest
            .config()
            .kernel_release
            .as_deref()
            .map(|k| k.contains('\\'))
            .unwrap_or(false);
        let kompat = guest.config().kernel_release.is_some()
            && guest.config().post_exec_at_exec_stop;
        if !guest.config().post_exec_at_exec_stop {
            // In-guest: post-exec runs at the first trapped syscall, so the
            // initial-stack walk below does not patch the guest's auxv, which
            // therefore differs from the ptrace backend's. The walk still runs,
            // from the live stack pointer, and can write the word after any
            // 11/12/13/14 (16 with zero_hwcap) it meets there (gating the
            // walk is a follow-up). Each is keyed once per exec (C3 amendments
            // kompat_auxv and fake_id_auxv). `zero_hwcap` needs `-k`, so
            // kompat_auxv covers it.
            if guest.config().kernel_release.is_some() {
                note_guest_refusal(GuestKind::KompatAuxv);
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot-tool: kompat auxv skipped: post-exec not at exec stop");
                }
            }
            if fake.is_some() {
                note_guest_refusal(GuestKind::FakeIdAuxv);
            }
        }
        let kompat_force = kompat && guest.config().kompat_force;
        // C4: the initial-stack walk. It patches the auxv only at the ptrace
        // exec stop; in-guest it still runs, from the live stack, does not
        // patch the auxv, and can write live stack words. Every
        // disjunct below is keyed in the in-guest branch above
        // (tests/c4_backend_branches.rs).
        if fake.is_some() || zero_hwcap || kompat {
            use reverie::syscalls::MemoryAccess as _;
            {
                let regs = guest.regs().await;
                let mut mem = guest.memory();
                let read64 = |mem: &<T as Guest<Self>>::Memory, at: u64| -> Option<u64> {
                    let a: reverie::syscalls::Addr<u8> =
                        unsafe { reverie::syscalls::Addr::from_raw_unchecked(at as usize) };
                    let mut b = [0u8; 8];
                    mem.read(a, &mut b).ok()?;
                    Some(u64::from_ne_bytes(b))
                };
                if let Some(argc) = read64(&mem, guest_stack_pointer(&regs)) {
                    // stack: argc, argv[argc+1], envp[n+1], auxv pairs
                    // (checked: argc is guest-controlled and must
                    // not overflow the offset in a debug build).
                    let Some(mut p) = argc
                        .checked_add(1)
                        .and_then(|n| n.checked_mul(8))
                        .and_then(|n| n.checked_add(8))
                        .and_then(|n| guest_stack_pointer(&regs).checked_add(n))
                    else {
                        return Ok(());
                    };
                    for _ in 0..4096 {
                        match read64(&mem, p) {
                            Some(0) => {
                                p += 8;
                                break;
                            }
                            Some(_) => p += 8,
                            None => break,
                        }
                    }
                    let auxv_start = p;
                    let mut pair_count = 0usize;
                    let mut random_pair: Option<(usize, u64)> = None;
                    for idx in 0..64 {
                        let (Some(ty), Some(val)) =
                            (read64(&mem, p), read64(&mem, p + 8))
                        else {
                            break;
                        };
                        if ty == 0 {
                            break;
                        }
                        pair_count = idx + 1;
                        if ty == 25 {
                            random_pair = Some((idx, val));
                        }
                        // Kompat discard: rewrite the pair in
                        // place to AT_IGNORE/0 (proot
                        // adjust_elf_auxv semantics). Type 32
                        // (AT_SYSINFO) is kept for parity with
                        // proot; the kernel gives it only to
                        // 32-bit processes, whose 4-byte auxv
                        // words this 8-byte walk never sees.
                        if kompat && (ty == 32 || ty == 33) {
                            let at: reverie::syscalls::AddrMut<u8> = unsafe {
                                reverie::syscalls::AddrMut::from_raw_unchecked(
                                    p as usize,
                                )
                            };
                            let av: reverie::syscalls::AddrMut<u8> = unsafe {
                                reverie::syscalls::AddrMut::from_raw_unchecked(
                                    (p + 8) as usize,
                                )
                            };
                            let _ = mem.write(at, &1u64.to_ne_bytes());
                            let _ = mem.write(av, &0u64.to_ne_bytes());
                            p += 16;
                            continue;
                        }
                        let new_val = match (ty, fake) {
                            (11, Some((u, _))) => Some(u as u64),
                            (12, Some((u, _))) => Some(u as u64),
                            (13, Some((_, g))) => Some(g as u64),
                            (14, Some((_, g))) => Some(g as u64),
                            (16, _) if zero_hwcap => Some(0),
                            _ => None,
                        };
                        if let Some(nv) = new_val {
                            if nv != val {
                                let a: reverie::syscalls::AddrMut<u8> = unsafe {
                                    reverie::syscalls::AddrMut::from_raw_unchecked(
                                        (p + 8) as usize,
                                    )
                                };
                                let _ = mem.write(a, &nv.to_ne_bytes());
                            }
                        }
                        p += 16;
                    }
                    // Forced kompat: AT_RANDOM must be the last
                    // vector. Deliberate deviation from proot:
                    // proot keeps the original AT_RANDOM and
                    // appends a second one whose value is the
                    // auxv array's own address; literoot moves
                    // the kernel's own pair to the end instead,
                    // so glibc's _dl_random keeps the real
                    // random pointer. Auxv readers scan the
                    // whole table, so the move is inert for
                    // every reader except exact-order observers
                    // like LD_SHOW_AUXV.
                    if kompat_force {
                        if let Some((ridx, rval)) = random_pair {
                            if pair_count > 0 && ridx + 1 < pair_count {
                                let src = auxv_start + ((ridx + 1) * 16) as u64;
                                let len = (pair_count - ridx - 1) * 16;
                                let mut buf = vec![0u8; len];
                                let sa: reverie::syscalls::Addr<u8> = unsafe {
                                    reverie::syscalls::Addr::from_raw_unchecked(
                                        src as usize,
                                    )
                                };
                                if mem.read_exact(sa, &mut buf).is_ok() {
                                    let da: reverie::syscalls::AddrMut<u8> = unsafe {
                                        reverie::syscalls::AddrMut::from_raw_unchecked(
                                            (auxv_start + (ridx * 16) as u64) as usize,
                                        )
                                    };
                                    if mem.write_exact(da, &buf).is_ok() {
                                        let last = auxv_start + ((pair_count - 1) * 16) as u64;
                                        let lt: reverie::syscalls::AddrMut<u8> = unsafe {
                                            reverie::syscalls::AddrMut::from_raw_unchecked(
                                                last as usize,
                                            )
                                        };
                                        let lv: reverie::syscalls::AddrMut<u8> = unsafe {
                                            reverie::syscalls::AddrMut::from_raw_unchecked(
                                                (last + 8) as usize,
                                            )
                                        };
                                        let _ = mem.write_exact(lt, &25u64.to_ne_bytes());
                                        let _ = mem.write_exact(lv, &rval.to_ne_bytes());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }


    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        // New dispatch of this thread: its translation memo entries and
        // searched bases are dropped (never consulted across its
        // dispatches), and its self-stop swallow is taken: it is armed until
        // this next intercepted dispatch; unsubscribed syscalls never reach
        // here and do not clear it. Only this thread's: another thread's
        // dispatch may be waiting on an injection meanwhile, with its entries
        // live (https://github.com/rrnewton/literoot/issues/9).
        let swallow_armed = {
            let tid = guest.tid().as_raw();
            let mut st = self.state.lock().unwrap();
            st.dispatch_seq = st.dispatch_seq.wrapping_add(1);
            st.translate_memo.retain(|((t, ..), _)| *t != tid);
            st.searched_bases.retain(|(t, _)| *t != tid);
            drop(st);
            std::mem::take(&mut guest.thread_state_mut().swallow_self_stop)
        };
        self.note_process_for_kill_on_exit(guest);
        if std::env::var_os("LITEROOT_DEBUG").is_some() {
            eprintln!("literoot-tool: syscall {:?}", syscall.number());
        }
        // Seed pid->exe for /proc/<pid>/exe of the initial
        // program (its own Tool may never call exe_guest).
        {
            let init = guest.config().initial_exe.clone();
            if !init.is_empty() {
                pid_exe_map()
                    .lock()
                    .unwrap()
                    .entry(guest.pid().as_raw())
                    .or_insert_with(|| {
                        let p = PathBuf::from(&init);
                        if p.is_absolute() {
                            self.canonical_exe(guest, &p)
                        } else {
                            p
                        }
                    });
            }
        }
        // aarch64 has no fork/vfork syscalls; only clone/clone3.
        let fork_like = match syscall.number() {
            #[cfg(target_arch = "x86_64")]
            reverie::syscalls::Sysno::fork | reverie::syscalls::Sysno::vfork => true,
            reverie::syscalls::Sysno::clone | reverie::syscalls::Sysno::clone3 => true,
            _ => false,
        };
        if let Some(answer) = self.seccomp_install(guest, syscall).await {
            return answer;
        }
        if let Some(answer) = self.dispatch_setter(guest, syscall).await {
            return answer;
        }
        if let Some(answer) = self.dead_base_gate(guest, syscall).await {
            return answer;
        }
        let result = match syscall {
            Syscall::Openat(openat) => {
                // O_CREAT opens can create components (kind
                // changes); plain opens cannot — gate the bump
                // to creators to keep the read hot path free of
                // shared-atomic writes.
                let _probe_bump = if openat.flags().contains(
                    reverie::syscalls::OFlag::O_CREAT,
                ) {
                    Some(ProbeBumpOnDrop)
                } else {
                    None
                };
                let Some(path_ptr) = openat.path() else {
                    return Ok(guest.inject(openat).await?);
                };
                let mut guest_path = path_ptr.read(&guest.memory())?;
                if self.dirfd_passthrough(guest, openat.dirfd(), &guest_path) {
                    return Ok(guest.inject(openat).await?);
                }
                // The self links are decided by the selected final
                // entry, not by the spelling. Another process's entries are
                // the kernel's.
                let follow = open_follows(openat.flags().bits() as u64);
                match self.self_link_route(guest, openat.dirfd(), &guest_path, follow)? {
                    SelfLink::Exe => guest_path = self.own_exe_route(guest, openat.dirfd()),
                    SelfLink::RowExe(pid) => {
                        if let Some(exe) = Self::row_exe_guest(pid) {
                            guest_path = exe;
                        }
                    }
                    SelfLink::Cmdline(pid) => {
                        if let Some(fd) = self.open_synthetic_cmdline(guest, pid, CmdlineOpen::Openat(openat)).await? {
                            return Ok(fd);
                        }
                    }
                    SelfLink::SharedCmdline(pid) => {
                        if let Some(fd) = self.open_shared_cmdline(guest, pid, CmdlineOpen::Openat(openat)).await? {
                            return Ok(fd);
                        }
                    }
                    SelfLink::Walk => {}
                }
                // O_NOFOLLOW opens the final symlink itself (O_PATH) or
                // fails ELOOP, and O_CREAT|O_EXCL fails EEXIST at it, so the
                // final component is not followed here.
                let host = if !follow {
                    self.translate_for(guest, openat.dirfd(), &guest_path)?
                } else {
                    self.translate_follow(guest, openat.dirfd(), &guest_path)?
                };
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        openat.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_guard);
                let mut opened_virtual = false;
                // Virtual bind-prefix directory: open the
                // nearest real ancestor and synthesize entries
                // in getdents64 (readdir nested bindings).
                let first = match first {
                    Err(e) if e == reverie::syscalls::Errno::ENOENT => {
                        let abs = {
                            let st = self.state.lock().unwrap();
                            self.guest_abs(guest, &st, openat.dirfd(), &guest_path)
                        };
                        if self.is_virtual_bind_dir(guest, &abs) {
                            match self.open_virtual_dir(guest, openat, &abs).await? {
                                Some(fd) => {
                                    opened_virtual = fd >= 0;
                                    Ok(fd)
                                }
                                None => Err(e),
                            }
                        } else {
                            Err(e)
                        }
                    }
                    other => other,
                };
                let ret = match first {
                    Ok(r) => r,
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        let saved = self.chmod_ancestors(&host);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &host, |ptr| {
                                openat.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        r2?
                    }
                    Err(e) => return Err(e.into()),
                };
                if ret >= 0 {
                    // Record fd → guest path for future *at calls.
                    let mut st = self.state.lock().unwrap();
                    let abs = self.guest_abs(guest, &st, openat.dirfd(), &guest_path);
                    let files = files_of(guest);
                    if !opened_virtual {
                        st.forget(files, ret as i32);
                    }
                    st.fdt_mut(files).fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Open(open) => {
                // Legacy open(2): musl ld.so uses it (measured:
                // without this arm, musl guests loaded host files).
                let _probe_bump = if open.flags().contains(
                    reverie::syscalls::OFlag::O_CREAT,
                ) {
                    Some(ProbeBumpOnDrop)
                } else {
                    None
                };
                let Some(path_ptr) = open.path() else {
                    return Ok(guest.inject(open).await?);
                };
                let mut guest_path = path_ptr.read(&guest.memory())?;
                // Legacy open decides as openat does, by the selected
                // final entry.
                let follow = open_follows(open.flags().bits() as u64);
                match self.self_link_route(guest, libc::AT_FDCWD, &guest_path, follow)? {
                    SelfLink::Exe => guest_path = self.own_exe_route(guest, libc::AT_FDCWD),
                    SelfLink::RowExe(pid) => {
                        if let Some(exe) = Self::row_exe_guest(pid) {
                            guest_path = exe;
                        }
                    }
                    SelfLink::Cmdline(pid) => {
                        if let Some(fd) = self.open_synthetic_cmdline(guest, pid, CmdlineOpen::Open(open)).await? {
                            return Ok(fd);
                        }
                    }
                    SelfLink::SharedCmdline(pid) => {
                        if let Some(fd) = self.open_shared_cmdline(guest, pid, CmdlineOpen::Open(open)).await? {
                            return Ok(fd);
                        }
                    }
                    SelfLink::Walk => {}
                }
                let host = if !follow {
                    self.translate_for(guest, libc::AT_FDCWD, &guest_path)?
                } else {
                    self.translate_follow(guest, libc::AT_FDCWD, &guest_path)?
                };
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        open.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret >= 0 {
                    let mut st = self.state.lock().unwrap();
                    let abs = self.guest_abs(guest, &st, libc::AT_FDCWD, &guest_path);
                    let files = files_of(guest);
                    st.forget(files, ret as i32);
                    st.fdt_mut(files).fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Stat(stat) => {
                let Some(path_ptr) = stat.path() else {
                    return Ok(guest.inject(stat).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &guest_path)?;
                let buf_raw = stat.stat().map(|p| p.0.as_raw());
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        stat.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, crate::arch::STAT_UID_OFF, crate::arch::STAT_GID_OFF);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Lstat(stat) => {
                let Some(path_ptr) = stat.path() else {
                    return Ok(guest.inject(stat).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_for(guest, libc::AT_FDCWD, &guest_path)?;
                let buf_raw = stat.stat().map(|p| p.0.as_raw());
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        stat.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, crate::arch::STAT_UID_OFF, crate::arch::STAT_GID_OFF);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Access(acc) => {
                let Some(path_ptr) = acc.path() else {
                    return Ok(guest.inject(acc).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &guest_path)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        acc.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Newfstatat(stat) => {
                let Some(path_ptr) = stat.path() else {
                    return Ok(guest.inject(stat).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                if guest_path.as_os_str().is_empty() {
                    return Ok(guest.inject(stat).await?);
                }
                if self.dirfd_passthrough(guest, stat.dirfd(), &guest_path) {
                    return Ok(guest.inject(stat).await?);
                }
                // Follows a final symlink unless AT_SYMLINK_NOFOLLOW, in the
                // guest namespace (a relative target may cross a bind).
                let host = if stat
                    .flags()
                    .contains(reverie::syscalls::AtFlags::AT_SYMLINK_NOFOLLOW)
                {
                    self.translate_for(guest, stat.dirfd(), &guest_path)?
                } else {
                    self.translate_follow(guest, stat.dirfd(), &guest_path)?
                };
                let buf_raw = stat.stat().map(|p| p.0.as_raw());
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        stat.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let abs = {
                    let st = self.state.lock().unwrap();
                    self.guest_abs(guest, &st, stat.dirfd(), &guest_path)
                };
                let first = guest.inject(rewritten).await;
                let first = match first {
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        drop(_guard);
                        let saved = self.chmod_ancestors(&host);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &host, |ptr| {
                                stat.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        r2
                    }
                    other => other,
                };
                let ret = match first {
                    Ok(r) => r,
                    Err(e)
                        if e == reverie::syscalls::Errno::ENOENT
                            && self.is_virtual_bind_dir(guest, &abs) =>
                    {
                        self.write_virtual_dir_stat(guest, buf_raw, crate::arch::STAT_MODE_OFF);
                        0
                    }
                    Err(e) => return Err(e.into()),
                };
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, crate::arch::STAT_UID_OFF, crate::arch::STAT_GID_OFF);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "aarch64")]
            Syscall::Fstatat(stat) => {
                let Some(path_ptr) = stat.path() else {
                    return Ok(guest.inject(stat).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                if guest_path.as_os_str().is_empty() {
                    return Ok(guest.inject(stat).await?);
                }
                if self.dirfd_passthrough(guest, stat.dirfd(), &guest_path) {
                    return Ok(guest.inject(stat).await?);
                }
                // Follows a final symlink unless AT_SYMLINK_NOFOLLOW, in the
                // guest namespace (a relative target may cross a bind).
                let host = if stat
                    .flags()
                    .contains(reverie::syscalls::AtFlags::AT_SYMLINK_NOFOLLOW)
                {
                    self.translate_for(guest, stat.dirfd(), &guest_path)?
                } else {
                    self.translate_follow(guest, stat.dirfd(), &guest_path)?
                };
                let buf_raw = stat.stat().map(|p| p.0.as_raw());
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        stat.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let abs = {
                    let st = self.state.lock().unwrap();
                    self.guest_abs(guest, &st, stat.dirfd(), &guest_path)
                };
                let first = guest.inject(rewritten).await;
                let first = match first {
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        drop(_guard);
                        let saved = self.chmod_ancestors(&host);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &host, |ptr| {
                                stat.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        r2
                    }
                    other => other,
                };
                let ret = match first {
                    Ok(r) => r,
                    Err(e)
                        if e == reverie::syscalls::Errno::ENOENT
                            && self.is_virtual_bind_dir(guest, &abs) =>
                    {
                        self.write_virtual_dir_stat(guest, buf_raw, crate::arch::STAT_MODE_OFF);
                        0
                    }
                    Err(e) => return Err(e.into()),
                };
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, crate::arch::STAT_UID_OFF, crate::arch::STAT_GID_OFF);
                }
                Ok(ret)
            }
            Syscall::Readlinkat(link) => {
                let Some(path_ptr) = link.path() else {
                    return Ok(guest.inject(link).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_for(guest, link.dirfd(), &guest_path)?;
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot-tool: readlinkat {guest_path:?} -> {host:?} magic={}", is_magic_proc_path(&guest_path));
                }
                // Decided by the selected final entry (a shared
                // row's exe answers from the row). An empty name reads the
                // fd's own link, judged by the fd's own host path.
                let final_entry = if host.as_os_str().is_empty() && link.dirfd() != libc::AT_FDCWD {
                    match std::fs::read_link(format!("{}/fd/{}", task_dir(guest), link.dirfd())) {
                        Ok(fd_host) if fd_host.is_absolute() => self.final_proc(guest, &fd_host),
                        _ => FinalProc::Ordinary,
                    }
                } else {
                    self.final_proc(guest, &host)
                };
                let buf = link.buf();
                let buf_len = link.buf_len();
                if let Some(answer) = self.shared_row_readlink(guest, final_entry, buf, buf_len) {
                    return answer;
                }
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        link.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                Ok(self.detranslate_into(guest, &host, &guest_path, final_entry, buf, buf_len, ret))
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Readlink(link) => {
                let Some(path_ptr) = link.path() else {
                    return Ok(guest.inject(link).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_for(guest, libc::AT_FDCWD, &guest_path)?;
                // As for readlinkat.
                let final_entry = self.final_proc(guest, &host);
                let buf = link.buf();
                let buf_len = link.bufsize();
                if let Some(answer) = self.shared_row_readlink(guest, final_entry, buf, buf_len) {
                    return answer;
                }
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        link.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                Ok(self.detranslate_into(guest, &host, &guest_path, final_entry, buf, buf_len, ret))
            }
            Syscall::Fchdir(fch) => {
                let ret = guest.inject(fch).await?;
                if ret == 0 {
                    // Replicated cwd follows the kernel's new cwd; the fd's
                    // guest path is only the preferred spelling (the fd can
                    // be replaced between the call and this check).
                    let cfg = self.config(guest);
                    let mut st = self.state.lock().unwrap();
                    // Recorded as opened, the name can still hold links:
                    // the cwd is the directory they resolve to.
                    let candidate = self
                        .fd_guest_path(guest, &cfg, &st, fch.fd())
                        .map(|p| canonical_dir(&cfg, &p));
                    st.cwd = self.live_cwd_guest_path(guest, &cfg, &st, candidate);
                }
                Ok(ret)
            }
            Syscall::Faccessat(acc) => {
                let Some(path_ptr) = acc.path() else {
                    return Ok(guest.inject(acc).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_follow(guest, acc.dirfd(), &guest_path)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        acc.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Unlinkat(unlink) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(path_ptr) = unlink.path() else {
                    return Ok(guest.inject(unlink).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_for(guest, unlink.dirfd(), &guest_path)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        unlink.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_guard);
                match first {
                    Ok(r) => Ok(r),
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        let saved = self.chmod_ancestors(&host);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &host, |ptr| {
                                unlink.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        Ok(r2?)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Syscall::Mkdirat(mkdir) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(path_ptr) = mkdir.path() else {
                    return Ok(guest.inject(mkdir).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_for(guest, mkdir.dirfd(), &guest_path)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        mkdir.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Renameat(rn) => {
                let _probe_bump = ProbeBumpOnDrop;
                let (Some(op), Some(np)) = (rn.oldpath(), rn.newpath()) else {
                    return Ok(guest.inject(rn).await?);
                };
                let old_g = op.read(&guest.memory())?;
                let new_g = np.read(&guest.memory())?;
                let old_h = self.translate_for(guest, rn.olddirfd(), &old_g)?;
                let new_h = self.translate_for(guest, rn.newdirfd(), &new_g)?;
                let (_g, rewritten) = self
                    .with_two_guest_paths(guest, &old_h, &new_h, |a, b| {
                        rn.with_oldpath(PathPtr::from_ptr(a))
                            .with_newpath(PathPtr::from_ptr(b))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    self.rewrite_cwd_prefix(guest, rn.olddirfd(), &old_g, rn.newdirfd(), &new_g);
                }
                Ok(ret)
            }
            Syscall::Renameat2(rn) => {
                let _probe_bump = ProbeBumpOnDrop;
                let (Some(op), Some(np)) = (rn.oldpath(), rn.newpath()) else {
                    return Ok(guest.inject(rn).await?);
                };
                let old_g = op.read(&guest.memory())?;
                let new_g = np.read(&guest.memory())?;
                let old_h = self.translate_for(guest, rn.olddirfd(), &old_g)?;
                let new_h = self.translate_for(guest, rn.newdirfd(), &new_g)?;
                let (_g, rewritten) = self
                    .with_two_guest_paths(guest, &old_h, &new_h, |a, b| {
                        rn.with_oldpath(PathPtr::from_ptr(a))
                            .with_newpath(PathPtr::from_ptr(b))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    self.rewrite_cwd_prefix(guest, rn.olddirfd(), &old_g, rn.newdirfd(), &new_g);
                }
                Ok(ret)
            }
            Syscall::Linkat(ln) => {
                let _probe_bump = ProbeBumpOnDrop;
                let (Some(op), Some(np)) = (ln.oldpath(), ln.newpath()) else {
                    return Ok(guest.inject(ln).await?);
                };
                // do_linkat: any other flag is EINVAL before either path
                // is looked up; AT_SYMLINK_FOLLOW follows oldpath's final
                // symlink, which must then resolve through the guest root.
                let flags = ln.flags().bits() as u32;
                if flags & !((libc::AT_SYMLINK_FOLLOW | libc::AT_EMPTY_PATH) as u32) != 0 {
                    return Err(reverie::syscalls::Errno::EINVAL.into());
                }
                let old_g = op.read(&guest.memory())?;
                let new_g = np.read(&guest.memory())?;
                let old_h = if flags & libc::AT_SYMLINK_FOLLOW as u32 != 0 {
                    self.translate_follow(guest, ln.olddirfd(), &old_g)?
                } else {
                    self.translate_for(guest, ln.olddirfd(), &old_g)?
                };
                let new_h = self.translate_for(guest, ln.newdirfd(), &new_g)?;
                let (_g, rewritten) = self
                    .with_two_guest_paths(guest, &old_h, &new_h, |a, b| {
                        ln.with_oldpath(PathPtr::from_ptr(a))
                            .with_newpath(PathPtr::from_ptr(b))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Symlinkat(sl) => {
                let _probe_bump = ProbeBumpOnDrop;
                // Target string is NOT translated (stored verbatim
                // in the link, guest-namespace meaning); only the
                // link path is.
                let Some(lp) = sl.linkpath() else {
                    return Ok(guest.inject(sl).await?);
                };
                let link_g = lp.read(&guest.memory())?;
                let link_h = self.translate_for(guest, sl.newdirfd(), &link_g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &link_h, |ptr| {
                        sl.with_linkpath(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Rename(rn) => {
                let _probe_bump = ProbeBumpOnDrop;
                let (Some(op), Some(np)) = (rn.oldpath(), rn.newpath()) else {
                    return Ok(guest.inject(rn).await?);
                };
                let old_g = op.read(&guest.memory())?;
                let new_g = np.read(&guest.memory())?;
                let old_h = self.translate_for(guest, libc::AT_FDCWD, &old_g)?;
                let new_h = self.translate_for(guest, libc::AT_FDCWD, &new_g)?;
                let (_g, rewritten) = self
                    .with_two_guest_paths(guest, &old_h, &new_h, |a, b| {
                        rn.with_oldpath(PathPtr::from_ptr(a))
                            .with_newpath(PathPtr::from_ptr(b))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    self.rewrite_cwd_prefix(
                        guest,
                        libc::AT_FDCWD,
                        &old_g,
                        libc::AT_FDCWD,
                        &new_g,
                    );
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Link(ln) => {
                let _probe_bump = ProbeBumpOnDrop;
                let (Some(op), Some(np)) = (ln.oldpath(), ln.newpath()) else {
                    return Ok(guest.inject(ln).await?);
                };
                let old_g = op.read(&guest.memory())?;
                let new_g = np.read(&guest.memory())?;
                let old_h = self.translate_for(guest, libc::AT_FDCWD, &old_g)?;
                let new_h = self.translate_for(guest, libc::AT_FDCWD, &new_g)?;
                let (_g, rewritten) = self
                    .with_two_guest_paths(guest, &old_h, &new_h, |a, b| {
                        ln.with_oldpath(PathPtr::from_ptr(a))
                            .with_newpath(PathPtr::from_ptr(b))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Symlink(sl) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(lp) = sl.linkpath() else {
                    return Ok(guest.inject(sl).await?);
                };
                let link_g = lp.read(&guest.memory())?;
                let link_h = self.translate_for(guest, libc::AT_FDCWD, &link_g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &link_h, |ptr| {
                        sl.with_linkpath(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Rmdir(rd) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(pp) = rd.path() else {
                    return Ok(guest.inject(rd).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, libc::AT_FDCWD, &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        rd.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_g);
                match first {
                    Ok(r) => Ok(r),
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        let saved = self.chmod_ancestors(&h);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &h, |ptr| {
                                rd.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        Ok(r2?)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Unlink(un) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(pp) = un.path() else {
                    return Ok(guest.inject(un).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, libc::AT_FDCWD, &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        un.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_g);
                match first {
                    Ok(r) => Ok(r),
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        let saved = self.chmod_ancestors(&h);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &h, |ptr| {
                                un.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        Ok(r2?)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Mkdir(md) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(pp) = md.path() else {
                    return Ok(guest.inject(md).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, libc::AT_FDCWD, &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        md.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Mknodat(mk) => {
                let _probe_bump = ProbeBumpOnDrop;
                let Some(pp) = mk.path() else {
                    return Ok(guest.inject(mk).await?);
                };
                if self.fake_ids(guest).is_some() {
                    let g = pp.read(&guest.memory())?;
                    let h = self.translate_for(guest, mk.dirfd(), &g)?;
                    use std::os::unix::fs::PermissionsExt as _;
                    return match std::fs::File::create(&h) {
                        Ok(_) => {
                            let mode = mk.mode().bits() & 0o7777;
                            let _ = std::fs::set_permissions(
                                &h,
                                std::fs::Permissions::from_mode(mode),
                            );
                            Ok(0)
                        }
                        Err(e) => Err(reverie::syscalls::Errno::new(
                            e.raw_os_error().unwrap_or(libc::EIO),
                        )
                        .into()),
                    };
                }
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, mk.dirfd(), &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        mk.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Fchownat(fc) => {
                // Fake-root: chown always reports success (design
                // §4.4); without -0 the path is translated and the
                // real call decides.
                if self.config(guest).fake_ids == Some((0, 0))
                    || (self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0)
                {
                    return Ok(0);
                }
                // The kernel rejects any other flag with EINVAL before it
                // looks at the path, so no translation can fail first.
                let valid = (libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) as u32;
                if fc.flags().bits() as u32 & !valid != 0 {
                    return Err(reverie::syscalls::Errno::EINVAL.into());
                }
                let Some(pp) = fc.path() else {
                    return Ok(guest.inject(fc).await?);
                };
                let g = pp.read(&guest.memory())?;
                // The kernel follows a final symlink unless
                // AT_SYMLINK_NOFOLLOW; resolve it here, through the guest
                // root, or the kernel would follow it in the host's.
                let h = if fc
                    .flags()
                    .contains(reverie::syscalls::AtFlags::AT_SYMLINK_NOFOLLOW)
                {
                    self.translate_for(guest, fc.dirfd(), &g)?
                } else {
                    self.translate_follow(guest, fc.dirfd(), &g)?
                };
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        fc.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Fchown(fc) => {
                // proot's fake_id0 rule at 4dba3afb: a requested id equal
                // to the fake real id becomes the caller's real id
                // (chown.c:10-25), the kernel runs the call, and only
                // EPERM/EACCES become success, only while the current fake
                // euid is 0 (fake_id0.c:503-527, :914-921).
                if self.fake_ids(guest).is_none() {
                    return Ok(guest.inject(fc).await?);
                }
                let [ruid, euid, _, rgid, _, _] = self.fake_state(guest);
                let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
                let mut call = fc;
                if call.owner() == ruid {
                    call = call.with_owner(uid);
                }
                if call.group() == rgid {
                    call = call.with_group(gid);
                }
                use reverie::syscalls::Errno;
                match guest.inject(call).await {
                    Err(e) if euid == 0 && (e == Errno::EPERM || e == Errno::EACCES) => Ok(0),
                    other => Ok(other?),
                }
            }
            Syscall::Statfs(sf) => {
                let Some(pp) = sf.path() else {
                    return Ok(guest.inject(sf).await?);
                };
                let g = pp.read(&guest.memory())?;
                if g.as_os_str().is_empty() {
                    // proot leaves an empty path untranslated
                    // (syscall/enter.c:58-72), so the kernel says ENOENT.
                    return Ok(guest.inject(sf).await?);
                }
                let host = self.translate_follow(guest, libc::AT_FDCWD, &g)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| sf.with_path(PathPtr::from_ptr(ptr)))
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Fchmodat(fc) => {
                let Some(pp) = fc.path() else {
                    return Ok(guest.inject(fc).await?);
                };
                let g = pp.read(&guest.memory())?;
                // fchmodat has no flags argument and always follows a
                // final symlink (do_fchmodat): resolve it through the
                // guest root.
                let h = self.translate_follow(guest, fc.dirfd(), &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        fc.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_g);
                match first {
                    Ok(r) => Ok(r),
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        let saved = self.chmod_ancestors(&h);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &h, |ptr| {
                                fc.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        Ok(r2?)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Syscall::Utimensat(ut) => {
                let Some(pp) = ut.path() else {
                    return Ok(guest.inject(ut).await?);
                };
                // The kernel's checks before the path lookup come first,
                // in its order: unreadable times are EFAULT and two
                // UTIME_OMITs succeed without the path (utimensat,
                // fs/utimes.c); then any flag other than
                // AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH is EINVAL
                // (do_utimes_path).
                if let Some(times) = ut.times() {
                    match guest.memory().read_value(times) {
                        Ok([a, m])
                            if a.tv_nsec == libc::UTIME_OMIT && m.tv_nsec == libc::UTIME_OMIT =>
                        {
                            return Ok(0);
                        }
                        Ok(_) => {}
                        // The kernel faults on the times before it reads
                        // the path.
                        Err(_) => return Ok(guest.inject(ut).await?),
                    }
                }
                let flags = ut.flags() as u32;
                if flags & !((libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) as u32) != 0 {
                    return Err(reverie::syscalls::Errno::EINVAL.into());
                }
                let g = pp.read(&guest.memory())?;
                if g.as_os_str().is_empty() {
                    return Ok(guest.inject(ut).await?);
                }
                // A final symlink is followed unless AT_SYMLINK_NOFOLLOW.
                let h = if flags & libc::AT_SYMLINK_NOFOLLOW as u32 != 0 {
                    self.translate_for(guest, ut.dirfd(), &g)?
                } else {
                    self.translate_follow(guest, ut.dirfd(), &g)?
                };
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        ut.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Statx(sx) => {
                let Some(pp) = sx.path() else {
                    return Ok(guest.inject(sx).await?);
                };
                let g = pp.read(&guest.memory())?;
                if g.as_os_str().is_empty() {
                    return Ok(guest.inject(sx).await?);
                }
                let h = if sx
                    .flags()
                    .contains(reverie::syscalls::AtFlags::AT_SYMLINK_NOFOLLOW)
                {
                    self.translate_for(guest, sx.dirfd(), &g)?
                } else {
                    self.translate_follow(guest, sx.dirfd(), &g)?
                };
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot-tool: statx dirfd={} {g:?} -> {h:?}", sx.dirfd());
                }
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        sx.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let buf_raw = sx.statx().map(|p| p.0.as_raw());
                let r = guest.inject(rewritten).await;
                let r = match r {
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        drop(_g);
                        let saved = self.chmod_ancestors(&h);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &h, |ptr| {
                                sx.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        r2
                    }
                    other => other,
                };
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot-tool: statx -> {r:?}");
                }
                let ret = match r {
                    Ok(r2) => r2,
                    Err(e) if e == reverie::syscalls::Errno::ENOENT => {
                        let abs = {
                            let st = self.state.lock().unwrap();
                            self.guest_abs(guest, &st, sx.dirfd(), &g)
                        };
                        if self.is_virtual_bind_dir(guest, &abs) {
                            self.write_virtual_dir_stat(guest, buf_raw, crate::arch::STATX_MODE_OFF);
                            0
                        } else {
                            return Err(e.into());
                        }
                    }
                    Err(e) => return Err(e.into()),
                };
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, crate::arch::STATX_UID_OFF, crate::arch::STATX_GID_OFF);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Chmod(cm) => {
                let Some(pp) = cm.path() else {
                    return Ok(guest.inject(cm).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_follow(guest, libc::AT_FDCWD, &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        cm.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_g);
                match first {
                    Ok(r) => Ok(r),
                    Err(e)
                        if e == reverie::syscalls::Errno::EACCES
                            && self.fake_ids(guest) == Some((0, 0)) =>
                    {
                        let saved = self.chmod_ancestors(&h);
                        let (_g2, rewritten2) = self
                            .with_guest_path(guest, &h, |ptr| {
                                cm.with_path(PathPtr::from_ptr(ptr))
                            })
                            .await?;
                        let r2 = guest.inject(rewritten2).await;
                        self.restore_ancestors(saved);
                        Ok(r2?)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Chown(co) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    return Ok(0);
                }
                let Some(pp) = co.path() else {
                    return Ok(guest.inject(co).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_follow(guest, libc::AT_FDCWD, &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        co.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Lchown(co) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    return Ok(0);
                }
                let Some(pp) = co.path() else {
                    return Ok(guest.inject(co).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, libc::AT_FDCWD, &g)?;
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        co.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Openat2(oa) => {
                // Translate the path only; open_how passes through
                // unchanged. literoot does not emulate the resolve flags:
                // RESOLVE_IN_ROOT re-roots the absolute host path at the
                // guest's dirfd, a known limit (design §4.9.8, (2b)).
                let _probe_bump = ProbeBumpOnDrop;
                let Some(path_ptr) = oa.path() else {
                    return Ok(guest.inject(oa).await?);
                };
                let mut guest_path = path_ptr.read(&guest.memory())?;
                if self.dirfd_passthrough(guest, oa.dirfd(), &guest_path) {
                    return Ok(guest.inject(oa).await?);
                }
                // The kernel copies open_how before it looks at the path
                // (an unreadable one is its EFAULT), then follows a final
                // symlink unless O_NOFOLLOW.
                let Some(how) = oa.how() else {
                    return Ok(guest.inject(oa).await?);
                };
                let Ok(how) = guest.memory().read_value(how) else {
                    return Ok(guest.inject(oa).await?);
                };
                let how: reverie::syscalls::OpenHow = how;
                // As for openat, by the selected final entry. A
                // synthesized cmdline is answered only for arguments the
                // kernel accepts, asked through the guarded probe; when the
                // probe cannot tell, the kernel's own file answers. A walk
                // error is the guest's, after the kernel's argument errors
                // (no gate, no count).
                let follow = open_follows(how.flags);
                // On ptrace the route checks the arguments in the tracer;
                // in-guest the guarded probe does.
                let probe_first = guest.config().tool_in_guest(); // cmdline: probe first in-guest
                match self.self_link_route(guest, oa.dirfd(), &guest_path, follow) {
                    Ok(SelfLink::Exe) => guest_path = self.own_exe_route(guest, oa.dirfd()),
                    Ok(SelfLink::RowExe(pid)) => {
                        if let Some(exe) = Self::row_exe_guest(pid) {
                            guest_path = exe;
                        }
                    }
                    Ok(SelfLink::Cmdline(pid)) => {
                        if !probe_first || self.openat2_guarded_probe(guest, oa).await? {
                            if let Some(fd) = self.open_synthetic_cmdline(guest, pid, CmdlineOpen::Openat2(oa, how)).await? {
                                return Ok(fd);
                            }
                        } else {
                            note_cmdline_fallback();
                        }
                    }
                    Ok(SelfLink::SharedCmdline(pid)) => {
                        if !probe_first || self.openat2_guarded_probe(guest, oa).await? {
                            if let Some(fd) = self.open_shared_cmdline(guest, pid, CmdlineOpen::Openat2(oa, how)).await? {
                                return Ok(fd);
                            }
                        } else {
                            note_cmdline_fallback();
                        }
                    }
                    Ok(SelfLink::Walk) => {}
                    Err(errno) => return self.openat2_arguments_first(guest, oa, errno.into()).await,
                }
                let host = if !follow {
                    self.translate_for(guest, oa.dirfd(), &guest_path)
                } else {
                    self.translate_follow(guest, oa.dirfd(), &guest_path)
                };
                let staged = match host {
                    Ok(host) => {
                        self.with_guest_path(guest, &host, |ptr| {
                            oa.with_path(PathPtr::from_ptr(ptr))
                        })
                        .await
                    }
                    Err(errno) => Err(errno.into()),
                };
                let (_g, rewritten) = match staged {
                    Ok(staged) => staged,
                    Err(error) => return self.openat2_arguments_first(guest, oa, error).await,
                };
                let ret = guest.inject(rewritten).await?;
                if ret >= 0 {
                    let mut st = self.state.lock().unwrap();
                    let abs = self.guest_abs(guest, &st, oa.dirfd(), &guest_path);
                    let files = files_of(guest);
                    st.forget(files, ret as i32);
                    st.fdt_mut(files).fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
            Syscall::NameToHandleAt(nh) => {
                // Any flag outside this set is EINVAL before the lookup
                // (name_to_handle_at, fs/fhandle.c): AT_SYMLINK_FOLLOW,
                // AT_EMPTY_PATH, AT_HANDLE_FID (0x200),
                // AT_HANDLE_MNT_ID_UNIQUE (0x1), AT_HANDLE_CONNECTABLE (0x2).
                let flags = nh.flags() as u32;
                let valid =
                    (libc::AT_SYMLINK_FOLLOW | libc::AT_EMPTY_PATH) as u32 | 0x200 | 0x1 | 0x2;
                // AT_HANDLE_CONNECTABLE conflicts with AT_HANDLE_FID and
                // AT_EMPTY_PATH, also before the lookup.
                let conflict = 0x200 | libc::AT_EMPTY_PATH as u32;
                if flags & !valid != 0 || (flags & 0x2 != 0 && flags & conflict != 0) {
                    return Err(reverie::syscalls::Errno::EINVAL.into());
                }
                let Some(pp) = nh.pathname() else {
                    return Ok(guest.inject(nh).await?);
                };
                let g = pp.read(&guest.memory())?;
                if g.as_os_str().is_empty() {
                    return Ok(guest.inject(nh).await?);
                }
                if self.dirfd_passthrough(guest, nh.dirfd(), &g) {
                    return Ok(guest.inject(nh).await?);
                }
                // AT_SYMLINK_FOLLOW follows the final symlink: through the
                // guest root.
                let h = if flags & libc::AT_SYMLINK_FOLLOW as u32 != 0 {
                    self.translate_follow(guest, nh.dirfd(), &g)?
                } else {
                    self.translate_for(guest, nh.dirfd(), &g)?
                };
                let (_g2, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        nh.with_pathname(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::OpenByHandleAt(_ob) => {
                // File handles embed host filesystem identity we
                // cannot reverse-translate soundly; refuse by
                // name instead of passing through (design S4.1).
                Err(reverie::syscalls::Errno::EOPNOTSUPP.into())
            }
            Syscall::Ptrace(pt) => {
                // Guest ptrace scope: on in-guest backends it
                // is refused by name (EPERM). Forwarding it
                // there livelocks: the child's every syscall
                // raises seccomp SIGSYS for the trap runtime,
                // and a guest tracer that continues it
                // suppressing that SIGSYS makes the child
                // re-trap forever while the parent spins in
                // wait (measured: test-ptrace-setoptions
                // hangs >60 s, both guest processes running,
                // launcher idle in epoll). Real guest-ptrace
                // support needs Reverie trap/ptrace
                // coexistence design; until then fail fast
                // instead of hanging.
                // On the ptrace backend (refuse_guest_ptrace
                // false) guest ptrace passes through to the
                // kernel, which does NOT refuse it wholesale:
                // TRACEME and targets inside literoot's traced
                // tree get EPERM from the occupied tracer
                // slot, but operations on outside pids
                // (SEIZE/INTERRUPT/PEEKUSER/DETACH) are
                // kernel-served, as at base.
                if guest.config().refuse_guest_ptrace {
                    use reverie::syscalls::SyscallInfo as _;
                    // The dispatch setter request, matched as the whole
                    // request word (C5.7), takes the dispatch line.
                    if crate::dead_base::is_ptrace_dispatch_setter(syscall.into_parts().1.arg0 as u64) {
                        note_guest_refusal(GuestKind::SyscallUserDispatch);
                    } else {
                        note_guest_refusal(GuestKind::Ptrace);
                    }
                    if pt.request() == libc::PTRACE_TRACEME as u32 {
                        guest.thread_state_mut().swallow_self_stop = true;
                    }
                    Err(reverie::syscalls::Errno::EPERM.into())
                } else {
                    Ok(guest.inject(pt).await?)
                }
            }
            Syscall::Kill(k) => {
                // Companion to the TRACEME refusal above:
                // guests that ignore the refusal and kill
                // themselves SIGSTOP anyway would stop
                // untraced with nobody to continue them
                // (measured: test-gdb-ptrace hangs in the
                // parent's wait). Swallow that self-stop
                // while the refusal is still armed:
                // swallow_armed was taken at dispatch entry
                // and is cleared by any other *intercepted*
                // syscall and on exec — unsubscribed
                // syscalls (getpid, write, nanosleep, ...)
                // do not clear it, which is the accepted
                // leftover window (a known limitation).
                // This is the one place kill() reports
                // success without delivering the signal.
                let swallow_self_stop = swallow_armed
                    && k.pid() == guest.pid().as_raw()
                    && k.sig() == libc::SIGSTOP;
                if swallow_self_stop {
                    note_guest_refusal(GuestKind::SelfStop);
                    Ok(0)
                } else {
                    Ok(guest.inject(k).await?)
                }
            }
            Syscall::Getdents64(gd) => {
                use std::os::unix::fs::MetadataExt as _;
                let cfg = self.config(guest);
                let files = files_of(guest);
                let status = fd_status(guest, gd.fd() as i32);
                let virt = {
                    let fd = gd.fd() as i32;
                    let mut st = self.state.lock().unwrap();
                    match &status {
                        // Closed, or not a directory: no record of this table
                        // answers for it; the kernel does (EBADF, ENOTDIR).
                        FdStatus::NoDir => {
                            st.forget(files, fd);
                            None
                        }
                        FdStatus::Open(md) => {
                            let t = st.fdt(files);
                            let (keep_virtual, stale) = if t.virtual_fds.contains_key(&fd) {
                                let keep = virtual_fd_path(&cfg, t, fd, md).is_some();
                                (keep, !keep)
                            } else {
                                // Getdents state built for another directory on
                                // this number (a dup onto it) is stale.
                                let other = st
                                    .stream(files, fd)
                                    .and_then(|s| s.obj)
                                    .is_some_and(|o| o != (md.dev(), md.ino()));
                                (false, other)
                            };
                            // A stale number leaves its stream to the tables
                            // that still hold it, and gets a fresh one.
                            if stale {
                                st.forget(files, fd);
                            }
                            if keep_virtual {
                                virtual_record(&st, files, fd)
                            } else {
                                st.stream_mut(files, fd).obj = Some((md.dev(), md.ino()));
                                None
                            }
                        }
                        // /proc unreadable: the record stands, as before.
                        FdStatus::Unknown => virtual_record(&st, files, fd),
                    }
                };
                match virt {
                    None => {
                        // Real dir: merge bind-child entries
                        // after kernel EOF.
                        let fd = gd.fd() as i32;
                        if let Some(served) = self.serve_pending(guest, files, fd, &gd) {
                            return Ok(served);
                        }
                        let buf = gd.dirent();
                        let ret = guest.inject(gd).await?;
                        if ret > 0 {
                            self.record_dirent_names(guest, fd, buf, ret as usize);
                        } else if ret == 0
                            && !self
                                .state
                                .lock()
                                .unwrap()
                                .stream(files, fd)
                                .is_some_and(|s| s.pending.is_some())
                        {
                            // Kernel EOF (once per fd): stage
                            // synthetic entries for bind children
                            // not yet seen. Mark done first so a
                            // following getdents returns real EOF.
                            self.state.lock().unwrap().stream_mut(files, fd).pending =
                                Some(Vec::new());
                            let cfg = self.config(guest);
                            let guest_dir = {
                                let st = self.state.lock().unwrap();
                                self.fd_guest_path(guest, &cfg, &st, fd)
                            };
                            if let Some(gd_path) = guest_dir {
                                let synth =
                                    self.build_synth_dirents(guest, &gd_path, true);
                                if !synth.is_empty() {
                                    // Serve them now, whole records only;
                                    // the rest waits in the stream.
                                    self.state.lock().unwrap().stream_mut(files, fd).pending =
                                        Some(synth);
                                    if let Some(served) = self.serve_pending(guest, files, fd, &gd)
                                    {
                                        return Ok(served);
                                    }
                                }
                            }
                        }
                        Ok(ret)
                    }
                    Some((_, true)) => Ok(0),
                    Some((guest_dir, false)) => {
                        {
                            let mut st = self.state.lock().unwrap();
                            let fd = gd.fd() as i32;
                            if st.fdt(files).virtual_fds.contains_key(&fd) {
                                st.stream_mut(files, fd).emitted = true;
                            }
                        }
                        Ok(self.synth_dirents(guest, gd.dirent(), gd.count(), &guest_dir))
                    }
                }
            }
            Syscall::Chdir(chdir) => {
                let Some(path_ptr) = chdir.path() else {
                    return Ok(guest.inject(chdir).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                // chdir follows a final symlink: resolve it through the
                // guest root, or the kernel's cwd lands in the host's. The
                // same walk names the directory reached in guest terms.
                let (host, resolved) =
                    self.translate_follow_guest(guest, libc::AT_FDCWD, &guest_path)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        chdir.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    let mut st = self.state.lock().unwrap();
                    if st.cwd == Path::new(UNNAMED_CWD) && !guest_path.is_absolute() {
                        // Relative to a cwd with no guest path: only the
                        // kernel knows where this landed.
                        let cfg = self.config_locked(guest, &st);
                        st.cwd = self.live_cwd_guest_path(guest, &cfg, &st, None);
                    } else if let Some(resolved) = resolved {
                        // The kernel's cwd is the directory the walk reached,
                        // every link and ".." resolved: relative calls are
                        // translated from st.cwd without walking it again.
                        st.cwd = resolved;
                    } else {
                        // No guest name for what the walk reached: the
                        // kernel's own cwd, translated back.
                        let cfg = self.config_locked(guest, &st);
                        st.cwd = self.live_cwd_guest_path(guest, &cfg, &st, None);
                    }
                }
                Ok(ret)
            }
            Syscall::Getcwd(getcwd) => {
                // Kernel truth, de-translated: our chdir injects
                // keep the real cwd in sync, so inject the real
                // getcwd (rename/rmdir of ancestors then reports
                // correctly, incl. ENOENT on removed cwd) and
                // reverse-translate the host path to guest.
                let buf = getcwd.buf();
                let size = getcwd.size();
                let ret = guest.inject(getcwd).await?;
                let Some(buf) = buf else {
                    return Ok(ret);
                };
                if ret <= 0 {
                    return Ok(ret);
                }
                use reverie::syscalls::MemoryAccess as _;
                use std::os::unix::ffi::OsStringExt as _;
                let mut mem = guest.memory();
                let addr: reverie::syscalls::AddrMut<u8> =
                    unsafe { std::mem::transmute_copy(&buf) };
                let n = (ret as usize).saturating_sub(1).min(size);
                let mut stored = vec![0u8; n];
                if mem.read(addr, &mut stored).is_err() {
                    return Ok(ret);
                }
                let cfg = self.config(guest);
                let host_path = PathBuf::from(
                    std::ffi::OsString::from_vec(stored),
                );
                // Bind aliases: several guest names can denote
                // the kernel cwd (/a and /b both -> /tmp). Keep
                // the replicated spelling when it names the same
                // host directory (test-bind-chdir-getcwd).
                let replicated = self.exe_guest_fallback(guest);
                let guest_cwd =
                    if cfg.translate(&replicated, Path::new("/"), None) == host_path {
                        replicated
                    } else {
                        cfg.reverse(&host_path).unwrap_or(replicated)
                    };
                // Keep replicated cwd in sync for relative ops.
                {
                    let mut st = self.state.lock().unwrap();
                    st.cwd = guest_cwd.clone();
                }
                let bytes = guest_cwd.as_os_str().as_bytes();
                if bytes.len() + 1 > size {
                    return Err(reverie::syscalls::Errno::ERANGE.into());
                }
                let mut with_nul = bytes.to_vec();
                with_nul.push(0);
                mem.write(addr, &with_nul)?;
                Ok((bytes.len() + 1) as i64)
            }
            // B4 step 4: snapshot-and-tail-inject. The syscall
            // itself is forwarded bit-identically; staging only
            // seeds the child's thread state (see
            // init_thread_state/handle_thread_start). The parent
            // clears its own copy after inject — init clones it
            // to the child inside that inject.
            Syscall::Clone(clone) => {
                let fam = reverie::syscalls::family::CloneFamily::Clone(clone);
                let flags = fam.flags(&guest.memory()).bits();
                if clone_is_process(flags) {
                    if let Err(e) = self.stage_fork_snapshot(guest) {
                        return Err(e.into());
                    }
                    self.stage_child_files(guest, flags);
                    let ret = guest.inject(clone).await;
                    self.clear_exec_snapshot(guest);
                    self.end_child_files(guest, ret.is_ok());
                    self.note_child_mount_ns(guest, flags, &ret);
                    Ok(ret?)
                } else {
                    self.stage_child_files(guest, flags);
                    let ret = guest.inject(clone).await;
                    self.end_child_files(guest, ret.is_ok());
                    self.note_child_mount_ns(guest, flags, &ret);
                    Ok(ret?)
                }
            }
            Syscall::Clone3(clone3) => {
                let fam = reverie::syscalls::family::CloneFamily::Clone3(clone3);
                let flags = fam.flags(&guest.memory()).bits();
                if clone_is_process(flags) {
                    if let Err(e) = self.stage_fork_snapshot(guest) {
                        return Err(e.into());
                    }
                    self.stage_child_files(guest, flags);
                    let ret = guest.inject(clone3).await;
                    self.clear_exec_snapshot(guest);
                    self.end_child_files(guest, ret.is_ok());
                    self.note_child_mount_ns(guest, flags, &ret);
                    Ok(ret?)
                } else {
                    self.stage_child_files(guest, flags);
                    let ret = guest.inject(clone3).await;
                    self.end_child_files(guest, ret.is_ok());
                    self.note_child_mount_ns(guest, flags, &ret);
                    Ok(ret?)
                }
            }
            #[cfg(not(target_arch = "aarch64"))]
            Syscall::Fork(fork) => {
                if let Err(e) = self.stage_fork_snapshot(guest) {
                    return Err(e.into());
                }
                self.stage_child_files(guest, libc::SIGCHLD as u64);
                let ret = guest.inject(fork).await;
                self.clear_exec_snapshot(guest);
                self.end_child_files(guest, ret.is_ok());
                self.note_child_mount_ns(guest, 0, &ret);
                Ok(ret?)
            }
            #[cfg(not(target_arch = "aarch64"))]
            Syscall::Vfork(vfork) => {
                if let Err(e) = self.stage_fork_snapshot(guest) {
                    return Err(e.into());
                }
                // vfork is clone(CLONE_VM | CLONE_VFORK | SIGCHLD).
                self.stage_child_files(
                    guest,
                    (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64,
                );
                let ret = guest.inject(vfork).await;
                self.clear_exec_snapshot(guest);
                self.end_child_files(guest, ret.is_ok());
                self.note_child_mount_ns(guest, 0, &ret);
                Ok(ret?)
            }
            Syscall::Setns(setns) => {
                // Any successful setns may move the caller out of the
                // tracer's mount namespace (nstype 0 names none): the ptrace
                // cmdline route then falls back for it.
                let ret = guest.inject(setns).await?;
                if ret == 0 {
                    note_mount_ns_moved(guest.pid().as_raw());
                }
                Ok(ret)
            }
            Syscall::Unshare(unshare) => {
                let files_flag = unshare.flags().bits() & libc::CLONE_FILES != 0;
                let mount_flag = unshare.flags().bits() & libc::CLONE_NEWNS != 0;
                let ret = guest.inject(unshare).await?;
                if ret == 0 && mount_flag {
                    note_mount_ns_moved(guest.pid().as_raw());
                }
                if ret == 0 && files_flag {
                    // The kernel gave the caller a copy of its table.
                    let own = files_of(guest);
                    let id = self
                        .state
                        .lock()
                        .unwrap()
                        .split_files(own, |fd| fd_identity(guest, fd));
                    guest.thread_state_mut().files = id;
                }
                Ok(ret)
            }
            Syscall::Other(Sysno::close_range, args) => {
                let (first, last, flags) = (args.arg0 as u32, args.arg1 as u32, args.arg2 as u32);
                let ret = guest
                    .inject(Syscall::Other(Sysno::close_range, args))
                    .await?;
                if ret == 0 {
                    let mut files = files_of(guest);
                    if flags & CLOSE_RANGE_UNSHARE != 0 {
                        // A copy of the table first, then the range closes
                        // in the copy only.
                        files = self
                            .state
                            .lock()
                            .unwrap()
                            .split_files(files, |fd| fd_identity(guest, fd));
                        guest.thread_state_mut().files = files;
                    }
                    if flags & CLOSE_RANGE_CLOEXEC == 0 {
                        let mut st = self.state.lock().unwrap();
                        let t = st.fdt(files);
                        let closed: Vec<i32> = t
                            .fds
                            .keys()
                            .chain(t.virtual_fds.keys())
                            .chain(t.streams.keys())
                            .copied()
                            .filter(|fd| *fd >= 0 && (first..=last).contains(&(*fd as u32)))
                            .collect();
                        for fd in closed {
                            st.forget(files, fd);
                            st.fdt_mut(files).fds.remove(&fd);
                        }
                    }
                }
                Ok(ret)
            }
            Syscall::Execve(execve) => {
                // Initial launcher execve: its path is already a
                // host path inside the rootfs (the launcher execs
                // the translated program/interp) — pass through.
                // Guest execves name guest paths and are always
                // translated, including in forked children whose
                // Tool state starts fresh (measured: a per-process
                // "first exec" flag leaked host binaries there).
                if !LAUNCHER_EXEC_SEEN.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let e = guest.inject(execve).await.unwrap_err();
                    return Err(e.into());
                }
                let Some(path_ptr) = execve.path() else {
                    let e = guest.inject(execve).await.unwrap_err();
                    return Err(e.into());
                };
                // The exe record (with its host flag) and the argv are
                // written below, before the injection, for the successor's
                // snapshot. A successful exec never returns here, so every
                // return is a failed exec, which leaves the process's exe
                // and argv as they were, as the kernel does.
                let prior = self.exec_identity(guest);
                let outcome: Result<i64, Error> = {
                    let guest = &mut *guest;
                    async move {
                        let mut guest_path = path_ptr.read(&guest.memory())?;
                        // Remember as-exec'd argv for /proc/self/cmdline.
                        {
                            use reverie::syscalls::ReadAddr as _;
                            let mut argv: Vec<Vec<u8>> = Vec::new();
                            if let Some(a) = execve.argv() {
                                if let Ok(ptrs) = a.read(&guest.memory()) {
                                    for p in ptrs.iter().take(64) {
                                        if let Ok(cs) = p.read(&guest.memory()) {
                                            argv.push(cs.into_bytes());
                                        }
                                    }
                                }
                            }
                            if argv.is_empty() {
                                argv.push(guest_path.as_os_str().as_bytes().to_vec());
                            }
                            pid_argv_map()
                                .lock()
                                .unwrap()
                                .insert(guest.pid().as_raw(), argv.clone());
                            self.state.lock().unwrap().argv = argv;
                        }
                        // As for open, by the selected final entry.
                        let mut own_exe_host = false;
                        match self.self_link_route(guest, libc::AT_FDCWD, &guest_path, true)? {
                            SelfLink::Exe => {
                                guest_path = self.own_exe_route(guest, libc::AT_FDCWD);
                                own_exe_host = self.state.lock().unwrap().exe_host;
                            }
                            SelfLink::RowExe(pid) => {
                                if let Some(exe) = Self::row_exe_guest(pid) {
                                    guest_path = exe;
                                }
                            }
                            // A cmdline file is not an executable: the kernel's answer.
                            SelfLink::Cmdline(_) | SelfLink::SharedCmdline(_) | SelfLink::Walk => {}
                        }
                        let (host, _, resolved, other) =
                            self.translate_follow_uncached(guest, libc::AT_FDCWD, &guest_path)?;
                        {
                            // The record names the file this exec reaches, so a
                            // later open or readlink of /proc/self/exe holds still
                            // when the walk went through another process's
                            // directory link and that process moves:
                            // the
                            // walk's canonical guest route; after a Raw hand-over,
                            // the reached file's name ([`Self::reached_exe_name`]),
                            // a host path when it has no guest name. Otherwise the
                            // spelling, made absolute, as before: its basename is
                            // the comm name the kernel gives the program.
                            let abs = {
                                let st = self.state.lock().unwrap();
                                self.guest_abs(guest, &st, libc::AT_FDCWD, &guest_path)
                            };
                            let (exe, exe_host) = if own_exe_host {
                                (guest_path.clone(), true)
                            } else {
                                match other {
                                    OtherLink::Raw => {
                                        let cfg = self.config(guest);
                                        Self::reached_exe_name(&cfg, &host).unwrap_or((abs, false))
                                    }
                                    OtherLink::Spliced => (resolved.unwrap_or(abs), false),
                                    OtherLink::None => (abs, false),
                                }
                            };
                            // A file with no guest name has no entry: the
                            // old exe's would be stale.
                            if !exe_host {
                                let canon = self.canonical_exe(guest, &exe);
                                pid_exe_map()
                                    .lock()
                                    .unwrap()
                                    .insert(guest.pid().as_raw(), canon);
                            } else {
                                pid_exe_map().lock().unwrap().remove(&guest.pid().as_raw());
                            }
                            let mut st = self.state.lock().unwrap();
                            st.exe_guest = exe;
                            st.exe_host = exe_host;
                        }
                        if std::env::var_os("LITEROOT_DEBUG").is_some() {
                            eprintln!("literoot-tool: execve {guest_path:?} -> {host:?}");
                        }
                        // PT_INTERP rewrite (design §4.7): exec the rootfs
                        // dynamic linker with the guest program as its
                        // argument, reusing the original argv pointers
                        // (only the pointer array + interp path are staged).
                        // Shebang scripts: the kernel would open the
                        // #! interpreter on the HOST (measured: apk
                        // trigger scripts ran host /bin/sh). `exec_script`
                        // builds its own exec of the guest interpreter
                        // (through that interpreter's loader when it is a
                        // dynamic ELF), with the script as its argument.
                        let is_fd_path = {
                            let c: Vec<String> = guest_path
                                .components()
                                .filter_map(|x| match x {
                                    std::path::Component::Normal(v) => {
                                        Some(v.to_string_lossy().into_owned())
                                    }
                                    _ => None,
                                })
                                .collect();
                            c.len() >= 3 && c[0] == "proc" && c[2] == "fd"
                        };
                        // The image as the calling thread names it
                        // (thread-self is its own task directory).
                        let image =
                            host_for_tool_read(&host, guest.pid().as_raw(), guest.tid().as_raw());
                        // fd-path scripts: skip sniffing entirely —
                        // reading the fd would drain pipe input.
                        let shebang = if is_fd_path {
                            None
                        } else {
                            std::fs::read(&image)
                                .ok()
                                .and_then(|img| parse_shebang(&img))
                        };
                        if let Some((script_interp, optarg)) = shebang {
                            // A successful inject never returns; any return
                            // is a failed exec, so drop the staged snapshot
                            // (the next exec re-stages from live state).
                            match self
                                .exec_script(guest, execve, &guest_path, &script_interp, optarg.as_deref())
                                .await
                            {
                                Ok(res) => {
                                    self.invalidate_exec_snapshot(guest)?;
                                    return res;
                                }
                                Err(e) => {
                                    self.invalidate_exec_snapshot(guest)?;
                                    return Err(e);
                                }
                            }
                        }
                        let interp = if is_fd_path {
                            None
                        } else {
                            std::fs::read(&image)
                                .ok()
                                .and_then(|img| crate::translate::elf_interp(&img))
                        };
                        if let Some(interp_guest) = interp {
                            match self
                                .exec_via_interp(guest, execve, &guest_path, &interp_guest)
                                .await
                            {
                                Ok(res) => {
                                    self.invalidate_exec_snapshot(guest)?;
                                    return res;
                                }
                                Err(e) => {
                                    self.invalidate_exec_snapshot(guest)?;
                                    return Err(e);
                                }
                            }
                        }
                        // Stage the path in the scratch page, not on
                        // the guest stack (stack staging corrupts the
                        // execve caller's frame in interp-route
                        // processes; measured EFAULT on second execve).
                        let mut path_bytes = host.as_os_str().as_bytes().to_vec();
                        path_bytes.push(0);
                        // The kernel's own limit on the name (getname,
                        // PATH_MAX with the NUL), and the page's size: a
                        // longer one would run into the next page, another
                        // thread's.
                        if path_bytes.len() > libc::PATH_MAX as usize {
                            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
                        }
                        let scratch = self.scratch_write(guest, &path_bytes).await?;
                        let rewritten = execve.with_path(PathPtr::from_ptr(
                            scratch as *const libc::c_char,
                        ));
                        if let Err(e) = self.stage_snapshot(guest) {
                            return Err(e.into());
                        }
                        // Success does not return; mirror strace-tool shape.
                        let e = guest.inject(rewritten).await.unwrap_err();
                        self.invalidate_exec_snapshot(guest)?;
                        Err::<i64, Error>(e.into())
                    }
                    .await
                };
                self.restore_exec_identity(guest, prior);
                outcome
            }
            // ---- identity (fake-root / -i, design §4.4) ----
            Syscall::Getuid(_) if self.fake_ids(guest).is_some() => {
                Ok(self.fake_state(guest)[0] as i64)
            }
            Syscall::Geteuid(_) if self.fake_ids(guest).is_some() => {
                Ok(self.fake_state(guest)[1] as i64)
            }
            Syscall::Getgid(_) if self.fake_ids(guest).is_some() => {
                Ok(self.fake_state(guest)[3] as i64)
            }
            Syscall::Getegid(_) if self.fake_ids(guest).is_some() => {
                Ok(self.fake_state(guest)[4] as i64)
            }
            Syscall::Getresuid(gr) if self.fake_ids(guest).is_some() => {
                let f = self.fake_state(guest);
                self.write_one_id(guest, gr.ruid(), f[0]);
                self.write_one_id(guest, gr.euid(), f[1]);
                self.write_one_id(guest, gr.suid(), f[2]);
                Ok(0)
            }
            Syscall::Getresgid(gr) if self.fake_ids(guest).is_some() => {
                let f = self.fake_state(guest);
                self.write_one_id(guest, gr.rgid(), f[3]);
                self.write_one_id(guest, gr.egid(), f[4]);
                self.write_one_id(guest, gr.sgid(), f[5]);
                Ok(0)
            }
            // ---- identity-only: proot's set*id rules (`fake_creds`) ----
            Syscall::Setuid(s) if self.identity_only(guest) => {
                self.with_reference_ids(guest, |u, _, root| u.set(s.uid(), root))?;
                Ok(0)
            }
            Syscall::Setgid(s) if self.identity_only(guest) => {
                self.with_reference_ids(guest, |_, g, root| g.set(s.uid(), root))?;
                Ok(0)
            }
            Syscall::Setreuid(s) if self.identity_only(guest) => {
                self.with_reference_ids(guest, |u, _, root| u.set_re(s.ruid(), s.euid(), root))?;
                Ok(0)
            }
            Syscall::Setregid(s) if self.identity_only(guest) => {
                self.with_reference_ids(guest, |_, g, root| g.set_re(s.rgid(), s.egid(), root))?;
                Ok(0)
            }
            Syscall::Setresuid(s) if self.identity_only(guest) => {
                self.with_reference_ids(guest, |u, _, root| {
                    u.set_res(s.ruid(), s.euid(), s.suid(), root)
                })?;
                Ok(0)
            }
            Syscall::Setresgid(s) if self.identity_only(guest) => {
                self.with_reference_ids(guest, |_, g, root| {
                    g.set_res(s.rgid(), s.egid(), s.sgid(), root)
                })?;
                Ok(0)
            }
            Syscall::Setfsuid(s) if self.identity_only(guest) => {
                let fsuid = s.into_parts().1.arg0 as u32;
                Ok(self.with_reference_ids(guest, |u, _, root| u.set_fs(fsuid, root)) as i64)
            }
            Syscall::Setfsgid(s) if self.identity_only(guest) => {
                let fsgid = s.into_parts().1.arg0 as u32;
                Ok(self.with_reference_ids(guest, |_, g, root| g.set_fs(fsgid, root)) as i64)
            }
            Syscall::Setuid(s) => {
                if self.fake_ids(guest).is_some() {
                    let fake_cfg = self.fake_ids(guest);
                    let mut st = self.state.lock().unwrap();
                    let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                    if f[1] == 0 {
                        f[0] = s.uid();
                        f[1] = s.uid();
                        f[2] = s.uid();
                    } else {
                        f[1] = s.uid();
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Setgid(s) => {
                if self.fake_ids(guest).is_some() {
                    let fake_cfg = self.fake_ids(guest);
                    let mut st = self.state.lock().unwrap();
                    let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                    if f[4] == 0 {
                        f[3] = s.uid();
                        f[4] = s.uid();
                        f[5] = s.uid();
                    } else {
                        f[4] = s.uid();
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Setreuid(s) => {
                if self.fake_ids(guest).is_some() {
                    let fake_cfg = self.fake_ids(guest);
                    let mut st = self.state.lock().unwrap();
                    let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                    if s.ruid() != u32::MAX {
                        f[0] = s.ruid();
                        f[2] = s.euid();
                    }
                    if s.euid() != u32::MAX {
                        f[1] = s.euid();
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Setregid(s) => {
                if self.fake_ids(guest).is_some() {
                    let fake_cfg = self.fake_ids(guest);
                    let mut st = self.state.lock().unwrap();
                    let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                    if s.rgid() != u32::MAX {
                        f[3] = s.rgid();
                        f[5] = s.egid();
                    }
                    if s.egid() != u32::MAX {
                        f[4] = s.egid();
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Setresuid(s) => {
                if self.fake_ids(guest).is_some() {
                    let fake_cfg = self.fake_ids(guest);
                    let mut st = self.state.lock().unwrap();
                    let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                    if s.ruid() != u32::MAX {
                        f[0] = s.ruid();
                    }
                    if s.euid() != u32::MAX {
                        f[1] = s.euid();
                    }
                    if s.suid() != u32::MAX {
                        f[2] = s.suid();
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Setresgid(s) => {
                if self.fake_ids(guest).is_some() {
                    let fake_cfg = self.fake_ids(guest);
                    let mut st = self.state.lock().unwrap();
                    let f = st.fake.get_or_insert_with(|| init_fake(fake_cfg));
                    if s.rgid() != u32::MAX {
                        f[3] = s.rgid();
                    }
                    if s.egid() != u32::MAX {
                        f[4] = s.egid();
                    }
                    if s.sgid() != u32::MAX {
                        f[5] = s.sgid();
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Setgroups(s) => {
                if self.fake_ids(guest).is_some() {
                    let _ = s;
                    Ok(0)
                } else {
                    Ok(guest.inject(s).await?)
                }
            }
            Syscall::Capset(c) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    let _ = c;
                    Ok(0)
                } else {
                    Ok(guest.inject(c).await?)
                }
            }
            // Fake root claims every setxattr; otherwise the kernel runs it on
            // the translated path, and identity-only claims its
            // permission errors (`identity_xattr_result`).
            Syscall::Setxattr(x) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    return Ok(0);
                }
                let Some(pp) = x.path() else {
                    let ret = guest.inject(x).await;
                    return self.identity_xattr_result(guest, ret);
                };
                let g = pp.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &g)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| x.with_path(PathPtr::from_ptr(ptr)))
                    .await?;
                let ret = guest.inject(rewritten).await;
                self.identity_xattr_result(guest, ret)
            }
            Syscall::Lsetxattr(x) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    return Ok(0);
                }
                let Some(pp) = x.path() else {
                    let ret = guest.inject(x).await;
                    return self.identity_xattr_result(guest, ret);
                };
                let g = pp.read(&guest.memory())?;
                let host = self.translate_for(guest, libc::AT_FDCWD, &g)?;
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| x.with_path(PathPtr::from_ptr(ptr)))
                    .await?;
                let ret = guest.inject(rewritten).await;
                self.identity_xattr_result(guest, ret)
            }
            Syscall::Fsetxattr(x) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    return Ok(0);
                }
                let ret = guest.inject(x).await;
                self.identity_xattr_result(guest, ret)
            }
            // ---- uname / hostname (design §2 -k) ----
            Syscall::Uname(un) => {
                let buf = un.buf();
                let ret = guest.inject(un).await?;
                if ret == 0 {
                    self.spoof_uname(guest, buf);
                }
                Ok(ret)
            }
            Syscall::Sethostname(sh) => {
                if self.fake_ids(guest).is_some() {
                    if sh.len() > MAX_UTS_BYTES {
                        return Err(reverie::syscalls::Errno::EINVAL.into());
                    }
                    if let Some(name) = sh.name() {
                        let mut v = vec![0u8; sh.len()];
                        let mem = guest.memory();
                        use reverie::syscalls::MemoryAccess as _;
                        let addr: reverie::syscalls::Addr<u8> =
                            unsafe { std::mem::transmute_copy(&name) };
                        if mem.read(addr, &mut v).is_ok() {
                            *UTS_NODENAME.lock().unwrap() =
                                Some(String::from_utf8_lossy(&v).into_owned());
                            Self::set_shared_uts_nodename(v);
                        }
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(sh).await?)
                }
            }
            Syscall::Setdomainname(sd) => {
                if self.fake_ids(guest).is_some() {
                    if sd.len() > MAX_UTS_BYTES {
                        return Err(reverie::syscalls::Errno::EINVAL.into());
                    }
                    if let Some(name) = sd.name() {
                        let mut v = vec![0u8; sd.len()];
                        let mem = guest.memory();
                        use reverie::syscalls::MemoryAccess as _;
                        let addr: reverie::syscalls::Addr<u8> =
                            unsafe { std::mem::transmute_copy(&name) };
                        if mem.read(addr, &mut v).is_ok() {
                            *UTS_DOMAIN.lock().unwrap() =
                                Some(String::from_utf8_lossy(&v).into_owned());
                            Self::set_shared_uts_domainname(v);
                        }
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(sd).await?)
                }
            }
            // ---- chroot emulation: re-root replicated state ----
            Syscall::Chroot(cr) => {
                let Some(pp) = cr.path() else {
                    return Ok(guest.inject(cr).await?);
                };
                let g = pp.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &g)?;
                // Only fake root may chroot: proot gives a non-root fake
                // euid the kernel's answer, and identity-only does not
                // trace chroot at all; either way on the translated path.
                if self.identity_only(guest)
                    || (self.fake_ids(guest).is_some() && self.fake_state(guest)[1] != 0)
                {
                    let (_guard, rewritten) = self
                        .with_guest_path(guest, &host, |ptr| cr.with_path(PathPtr::from_ptr(ptr)))
                        .await?;
                    return Ok(guest.inject(rewritten).await?);
                }
                if !host.is_dir() {
                    return Err(reverie::syscalls::Errno::ENOTDIR.into());
                }
                // Real chdir into it so kernel-relative ops and
                // /proc/self/cwd agree, then record the new root.
                let mut st = self.state.lock().unwrap();
                st.root_override = Some(host);
                st.cwd = PathBuf::from("/");
                Ok(0)
            }
            Syscall::Bind(b) => {
                use reverie::syscalls::FromToRaw as _;
                match self
                    .stage_sockaddr(guest, b.umyaddr(), b.addrlen(), false)
                    .await?
                {
                    Some((_g, raw, len)) => {
                        let rewritten = b
                            .with_umyaddr(reverie::syscalls::AddrMut::from_ptr(
                                raw as *const libc::sockaddr,
                            ))
                            .with_addrlen(len);
                        Ok(guest.inject(rewritten).await?)
                    }
                    None => Ok(guest.inject(b).await?),
                }
            }
            Syscall::Connect(c) => {
                use reverie::syscalls::FromToRaw as _;
                match self
                    .stage_sockaddr(guest, c.uservaddr(), c.addrlen(), true)
                    .await?
                {
                    Some((_g, raw, len)) => {
                        let rewritten = c
                            .with_uservaddr(reverie::syscalls::AddrMut::from_ptr(
                                raw as *const libc::sockaddr,
                            ))
                            .with_addrlen(len);
                        Ok(guest.inject(rewritten).await?)
                    }
                    None => Ok(guest.inject(c).await?),
                }
            }
            Syscall::Getsockname(gs) => {
                let addr = gs.usockaddr();
                let len_ptr = gs.usockaddr_len();
                let ret = guest.inject(gs).await?;
                if ret == 0 {
                    self.detranslate_sockaddr(guest, addr, len_ptr);
                }
                Ok(ret)
            }
            other => Ok(guest.inject(other).await?),
        };
        if fork_like && guest.config().kill_on_exit {
            if let Ok(child) = result {
                if child > 0 {
                    // Parent side of a successful fork: register
                    // the child before it can fork again (hop
                    // chains register every link).
                    register_fork_child(child as i32);
                }
            }
        }
        result
    }
}

impl RootfsTool {
    /// First-touch --kill-on-exit registration backstop: record
    /// this process in the pid registry the launcher kills from
    /// at root exit (ptrace), if creation-time registration did
    /// not already happen on this backend.
    fn note_process_for_kill_on_exit<T: Guest<Self>>(&self, guest: &T) {
        if !guest.config().kill_on_exit {
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            if st.kill_registered {
                return;
            }
            st.kill_registered = true;
        }
        register_guest_pid(guest.pid().as_raw());
    }

    /// Stage bytes at offset 0 of the calling thread's guest scratch page
    /// ([`Self::scratch_write_at`]). Returns the guest address. Used for
    /// execve paths, where guest-stack staging is unsafe (see
    /// [`RootfsThreadState::scratch`]).
    async fn scratch_write<T: Guest<Self>>(
        &self,
        guest: &mut T,
        bytes: &[u8],
    ) -> Result<usize, Error> {
        self.scratch_write_at(guest, bytes, 0).await
    }

    /// Stage `bytes` at `offset` in the calling thread's scratch page: its
    /// own, else a free page of this image (a pooled one or an exited
    /// thread's, zeroed first), else the first page of a new pool
    /// ([`Self::map_scratch`]). A write that would end past the page is
    /// ENAMETOOLONG. Returns the guest address.
    async fn scratch_write_at<T: Guest<Self>>(
        &self,
        guest: &mut T,
        bytes: &[u8],
        offset: usize,
    ) -> Result<usize, Error> {
        use reverie::syscalls::MemoryAccess as _;
        // Never past the thread's page (the next may be another thread's):
        // every caller is bounded below this, and this makes it so.
        if offset.checked_add(bytes.len()).is_none_or(|end| end > SCRATCH_PAGE) {
            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
        }
        let base = match guest.thread_state().scratch {
            Some(page) => page.addr,
            None => match self.take_free_page(guest)? {
                Some(addr) => addr,
                None => self.map_scratch(guest).await?,
            },
        };
        let mut mem = guest.memory();
        let addr: reverie::syscalls::AddrMut<u8> =
            unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(base + offset) };
        // All of it or an error, never a truncated argument.
        mem.write_exact(addr, bytes)?;
        Ok(base + offset)
    }

    /// A free page of this image (a pooled one or an exited thread's) for
    /// the calling thread, zeroed before the thread owns it, so nothing it
    /// left is ever read. Ok(None) when none is free. A zeroing that fails
    /// is the error, and that page is lost (never queued again).
    fn take_free_page<T: Guest<Self>>(&self, guest: &mut T) -> Result<Option<usize>, Error> {
        use reverie::syscalls::MemoryAccess as _;
        let page = {
            let mut st = self.state.lock().unwrap();
            let image = st.scratch_image;
            st.free_scratch.pop().map(|addr| ScratchPage { addr, image })
        };
        let Some(page) = page else {
            return Ok(None);
        };
        let addr: reverie::syscalls::AddrMut<u8> =
            unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(page.addr) };
        guest.memory().write_exact(addr, &[0u8; SCRATCH_PAGE])?;
        guest.thread_state_mut().scratch = Some(page);
        Ok(Some(page.addr))
    }

    /// Map a pool of [`SCRATCH_POOL`] scratch pages (one injected anonymous
    /// mmap, zero-filled by the kernel): the calling thread takes the
    /// first, tagged with the current image, and the rest go on the free
    /// list for the next new threads. The image is read before the mmap: if
    /// an exec started a new one meanwhile, the pool is of the old address
    /// space and nothing is queued (on the pinned Reverie a thread an exec
    /// kills never resumes its handler, so this is a guard, not a path).
    async fn map_scratch<T: Guest<Self>>(&self, guest: &mut T) -> Result<usize, Error> {
        let image = self.state.lock().unwrap().scratch_image;
        let mmap = reverie::syscalls::Mmap::new()
            .with_addr(None)
            .with_len(SCRATCH_PAGE * SCRATCH_POOL)
            .with_prot(
                reverie::syscalls::ProtFlags::PROT_READ
                    | reverie::syscalls::ProtFlags::PROT_WRITE,
            )
            .with_flags(
                reverie::syscalls::MapFlags::MAP_PRIVATE
                    | reverie::syscalls::MapFlags::MAP_ANONYMOUS,
            )
            .with_fd(-1)
            .with_offset(0);
        let addr = guest.inject(mmap).await? as usize;
        {
            let mut st = self.state.lock().unwrap();
            if st.scratch_image == image {
                // Popped from the end: the lowest pages go first.
                st.free_scratch.extend((1..SCRATCH_POOL).rev().map(|i| addr + i * SCRATCH_PAGE));
            }
        }
        guest.thread_state_mut().scratch = Some(ScratchPage { addr, image });
        Ok(addr)
    }

    /// Exec `guest_prog` through the rootfs interp `interp_guest`:
    /// new argv = [interp, guest_prog, orig argv[1..].., NULL],
    /// reusing original argument string pointers. The program's
    /// argv[0] becomes the guest program path as the caller spelled
    /// it (busybox applet selection by basename keeps working).
    /// POC cap: 15 original arguments (guest-stack arena budget);
    /// beyond that, refuses with E2BIG by name rather than
    /// truncating silently.
    async fn exec_via_interp<T: Guest<Self>>(
        &self,
        guest: &mut T,
        execve: reverie::syscalls::Execve,
        guest_prog: &Path,
        interp_guest: &str,
    ) -> Result<Result<i64, Error>, Error> {
        use reverie::Stack as _;
        use reverie::syscalls::CArrayPtr;
        use reverie::syscalls::CStrPtr;
        use reverie::syscalls::FromToRaw as _;

        let cfg = self.config(guest);
        // The kernel's execve follows the loader's final symlink: resolve
        // it here, through the guest root, not the host's.
        let interp_host = follow_guest_path(&cfg, (guest.pid().as_raw(), guest.tid().as_raw()), Path::new(interp_guest))?;
        let orig_argv: Vec<usize> = match execve.argv() {
            Some(argv) => argv
                .read(&guest.memory())?
                .iter()
                .map(|p| Some(*p).into_raw())
                .collect(),
            None => Vec::new(),
        };
        if orig_argv.len() > 15 {
            return Ok(Err(reverie::syscalls::Errno::E2BIG.into()));
        }
        let path_raw = execve.path().into_raw();
        let envp_raw = execve.envp().into_raw();

        let interp_c = CString::new(interp_host.as_os_str().as_bytes())
            .map_err(|_| reverie::syscalls::Errno::EINVAL)?;
        let interp_bytes = interp_c.as_bytes_with_nul();
        if interp_bytes.len() > 384 || guest_prog.as_os_str().len() + 1 > 256 {
            return Ok(Err(reverie::syscalls::Errno::ENAMETOOLONG.into()));
        }
        let mut interp_buf = [0u8; 384];
        interp_buf[..interp_bytes.len()].copy_from_slice(interp_bytes);

        let mut stack = guest.stack().await;
        let interp_ptr = stack.push(interp_buf).as_raw();
        let mut array = [0usize; 18];
        array[0] = interp_ptr;
        array[1] = path_raw;
        for (i, p) in orig_argv.iter().skip(1).enumerate() {
            array[2 + i] = *p;
        }
        let argv_ptr = stack.push(array).as_raw();
        let _guard = stack.commit()?;
        let rewritten = reverie::syscalls::Execve::new()
            .with_path(PathPtr::from_ptr(interp_ptr as *const libc::c_char))
            .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(argv_ptr))
            .with_envp(Option::<CArrayPtr<CStrPtr>>::from_raw(envp_raw));
        if let Err(e) = self.stage_snapshot(guest) {
            return Ok(Err(e.into()));
        }
        if let Err(e) = self.begin_interp_exec_stack_limit(guest).await {
            return Ok(Err(e.into()));
        }
        let e = guest.inject(rewritten).await.unwrap_err();
        let _ = self.restore_pending_stack_limit(guest).await;
        Ok(Err(e.into()))
    }

    /// Exec a shebang script through its guest interpreter (and
    /// that interpreter through its own PT_INTERP loader when it
    /// has one): argv = [loader?, script-interp, script, args..].
    async fn exec_script<T: Guest<Self>>(
        &self,
        guest: &mut T,
        execve: reverie::syscalls::Execve,
        _script_guest: &Path,
        script_interp: &str,
        script_opt: Option<&str>,
    ) -> Result<Result<i64, Error>, Error> {
        // Kernel binfmt argv for scripts: [interp, opt?, script,
        // orig args...] — what /proc/self/cmdline must show.
        {
            use std::os::unix::ffi::OsStrExt as _;
            let mut argv: Vec<Vec<u8>> = vec![script_interp.as_bytes().to_vec()];
            if let Some(opt) = script_opt {
                argv.push(opt.as_bytes().to_vec());
            }
            let prev = self.state.lock().unwrap().argv.clone();
            if prev.is_empty() {
                argv.push(_script_guest.as_os_str().as_bytes().to_vec());
            } else {
                argv.extend(prev);
            }
            pid_argv_map()
                .lock()
                .unwrap()
                .insert(guest.pid().as_raw(), argv.clone());
            self.state.lock().unwrap().argv = argv;
        }
        use reverie::Stack as _;
        use reverie::syscalls::CArrayPtr;
        use reverie::syscalls::CStrPtr;
        use reverie::syscalls::FromToRaw as _;

        let cfg = self.config(guest);
        let ids = (guest.pid().as_raw(), guest.tid().as_raw());
        let interp_host = follow_guest_path(&cfg, ids, Path::new(script_interp))?;
        // The interpreter's own loader, if it is a dynamic ELF.
        let loader_host = std::fs::read(&interp_host)
            .ok()
            .and_then(|img| crate::translate::elf_interp(&img))
            .map(|ld| follow_guest_path(&cfg, ids, Path::new(&ld)))
            .transpose()?;
        let orig_argv: Vec<usize> = match execve.argv() {
            Some(argv) => argv
                .read(&guest.memory())?
                .iter()
                .map(|p| Some(*p).into_raw())
                .collect(),
            None => Vec::new(),
        };
        if orig_argv.len() > 14 {
            return Ok(Err(reverie::syscalls::Errno::E2BIG.into()));
        }
        let script_raw = execve.path().into_raw();
        let envp_raw = execve.envp().into_raw();

        let stage = |s: &str| -> Result<[u8; 192], Error> {
            let c = CString::new(s).map_err(|_| reverie::syscalls::Errno::EINVAL)?;
            let b = c.as_bytes_with_nul();
            if b.len() > 192 {
                return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
            }
            let mut buf = [0u8; 192];
            buf[..b.len()].copy_from_slice(b);
            Ok(buf)
        };

        let mut stack = guest.stack().await;
        // argv[0] for the interpreter program: the guest interp path
        // as spelled in the shebang (busybox applet selection).
        let interp_argv0 = stack.push(stage(script_interp)?).as_raw();
        let opt_ptr = match script_opt {
            Some(opt) => Some(stack.push(stage(opt)?).as_raw()),
            None => None,
        };
        let (exec_ptr, mut array, mut base) = match &loader_host {
            Some(ld) => {
                let ld_ptr =
                    stack.push(stage(&ld.to_string_lossy())?).as_raw();
                let mut a = [0usize; 18];
                a[0] = ld_ptr;
                a[1] = interp_argv0;
                a[2] = script_raw;
                (ld_ptr, a, 3usize)
            }
            None => {
                let ih_ptr =
                    stack.push(stage(&interp_host.to_string_lossy())?).as_raw();
                let mut a = [0usize; 18];
                a[0] = interp_argv0;
                a[1] = script_raw;
                (ih_ptr, a, 2usize)
            }
        };
        if let Some(opt) = opt_ptr {
            // Insert opt before the script: shift script slot.
            array[base] = script_raw;
            array[base - 1] = opt;
            base += 1;
        }
        for (i, p) in orig_argv.iter().skip(1).enumerate() {
            array[base + i] = *p;
        }
        let argv_ptr = stack.push(array).as_raw();
        let _guard = stack.commit()?;
        let rewritten = reverie::syscalls::Execve::new()
            .with_path(PathPtr::from_ptr(exec_ptr as *const libc::c_char))
            .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(argv_ptr))
            .with_envp(Option::<CArrayPtr<CStrPtr>>::from_raw(envp_raw));
        // exec_script already rewrote state.argv to the kernel
        // binfmt argv above, so staging here captures the
        // successor's own argv as B4 requires.
        if let Err(e) = self.stage_snapshot(guest) {
            return Ok(Err(e.into()));
        }
        // A dynamic script interpreter is also started through its
        // rootfs loader as the main ET_DYN image, so it needs the
        // same finite-stack window as `exec_via_interp`.
        if loader_host.is_some() {
            if let Err(e) = self.begin_interp_exec_stack_limit(guest).await {
                return Ok(Err(e.into()));
            }
        }
        let e = guest.inject(rewritten).await.unwrap_err();
        if loader_host.is_some() {
            let _ = self.restore_pending_stack_limit(guest).await;
        }
        Ok(Err(e.into()))
    }

    fn config<T: Guest<Self>>(&self, guest: &T) -> RootConfig {
        // Authoritative on every backend: the backend delivers the
        // GlobalTool Config to each guest handle (in-guest tools
        // run in a different process than the launcher, so a
        // process-global stash cannot work there).
        // Per-dispatch memo: RootConfig::new canonicalizes bind
        // prefixes through the host filesystem, and several helpers
        // per dispatch ask for the config. Keyed by dispatch and
        // root override, so a mid-dispatch chroot is honored and
        // nothing survives into the next dispatch.
        {
            let st = self.state.lock().unwrap();
            if let Some((seq, root, cfg)) = &st.config_memo {
                if *seq == st.dispatch_seq && *root == st.root_override {
                    return cfg.clone();
                }
            }
        }
        let mut cfg = guest.config().to_root_config();
        let root_override = self.state.lock().unwrap().root_override.clone();
        if let Some(root) = &root_override {
            cfg.rootfs = root.clone();
        }
        {
            let mut st = self.state.lock().unwrap();
            st.config_memo = Some((st.dispatch_seq, root_override, cfg.clone()));
        }
        cfg
    }

    fn canonical_exe<T: Guest<Self>>(&self, guest: &T, p: &Path) -> PathBuf {
        let cfg = self.config(guest);
        follow_guest_path(&cfg, (guest.pid().as_raw(), guest.tid().as_raw()), p)
            .ok()
            .and_then(|resolved| cfg.reverse(&resolved))
            .unwrap_or_else(|| p.to_path_buf())
    }

    fn exe_guest<T: Guest<Self>>(&self, guest: &T) -> PathBuf {
        if std::env::var_os("LITEROOT_DEBUG").is_some() {
            eprintln!("literoot-tool: exe_guest init={:?}", guest.config().initial_exe);
        }
        let st = self.state.lock().unwrap();
        if st.exe_guest.as_os_str().is_empty() {
            drop(st);
            let init = guest.config().initial_exe.clone();
            if !init.is_empty() {
                pid_exe_map()
                    .lock()
                    .unwrap()
                    .entry(guest.pid().as_raw())
                    .or_insert_with(|| {
                        let p = PathBuf::from(&init);
                        if p.is_absolute() {
                            self.canonical_exe(guest, &p)
                        } else {
                            p
                        }
                    });
            }
            // Must be absolute: glibc _dl_get_origin asserts
            // /proc/self/exe starts with '/' (measured abort
            // in test-fork-vfork-execve with ./prog).
            initial_exe_guest(&init, &guest.config().cwd, &self.config(guest))
        } else {
            st.exe_guest.clone()
        }
    }

    /// The path an open or execve of the caller's own exe walks, in place
    /// of the spelled link: its recorded guest name; or, for an exe with
    /// no guest name ([`ProcState::exe_host`]), that host path, with this
    /// dispatch's translation of it (followed or not, from `dirfd`)
    /// memoized to itself, so the arm opens the host file as is.
    fn own_exe_route<T: Guest<Self>>(&self, guest: &T, dirfd: i32) -> PathBuf {
        let exe = self.exe_guest(guest);
        let tid = guest.tid().as_raw();
        let mut st = self.state.lock().unwrap();
        if st.exe_host {
            st.translate_memo
                .retain(|((t, fd, path, _), _)| !(*t == tid && *fd == dirfd && *path == exe));
            for follow in [false, true] {
                st.translate_memo
                    .push(((tid, dirfd, exe.clone(), follow), Ok((exe.clone(), 0, None, OtherLink::None))));
            }
        }
        exe
    }

    /// The host file a walk with a Raw hand-over reached (`host` still
    /// holds the other process's link), named without that link, and
    /// whether that name is a host path: the guest name when one leads
    /// back to the same file, else the host path. None when it cannot be
    /// named from the Tool (another mount namespace, a deleted file, a file
    /// the Tool cannot reach): the recorded exe then stays the spelling,
    /// disclosed in docs/design.md.
    fn reached_exe_name(cfg: &RootConfig, host: &Path) -> Option<(PathBuf, bool)> {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(host).ok()?;
        let named = std::fs::canonicalize(host).ok()?;
        let same = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.dev() == md.dev() && m.ino() == md.ino());
        if named.starts_with("/proc") || !same(&named) {
            return None;
        }
        match cfg.reverse(&named) {
            Some(g) if same(&cfg.translate(&g, Path::new("/"), None)) => Some((g, false)),
            _ => Some((named, true)),
        }
    }

    fn exe_guest_fallback<T: Guest<Self>>(&self, guest: &T) -> PathBuf {
        let st = self.state.lock().unwrap();
        if st.cwd == Path::new("/__literoot_unset__") {
            drop(st);
            self.seed_cwd(guest)
        } else {
            st.cwd.clone()
        }
    }

    /// After a successful rename, a replicated cwd under the
    /// old prefix follows to the new prefix (kernel getcwd
    /// also re-syncs on next call; this keeps relative ops
    /// correct in between).
    fn rewrite_cwd_prefix<T: Guest<Self>>(
        &self,
        guest: &T,
        old_dirfd: i32,
        old_g: &Path,
        new_dirfd: i32,
        new_g: &Path,
    ) {
        let mut st = self.state.lock().unwrap();
        // Both names as the kernel resolved them, links included: the
        // recorded cwd is canonical, so only a canonical prefix matches it.
        let cfg = self.config_locked(guest, &st);
        let old_abs = canonical_dir(&cfg, &self.guest_abs(guest, &st, old_dirfd, old_g));
        let new_abs = canonical_dir(&cfg, &self.guest_abs(guest, &st, new_dirfd, new_g));
        if let Ok(suffix) = st.cwd.clone().strip_prefix(&old_abs).map(|s| s.to_path_buf()) {
            let mut p = new_abs;
            if !suffix.as_os_str().is_empty() {
                p.push(suffix);
            }
            st.cwd = p;
        }
    }

    /// The fake ids every fake-identity rule uses; none under
    /// identity-only, which emulates only the set*id, setfs*id and setxattr
    /// calls (`fake_cred_ids`).
    /// `config` for a caller that already holds the state lock.
    fn config_locked<T: Guest<Self>>(&self, guest: &T, st: &ProcState) -> RootConfig {
        if let Some((seq, root, cfg)) = &st.config_memo {
            if *seq == st.dispatch_seq && *root == st.root_override {
                return cfg.clone();
            }
        }
        let mut cfg = guest.config().to_root_config();
        if let Some(root) = &st.root_override {
            cfg.rootfs = root.clone();
        }
        cfg
    }

    /// The replicated cwd after a successful chdir or fchdir, from the
    /// kernel's cwd of the calling task (/proc/<pid>/task/<tid>/cwd), which
    /// is right even if the fd was replaced after the call: `candidate`
    /// (the spelling the call implies) when it names that directory, else
    /// the link's target mapped into the guest when that name leads back to
    /// it, else UNNAMED_CWD for a directory with no guest path (deleted,
    /// outside every tree, shadowed by a deeper bind). When
    /// /proc cannot be read, `candidate` or the old cwd stands.
    fn live_cwd_guest_path<T: Guest<Self>>(
        &self,
        guest: &T,
        cfg: &RootConfig,
        st: &ProcState,
        candidate: Option<PathBuf>,
    ) -> PathBuf {
        use std::os::unix::fs::MetadataExt as _;
        let link = format!("{}/cwd", task_dir(guest));
        let live = match std::fs::metadata(&link) {
            Ok(md) => md,
            Err(_) => return candidate.unwrap_or_else(|| st.cwd.clone()),
        };
        if live.nlink() == 0 {
            return PathBuf::from(UNNAMED_CWD);
        }
        if let Some(p) = candidate {
            let virt = st
                .fdt(files_of(guest))
                .virtual_fds
                .values()
                .any(|v| *v == p)
                && same_file(&cfg.rootfs, &live);
            if virt || same_file(&cfg.translate(&p, Path::new("/"), None), &live) {
                return p;
            }
        }
        // A name that leads back to this directory: a deeper bind can
        // shadow the plain reverse.
        GuestProcLinks::new(cfg, guest.pid().as_raw(), guest.tid().as_raw())
            .verified_reverse(Path::new(&link), &live)
            .unwrap_or_else(|_| PathBuf::from(UNNAMED_CWD))
    }

    /// The guest path of the file open as `fd`, or None when it has none.
    /// The fd table learns a path at open but is not told about close,
    /// dup, close_range, close-on-exec or fds received over a socket, and
    /// it is copied across fork and exec, so a number it records can now
    /// be a different file (measured: rm's directory fd resolved to the
    /// lock file its parent dpkg had open under that number). So the
    /// kernel's /proc/<pid>/fd/<fd> decides:
    /// - a virtual bind-prefix directory (open_virtual_dir) keeps its
    ///   virtual path while the fd still holds the placeholder, the rootfs
    ///   root directory;
    /// - the entry stands while its translated host path is the same
    ///   file (device and inode) as the open one, whichever host spelling
    ///   a bind gives it;
    /// - otherwise the link's target mapped back into the guest namespace
    ///   (`RootConfig::reverse`), as proot resolves every dirfd;
    /// - None for a closed fd, a deleted file (no links left), a target
    ///   with no path (pipe:, socket:, anon_inode:) or one outside every
    ///   mapped tree;
    /// - the entry, as before, when /proc/<pid>/fd cannot be read at all.
    fn fd_guest_path<T: Guest<Self>>(
        &self,
        guest: &T,
        cfg: &RootConfig,
        st: &ProcState,
        fd: i32,
    ) -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt as _;
        let dir = format!("{}/fd", task_dir(guest));
        let link = format!("{dir}/{fd}");
        let table = st.fdt(files_of(guest));
        let recorded = table.fds.get(&fd);
        // lstat of the fd link says whether the fd is open; stat follows it
        // to the object, which fails for an O_PATH fd on a dangling symlink.
        if std::fs::symlink_metadata(&link).is_err() {
            return if std::fs::metadata(&dir).is_ok() {
                None
            } else {
                recorded.cloned()
            };
        }
        let Ok(live) = std::fs::metadata(&link) else {
            return std::fs::read_link(&link).ok().and_then(|t| cfg.reverse(&t));
        };
        if let Some(v) = virtual_fd_path(cfg, table, fd, &live) {
            return Some(v);
        }
        if live.nlink() == 0 {
            return None;
        }
        if let Some(p) = recorded {
            let host = cfg.translate(p, Path::new("/"), None);
            if let Ok(md) = std::fs::metadata(&host) {
                if (md.dev(), md.ino()) == (live.dev(), live.ino()) {
                    return Some(p.clone());
                }
            }
        }
        std::fs::read_link(&link).ok().and_then(|t| cfg.reverse(&t))
    }

    fn fake_ids<T: Guest<Self>>(&self, guest: &T) -> Option<(u32, u32)> {
        let cfg = self.config(guest);
        if cfg.identity_only {
            None
        } else {
            cfg.fake_ids
        }
    }

    /// The fake ids the set*id emulation starts from, identity-only
    /// included.
    fn fake_cred_ids<T: Guest<Self>>(&self, guest: &T) -> Option<(u32, u32)> {
        self.config(guest).fake_ids
    }

    fn identity_only<T: Guest<Self>>(&self, guest: &T) -> bool {
        self.config(guest).identity_only
    }

    /// Applies one of proot's set*id rules (`crate::fake_creds`) to the
    /// fake uids and gids; the caller is privileged when its fake
    /// effective uid is 0.
    fn with_reference_ids<T: Guest<Self>, R>(
        &self,
        guest: &T,
        rule: impl FnOnce(&mut Ids, &mut Ids, bool) -> R,
    ) -> R {
        let fake_cfg = self.fake_cred_ids(guest);
        let mut st = self.state.lock().unwrap();
        let f = *st.fake.get_or_insert_with(|| init_fake(fake_cfg));
        let (fsuid, fsgid) = st.fake_fs.unwrap_or((f[1], f[4]));
        let mut u = Ids {
            r: f[0],
            e: f[1],
            s: f[2],
            fs: fsuid,
        };
        let mut g = Ids {
            r: f[3],
            e: f[4],
            s: f[5],
            fs: fsgid,
        };
        let out = rule(&mut u, &mut g, f[1] == 0);
        st.fake = Some([u.r, u.e, u.s, g.r, g.e, g.s]);
        st.fake_fs = Some((u.fs, g.fs));
        out
    }

    /// A setxattr call's result. Under identity-only, EPERM and EACCES
    /// become success at any fake euid, as proot's
    /// `handle_perm_err_exit_end(tracee, config, true)` makes them for the
    /// three setxattr calls; other errors and successes stand.
    fn identity_xattr_result<T: Guest<Self>>(
        &self,
        guest: &T,
        ret: Result<i64, reverie::syscalls::Errno>,
    ) -> Result<i64, Error> {
        use reverie::syscalls::Errno;
        match ret {
            Err(e) if (e == Errno::EPERM || e == Errno::EACCES) && self.identity_only(guest) => {
                Ok(0)
            }
            other => Ok(other?),
        }
    }

    fn fake_state<T: Guest<Self>>(&self, guest: &T) -> [u32; 6] {
        let fake_cfg = self.fake_cred_ids(guest);
        let mut st = self.state.lock().unwrap();
        *st.fake.get_or_insert_with(|| init_fake(fake_cfg))
    }

    fn write_one_id<T: Guest<Self>>(
        &self,
        guest: &mut T,
        slot: Option<reverie::syscalls::AddrMut<libc::gid_t>>,
        val: u32,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        if let Some(slot) = slot {
            let mut mem = guest.memory();
            let addr: reverie::syscalls::AddrMut<u8> =
                unsafe { std::mem::transmute_copy(&slot) };
            let _ = mem.write(addr, &val.to_ne_bytes());
        }
    }

    fn write_res_ids<T: Guest<Self>>(
        &self,
        guest: &mut T,
        r: Option<reverie::syscalls::AddrMut<libc::gid_t>>,
        e: Option<reverie::syscalls::AddrMut<libc::gid_t>>,
        s: Option<reverie::syscalls::AddrMut<libc::gid_t>>,
        val: u32,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        let mut mem = guest.memory();
        for slot in [r, e, s].into_iter().flatten() {
            let addr: reverie::syscalls::AddrMut<u8> =
                unsafe { std::mem::transmute_copy(&slot) };
            let _ = mem.write(addr, &val.to_ne_bytes());
        }
    }

    /// Rewrite utsname fields per `-k` + sethostname overrides.
    /// Field layout: 6 x 65-byte strings (sysname, nodename,
    /// release, version, machine, domainname).
    fn spoof_uname<T: Guest<Self>>(
        &self,
        guest: &mut T,
        buf: Option<reverie::syscalls::AddrMut<libc::utsname>>,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        let Some(buf) = buf else { return };
        let cfg = self.config(guest);
        let kr = cfg.kernel_release.clone();
        let local_nodename = UTS_NODENAME.lock().unwrap().clone();
        let local_domain = UTS_DOMAIN.lock().unwrap().clone();
        let (nodename, domain) =
            match shared_record_file().and_then(|store| store.uts().ok()) {
                Some((node, domain)) => (
                    node.map(|v| String::from_utf8_lossy(&v).into_owned())
                        .or(local_nodename),
                    domain
                        .map(|v| String::from_utf8_lossy(&v).into_owned())
                        .or(local_domain),
                ),
                None => (local_nodename, local_domain),
            };
        if kr.is_none() && nodename.is_none() && domain.is_none() {
            return;
        }
        // Parse proot -k: backslash-separated UTS fields, "0" or
        // empty keeps the kernel value; no backslash = release.
        let mut fields: [Option<String>; 6] = Default::default();
        if let Some(k) = &kr {
            if k.contains('\\') {
                let k2 = k.strip_prefix('\\').unwrap_or(k);
                for (i, part) in k2.split('\\').take(6).enumerate() {
                    if !part.is_empty() && part != "0" {
                        fields[i] = Some(part.to_string());
                    }
                }
            } else {
                fields[2] = Some(k.clone());
            }
        }
        if let Some(n) = nodename {
            fields[1] = Some(n);
        }
        if let Some(d) = domain {
            fields[5] = Some(d);
        }
        let mut mem = guest.memory();
        let base: reverie::syscalls::AddrMut<u8> =
            unsafe { std::mem::transmute_copy(&buf) };
        for (i, f) in fields.iter().enumerate() {
            if let Some(val) = f {
                let mut cell = [0u8; 65];
                let bytes = val.as_bytes();
                let n = bytes.len().min(64);
                cell[..n].copy_from_slice(&bytes[..n]);
                // Field i lives at base + i*65; AddrMut arithmetic
                // via raw value reconstruction.
                let raw = {
                    let p: reverie::syscalls::Addr<u8> =
                        unsafe { std::mem::transmute_copy(&base) };
                    (unsafe { p.as_ptr() } as usize) + i * 65
                };
                let addr: reverie::syscalls::AddrMut<u8> =
                    unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(raw) };
                let _ = mem.write(addr, &cell);
            }
        }
    }

    /// True when the guest path is a strict prefix directory of
    /// some bind's guest path (a virtual intermediate dir that
    /// exists for traversal but is never created on the host —
    /// test-dont-pollute-rootfs, readdir nested bindings).
    fn is_virtual_bind_dir<T: Guest<Self>>(&self, guest: &T, guest_abs: &Path) -> bool {
        let cfg = self.config(guest);
        cfg.binds
            .iter()
            .any(|b| b.guest != guest_abs && b.guest.starts_with(guest_abs))
    }

    /// Write a fabricated directory stat (mode 040755) into a
    /// stat/statx buffer for a virtual bind dir.
    fn write_virtual_dir_stat<T: Guest<Self>>(
        &self,
        guest: &mut T,
        buf_raw: Option<usize>,
        mode_off: usize,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        let Some(raw) = buf_raw else { return };
        if raw == 0 {
            return;
        }
        let mut mem = guest.memory();
        let addr: reverie::syscalls::AddrMut<u8> =
            unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(raw + mode_off) };
        let mode: u32 = libc::S_IFDIR | 0o755;
        let _ = mem.write(addr, &mode.to_ne_bytes());
    }

    /// Fake-root permission dance (proot fake_id0): temporarily
    /// grant owner rwx on each ancestor directory of `host`,
    /// returning (path, old_mode) pairs to restore afterwards.
    /// Only for fake uid 0 (non-root -i must not bypass DAC).
    fn chmod_ancestors(&self, host: &Path) -> Vec<(PathBuf, u32)> {
        use std::os::unix::fs::PermissionsExt as _;
        let mut saved = Vec::new();
        // The target directory itself too (rm -fr on a mode-000
        // dir must be able to open/list it).
        if let Ok(md) = std::fs::metadata(host) {
            if md.is_dir() {
                let mode = md.permissions().mode();
                if mode & 0o700 != 0o700
                    && std::fs::set_permissions(
                        host,
                        std::fs::Permissions::from_mode(mode | 0o700),
                    )
                    .is_ok()
                {
                    saved.push((host.to_path_buf(), mode));
                }
            }
        }
        let mut cur = PathBuf::from("/");
        let comps: Vec<_> = host.components().collect();
        for c in comps.iter().take(comps.len().saturating_sub(1)) {
            if let std::path::Component::Normal(n) = c {
                cur.push(n);
                if let Ok(md) = std::fs::metadata(&cur) {
                    let mode = md.permissions().mode();
                    if mode & 0o700 != 0o700 {
                        if std::fs::set_permissions(
                            &cur,
                            std::fs::Permissions::from_mode(mode | 0o700),
                        )
                        .is_ok()
                        {
                            saved.push((cur.clone(), mode));
                        }
                    }
                }
            }
        }
        saved
    }

    fn restore_ancestors(&self, saved: Vec<(PathBuf, u32)>) {
        use std::os::unix::fs::PermissionsExt as _;
        for (p, mode) in saved.into_iter().rev() {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode));
        }
    }

    /// /proc/<pid>/cmdline synthesis for process `target_pid`, chosen by
    /// [`Self::self_link_route`]: the kernel buffer names our loader argv;
    /// guests must see the as-exec'd argv. Returns a descriptor of a memfd
    /// holding it ([`Self::open_argv_memfd`]), or Ok(None) for the kernel's
    /// own file: no argv to synthesize, or no memfd.
    async fn open_synthetic_cmdline<T: Guest<Self>>(
        &self,
        guest: &mut T,
        target_pid: i32,
        call: CmdlineOpen,
    ) -> Result<Option<i64>, Error> {
        let argv: Vec<Vec<u8>> = if target_pid == guest.pid().as_raw() {
            let materialized = self.current_argv(guest.config());
            if materialized.is_empty() {
                return Ok(None);
            }
            materialized
        } else {
            let argv = match Self::shared_process_record(target_pid) {
                Some(row) => row.argv,
                None => match pid_argv_map().lock().unwrap().get(&target_pid) {
                    Some(a) => a.clone(),
                    None => return Ok(None),
                },
            };
            if argv.is_empty() {
                let init = guest.config().initial_argv.clone();
                if init.is_empty() {
                    return Ok(None);
                }
                init.into_iter().map(|s| s.into_bytes()).collect::<Vec<_>>()
            } else {
                argv
            }
        };
        self.open_argv_memfd(guest, &argv, call).await
    }

    /// A1: the cmdline of a process with a shared-record row, from the row
    /// alone. A row gone since the entry was selected, or a row with no
    /// argv, gets the kernel's own file (Ok(None)); the bare-pid argv cache
    /// and the caller's initial argv never answer for it.
    async fn open_shared_cmdline<T: Guest<Self>>(
        &self,
        guest: &mut T,
        pid: i32,
        call: CmdlineOpen,
    ) -> Result<Option<i64>, Error> {
        match Self::shared_process_record(pid) {
            Some(row) if !row.argv.is_empty() => self.open_argv_memfd(guest, &row.argv, call).await,
            _ => Ok(None),
        }
    }

    /// A1: the guest path of a shared-record row's exe, which an open or
    /// execve of that process's `exe` link reaches instead of the kernel's
    /// link (on the in-guest backends, the loader). None, for the kernel's
    /// own link, when the row is gone or has no exe.
    fn row_exe_guest(pid: i32) -> Option<PathBuf> {
        use std::os::unix::ffi::OsStringExt as _;
        let row = Self::shared_process_record(pid)?;
        (!row.exe_guest.is_empty()).then(|| PathBuf::from(std::ffi::OsString::from_vec(row.exe_guest)))
    }

    /// A cmdline literoot answers itself (§4.9.5): a memfd holding `argv`,
    /// each argument NUL-terminated. On ptrace the tracer makes it and the
    /// guest's own call reopens it ([`Self::open_cmdline_via_tracer`]).
    /// In-guest an injected memfd_create makes it in the guest
    /// (MFD_CLOEXEC exactly when the guest's open asked for O_CLOEXEC), and
    /// the Tool fills it at offset 0
    /// ([`write_guest_fd`]), so the guest's descriptor reads it from the
    /// start. Ok(None), with the fallback line, when it cannot be made; the
    /// kernel's own file then answers:
    /// - the probe gate is closed (a guest filter installed or being
    ///   installed, or the thread's dispatch ON or unreadable), so nothing
    ///   is injected;
    /// - memfd_create fails, or admission refuses it;
    /// - the write fails, or the calling thread's descriptor is not the
    ///   empty memfd just made; the memfd is closed first.
    async fn open_argv_memfd<T: Guest<Self>>(
        &self,
        guest: &mut T,
        argv: &[Vec<u8>],
        call: CmdlineOpen,
    ) -> Result<Option<i64>, Error> {
        let mut content: Vec<u8> = Vec::new();
        for a in argv {
            content.extend_from_slice(a);
            content.push(0);
        }
        if !guest.config().tool_in_guest() { // cmdline: memfd route
            return self.open_cmdline_via_tracer(guest, &content, call).await;
        }
        if self.injection_gate_closed(guest) {
            note_cmdline_fallback();
            return Ok(None);
        }
        let flags = if call.cloexec() { libc::MFD_CLOEXEC } else { 0 };
        // A staging failure is the fallback too, not the open's error.
        // The name has a scratch slot of its own:
        // admission stages its status read in the path slots first.
        let Ok(name) = self.scratch_write_at(guest, b"literoot-cmdline\0", SCRATCH_MEMFD_NAME).await else {
            note_cmdline_fallback();
            return Ok(None);
        };
        let create = reverie::syscalls::MemfdCreate::new()
            .with_name(PathPtr::from_ptr(name as *const libc::c_char))
            .with_flags(flags);
        let fd = match self.admitted_inject(guest, Syscall::MemfdCreate(create)).await {
            Some(Ok(fd)) => fd as i32,
            _ => {
                note_cmdline_fallback();
                return Ok(None);
            }
        };
        if !write_guest_fd(guest.tid().as_raw(), fd, &content) {
            let _ = guest.inject(reverie::syscalls::Close::new().with_fd(fd)).await;
            note_cmdline_fallback();
            return Ok(None);
        }
        Ok(Some(fd as i64))
    }

    /// The ptrace answer for a cmdline literoot synthesizes.
    /// The tracer makes the
    /// memfd, fills it, makes it 0444 and seals it, and the guest's own call
    /// is rewritten to reopen it through
    /// `/proc/<tracer pid>/task/<tracer tid>/fd/<n>` (the tracer thread's own
    /// table, which a thread of a tracer with unshared tables need not share
    /// with its leader). The guest's call is the only syscall it injects,
    /// and what it writes into the guest is that call's arguments, staged in
    /// the thread's scratch page: the rewritten name and, for openat2, a
    /// 24-byte open_how. A thread with no page yet takes one from the pool,
    /// or, the pool used up, maps a new pool first (an injected mmap, which
    /// the guest's filters see: [`Self::map_scratch`]). The staging is a
    /// tracer write into the guest, which ptrace allows only over a guest
    /// the tracer may attach to (a non-dumpable guest cannot be staged into
    /// unless the tracer is privileged; true of every translated call). The
    /// descriptor identity check below does not need it. In order:
    /// 1. Preconditions, else the fallback: [`tracer_route_ready`], and the
    ///    guest has not left the tracer's mount namespace
    ///    ([`mount_ns_moved`]). The guest's real root is the tracer's
    ///    (literoot emulates chroot and never injects one; pivot_root needs a
    ///    new mount namespace), and the rewritten name is absolute with the
    ///    re-rooting resolve bits cleared, so the guest resolves it in the
    ///    procfs the tracer sees.
    /// 2. The kernel's argument checks, run by the tracer on a copy of the
    ///    guest's arguments against descriptor -1, which opens nothing:
    ///    EBADF means valid; EINVAL, E2BIG and EAGAIN are the guest's answer,
    ///    and so is EFAULT for an unreadable open_how (and openat2's size
    ///    checks, fs/open.c, in the kernel's order). A success was made up
    ///    by a filter: the fallback, closing nothing. So is a copy of
    ///    open_how the tracer cannot lay out as the guest has it.
    /// 3. The answers the flags alone decide, in the kernel's order (the
    ///    final entry is an existing regular file): O_CREAT|O_EXCL is EEXIST,
    ///    O_DIRECTORY (O_TMPFILE too) is ENOTDIR, and a write access mode or
    ///    O_TRUNC is EACCES unless [`tracer_overrides_dac`]. Under O_PATH
    ///    only the ENOTDIR case applies.
    /// 4. The rewritten call, with O_NOFOLLOW cleared (the guest named a
    ///    regular file; the rewritten final entry is a magic link), and for
    ///    openat2 the [`RESOLVE_BENEATH`]-family bits cleared in a staged
    ///    24-byte copy of open_how (step 2 proved any longer tail zero).
    ///    EMFILE, ENFILE and ENOMEM are the guest's answer; any other error is
    ///    the fallback. A descriptor the tracer can inspect must name the
    ///    memfd (same device and inode), or it is closed and the fallback
    ///    answers; one it cannot inspect (a non-dumpable guest) stands on
    ///    step 1.
    /// 5. The tracer's descriptor closes when the call has returned, or when
    ///    the handler is dropped; a restart code (ERESTART*) keeps it, held
    ///    for that thread until its next route call or its exit.
    ///
    /// The fallback is Ok(None) with the fallback line: the arm opens the
    /// kernel's own file.
    async fn open_cmdline_via_tracer<T: Guest<Self>>(
        &self,
        guest: &mut T,
        content: &[u8],
        call: CmdlineOpen,
    ) -> Result<Option<i64>, Error> {
        use reverie::syscalls::Errno;
        use reverie::syscalls::MemoryAccess as _;
        use std::os::fd::AsRawFd as _;
        use std::os::fd::FromRawFd as _;
        use std::os::unix::fs::FileExt as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let fallback = || {
            note_cmdline_fallback();
            Ok(None)
        };
        let tid = guest.tid().as_raw();
        release_held_tracer_fd(tid);
        // 1.
        if !tracer_route_ready() || mount_ns_moved(guest.pid().as_raw()) {
            return fallback();
        }
        // 2.
        let raw = call.raw();
        let x = c"x".as_ptr();
        let last_errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let (probe, probe_errno, how) = match call {
            CmdlineOpen::Openat(_) => {
                // SAFETY: a plain syscall; "x" is a valid string, and
                // descriptor -1 opens nothing.
                let r = unsafe {
                    libc::syscall(libc::SYS_openat, -1, x, raw.arg2 as libc::c_int, raw.arg3 as libc::c_uint)
                };
                (r, last_errno(), None)
            }
            #[cfg(target_arch = "x86_64")]
            CmdlineOpen::Open(_) => {
                // SAFETY: as above.
                let r = unsafe {
                    libc::syscall(libc::SYS_openat, -1, x, raw.arg1 as libc::c_int, raw.arg2 as libc::c_uint)
                };
                (r, last_errno(), None)
            }
            CmdlineOpen::Openat2(..) => {
                let (at, size) = (raw.arg2, raw.arg3);
                // openat2's own order (fs/open.c, SYSCALL_DEFINE4(openat2)):
                // the size against OPEN_HOW_SIZE_VER0 and the page size;
                // then copy_struct_from_user (include/linux/uaccess.h):
                // access_ok over the range, the extension past the 24 bytes
                // (check_zeroed_user: word by word, E2BIG at the first
                // nonzero word, EFAULT at an unreadable one), and only then
                // the 24 bytes. The tracer's openat2 runs those checks on a
                // copy laid out as the guest has it.
                open_how_size_check(size, page_size()).map_err(Error::from)?;
                if !user_range_ok(at, size) {
                    return Err(Errno::EFAULT.into());
                }
                let read = |addr: usize, buf: &mut [u8]| {
                    reverie::syscalls::Addr::<u8>::from_raw(addr)
                        .is_some_and(|from| guest.memory().read_exact(from, buf).is_ok())
                };
                let Some(copy) = LayoutCopy::new(at, size, page_size(), read) else {
                    return fallback();
                };
                // SAFETY: as above; `copy` maps every page of the `size`
                // bytes at `copy.ptr()`, unreadable where the guest's are.
                let r = unsafe { libc::syscall(libc::SYS_openat2, -1, x, copy.ptr(), size) };
                let e = last_errno();
                let how = copy.readable_prefix(24).map(|bytes| {
                    let word = |i: usize| u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
                    reverie::syscalls::OpenHow {
                        flags: word(0),
                        mode: word(8),
                        resolve: word(16),
                    }
                });
                (r, e, how)
            }
        };
        // A relative name at descriptor -1 opens nothing, so a success was
        // made up (a filter's SECCOMP_RET_ERRNO | 0, or a user-notification
        // answer) and names no descriptor this probe owns: nothing is
        // closed.
        if probe >= 0 {
            return fallback();
        }
        match probe_errno {
            libc::EBADF => {}
            // EFAULT is openat2's copy of the guest's open_how (the probe's
            // own name is the tracer's): the guest's answer too.
            libc::EINVAL | libc::E2BIG | libc::EAGAIN | libc::EFAULT => {
                return Err(Errno::new(probe_errno).into());
            }
            _ => return fallback(),
        }
        // 3.
        let flags = call.flags();
        let flag = |f: libc::c_int| flags & f as u64 != 0;
        let o_path = flag(libc::O_PATH);
        if !o_path && flag(libc::O_CREAT) && flag(libc::O_EXCL) {
            return Err(Errno::EEXIST.into());
        }
        if flag(libc::O_DIRECTORY) {
            return Err(Errno::ENOTDIR.into());
        }
        let writes = flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 || flag(libc::O_TRUNC);
        if !o_path && writes && !tracer_overrides_dac() {
            return Err(Errno::EACCES.into());
        }
        // 4. The memfd, in the tracer.
        // SAFETY: a plain syscall with a valid string.
        let made = unsafe {
            libc::memfd_create(c"literoot-cmdline".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if made < 0 {
            return fallback();
        }
        // SAFETY: memfd_create returned this new descriptor; it is owned here.
        let memfd = unsafe { std::fs::File::from_raw_fd(made) };
        if memfd.write_all_at(content, 0).is_err()
            || memfd.set_permissions(std::fs::Permissions::from_mode(0o444)).is_err()
        {
            return fallback();
        }
        // SAFETY: a plain fcntl on a descriptor owned here. Sealing is best
        // effort: it keeps a guest that may write a 0444 file
        // (CAP_DAC_OVERRIDE) from changing the answer.
        unsafe {
            libc::fcntl(
                memfd.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
            )
        };
        let Ok(want) = memfd.metadata() else {
            return fallback();
        };
        // The tracer thread's own table (`task/<tid>`): a thread that
        // unshared its table is not the group leader's.
        // SAFETY: a plain query.
        let me = unsafe { libc::gettid() };
        let path = format!("/proc/{}/task/{me}/fd/{}", std::process::id(), memfd.as_raw_fd());
        let Ok((_g, name)) = self.with_guest_path(guest, Path::new(&path), |ptr| ptr as usize).await else {
            return fallback();
        };
        let nofollow = libc::O_NOFOLLOW as usize;
        let rewritten = match call {
            CmdlineOpen::Openat(_) => Syscall::from_raw(
                Sysno::openat,
                SyscallArgs::new(libc::AT_FDCWD as isize as usize, name, raw.arg2 & !nofollow, raw.arg3, 0, 0),
            ),
            #[cfg(target_arch = "x86_64")]
            CmdlineOpen::Open(_) => {
                Syscall::from_raw(Sysno::open, SyscallArgs::new(name, raw.arg1 & !nofollow, raw.arg2, 0, 0, 0))
            }
            CmdlineOpen::Openat2(..) => {
                // The probe's EBADF means the kernel copied the 24 bytes.
                let Some(how) = how else {
                    return fallback();
                };
                let cleared = RESOLVE_NO_XDEV
                    | RESOLVE_NO_MAGICLINKS
                    | RESOLVE_NO_SYMLINKS
                    | RESOLVE_BENEATH
                    | RESOLVE_IN_ROOT
                    | RESOLVE_CACHED;
                let mut staged = Vec::with_capacity(24);
                staged.extend_from_slice(&(how.flags & !(nofollow as u64)).to_ne_bytes());
                staged.extend_from_slice(&how.mode.to_ne_bytes());
                staged.extend_from_slice(&(how.resolve & !cleared).to_ne_bytes());
                let Ok(at) = self.scratch_write_at(guest, &staged, SCRATCH_OPEN_HOW).await else {
                    return fallback();
                };
                Syscall::from_raw(
                    Sysno::openat2,
                    SyscallArgs::new(libc::AT_FDCWD as isize as usize, name, at, staged.len(), 0, 0),
                )
            }
        };
        match guest.inject(rewritten).await {
            Ok(fd) => {
                let seen = std::fs::metadata(format!("/proc/{tid}/fd/{fd}"));
                #[cfg(test)]
                let seen = if GUEST_FDS_UNREADABLE.with(|s| s.get()) {
                    Err(std::io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    seen
                };
                if let Ok(md) = seen {
                    if (md.dev(), md.ino()) != (want.dev(), want.ino()) {
                        let _ = guest.inject(reverie::syscalls::Close::new().with_fd(fd as i32)).await;
                        return fallback();
                    }
                }
                Ok(Some(fd))
            }
            Err(e) => match e.into_raw() {
                // ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK
                512 | 513 | 514 | 516 => {
                    HELD_TRACER_FDS.lock().unwrap().insert(tid, memfd);
                    Err(e.into())
                }
                libc::EMFILE | libc::ENFILE | libc::ENOMEM => Err(e.into()),
                _ => fallback(),
            },
        }
    }

    /// Whether the probe gate is closed for an injection literoot makes on
    /// its own account, without counting it as a probe: a guest filter
    /// installed or being installed (trigger 3), or the thread's dispatch
    /// mode ON or unreadable (trigger 6).
    fn injection_gate_closed<T: Guest<Self>>(&self, guest: &T) -> bool {
        let (dispatch, _, _) = self.dispatch_mode_unnoted(guest);
        dispatch != Some(false) || self.state.lock().unwrap().admission(guest.pid().as_raw()).closed()
    }

    /// Open the nearest existing ancestor of a virtual bind
    /// dir and mark the fd virtual (entries synthesized).
    async fn open_virtual_dir<T: Guest<Self>>(
        &self,
        guest: &mut T,
        orig: reverie::syscalls::Openat,
        guest_abs: &Path,
    ) -> Result<Option<i64>, Error> {
        let cfg = self.config(guest);
        let mut anc = guest_abs.to_path_buf();
        loop {
            if !anc.pop() {
                return Ok(None);
            }
            let host = cfg.translate(&anc, Path::new("/"), None);
            if host.is_dir() {
                // Open the rootfs root as placeholder fd: the
                // ancestor itself may be unreadable in-guest
                // (mode -rw in test-readdir-nested-bindings).
                let host = cfg.rootfs.clone();
                let (_g, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        orig.with_path(PathPtr::from_ptr(ptr))
                            .with_dirfd(libc::AT_FDCWD)
                    })
                    .await?;
                let fd = guest.inject(rewritten).await?;
                if fd >= 0 {
                    let mut st = self.state.lock().unwrap();
                    let files = files_of(guest);
                    st.forget(files, fd as i32);
                    let t = st.fdt_mut(files);
                    t.virtual_fds.insert(fd as i32, guest_abs.to_path_buf());
                    t.fds.insert(fd as i32, guest_abs.to_path_buf());
                }
                return Ok(Some(fd));
            }
        }
    }

    /// Synthesize linux_dirent64 records for a virtual dir:
    /// "." ".." plus one entry per bind child at this level.
    fn synth_dirents<T: Guest<Self>>(
        &self,
        guest: &mut T,
        dirent: Option<reverie::syscalls::AddrMut<libc::dirent64>>,
        count: u32,
        guest_dir: &Path,
    ) -> i64 {
        use reverie::syscalls::MemoryAccess as _;
        let Some(dirent) = dirent else { return 0 };
        if std::env::var_os("PROOT_DONT_POLLUTE_ROOTFS").is_some() {
            return 0;
        }
        let cfg = self.config(guest);
        let mut entries: Vec<(String, u8, u64)> =
            vec![(".".into(), 4, 0), ("..".into(), 4, 0)];
        for b in &cfg.binds {
            if let Ok(rest) = b.guest.strip_prefix(guest_dir) {
                let mut comps = rest.components();
                if let Some(first) = comps.next() {
                    let name = first.as_os_str().to_string_lossy().into_owned();
                    if entries.iter().any(|(n, _, _)| *n == name) {
                        continue;
                    }
                    let (ty, ino) = if comps.next().is_some() {
                        (4u8, 0u64)
                    } else {
                        match std::fs::metadata(&b.host) {
                            Ok(md) => {
                                use std::os::unix::fs::MetadataExt as _;
                                (
                                    if md.is_dir() {
                                        4
                                    } else if md.file_type().is_symlink() {
                                        10
                                    } else {
                                        8
                                    },
                                    md.ino(),
                                )
                            }
                            Err(_) => (8, 0),
                        }
                    };
                    entries.push((name, ty, ino));
                }
            }
        }
        let mut out: Vec<u8> = Vec::new();
        for (name, ty, ino) in &entries {
            let reclen = (19 + name.len() + 1 + 7) & !7;
            if out.len() + reclen > count as usize {
                break;
            }
            let off = (out.len() + reclen) as u64;
            out.extend_from_slice(&ino.to_ne_bytes());
            out.extend_from_slice(&off.to_ne_bytes());
            out.extend_from_slice(&(reclen as u16).to_ne_bytes());
            out.push(*ty);
            out.extend_from_slice(name.as_bytes());
            out.resize(out.len() + (reclen - (19 + name.len())), 0);
        }
        if out.is_empty() {
            return 0;
        }
        let mut mem = guest.memory();
        let addr: reverie::syscalls::AddrMut<u8> =
            unsafe { std::mem::transmute_copy(&dirent) };
        match mem.write(addr, &out) {
            Ok(_) => out.len() as i64,
            Err(_) => 0,
        }
    }

    fn record_dirent_names<T: Guest<Self>>(
        &self,
        guest: &mut T,
        fd: i32,
        dirent: Option<reverie::syscalls::AddrMut<libc::dirent64>>,
        total: usize,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        let Some(dirent) = dirent else { return };
        let mem = guest.memory();
        let base: reverie::syscalls::Addr<u8> =
            unsafe { std::mem::transmute_copy(&dirent) };
        let mut buf = vec![0u8; total];
        if mem.read(base, &mut buf).is_err() {
            return;
        }
        let mut names = std::collections::HashSet::new();
        let mut off = 0usize;
        while off + 19 <= buf.len() {
            let reclen =
                u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 19 || off + reclen > buf.len() {
                break;
            }
            let name_bytes = &buf[off + 19..off + reclen];
            let end = name_bytes
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(name_bytes.len());
            names.insert(String::from_utf8_lossy(&name_bytes[..end]).into_owned());
            off += reclen;
        }
        let files = files_of(guest);
        self.state.lock().unwrap().stream_mut(files, fd).seen = Some(names);
    }

    /// Build synthetic dirents for bind children of `guest_dir`
    /// (skipping names the kernel already returned when dedupe).
    fn build_synth_dirents<T: Guest<Self>>(
        &self,
        guest: &T,
        guest_dir: &Path,
        dedupe: bool,
    ) -> Vec<u8> {
        // PROOT_DONT_POLLUTE_ROOTFS: virtual entries stay
        // traversable (stat) but are hidden from listings.
        if std::env::var_os("PROOT_DONT_POLLUTE_ROOTFS").is_some() {
            return Vec::new();
        }
        let cfg = self.config(guest);
        let seen: std::collections::HashSet<String> = if dedupe {
            // fd unknown here; caller dedupes via dirent_seen in
            // synth_dirents path. This builder returns all.
            Default::default()
        } else {
            Default::default()
        };
        let mut entries: Vec<(String, u8, u64)> = Vec::new();
        for b in &cfg.binds {
            if let Ok(rest) = b.guest.strip_prefix(guest_dir) {
                let mut comps = rest.components();
                if let Some(first) = comps.next() {
                    let name = first.as_os_str().to_string_lossy().into_owned();
                    if seen.contains(&name)
                        || entries.iter().any(|(n, _, _)| *n == name)
                    {
                        continue;
                    }
                    let (ty, ino) = if comps.next().is_some() {
                        (4u8, 0u64)
                    } else {
                        match std::fs::metadata(&b.host) {
                            Ok(md) => {
                                use std::os::unix::fs::MetadataExt as _;
                                (
                                    if md.is_dir() {
                                        4
                                    } else if md.file_type().is_symlink() {
                                        10
                                    } else {
                                        8
                                    },
                                    md.ino(),
                                )
                            }
                            Err(_) => (8, 0),
                        }
                    };
                    entries.push((name, ty, ino));
                }
            }
        }
        // Dedupe against kernel-seen names for this fd is done by
        // filtering here via dirent_seen when present.
        let mut out: Vec<u8> = Vec::new();
        for (name, ty, ino) in &entries {
            let reclen = (19 + name.len() + 1 + 7) & !7;
            let off = (out.len() + reclen) as u64;
            out.extend_from_slice(&ino.to_ne_bytes());
            out.extend_from_slice(&off.to_ne_bytes());
            out.extend_from_slice(&(reclen as u16).to_ne_bytes());
            out.push(*ty);
            out.extend_from_slice(name.as_bytes());
            out.resize(out.len() + (reclen - (19 + name.len())), 0);
        }
        out
    }

    /// Fake-id stat post-processing (proot rule: files owned by
    /// the caller's real uid/gid show the fake ids).
    fn spoof_stat_ids<T: Guest<Self>>(
        &self,
        guest: &mut T,
        buf_raw: Option<usize>,
        uid_off: usize,
        gid_off: usize,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        let Some((fu, fg)) = self.fake_ids(guest) else { return };
        let Some(raw) = buf_raw else { return };
        if raw == 0 {
            return;
        }
        let mut mem = guest.memory();
        let read32 = |mem: &<T as Guest<Self>>::Memory, off: usize| -> Option<u32> {
            let addr: reverie::syscalls::AddrMut<u8> =
                unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(raw + off) };
            let a: reverie::syscalls::Addr<u8> =
                unsafe { std::mem::transmute_copy(&addr) };
            let mut b = [0u8; 4];
            mem.read(a, &mut b).ok()?;
            Some(u32::from_ne_bytes(b))
        };
        let real_uid = unsafe { libc::getuid() };
        let real_gid = unsafe { libc::getgid() };
        if read32(&mem, uid_off) == Some(real_uid) {
            let addr: reverie::syscalls::AddrMut<u8> =
                unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(raw + uid_off) };
            let _ = mem.write(addr, &fu.to_ne_bytes());
        }
        if read32(&mem, gid_off) == Some(real_gid) {
            let addr: reverie::syscalls::AddrMut<u8> =
                unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(raw + gid_off) };
            let _ = mem.write(addr, &fg.to_ne_bytes());
        }
    }

    fn seed_cwd<T: Guest<Self>>(&self, guest: &T) -> PathBuf {
        let cwd = guest.config().cwd.clone();
        if cwd.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(cwd)
        }
    }

    fn guest_abs<T: Guest<Self>>(
        &self,
        guest: &T,
        st: &ProcState,
        dirfd: i32,
        path: &Path,
    ) -> PathBuf {
        // Launch cwd from the guest handle, authoritative on every
        // backend. The previous CONFIG process-global fallback only
        // worked when every Tool lived in the tracer process (B4).
        let cfg_cwd = if st.cwd == Path::new("/__literoot_unset__") {
            self.seed_cwd(guest)
        } else {
            st.cwd.clone()
        };
        if path.is_absolute() {
            path.to_path_buf()
        } else if dirfd != libc::AT_FDCWD {
            let cfg = self.config_locked(guest, st);
            match self.fd_guest_path(guest, &cfg, st, dirfd) {
                Some(mut p) => {
                    p.push(path);
                    p
                }
                None => path.to_path_buf(),
            }
        } else {
            let mut p = cfg_cwd;
            p.push(path);
            p
        }
    }

    /// True when a relative path's dirfd has no guest path or is not a
    /// directory (unknown, stale, deleted, a pipe): the syscall must pass through
    /// untranslated so the kernel reports ENOTDIR/EBADF itself
    /// (test-openat-fd-edge-cases). Recoverable dirfds are
    /// cached into the fd table.
    fn dirfd_passthrough<T: Guest<Self>>(&self, guest: &T, dirfd: i32, path: &Path) -> bool {
        if path.is_absolute() || dirfd == libc::AT_FDCWD {
            return false;
        }
        let cfg = self.config(guest);
        let live = std::fs::metadata(format!("{}/fd/{}", task_dir(guest), dirfd));
        let mut st = self.state.lock().unwrap();
        // fd_guest_path checks a table entry against the open file, so a
        // stale entry never stops a passthrough.
        match (self.fd_guest_path(guest, &cfg, &st, dirfd), live) {
            (Some(g), Ok(md)) if md.is_dir() => {
                st.fdt_mut(files_of(guest)).fds.insert(dirfd, g);
                false
            }
            // /proc unreadable: the table entry stands, as before.
            (Some(_), Err(_)) => false,
            // A named non-directory: the kernel's ENOTDIR at the fd.
            (Some(_), Ok(_)) => true,
            // No guest name: only where the kernel cannot leave the fd
            // ([`unnamed_route`]); otherwise translation walks or refuses.
            (None, _) => {
                let base = format!("{}/fd/{}", task_dir(guest), dirfd);
                unnamed_route(&cfg, &base, path) == UnnamedRoute::Raw
            }
        }
    }

    /// [`FinalProc`] of the selected final host path `host`.
    fn final_proc<T: Guest<Self>>(&self, guest: &T, host: &Path) -> FinalProc {
        let cfg = self.config(guest);
        let links = GuestProcLinks::new(&cfg, guest.pid().as_raw(), guest.tid().as_raw());
        final_proc_entry(host, &links)
    }

    /// What an open or execve of `path` does with a self link,
    /// decided by the selected FINAL entry for the whole spelled path:
    /// synthesize for an owned process's procfs exe link or cmdline file,
    /// answer a shared-record row's exe and cmdline from the row, and walk
    /// anything else (another process's entries, a file or symlink bound
    /// there, a planted rootfs entry, a dangling symlink), so the kernel
    /// answers it. Plain `-r` keeps its synthesis only where the walk
    /// positively found no `/proc` or `/proc/<x>` (ENOENT). Names that
    /// cannot be a magic link or cmdline file skip the check.
    ///
    /// A call that follows a final symlink (`follow`: an open without
    /// O_NOFOLLOW, an execve) is decided again on the entry the follow
    /// resolves to in the guest's view, the host path it will inject: a
    /// symlink (or a chain of them) to the caller's own cmdline or exe is
    /// synthesized, and to a row's is answered from the row, exactly as if
    /// spelled (P1-B). A follow that cannot be resolved is that walk's own
    /// answer (a named refusal, or the guest's ELOOP). A call that does not
    /// follow ([`open_follows`]) opens an exe link itself, the caller's own
    /// or a row's, as the kernel does (ELOOP, or the link under O_PATH):
    /// the synthesis and the row answer only a follow.
    fn self_link_route<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
        follow: bool,
    ) -> Result<SelfLink, reverie::syscalls::Errno> {
        let spelled = self.spelled_self_link(guest, dirfd, path)?;
        if !follow {
            return match spelled {
                SelfLink::RowExe(_) => Ok(SelfLink::Walk),
                // The caller's own exe link is a link too:
                // the kernel opens it itself, ELOOP or the link
                // under O_PATH. Without /proc, where literoot presents the
                // link as existing, the consistent answer is ELOOP (plan
                // check note on Q4).
                SelfLink::Exe => {
                    if proc_parent_absent(&self.translate_for(guest, dirfd, path)?)? {
                        Err(reverie::syscalls::Errno::ELOOP)
                    } else {
                        Ok(SelfLink::Walk)
                    }
                }
                other => Ok(other),
            };
        }
        if spelled != SelfLink::Walk {
            return Ok(spelled);
        }
        let resolved = self.translate_follow(guest, dirfd, path)?;
        Ok(self.final_self_link(guest, self.final_proc(guest, &resolved)).unwrap_or(SelfLink::Walk))
    }

    /// The answer an owned or shared-record [`FinalProc`] gets at an open
    /// or execve; None for every other entry. The own exe test compares
    /// thread groups ([`final_proc_entry`] normalizes the link's pid).
    fn final_self_link<T: Guest<Self>>(&self, guest: &T, entry: FinalProc) -> Option<SelfLink> {
        use crate::translate::MagicKind;
        match entry {
            FinalProc::OwnedLink(link) if link.kind == MagicKind::Exe && link.pid == guest.pid().as_raw() => {
                Some(SelfLink::Exe)
            }
            // Another owned process's exe (a traced child on ptrace, whose
            // kernel link names the loader under literoot's exec model)
            // answers from its row, as a guest child's does
            // (ruled: the row, never pid_exe_map). Without a row, the
            // kernel's link.
            FinalProc::OwnedLink(link) if link.kind == MagicKind::Exe && has_shared_row(link.pid) => {
                Some(SelfLink::RowExe(link.pid))
            }
            FinalProc::OwnedCmdline(pid) => Some(SelfLink::Cmdline(pid)),
            FinalProc::SharedCmdline(pid) => Some(SelfLink::SharedCmdline(pid)),
            FinalProc::SharedExe(pid) => Some(SelfLink::RowExe(pid)),
            FinalProc::OwnedLink(_) | FinalProc::SharedLink(_) | FinalProc::Ordinary => None,
        }
    }

    /// [`Self::self_link_route`] on the spelled final entry, its final
    /// symlink not followed.
    fn spelled_self_link<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<SelfLink, reverie::syscalls::Errno> {
        if !final_name_may_be_proc(path) {
            return Ok(SelfLink::Walk);
        }
        let own = guest.pid().as_raw();
        let host = self.translate_for(guest, dirfd, path)?;
        let entry = self.final_proc(guest, &host);
        if let Some(answer) = self.final_self_link(guest, entry) {
            return Ok(answer);
        }
        Ok(if entry != FinalProc::Ordinary || !spells_proc_self_link(path) || !proc_parent_absent(&host)? {
            SelfLink::Walk
        } else if is_self_exe(path, own) {
            SelfLink::Exe
        } else {
            match spelled_cmdline_pid(path, own) {
                Some(pid) => SelfLink::Cmdline(pid),
                None => SelfLink::Walk,
            }
        })
    }

    /// The host path of a guest path, its final symlink not followed.
    /// More than 40 symlinks on the way is the guest's ELOOP.
    fn translate_for<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<PathBuf, reverie::syscalls::Errno> {
        self.translate_for_links(guest, dirfd, path)
            .map(|(host, _)| host)
    }

    /// [`Self::translate_for`] with the symlinks the walk followed, so a
    /// final-link resolution can continue the same 40-link budget.
    fn translate_for_links<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<(PathBuf, u32), reverie::syscalls::Errno> {
        self.translate_for_route(guest, dirfd, path)
            .map(|(host, links, _, _)| (host, links))
    }

    /// [`Self::translate_for_links`], also returning the guest route the
    /// walk came through: the canonical guest directory it walked from
    /// (the one an unnamed base's ".." landed on included) joined with the
    /// name. None when the name went to the kernel as is.
    fn translate_for_route<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<Walked, reverie::syscalls::Errno> {
        if let Some(hit) = self.memoized_translate(guest.tid().as_raw(), dirfd, path, false) {
            return hit.map_err(walk_errno);
        }
        let hit = self.translate_for_uncached(guest, dirfd, path);
        self.memoize_translate(guest.tid().as_raw(), dirfd, path, false, &hit);
        hit.map_err(walk_errno)
    }

    /// The memoized translation of this dispatch, if any. A failed walk is
    /// memoized too, so its refusal is noted once however many helpers
    /// translate the same name.
    fn memoized_translate(
        &self,
        tid: i32,
        dirfd: i32,
        path: &Path,
        follow: bool,
    ) -> Option<Result<Walked, crate::translate::WalkError>> {
        let st = self.state.lock().unwrap();
        let key = (tid, dirfd, path.to_path_buf(), follow);
        st.translate_memo
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.clone())
    }

    fn memoize_translate(
        &self,
        tid: i32,
        dirfd: i32,
        path: &Path,
        follow: bool,
        hit: &Result<Walked, crate::translate::WalkError>,
    ) {
        if let Err(e) = hit {
            note_walk_error(e);
        }
        let mut st = self.state.lock().unwrap();
        st.translate_memo.push(((tid, dirfd, path.to_path_buf(), follow), hit.clone()));
    }

    fn translate_for_uncached<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<Walked, crate::translate::WalkError> {
        let cfg = self.config(guest);
        let st = self.state.lock().unwrap();
        let cwd = if st.cwd == Path::new("/__literoot_unset__") {
            self.seed_cwd(guest)
        } else {
            st.cwd.clone()
        };
        // Unknown dirfds (inherited, SCM_RIGHTS, stdin...) recover
        // through /proc/<pid>/fd in fd_guest_path.
        let dirfd_guest = if dirfd == libc::AT_FDCWD {
            None
        } else {
            self.fd_guest_path(guest, &cfg, &st, dirfd)
        };
        let searched = st.searched_bases.contains(&(guest.tid().as_raw(), dirfd));
        // An empty path with a real dirfd (AT_EMPTY_PATH, or a call that
        // must fail ENOENT without it) names the fd's own object, which
        // the kernel already holds: leave it empty, so each syscall's own
        // empty-path rule applies (readlinkat(fd, "") on an O_PATH symlink
        // reads that link; translating would follow it).
        if dirfd != libc::AT_FDCWD && path.as_os_str().is_empty() {
            return Ok((PathBuf::new(), 0, None, OtherLink::None));
        }
        // A dirfd with no guest path (deleted, pipe, socket, outside every
        // mapped tree, closed), or a cwd with none ([`unnamed_route`]):
        // where the kernel can only fail at the object itself (ENOENT in a
        // deleted directory, ENOTDIR for a pipe) the name goes through it;
        // a ".." the kernel would take to a live directory continues from
        // that directory's guest name; a live directory with no guest name
        // is refused, since the kernel would walk the host's tree from it.
        let mut cwd = cwd;
        let mut dirfd_guest = dirfd_guest;
        let walked: PathBuf;
        let original = path;
        let mut path = path;
        if let Some(base) = unnamed_base(guest, dirfd, &cwd, dirfd_guest.as_deref(), path) {
            match unnamed_route(&cfg, &base, path) {
                UnnamedRoute::Raw if path.as_os_str().is_empty() => {
                    return Ok((PathBuf::new(), 0, None, OtherLink::None));
                }
                UnnamedRoute::Raw => return Ok((Path::new(&base).join(path), 0, None, OtherLink::None)),
                UnnamedRoute::Refused(kind) => {
                    return Err(crate::translate::WalkError::Refused(kind));
                }
                // Only the dead-base answer at dispatch can give the kernel's
                // argument checks and search check first; a translation that
                // reaches one without it fails closed. Where the gate was
                // closed at dispatch, this is that route's refusal: counted.
                UnnamedRoute::DeadName => {
                    drop(st);
                    self.count_closed_gate(guest);
                    return Err(crate::translate::WalkError::Refused(
                        crate::translate::PathRefusal::ProbeUnsupported,
                    ));
                }
                UnnamedRoute::Guest { climbed: true, .. } if !searched => {
                    drop(st);
                    self.count_closed_gate(guest);
                    return Err(crate::translate::WalkError::Refused(
                        crate::translate::PathRefusal::ProbeUnsupported,
                    ));
                }
                UnnamedRoute::Guest { dir, rest, .. } => {
                    cwd = dir;
                    dirfd_guest = None;
                    walked = guest_rest(rest);
                    path = &walked;
                }
            }
        }
        // Unknown non-path dirfd: relative resolution against cwd
        // would fabricate ENOENT where the kernel says ENOTDIR.
        // Signal via cwd sentinel handled by callers is complex;
        // the common case (dirfd is a real directory) recovers
        // above. Remaining unknown fds keep cwd-relative
        // behaviour — retained gap for pipe/socket dirfds is
        // fixed by the Openat arm's explicit check below.
        let _ = &dirfd_guest;
        let mut links = 0;
        let policy = GuestProcLinks::new(&cfg, guest.pid().as_raw(), guest.tid().as_raw());
        let mut host =
            cfg.translate_walk(path, &cwd, dirfd_guest.as_deref(), &mut links, &policy)?;
        let route = if path.is_absolute() {
            path.to_path_buf()
        } else {
            dirfd_guest.as_deref().unwrap_or(&cwd).join(path)
        };
        if std::env::var_os("LITEROOT_DEBUG").is_some() {
            eprintln!("literoot-tool: translate {path:?} cwd={cwd:?} -> {host:?}");
        }
        // Preserve a trailing slash: the kernel distinguishes
        // readlink/open on "x/" (ENOTDIR/EINVAL) from "x", and
        // lexical normalization would erase it.
        {
            use std::os::unix::ffi::OsStrExt as _;
            let bytes = original.as_os_str().as_bytes();
            if bytes.len() > 1 && bytes.ends_with(b"/") {
                host.push("");
            }
        }
        Ok((host, links, Some(route), policy.other_link()))
    }

    /// translate_for + final-component symlink following, for
    /// syscalls that follow symlinks (open/stat/access). Lstat and
    /// readlink must use plain translate_for. The final links share
    /// the walk's 40-link budget; more is the guest's ELOOP.
    fn translate_follow<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<PathBuf, reverie::syscalls::Errno> {
        self.translate_follow_uncached(guest, dirfd, path)
            .map(|(host, _, _, _)| host)
    }

    /// [`Self::translate_follow`], also returning the canonical guest path
    /// of what it reached (every link, ".", ".." and trailing slash
    /// resolved, the bind route kept), when the walk has a guest name. None
    /// after a Raw hand-over of another process's directory link: what the
    /// call reaches then is only known once it has run.
    fn translate_follow_guest<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<(PathBuf, Option<PathBuf>), reverie::syscalls::Errno> {
        self.translate_follow_uncached(guest, dirfd, path)
            .map(|(host, _, resolved, other)| (host, if other == OtherLink::Raw { None } else { resolved }))
    }

    fn translate_follow_uncached<T: Guest<Self>>(
        &self,
        guest: &T,
        dirfd: i32,
        path: &Path,
    ) -> Result<Walked, reverie::syscalls::Errno> {
        if let Some(hit) = self.memoized_translate(guest.tid().as_raw(), dirfd, path, true) {
            return hit.map_err(walk_errno);
        }
        let cfg = self.config(guest);
        // The final symlink is resolved from the guest route the walk came
        // through, keeping that alias; with none (the name went to the
        // kernel as is), a relative target is refused, never joined on the
        // host side.
        let (host, mut links, guest_path, other) = self.translate_for_route(guest, dirfd, path)?;
        let policy = GuestProcLinks::new(&cfg, guest.pid().as_raw(), guest.tid().as_raw());
        // The walk's Raw hand-over carries on into the final chain: a
        // relative target then resolves from the host parent, and its route
        // is not a stable guest directory.
        policy.carry(other);
        let hit = resolve_symlink_chain_guest(&cfg, guest_path, host, &mut links, Some(&policy))
            .map(|(resolved, resolved_guest)| {
                (resolved, links, resolved_guest, policy.other_link())
            });
        self.memoize_translate(guest.tid().as_raw(), dirfd, path, true, &hit);
        hit.map_err(walk_errno)
    }

    /// The dead-base answer at dispatch (fix 4: Ord, E1, P', C). For a call
    /// with a relative name whose base is a deleted directory (a dead NAME,
    /// or a ".." climb out of one), in the kernel's order:
    /// 1. the call's own argument checks: the probe ([`crate::dead_base`]);
    /// 2. the guest's own search check of every directory the walk
    ///    searches (E1);
    /// 3. the Tool's climb and decide;
    /// 4. the base re-read: the base must still be the directory decided
    ///    on (`base_moved` otherwise).
    ///
    /// Some(answer) ends the call here; None lets its arm translate it (a
    /// live base, or a climb whose search check passed, recorded in
    /// `searched_bases`).
    async fn dead_base_gate<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Option<Result<i64, Error>> {
        use crate::dead_base::Probe;
        use reverie::syscalls::SyscallInfo as _;
        let (nr, raw) = syscall.into_parts();
        let entry = crate::dead_base::dead_base_probe(nr)?;
        // A path call enters translation here (S.3's `translated`).
        self.state
            .lock()
            .unwrap()
            .admission(guest.pid().as_raw())
            .note_translation();
        if let Probe::Bind | Probe::Connect = entry.probe {
            return self.dead_base_socket(guest, nr, raw, entry).await;
        }
        let args = [raw.arg0, raw.arg1, raw.arg2, raw.arg3, raw.arg4, raw.arg5];
        // Two UTIME_OMITs succeed before the path is looked at: the arm
        // answers it (so would the probe, which is never trusted).
        let times: Option<reverie::syscalls::Addr<[libc::timespec; 2]>> =
            reverie::syscalls::FromToRaw::from_raw(args[2]);
        if let (Sysno::utimensat, Some(times)) = (nr, times) {
            if let Ok([a, m]) = guest.memory().read_value(times) {
                if a.tv_nsec == libc::UTIME_OMIT && m.tv_nsec == libc::UTIME_OMIT {
                    return None;
                }
            }
        }
        let cfg = self.config(guest);
        let mut gated = Vec::new();
        let mut gate_checked = false;
        for slot in entry.slots {
            let ptr: Option<PathPtr> =
                reverie::syscalls::FromToRaw::from_raw(args[slot.path as usize]);
            // An unreadable or absent name is the arm's (its own EFAULT).
            let Some(path) = ptr.and_then(|p| p.read(&guest.memory()).ok()) else {
                continue;
            };
            if path.as_os_str().is_empty() || path.is_absolute() {
                continue;
            }
            let dirfd = slot
                .dirfd
                .map(|i| args[i as usize] as i32)
                .unwrap_or(libc::AT_FDCWD);
            let Some(base) = self.unnamed_base_of(guest, &cfg, dirfd, &path) else {
                continue;
            };
            // S.3 placement: the gate is checked at the top of the
            // dead-base route, before C.1's reads and gather_*, without
            // counting. Closed, the call goes to its arm, which answers
            // exactly as without fix 4 (EBADF, ENOTDIR, a translation) and
            // refuses a dead-base name by name, counted there.
            if !gate_checked {
                gate_checked = true;
                if self.gate_closed_quiet(guest) {
                    return None;
                }
            }
            let dead_name = match unnamed_route(&cfg, &base, &path) {
                UnnamedRoute::DeadName => true,
                UnnamedRoute::Guest { climbed: true, .. } => false,
                _ => continue,
            };
            gated.push(GatedName {
                dirfd,
                identity: base_identity(&base),
                base,
                path,
                dead_name,
            });
        }
        if gated.is_empty() {
            return None;
        }
        // A dead-base route reached the gate: counted here. It was open at
        // the top; one that closed since is refused by name.
        if self.admission_closed(guest) {
            return Some(self.refuse_probe(crate::translate::PathRefusal::ProbeUnsupported));
        }
        // Step 1: the argument checks.
        if let Probe::T1 { nr: probe_nr, args: probe_args } = entry.probe {
            let names = match (
                self.scratch_write_at(guest, b"x\0", SCRATCH_PROBE_X).await,
                self.scratch_write_at(guest, b"y\0", SCRATCH_PROBE_Y).await,
            ) {
                (Ok(x), Ok(y)) => [x, y],
                (Err(e), _) | (_, Err(e)) => return Some(Err(e)),
            };
            let probe = crate::dead_base::build_t1(probe_nr, &probe_args, &raw, names);
            let result = match self.admitted_inject(guest, probe).await {
                Some(r) => r,
                None => {
                    return Some(
                        self.refuse_probe(crate::translate::PathRefusal::ProbeUnsupported),
                    );
                }
            };
            match crate::dead_base::classify(entry.probe, entry.pre_lookup, result) {
                crate::dead_base::ProbeOutcome::LookupReached => {}
                crate::dead_base::ProbeOutcome::Answer(e) => return Some(Err(e.into())),
                crate::dead_base::ProbeOutcome::Unsupported => {
                    return Some(
                        self.refuse_probe(crate::translate::PathRefusal::ProbeUnsupported),
                    );
                }
            }
        }
        // Steps 2-4, then the local answer.
        let open_flags = self.open_flags_of(guest, nr, &args);
        self.search_and_decide(guest, &cfg, entry, gated, open_flags)
            .await
    }

    /// Steps 2-4 of the dead-base answer for each gated name, in order: the
    /// guest's search check, the base re-read, and the Tool's decide. A
    /// dead NAME then gets EISDIR (an O_CREAT open of `x/`) or ENOENT, each
    /// recorded as `answered path dead_base_name`; a climb that lands on a
    /// live directory is left to the arm.
    async fn search_and_decide<T: Guest<Self>>(
        &self,
        guest: &mut T,
        cfg: &RootConfig,
        entry: crate::dead_base::Entry,
        gated: Vec<GatedName>,
        open_flags: Option<u64>,
    ) -> Option<Result<i64, Error>> {
        use crate::translate::PathRefusal;
        use reverie::syscalls::Errno;
        // setxattr and lsetxattr have no probe (D, P2-D1): where the answer
        // would come from the dead-base path, the argument errors native
        // gives first cannot be reproduced, so it is refused by name.
        let unavailable = entry.probe == crate::dead_base::Probe::Unavailable;
        for g in gated {
            let name = crate::dead_base::search_name(&g.path);
            let flags = crate::dead_base::search_flags(entry.ids, &name);
            let mut staged = name.as_os_str().as_bytes().to_vec();
            staged.push(0);
            if staged.len() > SCRATCH_SEARCH_MAX {
                return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
            }
            let ptr = match self
                .scratch_write_at(guest, &staged, SCRATCH_SEARCH)
                .await
            {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            let check = Syscall::Other(
                Sysno::faccessat2,
                reverie::syscalls::SyscallArgs::new(
                    g.dirfd as isize as usize,
                    ptr,
                    libc::X_OK as usize,
                    flags as usize,
                    0,
                    0,
                ),
            );
            let Some(result) = self.admitted_inject(guest, check).await else {
                return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
            };
            match result {
                Ok(0) => {}
                Err(e) if e == Errno::EACCES && !unavailable => {
                    note_path_report(Refusal::Answered(PathAnswer::DeadBaseSearch));
                    return Some(Err(Errno::EACCES.into()));
                }
                _ => return Some(self.refuse_probe(PathRefusal::ProbeUnsupported)),
            }
            // Step 4: the base is still the directory the gate decided on.
            if g.identity.is_none() || base_identity(&g.base) != g.identity {
                return Some(self.refuse_probe(PathRefusal::BaseMoved));
            }
            // Step 3: the Tool's climb and decide, after the search check.
            match unnamed_route(cfg, &g.base, &g.path) {
                UnnamedRoute::DeadName if g.dead_name => {
                    if unavailable {
                        return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
                    }
                    let answer = if open_flags.is_some_and(|f| {
                        crate::dead_base::create_with_trailing_slash(&g.path, f)
                    }) {
                        Errno::EISDIR
                    } else {
                        Errno::ENOENT
                    };
                    note_path_report(Refusal::Answered(PathAnswer::DeadBaseName));
                    return Some(Err(answer.into()));
                }
                UnnamedRoute::Guest { climbed: true, .. } if !g.dead_name => {
                    let tid = guest.tid().as_raw();
                    self.state.lock().unwrap().searched_bases.push((tid, g.dirfd));
                }
                UnnamedRoute::Refused(kind) => return Some(self.refuse_probe(kind)),
                // The base changed class between the decide and now.
                _ => return Some(self.refuse_probe(PathRefusal::BaseMoved)),
            }
        }
        None
    }

    /// The dead-base answer for bind and connect with a relative AF_UNIX
    /// name in a deleted cwd (fix 4, section C): the socket kind from the
    /// Tool's own /proc reads, then T3 (bind) or T4 (connect), the re-read
    /// of the descriptor, and steps 2-4.
    async fn dead_base_socket<T: Guest<Self>>(
        &self,
        guest: &mut T,
        nr: Sysno,
        raw: reverie::syscalls::SyscallArgs,
        entry: crate::dead_base::Entry,
    ) -> Option<Result<i64, Error>> {
        use crate::translate::PathRefusal;
        let fd = raw.arg0 as i32;
        let addrlen = raw.arg2 as i32;
        if !(3..=110).contains(&addrlen) {
            return None;
        }
        let addr: Option<reverie::syscalls::Addr<u8>> =
            reverie::syscalls::FromToRaw::from_raw(raw.arg1);
        let addr = addr?;
        let mut buf = vec![0u8; addrlen as usize];
        guest.memory().read(addr, &mut buf).ok()?;
        // AF_UNIX, non-abstract, relative.
        if u16::from_ne_bytes([buf[0], buf[1]]) != libc::AF_UNIX as u16
            || buf[2] == 0
            || buf[2] == b'/'
        {
            return None;
        }
        let end = buf[2..]
            .iter()
            .position(|&c| c == 0)
            .map(|p| p + 2)
            .unwrap_or(buf.len());
        use std::os::unix::ffi::OsStringExt as _;
        let path = PathBuf::from(std::ffi::OsString::from_vec(buf[2..end].to_vec()));
        let cfg = self.config(guest);
        let base = self.unnamed_base_of(guest, &cfg, libc::AT_FDCWD, &path)?;
        // S.3 placement: the gate first, before C.1's reads and gather_*,
        // without counting; closed, the call goes to its arm (as above).
        if self.gate_closed_quiet(guest) {
            return None;
        }
        let dead_name = match unnamed_route(&cfg, &base, &path) {
            UnnamedRoute::DeadName => true,
            UnnamedRoute::Guest { climbed: true, .. } => false,
            _ => return None,
        };
        let identity = base_identity(&base);
        // A dead-base route reached the gate: counted here (as above).
        if self.admission_closed(guest) {
            return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
        }
        // C step 1: the socket kind, from the Tool's own reads.
        let kind = match socket_kind(&task_dir(guest), fd) {
            Ok(kind) => kind,
            Err(SocketRead::Answer(e)) => return Some(Err(e.into())),
            Err(SocketRead::Unsupported) => {
                return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
            }
        };
        // C step 2: not positively AF_UNIX in the task's network namespace.
        if !kind.unix {
            return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
        }
        // C steps 3-4: T3 or T4 on the guest's own socket.
        let mut staged = [0u8; 128];
        staged[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        let len = if entry.probe == crate::dead_base::Probe::Bind {
            staged[2] = b'/';
            4
        } else {
            2
        };
        let ptr = match self.scratch_write_at(guest, &staged, SCRATCH_SOCKADDR).await {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        let probe = Syscall::Other(
            nr,
            reverie::syscalls::SyscallArgs::new(fd as isize as usize, ptr, len, 0, 0, 0),
        );
        let result = self.admitted_inject(guest, probe).await;
        // C step 5': the descriptor must still hold the socket identified
        // in step 1, before the result is used for anything.
        let Some(result) = result else {
            return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
        };
        if !socket_unchanged(&task_dir(guest), fd, &kind.link) {
            return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
        }
        match crate::dead_base::classify(entry.probe, entry.pre_lookup, result) {
            crate::dead_base::ProbeOutcome::LookupReached => {}
            crate::dead_base::ProbeOutcome::Answer(e) => return Some(Err(e.into())),
            crate::dead_base::ProbeOutcome::Unsupported => {
                return Some(self.refuse_probe(PathRefusal::ProbeUnsupported));
            }
        }
        let gated = vec![GatedName {
            dirfd: libc::AT_FDCWD,
            identity,
            base,
            path,
            dead_name,
        }];
        self.search_and_decide(guest, &cfg, entry, gated, None).await
    }

    /// The unnamed base a relative `path` resolves from (the calling task's
    /// cwd or dirfd through /proc), or None when its base has a guest name.
    fn unnamed_base_of<T: Guest<Self>>(
        &self,
        guest: &T,
        cfg: &RootConfig,
        dirfd: i32,
        path: &Path,
    ) -> Option<String> {
        let st = self.state.lock().unwrap();
        let cwd = if st.cwd == Path::new("/__literoot_unset__") {
            self.seed_cwd(guest)
        } else {
            st.cwd.clone()
        };
        let dirfd_guest = if dirfd == libc::AT_FDCWD {
            None
        } else {
            self.fd_guest_path(guest, cfg, &st, dirfd)
        };
        unnamed_base(guest, dirfd, &cwd, dirfd_guest.as_deref(), path)
    }

    /// The open flags of an open-family call, for the EISDIR check.
    fn open_flags_of<T: Guest<Self>>(&self, guest: &T, nr: Sysno, args: &[usize; 6]) -> Option<u64> {
        match nr {
            #[cfg(target_arch = "x86_64")]
            Sysno::open => Some(args[1] as u64),
            Sysno::openat => Some(args[2] as u64),
            // open_how's first field is the flags.
            Sysno::openat2 => {
                let how: Option<reverie::syscalls::Addr<u64>> =
                    reverie::syscalls::FromToRaw::from_raw(args[2]);
                guest.memory().read_value(how?).ok()
            }
            _ => None,
        }
    }

    /// A guest prctl(PR_SET_SYSCALL_USER_DISPATCH, mode, ...). In-guest, a
    /// mode other than OFF is refused (R1): EOPNOTSUPP and the dispatch line,
    /// nothing injected and the tracked mode left as it was, so no ordinary
    /// route reaches a BLOCK state. Otherwise the call is forwarded as the
    /// exact pending call, with no injection before it in this handler (C2.3),
    /// and the thread's tracked mode follows C2.2's rule. None for every other
    /// call.
    async fn dispatch_setter<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Option<Result<i64, Error>> {
        use reverie::syscalls::SyscallInfo as _;
        let (nr, raw) = syscall.into_parts();
        let args = [raw.arg0, raw.arg1, raw.arg2, raw.arg3, raw.arg4, raw.arg5].map(|a| a as u64);
        let mode = crate::dead_base::dispatch_setter_mode(nr, args)?;
        if crate::dead_base::refuses_dispatch_setter(guest.config().refuse_guest_dispatch, mode) {
            note_guest_refusal(GuestKind::SyscallUserDispatch);
            return Some(Err(reverie::syscalls::Errno::EOPNOTSUPP.into()));
        }
        // ON until the result is known: a cancelled call stays ON (C2.2).
        let was_on = std::mem::replace(&mut guest.thread_state_mut().sud_on, true);
        let result = guest.inject(syscall).await;
        let value = match result {
            Ok(r) => r,
            Err(e) => -(e.into_raw() as i64),
        };
        guest.thread_state_mut().sud_on =
            crate::dead_base::tracked_dispatch_after(was_on, mode, Some(value));
        Some(result.map_err(Into::into))
    }

    /// The probing thread's dispatch mode for trigger 6 (C1.1): Some(on), or
    /// None when it cannot be read (the probe fails closed), and whether it
    /// came from prctl tracking (`sud_fallback`). On the ptrace backend the
    /// kernel's own config is read from the tracer; EIO (before Linux 6.4),
    /// EINVAL (another struct size) and ENOSYS (something between literoot
    /// and the kernel) fall back to tracking, once-per-run noted; any other
    /// error fails closed. In-guest tracking is the only source.
    fn probe_dispatch_mode<T: Guest<Self>>(&self, guest: &T) -> (Option<bool>, bool) {
        let (mode, fallback, note) = self.dispatch_mode_unnoted(guest);
        if let Some(e) = note {
            note_dispatch_fallback(e);
        }
        (mode, fallback)
    }

    /// [`Self::probe_dispatch_mode`] without its fallback note: the mode,
    /// whether it came from tracking, and the config-read errno that made it.
    fn dispatch_mode_unnoted<T: Guest<Self>>(&self, guest: &T) -> (Option<bool>, bool, Option<i32>) {
        let tracked = guest.thread_state().sud_on;
        if guest.config().tool_in_guest() { // trigger 6: in-guest mode from tracking
            return (Some(tracked), true, None);
        }
        match read_dispatch_config(guest.tid().as_raw()) {
            Ok(on) => (Some(on), false, None),
            Err(e @ (libc::EIO | libc::EINVAL | libc::ENOSYS)) => (Some(tracked), true, Some(e)),
            Err(_) => (None, false, None),
        }
    }

    /// The first-callback filter count check (baseline delta (A)), in-guest:
    /// at a record's first thread start, before any guest call is
    /// translated, the count must equal the image's baseline plus the
    /// record's addend; otherwise the record latches and every probe,
    /// the first call's included, is refused. A flagged record skips the
    /// read: no fix-4 injection runs under a guest filter, and its probes
    /// are refused anyway.
    async fn first_callback_check<T: Guest<Self>>(&self, guest: &mut T) {
        if !guest.config().tool_in_guest() { // first-callback check: in-guest only
            return;
        }
        let pid = guest.pid().as_raw();
        {
            let mut st = self.state.lock().unwrap();
            let admission = st.admission(pid);
            if admission.first_check_done {
                return;
            }
            if admission.guest_filter {
                admission.first_check_done = true;
                return;
            }
        }
        let observed = self.guest_filter_count(guest).await;
        self.state
            .lock()
            .unwrap()
            .admission(pid)
            .first_callback_check(filter_baseline(), observed);
    }

    /// The calling thread's `Seccomp_filters` (C3.6), read untranslated
    /// through Tool injections: open, read and close of the host's
    /// /proc/self/status, staged in the scratch page's arm area, which no
    /// probe uses. Not host-authentic: the read follows the process's root
    /// and mount namespace (§4.9). None when unreadable or unparsable.
    async fn guest_filter_count<T: Guest<Self>>(&self, guest: &mut T) -> Option<u32> {
        use reverie::syscalls::MemoryAccess as _;
        let open = reverie::syscalls::Openat::new()
            .with_dirfd(libc::AT_FDCWD)
            .with_flags(reverie::syscalls::OFlag::O_RDONLY | reverie::syscalls::OFlag::O_CLOEXEC);
        let (_g, open) = self
            .with_guest_path(guest, Path::new("/proc/self/status"), |ptr| {
                open.with_path(PathPtr::from_ptr(ptr))
            })
            .await
            .ok()?;
        let fd = guest.inject(open).await.ok()? as i32;
        let buf = self.scratch_write_at(guest, &[], SCRATCH_STATUS).await.ok();
        let mut text = Vec::new();
        let complete = match buf {
            None => false,
            Some(buf) => loop {
                let addr: reverie::syscalls::AddrMut<u8> =
                    unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(buf) };
                let read = reverie::syscalls::Read::new()
                    .with_fd(fd)
                    .with_buf(Some(addr))
                    .with_len(SCRATCH_STATUS_LEN);
                match guest.inject(read).await {
                    Ok(0) => break true,
                    Ok(n) if n > 0 && (n as usize) <= SCRATCH_STATUS_LEN && text.len() < 65536 => {
                        let mut chunk = vec![0u8; n as usize];
                        let from: reverie::syscalls::Addr<u8> =
                            unsafe { reverie::syscalls::Addr::from_raw_unchecked(buf) };
                        if guest.memory().read_exact(from, &mut chunk).is_err() {
                            break false;
                        }
                        text.extend_from_slice(&chunk);
                    }
                    _ => break false,
                }
            },
        };
        let _ = guest.inject(reverie::syscalls::Close::new().with_fd(fd)).await;
        if !complete {
            return None;
        }
        u32::try_from(crate::dead_base::status_field(&text, b"Seccomp_filters")?).ok()
    }

    /// The record's kernel_id, read once, on the ptrace backend only: the
    /// tracer's own pidfd for the process, its pidfs inode (Linux 6.9+), else
    /// 0. Kernel metadata, not authenticated, not the identity. In-guest it
    /// is never collected (fix 4 makes no guest syscall for metadata) and
    /// the summaries carry 0, "uncollected".
    fn note_kernel_id<T: Guest<Self>>(&self, guest: &T) {
        if guest.config().tool_in_guest() { // kernel_id: never collected in-guest
            return;
        }
        let pid = guest.pid().as_raw();
        let mut st = self.state.lock().unwrap();
        let admission = st.admission(pid);
        if admission.kernel_id.is_none() {
            admission.kernel_id = Some(pidfs_inode(pid).unwrap_or(0));
        }
    }

    /// A guest seccomp filter install (S.3), forwarded unchanged under the
    /// thread group's admission: refused at once (EOPNOTSUPP and its line)
    /// while any probe of the group is in flight, never waiting; otherwise
    /// the attempt note is reported, the install injected, and its result
    /// recorded. No lock is held across the injection, and a cancelled
    /// installer gives the gate back ([`PendingInstall`]). None for every
    /// other call.
    async fn seccomp_install<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Option<Result<i64, Error>> {
        use reverie::syscalls::SyscallInfo as _;
        let (nr, raw) = syscall.into_parts();
        let args = [raw.arg0, raw.arg1, raw.arg2, raw.arg3, raw.arg4, raw.arg5].map(|a| a as u64);
        if !crate::dead_base::installs_seccomp_filter(nr, args) {
            return None;
        }
        let pid = guest.pid().as_raw();
        self.note_kernel_id(guest);
        let begun = self.state.lock().unwrap().admission(pid).begin_install();
        let ticket = match begun {
            Ok(ticket) => ticket,
            Err(in_flight) => {
                note_path_report(Refusal::InstallRefused { in_flight });
                return Some(Err(reverie::syscalls::Errno::EOPNOTSUPP.into()));
            }
        };
        let mut install = PendingInstall {
            state: &self.state,
            pid,
            ticket: Some(ticket),
            injecting: false,
        };
        // Reported before the injection, while no filter exists yet: a
        // filter that kills the process cannot lose it.
        note_now(guest, Note::FilterInstallAttempted).await;
        install.injecting = true;
        let result = guest.inject(syscall).await;
        install.finish(match result {
            Ok(r) => r,
            Err(e) => -(e.into_raw() as i64),
        });
        Some(result.map_err(Into::into))
    }

    /// Inject `probe` under the thread group's admission (S.3): None when
    /// it is refused (a guest filter installed or pending). The count is
    /// given back only when the result arrives.
    async fn admitted_inject<T: Guest<Self>>(
        &self,
        guest: &mut T,
        probe: Syscall,
    ) -> Option<Result<i64, reverie::syscalls::Errno>> {
        let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
        let ticket = self.state.lock().unwrap().admission(pid).admit(tid)?;
        // C3.6: in-guest, the filter count is checked after admission and
        // before the probe's injection.
        if guest.config().tool_in_guest() { // detector: in-guest filter count
            let observed = self.guest_filter_count(guest).await;
            let mut st = self.state.lock().unwrap();
            let admission = st.admission(pid);
            if !admission.filter_count_admits(filter_baseline(), observed) {
                admission.release(ticket);
                return None;
            }
        }
        let result = guest.inject(probe).await;
        self.state.lock().unwrap().admission(pid).release(ticket);
        Some(result)
    }

    /// The probe gate at the top of the dead-base route (S.3), where
    /// a route has reached it (counted in `probes`): true, and counted, when
    /// a guest filter is installed or being installed (trigger 3, `refused`)
    /// or the probing thread's syscall user dispatch is ON or unreadable
    /// (trigger 6, `sud_refused`).
    fn admission_closed<T: Guest<Self>>(&self, guest: &T) -> bool {
        self.note_kernel_id(guest);
        let (dispatch, fallback) = self.probe_dispatch_mode(guest);
        self.state
            .lock()
            .unwrap()
            .admission(guest.pid().as_raw())
            .probe_gate(dispatch, fallback)
    }

    /// The gate at the top of the dead-base route, without counting (S.3,
    /// P2-C1): closed when a guest filter is installed or being installed
    /// (trigger 3) or the thread's dispatch mode is ON or unreadable
    /// (trigger 6). Closed, the dispatch is remembered with its mode, so the
    /// arm's dead-base refusal counts it once ([`Self::count_closed_gate`]).
    fn gate_closed_quiet<T: Guest<Self>>(&self, guest: &T) -> bool {
        let (dispatch, fallback, note) = self.dispatch_mode_unnoted(guest);
        let mut st = self.state.lock().unwrap();
        let closed = st.admission(guest.pid().as_raw()).closed() || dispatch != Some(false);
        if closed {
            let seq = st.dispatch_seq;
            st.gate_closed_at = Some(GateClosed { seq, dispatch, fallback, note });
        }
        closed
    }

    /// Count a dead-base route's refusal whose gate was found closed at
    /// this dispatch, once: `probes`, and `refused` or `sud_refused`, as the
    /// open-gate path counts them.
    fn count_closed_gate<T: Guest<Self>>(&self, guest: &T) {
        let gate = {
            let mut st = self.state.lock().unwrap();
            match st.gate_closed_at {
                Some(g) if g.seq == st.dispatch_seq => st.gate_closed_at.take(),
                _ => None,
            }
        };
        let Some(gate) = gate else { return };
        self.note_kernel_id(guest);
        if let Some(e) = gate.note {
            note_dispatch_fallback(e);
        }
        self.state
            .lock()
            .unwrap()
            .admission(guest.pid().as_raw())
            .probe_gate(gate.dispatch, gate.fallback);
    }

    /// A probe refusal by name: EACCES and its line.
    fn refuse_probe(&self, kind: crate::translate::PathRefusal) -> Result<i64, Error> {
        note_path_report(Refusal::Path(kind));
        Err(reverie::syscalls::Errno::EACCES.into())
    }

    /// openat2 answers some errors before it looks at the path, so a
    /// translation failure must not replace them. Ask the kernel with the
    /// same open_how and size and a lookup that cannot start: the name "x"
    /// (staged in literoot's scratch mapping) against descriptor -1, so no
    /// flag combination (O_CREAT, O_TMPFILE, RESOLVE_*) can create or open
    /// anything. Only the errnos the kernel returns before lookup count;
    /// anything else (EBADF, from the lookup's start) means the arguments
    /// are valid and the translation error stands. In a v6.18.55-based
    /// tree:
    /// - EINVAL: usize < OPEN_HOW_SIZE_VER0 (fs/open.c:1480-1481); invalid
    ///   flags, resolve, scoping, mode, O_DIRECTORY|O_CREAT, O_TMPFILE and
    ///   O_PATH combinations in build_open_flags (fs/open.c:1259-1301),
    ///   which do_sys_openat2 runs first (fs/open.c:1427-1429);
    /// - E2BIG: usize > PAGE_SIZE (fs/open.c:1482-1483), or non-zero bytes
    ///   past the known struct (copy_struct_from_user,
    ///   include/linux/uaccess.h:403-405);
    /// - EFAULT: open_how unreadable (include/linux/uaccess.h:405, :409);
    ///   the probe's own name is always readable;
    /// - EMFILE: no free descriptor (get_unused_fd_flags, fs/open.c:1435,
    ///   fs/file.c:591), before do_filp_open.
    ///
    /// The probe is a call the guest did not make, so it runs as every
    /// other probe does: only with the probe gate open (no guest filter
    /// installed, pending or flagged, and the thread's dispatch mode OFF),
    /// checked without counting, and under the thread group's admission
    /// (S.3). With the gate closed the translation error stands, even where
    /// the kernel would answer an argument error first (a known difference,
    /// docs/design.md 4.9.3). A success, which only a filter can make on
    /// descriptor -1, names no descriptor the probe owns: nothing is closed
    /// (S.4).
    async fn openat2_arguments_first<T: Guest<Self>>(
        &self,
        guest: &mut T,
        oa: reverie::syscalls::Openat2,
        translation: Error,
    ) -> Result<i64, Error> {
        use reverie::syscalls::Errno;
        if self.gate_closed_quiet(guest) {
            return Err(translation);
        }
        // Its own scratch slot: admission stages its status read in the
        // path slots before the probe runs.
        let name = self
            .scratch_write_at(guest, b"x\0", SCRATCH_PROBE_NAME)
            .await?;
        let probe = oa
            .with_dirfd(-1)
            .with_path(PathPtr::from_ptr(name as *const libc::c_char));
        match self.admitted_inject(guest, Syscall::Openat2(probe)).await {
            Some(Err(errno))
                if [Errno::EINVAL, Errno::E2BIG, Errno::EFAULT, Errno::EMFILE].contains(&errno) =>
            {
                Err(errno.into())
            }
            _ => Err(translation),
        }
    }

    /// openat2's arguments, checked before a synthesized cmdline answers.
    /// The same probe as [`Self::openat2_arguments_first`] (the
    /// guest's open_how and size against descriptor -1, which opens
    /// nothing), behind the probe gate and under the thread group's
    /// admission (S.3). Ok(true) only for EBADF, the lookup's start: the
    /// arguments are valid and the synthesis answers. The pre-lookup errors
    /// (EINVAL, E2BIG, EFAULT, EMFILE) are the guest's answer. Ok(false)
    /// when the probe proves nothing (a closed gate, admission refused, or
    /// any other outcome, a success included; nothing is closed, S.4): the
    /// kernel's own file then answers, and checks the arguments itself.
    async fn openat2_guarded_probe<T: Guest<Self>>(
        &self,
        guest: &mut T,
        oa: reverie::syscalls::Openat2,
    ) -> Result<bool, Error> {
        use reverie::syscalls::Errno;
        if self.admission_closed(guest) {
            return Ok(false);
        }
        // Its own scratch slot: admission stages its status read in the
        // path slots before the probe runs.
        let name = self.scratch_write_at(guest, b"x\0", SCRATCH_PROBE_NAME).await?;
        let probe = oa.with_dirfd(-1).with_path(PathPtr::from_ptr(name as *const libc::c_char));
        match self.admitted_inject(guest, Syscall::Openat2(probe)).await {
            Some(Err(Errno::EBADF)) => Ok(true),
            Some(Err(errno))
                if [Errno::EINVAL, Errno::E2BIG, Errno::EFAULT, Errno::EMFILE].contains(&errno) =>
            {
                Err(errno.into())
            }
            _ => Ok(false),
        }
    }

    /// Stage a translated AF_UNIX sockaddr copy on the guest stack.
    /// Some((guard, raw_ptr, new_addrlen)) or None to pass through
    /// (non-Unix family, abstract socket, fault). Relative names are
    /// translated too: the kernel would resolve them, and any symlink in
    /// them, in the host's namespace. `follow` resolves a final symlink
    /// (connect looks the socket up following one; bind creates it and
    /// does not). A relative name the kernel resolves exactly as the guest
    /// walk did ([`Self::kernel_resolves_as_guest`]) goes to the kernel as
    /// the guest spelled it, at any length; any other name goes as its host
    /// path, and one longer than sun_path holds is ENAMETOOLONG.
    async fn stage_sockaddr<T: Guest<Self>>(
        &self,
        guest: &mut T,
        addr: Option<reverie::syscalls::AddrMut<'_, libc::sockaddr>>,
        addrlen: i32,
        follow: bool,
    ) -> Result<
        Option<(
            <<T as Guest<Self>>::Stack as reverie::Stack>::StackGuard,
            usize,
            i32,
        )>,
        Error,
    > {
        use reverie::syscalls::MemoryAccess as _;
        use reverie::Stack as _;
        use std::os::unix::ffi::OsStrExt as _;
        let Some(addr) = addr else { return Ok(None) };
        if !(3..=110).contains(&addrlen) {
            return Ok(None);
        }
        let mem = guest.memory();
        let base: reverie::syscalls::AddrMut<u8> =
            unsafe { std::mem::transmute_copy(&addr) };
        let base_r: reverie::syscalls::Addr<u8> =
            unsafe { std::mem::transmute_copy(&base) };
        let mut buf = vec![0u8; addrlen as usize];
        if mem.read(base_r, &mut buf).is_err() {
            return Ok(None);
        }
        // AF_UNIX=1, non-abstract (sun_path[0] != 0).
        if buf[0] != libc::AF_UNIX as u8 || buf.get(2).is_none_or(|&c| c == 0) {
            return Ok(None);
        }
        let end = buf[2..]
            .iter()
            .position(|&c| c == 0)
            .map(|p| p + 2)
            .unwrap_or(buf.len());
        use std::os::unix::ffi::OsStringExt as _;
        let guest_path =
            PathBuf::from(std::ffi::OsString::from_vec(buf[2..end].to_vec()));
        let (host, links) = if follow {
            let (host, links, _, _) =
                self.translate_follow_uncached(guest, libc::AT_FDCWD, &guest_path)?;
            (host, links)
        } else {
            self.translate_for_links(guest, libc::AT_FDCWD, &guest_path)?
        };
        // A relative name the kernel resolves exactly as the guest walk did
        // goes as the guest spelled it, at any length, so getsockname
        // answers what it answers natively. Otherwise the host path, which
        // must fit sun_path with its terminating NUL.
        const SUN_PATH_MAX: usize = 107;
        let name = if self.kernel_resolves_as_guest(guest, &guest_path, &host, links) {
            guest_path.as_os_str().as_bytes().to_vec()
        } else if host.as_os_str().len() <= SUN_PATH_MAX {
            host.as_os_str().as_bytes().to_vec()
        } else {
            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
        };
        let mut out = [0u8; 128];
        out[0] = buf[0];
        out[1] = buf[1];
        out[2..2 + name.len()].copy_from_slice(&name);
        let mut stack = guest.stack().await;
        let a = stack.push(out);
        let guard = stack.commit()?;
        let raw = unsafe { a.as_ptr() } as usize;
        // A name filling all 108 bytes of sun_path has no NUL; Linux takes
        // it with addrlen 110, the size of sockaddr_un, and rejects a longer
        // one (unix_validate_addr and unix_mkname_bsd, net/unix/af_unix.c).
        let len = 2 + name.len() + usize::from(name.len() <= SUN_PATH_MAX);
        Ok(Some((guard, raw, len as i32)))
    }

    /// Whether the kernel, given the guest's own relative spelling, resolves
    /// it to `host` exactly as the guest walk did: the name is relative and
    /// has no ".." component; the walk followed no link, the final
    /// component included; it crosses no bind (the host path is the
    /// translated cwd joined with the name, which a bind would change); and
    /// the kernel's cwd is that translated cwd. Then no part of the name is
    /// left for the kernel to resolve differently, apart from a concurrent
    /// change to the tree or the cwd (the time-of-check race every
    /// translation has).
    fn kernel_resolves_as_guest<T: Guest<Self>>(
        &self,
        guest: &T,
        guest_path: &Path,
        host: &Path,
        links: u32,
    ) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        use std::path::Component;
        if guest_path.is_absolute() || links != 0 {
            return false;
        }
        let mut relative = PathBuf::new();
        for component in guest_path.components() {
            match component {
                Component::Normal(name) => relative.push(name),
                Component::CurDir => {}
                _ => return false,
            }
        }
        // A final link the call itself would not follow (bind).
        if std::fs::symlink_metadata(host).is_ok_and(|m| m.file_type().is_symlink()) {
            return false;
        }
        // Before the first chdir the cwd is the launch directory, as in
        // every translation (translate_for_uncached).
        let cwd = self.state.lock().unwrap().cwd.clone();
        let cwd = if cwd == Path::new("/__literoot_unset__") {
            self.seed_cwd(guest)
        } else {
            cwd
        };
        if cwd == Path::new(UNNAMED_CWD) {
            return false;
        }
        let cwd_host = self.config(guest).translate(&cwd, Path::new("/"), None);
        if cwd_host.join(&relative) != host {
            return false;
        }
        let kernel_cwd = std::fs::metadata(format!("{}/cwd", task_dir(guest)));
        match (kernel_cwd, std::fs::metadata(&cwd_host)) {
            (Ok(kernel), Ok(translated)) => {
                kernel.dev() == translated.dev() && kernel.ino() == translated.ino()
            }
            _ => false,
        }
    }

    fn detranslate_sockaddr<T: Guest<Self>>(
        &self,
        guest: &mut T,
        addr: Option<reverie::syscalls::AddrMut<libc::sockaddr>>,
        len_ptr: Option<reverie::syscalls::AddrMut<libc::socklen_t>>,
    ) {
        use reverie::syscalls::MemoryAccess as _;
        let (Some(addr), Some(len_ptr)) = (addr, len_ptr) else { return };
        let mut mem = guest.memory();
        let len_addr: reverie::syscalls::AddrMut<u8> =
            unsafe { std::mem::transmute_copy(&len_ptr) };
        let mut lenb = [0u8; 4];
        let len_a: reverie::syscalls::Addr<u8> =
            unsafe { std::mem::transmute_copy(&len_addr) };
        if mem.read(len_a, &mut lenb).is_err() {
            return;
        }
        let total = (u32::from_ne_bytes(lenb) as usize).min(110);
        if total <= 2 {
            return;
        }
        let base: reverie::syscalls::AddrMut<u8> =
            unsafe { std::mem::transmute_copy(&addr) };
        let base_r: reverie::syscalls::Addr<u8> =
            unsafe { std::mem::transmute_copy(&base) };
        let mut buf = vec![0u8; total];
        if mem.read(base_r, &mut buf).is_err() {
            return;
        }
        if buf[0] != libc::AF_UNIX as u8 || buf[2] == 0 {
            return;
        }
        let end = buf[2..].iter().position(|&c| c == 0).map(|p| p + 2).unwrap_or(total);
        use std::os::unix::ffi::OsStringExt as _;
        let host_path = PathBuf::from(
            std::ffi::OsString::from_vec(buf[2..end].to_vec()),
        );
        let cfg = self.config(guest);
        if let Some(g) = cfg.reverse(&host_path) {
            use std::os::unix::ffi::OsStrExt as _;
            let gb = g.as_os_str().as_bytes();
            let new_total = 2 + gb.len() + 1;
            if new_total <= 110 {
                let mut out = vec![0u8; new_total];
                out[0] = buf[0];
                out[1] = buf[1];
                out[2..2 + gb.len()].copy_from_slice(gb);
                let _ = mem.write(base, &out);
                let _ = mem.write(len_addr, &(new_total as u32).to_ne_bytes());
            }
        }
    }

    /// Post-process a readlink result: de-translate the stored
    /// target in the guest buffer (design §4.5). On any memory
    /// fault the original result stands (never corrupt a
    /// successful readlink).
    /// A1: readlink of a shared-row process's exe, answered without
    /// injecting anything: the row's exe, written as the kernel writes a
    /// link (truncated to `buf_len`, no NUL counted). None for every other
    /// entry, and for a row gone since the entry was selected or with no
    /// exe: the kernel's answer.
    fn shared_row_readlink<T: Guest<Self>>(
        &self,
        guest: &mut T,
        final_entry: FinalProc,
        buf: Option<reverie::syscalls::AddrMut<libc::c_char>>,
        buf_len: usize,
    ) -> Option<Result<i64, Error>> {
        use reverie::syscalls::MemoryAccess as _;
        let FinalProc::SharedExe(pid) = final_entry else {
            return None;
        };
        let row = Self::shared_process_record(pid).filter(|row| !row.exe_guest.is_empty())?;
        // The kernel takes bufsiz as an int and refuses one <= 0
        // (do_readlinkat, fs/stat.c), so only the low 32 bits count.
        let bufsiz = buf_len as i32;
        if bufsiz <= 0 {
            return Some(Err(reverie::syscalls::Errno::EINVAL.into()));
        }
        let Some(buf) = buf else {
            return Some(Err(reverie::syscalls::Errno::EFAULT.into()));
        };
        let n = row.exe_guest.len().min(bufsiz as usize);
        let addr: reverie::syscalls::AddrMut<u8> = unsafe { std::mem::transmute_copy(&buf) };
        if guest.memory().write(addr, &row.exe_guest[..n]).is_err() {
            return Some(Err(reverie::syscalls::Errno::EFAULT.into()));
        }
        Some(Ok(n as i64))
    }

    fn detranslate_into<T: Guest<Self>>(
        &self,
        guest: &mut T,
        link_host: &Path,
        link_guest: &Path,
        final_entry: FinalProc,
        buf: Option<reverie::syscalls::AddrMut<libc::c_char>>,
        buf_len: usize,
        ret: i64,
    ) -> i64 {
        use reverie::syscalls::MemoryAccess as _;
        if ret <= 0 {
            return ret;
        }
        let Some(buf) = buf else { return ret };
        let n = (ret as usize).min(buf_len);
        let mut mem = guest.memory();
        let addr: reverie::syscalls::AddrMut<u8> =
            unsafe { std::mem::transmute_copy(&buf) };
        let mut stored = vec![0u8; n];
        if mem.read(addr, &mut stored).is_err() {
            return ret;
        }
        // A full buffer (ret == buf_len) may hold a truncated
        // host-form target. De-translating the truncated bytes
        // would return a short guest length, which a caller
        // growing its buffer while readlink fills it (gnulib
        // areadlink starts at 64 and doubles) reads as the
        // complete target. Re-read the link Tool-side so
        // de-translation starts from the complete stored
        // target; the write below truncates to buf_len exactly
        // as the kernel does, preserving the fill-signals-
        // growth protocol in guest-visible terms. On any
        // re-read failure the kernel-written bytes stand. The
        // re-read names the calling thread's entry, as the
        // kernel's read did: thread-self is its own task.
        if ret as usize >= buf_len {
            use std::os::unix::ffi::OsStrExt as _;
            let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
            if let Ok(full) = std::fs::read_link(host_for_tool_read(link_host, pid, tid)) {
                stored = full.as_os_str().as_bytes().to_vec();
            }
        }
        let cfg = self.config(guest);
        // An owned process's exe and the guest's own root are synthesized
        // from replicated state, not de-translated: the kernel values name
        // the loader / host root under our exec model. Which link it is
        // comes from the selected final entry, never the spelling.
        //
        // A guest process's link (its own or a row's) is answered by its
        // owner, whatever the naming: a numeric pid answers as /proc/self
        // does.
        use crate::translate::MagicKind;
        use std::os::unix::ffi::OsStrExt as _;
        let own = guest.pid().as_raw();
        let link_of = match final_entry {
            FinalProc::OwnedLink(l) | FinalProc::SharedLink(l) => Some((l.kind, l.pid)),
            _ => None,
        };
        let guest_bytes = match link_of {
            // The guest root, "/", for every guest process (before this
            // change the caller's own answered the host rootfs path, and a
            // row's the kernel's "/").
            Some((MagicKind::Root, _)) => b"/".to_vec(),
            Some((MagicKind::Exe, pid)) if pid == own => {
                let raw = self.exe_guest(guest);
                if self.state.lock().unwrap().exe_host {
                    // No guest name: the host file the exec reached.
                    raw.as_os_str().as_bytes().to_vec()
                } else {
                    self.canonical_exe(guest, &raw).as_os_str().as_bytes().to_vec()
                }
            }
            // Disclosed residual: without a row, an
            // owned child's exe falls back to pid_exe_map, keyed by bare
            // pid, so a reused pid or a fork child can read a stale value.
            // A row with no exe (an exec that reached a file with no guest
            // name) is the kernel's link, as for a shared row,
            // never an empty answer or that cache.
            Some((MagicKind::Exe, other)) => match Self::shared_process_record(other) {
                Some(row) if row.exe_guest.is_empty() => {
                    cfg.detranslate_readlink(link_host, link_guest, &stored)
                }
                Some(row) => row.exe_guest,
                None => match pid_exe_map().lock().unwrap().get(&other) {
                    Some(p) => p.as_os_str().as_bytes().to_vec(),
                    None => cfg.detranslate_readlink(link_host, link_guest, &stored),
                },
            },
            // cwd, fd/<n> and map_files/<r>: kernel-generated host paths,
            // reversed globally (deepest host binding), as the /proc/self
            // spellings are.
            Some(_) => match Path::new(std::ffi::OsStr::from_bytes(&stored)) {
                t if t.is_absolute() => match cfg.reverse(t) {
                    Some(g) => g.as_os_str().as_bytes().to_vec(),
                    None => stored.clone(),
                },
                _ => stored.clone(),
            },
            None => cfg.detranslate_readlink(link_host, link_guest, &stored),
        };
        if std::env::var_os("LITEROOT_DEBUG").is_some() {
            eprintln!(
                "literoot-tool: readlink {link_guest:?} stored={stored:?} guest={guest_bytes:?} ret={ret}"
            );
        }
        if guest_bytes == stored {
            return ret;
        }
        let write_n = guest_bytes.len().min(buf_len);
        // NUL-terminate at write_n: the kernel buffer was
        // pre-zeroed by callers expecting the returned length
        // to bound the string (test-readlink-proc-self-exe-raw).
        let mut out = guest_bytes[..write_n].to_vec();
        if write_n < buf_len {
            out.push(0);
        }
        if mem.write(addr, &out).is_err() {
            return ret;
        }
        write_n as i64
    }

    /// Two-path variant: scratch slots 0 and 1024.
    async fn with_two_guest_paths<T: Guest<Self>, S, F>(
        &self,
        guest: &mut T,
        host_a: &Path,
        host_b: &Path,
        f: F,
    ) -> Result<((), S), Error>
    where
        F: FnOnce(*const libc::c_char, *const libc::c_char) -> S,
    {
        let mk = |p: &Path| -> Result<Vec<u8>, Error> {
            let c = CString::new(p.as_os_str().as_bytes())
                .map_err(|_| reverie::syscalls::Errno::EINVAL)?;
            Ok(c.as_bytes_with_nul().to_vec())
        };
        let a = mk(host_a)?;
        let b = mk(host_b)?;
        if a.len() > 1024 || b.len() > 1024 {
            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
        }
        let pa = self.scratch_write_at(guest, &a, 0).await?;
        let pb = self.scratch_write_at(guest, &b, 1024).await?;
        Ok((
            (),
            f(pa as *const libc::c_char, pb as *const libc::c_char),
        ))
    }

    /// Stage `host` path bytes in the scratch page and build
    /// the rewritten syscall with `f`. (Guest-stack staging was
    /// measured to corrupt execve callers' frames; scratch page
    /// staging cannot.)
    async fn with_guest_path<T: Guest<Self>, S, F>(
        &self,
        guest: &mut T,
        host: &Path,
        f: F,
    ) -> Result<((), S), Error>
    where
        F: FnOnce(*const libc::c_char) -> S,
    {
        let cstr = CString::new(host.as_os_str().as_bytes())
            .map_err(|_| reverie::syscalls::Errno::EINVAL)?;
        let bytes = cstr.as_bytes_with_nul();
        if bytes.len() > 1024 {
            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
        }
        let ptr = self.scratch_write_at(guest, bytes, 0).await?;
        Ok(((), f(ptr as *const libc::c_char)))
    }

    fn drop(&mut self) {
        crate::translate::bump_probe_gen();
    }
}

/// Follow a symlink chain at the *final* component of a translated
/// host path, keeping absolute targets inside the rootfs (design
/// §4.2). Without this, the kernel resolves e.g. Alpine's
/// `/bin/sh -> /bin/busybox` against the host root and escapes.
/// Intermediate-component symlinks remain a documented gap.
/// Rewrite a host path containing /proc/self (or thread-self)
/// for Tool-side reading: the Tool's own /proc/self is the
/// wrong task; the guest's pid names the right one, and thread-self the
/// calling thread's own task directory.
fn host_for_tool_read(host: &Path, guest_pid: i32, guest_tid: i32) -> PathBuf {
    let s = host.to_string_lossy();
    // A thread with a descriptor table (unshare(CLONE_FILES)) or a cwd
    // (CLONE_FS) of its own has other entries there than the leader.
    let thread = format!("/proc/{guest_pid}/task/{guest_tid}");
    let process = format!("/proc/{guest_pid}");
    for (needle, with) in [("/proc/self/", &process), ("/proc/thread-self/", &thread)] {
        if let Some(idx) = s.find(needle) {
            let mut out = String::with_capacity(s.len() + with.len());
            out.push_str(&s[..idx]);
            out.push_str(with);
            out.push('/');
            out.push_str(&s[idx + needle.len()..]);
            return PathBuf::from(out);
        }
    }
    if let Some(base) = s.strip_suffix("/proc/self") {
        return PathBuf::from(format!("{base}{process}"));
    }
    if let Some(base) = s.strip_suffix("/proc/thread-self") {
        return PathBuf::from(format!("{base}{thread}"));
    }
    host.to_path_buf()
}

fn init_fake(ids: Option<(u32, u32)>) -> [u32; 6] {
    let (u, g) = ids.unwrap_or((0, 0));
    [u, u, u, g, g, g]
}

/// The replicated cwd after a chdir/fchdir into a directory with no guest
/// path (deleted, or outside every mapped tree). Relative paths then
/// resolve through /proc/<pid>/task/<tid>/cwd, the kernel's cwd.
const UNNAMED_CWD: &str = "/__literoot_unnamed_cwd__";

/// /proc/<pid>/task/<tid>: the CALLING task's view. A thread can unshare
/// its fd table (unshare(CLONE_FILES), close_range CLOSE_RANGE_UNSHARE) or
/// its cwd (CLONE_FS), so the leader's /proc/<pid> is not always its own.
fn task_dir<T: Guest<RootfsTool>>(guest: &T) -> String {
    format!(
        "/proc/{}/task/{}",
        guest.pid().as_raw(),
        guest.tid().as_raw()
    )
}

/// How a relative name resolves from a base with no guest name: the
/// calling task's cwd or dirfd, spelled `base` (/proc/<pid>/task/<tid>/cwd
/// or .../fd/<n>).
#[derive(Debug, PartialEq)]
enum UnnamedRoute {
    /// The kernel can only fail without leaving the base: a closed fd (its
    /// EBADF), a base that is not a directory (ENOTDIR before the first
    /// component: path_init, fs/namei.c:2621, for the dirfd itself;
    /// link_path_walk, :2529-2535, through /proc), or the deleted
    /// directory itself (an empty name or only "."). The name goes to the
    /// kernel through `base`.
    Raw,
    /// The kernel reaches a live directory that has this guest name, and
    /// the rest of the name continues from there, walked like any guest
    /// path. `climbed` when that took a ".." out of a deleted directory:
    /// then the guest's own search check must have passed first (E1).
    Guest {
        dir: PathBuf,
        rest: PathBuf,
        climbed: bool,
    },
    /// A name looked up in a deleted directory: the dead-base answer
    /// (the kernel's argument checks first, then its search check, then
    /// ENOENT), which only the syscall's own dispatch can give.
    DeadName,
    /// Refused by name, EACCES.
    Refused(crate::translate::PathRefusal),
}

/// What the Tool's stats of a base and its ".." climb found (G step 1).
#[derive(Debug)]
enum Climb {
    /// The fd link is positively absent while the fd directory reads: the
    /// kernel's EBADF.
    Closed,
    /// The base is not a directory.
    NonDir,
    /// A stat the Tool could not make, of the base or of a ".." the climb
    /// needed.
    Uninspectable,
    /// A deleted directory reached with nothing left but "." (the held
    /// object), or with a NAME next. `ups` ".." were climbed to get there.
    Dead {
        md: std::fs::Metadata,
        ups: usize,
        name_next: bool,
    },
    /// A live directory, `ups` ".." above the base, and the rest of the
    /// name after them.
    Live {
        md: std::fs::Metadata,
        ups: usize,
        rest: PathBuf,
    },
}

/// G step 1: the stats of `base` and of its ".." climb along `path`. A ".."
/// out of a deleted directory is the kernel's own (follow_dotdot,
/// fs/namei.c:2064, to the directory's old parent), read by stat-ing
/// `<base>/..`, until a live directory.
fn gather_climb(base: &str, path: &Path) -> Climb {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;
    let md = match std::fs::metadata(base) {
        Ok(md) => md,
        Err(_) => {
            let absent = matches!(
                std::fs::symlink_metadata(base),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            );
            let dir_reads = Path::new(base)
                .parent()
                .is_some_and(|d| std::fs::metadata(d).is_ok());
            return if absent && dir_reads {
                Climb::Closed
            } else {
                Climb::Uninspectable
            };
        }
    };
    if !md.is_dir() {
        return Climb::NonDir;
    }
    let mut rest = path.components().peekable();
    let mut cur = PathBuf::from(base);
    let mut md = md;
    let mut ups = 0;
    loop {
        if md.nlink() > 0 {
            return Climb::Live {
                md,
                ups,
                rest: rest.collect(),
            };
        }
        while rest.peek() == Some(&Component::CurDir) {
            rest.next();
        }
        match rest.peek() {
            Some(Component::ParentDir) => {}
            next => {
                let name_next = next.is_some();
                return Climb::Dead { md, ups, name_next };
            }
        }
        rest.next();
        cur.push("..");
        ups += 1;
        md = match std::fs::metadata(&cur) {
            Ok(md) => md,
            Err(_) => return Climb::Uninspectable,
        };
    }
}

/// G step 2: the base's /proc text.
fn gather_text(base: &str) -> std::io::Result<PathBuf> {
    std::fs::read_link(base)
}

/// G step 3: the base's text popped `ups` times, and its stat. None when
/// the text is not absolute or too short to pop.
fn gather_text_stat(
    text: &Path,
    ups: usize,
) -> Option<(PathBuf, std::io::Result<std::fs::Metadata>)> {
    if !text.is_absolute() {
        return None;
    }
    let mut host = text.to_path_buf();
    for _ in 0..ups {
        if !host.pop() {
            return None;
        }
    }
    let md = std::fs::metadata(&host);
    Some((host, md))
}

/// G step 4, pure: the route from the gathered facts. A guest name is used
/// only when the text still reaches the very directory the climb found
/// (device and inode); a directory replaced at the same name is not.
fn decide(
    climb: Climb,
    path: &Path,
    text: std::io::Result<PathBuf>,
    text_stat: impl FnOnce(&Path, usize) -> Option<(PathBuf, std::io::Result<std::fs::Metadata>)>,
    cfg: &RootConfig,
) -> UnnamedRoute {
    use crate::translate::PathRefusal;
    use std::os::unix::fs::MetadataExt as _;
    if path.as_os_str().is_empty() {
        return UnnamedRoute::Raw;
    }
    let (md, ups, rest, dead) = match climb {
        Climb::Closed | Climb::NonDir => return UnnamedRoute::Raw,
        Climb::Uninspectable => return UnnamedRoute::Refused(PathRefusal::BaseUninspectable),
        Climb::Dead { md, ups, name_next } => (md, ups, None, Some(name_next)),
        Climb::Live { md, ups, rest } => (md, ups, Some(rest), None),
    };
    let Ok(text) = text else {
        return UnnamedRoute::Refused(PathRefusal::BaseUninspectable);
    };
    let Some((host, host_md)) = text_stat(&text, ups) else {
        return UnnamedRoute::Refused(PathRefusal::BaseUninspectable);
    };
    let reaches = host_md.is_ok_and(|h| (h.dev(), h.ino()) == (md.dev(), md.ino()));
    if reaches {
        return match cfg.reverse(&host) {
            Some(dir) => UnnamedRoute::Guest {
                dir,
                rest: rest.unwrap_or_else(|| path.to_path_buf()),
                climbed: ups > 0,
            },
            None => UnnamedRoute::Refused(PathRefusal::BaseOutsideRoot),
        };
    }
    match dead {
        // A live directory the text does not lead back to.
        None => UnnamedRoute::Refused(PathRefusal::BaseMoved),
        Some(true) => UnnamedRoute::DeadName,
        // The deleted directory itself (reached through ".." or not): the
        // kernel holds it and can only fail there.
        Some(false) => UnnamedRoute::Raw,
    }
}

/// [`UnnamedRoute`] for `path` from `base`: G's three gather steps, in
/// production order, then [`decide`].
fn unnamed_route(cfg: &RootConfig, base: &str, path: &Path) -> UnnamedRoute {
    if path.as_os_str().is_empty() {
        return UnnamedRoute::Raw;
    }
    let climb = gather_climb(base, path);
    if matches!(climb, Climb::Closed | Climb::NonDir | Climb::Uninspectable) {
        return decide(climb, path, Ok(PathBuf::new()), |_, _| None, cfg);
    }
    let text = gather_text(base);
    decide(climb, path, text, gather_text_stat, cfg)
}

/// The base a relative `path` resolves from when it has no guest name:
/// the calling task's dirfd or cwd through /proc, or None when the path is
/// absolute or its base is named.
fn unnamed_base<T: Guest<RootfsTool>>(
    guest: &T,
    dirfd: i32,
    cwd: &Path,
    dirfd_guest: Option<&Path>,
    path: &Path,
) -> Option<String> {
    if path.is_absolute() {
        None
    } else if dirfd != libc::AT_FDCWD {
        dirfd_guest
            .is_none()
            .then(|| format!("{}/fd/{}", task_dir(guest), dirfd))
    } else {
        (cwd == Path::new(UNNAMED_CWD)).then(|| format!("{}/cwd", task_dir(guest)))
    }
}

/// The rest of a name after [`UnnamedRoute::Guest`]'s directory: "." when
/// nothing is left.
fn guest_rest(rest: PathBuf) -> PathBuf {
    if rest.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        rest
    }
}

/// The size of a thread's scratch page.
const SCRATCH_PAGE: usize = 4096;

/// Scratch pages mapped at once, by one injected mmap: at post-exec (the
/// exec'ing thread takes the first, the rest wait for new threads), and
/// when a new thread finds none free. A new thread maps nothing until the
/// pool is used up.
const SCRATCH_POOL: usize = 16;

/// A new scratch image number, never handed out before in this process.
fn next_scratch_image() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The filter-count read's buffer (C3.6): the arms' second path slot,
/// which no probe uses; the read runs at a thread's start or inside a
/// probe's admission, never while an arm has staged a path.
const SCRATCH_STATUS: usize = 1024;
const SCRATCH_STATUS_LEN: usize = 1024;

/// Scratch offsets for the dead-base probes, clear of the path staging
/// at 0..2048 that the arms use after the gate.
const SCRATCH_PROBE_X: usize = 2048;
const SCRATCH_PROBE_Y: usize = 2056;
/// Scratch offset of the open_how the ptrace cmdline route stages for the
/// guest's rewritten openat2 (24 bytes), clear of the path at 0.
const SCRATCH_OPEN_HOW: usize = 2304;
/// Scratch offset of the in-guest memfd's name, clear of the path slots the
/// admission's status read stages into before the memfd_create runs (tree
/// 6: staged in a path slot, the name became `/proc/self/status`).
const SCRATCH_MEMFD_NAME: usize = 2336;
/// Scratch offset of the guarded openat2 probe's name ("x"), for the same
/// reason (in a path slot it would become `/proc/self/status`, which the
/// probe would then open, so every in-guest openat2 cmdline would fall back).
const SCRATCH_PROBE_NAME: usize = 2368;
const SCRATCH_SOCKADDR: usize = 2560;
const SCRATCH_SEARCH: usize = 3072;
const SCRATCH_SEARCH_MAX: usize = 1024;

/// A dead-base gate found closed at the top of the route, before any read
/// (S.3): the dispatch, the probing thread's dispatch mode, whether that
/// mode came from tracking, and the config-read errno to note when the
/// refusal is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateClosed {
    seq: u64,
    dispatch: Option<bool>,
    fallback: bool,
    note: Option<i32>,
}

/// A relative name the dead-base gate answers: its dirfd (AT_FDCWD for the
/// cwd), its base through /proc and that base's identity when decided, the
/// name, and whether it is a dead NAME (else a ".." climb).
struct GatedName {
    dirfd: i32,
    identity: Option<(u64, u64)>,
    base: String,
    path: PathBuf,
    dead_name: bool,
}

/// The device and inode of the directory a /proc base names now.
fn base_identity(base: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(base).ok().map(|md| (md.dev(), md.ino()))
}

/// What the Tool's own reads say a descriptor holds (C step 1).
struct SocketKind {
    /// The `socket:[I]` text of /proc/<tid>/fd/<fd>.
    link: PathBuf,
    /// Inode I is listed in /proc/<tid>/net/unix: AF_UNIX in the task's
    /// current network namespace.
    unix: bool,
}

/// Why the socket reads give no kind.
enum SocketRead {
    /// The kernel's own answer before the lookup: EBADF or ENOTSOCK.
    Answer(reverie::syscalls::Errno),
    /// A read failed for another reason (on an in-guest backend a pre-run
    /// filter can fail it): no trustworthy answer.
    Unsupported,
}

/// C step 1, in the kernel's order: an O_PATH descriptor is no descriptor
/// to bind or connect (EBADF: fdget masks FMODE_PATH); a closed one is
/// EBADF; anything but a socket is ENOTSOCK. No guest syscall is made, and
/// no guest getsockopt, which a cgroup program could rewrite.
fn socket_kind(task: &str, fd: i32) -> Result<SocketKind, SocketRead> {
    use reverie::syscalls::Errno;
    let absent = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let info = match std::fs::read_to_string(format!("{task}/fdinfo/{fd}")) {
        Ok(info) => info,
        Err(e) if absent(&e) || fd < 0 => return Err(SocketRead::Answer(Errno::EBADF)),
        Err(_) => return Err(SocketRead::Unsupported),
    };
    let flags = info
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 8).ok())
        .ok_or(SocketRead::Unsupported)?;
    if flags & libc::O_PATH as u64 != 0 {
        return Err(SocketRead::Answer(Errno::EBADF));
    }
    let link = match std::fs::read_link(format!("{task}/fd/{fd}")) {
        Ok(link) => link,
        Err(e) if absent(&e) => return Err(SocketRead::Answer(Errno::EBADF)),
        Err(_) => return Err(SocketRead::Unsupported),
    };
    let text = link.as_os_str().as_bytes();
    let Some(inode) = text
        .strip_prefix(b"socket:[")
        .and_then(|t| t.strip_suffix(b"]"))
        .and_then(|t| std::str::from_utf8(t).ok())
    else {
        return Err(SocketRead::Answer(Errno::ENOTSOCK));
    };
    let unix = std::fs::read_to_string(format!("{task}/net/unix"))
        .map_err(|_| SocketRead::Unsupported)?
        .lines()
        .skip(1)
        .any(|l| l.split_whitespace().nth(6) == Some(inode));
    Ok(SocketKind { link, unix })
}

/// C step 5': the descriptor still names exactly the socket step 1 read.
fn socket_unchanged(task: &str, fd: i32, link: &Path) -> bool {
    #[cfg(test)]
    crate::dead_base::trace("reread");
    std::fs::read_link(format!("{task}/fd/{fd}")).is_ok_and(|now| now == link)
}

/// True when `path` is the same file (device and inode) as `live`.
fn same_file(path: &Path, live: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path)
        .map(|md| (md.dev(), md.ino()) == (live.dev(), live.ino()))
        .unwrap_or(false)
}

/// The virtual guest directory recorded for `fd` by open_virtual_dir, if
/// the fd (`live`, its metadata) still holds the placeholder: a directory
/// that is the rootfs root. Any other object under that number means the
/// record is stale.
fn virtual_fd_path(
    cfg: &RootConfig,
    table: &FdTable,
    fd: i32,
    live: &std::fs::Metadata,
) -> Option<PathBuf> {
    let v = table.virtual_fds.get(&fd)?;
    (live.is_dir() && same_file(&cfg.rootfs, live)).then(|| v.clone())
}

/// The virtual-directory record of number `fd` in table `files`: its guest
/// dir and whether its description's entries were emitted.
fn virtual_record(st: &ProcState, files: FilesId, fd: i32) -> Option<(PathBuf, bool)> {
    let v = st.fdt(files).virtual_fds.get(&fd)?;
    Some((v.clone(), st.stream(files, fd).is_some_and(|s| s.emitted)))
}

/// What a task's fd number holds now, from /proc/<pid>/task/<tid>/fd.
enum FdStatus {
    /// An open file, as stat sees it through the link.
    Open(std::fs::Metadata),
    /// Closed (the link is gone while the fd directory is readable), or
    /// open on an object stat cannot reach (an O_PATH fd on a dangling
    /// symlink): no directory record applies to it.
    NoDir,
    /// /proc cannot be read: nothing is known, records stand as before.
    Unknown,
}

fn fd_status<T: Guest<RootfsTool>>(guest: &T, fd: i32) -> FdStatus {
    let dir = format!("{}/fd", task_dir(guest));
    let link = format!("{dir}/{fd}");
    match std::fs::metadata(&link) {
        Ok(md) => FdStatus::Open(md),
        Err(_) if std::fs::symlink_metadata(&link).is_ok() => FdStatus::NoDir,
        Err(_) if std::fs::metadata(&dir).is_ok() => FdStatus::NoDir,
        Err(_) => FdStatus::Unknown,
    }
}

/// (dev, ino) of the object a task's fd number holds now, if /proc says.
fn fd_identity<T: Guest<RootfsTool>>(guest: &T, fd: i32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    match fd_status(guest, fd) {
        FdStatus::Open(md) => Some((md.dev(), md.ino())),
        FdStatus::NoDir | FdStatus::Unknown => None,
    }
}

/// Bumps the shared probe-cache generation on drop — placed at
/// the top of mutating arms so the bump lands AFTER the inject
/// completes on every return path (early passthroughs included;
/// over-invalidation on failed mutations is safe).
struct ProbeBumpOnDrop;
impl Drop for ProbeBumpOnDrop {
    fn drop(&mut self) {
        crate::translate::bump_probe_gen();
    }
}

/// Parse a `#!interp [arg]` first line. Returns (interp, optarg).
fn parse_shebang(image: &[u8]) -> Option<(String, Option<String>)> {
    if !image.starts_with(b"#!") {
        return None;
    }
    // Kernel reads at most BINPRM_BUF_SIZE (256) bytes for the
    // shebang line; longer lines truncate mid-token.
    let image = &image[..image.len().min(256)];
    let line_end = image.iter().position(|&c| c == b'\n').unwrap_or(image.len());
    let line = std::str::from_utf8(&image[2..line_end]).ok()?.trim();
    let mut parts = line.splitn(2, |c: char| c.is_whitespace());
    let interp = parts.next()?.trim().to_string();
    if interp.is_empty() {
        return None;
    }
    let opt = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    Some((interp, opt))
}

/// True when `path` traverses a /proc magic symlink component
/// (fd, exe, root, cwd, map_files) with further components or
/// `..` after it — such paths bypass lexical normalization.
fn is_magic_proc_path(path: &Path) -> bool {
    let comps: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            std::path::Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect();
    if comps.len() < 4 || comps[0] != "proc" {
        return false;
    }
    let magic = ["fd", "exe", "root", "cwd", "map_files"];
    // /proc/<pid-or-self>/<magic>/... — only paths *under*
    // a magic link bypass canonicalization. The exact
    // magic link itself is canonicalized normally, with
    // translate.rs refusing to splice it (except "root",
    // which must splice to name the guest root, since
    // literoot does not chroot). Classifying the raw path
    // here is only sound for absolute paths, matching the
    // comps[0]=="proc" check after RootDir filtering.
    magic.contains(&comps[2].as_str())
}

/// What the selected FINAL entry of a path is, judged from its
/// host path after binds and the tool view, never from the spelling.
/// Another process's entries are not decided here: they are the kernel's,
/// as under proot (literoot assumes non-hostile programs, §4.9.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalProc {
    /// Anything but an owned procfs magic link, an owned cmdline file, or a
    /// shared-record row's exe or cmdline: an ordinary path, the kernel's.
    Ordinary,
    /// A procfs magic link of a process the guest owns (its pid the
    /// thread group's).
    OwnedLink(crate::translate::MagicLink),
    /// The procfs cmdline file of a process the guest owns (its tgid).
    OwnedCmdline(i32),
    /// The `exe` link of a process the guest does not own that has a
    /// shared-record row (a guest child on the in-guest backends): readlink
    /// and open answer the row's exe.
    SharedExe(i32),
    /// The cmdline file of such a process: open answers the row's argv.
    SharedCmdline(i32),
    /// Any other magic link of such a process (root, cwd, fd/<n>,
    /// map_files/<r>), its pid the thread group's: readlink answers it as a
    /// guest process's.
    SharedLink(crate::translate::MagicLink),
}

/// Whether an open with `flags` follows a final symlink: not with
/// O_NOFOLLOW, and not with O_CREAT|O_EXCL, which the kernel turns into
/// O_NOFOLLOW (build_open_flags, fs/open.c).
fn open_follows(flags: u64) -> bool {
    let creat_excl = (libc::O_CREAT | libc::O_EXCL) as u64;
    flags & libc::O_NOFOLLOW as u64 == 0 && flags & creat_excl != creat_excl
}

/// Whether the final name of `host` can be a procfs entry literoot decides
/// at all: a magic link (exe, root, cwd, an entry of fd/ or map_files/) or
/// a cmdline file. Every other path skips the procfs checks (no statfs per
/// call).
fn final_name_may_be_proc(host: &Path) -> bool {
    fn name(p: Option<&Path>) -> Option<&str> {
        p.and_then(Path::file_name).and_then(|n| n.to_str())
    }
    matches!(name(Some(host)), Some("exe" | "root" | "cwd" | "cmdline"))
        || matches!(name(host.parent()), Some("fd" | "map_files"))
}

/// The pid of the cmdline file at tool-view host path `tv`:
/// `<procfs>/<N>/cmdline` or a thread's `<procfs>/<N>/task/<T>/cmdline`
/// (`/proc/thread-self/cmdline` in the tool view), N and T all digits; the
/// pid is N. The caller's lstat proves the file
/// exists.
fn proc_cmdline_pid(tv: &Path) -> Option<i32> {
    fn digits(dir: &Path) -> Option<&str> {
        let n = dir.file_name()?.to_str()?;
        (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).then_some(n)
    }
    if tv.file_name()? != "cmdline" {
        return None;
    }
    let root = crate::translate::procfs_root_of(tv)?;
    let mut dir = tv.parent()?;
    digits(dir)?;
    // A thread's cmdline: <N>/task/<T>, decided as <N>'s.
    if let Some(task) = dir.parent().filter(|t| t.file_name() == Some("task".as_ref())) {
        if task.parent().and_then(Path::parent) == Some(root.as_path()) {
            dir = task.parent()?;
        }
    }
    if dir.parent()? != root {
        return None;
    }
    digits(dir)?.parse().ok()
}


/// [`FinalProc`] of the selected final host path `host` (its final link not
/// followed), for the guest whose procfs answers `links` gives: F (the
/// parent is on procfs), the entry's own lstat (a symlink for a magic link,
/// a regular file for cmdline), and ownership of the pid, normalized to its
/// thread group first.
fn final_proc_entry(host: &Path, links: &GuestProcLinks<'_>) -> FinalProc {
    use crate::translate::ProcEntry;
    if !final_name_may_be_proc(host) {
        return FinalProc::Ordinary;
    }
    let (entry, tv) = crate::translate::proc_entry(host, links);
    match entry {
        ProcEntry::Magic(mut link) => {
            match std::fs::symlink_metadata(&tv) {
                Ok(md) if md.file_type().is_symlink() => {}
                _ => return FinalProc::Ordinary,
            }
            let (tgid, owned) = links.tgid_and_owned(link.pid);
            link.pid = tgid;
            if owned {
                FinalProc::OwnedLink(link)
            } else if has_shared_row(link.pid) {
                match link.kind {
                    crate::translate::MagicKind::Exe => FinalProc::SharedExe(link.pid),
                    _ => FinalProc::SharedLink(link),
                }
            } else {
                FinalProc::Ordinary
            }
        }
        ProcEntry::Inside => {
            let Some(pid) = proc_cmdline_pid(&tv) else {
                return FinalProc::Ordinary;
            };
            match std::fs::symlink_metadata(&tv) {
                Ok(md) if md.file_type().is_file() => {}
                _ => return FinalProc::Ordinary,
            }
            let (pid, owned) = links.tgid_and_owned(pid);
            if owned {
                FinalProc::OwnedCmdline(pid)
            } else if has_shared_row(pid) {
                FinalProc::SharedCmdline(pid)
            } else {
                FinalProc::Ordinary
            }
        }
        ProcEntry::NotProc | ProcEntry::Prefix(_) => FinalProc::Ordinary,
    }
}

/// Whether process `pid` has a shared-record row: a guest process that
/// published its exe and argv (A1). Its exe and cmdline are answered from
/// the row while the row has them.
fn has_shared_row(pid: i32) -> bool {
    RootfsTool::shared_process_record(pid).is_some()
}

/// The fallback of a cmdline literoot would answer itself but cannot (no
/// memfd, a closed probe gate, or a failed write): its line, `answered path
/// synthetic_file_unavailable`. The kernel's own file then answers.
fn note_cmdline_fallback() {
    note_path_report(Refusal::Path(crate::translate::PathRefusal::SyntheticFileUnavailable));
}

/// Write `content` at offset 0 of descriptor `fd` of guest thread `tid`,
/// from the Tool's side, without moving the guest's file offset (pwrite
/// never moves it). On ptrace the Tool is the tracer; in-guest it runs in
/// the guest process itself. The descriptor is `tid`'s, in that thread's
/// own table, which differs from its thread group leader's after
/// unshare(CLONE_FILES) or close_range(CLOSE_RANGE_UNSHARE).
/// First pidfd_open(tid, PIDFD_THREAD) and pidfd_getfd: a
/// thread pidfd names that thread, and pidfd_getfd reads its table
/// (pidfd_getfd, kernel/pid.c; fget_task, fs/file.c). If either call fails
/// (a kernel before PIDFD_THREAD, or a filter on the in-guest Tool's own
/// calls), a fresh open of /proc/<tid>/fd/<fd> for writing, which also
/// goes through that thread's table. Before any write, the file must be
/// the one /proc/<tid>/fd/<fd> names (same device and inode), a regular
/// file, and empty: the memfd just made. Otherwise nothing is written.
/// Then its mode is set to 0444, the kernel cmdline file's. True when
/// every byte is written and the mode set.
fn write_guest_fd(tid: i32, fd: i32, content: &[u8]) -> bool {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::fs::FileExt as _;
    use std::os::unix::fs::MetadataExt as _;
    // include/uapi/linux/pidfd.h: PIDFD_THREAD is O_EXCL.
    const PIDFD_THREAD: libc::c_uint = libc::O_EXCL as libc::c_uint;
    #[cfg(test)]
    if MEMFD_WRITE_FAILS.with(|s| s.get()) {
        return false;
    }
    let target = format!("/proc/{tid}/fd/{fd}");
    // The file the guest's descriptor names, through the magic link.
    let Ok(want) = std::fs::metadata(&target) else {
        return false;
    };
    let fresh = |file: &std::fs::File| {
        file.metadata().is_ok_and(|md| {
            md.file_type().is_file() && md.len() == 0 && (md.dev(), md.ino()) == (want.dev(), want.ino())
        })
    };
    // The bytes, then the kernel cmdline file's mode, 0444, as the ptrace
    // route's memfd has.
    let fill = |file: &std::fs::File| {
        use std::os::unix::fs::PermissionsExt as _;
        file.write_all_at(content, 0).is_ok()
            && file.set_permissions(std::fs::Permissions::from_mode(0o444)).is_ok()
    };
    #[cfg(test)]
    let pidfd_route = !MEMFD_PIDFD_OFF.with(|s| s.get());
    #[cfg(not(test))]
    let pidfd_route = true;
    if pidfd_route {
        use std::os::fd::AsRawFd as _;
        // SAFETY: a plain syscall with integer arguments.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, PIDFD_THREAD) };
        if pidfd >= 0 {
            // SAFETY: pidfd_open returned this new descriptor; it is owned here.
            let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd as i32) };
            // SAFETY: a plain syscall with integer arguments.
            let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
            if dup >= 0 {
                // SAFETY: pidfd_getfd returned this new descriptor; it is owned here.
                let file = unsafe { std::fs::File::from_raw_fd(dup as i32) };
                if !fresh(&file) {
                    return false;
                }
                #[cfg(test)]
                MEMFD_ROUTE.with(|r| r.set(Some(MemfdRoute::Pidfd)));
                return fill(&file);
            }
        }
    }
    match std::fs::OpenOptions::new().write(true).open(&target) {
        Ok(file) => {
            if !fresh(&file) {
                return false;
            }
            #[cfg(test)]
            MEMFD_ROUTE.with(|r| r.set(Some(MemfdRoute::Procfs)));
            fill(&file)
        }
        Err(_) => false,
    }
}

/// O'' synthesize-if-absent (plain `-r` with no guest /proc): the walk
/// positively found no `/proc` or `/proc/<x>` in the guest view, that is,
/// the selected final entry's parent does not exist (ENOENT). Any other
/// inspection error is the walk's own answer, never synthesis.
fn proc_parent_absent(host: &Path) -> Result<bool, reverie::syscalls::Errno> {
    let Some(parent) = host.parent() else {
        return Ok(false);
    };
    match std::fs::symlink_metadata(parent) {
        Ok(_) => Ok(false),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(true),
        Err(e) => Err(reverie::syscalls::Errno::new(
            e.raw_os_error().unwrap_or(libc::EACCES),
        )),
    }
}

/// Whether `path` spells one of the self links plain `-r` synthesizes when
/// the guest has no /proc: `/proc/<x>/{exe,root,cmdline}`, after lexical
/// `..` normalization (the handlers then apply their own spelled rules).
fn spells_proc_self_link(path: &Path) -> bool {
    let mut comps: Vec<std::ffi::OsString> = Vec::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                comps.pop();
            }
            std::path::Component::Normal(s) => comps.push(s.to_os_string()),
            _ => {}
        }
    }
    matches!(comps.as_slice(), [p, _, l] if p == "proc" && (l == "exe" || l == "root" || l == "cmdline"))
}

/// [`RootfsTool::self_link_route`]'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelfLink {
    /// Synthesize the process's own executable (its guest path).
    Exe,
    /// Synthesize process `pid`'s as-exec'd argv.
    Cmdline(i32),
    /// A1: process `pid`'s argv from its shared-record row; a row gone or
    /// empty by then gets the kernel's file.
    SharedCmdline(i32),
    /// A1: process `pid`'s exe from its shared-record row (its guest path);
    /// a row gone or empty by then gets the kernel's link.
    RowExe(i32),
    /// The ordinary path: no synthesis.
    Walk,
}

/// The guest's own open of a cmdline literoot answers itself (§4.9.5): the
/// call the ptrace route rewrites to reopen the tracer's memfd
/// ([`RootfsTool::open_cmdline_via_tracer`]), and whose O_CLOEXEC the
/// in-guest memfd follows. openat2 carries the open_how its arm read.
#[derive(Debug, Clone, Copy)]
enum CmdlineOpen {
    Openat(reverie::syscalls::Openat),
    #[cfg(target_arch = "x86_64")]
    Open(reverie::syscalls::Open),
    Openat2(reverie::syscalls::Openat2, reverie::syscalls::OpenHow),
}

impl CmdlineOpen {
    /// The call's raw arguments.
    fn raw(self) -> SyscallArgs {
        use reverie::syscalls::SyscallInfo as _;
        match self {
            CmdlineOpen::Openat(o) => Syscall::Openat(o).into_parts().1,
            #[cfg(target_arch = "x86_64")]
            CmdlineOpen::Open(o) => Syscall::Open(o).into_parts().1,
            CmdlineOpen::Openat2(o, _) => Syscall::Openat2(o).into_parts().1,
        }
    }

    /// The guest's O_* flags.
    fn flags(self) -> u64 {
        match self {
            CmdlineOpen::Openat(_) => self.raw().arg2 as u64,
            #[cfg(target_arch = "x86_64")]
            CmdlineOpen::Open(_) => self.raw().arg1 as u64,
            CmdlineOpen::Openat2(_, how) => how.flags,
        }
    }

    fn cloexec(self) -> bool {
        self.flags() & libc::O_CLOEXEC as u64 != 0
    }
}

/// include/uapi/linux/openat2.h: the resolve bits that act on the jump
/// through a magic link or re-root an absolute name. The ptrace cmdline
/// route clears them for its rewritten openat2 (the guest named a regular
/// file; the rewritten final entry is the tracer's magic link).
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;

/// openat2's size checks (fs/open.c): EINVAL below OPEN_HOW_SIZE_VER0 (24
/// bytes), E2BIG above the page size.
fn open_how_size_check(size: usize, page: usize) -> Result<(), reverie::syscalls::Errno> {
    if size < std::mem::size_of::<reverie::syscalls::OpenHow>() {
        Err(reverie::syscalls::Errno::EINVAL)
    } else if size > page {
        Err(reverie::syscalls::Errno::E2BIG)
    } else {
        Ok(())
    }
}

/// The kernel's PAGE_SIZE.
fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: a plain sysconf query.
    *PAGE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize)
}

/// access_ok for `len` bytes at `addr`: the range ends at or below the top
/// of the user address space (x86_64: TASK_SIZE_MAX, arch/x86/include/asm/
/// uaccess_64.h; arm64: 1 << VA_BITS, arch/arm64/include/asm/uaccess.h).
/// The top is the 5-level (x86_64) or 52-bit (arm64) one when a mapping
/// above the smaller one succeeds. arm64's tagged-address ABI is not
/// modelled: a tagged pointer is out of range here.
fn user_range_ok(addr: usize, len: usize) -> bool {
    static TOP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let top = *TOP.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        let (low, high) = ((1usize << 47) - 4096, (1usize << 56) - 4096);
        #[cfg(target_arch = "aarch64")]
        let (low, high) = (1usize << 48, 1usize << 52);
        let hint = 1usize << 50;
        // SAFETY: a fresh anonymous mapping at a hint, unmapped at once.
        let p = unsafe {
            libc::mmap(
                hint as *mut libc::c_void,
                page_size(),
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return low;
        }
        // SAFETY: the mapping just made.
        unsafe { libc::munmap(p, page_size()) };
        if p as usize >= low { high } else { low }
    });
    addr.checked_add(len).is_some_and(|end| end <= top)
}

/// A tracer copy of the guest's `len` bytes at `addr`, at the same offset
/// in a page, with every page the guest cannot read mapped PROT_NONE: a
/// kernel copy from it reads and faults where one from the guest's memory
/// would. `len` is at most a page, so at most two
/// pages.
struct LayoutCopy {
    base: *mut libc::c_void,
    map_len: usize,
    offset: usize,
    readable: Vec<bool>,
    page: usize,
}

impl LayoutCopy {
    /// `read(addr, buf)` reads the guest's bytes at `addr` into `buf`, false
    /// when it cannot. None when the tracer cannot map the copy, or cannot
    /// make a page the guest cannot read inaccessible in it.
    fn new(addr: usize, len: usize, page: usize, mut read: impl FnMut(usize, &mut [u8]) -> bool) -> Option<Self> {
        let first = addr & !(page - 1);
        let end = addr.checked_add(len)?;
        let map_len = end.checked_add(page - 1)? & !(page - 1);
        let map_len = map_len - first;
        // SAFETY: a fresh anonymous mapping, owned by the copy.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return None;
        }
        #[cfg(test)]
        LAYOUT_COPY_LIVE.with(|n| n.set(n.get() + 1));
        let mut copy = LayoutCopy { base, map_len, offset: addr - first, readable: Vec::new(), page };
        for i in 0..map_len / page {
            let start = first + i * page;
            let (lo, hi) = (addr.max(start), end.min(start + page));
            // SAFETY: [lo, hi) lies in page i of the mapping.
            let buf = unsafe { std::slice::from_raw_parts_mut(base.cast::<u8>().add(lo - first), hi - lo) };
            let ok = read(lo, buf);
            // A page left readable would let the kernel read zeros where
            // the guest's call faults: when it cannot
            // be made inaccessible there is no copy (`copy` is unmapped on
            // return), and the guest's own call answers.
            if !ok && !protect_none(base.cast::<u8>().wrapping_add(i * page).cast(), page) {
                return None;
            }
            copy.readable.push(ok);
        }
        Some(copy)
    }

    /// The copy's first byte, the guest's `addr`.
    fn ptr(&self) -> *const u8 {
        // SAFETY: inside the mapping.
        unsafe { self.base.cast::<u8>().add(self.offset) }
    }

    /// The first `n` bytes, when every page under them was readable.
    fn readable_prefix(&self, n: usize) -> Option<Vec<u8>> {
        let last = (self.offset + n - 1) / self.page;
        if !self.readable.get(..=last)?.iter().all(|ok| *ok) {
            return None;
        }
        // SAFETY: readable pages of the mapping.
        Some(unsafe { std::slice::from_raw_parts(self.ptr(), n) }.to_vec())
    }
}

/// mprotect(PROT_NONE) over `len` bytes of a [`LayoutCopy`]'s mapping at
/// `at`; false when it fails.
fn protect_none(at: *mut libc::c_void, len: usize) -> bool {
    #[cfg(test)]
    if LAYOUT_COPY_PROTECT_FAILS.with(|s| s.get()) {
        return false;
    }
    // SAFETY: a page of the copy's own mapping.
    unsafe { libc::mprotect(at, len, libc::PROT_NONE) == 0 }
}

impl Drop for LayoutCopy {
    fn drop(&mut self) {
        // SAFETY: the mapping `new` made.
        let unmapped = unsafe { libc::munmap(self.base, self.map_len) } == 0;
        #[cfg(test)]
        if unmapped {
            LAYOUT_COPY_LIVE.with(|n| n.set(n.get() - 1));
        }
        let _ = unmapped;
    }
}

/// Whether the ptrace cmdline route can be used at all, checked once: the
/// tracer is dumpable (a guest reopens its descriptor through
/// proc_fd_access_allowed, fs/proc/base.c, which needs ptrace read access
/// to the tracer), and its /proc names itself (the procfs a guest sharing
/// its mount namespace resolves). Logged once when it cannot.
fn tracer_route_ready() -> bool {
    #[cfg(test)]
    if TRACER_ROUTE_OFF.with(|s| s.get()) {
        return false;
    }
    static READY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *READY.get_or_init(|| {
        // SAFETY: a plain prctl query.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } == 1;
        let own_proc = std::fs::read_link("/proc/self")
            .ok()
            .and_then(|p| p.to_str()?.parse::<u32>().ok())
            == Some(std::process::id());
        if !(dumpable && own_proc) {
            eprintln!(
                "literoot: tracer cmdline route off (dumpable {dumpable}, /proc names the tracer {own_proc}): \
                 cmdline falls back to the kernel's file"
            );
        }
        dumpable && own_proc
    })
}

/// Whether the tracer has CAP_DAC_OVERRIDE-like credentials (effective uid
/// 0), under which a write open of a read-only file is not EACCES. The
/// tracer's credentials are the guest's: literoot changes none.
fn tracer_overrides_dac() -> bool {
    // SAFETY: a plain query.
    let euid = unsafe { libc::geteuid() };
    euid == 0
}

/// Guest processes that left the tracer's mount namespace:
/// their own unshare(CLONE_NEWNS) or any setns, a clone
/// with CLONE_NEWNS, or a parent that had left it when it created them.
/// Keyed by start-time-qualified identity, so a reused pid is a new
/// process. On ptrace every Tool lives in the tracer, which sees all of
/// those calls; the in-guest route never asks.
static MOVED_MOUNT_NS: std::sync::LazyLock<std::sync::Mutex<std::collections::BTreeSet<ProcessId>>> =
    std::sync::LazyLock::new(Default::default);

fn note_mount_ns_moved(pid: i32) {
    if let Some(id) = RootfsTool::guest_process_id(pid) {
        MOVED_MOUNT_NS.lock().unwrap().insert(id);
    }
}

/// Whether process `pid` may not share the tracer's mount namespace: it is
/// recorded as having left it, or its identity cannot be read.
fn mount_ns_moved(pid: i32) -> bool {
    match RootfsTool::guest_process_id(pid) {
        Some(id) => MOVED_MOUNT_NS.lock().unwrap().contains(&id),
        None => true,
    }
}

#[cfg(test)]
fn forget_mount_ns_moved(pid: i32) {
    if let Some(id) = RootfsTool::guest_process_id(pid) {
        MOVED_MOUNT_NS.lock().unwrap().remove(&id);
    }
}

/// Tracer memfds kept past a rewritten call that returned a restart code
/// (ERESTART*), by guest thread: the restarted call reopens the same
/// descriptor number, so it must stay open. Released at that thread's next
/// route call or its exit.
static HELD_TRACER_FDS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<i32, std::fs::File>>> =
    std::sync::LazyLock::new(Default::default);

fn release_held_tracer_fd(tid: i32) {
    HELD_TRACER_FDS.lock().unwrap().remove(&tid);
}

/// The pid a spelled `/proc/<x>/cmdline` names (`self` and `thread-self`
/// are `own`), after lexical `..` normalization.
fn spelled_cmdline_pid(path: &Path, own: i32) -> Option<i32> {
    let mut comps: Vec<std::ffi::OsString> = Vec::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                comps.pop();
            }
            std::path::Component::Normal(s) => comps.push(s.to_os_string()),
            _ => {}
        }
    }
    match comps.as_slice() {
        [p, x, l] if p == "proc" && l == "cmdline" => {
            if x == "self" || x == "thread-self" {
                Some(own)
            } else {
                x.to_str()?.parse().ok()
            }
        }
        _ => None,
    }
}

/// True for /proc/self/exe, /proc/thread-self/exe, /proc/<pid>/exe
/// for our own pid, after lexical normalization of `..` (the
/// /proc/1/../self/exe form used by upstream tests).
fn is_self_exe(link_guest: &Path, pid: i32) -> bool {
    let mut comps: Vec<std::ffi::OsString> = Vec::new();
    for c in link_guest.components() {
        match c {
            std::path::Component::ParentDir => {
                comps.pop();
            }
            std::path::Component::Normal(s) => comps.push(s.to_os_string()),
            _ => {}
        }
    }
    comps.len() == 3
        && comps[0] == "proc"
        && comps[2] == "exe"
        && (comps[1] == "self"
            || comps[1] == "thread-self"
            || comps[1].to_string_lossy() == pid.to_string())
}


/// The canonical guest path of the directory an absolute guest path names,
/// every link (the final one included) resolved through the guest root:
/// what a recorded cwd must be. The path itself when the walk has no guest
/// name or passes 40 links.
fn canonical_dir(cfg: &RootConfig, path: &Path) -> PathBuf {
    let mut links = 0;
    cfg.translate_counted(path, Path::new("/"), None, &mut links)
        .map_err(crate::translate::WalkError::from)
        .and_then(|host| {
            resolve_symlink_chain_guest(cfg, Some(path.to_path_buf()), host, &mut links, None)
        })
        .ok()
        .and_then(|(_, guest)| guest)
        .unwrap_or_else(|| path.to_path_buf())
}

/// The launch directory `-w` names as the kernel will hold it: the host
/// directory with every link resolved through the guest root, and its
/// canonical guest path. None when that is not a directory (or the walk
/// passes 40 links).
#[allow(dead_code)] // The launcher's (tool.rs); the preload build has no launcher.
pub(crate) fn launch_dir(cfg: &RootConfig, cwd_guest: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut links = 0;
    let host = cfg
        .translate_counted(cwd_guest, Path::new("/"), None, &mut links)
        .ok()?;
    let (host, guest) =
        resolve_symlink_chain_guest(cfg, Some(cwd_guest.to_path_buf()), host, &mut links, None)
            .ok()?;
    host.is_dir()
        .then(|| (host, guest.unwrap_or_else(|| cwd_guest.to_path_buf())))
}

/// The host path of an absolute guest path with its final symlink
/// followed, as one walk on the guest `pid`'s behalf: more than 40 links
/// is the guest's ELOOP, a refused /proc magic link its EACCES.
fn follow_guest_path(
    cfg: &RootConfig,
    (pid, tid): (i32, i32),
    path: &Path,
) -> Result<PathBuf, reverie::syscalls::Errno> {
    follow_guest_path_from(cfg, &GuestProcLinks::new(cfg, pid, tid), Path::new("/"), path)
        .map_err(|e| {
            note_walk_error(&e);
            walk_errno(e)
        })
}

/// [`follow_guest_path`] for a guest path that may be relative to the
/// guest directory `cwd`: the launcher's walk for the program, its
/// interpreter and its loader. Intermediate and final links share one
/// budget; past 40 the answer is ELOOP, never a host path that still holds
/// a link for the host kernel to follow. `proc` answers at /proc magic
/// links.
pub(crate) fn follow_guest_path_from(
    cfg: &RootConfig,
    proc: &dyn crate::translate::ProcLinks,
    cwd: &Path,
    path: &Path,
) -> Result<PathBuf, crate::translate::WalkError> {
    let mut links = 0;
    let route = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    cfg.translate_walk(path, cwd, None, &mut links, proc)
        .and_then(|host| resolve_symlink_chain(cfg, Some(route), host, &mut links, Some(proc)))
}

/// Follows a final-component symlink chain from `host`, the translation of
/// the guest path `guest` when the caller knows it. A relative target is
/// resolved from the link's GUEST directory and translated again, so the
/// guest spelling the walk came through (an alias bind, a nested bind)
/// decides where it lands, as proot's path/canon.c:330-341 does. Without a
/// guest path (a dirfd or cwd with no guest name) the target is joined on
/// the host side.
fn resolve_symlink_chain(
    cfg: &RootConfig,
    guest: Option<PathBuf>,
    host: PathBuf,
    links: &mut u32,
    proc: Option<&dyn crate::translate::ProcLinks>,
) -> Result<PathBuf, crate::translate::WalkError> {
    resolve_symlink_chain_guest(cfg, guest, host, links, proc).map(|(host, _)| host)
}

/// [`resolve_symlink_chain`], also returning the canonical guest path of
/// what the chain reached, when the walk has one: every link resolved,
/// the bind route it came through kept. None for /proc magic links and
/// walks with no guest name.
fn resolve_symlink_chain_guest(
    cfg: &RootConfig,
    guest: Option<PathBuf>,
    host: PathBuf,
    links: &mut u32,
    proc: Option<&dyn crate::translate::ProcLinks>,
) -> Result<(PathBuf, Option<PathBuf>), crate::translate::WalkError> {
    use crate::translate::MagicAction;
    use crate::translate::ProcEntry;
    // Keep the guest path canonical (no intermediate link, no ".."): its
    // parent is where a relative target resolves, and the route returned
    // with the host path is what a cwd record keeps. A walk on a guest's
    // behalf canonicalizes under its /proc policy too.
    let canonical = |path: &Path, base: &Path| match proc {
        Some(policy) => cfg.canonical_guest_walk(path, base, policy),
        None => Ok(cfg.canonical_guest(path, base)),
    };
    let translate = |path: &Path, base: &Path, links: &mut u32| match proc {
        Some(policy) => cfg.translate_walk(path, base, None, links, policy),
        None => Ok(cfg.translate_counted(path, base, None, links)?),
    };
    let mut guest = match guest {
        Some(g) => Some(canonical(&g, Path::new("/"))?),
        None => None,
    };
    let mut cur = host;
    let mut first = true;
    // Every link followed here, and every link inside its target,
    // counts against the walk's budget: past 40 the guest gets ELOOP, and
    // no path still holding a link reaches the kernel.
    loop {
        // The final entry in the real procfs, judged from its host path
        // (selected through binds): the policy decides what following a
        // magic link means, and procfs's own self/thread-self is followed
        // to the calling task's directory, never read Tool-side (that would
        // name the Tool). Without a policy, a magic link is never followed
        // Tool-side: readlink from the Tool process names the wrong task's
        // objects (measured: guest fd/0 resolved to the tracer's pipe).
        let mut read_at = None;
        if let Some(policy) = proc {
            let (entry, tv) = crate::translate::proc_entry(&cur, policy);
            match entry {
                ProcEntry::Magic(link) => match policy.follow(&link, &tv) {
                    MagicAction::Walk => {}
                    MagicAction::Reroot(dir) => {
                        crate::translate::take_link(links)?;
                        cur = translate(&dir, Path::new("/"), links)?;
                        guest = Some(dir);
                        continue;
                    }
                    MagicAction::Raw => {
                        // The kernel follows it: one more link.
                        crate::translate::take_link(links)?;
                        return Ok((cur, None));
                    }
                    MagicAction::Refuse(kind) => {
                        return Err(crate::translate::WalkError::Refused(kind));
                    }
                },
                ProcEntry::Prefix(target) => {
                    crate::translate::take_link(links)?;
                    let mut next = cur
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| PathBuf::from("/"));
                    let mut route = guest
                        .as_ref()
                        .and_then(|g| g.parent().map(Path::to_path_buf));
                    for c in &target {
                        next.push(c);
                        if let Some(r) = route.as_mut() {
                            r.push(c);
                        }
                    }
                    cur = next;
                    guest = route;
                    continue;
                }
                ProcEntry::Inside => read_at = Some(tv),
                ProcEntry::NotProc => {}
            }
        } else if std::mem::take(&mut first) && host_is_proc_magic(&cur) {
            return Ok((cur, None));
        }
        match std::fs::read_link(read_at.as_ref().unwrap_or(&cur)) {
            Ok(target) if target.is_absolute() => {
                crate::translate::take_link(links)?;
                cur = translate(&target, Path::new("/"), links)?;
                guest = Some(canonical(&target, Path::new("/"))?);
            }
            Ok(target) if proc.is_some_and(|p| p.raw_crossed()) => {
                // After a Raw hand-over the parent is the kernel's literal
                // route, whose links the walk already counted: walking it
                // again would charge the magic link and its tail twice.
                // The target resolves from the
                // host parent instead, counting only the links in its own
                // intermediate components, with the same conservative
                // counter.
                crate::translate::take_link(links)?;
                let parent = cur
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("/"));
                let tail: Vec<std::ffi::OsString> =
                    target.iter().map(|c| c.to_os_string()).collect();
                crate::translate::count_raw_tail(&parent, &tail, links)?;
                cur = parent.join(&target);
                guest = None;
            }
            Ok(target) => {
                crate::translate::take_link(links)?;
                let parent = guest
                    .as_ref()
                    .and_then(|g| g.parent().map(Path::to_path_buf));
                match parent {
                    Some(parent) => {
                        cur = translate(&target, &parent, links)?;
                        guest = Some(canonical(&target, &parent)?);
                    }
                    // No guest directory to resolve it from: joining it on
                    // the host side would walk the host's tree.
                    None => {
                        return Err(crate::translate::WalkError::Refused(
                            crate::translate::PathRefusal::NoGuestRoute,
                        ));
                    }
                }
            }
            Err(_) => break,
        }
    }
    Ok((cur, guest))
}

/// The guest's errno for a failed walk.
fn walk_errno(e: crate::translate::WalkError) -> reverie::syscalls::Errno {
    match e {
        crate::translate::WalkError::TooManyLinks => reverie::syscalls::Errno::ELOOP,
        crate::translate::WalkError::Refused(_) => reverie::syscalls::Errno::EACCES,
        crate::translate::WalkError::Kernel(e) => reverie::syscalls::Errno::new(e),
    }
}

/// The `Tgid:` and `TracerPid:` of host process `pid`.
fn proc_status_ids(pid: i32) -> Option<(i32, i32)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().parse::<i32>().ok())
    };
    Some((field("Tgid:")?, field("TracerPid:")?))
}

/// The /proc magic-link policy for walks on behalf of guest thread `tid` of
/// process `pid` (or of the launcher, for its own launch walk). Literoot
/// does not chroot: through the real procfs, `/proc/<x>/root` is the host's
/// `/`, and `cwd`, `fd/<n>`, `exe` and `map_files/<r>` are process x's
/// objects wherever they are on the host.
///
/// The walk hands it the link's HOST entry (selected through binds, then
/// [`Self::tool_view`]), so the owner is the pid in that path, never a
/// spelling: a bind that puts another process's directory at guest
/// `/proc/self` names that process.
///
/// - A guest process: one of the guest's own (itself, its threads, or on
///   the ptrace backend any task literoot's tracer traces), or a process
///   with a shared-record row (a guest child on the in-guest backends),
///   judged by its thread group:
///   - `root` continues from the guest root;
///   - `cwd`, and `fd/<n>` holding a directory, continue from the
///     directory's guest path, when it has one that leads back to the same
///     directory ([`Self::verified_reverse`]); refused,
///     `proc_link_outside_root`, when it has none: deleted, outside every
///     mapped tree, shadowed by a deeper bind, or moved between the
///     readlink and the check;
///   - `fd/<n>` holding anything else (a pipe, socket, anonymous inode or
///     regular file), `exe` and `map_files/<r>` pass to the kernel, which
///     can only answer ENOTDIR at that inode, as natively;
///   - an entry that does not exist is the kernel's ENOENT;
///   - following the link itself passes, except `root`, which is the guest
///     root.
/// - Any other process (a host process): literoot assumes non-hostile
///   programs (owner directive 2026-11-14), so its links are not refused.
///   - `root`, `cwd`, and `fd/<n>` holding a directory, continued past or
///     followed, continue from the directory's guest path when it has a
///     verified one, as for a guest process:
///     the walk, its link budget and any record of where the call landed
///     use the directory the link named when the Tool read it. The window:
///     if the process moves between that read and the call, the call runs
///     as if a moment earlier.
///   - Otherwise (outside the view, deleted, unreadable to the Tool, or a
///     failed check), the link and the rest of the path are the kernel's
///     (`MagicAction::Raw`), with the links in that rest counted against
///     the walk's budget ([`crate::translate::count_raw_tail`]); the walk
///     then reports [`crate::translate::ProcLinks::raw_crossed`], so no
///     caller records its route as a guest directory.
///   - `exe`, `map_files/<r>` and non-directory fds pass to the kernel.
///
/// Every process is judged under the caller's RootConfig: a guest child
/// that emulates a chroot of its own (`root_override`) is not represented
/// (disclosed in docs/design.md). A process that
/// exits and whose pid is reused between this check and the call is the
/// time-of-check race every translation has.
pub(crate) struct GuestProcLinks<'a> {
    cfg: &'a RootConfig,
    pid: i32,
    tid: i32,
    /// Set when a walk asked this policy handed another process's directory
    /// link to the kernel.
    raw: std::cell::Cell<bool>,
    /// Set when a walk asked this policy continued from another process's
    /// directory link's verified guest path.
    spliced: std::cell::Cell<bool>,
}

impl<'a> GuestProcLinks<'a> {
    pub(crate) fn new(cfg: &'a RootConfig, pid: i32, tid: i32) -> Self {
        Self {
            cfg,
            pid,
            tid,
            raw: std::cell::Cell::new(false),
            spliced: std::cell::Cell::new(false),
        }
    }

    /// How the walks asked this policy went through another process's
    /// directory link.
    pub(crate) fn other_link(&self) -> OtherLink {
        if self.raw.get() {
            OtherLink::Raw
        } else if self.spliced.get() {
            OtherLink::Spliced
        } else {
            OtherLink::None
        }
    }

    /// Carry an earlier walk's [`Self::other_link`] into this policy's (the
    /// final chain after the walk to it).
    pub(crate) fn carry(&self, other: OtherLink) {
        self.raw.set(self.raw.get() || other == OtherLink::Raw);
        self.spliced.set(self.spliced.get() || other == OtherLink::Spliced);
    }

    /// The thread group of host task `pid`, and whether it is a process of
    /// the guest's own, from one read of its status.
    /// procfs answers `/proc/<tid>/` for any thread id (hidden from
    /// readdir), so a pid in a procfs path may name a thread: its status
    /// `Tgid:` line. An unreadable status (the process is gone, and the
    /// kernel's answer stands) is `(pid, false)`, unless `pid` is the
    /// guest's own.
    fn tgid_and_owned(&self, pid: i32) -> (i32, bool) {
        if pid == self.pid {
            return (pid, true);
        }
        let Some((tgid, tracer)) = proc_status_ids(pid) else {
            return (pid, false);
        };
        let owned = tgid == self.pid
            || (tracer != 0
                && proc_status_ids(tracer)
                    .is_some_and(|(tracer_tgid, _)| tracer_tgid == std::process::id() as i32));
        (tgid, owned)
    }

    /// Whether `pid` is a guest process: its own, or one with a
    /// shared-record row, looked up by its thread group (a thread's own
    /// start time would miss the row).
    fn guest_process(&self, pid: i32) -> bool {
        let (tgid, owned) = self.tgid_and_owned(pid);
        owned || has_shared_row(tgid)
    }

    /// The link and everything after it go to the kernel; the walk records
    /// that it crossed another process's directory.
    fn raw_hand_over(&self) -> crate::translate::MagicAction {
        self.raw.set(true);
        crate::translate::MagicAction::Raw
    }

    /// A directory link (`root`, `cwd`, a directory `fd/<n>`) at host path
    /// `host`, continued past or followed: from its verified guest path,
    /// else refused for a guest process and the kernel's for any other.
    fn link_dir(&self, host: &Path, guest: bool) -> crate::translate::MagicAction {
        use crate::translate::MagicAction;
        use crate::translate::PathRefusal;
        // The object itself (the kernel follows the magic link): the kernel
        // cannot leave a non-directory, so the next component, "..", or a
        // trailing slash is its ENOTDIR.
        let md = match std::fs::metadata(host) {
            Ok(md) if !md.is_dir() => return MagicAction::Raw,
            Ok(md) => md,
            Err(_) if guest => return MagicAction::Refuse(PathRefusal::BaseUninspectable),
            Err(_) => return self.raw_hand_over(),
        };
        #[cfg(test)]
        if LINK_IDENTITY_FAILS.with(|f| f.get()) {
            return match guest {
                true => MagicAction::Refuse(PathRefusal::ProcLinkOutsideRoot),
                false => self.raw_hand_over(),
            };
        }
        match self.verified_reverse(host, &md) {
            Ok(dir) => {
                if !guest {
                    self.spliced.set(true);
                }
                MagicAction::Reroot(dir)
            }
            Err(kind) if guest => MagicAction::Refuse(kind),
            Err(_) => self.raw_hand_over(),
        }
    }

    /// The guest path of the directory `md` that the magic link at host
    /// path `host` names, when it has one leading back to it:
    /// 1. readlink gives an absolute target with no " (deleted)" suffix;
    /// 2. the target has the link's device and inode (the identity check:
    ///    the process did not move between the readlink and here; own
    ///    links have it too);
    /// 3. [`RootConfig::reverse`] names it;
    /// 4. that guest name, translated again, reaches the same device and
    ///    inode (the round trip: a deeper bind can shadow the name).
    ///
    /// Otherwise `proc_link_outside_root`, or `base_uninspectable` when
    /// the link cannot be read.
    pub(crate) fn verified_reverse(
        &self,
        host: &Path,
        md: &std::fs::Metadata,
    ) -> Result<PathBuf, crate::translate::PathRefusal> {
        use crate::translate::PathRefusal;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;
        let target = std::fs::read_link(host);
        #[cfg(test)]
        let target = match LINK_TARGET_OVERRIDE.with(|o| o.borrow().clone()) {
            Some(t) => Ok(t),
            None => target,
        };
        let target = match target {
            Ok(t) if t.is_absolute() => t,
            _ => return Err(PathRefusal::BaseUninspectable),
        };
        if target.as_os_str().as_bytes().ends_with(b" (deleted)") {
            return Err(PathRefusal::ProcLinkOutsideRoot);
        }
        let same = |p: &Path| {
            std::fs::metadata(p).is_ok_and(|m| m.dev() == md.dev() && m.ino() == md.ino())
        };
        if !same(&target) {
            return Err(PathRefusal::ProcLinkOutsideRoot);
        }
        let dir = self
            .cfg
            .reverse(&target)
            .ok_or(PathRefusal::ProcLinkOutsideRoot)?;
        if !same(&self.cfg.translate(&dir, Path::new("/"), None)) {
            return Err(PathRefusal::ProcLinkOutsideRoot);
        }
        Ok(dir)
    }
}

impl crate::translate::ProcLinks for GuestProcLinks<'_> {
    fn tool_view(&self, rel: &[std::ffi::OsString]) -> Vec<std::ffi::OsString> {
        crate::translate::tool_view_for(rel, self.pid, self.tid)
    }

    fn traverse(
        &self,
        link: &crate::translate::MagicLink,
        host: &Path,
    ) -> crate::translate::MagicAction {
        use crate::translate::MagicAction;
        use crate::translate::MagicKind;
        let guest = self.guest_process(link.pid);
        // A missing entry is an ordinary one: the walk's procfs probe
        // answers the kernel's ENOENT.
        if std::fs::symlink_metadata(host).is_err() {
            return MagicAction::Walk;
        }
        match link.kind {
            MagicKind::Root if guest => MagicAction::Reroot(PathBuf::from("/")),
            MagicKind::Root | MagicKind::Cwd | MagicKind::Fd => self.link_dir(host, guest),
            MagicKind::Exe | MagicKind::MapFiles => MagicAction::Raw,
        }
    }

    fn follow(
        &self,
        link: &crate::translate::MagicLink,
        host: &Path,
    ) -> crate::translate::MagicAction {
        use crate::translate::MagicAction;
        use crate::translate::MagicKind;
        let guest = self.guest_process(link.pid);
        match link.kind {
            MagicKind::Root if guest => MagicAction::Reroot(PathBuf::from("/")),
            // Another process's directory, followed as the final
            // component (chdir, open of a directory): its verified guest
            // path, so a record of where the call landed holds still.
            MagicKind::Root | MagicKind::Cwd if !guest => self.link_dir(host, false),
            MagicKind::Fd if !guest && std::fs::metadata(host).is_ok_and(|m| m.is_dir()) => {
                self.link_dir(host, false)
            }
            _ => MagicAction::Raw,
        }
    }

    fn raw_crossed(&self) -> bool {
        self.raw.get()
    }
}

/// A host path whose final component is a /proc magic link (or anything
/// under /proc/self), which a chain with no /proc policy never reads
/// Tool-side. A chain with one decides from the real procfs instead
/// ([`crate::translate::proc_entry`]).
fn host_is_proc_magic(host: &Path) -> bool {
    let comps: Vec<String> = host
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(v) => Some(v.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if comps.len() >= 3
        && comps[comps.len() - 3] == "proc"
        && ["fd", "exe", "root", "cwd", "map_files"].contains(&comps[comps.len() - 1].as_str())
    {
        return true;
    }
    if comps.len() >= 2 && comps[0] == "proc" {
        // Any /proc/<x>/fd|exe|... final magic component.
        let last2 = &comps[comps.len() - 2..];
        if last2[0] == "fd" || comps[1] == "self" || comps[1] == "thread-self" {
            return true;
        }
    }
    false
}

/// Process-global config stash for the ptrace (in-process Tool)
/// backend. The in-guest backend passes Config through its own
/// handoff instead (design §6); this stash is POC-only plumbing.
static CONFIG: Mutex<Option<LiterootConfig>> = Mutex::new(None);

/// Fake hostname/domainname set via emulated sethostname /
/// setdomainname (shared across the guest tree; ptrace backend
/// hosts all Tools in one process).
static UTS_NODENAME: Mutex<Option<String>> = Mutex::new(None);

/// One-shot: the launcher-issued first execve (already a host
/// path) passes through untranslated. A rootfs-prefix test
/// cannot express this (rootfs=/ matches everything, which
/// leaked fork-child execs and broke exe tracking).
static LAUNCHER_EXEC_SEEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Seed the launcher-exec one-shot: this Tool instance was
/// installed by the in-guest preload, so the launcher exec
/// already happened before the Tool existed and no execve it
/// will ever see is the launcher's. Called from the preload's
/// `.init_array` initializer in every new guest image;
/// fork children inherit the set flag. Without this, each
/// image's first guest execve took the passthrough and skipped
/// translation, the self-exe rewrite, shebang and PT_INTERP
/// handling (measured: nested exec died EOPNOTSUPP in-guest
/// while direct syscalls in the same guest passed).
pub fn mark_launcher_exec_seen() {
    LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Guest pids seen by Tools in this process, pid -> /proc
/// starttime (field 22; 0 = unread). Under ptrace every Tool
/// shares the tracer process, so the launcher can kill the
/// registered tree at root exit. In-guest the map is
/// per-process and is not kill authority: --kill-on-exit is
/// refused there until a launcher-side descent proof exists.
static GUEST_PIDS: std::sync::OnceLock<Mutex<std::collections::HashMap<i32, u64>>> =
    std::sync::OnceLock::new();

fn guest_pids() -> &'static Mutex<std::collections::HashMap<i32, u64>> {
    GUEST_PIDS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Start time (clock ticks since boot) of `pid`, for
/// reuse-safe kill verification.
pub fn proc_starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 22 overall; fields after comm's closing paren start
    // at field 3, so starttime is index 19 of the remainder.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Snapshot of registered guest pids (launcher kill-on-exit).
pub fn guest_pid_snapshot() -> Vec<(i32, u64)> {
    guest_pids()
        .lock()
        .unwrap()
        .iter()
        .map(|(p, s)| (*p, *s))
        .collect()
}

/// First guest pid ever registered in this process (the
/// initial guest under ptrace, where registration happens in
/// the tracer). Used only to recognize the root's exit_group.
static FIRST_GUEST_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// Raw wait status of the root guest's exit_group, recorded
/// Tool-side so the launcher can preserve the guest's real
/// exit code when it terminates a wedged tracer session.
static ROOT_EXIT_RAW: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// The root guest's recorded raw wait status, if observed.
pub fn root_exit_raw() -> Option<i32> {
    match ROOT_EXIT_RAW.load(std::sync::atomic::Ordering::SeqCst) {
        -1 => None,
        raw => Some(raw),
    }
}

/// Register a guest process at creation (pid + starttime).
/// Idempotent; called from Tool::new, handle_thread_start and
/// the first-syscall backstop so a process is recorded at the
/// earliest hook its backend actually delivers.
fn register_guest_pid(pid: i32) {
    let _ = FIRST_GUEST_PID.compare_exchange(
        0,
        pid,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    );
    let starttime = proc_starttime(pid).unwrap_or(0);
    guest_pids()
        .lock()
        .unwrap()
        .entry(pid)
        .or_insert(starttime);
}

/// Register a fork child from the parent side (fork return in
/// the parent): the child has not run yet, so this closes the
/// hop window where a fast chain link forks and exits before
/// any of its own hooks run.
fn register_fork_child(child_pid: i32) {
    register_guest_pid(child_pid);
}

/// Drop a guest pid from the registry (killed or proven dead).
pub fn forget_guest_pid(pid: i32) {
    guest_pids().lock().unwrap().remove(&pid);
}


/// Tool selector for an unwatched launch (today's only shape).
pub const TOOL_SELECTOR: &[u8] = b"literoot";
/// Tool selector for a watched launch: the launcher asserts a
/// real exec supervisor (`spawn_watched` + rearm loop) owns
/// this guest's exec stops. Written only by the watched spawn
/// path (W-2); never derived from guest-controlled input.
pub const TOOL_SELECTOR_WATCHED: &[u8] = b"literoot-watched";

/// Launcher side: the selector bytes for a launch. `watched`
/// may be true only when the caller actually spawned the guest
/// seized under a supervisor that re-bootstraps successors;
/// asserting it for an unwatched spawn would arm the guest's
/// exec forwarding into a dead trap handler.
#[allow(dead_code)] // launcher-side; unused in the preload build of this file
pub fn tool_selector(watched: bool) -> &'static [u8] {
    if watched {
        TOOL_SELECTOR_WATCHED
    } else {
        TOOL_SELECTOR
    }
}

/// Preload side: map a tool selector to the `exec_watch`
/// arming decision. "literoot" never arms. "literoot-watched"
/// arms only in `exec-watch` builds; a preload built without
/// the feature refuses the asserted launch by name rather
/// than silently running unarmed under a watcher (and a
/// feature-on preload under an unasserted launch simply
/// installs unarmed, exactly as today).
#[allow(dead_code)] // preload-side; unused in the launcher build of this file
pub fn exec_watch_for_selector(selector: &str) -> Result<bool, String> {
    match selector {
        "literoot" => Ok(false),
        "literoot-watched" => {
            #[cfg(feature = "exec-watch")]
            {
                Ok(true)
            }
            #[cfg(not(feature = "exec-watch"))]
            {
                Err("launcher asserted watched mode but this preload was \
                     built without the exec-watch feature"
                    .to_string())
            }
        }
        other => Err(format!(
            "unknown tool selector {other:?} (expected \"literoot\")"
        )),
    }
}
static UTS_DOMAIN: Mutex<Option<String>> = Mutex::new(None);

/// A process's exec identity before an execve handler writes the
/// successor's ([`RootfsTool::exec_identity`]).
struct ExecIdentity {
    exe_guest: PathBuf,
    exe_host: bool,
    argv: Vec<Vec<u8>>,
    pid_exe: Option<PathBuf>,
    pid_argv: Option<Vec<Vec<u8>>>,
}

/// pid -> guest exe path, for /proc/<pid>/exe de-translation of
/// *other* guest processes (e.g. sh reading /proc/$$/exe from a
/// child). Populated on every guest execve; ptrace backend hosts
/// all Tools in one process so a static map is exact there.
static PID_ARGV: std::sync::OnceLock<Mutex<std::collections::HashMap<i32, Vec<Vec<u8>>>>> =
    std::sync::OnceLock::new();

fn pid_argv_map() -> &'static Mutex<std::collections::HashMap<i32, Vec<Vec<u8>>>> {
    PID_ARGV.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

static PID_EXE: std::sync::OnceLock<Mutex<std::collections::HashMap<i32, PathBuf>>> =
    std::sync::OnceLock::new();

fn pid_exe_map() -> &'static Mutex<std::collections::HashMap<i32, PathBuf>> {
    PID_EXE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Stash the launch config for Tools constructed without Config
/// access (both backends construct via Default). In-guest, called
/// from `init_global_state`; under ptrace, by the launcher.
pub fn set_config(cfg: LiterootConfig) {
    *CONFIG.lock().unwrap() = Some(cfg);
}

#[cfg(test)]
#[path = "rootfs_tool_seams.rs"]
mod seams;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec_state::ExecState;

    /// The launcher and the preload compile these wire types from the same
    /// files: no `#[cfg` inside any of them may give the two builds
    /// different layouts behind one pasted wire digest (C5d, review).
    #[test]
    fn wire_types_have_no_cfg_inside() {
        let files = [
            (include_str!("rootfs_tool.rs"), &[
                "pub struct LiterootConfig {",
                "pub enum Refusal {",
                "pub enum Note {",
                "pub enum Summary {",
                "pub enum PathAnswer {",
                "pub enum ForkKind {",
                "pub enum UnsupportedKind {",
                "pub enum GuestKind {",
            ][..]),
            (include_str!("dead_base.rs"), &["pub enum FlagState {"][..]),
            (include_str!("translate.rs"), &["pub enum PathRefusal {"][..]),
        ];
        for (source, types) in files {
            for ty in types {
                let at = source.find(ty).unwrap_or_else(|| panic!("{ty} not found"));
                let body = &source[at..];
                let end = body.find("\n}\n").unwrap_or_else(|| panic!("{ty} not closed"));
                assert!(!body[..end].contains("#[cfg"), "{ty} has a cfg inside");
            }
        }
        assert!(include_str!("rootfs_tool.rs").contains("pub struct Refused(pub Vec<Refusal>);"));
    }

    /// A successor keeps the S.3 record exec carries (a state test: the
    /// successor route is not wired).
    #[test]
    fn from_exec_state_keeps_the_record() {
        let cfg = RootConfig::new(PathBuf::from("/"), Vec::new());
        let state = ExecState {
            cwd: b"/work".to_vec(),
            exe_guest: b"/bin/sh".to_vec(),
            record: crate::exec_state::LifetimeRecord {
                installs: 2,
                probes: 5,
                unseen_best_effort: 1,
                summary_emitted: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let tool = RootfsTool::from_exec_state(state, &cfg).unwrap();
        let st = tool.state.lock().unwrap();
        assert_eq!(
            (st.admission.installs, st.admission.probes, st.admission.unseen_best_effort),
            (2, 5, 1)
        );
        assert!(st.admission.summary_emitted);
        drop(st);
        // An emitted record does not emit again in the successor.
        assert!(tool.take_exit_summaries(1).is_empty());
    }

    /// A new group's first thread replaces the record whatever its pid,
    /// even the copied owner's (pid 1 of a new pid namespace).
    #[test]
    fn new_group_with_the_same_visible_pid_resets() {
        let tool = RootfsTool::default();
        let mut st = tool.state.lock().unwrap();
        let a = st.admission(1);
        let _probe = a.admit(1).unwrap();
        a.probes = 4;
        a.kernel_id = Some(9);
        assert!(a.begin_emission());
        st.start_new_group(1, crate::dead_base::NewGroup { flag: true, filter_addend: 1 });
        let a = st.admission(1);
        assert!(a.guest_filter && a.flag == crate::dead_base::FlagState::Inherited);
        assert_eq!((a.probes, a.probes_in_flight(), a.kernel_id), (0, 0, None));
        assert!(!a.summary_emitted && !a.first_check_done);
        assert_eq!(a.filter_addend, 1, "the child's expected count is its parent's");
    }

    /// The in-guest reporter takes the exit summaries before the inner
    /// on_exit_process runs, in one report; the inner one writes them only
    /// where the side log is open (never in a guest process).
    #[test]
    fn one_emitter_and_one_message_per_process() {
        let reporting = include_str!("../preload/src/reporting.rs");
        let exit = reporting
            .split("async fn on_exit_process")
            .nth(1)
            .and_then(|rest| rest.split("\n    }\n").next())
            .expect("reporter on_exit_process");
        assert_eq!(exit.matches("report(").count(), 1, "{exit}");
        let take = exit.find("take_exit_summaries").expect("takes the summaries");
        assert!(take < exit.find("report(").unwrap() && take < exit.find(".on_exit_process(").unwrap());
        let source = include_str!("rootfs_tool.rs");
        let inner = source
            .split("    async fn on_exit_process<G: GlobalRPC<LiterootGlobal>>(")
            .nth(1)
            .and_then(|rest| rest.split("\n    }\n").next())
            .expect("inner on_exit_process");
        let gate = inner.find("if crate::refusal_log::is_open() {").expect("log gate");
        assert!(gate < inner.find("take_exit_summaries").unwrap());
    }

    /// B4-1 wiring witness without any successor transport: a Tool
    /// rebuilt from a snapshot observes the predecessor's cwd, fd
    /// map and fake identity, with `bootstrapped` forced on and
    /// scratch left for `handle_post_exec` to reallocate.
    #[test]
    fn from_exec_state_restores_continuity() {
        let cfg = RootConfig::new(PathBuf::from("/"), Vec::new());
        let state = ExecState {
            cwd: b"/work".to_vec(),
            fds: vec![(5, b"/work".to_vec())],
            fake: Some([1000, 0, 0, 100, 0, 100]),
            exe_guest: b"/bin/sh".to_vec(),
            argv: vec![b"sh".to_vec()],
            ..Default::default()
        };
        let tool = RootfsTool::from_exec_state(state, &cfg).expect("restore");
        let st = tool.state.lock().unwrap();
        assert_eq!(st.cwd, PathBuf::from("/work"));
        assert_eq!(
            st.fdt(MAIN_FILES).fds.get(&5),
            Some(&PathBuf::from("/work"))
        );
        assert_eq!(st.fake, Some([1000, 0, 0, 100, 0, 100]));
        assert_eq!(st.exe_guest, PathBuf::from("/bin/sh"));
        assert!(st.bootstrapped);
        assert!(st.free_scratch.is_empty());
        assert_ne!(st.scratch_image, 0, "a number drawn from the counter");
    }

    #[test]
    fn thread_state_default_is_inert() {
        assert_eq!(RootfsThreadState::default().pending, None);
    }

    /// B4 step 4: a staged fork snapshot clones into the child
    /// thread state; unstaged parents and process-tree roots
    /// clone nothing. (Which clones stage is decided in the
    /// handler from clone flags — see clone_is_process.)
    #[test]
    fn init_thread_state_clones_only_staged_pending() {
        let tool = RootfsTool::default();
        let snap = ExecState {
            cwd: b"/work".to_vec(),
            exe_guest: b"/bin/sh".to_vec(),
            ..Default::default()
        };
        let staged = RootfsThreadState {
            pending: Some(snap.clone()),
            ..Default::default()
        };
        let child = tool.init_thread_state(
            reverie::Tid::from_raw(4243),
            Some((reverie::Tid::from_raw(4242), &staged)),
        );
        assert_eq!(child.pending, Some(snap));
        let unstaged = RootfsThreadState::default();
        let child = tool.init_thread_state(
            reverie::Tid::from_raw(4244),
            Some((reverie::Tid::from_raw(4242), &unstaged)),
        );
        assert_eq!(child.pending, None);
        let root = tool.init_thread_state(reverie::Tid::from_raw(4242), None);
        assert_eq!(root.pending, None);
    }

    /// A new thread group's first thread takes the S.3 flag its parent's
    /// clone staged; a thread of the same group takes none.
    #[test]
    fn init_thread_state_carries_the_new_group_flag() {
        let tool = RootfsTool::default();
        for flag in [false, true] {
            let group = crate::dead_base::NewGroup { flag, filter_addend: 2 };
            let parent = RootfsThreadState {
                child_group: Some(group),
                ..Default::default()
            };
            let child = tool.init_thread_state(
                reverie::Tid::from_raw(4243),
                Some((reverie::Tid::from_raw(4242), &parent)),
            );
            assert_eq!((child.new_group, child.child_group), (Some(group), None));
        }
        let child = tool.init_thread_state(
            reverie::Tid::from_raw(4243),
            Some((reverie::Tid::from_raw(4242), &RootfsThreadState::default())),
        );
        assert_eq!(child.new_group, None);
    }

    /// Only an in-guest process child that shares the address space trips
    /// the shared-record check.
    #[test]
    fn shares_record_in_guest_only_for_vm_sharing_process_children() {
        let vm = libc::CLONE_VM as u64;
        let thread = (libc::CLONE_THREAD | libc::CLONE_SIGHAND | libc::CLONE_VM) as u64;
        let vfork = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64;
        assert!(shares_record_in_guest(true, vm));
        assert!(shares_record_in_guest(true, vfork));
        assert!(!shares_record_in_guest(true, libc::SIGCHLD as u64));
        assert!(!shares_record_in_guest(true, thread));
        assert!(!shares_record_in_guest(false, vfork));
    }

    /// The exit summaries: none when nothing is due, the due kinds once,
    /// then nothing (exactly one emission per process).
    #[test]
    fn exit_summaries_are_emitted_once_and_only_when_due() {
        let tool = RootfsTool::default();
        assert!(tool.take_exit_summaries(77).is_empty());
        {
            let mut st = tool.state.lock().unwrap();
            let a = st.admission(77);
            let t = a.begin_install().unwrap();
            a.finish_install(t, Some(0));
            a.probes = 3;
            a.refused = 1;
        }
        let first = tool.take_exit_summaries(77);
        assert_eq!(
            first,
            vec![
                Refusal::Summary(Summary::Seccomp {
                    pid: 77,
                    kernel_id: 0,
                    flag: crate::dead_base::FlagState::Installed,
                    installs: 1,
                    installs_refused: 0,
                    translated: 0,
                    refused: 1,
                    unseen_best_effort: 0,
                }),
                Refusal::Summary(Summary::Probe {
                    pid: 77,
                    kernel_id: 0,
                    probes: 3,
                    sud_refused: 0,
                    sud_fallback: 0,
                }),
            ]
        );
        assert!(tool.take_exit_summaries(77).is_empty());
    }

    /// A new task takes the fd table its parent's clone handler staged, and
    /// the parent's own table when nothing was staged.
    #[test]
    fn init_thread_state_takes_the_staged_fd_table() {
        let tool = RootfsTool::default();
        let parent = RootfsThreadState {
            files: 2,
            child_files: Some(5),
            ..Default::default()
        };
        let child = tool.init_thread_state(
            reverie::Tid::from_raw(4243),
            Some((reverie::Tid::from_raw(4242), &parent)),
        );
        assert_eq!((child.files, child.child_files), (5, None));
        let parent = RootfsThreadState {
            files: 2,
            ..Default::default()
        };
        let child = tool.init_thread_state(
            reverie::Tid::from_raw(4243),
            Some((reverie::Tid::from_raw(4242), &parent)),
        );
        assert_eq!(child.files, 2);
        let root = tool.init_thread_state(reverie::Tid::from_raw(4242), None);
        assert_eq!(root.files, MAIN_FILES);
    }

    /// A split table starts as a copy; forgetting a number in it leaves the
    /// table it came from alone.
    #[test]
    fn a_split_fd_table_is_a_copy_and_forgets_on_its_own() {
        let tool = RootfsTool::default();
        let mut st = tool.state.lock().unwrap();
        let main = st.fdt_mut(MAIN_FILES);
        main.fds.insert(4, PathBuf::from("/v"));
        main.virtual_fds.insert(4, PathBuf::from("/v"));
        st.stream_mut(MAIN_FILES, 4).obj = Some((1, 2));
        let id = st.split_files(MAIN_FILES, |_| None);
        assert_ne!(id, MAIN_FILES);
        assert_eq!(st.fdt(id).virtual_fds.get(&4), Some(&PathBuf::from("/v")));
        st.forget(id, 4);
        assert!(st.fdt(id).virtual_fds.is_empty() && st.stream(id, 4).is_none());
        assert_eq!(st.fdt(id).fds.get(&4), Some(&PathBuf::from("/v")));
        assert_eq!(
            st.fdt(MAIN_FILES).virtual_fds.get(&4),
            Some(&PathBuf::from("/v"))
        );
        assert_eq!(st.stream(MAIN_FILES, 4).and_then(|s| s.obj), Some((1, 2)));
        assert_ne!(
            st.split_files(MAIN_FILES, |_| None),
            id,
            "ids are never reused"
        );
    }

    /// A split gives a stream without an identity the object its number
    /// holds at the split, and leaves an identity already recorded alone.
    #[test]
    fn a_split_seeds_missing_stream_identities() {
        let tool = RootfsTool::default();
        let mut st = tool.state.lock().unwrap();
        st.fdt_mut(MAIN_FILES).fds.insert(4, PathBuf::from("/a"));
        st.fdt_mut(MAIN_FILES).fds.insert(5, PathBuf::from("/b"));
        st.stream_mut(MAIN_FILES, 5).obj = Some((1, 2));
        let id = st.split_files(MAIN_FILES, |fd| {
            if fd == 5 {
                Some((1, 2))
            } else {
                Some((9, fd as u64))
            }
        });
        assert_eq!(st.stream(id, 4).and_then(|s| s.obj), Some((9, 4)));
        assert_eq!(st.stream(MAIN_FILES, 4).and_then(|s| s.obj), Some((9, 4)));
        assert_eq!(st.stream(id, 5).and_then(|s| s.obj), Some((1, 2)));
        // /proc cannot say: the recorded identity stands.
        let id2 = st.split_files(MAIN_FILES, |_| None);
        assert_eq!(st.stream(id2, 5).and_then(|s| s.obj), Some((1, 2)));
    }

    /// A number that now holds another object than its stream was built
    /// for leaves that stream at the split (to tables that still hold the
    /// old object), and both tables share a fresh stream for the object it
    /// holds now.
    #[test]
    fn a_split_detaches_a_stale_stream_first() {
        let tool = RootfsTool::default();
        let mut st = tool.state.lock().unwrap();
        st.fdt_mut(MAIN_FILES).fds.insert(4, PathBuf::from("/b"));
        {
            let s = st.stream_mut(MAIN_FILES, 4);
            s.obj = Some((1, 2));
            s.pending = Some(Vec::new());
        }
        let earlier = st.split_files(MAIN_FILES, |_| Some((1, 2)));
        // The number now holds (3, 4) in MAIN_FILES (a dup literoot did not see).
        let id = st.split_files(MAIN_FILES, |_| Some((3, 4)));
        let fresh = st.stream(MAIN_FILES, 4).cloned();
        assert_eq!(
            fresh.as_ref().map(|s| (s.obj, s.pending.is_some())),
            Some((Some((3, 4)), false))
        );
        assert_eq!(st.stream(id, 4), fresh.as_ref());
        assert_eq!(
            st.fdt(id).streams.get(&4),
            st.fdt(MAIN_FILES).streams.get(&4)
        );
        // The earlier copy still holds the stream built for (1, 2).
        assert_eq!(st.stream(earlier, 4).and_then(|s| s.obj), Some((1, 2)));
        assert_eq!(
            st.stream(earlier, 4).map(|s| s.pending.is_some()),
            Some(true)
        );
    }

    /// The two tables of a split hold the same streams: listing progress
    /// made through one is the other's (R9), including for a number that
    /// had no listing state before the split. A stream goes once no table
    /// holds it.
    #[test]
    fn a_split_fd_table_shares_its_streams() {
        let tool = RootfsTool::default();
        let mut st = tool.state.lock().unwrap();
        st.fdt_mut(MAIN_FILES)
            .virtual_fds
            .insert(4, PathBuf::from("/v"));
        st.stream_mut(MAIN_FILES, 4);
        st.fdt_mut(MAIN_FILES).fds.insert(5, PathBuf::from("/real"));
        let id = st.split_files(MAIN_FILES, |_| None);
        st.stream_mut(id, 4).emitted = true;
        st.stream_mut(id, 5).pending = Some(vec![7]);
        assert_eq!(
            virtual_record(&st, MAIN_FILES, 4),
            Some((PathBuf::from("/v"), true))
        );
        assert_eq!(
            st.stream(MAIN_FILES, 5).and_then(|s| s.pending.clone()),
            Some(vec![7])
        );
        st.forget(id, 5);
        assert_eq!(
            st.stream(MAIN_FILES, 5).and_then(|s| s.pending.clone()),
            Some(vec![7])
        );
        // A number the split copy reuses gets a stream of its own.
        st.stream_mut(id, 5).pending = Some(Vec::new());
        assert_eq!(
            st.stream(MAIN_FILES, 5).and_then(|s| s.pending.clone()),
            Some(vec![7])
        );
        st.forget(MAIN_FILES, 5);
        st.forget(id, 5);
        assert_eq!(st.streams.len(), 1, "only the stream of fd 4 is still held");
    }

    #[test]
    fn refusal_reporter_prints_first_and_every_hundredth_per_category() {
        let reporter = RefusalReporter::new();
        let first = reporter
            .message(RefusalCategory::Publish, "for pid 42: full")
            .expect("first publish refusal is reported");
        assert!(
            first.contains("shared record publish refused: for pid 42: full"),
            "first message: {first}"
        );
        assert_eq!(
            reporter.message(RefusalCategory::Publish, "for pid 43: full"),
            None,
            "second publish refusal must be suppressed"
        );
        assert!(
            reporter
                .message(RefusalCategory::UtsNodename, "full")
                .is_some_and(|message| {
                    message.contains("shared record UTS nodename write refused: full")
                }),
            "nodename has its own first report"
        );
        assert!(
            reporter
                .message(RefusalCategory::UtsDomainname, "full")
                .is_some_and(|message| {
                    message.contains("shared record UTS domainname write refused: full")
                }),
            "domainname has its own first report"
        );
        for _ in 0..97 {
            assert_eq!(
                reporter.message(RefusalCategory::Publish, "for pid 44: full"),
                None
            );
        }
        let hundredth = reporter
            .message(RefusalCategory::Publish, "for pid 45: full")
            .expect("hundredth publish refusal is summarized");
        assert!(
            hundredth.contains("100 refusals so far"),
            "summary message: {hundredth}"
        );
    }

    #[test]
    fn process_start_time_parser_uses_final_comm_close() {
        // comm is "my (proc) name": the tail begins at field 3,
        // so field 22 is tail index 19. Build that tail by
        // position instead of counting words in a long literal.
        let mut fields = vec!["S"; 20];
        fields[19] = "123456";
        let stat = format!("4242 (my (proc) name) {}", fields.join(" "));
        assert_eq!(
            parse_process_start_time(stat.as_bytes(), 4242),
            ProcessId::new(4242, 123456).ok()
        );
        assert_eq!(parse_process_start_time(stat.as_bytes(), 4243), None);
        let mut non_utf8 = b"4242 (bad\xff) ".to_vec();
        non_utf8.extend_from_slice(fields.join(" ").as_bytes());
        assert_eq!(
            parse_process_start_time(&non_utf8, 4242),
            ProcessId::new(4242, 123456).ok()
        );
        assert_eq!(parse_process_start_time(b"4242 (x) S", 4242), None);
        assert_eq!(parse_process_start_time(b"not-a-stat", 4242), None);
    }

    #[test]
    fn initial_exe_accessor_resolves_launch_relative_paths() {
        // Translation uses filesystem probes, so the launch cwd
        // must be a real directory for `..` to collapse.
        let rootfs =
            std::env::temp_dir().join(format!("literoot-initial-exe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rootfs);
        std::fs::create_dir_all(rootfs.join("work/dir")).expect("fixture rootfs");
        let root = RootConfig::new(rootfs.clone(), Vec::new());
        assert_eq!(
            initial_exe_guest("./prog", "/work/dir", &root),
            PathBuf::from("/work/dir/prog")
        );
        assert_eq!(
            initial_exe_guest("../x/prog", "/work/dir", &root),
            PathBuf::from("/work/x/prog")
        );
        assert_eq!(
            initial_exe_guest("", "/work/dir", &root),
            PathBuf::from("/proc/self/exe")
        );
        assert_eq!(
            initial_exe_guest("./prog", "", &root),
            PathBuf::from("/prog")
        );
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn fork_seed_gate_refuses_unbootstrapped_parent_and_preserves_fake() {
        let tool = RootfsTool::default();
        let cfg = LiterootConfig::default();
        let current_argv = vec![b"prog".to_vec()];
        {
            let mut st = tool.state.lock().unwrap();
            st.bootstrapped = false;
            st.fake = Some([9, 8, 7, 6, 5, 4]);
            let fake_before = st.fake;
            // The exact decision production staging uses:
            // nothing is staged for this clone.
            assert_eq!(
                fork_seed_if_bootstrapped(
                    &st,
                    MAIN_FILES,
                    &cfg,
                    Path::new("/bin/sh"),
                    &current_argv
                ),
                None
            );
            // The checked constructor still refuses by name if
            // a future caller bypasses the production gate.
            let result = fork_seed(&st, MAIN_FILES, &cfg, Path::new("/bin/sh"), &current_argv);
            assert_eq!(result, Err(reverie::syscalls::Errno::EINVAL));
            assert_eq!(st.fake, fake_before);
        }
        {
            let mut st = tool.state.lock().unwrap();
            st.bootstrapped = true;
            st.fake = Some([9, 8, 7, 6, 5, 4]);
            let seed = fork_seed_if_bootstrapped(
                &st,
                MAIN_FILES,
                &cfg,
                Path::new("/bin/sh"),
                &current_argv,
            )
            .expect("bootstrapped gate stages")
            .expect("bootstrapped fork seed");
            assert_eq!(seed.exe_guest, b"/bin/sh");
            assert_eq!(seed.argv, current_argv);
            assert_eq!(seed.fake, Some([9, 8, 7, 6, 5, 4]));
            assert_eq!(st.fake, Some([9, 8, 7, 6, 5, 4]));
        }
    }

    #[test]
    fn clone_is_process_classifies_flags() {
        let sigchld = libc::SIGCHLD as u64;
        // fork(2) as deduced by CloneFamily::flags.
        assert!(clone_is_process(sigchld));
        // vfork(2) deduced flags: still a new process.
        assert!(clone_is_process(
            libc::CLONE_VFORK as u64 | libc::CLONE_VM as u64 | sigchld
        ));
        // Thread creation must never stage a fork snapshot.
        assert!(!clone_is_process(
            libc::CLONE_THREAD as u64 | libc::CLONE_VM as u64 | sigchld
        ));
        // Unreadable clone3 args read back as empty flags; the
        // clone will fail in the kernel and the handler clears
        // the staged snapshot on return, so staging is safe.
        assert!(clone_is_process(0));
    }

    /// A relative final link with no guest route is refused by name
    /// (no_guest_route), counted as one link and never joined on the host
    /// side, where its ".." would leave the guest root; with a guest route
    /// it resolves from the route's parent, and an absolute target needs no
    /// route.
    #[test]
    fn chain_with_no_guest_route_refuses_a_relative_target() {
        use crate::translate::PathRefusal;
        use crate::translate::WalkError;
        let p = std::env::temp_dir().join(format!("literoot-no-route-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let root = p.join("root");
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::create_dir_all(p.join("outside")).unwrap();
        std::fs::write(root.join("outside/file"), b"GUEST").unwrap();
        std::fs::write(p.join("outside/file"), b"HOST-SIDE-MARKER").unwrap();
        std::os::unix::fs::symlink("../outside/file", root.join("rl")).unwrap();
        std::os::unix::fs::symlink("/outside/file", root.join("al")).unwrap();
        let cfg = RootConfig::new(root.clone(), Vec::new());
        let inside = Ok((
            root.join("outside/file"),
            Some(PathBuf::from("/outside/file")),
        ));
        let mut links = 0;
        let r = resolve_symlink_chain_guest(&cfg, None, root.join("rl"), &mut links, None);
        assert_eq!(
            r,
            Err(WalkError::Refused(PathRefusal::NoGuestRoute)),
            "no route: refused"
        );
        assert_eq!(links, 1, "the refused link counts");
        let mut links = 0;
        let route = Some(PathBuf::from("/rl"));
        let r = resolve_symlink_chain_guest(&cfg, route, root.join("rl"), &mut links, None);
        assert_eq!(r, inside, "from the route's parent");
        let mut links = 0;
        let r = resolve_symlink_chain_guest(&cfg, None, root.join("al"), &mut links, None);
        assert_eq!(r, inside, "an absolute target needs no route");
        std::fs::remove_dir_all(&p).unwrap();
    }

    /// The decide step never hands a base it could not inspect to the
    /// kernel: a stat error other than "absent", a readlink error and
    /// non-absolute /proc text are base_uninspectable; a text that does not
    /// lead back to the base is base_moved; a deleted base (nlink 0) is used
    /// only through a guest name that reaches it, else base_outside_root.
    /// None of them is Raw.
    #[test]
    fn decide_refuses_every_uninspectable_base() {
        use crate::translate::PathRefusal;
        let p = std::env::temp_dir().join(format!("literoot-decide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let dir = p.join("dir");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(p.join("file"), b"f").unwrap();
        let cfg = RootConfig::new(p.clone(), Vec::new());
        let elsewhere = RootConfig::new(p.join("elsewhere"), Vec::new());
        let uninspectable = UnnamedRoute::Refused(PathRefusal::BaseUninspectable);
        // ENOTDIR below a regular file: not "absent", for root as for others.
        let base = p.join("file/x");
        let base = base.to_str().unwrap();
        let climb = gather_climb(base, Path::new("../y"));
        assert!(matches!(climb, Climb::Uninspectable), "gather: {climb:?}");
        assert_eq!(
            unnamed_route(&cfg, base, Path::new("../y")),
            uninspectable,
            "the route"
        );
        let r = decide(
            Climb::Uninspectable,
            Path::new("../y"),
            Ok(PathBuf::new()),
            |_, _| None,
            &cfg,
        );
        assert_eq!(r, uninspectable, "decide");
        let md = || std::fs::metadata(&dir).unwrap();
        let live = || Climb::Live {
            md: md(),
            ups: 0,
            rest: PathBuf::from("y"),
        };
        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        let r = decide(live(), Path::new("y"), Err(eacces), gather_text_stat, &cfg);
        assert_eq!(r, uninspectable, "a readlink error");
        let relative = Ok(PathBuf::from("dir"));
        let r = decide(live(), Path::new("y"), relative, gather_text_stat, &cfg);
        assert_eq!(r, uninspectable, "non-absolute text");
        let r = decide(
            live(),
            Path::new("y"),
            Ok(dir.clone()),
            |t, _| {
                Some((
                    t.to_path_buf(),
                    Err(std::io::Error::from_raw_os_error(libc::EIO)),
                ))
            },
            &cfg,
        );
        assert_eq!(
            r,
            UnnamedRoute::Refused(PathRefusal::BaseMoved),
            "a stat error of the text"
        );
        let dead = || Climb::Dead {
            md: md(),
            ups: 0,
            name_next: true,
        };
        let r = decide(
            dead(),
            Path::new("x"),
            Ok(dir.clone()),
            gather_text_stat,
            &cfg,
        );
        let guest = UnnamedRoute::Guest {
            dir: PathBuf::from("/dir"),
            rest: PathBuf::from("x"),
            climbed: false,
        };
        assert_eq!(
            r, guest,
            "a deleted base through a guest name that reaches it"
        );
        let r = decide(
            dead(),
            Path::new("x"),
            Ok(dir.clone()),
            gather_text_stat,
            &elsewhere,
        );
        assert_eq!(
            r,
            UnnamedRoute::Refused(PathRefusal::BaseOutsideRoot),
            "no guest name"
        );
        std::fs::remove_dir_all(&p).unwrap();
    }

    /// The Tool's own reads of a /proc path name the calling thread's entry:
    /// /proc/thread-self is the caller's task directory and /proc/self its
    /// process. Every caller passes the guest's own tid: the readlink
    /// re-read (readlinkat, and readlink on x86_64) and both execve image
    /// reads (the shebang check and the PT_INTERP check). A textual guard
    /// beside the behavioural twins (the readlink unit, and
    /// seams::own_views::execve_through_thread_self_reads_the_callers_image
    /// for the execve reads): the callers are pinned in their source.
    #[test]
    fn tool_reads_name_the_calling_thread() {
        for (host, want) in [
            ("/proc/thread-self/fd/3", "/proc/10/task/11/fd/3"),
            ("/proc/self/cwd/x", "/proc/10/cwd/x"),
            ("/proc/thread-self", "/proc/10/task/11"),
            ("/proc/self", "/proc/10"),
            ("/r/x", "/r/x"),
        ] {
            assert_eq!(
                host_for_tool_read(Path::new(host), 10, 11),
                PathBuf::from(want),
                "{host}"
            );
        }
        let code = crate::test_source::without_test_items(include_str!("rootfs_tool.rs"));
        let open = "host_for_tool_read(";
        let calls: Vec<String> = code
            .match_indices(open)
            .map(|(i, _)| {
                let rest = &code[i + open.len()..];
                let mut depth = 1;
                let end = rest
                    .char_indices()
                    .find(|&(_, c)| {
                        depth += match c {
                            '(' => 1,
                            ')' => -1,
                            _ => 0,
                        };
                        depth == 0
                    })
                    .map(|(j, _)| j)
                    .unwrap();
                rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
            })
            .collect();
        assert_eq!(
            calls,
            [
                "&host, guest.pid().as_raw(), guest.tid().as_raw()",
                "link_host, pid, tid",
                "host: &Path, guest_pid: i32, guest_tid: i32",
            ],
            "every caller passes the guest's own tid"
        );
        let ids = "let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());";
        assert!(code.contains(ids), "the readlink caller's ids");
        let reads = code.matches("std::fs::read(&image)").count();
        assert_eq!(reads, 2, "both execve image reads use the thread's path");
    }
}

#[cfg(test)]
mod exec_watch_gate_tests {
    use super::{exec_watch_for_selector, tool_selector, TOOL_SELECTOR, TOOL_SELECTOR_WATCHED};

    #[test]
    fn selector_bytes_follow_watched_bit() {
        assert_eq!(tool_selector(false), TOOL_SELECTOR);
        assert_eq!(tool_selector(true), TOOL_SELECTOR_WATCHED);
        assert_eq!(tool_selector(false), b"literoot");
    }

    #[test]
    fn unwatched_selector_never_arms() {
        // The no-watcher case: an ordinary launch must install
        // unarmed in every build flavour, exactly as today.
        assert_eq!(exec_watch_for_selector("literoot"), Ok(false));
    }

    #[test]
    fn watched_selector_arms_only_with_feature() {
        #[cfg(feature = "exec-watch")]
        assert_eq!(exec_watch_for_selector("literoot-watched"), Ok(true));
        #[cfg(not(feature = "exec-watch"))]
        {
            let err = exec_watch_for_selector("literoot-watched").unwrap_err();
            assert!(
                err.contains("without the exec-watch feature"),
                "mismatch must refuse by name, got: {err}"
            );
        }
    }

    #[test]
    fn unknown_selector_refused_by_name() {
        let err = exec_watch_for_selector("bogus").unwrap_err();
        assert!(err.contains("unknown tool selector"), "got: {err}");
    }

    #[test]
    fn magic_proc_classification_stays_narrow() {
        use std::path::Path;
        // Only paths *under* a magic link bypass
        // canonicalization. The exact magic link and
        // relative shapes classify through canonicalize
        // (resolved against cwd/dirfd), never raw: a
        // re-widening to >=3 components made relative
        // proc/self/cwd/ escape to the host /proc.
        assert!(super::is_magic_proc_path(Path::new("/proc/self/cwd/passwd")));
        assert!(super::is_magic_proc_path(Path::new("/proc/self/fd/0")));
        assert!(!super::is_magic_proc_path(Path::new("/proc/self/cwd")));
        assert!(!super::is_magic_proc_path(Path::new("/proc/self/cwd/")));
        assert!(!super::is_magic_proc_path(Path::new("proc/self/cwd/")));
        assert!(!super::is_magic_proc_path(Path::new("./proc/self/cwd/")));
    }
}


/// The selected final entry is judged from its host path.
#[cfg(test)]
mod final_proc_tests {
    use std::path::Path;
    use std::path::PathBuf;

    use super::FinalProc;
    use super::GuestProcLinks;
    use super::final_proc_entry;
    use crate::translate::MagicKind;
    use crate::translate::RootConfig;

    fn me() -> (i32, i32) {
        let pid = std::process::id() as i32;
        (pid, unsafe { libc::gettid() })
    }

    fn entry(host: &str) -> FinalProc {
        let cfg = RootConfig::new(PathBuf::from("/"), Vec::new());
        let (pid, tid) = me();
        final_proc_entry(Path::new(host), &GuestProcLinks::new(&cfg, pid, tid))
    }

    /// A scratch directory of this test process, removed by the caller.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("literoot-final-proc-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn own_magic_links_and_cmdline_are_owned() {
        let (pid, tid) = me();
        for (host, kind) in [
            (format!("/proc/{pid}/exe"), MagicKind::Exe),
            (format!("/proc/{pid}/root"), MagicKind::Root),
            (format!("/proc/{pid}/cwd"), MagicKind::Cwd),
            (format!("/proc/{pid}/task/{tid}/cwd"), MagicKind::Cwd),
            ("/proc/self/exe".to_owned(), MagicKind::Exe),
            ("/proc/thread-self/root".to_owned(), MagicKind::Root),
            (format!("/proc/{pid}/fd/0"), MagicKind::Fd),
        ] {
            match entry(&host) {
                FinalProc::OwnedLink(link) => {
                    assert_eq!((link.pid, link.kind), (pid, kind), "{host}");
                }
                other => panic!("{host}: {other:?}"),
            }
        }
        assert_eq!(entry(&format!("/proc/{pid}/cmdline")), FinalProc::OwnedCmdline(pid));
        assert_eq!(entry("/proc/self/cmdline"), FinalProc::OwnedCmdline(pid));
        // A thread's cmdline is its process's.
        assert_eq!(entry(&format!("/proc/{pid}/task/{tid}/cmdline")), FinalProc::OwnedCmdline(pid));
        assert_eq!(entry("/proc/thread-self/cmdline"), FinalProc::OwnedCmdline(pid));
        assert_eq!(entry(&format!("/proc/self/task/{tid}/cmdline")), FinalProc::OwnedCmdline(pid));
        // A thread id names its thread group: the
        // test thread is not the process's leader.
        assert_ne!(tid, pid, "the unit needs a non-leader thread");
        assert_eq!(entry(&format!("/proc/{tid}/cmdline")), FinalProc::OwnedCmdline(pid));
        assert_eq!(entry(&format!("/proc/{tid}/task/{tid}/cmdline")), FinalProc::OwnedCmdline(pid));
        for host in [format!("/proc/{tid}/exe"), format!("/proc/{tid}/task/{tid}/exe")] {
            match entry(&host) {
                FinalProc::OwnedLink(link) => assert_eq!((link.pid, link.kind), (pid, MagicKind::Exe), "{host}"),
                other => panic!("{host}: {other:?}"),
            }
        }
        // Every other per-process file of the caller's is the kernel's.
        for file in ["environ", "maps", "smaps", "numa_maps", "mem"] {
            for host in [
                format!("/proc/{pid}/{file}"),
                format!("/proc/{pid}/task/{tid}/{file}"),
                format!("/proc/self/{file}"),
                format!("/proc/thread-self/{file}"),
            ] {
                assert_eq!(entry(&host), FinalProc::Ordinary, "{host}");
            }
        }
    }

    /// Another process's links and files (pid 1 is never this test's, and
    /// has no shared-record row): the kernel's, whatever the spelling, task
    /// paths included (owner directive 2026-11-14).
    #[test]
    fn another_process_is_the_kernels() {
        for host in [
            "/proc/1/exe",
            "/proc/1/root",
            "/proc/1/cwd",
            "/proc/1/cmdline",
            "/proc/1/task/1/cwd",
            "/proc/1/task/1/exe",
            "/proc/1/task/1/root",
            "/proc/1/task/1/cmdline",
            "/proc/1/environ",
            "/proc/1/maps",
            "/proc/1/smaps",
            "/proc/1/task/1/environ",
            "/proc/1/numa_maps",
            "/proc/1/mem",
        ] {
            assert_eq!(entry(host), FinalProc::Ordinary, "{host}");
        }
    }

    /// Anything else is ordinary: other procfs files, and a file or a
    /// dangling symlink that only carries a magic link's name.
    #[test]
    fn ordinary_entries_and_lookalikes_are_ordinary() {
        let (pid, _) = me();
        assert_eq!(entry(&format!("/proc/{pid}/status")), FinalProc::Ordinary);
        assert_eq!(entry("/proc/1/status"), FinalProc::Ordinary);
        let dir = scratch("lookalike");
        let file = dir.join("exe");
        std::fs::write(&file, b"x").unwrap();
        let dangling = dir.join("root");
        let _ = std::fs::remove_file(&dangling);
        std::os::unix::fs::symlink(dir.join("missing"), &dangling).unwrap();
        let cmdline = dir.join("cmdline");
        std::fs::write(&cmdline, b"x").unwrap();
        for p in [&file, &dangling, &cmdline] {
            assert_eq!(entry(p.to_str().unwrap()), FinalProc::Ordinary, "{p:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Synthesize-if-absent needs a positive ENOENT for the parent; any
    /// other inspection error is the walk's own answer.
    #[test]
    fn synthesis_needs_a_missing_proc_directory() {
        let dir = scratch("absent");
        assert_eq!(super::proc_parent_absent(&dir.join("proc/self/exe")), Ok(true));
        std::fs::create_dir_all(dir.join("proc/self")).unwrap();
        assert_eq!(super::proc_parent_absent(&dir.join("proc/self/exe")), Ok(false));
        assert_eq!(super::proc_parent_absent(&dir.join("proc/1/cmdline")), Ok(true));
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt as _;
            let locked = dir.join("proc");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(
                super::proc_parent_absent(&dir.join("proc/self/exe")),
                Err(reverie::syscalls::Errno::EACCES)
            );
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spelled_self_links() {
        assert!(super::spells_proc_self_link(Path::new("/proc/self/exe")));
        assert!(super::spells_proc_self_link(Path::new("/proc/1/../self/root")));
        assert!(super::spells_proc_self_link(Path::new("/proc/7/cmdline")));
        assert!(!super::spells_proc_self_link(Path::new("/proc/self/cwd")));
        assert!(!super::spells_proc_self_link(Path::new("/proc/self/exe/x")));
        assert_eq!(super::spelled_cmdline_pid(Path::new("/proc/self/cmdline"), 42), Some(42));
        assert_eq!(super::spelled_cmdline_pid(Path::new("/proc/7/cmdline"), 42), Some(7));
        assert_eq!(super::spelled_cmdline_pid(Path::new("/proc/x/cmdline"), 42), None);
        assert!(super::final_name_may_be_proc(Path::new("/a/fd/3")));
        assert!(super::final_name_may_be_proc(Path::new("/a/map_files/1-2")));
        assert!(!super::final_name_may_be_proc(Path::new("/a/status")));
        assert!(!super::final_name_may_be_proc(Path::new("/a/stat")));
        for name in ["environ", "maps", "smaps", "numa_maps", "mem"] {
            assert!(!super::final_name_may_be_proc(&Path::new("/a").join(name)), "{name}");
        }
    }

    /// The readlink arms decide by the final entry BEFORE the injection
    /// (E2: a shared row's exe answers from the row), and every open arm (openat, openat2, legacy open) and execve
    /// go through the final-entry route (O'').
    #[test]
    fn handlers_decide_by_the_final_entry_first() {
        let source = include_str!("rootfs_tool.rs");
        // Each arm's body ends at its rustfmt closing line (the arm's indent).
        let arm_body = |arm: &str| {
            let at = source.find(arm).expect(arm);
            let body = &source[at..];
            &body[..body.find("\n            }\n").expect("the arm's end")]
        };
        for arm in ["Syscall::Readlinkat(link) => {", "Syscall::Readlink(link) => {"] {
            let body = arm_body(arm);
            let gate = body.find("self.final_proc(guest,").expect("the gate");
            let inject = body.find("guest.inject(rewritten)").expect("the injection");
            assert!(gate < inject, "{arm}: the gate runs before the injection");
        }
        let mut routed = vec![
            "Syscall::Openat(openat) => {",
            "Syscall::Openat2(oa) => {",
            "Syscall::Execve(execve) => {",
        ];
        if cfg!(target_arch = "x86_64") {
            routed.push("Syscall::Open(open) => {");
        }
        for arm in routed {
            let body = arm_body(arm);
            let route = body.find("self.self_link_route(guest,").expect("the route");
            let inject = body.find("guest.inject(rewritten)").expect("the injection");
            assert!(route < inject, "{arm}: the route runs before the translated injection");
        }
        assert!(!source.contains(&["fn proc_pid", "_exe("].concat()), "spelled-pid synthesis is gone");
    }

    /// S.3 placement: in both dead-base
    /// routes a non-counting gate runs once the base is known to be unnamed
    /// and before C.1's reads and gather_* (`unnamed_route`); the counting
    /// gate runs only after the gather has shown a dead-base route.
    #[test]
    fn dead_base_gate_comes_first() {
        let source = include_str!("rootfs_tool.rs");
        for f in ["async fn dead_base_gate<", "async fn dead_base_socket<"] {
            let at = source.find(f).expect(f);
            let rest = &source[at + f.len()..];
            let end = ["\n    async fn ", "\n    fn "]
                .iter()
                .filter_map(|next| rest.find(next))
                .min()
                .expect("the next fn");
            let body = &rest[..end];
            let base = body.find("self.unnamed_base_of(").expect("the base");
            let gate = body.find("self.gate_closed_quiet(guest)").expect("the quiet gate");
            let gather = body.find("unnamed_route(&cfg").expect("the gather");
            let counted = body.find("if self.admission_closed(guest) {").expect("the counted gate");
            assert!(base < gate && gate < gather, "{f}: base, then the quiet gate, then gather");
            assert!(gather < counted, "{f}: probes are counted only once a dead-base route is known");
            assert_eq!(body.matches("self.gate_closed_quiet(guest)").count(), 1, "{f}");
            assert_eq!(body.matches("self.admission_closed(guest)").count(), 1, "{f}");
        }
    }

    /// In the socket route the descriptor re-read
    /// comes after the probe and before `classify`, once, with no other
    /// use of the result between them.
    #[test]
    fn socket_reread_precedes_classify() {
        let source = include_str!("rootfs_tool.rs");
        let f = "async fn dead_base_socket<";
        let at = source.find(f).expect(f);
        let rest = &source[at + f.len()..];
        let body = &rest[..rest.find("\n    fn ").expect("the next fn")];
        let probe = body.find("self.admitted_inject(guest, probe).await").expect("the probe");
        let reread = body.find("socket_unchanged(").expect("the re-read");
        let classify = body.find("crate::dead_base::classify(").expect("the classification");
        assert!(probe < reread && reread < classify, "probe, re-read, classify");
        assert_eq!(body.matches("socket_unchanged(").count(), 1);
        assert_eq!(body.matches("crate::dead_base::classify(").count(), 1);
    }
}
