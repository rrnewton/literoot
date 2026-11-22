//! Handler seams for fix 4 (test builds only): a recording Guest, and the
//! units that drive the Tool's handlers through it.
//!
//! The handlers run unchanged against [`RecordingGuest`]. Guest memory is
//! this test process's own (Reverie's `LocalMemory`), so a unit passes the
//! address of a local buffer as a pointer argument. Every injection and every
//! RPC to the launcher is recorded as one ordered event. An injection answers
//! from a script the unit sets up first; one the script does not expect
//! panics, so a unit also proves that nothing else was injected.
//!
//! A unit that needs a deleted cwd runs on its own thread after
//! `unshare(CLONE_FS)`, so its chdir and rmdir change only that thread's cwd;
//! its directories live under the temporary directory (`TMPDIR`; the test
//! runner points it inside its own run directory) and the unit removes them. The units hold one module lock, because the Tool's pending
//! refusal records are process-wide. No unit installs a filter or turns
//! syscall user dispatch on in this process: those calls are always answered
//! from the script, never run.

use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::LocalMemory;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

use super::LiterootConfig;
use super::LiterootGlobal;
use super::MemfdRoute;
use super::Refused;
use super::RootfsThreadState;
use super::RootfsTool;

/// The closure of [`Answer::WithState`].
pub(super) type StateFn = Box<dyn FnMut(&RootfsThreadState) -> Result<i64, Errno> + Send>;

/// What one scripted injection does.
pub(super) enum Answer {
    /// Return this result without running anything.
    Return(Result<i64, Errno>),
    /// Run the call in this thread (its pointers are this process's memory).
    Native,
    /// Run this closure while the injection is held, and return its result.
    Call(Box<dyn FnMut() -> Result<i64, Errno> + Send>),
    /// The injection's future is pending once, so the unit can drop the
    /// handler future there (a cancelled handler).
    Pend,
    /// Run this closure with the injecting thread's state (what Reverie
    /// hands a clone's child), and return its result.
    WithState(StateFn),
}

/// One recorded event, in the order the handler made it.
#[derive(Debug, Clone)]
pub(super) enum Event {
    /// An injection: its number and its six raw arguments.
    Inject(Sysno, [u64; 6]),
    /// An RPC to the launcher.
    Rpc(Refused),
    /// An injection of the in-guest admission's filter-count read (open of
    /// /proc/self/status, its reads, its close), run here under
    /// [`RecordingGuest::native_status`].
    Status(Sysno),
}

pub(super) struct NoStack;

pub(super) struct NoStackGuard;

impl Drop for NoStackGuard {
    fn drop(&mut self) {}
}

impl Stack for NoStack {
    type StackGuard = NoStackGuard;

    fn size(&self) -> usize {
        0
    }

    fn capacity(&self) -> usize {
        0
    }

    fn push<'stack, T>(&mut self, _value: T) -> Addr<'stack, T> {
        panic!("the recording guest has no stack")
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        panic!("the recording guest has no stack")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(NoStackGuard)
    }
}

/// A future that is pending once, then ready.
struct YieldOnce(bool);

impl std::future::Future for YieldOnce {
    type Output = ();

    fn poll(mut self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.0 {
            std::task::Poll::Ready(())
        } else {
            self.0 = true;
            std::task::Poll::Pending
        }
    }
}

pub(super) struct RecordingGuest {
    cfg: LiterootConfig,
    thread_state: RootfsThreadState,
    events: Mutex<Vec<Event>>,
    script: Mutex<VecDeque<Answer>>,
    /// The process id the Tool sees (default: this process).
    pid: Option<i32>,
    /// The thread id the Tool sees (default: the calling thread).
    tid: Option<i32>,
    /// The next RPC is pending once before it is recorded.
    rpc_pends: AtomicBool,
    /// Once the script is empty, run every further injection natively.
    native_rest: bool,
    /// Run the in-guest admission's status read natively, outside the
    /// script, recorded as [`Event::Status`]: a unit retargeted from the
    /// ptrace configuration scripts the same injections after it.
    pub(super) native_status: bool,
    /// The status read's descriptor while it is open.
    status_fd: Mutex<Option<i64>>,
}

impl RecordingGuest {
    pub(super) fn new(cfg: LiterootConfig) -> Self {
        let scratch = UNIT_SCRATCH.with(|s| s.get()).map(|addr| super::ScratchPage { addr, image: 0 });
        Self {
            cfg,
            thread_state: RootfsThreadState { scratch, ..RootfsThreadState::default() },
            events: Mutex::new(Vec::new()),
            script: Mutex::new(VecDeque::new()),
            pid: None,
            tid: None,
            rpc_pends: AtomicBool::new(false),
            native_rest: false,
            native_status: false,
            status_fd: Mutex::new(None),
        }
    }

    /// The same guest seen as another thread or process.
    pub(super) fn with_ids(mut self, pid: Option<i32>, tid: Option<i32>) -> Self {
        self.pid = pid;
        self.tid = tid;
        self
    }

    /// Queue the answers of the next injections.
    pub(super) fn expect(&self, answers: impl IntoIterator<Item = Answer>) {
        self.script.lock().unwrap().extend(answers);
    }

    /// The events so far, in order.
    pub(super) fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    /// The injections so far, in order.
    pub(super) fn injected(&self) -> Vec<(Sysno, [u64; 6])> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Inject(nr, args) => Some((nr, args)),
                Event::Rpc(_) | Event::Status(_) => None,
            })
            .collect()
    }

    /// Answers the script still holds.
    pub(super) fn unused(&self) -> usize {
        self.script.lock().unwrap().len()
    }
}

/// Poll a handler future once. Every await under the recording guest is
/// ready at once unless the script says otherwise, so a pending poll means
/// the handler waited on something.
pub(super) fn run<F: std::future::Future>(f: F) -> F::Output {
    poll_once(f).expect("a handler future under the recording guest went pending")
}

/// Poll a future once; None (and the future dropped) when it is pending.
pub(super) fn poll_once<F: std::future::Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut ctx = std::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut ctx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

/// Drive `RootfsTool::handle_syscall_event` for one call.
pub(super) fn dispatch(tool: &RootfsTool, guest: &mut RecordingGuest, syscall: Syscall) -> Result<i64, Error> {
    use reverie::Tool as _;
    run(tool.handle_syscall_event(guest, syscall))
}

/// The errno of a handler's answer, if it is one.
pub(super) fn errno(r: &Result<i64, Error>) -> Option<Errno> {
    match r {
        Err(Error::Errno(e)) => Some(*e),
        _ => None,
    }
}

#[reverie::tool]
impl GlobalRPC<LiterootGlobal> for RecordingGuest {
    async fn send_rpc(&self, message: Refused) {
        if self.rpc_pends.swap(false, Ordering::AcqRel) {
            YieldOnce(false).await;
        }
        self.events.lock().unwrap().push(Event::Rpc(message));
    }

    fn config(&self) -> &LiterootConfig {
        &self.cfg
    }
}

#[reverie::tool]
impl Guest<RootfsTool> for RecordingGuest {
    type Memory = LocalMemory;
    type Stack = NoStack;

    fn tid(&self) -> Pid {
        Pid::from_raw(self.tid.unwrap_or_else(|| unsafe { libc::gettid() }))
    }

    fn pid(&self) -> Pid {
        Pid::from_raw(self.pid.unwrap_or(std::process::id() as i32))
    }

    fn ppid(&self) -> Option<Pid> {
        None
    }

    // A test fake with no backend runtime.
    fn is_backend_runtime_bootstrap(&self) -> bool {
        false
    }

    fn memory(&self) -> Self::Memory {
        LocalMemory::new()
    }

    fn thread_state_mut(&mut self) -> &mut RootfsThreadState {
        &mut self.thread_state
    }

    fn thread_state(&self) -> &RootfsThreadState {
        &self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        // SAFETY: all-zero registers; no handler under test reads them.
        unsafe { std::mem::zeroed() }
    }

    async fn stack(&mut self) -> Self::Stack {
        NoStack
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (nr, a) = syscall.into_parts();
        let args = [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5].map(|v| v as u64);
        let status = self.native_status && {
            let fd = *self.status_fd.lock().unwrap();
            match nr {
                // SAFETY: the Tool staged this path in the unit's scratch
                // buffer, this process's memory, NUL-terminated.
                Sysno::openat => unsafe { std::ffi::CStr::from_ptr(args[1] as *const libc::c_char) }
                    .to_bytes()
                    == b"/proc/self/status",
                Sysno::read | Sysno::close => fd == Some(args[0] as i64),
                _ => false,
            }
        };
        if status {
            self.events.lock().unwrap().push(Event::Status(nr));
            // SAFETY: the Tool's own status read, with pointers into this
            // process's memory.
            let r = unsafe {
                libc::syscall(nr.id() as libc::c_long, args[0], args[1], args[2], args[3], args[4], args[5])
            };
            if r < 0 {
                return Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
            }
            let mut fd = self.status_fd.lock().unwrap();
            match nr {
                Sysno::openat => *fd = Some(r),
                Sysno::close => *fd = None,
                _ => {}
            }
            return Ok(r);
        }
        self.events.lock().unwrap().push(Event::Inject(nr, args));
        let answer = self.script.lock().unwrap().pop_front();
        let answer = answer.or(if self.native_rest { Some(Answer::Native) } else { None });
        match answer {
            Some(Answer::Return(r)) => r,
            Some(Answer::Native) => {
                // SAFETY: the unit chose to run this call here; its pointer
                // arguments are this process's own memory.
                let r = unsafe {
                    libc::syscall(
                        nr.id() as libc::c_long,
                        args[0], args[1], args[2], args[3], args[4], args[5],
                    )
                };
                if r < 0 {
                    Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)))
                } else {
                    Ok(r)
                }
            }
            Some(Answer::Call(mut f)) => f(),
            Some(Answer::WithState(mut f)) => f(&self.thread_state),
            Some(Answer::Pend) => {
                YieldOnce(false).await;
                Err(Errno::EINTR)
            }
            None => panic!("unscripted injection: {nr:?} {args:?}; so far {:?}", self.events()),
        }
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        let (nr, _) = syscall.into_parts();
        panic!("the recording guest cannot tail-inject {nr:?}")
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Ok(())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Ok(())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Ok(0)
    }
}

/// One serial lane for every unit here: the pending refusal records and the
/// dispatch-read seam are shared state.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// The path reports and answers made since the last call.
fn take_reports() -> Vec<super::Refusal> {
    std::mem::take(&mut *super::PENDING_PATH_REPORTS.lock().unwrap())
}

/// The guest refusal bits set since the last call.
fn take_guest_bits() -> u32 {
    super::PENDING_GUEST_REFUSALS.swap(0, Ordering::AcqRel)
}

fn dispatch_bit() -> u32 {
    let i = super::GUEST_KINDS
        .iter()
        .position(|&k| k == super::GuestKind::SyscallUserDispatch)
        .unwrap();
    1 << i
}

/// The ptrace backend's config: the Tool reads the dispatch mode from the
/// tracer (here the dispatch-read seam), and nothing is refused in-guest.
fn ptrace_cfg(root: &Path) -> LiterootConfig {
    LiterootConfig {
        rootfs: root.display().to_string(),
        cwd: "/".into(),
        ..LiterootConfig::default()
    }
}

/// An in-guest backend's config (trap, liteinst).
fn inguest_cfg(root: &Path) -> LiterootConfig {
    LiterootConfig {
        refuse_guest_ptrace: true,
        refuse_guest_dispatch: true,
        ..ptrace_cfg(root)
    }
}

/// A 4 KiB buffer in this process standing in for the guest scratch page.
struct Scratch(Box<[u8; 4096]>);

thread_local! {
    /// The unit's [`Scratch`] buffer once [`tool_with`] gave it: every
    /// [`RecordingGuest`] built on this unit thread meanwhile starts with it
    /// as its thread's scratch page. Cleared when the buffer is dropped.
    /// So every guest of a unit shares ONE page, which is right for units of
    /// one thread at a time; only `scratch_units` (and the units that set a
    /// page themselves) exercise distinct pages.
    static UNIT_SCRATCH: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

impl Scratch {
    fn new() -> Self {
        Scratch(Box::new([0; 4096]))
    }

    fn addr(&mut self) -> usize {
        self.0.as_mut_ptr() as usize
    }

    fn at(&self, offset: usize, len: usize) -> &[u8] {
        &self.0[offset..offset + len]
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let mine = self.0.as_ptr() as usize;
        if UNIT_SCRATCH.with(|s| s.get()) == Some(mine) {
            UNIT_SCRATCH.with(|s| s.set(None));
        }
    }
}

/// A Tool whose process has a deleted cwd (the guest cwd has no name) and
/// whose guests' scratch page is `scratch` ([`UNIT_SCRATCH`]), so no mmap
/// is injected.
fn tool_with(scratch: &mut Scratch) -> Arc<RootfsTool> {
    let tool = Arc::new(RootfsTool::default());
    tool.state.lock().unwrap().cwd = PathBuf::from(super::UNNAMED_CWD);
    let addr = scratch.addr();
    UNIT_SCRATCH.with(|s| s.set(Some(addr)));
    tool
}

/// A fresh directory for one unit.
fn unit_dir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "literoot-seam-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

/// Make `<root>/<name>` with `mode`, chdir this thread into it, and delete
/// it: this thread's cwd is then a deleted directory.
fn enter_dead(root: &Path, name: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = root.join(name);
    std::fs::create_dir(&dir).unwrap();
    std::env::set_current_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

/// Run `f` on a thread of its own whose cwd is a deleted directory of
/// `mode`, with the unit's root directory; the root is removed afterwards.
fn in_dead_cwd<R: Send>(mode: u32, f: impl FnOnce(&Path) -> R + Send) -> R {
    std::thread::scope(|s| {
        s.spawn(|| {
            // SAFETY: CLONE_FS only: this thread gets its own cwd and root.
            assert_eq!(unsafe { libc::unshare(libc::CLONE_FS) }, 0, "unshare(CLONE_FS)");
            set_dispatch_read(Some(Ok(false)));
            let root = unit_dir();
            enter_dead(&root, "dead", mode);
            let r = f(&root);
            set_dispatch_read(None);
            std::env::set_current_dir(&root).unwrap();
            std::env::set_current_dir(std::env::temp_dir()).unwrap();
            std::fs::remove_dir(&root).unwrap();
            r
        })
        .join()
        .unwrap()
    })
}

fn set_dispatch_read(answer: Option<Result<bool, i32>>) {
    super::DISPATCH_READ_SEAM.with(|s| s.set(answer));
}

/// An AF_UNIX socket of `ty` in this process.
fn unix_socket(ty: i32) -> i32 {
    let fd = unsafe { libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    fd
}

fn close(fd: i32) {
    unsafe { libc::close(fd) };
}

/// `{AF_UNIX, name}` and its length (the name and its NUL).
fn unix_addr(name: &[u8]) -> (Box<[u8; 110]>, usize) {
    let mut buf = Box::new([0u8; 110]);
    buf[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
    buf[2..2 + name.len()].copy_from_slice(name);
    (buf, 2 + name.len() + 1)
}

fn socket_call(nr: Sysno, fd: i32, addr: &[u8; 110], len: usize) -> Syscall {
    Syscall::from_raw(nr, SyscallArgs::new(fd as isize as usize, addr.as_ptr() as usize, len, 0, 0, 0))
}

/// mkdirat(AT_FDCWD, `name`, 0700): a T1 route.
fn mkdirat_call(name: &std::ffi::CStr) -> Syscall {
    Syscall::from_raw(
        Sysno::mkdirat,
        SyscallArgs::new(libc::AT_FDCWD as isize as usize, name.as_ptr() as usize, 0o700, 0, 0, 0),
    )
}

/// seccomp(SECCOMP_SET_MODE_FILTER, 0, prog): always answered from the
/// script, never run.
fn install_call() -> Syscall {
    Syscall::from_raw(
        Sysno::seccomp,
        SyscallArgs::new(libc::SECCOMP_SET_MODE_FILTER as usize, 0, 0x1000, 0, 0, 0),
    )
}

fn prctl_call(option: u64, mode: u64, offset: u64, len: u64, selector: u64) -> Syscall {
    Syscall::from_raw(
        Sysno::prctl,
        SyscallArgs::new(option as usize, mode as usize, offset as usize, len as usize, selector as usize, 0),
    )
}

fn raw_args(call: Syscall) -> [u64; 6] {
    let (_, a) = call.into_parts();
    [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5].map(|v| v as u64)
}

use super::Refusal;
use crate::translate::PathRefusal;

const PROBE_UNSUPPORTED: Refusal = Refusal::Path(PathRefusal::ProbeUnsupported);
const DEAD_BASE_NAME: Refusal = Refusal::Answered(super::PathAnswer::DeadBaseName);

fn ok0() -> Answer {
    Answer::Return(Ok(0))
}

fn err(e: Errno) -> Answer {
    Answer::Return(Err(e))
}

/// C.3, the "not proven" cell (N2): an EADDRINUSE from T3 is taken as the
/// positive signal whatever made it, so an LSM denying bind with EADDRINUSE
/// itself is answered by the local steps exactly as the kernel's own
/// LAST_ROOT mapping. The seam documents the cell: it cannot discriminate,
/// by construction.
#[test]
fn bind_eaddrinuse_not_proven() {
    let _lane = serial();
    take_reports();
    let answers = in_dead_cwd(0o700, |root| {
        let mut out = Vec::new();
        for t3 in [Answer::Native, err(Errno::EADDRINUSE)] {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([t3, Answer::Native]);
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(Sysno::bind, fd, &addr, len));
            close(fd);
            out.push((errno(&r), take_reports(), g.injected().len()));
        }
        out
    });
    assert_eq!(answers[0], (Some(Errno::ENOENT), vec![DEAD_BASE_NAME], 2), "the kernel's EADDRINUSE");
    assert_eq!(answers[1], answers[0], "an injected EADDRINUSE is not told apart");
}

/// C step 5': the descriptor is re-read after T3 or T4 on EVERY outcome,
/// an injection error included, before the result is used: a descriptor
/// that changed during the probe gives probe_unsupported (trigger 5) and
/// nothing after the probe is injected. The step observer at the real
/// re-read and at `classify` shows the order for every outcome: probe,
/// re-read, then (descriptor unchanged) classification; a skipped re-read
/// leaves no `reread` step. Control: unchanged, the positive signal reaches
/// the decide.
#[test]
fn reread_on_every_probe_outcome() {
    let _lane = serial();
    take_reports();
    fn take_trace() -> Vec<&'static str> {
        crate::dead_base::PROBE_TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
    }
    in_dead_cwd(0o700, |root| {
        let outcomes = [
            Ok(0),
            Ok(7),
            Err(Errno::EINVAL),
            Err(Errno::EADDRINUSE),
            Err(Errno::EPERM),
            Err(Errno::ENOSYS),
            Err(Errno::EINTR),
            Err(Errno::EBADF),
            Err(Errno::EACCES),
        ];
        for nr in [Sysno::bind, Sysno::connect] {
            for outcome in outcomes {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                let fd = unix_socket(libc::SOCK_STREAM);
                let other = unix_socket(libc::SOCK_STREAM);
                g.expect([Answer::Call(Box::new(move || {
                    crate::dead_base::trace("probe");
                    // The guest's descriptor now holds another socket.
                    assert_eq!(unsafe { libc::dup2(other, fd) }, fd);
                    outcome
                }))]);
                let (addr, len) = unix_addr(b"x");
                take_trace();
                let r = dispatch(&tool, &mut g, socket_call(nr, fd, &addr, len));
                close(fd);
                close(other);
                assert_eq!(errno(&r), Some(Errno::EACCES), "{nr:?} {outcome:?}");
                assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{nr:?} {outcome:?}");
                assert_eq!(g.injected().len(), 1, "{nr:?} {outcome:?}: only the probe");
                // The re-read ran after the probe, and the result was never
                // classified.
                assert_eq!(take_trace(), ["probe", "reread"], "{nr:?} {outcome:?}");
            }
        }
        // The same descriptor, every outcome: the re-read runs after the
        // probe and before classification, whatever the result.
        for (nr, signal) in [(Sysno::bind, Errno::EADDRINUSE), (Sysno::connect, Errno::EINVAL)] {
            for outcome in outcomes {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.expect([Answer::Call(Box::new(move || {
                    crate::dead_base::trace("probe");
                    outcome
                }))]);
                if outcome == Err(signal) {
                    g.expect([ok0()]);
                }
                let fd = unix_socket(libc::SOCK_STREAM);
                let (addr, len) = unix_addr(b"x");
                take_trace();
                let r = dispatch(&tool, &mut g, socket_call(nr, fd, &addr, len));
                close(fd);
                let trace = take_trace();
                assert_eq!(trace.get(..3), Some(&["probe", "reread", "classify"][..]), "{nr:?} {outcome:?}");
                assert_eq!(trace.iter().filter(|&&s| s == "reread").count(), 1, "{nr:?} {outcome:?}");
                if outcome == Err(signal) {
                    // Control: the positive signal reaches the decide.
                    assert_eq!(errno(&r), Some(Errno::ENOENT), "{nr:?}");
                    assert_eq!(take_reports(), vec![DEAD_BASE_NAME], "{nr:?}");
                } else {
                    take_reports();
                }
            }
        }
    });
}

/// C step 1 against the probe (SEAM: the race cannot be made deterministic
/// on a live kernel): the descriptor identified as AF_UNIX in step 1 holds
/// an AF_INET socket by the time the probe returns. The domain read no
/// longer matches, so the result is discarded: probe_unsupported, and
/// nothing more is injected.
#[test]
fn domain_read_mismatch_refused() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        for nr in [Sysno::bind, Sysno::connect] {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            let fd = unix_socket(libc::SOCK_STREAM);
            let inet = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            assert!(inet >= 0);
            let signal = if nr == Sysno::bind { Errno::EADDRINUSE } else { Errno::EINVAL };
            g.expect([Answer::Call(Box::new(move || {
                assert_eq!(unsafe { libc::dup2(inet, fd) }, fd);
                Err(signal)
            }))]);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(nr, fd, &addr, len));
            close(fd);
            close(inet);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{nr:?}");
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{nr:?}");
            assert_eq!(g.injected().len(), 1, "{nr:?}: only the probe");
        }
    });
}

/// C-a (N1): T4 is the guest's own connect with family AF_UNIX and addrlen
/// 2, which unix_validate_addr rejects with EINVAL before the UNIX_CONNECT
/// BPF hook (af_unix.c at v7.1.3: 1641 before 1645, 1522 before 1526). The
/// staged address is exactly the two family bytes.
#[test]
fn connect_probe_never_reaches_the_hook() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let mut scratch = Scratch::new();
        let tool = tool_with(&mut scratch);
        let mut g = RecordingGuest::new(ptrace_cfg(root));
        g.expect([Answer::Native, Answer::Native]);
        let fd = unix_socket(libc::SOCK_STREAM);
        let (addr, len) = unix_addr(b"x");
        let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
        close(fd);
        assert_eq!(errno(&r), Some(Errno::ENOENT));
        assert_eq!(take_reports(), vec![DEAD_BASE_NAME]);
        let (nr, args) = g.injected()[0];
        assert_eq!((nr, args[0], args[2]), (Sysno::connect, fd as u64, 2));
        let staged = args[1] as usize - scratch.addr();
        assert_eq!(scratch.at(staged, 2), (libc::AF_UNIX as u16).to_ne_bytes());
    });
}

/// SO_PASSPIDFD (include/uapi/asm-generic/socket.h).
const SO_PASSPIDFD: i32 = 76;

/// N1's guard: every connect kind, recorded injection by injection. No
/// injected connect has an addrlen above 2, and no injected bind has a name
/// other than "/" (addrlen 4). Each call gets the native answer (ENOENT in
/// a 0700 deleted cwd), and getsockname afterwards shows no autobind
/// (length 2, C-c).
#[test]
fn dispatch_seam_connect_kinds_inject_no_name() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let kinds: [(i32, Option<i32>); 5] = [
            (libc::SOCK_STREAM, None),
            (libc::SOCK_STREAM, Some(libc::SO_PASSCRED)),
            (libc::SOCK_STREAM, Some(SO_PASSPIDFD)),
            (libc::SOCK_DGRAM, Some(libc::SO_PASSCRED)),
            (libc::SOCK_SEQPACKET, Some(libc::SO_PASSCRED)),
        ];
        for (ty, opt) in kinds {
            for nr in [Sysno::connect, Sysno::bind] {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.expect([Answer::Native, Answer::Native]);
                let fd = unix_socket(ty);
                if let Some(opt) = opt {
                    let one: libc::c_int = 1;
                    let set = unsafe {
                        libc::setsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            opt,
                            (&one as *const libc::c_int).cast(),
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        )
                    };
                    assert_eq!(set, 0, "setsockopt {opt}");
                }
                let (addr, len) = unix_addr(b"x");
                let r = dispatch(&tool, &mut g, socket_call(nr, fd, &addr, len));
                let mut name = [0u8; 110];
                let mut name_len = name.len() as libc::socklen_t;
                let got = unsafe { libc::getsockname(fd, name.as_mut_ptr().cast(), &mut name_len) };
                close(fd);
                let what = format!("{nr:?} type {ty} opt {opt:?}");
                assert_eq!(errno(&r), Some(Errno::ENOENT), "{what}");
                assert_eq!(take_reports(), vec![DEAD_BASE_NAME], "{what}");
                assert_eq!((got, name_len), (0, 2), "{what}: no autobind");
                for (inr, args) in g.injected() {
                    let staged = args[1] as usize - scratch.addr();
                    match inr {
                        Sysno::connect => assert!(args[2] <= 2, "{what}: connect addrlen {}", args[2]),
                        Sysno::bind => {
                            assert_eq!(args[2], 4, "{what}");
                            assert_eq!(scratch.at(staged + 2, 2), b"/\0", "{what}");
                        }
                        Sysno::faccessat2 => {}
                        other => panic!("{what}: unexpected injection {other:?}"),
                    }
                }
            }
        }
    });
}

/// N2's pinned seam rows: T3 and T4 forced to EACCES (as W_OK on "/" would
/// also give) answer EACCES with exactly one probe_unsupported line and no
/// dead_base_name or dead_base_search record, and nothing after the probe is
/// injected.
#[test]
fn n2_eacces_from_t3_t4_is_refused_by_name() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        for nr in [Sysno::bind, Sysno::connect] {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([err(Errno::EACCES)]);
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(nr, fd, &addr, len));
            close(fd);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{nr:?}");
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{nr:?}");
            assert_eq!(g.injected().len(), 1, "{nr:?}");
        }
    });
}

/// Ord step 4: the cwd base is re-read after the search check. A CLONE_FS
/// sibling's chdir between the gate's decide and the re-read (here, during
/// the search check) leaves a different directory behind the same /proc
/// name: `refused path base_moved`.
#[test]
fn base_changed_during_search_refused() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let mut scratch = Scratch::new();
        let tool = tool_with(&mut scratch);
        let mut g = RecordingGuest::new(ptrace_cfg(root));
        let moved_to = root.to_path_buf();
        g.expect([
            err(Errno::EINVAL),
            Answer::Call(Box::new(move || {
                enter_dead(&moved_to, "second", 0o700);
                Ok(0)
            })),
        ]);
        let fd = unix_socket(libc::SOCK_STREAM);
        let (addr, len) = unix_addr(b"x");
        let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
        close(fd);
        assert_eq!(errno(&r), Some(Errno::EACCES));
        assert_eq!(take_reports(), vec![Refusal::Path(PathRefusal::BaseMoved)]);
        assert_eq!(g.injected().len(), 2);
    });
}

/// S.3 (ii): while A's probe is admitted and its injection is held, B's
/// install returns EOPNOTSUPP at once with `in_flight=1`, nothing of B's is
/// injected, and A then completes. No timeout or clock decides it: a B that
/// waited would leave its future pending, which `run` refuses.
#[test]
fn install_overlap_dependency() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let mut scratch = Scratch::new();
        let tool = tool_with(&mut scratch);
        let mut a = RecordingGuest::new(ptrace_cfg(root));
        let tid = unsafe { libc::gettid() };
        let b = Arc::new(Mutex::new(RecordingGuest::new(ptrace_cfg(root)).with_ids(None, Some(tid + 1))));
        let b_result = Arc::new(Mutex::new(None));
        let held = {
            let (tool, b, b_result) = (tool.clone(), b.clone(), b_result.clone());
            Answer::Call(Box::new(move || {
                let mut b = b.lock().unwrap();
                let r = dispatch(&tool, &mut b, install_call());
                *b_result.lock().unwrap() = Some((errno(&r), take_reports()));
                Err(Errno::EINVAL)
            }))
        };
        a.expect([held, ok0()]);
        let fd = unix_socket(libc::SOCK_STREAM);
        let (addr, len) = unix_addr(b"x");
        let r = dispatch(&tool, &mut a, socket_call(Sysno::connect, fd, &addr, len));
        close(fd);
        assert_eq!(
            b_result.lock().unwrap().take(),
            Some((Some(Errno::EOPNOTSUPP), vec![Refusal::InstallRefused { in_flight: 1 }])),
            "B returned while A's injection was held"
        );
        assert!(b.lock().unwrap().events().is_empty(), "no install injected");
        assert_eq!(errno(&r), Some(Errno::ENOENT), "A completes");
        assert_eq!(take_reports(), vec![DEAD_BASE_NAME]);
        let st = tool.state.lock().unwrap();
        assert_eq!((st.admission.installs, st.admission.installs_refused), (1, 1));
        assert!(!st.admission.guest_filter);
    });
}

/// S.3 through the handlers: A admitted and paused before its injection
/// completes; B's install is refused at once; after A completes, a new
/// install proceeds and sets the flag; a probe after that is refused with
/// nothing injected.
#[test]
fn install_refused_while_probe_admitted() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let mut scratch = Scratch::new();
        let tool = tool_with(&mut scratch);
        let mut a = RecordingGuest::new(ptrace_cfg(root));
        let tid = unsafe { libc::gettid() };
        let b = Arc::new(Mutex::new(RecordingGuest::new(ptrace_cfg(root)).with_ids(None, Some(tid + 1))));
        let refused = Arc::new(Mutex::new(None));
        let held = {
            let (tool, b, refused) = (tool.clone(), b.clone(), refused.clone());
            Answer::Call(Box::new(move || {
                let r = dispatch(&tool, &mut b.lock().unwrap(), install_call());
                *refused.lock().unwrap() = errno(&r);
                Err(Errno::EINVAL)
            }))
        };
        a.expect([held, ok0()]);
        let fd = unix_socket(libc::SOCK_STREAM);
        let (addr, len) = unix_addr(b"x");
        let call = socket_call(Sysno::connect, fd, &addr, len);
        assert_eq!(errno(&dispatch(&tool, &mut a, call)), Some(Errno::ENOENT));
        assert_eq!(refused.lock().unwrap().take(), Some(Errno::EOPNOTSUPP));
        assert_eq!(take_reports(), vec![Refusal::InstallRefused { in_flight: 1 }, DEAD_BASE_NAME]);
        // A new install proceeds and sets the flag.
        let mut b = b.lock().unwrap();
        b.expect([ok0()]);
        assert_eq!(dispatch(&tool, &mut b, install_call()).ok(), Some(0));
        assert!(tool.state.lock().unwrap().admission.guest_filter);
        // A probe after it is refused, nothing injected.
        let before = a.injected().len();
        assert_eq!(errno(&dispatch(&tool, &mut a, call)), Some(Errno::EACCES));
        assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED]);
        assert_eq!(a.injected().len(), before, "no probe under the new filter");
        close(fd);
    });
}

/// S.3: with an install pending, a dead-base name is refused
/// (probe_unsupported) by its arm, counted once per call, and nothing is
/// injected.
#[test]
fn probe_refused_while_install_pending() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let mut scratch = Scratch::new();
        let tool = tool_with(&mut scratch);
        let mut g = RecordingGuest::new(ptrace_cfg(root));
        let pid = std::process::id() as i32;
        let ticket = tool.state.lock().unwrap().admission(pid).begin_install().unwrap();
        let fd = unix_socket(libc::SOCK_STREAM);
        let (addr, len) = unix_addr(b"x");
        let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
        let name = c"x";
        let r1 = dispatch(&tool, &mut g, mkdirat_call(name));
        close(fd);
        assert_eq!((errno(&r), errno(&r1)), (Some(Errno::EACCES), Some(Errno::EACCES)));
        assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED, PROBE_UNSUPPORTED]);
        // Each arm's dead-name refusal counted once (the gate at the top
        // does not count).
        {
            let mut st = tool.state.lock().unwrap();
            let a = st.admission(pid);
            assert_eq!((a.probes, a.refused), (2, 2));
        }
        // A connect on a closed descriptor: the arm translates the name
        // before anything reads the socket, so probe_unsupported, the plan's
        // trigger-3 answer for a dead-base route (without fix 4 the dead name
        // went to the kernel, which answered EBADF).
        let closed = unix_socket(libc::SOCK_STREAM);
        close(closed);
        let r2 = dispatch(&tool, &mut g, socket_call(Sysno::connect, closed, &addr, len));
        assert_eq!(errno(&r2), Some(Errno::EACCES));
        assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED]);
        {
            let mut st = tool.state.lock().unwrap();
            let a = st.admission(pid);
            assert_eq!((a.probes, a.refused), (3, 3));
        }
        assert!(g.events().is_empty(), "nothing injected");
        tool.state.lock().unwrap().admission(pid).abandon_install(ticket);
    });
}

/// S.3 through the handler: an installer cancelled before its
/// injection (here at the attempt note's RPC, in-guest) leaves the flag
/// unchanged and readmits probes; one cancelled after the injection started
/// sets the flag.
#[test]
fn installer_cancelled_releases_pending() {
    use reverie::Tool as _;
    let _lane = serial();
    take_reports();
    let root = unit_dir();
    let tool = RootfsTool::default();
    let pid = std::process::id() as i32;
    let mut g = RecordingGuest::new(inguest_cfg(&root));
    g.rpc_pends.store(true, Ordering::Release);
    assert!(poll_once(tool.handle_syscall_event(&mut g, install_call())).is_none(), "pending at the note");
    {
        let mut st = tool.state.lock().unwrap();
        let a = st.admission(pid);
        assert_eq!((a.install_pending, a.guest_filter), (0, false), "cancelled before the injection");
        assert!(!a.closed(), "probes are admitted again");
    }
    assert!(g.injected().is_empty());
    g.expect([Answer::Pend]);
    assert!(poll_once(tool.handle_syscall_event(&mut g, install_call())).is_none(), "pending in the injection");
    {
        let mut st = tool.state.lock().unwrap();
        let a = st.admission(pid);
        assert_eq!((a.install_pending, a.guest_filter), (0, true), "cancelled after it may have run");
    }
    assert_eq!(g.injected().len(), 1);
    std::fs::remove_dir(&root).unwrap();
}

/// S.3's lifecycle through the handlers (ptrace, where each process has its
/// own Tool): P, whose record holds an addend and counters, has an admitted
/// probe held. P's sibling S vforks V through the production clone handler:
/// the clone stages V's group, V's thread state is made from S's by
/// `init_thread_state`, and V's start callback takes it. V starts with P's
/// addend and fresh counters; V's install proceeds and sets V's flag, while
/// P's flag, addend and counters are unchanged and P's probe completes. A
/// CLONE_THREAD sibling of P shares P's record: its install is refused with
/// P's probe in flight.
#[test]
fn admission_lifecycle() {
    use reverie::Tool as _;
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let mut scratch = Scratch::new();
        let p_tool = tool_with(&mut scratch);
        let pid = std::process::id() as i32;
        let tid = unsafe { libc::gettid() };
        // P's record is not empty: an addend the child inherits, and
        // counters it must not.
        {
            let mut st = p_tool.state.lock().unwrap();
            let a = st.admission(pid);
            a.filter_addend = 3;
            a.refused = 5;
            a.translated = 2;
        }
        let mut p = RecordingGuest::new(ptrace_cfg(root));
        // Beyond any pid_max: V's kernel id read finds no process.
        let v_pid = i32::MAX - 1;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let held = {
            let (p_tool, seen, root) = (p_tool.clone(), seen.clone(), root.to_path_buf());
            Answer::Call(Box::new(move || {
                // While P's probe is held, P's sibling S vforks V through
                // the production clone handler: S's clone stages V's group, the
                // child state is made from S's state as Reverie makes it,
                // and V's start callback takes it.
                let mut s_guest = RecordingGuest::new(ptrace_cfg(&root)).with_ids(None, Some(tid + 1));
                let v_report = Arc::new(Mutex::new(String::new()));
                let child = {
                    let (p_tool, root, v_report) = (p_tool.clone(), root.clone(), v_report.clone());
                    Answer::WithState(Box::new(move |s_state| {
                        let staged = s_state.child_group;
                        let v_state = p_tool.init_thread_state(
                            reverie::Tid::from_raw(v_pid),
                            Some((reverie::Tid::from_raw(tid + 1), s_state)),
                        );
                        let v_tool = RootfsTool::default();
                        let mut v = RecordingGuest::new(ptrace_cfg(&root)).with_ids(Some(v_pid), Some(v_pid));
                        v.thread_state = v_state;
                        run(v_tool.handle_thread_start(&mut v)).expect("V starts");
                        let fresh = {
                            let st = v_tool.state.lock().unwrap();
                            let a = &st.admission;
                            (a.filter_addend, a.refused, a.translated, a.probes_in_flight(), a.guest_filter)
                        };
                        v.expect([ok0()]);
                        let v_answer = dispatch(&v_tool, &mut v, install_call()).ok();
                        let after = {
                            let st = v_tool.state.lock().unwrap();
                            (st.admission.guest_filter, st.admission.installs)
                        };
                        *v_report.lock().unwrap() = format!(
                            "staged {staged:?} v fresh {fresh:?} install {v_answer:?} {after:?} cleared {}",
                            v.thread_state.new_group.is_none()
                        );
                        Ok(v_pid as i64)
                    }))
                };
                s_guest.expect([child]);
                // vfork as clone(CLONE_VM | CLONE_VFORK | SIGCHLD), which
                // both architectures have (flags are the first argument).
                let flags = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as usize;
                let vfork = Syscall::from_raw(Sysno::clone, SyscallArgs::new(flags, 0, 0, 0, 0, 0));
                let s_answer = dispatch(&p_tool, &mut s_guest, vfork).ok();
                let p_state = {
                    let st = p_tool.state.lock().unwrap();
                    let a = &st.admission;
                    (a.guest_filter, a.installs, a.probes_in_flight(), a.filter_addend, a.refused)
                };
                // S shares P's group state: its install is refused by name.
                let mut s2 = RecordingGuest::new(ptrace_cfg(&root)).with_ids(None, Some(tid + 2));
                let sibling_answer = errno(&dispatch(&p_tool, &mut s2, install_call()));
                seen.lock().unwrap().push(format!(
                    "{} | vfork {s_answer:?} s staged left {:?} | p {p_state:?} | sibling {sibling_answer:?} {}",
                    v_report.lock().unwrap(),
                    s_guest.thread_state.child_group,
                    s2.events().len()
                ));
                Err(Errno::EINVAL)
            }))
        };
        p.expect([held, ok0()]);
        let fd = unix_socket(libc::SOCK_STREAM);
        let (addr, len) = unix_addr(b"x");
        let r = dispatch(&p_tool, &mut p, socket_call(Sysno::connect, fd, &addr, len));
        close(fd);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            [format!(
                "staged Some(NewGroup {{ flag: false, filter_addend: 3 }}) \
                 v fresh (3, 0, 0, 0, false) install Some(0) (true, 1) cleared true \
                 | vfork Some({v_pid}) s staged left None \
                 | p (false, 0, 1, 3, 5) | sibling Some(EOPNOTSUPP) 0"
            )]
        );
        assert_eq!(errno(&r), Some(Errno::ENOENT), "P's probe completes");
        assert_eq!(take_reports(), vec![Refusal::InstallRefused { in_flight: 1 }, DEAD_BASE_NAME]);
        let st = p_tool.state.lock().unwrap();
        assert_eq!((st.admission.probes_in_flight(), st.admission.installs), (0, 1));
        assert!(!st.admission.guest_filter);
    });
}

/// S.4: EPERM from T1, T3, T4 and from the guest's search check is outside
/// every expected set: probe_unsupported, never a dead-base answer.
#[test]
fn eperm_from_each_probe_is_refused() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let name = c"x";
        let cases: Vec<(&str, Vec<Answer>, usize)> = vec![
            ("t1", vec![err(Errno::EPERM)], 1),
            ("t3", vec![err(Errno::EPERM)], 1),
            ("t4", vec![err(Errno::EPERM)], 1),
            ("check", vec![err(Errno::EINVAL), err(Errno::EPERM)], 2),
        ];
        for (what, answers, injected) in cases {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect(answers);
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let call = match what {
                "t1" => mkdirat_call(name),
                "t3" => socket_call(Sysno::bind, fd, &addr, len),
                _ => socket_call(Sysno::connect, fd, &addr, len),
            };
            let r = dispatch(&tool, &mut g, call);
            close(fd);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{what}");
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{what}");
            assert_eq!(g.injected().len(), injected, "{what}");
        }
    });
}

/// renameat and the stat-at call (newfstatat on x86_64, fstatat on aarch64)
/// have dead-base rows on both arches: in a deleted cwd each goes through
/// the gate, its T1 probe first (dirfd -1, the scripted EBADF), then the
/// guest's search check, to the dead-base answer ENOENT, recorded as
/// dead_base_name. Without its row the call skips the gate, and its arm
/// refuses the name (probe_unsupported) with nothing injected.
#[test]
fn renameat_and_statat_go_through_the_dead_base_gate() {
    let _lane = serial();
    take_reports();
    #[cfg(target_arch = "x86_64")]
    let statat = Sysno::newfstatat;
    #[cfg(target_arch = "aarch64")]
    let statat = Sysno::fstatat;
    in_dead_cwd(0o700, |root| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let fdcwd = libc::AT_FDCWD as isize as usize;
        let (x, y) = (c"x".as_ptr() as usize, c"y".as_ptr() as usize);
        let stp = &mut st as *mut libc::stat as usize;
        let cases = [
            (Sysno::renameat, Sysno::renameat2, SyscallArgs::new(fdcwd, x, fdcwd, y, 0, 0)),
            (statat, statat, SyscallArgs::new(fdcwd, x, stp, 0, 0, 0)),
        ];
        for (nr, probe_nr, args) in cases {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([err(Errno::EBADF), ok0()]);
            let r = dispatch(&tool, &mut g, Syscall::from_raw(nr, args));
            assert_eq!(errno(&r), Some(Errno::ENOENT), "{nr:?}");
            assert_eq!(take_reports(), vec![DEAD_BASE_NAME], "{nr:?}");
            let injected = g.injected();
            assert_eq!(
                injected.first().map(|(n, a)| (*n, a[0] as i64 as i32)),
                Some((probe_nr, -1)),
                "{nr:?}: the T1 probe first"
            );
            let check = injected.get(1).map(|(n, _)| *n);
            assert_eq!(check, Some(Sysno::faccessat2), "{nr:?}: the search check");
            assert_eq!(injected.len(), 2, "{nr:?}");
        }
    });
}

const DEAD_BASE_SEARCH: Refusal = Refusal::Answered(super::PathAnswer::DeadBaseSearch);

/// setxattr(`name`, `value`, `size`, `flags`) or lsetxattr on "x": a dead
/// base's T1 route through setxattrat.
fn setxattr_call(nr: Sysno, name: usize, value: usize, size: usize, flags: usize) -> Syscall {
    Syscall::from_raw(
        nr,
        SyscallArgs::new(c"x".as_ptr() as usize, name, value, size, flags, 0),
    )
}

/// setxattr and lsetxattr in a deleted cwd, scripted. The T1 probe is
/// setxattrat with dirfd -1, the staged "x", AT_SYMLINK_NOFOLLOW for
/// lsetxattr only, the guest's own name pointer, and the staged
/// `struct xattr_args` (the guest's value, size and flags) of 16 bytes at
/// SCRATCH_PROBE_XATTR_ARGS. EBADF goes on to the search check and ENOENT
/// (dead_base_name); each argument errno setxattr_copy can give is the
/// call's answer, with nothing more injected; ENOSYS (a kernel before 6.13)
/// and ENOMEM (not in the expected set) are probe_unsupported; a failed
/// search check is answered EACCES (dead_base_search). Before the probe was
/// restored, the last case and the dead name were refused by name.
#[test]
fn setxattr_probes_through_setxattrat() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let (name, value) = (c"user.a".as_ptr() as usize, c"v".as_ptr() as usize);
        let nofollow = libc::AT_SYMLINK_NOFOLLOW as u64;
        for (nr, at_flags) in [(Sysno::setxattr, 0), (Sysno::lsetxattr, nofollow)] {
            let call = setxattr_call(nr, name, value, 1, 1);
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([err(Errno::EBADF), ok0()]);
            let r = dispatch(&tool, &mut g, call);
            assert_eq!(errno(&r), Some(Errno::ENOENT), "{nr:?}");
            assert_eq!(take_reports(), vec![DEAD_BASE_NAME], "{nr:?}");
            let injected = g.injected();
            assert_eq!(injected.len(), 2, "{nr:?}: the probe and the search check");
            let (probe, a) = injected[0];
            assert_eq!(probe, Sysno::setxattrat, "{nr:?}");
            assert_eq!(a[0] as i64, -1, "{nr:?}: dirfd -1");
            assert_eq!([a[2], a[3], a[5]], [at_flags, name as u64, 16], "{nr:?}");
            let staged_at = scratch.addr() + super::SCRATCH_PROBE_XATTR_ARGS;
            assert_eq!(a[4], staged_at as u64, "{nr:?}: the staged struct");
            let (_, raw) = call.into_parts();
            let want = crate::dead_base::xattr_args(&raw);
            assert_eq!(
                scratch.at(super::SCRATCH_PROBE_XATTR_ARGS, 16),
                &want[..],
                "{nr:?}"
            );
            assert_eq!(injected[1].0, Sysno::faccessat2, "{nr:?}: the search check");

            for e in [Errno::EINVAL, Errno::ERANGE, Errno::EFAULT, Errno::E2BIG] {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.expect([err(e)]);
                let r = dispatch(&tool, &mut g, call);
                assert_eq!(errno(&r), Some(e), "{nr:?} {e:?}: the call's answer");
                assert!(take_reports().is_empty(), "{nr:?} {e:?}");
                assert_eq!(g.injected().len(), 1, "{nr:?} {e:?}: only the probe");
            }
            for e in [Errno::ENOSYS, Errno::ENOMEM] {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.expect([err(e)]);
                let r = dispatch(&tool, &mut g, call);
                assert_eq!(errno(&r), Some(Errno::EACCES), "{nr:?} {e:?}");
                assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{nr:?} {e:?}");
                assert_eq!(g.injected().len(), 1, "{nr:?} {e:?}: only the probe");
            }
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([err(Errno::EBADF), err(Errno::EACCES)]);
            let r = dispatch(&tool, &mut g, call);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{nr:?}: the search check");
            assert_eq!(take_reports(), vec![DEAD_BASE_SEARCH], "{nr:?}");
        }
    });
}

/// setxattr and lsetxattr in a deleted cwd against the REAL kernel: every
/// injection runs natively, and each case's answer through the Tool equals
/// the same call made natively in the same deleted cwd. The cases cover each
/// argument check setxattr_copy makes before the lookup (fs/xattr.c:622-645
/// at v7.1.3), including a size above u32::MAX, which setxattr takes as a
/// size_t and setxattrat as a u32. On a kernel without setxattrat (before
/// 6.13) every case is probe_unsupported instead.
#[test]
fn setxattr_probe_matches_native() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        let long = std::ffi::CString::new(format!("user.{}", "a".repeat(251))).unwrap();
        let (name, value) = (c"user.a".as_ptr() as usize, c"v".as_ptr() as usize);
        let cases: [(&str, usize, usize, usize, usize); 9] = [
            ("valid", name, value, 1, 0),
            ("flags 4", name, value, 1, 4),
            ("empty name", c"".as_ptr() as usize, value, 1, 0),
            ("256-byte name", long.as_ptr() as usize, value, 1, 0),
            ("size 65537", name, value, 65537, 0),
            ("size 2^32+1", name, value, (1 << 32) | 1, 0),
            ("value pointer 1", name, 1, 1, 0),
            ("name pointer 1", 1, value, 1, 0),
            ("no value", name, 0, 0, 0),
        ];
        // Does this kernel have setxattrat? Its own probe answers EBADF if so.
        let args = crate::dead_base::xattr_args(&SyscallArgs::new(0, name, value, 1, 0, 0));
        // Full-width variadic arguments: dirfd -1, at_flags 0, usize 16.
        let (dirfd, at_flags, usize_16): (libc::c_long, libc::c_long, libc::c_long) = (-1, 0, 16);
        let setxattrat = Sysno::setxattrat.id() as libc::c_long;
        // SAFETY: every pointer is this process's own memory.
        let has = unsafe {
            libc::syscall(
                setxattrat,
                dirfd,
                c"x".as_ptr(),
                at_flags,
                name,
                args.as_ptr(),
                usize_16,
            )
        } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS);
        for nr in [Sysno::setxattr, Sysno::lsetxattr] {
            for (what, n, v, size, flags) in cases {
                // SAFETY: as above; a bad pointer is the case under test.
                let native = unsafe {
                    libc::syscall(nr.id() as libc::c_long, c"x".as_ptr(), n, v, size, flags)
                };
                let native = (native < 0).then(|| {
                    Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
                });
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, setxattr_call(nr, n, v, size, flags));
                take_reports();
                if has {
                    assert_eq!(errno(&r), native, "{nr:?} {what}: the Tool against native");
                    assert!(
                        native.is_some(),
                        "{nr:?} {what}: a dead base never succeeds"
                    );
                } else {
                    assert_eq!(
                        errno(&r),
                        Some(Errno::EACCES),
                        "{nr:?} {what}: no setxattrat"
                    );
                }
            }
        }
    });
}

/// S.4: a T1 success is refused (probe_unsupported) and nothing is closed:
/// the number names whatever the guest already holds there. The sentinel is
/// a live descriptor of an owned scratch file; the result seam makes T1
/// return its number, for openat (an fd-returning call) and for mkdirat. It
/// still names the same file (dev+ino) afterwards, and no close is
/// injected.
#[test]
fn probe_success_keeps_guest_fd() {
    let _lane = serial();
    take_reports();
    fn identity(fd: i32) -> Option<(u64, u64)> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    }
    in_dead_cwd(0o700, |root| {
        // The sentinel: an owned scratch file's descriptor, live before
        // anything runs (a missing one fails the fixture, never passes).
        let file = root.join("sentinel");
        std::fs::write(&file, b"s").unwrap();
        let cfile = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        let fd = unsafe { libc::open(cfile.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd > 2, "fixture: the sentinel opens on a fresh number");
        let before = identity(fd).expect("fixture: the sentinel is live");
        let open_x = Syscall::from_raw(
            Sysno::openat,
            SyscallArgs::new(libc::AT_FDCWD as isize as usize, c"x".as_ptr() as usize, libc::O_RDONLY as usize, 0, 0, 0),
        );
        // The result seam makes T1 return the sentinel's number: the
        // fd-returning open, and mkdirat.
        for (what, call) in [("openat", open_x), ("mkdirat", mkdirat_call(c"x"))] {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([Answer::Return(Ok(fd as i64))]);
            let r = dispatch(&tool, &mut g, call);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{what}");
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{what}");
            assert_eq!(g.injected().len(), 1, "{what}: only the probe, no close");
            assert_eq!(identity(fd), Some(before), "{what}: the sentinel still names its file");
        }
        close(fd);
        std::fs::remove_file(&file).unwrap();
    });
}

/// B3 (P3-a): EINTR and every ERESTART* code from a probe are outside every
/// expected set: one injection, one probe_unsupported line, no retry.
#[test]
fn probe_eintr_not_retried() {
    let _lane = serial();
    take_reports();
    // ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK
    // (include/linux/errno.h).
    let codes = [Errno::EINTR, Errno::new(512), Errno::new(513), Errno::new(514), Errno::new(516)];
    in_dead_cwd(0o700, |root| {
        for code in codes {
            for t1 in [true, false] {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.expect([err(code)]);
                let fd = unix_socket(libc::SOCK_STREAM);
                let (addr, len) = unix_addr(b"x");
                let call = if t1 { mkdirat_call(c"x") } else { socket_call(Sysno::connect, fd, &addr, len) };
                let r = dispatch(&tool, &mut g, call);
                close(fd);
                assert_eq!(errno(&r), Some(Errno::EACCES), "{code:?} t1={t1}");
                assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{code:?} t1={t1}");
                assert_eq!(g.injected().len(), 1, "{code:?} t1={t1}: never a second injection");
            }
        }
    });
}

/// C2.3: on ptrace the dispatch setter and the filter install are forwarded
/// as the exact pending call: the only injection is the guest's own call
/// with its own arguments, and nothing is injected before it.
#[test]
fn sud_and_install_forward_in_place() {
    let _lane = serial();
    take_reports();
    let root = unit_dir();
    for call in [prctl_call(59, 1, 0x1000, 0x20, 0x3000), prctl_call(59, 0, 0, 0, 0), install_call()] {
        let tool = RootfsTool::default();
        let mut g = RecordingGuest::new(ptrace_cfg(&root));
        g.expect([ok0()]);
        let (nr, _) = call.into_parts();
        assert_eq!(dispatch(&tool, &mut g, call).ok(), Some(0), "{nr:?}");
        assert!(
            matches!(g.events().as_slice(), [Event::Inject(n, a)] if *n == nr && *a == raw_args(call)),
            "{nr:?}: {:?}",
            g.events()
        );
    }
    assert!(take_reports().is_empty());
    std::fs::remove_dir(&root).unwrap();
}

/// R1 (C5b.2, C5c a) through the handler: on an in-guest backend each
/// non-OFF mode, and the low-32 option match, gives EOPNOTSUPP, exactly one
/// dispatch line and no injection; the tracked mode is left as it was.
#[test]
fn sud_setter_refusal() {
    let _lane = serial();
    take_guest_bits();
    let root = unit_dir();
    let cases = [(59, 1), (59, 2), (59, 3), (59, 0x1_0000_0000), (59, u64::MAX), (0x1_0000_003b, 1)];
    for (option, mode) in cases {
        for was_on in [false, true] {
            let tool = RootfsTool::default();
            let mut g = RecordingGuest::new(inguest_cfg(&root));
            g.thread_state.sud_on = was_on;
            let r = dispatch(&tool, &mut g, prctl_call(option, mode, 0, 0, 0));
            assert_eq!(errno(&r), Some(Errno::EOPNOTSUPP), "{option:#x} {mode:#x}");
            assert_eq!(take_guest_bits(), dispatch_bit(), "{option:#x} {mode:#x}: one dispatch line");
            assert!(g.injected().is_empty(), "{option:#x} {mode:#x}");
            assert_eq!(g.thread_state.sud_on, was_on, "{option:#x} {mode:#x}");
        }
    }
    std::fs::remove_dir(&root).unwrap();
}

/// R1: a refused setter leaves no event at all: no injection, no forward,
/// no RPC.
#[test]
fn sud_setter_refusal_injects_nothing() {
    let _lane = serial();
    take_guest_bits();
    let root = unit_dir();
    let tool = RootfsTool::default();
    let mut g = RecordingGuest::new(inguest_cfg(&root));
    // One answer queued: it must be left unused.
    g.expect([ok0()]);
    let r = dispatch(&tool, &mut g, prctl_call(59, 1, 0x1000, 0x20, 0x3000));
    assert_eq!(errno(&r), Some(Errno::EOPNOTSUPP));
    assert!(g.events().is_empty(), "{:?}", g.events());
    assert_eq!(g.unused(), 1, "the queued answer was not taken");
    take_guest_bits();
    std::fs::remove_dir(&root).unwrap();
}

/// R1 keeps OFF: (59, 0, 0, 0, 0) is forwarded unchanged and tracked OFF on
/// 0; (59, 0, 1, 0, 0) is forwarded, the kernel's EINVAL is passed through
/// and the tracked mode is unchanged.
#[test]
fn sud_off_forwarded() {
    let _lane = serial();
    take_guest_bits();
    let root = unit_dir();
    let tool = RootfsTool::default();
    let mut g = RecordingGuest::new(inguest_cfg(&root));
    g.thread_state.sud_on = true;
    g.expect([ok0()]);
    let off = prctl_call(59, 0, 0, 0, 0);
    assert_eq!(dispatch(&tool, &mut g, off).ok(), Some(0));
    assert!(!g.thread_state.sud_on, "tracked OFF");
    // OFF with a non-zero offset: the kernel answers EINVAL without
    // changing anything (kernel/entry/syscall_user_dispatch.c).
    g.thread_state.sud_on = true;
    g.expect([Answer::Native]);
    let bad = prctl_call(59, 0, 1, 0, 0);
    assert_eq!(errno(&dispatch(&tool, &mut g, bad)), Some(Errno::EINVAL));
    assert!(g.thread_state.sud_on, "unchanged on EINVAL");
    assert_eq!(g.injected(), vec![(Sysno::prctl, raw_args(off)), (Sysno::prctl, raw_args(bad))]);
    assert_eq!(take_guest_bits(), 0, "no dispatch line");
    std::fs::remove_dir(&root).unwrap();
}

/// C5c a: OFF with a non-zero offset, length or selector is still forwarded;
/// the kernel answers EINVAL and the tracked mode is unchanged, ON or OFF.
#[test]
fn sud_off_bad_args_forwarded() {
    let _lane = serial();
    take_guest_bits();
    let root = unit_dir();
    let selector = 0u8;
    let selector = &selector as *const u8 as u64;
    for (offset, len, sel) in [(0x1000, 0, 0), (0, 0x20, 0), (0, 0, selector)] {
        for was_on in [false, true] {
            let tool = RootfsTool::default();
            let mut g = RecordingGuest::new(inguest_cfg(&root));
            g.thread_state.sud_on = was_on;
            g.expect([Answer::Native]);
            let call = prctl_call(59, 0, offset, len, sel);
            let r = dispatch(&tool, &mut g, call);
            assert_eq!(errno(&r), Some(Errno::EINVAL), "{offset:#x} {len:#x} {sel:#x}");
            assert_eq!(g.injected(), vec![(Sysno::prctl, raw_args(call))]);
            assert_eq!(g.thread_state.sud_on, was_on, "{offset:#x} {len:#x} {sel:#x}");
        }
    }
    assert_eq!(take_guest_bits(), 0);
    std::fs::remove_dir(&root).unwrap();
}

/// R3.1: in-guest the record's kernel_id is never collected (no guest
/// syscall for metadata): after an install the record holds none, and the
/// only events are the attempt note and the install itself. Control: on
/// ptrace the tracer collects it with its own descriptors (some value, 0
/// when the kernel has no pidfs), still with no injection for it.
#[test]
fn in_guest_record_collects_no_kernel_id() {
    let _lane = serial();
    take_reports();
    let root = unit_dir();
    let pid = std::process::id() as i32;
    let tool = RootfsTool::default();
    let mut g = RecordingGuest::new(inguest_cfg(&root));
    g.expect([err(Errno::EINVAL)]);
    let _ = dispatch(&tool, &mut g, install_call());
    assert_eq!(tool.state.lock().unwrap().admission(pid).kernel_id, None);
    {
        // The failed install's negative result passes through: no flag,
        // nothing pending, probes admitted again.
        let mut st = tool.state.lock().unwrap();
        let a = st.admission(pid);
        assert!(!a.guest_filter && a.install_pending == 0 && !a.closed(), "{a:?}");
    }
    assert!(
        matches!(g.events().as_slice(), [Event::Rpc(_), Event::Inject(Sysno::seccomp, _)]),
        "{:?}",
        g.events()
    );
    let tool = RootfsTool::default();
    let mut g = RecordingGuest::new(ptrace_cfg(&root));
    g.expect([err(Errno::EINVAL)]);
    let _ = dispatch(&tool, &mut g, install_call());
    assert!(tool.state.lock().unwrap().admission(pid).kernel_id.is_some());
    assert_eq!(g.injected().len(), 1);
    std::fs::remove_dir(&root).unwrap();
}

/// B2: in-guest, the install-attempt note is SENT (an RPC) before the
/// install is injected, so a filter that kills the process cannot lose it:
/// the events are `[rpc(note), inject(install)]`.
#[test]
fn install_note_sent_before_injection() {
    let _lane = serial();
    take_reports();
    let root = unit_dir();
    for call in [install_call(), prctl_call(libc::PR_SET_SECCOMP as u64, 2, 0x1000, 0, 0)] {
        let tool = RootfsTool::default();
        let mut g = RecordingGuest::new(inguest_cfg(&root));
        g.expect([ok0()]);
        let (nr, _) = call.into_parts();
        assert_eq!(dispatch(&tool, &mut g, call).ok(), Some(0), "{nr:?}");
        let events = g.events();
        let note = [Refusal::Note(super::Note::FilterInstallAttempted)];
        assert!(
            matches!(events.as_slice(), [Event::Rpc(Refused(sent)), Event::Inject(n, a)]
                if sent.as_slice() == note && *n == nr && *a == raw_args(call)),
            "{nr:?}: {events:?}"
        );
    }
    assert!(take_reports().is_empty());
    std::fs::remove_dir(&root).unwrap();
}

/// B2's ptrace twin, behavioural through this thread's side-log sink plus
/// a source-order witness. The sink (`refusal_log::SINK`, test builds only)
/// stands in for the side log, a process-wide OnceLock a unit cannot open
/// without moving every other unit's refusals into it: with it open, the
/// note is in the log when the install's one injection runs. The witness:
/// in seccomp_install the note is written before that injection, and
/// note_now's ptrace branch writes the line at once, with no queue.
#[test]
fn install_note_written_before_injection_on_ptrace() {
    let source = include_str!("rootfs_tool.rs");
    let start = source.find("    async fn seccomp_install<").expect("seccomp_install");
    let body = &source[start..];
    let body = &body[..body[1..].find("\n    async fn ").expect("next fn") + 1];
    let note = body.find("note_now(guest, Note::FilterInstallAttempted).await").expect("the note");
    let inject = body.find("guest.inject(syscall).await").expect("the injection");
    assert!(note < inject, "the note comes first");
    assert_eq!(body.matches("guest.inject(").count(), 1, "one injection");
    let start = source.find("async fn note_now<").expect("note_now");
    let note_now = &source[start..start + source[start..].find("\n}\n").expect("end")];
    let write = note_now.find("crate::refusal_log::write_line(").expect("the direct write");
    let open = note_now.find("if crate::refusal_log::is_open() {").expect("the ptrace branch");
    assert!(open < write && !note_now[..write].contains(".await"), "written at once");
    // Behavioural: with this thread's side-log sink open, as the ptrace
    // launcher's log is, the note is in the log when the install's
    // injection runs.
    let _lane = serial();
    take_reports();
    let note = Refusal::Note(super::Note::FilterInstallAttempted).line();
    let root = unit_dir();
    let tool = RootfsTool::default();
    let mut g = RecordingGuest::new(ptrace_cfg(&root));
    crate::refusal_log::SINK.with(|s| *s.borrow_mut() = Some(Vec::new()));
    let at_injection = Arc::new(Mutex::new(None));
    {
        let (at_injection, note) = (at_injection.clone(), note.clone());
        g.expect([Answer::Call(Box::new(move || {
            let lines = crate::refusal_log::SINK.with(|s| s.borrow().clone()).unwrap_or_default();
            *at_injection.lock().unwrap() = Some(lines.iter().filter(|l| **l == note).count());
            Ok(0)
        }))]);
    }
    assert_eq!(dispatch(&tool, &mut g, install_call()).ok(), Some(0));
    let lines = crate::refusal_log::SINK.with(|s| s.borrow_mut().take()).unwrap();
    assert_eq!(*at_injection.lock().unwrap(), Some(1), "the note was written before the injection");
    assert_eq!(lines.iter().filter(|l| **l == note).count(), 1, "one note: {lines:?}");
    assert!(g.events().iter().all(|e| !matches!(e, Event::Rpc(_))), "no RPC on ptrace");
    std::fs::remove_dir(&root).unwrap();
}

/// C4 config-read seams (SEAM EVIDENCE: this host cannot produce them). On
/// ptrace, EIO, EINVAL and ENOSYS from the dispatch-config read fall back to
/// prctl tracking (sud_fallback counts): tracking ON refuses the probe with
/// nothing injected, tracking OFF lets it answer natively. Their one
/// fallback line names the errno.
#[test]
fn sud_config_eio_falls_back() {
    let _lane = serial();
    take_reports();
    assert_eq!(super::dispatch_fallback_line(libc::EIO), "literoot: sud config read unavailable errno=EIO");
    assert_eq!(super::dispatch_fallback_line(libc::EINVAL), "literoot: sud config read unavailable errno=EINVAL");
    assert_eq!(super::dispatch_fallback_line(libc::ENOSYS), "literoot: sud config read unavailable errno=ENOSYS");
    in_dead_cwd(0o700, |root| {
        for e in [libc::EIO, libc::EINVAL, libc::ENOSYS] {
            for tracked in [true, false] {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(root));
                g.thread_state.sud_on = tracked;
                set_dispatch_read(Some(Err(e)));
                if !tracked {
                    g.expect([Answer::Native, Answer::Native]);
                }
                let fd = unix_socket(libc::SOCK_STREAM);
                let (addr, len) = unix_addr(b"x");
                let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
                close(fd);
                let st = tool.state.lock().unwrap();
                let counts = (st.admission.probes, st.admission.sud_refused, st.admission.sud_fallback);
                if tracked {
                    assert_eq!(errno(&r), Some(Errno::EACCES), "{e} ON");
                    assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{e} ON");
                    assert!(g.injected().is_empty(), "{e} ON: no probe");
                    assert_eq!(counts, (1, 1, 1), "{e} ON");
                } else {
                    assert_eq!(errno(&r), Some(Errno::ENOENT), "{e} OFF");
                    assert_eq!(take_reports(), vec![DEAD_BASE_NAME], "{e} OFF");
                    assert_eq!(counts, (1, 0, 1), "{e} OFF");
                }
            }
        }
        // The written line, through this thread's side-log sink: the first
        // fallback of the run writes it with the errno the read gave, before
        // that probe's refusal; a later fallback (another errno) writes
        // nothing more.
        super::DISPATCH_FALLBACK_NOTED.store(false, Ordering::SeqCst);
        crate::refusal_log::SINK.with(|s| *s.borrow_mut() = Some(Vec::new()));
        for e in [libc::EIO, libc::EINVAL] {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.thread_state.sud_on = true;
            set_dispatch_read(Some(Err(e)));
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
            close(fd);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{e}");
        }
        let lines = crate::refusal_log::SINK.with(|s| s.borrow_mut().take()).unwrap();
        let refusal = PROBE_UNSUPPORTED.line();
        assert_eq!(
            lines,
            [
                "literoot: sud config read unavailable errno=EIO".to_owned(),
                refusal.clone(),
                refusal,
            ],
            "once per run, with the read's errno"
        );
    });
}

/// C4: any other error from the config read (here ESRCH) fails closed for
/// that probe: probe_unsupported, nothing injected, and no fallback. And a
/// config read that succeeds wins over tracking: config ON with tracking
/// OFF refuses.
#[test]
fn sud_config_esrch_refuses() {
    let _lane = serial();
    take_reports();
    in_dead_cwd(0o700, |root| {
        for read in [Err(libc::ESRCH), Ok(true)] {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            set_dispatch_read(Some(read));
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
            close(fd);
            assert_eq!(errno(&r), Some(Errno::EACCES), "{read:?}");
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{read:?}");
            assert!(g.injected().is_empty(), "{read:?}");
            let st = tool.state.lock().unwrap();
            assert_eq!((st.admission.sud_refused, st.admission.sud_fallback), (1, 0), "{read:?}");
        }
    });
}

/// Batch C units that use this harness.
mod c_units {
    use super::*;

    /// This test process's own `Seccomp_filters` count.
    fn own_filter_count() -> u32 {
        let text = std::fs::read_to_string("/proc/self/status").unwrap();
        crate::dead_base::status_field(text.as_bytes(), b"Seccomp_filters").unwrap() as u32
    }

    /// C4.4, LD_PRELOAD route (trap, liteinst): the baseline is the count
    /// right after arming, so the first-callback check of a new image with
    /// no later install matches, and the first probe is admitted (its
    /// count read matches too). A Reverie install after the baseline read
    /// (count = baseline + 1) would latch the record at the first callback
    /// and refuse every probe, by name and counted, never silently.
    #[test]
    fn count_after_arming_is_baseline() {
        let _lane = serial();
        take_reports();
        let own = own_filter_count();
        in_dead_cwd(0o700, |root| {
            super::super::set_filter_baseline(own);
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(inguest_cfg(root));
            g.native_rest = true;
            run(tool.first_callback_check(&mut g));
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
            close(fd);
            assert_eq!(errno(&r), Some(Errno::ENOENT));
            assert_eq!(take_reports(), vec![DEAD_BASE_NAME]);
            {
                let st = tool.state.lock().unwrap();
                assert!(!st.admission.filter_latched && !st.admission.guest_filter);
                assert_eq!(st.admission.unseen_best_effort, 0);
            }
            assert!(g.injected().iter().any(|(nr, _)| *nr == Sysno::connect), "the probe ran");
            // An install after the baseline: the count reads baseline + 1.
            let mut scratch = Scratch::new();
            let status = scratch.addr() + super::super::SCRATCH_STATUS;
            let tool = tool_with(&mut scratch);
            let mut g = RecordingGuest::new(inguest_cfg(root));
            let text = format!("Name:\tx\nSeccomp_filters:\t{}\n", own + 1).into_bytes();
            g.expect([
                Answer::Return(Ok(900)),
                Answer::Call(Box::new(move || {
                    // SAFETY: `status` is inside this unit's live scratch buffer.
                    unsafe { std::ptr::copy_nonoverlapping(text.as_ptr(), status as *mut u8, text.len()) };
                    Ok(text.len() as i64)
                })),
                ok0(),
                ok0(),
            ]);
            run(tool.first_callback_check(&mut g));
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut g, socket_call(Sysno::connect, fd, &addr, len));
            close(fd);
            super::super::set_filter_baseline(u32::MAX);
            assert_eq!(errno(&r), Some(Errno::EACCES));
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED]);
            let st = tool.state.lock().unwrap();
            assert!(st.admission.filter_latched && st.admission.guest_filter);
            assert_eq!(st.admission.unseen_best_effort, 1);
            assert_eq!(g.injected().len(), 4, "only the status read: no probe");
        });
    }
}

/// S.3 on an in-guest configuration: the in-guest admission adds
/// the filter-count read between admission and the probe.
mod inguest_admission_units {
    use super::*;

    /// #43 in-guest: B's install arrives while A's admitted probe is in its
    /// status read (the first injection after admission). B is refused at
    /// once with `in_flight=1` and injects nothing; A's read, probe and
    /// search check then run (natively) and A completes.
    #[test]
    fn install_refused_during_inguest_status_read() {
        let _lane = serial();
        take_reports();
        let text = std::fs::read_to_string("/proc/self/status").unwrap();
        let own = crate::dead_base::status_field(text.as_bytes(), b"Seccomp_filters").unwrap() as u32;
        in_dead_cwd(0o700, |root| {
            super::super::set_filter_baseline(own);
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let mut a = RecordingGuest::new(inguest_cfg(root));
            a.native_rest = true;
            let tid = unsafe { libc::gettid() };
            let b_result = Arc::new(Mutex::new(None));
            let held = {
                let (tool, root, b_result) = (tool.clone(), root.to_path_buf(), b_result.clone());
                Answer::Call(Box::new(move || {
                    let mut b = RecordingGuest::new(inguest_cfg(&root)).with_ids(None, Some(tid + 1));
                    let r = dispatch(&tool, &mut b, install_call());
                    *b_result.lock().unwrap() = Some((errno(&r), take_reports(), b.injected().len()));
                    // A's status open, run here.
                    let fd = unsafe { libc::open(c"/proc/self/status".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                    if fd < 0 { Err(Errno::EIO) } else { Ok(fd as i64) }
                }))
            };
            a.expect([held]);
            let fd = unix_socket(libc::SOCK_STREAM);
            let (addr, len) = unix_addr(b"x");
            let r = dispatch(&tool, &mut a, socket_call(Sysno::connect, fd, &addr, len));
            close(fd);
            super::super::set_filter_baseline(u32::MAX);
            assert_eq!(
                b_result.lock().unwrap().take(),
                Some((Some(Errno::EOPNOTSUPP), vec![Refusal::InstallRefused { in_flight: 1 }], 0)),
                "B refused during A's status read"
            );
            assert_eq!(errno(&r), Some(Errno::ENOENT), "A completes");
            assert_eq!(take_reports(), vec![DEAD_BASE_NAME]);
            assert!(a.injected().iter().any(|(nr, _)| *nr == Sysno::connect), "A's probe ran");
            let st = tool.state.lock().unwrap();
            assert_eq!((st.admission.installs, st.admission.installs_refused), (1, 1));
            assert!(!st.admission.guest_filter && st.admission.probes_in_flight() == 0);
        });
    }
}

/// C4 (#76): the tracked dispatch mode's lifecycle.
mod sud_tracking_units {
    use super::*;

    /// A new thread starts OFF whatever its parent's mode; exec resets it
    /// (a source witness: post-exec runs only at a real exec stop); a
    /// forwarded prctl whose handler is cancelled in the injection is ON; a
    /// failed one leaves the mode; INCLUSIVE_ON (2) succeeding is ON, like
    /// EXCLUSIVE_ON (1).
    #[test]
    fn tracked_dispatch_lifecycle() {
        use reverie::Tool as _;
        let _lane = serial();
        take_guest_bits();
        let root = unit_dir();
        let tool = RootfsTool::default();
        // New thread: OFF, from an ON parent.
        let parent = RootfsThreadState { sud_on: true, ..RootfsThreadState::default() };
        let child = tool.init_thread_state(reverie::Tid::from_raw(2), Some((reverie::Tid::from_raw(1), &parent)));
        assert!(!child.sud_on, "a new thread starts OFF");
        // Exec: the post-exec handler resets it.
        let source = include_str!("rootfs_tool.rs");
        let at = source.find("async fn handle_post_exec<").expect("post-exec");
        let body = &source[at..at + source[at..].find("\n    }\n").expect("its end")];
        assert!(body.contains("guest.thread_state_mut().sud_on = false;"), "exec resets the mode");
        // Cancelled in the injection: ON, whatever the mode asked for.
        let mut g = RecordingGuest::new(inguest_cfg(&root));
        g.expect([Answer::Pend]);
        let off = prctl_call(59, 0, 0, 0, 0);
        assert!(poll_once(tool.handle_syscall_event(&mut g, off)).is_none(), "pending in the injection");
        assert!(g.thread_state.sud_on, "a cancelled prctl is ON");
        // Failed: the mode stands (ON here, then OFF).
        g.expect([err(Errno::EINVAL)]);
        assert_eq!(errno(&dispatch(&tool, &mut g, off)), Some(Errno::EINVAL));
        assert!(g.thread_state.sud_on, "a failed prctl leaves ON");
        g.thread_state.sud_on = false;
        g.expect([err(Errno::EINVAL)]);
        assert_eq!(errno(&dispatch(&tool, &mut g, off)), Some(Errno::EINVAL));
        assert!(!g.thread_state.sud_on, "a failed prctl leaves OFF");
        // INCLUSIVE_ON and EXCLUSIVE_ON succeeding (ptrace config, where the
        // setter is forwarded): ON.
        for mode in [2, 1] {
            let mut g = RecordingGuest::new(ptrace_cfg(&root));
            g.expect([ok0()]);
            let on = prctl_call(59, mode, 0, 0, 0);
            assert_eq!(dispatch(&tool, &mut g, on).ok(), Some(0), "mode {mode}");
            assert!(g.thread_state.sud_on, "mode {mode} is ON");
        }
        assert_eq!(take_guest_bits(), 0, "no dispatch line");
        std::fs::remove_dir(&root).unwrap();
    }
}

/// #35 (P2-C1): with the gate closed (trigger 3, an install pending;
/// trigger 6, dispatch ON), a call whose base has no guest name goes to its
/// arm, which answers as without fix 4: the kernel's EBADF for a closed
/// dirfd, its ENOTDIR for a pipe, a translation for a live directory. Only
/// a dead-base name is refused, and only it is counted.
mod gate_order_units {
    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Trigger {
        InstallPending,
        DispatchOn,
    }

    fn openat_at(dirfd: i32, name: &std::ffi::CStr) -> Syscall {
        Syscall::from_raw(
            Sysno::openat,
            SyscallArgs::new(dirfd as isize as usize, name.as_ptr() as usize, libc::O_RDONLY as usize, 0, 0, 0),
        )
    }

    /// (probes, refused, sud_refused) of this process's record.
    fn counts(tool: &RootfsTool) -> (u64, u64, u64) {
        let mut st = tool.state.lock().unwrap();
        let a = st.admission(std::process::id() as i32);
        (a.probes, a.refused, a.sud_refused)
    }

    fn closed_gate_keeps_the_arms_answers(trigger: Trigger) {
        let _lane = serial();
        take_reports();
        in_dead_cwd(0o700, |root| {
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            let pid = std::process::id() as i32;
            let ticket = match trigger {
                Trigger::InstallPending => Some(tool.state.lock().unwrap().admission(pid).begin_install().unwrap()),
                Trigger::DispatchOn => {
                    set_dispatch_read(Some(Ok(true)));
                    None
                }
            };
            let what = format!("{trigger:?}");
            // A closed dirfd: the kernel's EBADF, run natively.
            let closed = unix_socket(libc::SOCK_STREAM);
            close(closed);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([Answer::Native]);
            let r = dispatch(&tool, &mut g, openat_at(closed, c"x"));
            assert_eq!(errno(&r), Some(Errno::EBADF), "{what}: closed dirfd");
            assert_eq!(g.injected().len(), 1, "{what}: the call itself");
            assert_eq!(g.injected()[0].1[0] as i32, closed, "{what}: unchanged");
            // A pipe: the kernel's ENOTDIR, run natively.
            let mut ends = [0i32; 2];
            assert_eq!(unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([Answer::Native]);
            let r = dispatch(&tool, &mut g, openat_at(ends[0], c"x"));
            close(ends[0]);
            close(ends[1]);
            assert_eq!(errno(&r), Some(Errno::ENOTDIR), "{what}: pipe");
            assert_eq!(g.injected().len(), 1, "{what}: the call itself");
            // A live directory the Tool never opened: its translation.
            let live = unsafe {
                libc::open(
                    std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).unwrap().as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            assert!(live >= 0, "{what}: open the root");
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            g.expect([err(Errno::ENOENT)]);
            let r = dispatch(&tool, &mut g, openat_at(live, c"y"));
            close(live);
            assert_eq!(errno(&r), Some(Errno::ENOENT), "{what}: live dirfd");
            let host = format!("{}/y\0", root.display());
            assert_eq!(g.injected().len(), 1, "{what}: the translated open");
            assert_eq!(scratch.at(0, host.len()), host.as_bytes(), "{what}: staged host path");
            assert!(take_reports().is_empty(), "{what}: no refusal");
            assert_eq!(counts(&tool), (0, 0, 0), "{what}: none of these reached the gate's count");
            // A dead-base name: refused by name, counted once.
            let mut g = RecordingGuest::new(ptrace_cfg(root));
            let r = dispatch(&tool, &mut g, mkdirat_call(c"x"));
            assert_eq!(errno(&r), Some(Errno::EACCES), "{what}: dead name");
            assert_eq!(take_reports(), vec![PROBE_UNSUPPORTED], "{what}");
            assert!(g.injected().is_empty(), "{what}: nothing injected");
            let want = match trigger {
                Trigger::InstallPending => (1, 1, 0),
                Trigger::DispatchOn => (1, 0, 1),
            };
            assert_eq!(counts(&tool), want, "{what}: (probes, refused, sud_refused)");
            if let Some(ticket) = ticket {
                tool.state.lock().unwrap().admission(pid).abandon_install(ticket);
            }
        });
    }

    #[test]
    fn closed_gate_keeps_the_arms_answers_install_pending() {
        closed_gate_keeps_the_arms_answers(Trigger::InstallPending);
    }

    #[test]
    fn closed_gate_keeps_the_arms_answers_dispatch_on() {
        closed_gate_keeps_the_arms_answers(Trigger::DispatchOn);
    }
}

/// A1 units: a process the guest does not own answers from its
/// shared-record row (the row seam stands in for the store): readlink and
/// open of its exe, and an open of its cmdline. Pid 1 is never this test
/// process's, so it is never owned here.
mod a1_units {
    use super::*;

    /// The row seam for one unit, cleared on drop.
    pub(super) struct Rows;

    impl Rows {
        pub(super) fn set(rows: Vec<crate::shared_record::ProcessRecord>) -> Self {
            super::super::SHARED_ROW_SEAM.with(|s| *s.borrow_mut() = Some(rows));
            Rows
        }
    }

    impl Drop for Rows {
        fn drop(&mut self) {
            super::super::SHARED_ROW_SEAM.with(|s| *s.borrow_mut() = None);
            super::super::SHARED_ROW_SEAM_LOOKUPS.with(|n| n.set(None));
        }
    }

    /// The line of a cmdline literoot would answer but cannot: the kernel's
    /// own file answered (not a refusal; `answered path`).
    pub(super) const FALLBACK: Refusal = Refusal::Path(PathRefusal::SyntheticFileUnavailable);

    pub(super) fn row(pid: i32, exe: &[u8], argv: &[&[u8]]) -> crate::shared_record::ProcessRecord {
        crate::shared_record::ProcessRecord {
            id: crate::shared_record::ProcessId::new(pid, 1).unwrap(),
            exe_guest: exe.to_vec(),
            argv: argv.iter().map(|a| a.to_vec()).collect(),
        }
    }

    /// A Tool and an in-guest guest on the host root, so /proc is the
    /// host's procfs.
    pub(super) fn on_host_root(scratch: &mut Scratch) -> (Arc<RootfsTool>, RecordingGuest) {
        on_host_root_with(scratch, &[])
    }

    /// As [`on_host_root`], with the caller's initial argv.
    pub(super) fn on_host_root_with(scratch: &mut Scratch, initial_argv: &[&str]) -> (Arc<RootfsTool>, RecordingGuest) {
        let tool = tool_with(scratch);
        tool.state.lock().unwrap().cwd = PathBuf::from("/");
        let cfg = LiterootConfig {
            initial_argv: initial_argv.iter().map(|a| a.to_string()).collect(),
            ..inguest_cfg(Path::new("/"))
        };
        (tool, RecordingGuest::new(cfg))
    }

    pub(super) fn readlinkat_call(path: &std::ffi::CStr, buf: &mut [u8]) -> Syscall {
        Syscall::from_raw(
            Sysno::readlinkat,
            SyscallArgs::new(
                libc::AT_FDCWD as isize as usize,
                path.as_ptr() as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                0,
                0,
            ),
        )
    }

    /// As [`on_host_root_with`] on the ptrace configuration, where the
    /// probe gate reads the dispatch mode through the dispatch-read seam
    /// (set OFF here; the caller's guard resets it).
    pub(super) fn on_host_root_ptrace(scratch: &mut Scratch, initial_argv: &[&str]) -> (Arc<RootfsTool>, RecordingGuest) {
        let tool = tool_with(scratch);
        tool.state.lock().unwrap().cwd = PathBuf::from("/");
        let cfg = LiterootConfig {
            initial_argv: initial_argv.iter().map(|a| a.to_string()).collect(),
            ..ptrace_cfg(Path::new("/"))
        };
        set_dispatch_read(Some(Ok(false)));
        (tool, RecordingGuest::new(cfg))
    }

    /// As [`on_host_root_ptrace`] on an in-guest configuration, retargeted
    /// from it: the admission's
    /// status read runs natively outside the script ([`Event::Status`]),
    /// against this process's own filter count as the image baseline. The
    /// caller holds a [`Baseline`] guard.
    pub(super) fn on_host_root_inguest(scratch: &mut Scratch, initial_argv: &[&str]) -> (Arc<RootfsTool>, RecordingGuest) {
        let (tool, mut g) = on_host_root_with(scratch, initial_argv);
        set_dispatch_read(Some(Ok(false)));
        g.native_status = true;
        (tool, g)
    }

    /// The filter-count baseline set to this process's own count, reset on
    /// drop.
    pub(super) struct Baseline;

    impl Baseline {
        pub(super) fn own() -> Self {
            let text = std::fs::read_to_string("/proc/self/status").unwrap();
            let own = crate::dead_base::status_field(text.as_bytes(), b"Seccomp_filters").unwrap() as u32;
            super::super::set_filter_baseline(own);
            Baseline
        }
    }

    impl Drop for Baseline {
        fn drop(&mut self) {
            super::super::set_filter_baseline(u32::MAX);
        }
    }

    /// Resets the dispatch-read seam on drop.
    pub(super) struct DispatchOff;

    impl Drop for DispatchOff {
        fn drop(&mut self) {
            set_dispatch_read(None);
        }
    }

    pub(super) fn openat_call(path: &std::ffi::CStr) -> Syscall {
        openat_at(libc::AT_FDCWD, path, libc::O_RDONLY)
    }

    /// openat(`dirfd`, `path`, `flags`).
    pub(super) fn openat_at(dirfd: i32, path: &std::ffi::CStr, flags: i32) -> Syscall {
        Syscall::from_raw(
            Sysno::openat,
            SyscallArgs::new(dirfd as isize as usize, path.as_ptr() as usize, flags as usize, 0, 0, 0),
        )
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn open_call(path: &std::ffi::CStr) -> Syscall {
        open_with(path, libc::O_RDONLY)
    }

    /// open(`path`, `flags`).
    #[cfg(target_arch = "x86_64")]
    pub(super) fn open_with(path: &std::ffi::CStr, flags: i32) -> Syscall {
        Syscall::from_raw(Sysno::open, SyscallArgs::new(path.as_ptr() as usize, flags as usize, 0, 0, 0, 0))
    }

    /// openat2(AT_FDCWD, `path`, `how`, 24); `how` is {flags, mode, resolve}.
    pub(super) fn openat2_call(path: &std::ffi::CStr, how: &[u64; 3]) -> Syscall {
        openat2_at(libc::AT_FDCWD, path, how)
    }

    /// openat2(`dirfd`, `path`, `how`, 24).
    pub(super) fn openat2_at(dirfd: i32, path: &std::ffi::CStr, how: &[u64; 3]) -> Syscall {
        Syscall::from_raw(
            Sysno::openat2,
            SyscallArgs::new(
                dirfd as isize as usize,
                path.as_ptr() as usize,
                how.as_ptr() as usize,
                std::mem::size_of_val(how),
                0,
                0,
            ),
        )
    }

    /// (dev, ino) of descriptor `fd`.
    pub(super) fn dev_ino(fd: i32) -> (u64, u64) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0, "fstat");
        (st.st_dev as u64, st.st_ino as u64)
    }

    /// A native open of host `path` in this thread: the file it names, or
    /// its errno.
    pub(super) fn native(path: &str) -> Result<(u64, u64), Errno> {
        let c = std::ffi::CString::new(path).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        let id = dev_ino(fd);
        close(fd);
        Ok(id)
    }

    /// A handler's open answer as the file it names, or its errno; the
    /// descriptor is closed.
    pub(super) fn opened(label: &str, r: &Result<i64, Error>) -> Result<(u64, u64), Errno> {
        match r {
            Ok(fd) => {
                let id = dev_ino(*fd as i32);
                close(*fd as i32);
                Ok(id)
            }
            Err(_) => Err(errno(r).unwrap_or_else(|| panic!("{label}: not an errno"))),
        }
    }

    /// A native readlink of host `path`: its bytes, or its errno.
    pub(super) fn native_readlink(path: &str) -> Result<Vec<u8>, Errno> {
        use std::os::unix::ffi::OsStrExt as _;
        std::fs::read_link(path)
            .map(|t| t.as_os_str().as_bytes().to_vec())
            .map_err(|e| Errno::new(e.raw_os_error().unwrap_or(0)))
    }

    /// The bytes a handler's readlink answer wrote to `buf`, or its errno.
    pub(super) fn readlinked(r: &Result<i64, Error>, buf: &[u8]) -> Result<Vec<u8>, Errno> {
        match r {
            Ok(n) => Ok(buf[..*n as usize].to_vec()),
            Err(_) => Err(errno(r).expect("an errno")),
        }
    }

    /// The bytes of the synthesized cmdline at `fd`, after checking that the
    /// descriptor is literoot's memfd and reads from offset 0; then closed.
    pub(super) fn read_memfd(label: &str, fd: i32) -> Vec<u8> {
        // This thread's own table (a unit thread may have unshared it).
        let link = std::fs::read_link(format!("/proc/thread-self/fd/{fd}")).unwrap();
        assert!(
            link.to_string_lossy().starts_with("/memfd:literoot-cmdline"),
            "{label}: literoot's memfd, got {link:?}"
        );
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 0, "{label}: at offset 0");
        let mut buf = [0u8; 256];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        close(fd);
        buf[..n.max(0) as usize].to_vec()
    }

    /// A file in a fresh unit directory, standing in for a row's exe; the
    /// caller removes the directory.
    pub(super) fn exe_file() -> (PathBuf, PathBuf) {
        let dir = unit_dir();
        let exe = dir.join("row-exe");
        std::fs::write(&exe, b"x").unwrap();
        (dir, exe)
    }

    /// With a row (a guest child on the in-guest backends): readlink of its
    /// exe answers the row's bytes, truncated as the kernel truncates, and
    /// injects nothing; an open of its exe opens the row's exe; an open of
    /// its cmdline answers the row's argv in a memfd. A readlink of its
    /// cmdline file is the kernel's, and so is its cwd here (reversed as a
    /// guest process's, which on the host root is the same
    /// text; the guest root case is `row_root_cwd_fd_are_the_guests`).
    #[test]
    fn shared_row_answers_exe_and_cmdline() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let (dir, exe) = exe_file();
        let exe_bytes = exe.as_os_str().as_encoded_bytes().to_vec();
        let _rows = Rows::set(vec![row(1, &exe_bytes, &[b"row-a", b"x"])]);
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
        g.native_rest = true;
        let mut buf = [0u8; 256];
        let r = dispatch(&tool, &mut g, readlinkat_call(c"/proc/1/exe", &mut buf));
        assert_eq!(readlinked(&r, &buf), Ok(exe_bytes.clone()), "readlink exe: the row's");
        let mut short = [0u8; 4];
        let r = dispatch(&tool, &mut g, readlinkat_call(c"/proc/1/exe", &mut short));
        assert_eq!(r.ok(), Some(4));
        assert_eq!(&short[..], &exe_bytes[..4]);
        assert!(g.injected().is_empty(), "readlink of the row's exe injects nothing");
        let r = dispatch(&tool, &mut g, openat_call(c"/proc/1/exe"));
        assert_eq!(opened("open exe", &r), native(exe.to_str().unwrap()), "open exe: the row's exe");
        let r = dispatch(&tool, &mut g, openat_call(c"/proc/1/cmdline"));
        let fd = r.expect("open cmdline: a descriptor") as i32;
        let got = read_memfd("open cmdline", fd);
        assert!(got == b"row-a\0x\0", "open cmdline: read {} bytes, expected the row's 8", got.len());
        for path in ["/proc/1/cwd", "/proc/1/cmdline"] {
            let c = std::ffi::CString::new(path).unwrap();
            let mut buf = [0u8; 256];
            let r = dispatch(&tool, &mut g, readlinkat_call(&c, &mut buf));
            assert_eq!(readlinked(&r, &buf), native_readlink(path), "readlink {path}: the kernel's");
        }
        assert!(take_reports().is_empty());
        std::fs::remove_file(&exe).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// A row that vanishes between the entry's selection and the open, or a
    /// row with no argv (or no exe), gets the kernel's own file: never the
    /// bare-pid argv cache, the caller's initial argv, or another exe.
    #[test]
    fn vanished_or_empty_row_gets_the_kernels_file() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        super::super::pid_argv_map().lock().unwrap().insert(1, vec![b"cached".to_vec()]);
        for (what, rows, lookups, path) in [
            ("vanished, cmdline", vec![row(1, b"/row/exe-a1", &[b"row-a"])], Some(1), "/proc/1/cmdline"),
            ("empty argv, cmdline", vec![row(1, b"/row/exe-a1", &[])], None, "/proc/1/cmdline"),
            ("vanished, exe", vec![row(1, b"/row/exe-a1", &[b"row-a"])], Some(1), "/proc/1/exe"),
            ("empty exe, exe", vec![row(1, b"", &[b"row-a"])], None, "/proc/1/exe"),
        ] {
            let _rows = Rows::set(rows);
            // One lookup finds the row (the entry's selection), the next none.
            super::super::SHARED_ROW_SEAM_LOOKUPS.with(|n| n.set(lookups));
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let c = std::ffi::CString::new(path).unwrap();
            let r = dispatch(&tool, &mut g, openat_call(&c));
            assert_eq!(opened(what, &r), native(path), "{what}: the kernel's");
            assert!(take_reports().is_empty(), "{what}");
            assert_eq!(g.injected().len(), 1, "{what}: the translated open only");
        }
        super::super::pid_argv_map().lock().unwrap().remove(&1);
        // A row with no exe: readlink is the kernel's too.
        let _rows = Rows::set(vec![row(1, b"", &[b"row-a"])]);
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
        g.native_rest = true;
        let mut buf = [0u8; 256];
        let r = dispatch(&tool, &mut g, readlinkat_call(c"/proc/1/exe", &mut buf));
        assert_eq!(readlinked(&r, &buf), native_readlink("/proc/1/exe"), "readlink, empty exe");
    }

    /// readlink's bufsiz is the kernel's int (do_readlinkat, fs/stat.c):
    /// only the low 32 bits count, and a value <= 0 is EINVAL. A raw
    /// 0x1_0000_0004 answers 4 bytes; a zero or negative low word is EINVAL
    /// with nothing written.
    #[test]
    fn shared_row_readlink_bufsiz_is_an_int() {
        let _lane = serial();
        take_reports();
        let _rows = Rows::set(vec![row(1, b"/row/exe-a1", &[])]);
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root(&mut scratch);
        let call = |buf: &mut [u8; 64], raw_len: u64| {
            Syscall::from_raw(
                Sysno::readlinkat,
                SyscallArgs::new(
                    libc::AT_FDCWD as isize as usize,
                    c"/proc/1/exe".as_ptr() as usize,
                    buf.as_mut_ptr() as usize,
                    raw_len as usize,
                    0,
                    0,
                ),
            )
        };
        let mut buf = [0u8; 64];
        let r = dispatch(&tool, &mut g, call(&mut buf, 0x1_0000_0004));
        assert_eq!(r.ok(), Some(4), "the low word, 4");
        assert_eq!(&buf[..5], b"/row\0");
        for raw in [0x1_0000_0000u64, 0x8000_0000, 0xffff_ffff, 0xffff_ffff_ffff_ffff] {
            let mut buf = [0u8; 64];
            let r = dispatch(&tool, &mut g, call(&mut buf, raw));
            assert_eq!(errno(&r), Some(Errno::EINVAL), "{raw:#x}");
            assert_eq!(buf, [0u8; 64], "{raw:#x}: nothing written");
        }
        assert!(take_reports().is_empty());
        assert!(g.injected().is_empty());
    }

    /// P1-A: open(2) and openat2(2) decide by the final entry as openat
    /// does. With a row, the cmdline open answers the row's argv in a memfd
    /// (openat2 only after its argument probe, descriptor -1, which opens
    /// nothing) and an open of the exe opens the row's exe; an open_how the
    /// kernel rejects gets the kernel's EINVAL. Without a row, both are the
    /// kernel's. In-guest only (the ptrace route is
    /// [`super::tracer_route_units`]).
    #[test]
    fn open_and_openat2_route_like_openat() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let (dir, exe) = exe_file();
        let exe_bytes = exe.as_os_str().as_encoded_bytes().to_vec();
        let how = [libc::O_RDONLY as u64, 0, 0];
        type Arm<'a> = (&'a str, Box<dyn Fn(&std::ffi::CStr) -> Syscall + 'a>, bool);
        let arms: Vec<Arm<'_>> =
            vec![("openat2", Box::new(|p: &std::ffi::CStr| openat2_call(p, &how)), true)];
        #[cfg(target_arch = "x86_64")]
        let arms = {
            let mut arms = arms;
            arms.push(("open", Box::new(open_call), false));
            arms
        };
        for (arm, call, argument_probe) in &arms {
            {
                let _rows = Rows::set(vec![row(1, &exe_bytes, &[b"row-a", b"x"])]);
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_inguest(&mut scratch, &["caller-argv"]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call(c"/proc/1/cmdline"));
                let fd = r.ok().unwrap_or_else(|| panic!("{arm}: the open answers a descriptor")) as i32;
                let got = read_memfd(arm, fd);
                assert!(got == b"row-a\0x\0", "{arm}: read {} bytes, expected the row's 8", got.len());
                assert!(take_reports().is_empty(), "{arm}");
                let injected: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
                if *argument_probe {
                    assert_eq!(injected, vec![Sysno::openat2, Sysno::memfd_create], "{arm}: the probe, then the memfd");
                    assert_eq!(g.injected()[0].1[0] as i32, -1, "{arm}: the probe's descriptor");
                } else {
                    assert_eq!(injected, vec![Sysno::memfd_create], "{arm}: the memfd only");
                }
                let r = dispatch(&tool, &mut g, call(c"/proc/1/exe"));
                assert_eq!(opened(arm, &r), native(exe.to_str().unwrap()), "{arm}: the row's exe");
            }
            if *argument_probe {
                let _rows = Rows::set(vec![row(1, &exe_bytes, &[b"row-a", b"x"])]);
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
                g.native_rest = true;
                let bad = [libc::O_RDONLY as u64, 0, 1 << 40];
                let r = dispatch(&tool, &mut g, openat2_call(c"/proc/1/cmdline", &bad));
                assert_eq!(errno(&r), Some(Errno::EINVAL), "{arm}: bad open_how");
                assert!(take_reports().is_empty(), "{arm}: bad open_how");
                let injected = g.injected();
                assert_eq!(injected.len(), 1, "{arm}: the argument probe only");
                assert_eq!((injected[0].0, injected[0].1[0] as i32), (Sysno::openat2, -1), "{arm}");
            }
            for path in ["/proc/1/cmdline", "/proc/1/exe"] {
                let _rows = Rows::set(vec![row(2, b"/row/not-pid-1", &[b"x"])]);
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
                g.native_rest = true;
                let c = std::ffi::CString::new(path).unwrap();
                let r = dispatch(&tool, &mut g, call(&c));
                assert_eq!(opened(arm, &r), native(path), "{arm} {path}, no row: the kernel's");
                assert!(take_reports().is_empty(), "{arm} {path}");
                assert_eq!(g.injected().len(), 1, "{arm} {path}: the translated open only");
            }
        }
        std::fs::remove_file(&exe).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Without a row, another process's exe, cwd and cmdline are the
    /// kernel's, on readlink and open (owner directive 2026-11-14; before
    /// it, refused as proc_link_other_process).
    #[test]
    fn no_shared_row_is_the_kernels() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let _rows = Rows::set(vec![row(2, b"/row/not-pid-1", &[b"x"])]);
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
        g.native_rest = true;
        for path in ["/proc/1/exe", "/proc/1/cwd", "/proc/1/root"] {
            let c = std::ffi::CString::new(path).unwrap();
            let mut buf = [0u8; 256];
            let r = dispatch(&tool, &mut g, readlinkat_call(&c, &mut buf));
            assert_eq!(readlinked(&r, &buf), native_readlink(path), "readlink {path}");
            let r = dispatch(&tool, &mut g, openat_call(&c));
            assert_eq!(opened(path, &r), native(path), "open {path}");
        }
        let r = dispatch(&tool, &mut g, openat_call(c"/proc/1/cmdline"));
        assert_eq!(opened("cmdline", &r), native("/proc/1/cmdline"), "open cmdline");
        assert!(take_reports().is_empty());
    }

    /// (st_mode file type, dev, ino) of descriptor `fd`; O_PATH descriptors
    /// included.
    fn kind_dev_ino(fd: i32) -> (u32, u64, u64) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0, "fstat");
        (st.st_mode & libc::S_IFMT, st.st_dev as u64, st.st_ino as u64)
    }

    /// A call that does not follow opens a row's exe link itself, as the
    /// kernel does, on every open arm:
    /// O_NOFOLLOW is the kernel's ELOOP, and O_PATH|O_NOFOLLOW names the
    /// link (a symlink, the native open's device and inode), whose
    /// empty-name readlink answers as the readlink of its path does. A
    /// follow still opens the row's exe.
    #[test]
    fn row_exe_nofollow_is_the_link() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let (dir, exe) = exe_file();
        let exe_bytes = exe.as_os_str().as_encoded_bytes().to_vec();
        let nofollow = libc::O_RDONLY | libc::O_NOFOLLOW;
        let o_path = libc::O_PATH | libc::O_NOFOLLOW;
        let native_nofollow = {
            let fd = unsafe { libc::open(c"/proc/1/exe".as_ptr(), nofollow | libc::O_CLOEXEC) };
            if fd >= 0 {
                close(fd);
            }
            (fd < 0).then(|| std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        };
        assert_eq!(native_nofollow, Some(libc::ELOOP), "native: O_NOFOLLOW of /proc/1/exe");
        let native_link = {
            let fd = unsafe { libc::open(c"/proc/1/exe".as_ptr(), o_path | libc::O_CLOEXEC) };
            assert!(fd >= 0, "native O_PATH|O_NOFOLLOW of /proc/1/exe");
            let id = kind_dev_ino(fd);
            close(fd);
            id
        };
        assert_eq!(native_link.0, libc::S_IFLNK, "native: the link itself");
        // Each open_how outlives the calls built on it.
        let hows: [[u64; 3]; 3] = [nofollow, o_path, libc::O_RDONLY].map(|f| [f as u64, 0, 0]);
        let how_for = |flags: i32| -> &[u64; 3] { hows.iter().find(|h| h[0] == flags as u64).expect("a staged open_how") };
        type Arm<'a> = (&'a str, Box<dyn Fn(i32) -> Syscall + 'a>);
        let arms: Vec<Arm<'_>> = vec![
            ("openat", Box::new(|flags| openat_at(libc::AT_FDCWD, c"/proc/1/exe", flags))),
            ("openat2", Box::new(move |flags| openat2_call(c"/proc/1/exe", how_for(flags)))),
        ];
        #[cfg(target_arch = "x86_64")]
        let arms = {
            let mut arms = arms;
            arms.push(("open", Box::new(|flags| open_with(c"/proc/1/exe", flags))));
            arms
        };
        for (arm, call) in &arms {
            let _rows = Rows::set(vec![row(1, &exe_bytes, &[b"row-a"])]);
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, call(nofollow));
            assert_eq!(errno(&r), Some(Errno::ELOOP), "{arm} O_NOFOLLOW: the kernel's ELOOP");
            let r = dispatch(&tool, &mut g, call(o_path));
            let fd = r.ok().unwrap_or_else(|| panic!("{arm} O_PATH|O_NOFOLLOW: a descriptor")) as i32;
            assert_eq!(kind_dev_ino(fd), native_link, "{arm} O_PATH|O_NOFOLLOW: the link itself");
            let mut by_fd = [0u8; 256];
            let empty = Syscall::from_raw(
                Sysno::readlinkat,
                SyscallArgs::new(fd as usize, c"".as_ptr() as usize, by_fd.as_mut_ptr() as usize, by_fd.len(), 0, 0),
            );
            let r_fd = dispatch(&tool, &mut g, empty);
            let mut by_path = [0u8; 256];
            let r_path = dispatch(&tool, &mut g, readlinkat_call(c"/proc/1/exe", &mut by_path));
            assert_eq!(
                readlinked(&r_fd, &by_fd),
                readlinked(&r_path, &by_path),
                "{arm}: an empty-name readlink of the link answers as its path's"
            );
            close(fd);
            let r = dispatch(&tool, &mut g, call(libc::O_RDONLY));
            assert_eq!(opened(arm, &r), native(exe.to_str().unwrap()), "{arm} follow: the row's exe");
            assert!(take_reports().is_empty(), "{arm}");
        }
        std::fs::remove_file(&exe).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// O_CREAT|O_EXCL does not follow a final link (the
    /// kernel sets O_NOFOLLOW for it), so a row whose recorded exe is gone
    /// never creates that path: the kernel's EEXIST at the link, on every
    /// arm, and nothing is created.
    #[test]
    fn row_exe_create_exclusive_creates_nothing() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let dir = unit_dir();
        let gone = dir.join("gone-exe");
        let gone_bytes = gone.as_os_str().as_encoded_bytes().to_vec();
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
        let how = [flags as u64, 0o600, 0];
        let native = {
            let fd = unsafe { libc::open(c"/proc/1/exe".as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
            if fd >= 0 {
                close(fd);
            }
            (fd < 0).then(|| std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        };
        assert_eq!(native, Some(libc::EEXIST), "native: O_CREAT|O_EXCL of /proc/1/exe");
        let arms: Vec<(&str, Syscall)> = vec![
            ("openat", openat_at(libc::AT_FDCWD, c"/proc/1/exe", flags)),
            ("openat2", openat2_call(c"/proc/1/exe", &how)),
        ];
        #[cfg(target_arch = "x86_64")]
        let arms = {
            let mut arms = arms;
            arms.push(("open", open_with(c"/proc/1/exe", flags)));
            arms
        };
        for (arm, call) in arms {
            for ptrace in [true, false] {
                let label = format!("{arm} {}", if ptrace { "ptrace" } else { "in-guest" });
                let _rows = Rows::set(vec![row(1, &gone_bytes, &[b"row-a"])]);
                let mut scratch = Scratch::new();
                let (tool, mut g) =
                    if ptrace { on_host_root_ptrace(&mut scratch, &[]) } else { on_host_root(&mut scratch) };
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call);
                assert_eq!(errno(&r), Some(Errno::EEXIST), "{label}: the kernel's EEXIST");
                assert!(!gone.exists(), "{label}: nothing created");
                assert!(take_reports().is_empty(), "{label}");
            }
        }
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Another owned process's exe
    /// (a traced child on ptrace) answers from its row at a follow, and is
    /// the kernel's link without one; the caller's own stays its own.
    #[test]
    fn owned_child_exe_answers_from_its_row() {
        use super::super::{FinalProc, SelfLink};
        let _lane = serial();
        let _off = DispatchOff;
        let mut scratch = Scratch::new();
        let (tool, g) = on_host_root_ptrace(&mut scratch, &[]);
        let child = 4_000_000; // never a live pid: only the row seam answers
        let link = |pid| crate::translate::MagicLink { pid, tid: None, kind: crate::translate::MagicKind::Exe };
        let own = std::process::id() as i32;
        {
            let _rows = Rows::set(vec![row(child, b"/row/exe", &[b"c"])]);
            assert_eq!(tool.final_self_link(&g, FinalProc::OwnedLink(link(child))), Some(SelfLink::RowExe(child)));
            assert_eq!(tool.final_self_link(&g, FinalProc::OwnedLink(link(own))), Some(SelfLink::Exe));
        }
        let _rows = Rows::set(vec![]);
        assert_eq!(tool.final_self_link(&g, FinalProc::OwnedLink(link(child))), None, "no row: the kernel's link");
    }

    /// An owned process (here a child this process
    /// traces, as the ptrace backend traces a guest child) whose row has no
    /// exe (its exec reached a file with no guest name) reads the kernel's
    /// exe link at readlinkat and readlink: never an empty answer, and never
    /// the bare-pid cache.
    #[test]
    fn owned_child_with_an_empty_row_reads_the_kernels_exe() {
        use super::super::FinalProc;
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        // A child that ends when its input closes: no signal is sent to it.
        let mut child = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        // SAFETY: seizes this process's own child, without stopping it.
        let seized = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) };
        let seize_err = std::io::Error::last_os_error();
        let path = format!("/proc/{pid}/exe");
        let c = std::ffi::CString::new(path.clone()).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(seized, 0, "PTRACE_SEIZE: {seize_err}");
            super::super::pid_exe_map().lock().unwrap().insert(pid, PathBuf::from("/stale/cache"));
            let _rows = Rows::set(vec![row(pid, b"", &[b"c"])]);
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
            g.native_rest = true;
            assert!(
                matches!(tool.final_proc(&g, Path::new(&path)), FinalProc::OwnedLink(_)),
                "an owned process's link"
            );
            let kernel = native_readlink(&path);
            assert!(matches!(&kernel, Ok(t) if !t.is_empty()), "the kernel's link: {kernel:?}");
            let mut buf = [0u8; 4096];
            let r = dispatch(&tool, &mut g, readlinkat_call(&c, &mut buf));
            assert_eq!(readlinked(&r, &buf), kernel, "readlinkat: the kernel's");
            #[cfg(target_arch = "x86_64")]
            {
                let mut buf = [0u8; 4096];
                let call = Syscall::from_raw(
                    Sysno::readlink,
                    SyscallArgs::new(c.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0),
                );
                let r = dispatch(&tool, &mut g, call);
                assert_eq!(readlinked(&r, &buf), kernel, "readlink: the kernel's");
            }
            assert!(take_reports().is_empty());
        }));
        super::super::pid_exe_map().lock().unwrap().remove(&pid);
        drop(child.stdin.take());
        child.wait().unwrap();
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    /// An execve of a row's exe link runs the row's
    /// exe (the answer is scripted; nothing runs): the injected execve
    /// names its host path.
    #[test]
    fn row_exe_at_execve() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        super::super::LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        let (dir, exe) = exe_file();
        let exe_bytes = exe.as_os_str().as_encoded_bytes().to_vec();
        let _rows = Rows::set(vec![row(1, &exe_bytes, &[b"row-a"])]);
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
        g.expect([err(Errno::ENOEXEC)]);
        let call = Syscall::from_raw(Sysno::execve, SyscallArgs::new(c"/proc/1/exe".as_ptr() as usize, 0, 0, 0, 0, 0));
        let r = dispatch(&tool, &mut g, call);
        assert_eq!(errno(&r), Some(Errno::ENOEXEC), "the scripted answer");
        let injected = g.injected();
        let exec = injected.iter().find(|(nr, _)| *nr == Sysno::execve).expect("an execve");
        // SAFETY: the Tool staged the path in this unit's scratch buffer.
        let path = unsafe { std::ffi::CStr::from_ptr(exec.1[0] as *const libc::c_char) };
        assert_eq!(path.to_bytes(), exe_bytes.as_slice(), "the row's exe");
        take_reports();
        std::fs::remove_file(&exe).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}

/// P1-B: an open that follows a final symlink is decided on the entry the
/// follow resolves to in the guest's view, on every open arm: a link (or a
/// chain) to a row's cmdline answers the row, to the caller's own (by pid,
/// by a thread id, or through /proc/self) is synthesized, and to another
/// process's is the kernel's; a dangling link is the kernel's ENOENT;
/// O_NOFOLLOW opens the link itself (the kernel's ELOOP).
mod p1b_units {
    use super::a1_units::*;
    use super::*;

    /// A directory of links for one unit, removed on drop.
    struct Links(PathBuf);

    impl Links {
        fn new() -> Self {
            Links(unit_dir())
        }

        /// `<dir>/<name>` -> `target`, as a C string path.
        fn link(&self, name: &str, target: &str) -> std::ffi::CString {
            let at = self.0.join(name);
            std::os::unix::fs::symlink(target, &at).unwrap();
            std::ffi::CString::new(at.into_os_string().into_encoded_bytes()).unwrap()
        }
    }

    impl Drop for Links {
        fn drop(&mut self) {
            for entry in std::fs::read_dir(&self.0).unwrap() {
                let _ = std::fs::remove_file(entry.unwrap().path());
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    type Call<'a> = Box<dyn Fn(&std::ffi::CStr, bool) -> Syscall + 'a>;

    fn openat_flags(path: &std::ffi::CStr, nofollow: bool) -> Syscall {
        openat_at(libc::AT_FDCWD, path, libc::O_RDONLY | if nofollow { libc::O_NOFOLLOW } else { 0 })
    }

    #[cfg(target_arch = "x86_64")]
    fn open_flags(path: &std::ffi::CStr, nofollow: bool) -> Syscall {
        open_with(path, libc::O_RDONLY | if nofollow { libc::O_NOFOLLOW } else { 0 })
    }

    /// The three open arms: name, call (path, O_NOFOLLOW), and whether a
    /// synthesized answer injects openat2's argument probe first.
    fn arms<'a>(how: &'a [u64; 3], how_nofollow: &'a [u64; 3]) -> Vec<(&'static str, Call<'a>, bool)> {
        let arms: Vec<(&'static str, Call<'a>, bool)> = vec![
            ("openat", Box::new(openat_flags), false),
            (
                "openat2",
                Box::new(move |p: &std::ffi::CStr, nofollow: bool| {
                    openat2_call(p, if nofollow { how_nofollow } else { how })
                }),
                true,
            ),
        ];
        #[cfg(target_arch = "x86_64")]
        let arms = {
            let mut arms = arms;
            arms.push(("open", Box::new(open_flags), false));
            arms
        };
        arms
    }

    #[test]
    fn followed_links_are_decided_on_their_target() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let how = [libc::O_RDONLY as u64, 0, 0];
        let how_nofollow = [(libc::O_RDONLY | libc::O_NOFOLLOW) as u64, 0, 0];
        let own = std::process::id();
        let tid = unsafe { libc::gettid() };
        assert_ne!(tid as u32, own, "the unit needs a non-leader thread");
        let links = Links::new();
        let other = links.link("other", "/proc/1/cmdline");
        let chain = links.link("chain", &format!("{}/other", links.0.display()));
        let mine = links.link("mine", &format!("/proc/{own}/cmdline"));
        let by_tid = links.link("tid", &format!("/proc/{tid}/cmdline"));
        let self_link = links.link("self", "/proc/self/cmdline");
        let dangling = links.link("dangling", &format!("{}/missing", links.0.display()));
        for inguest in [false, true] {
        type Setup = fn(&mut Scratch, &[&str]) -> (Arc<RootfsTool>, RecordingGuest);
        let setup: Setup = if inguest { on_host_root_inguest } else { on_host_root_ptrace };
        for (arm, call, argument_probe) in &arms(&how, &how_nofollow) {
            // With a row for pid 1: the link and the chain answer the row.
            for (what, path) in [("link", &other), ("chain", &chain)] {
                let _rows = Rows::set(vec![row(1, b"/row/exe-a1", &[b"row-a", b"x"])]);
                let mut scratch = Scratch::new();
                let (tool, mut g) = setup(&mut scratch, &["caller-argv"]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call(path, false));
                let fd = r.ok().unwrap_or_else(|| panic!("{arm} {what}: a descriptor")) as i32;
                let got = read_memfd(arm, fd);
                assert!(got == b"row-a\0x\0", "{arm} {what}: read {} bytes, expected the row's 8", got.len());
                assert!(take_reports().is_empty(), "{arm} {what}");
            }
            // Without a row: the kernel's file; only the translated open is
            // injected.
            for (what, path) in [("link, no row", &other), ("chain, no row", &chain)] {
                let _rows = Rows::set(vec![row(2, b"/row/not-pid-1", &[b"x"])]);
                let mut scratch = Scratch::new();
                let (tool, mut g) = setup(&mut scratch, &[]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call(path, false));
                assert_eq!(opened(what, &r), native("/proc/1/cmdline"), "{arm} {what}: the kernel's");
                assert!(take_reports().is_empty(), "{arm} {what}");
                assert_eq!(g.injected().len(), 1, "{arm} {what}: the translated open only");
            }
            // A link to the caller's own cmdline, by pid, by a thread id, or
            // through /proc/self: synthesized from the caller's argv.
            for (what, path) in [("own pid", &mine), ("own tid", &by_tid), ("/proc/self", &self_link)] {
                let _rows = Rows::set(Vec::new());
                let mut scratch = Scratch::new();
                let (tool, mut g) = setup(&mut scratch, &["caller-argv"]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call(path, false));
                let fd = r.ok().unwrap_or_else(|| panic!("{arm} {what}: a descriptor")) as i32;
                let got = read_memfd(arm, fd);
                assert!(got == b"caller-argv\0", "{arm} {what}: read {} bytes, expected the caller's 12", got.len());
                assert!(take_reports().is_empty(), "{arm} {what}");
                if inguest {
                    let probes = g.injected().iter().filter(|(nr, _)| *nr == Sysno::openat2).count();
                    assert_eq!(probes, usize::from(*argument_probe), "{arm} {what}: argument probes");
                } else {
                    assert_eq!(g.injected().len(), 1, "{arm} {what}: ptrace, the guest's own call only");
                }
            }
            // A dangling link: the translated open runs, natively ENOENT.
            {
                let _rows = Rows::set(Vec::new());
                let mut scratch = Scratch::new();
                let (tool, mut g) = setup(&mut scratch, &[]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call(&dangling, false));
                assert_eq!(errno(&r), Some(Errno::ENOENT), "{arm} dangling");
                assert!(take_reports().is_empty(), "{arm} dangling");
            }
            // O_NOFOLLOW: the link itself is opened, natively ELOOP.
            {
                let _rows = Rows::set(Vec::new());
                let mut scratch = Scratch::new();
                let (tool, mut g) = setup(&mut scratch, &[]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call(&other, true));
                assert_eq!(errno(&r), Some(Errno::ELOOP), "{arm} O_NOFOLLOW");
                assert!(take_reports().is_empty(), "{arm} O_NOFOLLOW");
            }
        }
        }
    }
}

/// The openat2 argument probe before a synthesized cmdline: it runs behind
/// the probe gate and under admission; only EBADF lets the synthesis answer;
/// a success, EPERM, ENOSYS or any other result proves nothing, so the
/// kernel's own file answers (the fallback line), and nothing is closed. A
/// walk error, and an ordinary openat2, never meet the gate.
/// The guarded probe for openat2 of a cmdline literoot synthesizes: on the
/// in-guest backends only. The ptrace
/// route checks the arguments in the tracer instead ([`tracer_route_units`]).
mod openat2_probe_units {
    use super::a1_units::*;
    use super::*;

    const HOW: [u64; 3] = [libc::O_RDONLY as u64, 0, 0];

    fn shared_cmdline() -> Syscall {
        openat2_call(c"/proc/1/cmdline", &HOW)
    }

    /// (probes, refused, sud_refused) of this process's record.
    pub(super) fn counts(tool: &RootfsTool) -> (u64, u64, u64) {
        let mut st = tool.state.lock().unwrap();
        let a = st.admission(std::process::id() as i32);
        (a.probes, a.refused, a.sud_refused)
    }

    /// Close the gate one of four ways; the ticket of a pending install.
    /// "dispatch ON" is the dispatch-read seam on ptrace and the thread's
    /// tracked mode in-guest (where the Tool reads no kernel state).
    pub(super) fn close_gate(
        tool: &RootfsTool,
        g: &mut RecordingGuest,
        what: &str,
    ) -> Option<crate::dead_base::InstallTicket> {
        if what == "dispatch ON" {
            g.thread_state_mut().sud_on = true;
        }
        let pid = std::process::id() as i32;
        let mut ticket = None;
        {
            let mut st = tool.state.lock().unwrap();
            let a = st.admission(pid);
            match what {
                "flagged" => a.filter_latched = true,
                "filter installed" => a.guest_filter = true,
                "install pending" => ticket = Some(a.begin_install().unwrap()),
                _ => {}
            }
        }
        if what == "dispatch ON" {
            set_dispatch_read(Some(Ok(true)));
        }
        ticket
    }

    /// Reopen the gate [`close_gate`] closed.
    pub(super) fn reopen_gate(tool: &RootfsTool, ticket: Option<crate::dead_base::InstallTicket>) {
        if let Some(ticket) = ticket {
            tool.state.lock().unwrap().admission(std::process::id() as i32).abandon_install(ticket);
        }
        set_dispatch_read(Some(Ok(false)));
    }

    pub(super) const GATES: [&str; 4] = ["flagged", "filter installed", "install pending", "dispatch ON"];

    #[test]
    fn only_ebadf_lets_the_synthesis_answer() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        // An owned live sentinel descriptor, which a fake success names.
        let sentinel_dir = unit_dir();
        let sentinel_path = sentinel_dir.join("sentinel");
        std::fs::write(&sentinel_path, b"s").unwrap();
        let sentinel = std::fs::File::open(&sentinel_path).unwrap();
        let sentinel_fd = std::os::unix::io::AsRawFd::as_raw_fd(&sentinel);
        for (what, answer) in [
            ("fake success", Answer::Return(Ok(sentinel_fd as i64))),
            ("EPERM", err(Errno::EPERM)),
            ("ENOSYS", err(Errno::ENOSYS)),
            ("unexpected ENOENT", err(Errno::ENOENT)),
        ] {
            let _rows = Rows::set(vec![row(1, b"/row/exe-a1", &[b"row-a", b"x"])]);
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
            g.expect([answer]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, shared_cmdline());
            assert_eq!(opened(what, &r), native("/proc/1/cmdline"), "{what}: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "{what}");
            let injected = g.injected();
            assert_eq!(injected.len(), 2, "{what}: the probe, then the translated openat2; no close, no memfd");
            assert_eq!((injected[0].0, injected[0].1[0] as i32), (Sysno::openat2, -1), "{what}");
            assert_eq!(injected[1].0, Sysno::openat2, "{what}");
            assert!(unsafe { libc::fcntl(sentinel_fd, libc::F_GETFD) } >= 0, "{what}: the sentinel survives");
            assert_eq!(counts(&tool), (1, 0, 0), "{what}: one probe counted");
        }
        drop(sentinel);
        std::fs::remove_file(&sentinel_path).unwrap();
        std::fs::remove_dir(&sentinel_dir).unwrap();
    }

    /// The guarded probe opens its own name, "x" against descriptor -1, after
    /// the admission's status read staged its path; it gets EBADF and opens
    /// nothing, so the synthesis answers. Tree 6 found the name staged in a
    /// path slot the status read reuses: the probe opened
    /// /proc/self/status, a success that proved nothing (the kernel's file
    /// answered) and left that descriptor open in the guest.
    #[test]
    fn probe_opens_its_own_name_and_leaks_nothing() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        // Descriptors of this process open on its status file. Counted by
        // target, not in total: other unit threads open descriptors of their
        // own meanwhile; the probe's only possible leak is this one.
        let status_fds = || {
            let want = PathBuf::from(format!("/proc/{}/status", std::process::id()));
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter(|l| *l == want)
                .count()
        };
        let _rows = Rows::set(vec![row(1, b"/row/exe-a1", &[b"row-a", b"x"])]);
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
        g.native_rest = true;
        let before = status_fds();
        let r = dispatch(&tool, &mut g, shared_cmdline());
        let after = status_fds();
        let fd = r.expect("a descriptor") as i32;
        let injected = g.injected();
        let probe = injected.first().expect("the probe");
        assert_eq!((probe.0, probe.1[0] as i32), (Sysno::openat2, -1), "the probe comes first");
        // SAFETY: the Tool staged the name in the unit's scratch buffer,
        // NUL-terminated; nothing stages there after the probe.
        let name = unsafe { std::ffi::CStr::from_ptr(probe.1[1] as *const libc::c_char) };
        assert_eq!(name.to_bytes(), b"x", "the probe's own name");
        assert_eq!(read_memfd("probe", fd), b"row-a\0x\0", "EBADF: the synthesis answered");
        assert!(take_reports().is_empty(), "no fallback");
        assert_eq!(after, before, "no descriptor left open on the status file");
        assert_eq!(counts(&tool), (1, 0, 0), "one probe counted");
    }

    /// Under a closed gate the probe is not injected: the kernel's own file
    /// answers, with the fallback line, counted as a refused probe.
    #[test]
    fn closed_gate_falls_back_before_the_probe() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        for what in GATES {
            let _rows = Rows::set(vec![row(1, b"/row/exe-a1", &[b"row-a", b"x"])]);
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
            let ticket = close_gate(&tool, &mut g, what);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, shared_cmdline());
            assert_eq!(opened(what, &r), native("/proc/1/cmdline"), "{what}: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "{what}");
            let injected = g.injected();
            assert_eq!(injected.len(), 1, "{what}: the translated openat2 only, no probe");
            assert_ne!(injected[0].1[0] as i32, -1, "{what}: not the probe");
            let want = if what == "dispatch ON" { (1, 0, 1) } else { (1, 1, 0) };
            assert_eq!(counts(&tool), want, "{what}: (probes, refused, sud_refused)");
            reopen_gate(&tool, ticket);
        }
    }

    /// An installer arriving while the probe is held is refused at once
    /// with in_flight=1; the probe's EBADF then lets the row answer.
    #[test]
    fn installer_during_the_probe_is_refused() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let _rows = Rows::set(vec![row(1, b"/row/exe-a1", &[b"row-a", b"x"])]);
        let mut scratch = Scratch::new();
        let (tool, mut a) = on_host_root_inguest(&mut scratch, &[]);
        a.native_rest = true;
        let tid = unsafe { libc::gettid() };
        let b_result = Arc::new(Mutex::new(None));
        let held = {
            let (tool, b_result) = (tool.clone(), b_result.clone());
            Answer::Call(Box::new(move || {
                let mut b = RecordingGuest::new(inguest_cfg(Path::new("/"))).with_ids(None, Some(tid + 1));
                let r = dispatch(&tool, &mut b, install_call());
                *b_result.lock().unwrap() = Some((errno(&r), take_reports(), b.events().len()));
                Err(Errno::EBADF)
            }))
        };
        a.expect([held]);
        let r = dispatch(&tool, &mut a, shared_cmdline());
        assert_eq!(
            b_result.lock().unwrap().take(),
            Some((Some(Errno::EOPNOTSUPP), vec![Refusal::InstallRefused { in_flight: 1 }], 0)),
            "the installer was refused while the probe was held"
        );
        let fd = r.expect("the row answers after the probe's EBADF") as i32;
        let got = read_memfd("held probe", fd);
        assert!(got == b"row-a\0x\0", "read {} bytes, expected the row's 8", got.len());
        assert!(take_reports().is_empty());
        let st = tool.state.lock().unwrap();
        assert_eq!((st.admission.installs, st.admission.installs_refused), (1, 1));
        assert_eq!(st.admission.probes_in_flight(), 0, "the admission was released");
    }

    /// P2-G: walk errors keep their answer under every gate, with nothing
    /// counted: an ordinary 42-link chain (the walk's ELOOP), and a named
    /// walk refusal (the caller's own cwd outside the guest root,
    /// proc_link_outside_root). With the gate open the argument probe runs,
    /// and an argument error it reports (EINVAL) is the guest's answer
    /// instead (the kernel checks open_how first). The refusal line is
    /// written by the walk before the probe, a disclosed limit.
    ///
    /// Under a closed gate the probe does not run, so the walk's errno
    /// stands with nothing injected and nothing counted: the A3 ruling of
    /// 2026-11-15 (the probe gate, checked without counting, then
    /// admission, as for every other probe) replaced P2-G's closed-gate rows
    /// of 2026-11-14, which ran the probe unguarded. A double-error call
    /// under a closed gate then answers the walk's errno, a known difference
    /// (docs/design.md 4.9.3). One unit per gate calls this, so a mutant of
    /// the gate turns each closed gate's unit red on its own.
    fn walk_errors_rows(what: &str) {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        // The chain: c0 -> c1 -> ... -> c41 -> target.
        let dir = unit_dir();
        std::fs::write(dir.join("target"), b"t").unwrap();
        for i in 0..42 {
            let next = if i == 41 { "target".to_owned() } else { format!("c{}", i + 1) };
            std::os::unix::fs::symlink(&next, dir.join(format!("c{i}"))).unwrap();
        }
        let chain = std::ffi::CString::new(dir.join("c0").into_os_string().into_encoded_bytes()).unwrap();
        // A root with /proc bound: the test's cwd is outside it.
        let root = unit_dir();
        {
            let open = what == "open";
            // The chain, on the host root.
            {
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
                let ticket = close_gate(&tool, &mut g, what);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat2_call(&chain, &HOW));
                assert_eq!(errno(&r), Some(Errno::ELOOP), "{what}: the walk's ELOOP");
                assert!(take_reports().is_empty(), "{what}: chain");
                let injected = g.injected();
                if open {
                    assert_eq!(injected.len(), 1, "{what}: chain, the argument probe only");
                    assert_eq!(
                        (injected[0].0, injected[0].1[0] as i32),
                        (Sysno::openat2, -1),
                        "{what}"
                    );
                } else {
                    assert_eq!(
                        injected.len(),
                        0,
                        "{what}: chain, no probe under a closed gate"
                    );
                }
                assert_eq!(counts(&tool), (0, 0, 0), "{what}: chain, nothing counted");
                reopen_gate(&tool, ticket);
            }
            // The cwd outside the root.
            {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                tool.state.lock().unwrap().cwd = PathBuf::from("/");
                let cfg = LiterootConfig {
                    binds: vec![("/proc".into(), "/proc".into(), false)],
                    ..inguest_cfg(&root)
                };
                set_dispatch_read(Some(Ok(false)));
                let mut g = RecordingGuest::new(cfg);
                g.native_status = true;
                let ticket = close_gate(&tool, &mut g, what);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat2_call(c"/proc/self/cwd/x", &HOW));
                assert_eq!(errno(&r), Some(Errno::EACCES), "{what}: cwd outside the root");
                assert_eq!(take_reports(), vec![Refusal::Path(PathRefusal::ProcLinkOutsideRoot)], "{what}");
                let injected = g.injected();
                if open {
                    assert_eq!(injected.len(), 1, "{what}: cwd, the argument probe only");
                    assert_eq!(
                        (injected[0].0, injected[0].1[0] as i32),
                        (Sysno::openat2, -1),
                        "{what}"
                    );
                } else {
                    assert_eq!(
                        injected.len(),
                        0,
                        "{what}: cwd, no probe under a closed gate"
                    );
                }
                assert_eq!(counts(&tool), (0, 0, 0), "{what}: cwd, nothing counted");
                reopen_gate(&tool, ticket);
            }
            // The probe reports an argument error: it is the guest's.
            {
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
                let ticket = close_gate(&tool, &mut g, what);
                g.expect([err(Errno::EINVAL)]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat2_call(&chain, &HOW));
                if open {
                    assert_eq!(
                        errno(&r),
                        Some(Errno::EINVAL),
                        "{what}: chain, the probe's EINVAL"
                    );
                } else {
                    assert_eq!(
                        errno(&r),
                        Some(Errno::ELOOP),
                        "{what}: chain, the walk's ELOOP, no probe"
                    );
                }
                assert!(take_reports().is_empty(), "{what}: chain, EINVAL");
                if open {
                    assert_eq!(
                        g.injected().len(),
                        1,
                        "{what}: chain, EINVAL: the argument probe only"
                    );
                } else {
                    assert_eq!(
                        g.injected().len(),
                        0,
                        "{what}: chain, EINVAL: no probe under a closed gate"
                    );
                }
                assert_eq!(counts(&tool), (0, 0, 0), "{what}: chain, EINVAL: nothing counted");
                reopen_gate(&tool, ticket);
            }
            {
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                tool.state.lock().unwrap().cwd = PathBuf::from("/");
                let cfg = LiterootConfig {
                    binds: vec![("/proc".into(), "/proc".into(), false)],
                    ..inguest_cfg(&root)
                };
                set_dispatch_read(Some(Ok(false)));
                let mut g = RecordingGuest::new(cfg);
                g.native_status = true;
                let ticket = close_gate(&tool, &mut g, what);
                g.expect([err(Errno::EINVAL)]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat2_call(c"/proc/self/cwd/x", &HOW));
                if open {
                    assert_eq!(
                        errno(&r),
                        Some(Errno::EINVAL),
                        "{what}: cwd, the probe's EINVAL"
                    );
                } else {
                    assert_eq!(
                        errno(&r),
                        Some(Errno::EACCES),
                        "{what}: cwd, the walk's EACCES, no probe"
                    );
                    assert_eq!(
                        g.injected().len(),
                        0,
                        "{what}: cwd, EINVAL: no probe under a closed gate"
                    );
                }
                assert_eq!(
                    take_reports(),
                    vec![Refusal::Path(PathRefusal::ProcLinkOutsideRoot)],
                    "{what}: cwd, EINVAL: the walk's line, written before the probe"
                );
                assert_eq!(counts(&tool), (0, 0, 0), "{what}: cwd, EINVAL: nothing counted");
                reopen_gate(&tool, ticket);
            }
        }
        for entry in std::fs::read_dir(&dir).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(&dir).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// The walk errors with the probe gate open: the argument probe runs.
    #[test]
    fn walk_errors_keep_their_answer_open_gate() {
        walk_errors_rows("open");
    }

    /// The walk errors with a guest filter flagged: no probe, nothing counted.
    #[test]
    fn walk_errors_keep_their_answer_flagged() {
        assert_eq!(GATES[0], "flagged");
        walk_errors_rows(GATES[0]);
    }

    /// The walk errors with a guest filter installed: no probe, nothing
    /// counted.
    #[test]
    fn walk_errors_keep_their_answer_filter_installed() {
        assert_eq!(GATES[1], "filter installed");
        walk_errors_rows(GATES[1]);
    }

    /// The walk errors with a filter install pending: no probe, nothing
    /// counted.
    #[test]
    fn walk_errors_keep_their_answer_install_pending() {
        assert_eq!(GATES[2], "install pending");
        walk_errors_rows(GATES[2]);
    }

    /// The walk errors with the thread's dispatch mode ON: no probe, nothing
    /// counted.
    #[test]
    fn walk_errors_keep_their_answer_dispatch_on() {
        assert_eq!(GATES[3], "dispatch ON");
        walk_errors_rows(GATES[3]);
    }

    /// The argument probe opens its own name, "x" against descriptor -1,
    /// staged in a slot of its own: in-guest, admission's status read
    /// stages /proc/self/status in the path slots first, and a name staged
    /// there would make the probe open that file (a success that proves
    /// nothing, with a descriptor left in the guest).
    #[test]
    fn arguments_probe_opens_its_own_name() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let dir = unit_dir();
        std::fs::write(dir.join("target"), b"t").unwrap();
        for i in 0..42 {
            let next = if i == 41 {
                "target".to_owned()
            } else {
                format!("c{}", i + 1)
            };
            std::os::unix::fs::symlink(&next, dir.join(format!("c{i}"))).unwrap();
        }
        let chain = dir.join("c0").into_os_string().into_encoded_bytes();
        let chain = std::ffi::CString::new(chain).unwrap();
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat2_call(&chain, &HOW));
        assert_eq!(errno(&r), Some(Errno::ELOOP), "the walk's ELOOP");
        let injected = g.injected();
        let probe = injected.first().expect("the probe");
        assert_eq!(
            (probe.0, probe.1[0] as i32),
            (Sysno::openat2, -1),
            "the probe comes first"
        );
        // SAFETY: the Tool staged the name in the unit's scratch buffer,
        // NUL-terminated; nothing stages there after the probe.
        let name = unsafe { std::ffi::CStr::from_ptr(probe.1[1] as *const libc::c_char) };
        assert_eq!(name.to_bytes(), b"x", "the probe's own name");
        assert_eq!(injected.len(), 1, "the probe only");
        assert!(take_reports().is_empty());
        assert_eq!(counts(&tool), (0, 0, 0), "nothing counted");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// S.4 for the argument probe: a success (which only a filter can make
    /// on descriptor -1) names no descriptor the probe owns, so nothing is
    /// closed and the walk's error stands. The scripted success names a
    /// live sentinel, which survives.
    #[test]
    fn arguments_probe_success_closes_nothing() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let dir = unit_dir();
        std::fs::write(dir.join("target"), b"t").unwrap();
        for i in 0..42 {
            let next = if i == 41 {
                "target".to_owned()
            } else {
                format!("c{}", i + 1)
            };
            std::os::unix::fs::symlink(&next, dir.join(format!("c{i}"))).unwrap();
        }
        let chain = dir.join("c0").into_os_string().into_encoded_bytes();
        let chain = std::ffi::CString::new(chain).unwrap();
        // A raw descriptor, closed by hand: a mutant that closes it must not
        // also make a File's drop close a descriptor that is gone.
        let target = dir.join("target").into_os_string().into_encoded_bytes();
        let target = std::ffi::CString::new(target).unwrap();
        let sentinel_fd = unsafe { libc::open(target.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(sentinel_fd >= 0, "the sentinel opens");
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
        g.expect([Answer::Return(Ok(sentinel_fd as i64))]);
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat2_call(&chain, &HOW));
        assert_eq!(errno(&r), Some(Errno::ELOOP), "the walk's ELOOP");
        let injected = g.injected();
        assert_eq!(injected.len(), 1, "the argument probe only, no close");
        assert_eq!(
            (injected[0].0, injected[0].1[0] as i32),
            (Sysno::openat2, -1),
            "the probe"
        );
        assert!(
            unsafe { libc::fcntl(sentinel_fd, libc::F_GETFD) } >= 0,
            "the sentinel survives"
        );
        assert!(take_reports().is_empty());
        assert_eq!(counts(&tool), (0, 0, 0), "nothing counted");
        unsafe { libc::close(sentinel_fd) };
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An ordinary openat2 under a closed gate needs no probe: it is
    /// translated and run, with no refusal and no count.
    #[test]
    fn ordinary_openat2_ignores_the_gate() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let dir = unit_dir();
        let file = dir.join("plain");
        std::fs::write(&file, b"p").unwrap();
        let path = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_inguest(&mut scratch, &[]);
        let pid = std::process::id() as i32;
        let ticket = tool.state.lock().unwrap().admission(pid).begin_install().unwrap();
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat2_call(&path, &HOW));
        let fd = r.expect("the plain file opens") as i32;
        close(fd);
        assert!(take_reports().is_empty());
        assert_eq!(counts(&tool), (0, 0, 0));
        assert_eq!(g.injected().len(), 1, "the translated openat2 only");
        tool.state.lock().unwrap().admission(pid).abandon_install(ticket);
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}

/// The cmdline literoot answers itself (§4.9.5): a memfd made in the guest
/// by an injected memfd_create and filled from the Tool's side at offset 0;
/// MFD_CLOEXEC exactly when the guest asked for O_CLOEXEC; and the kernel's
/// own file, with the fallback line, when the memfd cannot be made.
mod memfd_units {
    use super::a1_units::*;
    use super::*;

    /// Clears both memfd write seams on drop.
    struct WriteSeams;

    impl Drop for WriteSeams {
        fn drop(&mut self) {
            super::super::MEMFD_PIDFD_OFF.with(|s| s.set(false));
            super::super::MEMFD_WRITE_FAILS.with(|s| s.set(false));
            super::super::MEMFD_ROUTE.with(|s| s.set(None));
        }
    }

    /// In-guest (the ptrace route is the tracer's: [`tracer_route_units`]).
    #[test]
    fn exact_argv_at_offset_zero() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seams = WriteSeams;
        take_reports();
        for (what, path, rows, want) in [
            ("own", c"/proc/self/cmdline", vec![], &b"caller-argv\0\0z\0"[..]),
            ("row", c"/proc/1/cmdline", vec![row(1, b"/row/exe", &[b"row-a", b"", b"x"])], &b"row-a\0\0x\0"[..]),
        ] {
            for pidfd_off in [false, true] {
                super::super::MEMFD_PIDFD_OFF.with(|s| s.set(pidfd_off));
                super::super::MEMFD_ROUTE.with(|s| s.set(None));
                let _rows = Rows::set(rows.clone());
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_inguest(&mut scratch, &["caller-argv", "", "z"]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat_call(path));
                let label = format!("{what}, pidfd route {}", if pidfd_off { "off" } else { "on" });
                let fd = r.ok().unwrap_or_else(|| panic!("{label}: a descriptor")) as i32;
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0, "{label}: fstat");
                assert_eq!(st.st_mode & 0o777, 0o444, "{label}: mode 0444, as the kernel's cmdline file");
                let got = read_memfd(&label, fd);
                assert!(got == want, "{label}: read {} bytes, expected {}", got.len(), want.len());
                let route = if pidfd_off { MemfdRoute::Procfs } else { MemfdRoute::Pidfd };
                assert_eq!(super::super::MEMFD_ROUTE.with(|s| s.get()), Some(route), "{label}: the route that wrote");
                assert!(take_reports().is_empty(), "{label}");
                let injected: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
                assert_eq!(injected, vec![Sysno::memfd_create], "{label}: the memfd only");
            }
        }
    }

    /// In-guest the memfd is named exactly as requested, after the
    /// admission's status read staged its own path: the name the kernel
    /// shows in /proc/self/maps for a mapping of it, and the name the
    /// injected memfd_create pointed at. Tree 6 found the name staged in a
    /// path slot the status read reuses, which named every memfd
    /// `/proc/self/status`.
    #[test]
    fn name_is_the_requested_one() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_inguest(&mut scratch, &["caller-argv"]);
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
        let fd = r.expect("a descriptor") as i32;
        assert!(g.events().iter().any(|e| matches!(e, Event::Status(Sysno::openat))), "the status read ran first");
        let created = g.injected().into_iter().find(|(nr, _)| *nr == Sysno::memfd_create).expect("the memfd");
        // SAFETY: the Tool staged the name in the unit's scratch buffer,
        // NUL-terminated; nothing stages there after the memfd_create.
        let name = unsafe { std::ffi::CStr::from_ptr(created.1[0] as *const libc::c_char) };
        assert_eq!(name.to_bytes(), b"literoot-cmdline", "the name memfd_create was given");
        // SAFETY: a read-only private mapping of the unit's own descriptor,
        // never touched, unmapped below.
        let at = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_PRIVATE, fd, 0) };
        assert_ne!(at, libc::MAP_FAILED, "map the memfd");
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let start = format!("{:x}-", at as usize);
        let line = maps.lines().find(|l| l.starts_with(&start)).expect("the mapping's line").to_owned();
        assert_eq!(unsafe { libc::munmap(at, 4096) }, 0);
        // The sixth field, the path, may itself contain spaces.
        let path = line.splitn(6, ' ').nth(5).unwrap_or("").trim_start();
        assert_eq!(path, "/memfd:literoot-cmdline (deleted)", "the name in /proc/self/maps");
        assert_eq!(read_memfd("name", fd), b"caller-argv\0");
        assert!(take_reports().is_empty());
    }

    /// In-guest the injected memfd_create carries MFD_CLOEXEC exactly when
    /// the guest asked; on ptrace the guest's own call, rewritten, keeps its
    /// flags (the tracer's memfd is always MFD_CLOEXEC, and private to it).
    #[test]
    fn cloexec_follows_the_guest() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        for ptrace in [false, true] {
        for cloexec in [false, true] {
            let flags = libc::O_RDONLY | if cloexec { libc::O_CLOEXEC } else { 0 };
            let how = [flags as u64, 0, 0];
            let arms: Vec<(&str, Syscall)> = vec![
                ("openat", openat_at(libc::AT_FDCWD, c"/proc/self/cmdline", flags)),
                ("openat2", openat2_call(c"/proc/self/cmdline", &how)),
            ];
            #[cfg(target_arch = "x86_64")]
            let arms = {
                let mut arms = arms;
                arms.push(("open", open_with(c"/proc/self/cmdline", flags)));
                arms
            };
            for (arm, call) in arms {
                let label = format!("{arm} {} cloexec {cloexec}", if ptrace { "ptrace" } else { "in-guest" });
                let mut scratch = Scratch::new();
                let (tool, mut g) = if ptrace {
                    on_host_root_ptrace(&mut scratch, &["caller-argv"])
                } else {
                    on_host_root_inguest(&mut scratch, &["caller-argv"])
                };
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call);
                let fd = r.ok().unwrap_or_else(|| panic!("{label}: a descriptor")) as i32;
                let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                assert_eq!(fd_flags & libc::FD_CLOEXEC != 0, cloexec, "{label}: FD_CLOEXEC");
                if ptrace {
                    let injected = g.injected();
                    assert_eq!(injected.len(), 1, "{label}: the guest's own call only");
                    assert!(!injected.iter().any(|(nr, _)| *nr == Sysno::memfd_create), "{label}: no memfd injected");
                } else {
                    let created =
                        g.injected().into_iter().find(|(nr, _)| *nr == Sysno::memfd_create).expect("the memfd");
                    assert_eq!(created.1[1] as u32 & libc::MFD_CLOEXEC != 0, cloexec, "{label}: MFD_CLOEXEC");
                }
                let got = read_memfd(&label, fd);
                assert!(got == b"caller-argv\0", "{label}: read {} bytes", got.len());
            }
        }
        }
        assert!(take_reports().is_empty());
    }

    /// In-guest, the kernel's own file answers, with the fallback line, when
    /// memfd_create fails, the gate is closed (nothing is injected for the
    /// memfd, and nothing counted), admission refuses, or the write fails
    /// (the memfd is closed first). In-guest; the ptrace route's fallbacks
    /// are [`tracer_route_units`].
    #[test]
    fn fallback_opens_the_kernel_file() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = WriteSeams;
        take_reports();
        let kernel = native("/proc/self/cmdline");
        // memfd_create fails.
        {
            let _base = Baseline::own();
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_inguest(&mut scratch, &["caller-argv"]);
            g.expect([err(Errno::ENOSYS)]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(opened("ENOSYS", &r), kernel, "ENOSYS: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "ENOSYS");
            let injected: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(injected, vec![Sysno::memfd_create, Sysno::openat], "ENOSYS");
        }
        // A closed gate: a filter installed.
        {
            let _base = Baseline::own();
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_inguest(&mut scratch, &["caller-argv"]);
            tool.state.lock().unwrap().admission(std::process::id() as i32).guest_filter = true;
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(opened("closed gate", &r), kernel, "closed gate: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "closed gate");
            let injected: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(injected, vec![Sysno::openat], "closed gate: the translated open only");
            let mut st = tool.state.lock().unwrap();
            let a = st.admission(std::process::id() as i32);
            assert_eq!((a.probes, a.refused, a.sud_refused), (0, 0, 0), "closed gate: nothing counted");
        }
        // In-guest, admission refuses (the filter count is not known).
        {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_with(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(opened("in-guest refused", &r), kernel, "in-guest refused: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "in-guest refused");
            assert!(!g.injected().iter().any(|(nr, _)| *nr == Sysno::memfd_create), "no memfd");
        }
        // The write fails: the memfd is closed, then the kernel answers.
        {
            let _base = Baseline::own();
            super::super::MEMFD_WRITE_FAILS.with(|s| s.set(true));
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_inguest(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            super::super::MEMFD_WRITE_FAILS.with(|s| s.set(false));
            let injected = g.injected();
            let nrs: Vec<Sysno> = injected.iter().map(|(nr, _)| *nr).collect();
            assert_eq!(nrs, vec![Sysno::memfd_create, Sysno::close, Sysno::openat], "write failure");
            let closed = injected[1].1[0] as i32;
            let now = std::fs::read_link(format!("/proc/self/fd/{closed}"));
            assert!(
                !now.is_ok_and(|l| l.to_string_lossy().starts_with("/memfd:")),
                "write failure: descriptor {closed} no longer names the memfd"
            );
            assert_eq!(opened("write failure", &r), kernel, "write failure: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "write failure");
        }
    }

    /// The write goes through the calling thread's own descriptor table.
    /// A worker that unshared CLONE_FILES gets
    /// its memfd at the number where the shared table holds a writable
    /// sentinel file: the memfd holds the argv, the sentinel is unchanged,
    /// and the route that wrote is the one asked for, on both routes,
    /// in-guest. On ptrace the guest's own call reopens the
    /// tracer's memfd through the tracer thread's own table (`task/<tid>`,
    /// here this thread's private one, never the leader's sentinel): the
    /// bytes, and nothing written into the guest's table.
    #[test]
    fn private_table_writes_the_requesting_thread() {
        let _lane = serial();
        take_reports();
        let dir = unit_dir();
        let path = dir.join("sentinel");
        std::fs::write(&path, b"s").unwrap();
        let sentinel = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let x = std::os::unix::io::AsRawFd::as_raw_fd(&sentinel);
        let own_filters = {
            let text = std::fs::read_to_string("/proc/self/status").unwrap();
            crate::dead_base::status_field(text.as_bytes(), b"Seccomp_filters").unwrap() as u32
        };
        std::thread::scope(|s| {
            s.spawn(|| {
                let _seams = WriteSeams;
                // SAFETY: CLONE_FILES only: this thread gets its own copy of the table.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_FILES) }, 0, "unshare(CLONE_FILES)");
                // Fill every free slot below x, then close this table's x:
                // x is its lowest free number, and no other thread shares it.
                let mut fillers = Vec::new();
                loop {
                    let d = unsafe { libc::fcntl(x, libc::F_DUPFD, 0) };
                    assert!(d >= 0, "F_DUPFD");
                    if d > x {
                        close(d);
                        break;
                    }
                    fillers.push(d);
                }
                close(x);
                set_dispatch_read(Some(Ok(false)));
                super::super::set_filter_baseline(own_filters);
                for ptrace in [true, false] {
                    let routes: &[(bool, MemfdRoute)] = if ptrace {
                        &[(false, MemfdRoute::Pidfd)]
                    } else {
                        &[(false, MemfdRoute::Pidfd), (true, MemfdRoute::Procfs)]
                    };
                    for &(pidfd_off, route) in routes {
                        super::super::MEMFD_PIDFD_OFF.with(|c| c.set(pidfd_off));
                        super::super::MEMFD_ROUTE.with(|c| c.set(None));
                        let label = format!("{} {route:?}", if ptrace { "ptrace" } else { "in-guest" });
                        let mut scratch = Scratch::new();
                        let tool = tool_with(&mut scratch);
                        tool.state.lock().unwrap().cwd = PathBuf::from("/");
                        let base = if ptrace { ptrace_cfg(Path::new("/")) } else { inguest_cfg(Path::new("/")) };
                        let cfg = LiterootConfig { initial_argv: vec!["caller-argv".into()], ..base };
                        let mut g = RecordingGuest::new(cfg);
                        g.native_rest = true;
                        let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
                        let fd = r.ok().unwrap_or_else(|| panic!("{label}: a descriptor")) as i32;
                        // In-guest the memfd is made in this table, at x. On ptrace the
                        // tracer's memfd is in this same test thread's table here (one
                        // process plays both), so the reopened descriptor is the next
                        // free number; in a real run the tracer is another process.
                        if !ptrace {
                            assert_eq!(fd, x, "{label}: the memfd took the sentinel's number");
                        }
                        let wrote = if ptrace { None } else { Some(route) };
                        assert_eq!(super::super::MEMFD_ROUTE.with(|c| c.get()), wrote, "{label}: the route that wrote");
                        let got = read_memfd(&label, fd);
                        assert!(got == b"caller-argv\0", "{label}: read {} bytes, expected the caller's 12", got.len());
                        assert_eq!(std::fs::read(&path).unwrap(), b"s", "{label}: the shared sentinel is unchanged");
                        assert!(take_reports().is_empty(), "{label}");
                    }
                }
                super::super::set_filter_baseline(u32::MAX);
                set_dispatch_read(None);
                for d in fillers {
                    close(d);
                }
            })
            .join()
            .unwrap()
        });
        drop(sentinel);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Before any write the descriptor must name an empty regular file
    /// (the memfd just made): a non-empty file or a pipe at that number is
    /// never written, on either route; an empty file is (the control).
    #[test]
    fn write_refuses_a_non_memfd_descriptor() {
        let _lane = serial();
        let _seams = WriteSeams;
        let tid = unsafe { libc::gettid() };
        let dir = unit_dir();
        let full = dir.join("full");
        std::fs::write(&full, b"keep").unwrap();
        let full_file = std::fs::OpenOptions::new().read(true).write(true).open(&full).unwrap();
        let mut pipe = [0i32; 2];
        assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0, "pipe2");
        for pidfd_off in [false, true] {
            super::super::MEMFD_PIDFD_OFF.with(|c| c.set(pidfd_off));
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&full_file);
            assert!(!super::super::write_guest_fd(tid, fd, b"argv\0"), "a non-empty file (pidfd off {pidfd_off})");
            assert_eq!(std::fs::read(&full).unwrap(), b"keep", "the non-empty file is unchanged (pidfd off {pidfd_off})");
            assert!(!super::super::write_guest_fd(tid, pipe[1], b"argv\0"), "a pipe (pidfd off {pidfd_off})");
            let mut b = [0u8; 8];
            assert_eq!(unsafe { libc::read(pipe[0], b.as_mut_ptr().cast(), b.len()) }, -1, "nothing in the pipe");
            let empty = dir.join(format!("empty-{pidfd_off}"));
            std::fs::write(&empty, b"").unwrap();
            let empty_file = std::fs::OpenOptions::new().read(true).write(true).open(&empty).unwrap();
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&empty_file);
            assert!(super::super::write_guest_fd(tid, fd, b"argv\0"), "an empty file is written (pidfd off {pidfd_off})");
            assert_eq!(std::fs::read(&empty).unwrap(), b"argv\0");
            drop(empty_file);
            std::fs::remove_file(&empty).unwrap();
        }
        close(pipe[0]);
        close(pipe[1]);
        drop(full_file);
        std::fs::remove_file(&full).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}

/// The ptrace answer for a synthesized cmdline:
/// the tracer's memfd, reopened by
/// the guest's own call, rewritten. No gate applies and nothing is injected
/// but that call; the kernel's argument and flag answers come first, in its
/// order; anything else falls back to the kernel's own file.
mod tracer_route_units {
    use super::a1_units::*;
    use super::openat2_probe_units::{close_gate, counts, reopen_gate, GATES};
    use super::*;

    /// Clears the route's seams on drop.
    struct RouteSeams;

    impl Drop for RouteSeams {
        fn drop(&mut self) {
            super::super::TRACER_ROUTE_OFF.with(|s| s.set(false));
            super::super::GUEST_FDS_UNREADABLE.with(|s| s.set(false));
            super::super::LAYOUT_COPY_PROTECT_FAILS.with(|s| s.set(false));
            super::super::forget_mount_ns_moved(std::process::id() as i32);
        }
    }

    /// openat2(`dirfd`, `path`, `how`, `size`) with `how` at any address.
    fn openat2_raw(dirfd: i32, path: &std::ffi::CStr, how: usize, size: usize) -> Syscall {
        Syscall::from_raw(
            Sysno::openat2,
            SyscallArgs::new(dirfd as isize as usize, path.as_ptr() as usize, how, size, 0, 0),
        )
    }

    /// The same openat2 run natively: the file it opens, or its errno.
    fn native_openat2(dirfd: i32, path: &std::ffi::CStr, how: usize, size: usize) -> Result<(u64, u64), Errno> {
        let fd = unsafe { libc::syscall(libc::SYS_openat2, dirfd, path.as_ptr(), how, size) };
        if fd < 0 {
            return Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        let id = dev_ino(fd as i32);
        close(fd as i32);
        Ok(id)
    }

    /// The path a rewritten call names (its pointer argument at `at`).
    fn named(args: &[u64; 6], at: usize) -> String {
        // SAFETY: the Tool staged the name in the unit's scratch buffer.
        unsafe { std::ffi::CStr::from_ptr(args[at] as *const libc::c_char) }
            .to_string_lossy()
            .into_owned()
    }

    /// Under every closed gate, as with none, the three arms answer the
    /// caller's argv and a row's from the tracer's memfd with one injection,
    /// the guest's own call naming /proc/<tracer>/task/<tid>/fd/<n>; nothing counted,
    /// no line.
    #[test]
    fn answers_under_every_gate() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let prefix = format!("/proc/{}/task/{}/fd/", std::process::id(), unsafe { libc::gettid() });
        for what in std::iter::once("open").chain(GATES) {
            for (who, path, rows, want) in [
                ("own", c"/proc/self/cmdline", vec![], &b"caller-argv\0"[..]),
                ("row", c"/proc/1/cmdline", vec![row(1, b"/row/exe", &[b"row-a", b"x"])], &b"row-a\0x\0"[..]),
            ] {
                let arms: Vec<(&str, Syscall, usize)> = vec![
                    ("openat", openat_call(path), 1),
                    ("openat2", openat2_call(path, &[libc::O_RDONLY as u64, 0, 0]), 1),
                ];
                #[cfg(target_arch = "x86_64")]
                let arms = {
                    let mut arms = arms;
                    arms.push(("open", open_call(path), 0));
                    arms
                };
                for (arm, call, at) in arms {
                    let label = format!("{what}, {who}, {arm}");
                    let _rows = Rows::set(rows.clone());
                    let mut scratch = Scratch::new();
                    let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
                    let ticket = close_gate(&tool, &mut g, what);
                    g.native_rest = true;
                    let r = dispatch(&tool, &mut g, call);
                    let fd = r.ok().unwrap_or_else(|| panic!("{label}: a descriptor")) as i32;
                    let got = read_memfd(&label, fd);
                    assert!(got == want, "{label}: read {} bytes, expected {}", got.len(), want.len());
                    let injected = g.injected();
                    assert_eq!(injected.len(), 1, "{label}: the guest's own call only");
                    assert!(named(&injected[0].1, at).starts_with(&prefix), "{label}: the tracer's memfd");
                    assert!(take_reports().is_empty(), "{label}");
                    assert_eq!(counts(&tool), (0, 0, 0), "{label}: nothing counted");
                    reopen_gate(&tool, ticket);
                }
            }
        }
    }

    /// The guest reads its argv even when the tracer cannot inspect the
    /// guest's descriptors (a non-dumpable guest): the identity check
    /// stands on the route's preconditions.
    #[test]
    fn uninspectable_guest_still_reads_its_argv() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        super::super::GUEST_FDS_UNREADABLE.with(|s| s.set(true));
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
        let fd = r.expect("a descriptor") as i32;
        assert!(read_memfd("uninspectable", fd) == b"caller-argv\0");
        assert!(take_reports().is_empty());
    }

    /// Fallbacks before anything is injected: the route reports itself
    /// unusable (a non-dumpable tracer, 1d), or the guest left the tracer's
    /// mount namespace (N1). The kernel's own file answers, with one line.
    #[test]
    fn preconditions_fall_back() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let kernel = native("/proc/self/cmdline");
        let pid = std::process::id() as i32;
        for what in ["tracer unusable", "mount namespace moved"] {
            match what {
                "tracer unusable" => super::super::TRACER_ROUTE_OFF.with(|s| s.set(true)),
                _ => super::super::note_mount_ns_moved(pid),
            }
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(opened(what, &r), kernel, "{what}: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "{what}");
            let injected: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(injected, vec![Sysno::openat], "{what}: the translated open only");
            super::super::TRACER_ROUTE_OFF.with(|s| s.set(false));
            super::super::forget_mount_ns_moved(pid);
        }
    }

    /// A filter the tracer inherited that makes the
    /// probe's call at descriptor -1 succeed with 0 (SECCOMP_RET_ERRNO | 0
    /// skips the call and returns 0, kernel/seccomp.c) is the fallback, on
    /// each arm, and closes nothing: descriptor 0, a sentinel file here,
    /// still names it. The filter is installed only in a child test process
    /// (this test re-run with LITEROOT_F4_PROBE_CHILD set, which also stops
    /// it re-running itself), on the thread running the test.
    #[test]
    fn made_up_probe_success_closes_nothing() {
        const CHILD: &str = "LITEROOT_F4_PROBE_CHILD";
        const NAME: &str = "rootfs_tool::seams::tracer_route_units::made_up_probe_success_closes_nothing";
        if std::env::var_os(CHILD).is_some() {
            made_up_probe_success_child();
            println!("F4 CHILD OK");
            return;
        }
        // Recursion guard, both halves: (1) the child runs with `--exact`
        // and this test's full name (only this one test runs in it) AND with
        // CHILD set; (2) this spawn runs only when CHILD is absent, and the
        // child's arm above returns before it, so a child never spawns.
        let out = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the child test process");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("F4 CHILD OK"),
            "child {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The child's half of [`made_up_probe_success_closes_nothing`].
    fn made_up_probe_success_child() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let dir = unit_dir();
        let sentinel = dir.join("sentinel");
        std::fs::write(&sentinel, b"s").unwrap();
        let file = std::fs::File::open(&sentinel).unwrap();
        // SAFETY: replaces this child's stdin (/dev/null) with the sentinel.
        assert_eq!(unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&file), 0) }, 0);
        drop(file);
        let id = dev_ino(0);
        fake_success_at_fd_minus_one();
        let kernel = native("/proc/self/cmdline");
        let how = [0u64; 3];
        let arms: Vec<(&str, Syscall, Sysno)> = vec![
            ("openat", openat_call(c"/proc/self/cmdline"), Sysno::openat),
            (
                "openat2",
                openat2_raw(libc::AT_FDCWD, c"/proc/self/cmdline", how.as_ptr() as usize, 24),
                Sysno::openat2,
            ),
        ];
        #[cfg(target_arch = "x86_64")]
        let arms = {
            let mut arms = arms;
            arms.push(("open", open_with(c"/proc/self/cmdline", libc::O_RDONLY), Sysno::open));
            arms
        };
        for (arm, call, nr) in arms {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, call);
            assert_eq!(opened(arm, &r), kernel, "{arm}: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "{arm}: one line");
            let nrs: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(nrs, vec![nr], "{arm}: the translated open only");
            // SAFETY: a plain descriptor query.
            assert_ne!(unsafe { libc::fcntl(0, libc::F_GETFD) }, -1, "{arm}: descriptor 0 is open");
            assert_eq!(dev_ino(0), id, "{arm}: descriptor 0 is still the sentinel");
        }
        std::fs::remove_file(&sentinel).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Installs, on the calling thread, a seccomp filter under which openat
    /// and openat2 at descriptor -1 (the low half of argument 0) return 0
    /// without running.
    fn fake_success_at_fd_minus_one() {
        let load = |k: u32| libc::sock_filter { code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, jt: 0, jf: 0, k };
        let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        };
        let ret = |k: u32| libc::sock_filter { code: (libc::BPF_RET | libc::BPF_K) as u16, jt: 0, jf: 0, k };
        // seccomp_data: nr at 0, args from 16, eight bytes each.
        let mut program = [
            load(0),
            jeq(libc::SYS_openat as u32, 1, 0),
            jeq(libc::SYS_openat2 as u32, 0, 3),
            load(16),
            jeq(u32::MAX, 0, 1),
            ret(libc::SECCOMP_RET_ERRNO),
            ret(libc::SECCOMP_RET_ALLOW),
        ];
        let fprog = libc::sock_fprog { len: program.len() as u16, filter: program.as_mut_ptr() };
        // SAFETY: prctl and seccomp read only the arguments given; `fprog`
        // points at `program`, which outlives both calls. No TSYNC: this
        // thread only.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0, "no_new_privs");
            assert_eq!(
                libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &raw const fprog),
                0,
                "seccomp: {}",
                std::io::Error::last_os_error()
            );
        }
        // The positive control: the probe's own call now succeeds with 0.
        // SAFETY: as in the probe; descriptor -1 opens nothing.
        let r = unsafe { libc::syscall(libc::SYS_openat, -1, c"x".as_ptr(), 0, 0) };
        assert_eq!(r, 0, "the filter makes openat(-1) succeed with 0");
    }

    /// The mount-namespace record (N1): set by a successful unshare with
    /// CLONE_NEWNS and a successful setns, never by a failed one, and for a
    /// child cloned with CLONE_NEWNS or from a parent already moved.
    #[test]
    fn mount_namespace_moves_are_tracked() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        let pid = std::process::id() as i32;
        let moved = || super::super::mount_ns_moved(pid);
        let unshare = |flags: i32| {
            Syscall::from_raw(Sysno::unshare, SyscallArgs::new(flags as usize, 0, 0, 0, 0, 0))
        };
        let setns = || Syscall::from_raw(Sysno::setns, SyscallArgs::new(3, libc::CLONE_NEWNS as usize, 0, 0, 0, 0));
        for (what, call, answer, want) in [
            ("unshare(CLONE_NEWNS) refused", unshare(libc::CLONE_NEWNS), err(Errno::EPERM), false),
            ("unshare(CLONE_NEWNS)", unshare(libc::CLONE_NEWNS), ok0(), true),
            ("unshare(CLONE_NEWUTS)", unshare(libc::CLONE_NEWUTS), ok0(), false),
            ("setns refused", setns(), err(Errno::EINVAL), false),
            ("setns", setns(), ok0(), true),
        ] {
            super::super::forget_mount_ns_moved(pid);
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
            g.expect([answer]);
            let _ = dispatch(&tool, &mut g, call);
            assert_eq!(moved(), want, "{what}");
        }
        // A child: a process this unit starts and ends itself.
        let mut child = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("cat");
        let cpid = child.id() as i32;
        let child_moved = || super::super::mount_ns_moved(cpid);
        let mut scratch = Scratch::new();
        let (tool, g) = on_host_root_ptrace(&mut scratch, &[]);
        super::super::forget_mount_ns_moved(pid);
        tool.note_child_mount_ns(&g, 0, &Ok(cpid as i64));
        assert!(!child_moved(), "a plain child of an unmoved parent");
        tool.note_child_mount_ns(&g, libc::CLONE_NEWNS as u64, &Ok(cpid as i64));
        assert!(child_moved(), "a child cloned with CLONE_NEWNS");
        super::super::forget_mount_ns_moved(cpid);
        super::super::note_mount_ns_moved(pid);
        tool.note_child_mount_ns(&g, 0, &Ok(cpid as i64));
        assert!(child_moved(), "a child of a moved parent");
        super::super::forget_mount_ns_moved(cpid);
        drop(child.stdin.take());
        child.wait().expect("cat exits");
        // A thread cloned with CLONE_NEWNS, through
        // the clone arm (the answer is scripted; nothing runs): the caller's
        // process counts as moved; a plain thread does not move it.
        let thread = (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD | libc::CLONE_FILES) as usize;
        for (what, flags, want) in [("a thread", thread, false), ("a thread with CLONE_NEWNS", thread | libc::CLONE_NEWNS as usize, true)] {
            super::super::forget_mount_ns_moved(pid);
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
            g.expect([Answer::Return(Ok(4_000_001))]);
            let call = Syscall::from_raw(Sysno::clone, SyscallArgs::new(flags, 0, 0, 0, 0, 0));
            assert_eq!(dispatch(&tool, &mut g, call).ok(), Some(4_000_001), "{what}");
            assert_eq!(moved(), want, "{what}");
        }
        super::super::forget_mount_ns_moved(pid);
    }

    /// O_NOFOLLOW names a regular file here (the cmdline file), so it is
    /// cleared in the rewritten call, whose final entry is a magic link: the
    /// bytes, on every arm, as natively.
    #[test]
    fn nofollow_is_cleared_in_the_rewrite() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW;
        let how = [flags as u64, 0, 0];
        let arms: Vec<(&str, Syscall, usize)> = vec![
            ("openat", openat_at(libc::AT_FDCWD, c"/proc/self/cmdline", flags), 2),
            ("openat2", openat2_call(c"/proc/self/cmdline", &how), 2),
        ];
        #[cfg(target_arch = "x86_64")]
        let arms = {
            let mut arms = arms;
            arms.push(("open", open_with(c"/proc/self/cmdline", flags), 1));
            arms
        };
        for (arm, call, at) in arms {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, call);
            let fd = r.ok().unwrap_or_else(|| panic!("{arm} O_NOFOLLOW: a descriptor")) as i32;
            assert!(read_memfd(arm, fd) == b"caller-argv\0", "{arm} O_NOFOLLOW: the bytes");
            let injected = g.injected();
            assert_eq!(injected.len(), 1, "{arm}: the guest's own call only");
            let rewritten = if arm == "openat2" {
                // SAFETY: the staged open_how is in this unit's scratch buffer.
                unsafe { *(injected[0].1[2] as *const u64) }
            } else {
                injected[0].1[at]
            };
            assert_eq!(rewritten & libc::O_NOFOLLOW as u64, 0, "{arm}: O_NOFOLLOW cleared");
            assert!(take_reports().is_empty(), "{arm}");
        }
    }

    /// The answers the arguments and flags decide come first, without the
    /// fallback line and with nothing injected (1a): each equal to the
    /// native open of the same file with the same flags. O_PATH keeps only
    /// the O_DIRECTORY answer.
    #[test]
    fn flag_answers_come_first() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let native_flags = |flags: i32| {
            let fd = unsafe { libc::open(c"/proc/self/cmdline".as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
            if fd < 0 {
                return Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
            }
            close(fd);
            Ok(())
        };
        for (what, flags) in [
            ("O_CREAT|O_EXCL", libc::O_CREAT | libc::O_EXCL),
            ("O_DIRECTORY", libc::O_DIRECTORY),
            ("O_WRONLY", libc::O_WRONLY),
            ("O_RDWR", libc::O_RDWR),
            ("O_TRUNC", libc::O_RDONLY | libc::O_TRUNC),
            ("O_TMPFILE read-only", libc::O_TMPFILE | libc::O_RDONLY),
            ("O_PATH|O_DIRECTORY", libc::O_PATH | libc::O_DIRECTORY),
        ] {
            let want = native_flags(flags);
            assert!(want.is_err(), "{what}: the native open fails (precondition)");
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            let r = dispatch(&tool, &mut g, openat_at(libc::AT_FDCWD, c"/proc/self/cmdline", flags));
            assert_eq!(errno(&r), want.err(), "{what}: the native answer");
            assert!(take_reports().is_empty(), "{what}: no fallback line");
            assert!(g.injected().is_empty(), "{what}: nothing injected");
        }
        // O_PATH with a write mode: a descriptor, as natively.
        assert!(native_flags(libc::O_PATH | libc::O_WRONLY).is_ok(), "O_PATH|O_WRONLY opens natively");
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat_at(libc::AT_FDCWD, c"/proc/self/cmdline", libc::O_PATH | libc::O_WRONLY));
        let fd = r.expect("O_PATH|O_WRONLY: a descriptor") as i32;
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        assert!(link.to_string_lossy().starts_with("/memfd:literoot-cmdline"), "O_PATH: the memfd, got {link:?}");
        close(fd);
        assert!(take_reports().is_empty());
    }

    /// openat2's size limit is the page size, not 4096 (fs/open.c):
    /// on 16 KiB and 64 KiB pages a size between 4097 and the
    /// page size is accepted, one byte past it is E2BIG, and below 24 is
    /// EINVAL whatever the page.
    #[test]
    fn open_how_size_limit_is_the_page_size() {
        use super::super::open_how_size_check as check;
        for page in [4096usize, 16384, 65536] {
            assert_eq!(check(23, page), Err(Errno::EINVAL), "{page}: 23");
            assert_eq!(check(24, page), Ok(()), "{page}: 24");
            assert_eq!(check(page, page), Ok(()), "{page}: a page");
            assert_eq!(check(page + 1, page), Err(Errno::E2BIG), "{page}: past a page");
        }
        assert_eq!(check(8192, 65536), Ok(()), "8192 on 64 KiB pages");
        assert_eq!(check(8192, 4096), Err(Errno::E2BIG), "8192 on 4 KiB pages");
    }

    /// access_ok's range check: a range that ends past
    /// the top of the user address space, or wraps, is out; one that ends
    /// at a page below the top is in.
    #[test]
    fn open_how_range_must_be_user_memory() {
        use super::super::user_range_ok as ok;
        assert!(ok(0x1000, 24));
        assert!(ok((1usize << 47) - 8192, 4096), "ends a page below the smallest top");
        assert!(!ok(usize::MAX - 7, 32), "wraps");
        assert!(!ok(1usize << 60, 24), "past every top");
        #[cfg(target_arch = "x86_64")]
        assert!(!ok((1usize << 56) - 8, 16), "crosses the 5-level top");
    }

    /// openat2's open_how is checked by the tracer first, in the kernel's
    /// order (1c, N2): its size (below 24 EINVAL, above a page E2BIG), an
    /// extension (zero is accepted, nonzero E2BIG, unreadable EFAULT), the
    /// resolve combinations the kernel refuses (BENEATH|IN_ROOT EINVAL,
    /// CACHED with O_CREAT EAGAIN). Each equals the native openat2 of the
    /// same arguments. The re-rooting resolve bits are cleared in the
    /// staged copy, so the cells native opens answer (from a /proc dirfd:
    /// BENEATH, IN_ROOT, NO_XDEV) give the bytes.
    #[test]
    fn openat2_how_is_checked_first() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        use super::super::{RESOLVE_BENEATH, RESOLVE_CACHED, RESOLVE_IN_ROOT, RESOLVE_NO_XDEV};
        let proc_dir = unsafe { libc::open(c"/proc".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(proc_dir >= 0, "open /proc");
        let rdonly = libc::O_RDONLY as u64;
        // Two pages, the second inaccessible: an extension ending there faults
        // (the kernel's page size).
        let page = super::super::page_size();
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), 2 * page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(map, libc::MAP_FAILED, "mmap");
        assert_eq!(unsafe { libc::mprotect(map.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) }, 0);
        let at_edge = unsafe { map.cast::<u8>().add(page - 24) } as usize;
        unsafe { std::ptr::copy_nonoverlapping([rdonly, 0u64, 0u64].as_ptr().cast::<u8>(), at_edge as *mut u8, 24) };
        // A nonzero extension word just before the inaccessible page: the
        // kernel checks the extension first and stops at it, E2BIG, never
        // reaching the fault (check_zeroed_user, lib/usercopy.c).
        let set_then_fault = unsafe { map.cast::<u8>().add(page - 32) } as usize;
        unsafe { std::ptr::copy_nonoverlapping([rdonly, 0u64, 0u64, 1u64].as_ptr().cast::<u8>(), set_then_fault as *mut u8, 32) };
        // Two more pages, the FIRST inaccessible: a header that faults behind
        // a readable nonzero extension is E2BIG too (the extension first).
        let map2 = unsafe {
            libc::mmap(std::ptr::null_mut(), 2 * page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(map2, libc::MAP_FAILED, "mmap");
        let header_faults = unsafe { map2.cast::<u8>().add(page - 8) } as usize;
        unsafe { std::ptr::write((header_faults + 24) as *mut u64, 1) };
        assert_eq!(unsafe { libc::mprotect(map2, page, libc::PROT_NONE) }, 0);
        let mut big = vec![0u8; page + 16];
        big[..8].copy_from_slice(&rdonly.to_ne_bytes());
        let ext_zero: [u64; 4] = [rdonly, 0, 0, 0];
        let ext_set: [u64; 4] = [rdonly, 0, 0, 1];
        let beneath_in_root: [u64; 3] = [rdonly, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT];
        let cached_creat: [u64; 3] = [(libc::O_RDONLY | libc::O_CREAT) as u64, 0o600, RESOLVE_CACHED];
        let bad_flags: [u64; 3] = [rdonly | (1 << 40), 0, 0];
        let refused: Vec<(&str, usize, usize)> = vec![
            ("size 16", ext_zero.as_ptr() as usize, 16),
            ("size above a page", big.as_ptr() as usize, page + 8),
            ("nonzero extension", ext_set.as_ptr() as usize, 32),
            ("unreadable extension", at_edge, 32),
            ("nonzero extension word, then an unreadable one", set_then_fault, 40),
            ("BENEATH|IN_ROOT", beneath_in_root.as_ptr() as usize, 24),
            ("CACHED with O_CREAT", cached_creat.as_ptr() as usize, 24),
            ("unknown flag bit", bad_flags.as_ptr() as usize, 24),
        ];
        for (what, how, size) in refused {
            let want = native_openat2(libc::AT_FDCWD, c"/proc/self/cmdline", how, size);
            assert!(want.is_err(), "{what}: the native openat2 fails (precondition)");
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            let r = dispatch(&tool, &mut g, openat2_raw(libc::AT_FDCWD, c"/proc/self/cmdline", how, size));
            assert_eq!(errno(&r), want.err(), "{what}: the native answer");
            assert!(take_reports().is_empty(), "{what}: no fallback line");
            assert!(g.injected().is_empty(), "{what}: nothing injected");
        }
        let accepted: Vec<(&str, i32, &std::ffi::CStr, [u64; 4], usize)> = vec![
            ("zero extension", libc::AT_FDCWD, c"/proc/self/cmdline", ext_zero, 32),
            ("BENEATH", proc_dir, c"self/cmdline", [rdonly, 0, RESOLVE_BENEATH, 0], 24),
            ("IN_ROOT", proc_dir, c"self/cmdline", [rdonly, 0, RESOLVE_IN_ROOT, 0], 24),
            ("NO_XDEV", proc_dir, c"self/cmdline", [rdonly, 0, RESOLVE_NO_XDEV, 0], 24),
        ];
        for (what, dirfd, path, how, size) in accepted {
            assert!(native_openat2(dirfd, path, how.as_ptr() as usize, size).is_ok(), "{what}: opens natively");
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat2_raw(dirfd, path, how.as_ptr() as usize, size));
            let fd = r.ok().unwrap_or_else(|| panic!("{what}: a descriptor")) as i32;
            assert!(read_memfd(what, fd) == b"caller-argv\0", "{what}: the bytes");
            let injected = g.injected();
            assert_eq!(injected.len(), 1, "{what}: the guest's own call only");
            assert_eq!(injected[0].1[3], 24, "{what}: a 24-byte staged open_how");
            // SAFETY: the staged open_how is in this unit's scratch buffer.
            let staged = unsafe { std::slice::from_raw_parts(injected[0].1[2] as *const u64, 3) };
            assert_eq!(staged[2], 0, "{what}: the re-rooting resolve bits cleared");
            assert!(take_reports().is_empty(), "{what}");
        }
        // An unreadable header behind a readable nonzero extension: the arm
        // cannot read the flags, so the guest's own call goes to the kernel,
        // which answers from the guest's memory: E2BIG (the extension first).
        {
            let want = native_openat2(libc::AT_FDCWD, c"/proc/self/cmdline", header_faults, 32);
            assert_eq!(want, Err(Errno::E2BIG), "unreadable header: E2BIG natively (precondition)");
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            let call = openat2_raw(libc::AT_FDCWD, c"/proc/self/cmdline", header_faults, 32);
            let r = dispatch(&tool, &mut g, call);
            assert_eq!(errno(&r), Some(Errno::E2BIG), "unreadable header: the kernel's E2BIG");
            let injected = g.injected();
            assert_eq!(injected.len(), 1, "unreadable header: the guest's call only");
            assert_eq!((injected[0].0, injected[0].1[2], injected[0].1[3]), (Sysno::openat2, header_faults as u64, 32));
            assert!(take_reports().is_empty(), "unreadable header");
        }
        // A page-sized open_how with a zero extension is accepted.
        {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.native_rest = true;
            assert!(native_openat2(libc::AT_FDCWD, c"/proc/self/cmdline", big.as_ptr() as usize, page).is_ok(), "page-sized: opens natively");
            let r = dispatch(&tool, &mut g, openat2_raw(libc::AT_FDCWD, c"/proc/self/cmdline", big.as_ptr() as usize, page));
            let fd = r.expect("page-sized: a descriptor") as i32;
            assert!(read_memfd("page-sized", fd) == b"caller-argv\0", "page-sized: the bytes");
            assert!(take_reports().is_empty(), "page-sized");
        }
        unsafe { libc::munmap(map, 2 * page) };
        unsafe { libc::munmap(map2, 2 * page) };
        close(proc_dir);
    }

    /// When the tracer cannot make a page of its
    /// open_how copy inaccessible (an mprotect a filter refuses), the copy
    /// is unmapped and the guest's own call answers, from the guest's
    /// memory: the kernel's EFAULT for a readable 24-byte header ending at
    /// a page boundary with a zero extension in the inaccessible page, and
    /// its E2BIG for a nonzero extension word before that page. With the
    /// protection working, the same calls are the tracer's answer with
    /// nothing injected (the control), and no copy outlives a call.
    #[test]
    fn open_how_copy_fails_closed_when_protection_fails() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let live = || super::super::LAYOUT_COPY_LIVE.with(|n| n.get());
        let rdonly = libc::O_RDONLY as u64;
        let page = super::super::page_size();
        // SAFETY: a fresh anonymous mapping, the second page made
        // inaccessible; unmapped below.
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), 2 * page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(map, libc::MAP_FAILED, "mmap");
        assert_eq!(unsafe { libc::mprotect(map.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) }, 0);
        let cases: [(&str, Vec<u64>, usize, Errno); 2] = [
            ("zero extension in an inaccessible page", vec![rdonly, 0, 0], 32, Errno::EFAULT),
            ("nonzero extension word, then an inaccessible page", vec![rdonly, 0, 0, 1], 40, Errno::E2BIG),
        ];
        for (what, words, size, want) in cases {
            let at = map as usize + page - 8 * words.len();
            // SAFETY: the words end at the inaccessible page.
            unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), at as *mut u64, words.len()) };
            let call = || openat2_raw(libc::AT_FDCWD, c"/proc/self/cmdline", at, size);
            assert_eq!(native_openat2(libc::AT_FDCWD, c"/proc/self/cmdline", at, size), Err(want), "{what}: natively (precondition)");
            let before = live();
            {
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
                let r = dispatch(&tool, &mut g, call());
                assert_eq!(errno(&r), Some(want), "{what}: the tracer's answer (control)");
                assert!(g.injected().is_empty(), "{what}: nothing injected (control)");
                assert!(take_reports().is_empty(), "{what}: no line (control)");
                assert_eq!(live(), before, "{what}: the copy unmapped (control)");
            }
            super::super::LAYOUT_COPY_PROTECT_FAILS.with(|s| s.set(true));
            {
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, call());
                assert_eq!(errno(&r), Some(want), "{what}: the kernel's answer to the guest's own call");
                let injected = g.injected();
                assert_eq!(injected.len(), 1, "{what}: the guest's call only");
                assert_eq!((injected[0].0, injected[0].1[2], injected[0].1[3]), (Sysno::openat2, at as u64, size as u64), "{what}");
                assert_eq!(take_reports(), vec![FALLBACK], "{what}: the fallback line");
                assert_eq!(live(), before, "{what}: the refused copy unmapped");
            }
            super::super::LAYOUT_COPY_PROTECT_FAILS.with(|s| s.set(false));
        }
        // The counter counts: a copy over readable memory is live until dropped.
        let header = [rdonly, 0u64, 0u64];
        let before = live();
        let copy = super::super::LayoutCopy::new(header.as_ptr() as usize, 24, page, |addr, buf| {
            // SAFETY: `header` is this unit's own memory.
            unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len()) };
            true
        });
        assert!(copy.is_some() && live() == before + 1, "a live copy");
        drop(copy);
        assert_eq!(live(), before, "unmapped on drop");
        unsafe { libc::munmap(map, 2 * page) };
    }

    /// The rewritten call's own errors (1a, N1): an inaccessible or missing
    /// tracer path (EACCES, ENOENT) falls back to the kernel's file with
    /// one line; EMFILE is the guest's; a restart code keeps the tracer's
    /// memfd for that thread until its next route call (1e); a descriptor
    /// that names another object is closed and the kernel's file answers.
    #[test]
    fn rewritten_call_errors() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seams = RouteSeams;
        take_reports();
        let kernel = native("/proc/self/cmdline");
        let tid = unsafe { libc::gettid() };
        for e in [Errno::EACCES, Errno::ENOENT] {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.expect([err(e)]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(opened("scripted", &r), kernel, "{e:?}: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "{e:?}: one line");
            let nrs: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(nrs, vec![Sysno::openat, Sysno::openat], "{e:?}: rewritten, then translated");
        }
        {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.expect([err(Errno::EMFILE)]);
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(errno(&r), Some(Errno::EMFILE), "EMFILE is the guest's");
            assert!(take_reports().is_empty(), "EMFILE: no line");
        }
        {
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.expect([err(Errno::new(512))]);
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(errno(&r), Some(Errno::new(512)), "the restart code passes");
            assert!(super::super::HELD_TRACER_FDS.lock().unwrap().contains_key(&tid), "the memfd is held");
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            let fd = r.expect("the next call answers") as i32;
            assert!(read_memfd("after restart", fd) == b"caller-argv\0");
            assert!(!super::super::HELD_TRACER_FDS.lock().unwrap().contains_key(&tid), "released by the next route call");
            assert!(take_reports().is_empty());
        }
        {
            let dir = unit_dir();
            let other = dir.join("other");
            std::fs::write(&other, b"o").unwrap();
            let other_c = std::ffi::CString::new(other.as_os_str().as_encoded_bytes()).unwrap();
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &["caller-argv"]);
            g.expect([Answer::Call(Box::new(move || {
                let fd = unsafe { libc::open(other_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 { Err(Errno::EIO) } else { Ok(fd as i64) }
            }))]);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cmdline"));
            assert_eq!(opened("wrong object", &r), kernel, "wrong object: the kernel's file");
            assert_eq!(take_reports(), vec![FALLBACK], "wrong object: one line");
            let nrs: Vec<Sysno> = g.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(nrs, vec![Sysno::openat, Sysno::close, Sysno::openat], "wrong object: closed, then translated");
            std::fs::remove_file(&other).unwrap();
            std::fs::remove_dir(&dir).unwrap();
        }
    }
}

/// An AF_UNIX name whose host path does not fit sun_path answers by its
/// parent's lstat (`overlong_sockname_errno`): the errno of a parent that
/// cannot be reached, ENOTDIR for a parent that is neither a directory nor
/// a symlink, else the designed ENAMETOOLONG. A parent that is itself a
/// symlink, to a directory, to a file or dangling, is never followed on
/// the host: the answer is ENAMETOOLONG. So is a host path with a literal
/// ".." tail, which the ".." guard refuses. For connect (follow), a
/// directory parent answers by the final name's lstat: its errno when it
/// cannot be reached (ENOENT when missing), else ENAMETOOLONG; a link
/// there is never followed on the host either.
mod sockname_units {
    use super::*;

    #[test]
    fn an_overlong_name_answers_by_its_parent() {
        // A pid-named directory left by an earlier test process with the
        // same pid survives when that process died before its cleanup.
        let scratch = std::env::temp_dir()
            .join(format!("literoot-sockname-units-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join("dir")).unwrap();
        std::fs::write(scratch.join("file"), "").unwrap();
        std::os::unix::fs::symlink(scratch.join("dir"), scratch.join("dir-link")).unwrap();
        std::os::unix::fs::symlink(scratch.join("file"), scratch.join("file-link")).unwrap();
        std::os::unix::fs::symlink(scratch.join("gone"), scratch.join("dangling")).unwrap();
        let long = "s".repeat(120);
        std::fs::create_dir_all(scratch.join("with-file")).unwrap();
        std::fs::write(scratch.join("with-file").join(&long), "").unwrap();
        std::fs::create_dir_all(scratch.join("with-link")).unwrap();
        std::os::unix::fs::symlink(scratch.join("gone"), scratch.join("with-link").join(&long))
            .unwrap();
        let answer = |parent: &str, follow: bool| {
            super::super::overlong_sockname_errno(&scratch.join(parent).join(&long), follow)
        };
        assert_eq!(answer("missing", false), Errno::ENOENT, "a missing parent");
        assert_eq!(answer("missing/deeper", false), Errno::ENOENT, "a missing grandparent");
        assert_eq!(answer("file/sub", false), Errno::ENOTDIR, "a file on the parent's path");
        assert_eq!(answer("dir", false), Errno::ENAMETOOLONG, "an existing directory parent");
        assert_eq!(answer("file", false), Errno::ENOTDIR, "an existing non-directory parent");
        assert_eq!(answer("dir-link", false), Errno::ENAMETOOLONG, "a symlink parent to a directory");
        assert_eq!(answer("file-link", false), Errno::ENAMETOOLONG, "a symlink parent to a file");
        assert_eq!(answer("dangling", false), Errno::ENAMETOOLONG, "a dangling symlink parent");
        // A literal ".." tail is the ".." guard's: unchanged.
        assert_eq!(answer("missing/..", false), Errno::ENAMETOOLONG, "missing/.. tail");
        assert_eq!(answer("file/..", false), Errno::ENAMETOOLONG, "file/.. tail");
        // connect (follow): the same parent rules, then the final name.
        assert_eq!(answer("missing", true), Errno::ENOENT, "connect: a missing parent");
        assert_eq!(answer("file", true), Errno::ENOTDIR, "connect: a non-directory parent");
        assert_eq!(answer("dir-link", true), Errno::ENAMETOOLONG, "connect: a symlink parent");
        assert_eq!(answer("dir", true), Errno::ENOENT, "connect: a missing final name");
        assert_eq!(answer("with-file", true), Errno::ENAMETOOLONG, "connect: an existing final");
        assert_eq!(answer("with-link", true), Errno::ENAMETOOLONG, "connect: a dangling host link");
        assert_eq!(answer("missing/..", true), Errno::ENAMETOOLONG, "connect: a .. tail");
        std::fs::remove_dir_all(&scratch).unwrap();
    }
}

/// Another process's directory link continued past or followed:
/// spliced from its verified guest path, else the kernel's with the links
/// in the rest counted; what a call reached is recorded so that it holds
/// still when that process moves. The other process P is a `sh` child the
/// unit starts and ends itself (same uid, never the guest's): it changes
/// into a directory, says "ready", and moves on a line read from its stdin.
mod raw_walk_units {
    use super::a1_units::*;
    use super::*;
    use std::io::{BufRead as _, Write as _};

    struct Other {
        child: std::process::Child,
        stdin: Option<std::process::ChildStdin>,
        out: std::io::BufReader<std::process::ChildStdout>,
    }

    impl Other {
        fn start(dir: &Path) -> Self {
            let mut child = std::process::Command::new("sh")
                .args(["-c", "cd \"$1\" && echo ready && read d && cd \"$d\" && echo moved && read x", "sh"])
                .arg(dir)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("sh");
            let stdin = child.stdin.take();
            let out = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut other = Other { child, stdin, out };
            other.expect_line("ready");
            other
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        fn expect_line(&mut self, want: &str) {
            let mut line = String::new();
            self.out.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), want, "the other process");
        }

        fn move_to(&mut self, dir: &Path) {
            let stdin = self.stdin.as_mut().unwrap();
            stdin.write_all(dir.as_os_str().as_encoded_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
            stdin.flush().unwrap();
            self.expect_line("moved");
        }
    }

    impl Drop for Other {
        fn drop(&mut self) {
            drop(self.stdin.take());
            let _ = self.child.wait();
        }
    }

    /// Clears the identity seam on drop.
    struct IdentitySeam;

    impl Drop for IdentitySeam {
        fn drop(&mut self) {
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(false));
        }
    }

    /// Run `f` on a thread with its own cwd (CLONE_FS unshared).
    fn in_own_fs<R: Send>(f: impl FnOnce() -> R + Send) -> R {
        std::thread::scope(|s| {
            s.spawn(|| {
                // SAFETY: CLONE_FS only: this thread gets its own cwd and root.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_FS) }, 0, "unshare(CLONE_FS)");
                let r = f();
                std::env::set_current_dir(std::env::temp_dir()).unwrap();
                r
            })
            .join()
            .unwrap()
        })
    }

    fn cstr(p: &Path) -> std::ffi::CString {
        std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap()
    }

    fn chdir_call(path: &std::ffi::CStr) -> Syscall {
        Syscall::from_raw(Sysno::chdir, SyscallArgs::new(path.as_ptr() as usize, 0, 0, 0, 0, 0))
    }

    fn getcwd_call(buf: &mut [u8]) -> Syscall {
        Syscall::from_raw(Sysno::getcwd, SyscallArgs::new(buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0, 0))
    }

    fn file_id(p: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(p).unwrap();
        (md.dev(), md.ino())
    }

    /// The configurations: (label, in-guest, the identity check forced to
    /// fail so the walk stays literal).
    const MODES: [(&str, bool, bool); 4] = [
        ("ptrace spliced", false, false),
        ("ptrace literal", false, true),
        ("in-guest spliced", true, false),
        ("in-guest literal", true, true),
    ];

    fn guest_for(scratch: &mut Scratch, inguest: bool) -> (Arc<RootfsTool>, RecordingGuest) {
        if inguest {
            on_host_root_inguest(scratch, &[])
        } else {
            on_host_root_ptrace(scratch, &[])
        }
    }

    /// Two trees, A and B, each with sub/x and prog (different files).
    fn trees() -> (PathBuf, PathBuf, PathBuf) {
        let base = unit_dir();
        for t in ["a", "b"] {
            std::fs::create_dir_all(base.join(t).join("sub")).unwrap();
            std::fs::write(base.join(t).join("sub/x"), t).unwrap();
            std::fs::write(base.join(t).join("prog"), t).unwrap();
        }
        (base.clone(), base.join("a"), base.join("b"))
    }

    /// chdir("/proc/P/cwd/sub"), then P moves: a relative open still names
    /// A/sub/x and getcwd says A/sub, spliced and literal (A inside the
    /// view, the identity check forced to fail), on ptrace and in-guest.
    /// Outside the view (a root that excludes A) the cwd has no guest name:
    /// UNNAMED_CWD, and the open never reaches B.
    #[test]
    fn moved_cwd_keeps_the_reached_directory() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seam = IdentitySeam;
        take_reports();
        let (base, a, b) = trees();
        for (mode, inguest, literal) in MODES {
            in_own_fs(|| {
                super::super::LINK_IDENTITY_FAILS.with(|s| s.set(literal));
                let mut p = Other::start(&a);
                let mut scratch = Scratch::new();
                let (tool, mut g) = guest_for(&mut scratch, inguest);
                g.native_rest = true;
                let spelled = cstr(&PathBuf::from(format!("/proc/{}/cwd/sub", p.pid())));
                let r = dispatch(&tool, &mut g, chdir_call(&spelled));
                assert_eq!(r.ok(), Some(0), "{mode}: chdir");
                p.move_to(&b);
                let r = dispatch(&tool, &mut g, openat_call(c"x"));
                assert_eq!(opened(mode, &r), Ok(file_id(&a.join("sub/x"))), "{mode}: A/sub/x");
                assert_eq!(tool.state.lock().unwrap().cwd, a.join("sub"), "{mode}: the recorded cwd");
                let mut buf = [0u8; 4096];
                let r = dispatch(&tool, &mut g, getcwd_call(&mut buf));
                let n = r.expect("getcwd") as usize;
                assert_eq!(&buf[..n.saturating_sub(1)], a.join("sub").as_os_str().as_encoded_bytes(), "{mode}: getcwd");
                assert!(take_reports().is_empty(), "{mode}");
            });
        }
        // Outside the view.
        for inguest in [false, true] {
            in_own_fs(|| {
                let mut p = Other::start(&a);
                let root = unit_dir();
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                tool.state.lock().unwrap().cwd = PathBuf::from("/");
                let mk = if inguest { inguest_cfg } else { ptrace_cfg };
                let cfg = LiterootConfig { binds: vec![("/proc".into(), "/proc".into(), false)], ..mk(&root) };
                set_dispatch_read(Some(Ok(false)));
                let mut g = RecordingGuest::new(cfg);
                g.native_rest = true;
                g.native_status = inguest;
                let spelled = cstr(&PathBuf::from(format!("/proc/{}/cwd/sub", p.pid())));
                let r = dispatch(&tool, &mut g, chdir_call(&spelled));
                assert_eq!(r.ok(), Some(0), "outside, in-guest {inguest}: chdir");
                p.move_to(&b);
                assert_eq!(
                    tool.state.lock().unwrap().cwd,
                    PathBuf::from(super::super::UNNAMED_CWD),
                    "outside, in-guest {inguest}: no guest name"
                );
                let r = dispatch(&tool, &mut g, openat_call(c"x"));
                assert_ne!(opened("outside", &r), Ok(file_id(&b.join("sub/x"))), "outside: never B's file");
                take_reports();
                std::fs::remove_dir(&root).unwrap();
            });
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A tree for the link budget: in `dir`, l0 -> l1 -> ... -> l19 ->
    /// /proc/P/cwd (20 links, then the magic link), and in A a chain of `n`
    /// links c0 -> ... -> d, a directory holding f.
    fn budget_tree(dir: &Path, a: &Path, pid: u32, n: usize) {
        for i in 0..20 {
            let next = if i == 19 { format!("/proc/{pid}/cwd") } else { format!("l{}", i + 1) };
            std::os::unix::fs::symlink(next, dir.join(format!("l{i}"))).unwrap();
        }
        std::fs::create_dir_all(a.join("d")).unwrap();
        std::fs::write(a.join("d/f"), b"f").unwrap();
        for i in 0..n {
            let next = if i + 1 == n { "d".to_owned() } else { format!("c{}", i + 1) };
            std::os::unix::fs::symlink(next, a.join(format!("c{i}"))).unwrap();
        }
    }

    /// The link budget spans the other process's link (F3): 20 prefix
    /// links, the magic link and a 20-link chain in A are 41, ELOOP first
    /// natively and on all three arms; with a 19-link chain (40) both open
    /// the file. Spliced and literal are separate units, so each half of the
    /// budget has its own oracle (split mutants).
    fn link_budget(literal: bool) {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seam = IdentitySeam;
        take_reports();
        for (n, loops) in [(20usize, true), (19, false)] {
            let dir = unit_dir();
            let a = unit_dir();
            let p = Other::start(&a);
            budget_tree(&dir, &a, p.pid(), n);
            let path = cstr(&dir.join("l0/c0/f"));
            let want = native(path.to_str().unwrap());
            if loops {
                assert_eq!(want, Err(Errno::ELOOP), "41 links: ELOOP natively (precondition)");
            } else {
                assert_eq!(want, Ok(file_id(&a.join("d/f"))), "40 links: the file natively (precondition)");
            }
            for inguest in [false, true] {
                super::super::LINK_IDENTITY_FAILS.with(|s| s.set(literal));
                let arms: Vec<(&str, Syscall)> = vec![
                    ("openat", openat_call(&path)),
                    ("openat2", openat2_call(&path, &[libc::O_RDONLY as u64, 0, 0])),
                ];
                #[cfg(target_arch = "x86_64")]
                let arms = {
                    let mut arms = arms;
                    arms.push(("open", open_call(&path)));
                    arms
                };
                for (arm, call) in arms {
                    let label = format!("{n}-link chain, literal {literal}, in-guest {inguest}, {arm}");
                    let mut scratch = Scratch::new();
                    let (tool, mut g) = guest_for(&mut scratch, inguest);
                    g.native_rest = true;
                    let r = dispatch(&tool, &mut g, call);
                    assert_eq!(opened(&label, &r), want, "{label}");
                    take_reports();
                }
            }
            drop(p);
            std::fs::remove_dir_all(&dir).unwrap();
            std::fs::remove_dir_all(&a).unwrap();
        }
    }

    #[test]
    fn link_budget_spans_another_cwd_spliced() {
        link_budget(false);
    }

    #[test]
    fn link_budget_spans_another_cwd_literal() {
        link_budget(true);
    }

    /// A "/." after a Raw hand-over over a missing directory reaches the
    /// kernel as spelled: a mkdir of P's cwd + "missing/." is ENOENT, as
    /// natively, and creates nothing (dropping the "/." would create
    /// "missing").
    #[test]
    fn mkdir_missing_dot_after_handover_creates_nothing() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seam = IdentitySeam;
        take_reports();
        let a = unit_dir();
        let p = Other::start(&a);
        let path = cstr(&PathBuf::from(format!("/proc/{}/cwd/missing/.", p.pid())));
        let native = unsafe { libc::mkdirat(libc::AT_FDCWD, path.as_ptr(), 0o755) };
        let native_err = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((native, native_err), (-1, Some(libc::ENOENT)), "natively ENOENT");
        assert!(!a.join("missing").exists(), "natively nothing created");
        for (label, inguest, literal) in MODES {
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(literal));
            let mut scratch = Scratch::new();
            let (tool, mut g) = guest_for(&mut scratch, inguest);
            g.native_rest = true;
            let call = Syscall::from_raw(
                Sysno::mkdirat,
                SyscallArgs::new(libc::AT_FDCWD as usize, path.as_ptr() as usize, 0o755, 0, 0, 0),
            );
            let r = dispatch(&tool, &mut g, call);
            let created = a.join("missing").exists();
            if created {
                std::fs::remove_dir(a.join("missing")).unwrap();
            }
            assert!(!created, "{label}: missing/. created missing");
            assert_eq!(errno(&r), Some(Errno::ENOENT), "{label}: ENOENT");
            take_reports();
        }
        super::super::LINK_IDENTITY_FAILS.with(|s| s.set(false));
        drop(p);
        std::fs::remove_dir_all(&a).unwrap();
    }

    /// A trailing slash (or "/.") makes the kernel follow
    /// the final link, even under O_NOFOLLOW, so after a hand-over it counts
    /// against the same budget, once: 20 prefix links, the magic link and a
    /// final 20-link chain ending in a directory are 41, ELOOP natively and
    /// here; a 19-link chain (40) opens the directory. Spliced and literal,
    /// with and without O_NOFOLLOW, ptrace and in-guest.
    #[test]
    fn slash_forced_final_link_counts_once() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seam = IdentitySeam;
        take_reports();
        for (n, loops) in [(20usize, true), (19, false)] {
            let dir = unit_dir();
            let a = unit_dir();
            let p = Other::start(&a);
            budget_tree(&dir, &a, p.pid(), n);
            for suffix in ["c0/", "c0/."] {
                let path = cstr(&PathBuf::from(format!("{}/l0/{suffix}", dir.display())));
                for nofollow in [false, true] {
                    let flags = libc::O_RDONLY | libc::O_DIRECTORY | if nofollow { libc::O_NOFOLLOW } else { 0 };
                    let want = {
                        let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
                        if fd < 0 {
                            Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)))
                        } else {
                            let id = dev_ino(fd);
                            close(fd);
                            Ok(id)
                        }
                    };
                    if loops {
                        assert_eq!(want, Err(Errno::ELOOP), "{suffix} nofollow {nofollow}: 41 links natively");
                    } else {
                        assert_eq!(want, Ok(file_id(&a.join("d"))), "{suffix} nofollow {nofollow}: 40 natively");
                    }
                    for literal in [false, true] {
                        for inguest in [false, true] {
                            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(literal));
                            let label = format!("{n}-link chain, {suffix}, nofollow {nofollow}, literal {literal}, in-guest {inguest}");
                            let mut scratch = Scratch::new();
                            let (tool, mut g) = guest_for(&mut scratch, inguest);
                            g.native_rest = true;
                            let r = dispatch(&tool, &mut g, openat_at(libc::AT_FDCWD, &path, flags));
                            assert_eq!(opened(&label, &r), want, "{label}");
                            take_reports();
                        }
                    }
                }
            }
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(false));
            drop(p);
            std::fs::remove_dir_all(&dir).unwrap();
            std::fs::remove_dir_all(&a).unwrap();
        }
    }

    /// N4: after a literal hand-over, a relative final link resolves from the
    /// host parent and charges only itself: /proc/P/cwd, 19 intermediate
    /// links and one relative final link are 21 links natively, and the
    /// file opens; so does a short final chain (three links).
    #[test]
    fn relative_final_link_after_a_literal_hand_over() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seam = IdentitySeam;
        take_reports();
        let a = unit_dir();
        let p = Other::start(&a);
        std::fs::create_dir(a.join("d")).unwrap();
        std::fs::write(a.join("d/f2"), b"f").unwrap();
        for i in 0..19 {
            let next = if i == 18 { "d".to_owned() } else { format!("i{}", i + 1) };
            std::os::unix::fs::symlink(next, a.join(format!("i{i}"))).unwrap();
        }
        std::os::unix::fs::symlink("f2", a.join("d/fl")).unwrap();
        std::os::unix::fs::symlink("g1", a.join("d/chain")).unwrap();
        std::os::unix::fs::symlink("g2", a.join("d/g1")).unwrap();
        std::os::unix::fs::symlink("f2", a.join("d/g2")).unwrap();
        let want = Ok(file_id(&a.join("d/f2")));
        for last in ["fl", "chain"] {
            let path = cstr(&PathBuf::from(format!("/proc/{}/cwd/i0/{last}", p.pid())));
            assert_eq!(native(path.to_str().unwrap()), want, "{last}: natively (precondition)");
            for inguest in [false, true] {
                super::super::LINK_IDENTITY_FAILS.with(|s| s.set(true));
                let mut scratch = Scratch::new();
                let (tool, mut g) = guest_for(&mut scratch, inguest);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat_call(&path));
                assert_eq!(opened(last, &r), want, "{last}, in-guest {inguest}: the file");
                assert!(take_reports().is_empty(), "{last}");
            }
        }
        drop(p);
        std::fs::remove_dir_all(&a).unwrap();
    }

    /// 3a: the tail counter stops, without ELOOP, at a magic link in the
    /// tail: from A, m -> /proc/P/cwd is one link, then procfs, where the
    /// count ends; the walk itself reaches the file, as natively.
    #[test]
    fn tail_count_stops_at_a_magic_link() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        let _seam = IdentitySeam;
        take_reports();
        let a = unit_dir();
        let p = Other::start(&a);
        std::fs::write(a.join("f"), b"f").unwrap();
        std::os::unix::fs::symlink(format!("/proc/{}/cwd", p.pid()), a.join("m")).unwrap();
        let tail: Vec<std::ffi::OsString> = ["m", "m", "m", "f"].iter().map(|c| (*c).into()).collect();
        let mut links = 0u32;
        crate::translate::count_raw_tail(&a, &tail, &mut links).unwrap();
        assert_eq!(links, 1, "one link counted, then procfs stops the count");
        let path = cstr(&PathBuf::from(format!("/proc/{}/cwd/m/m/m/f", p.pid())));
        let want = Ok(file_id(&a.join("f")));
        assert_eq!(native(path.to_str().unwrap()), want, "natively (precondition)");
        super::super::LINK_IDENTITY_FAILS.with(|s| s.set(true));
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
        g.native_rest = true;
        let r = dispatch(&tool, &mut g, openat_call(&path));
        assert_eq!(opened("magic tail", &r), want, "the file");
        drop(p);
        std::fs::remove_dir_all(&a).unwrap();
    }

    /// The identity check (own links have it too): a link whose text names
    /// another directory than the link's
    /// own (the text overridden to B while the link names A) is never
    /// spliced. Another process's link stays the kernel's (A/sub/x, never
    /// B/sub/x); the caller's own is refused (no verified guest name).
    #[test]
    fn wrong_target_is_not_spliced() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        struct Override;
        impl Drop for Override {
            fn drop(&mut self) {
                super::super::LINK_TARGET_OVERRIDE.with(|o| *o.borrow_mut() = None);
            }
        }
        let (base, a, b) = trees();
        in_own_fs(|| {
            let _ov = Override;
            let p = Other::start(&a);
            super::super::LINK_TARGET_OVERRIDE.with(|o| *o.borrow_mut() = Some(b.clone()));
            let mut scratch = Scratch::new();
            let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
            g.native_rest = true;
            let other = cstr(&PathBuf::from(format!("/proc/{}/cwd/sub/x", p.pid())));
            let r = dispatch(&tool, &mut g, openat_call(&other));
            assert_eq!(opened("other", &r), Ok(file_id(&a.join("sub/x"))), "another process's: A/sub/x");
            assert!(take_reports().is_empty(), "another process's: no line");
            std::env::set_current_dir(&a).unwrap();
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/thread-self/cwd/sub/x"));
            assert_eq!(errno(&r), Some(Errno::EACCES), "own: refused");
            assert_eq!(take_reports(), vec![Refusal::Path(PathRefusal::ProcLinkOutsideRoot)], "own");
            set_dispatch_read(None);
        });
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// N3: a deeper bind can shadow the reverse of a link's target. With A
    /// bound at /m and B at /m/sub, P's cwd A/sub reverses to /m/sub, which
    /// names B/sub: the round trip fails, so another process's link stays
    /// the kernel's (A/sub/x, never B's), the caller's own is refused, and a
    /// chdir through it records no guest name.
    #[test]
    fn shadowed_name_is_not_spliced() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let (base, a, b) = trees();
        let root = unit_dir();
        let cfg = || LiterootConfig {
            binds: vec![
                ("/proc".into(), "/proc".into(), false),
                ("/m".into(), a.display().to_string(), false),
                ("/m/sub".into(), b.display().to_string(), false),
            ],
            ..ptrace_cfg(&root)
        };
        in_own_fs(|| {
            let p = Other::start(&a.join("sub"));
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            tool.state.lock().unwrap().cwd = PathBuf::from("/");
            set_dispatch_read(Some(Ok(false)));
            let mut g = RecordingGuest::new(cfg());
            g.native_rest = true;
            let other = cstr(&PathBuf::from(format!("/proc/{}/cwd/x", p.pid())));
            let r = dispatch(&tool, &mut g, openat_call(&other));
            assert_eq!(opened("other", &r), Ok(file_id(&a.join("sub/x"))), "another process's: A/sub/x");
            let dir = cstr(&PathBuf::from(format!("/proc/{}/cwd", p.pid())));
            let r = dispatch(&tool, &mut g, chdir_call(&dir));
            assert_eq!(r.ok(), Some(0), "chdir");
            assert_eq!(tool.state.lock().unwrap().cwd, PathBuf::from(super::super::UNNAMED_CWD), "no guest name");
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/cwd/x"));
            assert_eq!(errno(&r), Some(Errno::EACCES), "own: refused");
            assert_eq!(take_reports(), vec![Refusal::Path(PathRefusal::ProcLinkOutsideRoot)], "own");
            set_dispatch_read(None);
        });
        std::fs::remove_dir(&root).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn execve_call(path: &std::ffi::CStr) -> Syscall {
        Syscall::from_raw(Sysno::execve, SyscallArgs::new(path.as_ptr() as usize, 0, 0, 0, 0, 0))
    }

    /// F2b, 3b, N5: an execve through /proc/P/cwd that succeeds records the
    /// file it reached: spliced, literal (the identity check forced to
    /// fail, A inside the view) and outside the view (A excluded: the host
    /// path, with no guest name). The exec is scripted to succeed, so the
    /// handler never returns (its future is dropped at the injection);
    /// the successor's state comes only from the staged snapshot (the
    /// record is cleared first, then the snapshot applied as post-exec
    /// applies it). After P moves, an open of /proc/self/exe opens A's
    /// prog, and readlink names it.
    #[test]
    fn execve_through_another_cwd_records_the_reached_exe() {
        use reverie::Tool as _;
        let _lane = serial();
        let _off = DispatchOff;
        let _seam = IdentitySeam;
        take_reports();
        super::super::LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        let (base, a, b) = trees();
        for mode in ["spliced", "literal", "outside"] {
            let mut p = Other::start(&a);
            let root = if mode == "outside" { unit_dir() } else { PathBuf::from("/") };
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            tool.state.lock().unwrap().cwd = PathBuf::from("/");
            let cfg = LiterootConfig { binds: vec![("/proc".into(), "/proc".into(), false)], ..ptrace_cfg(&root) };
            set_dispatch_read(Some(Ok(false)));
            let mut g = RecordingGuest::new(cfg);
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(mode == "literal"));
            let prog = cstr(&PathBuf::from(format!("/proc/{}/cwd/prog", p.pid())));
            let pid = std::process::id() as i32;
            super::super::pid_exe_map().lock().unwrap().insert(pid, PathBuf::from("/stale/exe"));
            g.expect([Answer::Pend]);
            assert!(
                poll_once(tool.handle_syscall_event(&mut g, execve_call(&prog))).is_none(),
                "{mode}: a successful exec never returns"
            );
            // No bare-pid entry for a file with no
            // guest name, and never the old exe's.
            let entry = super::super::pid_exe_map().lock().unwrap().remove(&pid);
            if mode == "outside" {
                assert_eq!(entry, None, "{mode}: no pid_exe_map entry");
            } else {
                assert_eq!(entry, Some(a.join("prog")), "{mode}: pid_exe_map names the reached file");
            }
            {
                let mut st = tool.state.lock().unwrap();
                st.exe_guest = PathBuf::from("/not/the/successor");
                st.exe_host = mode != "outside";
            }
            assert_eq!(tool.consume_pending(&mut g), Ok(true), "{mode}: the staged snapshot");
            {
                let st = tool.state.lock().unwrap();
                assert_eq!(st.exe_guest, a.join("prog"), "{mode}: the reached file");
                assert_eq!(st.exe_host, mode == "outside", "{mode}: a host path only outside the view");
            }
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(false));
            p.move_to(&b);
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/exe"));
            assert_eq!(opened(mode, &r), Ok(file_id(&a.join("prog"))), "{mode}: /proc/self/exe after P moved");
            let mut buf = [0u8; 4096];
            let r = dispatch(&tool, &mut g, readlinkat_call(c"/proc/self/exe", &mut buf));
            assert_eq!(
                readlinked(&r, &buf),
                Ok(a.join("prog").as_os_str().as_encoded_bytes().to_vec()),
                "{mode}: readlink /proc/self/exe"
            );
            take_reports();
            set_dispatch_read(None);
            drop(p);
            if mode == "outside" {
                std::fs::remove_dir(&root).unwrap();
            }
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// An execve whose host path, with its NUL, is
    /// longer than PATH_MAX is ENAMETOOLONG (the kernel's getname answer
    /// for such a name), with nothing staged or injected; one exactly
    /// PATH_MAX long is staged and injected. The guest's names are legal
    /// (the root makes the host path longer). The thread's 4096-byte page
    /// ends where an inaccessible page begins, so a write past it fails
    /// rather than lands; and scratch_write_at refuses any write that would
    /// end past the 4096 bytes. The hardware page is the kernel's, and on a
    /// smaller one the 16 KiB and 64 KiB layouts too, where the thread's
    /// page is the last 4096 bytes of a hardware page.
    #[test]
    fn execve_host_path_over_path_max_is_enametoolong() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        super::super::LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        let root = unit_dir();
        // The scratch page, a logical 4096 bytes whatever the hardware page.
        let slot = 4096usize;
        let max = libc::PATH_MAX as usize;
        // A guest name whose host path (root + name) is `host_len` bytes.
        let name_for = |host_len: usize| {
            let mut name = String::new();
            let want = host_len - root.as_os_str().len();
            while name.len() + 201 < want {
                name.push('/');
                name.push_str(&"d".repeat(200));
            }
            name.push('/');
            name.push_str(&"p".repeat(want - name.len()));
            name
        };
        let host_page = super::super::page_size();
        let mut pages = vec![host_page];
        pages.extend([16384usize, 65536].into_iter().filter(|p| *p > host_page && p % host_page == 0));
        for page in pages {
            // SAFETY: a fresh anonymous mapping, its second `page` bytes
            // made inaccessible; unmapped below.
            let map = unsafe {
                libc::mmap(std::ptr::null_mut(), 2 * page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
            };
            assert_ne!(map, libc::MAP_FAILED, "{page}: mmap");
            assert_eq!(unsafe { libc::mprotect(map.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) }, 0, "{page}: mprotect");
            let addr = map as usize + page - slot;
            for (host_len, refused) in [(max, true), (max - 1, false)] {
                let what = format!("{page}-byte pages, {host_len}+NUL");
                let name = name_for(host_len);
                assert!(name.len() < max, "the guest's name is legal");
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                let mut g = RecordingGuest::new(ptrace_cfg(&root));
                // The thread's page ends at the inaccessible one.
                use reverie::syscalls::MemoryAccess as _;
                let mut byte = [0u8; 1];
                let at = |a: usize| reverie::syscalls::Addr::<u8>::from_raw(a).unwrap();
                assert!(g.memory().read_exact(at(addr + slot - 1), &mut byte).is_ok(), "{what}: the page's last byte");
                assert!(g.memory().read_exact(at(addr + slot), &mut byte).is_err(), "{what}: the next byte faults");
                let image = tool.state.lock().unwrap().scratch_image;
                g.thread_state_mut().scratch = Some(super::super::ScratchPage { addr, image });
                let c = std::ffi::CString::new(name).unwrap();
                if refused {
                    let r = dispatch(&tool, &mut g, execve_call(&c));
                    assert_eq!(errno(&r), Some(Errno::ENAMETOOLONG), "{what}: ENAMETOOLONG");
                    assert!(g.injected().is_empty(), "{what}: nothing injected");
                } else {
                    g.expect([err(Errno::ENOEXEC)]);
                    let r = dispatch(&tool, &mut g, execve_call(&c));
                    assert_eq!(errno(&r), Some(Errno::ENOEXEC), "{what}: staged, the scripted answer");
                    let call = g.injected();
                    assert_eq!(call.len(), 1);
                    assert_eq!((call[0].0, call[0].1[0] as usize), (Sysno::execve, addr), "{what}: staged at the page");
                }
                if refused {
                    let past = run(tool.scratch_write_at(&mut g, &[1u8; 8], slot - 4));
                    assert_eq!(errno(&past.map(|a| a as i64)), Some(Errno::ENAMETOOLONG), "{what}: a write ending past the page");
                    assert_eq!(run(tool.scratch_write_at(&mut g, &[1u8; 8], slot - 8)).ok(), Some(addr + slot - 8), "{what}: an exact fit");
                }
                take_reports();
            }
            unsafe { libc::munmap(map, 2 * page) };
        }
        std::fs::remove_dir(&root).unwrap();
    }

    /// A failed execve (through /proc/P/cwd, on each
    /// route above) leaves the process's exe as it was, host flag included,
    /// and its argv, as the kernel leaves them: the record, the bare-pid
    /// maps, and what open and readlink of /proc/self/exe answer. The prior
    /// host flag is the opposite of what the attempted exec would record.
    #[test]
    fn failed_execve_keeps_the_prior_exe_and_argv() {
        let _lane = serial();
        let _off = DispatchOff;
        let _seam = IdentitySeam;
        take_reports();
        super::super::LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        let (base, a, _b) = trees();
        let (dir, before) = exe_file();
        let pid = std::process::id() as i32;
        for mode in ["spliced", "literal", "outside"] {
            let p = Other::start(&a);
            let root = if mode == "outside" { unit_dir() } else { PathBuf::from("/") };
            let mut scratch = Scratch::new();
            let tool = tool_with(&mut scratch);
            // Inside the view: the host file, recorded as a host path. Outside
            // it: a file under that root, recorded by its guest name.
            let prior_host = mode != "outside";
            let (prior, prior_file) = if prior_host {
                (before.clone(), before.clone())
            } else {
                std::fs::write(root.join("prior"), b"x").unwrap();
                (PathBuf::from("/prior"), root.join("prior"))
            };
            {
                let mut st = tool.state.lock().unwrap();
                st.cwd = PathBuf::from("/");
                st.exe_guest = prior.clone();
                st.exe_host = prior_host;
                st.argv = vec![b"before".to_vec()];
            }
            super::super::pid_exe_map().lock().unwrap().insert(pid, prior.clone());
            super::super::pid_argv_map().lock().unwrap().remove(&pid);
            let cfg = LiterootConfig { binds: vec![("/proc".into(), "/proc".into(), false)], ..ptrace_cfg(&root) };
            set_dispatch_read(Some(Ok(false)));
            let mut g = RecordingGuest::new(cfg);
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(mode == "literal"));
            let prog = cstr(&PathBuf::from(format!("/proc/{}/cwd/prog", p.pid())));
            g.expect([err(Errno::ENOEXEC)]);
            let r = dispatch(&tool, &mut g, execve_call(&prog));
            assert_eq!(errno(&r), Some(Errno::ENOEXEC), "{mode}: the scripted answer");
            assert_eq!(g.injected().last().map(|(nr, _)| *nr), Some(Sysno::execve), "{mode}: the exec was injected");
            {
                let st = tool.state.lock().unwrap();
                assert_eq!(st.exe_guest, prior, "{mode}: the prior exe");
                assert_eq!(st.exe_host, prior_host, "{mode}: the prior host flag");
                assert_eq!(st.argv, vec![b"before".to_vec()], "{mode}: the prior argv");
            }
            assert_eq!(super::super::pid_exe_map().lock().unwrap().get(&pid), Some(&prior), "{mode}: pid_exe_map");
            assert_eq!(super::super::pid_argv_map().lock().unwrap().get(&pid), None, "{mode}: pid_argv_map");
            assert!(g.thread_state.pending.is_none(), "{mode}: no snapshot left staged");
            super::super::LINK_IDENTITY_FAILS.with(|s| s.set(false));
            g.native_rest = true;
            let r = dispatch(&tool, &mut g, openat_call(c"/proc/self/exe"));
            assert_eq!(opened(mode, &r), Ok(file_id(&prior_file)), "{mode}: /proc/self/exe is the prior file");
            let mut buf = [0u8; 4096];
            let r = dispatch(&tool, &mut g, readlinkat_call(c"/proc/self/exe", &mut buf));
            assert_eq!(
                readlinked(&r, &buf),
                Ok(prior.as_os_str().as_encoded_bytes().to_vec()),
                "{mode}: readlink /proc/self/exe names the prior file"
            );
            super::super::pid_exe_map().lock().unwrap().remove(&pid);
            take_reports();
            set_dispatch_read(None);
            drop(p);
            if mode == "outside" {
                std::fs::remove_file(&prior_file).unwrap();
                std::fs::remove_dir(&root).unwrap();
            }
        }
        std::fs::remove_file(&before).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }
}

/// The guest's own views (§4.9.8), on a root that is not the host's, with
/// /proc bound: cmdline is synthesized (a memfd), exe is the guest's exe,
/// root is the guest root (and a name under it the guest's), and cwd is the
/// kernel's, on every own naming (by pid, by a thread id normalized to its
/// thread group, self, thread-self, task/<tid>), plain, through a symlink,
/// from a dirfd on /proc or /proc/<pid>, and relative to a cwd of
/// /proc/<pid>. Another process's entries are the kernel's (owner directive
/// 2026-11-14), on readlink and open.
mod own_views {
    use super::a1_units::*;
    use super::*;

    /// What a cell answers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Want<'a> {
        /// The caller's own argv, in literoot's memfd.
        OwnArgv,
        /// A descriptor on this host file.
        File(&'a Path),
        /// What a native open of the same host path gives in this thread.
        Native,
    }

    /// The test's own `Seccomp_filters` count (the in-guest baseline).
    fn own_filter_count() -> u32 {
        let text = std::fs::read_to_string("/proc/self/status").unwrap();
        crate::dead_base::status_field(text.as_bytes(), b"Seccomp_filters").unwrap() as u32
    }

    /// A Tool and guest on `root` with /proc bound, the guest exe `/app`,
    /// and the guest cwd `cwd`.
    fn on_root(scratch: &mut Scratch, root: &Path, ptrace: bool, cwd: &str) -> (Arc<RootfsTool>, RecordingGuest) {
        let tool = tool_with(scratch);
        {
            let mut st = tool.state.lock().unwrap();
            st.cwd = PathBuf::from(cwd);
            st.exe_guest = PathBuf::from("/app");
        }
        let base = if ptrace { ptrace_cfg(root) } else { inguest_cfg(root) };
        let cfg = LiterootConfig {
            binds: vec![("/proc".into(), "/proc".into(), false)],
            initial_argv: vec!["caller-argv".into()],
            ..base
        };
        let mut g = RecordingGuest::new(cfg);
        g.native_rest = true;
        (tool, g)
    }

    /// One cell: dispatch `call` and assert `want` (`host` is the host path
    /// a native open compares with).
    #[allow(clippy::too_many_arguments)]
    fn cell(label: &str, root: &Path, ptrace: bool, cwd: &str, call: Syscall, host: &str, want: Want<'_>) {
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_root(&mut scratch, root, ptrace, cwd);
        let r = dispatch(&tool, &mut g, call);
        let reports = take_reports();
        match want {
            Want::OwnArgv => {
                let fd = r.ok().unwrap_or_else(|| panic!("{label}: a descriptor")) as i32;
                let got = read_memfd(label, fd);
                assert!(got == b"caller-argv\0", "{label}: read {} bytes, expected the caller's 12", got.len());
            }
            Want::File(file) => {
                assert_eq!(opened(label, &r), native(file.to_str().unwrap()), "{label}: {file:?}");
            }
            Want::Native => {
                assert_eq!(opened(label, &r), native(host), "{label}: the kernel's answer");
            }
        }
        assert!(reports.is_empty(), "{label}: reports {reports:?}");
    }

    /// Run `f` on a thread of its own (CLONE_FS unshared) whose cwd is
    /// `<root>/work`, with the dispatch-read seam OFF and, in-guest, the
    /// filter baseline set.
    fn in_root_thread(root: &Path, f: impl FnOnce() + Send) {
        let own = own_filter_count();
        std::thread::scope(|s| {
            s.spawn(|| {
                // SAFETY: CLONE_FS only: this thread gets its own cwd and root.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_FS) }, 0, "unshare(CLONE_FS)");
                std::env::set_current_dir(root.join("work")).unwrap();
                set_dispatch_read(Some(Ok(false)));
                super::super::set_filter_baseline(own);
                f();
                super::super::set_filter_baseline(u32::MAX);
                set_dispatch_read(None);
            })
            .join()
            .unwrap()
        })
    }

    #[test]
    fn own_views_on_every_naming() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::create_dir(root.join("links")).unwrap();
        std::fs::write(root.join("app"), b"x").unwrap();
        let (root_s, app) = (root.clone(), root.join("app"));
        in_root_thread(&root, || {
            let pid = std::process::id() as i32;
            let tid = unsafe { libc::gettid() };
            assert_ne!(tid, pid, "the unit needs a non-leader thread");
            let entries: [(&str, Want<'_>); 5] = [
                ("cmdline", Want::OwnArgv),
                ("exe", Want::File(&app)),
                ("root", Want::File(&root_s)),
                ("root/app", Want::File(&app)),
                ("cwd", Want::Native),
            ];
            let how = [libc::O_RDONLY as u64, 0, 0];
            let mut next_link = 0;
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                for (entry, want) in entries {
                    // (naming label, guest path = host path under the bind)
                    let namings = [
                        ("/proc/<pid>", format!("/proc/{pid}/{entry}")),
                        ("/proc/<pid>/task/<tid>", format!("/proc/{pid}/task/{tid}/{entry}")),
                        ("/proc/self", format!("/proc/self/{entry}")),
                        ("/proc/thread-self", format!("/proc/thread-self/{entry}")),
                        ("/proc/self/task/<tid>", format!("/proc/self/task/{tid}/{entry}")),
                        ("/proc/<tid>", format!("/proc/{tid}/{entry}")),
                        ("/proc/<tid>/task/<tid>", format!("/proc/{tid}/task/{tid}/{entry}")),
                    ];
                    for (naming, path) in namings {
                        let c = std::ffi::CString::new(path.clone()).unwrap();
                        next_link += 1;
                        let link = format!("/links/l{next_link}");
                        std::os::unix::fs::symlink(&path, root_s.join(&link[1..])).unwrap();
                        let lc = std::ffi::CString::new(link).unwrap();
                        let arms: Vec<(&str, Syscall, Syscall)> = vec![
                            ("openat", openat_call(&c), openat_call(&lc)),
                            ("openat2", openat2_call(&c, &how), openat2_call(&lc, &how)),
                        ];
                        #[cfg(target_arch = "x86_64")]
                        let arms = {
                            let mut arms = arms;
                            arms.push(("open", open_call(&c), open_call(&lc)));
                            arms
                        };
                        for (arm, plain, through) in arms {
                            let label = format!("{arm} {config} own {naming}/{entry}");
                            cell(&label, &root_s, ptrace, "/work", plain, &path, want);
                            let label = format!("{arm} {config} own symlink to {naming}/{entry}");
                            cell(&label, &root_s, ptrace, "/work", through, &path, want);
                        }
                    }
                    // A dirfd on /proc/<pid> and on /proc (openat, openat2),
                    // and a cwd of /proc/<pid> (every arm).
                    let host = format!("/proc/{pid}/{entry}");
                    let at_pid = std::fs::File::open(format!("/proc/{pid}")).unwrap();
                    let at_proc = std::fs::File::open("/proc").unwrap();
                    let (fd_pid, fd_proc) = (
                        std::os::unix::io::AsRawFd::as_raw_fd(&at_pid),
                        std::os::unix::io::AsRawFd::as_raw_fd(&at_proc),
                    );
                    let rel = std::ffi::CString::new(entry).unwrap();
                    let under = std::ffi::CString::new(format!("{pid}/{entry}")).unwrap();
                    let forms: Vec<(&str, &str, Syscall)> = vec![
                        ("openat", "dirfd /proc/<pid>", openat_at(fd_pid, &rel, libc::O_RDONLY)),
                        ("openat", "dirfd /proc", openat_at(fd_proc, &under, libc::O_RDONLY)),
                        ("openat2", "dirfd /proc/<pid>", openat2_at(fd_pid, &rel, &how)),
                        ("openat2", "dirfd /proc", openat2_at(fd_proc, &under, &how)),
                        ("openat", "cwd /proc/<pid>", openat_call(&rel)),
                        ("openat2", "cwd /proc/<pid>", openat2_call(&rel, &how)),
                    ];
                    #[cfg(target_arch = "x86_64")]
                    let forms = {
                        let mut forms = forms;
                        forms.push(("open", "cwd /proc/<pid>", open_call(&rel)));
                        forms
                    };
                    for (arm, form, call) in forms {
                        let cwd = if form.starts_with("cwd") { format!("/proc/{pid}") } else { "/work".to_owned() };
                        let label = format!("{arm} {config} own {form} {entry}");
                        cell(&label, &root_s, ptrace, &cwd, call, &host, want);
                    }
                }
            }
        });
        for entry in std::fs::read_dir(root.join("links")).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(root.join("links")).unwrap();
        std::fs::remove_dir(root.join("work")).unwrap();
        std::fs::remove_file(root.join("app")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// Another process (the test's parent, the same uid, never owned): its
    /// exe, cwd, root, cmdline, environ and maps open as the kernel opens
    /// them, by pid and by its task directory, plain and through a symlink;
    /// readlink of its exe, cwd, root and fd/0 is the kernel's; and an
    /// O_PATH open of its fd/0 names the kernel's object. Nothing is
    /// refused (owner directive 2026-11-14).
    #[test]
    fn other_process_is_native() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::create_dir(root.join("links")).unwrap();
        std::fs::write(root.join("app"), b"x").unwrap();
        let root_s = root.clone();
        in_root_thread(&root, || {
            let parent = unsafe { libc::getppid() };
            let how = [libc::O_RDONLY as u64, 0, 0];
            let mut next_link = 0;
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                for entry in ["exe", "cwd", "root", "cmdline", "environ", "maps"] {
                    for path in [format!("/proc/{parent}/{entry}"), format!("/proc/{parent}/task/{parent}/{entry}")] {
                        let c = std::ffi::CString::new(path.clone()).unwrap();
                        next_link += 1;
                        let link = format!("/links/o{next_link}");
                        std::os::unix::fs::symlink(&path, root_s.join(&link[1..])).unwrap();
                        let lc = std::ffi::CString::new(link).unwrap();
                        for (arm, call) in [
                            ("openat", openat_call(&c)),
                            ("openat2", openat2_call(&c, &how)),
                            ("openat symlink", openat_call(&lc)),
                        ] {
                            let label = format!("{arm} {config} other {path}");
                            cell(&label, &root_s, ptrace, "/work", call, &path, Want::Native);
                        }
                    }
                }
                for entry in ["exe", "cwd", "root", "fd/0"] {
                    let path = format!("/proc/{parent}/{entry}");
                    let c = std::ffi::CString::new(path.clone()).unwrap();
                    let mut scratch = Scratch::new();
                    let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                    let mut buf = [0u8; 4096];
                    let r = dispatch(&tool, &mut g, readlinkat_call(&c, &mut buf));
                    let want = native_readlink(&path);
                    // A target under the guest root reads back in the guest's
                    // form; every other target is the kernel's text.
                    if let Ok(t) = &want {
                        assert!(!Path::new(std::str::from_utf8(t).unwrap_or("")).starts_with(&root_s), "{path}");
                    }
                    assert_eq!(readlinked(&r, &buf), want, "readlink {config} other {path}");
                    assert!(take_reports().is_empty(), "readlink {config} other {path}");
                }
                let path = format!("/proc/{parent}/fd/0");
                let c = std::ffi::CString::new(path.clone()).unwrap();
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                let r = dispatch(&tool, &mut g, openat_at(libc::AT_FDCWD, &c, libc::O_PATH));
                let native_path = {
                    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                    if fd < 0 {
                        Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)))
                    } else {
                        let id = dev_ino(fd);
                        close(fd);
                        Ok(id)
                    }
                };
                assert_eq!(opened("O_PATH fd/0", &r), native_path, "O_PATH {config} other fd/0");
                assert!(take_reports().is_empty(), "O_PATH {config} other fd/0");
            }
        });
        for entry in std::fs::read_dir(root.join("links")).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(root.join("links")).unwrap();
        std::fs::remove_dir(root.join("work")).unwrap();
        std::fs::remove_file(root.join("app")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// A readlink answer as bytes, through the handler.
    fn readlink_via(root: &Path, ptrace: bool, path: &str) -> Result<Vec<u8>, Errno> {
        let c = std::ffi::CString::new(path).unwrap();
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_root(&mut scratch, root, ptrace, "/work");
        let mut buf = [0u8; 4096];
        let r = dispatch(&tool, &mut g, readlinkat_call(&c, &mut buf));
        let got = readlinked(&r, &buf);
        assert!(take_reports().is_empty(), "readlink {path}");
        got
    }

    /// The guest's own links are answered by their owner, whatever the
    /// naming: a numeric pid or tid reads as /proc/self or /proc/thread-self
    /// does; cwd and a directory fd/<n> give guest paths; root is "/"
    /// (before this change, the host rootfs path: a disclosed change).
    #[test]
    fn own_numeric_readlink_is_reversed() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        let root_s = root.clone();
        in_root_thread(&root, || {
            let pid = std::process::id() as i32;
            let tid = unsafe { libc::gettid() };
            let dir = std::fs::File::open(root_s.join("work")).unwrap();
            let n = std::os::unix::io::AsRawFd::as_raw_fd(&dir);
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                for naming in [format!("/proc/{tid}"), format!("/proc/{pid}/task/{tid}"), "/proc/thread-self".to_owned()] {
                    assert_eq!(readlink_via(&root_s, ptrace, &format!("{naming}/cwd")), Ok(b"/work".to_vec()), "{config} {naming}/cwd");
                }
                for naming in [format!("/proc/{pid}"), format!("/proc/{tid}"), "/proc/self".to_owned()] {
                    assert_eq!(readlink_via(&root_s, ptrace, &format!("{naming}/fd/{n}")), Ok(b"/work".to_vec()), "{config} {naming}/fd/{n}");
                    assert_eq!(readlink_via(&root_s, ptrace, &format!("{naming}/root")), Ok(b"/".to_vec()), "{config} {naming}/root");
                }
                // The process cwd (the leader's) reads the same by pid as by self.
                assert_eq!(
                    readlink_via(&root_s, ptrace, &format!("/proc/{pid}/cwd")),
                    readlink_via(&root_s, ptrace, "/proc/self/cwd"),
                    "{config}: /proc/<pid>/cwd as /proc/self/cwd"
                );
            }
            drop(dir);
        });
        std::fs::remove_dir(root.join("work")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// The caller's own exe link opened without following
    /// is the link, as natively: O_NOFOLLOW gives ELOOP, O_PATH|O_NOFOLLOW
    /// names the link itself (a symlink, the native object), and
    /// O_CREAT|O_EXCL gives EEXIST; a follow still opens the
    /// guest's exe. Without /proc in the view, where literoot presents the
    /// link, O_NOFOLLOW is ELOOP.
    #[test]
    fn own_exe_nofollow_is_the_link() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::write(root.join("app"), b"x").unwrap();
        let (root_s, app) = (root.clone(), root.join("app"));
        in_root_thread(&root, || {
            let pid = std::process::id() as i32;
            let open_native = |path: &str, flags: i32| {
                let c = std::ffi::CString::new(path).unwrap();
                let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
                if fd < 0 {
                    return Err(Errno::new(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
                }
                let id = dev_ino(fd);
                close(fd);
                Ok(id)
            };
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                for path in ["/proc/self/exe".to_owned(), format!("/proc/{pid}/exe")] {
                    let c = std::ffi::CString::new(path.clone()).unwrap();
                    for (what, flags) in [
                        ("O_NOFOLLOW", libc::O_RDONLY | libc::O_NOFOLLOW),
                        ("O_PATH|O_NOFOLLOW", libc::O_PATH | libc::O_NOFOLLOW),
                        ("O_CREAT|O_EXCL", libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL),
                    ] {
                        let mode = if flags & libc::O_CREAT != 0 { 0o600 } else { 0 };
                        let how = [flags as u64, mode, 0];
                        let arms: Vec<(&str, Syscall)> =
                            vec![("openat", openat_at(libc::AT_FDCWD, &c, flags)), ("openat2", openat2_call(&c, &how))];
                        #[cfg(target_arch = "x86_64")]
                        let arms = {
                            let mut arms = arms;
                            arms.push(("open", open_with(&c, flags)));
                            arms
                        };
                        for (arm, call) in arms {
                            let label = format!("{arm} {config} {path} {what}");
                            let mut scratch = Scratch::new();
                            let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                            let r = dispatch(&tool, &mut g, call);
                            assert_eq!(opened(&label, &r), open_native(&path, flags), "{label}: native");
                            assert!(take_reports().is_empty(), "{label}");
                        }
                    }
                    let label = format!("{config} {path} follow");
                    cell(&label, &root_s, ptrace, "/work", openat_call(&c), &path, Want::File(&app));
                }
                // No /proc in the view: the presented link is not followed.
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                tool.state.lock().unwrap().exe_guest = PathBuf::from("/app");
                let base = if ptrace { ptrace_cfg(&root_s) } else { inguest_cfg(&root_s) };
                let mut g = RecordingGuest::new(base);
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat_at(libc::AT_FDCWD, c"/proc/self/exe", libc::O_RDONLY | libc::O_NOFOLLOW));
                assert_eq!(errno(&r), Some(Errno::ELOOP), "{config}: no /proc, O_NOFOLLOW");
            }
        });
        std::fs::remove_dir(root.join("work")).unwrap();
        std::fs::remove_file(root.join("app")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// The own fd/<n>, map_files/<k> and traversal cells.
    /// A directory fd/<n> opens that directory; a regular-file fd/<n> opens
    /// that file; map_files/<k> is the kernel's (and ENOENT under
    /// task/<tid>, as natively); cwd/x and fd/<n>/x continue from the guest
    /// path, on every naming that names this thread's cwd or the process's
    /// table.
    #[test]
    fn own_fd_map_files_and_traversal() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::write(root.join("work/x"), b"x").unwrap();
        std::fs::write(root.join("plain"), b"p").unwrap();
        let root_s = root.clone();
        in_root_thread(&root, || {
            let pid = std::process::id() as i32;
            let tid = unsafe { libc::gettid() };
            let dir = std::fs::File::open(root_s.join("work")).unwrap();
            let file = std::fs::File::open(root_s.join("plain")).unwrap();
            let (nd, nf) = (
                std::os::unix::io::AsRawFd::as_raw_fd(&dir),
                std::os::unix::io::AsRawFd::as_raw_fd(&file),
            );
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let range = maps.lines().next().unwrap().split_whitespace().next().unwrap().to_owned();
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                let table = [format!("/proc/{pid}"), format!("/proc/{tid}"), "/proc/self".to_owned(), "/proc/thread-self".to_owned()];
                for naming in &table {
                    let w = root_s.join("work");
                    let p = root_s.join("plain");
                    let x = root_s.join("work/x");
                    let cells: [(String, Want<'_>); 4] = [
                        (format!("{naming}/fd/{nd}"), Want::File(&w)),
                        (format!("{naming}/fd/{nf}"), Want::File(&p)),
                        (format!("{naming}/fd/{nd}/x"), Want::File(&x)),
                        (format!("{naming}/map_files/{range}"), Want::Native),
                    ];
                    for (path, want) in cells {
                        let c = std::ffi::CString::new(path.clone()).unwrap();
                        cell(&format!("{config} {path}"), &root_s, ptrace, "/work", openat_call(&c), &path, want);
                    }
                }
                for naming in [format!("/proc/{tid}"), format!("/proc/{pid}/task/{tid}"), "/proc/thread-self".to_owned()] {
                    let x = root_s.join("work/x");
                    let path = format!("{naming}/cwd/x");
                    let c = std::ffi::CString::new(path.clone()).unwrap();
                    cell(&format!("{config} {path}"), &root_s, ptrace, "/work", openat_call(&c), &path, Want::File(&x));
                }
                let path = format!("/proc/{pid}/task/{tid}/map_files/{range}");
                assert_eq!(native(&path), Err(Errno::ENOENT), "no map_files under task/<tid> (precondition)");
                let c = std::ffi::CString::new(path.clone()).unwrap();
                cell(&format!("{config} {path}"), &root_s, ptrace, "/work", openat_call(&c), &path, Want::Native);
            }
            drop((dir, file));
        });
        std::fs::remove_file(root.join("work/x")).unwrap();
        std::fs::remove_file(root.join("plain")).unwrap();
        std::fs::remove_dir(root.join("work")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// A child the unit starts and ends itself: its cwd `<root>/work` and
    /// its descriptor 3 on that directory.
    struct Child(std::process::Child);

    impl Child {
        fn start(root: &Path) -> Self {
            use std::io::BufRead as _;
            let mut child = std::process::Command::new("sh")
                .args(["-c", "cd \"$1/work\" && exec 3<\"$1/work\" && echo ready && read x", "sh"])
                .arg(root)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("sh");
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "ready");
            Child(child)
        }
    }

    impl Drop for Child {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }

    /// Guest children are guest processes: with a
    /// row, a child's root continues from the guest root, its cwd from its
    /// guest cwd, and readlink of its cwd, fd/3 and root gives guest paths,
    /// on both configurations (every process judged under the caller's
    /// root, the equal-root case). Control: without a row the
    /// same child is a host process, and its cwd reads as the kernel's.
    #[test]
    fn row_root_cwd_fd_are_the_guests() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::write(root.join("work/x"), b"x").unwrap();
        std::fs::write(root.join("app"), b"a").unwrap();
        let root_s = root.clone();
        let child = Child::start(&root);
        let c = child.0.id() as i32;
        in_root_thread(&root, || {
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                let _rows = Rows::set(vec![row(c, b"/app", &[b"child"])]);
                let (app, x) = (root_s.join("app"), root_s.join("work/x"));
                for (path, want) in [(format!("/proc/{c}/root/app"), Want::File(&app)), (format!("/proc/{c}/cwd/x"), Want::File(&x))] {
                    let cs = std::ffi::CString::new(path.clone()).unwrap();
                    cell(&format!("{config} row {path}"), &root_s, ptrace, "/work", openat_call(&cs), &path, want);
                }
                assert_eq!(readlink_via(&root_s, ptrace, &format!("/proc/{c}/cwd")), Ok(b"/work".to_vec()), "{config} row cwd");
                assert_eq!(readlink_via(&root_s, ptrace, &format!("/proc/{c}/fd/3")), Ok(b"/work".to_vec()), "{config} row fd/3");
                assert_eq!(readlink_via(&root_s, ptrace, &format!("/proc/{c}/root")), Ok(b"/".to_vec()), "{config} row root");
                drop(_rows);
                let path = format!("/proc/{c}/cwd");
                assert_eq!(readlink_via(&root_s, ptrace, &path), native_readlink(&path), "{config} no row: the kernel's");
            }
        });
        drop(child);
        std::fs::remove_file(root.join("work/x")).unwrap();
        std::fs::remove_file(root.join("app")).unwrap();
        std::fs::remove_dir(root.join("work")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// End `child` the way it expects, by closing its stdin. A child still
    /// alive 10 s later fails the unit; it is never killed.
    fn end_child(mut child: Child) {
        drop(child.0.stdin.take());
        for _ in 0..200 {
            if child.0.try_wait().expect("try_wait").is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let pid = child.0.id();
        std::mem::forget(child);
        panic!("child {pid} still alive 10 s after its stdin closed (not killed)");
    }

    /// A host directory S holding `file` (HOST), and the same path under
    /// `root` holding GUEST: the guest's file is returned.
    fn host_and_guest_s(root: &Path) -> (PathBuf, PathBuf) {
        let s = unit_dir();
        std::fs::write(s.join("file"), b"HOST").unwrap();
        let inner = root.join(s.strip_prefix("/").unwrap());
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("file"), b"GUEST").unwrap();
        (s, inner.join("file"))
    }

    /// Run `f` on [`in_root_thread`]'s thread with a descriptor table of its
    /// own too (unshare(CLONE_FILES)), in which `n`, a descriptor of
    /// `<root>/bbb` in the process table (the leader's), is replaced by a
    /// descriptor of `<root>/aaa`.
    fn in_split_table(root: &Path, n: i32, f: impl FnOnce() + Send) {
        let aaa = root.join("aaa");
        in_root_thread(root, move || {
            // SAFETY: CLONE_FILES only: this thread gets its own copy of the
            // descriptor table.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_FILES) },
                0,
                "unshare(CLONE_FILES)"
            );
            let a = std::fs::File::open(&aaa).unwrap();
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&a);
            // SAFETY: both are descriptors of this thread's own table.
            assert_eq!(unsafe { libc::dup2(fd, n) }, n, "dup2 onto {n}");
            drop(a);
            f();
        });
    }

    /// A readlink that fills its buffer is read again whole on the Tool's
    /// side before it is de-translated, and that read names the CALLING
    /// thread's entry. Here the caller's descriptor table is its own:
    /// descriptor N names <root>/aaa in it and <root>/bbb in the process
    /// table. A 2-byte readlink of /proc/thread-self/fd/N answers "/a", the
    /// start of the caller's "/aaa" (the leader's entry would give "/b"), on
    /// both configurations, through readlinkat and, on x86_64, readlink.
    #[test]
    fn truncated_thread_self_readlink_reads_the_callers_table() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        for d in ["work", "aaa", "bbb"] {
            std::fs::create_dir(root.join(d)).unwrap();
        }
        let leaders = std::fs::File::open(root.join("bbb")).unwrap();
        let n = std::os::unix::io::AsRawFd::as_raw_fd(&leaders);
        let root_s = root.clone();
        in_split_table(&root, n, || {
            let path = std::ffi::CString::new(format!("/proc/thread-self/fd/{n}")).unwrap();
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                {
                    let mut scratch = Scratch::new();
                    let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                    let mut buf = [0u8; 2];
                    let r = dispatch(&tool, &mut g, readlinkat_call(&path, &mut buf));
                    assert_eq!(
                        readlinked(&r, &buf),
                        Ok(b"/a".to_vec()),
                        "{config} readlinkat"
                    );
                    assert!(take_reports().is_empty(), "{config} readlinkat");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    let mut scratch = Scratch::new();
                    let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                    let mut buf = [0u8; 2];
                    let call = Syscall::from_raw(
                        Sysno::readlink,
                        SyscallArgs::new(
                            path.as_ptr() as usize,
                            buf.as_mut_ptr() as usize,
                            buf.len(),
                            0,
                            0,
                            0,
                        ),
                    );
                    let r = dispatch(&tool, &mut g, call);
                    assert_eq!(
                        readlinked(&r, &buf),
                        Ok(b"/a".to_vec()),
                        "{config} readlink"
                    );
                    assert!(take_reports().is_empty(), "{config} readlink");
                }
            }
        });
        drop(leaders);
        for d in ["work", "aaa", "bbb"] {
            std::fs::remove_dir(root.join(d)).unwrap();
        }
        std::fs::remove_dir(&root).unwrap();
    }

    /// A walk that continues past /proc/thread-self is in the calling
    /// thread's own task directory: with the caller's descriptor table its
    /// own, /proc/thread-self/fd/N/x opens <root>/aaa/x (the caller's N), not
    /// <root>/bbb/x (the process table's), on both configurations.
    #[test]
    fn thread_self_fd_is_the_callers_table() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        for d in ["work", "aaa", "bbb"] {
            std::fs::create_dir(root.join(d)).unwrap();
        }
        std::fs::write(root.join("aaa/x"), b"A").unwrap();
        std::fs::write(root.join("bbb/x"), b"B").unwrap();
        let leaders = std::fs::File::open(root.join("bbb")).unwrap();
        let n = std::os::unix::io::AsRawFd::as_raw_fd(&leaders);
        let root_s = root.clone();
        in_split_table(&root, n, || {
            let path = format!("/proc/thread-self/fd/{n}/x");
            let c = std::ffi::CString::new(path.clone()).unwrap();
            let x = root_s.join("aaa/x");
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                cell(
                    &format!("{config} {path}"),
                    &root_s,
                    ptrace,
                    "/work",
                    openat_call(&c),
                    &path,
                    Want::File(&x),
                );
            }
        });
        drop(leaders);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A task directory only the guest has stays in procfs: the guest here
    /// is a process of its own (a child, C, whose task directory the
    /// Tool's /proc/self does not have), and
    /// /proc/self/task/<C>/../<C>/root/S/file is walked in the guest's
    /// procfs view, the ".." included, to the guest root: <root>/S/file,
    /// not the Tool's view (ENOENT) or a literal tail for the kernel.
    #[test]
    fn guest_only_task_dir_and_parent_stay_in_procfs() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        let (s, file) = host_and_guest_s(&root);
        let child = Child::start(&root);
        let c = child.0.id() as i32;
        let root_s = root.clone();
        let path = format!("/proc/self/task/{c}/../{c}/root{}/file", s.display());
        in_root_thread(&root, || {
            let cs = std::ffi::CString::new(path.clone()).unwrap();
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                let mut scratch = Scratch::new();
                let (tool, g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                let mut g = g.with_ids(Some(c), Some(c));
                let r = dispatch(&tool, &mut g, openat_call(&cs));
                assert_eq!(
                    opened(config, &r),
                    native(file.to_str().unwrap()),
                    "{config} {path}"
                );
                assert!(take_reports().is_empty(), "{config} {path}");
            }
        });
        end_child(child);
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&s).unwrap();
    }

    /// A planted rootfs `proc` link is an ordinary guest symlink: with no
    /// /proc bind, <root>/proc -> "/proc" resolves inside the guest root to
    /// itself, so proc/self/root/S/file loops to ELOOP, as natively in a
    /// chroot at <root>; it never reaches the host's procfs.
    #[test]
    fn planted_rootfs_proc_link_loops_in_the_guest() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::os::unix::fs::symlink("/proc", root.join("proc")).unwrap();
        let (s, _) = host_and_guest_s(&root);
        let root_s = root.clone();
        let path = format!("proc/self/root{}/file", s.display());
        in_root_thread(&root, || {
            let cs = std::ffi::CString::new(path.clone()).unwrap();
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                let mut scratch = Scratch::new();
                let tool = tool_with(&mut scratch);
                tool.state.lock().unwrap().cwd = PathBuf::from("/");
                let mut g = RecordingGuest::new(if ptrace {
                    ptrace_cfg(&root_s)
                } else {
                    inguest_cfg(&root_s)
                });
                g.native_rest = true;
                let r = dispatch(&tool, &mut g, openat_call(&cs));
                assert_eq!(opened(config, &r), Err(Errno::ELOOP), "{config} {path}");
                assert!(take_reports().is_empty(), "{config} {path}");
            }
        });
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&s).unwrap();
    }

    /// Every reroot at the guest's own `root` link is one link of the
    /// walk's 40, as natively (each magic link is a followed link, and the
    /// 41st fails): "/proc/<pid>/root" 40 times, then S/file, opens
    /// <root>/S/file; 41 times is ELOOP. On both configurations.
    #[test]
    fn own_root_reroots_charge_the_link_budget() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        let (s, file) = host_and_guest_s(&root);
        let root_s = root.clone();
        in_root_thread(&root, || {
            let link = format!("/proc/{}/root", std::process::id());
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                for (reroots, want) in [
                    (40, native(file.to_str().unwrap())),
                    (41, Err(Errno::ELOOP)),
                ] {
                    let label = format!("{config}: {reroots} reroots");
                    let path = format!("{}{}/file", link.repeat(reroots), s.display());
                    let cs = std::ffi::CString::new(path).unwrap();
                    let mut scratch = Scratch::new();
                    let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                    let r = dispatch(&tool, &mut g, openat_call(&cs));
                    assert_eq!(opened(&label, &r), want, "{label}");
                    assert!(take_reports().is_empty(), "{label}");
                }
            }
        });
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&s).unwrap();
    }

    /// An ordinary directory bound at /proc/self/root is that directory, not
    /// procfs's magic link: the walk classifies the host path it selected
    /// (the bind's), so /proc/self/root/x opens H/x, not <root>/x. On both
    /// configurations. (Only the spelling `self` matches such a bind, a
    /// guest-path prefix as in proot; /proc/<pid>/root stays the magic link,
    /// a disclosed difference.)
    #[test]
    fn directory_bound_at_self_root_is_ordinary() {
        let _lane = serial();
        take_reports();
        let root = unit_dir();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::write(root.join("x"), b"GUEST").unwrap();
        let h = unit_dir();
        std::fs::write(h.join("x"), b"BOUND").unwrap();
        let (root_s, h_s) = (root.clone(), h.clone());
        in_root_thread(&root, || {
            let path = "/proc/self/root/x";
            let cs = std::ffi::CString::new(path).unwrap();
            for ptrace in [true, false] {
                let config = if ptrace { "ptrace" } else { "in-guest" };
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_root(&mut scratch, &root_s, ptrace, "/work");
                g.cfg
                    .binds
                    .push(("/proc/self/root".into(), h_s.display().to_string(), false));
                let r = dispatch(&tool, &mut g, openat_call(&cs));
                assert_eq!(
                    opened(config, &r),
                    native(h_s.join("x").to_str().unwrap()),
                    "{config} {path}"
                );
                assert!(take_reports().is_empty(), "{config} {path}");
            }
        });
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&h).unwrap();
    }

    /// A 64-bit little-endian ELF header with one program header, PT_INTERP,
    /// naming `interp`: what the Tool's PT_INTERP check reads.
    fn elf_with_interp(interp: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 120];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&1u16.to_le_bytes());
        image[64..68].copy_from_slice(&3u32.to_le_bytes());
        image[72..80].copy_from_slice(&120u64.to_le_bytes());
        image[96..104].copy_from_slice(&(interp.len() as u64 + 1).to_le_bytes());
        image.extend_from_slice(interp);
        image.push(0);
        image
    }

    /// An execve through a rootfs symlink to the calling thread's own
    /// descriptor (R/link -> /proc/thread-self/fd/N) reads the image that
    /// descriptor names, as the kernel does: the walk hands the literal
    /// thread-self path to the Tool's shebang and PT_INTERP checks, which
    /// must read the caller's entry, not the thread group leader's. Here N
    /// names, in the caller's own table, a script ("#!/loop") or an ELF
    /// whose PT_INTERP is "/loop", and in the leader's table a plain file.
    /// /loop is a symlink to itself, so the answer is the interpreter's
    /// ELOOP and nothing is executed. Reading the leader's plain file, the
    /// Tool would execute it (here a scripted ENOEXEC). Ptrace only:
    /// in-guest exec is refused by name.
    #[test]
    fn execve_through_thread_self_reads_the_callers_image() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        super::super::LAUNCHER_EXEC_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        let pid = std::process::id() as i32;
        let images = [
            ("script", b"#!/loop\n".to_vec()),
            ("elf", elf_with_interp(b"/loop")),
        ];
        for (what, image) in images {
            let root = unit_dir();
            std::fs::create_dir(root.join("work")).unwrap();
            std::fs::write(root.join("aaa"), &image).unwrap();
            std::fs::write(root.join("bbb"), b"plain\n").unwrap();
            std::os::unix::fs::symlink("/loop", root.join("loop")).unwrap();
            let leaders = std::fs::File::open(root.join("bbb")).unwrap();
            let n = std::os::unix::io::AsRawFd::as_raw_fd(&leaders);
            let target = format!("/proc/thread-self/fd/{n}");
            std::os::unix::fs::symlink(&target, root.join("link")).unwrap();
            let root_s = root.clone();
            in_split_table(&root, n, || {
                set_dispatch_read(Some(Ok(false)));
                let mut scratch = Scratch::new();
                let (tool, mut g) = on_root(&mut scratch, &root_s, true, "/work");
                g.native_rest = false;
                g.expect([err(Errno::ENOEXEC)]);
                let link = c"/link".as_ptr() as usize;
                let call = Syscall::from_raw(Sysno::execve, SyscallArgs::new(link, 0, 0, 0, 0, 0));
                let r = dispatch(&tool, &mut g, call);
                assert_eq!(
                    errno(&r),
                    Some(Errno::ELOOP),
                    "{what}: the interpreter's ELOOP"
                );
                let injected = g.injected();
                let execs = injected
                    .iter()
                    .filter(|(nr, _)| *nr == Sysno::execve)
                    .count();
                assert_eq!(execs, 0, "{what}: the leader's plain file is not executed");
                set_dispatch_read(None);
            });
            take_reports();
            drop(leaders);
            super::super::pid_argv_map().lock().unwrap().remove(&pid);
            super::super::pid_exe_map().lock().unwrap().remove(&pid);
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}

/// Fix 4's recovered route: a relative final symlink reached through a ".."
/// out of a deleted directory resolves from the guest directory the climb
/// landed on, never from the link's host parent. A unit directory P holds
/// the guest root R = P/root, and decoys beside R on the host side that a
/// host-side join would reach.
mod route_units {
    use super::a1_units::*;
    use super::*;

    struct Tree {
        p: PathBuf,
        root: PathBuf,
        /// A descriptor on R/dd, which is removed.
        d: std::fs::File,
    }

    impl Tree {
        /// R/outside/file holds GUEST (5 bytes), the decoy P/outside/file
        /// HOST-SIDE-MARKER (16 bytes). R/rl -> ../outside/file; R/c1 ->
        /// ../a/l2 and R/a/l2 -> ../../outside/file, with the decoy P/a/l2
        /// -> ../outside/file.
        fn new() -> Self {
            let p = unit_dir();
            let root = p.join("root");
            for d in ["root/outside", "root/a", "root/dd", "outside", "a"] {
                std::fs::create_dir_all(p.join(d)).unwrap();
            }
            std::fs::write(root.join("outside/file"), b"GUEST").unwrap();
            std::fs::write(p.join("outside/file"), b"HOST-SIDE-MARKER").unwrap();
            for (link, target) in [
                ("root/rl", "../outside/file"),
                ("root/c1", "../a/l2"),
                ("root/a/l2", "../../outside/file"),
                ("a/l2", "../outside/file"),
            ] {
                std::os::unix::fs::symlink(target, p.join(link)).unwrap();
            }
            let d = std::fs::File::open(root.join("dd")).unwrap();
            std::fs::remove_dir(root.join("dd")).unwrap();
            Tree { p, root, d }
        }

        fn fd(&self) -> i32 {
            std::os::unix::io::AsRawFd::as_raw_fd(&self.d)
        }

        fn guest_file(&self) -> (u64, u64) {
            file_id(&self.root.join("outside/file"))
        }

        fn decoy(&self) -> (u64, u64) {
            file_id(&self.p.join("outside/file"))
        }

        /// A ptrace Tool and guest on R with the guest cwd "/", whose
        /// injections run natively here.
        fn guest(&self, scratch: &mut Scratch) -> (Arc<RootfsTool>, RecordingGuest) {
            let tool = tool_with(scratch);
            tool.state.lock().unwrap().cwd = PathBuf::from("/");
            let mut g = RecordingGuest::new(ptrace_cfg(&self.root));
            g.native_rest = true;
            (tool, g)
        }

        fn remove(self) {
            drop(self.d);
            std::fs::remove_dir_all(&self.p).unwrap();
        }
    }

    fn file_id(p: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(p).unwrap();
        (md.dev(), md.ino())
    }

    /// Run `f` on a thread with a cwd of its own (CLONE_FS unshared) and the
    /// dispatch-read seam OFF, so the dead-base gate admits its probes.
    fn in_own_cwd<R: Send>(f: impl FnOnce() -> R + Send) -> R {
        std::thread::scope(|s| {
            s.spawn(|| {
                // SAFETY: CLONE_FS only: this thread gets its own cwd and root.
                assert_eq!(
                    unsafe { libc::unshare(libc::CLONE_FS) },
                    0,
                    "unshare(CLONE_FS)"
                );
                set_dispatch_read(Some(Ok(false)));
                let r = f();
                set_dispatch_read(None);
                std::env::set_current_dir(std::env::temp_dir()).unwrap();
                r
            })
            .join()
            .unwrap()
        })
    }

    /// openat(D, "../rl"): the climb out of the deleted R/dd lands on the
    /// guest root, and rl's relative target resolves from there, to
    /// R/outside/file, never to the decoy P/outside/file.
    #[test]
    fn dirfd_climb_follows_a_relative_link_in_the_guest() {
        let _lane = serial();
        take_reports();
        let t = Tree::new();
        in_own_cwd(|| {
            let mut scratch = Scratch::new();
            let (tool, mut g) = t.guest(&mut scratch);
            let r = dispatch(&tool, &mut g, openat_at(t.fd(), c"../rl", libc::O_RDONLY));
            let got = opened("openat(D, ../rl)", &r);
            assert_ne!(got, Ok(t.decoy()), "the host sibling P/outside/file");
            assert_eq!(got, Ok(t.guest_file()), "R/outside/file");
            assert!(take_reports().is_empty());
        });
        t.remove();
    }

    /// fchdir(D), then openat(AT_FDCWD, "../rl"): from the deleted cwd the
    /// climb lands on the guest root the same way: R/outside/file.
    #[test]
    fn cwd_climb_follows_a_relative_link_in_the_guest() {
        let _lane = serial();
        take_reports();
        let t = Tree::new();
        in_own_cwd(|| {
            let mut scratch = Scratch::new();
            let (tool, mut g) = t.guest(&mut scratch);
            let fchdir = Syscall::from_raw(
                Sysno::fchdir,
                SyscallArgs::new(t.fd() as usize, 0, 0, 0, 0, 0),
            );
            assert_eq!(dispatch(&tool, &mut g, fchdir).ok(), Some(0), "fchdir(D)");
            let r = dispatch(&tool, &mut g, openat_call(c"../rl"));
            let got = opened("openat(AT_FDCWD, ../rl)", &r);
            assert_ne!(got, Ok(t.decoy()), "the host sibling P/outside/file");
            assert_eq!(got, Ok(t.guest_file()), "R/outside/file");
            assert!(take_reports().is_empty());
        });
        t.remove();
    }

    /// openat(D, "../c1"), a chain of two relative links whose ".." both
    /// reach the guest root: c1 -> ../a/l2 -> ../../outside/file is
    /// R/outside/file. A host-side join would follow the decoy P/a/l2 to
    /// P/outside/file.
    #[test]
    fn climb_follows_a_relative_chain_across_the_guest_root() {
        let _lane = serial();
        take_reports();
        let t = Tree::new();
        in_own_cwd(|| {
            let mut scratch = Scratch::new();
            let (tool, mut g) = t.guest(&mut scratch);
            let r = dispatch(&tool, &mut g, openat_at(t.fd(), c"../c1", libc::O_RDONLY));
            let got = opened("openat(D, ../c1)", &r);
            assert_ne!(got, Ok(t.decoy()), "the host sibling P/outside/file");
            assert_eq!(got, Ok(t.guest_file()), "R/outside/file");
            assert!(take_reports().is_empty());
        });
        t.remove();
    }

    /// The stat-at call (newfstatat on x86_64, fstatat on aarch64) of
    /// (D, "../rl") sees R/outside/file: its inode and its 5 bytes, not the
    /// decoy's 16.
    #[test]
    fn climb_stat_sees_the_guest_file() {
        let _lane = serial();
        take_reports();
        #[cfg(target_arch = "x86_64")]
        let statat = Sysno::newfstatat;
        #[cfg(target_arch = "aarch64")]
        let statat = Sysno::fstatat;
        let t = Tree::new();
        in_own_cwd(|| {
            let mut scratch = Scratch::new();
            let (tool, mut g) = t.guest(&mut scratch);
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let stp = &mut st as *mut libc::stat as usize;
            let name = c"../rl".as_ptr() as usize;
            let call = Syscall::from_raw(
                statat,
                SyscallArgs::new(t.fd() as usize, name, stp, 0, 0, 0),
            );
            assert_eq!(
                dispatch(&tool, &mut g, call).ok(),
                Some(0),
                "stat-at(D, ../rl)"
            );
            let got = (st.st_dev as u64, st.st_ino as u64);
            assert_ne!(got, t.decoy(), "the host sibling P/outside/file");
            assert_eq!(got, t.guest_file(), "R/outside/file");
            assert_eq!(st.st_size, 5, "GUEST's size");
            assert!(take_reports().is_empty());
        });
        t.remove();
    }
}

/// Each thread stages in a scratch page of its own (one page per process
/// would let one thread's staging overwrite another's before
/// the kernel read it).
mod scratch_units {
    use super::a1_units::*;
    use super::*;
    use super::super::ScratchPage;
    use reverie::Tool as _;
    use std::os::unix::ffi::OsStringExt as _;

    const THREAD: u64 = (libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM) as u64;

    fn unlinkat_call(path: &std::ffi::CStr) -> Syscall {
        Syscall::from_raw(
            Sysno::unlinkat,
            SyscallArgs::new(libc::AT_FDCWD as isize as usize, path.as_ptr() as usize, 0, 0, 0, 0),
        )
    }

    /// The pool's size in bytes.
    const POOL_LEN: usize = 4096 * super::super::SCRATCH_POOL;

    /// The answer to a thread's pool mmap: anonymous pages mapped here
    /// (what the Tool's injected mmap asks for), never the call itself.
    fn map_page() -> Answer {
        Answer::Call(Box::new(|| {
            // SAFETY: a fresh anonymous mapping; the unit unmaps it.
            let at = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    POOL_LEN,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(at, libc::MAP_FAILED, "map the pool");
            Ok(at as i64)
        }))
    }

    /// The bytes of the NUL-terminated string at `at`, in this process.
    fn c_str_at(at: u64) -> Vec<u8> {
        // SAFETY: a pointer the Tool staged in this process's memory,
        // NUL-terminated, still mapped.
        unsafe { std::ffi::CStr::from_ptr(at as *const libc::c_char) }.to_bytes().to_vec()
    }

    /// A new thread `tid` of `a`'s process, as A's clone handler and
    /// Reverie make it: the state `init_thread_state` gives it after
    /// `stage_child_files` staged A's decision.
    fn new_thread(tool: &RootfsTool, a: &mut RecordingGuest, tid: i32) -> RecordingGuest {
        tool.stage_child_files(a, THREAD);
        let parent = (reverie::Tid::from_raw(unsafe { libc::gettid() }), a.thread_state());
        let state = tool.init_thread_state(reverie::Tid::from_raw(tid), Some(parent));
        tool.end_child_files(a, true);
        let mut b = RecordingGuest::new(a.cfg.clone()).with_ids(None, Some(tid));
        *b.thread_state_mut() = state;
        b
    }

    /// The forced interleaving: thread A's unlinkat is held at its
    /// injection, after A staged its path, while thread B's whole unlinkat
    /// handler runs (the held-injection closure, no timing). B maps a page
    /// of its own; A's call still names A's path. With one page for both,
    /// B's path overwrites A's and A's unlink names B's file.
    #[test]
    fn threads_stage_in_their_own_pages() {
        let _lane = serial();
        let _off = DispatchOff;
        let _base = Baseline::own();
        take_reports();
        // Names in a fresh unit directory: never executed (every call is
        // answered from the script), never a real system file.
        let dir = unit_dir();
        let a_path = std::ffi::CString::new(dir.join("thread-a-file").into_os_string().into_vec()).unwrap();
        let b_path = std::ffi::CString::new(dir.join("b").into_os_string().into_vec()).unwrap();
        for ptrace in [true, false] {
            let label = if ptrace { "ptrace" } else { "in-guest" };
            let mut scratch = Scratch::new();
            let (tool, mut a) = if ptrace {
                on_host_root_ptrace(&mut scratch, &[])
            } else {
                on_host_root_inguest(&mut scratch, &[])
            };
            let tid = unsafe { libc::gettid() };
            let b = Arc::new(Mutex::new(new_thread(&tool, &mut a, tid + 1)));
            let b_page = Arc::new(Mutex::new(None));
            let held = {
                let (tool, b, b_page, b_path) = (tool.clone(), b.clone(), b_page.clone(), b_path.clone());
                Answer::Call(Box::new(move || {
                    let mut b = b.lock().unwrap();
                    b.expect([map_page(), Answer::Return(Ok(0))]);
                    let r = dispatch(&tool, &mut b, unlinkat_call(&b_path));
                    *b_page.lock().unwrap() = Some((r.ok(), b.thread_state().scratch));
                    Ok(0)
                }))
            };
            a.expect([held]);
            let r = dispatch(&tool, &mut a, unlinkat_call(&a_path));
            assert_eq!(r.ok(), Some(0), "{label}: A completes");
            let a_call = a.injected().into_iter().find(|(nr, _)| *nr == Sysno::unlinkat).expect("A's call");
            let b_events = b.lock().unwrap().injected();
            let b_call = *b_events.iter().find(|(nr, _)| *nr == Sysno::unlinkat).expect("B's call");
            // What A's kernel call reads once it runs, after B's handler.
            assert_eq!(c_str_at(a_call.1[1]), a_path.as_bytes(), "{label}: A's call names A's path");
            assert_eq!(c_str_at(b_call.1[1]), b_path.as_bytes(), "{label}: B's call names B's path");
            let (b_result, b_page) = b_page.lock().unwrap().take().expect("B ran while A's call was held");
            assert_eq!(b_result, Some(0), "{label}: B completes");
            let kinds: Vec<Sysno> = b_events.iter().map(|(nr, _)| *nr).collect();
            assert_eq!(kinds, vec![Sysno::mmap, Sysno::unlinkat], "{label}: B maps its own page, then calls");
            let b_page = b_page.expect("B's page");
            let a_page = a.thread_state().scratch.expect("A's page").addr;
            assert_ne!(b_page.addr, a_page, "{label}: two pages");
            assert_eq!(a_call.1[1] as usize, a_page, "{label}: A staged in A's page");
            assert_eq!(b_call.1[1] as usize, b_page.addr, "{label}: B staged in B's page");
            // SAFETY: B's page, mapped natively above, used by nothing else.
            assert_eq!(unsafe { libc::munmap(b_page.addr as *mut libc::c_void, POOL_LEN) }, 0);
        }
        assert!(take_reports().is_empty());
        std::fs::remove_dir(&dir).unwrap();
    }

    /// An exited thread's page is reused by the next new thread, zeroed
    /// before that thread stages in it; a page of an earlier image (a
    /// thread exec killed) is never reused, nor one page twice.
    #[test]
    fn reused_page_is_zeroed_and_of_this_image() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let mut scratch = Scratch::new();
        let (tool, mut a) = on_host_root_ptrace(&mut scratch, &[]);
        let tid = unsafe { libc::gettid() };
        let mut left = Scratch::new();
        let image = tool.state.lock().unwrap().scratch_image;
        let left_page = ScratchPage { addr: left.addr(), image };
        let exiting = RecordingGuest::new(a.cfg.clone()).with_ids(None, Some(tid + 1));
        let exited = RootfsThreadState { scratch: Some(left_page), ..RootfsThreadState::default() };
        let exit = |tool: &RootfsTool, g: &RecordingGuest, state: RootfsThreadState, tid: i32| {
            run(tool.on_exit_thread(reverie::Tid::from_raw(tid), g, state, reverie::ExitStatus::Exited(0)))
                .expect("exit");
        };
        exit(&tool, &exiting, exited.clone(), tid + 1);
        exit(&tool, &exiting, exited.clone(), tid + 1);
        assert_eq!(tool.state.lock().unwrap().free_scratch, vec![left_page.addr], "queued once");
        // Bytes the exited thread left, beyond anything the next stages.
        left.0.fill(0xa5);
        let mut c = new_thread(&tool, &mut a, tid + 2);
        c.expect([Answer::Return(Ok(0))]);
        // Never executed: answered from the script.
        assert_eq!(dispatch(&tool, &mut c, unlinkat_call(c"/x")).ok(), Some(0));
        let call = c.injected();
        assert_eq!(call.len(), 1, "the call only, no mmap: {call:?}");
        assert_eq!(call[0].1[1] as usize, left_page.addr, "the reused page");
        assert_eq!(c.thread_state().scratch, Some(left_page));
        assert_eq!(left.at(0, 3), b"/x\0");
        assert!(left.at(3, 4096 - 3).iter().all(|&b| b == 0), "zeroed before reuse");
        assert!(tool.state.lock().unwrap().free_scratch.is_empty());
        // A page of the previous image: exec drew a new number.
        tool.state.lock().unwrap().new_scratch_image();
        exit(&tool, &exiting, exited, tid + 1);
        assert!(tool.state.lock().unwrap().free_scratch.is_empty(), "an old image's page is not reused");
        assert!(take_reports().is_empty());
    }

    /// Post-exec maps a pool, so the next 15 new
    /// threads stage with no mmap injected (their only injection is the
    /// call itself, scripted to fail with EPERM: an mmap would take that
    /// answer and fail an assertion, never use a made-up address), and the
    /// 16th, the pool used up, injects one mmap for a new pool.
    #[test]
    fn pool_serves_new_threads_without_an_mmap() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        // The counts are the requirement's (16 pages, 15 new threads, 65536
        // bytes), not read from the constant: a smaller pool must fail here.
        let pool = 16usize;
        let mut scratch = Scratch::new();
        let (tool, mut a) = on_host_root_ptrace(&mut scratch, &[]);
        // Post-exec: the exec'ing thread A's page dropped, the pool mapped.
        a.thread_state_mut().scratch = None;
        a.expect([map_page()]);
        let base = run(tool.map_scratch(&mut a)).expect("the pool");
        let mapped = a.injected();
        assert_eq!(mapped.len(), 1);
        assert_eq!((mapped[0].0, mapped[0].1[1] as usize), (Sysno::mmap, 65536), "one mmap of the 16-page pool");
        let tid = unsafe { libc::gettid() };
        for i in 1..pool {
            let mut t = new_thread(&tool, &mut a, tid + i as i32);
            t.expect([err(Errno::EPERM)]);
            // Never executed: answered from the script.
            assert_eq!(errno(&dispatch(&tool, &mut t, unlinkat_call(c"/x"))), Some(Errno::EPERM), "thread {i}");
            let kinds: Vec<Sysno> = t.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(kinds, vec![Sysno::unlinkat], "thread {i}: no mmap");
            assert_eq!(t.thread_state().scratch.map(|p| p.addr), Some(base + i * 4096), "thread {i}: a pool page");
        }
        let mut t = new_thread(&tool, &mut a, tid + pool as i32);
        t.expect([map_page(), Answer::Return(Ok(0))]);
        assert_eq!(dispatch(&tool, &mut t, unlinkat_call(c"/x")).ok(), Some(0), "the 16th");
        let kinds: Vec<Sysno> = t.injected().iter().map(|(nr, _)| *nr).collect();
        assert_eq!(kinds, vec![Sysno::mmap, Sysno::unlinkat], "the 16th maps a new pool");
        let second = t.thread_state().scratch.expect("the 16th's page").addr;
        // SAFETY: the two pools mapped natively above, used by nothing else.
        unsafe {
            assert_eq!(libc::munmap(base as *mut libc::c_void, POOL_LEN), 0);
            assert_eq!(libc::munmap(second as *mut libc::c_void, POOL_LEN), 0);
        }
        assert!(take_reports().is_empty());
    }

    /// A staged write that only partly lands (its end in an inaccessible
    /// page) is EFAULT, never a truncated argument that still answers with
    /// its address: here the thread's page is placed across a guard page.
    #[test]
    fn short_staging_write_is_an_error() {
        let _lane = serial();
        let mut scratch = Scratch::new();
        let (tool, mut g) = on_host_root_ptrace(&mut scratch, &[]);
        let page = super::super::page_size();
        // SAFETY: a fresh anonymous mapping, its second page inaccessible;
        // unmapped below.
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), 2 * page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(map, libc::MAP_FAILED, "mmap");
        assert_eq!(unsafe { libc::mprotect(map.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) }, 0);
        // The 4096-byte page's second half lies in the inaccessible page.
        let addr = map as usize + page - 2048;
        let image = tool.state.lock().unwrap().scratch_image;
        g.thread_state_mut().scratch = Some(ScratchPage { addr, image });
        assert_eq!(run(tool.scratch_write_at(&mut g, &[1u8; 16], 2032)).ok(), Some(addr + 2032), "a write that fits");
        let short = run(tool.scratch_write_at(&mut g, &[1u8; 16], 2040));
        assert_eq!(errno(&short.map(|a| a as i64)), Some(Errno::EFAULT), "8 of 16 bytes would land");
        unsafe { libc::munmap(map, 2 * page) };
    }

    /// A vfork or posix_spawn child shares its caller's page. A caller that
    /// has staged nothing takes a free page of its process (zeroed) before
    /// the clone, so the child stages there with no mmap and the next spawn
    /// reuses it. Otherwise the child, on ptrace a new process with a fresh
    /// Tool and no free pages, maps a whole pool on every spawn, which the
    /// caller's process never reuses.
    #[test]
    fn vfork_caller_takes_a_free_page_first() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let mut scratch = Scratch::new();
        let (tool, mut a) = on_host_root_ptrace(&mut scratch, &[]);
        a.thread_state_mut().scratch = None;
        a.expect([map_page()]);
        let base = run(tool.map_scratch(&mut a)).expect("the pool");
        let tid = unsafe { libc::gettid() };
        let mut t = new_thread(&tool, &mut a, tid + 1);
        assert_eq!(t.thread_state().scratch, None, "T has staged nothing yet");
        assert_eq!(tool.state.lock().unwrap().free_scratch.len(), 15, "15 free pages");
        // The page T takes (the lowest free one), dirtied: it must be zeroed.
        let page = base + 4096;
        // SAFETY: a page of the pool mapped natively above.
        unsafe { std::ptr::write_bytes(page as *mut u8, 0xa5, 4096) };
        let vfork = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64;
        for spawn in 1..=2 {
            tool.stage_child_files(&mut t, vfork);
            let mut child_scratch = Scratch::new();
            let (child_tool, _unused) = on_host_root_ptrace(&mut child_scratch, &[]);
            let parent = (reverie::Tid::from_raw(tid + 1), t.thread_state());
            let state = child_tool.init_thread_state(reverie::Tid::from_raw(tid + 1 + spawn), Some(parent));
            tool.end_child_files(&mut t, true);
            assert_eq!(t.thread_state().scratch.map(|p| p.addr), Some(page), "spawn {spawn}: T's page");
            assert_eq!(tool.state.lock().unwrap().free_scratch.len(), 14, "spawn {spawn}: one page taken, once");
            if spawn == 1 {
                // SAFETY: the page T took, mapped above.
                let bytes = unsafe { std::slice::from_raw_parts(page as *const u8, 4096) };
                assert!(bytes.iter().all(|b| *b == 0), "zeroed before T owns it");
            }
            let mut c = RecordingGuest::new(a.cfg.clone()).with_ids(None, Some(tid + 1 + spawn));
            *c.thread_state_mut() = state;
            assert_eq!(c.thread_state().scratch.map(|p| p.addr), Some(page), "spawn {spawn}: the child shares it");
            c.expect([err(Errno::EPERM)]);
            assert_eq!(errno(&dispatch(&child_tool, &mut c, unlinkat_call(c"/x"))), Some(Errno::EPERM), "spawn {spawn}");
            let kinds: Vec<Sysno> = c.injected().iter().map(|(nr, _)| *nr).collect();
            assert_eq!(kinds, vec![Sysno::unlinkat], "spawn {spawn}: the child maps nothing");
        }
        // SAFETY: the pool mapped natively above, used by nothing else.
        unsafe { assert_eq!(libc::munmap(base as *mut libc::c_void, POOL_LEN), 0) };
        assert!(take_reports().is_empty());
    }

    /// On ptrace each process has a fresh Tool, and a
    /// fork child's first thread inherits the caller's page, tagged with the
    /// caller's image. After the child's own exec, that page (of the
    /// caller's old address space) is not of the child's image, so it is
    /// never queued for the child's new threads. With a per-process counter
    /// both images would be number 1 (each exec'd once from 0).
    #[test]
    fn a_fork_childs_inherited_page_is_not_of_its_image() {
        let _lane = serial();
        let mut scratch = Scratch::new();
        let (_tool, g) = on_host_root_ptrace(&mut scratch, &[]);
        let parent = RootfsTool::default();
        parent.state.lock().unwrap().new_scratch_image();
        let inherited = ScratchPage { addr: 0x1000, image: parent.state.lock().unwrap().scratch_image };
        let child = RootfsTool::default();
        child.state.lock().unwrap().new_scratch_image();
        let state = RootfsThreadState { scratch: Some(inherited), ..RootfsThreadState::default() };
        let tid = reverie::Tid::from_raw(unsafe { libc::gettid() } + 1);
        run(child.on_exit_thread(tid, &g, state, reverie::ExitStatus::Exited(0))).expect("exit");
        assert!(child.state.lock().unwrap().free_scratch.is_empty(), "the caller's page is not the child's");
    }

    /// Exec starts a new image: the number advances and the queued pages
    /// are dropped (unmapped by the exec), and the post-exec handler both
    /// does that and drops the exec'ing thread's own page before mapping a
    /// new one.
    #[test]
    fn exec_starts_a_new_image() {
        let tool = RootfsTool::default();
        {
            let mut st = tool.state.lock().unwrap();
            // Numbers the counter handed out: each draw is later than the
            // last, whatever other units draw meanwhile.
            st.new_scratch_image();
            let prior = st.scratch_image;
            st.free_scratch = vec![0x1000, 0x2000];
            st.new_scratch_image();
            let first = st.scratch_image;
            assert!(first > prior && st.free_scratch.is_empty(), "a new number, the queue dropped");
            st.new_scratch_image();
            assert!(st.scratch_image > first, "never the same number twice");
        }
        let source = include_str!("rootfs_tool.rs");
        let at = source.find("async fn handle_post_exec<").expect("post-exec");
        let body = &source[at..at + source[at..].find("\n    }\n").expect("its end")];
        let new_image = body.find("st.new_scratch_image();").expect("the new image");
        let dropped = body.find("guest.thread_state_mut().scratch = None;").expect("the old page dropped");
        let mapped = body.find("self.map_scratch(guest).await").expect("a new page mapped");
        assert!(new_image < mapped && dropped < mapped, "both before the new page is mapped");
    }

    /// Which page a clone's child starts with: a fork child keeps the
    /// caller's (its copy is its own), a vfork child shares it (the caller
    /// is suspended with nothing staged), a thread or a CLONE_VM process
    /// gets none.
    #[test]
    fn clone_children_pages() {
        let page = Some(ScratchPage { addr: 0x1000, image: 2 });
        let vfork = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64;
        for (what, flags, want) in [
            ("fork", libc::SIGCHLD as u64, page),
            ("vfork", vfork, page),
            ("posix_spawn", vfork, page),
            ("thread", THREAD, None),
            ("CLONE_VM process", (libc::CLONE_VM | libc::SIGCHLD) as u64, None),
            ("thread with CLONE_VFORK", THREAD | libc::CLONE_VFORK as u64, None),
        ] {
            assert_eq!(super::super::child_scratch(flags, page), want, "{what}");
        }
        assert_eq!(super::super::child_scratch(libc::SIGCHLD as u64, None), None, "nothing to keep");
    }
}

/// https://github.com/rrnewton/literoot/issues/9: the translation memo and
/// the searched bases are per thread. Two threads of one process with split
/// descriptor tables (A unshared CLONE_FILES) both name descriptor N: in A's
/// table a deleted directory, in the process table (B's) a live one. B's
/// whole dispatch runs inside A's held search-check injection, as another
/// thread's handler can on ptrace while A waits.
mod memo_units {
    use super::a1_units::*;
    use super::*;

    /// A free descriptor number for this unit's tables, high enough that no
    /// other unit uses it.
    const N: i32 = 987;
    const N2: i32 = 988;

    /// Run `f(main_tid)` on a thread of its own that unshared CLONE_FILES,
    /// `main_tid` being the calling thread's id (still alive, on the process
    /// table).
    fn on_split_table<R: Send>(f: impl FnOnce(i32) -> R + Send) -> R {
        let main_tid = unsafe { libc::gettid() };
        std::thread::scope(|s| {
            s.spawn(|| {
                // SAFETY: CLONE_FILES only: this thread gets its own table copy.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_FILES) }, 0, "unshare(CLONE_FILES)");
                f(main_tid)
            })
            .join()
            .unwrap()
        })
    }

    /// `dir` opened O_PATH|O_DIRECTORY at descriptor `at` of this thread's
    /// table.
    fn open_dir_at(dir: &Path, at: i32) {
        let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(fd >= 0, "open {}", dir.display());
        assert_eq!(unsafe { libc::dup2(fd, at) }, at);
        close(fd);
    }

    fn openat_n(path: &std::ffi::CStr) -> Syscall {
        Syscall::from_raw(
            Sysno::openat,
            SyscallArgs::new(N as usize, path.as_ptr() as usize, libc::O_RDONLY as usize, 0, 0, 0),
        )
    }

    /// The translate_memo case of issue 9. A's openat(N, "../x") climbs out
    /// of its deleted directory D (in the unit directory U): natively U/x.
    /// While A's search check is held, B's openat(N, "../x") translates
    /// from the live L = U/live/d: U/live/x, memoized. A's call must still
    /// open U/x; with a memo shared by the threads it opened U/live/x.
    #[test]
    fn a_threads_translation_is_its_own() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let u = unit_dir();
        std::fs::create_dir_all(u.join("live/d")).unwrap();
        std::fs::write(u.join("x"), b"a's").unwrap();
        std::fs::write(u.join("live/x"), b"b's").unwrap();
        let want = native(u.join("x").to_str().unwrap());
        let wrong = native(u.join("live/x").to_str().unwrap());
        assert_ne!(want, wrong);
        // The process table (B's): N is the live L.
        open_dir_at(&u.join("live/d"), N);
        let (got, b_result) = on_split_table(|main_tid| {
            // A's table: N is the deleted D.
            std::fs::create_dir(u.join("dead")).unwrap();
            open_dir_at(&u.join("dead"), N);
            std::fs::remove_dir(u.join("dead")).unwrap();
            let mut scratch = Scratch::new();
            let (tool, mut a) = on_host_root_ptrace(&mut scratch, &[]);
            let mut b_page = Scratch::new();
            let mut b = RecordingGuest::new(a.cfg.clone()).with_ids(None, Some(main_tid));
            b.thread_state_mut().scratch = Some(super::super::ScratchPage { addr: b_page.addr(), image: 0 });
            let b = Arc::new(Mutex::new(b));
            let b_result = Arc::new(Mutex::new(None));
            let held = {
                let (tool, b, b_result) = (tool.clone(), b.clone(), b_result.clone());
                Answer::Call(Box::new(move || {
                    let mut b = b.lock().unwrap();
                    // B's call is answered from the script: never executed.
                    b.expect([Answer::Return(Ok(55))]);
                    let r = dispatch(&tool, &mut b, openat_n(c"../x"));
                    let staged = b.injected().last().map(|(_, args)| {
                        // SAFETY: B staged the name in its own page.
                        unsafe { std::ffi::CStr::from_ptr(args[1] as *const libc::c_char) }.to_bytes().to_vec()
                    });
                    *b_result.lock().unwrap() = Some((r.ok(), staged));
                    Ok(0)
                }))
            };
            // A: the argument probe (EBADF: the lookup is reached), the
            // search check (held: B runs), then its own call, natively.
            a.expect([err(Errno::EBADF), held]);
            a.native_rest = true;
            let r = dispatch(&tool, &mut a, openat_n(c"../x"));
            let got = opened("A", &r);
            close(N);
            set_dispatch_read(None);
            drop(b_page);
            let b_result = b_result.lock().unwrap().take();
            (got, b_result)
        });
        close(N);
        let (b_ret, b_staged) = b_result.expect("B ran while A's search check was held");
        assert_eq!(b_ret, Some(55), "B completes");
        let b_name = u.join("live/x");
        assert_eq!(b_staged, Some(b_name.as_os_str().as_encoded_bytes().to_vec()), "B's call names B's file");
        assert_eq!(got, want, "A opens the file next to its own deleted directory, not B's");
        assert!(take_reports().is_empty());
        std::fs::remove_dir_all(&u).unwrap();
    }

    /// The searched_bases case of issue 9: A's renameat2(N, "../a", N2,
    /// "../b", 0) climbs out of two deleted directories; A's first search check
    /// passes, and B's whole dispatch runs inside A's second. A's call must
    /// still translate both climbs and rename U/a to U/b, as natively; with
    /// the searched bases shared by the threads, B's dispatch cleared A's
    /// first one and A's call was refused.
    #[test]
    fn a_threads_searched_bases_are_its_own() {
        let _lane = serial();
        let _off = DispatchOff;
        take_reports();
        let u = unit_dir();
        std::fs::create_dir_all(u.join("live/d")).unwrap();
        std::fs::write(u.join("a"), b"a").unwrap();
        open_dir_at(&u.join("live/d"), N);
        let r = on_split_table(|main_tid| {
            for (name, at) in [("dead1", N), ("dead2", N2)] {
                std::fs::create_dir(u.join(name)).unwrap();
                open_dir_at(&u.join(name), at);
                std::fs::remove_dir(u.join(name)).unwrap();
            }
            let mut scratch = Scratch::new();
            let (tool, mut a) = on_host_root_ptrace(&mut scratch, &[]);
            let mut b_page = Scratch::new();
            let mut b = RecordingGuest::new(a.cfg.clone()).with_ids(None, Some(main_tid));
            b.thread_state_mut().scratch = Some(super::super::ScratchPage { addr: b_page.addr(), image: 0 });
            let b = Arc::new(Mutex::new(b));
            let held = {
                let (tool, b) = (tool.clone(), b.clone());
                Answer::Call(Box::new(move || {
                    let mut b = b.lock().unwrap();
                    b.expect([Answer::Return(Ok(55))]);
                    let _ = dispatch(&tool, &mut b, openat_n(c"../x"));
                    Ok(0)
                }))
            };
            let call = Syscall::from_raw(
                Sysno::renameat2,
                SyscallArgs::new(N as usize, c"../a".as_ptr() as usize, N2 as usize, c"../b".as_ptr() as usize, 0, 0),
            );
            // A: the argument probe, the first search check (passes), the
            // second (held: B runs), then its own call, natively.
            a.expect([err(Errno::EBADF), ok0(), held]);
            a.native_rest = true;
            let r = dispatch(&tool, &mut a, call);
            close(N);
            close(N2);
            set_dispatch_read(None);
            drop(b_page);
            r.ok()
        });
        close(N);
        assert_eq!(r, Some(0), "A's rename completes");
        assert!(!u.join("a").exists() && u.join("b").exists(), "U/a renamed to U/b");
        assert!(take_reports().is_empty());
        std::fs::remove_dir_all(&u).unwrap();
    }

    /// The self-stop swallow is the arming thread's: A's refused
    /// PTRACE_TRACEME arms it for A's next self-SIGSTOP only. A sibling B's
    /// dispatch neither takes it nor uses it: B's own SIGSTOP of the process
    /// is delivered (injected), and A's is still swallowed afterwards. Run on
    /// an in-guest configuration, where TRACEME is refused, with two guests
    /// of one process standing for two threads.
    #[test]
    fn a_threads_self_stop_swallow_is_its_own() {
        let _lane = serial();
        take_guest_bits();
        let root = unit_dir();
        let tool = RootfsTool::default();
        let tid = unsafe { libc::gettid() };
        let pid = std::process::id() as usize;
        let mut a = RecordingGuest::new(inguest_cfg(&root));
        let mut b = RecordingGuest::new(inguest_cfg(&root)).with_ids(None, Some(tid + 1));
        let traceme = Syscall::from_raw(Sysno::ptrace, SyscallArgs::new(libc::PTRACE_TRACEME as usize, 0, 0, 0, 0, 0));
        let self_stop = || Syscall::from_raw(Sysno::kill, SyscallArgs::new(pid, libc::SIGSTOP as usize, 0, 0, 0, 0));
        assert_eq!(errno(&dispatch(&tool, &mut a, traceme)), Some(Errno::EPERM), "A's TRACEME refused");
        assert!(a.injected().is_empty(), "nothing of A's injected");
        take_guest_bits();
        // B's SIGSTOP of the process: B's swallow is not armed.
        b.expect([ok0()]);
        assert_eq!(dispatch(&tool, &mut b, self_stop()).ok(), Some(0), "B's kill");
        let kinds: Vec<Sysno> = b.injected().iter().map(|(nr, _)| *nr).collect();
        assert_eq!(kinds, vec![Sysno::kill], "B's self-stop is delivered, not swallowed");
        // A's next self-stop: still armed.
        assert_eq!(dispatch(&tool, &mut a, self_stop()).ok(), Some(0), "A's kill");
        assert!(a.injected().is_empty(), "A's self-stop is swallowed");
        take_guest_bits();
        std::fs::remove_dir(&root).unwrap();
    }
}
