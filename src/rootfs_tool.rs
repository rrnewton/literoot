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
use reverie::GlobalTool;
use reverie::GlobalRPC as _;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::MemoryAccess as _;
use reverie::syscalls::PathPtr;
use reverie::syscalls::ReadAddr;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo as _;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

use crate::exec_state::{ExecState, ExecStateError};
use crate::shared_record::{ProcessId, ProcessRecord, shared_record_file};
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
    /// Guest path of the initial program (argv-resolved).
    pub initial_exe: String,
    /// Full initial argv as spelled on the literoot command
    /// line (for /proc/self/cmdline synthesis).
    pub initial_argv: Vec<String>,
}

impl LiterootConfig {
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
        c
    }
}

/// Process-tree global state: just the immutable config (no hot-path
/// RPC is ever sent; see design §6).
#[derive(Debug, Default)]
pub struct LiterootGlobal {
    config: std::sync::OnceLock<RootConfig>,
}

/// Unused RPC message (GlobalTool requires the types to exist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoMsg;

#[reverie::global_tool]
impl GlobalTool for LiterootGlobal {
    type Request = NoMsg;
    type Response = ();
    type Config = LiterootConfig;

    async fn init_global_state(cfg: &Self::Config) -> Self {
        set_config(cfg.clone());
        let g = Self::default();
        let _ = g.config.set(cfg.to_root_config());
        g
    }

    async fn receive_rpc(&self, _from: Pid, _msg: NoMsg) {}
}

/// Per-process replicated state (design §6).
/// Fields are `pub(crate)` so `crate::exec_state` can snapshot and
/// restore the exec-continuity subset (B4) without a second copy
/// of the layout living in two modules.
#[derive(Debug)]
pub(crate) struct ProcState {
    pub(crate) cwd: PathBuf,
    /// fd → guest path it denotes (for *at resolution, §4.3).
    pub(crate) fds: HashMap<i32, PathBuf>,
    /// False until the initial (launcher-issued) execve has passed:
    /// its path is already a host path and must not be translated.
    pub(crate) bootstrapped: bool,
    /// Emulated chroot: host directory acting as the new root.
    pub(crate) root_override: Option<PathBuf>,
    /// Guest scratch page (injected mmap) for execve path
    /// staging: guest-stack staging corrupts the execve
    /// caller's frame in interp-route processes (measured
    /// EFAULT on second execve, test-execve-eacces-enoexec).
    pub(crate) scratch: Option<usize>,
    /// Guest path of the current program image (for
    /// /proc/self/exe de-translation; seeded from Config).
    pub(crate) exe_guest: PathBuf,
    /// Fds opened on virtual bind-prefix dirs:
    /// guest dir -> entries already emitted.
    pub(crate) virtual_fds: std::collections::HashMap<i32, (PathBuf, bool)>,
    /// Synthetic dirents pending for real dir fds with bind
    /// children (merged listings).
    pub(crate) dirent_pending: std::collections::HashMap<i32, Vec<u8>>,
    /// Names the kernel already returned per dir fd (dedupe).
    pub(crate) dirent_seen: std::collections::HashMap<i32, std::collections::HashSet<String>>,
    /// As-exec'd argv of the current image (cmdline synthesis).
    pub(crate) argv: Vec<Vec<u8>>,
    /// Stateful fake identity (r/e/s uid+gid) under -0/-i:
    /// setres* must be observable via getres* afterwards.
    pub(crate) fake: Option<[u32; 6]>,
    /// Per-dispatch translation memo (stat-gap fix): one syscall
    /// dispatch translates the same (dirfd, path) through several
    /// helpers; memoize within the dispatch only, keyed by the
    /// dispatch counter below. Never lives across dispatches, so no
    /// cross-syscall staleness is possible.
    pub(crate) dispatch_seq: u64,
    pub(crate) translate_memo: Vec<((u64, i32, PathBuf, bool), PathBuf)>,
    /// RootConfig built for the current dispatch (same keying: a
    /// RootConfig rebuild re-canonicalizes every bind prefix, which
    /// probes the host filesystem; several helpers per dispatch ask
    /// for the config).
    pub(crate) config_memo: Option<(u64, Option<PathBuf>, RootConfig)>,
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
                fds: HashMap::new(),
                bootstrapped: false,
                root_override: None,
                scratch: None,
                exe_guest: PathBuf::new(),
                fake: None,
                dispatch_seq: 0,
                translate_memo: Vec::new(),
                config_memo: None,
                argv: Vec::new(),
                virtual_fds: std::collections::HashMap::new(),
                dirent_pending: std::collections::HashMap::new(),
                dirent_seen: std::collections::HashMap::new(),
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
}

impl RootfsTool {
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
            ExecState::capture(&st, guest.config())
        };
        // Prove the canonical bytes fit the cap now, while refusal
        // is still possible; the bytes themselves are discarded
        // (the pending slot carries the value).
        snapshot.encode().map_err(|e| match e {
            ExecStateError::TooLarge => reverie::syscalls::Errno::E2BIG,
            _ => reverie::syscalls::Errno::EIO,
        })?;
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
        let row = ProcessRecord {
            id,
            exe_guest: self
                .exe_guest(guest)
                .as_os_str()
                .as_bytes()
                .to_vec(),
            argv: self.current_argv(guest.config()),
        };
        if let Err(err) = store.publish(row) {
            if std::env::var_os("LITEROOT_DEBUG").is_some() {
                eprintln!(
                    "literoot: shared record publish unavailable: {err}"
                );
            }
        }
    }

    fn shared_process_record(pid: i32) -> Option<ProcessRecord> {
        let id = Self::guest_process_id(pid)?;
        shared_record_file()?.lookup(id).ok().flatten()
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
            match fork_seed_if_bootstrapped(&st, guest.config(), &current_exe, &current_argv) {
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
    let text = std::str::from_utf8(stat).ok()?;
    let (prefix, tail) = text.rsplit_once(')')?;
    let raw_pid: i32 = prefix.split_whitespace().next()?.parse().ok()?;
    if raw_pid != pid {
        return None;
    }
    let start_time: u64 = tail.split_whitespace().nth(19)?.parse().ok()?;
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
    cfg: &LiterootConfig,
    current_exe: &Path,
    current_argv: &[Vec<u8>],
) -> Result<ExecState, reverie::syscalls::Errno> {
    if !st.bootstrapped {
        return Err(reverie::syscalls::Errno::EINVAL);
    }
    Ok(ExecState::capture_fork_seed(
        st,
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
    cfg: &LiterootConfig,
    current_exe: &Path,
    current_argv: &[Vec<u8>],
) -> Option<Result<ExecState, reverie::syscalls::Errno>> {
    if !st.bootstrapped {
        return None;
    }
    Some(fork_seed(st, cfg, current_exe, current_argv))
}

/// B4 step 4 staging decision: snapshot for a new *process*, never
/// for a new thread in the same thread group. Unreadable clone3
/// args read back as empty flags (CloneFamily::flags), which
/// stages — safe, because that clone fails in the kernel and the
/// handler clears the snapshot on return.
fn clone_is_process(flags: u64) -> bool {
    flags & (libc::CLONE_THREAD as u64) == 0
}

// Reverie's ptrace guest-stack arena is ~896 bytes total; stage at
// most 768 bytes of translated path (POC limit — the in-guest
// backend uses Tool-region scratch instead, design §6).
const PATH_BUF: usize = 768;


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
            Sysno::fchmodat,
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
            Sysno::setgroups,
            Sysno::sethostname,
            Sysno::setdomainname,
            Sysno::chroot,
            Sysno::getdents64,
            Sysno::openat2,
            Sysno::name_to_handle_at,
            Sysno::open_by_handle_at,
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
            },
            None => RootfsThreadState::default(),
        }
    }

    async fn handle_thread_start<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), Error> {
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
        Ok(())
    }

    async fn handle_post_exec<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
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
            // New image: any previous scratch mapping is gone.
            st.scratch = None;
        }
        // Pre-allocate the execve scratch page here: injecting
        // an mmap between a guest's two execve calls was
        // measured to make the second fail EFAULT.
        {
            let needs = self.state.lock().unwrap().scratch.is_none();
            if needs {
                let mmap = reverie::syscalls::Mmap::new()
                    .with_addr(None)
                    .with_len(4096)
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
                if let Ok(addr) = guest.inject(mmap).await {
                    self.state.lock().unwrap().scratch = Some(addr as usize);
                }
            }
        }
        self.publish_self_shared(guest);
        // Setuid/setgid exec under fake identity: euid/suid take
        // the file owner's fake id (owner == real caller maps to
        // 0 by proot's fake-id rule; test-getresid-native).
        if self.fake_ids(guest).is_some() {
            use std::os::unix::fs::MetadataExt as _;
            let exe = self.exe_guest(guest);
            let host = self.translate_follow(guest, libc::AT_FDCWD, &exe);
            if let Ok(md) = std::fs::metadata(&host) {
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
        // string leaves it alone).
        let fake = self.fake_ids(guest);
        let zero_hwcap = guest
            .config()
            .kernel_release
            .as_deref()
            .map(|k| k.contains('\\'))
            .unwrap_or(false);
        if fake.is_some() || zero_hwcap {
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
                    let mut p = guest_stack_pointer(&regs) + 8 + (argc + 1) * 8;
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
                    for _ in 0..64 {
                        let (Some(ty), Some(val)) =
                            (read64(&mem, p), read64(&mem, p + 8))
                        else {
                            break;
                        };
                        if ty == 0 {
                            break;
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
        // New dispatch: per-dispatch translation memo is keyed by this
        // counter and never consulted across dispatches.
        {
            let mut st = self.state.lock().unwrap();
            st.dispatch_seq = st.dispatch_seq.wrapping_add(1);
            st.translate_memo.clear();
        }
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
        match syscall {
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
                if is_self_exe(&guest_path, guest.pid().as_raw()) {
                    guest_path = self.exe_guest(guest);
                }
                if let Some(fd) = self.open_synthetic_cmdline(guest, &guest_path).await {
                    return Ok(fd);
                }
                if self.dirfd_passthrough(guest, openat.dirfd(), &guest_path) {
                    return Ok(guest.inject(openat).await?);
                }
                let host = self.translate_follow(guest, openat.dirfd(), &guest_path);
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        openat.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let first = guest.inject(rewritten).await;
                drop(_guard);
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
                                Some(fd) => Ok(fd),
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
                    st.fds.insert(ret as i32, abs);
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
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &guest_path);
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        open.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret >= 0 {
                    let mut st = self.state.lock().unwrap();
                    let abs = self.guest_abs(guest, &st, libc::AT_FDCWD, &guest_path);
                    st.fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Stat(stat) => {
                let Some(path_ptr) = stat.path() else {
                    return Ok(guest.inject(stat).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &guest_path);
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
                let host = self.translate_for(guest, libc::AT_FDCWD, &guest_path);
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
                let host = self.translate_follow(guest, libc::AT_FDCWD, &guest_path);
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
                let host = self.translate_for(guest, stat.dirfd(), &guest_path);
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
                let host = self.translate_for(guest, stat.dirfd(), &guest_path);
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
                let host = self.translate_for(guest, link.dirfd(), &guest_path);
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot-tool: readlinkat {guest_path:?} -> {host:?} magic={}", is_magic_proc_path(&guest_path));
                }
                let buf = link.buf();
                let buf_len = link.buf_len();
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        link.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                Ok(self.detranslate_into(guest, &host, &guest_path, buf, buf_len, ret))
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::Readlink(link) => {
                let Some(path_ptr) = link.path() else {
                    return Ok(guest.inject(link).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_for(guest, libc::AT_FDCWD, &guest_path);
                let buf = link.buf();
                let buf_len = link.bufsize();
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        link.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                Ok(self.detranslate_into(guest, &host, &guest_path, buf, buf_len, ret))
            }
            Syscall::Fchdir(fch) => {
                let ret = guest.inject(fch).await?;
                if ret == 0 {
                    // Replicated cwd follows the fd's guest path;
                    // unknown fds recover via /proc/<pid>/fd.
                    let recovered = {
                        let st = self.state.lock().unwrap();
                        st.fds.get(&fch.fd()).cloned()
                    };
                    let new_cwd = recovered.or_else(|| {
                        let target = std::fs::read_link(format!(
                            "/proc/{}/fd/{}",
                            guest.pid().as_raw(),
                            fch.fd()
                        ))
                        .ok()?;
                        self.config(guest).reverse(&target)
                    });
                    if let Some(p) = new_cwd {
                        self.state.lock().unwrap().cwd = p;
                    }
                }
                Ok(ret)
            }
            Syscall::Faccessat(acc) => {
                let Some(path_ptr) = acc.path() else {
                    return Ok(guest.inject(acc).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                let host = self.translate_follow(guest, acc.dirfd(), &guest_path);
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
                let host = self.translate_for(guest, unlink.dirfd(), &guest_path);
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
                let host = self.translate_for(guest, mkdir.dirfd(), &guest_path);
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
                let old_h = self.translate_for(guest, rn.olddirfd(), &old_g);
                let new_h = self.translate_for(guest, rn.newdirfd(), &new_g);
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
                let old_h = self.translate_for(guest, rn.olddirfd(), &old_g);
                let new_h = self.translate_for(guest, rn.newdirfd(), &new_g);
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
                let old_g = op.read(&guest.memory())?;
                let new_g = np.read(&guest.memory())?;
                let old_h = self.translate_for(guest, ln.olddirfd(), &old_g);
                let new_h = self.translate_for(guest, ln.newdirfd(), &new_g);
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
                let link_h = self.translate_for(guest, sl.newdirfd(), &link_g);
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
                let old_h = self.translate_for(guest, libc::AT_FDCWD, &old_g);
                let new_h = self.translate_for(guest, libc::AT_FDCWD, &new_g);
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
                let old_h = self.translate_for(guest, libc::AT_FDCWD, &old_g);
                let new_h = self.translate_for(guest, libc::AT_FDCWD, &new_g);
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
                let link_h = self.translate_for(guest, libc::AT_FDCWD, &link_g);
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
                let h = self.translate_for(guest, libc::AT_FDCWD, &g);
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
                let h = self.translate_for(guest, libc::AT_FDCWD, &g);
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
                let h = self.translate_for(guest, libc::AT_FDCWD, &g);
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
                    let h = self.translate_for(guest, mk.dirfd(), &g);
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
                let h = self.translate_for(guest, mk.dirfd(), &g);
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
                let Some(pp) = fc.path() else {
                    return Ok(guest.inject(fc).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, fc.dirfd(), &g);
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        fc.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Fchmodat(fc) => {
                let Some(pp) = fc.path() else {
                    return Ok(guest.inject(fc).await?);
                };
                let g = pp.read(&guest.memory())?;
                let h = self.translate_for(guest, fc.dirfd(), &g);
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
                let g = pp.read(&guest.memory())?;
                if g.as_os_str().is_empty() {
                    return Ok(guest.inject(ut).await?);
                }
                let h = self.translate_for(guest, ut.dirfd(), &g);
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
                let h = self.translate_for(guest, sx.dirfd(), &g);
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
                let h = self.translate_follow(guest, libc::AT_FDCWD, &g);
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
                let h = self.translate_follow(guest, libc::AT_FDCWD, &g);
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
                let h = self.translate_for(guest, libc::AT_FDCWD, &g);
                let (_g, rewritten) = self
                    .with_guest_path(guest, &h, |ptr| {
                        co.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                Ok(guest.inject(rewritten).await?)
            }
            Syscall::Openat2(oa) => {
                // Translate the path only; open_how passes
                // through (resolve flags honoured by our own
                // clamping canonicalization, design S5.1).
                let _probe_bump = ProbeBumpOnDrop;
                let Some(path_ptr) = oa.path() else {
                    return Ok(guest.inject(oa).await?);
                };
                let guest_path = path_ptr.read(&guest.memory())?;
                if self.dirfd_passthrough(guest, oa.dirfd(), &guest_path) {
                    return Ok(guest.inject(oa).await?);
                }
                let host = self.translate_follow(guest, oa.dirfd(), &guest_path);
                let (_g, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        oa.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret >= 0 {
                    let mut st = self.state.lock().unwrap();
                    let abs = self.guest_abs(guest, &st, oa.dirfd(), &guest_path);
                    st.fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
            Syscall::NameToHandleAt(nh) => {
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
                let h = self.translate_for(guest, nh.dirfd(), &g);
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
            Syscall::Getdents64(gd) => {
                let virt = {
                    let st = self.state.lock().unwrap();
                    st.virtual_fds.get(&(gd.fd() as i32)).cloned()
                };
                match virt {
                    None => {
                        // Real dir: merge bind-child entries
                        // after kernel EOF.
                        let fd = gd.fd() as i32;
                        let pending = {
                            let st = self.state.lock().unwrap();
                            st.dirent_pending.get(&fd).cloned()
                        };
                        if let Some(mut pend) = pending {
                            if pend.is_empty() {
                                return Ok(guest.inject(gd).await?);
                            }
                            use reverie::syscalls::MemoryAccess as _;
                            // Serve whole records that fit.
                            let mut take = 0usize;
                            while take + 19 <= pend.len() {
                                let reclen = u16::from_ne_bytes([
                                    pend[take + 16],
                                    pend[take + 17],
                                ]) as usize;
                                if reclen < 19 || take + reclen > gd.count() as usize {
                                    break;
                                }
                                take += reclen;
                            }
                            if take == 0 {
                                // Single record larger than the
                                // guest buffer: kernel would EINVAL;
                                // drop pending and defer to kernel.
                                self.state
                                    .lock()
                                    .unwrap()
                                    .dirent_pending
                                    .insert(fd, Vec::new());
                                return Ok(guest.inject(gd).await?);
                            }
                            let chunk: Vec<u8> = pend.drain(..take).collect();
                            {
                                let mut st = self.state.lock().unwrap();
                                st.dirent_pending.insert(fd, pend);
                            }
                            if let Some(dirent) = gd.dirent() {
                                let mut mem = guest.memory();
                                let addr: reverie::syscalls::AddrMut<u8> =
                                    unsafe { std::mem::transmute_copy(&dirent) };
                                let _ = mem.write(addr, &chunk);
                                return Ok(chunk.len() as i64);
                            }
                            return Ok(0);
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
                                .dirent_pending
                                .contains_key(&fd)
                        {
                            // Kernel EOF (once per fd): stage
                            // synthetic entries for bind children
                            // not yet seen. Mark done first so a
                            // following getdents returns real EOF.
                            self.state
                                .lock()
                                .unwrap()
                                .dirent_pending
                                .insert(fd, Vec::new());
                            let guest_dir = {
                                let st = self.state.lock().unwrap();
                                st.fds.get(&fd).cloned()
                            };
                            if let Some(gd_path) = guest_dir {
                                let synth =
                                    self.build_synth_dirents(guest, &gd_path, true);
                                if !synth.is_empty() {
                                    // Serve synthetic entries now
                                    // (same shape as the pending
                                    // path above, without recursion).
                                    use reverie::syscalls::MemoryAccess as _;
                                    if synth.len() <= gd.count() as usize {
                                        if let Some(dirent) = gd.dirent() {
                                            let mut mem = guest.memory();
                                            let addr: reverie::syscalls::AddrMut<u8> =
                                                unsafe {
                                                    std::mem::transmute_copy(&dirent)
                                                };
                                            let _ = mem.write(addr, &synth);
                                            return Ok(synth.len() as i64);
                                        }
                                    } else {
                                        let mut st = self.state.lock().unwrap();
                                        st.dirent_pending.insert(fd, synth);
                                        drop(st);
                                        let pend = {
                                            let st = self.state.lock().unwrap();
                                            st.dirent_pending
                                                .get(&fd)
                                                .cloned()
                                                .unwrap_or_default()
                                        };
                                        let take =
                                            pend.len().min(gd.count() as usize);
                                        if let Some(dirent) = gd.dirent() {
                                            let mut mem = guest.memory();
                                            let addr: reverie::syscalls::AddrMut<u8> =
                                                unsafe {
                                                    std::mem::transmute_copy(&dirent)
                                                };
                                            let _ = mem.write(addr, &pend[..take]);
                                            let rest = pend[take..].to_vec();
                                            self.state
                                                .lock()
                                                .unwrap()
                                                .dirent_pending
                                                .insert(fd, rest);
                                            return Ok(take as i64);
                                        }
                                    }
                                    return Ok(0);
                                }
                            }
                        }
                        Ok(ret)
                    }
                    Some((_, true)) => Ok(0),
                    Some((guest_dir, false)) => {
                        {
                            let mut st = self.state.lock().unwrap();
                            if let Some(v) = st.virtual_fds.get_mut(&(gd.fd() as i32)) {
                                v.1 = true;
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
                let host = self.translate_for(guest, libc::AT_FDCWD, &guest_path);
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        chdir.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                let ret = guest.inject(rewritten).await?;
                if ret == 0 {
                    let mut st = self.state.lock().unwrap();
                    st.cwd = self.guest_abs(guest, &st, libc::AT_FDCWD, &guest_path);
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
                if clone_is_process(fam.flags(&guest.memory()).bits()) {
                    if let Err(e) = self.stage_fork_snapshot(guest) {
                        return Err(e.into());
                    }
                    let ret = guest.inject(clone).await;
                    self.clear_exec_snapshot(guest);
                    Ok(ret?)
                } else {
                    Ok(guest.inject(clone).await?)
                }
            }
            Syscall::Clone3(clone3) => {
                let fam = reverie::syscalls::family::CloneFamily::Clone3(clone3);
                if clone_is_process(fam.flags(&guest.memory()).bits()) {
                    if let Err(e) = self.stage_fork_snapshot(guest) {
                        return Err(e.into());
                    }
                    let ret = guest.inject(clone3).await;
                    self.clear_exec_snapshot(guest);
                    Ok(ret?)
                } else {
                    Ok(guest.inject(clone3).await?)
                }
            }
            #[cfg(not(target_arch = "aarch64"))]
            Syscall::Fork(fork) => {
                if let Err(e) = self.stage_fork_snapshot(guest) {
                    return Err(e.into());
                }
                let ret = guest.inject(fork).await;
                self.clear_exec_snapshot(guest);
                Ok(ret?)
            }
            #[cfg(not(target_arch = "aarch64"))]
            Syscall::Vfork(vfork) => {
                if let Err(e) = self.stage_fork_snapshot(guest) {
                    return Err(e.into());
                }
                let ret = guest.inject(vfork).await;
                self.clear_exec_snapshot(guest);
                Ok(ret?)
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
                if is_self_exe(&guest_path, guest.pid().as_raw()) {
                    guest_path = self.exe_guest(guest);
                }
                {
                    let abs = {
                        let st = self.state.lock().unwrap();
                        self.guest_abs(guest, &st, libc::AT_FDCWD, &guest_path)
                    };
                    let canon = self.canonical_exe(guest, &abs);
                    pid_exe_map()
                        .lock()
                        .unwrap()
                        .insert(guest.pid().as_raw(), canon);
                    let mut st = self.state.lock().unwrap();
                    st.exe_guest = abs;
                }
                let host = self.translate_follow(guest, libc::AT_FDCWD, &guest_path);
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot-tool: execve {guest_path:?} -> {host:?}");
                }
                // PT_INTERP rewrite (design §4.7): exec the rootfs
                // dynamic linker with the guest program as its
                // argument, reusing the original argv pointers
                // (only the pointer array + interp path are staged).
                // Shebang scripts: the kernel would open the
                // #! interpreter on the HOST (measured: apk
                // trigger scripts ran host /bin/sh). Rewrite to
                // exec the guest interpreter with the script as
                // its argument, then apply the PT_INTERP logic to
                // that interpreter via a plain translated exec of
                // its loader chain (exec_via_interp on the script
                // interpreter's ELF).
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
                // fd-path scripts: skip sniffing entirely —
                // reading the fd would drain pipe input.
                let shebang = if is_fd_path {
                    None
                } else {
                    std::fs::read(&host_for_tool_read(&host, guest.pid().as_raw()))
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
                            self.clear_exec_snapshot(guest);
                            return res;
                        }
                        Err(e) => {
                            self.clear_exec_snapshot(guest);
                            return Err(e);
                        }
                    }
                }
                let interp = if is_fd_path {
                    None
                } else {
                    std::fs::read(&host_for_tool_read(&host, guest.pid().as_raw()))
                        .ok()
                        .and_then(|img| crate::translate::elf_interp(&img))
                };
                if let Some(interp_guest) = interp {
                    match self
                        .exec_via_interp(guest, execve, &guest_path, &interp_guest)
                        .await
                    {
                        Ok(res) => {
                            self.clear_exec_snapshot(guest);
                            return res;
                        }
                        Err(e) => {
                            self.clear_exec_snapshot(guest);
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
                let scratch = self.scratch_write(guest, &path_bytes).await?;
                let rewritten = execve.with_path(PathPtr::from_ptr(
                    scratch as *const libc::c_char,
                ));
                if let Err(e) = self.stage_snapshot(guest) {
                    return Err(e.into());
                }
                // Success does not return; mirror strace-tool shape.
                let e = guest.inject(rewritten).await.unwrap_err();
                self.clear_exec_snapshot(guest);
                Err(e.into())
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
            Syscall::Setxattr(x) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    let _ = x;
                    Ok(0)
                } else {
                    Ok(guest.inject(x).await?)
                }
            }
            Syscall::Lsetxattr(x) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    let _ = x;
                    Ok(0)
                } else {
                    Ok(guest.inject(x).await?)
                }
            }
            Syscall::Fsetxattr(x) => {
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] == 0 {
                    let _ = x;
                    Ok(0)
                } else {
                    Ok(guest.inject(x).await?)
                }
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
                    if let Some(name) = sh.name() {
                        let mut v = vec![0u8; sh.len()];
                        let mem = guest.memory();
                        use reverie::syscalls::MemoryAccess as _;
                        let addr: reverie::syscalls::Addr<u8> =
                            unsafe { std::mem::transmute_copy(&name) };
                        if mem.read(addr, &mut v).is_ok() {
                            *UTS_NODENAME.lock().unwrap() =
                                Some(String::from_utf8_lossy(&v).into_owned());
                            if let Some(store) = shared_record_file() {
                                let _ = store.set_uts_nodename(Some(v));
                            }
                        }
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(sh).await?)
                }
            }
            Syscall::Setdomainname(sd) => {
                if self.fake_ids(guest).is_some() {
                    if let Some(name) = sd.name() {
                        let mut v = vec![0u8; sd.len()];
                        let mem = guest.memory();
                        use reverie::syscalls::MemoryAccess as _;
                        let addr: reverie::syscalls::Addr<u8> =
                            unsafe { std::mem::transmute_copy(&name) };
                        if mem.read(addr, &mut v).is_ok() {
                            *UTS_DOMAIN.lock().unwrap() =
                                Some(String::from_utf8_lossy(&v).into_owned());
                            if let Some(store) = shared_record_file() {
                                let _ = store.set_uts_domainname(Some(v));
                            }
                        }
                    }
                    Ok(0)
                } else {
                    Ok(guest.inject(sd).await?)
                }
            }
            // ---- chroot emulation: re-root replicated state ----
            Syscall::Chroot(cr) => {
                // Only fake-root may chroot (proot: non-root fake
                // ids get the kernel EPERM).
                if self.fake_ids(guest).is_some() && self.fake_state(guest)[1] != 0 {
                    return Ok(guest.inject(cr).await?);
                }
                let Some(pp) = cr.path() else {
                    return Ok(guest.inject(cr).await?);
                };
                let g = pp.read(&guest.memory())?;
                let host = self.translate_follow(guest, libc::AT_FDCWD, &g);
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
                match self.stage_sockaddr(guest, b.umyaddr(), b.addrlen()).await? {
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
                match self.stage_sockaddr(guest, c.uservaddr(), c.addrlen()).await? {
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
        }
    }
}

impl RootfsTool {
    /// Stage bytes in the per-process guest scratch page
    /// (injected anonymous mmap, allocated once). Returns the
    /// guest address. Used for execve paths, where guest-stack
    /// staging is unsafe (see ProcState::scratch).
    async fn scratch_write<T: Guest<Self>>(
        &self,
        guest: &mut T,
        bytes: &[u8],
    ) -> Result<usize, Error> {
        self.scratch_write_at(guest, bytes, 0).await
    }

    async fn scratch_write_at<T: Guest<Self>>(
        &self,
        guest: &mut T,
        bytes: &[u8],
        offset: usize,
    ) -> Result<usize, Error> {
        use reverie::syscalls::MemoryAccess as _;
        let existing = self.state.lock().unwrap().scratch;
        let base = match existing {
            Some(b) => b,
            None => {
                let mmap = reverie::syscalls::Mmap::new()
                    .with_addr(None)
                    .with_len(4096)
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
                self.state.lock().unwrap().scratch = Some(addr);
                addr
            }
        };
        let mut mem = guest.memory();
        let addr: reverie::syscalls::AddrMut<u8> =
            unsafe { reverie::syscalls::AddrMut::from_raw_unchecked(base + offset) };
        mem.write(addr, bytes)?;
        Ok(base + offset)
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
        let interp_host = cfg.translate(Path::new(interp_guest), Path::new("/"), None);
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
        let e = guest.inject(rewritten).await.unwrap_err();
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
        let interp_host = {
            let h = cfg.translate(Path::new(script_interp), Path::new("/"), None);
            resolve_symlink_chain(&cfg, h)
        };
        // The interpreter's own loader, if it is a dynamic ELF.
        let loader_host = std::fs::read(&interp_host)
            .ok()
            .and_then(|img| crate::translate::elf_interp(&img))
            .map(|ld| {
                let h = cfg.translate(Path::new(&ld), Path::new("/"), None);
                resolve_symlink_chain(&cfg, h)
            });
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
        let e = guest.inject(rewritten).await.unwrap_err();
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
        let host = cfg.translate(p, Path::new("/"), None);
        let resolved = resolve_symlink_chain(&cfg, host);
        cfg.reverse(&resolved).unwrap_or_else(|| p.to_path_buf())
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
        let old_abs = self.guest_abs(guest, &st, old_dirfd, old_g);
        let new_abs = self.guest_abs(guest, &st, new_dirfd, new_g);
        if let Ok(suffix) = st.cwd.clone().strip_prefix(&old_abs).map(|s| s.to_path_buf()) {
            let mut p = new_abs;
            if !suffix.as_os_str().is_empty() {
                p.push(suffix);
            }
            st.cwd = p;
        }
    }

    fn fake_ids<T: Guest<Self>>(&self, guest: &T) -> Option<(u32, u32)> {
        self.config(guest).fake_ids
    }

    fn fake_state<T: Guest<Self>>(&self, guest: &T) -> [u32; 6] {
        let fake_cfg = self.fake_ids(guest);
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

    /// /proc/self/cmdline (or own-pid) synthesis: the kernel
    /// buffer names our loader argv; guests must see the
    /// as-exec'd argv. Returns a host temp-file fd via injected
    /// openat, or None to fall through.
    async fn open_synthetic_cmdline<T: Guest<Self>>(
        &self,
        guest: &mut T,
        guest_path: &Path,
    ) -> Option<i64> {
        let comps: Vec<String> = guest_path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(v) => Some(v.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        let target_pid: Option<i32> = if comps.len() == 3 && comps[0] == "proc" && comps[2] == "cmdline" {
            if comps[1] == "self" || comps[1] == "thread-self" {
                Some(guest.pid().as_raw())
            } else {
                comps[1].parse().ok()
            }
        } else {
            None
        };
        let Some(target_pid) = target_pid else { return None };
        let argv: Vec<Vec<u8>> = if target_pid == guest.pid().as_raw() {
            let materialized = self.current_argv(guest.config());
            if materialized.is_empty() {
                return None;
            }
            materialized
        } else {
            let argv = match Self::shared_process_record(target_pid) {
                Some(row) => row.argv,
                None => match pid_argv_map().lock().unwrap().get(&target_pid) {
                    Some(a) => a.clone(),
                    None => return None,
                },
            };
            if argv.is_empty() {
                let init = guest.config().initial_argv.clone();
                if init.is_empty() {
                    return None;
                }
                init.into_iter().map(|s| s.into_bytes()).collect::<Vec<_>>()
            } else {
                argv
            }
        };
        let mut content: Vec<u8> = Vec::new();
        for a in &argv {
            content.extend_from_slice(a);
            content.push(0);
        }
        let tmp = format!("/tmp/.literoot-cmdline-{}", guest.pid().as_raw());
        std::fs::write(&tmp, &content).ok()?;
        let open_req = reverie::syscalls::Openat::new()
            .with_dirfd(libc::AT_FDCWD)
            .with_flags(reverie::syscalls::OFlag::O_RDONLY);
        let (_g, rewritten) = self
            .with_guest_path(guest, Path::new(&tmp), |ptr| {
                open_req.with_path(PathPtr::from_ptr(ptr))
            })
            .await
            .ok()?;
        let r = guest.inject(rewritten).await.ok();
        let _ = std::fs::remove_file(&tmp);
        r
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
                    st.virtual_fds
                        .insert(fd as i32, (guest_abs.to_path_buf(), false));
                    st.fds.insert(fd as i32, guest_abs.to_path_buf());
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
        self.state
            .lock()
            .unwrap()
            .dirent_seen
            .insert(fd, names);
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
            match st.fds.get(&dirfd) {
                Some(d) => {
                    let mut p = d.clone();
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

    /// True when a relative path's dirfd is unknown and not
    /// recoverable as a directory: the syscall must pass through
    /// untranslated so the kernel reports ENOTDIR/EBADF itself
    /// (test-openat-fd-edge-cases). Recoverable dirfds are
    /// cached into the fd table.
    fn dirfd_passthrough<T: Guest<Self>>(&self, guest: &T, dirfd: i32, path: &Path) -> bool {
        if path.is_absolute() || dirfd == libc::AT_FDCWD {
            return false;
        }
        {
            let st = self.state.lock().unwrap();
            if st.fds.contains_key(&dirfd) {
                return false;
            }
        }
        if let Ok(target) =
            std::fs::read_link(format!("/proc/{}/fd/{}", guest.pid().as_raw(), dirfd))
        {
            let cfg = self.config(guest);
            if target.is_dir() {
                if let Some(g) = cfg.reverse(&target) {
                    self.state.lock().unwrap().fds.insert(dirfd, g);
                    return false;
                }
            }
        }
        true
    }

    fn translate_for<T: Guest<Self>>(&self, guest: &T, dirfd: i32, path: &Path) -> PathBuf {
        if let Some(hit) = self.memoized_translate(dirfd, path, false) {
            return hit;
        }
        let host = self.translate_for_uncached(guest, dirfd, path);
        self.memoize_translate(dirfd, path, false, &host);
        host
    }

    fn memoized_translate(&self, dirfd: i32, path: &Path, follow: bool) -> Option<PathBuf> {
        let st = self.state.lock().unwrap();
        let key = (st.dispatch_seq, dirfd, path.to_path_buf(), follow);
        st.translate_memo
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.clone())
    }

    fn memoize_translate(&self, dirfd: i32, path: &Path, follow: bool, host: &Path) {
        let mut st = self.state.lock().unwrap();
        let key = (st.dispatch_seq, dirfd, path.to_path_buf(), follow);
        st.translate_memo.push((key, host.to_path_buf()));
    }

    fn translate_for_uncached<T: Guest<Self>>(&self, guest: &T, dirfd: i32, path: &Path) -> PathBuf {
        let cfg = self.config(guest);
        let st = self.state.lock().unwrap();
        let cwd = if st.cwd == Path::new("/__literoot_unset__") {
            self.seed_cwd(guest)
        } else {
            st.cwd.clone()
        };
        let dirfd_guest = if dirfd == libc::AT_FDCWD {
            None
        } else if let Some(p) = st.fds.get(&dirfd).cloned() {
            Some(p)
        } else {
            // Unknown dirfd (inherited, SCM_RIGHTS, stdin...):
            // recover its guest path via /proc/<pid>/fd; non-path
            // fds (pipe/socket) recover to None-of-a-flag: use a
            // sentinel guest path that makes translate produce a
            // path under the fd's own name so the kernel still
            // reports ENOTDIR/EBADF faithfully is NOT possible —
            // instead record the recovery or mark unknown.
            match std::fs::read_link(format!("/proc/{}/fd/{}", guest.pid().as_raw(), dirfd)) {
                Ok(target) => cfg.reverse(&target),
                Err(_) => None,
            }
        };
        // Unknown non-path dirfd: relative resolution against cwd
        // would fabricate ENOENT where the kernel says ENOTDIR.
        // Signal via cwd sentinel handled by callers is complex;
        // the common case (dirfd is a real directory) recovers
        // above. Remaining unknown fds keep cwd-relative
        // behaviour — retained gap for pipe/socket dirfds is
        // fixed by the Openat arm's explicit check below.
        let _ = &dirfd_guest;
        // /proc magic links (fd/exe/root/cwd/map_files) must not
        // be lexically normalized: ".." after a magic component
        // is an error in the kernel, not a parent traversal
        // (test-proc-self-readlink-edge-cases).
        if is_magic_proc_path(path) {
            let mut host = cfg.translate_raw(path, &cwd);
            use std::os::unix::ffi::OsStrExt as _;
            let bytes = path.as_os_str().as_bytes();
            if bytes.len() > 1 && bytes.ends_with(b"/") {
                host.push("");
            }
            return host;
        }
        let mut host = cfg.translate(path, &cwd, dirfd_guest.as_deref());
        if std::env::var_os("LITEROOT_DEBUG").is_some() {
            eprintln!("literoot-tool: translate {path:?} cwd={cwd:?} -> {host:?}");
        }
        // Preserve a trailing slash: the kernel distinguishes
        // readlink/open on "x/" (ENOTDIR/EINVAL) from "x", and
        // lexical normalization would erase it.
        {
            use std::os::unix::ffi::OsStrExt as _;
            let bytes = path.as_os_str().as_bytes();
            if bytes.len() > 1 && bytes.ends_with(b"/") {
                host.push("");
            }
        }
        host
    }

    /// translate_for + final-component symlink following, for
    /// syscalls that follow symlinks (open/stat/access). Lstat and
    /// readlink must use plain translate_for.
    fn translate_follow<T: Guest<Self>>(&self, guest: &T, dirfd: i32, path: &Path) -> PathBuf {
        if let Some(hit) = self.memoized_translate(dirfd, path, true) {
            return hit;
        }
        let cfg = self.config(guest);
        let host = self.translate_for(guest, dirfd, path);
        let resolved = resolve_symlink_chain(&cfg, host);
        self.memoize_translate(dirfd, path, true, &resolved);
        resolved
    }

    /// Stage a translated AF_UNIX sockaddr copy on the guest
    /// stack. Some((guard, raw_ptr, new_addrlen)) or None to pass
    /// through (non-Unix family, abstract socket, fault).
    async fn stage_sockaddr<T: Guest<Self>>(
        &self,
        guest: &mut T,
        addr: Option<reverie::syscalls::AddrMut<'_, libc::sockaddr>>,
        addrlen: i32,
    ) -> Result<
        Option<(
            <<T as Guest<Self>>::Stack as reverie::Stack>::StackGuard,
            usize,
            i32,
        )>,
        Error,
    > {
        use reverie::Stack as _;
        use reverie::syscalls::MemoryAccess as _;
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
        // AF_UNIX=1, non-abstract (sun_path[0] != 0), absolute only.
        if buf[0] != libc::AF_UNIX as u8 || buf.get(2) != Some(&b'/') {
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
        let host = self.translate_for(guest, libc::AT_FDCWD, &guest_path);
        use std::os::unix::ffi::OsStrExt as _;
        let hb = host.as_os_str().as_bytes();
        if hb.len() + 3 > 110 {
            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
        }
        let mut out = [0u8; 128];
        out[0] = buf[0];
        out[1] = buf[1];
        out[2..2 + hb.len()].copy_from_slice(hb);
        let mut stack = guest.stack().await;
        let a = stack.push(out);
        let guard = stack.commit()?;
        let raw = unsafe { a.as_ptr() } as usize;
        Ok(Some((guard, raw, (2 + hb.len() + 1) as i32)))
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
    fn detranslate_into<T: Guest<Self>>(
        &self,
        guest: &mut T,
        link_host: &Path,
        link_guest: &Path,
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
        let cfg = self.config(guest);
        // /proc/self/exe and /proc/self/root are synthesized from
        // replicated state, not de-translated: the kernel values
        // name the loader / host root under our exec model.
        let norm_guest = cfg.translate(link_guest, Path::new("/"), None);
        let _ = norm_guest;
        let guest_bytes = if link_guest == Path::new("/proc/self/root")
            || link_guest == Path::new("/proc/thread-self/root")
        {
            use std::os::unix::ffi::OsStrExt as _;
            cfg.rootfs.as_os_str().as_bytes().to_vec()
        } else if is_self_exe(link_guest, guest.pid().as_raw()) {
            use std::os::unix::ffi::OsStrExt as _;
            let raw = self.exe_guest(guest);
            self.canonical_exe(guest, &raw)
                .as_os_str()
                .as_bytes()
                .to_vec()
        } else if let Some(other) = proc_pid_exe(link_guest) {
            use std::os::unix::ffi::OsStrExt as _;
            match Self::shared_process_record(other) {
                Some(row) => row.exe_guest,
                None => match pid_exe_map().lock().unwrap().get(&other) {
                    Some(p) => p.as_os_str().as_bytes().to_vec(),
                    None => {
                        cfg.detranslate_readlink(link_host, link_guest, &stored)
                    }
                },
            }
        } else {
            cfg.detranslate_readlink(link_host, link_guest, &stored)
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
/// wrong task; the guest's pid names the right one.
fn host_for_tool_read(host: &Path, guest_pid: i32) -> PathBuf {
    let s = host.to_string_lossy();
    for needle in ["/proc/self/", "/proc/thread-self/"] {
        if let Some(idx) = s.find(needle) {
            let mut out = String::with_capacity(s.len() + 8);
            out.push_str(&s[..idx]);
            out.push_str(&format!("/proc/{guest_pid}/"));
            out.push_str(&s[idx + needle.len()..]);
            return PathBuf::from(out);
        }
    }
    if s.ends_with("/proc/self") || s.ends_with("/proc/thread-self") {
        let base = s.trim_end_matches("/proc/self").trim_end_matches("/proc/thread-self");
        return PathBuf::from(format!("{base}/proc/{guest_pid}"));
    }
    host.to_path_buf()
}


fn init_fake(ids: Option<(u32, u32)>) -> [u32; 6] {
    let (u, g) = ids.unwrap_or((0, 0));
    [u, u, u, g, g, g]
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
    // /proc/<pid-or-self>/<magic>/...
    magic.contains(&comps[2].as_str()) && comps.len() > 3
}

/// Parse /proc/<pid>/exe (any pid) after lexical normalization.
fn proc_pid_exe(link_guest: &Path) -> Option<i32> {
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
    if comps.len() == 3 && comps[0] == "proc" && comps[2] == "exe" {
        comps[1].to_string_lossy().parse().ok()
    } else {
        None
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


fn resolve_symlink_chain(cfg: &RootConfig, host: PathBuf) -> PathBuf {
    // Never follow /proc magic links Tool-side: readlink from
    // the Tool process names the wrong task's objects
    // (measured: guest fd/0 resolved to the tracer's pipe).
    {
        let comps: Vec<String> = host
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(v) => Some(v.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        if comps.len() >= 3
            && comps[comps.len() - 3] == "proc"
            && ["fd", "exe", "root", "cwd", "map_files"]
                .contains(&comps[comps.len() - 1].as_str())
        {
            return host;
        }
        if comps.len() >= 2 && comps[0] == "proc" {
            // Any /proc/<x>/fd|exe|... final magic component.
            let last2 = &comps[comps.len() - 2..];
            if last2[0] == "fd" || comps[1] == "self" || comps[1] == "thread-self" {
                return host;
            }
        }
    }
    let mut cur = host;
    for _ in 0..40 {
        match std::fs::read_link(&cur) {
            Ok(target) if target.is_absolute() => {
                cur = cfg.translate(&target, Path::new("/"), None);
            }
            Ok(target) => {
                let mut next = cur
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("/"));
                next.push(target);
                cur = next;
            }
            Err(_) => break,
        }
    }
    cur
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
static UTS_DOMAIN: Mutex<Option<String>> = Mutex::new(None);

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
mod tests {
    use super::*;
    use crate::exec_state::ExecState;

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
        assert_eq!(st.fds.get(&5), Some(&PathBuf::from("/work")));
        assert_eq!(st.fake, Some([1000, 0, 0, 100, 0, 100]));
        assert_eq!(st.exe_guest, PathBuf::from("/bin/sh"));
        assert!(st.bootstrapped);
        assert_eq!(st.scratch, None);
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
                fork_seed_if_bootstrapped(&st, &cfg, Path::new("/bin/sh"), &current_argv),
                None
            );
            // The checked constructor still refuses by name if
            // a future caller bypasses the production gate.
            let result = fork_seed(&st, &cfg, Path::new("/bin/sh"), &current_argv);
            assert_eq!(result, Err(reverie::syscalls::Errno::EINVAL));
            assert_eq!(st.fake, fake_before);
        }
        {
            let mut st = tool.state.lock().unwrap();
            st.bootstrapped = true;
            st.fake = Some([9, 8, 7, 6, 5, 4]);
            let seed = fork_seed_if_bootstrapped(&st, &cfg, Path::new("/bin/sh"), &current_argv)
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
}
