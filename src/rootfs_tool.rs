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

use crate::translate::{Bind, RootConfig};

/// Serializable launch config (GlobalTool::Config).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiterootConfig {
    pub rootfs: String,
    pub binds: Vec<(String, String)>, // (guest, host)
    pub cwd: String,
    pub fake_root: bool,
    pub fake_uid: Option<u32>,
    pub fake_gid: Option<u32>,
    pub kernel_release: Option<String>,
    /// Guest path of the initial program (argv-resolved).
    pub initial_exe: String,
}

impl LiterootConfig {
    fn to_root_config(&self) -> RootConfig {
        let mut c = RootConfig::new(
            PathBuf::from(&self.rootfs),
            self.binds
                .iter()
                .map(|(g, h)| Bind { guest: PathBuf::from(g), host: PathBuf::from(h), no_follow: false })
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
#[derive(Debug)]
struct ProcState {
    cwd: PathBuf,
    /// fd → guest path it denotes (for *at resolution, §4.3).
    fds: HashMap<i32, PathBuf>,
    /// False until the initial (launcher-issued) execve has passed:
    /// its path is already a host path and must not be translated.
    bootstrapped: bool,
    /// Emulated chroot: host directory acting as the new root.
    root_override: Option<PathBuf>,
    /// Guest path of the current program image (for
    /// /proc/self/exe de-translation; seeded from Config).
    exe_guest: PathBuf,
    /// Fds opened on virtual bind-prefix dirs:
    /// guest dir -> entries already emitted.
    virtual_fds: std::collections::HashMap<i32, (PathBuf, bool)>,
    /// Stateful fake identity (r/e/s uid+gid) under -0/-i:
    /// setres* must be observable via getres* afterwards.
    fake: Option<[u32; 6]>,
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
                exe_guest: PathBuf::new(),
                fake: None,
                virtual_fds: std::collections::HashMap::new(),
            }),
        }
    }
}

// Reverie's ptrace guest-stack arena is ~896 bytes total; stage at
// most 768 bytes of translated path (POC limit — the in-guest
// backend uses Tool-region scratch instead, design §6).
const PATH_BUF: usize = 768;

#[reverie::tool]
impl Tool for RootfsTool {
    type GlobalState = LiterootGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &LiterootConfig) -> Subscription {
        let mut subs = Subscription::none();
        subs.syscalls([
            Sysno::openat,
            Sysno::open,
            Sysno::stat,
            Sysno::lstat,
            Sysno::access,
            Sysno::newfstatat,
            Sysno::readlinkat,
            Sysno::readlink,
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
            Sysno::rename,
            Sysno::link,
            Sysno::symlink,
            Sysno::rmdir,
            Sysno::unlink,
            Sysno::mkdir,
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
            Sysno::capset,
            Sysno::setxattr,
            Sysno::lsetxattr,
            Sysno::fsetxattr,
            Sysno::bind,
            Sysno::connect,
            Sysno::getsockname,
            Sysno::chmod,
            Sysno::chown,
            Sysno::lchown,
        ]);
        subs
    }

    async fn handle_post_exec<T: Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::syscalls::Errno> {
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
        let mut stack = guest.stack().await;
        let addr = stack.push(cell);
        if stack.commit().is_ok() {
            let prctl = reverie::syscalls::Prctl::new()
                .with_option(libc::PR_SET_NAME)
                .with_arg2(unsafe { addr.as_ptr() } as u64);
            let _ = guest.inject(prctl).await;
        }
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
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
                let Some(path_ptr) = openat.path() else {
                    return Ok(guest.inject(openat).await?);
                };
                let mut guest_path = path_ptr.read(&guest.memory())?;
                if is_self_exe(&guest_path, guest.pid().as_raw()) {
                    guest_path = self.exe_guest(guest);
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
                            self.guest_abs(&st, openat.dirfd(), &guest_path)
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
                    let abs = self.guest_abs(&st, openat.dirfd(), &guest_path);
                    st.fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
            Syscall::Open(open) => {
                // Legacy open(2): musl ld.so uses it (measured:
                // without this arm, musl guests loaded host files).
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
                    let abs = self.guest_abs(&st, libc::AT_FDCWD, &guest_path);
                    st.fds.insert(ret as i32, abs);
                }
                Ok(ret)
            }
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
                    self.spoof_stat_ids(guest, buf_raw, 28, 32);
                }
                Ok(ret)
            }
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
                    self.spoof_stat_ids(guest, buf_raw, 28, 32);
                }
                Ok(ret)
            }
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
                    self.guest_abs(&st, stat.dirfd(), &guest_path)
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
                        self.write_virtual_dir_stat(guest, buf_raw, 24);
                        0
                    }
                    Err(e) => return Err(e.into()),
                };
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, 28, 32);
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
                crate::translate::bump_probe_gen();
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
                crate::translate::bump_probe_gen();
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
                crate::translate::bump_probe_gen();
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
                crate::translate::bump_probe_gen();
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
                crate::translate::bump_probe_gen();
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
                crate::translate::bump_probe_gen();
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
            Syscall::Rename(rn) => {
                crate::translate::bump_probe_gen();
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
            Syscall::Link(ln) => {
                crate::translate::bump_probe_gen();
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
            Syscall::Symlink(sl) => {
                crate::translate::bump_probe_gen();
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
            Syscall::Rmdir(rd) => {
                crate::translate::bump_probe_gen();
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
            Syscall::Unlink(un) => {
                crate::translate::bump_probe_gen();
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
            Syscall::Mkdir(md) => {
                crate::translate::bump_probe_gen();
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
                crate::translate::bump_probe_gen();
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
                if self.config(guest).fake_root {
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
                            self.guest_abs(&st, sx.dirfd(), &g)
                        };
                        if self.is_virtual_bind_dir(guest, &abs) {
                            self.write_virtual_dir_stat(guest, buf_raw, 28);
                            0
                        } else {
                            return Err(e.into());
                        }
                    }
                    Err(e) => return Err(e.into()),
                };
                if ret == 0 {
                    self.spoof_stat_ids(guest, buf_raw, 20, 24);
                }
                Ok(ret)
            }
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
            Syscall::Chown(co) => {
                if self.fake_ids(guest).is_some() {
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
            Syscall::Lchown(co) => {
                if self.fake_ids(guest).is_some() {
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
            Syscall::Getdents64(gd) => {
                let virt = {
                    let st = self.state.lock().unwrap();
                    st.virtual_fds.get(&(gd.fd() as i32)).cloned()
                };
                match virt {
                    None => Ok(guest.inject(gd).await?),
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
                    st.cwd = self.guest_abs(&st, libc::AT_FDCWD, &guest_path);
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
                if is_self_exe(&guest_path, guest.pid().as_raw()) {
                    guest_path = self.exe_guest(guest);
                }
                {
                    let abs = {
                        let st = self.state.lock().unwrap();
                        self.guest_abs(&st, libc::AT_FDCWD, &guest_path)
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
                    match self
                        .exec_script(guest, execve, &guest_path, &script_interp, optarg.as_deref())
                        .await
                    {
                        Ok(never) => return never,
                        Err(e) => return Err(e),
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
                        Ok(never) => return never,
                        Err(e) => return Err(e),
                    }
                }
                let (_guard, rewritten) = self
                    .with_guest_path(guest, &host, |ptr| {
                        execve.with_path(PathPtr::from_ptr(ptr))
                    })
                    .await?;
                // Success does not return; mirror strace-tool shape.
                let e = guest.inject(rewritten).await.unwrap_err();
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
        let e = guest.inject(rewritten).await.unwrap_err();
        Ok(Err(e.into()))
    }

    fn config<T: Guest<Self>>(&self, guest: &T) -> RootConfig {
        // Authoritative on every backend: the backend delivers the
        // GlobalTool Config to each guest handle (in-guest tools
        // run in a different process than the launcher, so a
        // process-global stash cannot work there).
        let mut cfg = guest.config().to_root_config();
        if let Some(root) = self.state.lock().unwrap().root_override.clone() {
            cfg.rootfs = root;
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
            if init.is_empty() {
                PathBuf::from("/proc/self/exe")
            } else {
                // Must be absolute: glibc _dl_get_origin asserts
                // /proc/self/exe starts with '/' (measured abort
                // in test-fork-vfork-execve with ./prog).
                let p = PathBuf::from(init);
                if p.is_absolute() {
                    p
                } else {
                    let cfg = self.config(guest);
                    let host = cfg.translate(&p, &self.seed_cwd(guest), None);
                    cfg.reverse(&host).unwrap_or(p)
                }
            }
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
        let old_abs = self.guest_abs(&st, old_dirfd, old_g);
        let new_abs = self.guest_abs(&st, new_dirfd, new_g);
        let _ = guest;
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
        let nodename = UTS_NODENAME.lock().unwrap().clone();
        let domain = UTS_DOMAIN.lock().unwrap().clone();
        if kr.is_none() && nodename.is_none() && domain.is_none() {
            return;
        }
        // Parse proot -k: backslash-separated UTS fields, "0" or
        // empty keeps the kernel value; no backslash = release.
        let mut fields: [Option<String>; 6] = Default::default();
        if let Some(k) = &kr {
            if k.contains('\\') {
                for (i, part) in k.split('\\').take(6).enumerate() {
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

    fn guest_abs(&self, st: &ProcState, dirfd: i32, path: &Path) -> PathBuf {
        let cfg_cwd = if st.cwd == Path::new("/__literoot_unset__") {
            CONFIG
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| PathBuf::from(&c.cwd))
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| PathBuf::from("/"))
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
        let cfg = self.config(guest);
        let host = self.translate_for(guest, dirfd, path);
        resolve_symlink_chain(&cfg, host)
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
            match pid_exe_map().lock().unwrap().get(&other) {
                Some(p) => p.as_os_str().as_bytes().to_vec(),
                None => cfg.detranslate_readlink(link_host, link_guest, &stored),
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
        if mem.write(addr, &guest_bytes[..write_n]).is_err() {
            return ret;
        }
        write_n as i64
    }

    /// Two-path variant of `with_guest_path` (rename/link): both
    /// strings staged under one stack guard (2×256B budget each).
    async fn with_two_guest_paths<T: Guest<Self>, S, F>(
        &self,
        guest: &mut T,
        host_a: &Path,
        host_b: &Path,
        f: F,
    ) -> Result<(<<T as Guest<Self>>::Stack as reverie::Stack>::StackGuard, S), Error>
    where
        F: FnOnce(*const libc::c_char, *const libc::c_char) -> S,
    {
        use reverie::Stack as _;
        let stage = |p: &Path| -> Result<[u8; 256], Error> {
            let c = CString::new(p.as_os_str().as_bytes())
                .map_err(|_| reverie::syscalls::Errno::EINVAL)?;
            let b = c.as_bytes_with_nul();
            if b.len() > 256 {
                return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
            }
            let mut buf = [0u8; 256];
            buf[..b.len()].copy_from_slice(b);
            Ok(buf)
        };
        let mut stack = guest.stack().await;
        let a = stack.push(stage(host_a)?);
        let b = stack.push(stage(host_b)?);
        let guard = stack.commit()?;
        let pa = unsafe { a.as_ptr() } as *const libc::c_char;
        let pb = unsafe { b.as_ptr() } as *const libc::c_char;
        Ok((guard, f(pa, pb)))
    }

    /// Stage `host` path bytes on the guest stack and build the
    /// rewritten syscall with `f`. The returned guard MUST be held
    /// by the caller across `inject` (dropping it sooner frees the
    /// staged bytes — measured: guest then reads garbage paths).
    async fn with_guest_path<T: Guest<Self>, S, F>(
        &self,
        guest: &mut T,
        host: &Path,
        f: F,
    ) -> Result<(<<T as Guest<Self>>::Stack as reverie::Stack>::StackGuard, S), Error>
    where
        F: FnOnce(*const libc::c_char) -> S,
    {
        use reverie::Stack as _;
        let cstr = CString::new(host.as_os_str().as_bytes())
            .map_err(|_| reverie::syscalls::Errno::EINVAL)?;
        let bytes = cstr.as_bytes_with_nul();
        if bytes.len() > PATH_BUF {
            return Err(reverie::syscalls::Errno::ENAMETOOLONG.into());
        }
        let mut buf = [0u8; PATH_BUF];
        buf[..bytes.len()].copy_from_slice(bytes);
        let mut stack = guest.stack().await;
        let addr = stack.push(buf);
        let guard = stack.commit()?;
        let ptr = unsafe { addr.as_ptr() } as *const libc::c_char;
        Ok((guard, f(ptr)))
    }
}


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

/// Follow a symlink chain at the *final* component of a translated
/// host path, keeping absolute targets inside the rootfs (design
/// §4.2). Without this, the kernel resolves e.g. Alpine's
/// `/bin/sh -> /bin/busybox` against the host root and escapes.
/// Intermediate-component symlinks remain a documented gap.
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
static UTS_DOMAIN: Mutex<Option<String>> = Mutex::new(None);

/// pid -> guest exe path, for /proc/<pid>/exe de-translation of
/// *other* guest processes (e.g. sh reading /proc/$$/exe from a
/// child). Populated on every guest execve; ptrace backend hosts
/// all Tools in one process so a static map is exact there.
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
