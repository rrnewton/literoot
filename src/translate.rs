//! Arch-free guest→host path translation (design §4.2/§6).
//!
//! Pure and std-only so it unit-tests without any backend and can be
//! shared unchanged by the x86-64 (M1) and aarch64 (M2) Tools.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::OnceLock;

/// Probe-cache generation: bumped by the Tool on any successful
/// mutating path syscall so cached component kinds never outlive
/// a rename/unlink/symlink change. If no shared generation memfd
/// was adopted (the identity env was scrubbed, or no copy was
/// inherited), this silently falls back to the process-local
/// counter (per-process coherence only) — same stated limit
/// class as host-side mutation.
///
/// Coherence scope: the counter lives in a launcher-created
/// memfd (MAP_SHARED) inherited across the whole guest tree, so
/// a mutation in any guest process invalidates every process's
/// cache. In-guest, each image's preload maps it before the
/// guest runs (`adopt_shared_gen`, called by the preload's
/// runtime_memfds module), and fork children inherit that
/// mapping. Without the memfd (unit tests, --check) it falls
/// back to a process-local atomic. Host-side mutation (outside
/// any guest) is NOT detected — a stated divergence from proot,
/// which re-probes on every canonicalization.
static PROBE_GEN_LOCAL: AtomicU64 = AtomicU64::new(0);
static PROBE_GEN_SHARED: OnceLock<usize> = OnceLock::new();
/// The descriptor this process holds on the shared generation
/// memfd, or -1. The counter itself is reached through the
/// mapping; the descriptor is kept only so that an exec inherits
/// the memfd. In-guest it is a number the runtime keeps the guest
/// away from, and it changes when a fork child re-places its copy.
static PROBE_GEN_FD: AtomicI32 = AtomicI32::new(-1);
/// The file identity of the adopted shared generation memfd.
static PROBE_GEN_IDENTITY: OnceLock<FdIdentity> = OnceLock::new();

/// Internal launcher-to-preload environment variable naming the
/// shared generation memfd by file identity
/// ([`FdIdentity::encode`]), never by descriptor number: each
/// in-guest image finds its inherited copy by this identity and
/// moves it to a number the runtime keeps the guest away from, so
/// the number differs per process. The identity protects against
/// number reuse; it is not authentication. A guest can point it at
/// any file it holds, which desyncs only its own tree.
pub const PROBE_GEN_ID_ENV: &str = "LITEROOT_PROBE_GEN_ID";

fn shared_gen() -> Option<&'static AtomicU64> {
    // Mutant switch for the coherence test: force the
    // process-local generation (must FAIL cross-process).
    // TEST-ONLY: production must never set this; it opts the
    // process out of shared coherence (a guest can only desync
    // itself, but the resulting numbers must not be quoted).
    if std::env::var_os("LITEROOT_PROBE_LOCAL").is_some() {
        return None;
    }
    PROBE_GEN_SHARED
        .get()
        .map(|p| unsafe { &*(*p as *const AtomicU64) })
}

/// mmap the shared generation counter from `fd` (idempotent).
/// Returns whether the counter is mapped.
pub fn init_shared_gen_from_fd(fd: i32) -> bool {
    if PROBE_GEN_SHARED.get().is_some() {
        return true;
    }
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            8,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if ptr != libc::MAP_FAILED {
            let _ = PROBE_GEN_SHARED.set(ptr as usize);
        }
    }
    PROBE_GEN_SHARED.get().is_some()
}

/// Adopt the shared generation memfd open at `fd` with file
/// identity `identity` (in-guest preload, before the guest runs):
/// map the counter and remember the descriptor. Returns whether
/// the counter is mapped.
#[allow(dead_code)] // The in-guest preload (preload/src/runtime_memfds.rs) is the caller.
pub fn adopt_shared_gen(fd: i32, identity: FdIdentity) -> bool {
    if !init_shared_gen_from_fd(fd) {
        return false;
    }
    let _ = PROBE_GEN_IDENTITY.set(identity);
    PROBE_GEN_FD.store(fd, Ordering::Release);
    true
}

/// The shared generation memfd this process holds: its current
/// descriptor and its file identity.
#[allow(dead_code)] // The in-guest preload (preload/src/runtime_memfds.rs) is the caller.
pub fn shared_gen_descriptor() -> Option<(i32, FdIdentity)> {
    let fd = PROBE_GEN_FD.load(Ordering::Acquire);
    if fd < 0 {
        return None;
    }
    PROBE_GEN_IDENTITY.get().map(|identity| (fd, *identity))
}

/// Record the descriptor this process now holds on the shared
/// generation memfd after moving it, or -1 when it holds none.
/// The mapping is unaffected either way.
#[allow(dead_code)] // The in-guest preload (preload/src/runtime_memfds.rs) is the caller.
pub fn set_shared_gen_fd(fd: i32) {
    PROBE_GEN_FD.store(fd, Ordering::Release);
}

/// Create the shared generation memfd (launcher side). Returns
/// the fd (CLOEXEC cleared, so the in-guest tree inherits it; the
/// launcher hands the guest its identity, not its number), or -1.
///
/// The size is sealed (F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_SEAL)
/// before the first mmap: every process maps exactly these 8
/// bytes, and a truncate through any descriptor or path would
/// otherwise make the next counter access fault (SIGBUS). The
/// contents stay writable, as the counter must be.
pub fn create_shared_gen_fd() -> i32 {
    unsafe {
        let name = c"literoot-probe-gen";
        let fd = libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING);
        if fd < 0 {
            return -1;
        }
        if libc::ftruncate(fd, 8) != 0
            || libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
            ) != 0
        {
            libc::close(fd);
            return -1;
        }
        init_shared_gen_from_fd(fd);
        fd
    }
}

/// A file's identity as `fstat` reports it: the launcher hands an
/// in-guest image this pair instead of a descriptor number, and
/// the image finds its inherited copy by it
/// ([`find_read_write_descriptor`]). It protects against number
/// reuse; it is not authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl FdIdentity {
    /// The identity of the file open at `fd`.
    pub fn of_fd(fd: i32) -> std::io::Result<Self> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat borrows the descriptor and writes only
        // through `stat`; a closed number is reported as EBADF.
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        })
    }

    /// `<st_dev>:<st_ino>` in decimal, the environment form.
    pub fn encode(self) -> String {
        format!("{}:{}", self.dev, self.ino)
    }

    /// The inverse of [`FdIdentity::encode`]; `None` for anything
    /// else.
    #[allow(dead_code)] // The in-guest preload is the caller.
    pub fn decode(text: &str) -> Option<Self> {
        let (dev, ino) = text.split_once(':')?;
        Some(Self {
            dev: dev.parse().ok()?,
            ino: ino.parse().ok()?,
        })
    }
}

/// The highest-numbered descriptor this process has open for
/// reading and writing on the file `identity` names, found by
/// listing `/proc/self/fd`, or `None`. Highest, because a copy the
/// runtime placed sits at or above its reserved minimum, above any
/// number a program gets by lowest-free allocation; read-write,
/// because a read-only reopen of the same file is not a copy the
/// launcher handed down. Run it before the guest's first
/// instruction in the image: it names descriptors through ordinary
/// syscalls, which the installed runtime refuses on its own
/// protected numbers.
#[allow(dead_code)] // The in-guest preload (preload/src/runtime_memfds.rs) is the caller.
pub fn find_read_write_descriptor(identity: FdIdentity) -> std::io::Result<Option<i32>> {
    let mut found = None;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        // The listing's own directory descriptor and numbers closed
        // since the listing fail or differ here and are skipped.
        if FdIdentity::of_fd(fd).ok() != Some(identity) {
            continue;
        }
        // SAFETY: F_GETFL only reads this descriptor's status flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDWR {
            continue;
        }
        found = found.max(Some(fd));
    }
    Ok(found)
}

pub fn probe_gen() -> u64 {
    match shared_gen() {
        Some(g) => g.load(Ordering::SeqCst),
        None => PROBE_GEN_LOCAL.load(Ordering::SeqCst),
    }
}

pub fn bump_probe_gen() {
    match shared_gen() {
        Some(g) => {
            g.fetch_add(1, Ordering::SeqCst);
        }
        None => {
            PROBE_GEN_LOCAL.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ProbeKind {
    Dir,
    Symlink,
    Other,
    Missing,
}

// Process-global, not thread-local: in-guest dispatch may run on a
// different host thread per syscall, so a thread-local cache never
// warmed there (measured: bind-root probes paid in full on every
// in-guest dispatch while the ptrace tracer's single thread hit).
// Entries stay generation-validated exactly as before.
static PROBE_CACHE: std::sync::Mutex<Option<HashMap<PathBuf, (u64, ProbeKind)>>> =
    std::sync::Mutex::new(None);

/// symlink_metadata with a generation-validated cache. The
/// canonicalizer probes every intermediate component on every
/// syscall; without this, a stat loop pays one extra real
/// syscall per component (measured in-guest regression).
fn probe(host: &Path) -> ProbeKind {
    let gen = probe_gen();
    if let Some(k) = PROBE_CACHE
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(host)
        .and_then(|(g, k)| if *g == gen { Some(*k) } else { None })
    {
        return k;
    }
    let k = match std::fs::symlink_metadata(host) {
        Ok(m) if m.file_type().is_symlink() => ProbeKind::Symlink,
        Ok(m) if m.is_dir() => ProbeKind::Dir,
        Ok(_) => ProbeKind::Other,
        Err(_) => ProbeKind::Missing,
    };
    {
        let mut guard = PROBE_CACHE.lock().unwrap();
        let c = guard.get_or_insert_with(HashMap::new);
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(host.to_path_buf(), (gen, k));
    }
    k
}

/// [`probe`] without the cache, for procfs entries: pids, tids and fds
/// come and go without a generation bump.
fn probe_uncached(host: &Path) -> ProbeKind {
    match std::fs::symlink_metadata(host) {
        Ok(m) if m.file_type().is_symlink() => ProbeKind::Symlink,
        Ok(m) if m.is_dir() => ProbeKind::Dir,
        Ok(_) => ProbeKind::Other,
        Err(_) => ProbeKind::Missing,
    }
}

/// How many symlinks one path walk may follow: the kernel's MAXSYMLINKS
/// (include/linux/namei.h), counted over the whole walk, intermediate and
/// final links alike.
pub const MAX_SYMLINKS: u32 = 40;

/// A path walk needed more than [`MAX_SYMLINKS`] links; the guest's ELOOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyLinks;

/// Count one more followed link against a walk's budget: the kernel's
/// `if (nd->total_link_count++ >= MAXSYMLINKS) return -ELOOP` (pick_link,
/// fs/namei.c), so the 41st link fails.
pub fn take_link(links: &mut u32) -> Result<(), TooManyLinks> {
    if *links >= MAX_SYMLINKS {
        return Err(TooManyLinks);
    }
    *links += 1;
    Ok(())
}

/// A path refusal literoot makes by name: the closed family of
/// `literoot: refused path <kind>` side-log lines (docs/design.md §4.9).
///
/// Its wire form (serde) is in rootfs_tool.rs: this file is also built
/// without serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRefusal {
    /// The base of a relative name could not be inspected (a stat or
    /// readlink error, a /proc text that is not absolute, or a climb the
    /// Tool may not make).
    BaseUninspectable,
    /// A live base whose /proc name leads back to it but has no guest name.
    BaseOutsideRoot,
    /// A /proc magic link of the guest's own process whose object has no
    /// guest name.
    ProcLinkOutsideRoot,
    /// A /proc magic link of a process that is not the guest's.
    ProcLinkOtherProcess,
    /// The base's /proc name does not lead back to it (moved, or held in
    /// another mount namespace).
    BaseMoved,
    /// A final symlink reached with no guest route to resolve it from.
    NoGuestRoute,
    /// literoot has no trustworthy probe for the call.
    ProbeUnsupported,
    /// A synthetic cmdline file could not be made in a private directory,
    /// or was replaced before the guest's open.
    SyntheticFileUnavailable,
}

impl PathRefusal {
    /// The side-log token.
    pub fn token(self) -> &'static str {
        match self {
            PathRefusal::BaseUninspectable => "base_uninspectable",
            PathRefusal::BaseOutsideRoot => "base_outside_root",
            PathRefusal::ProcLinkOutsideRoot => "proc_link_outside_root",
            PathRefusal::ProcLinkOtherProcess => "proc_link_other_process",
            PathRefusal::BaseMoved => "base_moved",
            PathRefusal::NoGuestRoute => "no_guest_route",
            PathRefusal::ProbeUnsupported => "probe_unsupported",
            PathRefusal::SyntheticFileUnavailable => "synthetic_file_unavailable",
        }
    }
}

/// Every [`PathRefusal`], in side-log order.
#[cfg_attr(not(test), allow(dead_code))] // The kind-list units are its callers.
pub const PATH_REFUSALS: [PathRefusal; 8] = [
    PathRefusal::BaseUninspectable,
    PathRefusal::BaseOutsideRoot,
    PathRefusal::ProcLinkOutsideRoot,
    PathRefusal::ProcLinkOtherProcess,
    PathRefusal::BaseMoved,
    PathRefusal::NoGuestRoute,
    PathRefusal::ProbeUnsupported,
    PathRefusal::SyntheticFileUnavailable,
];

/// Why a guest path walk failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// More than [`MAX_SYMLINKS`] links: the guest's ELOOP.
    TooManyLinks,
    /// A refusal by name: the guest's EACCES.
    Refused(PathRefusal),
    /// The kernel's own answer for a component the walk cannot pass inside
    /// the real procfs (ENOENT for a missing entry, ENOTDIR for a
    /// non-directory), instead of a literal tail for the kernel.
    Kernel(i32),
}

impl From<TooManyLinks> for WalkError {
    fn from(_: TooManyLinks) -> Self {
        WalkError::TooManyLinks
    }
}

/// Which /proc magic link a walk reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicKind {
    Root,
    Cwd,
    Exe,
    Fd,
    MapFiles,
}

/// A /proc magic link, read from the HOST path the walk selected (through
/// binds, then [`ProcLinks::tool_view`]): `<procfs>/<pid>[/task/<tid>]/
/// {root,cwd,exe}` or `.../{fd,map_files}/<entry>`. The kernel follows it
/// to an object of process `pid` that the guest root does not contain
/// (literoot does not chroot, so `root` is the host's `/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicLink {
    pub pid: i32,
    pub tid: Option<i32>,
    pub kind: MagicKind,
}

/// A component's place in the real procfs, judged from its host path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcEntry {
    /// Not an entry of the real procfs.
    NotProc,
    /// procfs's own `self` or `thread-self` symlink. Its target, numeric,
    /// relative to the procfs root: `[P]` or `[P, task, T]`.
    Prefix(Vec<std::ffi::OsString>),
    /// A magic link of the real procfs.
    Magic(MagicLink),
    /// Any other entry inside the real procfs, missing ones included.
    Inside,
}

/// `fs/proc/root.c`'s PROC_SUPER_MAGIC.
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// Whether the file system holding `path` is procfs (statfs, which follows
/// a final symlink: callers pass a directory).
fn on_procfs(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a statfs buffer of the right size.
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut st) };
    rc == 0 && st.f_type as i64 == PROC_SUPER_MAGIC
}

/// The procfs mount root holding host path `host`, if its parent is on
/// procfs (F: an entry is procfs's only when its parent is): the topmost
/// ancestor still on procfs.
pub fn procfs_root_of(host: &Path) -> Option<PathBuf> {
    let mut root = host.parent()?.to_path_buf();
    if !on_procfs(&root) {
        return None;
    }
    while let Some(up) = root.parent() {
        if up.as_os_str().is_empty() || !on_procfs(up) {
            break;
        }
        root = up.to_path_buf();
    }
    Some(root)
}

/// The components of `host` below the procfs root `root`.
fn below(root: &Path, host: &Path) -> Option<Vec<std::ffi::OsString>> {
    let rest = host.strip_prefix(root).ok()?;
    Some(
        rest.components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_os_string()),
                _ => None,
            })
            .collect(),
    )
}

/// Classify a procfs-relative component list, already mapped by the
/// policy's tool view (no `self`/`thread-self` left in it except as the
/// whole list).
fn classify_rel(spelled: &[std::ffi::OsString], view: &[std::ffi::OsString]) -> ProcEntry {
    if spelled.len() == 1 && matches!(spelled[0].to_str(), Some("self" | "thread-self")) {
        return ProcEntry::Prefix(view.to_vec());
    }
    let num = |c: &std::ffi::OsString| -> Option<i32> {
        let s = c.to_str()?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let Some(pid) = view.first().and_then(num) else {
        return ProcEntry::Inside;
    };
    let (tid, tail) = if view.len() >= 4 && view[1] == "task" {
        match num(&view[2]) {
            Some(t) => (Some(t), &view[3..]),
            None => return ProcEntry::Inside,
        }
    } else {
        (None, &view[1..])
    };
    let kind = match tail {
        [l] => match l.to_str() {
            Some("root") => MagicKind::Root,
            Some("cwd") => MagicKind::Cwd,
            Some("exe") => MagicKind::Exe,
            _ => return ProcEntry::Inside,
        },
        [l, _] => match l.to_str() {
            Some("fd") => MagicKind::Fd,
            Some("map_files") => MagicKind::MapFiles,
            _ => return ProcEntry::Inside,
        },
        _ => return ProcEntry::Inside,
    };
    ProcEntry::Magic(MagicLink { pid, tid, kind })
}

/// [`ProcEntry`] of host path `host` under the procfs root `root`, with
/// `proc`'s tool view; and the tool-view host path for Tool-side reads.
fn entry_under(
    root: &Path,
    host: &Path,
    proc: &dyn ProcLinks,
) -> Option<(ProcEntry, PathBuf)> {
    let spelled = below(root, host)?;
    if spelled.is_empty() {
        return Some((ProcEntry::Inside, host.to_path_buf()));
    }
    let view = proc.tool_view(&spelled);
    let mut tv = root.to_path_buf();
    for c in &view {
        tv.push(c);
    }
    Some((classify_rel(&spelled, &view), tv))
}

/// [`ProcEntry`] of `host`, finding its procfs root first, and the
/// tool-view path. `(NotProc, host)` outside procfs.
pub fn proc_entry(host: &Path, proc: &dyn ProcLinks) -> (ProcEntry, PathBuf) {
    match procfs_root_of(host).and_then(|root| entry_under(&root, host, proc)) {
        Some(found) => found,
        None => (ProcEntry::NotProc, host.to_path_buf()),
    }
}

/// What a guest walk does at a /proc magic link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicAction {
    /// An ordinary component.
    Walk,
    /// Continue from this canonical guest directory instead, with the
    /// same link budget (".." then clamps at the guest root).
    Reroot(PathBuf),
    /// Hand the link, and anything after it, to the kernel as spelled.
    Raw,
    /// Refuse the walk by name.
    Refuse(PathRefusal),
}

/// The guest's answers at /proc: whose process a link belongs to decides
/// it, and which process `self` names, which only the caller knows.
pub trait ProcLinks {
    /// Map procfs-relative components for Tool-side reads: `self` becomes
    /// the guest's tgid and `thread-self` its `<tgid>/task/<tid>`, as the
    /// calling task sees them; everything else is kept.
    fn tool_view(&self, rel: &[std::ffi::OsString]) -> Vec<std::ffi::OsString>;
    /// The walk continues past `link` (more components, or a trailing
    /// slash). `host` is the link's tool-view host path.
    fn traverse(&self, link: &MagicLink, host: &Path) -> MagicAction;
    /// A call follows `link` itself, as its final component.
    fn follow(&self, link: &MagicLink, host: &Path) -> MagicAction;
    /// Whether a walk asked this policy has handed another process's
    /// directory link to the kernel (a Raw hand-over it could not splice):
    /// the route past it names no stable guest directory.
    fn raw_crossed(&self) -> bool {
        false
    }
}

/// Count, against `links`, the plain symlinks the kernel follows in the
/// intermediate components of `tail` (every component but the last),
/// walking on from the directory the magic link `start` names: the rest of
/// a walk after a Raw hand-over, which the kernel walks with the budget the
/// walk has left. It walks the kernel's
/// own objects: `start` is opened (the kernel follows the magic link, in
/// the other process's mount namespace), then each component by `openat`
/// from that descriptor; an absolute target restarts at the host root, the
/// calling guest's own (literoot does not chroot). Conservative: over-counting would turn a
/// native success into ELOOP, so it stops counting, with no error, at
/// anything it does not model: any directory on procfs (magic links, self,
/// thread-self), a component it cannot open, stat or read, or a
/// non-directory. Only the links it actually followed can give ELOOP.
pub(crate) fn count_raw_tail(
    start: &Path,
    tail: &[std::ffi::OsString],
    links: &mut u32,
) -> Result<(), WalkError> {
    use std::collections::VecDeque;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    const DIR: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // A directory descriptor at `name` from `at` (None: an absolute path),
    // refused when the directory is on procfs.
    fn open_dir(at: Option<&OwnedFd>, name: &[u8], extra: i32) -> Option<OwnedFd> {
        let c = std::ffi::CString::new(name).ok()?;
        let dirfd = at.map(|f| f.as_raw_fd()).unwrap_or(libc::AT_FDCWD);
        // SAFETY: a NUL-terminated name; the result is checked.
        let fd = unsafe { libc::openat(dirfd, c.as_ptr(), DIR | extra) };
        if fd < 0 {
            return None;
        }
        // SAFETY: a descriptor this call just opened and owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: an open descriptor and a statfs buffer of the right size.
        let rc = unsafe { libc::fstatfs(fd.as_raw_fd(), &mut st) };
        (rc == 0 && st.f_type as i64 != PROC_SUPER_MAGIC).then_some(fd)
    }
    let Some((_, inner)) = tail.split_last() else {
        return Ok(());
    };
    let Some(mut cur) = open_dir(None, start.as_os_str().as_bytes(), 0) else {
        return Ok(());
    };
    let mut pending: VecDeque<std::ffi::OsString> = inner.iter().cloned().collect();
    while let Some(c) = pending.pop_front() {
        if c.is_empty() || c == "." {
            continue;
        }
        let Ok(name) = std::ffi::CString::new(c.as_bytes()) else {
            return Ok(());
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: an open descriptor, a NUL-terminated name, a stat buffer.
        let rc = unsafe { libc::fstatat(cur.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if rc != 0 {
            return Ok(());
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => match open_dir(Some(&cur), c.as_bytes(), libc::O_NOFOLLOW) {
                Some(next) => cur = next,
                None => return Ok(()),
            },
            libc::S_IFLNK => {
                let mut buf = vec![0u8; libc::PATH_MAX as usize];
                // SAFETY: an open descriptor, a NUL-terminated name, and a
                // buffer of the length passed.
                let n = unsafe {
                    libc::readlinkat(cur.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
                };
                if n < 0 || n as usize >= buf.len() {
                    return Ok(());
                }
                buf.truncate(n as usize);
                take_link(links)?;
                let target = PathBuf::from(std::ffi::OsString::from_vec(buf));
                if target.is_absolute() {
                    match open_dir(None, b"/", 0) {
                        Some(root) => cur = root,
                        None => return Ok(()),
                    }
                }
                for comp in target.components().rev() {
                    match comp {
                        Component::Normal(s) => pending.push_front(s.to_os_string()),
                        Component::ParentDir => pending.push_front("..".into()),
                        Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
                    }
                }
            }
            _ => return Ok(()),
        }
    }
    Ok(())
}

/// The tool view of the procfs-relative `rel` for guest `pid` (thread
/// `tid`).
pub fn tool_view_for(
    rel: &[std::ffi::OsString],
    pid: i32,
    tid: i32,
) -> Vec<std::ffi::OsString> {
    let mut out = Vec::with_capacity(rel.len() + 2);
    match rel.first().and_then(|c| c.to_str()) {
        Some("self") => out.push(std::ffi::OsString::from(pid.to_string())),
        Some("thread-self") => {
            out.push(std::ffi::OsString::from(pid.to_string()));
            out.push(std::ffi::OsString::from("task"));
            out.push(std::ffi::OsString::from(tid.to_string()));
        }
        _ => return rel.to_vec(),
    }
    out.extend(rel[1..].iter().cloned());
    out
}

/// A canonical guest path, and the bind its walk crossed, if any: that
/// bind's guest prefix components and its host prefix.
type Canonical = (PathBuf, Option<(Vec<std::ffi::OsString>, PathBuf)>);

/// One bind entry: guest prefix → host prefix (proot `-b host[:guest]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub guest: PathBuf,
    pub host: PathBuf,
    /// proot `host:guest!`: binding not followed during symlink
    /// canonicalization (parsed; swap semantics tracked in
    /// docs/proot-suite-results.md retained failures).
    pub no_follow: bool,
}

/// Immutable launch configuration replicated into every guest process
/// (design §6). Never mutated after construction.
#[derive(Debug, Clone)]
pub struct RootConfig {
    /// Canonical host path of the rootfs.
    pub rootfs: PathBuf,
    /// Bind table, matched longest-guest-prefix-first.
    pub binds: Vec<Bind>,
    /// Fake-root (`-0`) enabled.
    pub fake_root: bool,
    /// Spoofed (uid, gid) from `-0` (0,0) or `-i uid:gid`.
    pub fake_ids: Option<(u32, u32)>,
    /// Spoofed kernel release (`-k`), if any.
    pub kernel_release: Option<String>,
    /// Identity-only: when the `-i` ids are the caller's own non-root ids,
    /// only the set*id, setfs*id and setxattr calls are emulated. The CLI
    /// requests it unless `--no-identity-only`; the launcher passes it on
    /// only for such ids.
    pub identity_only: bool,
}

impl RootConfig {
    pub fn new(rootfs: PathBuf, mut binds: Vec<Bind>) -> Self {
        // Canonicalize bind guest prefixes (symlinks inside the
        // rootfs resolved): mid-walk binding substitution compares
        // canonical stacks (test-readdir-symlinked-dir).
        for b in &mut binds {
            // `!` bindings match the literal spelling only:
            // never canonicalize their guest side.
            if !b.no_follow {
                b.guest = canonicalize_plain(&rootfs, &b.guest);
            }
        }
        Self {
            rootfs,
            binds,
            fake_root: false,
            fake_ids: None,
            kernel_release: None,
            identity_only: false,
        }
    }

    /// Lexically normalize a guest path against `cwd` (a guest path),
    /// clamping `..` at the guest root so it can never escape.
    fn normalize_guest(&self, path: &Path, cwd: &Path) -> PathBuf {
        let mut out: Vec<std::ffi::OsString> = Vec::new();
        let base: Vec<Component> = if path.is_absolute() {
            Vec::new()
        } else {
            cwd.components().collect()
        };
        for c in base.iter().copied().chain(path.components()) {
            match c {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(s) => out.push(s.to_os_string()),
                Component::Prefix(_) => {}
            }
        }
        let mut p = PathBuf::from("/");
        for s in out {
            p.push(s);
        }
        p
    }

    /// Host path for a canonical guest-component stack.
    fn host_of(&self, stack: &[std::ffi::OsString]) -> PathBuf {
        self.host_of_bound(stack, None)
    }

    /// Host path with a mid-walk binding substitution: when the
    /// guest walk crossed a bind's guest prefix exactly, the
    /// host side continues from that bind's host tree even if
    /// later symlink resolution changes the guest spelling
    /// (proot canonicalize; test-readdir-symlinked-dir).
    fn host_of_bound(
        &self,
        stack: &[std::ffi::OsString],
        bound: Option<&(Vec<std::ffi::OsString>, PathBuf)>,
    ) -> PathBuf {
        if let Some((guest_comps, host_base)) = bound {
            if stack.len() >= guest_comps.len()
                && stack[..guest_comps.len()] == guest_comps[..]
            {
                let mut h = host_base.clone();
                for c in &stack[guest_comps.len()..] {
                    h.push(c);
                }
                return h;
            }
        }
        let mut g = PathBuf::from("/");
        for c in stack {
            g.push(c);
        }
        self.translate_absolute(&g)
    }

    /// Deepest bind whose guest prefix equals the current stack.
    fn bind_at(
        &self,
        stack: &[std::ffi::OsString],
    ) -> Option<(Vec<std::ffi::OsString>, PathBuf)> {
        let mut best: Option<(Vec<std::ffi::OsString>, PathBuf)> = None;
        for b in &self.binds {
            let comps: Vec<std::ffi::OsString> = b
                .guest
                .components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_os_string()),
                    _ => None,
                })
                .collect();
            if comps.len() == stack.len() && comps[..] == stack[..] {
                best = Some((comps, b.host.clone()));
            }
        }
        best
    }

    /// Kernel-faithful guest canonicalization (proot's
    /// canonicalize): walk components, resolving symlinks through
    /// the host FS, collapsing `..` only where the kernel would
    /// (current component is a directory after symlink
    /// resolution). File/`..` and nonexistent/`..` keep a literal
    /// tail so the kernel reports ENOTDIR/ENOENT itself
    /// (test-path-traversal-conformance).
    fn canonicalize(&self, base: &Path, path: &Path) -> PathBuf {
        match self.canonicalize_inner(base, path, None, None) {
            Ok((p, _)) => p,
            Err(_) => unreachable!("an uncounted walk with no policy cannot fail"),
        }
    }

    /// The guest path `path` names from the canonical guest directory
    /// `cwd`, walked as `translate` walks it: intermediate symlinks are
    /// resolved and ".." pops the directory it follows, but the final
    /// component is not followed.
    pub fn canonical_guest(&self, path: &Path, cwd: &Path) -> PathBuf {
        let base = if path.is_absolute() {
            Path::new("/")
        } else {
            cwd
        };
        self.canonicalize(base, path)
    }

    /// [`Self::canonical_guest`] for a walk on a guest's behalf: `proc`
    /// answers at every /proc magic link the walk passes through, so the
    /// canonical path names where the guest's call lands (a rerooted
    /// `/proc/self/root/x` is `/x`).
    pub fn canonical_guest_walk(
        &self,
        path: &Path,
        cwd: &Path,
        proc: &dyn ProcLinks,
    ) -> Result<PathBuf, WalkError> {
        let base = if path.is_absolute() {
            Path::new("/")
        } else {
            cwd
        };
        self.canonicalize_inner(base, path, None, Some(proc))
            .map(|(p, _)| p)
    }

    /// A relative `path` is walked from `base` as if spelled after it, so
    /// `base` need not be canonical. With `links`, every symlink the walk
    /// splices counts against one budget shared with the caller, and the walk fails with
    /// [`TooManyLinks`] at the link past [`MAX_SYMLINKS`], as the kernel's
    /// does. Without it, a walk stops splicing after 40 links and leaves
    /// the rest literal (callers outside the guest's own path walks).
    /// With `proc`, the walk asks it at every /proc magic link it passes
    /// through; without, the link is spliced (`root`) or left for the
    /// kernel (the others), the context-free behaviour.
    ///
    /// With `proc`, an entry counts as the real procfs's only when its host
    /// path (selected through binds on the spelled stack) has a parent on
    /// procfs, and its Tool-side reads use `proc`'s tool view, so `self`
    /// names the guest. Inside procfs:
    /// - procfs's own `self` and `thread-self`, continued through, cost one
    ///   link and are never spliced forward (a bind below the spelling
    ///   still matches); a ".." with one of them on top lands in its
    ///   target's parent, as the kernel's does;
    /// - a magic link continued through is the policy's: a Reroot or a Raw
    ///   hand-over costs one link (the guest's kernel would follow it);
    /// - a missing or non-directory entry the walk must pass is the
    ///   kernel's ENOENT or ENOTDIR at once, never a literal tail;
    /// - the probe cache is not used: pids, tids and fds change without a
    ///   generation bump.
    fn canonicalize_inner(
        &self,
        base: &Path,
        path: &Path,
        mut links: Option<&mut u32>,
        proc: Option<&dyn ProcLinks>,
    ) -> Result<Canonical, WalkError> {
        use std::collections::VecDeque;
        #[derive(Clone)]
        enum Comp {
            Root,
            Dot,
            DotDot,
            Name(std::ffi::OsString),
            /// The end of a Reroot's directory, with the link count right
            /// after the Reroot was charged: walking a canonical guest
            /// directory charges nothing more.
            RerootEnd(u32),
        }
        fn to_comp(c: Component) -> Comp {
            match c {
                Component::RootDir => Comp::Root,
                Component::CurDir => Comp::Dot,
                Component::ParentDir => Comp::DotDot,
                Component::Normal(s) => Comp::Name(s.to_os_string()),
                Component::Prefix(_) => Comp::Root,
            }
        }
        // One more link the guest's kernel follows: counted against the
        // walk's budget, or, for a walk without one, against the 40-hop
        // cap of the context-free walk.
        fn charge(links: &mut Option<&mut u32>, hops: &mut u32) -> Result<(), WalkError> {
            *hops += 1;
            if let Some(n) = links.as_deref_mut() {
                take_link(n)?;
            }
            Ok(())
        }
        // A relative path walks its base too, component by component, with
        // the same link budget and bind handling: a recorded cwd or
        // directory name that still holds a link (or a "..") must not be
        // handed to the kernel to follow in the host's namespace. A
        // canonical base has no link to count.
        let mut stack: Vec<std::ffi::OsString> = Vec::new();
        let mut bound = self.bind_at(&stack);
        let mut pending: VecDeque<Comp> = if path.is_absolute() {
            path.components().map(to_comp).collect()
        } else {
            std::iter::once(Comp::Root)
                .chain(base.components().map(to_comp))
                .chain(path.components().map(to_comp))
                .collect()
        };
        // A trailing slash forces resolution of the final
        // component (kernel directory semantics).
        let force_final = {
            use std::os::unix::ffi::OsStrExt as _;
            let b = path.as_os_str().as_bytes();
            b.ends_with(b"/") || b.ends_with(b"/.")
        };
        let mut literal: Vec<std::ffi::OsString> = Vec::new();
        // The tool-view host path of the magic link a Raw hand-over passed to
        // the kernel, whose literal rest the kernel walks.
        let mut raw_start: Option<PathBuf> = None;
        let mut unresolved = false;
        let mut hops = 0u32;
        // The procfs root this walk is inside, once found (policy walks).
        let mut proc_root: Option<PathBuf> = None;
        while let Some(comp) = pending.pop_front() {
            if !literal.is_empty() {
                match comp {
                    Comp::Name(s) => literal.push(s),
                    Comp::DotDot => literal.push(std::ffi::OsString::from("..")),
                    Comp::Dot => literal.push(std::ffi::OsString::from(".")),
                    Comp::Root | Comp::RerootEnd(_) => {}
                }
                continue;
            }
            match comp {
                Comp::RerootEnd(at) => {
                    if let Some(n) = links.as_deref() {
                        debug_assert_eq!(*n, at, "a Reroot's directory re-walk charged a link");
                    }
                    let _ = at;
                }
                Comp::Root => stack.clear(),
                Comp::Dot => {}
                Comp::DotDot => {
                    if unresolved {
                        literal.push(std::ffi::OsString::from(".."));
                        continue;
                    }
                    if stack.is_empty() {
                        // Clamp at guest root.
                        continue;
                    }
                    // Resolve a symlink at the top first: its
                    // parent is the target's parent, not ours.
                    let host = self.host_of_bound(&stack, bound.as_ref());
                    let mut read_at = None;
                    if let Some(policy) = proc {
                        if let Some((entry, tv)) =
                            self.proc_class(&host, &mut proc_root, policy, false)
                        {
                            if let ProcEntry::Prefix(target) = entry {
                                // procfs's self/thread-self on top: the
                                // parent of its target (`[P]` or
                                // `[P, task, T]`).
                                stack.pop();
                                if target.len() > 1 {
                                    stack.extend(target[..target.len() - 1].iter().cloned());
                                }
                                self.rebind(&stack, &mut bound);
                                continue;
                            }
                            read_at = Some(tv);
                        }
                    }
                    let kind = match &read_at {
                        Some(tv) => probe_uncached(tv),
                        None => probe(&host),
                    };
                    match kind {
                        ProbeKind::Symlink => {
                            hops += 1;
                            if let Some(n) = links.as_deref_mut() {
                                take_link(n)?;
                            } else if hops > 40 {
                                literal.push(std::ffi::OsString::from(".."));
                                continue;
                            }
                            let target = std::fs::read_link(read_at.as_ref().unwrap_or(&host))
                                .unwrap_or_default();
                            stack.pop();
                            if target.is_absolute() {
                                stack.clear();
                            }
                            let mut rest: VecDeque<Comp> =
                                target.components().map(to_comp).collect();
                            rest.push_back(Comp::DotDot);
                            rest.extend(pending);
                            pending = rest;
                        }
                        ProbeKind::Dir => {
                            stack.pop();
                        }
                        ProbeKind::Missing if read_at.is_some() => {
                            return Err(WalkError::Kernel(libc::ENOENT));
                        }
                        ProbeKind::Other if read_at.is_some() => {
                            return Err(WalkError::Kernel(libc::ENOTDIR));
                        }
                        ProbeKind::Other | ProbeKind::Missing => {
                            // File/.. : kernel ENOTDIR — keep literal.
                            literal.push(std::ffi::OsString::from(".."));
                        }
                    }
                }
                Comp::Name(s) => {
                    stack.push(s);
                    // Deepest exact bind wins; re-check on every
                    // push (nested binds /data vs /data/inner).
                    let crossed = self.rebind(&stack, &mut bound);
                    let continuing = !pending.is_empty() || force_final;
                    let host = self.host_of_bound(&stack, bound.as_ref());
                    // The real procfs, judged from the host path the walk
                    // selected: the caller's policy decides at a magic
                    // link and at self/thread-self, before anything below
                    // could splice them from the Tool's own process or
                    // leave them for the kernel to follow on the host.
                    let mut proc_view: Option<PathBuf> = None;
                    if let Some(policy) = proc {
                        if let Some((entry, tv)) =
                            self.proc_class(&host, &mut proc_root, policy, crossed)
                        {
                            if continuing {
                                match entry {
                                    ProcEntry::Magic(link) => match policy.traverse(&link, &tv) {
                                        MagicAction::Walk => {}
                                        MagicAction::Reroot(dir) => {
                                            charge(&mut links, &mut hops)?;
                                            // A fresh walk from the guest
                                            // directory: what the Tool's own
                                            // view showed on the way here
                                            // must not keep a ".." literal.
                                            unresolved = false;
                                            let at = links.as_deref().copied().unwrap_or(0);
                                            let mut rest: VecDeque<Comp> =
                                                std::iter::once(Comp::Root)
                                                    .chain(dir.components().map(to_comp))
                                                    .chain(std::iter::once(Comp::RerootEnd(at)))
                                                    .collect();
                                            rest.extend(pending);
                                            pending = rest;
                                            continue;
                                        }
                                        MagicAction::Raw => {
                                            charge(&mut links, &mut hops)?;
                                            if let Some(name) = stack.pop() {
                                                literal.push(name);
                                            }
                                            raw_start = Some(tv.clone());
                                            continue;
                                        }
                                        MagicAction::Refuse(kind) => {
                                            return Err(WalkError::Refused(kind));
                                        }
                                    },
                                    ProcEntry::Prefix(_) => {
                                        charge(&mut links, &mut hops)?;
                                        continue;
                                    }
                                    ProcEntry::Inside | ProcEntry::NotProc => {}
                                }
                            }
                            proc_view = Some(tv);
                        }
                    }
                    // Inside procfs the walk passes only what exists, and
                    // only directories: the kernel's own error otherwise.
                    let proc_kind = match (continuing, proc_view.as_ref()) {
                        (true, Some(tv)) => match probe_uncached(tv) {
                            ProbeKind::Missing => return Err(WalkError::Kernel(libc::ENOENT)),
                            ProbeKind::Other => return Err(WalkError::Kernel(libc::ENOTDIR)),
                            k => Some(k),
                        },
                        _ => None,
                    };
                    // Never splice /proc/self (or /proc/<pid>)
                    // itself, or the magic link under it
                    // (fd/exe/cwd/map_files): resolving either
                    // from the Tool process would name the
                    // wrong task (measured: guest read the
                    // tracer's /proc/self/status; lstat on
                    // /proc/self/cwd/ spliced the launcher's
                    // own cwd under the rootfs -> ENOENT).
                    // "root" is deliberately excluded: literoot
                    // does not chroot, so splicing the Tool's
                    // /proc/self/root ("/") and re-rooting it
                    // under the rootfs names the guest root,
                    // while passing it through would leak the
                    // host root to the guest. A walk with a policy
                    // decides those above, from the host path, so the
                    // spelled rule applies only without one; with one,
                    // a rootfs `proc/...` that is not the real procfs
                    // is an ordinary rootfs entry.
                    let proc_head = proc.is_none()
                        && stack
                            .first()
                            .map(|c| c.as_os_str() == "proc")
                            .unwrap_or(false)
                        && (stack.len() <= 2
                            || (stack.len() == 3
                                && matches!(
                                    stack[2].as_os_str().to_str(),
                                    Some("fd" | "exe" | "cwd" | "map_files")
                                )));
                    // A just-crossed binding is terminal: do not
                    // splice the bound host root itself (e.g.
                    // /bin -> usr/bin would leave the binding).
                    let at_bound_root = bound
                        .as_ref()
                        .map(|(gc, _)| stack.len() == gc.len())
                        .unwrap_or(false);
                    if continuing && !proc_head && !at_bound_root {
                        // Intermediate component: resolve symlink
                        // splice; stop at nonexistent (literal tail).
                        let kind = match proc_kind {
                            Some(k) => k,
                            None => probe(&host),
                        };
                        match kind {
                            ProbeKind::Symlink => {
                                hops += 1;
                                let splice = match links.as_deref_mut() {
                                    Some(n) => take_link(n).map(|()| true)?,
                                    None => hops <= 40,
                                };
                                if splice {
                                    let target =
                                        std::fs::read_link(proc_view.as_ref().unwrap_or(&host))
                                            .unwrap_or_default();
                                    stack.pop();
                                    if target.is_absolute() {
                                        stack.clear();
                                    }
                                    let mut rest: VecDeque<Comp> =
                                        target.components().map(to_comp).collect();
                                    rest.extend(pending);
                                    pending = rest;
                                }
                            }
                            ProbeKind::Dir | ProbeKind::Other => {}
                            ProbeKind::Missing => {
                                // Nonexistent intermediate: keep
                                // walking lexically (bind matching
                                // still applies); only a later `..`
                                // needs the literal tail.
                                unresolved = true;
                            }
                        }
                    }
                }
            }
        }
        if bound.is_none() {
            bound = self.bind_at(&stack);
        }
        // After a Raw hand-over the kernel walks the literal rest with the
        // budget this walk has left: its intermediate links count now (the
        // final component is the caller's to follow or not). A trailing
        // slash or "/." makes the kernel follow the final component too,
        // whatever the call (even O_NOFOLLOW), and the caller's final-link
        // check cannot see a link behind the slash, so it counts here, once,
        // as an intermediate one.
        if let (Some(start), Some(n)) = (raw_start.as_ref(), links) {
            use std::os::unix::ffi::OsStrExt as _;
            let raw = path.as_os_str().as_bytes();
            let slash_forced = raw.ends_with(b"/") || raw.ends_with(b"/.");
            let mut tail = literal[1..].to_vec();
            if slash_forced {
                tail.push(std::ffi::OsString::from("."));
            }
            if tail.len() > 1 {
                count_raw_tail(start, &tail, n)?;
            }
        }
        // Trailing "/." (invisible to Path::components) forces
        // directory semantics in the kernel: keep it literal
        // when the final component is not a plain directory.
        {
            use std::os::unix::ffi::OsStrExt as _;
            let raw = path.as_os_str().as_bytes();
            // After a Raw hand-over too (a literal tail): dropping it there
            // made the kernel see the bare final component.
            if (raw.ends_with(b"/.") || raw.ends_with(b"/./")) && !(literal.is_empty() && stack.is_empty()) {
                // Always preserve: kernel handles "d/." (open
                // succeeds, rmdir EINVAL, readlink EINVAL) —
                // collapsing it changes all three.
                literal.push(std::ffi::OsString::from("."));
            }
        }
        // Build by bytes (OsStrExt in scope): PathBuf::push normalizes away a
        // trailing "." component, which would erase the
        // ENOTDIR the kernel must report.
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let mut bytes: Vec<u8> = vec![b'/'];
        for c in stack.iter().chain(literal.iter()) {
            if c.as_os_str() == "\u{1}" {
                continue;
            }
            if bytes.len() > 1 {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(c.as_os_str().as_bytes());
        }
        Ok((PathBuf::from(std::ffi::OsString::from_vec(bytes)), bound))
    }

    /// Bind bookkeeping after the stack changed: the deepest bind whose
    /// guest prefix equals the stack wins (nested binds /data vs
    /// /data/inner), and a bind the stack left is dropped. True when a bind
    /// was crossed exactly here.
    fn rebind(
        &self,
        stack: &[std::ffi::OsString],
        bound: &mut Option<(Vec<std::ffi::OsString>, PathBuf)>,
    ) -> bool {
        match self.bind_at(stack) {
            Some(deeper) => {
                if std::env::var_os("LITEROOT_DEBUG").is_some() {
                    eprintln!("literoot: bind_at {stack:?} -> {deeper:?}");
                }
                *bound = Some(deeper);
                true
            }
            None => {
                if let Some((gc, _)) = bound.as_ref() {
                    if stack.len() < gc.len() || stack[..gc.len()] != gc[..] {
                        *bound = None;
                    }
                }
                false
            }
        }
    }

    /// The procfs class of a walk's host path, with its tool-view path.
    /// The walk enters procfs only at a component whose name procfs uses
    /// for a process or for itself (`self`, `thread-self`, digits), or at a
    /// bind's host root, and only when its parent is on procfs; below the
    /// root it found, every entry is classified.
    fn proc_class(
        &self,
        host: &Path,
        proc_root: &mut Option<PathBuf>,
        policy: &dyn ProcLinks,
        crossed: bool,
    ) -> Option<(ProcEntry, PathBuf)> {
        if let Some(root) = proc_root.as_ref() {
            if host.starts_with(root) && host != root.as_path() {
                return entry_under(root, host, policy);
            }
        }
        let name = host.file_name()?.to_str()?;
        let hint = matches!(name, "self" | "thread-self")
            || (!name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()));
        if !hint && !crossed {
            return None;
        }
        let root = procfs_root_of(host)?;
        let found = entry_under(&root, host, policy);
        *proc_root = Some(root);
        found
    }

    /// Translate a guest path to its host path. `cwd` is the guest cwd
    /// from replicated per-process state; `dirfd_guest` is the guest
    /// path denoted by a real dirfd, when the call is fd-relative.
    pub fn translate(&self, path: &Path, cwd: &Path, dirfd_guest: Option<&Path>) -> PathBuf {
        match self.translate_links(path, cwd, dirfd_guest, None, None) {
            Ok(host) => host,
            Err(_) => unreachable!("an uncounted walk with no policy cannot fail"),
        }
    }

    /// [`Self::translate`] for a guest path walk: the symlinks it splices
    /// count against `links`, shared with the rest of the walk, and more
    /// than [`MAX_SYMLINKS`] in all is [`TooManyLinks`] (the guest's
    /// ELOOP) instead of a host path that still holds a link for the
    /// kernel to follow in the host's namespace.
    pub fn translate_counted(
        &self,
        path: &Path,
        cwd: &Path,
        dirfd_guest: Option<&Path>,
        links: &mut u32,
    ) -> Result<PathBuf, TooManyLinks> {
        self.translate_links(path, cwd, dirfd_guest, Some(links), None)
            .map_err(|e| match e {
                WalkError::TooManyLinks => TooManyLinks,
                WalkError::Refused(_) | WalkError::Kernel(_) => {
                    unreachable!("a walk with no policy refuses nothing")
                }
            })
    }

    /// [`Self::translate_counted`] for a walk on a guest's behalf: `proc`
    /// answers at every /proc magic link (see [`ProcLinks`]), and may
    /// refuse ([`WalkError::Refused`]).
    pub fn translate_walk(
        &self,
        path: &Path,
        cwd: &Path,
        dirfd_guest: Option<&Path>,
        links: &mut u32,
        proc: &dyn ProcLinks,
    ) -> Result<PathBuf, WalkError> {
        self.translate_links(path, cwd, dirfd_guest, Some(links), Some(proc))
    }

    fn translate_links(
        &self,
        path: &Path,
        cwd: &Path,
        dirfd_guest: Option<&Path>,
        mut links: Option<&mut u32>,
        proc: Option<&dyn ProcLinks>,
    ) -> Result<PathBuf, WalkError> {
        // Empty path (AT_EMPTY_PATH): denotes the dirfd itself.
        if path.as_os_str().is_empty() {
            if let Some(d) = dirfd_guest {
                let (dir, _) =
                    self.canonicalize_inner(Path::new("/"), d, links.as_deref_mut(), proc)?;
                return Ok(self.translate_absolute(&dir));
            }
            return Ok(self.rootfs.clone());
        }
        let (guest_abs, bound) = if path.is_absolute() {
            self.canonicalize_inner(Path::new("/"), path, links, proc)?
        } else if let Some(d) = dirfd_guest {
            self.canonicalize_inner(d, path, links, proc)?
        } else {
            self.canonicalize_inner(cwd, path, links, proc)?
        };
        let mut host = match &bound {
            Some(_) => {
                let comps: Vec<std::ffi::OsString> = guest_abs
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(s2) => Some(s2.to_os_string()),
                        Component::ParentDir => Some(std::ffi::OsString::from("..")),
                        Component::CurDir => Some(std::ffi::OsString::from(".")),
                        _ => None,
                    })
                    .collect();
                self.host_of_bound(&comps, bound.as_ref())
            }
            None => self.translate_absolute(&guest_abs),
        };
        // translate_absolute's PathBuf joins would normalize a
        // trailing "/." away; restore it byte-wise.
        {
            use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
            if guest_abs.as_os_str().as_bytes().ends_with(b"/.")
                && !host.as_os_str().as_bytes().ends_with(b"/.")
            {
                let mut b = host.as_os_str().as_bytes().to_vec();
                b.extend_from_slice(b"/.");
                host = PathBuf::from(std::ffi::OsString::from_vec(b));
            }
        }
        Ok(host)
    }

    fn translate_absolute(&self, guest_abs: &Path) -> PathBuf {
        // Longest matching bind guest-prefix wins; default is rootfs.
        let mut best: Option<&Bind> = None;
        for b in &self.binds {
            if guest_abs.starts_with(&b.guest) {
                let better = match best {
                    None => true,
                    Some(prev) => {
                        b.guest.components().count() > prev.guest.components().count()
                    }
                };
                if better {
                    best = Some(b);
                }
            }
        }
        match best {
            Some(b) => {
                let suffix = guest_abs.strip_prefix(&b.guest).unwrap_or(Path::new(""));
                let mut p = b.host.clone();
                if !suffix.as_os_str().is_empty() {
                    p.push(suffix);
                }
                p
            }
            None => {
                let suffix = guest_abs.strip_prefix("/").unwrap_or(guest_abs);
                let mut p = self.rootfs.clone();
                if !suffix.as_os_str().is_empty() {
                    p.push(suffix);
                }
                p
            }
        }
    }

    /// Reverse-translate a host path (from e.g. /proc/self/fd) back to
    /// its guest path, or None if it is outside every mapped tree.
    pub fn reverse(&self, host: &Path) -> Option<PathBuf> {
        // Deepest host-side binding wins — including the rootfs
        // itself as a candidate (a rootfs under /tmp must beat a
        // -b /tmp:/ced bind for paths physically in the rootfs).
        let rootfs_n = if host.starts_with(&self.rootfs) {
            Some(self.rootfs.components().count())
        } else {
            None
        };
        let mut best: Option<(&Bind, usize)> = None;
        for b in &self.binds {
            if host.starts_with(&b.host) {
                let n = b.host.components().count();
                if rootfs_n.map(|rn| n <= rn).unwrap_or(false) {
                    continue;
                }
                if best.map(|(_, m)| n > m).unwrap_or(true) {
                    best = Some((b, n));
                }
            }
        }
        if let Some((b, _)) = best {
            let suffix = host.strip_prefix(&b.host).ok()?;
            let mut p = b.guest.clone();
            if !suffix.as_os_str().is_empty() {
                p.push(suffix);
            }
            return Some(p);
        }
        let suffix = host.strip_prefix(&self.rootfs).ok()?;
        let mut p = PathBuf::from("/");
        if !suffix.as_os_str().is_empty() {
            p.push(suffix);
        }
        Some(p)
    }
}

impl RootConfig {
    /// De-translate a readlink result (design §4.5; semantics
    /// pinned by upstream proot tests test-readlink-bind-detranslate
    /// and test-readlink-deepest-binding):
    ///
    /// - Relative stored targets pass through verbatim.
    /// - Absolute stored target, link file lives under a bind's
    ///   host tree: the target was written in host-namespace terms,
    ///   so reverse-translate it host→guest (deepest host binding
    ///   wins, per `reverse`).
    /// - Absolute stored target, link lives in the rootfs: the
    ///   target is already a guest path; return it normalized
    ///   through translate+reverse (identity unless binds alias it).
    pub fn detranslate_readlink(
        &self,
        link_host: &Path,
        link_guest: &Path,
        stored: &[u8],
    ) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt as _;
        let target = Path::new(std::ffi::OsStr::from_bytes(stored));
        if !target.is_absolute() {
            return stored.to_vec();
        }
        // Kernel-generated /proc/self/* targets are host paths:
        // reverse-translate globally (deepest host binding).
        if link_guest.starts_with("/proc/self") || link_guest.starts_with("/proc/thread-self") {
            return match self.reverse(target) {
                Some(g) => g.as_os_str().as_bytes().to_vec(),
                None => stored.to_vec(),
            };
        }
        // Otherwise the stored target is interpreted in the
        // namespace of the binding that contains the link: only a
        // target under that binding's host prefix is rewritten to
        // the guest prefix; anything else passes through (it was
        // written as a guest path, e.g. by a guest symlink call).
        // The rootfs counts as the binding guest=/ host=<rootfs>
        // and wins over shallower binds for links inside it.
        let mut binding: Option<(PathBuf, PathBuf, usize)> = None;
        for (guest, host) in std::iter::once((PathBuf::from("/"), self.rootfs.clone()))
            .chain(self.binds.iter().map(|b| (b.guest.clone(), b.host.clone())))
        {
            if link_host.starts_with(&host) {
                let n = host.components().count();
                if binding
                    .as_ref()
                    .map(|(_, _, m)| n > *m)
                    .unwrap_or(true)
                {
                    binding = Some((guest, host, n));
                }
            }
        }
        match binding {
            Some((guest_prefix, host_prefix, _)) => {
                match target.strip_prefix(host_prefix) {
                    Ok(suffix) => {
                        let mut out = guest_prefix.to_path_buf();
                        if !suffix.as_os_str().is_empty() {
                            out.push(suffix);
                        }
                        out.as_os_str().as_bytes().to_vec()
                    }
                    Err(_) => stored.to_vec(),
                }
            }
            None => stored.to_vec(),
        }
    }
}

/// Canonicalize a guest path against the rootfs only (no bind
/// consultation): symlink splice + kernel-faithful `..`.
fn canonicalize_plain(rootfs: &Path, guest: &Path) -> PathBuf {
    use std::collections::VecDeque;
    #[derive(Clone)]
    enum C {
        Root,
        Dot,
        DotDot,
        Name(std::ffi::OsString),
    }
    fn tc(c: Component) -> C {
        match c {
            Component::RootDir => C::Root,
            Component::CurDir => C::Dot,
            Component::ParentDir => C::DotDot,
            Component::Normal(s) => C::Name(s.to_os_string()),
            Component::Prefix(_) => C::Root,
        }
    }
    let host_of = |stack: &[std::ffi::OsString]| -> PathBuf {
        let mut h = rootfs.to_path_buf();
        for c in stack {
            h.push(c);
        }
        h
    };
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    let mut pending: VecDeque<C> = guest.components().map(tc).collect();
    let mut hops = 0u32;
    while let Some(c) = pending.pop_front() {
        match c {
            C::Root => stack.clear(),
            C::Dot => {}
            C::DotDot => {
                if !stack.is_empty() {
                    stack.pop();
                }
            }
            C::Name(n) => {
                stack.push(n);
                let host = host_of(&stack);
                // Route through the generation-validated probe cache:
                // bind-prefix canonicalization runs on every config
                // rebuild (several per dispatch) and must not re-stat
                // the same bind roots each time.
                if probe(&host) == ProbeKind::Symlink {
                    if hops <= 40 {
                        hops += 1;
                        let target = std::fs::read_link(&host).unwrap_or_default();
                        stack.pop();
                        if target.is_absolute() {
                            stack.clear();
                        }
                        let mut rest: VecDeque<C> =
                            target.components().map(tc).collect();
                        rest.extend(pending);
                        pending = rest;
                    }
                }
            }
        }
    }
    let mut out = PathBuf::from("/");
    for c in &stack {
        out.push(c);
    }
    out
}

/// Extract `PT_INTERP` from an ELF64 (LE/BE) image prefix, if any.
/// Used to run a rootfs binary through the *rootfs's* dynamic
/// linker (design §4.7): the kernel would otherwise open the
/// interp path on the host, where e.g. musl's loader is absent.
pub fn elf_interp(image: &[u8]) -> Option<String> {
    if image.len() < 64 || &image[0..4] != b"\x7fELF" || image[4] != 2 {
        return None;
    }
    let le = image[5] == 1;
    let rd16 = |o: usize| -> Option<u16> {
        let b = image.get(o..o + 2)?;
        Some(if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    };
    let rd32 = |o: usize| -> Option<u32> {
        let b = image.get(o..o + 4)?;
        Some(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let rd64 = |o: usize| -> Option<u64> {
        let b = image.get(o..o + 8)?;
        let a: [u8; 8] = b.try_into().ok()?;
        Some(if le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
    };
    let phoff = rd64(32)? as usize;
    let phentsize = rd16(54)? as usize;
    let phnum = rd16(56)? as usize;
    const PT_INTERP: u32 = 3;
    for i in 0..phnum {
        let off = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if rd32(off)? != PT_INTERP {
            continue;
        }
        let p_offset = rd64(off + 8)? as usize;
        let p_filesz = rd64(off + 32)? as usize;
        let raw = image.get(p_offset..p_offset.checked_add(p_filesz)?)?;
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        return String::from_utf8(raw[..end].to_vec()).ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RootConfig {
        RootConfig::new(
            PathBuf::from("/srv/rootfs"),
            vec![
                Bind { guest: PathBuf::from("/dev"), host: PathBuf::from("/dev"), no_follow: false },
                Bind { guest: PathBuf::from("/data"), host: PathBuf::from("/home/u/data"), no_follow: false },
                Bind {
                    guest: PathBuf::from("/data/inner"),
                    host: PathBuf::from("/mnt/inner"), no_follow: false,
                },
            ],
        )
    }

    #[test]
    fn absolute_into_rootfs() {
        let c = cfg();
        assert_eq!(
            c.translate(Path::new("/etc/os-release"), Path::new("/"), None),
            PathBuf::from("/srv/rootfs/etc/os-release")
        );
    }

    #[test]
    fn proc_self_magic_link_not_spliced_from_tool_cwd() {
        // Regression (test-lstat-trailing-slash-symlink,
        // dynamic guests): lstat("/proc/self/cwd/") must
        // reach the kernel as the guest's own magic link.
        // Canonicalizing it here spliced the symlink target
        // read from the *Tool's* /proc/self/cwd (the
        // launcher's host cwd) and re-rooted that absolute
        // host path under the rootfs, yielding ENOENT.
        let c = RootConfig::new(
            PathBuf::from("/srv/rootfs"),
            vec![Bind {
                guest: PathBuf::from("/proc"),
                host: PathBuf::from("/proc"),
                no_follow: false,
            }],
        );
        for p in [
            "/proc/self/cwd/",
            "/proc/self/cwd",
            "/proc/self/exe",
            "/proc/1234/cwd/",
        ] {
            assert_eq!(
                c.translate(Path::new(p), Path::new("/"), None),
                PathBuf::from(p),
                "{p} must pass through via the /proc bind, unspliced"
            );
        }
        // /proc/self/root is the exception: literoot does
        // not chroot, so splicing the Tool's root link ("/")
        // and re-rooting it names the guest rootfs root.
        // Passing it through would leak the host root.
        assert_eq!(
            c.translate(Path::new("/proc/self/root/"), Path::new("/"), None),
            PathBuf::from("/srv/rootfs/"),
            "/proc/self/root/ must name the rootfs root, not the host root"
        );
        // Relative proc/... paths classify on the resolved
        // guest path: from cwd /home they are ordinary
        // rootfs paths under /home, never the host /proc.
        for p in ["proc/self/cwd/", "./proc/self/cwd/"] {
            assert_eq!(
                c.translate(Path::new(p), Path::new("/home"), None),
                PathBuf::from("/srv/rootfs/home/proc/self/cwd"),
                "relative {p} from /home must stay inside the rootfs"
            );
        }
    }

    #[test]
    fn relative_against_cwd() {
        let c = cfg();
        assert_eq!(
            c.translate(Path::new("foo/bar"), Path::new("/work"), None),
            PathBuf::from("/srv/rootfs/work/foo/bar")
        );
    }

    #[test]
    fn dotdot_clamps_at_root() {
        let c = cfg();
        // Nonexistent intermediate (cfg rootfs does not exist on
        // disk): kernel-faithful literal tail, NOT lexical
        // collapse (test-path-traversal-conformance).
        assert_eq!(
            c.translate(Path::new("/a/../../etc/passwd"), Path::new("/"), None),
            PathBuf::from("/srv/rootfs/a/../../etc/passwd")
        );
        assert_eq!(
            c.translate(Path::new("../../../etc/shadow"), Path::new("/x"), None),
            PathBuf::from("/srv/rootfs/x/../../../etc/shadow")
        );
    }

    #[test]
    fn longest_bind_wins() {
        let c = cfg();
        assert_eq!(
            c.translate(Path::new("/data/inner/f"), Path::new("/"), None),
            PathBuf::from("/mnt/inner/f")
        );
        assert_eq!(
            c.translate(Path::new("/data/other/f"), Path::new("/"), None),
            PathBuf::from("/home/u/data/other/f")
        );
        assert_eq!(
            c.translate(Path::new("/dev/null"), Path::new("/"), None),
            PathBuf::from("/dev/null")
        );
    }

    #[test]
    fn dirfd_relative() {
        let c = cfg();
        assert_eq!(
            c.translate(
                Path::new("sub/f"),
                Path::new("/elsewhere"),
                Some(Path::new("/var/lib"))
            ),
            PathBuf::from("/srv/rootfs/var/lib/sub/f")
        );
        assert_eq!(
            c.translate(Path::new(""), Path::new("/"), Some(Path::new("/var"))),
            PathBuf::from("/srv/rootfs/var")
        );
    }

    #[test]
    fn reverse_roundtrip() {
        let c = cfg();
        assert_eq!(
            c.reverse(Path::new("/srv/rootfs/etc/hosts")),
            Some(PathBuf::from("/etc/hosts"))
        );
        assert_eq!(
            c.reverse(Path::new("/home/u/data/f")),
            Some(PathBuf::from("/data/f"))
        );
        assert_eq!(c.reverse(Path::new("/tmp/unrelated")), None);
    }

    #[test]
    fn detranslate_cases() {
        // Mirrors upstream test-readlink-bind-detranslate/deepest.
        let c = RootConfig::new(
            PathBuf::from("/srv/rootfs"),
            vec![Bind { guest: PathBuf::from("/ced"), host: PathBuf::from("/tmp"), no_follow: false }],
        );
        // Link in bind tree, host-written absolute target.
        assert_eq!(
            c.detranslate_readlink(Path::new("/tmp/SYM"), Path::new("/ced/SYM"), b"/tmp/REG"),
            b"/ced/REG".to_vec()
        );
        // Link in rootfs, guest-written absolute target: unchanged.
        assert_eq!(
            c.detranslate_readlink(Path::new("/srv/rootfs/tmp/SYM"), Path::new("/tmp/SYM"), b"/tmp/REG"),
            b"/tmp/REG".to_vec()
        );
        // Guest-written absolute target outside the link's
        // binding: verbatim (upstream deepest-binding tail case).
        assert_eq!(
            c.detranslate_readlink(Path::new("/tmp/L"), Path::new("/ced/L"), b"/bin/bar"),
            b"/bin/bar".to_vec()
        );
        // Relative target: verbatim either way.
        assert_eq!(
            c.detranslate_readlink(Path::new("/tmp/SYM"), Path::new("/ced/SYM"), b"./true"),
            b"./true".to_vec()
        );
        // /proc/self/cwd style: link under /proc bind, target is
        // host cwd inside rootfs.
        let c2 = RootConfig::new(
            PathBuf::from("/srv/rootfs"),
            vec![Bind { guest: PathBuf::from("/proc"), host: PathBuf::from("/proc"), no_follow: false }],
        );
        assert_eq!(
            c2.detranslate_readlink(Path::new("/proc/self/cwd"), Path::new("/proc/self/cwd"), b"/srv/rootfs/work"),
            b"/work".to_vec()
        );
    }

    #[test]
    fn root_itself() {
        let c = cfg();
        assert_eq!(
            c.translate(Path::new("/"), Path::new("/"), None),
            PathBuf::from("/srv/rootfs")
        );
    }
}

#[cfg(test)]
mod shared_gen_tests {
    use super::*;

    fn memfd(name: &std::ffi::CStr) -> i32 {
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        fd
    }

    fn close(fd: i32) {
        unsafe { libc::close(fd) };
    }

    #[test]
    fn identity_round_trips_and_rejects_other_text() {
        let identity = FdIdentity { dev: 64769, ino: 1234567 };
        assert_eq!(identity.encode(), "64769:1234567");
        assert_eq!(FdIdentity::decode("64769:1234567"), Some(identity));
        for bad in ["", "7", "7:", ":7", "7:8:9", "-1:2", "a:2", "7 :8", "3"] {
            assert_eq!(FdIdentity::decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn find_takes_the_highest_read_write_copy_of_that_file_only() {
        let file = memfd(c"literoot-find-test");
        let identity = FdIdentity::of_fd(file).unwrap();
        let other = memfd(c"literoot-find-other");
        // A read-write duplicate high up: the copy a placement leaves.
        let high = unsafe { libc::fcntl(file, libc::F_DUPFD_CLOEXEC, 700) };
        assert!(high >= 700);
        // A read-only reopen of the same file, higher still: not a
        // handed-down copy, so it must not win.
        let path = std::ffi::CString::new(format!("/proc/self/fd/{file}")).unwrap();
        let read_only = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(read_only >= 0);
        let read_only_high = unsafe { libc::fcntl(read_only, libc::F_DUPFD_CLOEXEC, 900) };
        assert!(read_only_high >= 900);
        assert_eq!(find_read_write_descriptor(identity).unwrap(), Some(high));
        close(high);
        assert_eq!(find_read_write_descriptor(identity).unwrap(), Some(file));
        close(file);
        // Only read-only copies of it remain open.
        assert_eq!(find_read_write_descriptor(identity).unwrap(), None);
        close(read_only);
        close(read_only_high);
        assert_eq!(find_read_write_descriptor(identity).unwrap(), None);
        close(other);
    }

    #[test]
    fn shared_gen_memfd_is_size_sealed_before_use() {
        let fd = create_shared_gen_fd();
        assert!(fd >= 0, "create_shared_gen_fd failed");
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        assert_eq!(
            seals,
            libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
            "seals {seals:#x}"
        );
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
        assert_eq!(stat.st_size, 8);
        // Neither descriptor nor path can resize it.
        assert_eq!(unsafe { libc::ftruncate(fd, 0) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(unsafe { libc::truncate(path.as_ptr(), 4096) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        assert!(PROBE_GEN_SHARED.get().is_some(), "the counter is mapped");
        close(fd);
    }
}
