//! Arch-free guest→host path translation (design §4.2/§6).
//!
//! Pure and std-only so it unit-tests without any backend and can be
//! shared unchanged by the x86-64 (M1) and aarch64 (M2) Tools.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Probe-cache generation: bumped by the Tool on any successful
/// mutating path syscall so cached component kinds never outlive
/// a rename/unlink/symlink change. If the memfd env is scrubbed
/// or the fd was closed before first use, this silently falls
/// back to the process-local counter (per-process coherence
/// only) — same stated limit class as host-side mutation.
///
/// Coherence scope: the counter lives in a launcher-created
/// memfd (MAP_SHARED) inherited across the whole guest tree, so
/// a mutation in any guest process invalidates every process's
/// cache. Without the memfd (unit tests, --check) it falls back
/// to a process-local atomic. Host-side mutation (outside any
/// guest) is NOT detected — a stated divergence from proot,
/// which re-probes on every canonicalization.
static PROBE_GEN_LOCAL: AtomicU64 = AtomicU64::new(0);
static PROBE_GEN_SHARED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn shared_gen() -> Option<&'static AtomicU64> {
    // Mutant switch for the coherence test: force the
    // process-local generation (must FAIL cross-process).
    if std::env::var_os("LITEROOT_PROBE_LOCAL").is_some() {
        return None;
    }
    if let Some(p) = PROBE_GEN_SHARED.get() {
        return Some(unsafe { &*(*p as *const AtomicU64) });
    }
    if let Ok(fd_s) = std::env::var("LITEROOT_PROBE_GEN_FD") {
        if let Ok(fd) = fd_s.parse::<i32>() {
            init_shared_gen_from_fd(fd);
            return PROBE_GEN_SHARED
                .get()
                .map(|p| unsafe { &*(*p as *const AtomicU64) });
        }
    }
    None
}

/// mmap the shared generation counter from `fd` (idempotent).
pub fn init_shared_gen_from_fd(fd: i32) {
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
}

/// Create the shared generation memfd (launcher side). Returns
/// the fd (CLOEXEC cleared) to pass to the guest via env, or -1.
pub fn create_shared_gen_fd() -> i32 {
    unsafe {
        let name = c"literoot-probe-gen";
        let fd = libc::memfd_create(name.as_ptr(), 0);
        if fd < 0 {
            return -1;
        }
        if libc::ftruncate(fd, 8) != 0 {
            libc::close(fd);
            return -1;
        }
        init_shared_gen_from_fd(fd);
        fd
    }
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

thread_local! {
    static PROBE_CACHE: RefCell<HashMap<PathBuf, (u64, ProbeKind)>> =
        RefCell::new(HashMap::new());
}

/// symlink_metadata with a generation-validated cache. The
/// canonicalizer probes every intermediate component on every
/// syscall; without this, a stat loop pays one extra real
/// syscall per component (measured in-guest regression).
fn probe(host: &Path) -> ProbeKind {
    let gen = probe_gen();
    if let Some(k) = PROBE_CACHE.with(|c| {
        c.borrow()
            .get(host)
            .and_then(|(g, k)| if *g == gen { Some(*k) } else { None })
    }) {
        return k;
    }
    let k = match std::fs::symlink_metadata(host) {
        Ok(m) if m.file_type().is_symlink() => ProbeKind::Symlink,
        Ok(m) if m.is_dir() => ProbeKind::Dir,
        Ok(_) => ProbeKind::Other,
        Err(_) => ProbeKind::Missing,
    };
    PROBE_CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(host.to_path_buf(), (gen, k));
    });
    k
}

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
}

impl RootConfig {
    pub fn new(rootfs: PathBuf, mut binds: Vec<Bind>) -> Self {
        // Canonicalize bind guest prefixes (symlinks inside the
        // rootfs resolved): mid-walk binding substitution compares
        // canonical stacks (test-readdir-symlinked-dir).
        for b in &mut binds {
            b.guest = canonicalize_plain(&rootfs, &b.guest);
        }
        Self { rootfs, binds, fake_root: false, fake_ids: None, kernel_release: None }
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
        self.canonicalize_inner(base, path).0
    }

    fn canonicalize_inner(&self, base: &Path, path: &Path) -> (PathBuf, Option<(Vec<std::ffi::OsString>, PathBuf)>) {
        use std::collections::VecDeque;
        #[derive(Clone)]
        enum Comp {
            Root,
            Dot,
            DotDot,
            Name(std::ffi::OsString),
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
        let mut stack: Vec<std::ffi::OsString> = if path.is_absolute() {
            Vec::new()
        } else {
            base.components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_os_string()),
                    _ => None,
                })
                .collect()
        };
        let mut bound = self.bind_at(&stack);
        let mut pending: VecDeque<Comp> =
            path.components().map(to_comp).collect();
        let mut literal: Vec<std::ffi::OsString> = Vec::new();
        let mut unresolved = false;
        let mut hops = 0u32;
        while let Some(comp) = pending.pop_front() {
            if !literal.is_empty() {
                match comp {
                    Comp::Name(s) => literal.push(s),
                    Comp::DotDot => literal.push(std::ffi::OsString::from("..")),
                    Comp::Dot => literal.push(std::ffi::OsString::from(".")),
                    Comp::Root => {}
                }
                continue;
            }
            match comp {
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
                    match probe(&host) {
                        ProbeKind::Symlink => {
                            hops += 1;
                            if hops > 40 {
                                literal.push(std::ffi::OsString::from(".."));
                                continue;
                            }
                            let target = std::fs::read_link(&host)
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
                    match self.bind_at(&stack) {
                        Some(deeper) => {
                            if std::env::var_os("LITEROOT_DEBUG").is_some() {
                                eprintln!("literoot: bind_at {stack:?} -> {deeper:?}");
                            }
                            bound = Some(deeper)
                        }
                        None => {
                            if let Some((gc, _)) = &bound {
                                if stack.len() < gc.len()
                                    || stack[..gc.len()] != gc[..]
                                {
                                    bound = None;
                                }
                            }
                        }
                    }
                    // Never splice /proc/self (or /proc/<pid>)
                    // itself: resolving it from the Tool process
                    // would name the wrong task (measured:
                    // guest read the tracer's /proc/self/status).
                    let proc_head = stack.len() <= 2
                        && stack
                            .first()
                            .map(|c| c.as_os_str() == "proc")
                            .unwrap_or(false);
                    if !pending.is_empty() && !proc_head {
                        // Intermediate component: resolve symlink
                        // splice; stop at nonexistent (literal tail).
                        let host = self.host_of_bound(&stack, bound.as_ref());
                        match probe(&host) {
                            ProbeKind::Symlink => {
                                hops += 1;
                                if hops <= 40 {
                                    let target = std::fs::read_link(&host)
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
        // Trailing "/." (invisible to Path::components) forces
        // directory semantics in the kernel: keep it literal
        // when the final component is not a plain directory.
        {
            use std::os::unix::ffi::OsStrExt as _;
            let raw = path.as_os_str().as_bytes();
            if (raw.ends_with(b"/.") || raw.ends_with(b"/./")) && literal.is_empty() && !stack.is_empty() {
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
        (PathBuf::from(std::ffi::OsString::from_vec(bytes)), bound)
    }

    /// Translate a guest path to its host path. `cwd` is the guest cwd
    /// from replicated per-process state; `dirfd_guest` is the guest
    /// path denoted by a real dirfd, when the call is fd-relative.
    pub fn translate(&self, path: &Path, cwd: &Path, dirfd_guest: Option<&Path>) -> PathBuf {
        // Empty path (AT_EMPTY_PATH): denotes the dirfd itself.
        if path.as_os_str().is_empty() {
            if let Some(d) = dirfd_guest {
                return self.translate_absolute(&self.canonicalize(Path::new("/"), d));
            }
            return self.rootfs.clone();
        }
        let (guest_abs, bound) = if path.is_absolute() {
            self.canonicalize_inner(Path::new("/"), path)
        } else if let Some(d) = dirfd_guest {
            self.canonicalize_inner(d, path)
        } else {
            self.canonicalize_inner(cwd, path)
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
        host
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

    /// Translate WITHOUT lexical normalization (magic /proc paths):
    /// longest bind guest-prefix match on the raw path, else
    /// rootfs + raw path. Relative paths join the guest cwd raw.
    pub fn translate_raw(&self, path: &Path, cwd: &Path) -> PathBuf {
        use std::os::unix::ffi::OsStrExt as _;
        let abs: PathBuf = if path.is_absolute() {
            path.to_path_buf()
        } else {
            let mut p = cwd.to_path_buf();
            p.push(path);
            p
        };
        let mut best: Option<&Bind> = None;
        for b in &self.binds {
            if abs.starts_with(&b.guest) {
                if best
                    .map(|p: &Bind| {
                        b.guest.components().count() > p.guest.components().count()
                    })
                    .unwrap_or(true)
                {
                    best = Some(b);
                }
            }
        }
        let _ = abs.as_os_str().as_bytes();
        match best {
            Some(b) => {
                let suffix = abs.strip_prefix(&b.guest).unwrap_or(Path::new(""));
                let mut p = b.host.clone();
                if !suffix.as_os_str().is_empty() {
                    p.push(suffix);
                }
                p
            }
            None => {
                let suffix = abs.strip_prefix("/").unwrap_or(&abs);
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
                if let Ok(m) = std::fs::symlink_metadata(&host) {
                    if m.file_type().is_symlink() && hops <= 40 {
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
