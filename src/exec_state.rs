//! Bounded canonical `ExecState`: the per-process `RootfsTool`
//! continuity state that must survive an exec boundary (B4).
//!
//! One versioned payload, transport-neutral: the native route
//! carries it inside `RootfsThreadState::pending`, later routes
//! deliver `encode()` bytes to the same restore seam. Capture is
//! synchronous at the final exec inject boundary; restore applies
//! to a fresh `ProcState` before `handle_post_exec` runs.
//!
//! The payload describes guest-semantic state only — raw OS path
//! bytes, never pointers or host addresses (the chroot override is
//! host directory bytes, re-validated against the launch config
//! on restore). The scratch pages (each thread's, the image number
//! and the reuse list), getcwd's page (`getcwd_scratch`) and the
//! per-dispatch memos never cross.
//! Shared cross-process facts (PID exe/argv directory, UTS names,
//! immutable config) are explicitly not part of this payload.
//!
//! This module performs no I/O and issues no syscalls.

use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::rootfs_tool::{DirStream, FdTable, FilesId, LiterootConfig, ProcState, MAIN_FILES};
use crate::translate::RootConfig;

/// Wire magic ("LRX1").
pub const MAGIC: &[u8; 4] = b"LRX1";
/// Only supported wire version. Version 2 added each listing's
/// directory identity (`dirent_obj`); version 3 the S.3 record's lifetime
/// part (`record`), which exec keeps. Versions 1 and 2 are refused.
pub const VERSION: u16 = 3;
/// Hard cap on the encoded payload (aligned with the native
/// route's successor-state cap). Capture refuses by name above
/// this rather than truncating: a truncated fd map changes `*at`
/// resolution semantics.
pub const MAX_ENCODED_BYTES: usize = 1024 * 1024;

const FLAG_HAS_FAKE: u16 = 1 << 0;
const FLAG_HAS_ROOT_OVERRIDE: u16 = 1 << 1;
/// `exe_guest` is a host path (`ProcState::exe_host`). A flag with no
/// payload of its own: a record without it reads as before.
const FLAG_EXE_HOST: u16 = 1 << 2;
const CWD_SENTINEL: &[u8] = b"/__literoot_unset__";

/// Canonical exec-continuity snapshot. Path-like fields are raw
/// OS bytes; map-shaped fields are kept sorted by fd so two
/// encodes of one snapshot are byte-equal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecState {
    pub cwd: Vec<u8>,
    pub root_override: Option<Vec<u8>>,
    pub fds: Vec<(i32, Vec<u8>)>,
    pub fake: Option<[u32; 6]>,
    pub exe_guest: Vec<u8>,
    /// `exe_guest` is a host path, with no guest name.
    #[serde(default)]
    pub exe_host: bool,
    pub argv: Vec<Vec<u8>>,
    pub virtual_fds: Vec<(i32, Vec<u8>, bool)>,
    pub dirent_pending: Vec<(i32, Vec<u8>)>,
    pub dirent_seen: Vec<(i32, Vec<Vec<u8>>)>,
    /// (fd, dev, ino) of the directory each listing state was built for:
    /// without it a restored pending listing could be served for another
    /// directory dup'd onto the number.
    #[serde(default)]
    pub dirent_obj: Vec<(i32, u64, u64)>,
    /// The S.3 record's lifetime part, which exec keeps:
    /// applied only by the successor constructor, never at a fork restore
    /// (a fork seed carries the default).
    #[serde(default)]
    pub record: LifetimeRecord,
}

/// The lifetime part of a process's S.3 record: the flag, both exit
/// summaries' counters, and whether they were emitted. The transient
/// admission state (probes in flight, installs pending), the per-image
/// baseline and the kernel metadata are not carried: exec resets them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifetimeRecord {
    pub guest_filter: bool,
    pub flag: crate::dead_base::FlagState,
    pub installs: u64,
    pub installs_refused: u64,
    pub translated: u64,
    pub refused: u64,
    pub unseen_best_effort: u64,
    pub probes: u64,
    pub sud_refused: u64,
    pub sud_fallback: u64,
    pub summary_emitted: bool,
}

impl LifetimeRecord {
    /// The part of `a` exec keeps. An install still pending in another
    /// thread ends with that thread in the exec (de_thread): its result is
    /// unknown, so the flag is set conservatively.
    pub fn of(a: &crate::dead_base::Admission) -> Self {
        let guest_filter = a.guest_filter || a.install_pending > 0;
        let flag = match a.flag {
            crate::dead_base::FlagState::None if guest_filter => crate::dead_base::FlagState::Installed,
            flag => flag,
        };
        Self {
            guest_filter,
            flag,
            installs: a.installs,
            installs_refused: a.installs_refused,
            translated: a.translated,
            refused: a.refused,
            unseen_best_effort: a.unseen_best_effort,
            probes: a.probes,
            sud_refused: a.sud_refused,
            sud_fallback: a.sud_fallback,
            summary_emitted: a.summary_emitted,
        }
    }

    /// The record a successor image starts with.
    pub fn admission(self) -> crate::dead_base::Admission {
        crate::dead_base::Admission {
            guest_filter: self.guest_filter,
            flag: self.flag,
            installs: self.installs,
            installs_refused: self.installs_refused,
            translated: self.translated,
            refused: self.refused,
            unseen_best_effort: self.unseen_best_effort,
            probes: self.probes,
            sud_refused: self.sud_refused,
            sud_fallback: self.sud_fallback,
            summary_emitted: self.summary_emitted,
            ..Default::default()
        }
    }

    fn counters(&self) -> [u64; 8] {
        [
            self.installs,
            self.installs_refused,
            self.translated,
            self.refused,
            self.unseen_best_effort,
            self.probes,
            self.sud_refused,
            self.sud_fallback,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStateError {
    BadMagic,
    UnsupportedVersion(u16),
    Truncated,
    TrailingBytes,
    TooLarge,
    UnsortedOrDuplicateFd,
    NegativeFd,
    RelativePath,
    UnmappableRootOverride,
    Malformed,
}

impl std::fmt::Display for ExecStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "exec-state: bad magic"),
            Self::UnsupportedVersion(v) => {
                write!(f, "exec-state: unsupported version {v}")
            }
            Self::Truncated => write!(f, "exec-state: truncated input"),
            Self::TrailingBytes => write!(f, "exec-state: trailing bytes"),
            Self::TooLarge => write!(f, "exec-state: over size cap"),
            Self::UnsortedOrDuplicateFd => {
                write!(f, "exec-state: fds not strictly increasing")
            }
            Self::NegativeFd => write!(f, "exec-state: negative fd"),
            Self::RelativePath => write!(f, "exec-state: relative path"),
            Self::UnmappableRootOverride => {
                write!(f, "exec-state: root override not under launch config")
            }
            Self::Malformed => write!(f, "exec-state: malformed field"),
        }
    }
}

impl std::error::Error for ExecStateError {}

impl ExecState {
    /// Snapshot `st` at the exec boundary. The caller has already
    /// written the successor's `exe_guest`/argv into `st`. The
    /// cwd sentinel materializes from `cfg.cwd` (empty means "/").
    /// Fake state is captured exactly as-is — capturing must not
    /// initialize it, or `handle_post_exec`'s setuid transition
    /// would apply to the wrong base.
    pub fn capture(st: &ProcState, files: FilesId, cfg: &LiterootConfig) -> Self {
        fn bytes(p: &PathBuf) -> Vec<u8> {
            p.as_os_str().as_bytes().to_vec()
        }
        let cwd = if st.cwd.as_os_str().as_bytes() == CWD_SENTINEL {
            if cfg.cwd.is_empty() {
                b"/".to_vec()
            } else {
                cfg.cwd.clone().into_bytes()
            }
        } else {
            bytes(&st.cwd)
        };
        // The fd table of the capturing task: after exec, or in a fork
        // child, it is the process's only table.
        let t = st.fdt(files);
        let mut fds: Vec<(i32, Vec<u8>)> = t.fds.iter().map(|(fd, p)| (*fd, bytes(p))).collect();
        fds.sort();
        let mut virtual_fds: Vec<(i32, Vec<u8>, bool)> = t
            .virtual_fds
            .iter()
            .map(|(fd, p)| {
                (
                    *fd,
                    bytes(p),
                    st.stream(files, *fd).is_some_and(|s| s.emitted),
                )
            })
            .collect();
        virtual_fds.sort();
        // Each number's listing state comes from the stream it holds; the
        // successor holds one stream per number.
        let streams: Vec<(i32, &DirStream)> = t
            .streams
            .keys()
            .filter_map(|fd| st.stream(files, *fd).map(|s| (*fd, s)))
            .collect();
        let mut dirent_pending: Vec<(i32, Vec<u8>)> = streams
            .iter()
            .filter_map(|(fd, s)| s.pending.clone().map(|b| (*fd, b)))
            .collect();
        dirent_pending.sort();
        let mut dirent_seen: Vec<(i32, Vec<Vec<u8>>)> = streams
            .iter()
            .filter_map(|(fd, s)| {
                let names = s.seen.as_ref()?;
                let mut v: Vec<Vec<u8>> = names.iter().map(|n| n.clone().into_bytes()).collect();
                v.sort();
                Some((*fd, v))
            })
            .collect();
        dirent_seen.sort();
        let mut dirent_obj: Vec<(i32, u64, u64)> = streams
            .iter()
            .filter_map(|(fd, s)| s.obj.map(|(dev, ino)| (*fd, dev, ino)))
            .collect();
        dirent_obj.sort();
        // exe_guest is seeded lazily from config on first use, so
        // a fork before any exec (or any exe_guest() call) still
        // holds the empty default. Materialize it the same way:
        // fall back to cfg.initial_exe, absolutized against the
        // materialized cwd. Without this, capture of a perfectly
        // live pre-exec state would encode a relative/empty path
        // and refuse the fork.
        let exe_guest = {
            let raw: &[u8] = if st.exe_guest.as_os_str().is_empty() {
                cfg.initial_exe.as_bytes()
            } else {
                st.exe_guest.as_os_str().as_bytes()
            };
            if raw.first() == Some(&b'/') {
                raw.to_vec()
            } else if raw.is_empty() {
                cwd.clone()
            } else {
                let mut joined = cwd.clone();
                if !joined.ends_with(b"/") {
                    joined.push(b'/');
                }
                joined.extend_from_slice(raw);
                joined
            }
        };
        ExecState {
            cwd,
            root_override: st.root_override.as_ref().map(bytes),
            fds,
            fake: st.fake,
            exe_guest,
            exe_host: st.exe_host,
            argv: st.argv.clone(),
            virtual_fds,
            dirent_pending,
            dirent_seen,
            dirent_obj,
            record: LifetimeRecord::of(&st.admission),
        }
    }

    /// Capture the seed for a fork child that has not exec'd.
    ///
    /// Unlike an exec-boundary capture, the caller has not just
    /// staged a successor image into `st`: the seed describes the
    /// parent's *current* image. That image is not recomputed
    /// here. The caller supplies the values returned by its own
    /// current-image accessors (`RootfsTool::exe_guest` for
    /// `current_exe`, and the same materialized-argv value its
    /// `/proc/self/cmdline` path uses for `current_argv`), so
    /// launch-cwd-relative resolution, translation/reverse
    /// normalization, and the empty-`initial_exe` fallback stay
    /// in exactly one place. This function never resolves an
    /// exe against `st.cwd`, `cfg.cwd`, or `cfg.initial_exe`.
    ///
    /// `apply_to` forces `bootstrapped = true`, so fork wiring
    /// must stage this seed only for a bootstrapped parent (or
    /// first extend the restore contract); capturing does not
    /// record that bit. Fake state is copied exactly by
    /// `capture` and is not initialized or altered here. The
    /// result uses the unchanged LRx1 wire format; fork and
    /// exec do not get separate state encodings.
    #[allow(dead_code)] // Fork wiring is the first production caller.
    pub fn capture_fork_seed(
        st: &ProcState,
        files: FilesId,
        cfg: &LiterootConfig,
        current_exe: &Path,
        current_argv: &[Vec<u8>],
    ) -> Self {
        let mut seed = Self::capture(st, files, cfg);
        seed.exe_guest = current_exe.as_os_str().as_bytes().to_vec();
        seed.argv = current_argv.to_vec();
        // A fork child's record is a new group's (its first thread's
        // start), never its parent's.
        seed.record = LifetimeRecord::default();
        seed
    }

    /// Apply this snapshot to a fresh `ProcState`. Validates
    /// before mutating: on error `st` is unchanged and the caller
    /// must fail admission by name rather than fall back to
    /// launch-config seeding. Forces `bootstrapped = true`;
    /// leaves the scratch-page fields (`getcwd_scratch` too) and the
    /// per-dispatch memos untouched (callers start from a default state
    /// where they are empty).
    pub fn apply_to(&self, st: &mut ProcState, cfg: &RootConfig) -> Result<(), ExecStateError> {
        // Validate everything before mutating: a failed restore is
        // a fatal admission error, never a partial apply.
        self.validate_guest_paths()?;
        let root_override = match &self.root_override {
            None => None,
            Some(host) => {
                let host_path = path_from_bytes(host);
                // The override must reverse-map under the launch
                // config; never trust an arbitrary host directory.
                // `cfg` must be the launch config
                // (`guest.config().to_root_config()`), not a config
                // already folded with a previous override.
                if cfg.reverse(&host_path).is_none() {
                    return Err(ExecStateError::UnmappableRootOverride);
                }
                Some(host_path)
            }
        };
        st.cwd = path_from_bytes(&self.cwd);
        st.root_override = root_override;
        let mut table = FdTable {
            fds: self
                .fds
                .iter()
                .map(|(fd, p)| (*fd, path_from_bytes(p)))
                .collect(),
            ..Default::default()
        };
        st.fake = self.fake;
        st.exe_guest = path_from_bytes(&self.exe_guest);
        st.exe_host = self.exe_host;
        st.argv = self.argv.clone();
        // One stream per number with listing state, holding all of it,
        // the directory identity included (R8).
        let mut streams: std::collections::BTreeMap<i32, DirStream> = Default::default();
        for (fd, p, emitted) in &self.virtual_fds {
            table.virtual_fds.insert(*fd, path_from_bytes(p));
            streams.entry(*fd).or_default().emitted = *emitted;
        }
        for (fd, b) in &self.dirent_pending {
            streams.entry(*fd).or_default().pending = Some(b.clone());
        }
        for (fd, names) in &self.dirent_seen {
            streams.entry(*fd).or_default().seen = Some(
                names
                    .iter()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .collect::<HashSet<String>>(),
            );
        }
        for (fd, dev, ino) in &self.dirent_obj {
            streams.entry(*fd).or_default().obj = Some((*dev, *ino));
        }
        st.streams = HashMap::new();
        st.next_stream = 0;
        for (fd, stream) in streams {
            st.next_stream += 1;
            table.streams.insert(fd, st.next_stream);
            st.streams.insert(st.next_stream, stream);
        }
        // One table: the snapshot is the capturing task's, and the
        // restored process starts single-threaded on it.
        st.tables = HashMap::from([(MAIN_FILES, table)]);
        st.next_files = MAIN_FILES;
        st.bootstrapped = true;
        st.initial_stack_limit_consumed = true;
        Ok(())
    }

    fn validate_guest_paths(&self) -> Result<(), ExecStateError> {
        fn absolute(p: &[u8]) -> Result<(), ExecStateError> {
            if p.first() == Some(&b'/') {
                Ok(())
            } else {
                Err(ExecStateError::RelativePath)
            }
        }
        fn fd_ok(fd: i32) -> Result<(), ExecStateError> {
            if fd < 0 {
                Err(ExecStateError::NegativeFd)
            } else {
                Ok(())
            }
        }
        absolute(&self.cwd)?;
        absolute(&self.exe_guest)?;
        if let Some(root) = &self.root_override {
            absolute(root)?;
        }
        for (fd, p) in &self.fds {
            fd_ok(*fd)?;
            absolute(p)?;
        }
        for (fd, p, _) in &self.virtual_fds {
            fd_ok(*fd)?;
            absolute(p)?;
        }
        for (fd, _) in &self.dirent_pending {
            fd_ok(*fd)?;
        }
        for (fd, _) in &self.dirent_seen {
            fd_ok(*fd)?;
        }
        for (fd, _, _) in &self.dirent_obj {
            fd_ok(*fd)?;
        }
        Ok(())
    }

    fn canonical(&self) -> ExecState {
        let mut s = self.clone();
        s.fds.sort();
        s.virtual_fds.sort();
        s.dirent_pending.sort();
        s.dirent_seen.sort();
        for (_, names) in &mut s.dirent_seen {
            names.sort();
            names.dedup();
        }
        s.dirent_obj.sort();
        s
    }

    /// Canonical encoding: deterministic for equal snapshots.
    /// Input order never leaks into the bytes (see the
    /// order-independence test, which is the mutation arm for
    /// dropped sorting).
    pub fn encode(&self) -> Result<Vec<u8>, ExecStateError> {
        self.validate_guest_paths()?;
        let s = self.canonical();
        check_sorted_fds(s.fds.iter().map(|(fd, _)| *fd))?;
        check_sorted_fds(s.virtual_fds.iter().map(|(fd, _, _)| *fd))?;
        check_sorted_fds(s.dirent_pending.iter().map(|(fd, _)| *fd))?;
        check_sorted_fds(s.dirent_seen.iter().map(|(fd, _)| *fd))?;
        check_sorted_fds(s.dirent_obj.iter().map(|(fd, _, _)| *fd))?;
        let mut flags = 0u16;
        if s.fake.is_some() {
            flags |= FLAG_HAS_FAKE;
        }
        if s.root_override.is_some() {
            flags |= FLAG_HAS_ROOT_OVERRIDE;
        }
        if s.exe_host {
            flags |= FLAG_EXE_HOST;
        }
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        put_bytes(&mut out, &s.cwd);
        if let Some(root) = &s.root_override {
            put_bytes(&mut out, root);
        }
        put_count(&mut out, s.fds.len())?;
        for (fd, p) in &s.fds {
            out.extend_from_slice(&fd.to_le_bytes());
            put_bytes(&mut out, p);
        }
        if let Some(fake) = &s.fake {
            for v in fake {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        put_bytes(&mut out, &s.exe_guest);
        put_count(&mut out, s.argv.len())?;
        for a in &s.argv {
            put_bytes(&mut out, a);
        }
        put_count(&mut out, s.virtual_fds.len())?;
        for (fd, p, emitted) in &s.virtual_fds {
            out.extend_from_slice(&fd.to_le_bytes());
            put_bytes(&mut out, p);
            out.push(u8::from(*emitted));
        }
        put_count(&mut out, s.dirent_pending.len())?;
        for (fd, b) in &s.dirent_pending {
            out.extend_from_slice(&fd.to_le_bytes());
            put_bytes(&mut out, b);
        }
        put_count(&mut out, s.dirent_seen.len())?;
        for (fd, names) in &s.dirent_seen {
            out.extend_from_slice(&fd.to_le_bytes());
            put_count(&mut out, names.len())?;
            for n in names {
                put_bytes(&mut out, n);
            }
        }
        put_count(&mut out, s.dirent_obj.len())?;
        for (fd, dev, ino) in &s.dirent_obj {
            out.extend_from_slice(&fd.to_le_bytes());
            out.extend_from_slice(&dev.to_le_bytes());
            out.extend_from_slice(&ino.to_le_bytes());
        }
        let record = &s.record;
        out.push(u8::from(record.guest_filter));
        out.push(match record.flag {
            crate::dead_base::FlagState::None => 0,
            crate::dead_base::FlagState::Installed => 1,
            crate::dead_base::FlagState::Inherited => 2,
        });
        for v in record.counters() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.push(u8::from(record.summary_emitted));
        if out.len() > MAX_ENCODED_BYTES {
            return Err(ExecStateError::TooLarge);
        }
        Ok(out)
    }

    /// Decode with every length/count checked against the
    /// remaining input before allocation; trailing bytes refuse.
    /// B4-1 ships this behind unit tests; the successor transports
    /// (B4 step 5) are its first production callers.
    #[allow(dead_code)]
    pub fn decode(bytes: &[u8]) -> Result<Self, ExecStateError> {
        if bytes.len() > MAX_ENCODED_BYTES {
            return Err(ExecStateError::TooLarge);
        }
        let mut r = Reader { buf: bytes, pos: 0 };
        if r.take(4)? != MAGIC.as_slice() {
            return Err(ExecStateError::BadMagic);
        }
        let version = r.u16()?;
        if version != VERSION {
            return Err(ExecStateError::UnsupportedVersion(version));
        }
        let flags = r.u16()?;
        if flags & !(FLAG_HAS_FAKE | FLAG_HAS_ROOT_OVERRIDE | FLAG_EXE_HOST) != 0 {
            return Err(ExecStateError::Malformed);
        }
        let cwd = r.bytes()?.to_vec();
        let root_override = if flags & FLAG_HAS_ROOT_OVERRIDE != 0 {
            Some(r.bytes()?.to_vec())
        } else {
            None
        };
        let fds = r.fd_paths()?;
        let fake = if flags & FLAG_HAS_FAKE != 0 {
            let mut f = [0u32; 6];
            for v in &mut f {
                *v = r.u32()?;
            }
            Some(f)
        } else {
            None
        };
        let exe_guest = r.bytes()?.to_vec();
        let exe_host = flags & FLAG_EXE_HOST != 0;
        let argv = r.byte_list()?;
        let n_virtual = r.count()?;
        let mut virtual_fds = Vec::new();
        let mut prev: Option<i32> = None;
        for _ in 0..n_virtual {
            let fd = r.fd(&mut prev)?;
            let p = r.bytes()?.to_vec();
            let emitted = match r.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(ExecStateError::Malformed),
            };
            virtual_fds.push((fd, p, emitted));
        }
        let dirent_pending = r.fd_paths()?;
        let n_seen = r.count()?;
        let mut dirent_seen = Vec::new();
        let mut prev: Option<i32> = None;
        for _ in 0..n_seen {
            let fd = r.fd(&mut prev)?;
            let names = r.byte_list()?;
            if names.windows(2).any(|w| w[0] >= w[1]) {
                return Err(ExecStateError::Malformed);
            }
            dirent_seen.push((fd, names));
        }
        let n_obj = r.count()?;
        let mut dirent_obj = Vec::new();
        let mut prev: Option<i32> = None;
        for _ in 0..n_obj {
            let fd = r.fd(&mut prev)?;
            let dev = r.u64()?;
            let ino = r.u64()?;
            dirent_obj.push((fd, dev, ino));
        }
        let flag_byte = |b: u8| match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ExecStateError::Malformed),
        };
        let guest_filter = flag_byte(r.take(1)?[0])?;
        let flag = match r.take(1)?[0] {
            0 => crate::dead_base::FlagState::None,
            1 => crate::dead_base::FlagState::Installed,
            2 => crate::dead_base::FlagState::Inherited,
            _ => return Err(ExecStateError::Malformed),
        };
        let mut counters = [0u64; 8];
        for v in &mut counters {
            *v = r.u64()?;
        }
        let summary_emitted = flag_byte(r.take(1)?[0])?;
        let [installs, installs_refused, translated, refused, unseen_best_effort, probes, sud_refused, sud_fallback] =
            counters;
        let record = LifetimeRecord {
            guest_filter,
            flag,
            installs,
            installs_refused,
            translated,
            refused,
            unseen_best_effort,
            probes,
            sud_refused,
            sud_fallback,
            summary_emitted,
        };
        if r.pos != bytes.len() {
            return Err(ExecStateError::TrailingBytes);
        }
        let state = ExecState {
            cwd,
            root_override,
            fds,
            fake,
            exe_guest,
            exe_host,
            argv,
            virtual_fds,
            dirent_pending,
            dirent_seen,
            dirent_obj,
            record,
        };
        state.validate_guest_paths()?;
        Ok(state)
    }
}

fn path_from_bytes(b: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(b.to_vec()))
}

fn check_sorted_fds(fds: impl Iterator<Item = i32>) -> Result<(), ExecStateError> {
    let mut prev: Option<i32> = None;
    for fd in fds {
        if let Some(p) = prev {
            if fd <= p {
                return Err(ExecStateError::UnsortedOrDuplicateFd);
            }
        }
        prev = Some(fd);
    }
    Ok(())
}

fn put_count(out: &mut Vec<u8>, n: usize) -> Result<(), ExecStateError> {
    let n = u32::try_from(n).map_err(|_| ExecStateError::TooLarge)?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    // Lengths above u32::MAX cannot occur under the total cap;
    // encode() checks the assembled size before returning.
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

#[allow(dead_code)] // used by `decode` (see its note)
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ExecStateError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or(ExecStateError::Truncated)?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, ExecStateError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ExecStateError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ExecStateError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i32(&mut self) -> Result<i32, ExecStateError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<&'a [u8], ExecStateError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A count is only ever trusted after bounding it by the
    /// remaining input (every entry costs at least one byte), so
    /// a hostile count cannot force a huge allocation.
    fn count(&mut self) -> Result<usize, ExecStateError> {
        let n = self.u32()? as usize;
        if n > self.buf.len() - self.pos {
            return Err(ExecStateError::Truncated);
        }
        Ok(n)
    }

    fn fd(&mut self, prev: &mut Option<i32>) -> Result<i32, ExecStateError> {
        let fd = self.i32()?;
        if fd < 0 {
            return Err(ExecStateError::NegativeFd);
        }
        if let Some(p) = *prev {
            if fd <= p {
                return Err(ExecStateError::UnsortedOrDuplicateFd);
            }
        }
        *prev = Some(fd);
        Ok(fd)
    }

    fn fd_paths(&mut self) -> Result<Vec<(i32, Vec<u8>)>, ExecStateError> {
        let n = self.count()?;
        let mut out = Vec::new();
        let mut prev = None;
        for _ in 0..n {
            let fd = self.fd(&mut prev)?;
            out.push((fd, self.bytes()?.to_vec()));
        }
        Ok(out)
    }

    fn byte_list(&mut self) -> Result<Vec<Vec<u8>>, ExecStateError> {
        let n = self.count()?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(self.bytes()?.to_vec());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translate::RootConfig;
    use std::collections::HashMap;

    fn full_state() -> ExecState {
        ExecState {
            cwd: b"/work/dir".to_vec(),
            root_override: Some(b"/host/root".to_vec()),
            fds: vec![
                (3, b"/etc".to_vec()),
                (7, b"/tmp/nonutf8-\xff".to_vec()),
                (9, b"/".to_vec()),
            ],
            fake: Some([1000, 0, 0, 100, 0, 100]),
            exe_guest: b"/bin/sh".to_vec(),
            exe_host: false,
            argv: vec![b"sh".to_vec(), b"-c".to_vec(), b"echo hi".to_vec()],
            virtual_fds: vec![(4, b"/virt".to_vec(), true), (8, b"/v2".to_vec(), false)],
            dirent_pending: vec![(4, vec![1, 2, 3, 0, 255])],
            dirent_seen: vec![(4, vec![b"alpha".to_vec(), b"beta".to_vec()]), (9, vec![])],
            dirent_obj: vec![(4, 0x801, u64::MAX), (9, 0, 0)],
            record: LifetimeRecord {
                guest_filter: true,
                flag: crate::dead_base::FlagState::Inherited,
                installs: 11,
                installs_refused: 12,
                translated: 13,
                refused: 14,
                unseen_best_effort: 15,
                probes: 16,
                sud_refused: 17,
                sud_fallback: 18,
                summary_emitted: false,
            },
        }
    }

    fn minimal_state() -> ExecState {
        ExecState {
            cwd: b"/".to_vec(),
            exe_guest: b"/init".to_vec(),
            ..Default::default()
        }
    }

    fn proc_state() -> ProcState {
        ProcState {
            cwd: PathBuf::from("/work/dir"),
            tables: HashMap::new(),
            next_files: MAIN_FILES,
            streams: HashMap::new(),
            next_stream: 0,
            bootstrapped: true,
            root_override: None,
            scratch_image: 3,
            free_scratch: vec![0x1000],
            getcwd_scratch: Some(0x2000),
            exe_guest: PathBuf::from("/bin/sh"),
            exe_host: false,
            argv: vec![b"sh".to_vec()],
            fake: None,
            fake_fs: None,
            dispatch_seq: 7,
            translate_memo: Vec::new(),
            searched_bases: Vec::new(),
            gate_closed_at: None,
            admission: Default::default(),
            config_memo: None,
            pending_stack_limit: None,
            initial_stack_limit_consumed: false,
            kill_registered: false,
        }
    }

    fn cfg(cwd: &str) -> LiterootConfig {
        LiterootConfig {
            cwd: cwd.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_full() {
        let s = full_state();
        let bytes = s.encode().expect("encode full");
        assert_eq!(&bytes[0..4], MAGIC);
        assert_eq!(ExecState::decode(&bytes).expect("decode full"), s);
    }

    /// The exe-host flag survives exec: set,
    /// it is encoded as its bit and read back; clear, the bytes are those
    /// of a record from before it; capture and apply carry it.
    #[test]
    fn exe_host_flag_round_trips() {
        let mut s = minimal_state();
        let plain = s.encode().expect("encode plain");
        s.exe_host = true;
        let flagged = s.encode().expect("encode flagged");
        assert_eq!(u16::from_le_bytes([plain[6], plain[7]]) & FLAG_EXE_HOST, 0);
        assert_eq!(u16::from_le_bytes([flagged[6], flagged[7]]) & FLAG_EXE_HOST, FLAG_EXE_HOST);
        assert_eq!(plain.len(), flagged.len(), "the flag has no payload");
        assert!(ExecState::decode(&flagged).expect("decode flagged").exe_host);
        assert!(!ExecState::decode(&plain).expect("decode plain").exe_host);
        let mut st = proc_state();
        st.exe_host = true;
        let cap = ExecState::capture(&st, MAIN_FILES, &cfg("/work/dir"));
        assert!(cap.exe_host);
        let mut fresh = proc_state();
        cap.apply_to(&mut fresh, &RootConfig::new(PathBuf::from("/"), Vec::new()))
            .expect("apply");
        assert!(fresh.exe_host);
    }

    #[test]
    fn roundtrip_minimal_none_stays_none() {
        let s = minimal_state();
        assert_eq!(s.fake, None);
        assert_eq!(s.root_override, None);
        let bytes = s.encode().expect("encode minimal");
        let back = ExecState::decode(&bytes).expect("decode minimal");
        assert_eq!(back, s);
        assert_eq!(back.fake, None, "None fake must not become Some(default)");
    }

    #[test]
    fn deterministic_reencode() {
        let s = full_state();
        let a = s.encode().expect("encode a");
        let b = s.encode().expect("encode b");
        assert_eq!(a, b);
        let back = ExecState::decode(&a).expect("decode");
        assert_eq!(back.encode().expect("re-encode"), a);
    }

    /// Mutation arm: encoding must canonicalize order. If encode
    /// (or capture) ever drops its sorting, the two differently
    /// ordered states below encode differently and this fails.
    #[test]
    fn encode_order_independent() {
        let mut a = full_state();
        let b = full_state();
        a.fds.reverse();
        a.virtual_fds.reverse();
        a.dirent_pending.reverse();
        a.dirent_seen.reverse();
        for (_, names) in &mut a.dirent_seen {
            names.reverse();
        }
        a.dirent_obj.reverse();
        assert_ne!(a.fds, b.fds, "test setup: orders must differ");
        assert_eq!(
            a.encode().expect("encode shuffled"),
            b.encode().expect("encode sorted"),
            "canonical encoding must hide input order"
        );
        // Same requirement through capture(): HashMap iteration
        // order must never leak into the bytes.
        let mut p1 = proc_state();
        p1.fdt_mut(MAIN_FILES).fds.insert(9, PathBuf::from("/nine"));
        p1.fdt_mut(MAIN_FILES)
            .fds
            .insert(3, PathBuf::from("/three"));
        p1.fdt_mut(MAIN_FILES)
            .fds
            .insert(7, PathBuf::from("/seven"));
        let mut p2 = proc_state();
        p2.fdt_mut(MAIN_FILES)
            .fds
            .insert(7, PathBuf::from("/seven"));
        p2.fdt_mut(MAIN_FILES).fds.insert(9, PathBuf::from("/nine"));
        p2.fdt_mut(MAIN_FILES)
            .fds
            .insert(3, PathBuf::from("/three"));
        let c = cfg("/work/dir");
        assert_eq!(
            ExecState::capture(&p1, MAIN_FILES, &c)
                .encode()
                .expect("encode cap1"),
            ExecState::capture(&p2, MAIN_FILES, &c)
                .encode()
                .expect("encode cap2"),
        );
    }

    #[test]
    fn reject_bad_magic_and_version() {
        let mut bytes = minimal_state().encode().expect("encode");
        bytes[0] = b'X';
        assert_eq!(ExecState::decode(&bytes), Err(ExecStateError::BadMagic));
        // Version 1 (no directory identities), version 2 (no S.3 record)
        // and anything newer refuse.
        for v in [1u8, 2, 4] {
            let mut bytes = minimal_state().encode().expect("encode");
            bytes[4] = v;
            bytes[5] = 0;
            assert_eq!(
                ExecState::decode(&bytes),
                Err(ExecStateError::UnsupportedVersion(v.into()))
            );
        }
    }

    #[test]
    fn reject_truncated_and_trailing() {
        let bytes = full_state().encode().expect("encode");
        for cut in [0, 3, 7, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(
                ExecState::decode(&bytes[..cut]),
                Err(ExecStateError::Truncated),
                "cut at {cut} must refuse as truncated"
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(ExecState::decode(&long), Err(ExecStateError::TrailingBytes));
    }

    /// Hand-built minimal wire (header, cwd, given fds, rest
    /// empty) so decode-side order enforcement is exercised
    /// without going through the canonicalizing encoder.
    fn wire_with_fds(fds: &[(i32, &[u8])]) -> Vec<u8> {
        fn put(out: &mut Vec<u8>, b: &[u8]) {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // no fake, no root
        put(&mut out, b"/");
        out.extend_from_slice(&(fds.len() as u32).to_le_bytes());
        for (fd, p) in fds {
            out.extend_from_slice(&fd.to_le_bytes());
            put(&mut out, p);
        }
        put(&mut out, b"/init");
        // Empty argv, virtual_fds, dirent_pending, dirent_seen, dirent_obj.
        for _ in 0..5 {
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        // The default record: flags 0, eight zero counters, not emitted.
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&[0; 64]);
        out.push(0);
        out
    }

    /// Exec keeps both summaries' lifetime counters and the flag, every
    /// field with its own value; a malformed flag byte refuses.
    #[test]
    fn exec_state_v3_round_trip_keeps_both_summaries_lifetime_counts() {
        for flag in crate::dead_base::FLAG_STATES {
            let mut s = minimal_state();
            s.record = LifetimeRecord {
                guest_filter: flag != crate::dead_base::FlagState::None,
                flag,
                installs: 1,
                installs_refused: 2,
                translated: 3,
                refused: 4,
                unseen_best_effort: 5,
                probes: 6,
                sud_refused: 7,
                sud_fallback: u64::MAX,
                summary_emitted: true,
            };
            let bytes = s.encode().expect("encode");
            assert_eq!(ExecState::decode(&bytes).expect("decode"), s);
            let a = s.record.admission();
            assert_eq!(LifetimeRecord::of(&a), s.record);
            assert!(a.in_flight.is_empty() && a.install_pending == 0 && a.kernel_id.is_none());
        }
        let mut bytes = minimal_state().encode().expect("encode");
        let flag_at = bytes.len() - 1 - 64 - 1;
        bytes[flag_at] = 3;
        assert_eq!(ExecState::decode(&bytes), Err(ExecStateError::Malformed));
    }

    /// An install pending at exec flags the record conservatively.
    #[test]
    fn exec_record_flags_a_pending_install() {
        let mut a = crate::dead_base::Admission::default();
        let _t = a.begin_install().unwrap();
        let r = LifetimeRecord::of(&a);
        assert!(r.guest_filter && r.flag == crate::dead_base::FlagState::Installed);
        assert_eq!(r.installs, 1);
    }

    /// A fork seed carries no record: the child starts a new group.
    /// R3.4: a fork child's restore (consume_pending's `apply_to`) never
    /// applies an exec state's record, even one that carries counters: the
    /// child's record is a new group's, set at its first thread's start.
    /// Only the successor constructor (`RootfsTool::from_exec_state`)
    /// applies it.
    #[test]
    fn fork_restore_does_not_apply_the_record() {
        let mut st = proc_state();
        let state = ExecState {
            cwd: b"/work".to_vec(),
            exe_guest: b"/bin/sh".to_vec(),
            record: LifetimeRecord {
                guest_filter: true,
                flag: crate::dead_base::FlagState::Installed,
                installs: 4,
                probes: 9,
                summary_emitted: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let root = crate::translate::RootConfig::new(PathBuf::from("/"), Vec::new());
        state.apply_to(&mut st, &root).unwrap();
        assert_eq!(st.cwd, PathBuf::from("/work"), "the restore ran");
        assert_eq!(LifetimeRecord::of(&st.admission), LifetimeRecord::default());
        assert!(!st.admission.guest_filter && !st.admission.summary_emitted);
    }

    #[test]
    fn fork_seed_carries_no_record() {
        let mut st = proc_state();
        st.admission.installs = 3;
        st.admission.guest_filter = true;
        let seed = ExecState::capture_fork_seed(&st, MAIN_FILES, &cfg("/"), Path::new("/bin/sh"), &[]);
        assert_eq!(seed.record, LifetimeRecord::default());
        let exec = ExecState::capture(&st, MAIN_FILES, &cfg("/"));
        assert_eq!(exec.record.installs, 3);
    }

    #[test]
    fn decode_rejects_unsorted_and_duplicate_fds() {
        let desc = wire_with_fds(&[(9, b"/nine"), (3, b"/three")]);
        assert_eq!(
            ExecState::decode(&desc),
            Err(ExecStateError::UnsortedOrDuplicateFd)
        );
        let dup = wire_with_fds(&[(3, b"/a"), (3, b"/b")]);
        assert_eq!(
            ExecState::decode(&dup),
            Err(ExecStateError::UnsortedOrDuplicateFd)
        );
        let ok = wire_with_fds(&[(3, b"/a"), (9, b"/b")]);
        assert!(ExecState::decode(&ok).is_ok());
    }

    #[test]
    fn reject_unsorted_duplicate_negative_relative() {
        let mut neg = minimal_state();
        neg.fds = vec![(-1, b"/x".to_vec())];
        assert_eq!(neg.encode(), Err(ExecStateError::NegativeFd));
        let mut rel = minimal_state();
        rel.cwd = b"relative/dir".to_vec();
        assert_eq!(rel.encode(), Err(ExecStateError::RelativePath));
        let mut rel_exe = minimal_state();
        rel_exe.exe_guest = b"bin/sh".to_vec();
        assert_eq!(rel_exe.encode(), Err(ExecStateError::RelativePath));
    }

    #[test]
    fn encode_refuses_over_cap() {
        let mut s = minimal_state();
        s.cwd = vec![b'x'; MAX_ENCODED_BYTES];
        s.cwd[0] = b'/';
        assert_eq!(s.encode(), Err(ExecStateError::TooLarge));
        // Decode of an over-cap buffer refuses before parsing.
        let big = vec![0u8; MAX_ENCODED_BYTES + 1];
        assert_eq!(ExecState::decode(&big), Err(ExecStateError::TooLarge));
    }

    #[test]
    fn capture_materializes_sentinel_cwd() {
        let mut st = proc_state();
        st.cwd = PathBuf::from("/__literoot_unset__");
        let s = ExecState::capture(&st, MAIN_FILES, &cfg("/from/config"));
        assert_eq!(s.cwd, b"/from/config");
        let s = ExecState::capture(&st, MAIN_FILES, &cfg(""));
        assert_eq!(s.cwd, b"/");
        // A real cwd is never replaced by config.
        st.cwd = PathBuf::from("/real");
        let s = ExecState::capture(&st, MAIN_FILES, &cfg("/from/config"));
        assert_eq!(s.cwd, b"/real");
    }

    #[test]
    fn capture_materializes_unseeded_exe_guest() {
        // Regression: a fork before any exec/exe_guest() call
        // holds the empty default; capture must seed it from
        // config (absolutized) instead of encoding an
        // empty/relative path that encode() would refuse.
        let mut st = proc_state();
        st.exe_guest = PathBuf::new();
        let mut c = cfg("/work/dir");
        c.initial_exe = "/bin/sh".to_string();
        let s = ExecState::capture(&st, MAIN_FILES, &c);
        assert_eq!(s.exe_guest, b"/bin/sh");
        assert!(s.encode().is_ok());
        c.initial_exe = "bin/sh".to_string();
        let s = ExecState::capture(&st, MAIN_FILES, &c);
        assert_eq!(s.exe_guest, b"/work/dir/bin/sh");
        assert!(s.encode().is_ok());
        // A materialized exe_guest is never replaced by config.
        st.exe_guest = PathBuf::from("/bin/bash");
        let s = ExecState::capture(&st, MAIN_FILES, &c);
        assert_eq!(s.exe_guest, b"/bin/bash");
    }

    #[test]
    fn fork_seed_records_accessor_values_for_unseeded_state() {
        let mut st = proc_state();
        st.exe_guest = PathBuf::new();
        st.argv.clear();
        let mut c = cfg("/work/dir");
        c.initial_exe = "/bin/sh".to_string();
        c.initial_argv = vec!["sh".to_string(), "-i".to_string()];
        // These are the values RootfsTool's current-image
        // accessors return for this state; the seed records
        // them rather than deriving a second materialization.
        let current_argv = vec![b"sh".to_vec(), b"-i".to_vec()];
        let seed =
            ExecState::capture_fork_seed(&st, MAIN_FILES, &c, Path::new("/bin/sh"), &current_argv);
        assert_eq!(seed.exe_guest, b"/bin/sh");
        assert_eq!(seed.argv, current_argv);
        assert!(seed.encode().is_ok());
    }

    #[test]
    fn fork_seed_does_not_re_resolve_accessor_exe_against_current_cwd() {
        let mut st = proc_state();
        st.cwd = PathBuf::from("/current/elsewhere");
        st.exe_guest = PathBuf::new();
        st.argv.clear();
        let fake_before = st.fake;
        let current_argv = vec![b"prog".to_vec()];
        let mut c = cfg("/work/dir");
        c.initial_argv = vec!["prog".to_string()];

        // Each supplied exe is the output RootfsTool::exe_guest
        // produces for the adjacent initial_exe spelling. The
        // seed must preserve it byte-for-byte instead of joining
        // the spelling onto st.cwd (the pre-fix behavior).
        c.initial_exe = "./prog".to_string();
        let seed = ExecState::capture_fork_seed(
            &st,
            MAIN_FILES,
            &c,
            Path::new("/work/dir/prog"),
            &current_argv,
        );
        assert_eq!(seed.exe_guest, b"/work/dir/prog");

        c.initial_exe = "../x/prog".to_string();
        let seed = ExecState::capture_fork_seed(
            &st,
            MAIN_FILES,
            &c,
            Path::new("/work/x/prog"),
            &current_argv,
        );
        assert_eq!(seed.exe_guest, b"/work/x/prog");

        c.initial_exe = String::new();
        let seed = ExecState::capture_fork_seed(
            &st,
            MAIN_FILES,
            &c,
            Path::new("/proc/self/exe"),
            &current_argv,
        );
        assert_eq!(seed.exe_guest, b"/proc/self/exe");
        assert_eq!(seed.fake, fake_before);

        c.cwd = String::new();
        c.initial_exe = "./prog".to_string();
        let seed =
            ExecState::capture_fork_seed(&st, MAIN_FILES, &c, Path::new("/prog"), &current_argv);
        assert_eq!(seed.exe_guest, b"/prog");
        assert_eq!(seed.fake, fake_before);
    }

    #[test]
    fn fork_seed_preserves_materialized_current_image() {
        let mut st = proc_state();
        st.exe_guest = PathBuf::from("/bin/bash");
        st.argv = vec![b"bash".to_vec()];
        let fake_before = st.fake;
        let mut c = cfg("/work/dir");
        c.initial_exe = "/bin/sh".to_string();
        c.initial_argv = vec!["sh".to_string()];
        let current_argv = vec![b"bash".to_vec()];
        let seed = ExecState::capture_fork_seed(
            &st,
            MAIN_FILES,
            &c,
            Path::new("/bin/bash"),
            &current_argv,
        );
        assert_eq!(seed.exe_guest, b"/bin/bash");
        assert_eq!(seed.argv, current_argv);
        assert_eq!(seed.fake, fake_before);
    }

    #[test]
    fn fork_seed_prefers_current_argv_over_state_and_initial_argv() {
        let mut st = proc_state();
        st.fake = Some([9, 8, 7, 6, 5, 4]);
        st.argv = vec![b"state-argv".to_vec()];
        let mut c = cfg("/work/dir");
        c.initial_exe = "./prog".to_string();
        c.initial_argv = vec!["initial-argv".to_string()];
        let current_argv = vec![b"current-argv".to_vec(), b"-x".to_vec()];
        let seed = ExecState::capture_fork_seed(
            &st,
            MAIN_FILES,
            &c,
            Path::new("/work/dir/prog"),
            &current_argv,
        );
        assert_eq!(seed.argv, current_argv);
        assert_eq!(seed.fake, Some([9, 8, 7, 6, 5, 4]));
    }

    #[test]
    fn capture_never_initializes_fake() {
        let mut st = proc_state();
        st.fake = None;
        assert_eq!(ExecState::capture(&st, MAIN_FILES, &cfg("/")).fake, None);
        st.fake = Some([1, 2, 3, 4, 5, 6]);
        assert_eq!(
            ExecState::capture(&st, MAIN_FILES, &cfg("/")).fake,
            Some([1, 2, 3, 4, 5, 6]),
            "capture copies fake exactly; handle_post_exec transitions it"
        );
        // Scratch/dispatch memos never cross: capture output has no
        // place to put them (struct equality covers the rest).
        let s = ExecState::capture(&st, MAIN_FILES, &cfg("/"));
        assert_eq!(s.exe_guest, b"/bin/sh");
        assert_eq!(s.argv, vec![b"sh".to_vec()]);
    }

    #[test]
    fn apply_restores_and_forces_bootstrapped() {
        let root = RootConfig::new(PathBuf::from("/"), Vec::new());
        let src = full_state();
        let mut st = proc_state();
        st.bootstrapped = false;
        st.cwd = PathBuf::from("/__literoot_unset__");
        let mut want = src.clone();
        want.root_override = Some(b"/".to_vec());
        want.apply_to(&mut st, &root).expect("apply");
        assert!(st.bootstrapped, "restored state is never the initial image");
        assert_eq!(st.cwd.as_os_str().as_bytes(), want.cwd.as_slice());
        assert_eq!(
            st.root_override.as_ref().map(|p| p.as_os_str().as_bytes()),
            Some(b"/".as_slice())
        );
        assert_eq!(st.fake, want.fake);
        assert_eq!(
            st.exe_guest.as_os_str().as_bytes(),
            want.exe_guest.as_slice()
        );
        assert_eq!(st.argv, want.argv);
        let t = st.fdt(MAIN_FILES);
        assert_eq!(t.fds.len(), 3);
        assert_eq!(
            t.fds.get(&7).map(|p| p.as_os_str().as_bytes()),
            Some(b"/tmp/nonutf8-\xff".as_slice())
        );
        assert_eq!(t.virtual_fds.len(), 2);
        let s4 = st.stream(MAIN_FILES, 4).expect("fd 4 has listing state");
        assert!(s4.emitted);
        assert_eq!(s4.pending, Some(vec![1, 2, 3, 0, 255]));
        assert_eq!(
            s4.seen.as_ref().map(|s| s.len()),
            Some(2),
            "dirent names restore as a set"
        );
        // R8: the identity a listing was built for restores with it.
        assert_eq!(s4.obj, Some((0x801, u64::MAX)));
        assert_eq!(st.stream(MAIN_FILES, 9).and_then(|s| s.obj), Some((0, 0)));
        assert_eq!(st.stream(MAIN_FILES, 8).map(|s| s.emitted), Some(false));
        assert_eq!(st.streams.len(), 3, "one stream per fd with listing state");
    }

    /// R8: every part of a number's listing state survives capture and
    /// apply together, its directory identity included; numbers keep
    /// separate streams in the successor.
    #[test]
    fn listing_state_and_its_identity_survive_capture_and_apply() {
        let mut st = proc_state();
        st.fdt_mut(MAIN_FILES).fds.insert(3, PathBuf::from("/a"));
        {
            let s = st.stream_mut(MAIN_FILES, 3);
            s.pending = Some(vec![9, 9]);
            s.seen = Some(HashSet::from(["x".to_string()]));
            s.obj = Some((5, 6));
        }
        st.stream_mut(MAIN_FILES, 4).obj = Some((7, 8));
        let snap = ExecState::capture(&st, MAIN_FILES, &cfg("/"));
        assert_eq!(snap.dirent_obj, vec![(3, 5, 6), (4, 7, 8)]);
        let decoded = ExecState::decode(&snap.encode().expect("encode")).expect("decode");
        assert_eq!(decoded, snap);
        let mut restored = proc_state();
        decoded
            .apply_to(&mut restored, &RootConfig::new("/".into(), Vec::new()))
            .expect("apply");
        assert_eq!(restored.stream(MAIN_FILES, 3), st.stream(MAIN_FILES, 3));
        assert_eq!(restored.stream(MAIN_FILES, 4), st.stream(MAIN_FILES, 4));
        assert_ne!(
            restored.fdt(MAIN_FILES).streams.get(&3),
            restored.fdt(MAIN_FILES).streams.get(&4)
        );
    }

    /// capture reads the named fd table only; apply_to leaves exactly one
    /// table, MAIN_FILES, holding it.
    #[test]
    fn capture_takes_one_table_and_apply_leaves_only_main() {
        let mut st = proc_state();
        st.fdt_mut(MAIN_FILES).fds.insert(3, PathBuf::from("/main"));
        let other = st.split_files(MAIN_FILES, |_| None);
        st.fdt_mut(other).fds.insert(3, PathBuf::from("/other"));
        st.fdt_mut(other).fds.insert(5, PathBuf::from("/five"));
        let c = cfg("/");
        let snap = ExecState::capture(&st, other, &c);
        assert_eq!(
            snap.fds,
            vec![(3, b"/other".to_vec()), (5, b"/five".to_vec())]
        );
        let mut restored = proc_state();
        restored.split_files(MAIN_FILES, |_| None);
        snap.apply_to(&mut restored, &RootConfig::new("/".into(), Vec::new()))
            .expect("apply");
        assert_eq!(restored.tables.len(), 1);
        assert_eq!(restored.next_files, MAIN_FILES);
        assert_eq!(
            restored.fdt(MAIN_FILES).fds.get(&5),
            Some(&PathBuf::from("/five"))
        );
    }

    #[test]
    fn apply_rejects_unmappable_root_override_without_mutating() {
        let root = RootConfig::new(std::env::temp_dir(), Vec::new());
        let mut s = minimal_state();
        s.root_override = Some(b"/definitely/outside/the/rootfs".to_vec());
        let mut st = proc_state();
        let before_cwd = st.cwd.clone();
        assert_eq!(
            s.apply_to(&mut st, &root),
            Err(ExecStateError::UnmappableRootOverride)
        );
        assert_eq!(st.cwd, before_cwd, "failed apply must not mutate");
        assert_eq!(st.root_override, None);
    }
}
