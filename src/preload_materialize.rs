//! The in-guest preload, found without a second build step.
//!
//! `cargo install` builds the preload with the launcher and embeds it
//! (build.rs). At launch, [`select`] picks the preload in this order:
//!
//! 1. `LITEROOT_PRELOAD`, admitted by its compatibility stamp
//!    (`preload_stamp`): `protocol_version` and flavour must equal this
//!    launcher's record for the selected flavour. A set but missing or
//!    unreadable file refuses; it never falls through to the embedded blob.
//!    The file is never written.
//! 2. The embedded blob, materialized into a private, content-addressed
//!    cache: `<cache>/literoot/<full sha256>/libliteroot_preload.so`, where
//!    `<cache>` is `$XDG_CACHE_HOME` when set and absolute, else
//!    `$HOME/.cache`.
//! 3. Otherwise a named refusal.
//!
//! Every failure is a named refusal with a closed side-log token. None of
//! them ever substitutes ptrace.
//!
//! Cache mechanics. `literoot/` and `literoot/<sha>/` are created with
//! mode 0700, set explicitly, never derived from the umask. A pre-existing
//! one must be a directory owned by the effective uid with no group or
//! other bits and no setuid, setgid or sticky bit; the XDG root itself is
//! not checked. A cache directory qualifies only if a one-page file created
//! in it can be mapped PROT_EXEC. Under an exclusive lock (`<sha>/.lock`)
//! an entry that is missing, whose bytes do not hash to the embedded
//! digest, or whose mode is not 0500 is published again: an O_EXCL
//! temporary file, written, fsynced, set to 0500, then renamed onto the
//! final path. The final path is never opened for writing. A final path
//! that is a symlink or not a regular file refuses by name; it is never
//! followed, read or replaced. The final canonical path is then checked for
//! an LD_PRELOAD separator and mapped PROT_EXEC once; immediately before
//! that path is handed to the launcher, the final path is checked again: a
//! regular file, mode 0500, holding the embedded bytes.
//!
//! Boundary: between that last hash and the guest's ld.so opening the
//! path, a writer with the same uid could replace the file. Same-uid
//! writers are outside the threat model; the 0700 directories keep other
//! uids out. Files outside the cache, `LITEROOT_PRELOAD` above all, are
//! never written, removed or rebuilt over. Entries of other versions are
//! never deleted: children of a live older run still load them by path.

use std::ffi::OsString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::preload_stamp;

/// One embedded preload blob and the digest build.rs recorded for it.
#[derive(Clone, Copy)]
pub struct Embedded {
    pub bytes: &'static [u8],
    pub sha256: &'static str,
}

// PROTOCOL_VERSION, EMBEDDED_LITEINST and EMBEDDED_TRAPHOST, written by
// build.rs.
include!(concat!(env!("OUT_DIR"), "/embedded_preload.rs"));

/// The cached file's name.
pub const FILE_NAME: &str = "libliteroot_preload.so";

/// Which preload a launch needs. The flavour follows the actual dispatch,
/// not the backend word: on a build without `inguest-trap`, `--backend
/// trap` runs the liteinst preload with site patching off.
#[allow(dead_code)] // a build drives one flavour or both
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavour {
    Liteinst,
    TrapHost,
}

impl Flavour {
    pub fn stamp(self) -> u32 {
        match self {
            Flavour::Liteinst => preload_stamp::FLAVOUR_LITEINST,
            Flavour::TrapHost => preload_stamp::FLAVOUR_TRAPHOST,
        }
    }

    fn embedded(self) -> Option<Embedded> {
        match self {
            Flavour::Liteinst => EMBEDDED_LITEINST,
            Flavour::TrapHost => EMBEDDED_TRAPHOST,
        }
    }
}

/// A named refusal: the side-log token, the named refusal written to
/// stderr as one whole line, and an optional detail for a separate line.
#[derive(Debug)]
pub struct Refusal {
    pub token: &'static str,
    pub message: &'static str,
    pub detail: Option<String>,
}

impl Refusal {
    fn new(token: &'static str, message: &'static str, detail: impl Into<String>) -> Self {
        Refusal {
            token,
            message,
            detail: Some(detail.into()),
        }
    }

    /// The launcher's error text. The launcher prefixes `literoot: `, so
    /// the named refusal is a whole line and the detail is its own line.
    pub fn text(&self) -> String {
        match &self.detail {
            None => self.message.to_owned(),
            Some(detail) => format!("{}\nliteroot: {detail}", self.message),
        }
    }
}

// The named refusals. Tokens are in side_log's closed LAUNCHER set.
const EMBEDDED_DIGEST: (&str, &str) = ("preload_digest", "preload digest mismatch (embedded)");
const CACHE_DIR: (&str, &str) = (
    "cache_dir",
    "no writable private cache directory for the in-guest preload",
);
const CACHE_WRITE: (&str, &str) = ("cache_write", "preload cache write failed");
const CACHE_DIGEST: (&str, &str) = ("preload_digest", "preload digest mismatch");
const STAMP: (&str, &str) = ("preload_stamp", "preload stamp mismatch: rebuild the preload");
const PROBE: (&str, &str) = ("preload_probe", "preload cannot be mapped executable here");
const SEPARATOR: (&str, &str) = ("preload_separator", "preload path contains a separator");
const MISSING: (&str, &str) = ("preload_missing", "LITEROOT_PRELOAD names no readable file");
/// What a user does about a missing or unreadable LITEROOT_PRELOAD. It ends
/// the detail line, so the named refusal stays one whole line.
const MISSING_HINT: &str =
    "point LITEROOT_PRELOAD at a readable preload built with this literoot, or unset it to use the embedded one";
const NOT_BUILT: (&str, &str) = ("not_built", "in-guest not built into this binary");

fn refuse((token, message): (&'static str, &'static str), detail: impl Into<String>) -> Refusal {
    Refusal::new(token, message, detail)
}

/// The operations the unit seams replace. Production uses [`Hooks::REAL`].
pub(crate) struct Hooks {
    pub write: fn(&mut File, &[u8]) -> io::Result<()>,
    pub dir_probe_map: fn(&File, usize) -> io::Result<()>,
    pub final_map: fn(&File, usize) -> io::Result<()>,
    pub after_publish: fn(&Path),
    pub in_lock: fn(),
}

fn write_all(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)
}

fn no_after_publish(_: &Path) {}

fn no_in_lock() {}

impl Hooks {
    pub const REAL: Hooks = Hooks {
        write: write_all,
        dir_probe_map: map_exec,
        final_map: map_exec,
        after_publish: no_after_publish,
        in_lock: no_in_lock,
    };
}

/// Map `len` bytes of `file` PROT_READ|PROT_EXEC and unmap at once.
fn map_exec(file: &File, len: usize) -> io::Result<()> {
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::munmap(addr, len) };
    Ok(())
}

fn page_size() -> usize {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page > 0 { page as usize } else { 4096 }
}

/// A name component no other launch uses.
fn unique() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        nanos,
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Read at most `cap` bytes; more is an error.
fn read_capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::other(format!("larger than {cap} bytes")));
    }
    Ok(bytes)
}

/// The preload for this launch, as the canonical path to hand to the
/// launcher.
pub fn select(flavour: Flavour) -> Result<PathBuf, Refusal> {
    if let Some(user) = std::env::var_os("LITEROOT_PRELOAD") {
        return admit_user(Path::new(&user), flavour, &Hooks::REAL);
    }
    let Some(embedded) = flavour.embedded() else {
        return Err(refuse(
            NOT_BUILT,
            "this binary embeds no preload for this backend",
        ));
    };
    let candidates = cache_candidates(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"));
    materialize(embedded.bytes, embedded.sha256, &candidates, &Hooks::REAL)
}

/// The cache roots to try, in order: `$XDG_CACHE_HOME/literoot` when set,
/// non-empty and absolute (a relative value is ignored), then
/// `$HOME/.cache/literoot` when HOME is set and absolute.
pub(crate) fn cache_candidates(xdg: Option<OsString>, home: Option<OsString>) -> Vec<PathBuf> {
    let absolute = |v: Option<OsString>| {
        v.filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let mut candidates = Vec::new();
    if let Some(xdg) = absolute(xdg) {
        candidates.push(xdg.join("literoot"));
    }
    if let Some(home) = absolute(home) {
        candidates.push(home.join(".cache").join("literoot"));
    }
    candidates
}

/// Admit a user-supplied preload by its stamp. The file is read once, into
/// memory, and never written.
pub(crate) fn admit_user(path: &Path, flavour: Flavour, hooks: &Hooks) -> Result<PathBuf, Refusal> {
    let bytes = read_capped(path, preload_stamp::MAX_FILE)
        .map_err(|e| refuse(MISSING, format!("{}: {e}; {MISSING_HINT}", path.display())))?;
    let stamp = preload_stamp::parse(&bytes)
        .map_err(|why| refuse(STAMP, format!("{}: {why}", path.display())))?;
    preload_stamp::check(&stamp, PROTOCOL_VERSION, flavour.stamp())
        .map_err(|why| refuse(STAMP, format!("{}: {why}", path.display())))?;
    let canonical = path
        .canonicalize()
        .map_err(|e| refuse(MISSING, format!("{}: {e}; {MISSING_HINT}", path.display())))?;
    check_separator(&canonical)?;
    final_probe(&canonical, hooks)?;
    Ok(canonical)
}

/// ld.so splits LD_PRELOAD on these bytes.
fn check_separator(path: &Path) -> Result<(), Refusal> {
    if path
        .as_os_str()
        .as_bytes()
        .iter()
        .any(|&b| matches!(b, b' ' | b':' | b'\t' | b'\n'))
    {
        return Err(refuse(SEPARATOR, format!("{:?}", path)));
    }
    Ok(())
}

/// The final-file probe: the file itself must map PROT_EXEC.
fn final_probe(path: &Path, hooks: &Hooks) -> Result<(), Refusal> {
    let file = File::open(path).map_err(|e| refuse(PROBE, format!("{}: {e}", path.display())))?;
    (hooks.final_map)(&file, page_size())
        .map_err(|e| refuse(PROBE, format!("{}: {e}", path.display())))
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// A directory we may use: a real directory (symlinks are not followed),
/// owned by the effective uid, with no group or other bits and no setuid,
/// setgid or sticky bit.
fn validate_private(dir: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.file_type().is_dir() {
        return Err(format!("{}: not a directory", dir.display()));
    }
    if meta.uid() != euid() {
        return Err(format!(
            "{}: owned by uid {}, not the effective uid {}",
            dir.display(),
            meta.uid(),
            euid()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{}: mode {:o} has group or other bits",
            dir.display(),
            meta.mode() & 0o7777
        ));
    }
    if meta.mode() & 0o7000 != 0 {
        return Err(format!(
            "{}: mode {:o} has a setuid, setgid or sticky bit",
            dir.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Create `dir` at mode 0700 (set explicitly) or validate it when it
/// already exists. Missing ancestors are created 0700; existing ones are
/// left alone. Another launch creating it first is fine: it is validated.
fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => return validate_private(dir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    if let Some(parent) = dir.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 {}: {e}", dir.display()))?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("create {}: {e}", dir.display())),
    }
    validate_private(dir)
}

/// The directory probe: create a one-page file, ftruncate it to
/// one page, map it PROT_EXEC, unmap, unlink. Writable AND mappable.
fn probe_dir(dir: &Path, hooks: &Hooks) -> Result<(), String> {
    let page = page_size();
    let path = dir.join(format!(".probe-{}", unique()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)
        .map_err(|e| format!("{}: create probe file: {e}", dir.display()))?;
    let result = file
        .set_len(page as u64)
        .map_err(|e| format!("{}: ftruncate probe file: {e}", dir.display()))
        .and_then(|()| {
            (hooks.dir_probe_map)(&file, page)
                .map_err(|e| format!("{}: map probe file PROT_EXEC: {e}", dir.display()))
        });
    drop(file);
    let _ = std::fs::remove_file(&path);
    result
}

/// Publish `blob` at `final_path`: O_EXCL temporary, write, fsync, chmod
/// 0500, rename. The final path is never opened for writing.
fn publish(entry: &Path, final_path: &Path, blob: &[u8], hooks: &Hooks) -> Result<(), String> {
    let tmp = entry.join(format!(".tmp-{}", unique()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&tmp)
        .map_err(|e| format!("create {}: {e}", tmp.display()))?;
    let result = (|| -> Result<(), String> {
        (hooks.write)(&mut file, blob).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        file.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o500))
            .map_err(|e| format!("chmod 0500 {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, final_path)
            .map_err(|e| format!("rename onto {}: {e}", final_path.display()))
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    } else if let Ok(dir) = File::open(entry) {
        let _ = dir.sync_all();
    }
    result
}

/// Take the entry's exclusive lock. Held until the returned file drops.
fn lock_entry(entry: &Path) -> Result<File, String> {
    let path = entry.join(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(format!("lock {}: {err}", path.display()));
        }
    }
}

/// The state of an entry's final path.
#[derive(PartialEq, Eq)]
enum Entry {
    Absent,
    /// A regular file, mode 0500, holding exactly the blob's bytes.
    Matches,
    /// A regular file to publish again: other bytes, unreadable, larger
    /// than the blob, or a mode other than 0500.
    Differs,
    /// A symlink or another non-regular file: refused by name, never
    /// followed, read or replaced.
    Unusable(String),
}

fn entry_state(final_path: &Path, blob_len: usize, digest: &str) -> Entry {
    let symlink = || Entry::Unusable(format!("{}: a symlink, not a regular file", final_path.display()));
    let not_regular = || Entry::Unusable(format!("{}: not a regular file", final_path.display()));
    match std::fs::symlink_metadata(final_path) {
        Ok(meta) if meta.file_type().is_symlink() => return symlink(),
        Ok(meta) if !meta.file_type().is_file() => return not_regular(),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Entry::Absent,
        Err(_) => return Entry::Differs,
    }
    // O_NOFOLLOW and O_NONBLOCK: a symlink or FIFO swapped in after the
    // check above is neither followed nor waited on.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(final_path)
    {
        Ok(file) => file,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return symlink(),
        Err(_) => return Entry::Differs,
    };
    let Ok(meta) = file.metadata() else {
        return Entry::Differs;
    };
    if !meta.file_type().is_file() {
        return not_regular();
    }
    let mut bytes = Vec::new();
    if (&file)
        .take(blob_len as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > blob_len
        || preload_stamp::sha256_hex(&bytes) != digest
        || meta.mode() & 0o7777 != 0o500
    {
        return Entry::Differs;
    }
    Entry::Matches
}

/// Materialize the embedded `blob` (whose recorded digest is `digest`)
/// into the first qualifying cache root and return the final canonical
/// path, verified immediately before it is returned.
pub(crate) fn materialize(
    blob: &[u8],
    digest: &str,
    candidates: &[PathBuf],
    hooks: &Hooks,
) -> Result<PathBuf, Refusal> {
    let actual = preload_stamp::sha256_hex(blob);
    if actual != digest {
        return Err(refuse(
            EMBEDDED_DIGEST,
            format!("embedded bytes hash to {actual}, recorded {digest}"),
        ));
    }
    let mut why = Vec::new();
    let mut root = None;
    for candidate in candidates {
        match ensure_private_dir(candidate).and_then(|()| probe_dir(candidate, hooks)) {
            Ok(()) => {
                root = Some(candidate);
                break;
            }
            Err(e) => why.push(e),
        }
    }
    let Some(root) = root else {
        if why.is_empty() {
            why.push("XDG_CACHE_HOME is unset, empty or relative, and HOME is unset".into());
        }
        return Err(refuse(CACHE_DIR, why.join("; ")));
    };
    let entry = root.join(digest);
    match std::fs::symlink_metadata(&entry) {
        Ok(_) => validate_private(&entry).map_err(|e| refuse(CACHE_DIR, e))?,
        Err(_) => ensure_private_dir(&entry).map_err(|e| refuse(CACHE_WRITE, e))?,
    }
    let lock = lock_entry(&entry).map_err(|e| refuse(CACHE_WRITE, e))?;
    (hooks.in_lock)();
    let final_path = entry.join(FILE_NAME);
    let state = entry_state(&final_path, blob.len(), digest);
    if let Entry::Unusable(why) = &state {
        return Err(refuse(CACHE_DIR, why.clone()));
    }
    if state != Entry::Matches {
        publish(&entry, &final_path, blob, hooks).map_err(|e| refuse(CACHE_WRITE, e))?;
        (hooks.after_publish)(&final_path);
        if state == Entry::Differs {
            eprintln!("literoot: preload rematerialized");
        }
    }
    let canonical = final_path
        .canonicalize()
        .map_err(|e| refuse(CACHE_WRITE, format!("{}: {e}", final_path.display())))?;
    check_separator(&canonical)?;
    final_probe(&canonical, hooks)?;
    // Checked at hand-over, after publication, immediately before the
    // launcher gets the canonical path: the final path is still a regular
    // file (not a symlink), mode 0500, holding the embedded bytes.
    match entry_state(&final_path, blob.len(), digest) {
        Entry::Matches => {}
        Entry::Unusable(why) => return Err(refuse(CACHE_DIR, why)),
        Entry::Absent | Entry::Differs => {
            return Err(refuse(
                CACHE_DIGEST,
                format!(
                    "{} does not hold the embedded bytes (sha256 {digest}) at mode 0500 after rematerialization",
                    final_path.display()
                ),
            ));
        }
    }
    drop(lock);
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use super::*;

    /// A fresh directory under the temporary directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("literoot-materialize-{label}-{}", unique()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ok_map(_: &File, _: usize) -> io::Result<()> {
        Ok(())
    }

    /// A LITEROOT_PRELOAD that names no readable file is refused by name,
    /// as one whole line, and the detail line says what to do about it.
    #[test]
    fn missing_user_preload_is_refused_by_name_with_a_hint() {
        let scratch = Scratch::new("missing-preload");
        let path = scratch.0.join("no-such-preload.so");
        let refusal = admit_user(&path, Flavour::Liteinst, &Hooks::REAL).unwrap_err();
        assert_eq!(refusal.token, "preload_missing");
        let text = refusal.text();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("LITEROOT_PRELOAD names no readable file"), "{text}");
        let detail = lines.next().unwrap_or_default();
        assert!(detail.starts_with(&format!("literoot: {}: ", path.display())), "{detail}");
        assert!(
            detail.ends_with("point LITEROOT_PRELOAD at a readable preload built with this literoot, \
                              or unset it to use the embedded one"),
            "the detail ends with what to do: {detail}"
        );
        assert_eq!(lines.next(), None, "{text}");
    }

    fn denied_map(_: &File, _: usize) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }

    fn failing_write(_: &mut File, _: &[u8]) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }

    /// Overwrite the published file, as a fault after publication would.
    fn corrupt_after_publish(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(path, b"not the embedded bytes").unwrap();
    }

    /// The seams with the mapping probes stubbed out, so a noexec
    /// temporary directory cannot decide these tests.
    const SEAMS: Hooks = Hooks {
        write: write_all,
        dir_probe_map: ok_map,
        final_map: ok_map,
        after_publish: no_after_publish,
        in_lock: no_in_lock,
    };

    fn blob() -> Vec<u8> {
        b"literoot preload test bytes ".repeat(64)
    }

    fn assert_refusal(result: Result<PathBuf, Refusal>, token: &str, message: &str) -> Refusal {
        match result {
            Ok(path) => panic!("expected refusal {token}, got {}", path.display()),
            Err(r) => {
                assert_eq!(r.token, token, "{r:?}");
                assert_eq!(r.message, message, "{r:?}");
                r
            }
        }
    }

    #[test]
    fn materialize_publishes_a_private_entry() {
        let scratch = Scratch::new("ok");
        let root = scratch.0.join("cache").join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        let path = materialize(&bytes, &digest, &[root.clone()], &SEAMS).unwrap();
        assert_eq!(path, root.join(&digest).join(FILE_NAME).canonicalize().unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join(&digest)), 0o700);
        assert_eq!(mode(&path), 0o500);
    }

    #[test]
    fn n01_embedded_digest_refuses() {
        let scratch = Scratch::new("n01");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let other = preload_stamp::sha256_hex(b"some other blob");
        assert_refusal(
            materialize(&bytes, &other, &[root.clone()], &SEAMS),
            "preload_digest",
            "preload digest mismatch (embedded)",
        );
        assert!(!root.exists(), "nothing is created for a tampered blob");
    }

    #[test]
    fn n02_noexec_probe_refuses() {
        let scratch = Scratch::new("n02");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        let hooks = Hooks {
            dir_probe_map: denied_map,
            ..SEAMS
        };
        let r = assert_refusal(
            materialize(&bytes, &digest, &[root.clone()], &hooks),
            "cache_dir",
            "no writable private cache directory for the in-guest preload",
        );
        assert!(r.detail.unwrap().contains("PROT_EXEC"));
        assert!(!root.join(&digest).exists(), "no entry in an unqualified root");
    }

    #[test]
    fn n03_cache_write_refuses() {
        let scratch = Scratch::new("n03");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        let hooks = Hooks {
            write: failing_write,
            ..SEAMS
        };
        assert_refusal(
            materialize(&bytes, &digest, &[root.clone()], &hooks),
            "cache_write",
            "preload cache write failed",
        );
        let entry = root.join(&digest);
        assert!(!entry.join(FILE_NAME).exists(), "nothing was published");
        let left: Vec<_> = std::fs::read_dir(&entry)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![OsString::from(".lock")], "no temporary file is left");
    }

    #[test]
    fn n04_persistent_mismatch_refuses() {
        let scratch = Scratch::new("n04");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        let hooks = Hooks {
            after_publish: corrupt_after_publish,
            ..SEAMS
        };
        assert_refusal(
            materialize(&bytes, &digest, &[root], &hooks),
            "preload_digest",
            "preload digest mismatch",
        );
    }

    #[test]
    fn n06_final_probe_refuses() {
        let scratch = Scratch::new("n06");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        let hooks = Hooks {
            final_map: denied_map,
            ..SEAMS
        };
        assert_refusal(
            materialize(&bytes, &digest, &[root], &hooks),
            "preload_probe",
            "preload cannot be mapped executable here",
        );
    }

    /// A pre-existing cache directory with a setgid or a sticky bit is not
    /// private: it refuses by name and nothing is created in it.
    #[test]
    fn special_bits_dir_refuses() {
        for bits in [0o2700, 0o1700] {
            let scratch = Scratch::new("special");
            let root = scratch.0.join("literoot");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(bits)).unwrap();
            let mode = std::fs::symlink_metadata(&root).unwrap().mode() & 0o7777;
            assert_eq!(mode, bits, "could not induce mode {bits:o} on the fixture directory");
            let bytes = blob();
            let digest = preload_stamp::sha256_hex(&bytes);
            let r = assert_refusal(
                materialize(&bytes, &digest, &[root.clone()], &SEAMS),
                "cache_dir",
                "no writable private cache directory for the in-guest preload",
            );
            assert!(
                r.detail.as_deref().unwrap_or("").contains("setuid, setgid or sticky"),
                "{r:?}"
            );
            assert!(!root.join(&digest).exists(), "nothing is created in it");
        }
    }

    /// A cache hit needs a regular file: a symlink at the final path, even
    /// to the same bytes at mode 0500, refuses by name and is neither
    /// followed nor replaced.
    #[test]
    fn symlinked_final_path_refuses() {
        let scratch = Scratch::new("symlink");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        materialize(&bytes, &digest, &[root.clone()], &SEAMS).unwrap();
        let final_path = root.join(&digest).join(FILE_NAME);
        let outside = scratch.0.join("outside.so");
        std::fs::write(&outside, &bytes).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::remove_file(&final_path).unwrap();
        std::os::unix::fs::symlink(&outside, &final_path).unwrap();
        let r = assert_refusal(
            materialize(&bytes, &digest, &[root.clone()], &SEAMS),
            "cache_dir",
            "no writable private cache directory for the in-guest preload",
        );
        assert!(r.detail.as_deref().unwrap_or("").contains("a symlink"), "{r:?}");
        assert!(
            std::fs::symlink_metadata(&final_path).unwrap().file_type().is_symlink(),
            "the symlink is not replaced"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), bytes, "the outside file is untouched");
    }

    /// A directory at the final path is not a regular file: it refuses by
    /// name and is left in place.
    #[test]
    fn non_regular_final_path_refuses() {
        let scratch = Scratch::new("nonregular");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        materialize(&bytes, &digest, &[root.clone()], &SEAMS).unwrap();
        let final_path = root.join(&digest).join(FILE_NAME);
        std::fs::remove_file(&final_path).unwrap();
        std::fs::create_dir(&final_path).unwrap();
        let r = assert_refusal(
            materialize(&bytes, &digest, &[root.clone()], &SEAMS),
            "cache_dir",
            "no writable private cache directory for the in-guest preload",
        );
        assert!(r.detail.as_deref().unwrap_or("").contains("not a regular file"), "{r:?}");
        assert!(std::fs::symlink_metadata(&final_path).unwrap().is_dir(), "left in place");
    }

    /// A cached file with the embedded bytes but a mode other than 0500 is
    /// published again, as a new file at 0500, not trusted as found.
    #[test]
    fn widened_mode_republishes() {
        let scratch = Scratch::new("mode");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        materialize(&bytes, &digest, &[root.clone()], &SEAMS).unwrap();
        let final_path = root.join(&digest).join(FILE_NAME);
        std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = std::fs::symlink_metadata(&final_path).unwrap();
        assert_eq!(before.mode() & 0o7777, 0o755, "could not induce mode 0755");
        let path = materialize(&bytes, &digest, &[root.clone()], &SEAMS).unwrap();
        let after = std::fs::symlink_metadata(&final_path).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o500, "published again at 0500");
        assert_ne!(after.ino(), before.ino(), "a new file was renamed into place");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    /// A minimal ELF64 LE file with one PT_NOTE holding `note`.
    fn elf_with_note(note: &[u8]) -> Vec<u8> {
        let mut elf = vec![0u8; 64 + 56];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&4u32.to_le_bytes()); // PT_NOTE
        elf[ph + 8..ph + 16].copy_from_slice(&120u64.to_le_bytes()); // p_offset
        elf[ph + 32..ph + 40].copy_from_slice(&(note.len() as u64).to_le_bytes()); // p_filesz
        elf.extend_from_slice(note);
        elf
    }

    #[test]
    fn n16_flavour_mismatch_refuses() {
        let scratch = Scratch::new("n16");
        let path = scratch.0.join("user-preload.so");
        let note = preload_stamp::note_bytes(PROTOCOL_VERSION, preload_stamp::FLAVOUR_LITEINST);
        std::fs::write(&path, elf_with_note(&note)).unwrap();
        let before = std::fs::read(&path).unwrap();
        // The right flavour is admitted (version valid) ...
        let canonical = path.canonicalize().unwrap();
        assert_eq!(admit_user(&path, Flavour::Liteinst, &SEAMS).unwrap(), canonical);
        // ... and the same valid version with the wrong flavour refuses.
        let r = assert_refusal(
            admit_user(&path, Flavour::TrapHost, &SEAMS),
            "preload_stamp",
            "preload stamp mismatch: rebuild the preload",
        );
        assert!(r.detail.unwrap().contains("flavour"));
        assert_eq!(std::fs::read(&path).unwrap(), before, "the user file is never written");
    }

    static INSIDE: AtomicBool = AtomicBool::new(false);
    static OVERLAPPED: AtomicBool = AtomicBool::new(false);
    static PUBLISHED: AtomicUsize = AtomicUsize::new(0);

    fn slow_locked_section() {
        if INSIDE.swap(true, Ordering::SeqCst) {
            OVERLAPPED.store(true, Ordering::SeqCst);
        }
        std::thread::sleep(Duration::from_millis(300));
        INSIDE.store(false, Ordering::SeqCst);
    }

    fn count_publish(_: &Path) {
        PUBLISHED.fetch_add(1, Ordering::SeqCst);
    }

    static LOCKED: Hooks = Hooks {
        write: write_all,
        dir_probe_map: ok_map,
        final_map: ok_map,
        after_publish: count_publish,
        in_lock: slow_locked_section,
    };

    /// The cache lock: two materializations of one fresh entry, with a delay
    /// inside the locked section, never overlap there, and exactly one
    /// publishes.
    #[test]
    fn lock_materialize_concurrent() {
        let scratch = Scratch::new("lock");
        let root = scratch.0.join("literoot");
        let bytes = blob();
        let digest = preload_stamp::sha256_hex(&bytes);
        let results: Vec<Result<PathBuf, Refusal>> = std::thread::scope(|s| {
            let a = s.spawn(|| materialize(&bytes, &digest, &[root.clone()], &LOCKED));
            let b = s.spawn(|| materialize(&bytes, &digest, &[root.clone()], &LOCKED));
            vec![a.join().unwrap(), b.join().unwrap()]
        });
        let paths: Vec<PathBuf> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(paths[0], paths[1]);
        assert!(!OVERLAPPED.load(Ordering::SeqCst), "the locked sections overlapped");
        assert_eq!(PUBLISHED.load(Ordering::SeqCst), 1, "exactly one publish");
    }
}
