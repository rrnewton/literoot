//! The private runtime package: literoot's fixed musl runtime image and its
//! facts, and the one custody point that turns them into Reverie's
//! `AuditedRuntimeImage` (row d, design note section 4).
//!
//! The package is two files that only the installer writes, ELF first and
//! JSON last: `literoot_private_runtime.elf` and
//! `literoot_private_runtime.package.json`, schema
//! `literoot.private-static-runtime-data.v1` (Hermit's field set, plus the
//! successor entry). They are found in `$LITEROOT_RUNTIME_DIR`, else beside
//! the literoot binary.
//!
//! The producer can check that the facts match the bytes, not that the pair
//! is authentic (`RuntimeImageFacts`, Reverie producer.rs). Authenticating it
//! is this module's job: both files are opened O_NOFOLLOW, must be regular
//! files owned by the effective user and not writable by group or others
//! (checked with fstat on the opened descriptor, not the path), are read once
//! and kept open for the run, and must not change identity or bytes
//! (`RuntimePackage::verify`). The trusted writers are therefore the
//! installer and the effective user. The mode check is a property of the
//! file at open, not a revocation: a descriptor that another process opened
//! for writing while the file was still group- or other-writable, or a
//! shared writable mapping of it, can still write afterwards. The retained
//! bytes let `verify` detect such a change when it is called; nothing here
//! prevents it.
//! Facts come only from the package, never from argv or the environment.
//! [`open_audited`] is the only caller of `AuditedRuntimeImage::new` in
//! literoot; a test pins that.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use reverie_inguest::launcher::exec_stop::producer::AuditedRuntimeImage;
use reverie_inguest::launcher::exec_stop::producer::EntryPoint;
use reverie_inguest::launcher::exec_stop::producer::RuntimeImageFacts;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

pub const SCHEMA: &str = "literoot.private-static-runtime-data.v1";
pub const ELF_FILE: &str = "literoot_private_runtime.elf";
pub const DATA_FILE: &str = "literoot_private_runtime.package.json";
/// Overrides the package directory (else: the binary's own directory).
pub const DIR_ENV: &str = "LITEROOT_RUNTIME_DIR";
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const MAX_DATA: u64 = 1024 * 1024;

// These values describe bytes. Parsing them grants nothing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageData {
    schema: String,
    image: ImageData,
    entry: u64,
    terminal_int3: u64,
    successor_entry: u64,
    successor_terminal_int3: u64,
    fallback_entry: u64,
    completion_syscall: u64,
    observed: ObservedData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageData {
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedData {
    layout_address: u64,
    reference_address: u64,
    handler_address: u64,
    handler_bytes: u64,
    handler_sha256: String,
    dev_null_address: u64,
    sites: [[u64; 4]; 4],
    ordinary_post_ips: Vec<u64>,
}

fn refused(why: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("literoot: private runtime package: {why}"))
}

fn digest(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(refused("a SHA-256 is not 64 lowercase hex digits"));
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(refused)?;
    }
    Ok(out)
}

fn parse_data(bytes: &[u8]) -> io::Result<PackageData> {
    let data: PackageData = serde_json::from_slice(bytes).map_err(refused)?;
    if data.schema != SCHEMA {
        return Err(refused(format!("schema {:?} is not {SCHEMA}", data.schema)));
    }
    if data.image.bytes == 0 || data.image.bytes > MAX_IMAGE {
        return Err(refused("image size out of range"));
    }
    digest(&data.image.sha256)?;
    digest(&data.observed.handler_sha256)?;
    let ips = &data.observed.ordinary_post_ips;
    if data.observed.handler_bytes == 0
        || data.observed.handler_bytes > 64 * 1024
        || ips.is_empty()
        || ips.len() > 4096
        || !ips.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(refused("observed handler or site facts out of range"));
    }
    if data.fallback_entry >= data.completion_syscall {
        return Err(refused("fallback_entry is not below completion_syscall"));
    }
    Ok(data)
}

/// One package file, opened once and kept open for the run.
struct RetainedFile {
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
    state: [u64; 8],
}

/// The identity of an opened package file, from fstat on its descriptor.
/// Refuses anything but a regular file owned by the effective user and not
/// writable by group or others.
fn state(path: &Path, file: &File) -> io::Result<[u64; 8]> {
    let m = file.metadata()?;
    if !m.is_file() {
        return Err(refused(format!("{}: not a regular file", path.display())));
    }
    // SAFETY: geteuid takes no arguments and only reads the caller's identity.
    if m.uid() != unsafe { libc::geteuid() } {
        return Err(refused(format!("{}: not owned by the effective user", path.display())));
    }
    if m.mode() & 0o022 != 0 {
        return Err(refused(format!(
            "{}: mode {:o} is writable by group or others",
            path.display(),
            m.mode() & 0o7777
        )));
    }
    Ok([
        m.dev(),
        m.ino(),
        m.len(),
        u64::from(m.mode()),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ])
}

impl RetainedFile {
    fn open(path: &Path, limit: u64) -> io::Result<Self> {
        // O_NONBLOCK lets a FIFO or device reach the regular-file refusal
        // instead of blocking in open.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| refused(format!("{}: {e}", path.display())))?;
        let before = state(path, &file)?;
        if before[2] == 0 || before[2] > limit {
            return Err(refused(format!("{}: size out of range", path.display())));
        }
        let mut bytes = vec![0; usize::try_from(before[2]).map_err(refused)?];
        file.read_exact_at(&mut bytes, 0)?;
        if state(path, &file)? != before {
            return Err(refused(format!("{}: changed while read", path.display())));
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            bytes,
            state: before,
        })
    }

    fn verify(&self) -> io::Result<()> {
        if state(&self.path, &self.file)? != self.state {
            return Err(refused(format!("{}: changed identity after open", self.path.display())));
        }
        let mut bytes = vec![0; self.bytes.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if bytes != self.bytes || state(&self.path, &self.file)? != self.state {
            return Err(refused(format!("{}: changed bytes after open", self.path.display())));
        }
        Ok(())
    }
}

/// The audited runtime image and the package files it came from, kept open.
pub struct RuntimePackage {
    image: AuditedRuntimeImage,
    elf: RetainedFile,
    data: RetainedFile,
    fallback_entry: u64,
    completion_syscall: u64,
}

impl std::fmt::Debug for RuntimePackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimePackage")
            .field("image", &self.image)
            .finish_non_exhaustive()
    }
}

impl RuntimePackage {
    pub fn image(&self) -> &AuditedRuntimeImage {
        &self.image
    }

    /// The observer coordinates checked at open: the fallback entry and the
    /// `syscall; ud2` completion site.
    pub fn observer_coordinates(&self) -> (u64, u64) {
        (self.fallback_entry, self.completion_syscall)
    }

    /// Both files still have the identity and bytes read at open.
    pub fn verify(&self) -> io::Result<()> {
        self.data.verify()?;
        self.elf.verify()?;
        self.data.verify()
    }
}

/// The package directory: `$LITEROOT_RUNTIME_DIR`, else the directory of
/// the running literoot binary.
pub fn package_dir() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let exe = std::env::current_exe()?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| refused("the literoot binary has no parent directory"))
}

/// Open, authenticate and audit the package in `dir`. The JSON is read
/// first, then the ELF; the ELF's size and SHA-256 must match the JSON's;
/// the facts are built field by field and audited by
/// `AuditedRuntimeImage::new`; then the observer coordinates must name
/// executable bytes, the completion site exactly `syscall; ud2`; and both
/// files are verified unchanged.
pub fn open_audited(dir: &Path) -> io::Result<RuntimePackage> {
    if !cfg!(target_arch = "x86_64") {
        return Err(refused("the private runtime package is x86-64 only"));
    }
    let data = RetainedFile::open(&dir.join(DATA_FILE), MAX_DATA)?;
    let parsed = parse_data(&data.bytes)?;
    let elf = RetainedFile::open(&dir.join(ELF_FILE), MAX_IMAGE)?;
    let image_sha256 = digest(&parsed.image.sha256)?;
    if elf.state[2] != parsed.image.bytes {
        return Err(refused("the ELF's size differs from the package data"));
    }
    if <[u8; 32]>::from(Sha256::digest(&elf.bytes)) != image_sha256 {
        return Err(refused("the ELF's SHA-256 differs from the package data"));
    }
    let observed = parsed.observed;
    let facts = RuntimeImageFacts {
        image_sha256,
        layout_address: observed.layout_address,
        reference_address: observed.reference_address,
        sites: observed.sites,
        ordinary_post_ips: observed.ordinary_post_ips,
        handler_address: observed.handler_address,
        handler_bytes: observed.handler_bytes,
        handler_sha256: digest(&observed.handler_sha256)?,
        dev_null_address: observed.dev_null_address,
        initial_entry: Some(EntryPoint {
            entry: parsed.entry,
            terminal_trap: parsed.terminal_int3,
        }),
        successor_entry: Some(EntryPoint {
            entry: parsed.successor_entry,
            terminal_trap: parsed.successor_terminal_int3,
        }),
        // x86-64 images declare no data in executable segments.
        data_ranges: Vec::new(),
    };
    let image = AuditedRuntimeImage::new(elf.bytes.clone(), facts)
        .map_err(|e| refused(format!("audit: {e}")))?;
    image
        .exact_executable(parsed.fallback_entry, 1)
        .map_err(|e| refused(format!("fallback_entry: {e}")))?;
    let completion = image
        .exact_executable(parsed.completion_syscall, 4)
        .map_err(|e| refused(format!("completion_syscall: {e}")))?;
    if completion != [0x0f, 0x05, 0x0f, 0x0b] {
        return Err(refused("completion_syscall is not `syscall; ud2`"));
    }
    let package = RuntimePackage {
        image,
        elf,
        data,
        fallback_entry: parsed.fallback_entry,
        completion_syscall: parsed.completion_syscall,
    };
    package.verify()?;
    Ok(package)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use super::*;

    const ELF: &[u8] = b"\x7fELF not really a runtime image";
    /// Same length as `ELF`, different bytes.
    const SAME_LEN_ELF: &[u8] = b"\x7fELF not really a runtime IMAGE";

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dir(label: &str) -> Dir {
        let d = std::env::temp_dir().join(format!(
            "literoot-runtime-package-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A package whose data is well formed and matches `ELF`.
    fn data() -> serde_json::Value {
        serde_json::json!({
            "schema": SCHEMA,
            "image": {"bytes": ELF.len(), "sha256": hex(&Sha256::digest(ELF))},
            "entry": 0x401000,
            "terminal_int3": 0x401100,
            "successor_entry": 0x402000,
            "successor_terminal_int3": 0x402100,
            "fallback_entry": 0x403000,
            "completion_syscall": 0x403100,
            "observed": {
                "layout_address": 0x500000,
                "reference_address": 0x501000,
                "handler_address": 0x404000,
                "handler_bytes": 64,
                "handler_sha256": hex(&[7; 32]),
                "dev_null_address": 0x502000,
                "sites": [[0x405000, 0x405002, 158, 1], [0x405010, 0x405012, 218, 2],
                          [0x405020, 0x405022, 7, 3], [0x405030, 0x405032, 2, 4]],
                "ordinary_post_ips": [0x406002, 0x406012],
            },
        })
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Writes both files afresh with mode 0644, whatever the umask or the
    /// mode an earlier case left (a 0400 file cannot be rewritten).
    fn write(d: &Dir, data: &serde_json::Value, elf: &[u8]) {
        let _ = std::fs::remove_file(d.0.join(ELF_FILE));
        let _ = std::fs::remove_file(d.0.join(DATA_FILE));
        std::fs::write(d.0.join(ELF_FILE), elf).unwrap();
        std::fs::write(d.0.join(DATA_FILE), serde_json::to_vec(data).unwrap()).unwrap();
        chmod(&d.0.join(ELF_FILE), 0o644);
        chmod(&d.0.join(DATA_FILE), 0o644);
    }

    fn refusal(d: &Dir) -> String {
        open_audited(&d.0).unwrap_err().to_string()
    }

    #[test]
    fn a_matching_package_reaches_the_audit() {
        // Everything literoot checks passes, so the refusal is the audit's:
        // these bytes are not an ELF runtime image.
        let d = dir("audit");
        write(&d, &data(), ELF);
        let why = refusal(&d);
        assert!(why.contains("private runtime package: audit:"), "{why}");
    }

    #[test]
    fn a_symlinked_package_file_is_refused() {
        let d = dir("symlink");
        write(&d, &data(), ELF);
        let real = d.0.join("real.json");
        std::fs::rename(d.0.join(DATA_FILE), &real).unwrap();
        symlink(&real, d.0.join(DATA_FILE)).unwrap();
        let why = refusal(&d);
        assert!(why.contains(DATA_FILE) && why.contains("symbolic links"), "{why}");
    }

    #[test]
    fn a_same_size_elf_with_a_stale_digest_is_refused() {
        // Same length, different bytes: only the SHA-256 comparison can
        // refuse this, before the audit.
        assert_eq!(SAME_LEN_ELF.len(), ELF.len());
        assert_ne!(SAME_LEN_ELF, ELF);
        let d = dir("sha");
        write(&d, &data(), SAME_LEN_ELF);
        let why = refusal(&d);
        assert!(why.contains("the ELF's SHA-256 differs"), "{why}");
    }

    #[test]
    fn an_elf_whose_size_differs_from_its_data_is_refused() {
        let d = dir("size");
        let mut long = data();
        long["image"]["bytes"] = serde_json::json!(ELF.len() + 1);
        write(&d, &long, ELF);
        let why = refusal(&d);
        assert!(why.contains("the ELF's size differs"), "{why}");
    }

    #[test]
    fn a_group_or_other_writable_package_file_is_refused_by_name() {
        let d = dir("mode");
        for file in [DATA_FILE, ELF_FILE] {
            for mode in [0o664, 0o646, 0o666] {
                write(&d, &data(), ELF);
                chmod(&d.0.join(file), mode);
                let why = refusal(&d);
                let named = format!("{file}: mode {mode:o} is writable by group or others");
                assert!(why.contains(&named), "{file} {mode:o}: {why}");
            }
        }
    }

    #[test]
    fn safe_package_file_modes_pass_custody() {
        // Not writable by group or others: the refusal is the audit's.
        let d = dir("safe-mode");
        for mode in [0o644, 0o640, 0o600, 0o444, 0o400] {
            write(&d, &data(), ELF);
            chmod(&d.0.join(DATA_FILE), mode);
            chmod(&d.0.join(ELF_FILE), mode);
            let why = refusal(&d);
            assert!(why.contains("private runtime package: audit:"), "{mode:o}: {why}");
        }
    }

    #[test]
    fn a_file_changed_after_open_fails_verify() {
        // RetainedFile is what the package keeps; a change of size or bytes
        // after the read is caught by verify.
        let d = dir("changed");
        let path = d.0.join(ELF_FILE);
        std::fs::write(&path, ELF).unwrap();
        chmod(&path, 0o644);
        let retained = RetainedFile::open(&path, MAX_IMAGE).unwrap();
        retained.verify().unwrap();
        std::fs::write(&path, b"\x7fELF grown after the package was opened").unwrap();
        let why = retained.verify().unwrap_err().to_string();
        assert!(why.contains(&format!("{ELF_FILE}: changed")), "{why}");
    }

    #[test]
    fn out_of_range_facts_are_refused() {
        let d = dir("range");
        for (pointer, value, why) in [
            ("/observed/handler_bytes", serde_json::json!(0), "out of range"),
            ("/observed/handler_bytes", serde_json::json!(65537), "out of range"),
            ("/observed/ordinary_post_ips", serde_json::json!([]), "out of range"),
            ("/observed/ordinary_post_ips", serde_json::json!([2, 1]), "out of range"),
            ("/image/bytes", serde_json::json!(0), "image size"),
            ("/image/sha256", serde_json::json!("AB".repeat(32)), "lowercase hex"),
            ("/fallback_entry", serde_json::json!(0x403100), "fallback_entry"),
            ("/schema", serde_json::json!("hermit.private-static-runtime-data.v1"), "schema"),
        ] {
            let mut bad = data();
            *bad.pointer_mut(pointer).unwrap() = value;
            write(&d, &bad, ELF);
            let got = refusal(&d);
            assert!(got.contains(why), "{pointer}: {got}");
        }
    }

    #[test]
    fn an_absent_or_unknown_key_is_refused() {
        let d = dir("keys");
        for key in ["successor_entry", "completion_syscall", "observed"] {
            let mut bad = data();
            bad.as_object_mut().unwrap().remove(key);
            write(&d, &bad, ELF);
            let got = refusal(&d);
            assert!(got.contains("missing field"), "{key}: {got}");
        }
        let mut extra = data();
        extra["ready"] = serde_json::json!(true);
        write(&d, &extra, ELF);
        assert!(refusal(&d).contains("unknown field"));
    }

    #[test]
    fn an_absent_package_is_refused_by_name() {
        let d = dir("absent");
        let got = refusal(&d);
        assert!(got.contains(DATA_FILE), "{got}");
    }

    #[test]
    fn open_audited_is_the_only_caller_of_the_audit() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        // Built, so this file's own needle is not a match.
        let needle = ["AuditedRuntimeImage", "::new("].concat();
        let mut calls = Vec::new();
        let mut stack = vec![root.join("src"), root.join("preload/src")];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                for entry in std::fs::read_dir(&path).unwrap() {
                    stack.push(entry.unwrap().path());
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for (i, line) in text.lines().enumerate() {
                    if line.contains(&needle) && !line.trim_start().starts_with("//") {
                        calls.push(format!("{}:{}", path.display(), i + 1));
                    }
                }
            }
        }
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].contains("src/runtime_package.rs"), "{calls:?}");
    }
}
