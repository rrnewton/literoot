//! Rebuild freshness of the embedded preload: two checks, never
//! relabelled as each other:
//!
//! - freshness: a controlled change to a scratch copy of src/translate.rs,
//!   which the preload compiles, changes the embedded artifact's digest;
//! - invalidation: a touch-only change (mtime, same bytes) reruns the build
//!   script and its nested preload build; identical output bytes are
//!   permitted.
//!
//! Both build a scratch copy of this checkout's tracked files (`git
//! ls-files`) into their own target and build directories, and read the
//! digest from the one receipt build.rs writes. The third check, that a
//! lock-only change of the pinned Reverie revision changes the stamp's
//! protocol_version, needs no build.

#![cfg(any(feature = "in-guest", feature = "inguest-trap"))]

#[path = "../src/preload_stamp.rs"]
mod preload_stamp;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A fresh copy of the checkout's tracked files.
fn scratch_copy(label: &str) -> PathBuf {
    let root = manifest_dir();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dst = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("t6-{label}-{}-{nanos}", std::process::id()));
    let listed = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["ls-files", "-z"])
        .output()
        .expect("git is required to copy the checkout");
    assert!(listed.status.success(), "git ls-files failed: {listed:?}");
    let mut copied = 0;
    for rel in listed.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let rel = std::str::from_utf8(rel).expect("tracked paths are UTF-8");
        let from = root.join(rel);
        if !from.is_file() {
            continue;
        }
        let to = dst.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(&from, &to).unwrap_or_else(|e| panic!("copy {rel}: {e}"));
        copied += 1;
    }
    assert!(copied > 0, "no tracked files copied");
    dst
}

/// One debug build of the scratch copy's literoot binary, in its own target
/// and build directories, whatever directories the caller's environment
/// names.
fn build(scratch: &Path) {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(scratch)
        .args(["build", "--locked", "--bin", "literoot"])
        .arg("--manifest-path")
        .arg(scratch.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(scratch.join("t6-target"))
        .env_remove("CARGO_TARGET_DIR")
        .env("CARGO_BUILD_BUILD_DIR", scratch.join("t6-build"))
        .output()
        .expect("run cargo");
    assert!(
        out.status.success(),
        "scratch build failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn receipts_under(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            receipts_under(&path, found);
        } else if kind.is_file()
            && path.extension().is_some_and(|e| e == "receipt")
            && path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == "preload-embed")
        {
            found.push(path);
        }
    }
}

/// The one receipt in the scratch build directory: its path, digest and
/// modification time.
fn receipt(scratch: &Path) -> (PathBuf, String, SystemTime) {
    let mut found = Vec::new();
    receipts_under(&scratch.join("t6-build"), &mut found);
    assert_eq!(found.len(), 1, "exactly one receipt: {found:?}");
    let path = found.pop().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let digests: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("digest=")).collect();
    assert_eq!(digests.len(), 1, "one digest line: {text}");
    let digest = digests[0].to_owned();
    assert!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "digest is lowercase hex sha256: {digest}"
    );
    let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    (path, digest, mtime)
}

#[test]
fn t6_semantic_change_changes_digest() {
    let scratch = scratch_copy("semantic");
    build(&scratch);
    let (_, before, _) = receipt(&scratch);
    let translate = scratch.join("src/translate.rs");
    let mut text = std::fs::read_to_string(&translate).unwrap();
    text.push_str("\n#[allow(dead_code)]\npub(crate) const T6_FRESHNESS_PROBE: u32 = 2;\n");
    std::fs::write(&translate, text).unwrap();
    build(&scratch);
    let (_, after, _) = receipt(&scratch);
    assert_ne!(before, after, "a change to src/translate.rs must change the embedded digest");
}

/// Invalidation only: the receipt is rewritten, so build.rs and its nested
/// preload build ran again. Identical output bytes are permitted, not
/// asserted, so the digests are not compared.
#[test]
fn t6_touch_only_reruns_build_script() {
    let scratch = scratch_copy("touch");
    build(&scratch);
    let (path, _, before) = receipt(&scratch);
    let translate = scratch.join("src/translate.rs");
    let bytes = std::fs::read(&translate).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::File::options()
        .write(true)
        .open(&translate)
        .unwrap()
        .set_modified(SystemTime::now())
        .unwrap();
    assert_eq!(std::fs::read(&translate).unwrap(), bytes, "touch only, same bytes");
    build(&scratch);
    let (path_after, _, after) = receipt(&scratch);
    assert_eq!(path, path_after, "the same build-script output directory");
    assert!(after > before, "the touch must rerun build.rs and its nested build");
}

#[test]
fn t6_lockfile_rev_changes_version() {
    let root = manifest_dir();
    let files: Vec<(&str, Vec<u8>)> = preload_stamp::STAMP_FILES
        .iter()
        .map(|rel| (*rel, std::fs::read(root.join(rel)).unwrap()))
        .collect();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
    let base = preload_stamp::protocol_version_of(&files, &lock).unwrap();
    let revisions = preload_stamp::reverie_revisions(&lock).unwrap();
    let rev = revisions
        .lines()
        .next()
        .and_then(|l| l.split_once('='))
        .map(|(_, r)| r.to_owned())
        .unwrap();
    assert_eq!(rev.len(), 40, "a full git revision: {rev}");
    let moved = lock.replace(&rev, &"0".repeat(40));
    assert_ne!(moved, lock);
    let changed = preload_stamp::protocol_version_of(&files, &moved).unwrap();
    assert_ne!(base, changed, "a Reverie revision change must change protocol_version");
    // An unrelated lockfile change leaves it alone: only the revisions count.
    let unrelated = format!("{lock}\n# unrelated\n");
    assert_eq!(preload_stamp::protocol_version_of(&files, &unrelated).unwrap(), base);
}
