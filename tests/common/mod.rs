//! Helpers shared by the integration tests that launch literoot.

#![allow(dead_code)] // each test binary uses its own subset

use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

// Resolution follows tool.rs's convention: $LITEROOT_PRELOAD wins,
// then $CARGO_TARGET_DIR/release, then the preload-local target.
pub fn resolve_preload() -> PathBuf {
    if let Ok(p) = std::env::var("LITEROOT_PRELOAD") {
        return PathBuf::from(p);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        let td = PathBuf::from(td);
        let td = if td.is_absolute() { td } else { root.join(td) };
        let cand = td.join("release/libliteroot_preload.so");
        if cand.exists() {
            return cand;
        }
    }
    root.join("preload/target/release/libliteroot_preload.so")
}

pub fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

/// Run literoot in its own process group, killing the group after 10 s.
pub fn run_bounded(mut cmd: Command, what: &str) -> Output {
    use std::os::unix::process::CommandExt as _;
    cmd.process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child: Child = cmd.spawn().expect("spawn literoot");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait literoot") {
            Some(_) => return child.wait_with_output().expect("collect output"),
            None if Instant::now() >= deadline => {
                extern "C" {
                    fn kill(pid: i32, sig: i32) -> i32;
                }
                unsafe {
                    kill(-(child.id() as i32), 9);
                }
                let _ = child.kill();
                let out = child.wait_with_output().expect("collect killed output");
                panic!("{what}: literoot did not finish within 10 s: {out:?}");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// A failed fixture build is a skip, never a pass; under
/// LITEROOT_REQUIRE_FIXTURES it fails the test instead.
pub fn fixture_or_skip(built: &Output, what: &str) -> bool {
    if built.status.success() {
        return true;
    }
    assert!(
        std::env::var_os("LITEROOT_REQUIRE_FIXTURES").is_none(),
        "{what} build failed under LITEROOT_REQUIRE_FIXTURES: {built:?}"
    );
    eprintln!("{what}: SKIP (not a pass): build failed: {built:?}");
    false
}
