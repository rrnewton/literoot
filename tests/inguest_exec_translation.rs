//! Regression: an in-guest image's first execve must take the
//! translated route, not the launcher passthrough.
//!
//! `LAUNCHER_EXEC_SEEN` (rootfs_tool.rs) lets the one
//! launcher-issued execve (already a host path, seen only by the
//! ptrace coordinator) pass through untranslated. In-guest the
//! preload Tool is installed after that exec, in every new
//! image, so without seeding from the preload bootstrap the
//! first guest execve of each image skipped translation, the
//! /proc/self/exe rewrite, shebang and PT_INTERP handling
//! (measured: every nested exec in the proot suite died with
//! "Operation not supported" while direct syscalls passed).
//!
//! The guest below mirrors upstream test-exec-proc-self-exe:
//! it execs /proc/self/exe with an env marker. The oracle is
//! the Tool's own LITEROOT_DEBUG translation line for that
//! execve, which only the translated route prints; the
//! passthrough route injects before it. (Whether the exec
//! itself then succeeds is the backend's successor machinery,
//! not this test's claim.)
//!
//! Fails when the preload has not been built (same convention
//! as probe_coherence's in-guest test; only an explicit
//! LITEROOT_ALLOW_SKIP_PRELOAD opt-in skips):
//!   cargo build --release --manifest-path preload/Cargo.toml

use std::path::PathBuf;
use std::process::Command;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

// Resolution follows tool.rs's convention: $LITEROOT_PRELOAD wins,
// then $CARGO_TARGET_DIR/release, then the preload-local target.
fn preload_path() -> PathBuf {
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

const GUEST_C: &str = r#"
#include <unistd.h>
#include <stdlib.h>
int main(void) {
    char *void_array[] = { NULL };
    if (getenv("PROC_SELF_EXE") != NULL)
        exit(EXIT_SUCCESS);
    setenv("PROC_SELF_EXE", "1", 1);
    execv("/proc/self/exe", void_array);
    exit(EXIT_FAILURE);
}
"#;

#[test]
fn inguest_first_execve_takes_translated_route() {
    let preload = preload_path();
    if !preload.exists() {
        // A silent skip here would let the suite count this test
        // as passed without running it: fail loudly unless a human
        // explicitly opted in, as in probe_coherence.
        if std::env::var_os("LITEROOT_ALLOW_SKIP_PRELOAD").is_some() {
            eprintln!("inguest-exec: preload not built — skipping (opt-in)");
            return;
        }
        panic!(
            "inguest-exec: preload not built at {} — build the preload \
             (cargo build -p literoot-preload --release) or set \
             LITEROOT_ALLOW_SKIP_PRELOAD=1 to skip explicitly",
            preload.display()
        );
    }
    let dir = std::env::temp_dir().join(format!("literoot-igexec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["bin", "lib64", "src"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::write(dir.join("src/selfexe.c"), GUEST_C).unwrap();
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(dir.join("bin/selfexe"))
        .arg(dir.join("src/selfexe.c"))
        .output()
        .expect("cc");
    if !cc.status.success() {
        eprintln!("inguest-exec: cc unavailable — skipping");
        return;
    }
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        let src = PathBuf::from(format!("/lib64/{lib}"));
        if src.exists() {
            std::fs::copy(&src, dir.join("lib64").join(lib)).unwrap();
        }
    }
    let root = dir.to_string_lossy().to_string();
    let out = Command::new(literoot_bin())
        .args(["--backend", "trap", "-r", &root, "/bin/selfexe"])
        .env("LITEROOT_PRELOAD", &preload)
        .env("LITEROOT_DEBUG", "1")
        .output()
        .expect("spawn literoot trap guest");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        stderr.contains("execve \"/proc/self/exe\" ->") || stderr.contains("execve \"/bin/selfexe\" ->"),
        "first in-guest execve did not take the translated route \
         (launcher passthrough leaked into the guest): status={:?} stderr={stderr:?}",
        out.status
    );
}
