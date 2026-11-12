//! Static-initial canary for bucket (a) of the trap
//! suite classification (53 names).
//!
//! The guest is a statically linked initial program
//! (ET_EXEC, no PT_INTERP) of exactly the shape the
//! upstream proot suite rootfs helpers have. Under the
//! ptrace backend it runs today (control test). Under
//! the in-guest trap backend it is refused pre-spawn by
//! Reverie's A6 static-admission gate, because no
//! preload can load into a static image and the exec
//! route that would admit it (private initializer +
//! Ready/entry + successor admission, Reverie PR #1327
//! chain) is not in the pinned Reverie. The trap canary
//! is therefore quarantined with #[ignore] as a known
//! failure: its body stays strict (exact guest exit 7
//! plus marker content, never accepting the A6 refusal),
//! runnable explicitly with --ignored, and it is the
//! first test to un-ignore when static admission lands.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::literoot_bin;
use common::resolve_preload;
use common::run_bounded;

const STATIC_GUEST_C: &str = r#"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return 3;
    const char *s = "static-ran\n";
    if (write(fd, s, strlen(s)) != (ssize_t)strlen(s)) return 4;
    close(fd);
    return 7;
}
"#;

fn build_static_guest(dir: &std::path::Path) -> Option<PathBuf> {
    std::fs::write(dir.join("static-guest.c"), STATIC_GUEST_C).unwrap();
    let bin = dir.join("static-guest");
    let cc = Command::new("cc")
        .args(["-O2", "-static", "-o"])
        .arg(&bin)
        .arg(dir.join("static-guest.c"))
        .output()
        .expect("cc is required to build the static guest");
    if !cc.status.success() {
        assert!(
            std::env::var_os("LITEROOT_REQUIRE_FIXTURES").is_none(),
            "static guest build failed under LITEROOT_REQUIRE_FIXTURES: {cc:?}"
        );
        eprintln!("static-initial: SKIP (not a pass): cc -static unavailable: {cc:?}");
        return None;
    }
    Some(bin)
}

fn scratch_rootfs_with_guest(bin: &std::path::Path) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "literoot-static-initial-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["bin", "tmp"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::copy(bin, dir.join("bin/static-guest")).unwrap();
    dir
}

/// Control: the same static initial guest passes under
/// the ptrace backend today (exact exit 7 + marker).
/// This proves the guest itself, so the trap canary
/// below isolates static admission, not guest validity.
#[test]
fn static_initial_ptrace_control() {
    let src = std::env::temp_dir()
        .join(format!("literoot-static-initial-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    let Some(bin) = build_static_guest(&src) else { return };
    let root = scratch_rootfs_with_guest(&bin);
    let root_s = root.to_string_lossy().to_string();
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", "ptrace", "-r", &root_s, "/bin/static-guest", "/tmp/marker.txt"]);
    let out = run_bounded(cmd, "ptrace control");
    let marker = std::fs::read_to_string(root.join("tmp/marker.txt")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&src);
    assert_eq!(
        out.status.code(),
        Some(7),
        "static initial guest must run under ptrace: {out:?}"
    );
    assert_eq!(marker, "static-ran\n");
}

/// Canary: the same static initial guest must run under
/// the in-guest trap backend once static admission lands
/// (Reverie exec route, PR #1327 chain).
/// Today it is refused pre-spawn by the A6 gate
/// ("static executables are not supported by the
/// in-guest backend (no PT_INTERP)"), so this test is
/// quarantined as a known failure — never weakened to
/// accept the refusal. Un-ignore it when the pin gains
/// a Ready-capable private initializer.
#[test]
#[ignore = "known failure: static initial admission blocked on Reverie exec route (PR #1327), bead dh-35ic7"]
fn static_initial_trap_canary() {
    let preload = resolve_preload();
    assert!(
        preload.exists(),
        "static-initial trap canary requires the preload built: \
         cargo build --release --manifest-path preload/Cargo.toml"
    );
    let src = std::env::temp_dir()
        .join(format!("literoot-static-initial-trap-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    let bin = build_static_guest(&src).expect("static guest build required for canary");
    let root = scratch_rootfs_with_guest(&bin);
    let root_s = root.to_string_lossy().to_string();
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", "trap", "-r", &root_s, "/bin/static-guest", "/tmp/marker.txt"])
        .env("LITEROOT_PRELOAD", &preload);
    let out = run_bounded(cmd, "trap canary");
    let marker = std::fs::read_to_string(root.join("tmp/marker.txt")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&src);
    assert_eq!(
        out.status.code(),
        Some(7),
        "static initial guest must run under trap once admitted: {out:?}"
    );
    assert_eq!(marker, "static-ran\n");
}
