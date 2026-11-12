//! Probe-cache coherence across guest processes sharing one
//! rootfs (review gate): process A replaces a symlink with a
//! real directory; process B, which previously resolved through
//! the symlink (caching its kind), must observe the new layout.
//! Without shared generation invalidation B keeps splicing the
//! stale symlink kind and never sees the directory's contents.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

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

fn sh(rootfs: &str, script: &str) -> std::process::Output {
    Command::new(literoot_bin())
        .args(["-r", rootfs, "-b", "/dev:/dev", "/bin/sh", "-c", script])
        .env("PATH", "/bin:/usr/bin")
        .output()
        .expect("spawn literoot sh")
}

#[test]
fn cross_process_symlink_swap_is_visible() {
    // Ptrace variant: all Tools share the tracer process, so
    // this proves tracer-internal coherence only; the
    // in-guest variant below is the discriminating one.
    let root = std::env::temp_dir().join(format!("literoot-coherence-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for sub in ["bin", "lib64", "d1", "work"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    for bin in ["sh", "cat", "ln", "rm", "mkdir", "sleep"] {
        std::fs::copy(format!("/bin/{bin}"), root.join("bin").join(bin)).unwrap();
    }
    for lib in [
        "libc.so.6",
        "libtinfo.so.6",
        "libcap.so.2",
        "libpcre2-8.so.0",
        "libselinux.so.1",
        "ld-linux-x86-64.so.2",
    ] {
        let src = PathBuf::from(format!("/lib64/{lib}"));
        if src.exists() {
            std::fs::copy(&src, root.join("lib64").join(lib)).unwrap();
        }
    }
    std::fs::write(root.join("d1/file"), "from-d1\n").unwrap();
    // /link -> /d1 initially (symlink inside the rootfs).
    std::os::unix::fs::symlink("/d1", root.join("link")).unwrap();
    let root_s = root.to_string_lossy().to_string();

    // B warms its probe cache: /link is a symlink to a dir.
    let out = sh(&root_s, "cat /link/file");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "from-d1\n",
        "warmup resolve failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // One literoot guest tree with two processes: background
    // swapper replaces the symlink with a real directory while
    // the foreground keeps resolving through it. A single
    // literoot invocation keeps both processes under one tracer
    // (ptrace) — the in-guest shared-memfd path is exercised by
    // the same generation counter.
    let script = r#"
        ( sleep 0.3; rm /link; mkdir /link; echo from-realdir > /link/file ) &
        i=0
        while [ $i -lt 40 ]; do
            c=$(cat /link/file 2>/dev/null)
            if [ "$c" = "from-realdir" ]; then echo SAW-REALDIR; exit 0; fi
            i=$((i+1))
            sleep 0.1
        done
        echo STUCK
        exit 1
    "#;
    let start = Instant::now();
    let out = sh(&root_s, script);
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("SAW-REALDIR"),
        "cross-process swap never became visible ({elapsed:?}): stdout={stdout:?} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(elapsed < Duration::from_secs(10), "swap took too long: {elapsed:?}");
    let _ = std::fs::remove_dir_all(&root);
}

const SWAP_GUEST_C: &str = r#"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        // Swapper: replace symlink /link with a real directory.
        usleep(300000);
        unlink("/link");
        mkdir("/link", 0755);
        int fd = open("/link/file", O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fd >= 0) { const char *s = "from-realdir\n"; write(fd, s, strlen(s)); close(fd); }
        _exit(0);
    }
    char buf[64];
    for (int i = 0; i < 40; i++) {
        int fd = open("/link/file", O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf)-1);
            close(fd);
            if (n > 0) {
                buf[n] = 0;
                if (strstr(buf, "from-realdir")) { puts("SAW-REALDIR"); return 0; }
            }
        }
        usleep(100000);
    }
    puts("STUCK");
    return 1;
}
"#;

#[test]
fn in_guest_cross_process_swap_shared_vs_mutant() {
    // Build the fork-only guest (no execve after fork, so the
    // in-guest backend's stage-1b exec refusal does not apply).
    let dir = std::env::temp_dir().join(format!("literoot-coh-ig-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/swap.c"), SWAP_GUEST_C).unwrap();
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(dir.join("swap"))
        .arg(dir.join("src/swap.c"))
        .output()
        .expect("cc");
    if !cc.status.success() {
        eprintln!("coherence-ig: cc unavailable — skipping");
        return;
    }
    let preload = preload_path();
    if !preload.exists() {
        // A silent skip here once hid a preload compile break:
        // fail loudly unless a human explicitly opted in.
        // Integration gates never set LITEROOT_ALLOW_SKIP_PRELOAD.
        if std::env::var("LITEROOT_ALLOW_SKIP_PRELOAD").as_deref() == Ok("1") {
            eprintln!("coherence-ig: preload not built — skipping (opt-in)");
            return;
        }
        panic!(
            "coherence-ig: preload not built at {} — build the preload \
             (cargo build -p literoot-preload --release) or set \
             LITEROOT_ALLOW_SKIP_PRELOAD=1 to skip explicitly",
            preload.display()
        );
    }
    let mk_root = |name: &str| -> String {
        let root = dir.join(name);
        for sub in ["bin", "lib64", "d1"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::copy(dir.join("swap"), root.join("bin/swap")).unwrap();
        for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
            std::fs::copy(format!("/lib64/{lib}"), root.join("lib64").join(lib)).unwrap();
        }
        std::fs::write(root.join("d1/file"), "from-d1\n").unwrap();
        let _ = std::fs::remove_file(root.join("link"));
        std::os::unix::fs::symlink("/d1", root.join("link")).unwrap();
        root.to_string_lossy().to_string()
    };
    let run = |root: &str, mutant: bool| -> String {
        let mut cmd = Command::new(literoot_bin());
        cmd.args(["--backend", "liteinst", "-r", root, "/bin/swap"])
            .env("LITEROOT_PRELOAD", &preload);
        if mutant {
            cmd.env("LITEROOT_PROBE_LOCAL", "1");
        }
        let out = cmd.output().expect("spawn in-guest swap");
        // Carry status + stderr into the assertion messages: a
        // failed launch (e.g. preload install refusal) must not
        // read as a coherence failure ("swap invisible").
        format!(
            "stdout={} status={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    };
    // Shared generation: swap must become visible.
    let shared = run(&mk_root("root-shared"), false);
    assert!(
        shared.contains("SAW-REALDIR"),
        "shared-gen in-guest swap invisible: {shared:?}"
    );
    // Forced-local mutant: each preload process has its own
    // generation, so the resolver's cached symlink kind is
    // never invalidated by the swapper — must stay stuck.
    // (If this ever passes, the test no longer discriminates.)
    let mutant = run(&mk_root("root-mutant"), true);
    assert!(
        mutant.contains("STUCK"),
        "mutant unexpectedly saw swap (test does not discriminate): {mutant:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
