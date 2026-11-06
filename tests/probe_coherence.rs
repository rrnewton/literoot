//! Probe-cache coherence across guest processes sharing one
//! rootfs (coord7 gate): process A replaces a symlink with a
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

fn sh(rootfs: &str, script: &str) -> std::process::Output {
    Command::new(literoot_bin())
        .args(["-r", rootfs, "-b", "/dev:/dev", "/bin/sh", "-c", script])
        .env("PATH", "/bin:/usr/bin")
        .output()
        .expect("spawn literoot sh")
}

#[test]
fn cross_process_symlink_swap_is_visible() {
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
