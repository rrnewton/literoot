//! The in-guest preload either arms literoot in its image or stops the
//! program with a named error; it never lets the program run without
//! literoot.
//!
//! - Loaded with no literoot bootstrap (here: by LD_PRELOAD into a native
//!   scratch program), the preload refuses by name.
//! - The same holds when its file name cannot be resolved (an unlinked
//!   copy loaded through /proc/self/fd): whether it is the program itself
//!   is decided by load address, never by a file-system lookup that can
//!   fail.
//! - Under literoot's in-guest backends, each image that runs is armed: a
//!   child image reports whether a guest-only path resolves, which only an
//!   armed image can do. The rows include a parent that closes every
//!   inherited descriptor above 2 (close_range) before its exec, as daemons
//!   do. Each run either has an armed child or reports the exec's failure
//!   (today both in-guest backends refuse a guest execve with EOPNOTSUPP),
//!   and never an unarmed child; the outcome is printed for the record.
//!   This test is compiled only when the binary has the in-guest feature: a
//!   build without it (for example --no-default-features --features run)
//!   has no in-guest backend to arm, so the test is left out at compile
//!   time rather than skipped at run time.
//!
//! Fails when the preload has not been built (only an explicit
//! LITEROOT_ALLOW_SKIP_PRELOAD opt-in skips):
//!   cargo build --release --manifest-path preload/Cargo.toml

mod common;

use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use common::fixture_or_skip;
#[cfg(feature = "in-guest")]
use common::literoot_bin;
use common::resolve_preload;
use common::run_bounded;

const NO_BOOTSTRAP: &str = "literoot-preload: loaded without a literoot bootstrap";

const NATIVE_C: &str = r#"
#include <stdio.h>
int main(void) {
    puts("ran");
    return 0;
}
"#;

/// The image's armed test: /bin/arming-probe exists only in the rootfs, so
/// only an armed image, whose paths literoot translates, finds it.
#[cfg(feature = "in-guest")]
const GUEST_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

static const char *armed(void) {
    return access("/bin/arming-probe", X_OK) == 0 ? "armed" : "UNARMED";
}

int main(int argc, char **argv) {
    if (getenv("ARMING_PROBE_CHILD") != NULL) {
        printf("child %s\n", armed());
        return 0;
    }
    printf("parent %s\n", armed());
    setenv("ARMING_PROBE_CHILD", "1", 1);
    if (argc > 1 && strcmp(argv[1], "close") == 0) {
        long r = syscall(SYS_close_range, 3U, ~0U, 0U);
        if (r < 0) printf("close_range -1 errno %d\n", errno);
        else printf("close_range %ld\n", r);
    }
    fflush(stdout);
    char *args[] = { "/bin/arming-probe", NULL };
    execv(args[0], args);
    printf("execv -1 errno %d\n", errno);
    return 0;
}
"#;

fn preload_or_skip() -> Option<PathBuf> {
    let preload = resolve_preload();
    if preload.exists() {
        return Some(preload);
    }
    if std::env::var("LITEROOT_ALLOW_SKIP_PRELOAD").as_deref() == Ok("1") {
        eprintln!("preload-never-unarmed: preload not built, skipping (opt-in)");
        return None;
    }
    panic!(
        "preload-never-unarmed: preload not built at {} (cargo build --release \
         --manifest-path preload/Cargo.toml) or set LITEROOT_ALLOW_SKIP_PRELOAD=1",
        preload.display()
    );
}

fn cc(out: &Path, source: &str) -> Output {
    Command::new("cc")
        .args(["-O2", "-Wall", "-Werror", "-o"])
        .arg(out)
        .args(["-x", "c", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(source.as_bytes())?;
            child.wait_with_output()
        })
        .expect("cc is required to build the probes")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A child with no core file for its expected abort, and, with `fd`,
/// that descriptor inherited as descriptor 7.
fn native(probe: &Path, preload: &str, fd: Option<i32>) -> Command {
    extern "C" {
        fn setrlimit(resource: i32, rlim: *const [u64; 2]) -> i32;
        fn dup2(old: i32, new: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    const F_SETFD: i32 = 2;
    const RLIMIT_CORE: i32 = 4;
    let mut cmd = Command::new(probe);
    cmd.env("LD_PRELOAD", preload);
    unsafe {
        cmd.pre_exec(move || {
            if setrlimit(RLIMIT_CORE, &[0, 0]) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // dup2 onto itself would keep close-on-exec.
            let inherited = match fd {
                Some(7) => fcntl(7, F_SETFD, 0) == 0,
                Some(fd) => dup2(fd, 7) == 7,
                None => true,
            };
            if !inherited {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

fn assert_refused_by_name(what: &str, out: &Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.signal(),
        Some(6),
        "{what}: expected the preload's abort: {out:?}"
    );
    assert!(!stdout.contains("ran"), "{what}: the program ran: {out:?}");
    assert!(stderr.contains(NO_BOOTSTRAP), "{what}: {stderr:?}");
}

/// A scratch dir with the native probe built in it, or None to skip.
fn native_probe(name: &str) -> Option<(PathBuf, PathBuf)> {
    let dir = scratch(name);
    let probe = dir.join("probe");
    if !fixture_or_skip(&cc(&probe, NATIVE_C), "native probe") {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    Some((dir, probe))
}

#[test]
fn preload_without_a_bootstrap_refuses_by_name() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let Some((dir, probe)) = native_probe("preload-no-bootstrap") else {
        return;
    };
    let out = run_bounded(
        native(&probe, preload.to_str().unwrap(), None),
        "preload by path",
    );
    assert_refused_by_name("preload by path", &out);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn unresolvable_preload_name_still_refuses_by_name() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let Some((dir, probe)) = native_probe("preload-unlinked") else {
        return;
    };
    // An unlinked copy, open as descriptor 7: its name no longer resolves.
    let copy = dir.join("copy.so");
    std::fs::copy(&preload, &copy).unwrap();
    let file = std::fs::File::open(&copy).unwrap();
    std::fs::remove_file(&copy).unwrap();
    use std::os::fd::AsRawFd as _;
    let out = run_bounded(
        native(&probe, "/proc/self/fd/7", Some(file.as_raw_fd())),
        "unlinked preload",
    );
    drop(file);
    assert_refused_by_name("unlinked preload", &out);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The host's dynamic loader and C library, copied to the same paths in the
/// rootfs, so a dynamic guest runs there.
#[cfg(feature = "in-guest")]
fn copy_runtime(root: &Path) {
    for lib in [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib64/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/ld-linux-aarch64.so.1",
        "/lib64/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/libc.so.6",
    ] {
        let src = Path::new(lib);
        if src.exists() {
            let dst = root.join(lib.strip_prefix('/').unwrap());
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(src, dst).unwrap();
        }
    }
}

// Both rows (liteinst and trap) need the binary's in-guest backends.
#[cfg(feature = "in-guest")]
#[test]
fn every_in_guest_image_is_armed_or_refused_by_name() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = scratch("preload-armed-images");
    let root = dir.join("root");
    std::fs::create_dir_all(root.join("bin")).unwrap();
    if !fixture_or_skip(&cc(&root.join("bin/arming-probe"), GUEST_C), "guest probe") {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    assert!(
        !Path::new("/bin/arming-probe").exists(),
        "/bin/arming-probe exists on the host"
    );
    copy_runtime(&root);

    for backend in ["liteinst", "trap"] {
        for mode in ["exec", "close"] {
            let what = format!("{backend} {mode}");
            let mut cmd = Command::new(literoot_bin());
            cmd.args(["--backend", backend, "-r"])
                .arg(&root)
                .args(["/bin/arming-probe", mode])
                .env("LITEROOT_PRELOAD", &preload);
            let out = run_bounded(cmd, &what);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            eprintln!(
                "{what}: status {:?}; stdout {stdout:?}; stderr {:?}",
                out.status,
                stderr.lines().last().unwrap_or("")
            );
            assert!(
                stdout.starts_with("parent armed\n"),
                "{what}: the first image is not armed: {out:?}"
            );
            assert!(
                !stdout.contains("child UNARMED"),
                "{what}: a child image ran without literoot: {out:?}"
            );
            assert!(
                stdout.contains("child armed\n") || stdout.contains("execv -1 errno "),
                "{what}: neither an armed child nor the exec's failure: {out:?}"
            );
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Every hint that tells a user how to get the preload names a command that
/// works in this repository, where the preload is its own workspace at
/// preload/Cargo.toml; and a missing LITEROOT_PRELOAD stays refused by name.
/// src/tool.rs no longer has a preload-not-found hint: the embedded preload
/// replaced it, and an unreadable LITEROOT_PRELOAD is refused as
/// preload_missing (src/preload_materialize.rs, exercised end to end by
/// tests/install_preload_twin.sh N11). The hints left are build.rs's offline
/// fetch hint and the test-skip hints.
#[test]
fn preload_hints_name_this_repository_path() {
    let files: [(&str, &str); 6] = [
        ("src/tool.rs", include_str!("../src/tool.rs")),
        ("src/preload_materialize.rs", include_str!("../src/preload_materialize.rs")),
        ("build.rs", include_str!("../build.rs")),
        ("tests/backend_smoke.rs", include_str!("backend_smoke.rs")),
        ("tests/inguest_exec_translation.rs", include_str!("inguest_exec_translation.rs")),
        ("tests/probe_coherence.rs", include_str!("probe_coherence.rs")),
    ];
    for (name, text) in files {
        assert!(
            !text.contains("literoot/preload/Cargo.toml"),
            "{name}: names literoot/preload/Cargo.toml"
        );
        for line in text.lines().filter(|l| l.contains("cargo build -p literoot-preload")) {
            assert!(
                line.contains("--manifest-path preload/Cargo.toml"),
                "{name}: {line:?} cannot work from the repository root"
            );
        }
    }
    assert!(
        files[2].1.contains("--manifest-path preload/Cargo.toml"),
        "build.rs: the offline fetch hint"
    );
    assert!(
        files[1].1.contains(r#"("preload_missing", "LITEROOT_PRELOAD names no readable file")"#),
        "the named refusal for a missing preload"
    );
}
