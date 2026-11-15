//! getcwd answers from the guest path, and no host byte reaches the
//! guest's buffer (https://github.com/rrnewton/literoot/issues/12).
//!
//! The probe fills each buffer with 0xA5, calls the raw getcwd syscall
//! and reports the result and how many bytes it may not have touched
//! changed ("dirty"): after a success, the bytes past the NUL; after a
//! failure, the whole buffer. Linux copies exactly the answer and its
//! NUL, and nothing at all on ERANGE (fs/d_path.c, getcwd).
//!
//! - `root`: cwd "/" in a 64-byte buffer. The guest root's host path is
//!   longer than 64 bytes; a chroot answers "/".
//! - `sub`: cwd "/sub" in a 4096-byte buffer: "/sub", and every byte
//!   after its NUL still 0xA5, so none of the host path is left there.
//! - `bind-erange`: the cwd is a bind whose guest path is longer than
//!   its host path, in a buffer that holds the host path but not the
//!   guest one: ERANGE, and the buffer untouched.
//! - `exact`: cwd "/sub" in a 5-byte buffer, which fits "/sub" and its
//!   NUL exactly, though not the host path.

mod common;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use common::fixture_or_skip;
use common::literoot_bin;
use common::run_bounded;

const PROBE_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static char buf[4096];

static void probe(const char *name, const char *dir, size_t cap, size_t size) {
    if (chdir(dir) != 0) {
        printf("%s chdir errno %d\n", name, errno);
        return;
    }
    memset(buf, 0xA5, sizeof buf);
    errno = 0;
    long rc = syscall(SYS_getcwd, buf, size);
    int e = errno;
    size_t from = rc > 0 ? (size_t) rc : 0, dirty = 0;
    for (size_t i = from; i < cap; i++)
        dirty += (unsigned char) buf[i] != 0xA5;
    if (rc > 0)
        printf("%s rc %ld path %s dirty %zu\n", name, rc, buf, dirty);
    else
        printf("%s rc %ld errno %d dirty %zu\n", name, rc, e, dirty);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    probe("root", "/", 64, 64);
    probe("sub", "/sub", sizeof buf, sizeof buf);
    probe("bind-erange", argv[1], sizeof buf, (size_t) atol(argv[2]));
    probe("exact", "/sub", sizeof buf, 5);
    return 0;
}
"#;

struct Fixture {
    scratch: PathBuf,
    root: PathBuf,
    bind_host: PathBuf,
    bind_guest: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// A rootfs whose host path is longer than 64 bytes, with /sub, a short
/// host directory to bind, and the probe built with `cc_flags`.
/// `None` is a skip, never a pass.
fn fixture(label: &str, cc_flags: &[&str]) -> Option<Fixture> {
    let scratch =
        std::env::temp_dir().join(format!("literoot-getcwd-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    // An 80-byte component keeps the root's host path past 64 bytes
    // wherever the temporary directory is.
    let root = scratch.join("r".repeat(80)).join("root");
    let bind_host = scratch.join("b");
    for d in [&root.join("bin"), &root.join("sub"), &bind_host] {
        std::fs::create_dir_all(d).unwrap();
    }
    let fx = Fixture {
        bind_host: bind_host.canonicalize().unwrap(),
        root: root.canonicalize().unwrap(),
        scratch,
        // Six 50-byte components: 306 bytes, longer than the bind's host
        // path (asserted below).
        bind_guest: (0..6).map(|i| format!("/{i}{}", "g".repeat(49))).collect(),
    };
    let built = Command::new("cc")
        .args(["-O2", "-Wall", "-Werror"])
        .args(cc_flags)
        .arg("-o")
        .arg(fx.root.join("bin/probe"))
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(PROBE_C.as_bytes())?;
            child.wait_with_output()
        })
        .expect("cc is required to build the probe");
    if !fixture_or_skip(&built, &format!("getcwd probe ({label})")) {
        return None;
    }
    let host_len = fx.root.as_os_str().len();
    assert!(
        host_len > 64,
        "the root's host path is {host_len} bytes, not > 64"
    );
    let bind_len = fx.bind_host.as_os_str().len();
    assert!(
        fx.bind_guest.len() > bind_len + 1,
        "the bind's guest path ({}) must be longer than its host path ({bind_len}) plus its NUL",
        fx.bind_guest.len()
    );
    Some(fx)
}

/// Launch the probe and compare its report with Linux's answers.
fn check(fx: &Fixture, backend: &str, preload: Option<&Path>) {
    // A buffer that holds the bind's host path and NUL, but not its
    // guest path: Linux has nothing to write, so ERANGE.
    let bind_size = fx.bind_host.as_os_str().len() + 1;
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["--backend", backend])
        .arg("-r")
        .arg(&fx.root)
        .arg("-b")
        .arg(format!("{}:{}", fx.bind_host.display(), fx.bind_guest))
        .arg("/bin/probe")
        .arg(&fx.bind_guest)
        .arg(bind_size.to_string());
    if let Some(preload) = preload {
        cmd.env("LITEROOT_PRELOAD", preload);
    }
    let out = run_bounded(cmd, backend);
    assert!(out.status.success(), "{backend}: {out:?}");
    let got: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let want = [
        "root rc 2 path / dirty 0",
        "sub rc 5 path /sub dirty 0",
        "bind-erange rc -1 errno 34 dirty 0",
        "exact rc 5 path /sub dirty 0",
    ];
    assert_eq!(
        got,
        want,
        "{backend}: stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn getcwd_writes_only_the_guest_path_ptrace() {
    let Some(fx) = fixture("ptrace", &["-static"]) else {
        return;
    };
    check(&fx, "ptrace", None);
}

/// The in-guest backends run the same Tool code inside the guest, with
/// a dynamic probe (the in-guest runtime loads through the dynamic
/// loader), so the rootfs gets the host's libc and loader.
#[cfg(target_arch = "x86_64")]
#[test]
fn getcwd_writes_only_the_guest_path_inguest() {
    let preload = common::resolve_preload();
    if !preload.exists() {
        // As in inguest_exec_translation: fail unless a human opted in.
        if std::env::var("LITEROOT_ALLOW_SKIP_PRELOAD").as_deref() == Ok("1") {
            eprintln!("getcwd in-guest: preload not built: SKIP (opt-in, not a pass)");
            return;
        }
        panic!(
            "getcwd in-guest: preload not built at {}; build it or set \
             LITEROOT_ALLOW_SKIP_PRELOAD=1 to skip explicitly",
            preload.display()
        );
    }
    for backend in ["trap", "liteinst"] {
        let Some(fx) = fixture(backend, &[]) else {
            return;
        };
        std::fs::create_dir_all(fx.root.join("lib64")).unwrap();
        for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
            std::fs::copy(
                Path::new("/lib64").join(lib),
                fx.root.join("lib64").join(lib),
            )
            .unwrap_or_else(|e| panic!("copy /lib64/{lib}: {e}"));
        }
        check(&fx, backend, Some(&preload));
    }
}
