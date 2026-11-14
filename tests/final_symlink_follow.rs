//! fchownat follows a final symlink through the guest root, never the
//! host's. A static guest in a scratch rootfs chowns, to the caller's own
//! ids, through symlinks whose absolute targets name paths that exist on
//! one side only:
//!
//! - `/abs` holds the absolute host path of a file outside the rootfs.
//!   Through the guest root that path does not exist, so following it is
//!   ENOENT, and the host file is untouched (its ctime, which every
//!   successful chown updates, stays the same);
//! - `/twin` holds `/twin-dir/target`, which exists only inside the
//!   rootfs: following it reaches that file and clears its set-ID bits;
//! - `/rel` holds a relative target beside it, followed the same way.
//!
//! With AT_SYMLINK_NOFOLLOW the call changes the link itself; an invalid
//! flag stays the kernel's EINVAL.

mod common;

use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use common::fixture_or_skip;
use common::literoot_bin;
use common::run_bounded;

const PROBE_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static void res(const char *what, long r) {
    if (r < 0) printf("%s -1 errno %d\n", what, errno);
    else printf("%s %ld\n", what, r);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    long u = atol(argv[1]), g = atol(argv[2]);
    res("fchownat(abs,0)", syscall(SYS_fchownat, AT_FDCWD, "/abs", u, g, 0L));
    res("fchownat(abs,nofollow)",
        syscall(SYS_fchownat, AT_FDCWD, "/abs", u, g, (long) AT_SYMLINK_NOFOLLOW));
    res("fchownat(twin,0)", syscall(SYS_fchownat, AT_FDCWD, "/twin", u, g, 0L));
    res("fchownat(rel,0)", syscall(SYS_fchownat, AT_FDCWD, "/rel", u, g, 0L));
    res("fchownat(rel,bad)", syscall(SYS_fchownat, AT_FDCWD, "/rel", u, g, 1L));
#ifdef SYS_chown
    res("chown(abs)", syscall(SYS_chown, "/abs", u, g));
#endif
    return 0;
}
"#;

/// (uid, gid, ctime seconds, ctime nanoseconds) without following.
fn stamp(path: &Path) -> (u32, u32, i64, i64) {
    let m = std::fs::symlink_metadata(path).unwrap();
    (m.uid(), m.gid(), m.ctime(), m.ctime_nsec())
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn fchownat_follows_a_final_symlink_through_the_guest_root() {
    let scratch = std::env::temp_dir().join(format!(
        "literoot-final-symlink-follow-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    let host = scratch.join("host");
    let root = scratch.join("root");
    for d in [&host, &root.join("bin"), &root.join("twin-dir")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let probe = root.join("bin/probe");
    let built = Command::new("cc")
        .args(["-O2", "-Wall", "-Werror", "-static", "-o"])
        .arg(&probe)
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
    if !fixture_or_skip(&built, "static fchownat probe") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }

    // The host file outside the rootfs, and the absolute guest path of the
    // twin, which must not exist on the host.
    let target = host.join("target");
    std::fs::write(&target, "host").unwrap();
    let target = target.canonicalize().unwrap();
    assert!(
        std::fs::symlink_metadata(root.join(target.strip_prefix("/").unwrap())).is_err(),
        "the host target's path must not exist inside the rootfs"
    );
    assert!(
        std::fs::symlink_metadata("/twin-dir").is_err(),
        "/twin-dir exists on the host"
    );
    std::os::unix::fs::symlink(&target, root.join("abs")).unwrap();
    std::os::unix::fs::symlink("/twin-dir/target", root.join("twin")).unwrap();
    std::os::unix::fs::symlink("rel-target", root.join("rel")).unwrap();
    std::fs::write(root.join("twin-dir/target"), "twin").unwrap();
    std::fs::write(root.join("rel-target"), "rel").unwrap();

    let (uid, gid) = {
        let m = std::fs::metadata(&scratch).unwrap();
        (m.uid(), m.gid())
    };
    assert_ne!(uid, 0, "this test needs a non-root caller");
    let mut want = vec![
        "fchownat(abs,0) -1 errno 2".to_string(),
        "fchownat(abs,nofollow) 0".to_string(),
        "fchownat(twin,0) 0".to_string(),
        "fchownat(rel,0) 0".to_string(),
        "fchownat(rel,bad) -1 errno 22".to_string(),
    ];
    if cfg!(target_arch = "x86_64") {
        want.push("chown(abs) -1 errno 2".to_string());
    }

    // Without fake ids, and with fake ids that are not root (they reach
    // the kernel's call too).
    let other = format!("{}:{}", uid + 1, gid + 1);
    for (name, flags) in [
        ("plain", vec![]),
        ("fake-other", vec!["-i", other.as_str()]),
    ] {
        set_mode(&root.join("twin-dir/target"), 0o6755);
        set_mode(&root.join("rel-target"), 0o6755);
        let host_before = stamp(&target);
        let abs_before = stamp(&root.join("abs"));
        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut cmd = Command::new(literoot_bin());
        cmd.args(&flags)
            .arg("-r")
            .arg(&root)
            .arg("/bin/probe")
            .args([uid.to_string(), gid.to_string()]);
        let out = run_bounded(cmd, name);
        assert!(out.status.success(), "{name}: {out:?}");
        let got: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(got, want, "{name}");

        assert_eq!(stamp(&target), host_before, "{name}: the host file changed");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "host", "{name}");
        assert_ne!(
            stamp(&root.join("abs")),
            abs_before,
            "{name}: NOFOLLOW did not reach the link"
        );
        // A chown by the owner clears the set-ID bits of what it reached.
        assert_eq!(mode(&root.join("twin-dir/target")), 0o755, "{name}: twin");
        assert_eq!(mode(&root.join("rel-target")), 0o755, "{name}: rel-target");
    }
    std::fs::remove_dir_all(&scratch).unwrap();
}
