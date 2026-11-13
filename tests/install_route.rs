//! Two calls a package install makes, on the ptrace backend: statfs on a
//! path (apt's free-space check) goes to the translated path, and fchown
//! under `-0` reports success as fchownat does (dpkg-deb's tar sets the
//! owner of the files it extracts). Native runs are the oracle.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

const GUEST_C: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/statfs.h>
#include <unistd.h>

static void say(const char *what, int r, int e) {
    if (r < 0) printf("%s -1 errno %d\n", what, e);
    else printf("%s %d\n", what, r);
}

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    const char *dir = argv[1];
    unsigned uid = (unsigned) strtoul(argv[2], 0, 10), gid = (unsigned) strtoul(argv[3], 0, 10);
    char path[4096];
    struct statfs sf;
    int r = statfs(dir, &sf), e = errno;
    say("statfs(dir)", r, e);
    if (r == 0) printf("statfs(dir) type %lx\n", (unsigned long) sf.f_type);
    snprintf(path, sizeof path, "%s/missing", dir);
    r = statfs(path, &sf); e = errno;
    say("statfs(dir/missing)", r, e);
    snprintf(path, sizeof path, "%s/file", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) return 3;
    r = fchown(fd, 0, 0); e = errno;
    say("fchown(root)", r, e);
    r = fchown(fd, uid, gid); e = errno;
    say("fchown(own)", r, e);
    close(fd);
    return 0;
}
"#;

fn real_ids() -> (u32, u32) {
    extern "C" {
        fn getuid() -> u32;
        fn getgid() -> u32;
    }
    unsafe { (getuid(), getgid()) }
}

fn own_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-install-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_guest(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("guest.c"), GUEST_C).unwrap();
    let bin = dir.join("guest");
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(dir.join("guest.c"))
        .output()
        .expect("cc is required to build the install guest");
    assert!(cc.status.success(), "cc failed: {cc:?}");
    bin
}

fn stdout(out: std::process::Output, what: &str) -> String {
    assert!(out.status.success(), "{what}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// The guest under literoot with `flags`, its work directory bound at `/w`
/// under `-r /`, so a path left untranslated names a missing host `/w`.
fn under_literoot(dir: &Path, guest: &Path, name: &str, flags: &[&str]) -> String {
    let work = dir.join(name);
    std::fs::create_dir(&work).unwrap();
    let (uid, gid) = real_ids();
    let mut cmd = Command::new(common::literoot_bin());
    cmd.args(flags)
        .args(["-r", "/", "-b"])
        .arg(format!("{}:/w", work.display()))
        .arg(guest)
        .args(["/w", &uid.to_string(), &gid.to_string()]);
    stdout(common::run_bounded(cmd, name), name)
}

#[test]
fn statfs_is_translated_and_fake_root_fchown_succeeds() {
    let (uid, gid) = real_ids();
    if uid == 0 {
        // Not a pass: root's real fchown succeeds, so the fake-root case
        // shows nothing.
        eprintln!("SKIPPED (real uid 0): fchown to root needs a non-root caller to differ");
        return;
    }
    let dir = own_dir("route");
    let guest = build_guest(&dir);

    let work = dir.join("native");
    std::fs::create_dir(&work).unwrap();
    let mut cmd = Command::new(&guest);
    cmd.arg(&work).args([uid.to_string(), gid.to_string()]);
    let native = stdout(common::run_bounded(cmd, "native"), "native");
    let fs_type = native
        .lines()
        .find_map(|l| l.strip_prefix("statfs(dir) type "))
        .expect("native statfs type")
        .to_string();
    assert_eq!(
        native,
        format!(
            "statfs(dir) 0\n\
             statfs(dir) type {fs_type}\n\
             statfs(dir/missing) -1 errno 2\n\
             fchown(root) -1 errno 1\n\
             fchown(own) 0\n"
        )
    );

    // Without -0 everything is the kernel's, on the translated path.
    assert_eq!(under_literoot(&dir, &guest, "plain", &[]), native);
    // Fake root: chown to root succeeds as it does through fchownat.
    assert_eq!(
        under_literoot(&dir, &guest, "fake-root", &["-0"]),
        native.replace("fchown(root) -1 errno 1", "fchown(root) 0")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
