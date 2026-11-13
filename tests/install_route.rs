//! Calls a package install makes, on the ptrace backend: statfs on a path
//! (apt's free-space check) goes to the translated path; fchown (dpkg-deb's
//! tar sets the owner of the files it extracts) follows proot's fake_id0
//! rules; and a dirfd that reuses a closed number (rm's dup'd directory fd
//! under dpkg) resolves to its own directory. Native runs are the oracle.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

/// statfs cases: argv dir, dest. `dir/relative` is a symlink to `../dest`.
const STATFS_C: &str = r#"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/statfs.h>

static void say(const char *what, int r, int e) {
    if (r < 0) printf("%s -1 errno %d\n", what, e);
    else printf("%s %d\n", what, r);
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *dir = argv[1], *dest = argv[2];
    char path[4096];
    struct statfs sf, df;
    int r = statfs(dir, &sf), e = errno;
    say("statfs(dir)", r, e);
    if (r == 0) printf("statfs(dir) type %lx\n", (unsigned long) sf.f_type);
    snprintf(path, sizeof path, "%s/missing", dir);
    r = statfs(path, &sf); e = errno;
    say("statfs(dir/missing)", r, e);
    snprintf(path, sizeof path, "%s/file/x", dir);
    r = statfs(path, &sf); e = errno;
    say("statfs(dir/file/x)", r, e);
    r = statfs("", &sf); e = errno;
    say("statfs(empty)", r, e);
    snprintf(path, sizeof path, "%s/relative", dir);
    r = statfs(path, &sf); e = errno;
    say("statfs(dir/relative)", r, e);
    int rd = statfs(dest, &df);
    printf("statfs(dir/relative) is dest %d\n",
           r == 0 && rd == 0 && sf.f_type == df.f_type
               && memcmp(&sf.f_fsid, &df.f_fsid, sizeof sf.f_fsid) == 0);
    return 0;
}
"#;

/// fchown cases: argv dir, uid, gid. `other` is uid+1:gid+1 (the ids the
/// `-i` case fakes), `unrelated` uid+2:gid+2. setuid(other) comes last.
/// The kernel clears the set-ID bits on a successful chown, so the mode
/// after fchown(own) shows that the real call ran.
const FCHOWN_C: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void say(const char *what, long r, int e) {
    if (r < 0) printf("%s -1 errno %d\n", what, e);
    else printf("%s %ld\n", what, r);
}

static void one(const char *what, int fd, unsigned u, unsigned g) {
    long r = syscall(SYS_fchown, fd, u, g);
    say(what, r, errno);
}

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    const char *dir = argv[1];
    unsigned uid = (unsigned) strtoul(argv[2], 0, 10), gid = (unsigned) strtoul(argv[3], 0, 10);
    char path[4096];
    snprintf(path, sizeof path, "%s/file", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) return 3;
    one("fchown(badfd,root)", -1, 0, 0);
    one("fchown(badfd,-1,-1)", -1, -1, -1);
    one("fchown(root)", fd, 0, 0);
    fchmod(fd, 06755);
    one("fchown(own)", fd, uid, gid);
    struct stat st;
    fstat(fd, &st);
    printf("mode after fchown(own) %o\n", (unsigned) (st.st_mode & 07777));
    one("fchown(other)", fd, uid + 1, gid + 1);
    one("fchown(-1,other)", fd, -1, gid + 1);
    one("fchown(unrelated)", fd, uid + 2, gid + 2);
    long r = syscall(SYS_setuid, uid + 1);
    say("setuid(other)", r, errno);
    one("fchown(root) after setuid", fd, 0, 0);
    return 0;
}
"#;

/// Dirfds the fd table cannot name from its own records: argv dir, which
/// holds `lock`, `a/victim`, `b/victim` and an empty `c`.
/// 1. `lock` (a file) is opened as fd n and closed; `b` is dup'd onto n.
/// 2. `a` is opened as fd m and closed; `b` is dup'd onto m. A table that
///    still says m is `a` would unlink `a/victim` and report success.
/// 3. `c` is opened, then removed: a deleted directory.
/// 4. A pipe.
const STALE_FD_C: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int exists(const char *dir, const char *name) {
    char p[4096];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    return access(p, F_OK) == 0;
}

static void say(const char *what, int r, int e) {
    printf("%s %d errno %d\n", what, r, r < 0 ? e : 0);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char lock[4096], a[4096], b[4096], c[4096];
    snprintf(lock, sizeof lock, "%s/lock", argv[1]);
    snprintf(a, sizeof a, "%s/a", argv[1]);
    snprintf(b, sizeof b, "%s/b", argv[1]);
    snprintf(c, sizeof c, "%s/c", argv[1]);
    int fb = open(b, O_RDONLY | O_DIRECTORY);
    if (fb < 0) return 3;

    int fl = open(lock, O_RDONLY);
    if (fl < 0) return 3;
    close(fl);
    int d1 = fcntl(fb, F_DUPFD, 0);
    printf("1 dup took the file's number %d\n", d1 == fl);
    int f = openat(d1, "made1", O_WRONLY | O_CREAT | O_EXCL, 0644);
    say("1 openat(dup,made1)", f < 0 ? -1 : 0, errno);
    printf("1 b/made1 %d\n", exists(b, "made1"));

    int fa = open(a, O_RDONLY | O_DIRECTORY);
    if (fa < 0) return 3;
    close(fa);
    int d2 = fcntl(fb, F_DUPFD, 0);
    printf("2 dup took the directory's number %d\n", d2 == fa);
    int r = unlinkat(d2, "victim", 0);
    say("2 unlinkat(dup,victim)", r, errno);
    printf("2 a/victim %d b/victim %d\n", exists(a, "victim"), exists(b, "victim"));
    f = openat(d2, "made2", O_WRONLY | O_CREAT | O_EXCL, 0644);
    say("2 openat(dup,made2)", f < 0 ? -1 : 0, errno);
    printf("2 a/made2 %d b/made2 %d\n", exists(a, "made2"), exists(b, "made2"));

    int fc = open(c, O_RDONLY | O_DIRECTORY);
    if (fc < 0 || rmdir(c) != 0) return 3;
    r = unlinkat(fc, "x", 0);
    say("3 unlinkat(deleted,x)", r, errno);
    f = openat(fc, "x", O_WRONLY | O_CREAT, 0644);
    say("3 openat(deleted,x)", f < 0 ? -1 : 0, errno);

    int p[2];
    if (pipe(p) != 0) return 3;
    r = unlinkat(p[0], "x", 0);
    say("4 unlinkat(pipe,x)", r, errno);
    r = mkdirat(p[0], "x", 0755);
    say("4 mkdirat(pipe,x)", r, errno);
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

fn build_guest(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).unwrap();
    let bin = dir.join(name);
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc is required to build the install guest");
    assert!(cc.status.success(), "cc failed: {cc:?}");
    bin
}

fn stdout(out: std::process::Output, what: &str) -> String {
    assert!(out.status.success(), "{what}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// `guest` under literoot with `flags`, `work` bound at `/w` under `-r /`,
/// so a path left untranslated names a missing host `/w`.
fn under_literoot(work: &Path, guest: &Path, name: &str, flags: &[&str], args: &[&str]) -> String {
    let mut cmd = Command::new(common::literoot_bin());
    cmd.args(flags)
        .args(["-r", "/", "-b"])
        .arg(format!("{}:/w", work.display()))
        .arg(guest)
        .args(args);
    stdout(common::run_bounded(cmd, name), name)
}

fn run_native(guest: &Path, name: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(guest);
    cmd.args(args);
    stdout(common::run_bounded(cmd, name), name)
}

/// A work directory holding `file` and `relative -> ../dest`.
fn statfs_work(parent: &Path, name: &str) -> PathBuf {
    let work = parent.join(name);
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("file"), "x").unwrap();
    std::os::unix::fs::symlink("../dest", work.join("relative")).unwrap();
    work
}

#[test]
fn statfs_is_translated_and_keeps_native_errors() {
    let dir = own_dir("statfs");
    let guest = build_guest(&dir, "statfs", STATFS_C);

    // Natively `../dest` is a real directory next to the work directory.
    let nat = dir.join("native");
    let work = statfs_work(&nat, "w");
    let dest = nat.join("dest");
    std::fs::create_dir(&dest).unwrap();
    let native = run_native(
        &guest,
        "native",
        &[work.to_str().unwrap(), dest.to_str().unwrap()],
    );
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
             statfs(dir/file/x) -1 errno 20\n\
             statfs(empty) -1 errno 2\n\
             statfs(dir/relative) 0\n\
             statfs(dir/relative) is dest 1\n"
        )
    );

    // Under literoot `/dest` is a bind and nothing named `dest` sits next
    // to the work directory on the host, so the link resolves only through
    // the guest namespace.
    let dest = dir.join("bound-dest");
    std::fs::create_dir(&dest).unwrap();
    let dest_bind = format!("{}:/dest", dest.display());
    for (name, flags) in [
        ("plain", vec![]),
        ("fake-root", vec!["-0"]),
        ("fake-other", vec!["-i", "12345:23456"]),
    ] {
        let work = statfs_work(&dir.join(name), "w");
        assert!(!work.join("../dest").exists());
        let mut flags = flags;
        flags.extend(["-b", dest_bind.as_str()]);
        assert_eq!(
            under_literoot(&work, &guest, name, &flags, &["/w", "/dest"]),
            native,
            "{name}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The native output with each listed line replaced (the line must exist).
fn with_lines(native: &str, changes: &[(&str, &str)]) -> String {
    let mut out: Vec<String> = native.lines().map(str::to_string).collect();
    for (prefix, line) in changes {
        let at = out
            .iter()
            .position(|l| l.starts_with(&format!("{prefix} ")) || l == prefix)
            .unwrap_or_else(|| panic!("no {prefix} line in {native}"));
        out[at] = line.to_string();
    }
    out.join("\n") + "\n"
}

#[test]
fn fchown_follows_proots_fake_id_rules() {
    let (uid, gid) = real_ids();
    // A required failure, not a skip: as root the kernel grants every
    // chown, so none of the fake-id rules below would be exercised.
    assert_ne!(uid, 0, "this test needs a non-root caller");
    let dir = own_dir("fchown");
    let guest = build_guest(&dir, "fchown", FCHOWN_C);
    let (u, g) = (uid.to_string(), gid.to_string());
    let args = ["/w", u.as_str(), g.as_str()];

    let work = dir.join("native");
    std::fs::create_dir(&work).unwrap();
    let native = run_native(&guest, "native", &[work.to_str().unwrap(), &u, &g]);
    // The rows that need privilege are fixed; the group-only row depends
    // on this caller's supplementary groups, so it is only carried over.
    let other_gid = native
        .lines()
        .find(|l| l.starts_with("fchown(-1,other) "))
        .expect("fchown(-1,other) row")
        .to_string();
    assert_eq!(
        native,
        format!(
            "fchown(badfd,root) -1 errno 9\n\
             fchown(badfd,-1,-1) -1 errno 9\n\
             fchown(root) -1 errno 1\n\
             fchown(own) 0\n\
             mode after fchown(own) 755\n\
             fchown(other) -1 errno 1\n\
             {other_gid}\n\
             fchown(unrelated) -1 errno 1\n\
             setuid(other) -1 errno 1\n\
             fchown(root) after setuid -1 errno 1\n"
        )
    );

    let run = |name: &str, flags: &[&str]| {
        let work = dir.join(name);
        std::fs::create_dir(&work).unwrap();
        under_literoot(&work, &guest, name, flags, &args)
    };
    let own = format!("{uid}:{gid}");
    let other = format!("{}:{}", uid + 1, gid + 1);

    // Without fake ids, and with the caller's own ids (identity-only),
    // every row is the kernel's.
    assert_eq!(run("plain", &[]), native);
    assert_eq!(run("identity", &["-i", &own]), native);

    // Fake root: the kernel runs each call (a bad fd stays EBADF); its
    // permission errors become success while the fake euid is 0, and no
    // longer after setuid drops it.
    assert_eq!(
        run("fake-root", &["-0"]),
        with_lines(
            &native,
            &[
                ("fchown(root)", "fchown(root) 0"),
                ("fchown(other)", "fchown(other) 0"),
                ("fchown(-1,other)", "fchown(-1,other) 0"),
                ("fchown(unrelated)", "fchown(unrelated) 0"),
                ("setuid(other)", "setuid(other) 0"),
            ]
        )
    );

    // Other ids: requested ids equal to the fake real ids become the
    // caller's own, so chown to the fake ids succeeds; other ids do not.
    assert_eq!(
        run("fake-other", &["-i", &other]),
        with_lines(
            &native,
            &[
                ("fchown(other)", "fchown(other) 0"),
                ("fchown(-1,other)", "fchown(-1,other) 0"),
                ("setuid(other)", "setuid(other) 0"),
            ]
        )
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A work directory with `lock`, `a/victim`, `b/victim` and an empty `c`.
fn stale_fd_work(parent: &Path, name: &str) -> PathBuf {
    let work = parent.join(name);
    for d in ["a", "b"] {
        std::fs::create_dir_all(work.join(d)).unwrap();
        std::fs::write(work.join(d).join("victim"), "x").unwrap();
    }
    std::fs::create_dir(work.join("c")).unwrap();
    std::fs::write(work.join("lock"), "").unwrap();
    work
}

#[test]
fn a_dirfd_the_fd_table_cannot_name_resolves_to_its_own_file() {
    let dir = own_dir("stale-fd");
    let guest = build_guest(&dir, "stale", STALE_FD_C);
    let work = stale_fd_work(&dir, "native");
    let native = run_native(&guest, "native", &[work.to_str().unwrap()]);
    assert_eq!(
        native,
        "1 dup took the file's number 1\n\
         1 openat(dup,made1) 0 errno 0\n\
         1 b/made1 1\n\
         2 dup took the directory's number 1\n\
         2 unlinkat(dup,victim) 0 errno 0\n\
         2 a/victim 1 b/victim 0\n\
         2 openat(dup,made2) 0 errno 0\n\
         2 a/made2 0 b/made2 1\n\
         3 unlinkat(deleted,x) -1 errno 2\n\
         3 openat(deleted,x) -1 errno 2\n\
         4 unlinkat(pipe,x) -1 errno 20\n\
         4 mkdirat(pipe,x) -1 errno 20\n"
    );
    for (name, flags) in [("plain", vec![]), ("fake-root", vec!["-0"])] {
        let work = stale_fd_work(&dir, name);
        assert_eq!(
            under_literoot(&work, &guest, name, &flags, &["/w"]),
            native,
            "{name}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
