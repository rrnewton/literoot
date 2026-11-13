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

/// Every reader of the fd table, and fds or a cwd with no guest path:
/// argv dir. In the work directory: b/b1, b/b2, `c4 (deleted)/victim`,
/// `e (deleted)/victim`, and `a` whose `v/bound/marker` (content "m") and
/// `child` exist natively but are binds under literoot, so `a/v` is a
/// virtual bind-prefix directory there.
const FD_READERS_C: &str = r#"
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void say(const char *what, long r, int e) {
    printf("%s %ld errno %d\n", what, r < 0 ? -1L : r, r < 0 ? e : 0);
}

static int exists(const char *p) { return access(p, F_OK) == 0; }

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *) a, *(char *const *) b);
}

/* Open `a` (the fd table records it), close it, and dup `fb` onto the
 * same number: a number whose entry still names `a`. */
static int stale(const char *a, int fb) {
    int x = open(a, O_RDONLY | O_DIRECTORY);
    close(x);
    int d = fcntl(fb, F_DUPFD, 0);
    return d == x ? d : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *dir = argv[1];
    char p[4096], q[4096], buf[256];
    long r;

    /* 5: a virtual bind-prefix directory fd, then a bound child through it. */
    snprintf(p, sizeof p, "%s/a/v", dir);
    int dv = open(p, O_RDONLY | O_DIRECTORY);
    say("5 open(a/v)", dv < 0 ? -1 : 0, errno);
    int fm = openat(dv, "bound/marker", O_RDONLY);
    memset(buf, 0, sizeof buf);
    r = fm < 0 ? -1 : read(fm, buf, sizeof buf - 1);
    printf("5 openat(a/v,bound/marker) %s\n", r > 0 ? buf : "-");
    struct stat st;
    r = fstatat(dv, "bound/marker", &st, 0);
    printf("5 fstatat(a/v,bound/marker) %ld size %ld\n", r, r == 0 ? (long) st.st_size : -1L);

    /* 6-8: numbers whose table entry is `a`, now holding `b`. Each reader
     * gets its own fresh number, so no earlier call has corrected the
     * entry (openat's passthrough check records what it finds). */
    snprintf(p, sizeof p, "%s/a", dir);
    snprintf(q, sizeof q, "%s/b", dir);
    int fb = open(q, O_RDONLY | O_DIRECTORY);
    if (fb < 0) return 3;
    int fa = open(p, O_RDONLY | O_DIRECTORY);
    close(fa);
    int dd = fcntl(fb, F_DUPFD, 0);
    printf("6 dup took a's number %d\n", dd == fa);
    r = openat(dd, "v", O_RDONLY | O_DIRECTORY);
    say("6 openat(dup,v)", r, errno);
    struct statx sx;
    r = syscall(SYS_statx, stale(p, fb), "v", 0, STATX_BASIC_STATS, &sx);
    say("6 statx(dup,v)", r, errno);
    int dg = stale(p, fb);
    char *names[64]; int n = 0;
    char dbuf[4096];
    for (;;) {
        long got = syscall(SYS_getdents64, dg, dbuf, sizeof dbuf);
        if (got <= 0) break;
        for (long off = 0; off < got;) {
            struct dirent64 *de = (struct dirent64 *) (dbuf + off);
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") && n < 64)
                names[n++] = strdup(de->d_name);
            off += de->d_reclen;
        }
    }
    qsort(names, n, sizeof names[0], cmp);
    printf("7 getdents(dup)");
    for (int i = 0; i < n; i++) printf(" %s", names[i]);
    printf("\n");
    r = fchdir(stale(p, fb));
    say("8 fchdir(dup)", r, errno);
    r = openat(AT_FDCWD, "made5", O_WRONLY | O_CREAT | O_EXCL, 0644);
    say("8 openat(cwd,made5)", r < 0 ? -1 : 0, errno);
    snprintf(p, sizeof p, "%s/b/made5", dir); snprintf(q, sizeof q, "%s/a/made5", dir);
    printf("8 b/made5 %d a/made5 %d\n", exists(p), exists(q));

    /* 9: fchdir into a deleted directory, then chdir("..") out of it. */
    if (chdir(dir) != 0) return 3;
    mkdir("c3", 0700);
    int d3 = open("c3", O_RDONLY | O_DIRECTORY);
    if (d3 < 0 || rmdir("c3") != 0) return 3;
    r = fchdir(d3);
    say("9 fchdir(deleted)", r, errno);
    r = openat(AT_FDCWD, "made", O_WRONLY | O_CREAT | O_EXCL, 0644);
    say("9 openat(cwd,made)", r < 0 ? -1 : 0, errno);
    r = getcwd(buf, sizeof buf) ? 0 : -1;
    say("9 getcwd", r, errno);
    r = chdir("..");
    say("9 chdir(..)", r, errno);
    r = openat(AT_FDCWD, "made4", O_WRONLY | O_CREAT | O_EXCL, 0644);
    say("9 openat(cwd,made4)", r < 0 ? -1 : 0, errno);
    snprintf(p, sizeof p, "%s/made4", dir); snprintf(q, sizeof q, "%s/made", dir);
    printf("9 made4 %d made %d\n", exists(p), exists(q));

    /* 10: empty paths keep their own rules. */
    int fr = open("reg", O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fr < 0 || unlink("reg") != 0) return 3;
    r = readlinkat(fr, "", buf, sizeof buf);
    say("10 readlinkat(deleted-regular,\"\")", r, errno);
    if (symlink("target", "lnk") != 0) return 3;
    int fl = open("lnk", O_PATH | O_NOFOLLOW);
    memset(buf, 0, sizeof buf);
    r = readlinkat(fl, "", buf, sizeof buf - 1);
    printf("10 readlinkat(O_PATH-symlink,\"\") %ld %s\n", r, r > 0 ? buf : "-");
    r = open("lnk", O_RDONLY | O_NOFOLLOW);
    say("10 open(lnk,O_NOFOLLOW)", r < 0 ? -1 : 0, errno);
    r = mkdirat(d3, "", 0755);
    say("10 mkdirat(deleted-dir,\"\")", r, errno);

    /* 11: a deleted directory whose /proc text names a real directory. */
    mkdir("c4", 0700);
    int d4 = open("c4", O_RDONLY | O_DIRECTORY);
    if (d4 < 0 || rmdir("c4") != 0) return 3;
    r = unlinkat(d4, "victim", 0);
    say("11 unlinkat(deleted,victim)", r, errno);
    printf("11 c4 (deleted)/victim %d\n", exists("c4 (deleted)/victim"));

    /* 12: a live directory whose name ends in " (deleted)". */
    int fe = open("e (deleted)", O_RDONLY | O_DIRECTORY);
    r = unlinkat(fe, "victim", 0);
    say("12 unlinkat(live-e,victim)", r, errno);
    printf("12 e (deleted)/victim %d\n", exists("e (deleted)/victim"));
    return 0;
}
"#;

/// A thread with a private fd table: argv dir, holding a/victim, b/victim,
/// a/victim2, b/victim2. The leader opens `a` as fd n; the worker unshares
/// its fd table, closes n and opens `b`, which takes n in its table only.
const FD_THREAD_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

static const char *dir;
static int fa;

static int exists(const char *d, const char *n) {
    char p[4096];
    snprintf(p, sizeof p, "%s/%s/%s", dir, d, n);
    return access(p, F_OK) == 0;
}

static void *worker(void *arg) {
    (void) arg;
    char b[4096];
    snprintf(b, sizeof b, "%s/b", dir);
    if (unshare(CLONE_FILES) != 0) { printf("unshare failed %d\n", errno); return 0; }
    close(fa);
    int fb = open(b, O_RDONLY | O_DIRECTORY);
    printf("worker b took the leader's number %d\n", fb == fa);
    int r = unlinkat(fb, "victim", 0);
    printf("worker unlinkat(n,victim) %d errno %d\n", r, r ? errno : 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    dir = argv[1];
    char a[4096];
    snprintf(a, sizeof a, "%s/a", dir);
    fa = open(a, O_RDONLY | O_DIRECTORY);
    if (fa < 0) return 3;
    pthread_t t;
    if (pthread_create(&t, 0, worker, 0) != 0) return 3;
    pthread_join(t, 0);
    printf("a/victim %d b/victim %d\n", exists("a", "victim"), exists("b", "victim"));
    int r = unlinkat(fa, "victim2", 0);
    printf("leader unlinkat(n,victim2) %d errno %d\n", r, r ? errno : 0);
    printf("a/victim2 %d b/victim2 %d\n", exists("a", "victim2"), exists("b", "victim2"));
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
        .args(["-O2", "-pthread", "-o"])
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

/// The work directory for FD_READERS_C. `native` puts a/v/bound/marker and
/// a/child in place; under literoot they come from binds.
fn fd_readers_work(parent: &Path, name: &str, native: bool) -> PathBuf {
    let work = parent.join(name);
    for d in ["a", "b", "c4 (deleted)", "e (deleted)"] {
        std::fs::create_dir_all(work.join(d)).unwrap();
    }
    std::fs::write(work.join("b/b1"), "").unwrap();
    std::fs::write(work.join("b/b2"), "").unwrap();
    std::fs::write(work.join("c4 (deleted)/victim"), "").unwrap();
    std::fs::write(work.join("e (deleted)/victim"), "").unwrap();
    if native {
        std::fs::create_dir_all(work.join("a/v/bound")).unwrap();
        std::fs::write(work.join("a/v/bound/marker"), "m").unwrap();
        std::fs::create_dir_all(work.join("a/child")).unwrap();
    }
    work
}

#[test]
fn every_fd_table_reader_and_unnamed_fds_and_cwds_match_native() {
    let dir = own_dir("fd-readers");
    let guest = build_guest(&dir, "readers", FD_READERS_C);
    let work = fd_readers_work(&dir, "native", true);
    let native = run_native(&guest, "native", &[work.to_str().unwrap()]);
    assert_eq!(
        native,
        "5 open(a/v) 0 errno 0\n\
         5 openat(a/v,bound/marker) m\n\
         5 fstatat(a/v,bound/marker) 0 size 1\n\
         6 dup took a's number 1\n\
         6 openat(dup,v) -1 errno 2\n\
         6 statx(dup,v) -1 errno 2\n\
         7 getdents(dup) b1 b2\n\
         8 fchdir(dup) 0 errno 0\n\
         8 openat(cwd,made5) 0 errno 0\n\
         8 b/made5 1 a/made5 0\n\
         9 fchdir(deleted) 0 errno 0\n\
         9 openat(cwd,made) -1 errno 2\n\
         9 getcwd -1 errno 2\n\
         9 chdir(..) 0 errno 0\n\
         9 openat(cwd,made4) 0 errno 0\n\
         9 made4 1 made 0\n\
         10 readlinkat(deleted-regular,\"\") -1 errno 2\n\
         10 readlinkat(O_PATH-symlink,\"\") 6 target\n\
         10 open(lnk,O_NOFOLLOW) -1 errno 40\n\
         10 mkdirat(deleted-dir,\"\") -1 errno 2\n\
         11 unlinkat(deleted,victim) -1 errno 2\n\
         11 c4 (deleted)/victim 1\n\
         12 unlinkat(live-e,victim) 0 errno 0\n\
         12 e (deleted)/victim 0\n"
    );
    // Under literoot a/v/bound and a/child are binds, so a/v is a virtual
    // bind-prefix directory and a/child is a synthetic entry of a.
    let bound = dir.join("bound-v");
    std::fs::create_dir(&bound).unwrap();
    std::fs::write(bound.join("marker"), "m").unwrap();
    let child = dir.join("bound-child");
    std::fs::create_dir(&child).unwrap();
    let binds = [
        format!("{}:/w/a/v/bound", bound.display()),
        format!("{}:/w/a/child", child.display()),
    ];
    for (name, mode) in [("plain", vec![]), ("fake-root", vec!["-0"])] {
        let work = fd_readers_work(&dir, name, false);
        let mut flags = mode;
        for b in &binds {
            flags.extend(["-b", b.as_str()]);
        }
        assert_eq!(
            under_literoot(&work, &guest, name, &flags, &["/w"]),
            native,
            "{name}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_thread_with_its_own_fd_table_resolves_its_own_fds() {
    let dir = own_dir("fd-thread");
    let guest = build_guest(&dir, "thread", FD_THREAD_C);
    let setup = |name: &str| {
        let work = dir.join(name);
        for d in ["a", "b"] {
            std::fs::create_dir_all(work.join(d)).unwrap();
            for v in ["victim", "victim2"] {
                std::fs::write(work.join(d).join(v), "").unwrap();
            }
        }
        work
    };
    let work = setup("native");
    let native = run_native(&guest, "native", &[work.to_str().unwrap()]);
    assert_eq!(
        native,
        "worker b took the leader's number 1\n\
         worker unlinkat(n,victim) 0 errno 0\n\
         a/victim 1 b/victim 0\n\
         leader unlinkat(n,victim2) 0 errno 0\n\
         a/victim2 0 b/victim2 1\n"
    );
    for (name, flags) in [("plain", vec![]), ("fake-root", vec!["-0"])] {
        let work = setup(name);
        assert_eq!(
            under_literoot(&work, &guest, name, &flags, &["/w"]),
            native,
            "{name}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
