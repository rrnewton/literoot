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

/// Fd-number state per fd table, closed fds, and the readers that recover a
/// virtual directory's name (argv dir, the fd-readers layout: under literoot
/// `a/v` is a virtual bind-prefix directory over the bind `a/v/bound`, and
/// `a/child` is a bind under the real directory `a`).
const FD_TABLES_C: &str = r#"
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *dir;
static int nv, fb;

static void say(const char *what, long r, int e) {
    printf("%s %ld errno %d\n", what, r < 0 ? -1L : r, r < 0 ? e : 0);
}

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *) a, *(char *const *) b);
}

/* Every name getdents64 returns on fd (buffer of size bufsz), sorted,
 * without "." and "..". */
static void list(const char *what, int fd, size_t bufsz) {
    char *names[64]; int n = 0;
    char buf[4096];
    for (;;) {
        long got = syscall(SYS_getdents64, fd, buf, bufsz);
        if (got <= 0) break;
        for (long off = 0; off < got;) {
            struct dirent64 *de = (struct dirent64 *) (buf + off);
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") && n < 64)
                names[n++] = strdup(de->d_name);
            off += de->d_reclen;
        }
    }
    qsort(names, n, sizeof names[0], cmp);
    printf("%s", what);
    for (int i = 0; i < n; i++) printf(" %s", names[i]);
    printf("\n");
}

/* Read entries one small buffer at a time until `want` names (counting
 * "." and "..") arrived; returns how many did. */
static int partial(int fd, int want) {
    char buf[32];
    int seen = 0;
    while (seen < want) {
        long got = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (got <= 0) break;
        for (long off = 0; off < got;) {
            off += ((struct dirent64 *) (buf + off))->d_reclen;
            seen++;
        }
    }
    return seen;
}

static void read_marker(const char *what, int dfd, const char *rel) {
    char buf[64] = {0};
    int f = openat(dfd, rel, O_RDONLY);
    long r = f < 0 ? -1 : read(f, buf, sizeof buf - 1);
    if (f >= 0) close(f);
    printf("%s %s\n", what, r > 0 ? buf : "-");
}

/* R5: a private table invalidates its own number, not the leader's. */
static void *worker_getdents(void *arg) {
    (void) arg;
    if (unshare(CLONE_FILES) != 0) return 0;
    dup2(fb, nv);
    list("r5 worker getdents(n)", nv, 4096);
    return 0;
}

static void *worker_open(void *arg) {
    (void) arg;
    char b[4096];
    snprintf(b, sizeof b, "%s/b", dir);
    if (unshare(CLONE_FILES) != 0) return 0;
    close(nv);
    int x = open(b, O_RDONLY | O_DIRECTORY);
    printf("r5 worker2 b took n %d\n", x == nv);
    return 0;
}

static void *worker_fstatat(void *arg) {
    (void) arg;
    struct stat st;
    if (unshare(CLONE_FILES) != 0) return 0;
    dup2(fb, nv);
    long r = fstatat(nv, "b1", &st, 0);
    say("r7 worker3 fstatat(n,b1)", r, errno);
    return 0;
}

static void run(void *(*fn)(void *)) {
    pthread_t t;
    if (pthread_create(&t, 0, fn, 0) == 0) pthread_join(t, 0);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    dir = argv[1];
    char p[4096];
    long r;
    snprintf(p, sizeof p, "%s/a/v", dir);
    nv = open(p, O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/b", dir);
    fb = open(p, O_RDONLY | O_DIRECTORY);
    if (nv < 0 || fb < 0) return 3;

    run(worker_getdents);
    read_marker("r5 leader openat(n,bound/marker)", nv, "bound/marker");
    list("r5 leader getdents(n)", nv, 4096);
    run(worker_open);
    read_marker("r5 leader2 openat(n,bound/marker)", nv, "bound/marker");

    /* R7 mc, threaded: the worker's passthrough must not rename the
     * leader's number. */
    run(worker_fstatat);
    r = fchdir(nv);
    say("r7 leader fchdir(n)", r, errno);
    read_marker("r7 leader open(bound/marker)", AT_FDCWD, "bound/marker");
    if (chdir(dir) != 0) return 3;

    /* R7 mc, one table: the number's path record says b while it holds the
     * virtual directory again (a dup of a second fd on it). */
    snprintf(p, sizeof p, "%s/a/v", dir);
    int n2 = open(p, O_RDONLY | O_DIRECTORY);
    int x2 = open(p, O_RDONLY | O_DIRECTORY);
    struct stat st;
    dup2(fb, n2);
    r = fstatat(n2, "b1", &st, 0);
    say("r7 fstatat(dup-b,b1)", r, errno);
    dup2(x2, n2);
    r = fchdir(n2);
    say("r7 fchdir(dup-v)", r, errno);
    read_marker("r7 open(bound/marker)", AT_FDCWD, "bound/marker");
    if (chdir(dir) != 0) return 3;

    /* R7 mq: a closed dirfd keeps the kernel's EBADF; a duplicate the fd
     * table never saw still resolves through its bind. */
    snprintf(p, sizeof p, "%s/b", dir);
    int d = open(p, O_RDONLY | O_DIRECTORY);
    close(d);
    r = openat(d, "x", O_RDONLY);
    say("r7 closed openat(d,x)", r, errno);
    snprintf(p, sizeof p, "%s/a", dir);
    int fa = open(p, O_RDONLY | O_DIRECTORY);
    int hi = dup2(fa, 900);
    r = openat(hi, "child", O_RDONLY | O_DIRECTORY);
    say("r7 uncached-dup openat(900,child)", r < 0 ? -1 : 0, errno);

    /* R6: a closed virtual fd and a closed or replaced number with
     * enumeration state are the kernel's. */
    snprintf(p, sizeof p, "%s/a/v", dir);
    int cv = open(p, O_RDONLY | O_DIRECTORY);
    close(cv);
    char buf[256];
    r = syscall(SYS_getdents64, cv, buf, sizeof buf);
    say("r6 closed-virtual getdents", r, errno);
    snprintf(p, sizeof p, "%s/a", dir);
    int dp = open(p, O_RDONLY | O_DIRECTORY);
    printf("r6 partial read %d\n", partial(dp, 3));
    close(dp);
    r = syscall(SYS_getdents64, dp, buf, sizeof buf);
    say("r6 closed-pending getdents", r, errno);
    int dq = open(p, O_RDONLY | O_DIRECTORY);
    printf("r6 partial read %d\n", partial(dq, 3));
    snprintf(p, sizeof p, "%s/b", dir);
    int fb2 = open(p, O_RDONLY | O_DIRECTORY);
    dup2(fb2, dq);
    list("r6 dup-onto-pending getdents", dq, 4096);
    return 0;
}
"#;

/// Directory streams: listing progress belongs to the open file description
/// (R9: shared by the two tables of a split) and survives fork and exec with
/// the identity that validates it (R8). Run in `/w` as for FD_TABLES_C, where
/// `a` has two entries besides "." and ".." (`v` and `child`, from binds
/// under literoot) and `b` holds `b1` and `b2`.
const FD_STREAMS_C: &str = r#"
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif

static const char *dir;
static int n, fb;

static void say(const char *what, long r, int e) {
    printf("%s %ld errno %d\n", what, r < 0 ? -1L : r, r < 0 ? e : 0);
}

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *) a, *(char *const *) b);
}

/* Every name getdents64 returns on fd, sorted, without "." and "..". */
static void list(const char *what, int fd) {
    char *names[64]; int k = 0;
    char buf[4096];
    for (;;) {
        long got = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (got <= 0) break;
        for (long off = 0; off < got;) {
            struct dirent64 *de = (struct dirent64 *) (buf + off);
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") && k < 64)
                names[k++] = strdup(de->d_name);
            off += de->d_reclen;
        }
    }
    qsort(names, k, sizeof names[0], cmp);
    printf("%s", what);
    for (int i = 0; i < k; i++) printf(" %s", names[i]);
    printf("\n");
}

/* How many records are left on fd ("." and ".." included). Raw syscalls
 * only: the clone child below runs it without a thread of its own. */
static int rest(int fd) {
    char buf[4096];
    int k = 0;
    for (;;) {
        long got = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (got <= 0) return k;
        for (long off = 0; off < got; k++)
            off += ((struct dirent64 *) (buf + off))->d_reclen;
    }
}

/* Read one small buffer at a time until 3 records arrived. */
static void partial3(int fd) {
    char buf[32];
    int seen = 0;
    while (seen < 3) {
        long got = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (got <= 0) break;
        for (long off = 0; off < got; seen++)
            off += ((struct dirent64 *) (buf + off))->d_reclen;
    }
}

static int open_dir(const char *rel) {
    char p[4096];
    snprintf(p, sizeof p, "%s/%s", dir, rel);
    return open(p, O_RDONLY | O_DIRECTORY);
}

static void leader_getdents(const char *what) {
    char buf[4096];
    long r = syscall(SYS_getdents64, n, buf, sizeof buf);
    say(what, r, errno);
}

static void run(void *(*fn)(void *)) {
    pthread_t t;
    if (pthread_create(&t, 0, fn, 0) == 0) pthread_join(t, 0);
}

static void *unshare_list(void *arg) {
    (void) arg;
    if (unshare(CLONE_FILES) == 0) list("r9 unshare worker list(v)", n);
    return 0;
}

static void *unshare_rest(void *arg) {
    (void) arg;
    if (unshare(CLONE_FILES) == 0) printf("r9 unshare worker rest(a) %d\n", rest(n));
    return 0;
}

static void *close_range_list(void *arg) {
    (void) arg;
    if (syscall(SYS_close_range, 1000U, 1000U, CLOSE_RANGE_UNSHARE) == 0)
        list("r9 close_range worker list(v)", n);
    return 0;
}

static void *unshare_reuse(void *arg) {
    (void) arg;
    if (unshare(CLONE_FILES) != 0) return 0;
    dup2(fb, n);
    list("r9 reuse worker list(n)", n);
    return 0;
}

/* A stream first listed after the split: worker 2 holds A on n in its own
 * table while worker 1 dups B onto n in another and lists it. B must not
 * become the identity of the stream the leader and worker 2 share for A. */
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int w2_ready, w2_go;

static void *seeded_worker2(void *arg) {
    (void) arg;
    int ok = unshare(CLONE_FILES) == 0;
    pthread_mutex_lock(&mu);
    w2_ready = 1;
    pthread_cond_broadcast(&cv);
    while (!w2_go) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    if (ok) printf("r9 seeded worker2 rest(a) %d\n", rest(n));
    return 0;
}

static void *seeded_worker1(void *arg) {
    (void) arg;
    if (unshare(CLONE_FILES) != 0) return 0;
    dup2(fb, n);
    list("r9 seeded worker1 list(n)", n);
    return 0;
}

static void seeded_case(void) {
    pthread_t w2;
    if (pthread_create(&w2, 0, seeded_worker2, 0) != 0) return;
    pthread_mutex_lock(&mu);
    while (!w2_ready) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    run(seeded_worker1);
    list("r9 seeded leader list(a)", n);
    fflush(stdout);
    pthread_mutex_lock(&mu);
    w2_go = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    pthread_join(w2, 0);
}

/* A stream recorded for B on a number that now holds A (a dup onto it
 * before the split): the split must not share B's stream for A. */
static int w3_ready, w3_go;

static void *stale_worker(void *arg) {
    (void) arg;
    int ok = unshare(CLONE_FILES) == 0;
    pthread_mutex_lock(&mu);
    w3_ready = 1;
    pthread_cond_broadcast(&cv);
    while (!w3_go) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    if (ok) printf("r9 stale worker rest(n) %d\n", rest(n));
    return 0;
}

static void stale_case(void) {
    n = open_dir("b");
    int m = open_dir("a");
    if (n < 0 || m < 0) return;
    list("r9 stale leader list(b)", n);
    dup2(m, n);
    pthread_t w;
    if (pthread_create(&w, 0, stale_worker, 0) != 0) return;
    pthread_mutex_lock(&mu);
    while (!w3_ready) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    list("r9 stale leader list(n)", n);
    fflush(stdout);
    pthread_mutex_lock(&mu);
    w3_go = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    pthread_join(w, 0);
}

/* A thread made by clone without CLONE_FILES: it gets a copy of the table.
 * No libc in it (it has no thread pointer of its own). */
static volatile int clone_rest = -1;
static volatile pid_t clone_tid;

static int clone_child(void *arg) {
    (void) arg;
    clone_rest = rest(n);
    syscall(SYS_exit, 0);
    return 0;
}

static void clone_case(void) {
    static char stack[64 * 1024] __attribute__((aligned(16)));
    int flags = CLONE_VM | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
        | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    pid_t t = clone(clone_child, stack + sizeof stack, flags, 0,
                    (pid_t *) &clone_tid, 0, (pid_t *) &clone_tid);
    if (t < 0) return;
    while (clone_tid != 0)
        syscall(SYS_futex, &clone_tid, FUTEX_WAIT, t, 0, 0, 0);
    printf("r9 clone worker rest(a) %d\n", clone_rest);
}

/* After fork or exec: B dup'd onto A's number lists B only; an unchanged
 * second A keeps its one remaining record. */
static void r8_child(const char *how, int na, int nb, int na2) {
    char what[64];
    dup2(nb, na);
    snprintf(what, sizeof what, "r8 %s child dup-b list(n)", how);
    list(what, na);
    printf("r8 %s child rest(a2) %d\n", how, rest(na2));
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc == 6 && strcmp(argv[1], "exec-child") == 0) {
        /* The exec'd image: never execs again. */
        dir = argv[2];
        r8_child("exec", atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
        return 0;
    }
    if (argc != 2) return 2;
    dir = argv[1];
    fb = open_dir("b");
    if (fb < 0) return 3;

    n = open_dir("a/v");
    run(unshare_list);
    leader_getdents("r9 unshare leader getdents(v)");
    n = open_dir("a");
    partial3(n);
    run(unshare_rest);
    leader_getdents("r9 unshare leader getdents(a)");
    n = open_dir("a/v");
    run(close_range_list);
    leader_getdents("r9 close_range leader getdents(v)");
    n = open_dir("a");
    partial3(n);
    clone_case();
    leader_getdents("r9 clone leader getdents(a)");
    n = open_dir("a");
    partial3(n);
    run(unshare_reuse);
    printf("r9 reuse leader rest(a) %d\n", rest(n));
    fb = open_dir("b");
    n = open_dir("a");
    if (fb < 0 || n < 0) return 3;
    seeded_case();
    stale_case();

    const char *hows[] = {"fork", "exec"};
    for (int i = 0; i < 2; i++) {
        int na = open_dir("a"), nb = open_dir("b"), na2 = open_dir("a");
        if (na < 0 || nb < 0 || na2 < 0) return 3;
        partial3(na);
        partial3(na2);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            if (i == 0) {
                r8_child("fork", na, nb, na2);
                _exit(0);
            }
            char a[16], b[16], a2[16];
            snprintf(a, sizeof a, "%d", na);
            snprintf(b, sizeof b, "%d", nb);
            snprintf(a2, sizeof a2, "%d", na2);
            execl(argv[0], argv[0], "exec-child", dir, a, b, a2, (char *) 0);
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        printf("r8 %s child status %d\n", hows[i], status);
    }
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

#[test]
fn fd_state_belongs_to_its_own_fd_table_and_closed_fds_are_the_kernels() {
    let dir = own_dir("fd-tables");
    let guest = build_guest(&dir, "tables", FD_TABLES_C);
    let work = fd_readers_work(&dir, "native", true);
    let native = run_native(&guest, "native", &[work.to_str().unwrap()]);
    assert_eq!(
        native,
        "r5 worker getdents(n) b1 b2\n\
         r5 leader openat(n,bound/marker) m\n\
         r5 leader getdents(n) bound\n\
         r5 worker2 b took n 1\n\
         r5 leader2 openat(n,bound/marker) m\n\
         r7 worker3 fstatat(n,b1) 0 errno 0\n\
         r7 leader fchdir(n) 0 errno 0\n\
         r7 leader open(bound/marker) m\n\
         r7 fstatat(dup-b,b1) 0 errno 0\n\
         r7 fchdir(dup-v) 0 errno 0\n\
         r7 open(bound/marker) m\n\
         r7 closed openat(d,x) -1 errno 9\n\
         r7 uncached-dup openat(900,child) 0 errno 0\n\
         r6 closed-virtual getdents -1 errno 9\n\
         r6 partial read 3\n\
         r6 closed-pending getdents -1 errno 9\n\
         r6 partial read 3\n\
         r6 dup-onto-pending getdents b1 b2\n"
    );
    // The same binds as every_fd_table_reader_and_unnamed_fds_and_cwds_match_native.
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
fn a_directory_stream_is_shared_by_split_tables_and_survives_fork_and_exec() {
    let dir = own_dir("fd-streams");
    let guest = build_guest(&dir, "streams", FD_STREAMS_C);
    let work = fd_readers_work(&dir, "native", true);
    let native = run_native(&guest, "native", &[work.to_str().unwrap()]);
    assert_eq!(
        native,
        "r9 unshare worker list(v) bound\n\
         r9 unshare leader getdents(v) 0 errno 0\n\
         r9 unshare worker rest(a) 1\n\
         r9 unshare leader getdents(a) 0 errno 0\n\
         r9 close_range worker list(v) bound\n\
         r9 close_range leader getdents(v) 0 errno 0\n\
         r9 clone worker rest(a) 1\n\
         r9 clone leader getdents(a) 0 errno 0\n\
         r9 reuse worker list(n) b1 b2\n\
         r9 reuse leader rest(a) 1\n\
         r9 seeded worker1 list(n) b1 b2\n\
         r9 seeded leader list(a) child v\n\
         r9 seeded worker2 rest(a) 0\n\
         r9 stale leader list(b) b1 b2\n\
         r9 stale leader list(n) child v\n\
         r9 stale worker rest(n) 0\n\
         r8 fork child dup-b list(n) b1 b2\n\
         r8 fork child rest(a2) 1\n\
         r8 fork child status 0\n\
         r8 exec child dup-b list(n) b1 b2\n\
         r8 exec child rest(a2) 1\n\
         r8 exec child status 0\n"
    );
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
