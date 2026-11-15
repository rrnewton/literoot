//! Calls that follow a final symlink resolve it through the guest root,
//! never the host's, and a path walk past 40 symlinks is ELOOP.
//!
//! A static probe in a scratch rootfs makes each call through symlinks
//! whose absolute targets exist on one side only:
//!
//! - an `/abs-*` link holds the absolute host path of a scratch file,
//!   directory or socket outside the rootfs. Through the guest root that
//!   path does not exist, so each call is ENOENT and the host object is
//!   untouched;
//! - a `/twin-*` link holds an absolute path that exists only inside the
//!   rootfs: the call reaches that object;
//! - a 41-link chain whose last link holds a host path is ELOOP, and a
//!   40-link chain to a guest file resolves.
//!
//! Each call keeps the kernel's checks that come before its path lookup:
//! an invalid flag is EINVAL, and utimensat with two UTIME_OMITs succeeds
//! without the path.
//!
//! The ptrace backend is built only with the `run` feature (the default,
//! and ptrace-only); a trap-only build compiles it out and refuses it by
//! name, so there this file is empty.

#![cfg(feature = "run")]

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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* 81 bytes: fits sun_path as the guest spells it, not once translated. */
#define LONG_SOCK "sock-with-a-long-name-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
/* The same length, names that must not reach the kernel as spelled. */
#define LONG_B "sock-with-a-long-name-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define LONG_LINK "link-with-a-long-name-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

/* Counts the open descriptors below 64 while the main thread connects:
 * literoot must not put a descriptor of its own in the guest's table. */
static volatile int watch_stop;
static int watch_max;
static int open_fds(void) {
    int n = 0;
    for (int fd = 0; fd < 64; fd++)
        if (fcntl(fd, F_GETFD) >= 0) n++;
    return n;
}
static void *watch(void *arg) {
    (void) arg;
    while (!watch_stop) {
        int n = open_fds();
        if (n > watch_max) watch_max = n;
    }
    return NULL;
}

#ifndef SYS_openat2
#define SYS_openat2 437
#endif
struct how { unsigned long long flags, mode, resolve; };

static void res(const char *what, long r) {
    if (r < 0) printf("%s -1 errno %d\n", what, errno);
    else printf("%s %ld\n", what, r);
}

/* A call returning a descriptor or 0: "ok" rather than the number. */
static void ok(const char *what, long r) {
    if (r < 0) printf("%s -1 errno %d\n", what, errno);
    else printf("%s ok\n", what);
}

/* Run argv[0] in a child; its exit is 100 + errno when execve fails. */
static void run_child(const char *what, char *path) {
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { path, NULL };
        execve(argv[0], argv, NULL);
        _exit(100 + errno);
    }
    int ws = 0;
    waitpid(pid, &ws, 0);
    printf("%s %s %d\n", what, WIFEXITED(ws) ? "exit" : "signal",
           WIFEXITED(ws) ? WEXITSTATUS(ws) : WTERMSIG(ws));
}

/* 0 or any errno but ENOENT: the call found the object (handles depend on
 * the filesystem). */
static void found(const char *what, long r) {
    printf("%s %s\n", what, (r >= 0 || errno != ENOENT) ? "found" : "ENOENT");
}

static long unix_call(int do_bind, const char *path) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path, sizeof a.sun_path - 1);
    long r = do_bind ? bind(s, (struct sockaddr *) &a, sizeof a)
                     : connect(s, (struct sockaddr *) &a, sizeof a);
    int e = errno;
    close(s);
    errno = e;
    return r;
}

int main(int argc, char **argv) {
    struct timespec omit[2] = { { 0, UTIME_OMIT }, { 0, UTIME_OMIT } };
    char handle[8 + 128];
    int mnt;
    char cwd[4096];

    /* Started with -w through a link: create relative to that cwd, and
     * bind a long relative name, which reaches the kernel as spelled only
     * when the kernel's cwd is the translated cwd. */
    if (argc > 1 && strcmp(argv[1], "w") == 0) {
        res("mkdir(after -w)", syscall(SYS_mkdirat, AT_FDCWD, "w-made", 0755L));
        res("bind(rel-long after -w)", unix_call(1, LONG_SOCK));
        return 0;
    }

    res("fchmodat(abs)", syscall(SYS_fchmodat, AT_FDCWD, "/abs-file", 0600L));
    res("fchmodat(twin)", syscall(SYS_fchmodat, AT_FDCWD, "/twin-file", 0600L));

    res("utimensat(abs,0)", syscall(SYS_utimensat, AT_FDCWD, "/abs-file", NULL, 0L));
    res("utimensat(abs,nofollow)",
        syscall(SYS_utimensat, AT_FDCWD, "/abs-file", NULL, (long) AT_SYMLINK_NOFOLLOW));
    res("utimensat(twin,0)", syscall(SYS_utimensat, AT_FDCWD, "/twin-file", NULL, 0L));
    res("utimensat(abs,omit)", syscall(SYS_utimensat, AT_FDCWD, "/abs-file", omit, 0L));
    /* Two OMITs succeed before the path: even one past the link budget. */
    res("utimensat(c0,omit)", syscall(SYS_utimensat, AT_FDCWD, "/c0", omit, 0L));
    res("utimensat(long,bad)", syscall(SYS_utimensat, AT_FDCWD, "/long", NULL, 1L));

    res("linkat(abs,follow)",
        syscall(SYS_linkat, AT_FDCWD, "/abs-file", AT_FDCWD, "/hl-abs", (long) AT_SYMLINK_FOLLOW));
    res("linkat(abs,0)", syscall(SYS_linkat, AT_FDCWD, "/abs-file", AT_FDCWD, "/hl-link", 0L));
    res("linkat(twin,follow)",
        syscall(SYS_linkat, AT_FDCWD, "/twin-file", AT_FDCWD, "/hl-twin", (long) AT_SYMLINK_FOLLOW));
    /* An invalid flag with AT_SYMLINK_FOLLOW: following /long first would
     * answer the staging bound's ENAMETOOLONG instead of EINVAL. */
    res("linkat(long,bad|follow)",
        syscall(SYS_linkat, AT_FDCWD, "/long", AT_FDCWD, "/hl-bad", 0x200L | AT_SYMLINK_FOLLOW));

    memset(handle, 0, sizeof handle);
    *(unsigned int *) handle = 128;
    res("name_to_handle_at(abs,follow)",
        syscall(SYS_name_to_handle_at, AT_FDCWD, "/abs-file", handle, &mnt, (long) AT_SYMLINK_FOLLOW));
    *(unsigned int *) handle = 128;
    found("name_to_handle_at(twin,follow)",
          syscall(SYS_name_to_handle_at, AT_FDCWD, "/twin-file", handle, &mnt, (long) AT_SYMLINK_FOLLOW));
    *(unsigned int *) handle = 128;
    found("name_to_handle_at(abs,0)",
          syscall(SYS_name_to_handle_at, AT_FDCWD, "/abs-file", handle, &mnt, 0L));
    res("name_to_handle_at(long,bad|follow)",
        syscall(SYS_name_to_handle_at, AT_FDCWD, "/long", handle, &mnt, 0x4000L | AT_SYMLINK_FOLLOW));
    /* AT_HANDLE_CONNECTABLE (0x2) with AT_HANDLE_FID (0x200). */
    res("name_to_handle_at(long,connectable|fid|follow)",
        syscall(SYS_name_to_handle_at, AT_FDCWD, "/long", handle, &mnt,
                0x2L | 0x200L | AT_SYMLINK_FOLLOW));

    res("connect(abs)", unix_call(0, "/abs-sock"));
    res("connect(twin)", unix_call(0, "/twin-sock"));

    struct how h = { O_RDONLY | O_NOFOLLOW, 0, 0 };
    res("openat2(twin,nofollow)", syscall(SYS_openat2, AT_FDCWD, "/twin-file", &h, sizeof h));
    h.flags = O_PATH | O_NOFOLLOW;
    long fd = syscall(SYS_openat2, AT_FDCWD, "/twin-file", &h, sizeof h);
    struct stat st;
    printf("openat2(twin,path|nofollow) %s\n",
           fd >= 0 && fstat((int) fd, &st) == 0 && S_ISLNK(st.st_mode) ? "link" : "not-link");
    h.flags = O_RDONLY;
    ok("openat2(twin,0)", syscall(SYS_openat2, AT_FDCWD, "/twin-file", &h, sizeof h));
    /* openat2 checks its arguments before the path: a path past the link
     * budget is ELOOP only when they are valid. */
    res("openat2(c0)", syscall(SYS_openat2, AT_FDCWD, "/c0", &h, sizeof h));
    struct how bad = { O_RDONLY | (1ULL << 40), 0, 0 };
    res("openat2(c0,bad flag)", syscall(SYS_openat2, AT_FDCWD, "/c0", &bad, sizeof bad));
    res("openat2(c0,size 16)", syscall(SYS_openat2, AT_FDCWD, "/c0", &h, 16L));
    /* Valid RESOLVE_BENEATH (0x08) and RESOLVE_IN_ROOT (0x10) arguments:
     * the kernel's own check must not answer for the path. These rows pin
     * literoot's answers today (40, 36), not the native ones: natively an
     * absolute name under RESOLVE_BENEATH is EXDEV (18), and under
     * RESOLVE_IN_ROOT from AT_FDCWD "/c0" and "/long" resolve inside the
     * cwd, /guest-cwd, where neither exists: ENOENT (2). RESOLVE_*
     * semantics are (2b)'s work, which changes these rows knowingly. */
    struct how r = { O_RDONLY, 0, 0x08 };
    res("openat2(c0,beneath)", syscall(SYS_openat2, AT_FDCWD, "/c0", &r, sizeof r));
    res("openat2(long,beneath)", syscall(SYS_openat2, AT_FDCWD, "/long", &r, sizeof r));
    r.resolve = 0x10;
    res("openat2(c0,in root)", syscall(SYS_openat2, AT_FDCWD, "/c0", &r, sizeof r));
    res("openat2(long,in root)", syscall(SYS_openat2, AT_FDCWD, "/long", &r, sizeof r));
    /* Creating flags: the check itself must create nothing. */
    struct how c = { O_CREAT | O_WRONLY, 0644, 0 };
    res("openat2(c0,creat)", syscall(SYS_openat2, AT_FDCWD, "/c0", &c, sizeof c));
    struct how tmp = { O_TMPFILE | O_RDWR, 0600, 0 };
    res("openat2(long,tmpfile)", syscall(SYS_openat2, AT_FDCWD, "/long", &tmp, sizeof tmp));

    res("fchmodat(chain41)", syscall(SYS_fchmodat, AT_FDCWD, "/c0", 0600L));
    res("fchmodat(chain40)", syscall(SYS_fchmodat, AT_FDCWD, "/k0", 0600L));
    res("stat(dirchain41)", syscall(SYS_newfstatat, AT_FDCWD, "/d0/file", &st, 0L));
    /* One budget for the whole walk: 20 directory links, then 21 or 20
     * final links. */
    res("fchmodat(mixed41)", syscall(SYS_fchmodat, AT_FDCWD, "/m0/q0", 0600L));
    res("fchmodat(mixed40)", syscall(SYS_fchmodat, AT_FDCWD, "/m0/r0", 0600L));

    res("chdir(abs)", syscall(SYS_chdir, "/abs-dir"));
    /* Each relative call runs right after its chdir or open, before any
     * getcwd, which re-reads the kernel's cwd. */
    res("chdir(twin)", syscall(SYS_chdir, "/twin-dir-link"));
    res("mkdir(rel)", syscall(SYS_mkdirat, AT_FDCWD, "made-here", 0755L));
    /* A relative AF_UNIX name is translated like any path. This one's host
     * name passes 107 bytes, but it is relative, has no "..", crosses no
     * link or bind, and the kernel's cwd is the translated cwd: it goes to
     * the kernel as spelled, and getsockname returns it as natively. */
    {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un a, g;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        strcpy(a.sun_path, LONG_SOCK);
        res("bind(rel-long)", bind(s, (struct sockaddr *) &a, sizeof a));
        int base = open_fds() + 1; /* each connect's own socket */
        pthread_t t;
        pthread_create(&t, NULL, watch, NULL);
        int refused = 0;
        for (int i = 0; i < 200; i++)
            if (unix_call(0, LONG_SOCK) < 0 && errno == ECONNREFUSED) refused++;
        watch_stop = 1;
        pthread_join(t, NULL);
        printf("connect(rel-long, not listening) refused %d\n", refused);
        printf("fd-watch extra %d\n", watch_max > base ? watch_max - base : 0);
        listen(s, 4);
        socklen_t gl = sizeof g;
        memset(&g, 0, sizeof g);
        long r = getsockname(s, (struct sockaddr *) &g, &gl);
        printf("getsockname(rel-long) %s len %d\n",
               r == 0 && strcmp(g.sun_path, LONG_SOCK) == 0 ? "same" : "different", (int) gl);
        res("connect(getsockname name)", unix_call(0, g.sun_path));
        close(s);
    }
    /* Too long once translated, and the kernel would not resolve the
     * spelling as the guest walk did: ENAMETOOLONG. */
    res("bind(../long)", unix_call(1, "../twin-dir/" LONG_B));
    res("bind(link/long)", unix_call(1, "lnk/" LONG_B));
    res("connect(long final link)", unix_call(0, LONG_LINK));
    res("bind(long final link)", unix_call(1, LONG_LINK));
    res("bind(bound/long)", unix_call(1, "bound/" LONG_B));
    res("connect(rel-abs)", unix_call(0, "rel-abs-sock"));
    res("connect(dirlink/sock)", unix_call(0, "abs-dir-link/sock"));
    if (getcwd(cwd, sizeof cwd)) printf("getcwd %s\n", cwd);
    else res("getcwd", -1);

    /* /both-link holds an absolute path that exists on both sides: chdir
     * succeeds in the guest root either way, and only the next relative
     * call shows whether the recorded cwd still holds the link. */
    res("chdir(both/)", syscall(SYS_chdir, "/both-link/"));
    res("mkdir(after both/)", syscall(SYS_mkdirat, AT_FDCWD, "tslash", 0755L));
    if (getcwd(cwd, sizeof cwd)) printf("getcwd %s\n", cwd);
    else res("getcwd", -1);
    res("chdir(both/sub)", syscall(SYS_chdir, "/both-link/sub"));
    res("mkdir(after both/sub)", syscall(SYS_mkdirat, AT_FDCWD, "mid", 0755L));
    res("chdir(both/..)", syscall(SYS_chdir, "/both-link/.."));
    res("mkdir(after both/..)", syscall(SYS_mkdirat, AT_FDCWD, "dotdot", 0755L));
    /* /a and /b bind the same host directory; only /a has a nested bind
     * at dest/child. Entered through /b, child is the shared one. */
    res("chdir(/b/link)", syscall(SYS_chdir, "/b/link"));
    res("mkdir(after /b/link)", syscall(SYS_mkdirat, AT_FDCWD, "child/made", 0755L));

    /* A directory opened through the link, then used as a base. */
    long dfd = syscall(SYS_openat, AT_FDCWD, "/both-link/sub", O_RDONLY | O_DIRECTORY);
    ok("open(both/sub)", dfd);
    ok("openat(fd,create)",
       syscall(SYS_openat, (int) dfd, "fd-made", O_CREAT | O_WRONLY | O_CLOEXEC, 0644));
    res("fchdir(fd)", syscall(SYS_fchdir, (int) dfd));
    res("mkdir(after fchdir)", syscall(SYS_mkdirat, AT_FDCWD, "fchdir-made", 0755L));
    if (getcwd(cwd, sizeof cwd)) printf("getcwd %s\n", cwd);
    else res("getcwd", -1);
    /* The cwd's own directory renamed to a name through the link. */
    res("mkdir(/rn-dir)", syscall(SYS_mkdirat, AT_FDCWD, "/rn-dir", 0755L));
    res("chdir(/rn-dir)", syscall(SYS_chdir, "/rn-dir"));
    res("rename(/rn-dir,both/rn-moved)",
        syscall(SYS_renameat, AT_FDCWD, "/rn-dir", AT_FDCWD, "/both-link/rn-moved"));
    res("mkdir(after rename)", syscall(SYS_mkdirat, AT_FDCWD, "after-rename", 0755L));
    if (getcwd(cwd, sizeof cwd)) printf("getcwd %s\n", cwd);
    else res("getcwd", -1);

    /* PT_INTERP: /bin/interp-probe names /ld-abs as its loader, a link to
     * the host's loader by absolute path. Through the guest root there
     * is no such loader, so execve is ENOENT. /bin/interp-twin names
     * /ld-twin, a link to a loader copy that exists only in the guest
     * root: it runs. */
    run_child("execve(interp-abs)", "/bin/interp-probe");
    run_child("execve(interp-twin)", "/bin/interp-twin");
    return 0;
}
"#;

/// The probe's long relative AF_UNIX names, as in `PROBE_C`.
const LONG_SOCK: &str =
    "sock-with-a-long-name-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const LONG_B: &str =
    "sock-with-a-long-name-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LONG_LINK: &str =
    "link-with-a-long-name-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

/// The dynamic probe, built twice: as /bin/interp-probe, whose loader
/// /ld-abs names the host's loader (it never runs when execve is right),
/// and as /bin/interp-twin, whose loader /ld-twin names a copy that exists
/// only in the rootfs (it runs and exits 7).
const INTERP_PROBE_C: &str = "int main(void) { return 7; }\n";

/// (mode, nlink, mtime s, mtime ns, ctime s, ctime ns) without following.
fn stamp(path: &Path) -> (u32, u64, i64, i64, i64, i64) {
    let m = std::fs::symlink_metadata(path).unwrap();
    (
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn cc(out: &Path, source: &str, flags: &[&str]) -> std::process::Output {
    Command::new("cc")
        .args(["-O2", "-Wall", "-Werror"])
        .args(flags)
        .arg("-o")
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

/// The host's own dynamic loader, by the path a dynamic C program names.
fn host_loader() -> Option<std::path::PathBuf> {
    let out = Command::new("cc")
        .arg("-print-file-name=ld-linux-x86-64.so.2")
        .output()
        .ok()?;
    let p = std::path::PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    if p.is_absolute() && p.exists() {
        return Some(p);
    }
    ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
}

/// The host's C library, by its canonical path.
fn host_libc() -> Option<std::path::PathBuf> {
    let out = Command::new("cc")
        .arg("-print-file-name=libc.so.6")
        .output()
        .ok()?;
    let p = std::path::PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    p.canonicalize().ok().filter(|p| p.is_absolute())
}

/// Names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Every entry named `name` under `dir`, descending into directories only
/// (never through a symlink).
fn named_anywhere(dir: &Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_name() == name {
                found.push(path.clone());
            }
            if entry.file_type().unwrap().is_dir() {
                pending.push(path);
            }
        }
    }
    found.sort();
    found
}

/// `path` inside the rootfs: `root` joined with the absolute `path`.
fn inside(root: &Path, path: &Path) -> std::path::PathBuf {
    root.join(path.strip_prefix("/").unwrap())
}

#[test]
fn calls_resolve_final_symlinks_through_the_guest_root() {
    let scratch =
        std::env::temp_dir().join(format!("literoot-guest-root-follow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let host = scratch.join("host");
    let root = scratch.join("root");
    for d in [
        host.clone(),
        host.join("dir"),
        host.join("both/sub"),
        root.join("bin"),
        root.join("twin-dir/lnkdir"),
        root.join("guest-cwd"),
        root.join("mdir"),
        root.join("ldcopy"),
        scratch.join("shared/dest/child"),
        scratch.join("other"),
        scratch.join("bound-host"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let built = cc(&root.join("bin/probe"), PROBE_C, &["-static", "-pthread"]);
    if !fixture_or_skip(&built, "static guest-root probe") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let Some(loader) = host_loader() else {
        panic!("no host dynamic loader found for the PT_INTERP row");
    };
    let Some(libc) = host_libc() else {
        panic!("no host C library found for the PT_INTERP control row");
    };
    for (bin, interp) in [("interp-probe", "/ld-abs"), ("interp-twin", "/ld-twin")] {
        let flag = format!("-Wl,--dynamic-linker={interp}");
        let built = cc(
            &root.join("bin").join(bin),
            INTERP_PROBE_C,
            &[flag.as_str()],
        );
        assert!(built.status.success(), "{bin}: {built:?}");
    }
    // The control's loader and C library exist only inside the rootfs.
    std::fs::copy(&loader, root.join("ldcopy/ld.so")).unwrap();
    std::fs::create_dir_all(inside(&root, libc.parent().unwrap())).unwrap();
    std::fs::copy(&libc, inside(&root, &libc)).unwrap();

    // Host objects outside the rootfs, by canonical absolute path.
    let host = host.canonicalize().unwrap();
    let file = host.join("file");
    std::fs::write(&file, "host").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let sock_path = host.join("sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let dir_listener = std::os::unix::net::UnixListener::bind(host.join("dir/sock")).unwrap();
    for p in [&file, &sock_path, &host.join("dir"), &host.join("ldcopy")] {
        assert!(
            std::fs::symlink_metadata(inside(&root, p)).is_err(),
            "{} must not exist inside the rootfs",
            p.display()
        );
    }
    for p in ["/twin-dir", "/twin-file", "/twin-sock", "/ldcopy"] {
        assert!(
            std::fs::symlink_metadata(p).is_err(),
            "{p} exists on the host"
        );
    }
    // /both-link holds an absolute path that exists on both sides.
    let both = host.join("both");
    std::fs::create_dir_all(inside(&root, &both).join("sub")).unwrap();
    let link =
        |target: &Path, name: &str| std::os::unix::fs::symlink(target, root.join(name)).unwrap();
    link(&file, "abs-file");
    link(&sock_path, "abs-sock");
    link(&host.join("dir"), "abs-dir");
    link(&loader, "ld-abs");
    link(Path::new("/ldcopy/ld.so"), "ld-twin");
    link(Path::new("/twin-dir/file"), "twin-file");
    link(Path::new("/twin-dir/sock"), "twin-sock");
    link(Path::new("/twin-dir"), "twin-dir-link");
    link(&both, "both-link");
    link(&sock_path, "twin-dir/rel-abs-sock");
    link(&host.join("dir"), "twin-dir/abs-dir-link");
    link(Path::new("lnkdir"), "twin-dir/lnk");
    link(Path::new(LONG_SOCK), &format!("twin-dir/{LONG_LINK}"));
    std::os::unix::fs::symlink("dest", scratch.join("shared/link")).unwrap();
    std::fs::write(root.join("twin-dir/file"), "twin").unwrap();
    std::fs::set_permissions(
        root.join("twin-dir/file"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let twin_listener = std::os::unix::net::UnixListener::bind(root.join("twin-dir/sock")).unwrap();
    // 120 components of 9 bytes: past the staging bound once resolved.
    let long: String = (0..120).map(|i| format!("/c{i:07}")).collect();
    link(Path::new(&long), "long");
    // /c0 -> /c1 -> ... -> /c40 -> the host file: 41 links. /k0 -> ... ->
    // /k39 -> /twin-dir/file: 40 links. /d0 -> ... -> /d40 -> the host
    // dir, as directories on the way to /d0/file: 41 links.
    for i in 0..41 {
        let next = if i == 40 {
            file.clone()
        } else {
            format!("/c{}", i + 1).into()
        };
        link(&next, &format!("c{i}"));
        let next = if i == 40 {
            host.join("dir")
        } else {
            format!("/d{}", i + 1).into()
        };
        link(&next, &format!("d{i}"));
    }
    for i in 0..40 {
        let next: std::path::PathBuf = if i == 39 {
            "/twin-dir/file".into()
        } else {
            format!("/k{}", i + 1).into()
        };
        link(&next, &format!("k{i}"));
    }
    // /m0 -> ... -> /m19 -> /mdir: 20 directory links. Then /mdir/q0 ->
    // /q1 -> ... -> /q20 -> /twin-dir/file is 21 final links (41 in all),
    // and /mdir/r0 -> /r1 -> ... -> /r19 -> /twin-dir/file is 20 (40).
    for i in 0..20 {
        let next = if i == 19 {
            "/mdir".to_string()
        } else {
            format!("/m{}", i + 1)
        };
        link(Path::new(&next), &format!("m{i}"));
    }
    for (prefix, count) in [("q", 21), ("r", 20)] {
        for i in 0..count {
            let next = if i == count - 1 {
                "/twin-dir/file".to_string()
            } else {
                format!("/{prefix}{}", i + 1)
            };
            let name = if i == 0 {
                format!("mdir/{prefix}0")
            } else {
                format!("{prefix}{i}")
            };
            link(Path::new(&next), &name);
        }
    }
    std::fs::write(host.join("dir/file"), "host").unwrap();
    // The bound socket's host name must not fit sun_path (107 bytes and
    // a NUL), or the row would not test the kernel-spelling rule.
    let long_sock = root.join("twin-dir").join(LONG_SOCK);
    assert!(long_sock.as_os_str().len() > 107, "{}", long_sock.display());

    let file_before = stamp(&file);
    let dir_before = stamp(&host.join("dir"));
    std::thread::sleep(std::time::Duration::from_millis(20));

    let bind = |host: &Path, guest: &str| format!("{}:{guest}", host.display());
    let mut cmd = Command::new(literoot_bin());
    cmd.arg("-r")
        .arg(&root)
        .args(["-b", &bind(&scratch.join("shared"), "/a")])
        .args(["-b", &bind(&scratch.join("shared"), "/b")])
        .args(["-b", &bind(&scratch.join("other"), "/a/dest/child")])
        .args(["-b", &bind(&scratch.join("bound-host"), "/twin-dir/bound")])
        .arg("-w")
        .arg("/guest-cwd")
        .arg("/bin/probe");
    let out = run_bounded(cmd, "probe");
    assert!(out.status.success(), "probe: {out:?}");
    let got: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut want: Vec<String> = [
        "fchmodat(abs) -1 errno 2",
        "fchmodat(twin) 0",
        "utimensat(abs,0) -1 errno 2",
        "utimensat(abs,nofollow) 0",
        "utimensat(twin,0) 0",
        "utimensat(abs,omit) 0",
        "utimensat(c0,omit) 0",
        "utimensat(long,bad) -1 errno 22",
        "linkat(abs,follow) -1 errno 2",
        "linkat(abs,0) 0",
        "linkat(twin,follow) 0",
        "linkat(long,bad|follow) -1 errno 22",
        "name_to_handle_at(abs,follow) -1 errno 2",
        "name_to_handle_at(twin,follow) found",
        "name_to_handle_at(abs,0) found",
        "name_to_handle_at(long,bad|follow) -1 errno 22",
        "name_to_handle_at(long,connectable|fid|follow) -1 errno 22",
        "connect(abs) -1 errno 2",
        "connect(twin) 0",
        "openat2(twin,nofollow) -1 errno 40",
        "openat2(twin,path|nofollow) link",
        "openat2(twin,0) ok",
        "openat2(c0) -1 errno 40",
        "openat2(c0,bad flag) -1 errno 22",
        "openat2(c0,size 16) -1 errno 22",
        "openat2(c0,beneath) -1 errno 40",
        "openat2(long,beneath) -1 errno 36",
        "openat2(c0,in root) -1 errno 40",
        "openat2(long,in root) -1 errno 36",
        "openat2(c0,creat) -1 errno 40",
        "openat2(long,tmpfile) -1 errno 36",
        "fchmodat(chain41) -1 errno 40",
        "fchmodat(chain40) 0",
        "stat(dirchain41) -1 errno 40",
        "fchmodat(mixed41) -1 errno 40",
        "fchmodat(mixed40) 0",
        "chdir(abs) -1 errno 2",
        "chdir(twin) 0",
        "mkdir(rel) 0",
        "bind(rel-long) 0",
        "connect(rel-long, not listening) refused 200",
        "fd-watch extra 0",
        "getsockname(rel-long) same len 84",
        "connect(getsockname name) 0",
        "bind(../long) -1 errno 36",
        "bind(link/long) -1 errno 36",
        "connect(long final link) -1 errno 36",
        "bind(long final link) -1 errno 36",
        "bind(bound/long) -1 errno 36",
        "connect(rel-abs) -1 errno 2",
        "connect(dirlink/sock) -1 errno 2",
        "getcwd /twin-dir",
        "chdir(both/) 0",
        "mkdir(after both/) 0",
        "GETCWD_BOTH",
        "chdir(both/sub) 0",
        "mkdir(after both/sub) 0",
        "chdir(both/..) 0",
        "mkdir(after both/..) 0",
        "chdir(/b/link) 0",
        "mkdir(after /b/link) 0",
        "open(both/sub) ok",
        "openat(fd,create) ok",
        "fchdir(fd) 0",
        "mkdir(after fchdir) 0",
        "GETCWD_BOTH_SUB",
        "mkdir(/rn-dir) 0",
        "chdir(/rn-dir) 0",
        "rename(/rn-dir,both/rn-moved) 0",
        "mkdir(after rename) 0",
    ]
    .iter()
    .map(|s| match *s {
        "GETCWD_BOTH" => format!("getcwd {}", both.display()),
        "GETCWD_BOTH_SUB" => format!("getcwd {}/sub", both.display()),
        s => s.to_string(),
    })
    .collect();
    want.push(format!("getcwd {}/rn-moved", both.display()));
    want.push("execve(interp-abs) exit 102".to_string());
    want.push("execve(interp-twin) exit 7".to_string());
    assert_eq!(got, want);

    // Started with -w through the link: the kernel's cwd is the guest-root
    // side, and so is a relative create.
    let mut cmd = Command::new(literoot_bin());
    cmd.arg("-r")
        .arg(&root)
        .args(["-w", "/both-link", "/bin/probe", "w"]);
    let out = run_bounded(cmd, "probe -w");
    assert!(out.status.success(), "probe -w: {out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "mkdir(after -w) 0\nbind(rel-long after -w) 0\n"
    );

    // The host objects outside the rootfs are untouched.
    assert_eq!(stamp(&file), file_before, "the host file changed");
    assert_eq!(stamp(&host.join("dir")), dir_before, "the host dir changed");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "host");
    assert_eq!(
        names(&both),
        ["sub"],
        "a relative call reached the host side"
    );
    assert!(
        names(&both.join("sub")).is_empty(),
        "a call reached the host side"
    );
    // The calls reached the guest's objects instead.
    let twin = std::fs::metadata(root.join("twin-dir/file")).unwrap();
    assert_eq!(
        twin.mode() & 0o7777,
        0o600,
        "fchmodat did not reach the twin"
    );
    assert_eq!(twin.nlink(), 2, "linkat FOLLOW did not link the twin");
    assert!(
        std::fs::symlink_metadata(root.join("hl-link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "linkat without FOLLOW must link the symlink itself"
    );
    assert!(
        root.join("twin-dir/made-here").is_dir(),
        "mkdir after chdir"
    );
    let guest_both = inside(&root, &both);
    for made in [
        guest_both.join("tslash"),
        guest_both.join("sub/mid"),
        inside(&root, &host).join("dotdot"),
        scratch.join("shared/dest/child/made"),
        guest_both.join("sub/fchdir-made"),
        guest_both.join("rn-moved/after-rename"),
        guest_both.join("w-made"),
    ] {
        assert!(made.is_dir(), "{} was not created", made.display());
    }
    assert!(
        guest_both.join("sub/fd-made").is_file(),
        "openat(fd) create"
    );
    // Under -w the kernel's cwd is the guest-root side too: the long
    // relative bind went to the kernel as spelled and landed there.
    assert!(
        std::fs::symlink_metadata(guest_both.join(LONG_SOCK))
            .unwrap()
            .file_type()
            .is_socket(),
        "bind with a long relative name under -w"
    );
    assert!(
        names(&scratch.join("other")).is_empty(),
        "the /a bind was used"
    );
    // The kernel created the socket where the translated cwd names it:
    // the kernel's cwd and the translated one are the same directory.
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        std::fs::symlink_metadata(&long_sock)
            .unwrap()
            .file_type()
            .is_socket(),
        "bind with a long relative name"
    );
    // Neither the refused names nor the openat2 check created anything.
    for dir in [
        root.join("twin-dir"),
        scratch.join("bound-host"),
        root.clone(),
    ] {
        let made: Vec<String> = names(&dir)
            .into_iter()
            .filter(|n| n.contains("bbbb") || n == "x")
            .collect();
        assert!(made.is_empty(), "{}: {made:?}", dir.display());
    }
    // The openat2 probe's name "x" exists nowhere in the scratch tree, the
    // rows' kernel cwd (/guest-cwd) included: its descriptor -1 is what
    // keeps O_CREAT and O_TMPFILE from making anything.
    assert_eq!(
        named_anywhere(&scratch, "x"),
        Vec::<std::path::PathBuf>::new()
    );
    assert!(!root.join("twin-dir/lnkdir").join(LONG_B).exists());
    drop((listener, dir_listener, twin_listener));
    std::fs::remove_dir_all(&scratch).unwrap();
}

/// Prints INSIDE: the program the guest root holds at the shared path.
const INSIDE_C: &str = "#include <stdio.h>\nint main(void) { puts(\"INSIDE\"); return 0; }\n";
/// Prints OUTSIDE and exits 9: the host's program at the same path, which
/// a launch must never run.
const OUTSIDE_C: &str = "#include <stdio.h>\nint main(void) { puts(\"OUTSIDE\"); return 9; }\n";

/// The launcher resolves the program, a shebang interpreter and a PT_INTERP
/// loader by the same walk as every guest call: intermediate and final
/// links share one 40-link budget, and the 41st is ELOOP. A path that
/// still holds a link never reaches the host kernel, which would follow it
/// to the host's program at the same path.
#[test]
fn launcher_resolves_through_the_guest_root_with_one_budget() {
    let scratch =
        std::env::temp_dir().join(format!("literoot-launcher-follow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let root = scratch.join("root");
    for d in [
        root.join("bin"),
        root.join("realdir"),
        root.join("pbin"),
        scratch.join("s"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let scratch = scratch.canonicalize().unwrap();
    let root = scratch.join("root");
    // S exists on both sides: the host's OUTSIDE, the guest's INSIDE.
    let s = scratch.join("s/prog");
    let built = cc(&s, OUTSIDE_C, &["-static"]);
    if !fixture_or_skip(&built, "static outside program") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    std::fs::create_dir_all(inside(&root, s.parent().unwrap())).unwrap();
    assert!(cc(&inside(&root, &s), INSIDE_C, &["-static"])
        .status
        .success());
    // SL, the loader: the host's OUTSIDE, the guest's copy of the real
    // loader (with the C library it needs inside the rootfs).
    let sl = scratch.join("s/ld.so");
    assert!(cc(&sl, OUTSIDE_C, &["-static"]).status.success());
    let loader = host_loader().expect("no host dynamic loader for the loader rows");
    let libc = host_libc().expect("no host C library for the loader rows");
    std::fs::copy(&loader, inside(&root, &sl)).unwrap();
    std::fs::create_dir_all(inside(&root, libc.parent().unwrap())).unwrap();
    std::fs::copy(&libc, inside(&root, &libc)).unwrap();
    // S2: an executable file on the host, a directory in the guest.
    let s2 = scratch.join("s/pp");
    assert!(cc(&s2, OUTSIDE_C, &["-static"]).status.success());
    std::fs::create_dir_all(inside(&root, &s2)).unwrap();

    let link = |target: &Path, name: &str| {
        std::os::unix::fs::symlink(target, root.join(name)).unwrap();
    };
    // A chain `<p>1 -> <p>2 -> ... -> <p>N -> target`: N links.
    let chain = |p: &str, n: usize, target: &Path| {
        for i in 1..=n {
            let next = if i == n {
                target.to_path_buf()
            } else {
                format!("/{p}{}", i + 1).into()
            };
            link(&next, &format!("{p}{i}"));
        }
    };
    chain("p", 41, &s);
    chain("e", 40, &s);
    chain("ld", 41, &sl);
    chain("le", 40, &sl);
    chain("i", 41, &s);
    chain("j", 40, &s);
    // /dl1 -> ... -> /dl20 -> /realdir: 20 directory links. Then
    // /realdir/f -> /f2 -> ... -> /f21 -> S is 21 final links (41 in all),
    // and /realdir/h -> /h2 -> ... -> /h20 -> S is 20 (40).
    chain("dl", 20, Path::new("/realdir"));
    for (p, n) in [("f", 21), ("h", 20)] {
        for i in 1..=n {
            let next: std::path::PathBuf = if i == n {
                s.clone()
            } else {
                format!("/{p}{}", i + 1).into()
            };
            let name = if i == 1 {
                format!("realdir/{p}1")
            } else {
                format!("{p}{i}")
            };
            link(&next, &name);
        }
    }
    link(&s2, "pbin/pp");
    for (bin, interp) in [("dyn41", "/ld1"), ("dyn40", "/le1")] {
        let flag = format!("-Wl,--dynamic-linker={interp}");
        let built = cc(
            &root.join("bin").join(bin),
            INTERP_PROBE_C,
            &[flag.as_str()],
        );
        assert!(built.status.success(), "{bin}: {built:?}");
    }
    for (script, interp) in [("sh41", "/i1"), ("sh40", "/j1")] {
        let path = root.join("bin").join(script);
        std::fs::write(&path, format!("#!{interp}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let launch = |prog: &str, path_env: Option<&str>| {
        let mut cmd = Command::new(literoot_bin());
        cmd.arg("-r").arg(&root).arg(prog);
        if let Some(p) = path_env {
            cmd.env("PATH", p);
        }
        let out = run_bounded(cmd, prog);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (out.status.code(), stdout, stderr)
    };
    let eloop = "Too many levels of symbolic links";
    let mut got = Vec::new();
    for (row, prog) in [
        ("prog 41", "/p1"),
        ("prog 40", "/e1"),
        ("mixed 20+21", "/dl1/f1"),
        ("mixed 20+20", "/dl1/h1"),
        ("loader 41", "/bin/dyn41"),
        ("loader 40", "/bin/dyn40"),
        ("shebang 41", "/bin/sh41"),
        ("shebang 40", "/bin/sh40"),
    ] {
        // The outcome, not a panic, so a red run lists every row.
        let (code, stdout, stderr) = launch(prog, None);
        let outcome = if stdout.contains("OUTSIDE") {
            "the host's program ran".to_string()
        } else if stderr.contains(eloop) {
            "ELOOP".to_string()
        } else {
            format!("exit {code:?} {}", stdout.trim())
        };
        got.push(format!("{row}: {outcome}"));
    }
    let (_, stdout, stderr) = launch("pp", Some("/pbin"));
    got.push(format!(
        "PATH: {}",
        if stdout.contains("OUTSIDE") {
            "the host's program ran"
        } else if stderr.contains("not found in rootfs PATH") {
            "not found"
        } else if stderr.contains("Permission denied") {
            "permission denied"
        } else {
            "other"
        }
    ));
    assert_eq!(
        got,
        [
            "prog 41: ELOOP",
            "prog 40: exit Some(0) INSIDE",
            "mixed 20+21: ELOOP",
            "mixed 20+20: exit Some(0) INSIDE",
            "loader 41: ELOOP",
            "loader 40: exit Some(7) ",
            "shebang 41: ELOOP",
            "shebang 40: exit Some(0) INSIDE",
            "PATH: not found",
        ]
    );
    std::fs::remove_dir_all(&scratch).unwrap();
}

/// AF_UNIX names under the kernel-spelling rule: a relative name goes to
/// the kernel as the guest spelled it only when the kernel resolves it
/// exactly as the guest walk did. Each guard has a row it alone refuses.
const UNIX_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define LONG_B "sock-with-a-long-name-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static void res(const char *what, long r) {
    if (r < 0) printf("%s -1 errno %d\n", what, errno);
    else printf("%s %ld\n", what, r);
}

/* bind or connect `name` (len bytes, no NUL added) with addrlen `alen`. */
static long call(int do_bind, const char *name, size_t len, socklen_t alen, int *keep) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, name, len);
    long r = do_bind ? bind(s, (struct sockaddr *) &a, alen)
                     : connect(s, (struct sockaddr *) &a, alen);
    int e = errno;
    if (keep && r == 0) *keep = s;
    else close(s);
    errno = e;
    return r;
}

static long bind_name(const char *name) {
    return call(1, name, strlen(name), sizeof(struct sockaddr_un), NULL);
}

/* bind, getsockname and connect for one name, as native prints them. */
static void triple(const char *tag, const char *name, size_t len) {
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) + len + (len < 108);
    int s = -1;
    char what[64];
    snprintf(what, sizeof what, "bind%s", tag);
    res(what, call(1, name, len, alen, &s));
    if (s >= 0) {
        struct sockaddr_storage g;
        socklen_t gl = sizeof g;
        memset(&g, 0, sizeof g);
        long r = getsockname(s, (struct sockaddr *) &g, &gl);
        const char *path = ((struct sockaddr_un *) &g)->sun_path;
        printf("getsockname%s %ld len %d %s\n", tag, r, (int) gl,
               memcmp(path, name, len) == 0 && (len == 108 || path[len] == 0) ? "same" : "different");
        close(s);
    }
    snprintf(what, sizeof what, "connect%s", tag);
    res(what, call(0, name, len, alen, NULL));
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "sun") == 0) {
        char n108[108];
        memset(n108, 'n', sizeof n108);
        triple("108", n108, sizeof n108);
        triple("7", "sock7xx", 7);
        return 0;
    }
    /* Started in /cwd. A literal ".." after a file or a missing name: the
     * host path is the cwd joined with the name, and only the ".." guard
     * refuses. Natively these are ENOTDIR (20) and ENOENT (2). */
    res("bind(file/../long)", bind_name("rf/../" LONG_B));
    res("bind(missing/../long)", bind_name("missing/../" LONG_B));
    /* tlink is a link to the guest path a bind maps back onto tlink's own
     * host path: the walk follows a link, yet the host path is still the
     * cwd joined with the name. Only the no-link guard refuses. */
    res("bind(link onto a bind/long)", bind_name("tlink/" LONG_B));
    /* Another process renames our cwd and makes a new directory under the
     * old name: the recorded cwd now names a different directory from the
     * kernel's. Only the kernel-cwd guard refuses. */
    res("chdir(/kc/d)", chdir("/kc/d"));
    pid_t pid = fork();
    if (pid == 0) {
        if (rename("/kc/d", "/kc/e") != 0 || mkdir("/kc/d", 0755) != 0) _exit(1);
        _exit(0);
    }
    int ws = 0;
    waitpid(pid, &ws, 0);
    printf("child exit %d\n", WIFEXITED(ws) ? WEXITSTATUS(ws) : -1);
    res("bind(long, cwd renamed by another process)", bind_name(LONG_B));
    return 0;
}
"#;

#[test]
fn unix_names_reach_the_kernel_only_as_the_walk_resolved() {
    use std::os::unix::fs::FileTypeExt as _;
    let scratch = std::env::temp_dir().join(format!("literoot-unix-names-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let root = scratch.join("root");
    for d in [
        root.join("bin"),
        root.join("cwd"),
        root.join("kc/d"),
        scratch.join("t"),
        scratch.join("native"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let scratch = scratch.canonicalize().unwrap();
    let root = scratch.join("root");
    let probe = root.join("bin/unixprobe");
    let built = cc(&probe, UNIX_C, &["-static"]);
    if !fixture_or_skip(&built, "static AF_UNIX probe") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    std::fs::write(root.join("cwd/rf"), "file").unwrap();
    // tlink -> T (an absolute host path), and the bind maps guest T back
    // onto tlink's host path.
    let t = scratch.join("t");
    std::os::unix::fs::symlink(&t, root.join("cwd/tlink")).unwrap();
    let tlink_host = root.join("cwd/tlink");
    // The guards matter only when the translated name does not fit
    // sun_path (107 bytes and a NUL).
    for prefix in ["cwd/rf/../", "cwd/missing/../", "cwd/tlink/", "kc/d/"] {
        let host = format!("{}/{prefix}{LONG_B}", root.display());
        assert!(host.len() > 107, "{host}");
    }

    let mut cmd = Command::new(literoot_bin());
    cmd.arg("-r")
        .arg(&root)
        .arg("-b")
        .arg(format!("{}:{}", tlink_host.display(), t.display()))
        .args(["-w", "/cwd", "/bin/unixprobe"]);
    let out = run_bounded(cmd, "unix guards");
    assert!(out.status.success(), "unix guards: {out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "bind(file/../long) -1 errno 36\n\
         bind(missing/../long) -1 errno 36\n\
         bind(link onto a bind/long) -1 errno 36\n\
         chdir(/kc/d) 0\n\
         child exit 0\n\
         bind(long, cwd renamed by another process) -1 errno 36\n"
    );
    // No refused name was created anywhere.
    assert!(names(&t).is_empty(), "a socket reached T: {:?}", names(&t));
    for dir in [root.join("cwd"), root.join("kc/d"), root.join("kc/e")] {
        let made: Vec<String> = names(&dir)
            .into_iter()
            .filter(|n| n.contains("bbbb"))
            .collect();
        assert!(made.is_empty(), "{}: {made:?}", dir.display());
    }

    // A full 108-byte name and a short one: literoot's bind, getsockname
    // and connect answer exactly what the native calls answer. The guest
    // runs in /cwd, whose host path makes the 108-byte name too long to
    // send translated.
    let mut native = Command::new(&probe);
    native.arg("sun").current_dir(scratch.join("native"));
    let native = run_bounded(native, "native sun");
    assert!(native.status.success(), "native sun: {native:?}");
    let mut guest = Command::new(literoot_bin());
    guest
        .arg("-r")
        .arg(&root)
        .args(["-w", "/cwd", "/bin/unixprobe", "sun"]);
    let guest = run_bounded(guest, "literoot sun");
    assert!(guest.status.success(), "literoot sun: {guest:?}");
    let native = String::from_utf8(native.stdout).unwrap();
    assert_eq!(String::from_utf8(guest.stdout).unwrap(), native);
    assert!(native.starts_with("bind108 0\n"), "native: {native}");
    assert!(
        std::fs::symlink_metadata(root.join("cwd").join("n".repeat(108)))
            .unwrap()
            .file_type()
            .is_socket(),
        "the 108-byte name was bound in the guest's cwd"
    );
    std::fs::remove_dir_all(&scratch).unwrap();
}

/// A /proc magic link (root, cwd, fd/<n>, exe, map_files/<r>) names an
/// object of its process that the guest root does not contain: literoot
/// does not chroot, so `root` is the host's `/`. A guest's own links
/// continue under the guest root; another process's are EACCES.
const PROC_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define UP "../../../../../../../../../../../../../../../../"

static void res(const char *what, long r) {
    if (r < 0) printf("%s -1 errno %d\n", what, errno);
    else printf("%s 0\n", what);
}

/* The first line of the file, or the errno. */
static void show(const char *what, int fd) {
    if (fd < 0) { printf("%s -1 errno %d\n", what, errno); return; }
    char b[64];
    ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    b[n < 0 ? 0 : n] = 0;
    char *nl = strchr(b, '\n');
    if (nl) *nl = 0;
    printf("%s %s\n", what, b);
}
static void rd(const char *what, const char *path) { show(what, open(path, O_RDONLY)); }

int main(int argc, char **argv) {
    /* argv: S (absolute), the host process's pid, its first mapping. */
    if (argc < 4) return 2;
    const char *s = argv[1], *srel = argv[1] + 1, *hpid = argv[2], *range = argv[3];
    char p[1024], q[64];
    int tid = (int) syscall(SYS_gettid);

    snprintf(p, sizeof p, "/proc/self/root%s/file", s);
    rd("root(self)", p);
    snprintf(p, sizeof p, "/proc/thread-self/root%s/file", s);
    rd("root(thread-self)", p);
    snprintf(p, sizeof p, "/proc/%d/root%s/file", (int) getpid(), s);
    rd("root(pid)", p);
    snprintf(p, sizeof p, "/proc/self/task/%d/root%s/file", tid, s);
    rd("root(task)", p);
    int fd = open("/proc/self/root", O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%s/file", srel);
    if (fd < 0) res("open(root)", -1);
    else { show("open(root)+openat", openat(fd, p, O_RDONLY)); close(fd); }
    res("chdir(root)", chdir("/proc/self/root"));
    rd("read after chdir(root)", p);
    if (getcwd(q, sizeof q)) printf("getcwd %s\n", q);
    chdir("/");
    snprintf(p, sizeof p, "/proc/self/root%s/made", s);
    fd = open(p, O_CREAT | O_WRONLY, 0644);
    res("create(root/made)", fd);
    if (fd >= 0) close(fd);
    chdir("/proc");
    snprintf(p, sizeof p, "self/root%s/file", s);
    rd("rel root", p);

    res("chdir(/gdir)", chdir("/gdir"));
    snprintf(p, sizeof p, "/proc/self/cwd/" UP "%s/file", srel);
    rd("cwd up", p);
    rd("cwd hlink", "/proc/self/cwd/hlink/file");
    snprintf(p, sizeof p, "/proc/self/task/%d/cwd/" UP "%s/file", tid, srel);
    rd("task cwd up", p);
    snprintf(p, sizeof p, "../proc/self/cwd/" UP "%s/file", srel);
    rd("rel cwd up", p);
    fd = open("/proc/self/cwd", O_RDONLY | O_DIRECTORY);
    if (fd < 0) res("open(cwd)", -1);
    else { show("open(cwd)+openat hlink", openat(fd, "hlink/file", O_RDONLY)); close(fd); }
    int dfd = open("/gdir", O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "/proc/self/fd/%d/" UP "%s/file", dfd, srel);
    rd("fd up", p);
    snprintf(p, sizeof p, "/proc/self/fd/%d/hlink/file", dfd);
    rd("fd hlink", p);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    snprintf(p, sizeof p, "/proc/self/fd/%d/x", sock);
    rd("fd sock", p);

    /* A guest child, in /gsub, waiting. */
    int pp[2];
    if (pipe(pp) != 0) return 3;
    pid_t c = fork();
    if (c == 0) {
        if (chdir("/gsub") != 0) _exit(1);
        if (write(pp[1], "r", 1) != 1) _exit(1);
        for (;;) pause();
    }
    char r;
    if (read(pp[0], &r, 1) != 1) return 4;
    snprintf(p, sizeof p, "/proc/%d/root%s/file", (int) c, s);
    rd("child root", p);
    snprintf(p, sizeof p, "/proc/%d/cwd/" UP "%s/file", (int) c, srel);
    rd("child cwd up", p);
    snprintf(p, sizeof p, "/proc/%d/cwd/gfile", (int) c);
    rd("child cwd", p);
    kill(c, SIGKILL);
    waitpid(c, NULL, 0);

    /* A host process outside the guest. */
    struct stat st;
    snprintf(p, sizeof p, "/proc/%s/root%s/file", hpid, s);
    rd("H root", p);
    snprintf(p, sizeof p, "/proc/%s/cwd/marker", hpid);
    rd("H cwd", p);
    snprintf(p, sizeof p, "/proc/%s/root", hpid);
    res("stat(H root)", stat(p, &st));
    snprintf(p, sizeof p, "/proc/%s/cwd", hpid);
    long ch = chdir(p);
    res("chdir(H cwd)", ch);
    chdir("/gdir");
    snprintf(p, sizeof p, "../proc/%s/cwd/marker", hpid);
    rd("H rel cwd", p);
    snprintf(p, sizeof p, "/proc/%s/fd/3/marker", hpid);
    rd("H fd", p);
    snprintf(p, sizeof p, "/proc/%s/exe", hpid);
    res("stat(H exe)", stat(p, &st));
    snprintf(p, sizeof p, "/proc/%s/map_files/%s", hpid, range);
    res("stat(H map_files)", stat(p, &st));
    return 0;
}
"#;

/// The host process for the /proc rows: in its own directory, which it
/// also holds open as descriptor 3, waiting until killed.
const PROC_HOST_C: &str = r#"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int d = open(".", O_RDONLY | O_DIRECTORY);
    if (d != 3 && dup2(d, 3) != 3) return 1;
    puts("ready");
    fflush(stdout);
    for (;;) pause();
}
"#;

/// Kills the host process when the test ends, however it ends.
/// Whether the kernel lets this process follow another same-uid process's
/// map_files links: CAP_SYS_ADMIN (bit 21) or CAP_CHECKPOINT_RESTORE (bit 40)
/// in its effective set, held in the initial user namespace (an identity
/// uid_map), where proc_map_files_get_link checks them.
fn map_files_followable() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(|v| u64::from_str_radix(v.trim(), 16).unwrap())
        .unwrap();
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").unwrap();
    let initial = uid_map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"];
    initial && eff & (1 << 21 | 1 << 40) != 0
}

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn proc_magic_links_follow_the_guest_process() {
    let scratch = std::env::temp_dir().join(format!("literoot-proc-links-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let root = scratch.join("root");
    for d in [
        root.join("bin"),
        root.join("gdir"),
        root.join("gsub"),
        root.join("proc"),
        scratch.join("s"),
        scratch.join("hostcwd"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let scratch = scratch.canonicalize().unwrap();
    let root = scratch.join("root");
    let built = cc(&root.join("bin/procprobe"), PROC_C, &["-static"]);
    if !fixture_or_skip(&built, "static /proc probe") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let helper = scratch.join("prochost");
    assert!(cc(&helper, PROC_HOST_C, &["-static"]).status.success());
    // S holds HOST on the host and GUEST in the guest root.
    let s = scratch.join("s");
    std::fs::write(s.join("file"), "HOST").unwrap();
    std::fs::create_dir_all(inside(&root, &s)).unwrap();
    std::fs::write(inside(&root, &s).join("file"), "GUEST").unwrap();
    std::os::unix::fs::symlink(&s, root.join("gdir/hlink")).unwrap();
    std::fs::write(root.join("gsub/gfile"), "GFILE").unwrap();
    std::fs::write(scratch.join("hostcwd/marker"), "HOSTCWD").unwrap();

    let mut host = Command::new(&helper);
    host.current_dir(scratch.join("hostcwd"))
        .stdout(std::process::Stdio::piped());
    let mut host = KillOnDrop(host.spawn().expect("start the host process"));
    {
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::BufReader::new(host.0.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
    }
    let hpid = host.0.id().to_string();
    let maps = std::fs::read_to_string(format!("/proc/{hpid}/maps")).unwrap();
    let range = maps
        .split_whitespace()
        .next()
        .unwrap()
        .split('-')
        .map(|h| h.trim_start_matches('0'))
        .collect::<Vec<_>>()
        .join("-");

    let run = |config: &[&str]| -> Vec<String> {
        let mut cmd = Command::new(literoot_bin());
        cmd.args(config)
            .arg(&root)
            .args(["-w", "/", "/bin/procprobe"])
            .arg(&s)
            .arg(&hpid)
            .arg(&range);
        let out = run_bounded(cmd, "proc probe");
        assert!(out.status.success(), "proc probe {config:?}: {out:?}");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    };
    // The host process H's rows are the kernel's answers, as under proot:
    // H's root, its cwd and its directory descriptor 3 read the host's S and
    // HOSTCWD, and stat and chdir succeed. Earlier drafts of this test
    // expected EACCES; fix 4's plan ruling Q1 of 2026-11-14 (plan sha256
    // fc4a6bfea81930704fe0e67bb2e29b0cdf69b5f4a122859c106b911c15d12443,
    // ruling text sha256
    // 0d3d509328ec0b34439f538bed8ecec25c0de7eec3325ed5ee27d0ee65173e46)
    // made them the kernel's, under the owner directive of that day that
    // literoot assumes non-hostile programs (docs/design.md section
    // 4.9.8). Under the same ruling the caller's own descriptor that is
    // not a directory is the kernel's too: "fd sock" is ENOTDIR, the
    // kernel's answer for a name below a socket. H's map_files row is the
    // kernel's rule for a same-uid reader that is not H's parent, which the
    // guest is: the lookup passes (mm_access with PTRACE_MODE_READ_FSCREDS,
    // fs/proc/base.c:2348 at v6.18.55), and stat, which follows the link,
    // gets EPERM from proc_map_files_get_link unless the caller has
    // CAP_CHECKPOINT_RESTORE or CAP_SYS_ADMIN in the initial user namespace
    // (fs/proc/base.c:2287-2292, include/linux/capability.h:200-203). The
    // guest runs with this test's credentials.
    // "getcwd /" is unchanged: the getcwd arm runs the real getcwd with the
    // probe's 64-byte buffer, so the run needs a scratch path shorter than
    // that, an environment requirement, not a weaker check.
    let h_map_files = if map_files_followable() {
        "stat(H map_files) 0"
    } else {
        "stat(H map_files) -1 errno 1"
    }
    .to_string();
    let procfs: Vec<String> = [
        "root(self) GUEST",
        "root(thread-self) GUEST",
        "root(pid) GUEST",
        "root(task) GUEST",
        "open(root)+openat GUEST",
        "chdir(root) 0",
        "read after chdir(root) GUEST",
        "getcwd /",
        "create(root/made) 0",
        "rel root GUEST",
        "chdir(/gdir) 0",
        "cwd up GUEST",
        "cwd hlink GUEST",
        "task cwd up GUEST",
        "rel cwd up GUEST",
        "open(cwd)+openat hlink GUEST",
        "fd up GUEST",
        "fd hlink GUEST",
        "fd sock -1 errno 20",
        "child root GUEST",
        "child cwd up GUEST",
        "child cwd GFILE",
        "H root HOST",
        "H cwd HOSTCWD",
        "stat(H root) 0",
        "chdir(H cwd) 0",
        "H rel cwd HOSTCWD",
        "H fd HOSTCWD",
        "stat(H exe) 0",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain(std::iter::once(h_map_files))
    .collect();
    for config in [&["-R"][..], &["-b", "/proc", "-r"][..]] {
        assert_eq!(run(config), procfs, "{config:?}");
        // Nothing was written on the host: S, the host process's directory.
        assert_eq!(
            names(&s),
            ["file"],
            "{config:?}: a call reached the host's S"
        );
        assert_eq!(std::fs::read_to_string(s.join("file")).unwrap(), "HOST");
        assert_eq!(names(&scratch.join("hostcwd")), ["marker"]);
        assert!(inside(&root, &s).join("made").exists(), "{config:?}");
        std::fs::remove_file(inside(&root, &s).join("made")).unwrap();
    }
    // Without the real procfs at /proc there is no magic link to follow.
    let plain: Vec<String> = [
        "root(self) -1 errno 2",
        "root(thread-self) -1 errno 2",
        "root(pid) -1 errno 2",
        "root(task) -1 errno 2",
        "open(root) -1 errno 2",
        "chdir(root) -1 errno 2",
        "read after chdir(root) GUEST",
        "getcwd /",
        "create(root/made) -1 errno 2",
        "rel root -1 errno 2",
        "chdir(/gdir) 0",
        "cwd up -1 errno 2",
        "cwd hlink -1 errno 2",
        "task cwd up -1 errno 2",
        "rel cwd up -1 errno 2",
        "open(cwd) -1 errno 2",
        "fd up -1 errno 2",
        "fd hlink -1 errno 2",
        "fd sock -1 errno 2",
        "child root -1 errno 2",
        "child cwd up -1 errno 2",
        "child cwd -1 errno 2",
        "H root -1 errno 2",
        "H cwd -1 errno 2",
        "stat(H root) -1 errno 2",
        "chdir(H cwd) -1 errno 2",
        "H rel cwd -1 errno 2",
        "H fd -1 errno 2",
        "stat(H exe) -1 errno 2",
        "stat(H map_files) -1 errno 2",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(run(&["-r"]), plain, "-r");
    drop(host);
    std::fs::remove_dir_all(&scratch).unwrap();
}

/// The guest probe for bases with no guest name: a directory outside the
/// guest root received over a socket, a deleted directory, and a pipe.
const UNNAMED_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define UP "../../../../../../../../../../../../../../../../"

struct how { unsigned long long flags, mode, resolve; };

static void res(const char *what, long r) {
    if (r < 0) printf("%s -1 errno %d\n", what, errno);
    else printf("%s 0\n", what);
}

/* The first line of the file, or the errno. */
static void show(const char *what, int fd) {
    if (fd < 0) { printf("%s -1 errno %d\n", what, errno); return; }
    char b[64];
    ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    b[n < 0 ? 0 : n] = 0;
    char *nl = strchr(b, '\n');
    if (nl) *nl = 0;
    printf("%s %s\n", what, b);
}

/* A descriptor received over the socket at `name`, or -1. */
static int receive(const char *name) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    strncpy(a.sun_path, name, sizeof a.sun_path - 1);
    if (connect(s, (struct sockaddr *) &a, sizeof a) != 0) return -1;
    char byte, ctl[CMSG_SPACE(sizeof(int))];
    struct iovec io = { &byte, 1 };
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = ctl,
                        .msg_controllen = sizeof ctl };
    if (recvmsg(s, &m, 0) != 1) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof fd);
    close(s);
    return fd;
}

static void *second_thread(void *arg) {
    (void) arg;
    show("u4 thread open(marker)", open("marker", O_RDONLY));
    return NULL;
}

int main(int argc, char **argv) {
    /* argv: S (absolute). */
    if (argc < 2) return 2;
    const char *srel = argv[1] + 1;
    char p[1024];
    struct stat st;

    int n = receive("/hsock");
    res("recv", n);
    show("u1 openat(N,marker)", openat(n, "marker", O_RDONLY));
    res("u1s fstatat(N,marker)", fstatat(n, "marker", &st, 0));
    char sx[256];
    res("u1x statx(N,marker)", syscall(SYS_statx, n, "marker", 0, 0x7ff, sx));
    struct how h = { O_RDONLY, 0, 0 };
    show("u1o openat2(N,marker)", (int) syscall(SYS_openat2, n, "marker", &h, sizeof h));
    snprintf(p, sizeof p, "../%s/file", strrchr(argv[1], '/') + 1);
    show("u2 openat(N,../s/file)", openat(n, p, O_RDONLY));
    res("u3 fchdir(N)", fchdir(n));
    show("u3 open(marker)", open("marker", O_RDONLY));
    pthread_t t;
    if (pthread_create(&t, NULL, second_thread, NULL) == 0) pthread_join(t, NULL);
    snprintf(p, sizeof p, UP "%s/file", srel);
    show("u5 open(UP S/file)", open(p, O_RDONLY));
    res("u5 chdir(/)", chdir("/"));

    res("mkdir(/dd)", mkdir("/dd", 0755));
    int d = open("/dd", O_RDONLY | O_DIRECTORY);
    res("rmdir(/dd)", rmdir("/dd"));
    show("d1 openat(D,x)", openat(d, "x", O_RDONLY));
    snprintf(p, sizeof p, UP "%s/file", srel);
    show("d2 openat(D,UP S/file)", openat(d, p, O_RDONLY));
    res("d3 fchdir(D)", fchdir(d));
    show("d3 open(UP S/file)", open(p, O_RDONLY));
    res("d3 chdir(..)", chdir(".."));
    show("d3 open(gfile)", open("gfile", O_RDONLY));
    chdir("/");

    int pp[2];
    if (pipe(pp) != 0) return 3;
    show("p1 openat(P,x)", openat(pp[0], "x", O_RDONLY));
    show("p1 openat(P,../x)", openat(pp[0], "../x", O_RDONLY));
    return 0;
}
"#;

/// The host process for the unnamed-base rows: binds the socket at
/// argv[1], sends one connection a descriptor of the directory argv[2],
/// and waits until killed.
const UNNAMED_HOST_C: &str = r#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int dir = open(argv[2], O_RDONLY | O_DIRECTORY);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    strncpy(a.sun_path, argv[1], sizeof a.sun_path - 1);
    if (dir < 0 || bind(s, (struct sockaddr *) &a, sizeof a) != 0 || listen(s, 1) != 0) return 1;
    puts("ready");
    fflush(stdout);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        char byte = 'd', ctl[CMSG_SPACE(sizeof(int))];
        struct iovec io = { &byte, 1 };
        struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = ctl,
                            .msg_controllen = sizeof ctl };
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = SOL_SOCKET;
        h->cmsg_type = SCM_RIGHTS;
        h->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(h), &dir, sizeof dir);
        if (sendmsg(c, &m, 0) != 1) return 1;
        close(c);
    }
}
"#;

#[test]
fn unnamed_bases_never_reach_the_host() {
    let scratch = std::env::temp_dir().join(format!("literoot-unnamed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let root = scratch.join("root");
    for d in [root.join("bin"), scratch.join("s"), scratch.join("hdir")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let scratch = scratch.canonicalize().unwrap();
    let root = scratch.join("root");
    let built = cc(
        &root.join("bin/unnamedprobe"),
        UNNAMED_C,
        &["-static", "-pthread"],
    );
    if !fixture_or_skip(&built, "static unnamed-base probe") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let helper = scratch.join("unnamedhost");
    assert!(cc(&helper, UNNAMED_HOST_C, &["-static"]).status.success());
    // S holds HOST on the host and GUEST in the guest root; H, outside the
    // guest root, holds HOSTDIR.
    let s = scratch.join("s");
    std::fs::write(s.join("file"), "HOST").unwrap();
    std::fs::create_dir_all(inside(&root, &s)).unwrap();
    std::fs::write(inside(&root, &s).join("file"), "GUEST").unwrap();
    std::fs::write(root.join("gfile"), "GFILE").unwrap();
    let hdir = scratch.join("hdir");
    std::fs::write(hdir.join("marker"), "HOSTDIR").unwrap();

    let mut host = Command::new(&helper);
    host.arg(root.join("hsock"))
        .arg(&hdir)
        .stdout(std::process::Stdio::piped());
    let mut host = KillOnDrop(host.spawn().expect("start the host process"));
    {
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::BufReader::new(host.0.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
    }

    let expected: Vec<String> = [
        "recv 0",
        "u1 openat(N,marker) -1 errno 13",
        "u1s fstatat(N,marker) -1 errno 13",
        "u1x statx(N,marker) -1 errno 13",
        "u1o openat2(N,marker) -1 errno 13",
        "u2 openat(N,../s/file) -1 errno 13",
        "u3 fchdir(N) 0",
        "u3 open(marker) -1 errno 13",
        "u4 thread open(marker) -1 errno 13",
        "u5 open(UP S/file) -1 errno 13",
        "u5 chdir(/) 0",
        "mkdir(/dd) 0",
        "rmdir(/dd) 0",
        "d1 openat(D,x) -1 errno 2",
        "d2 openat(D,UP S/file) GUEST",
        "d3 fchdir(D) 0",
        "d3 open(UP S/file) GUEST",
        "d3 chdir(..) 0",
        "d3 open(gfile) GFILE",
        "p1 openat(P,x) -1 errno 20",
        "p1 openat(P,../x) -1 errno 20",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for config in [&["-R"][..], &["-r"][..]] {
        let mut cmd = Command::new(literoot_bin());
        cmd.args(config)
            .arg(&root)
            .args(["-w", "/", "/bin/unnamedprobe"])
            .arg(&s);
        let out = run_bounded(cmd, "unnamed-base probe");
        assert!(
            out.status.success(),
            "unnamed-base probe {config:?}: {out:?}"
        );
        let lines: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(lines, expected, "{config:?}");
        // Nothing reached the host: S and H are as they were.
        assert_eq!(
            names(&s),
            ["file"],
            "{config:?}: a call reached the host's S"
        );
        assert_eq!(std::fs::read_to_string(s.join("file")).unwrap(), "HOST");
        assert_eq!(names(&hdir), ["marker"], "{config:?}: a call reached H");
        assert_eq!(
            std::fs::read_to_string(hdir.join("marker")).unwrap(),
            "HOSTDIR"
        );
    }
    drop(host);
    std::fs::remove_dir_all(&scratch).unwrap();
}
