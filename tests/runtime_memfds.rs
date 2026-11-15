//! The launcher-created shared memfds (the probe-cache generation and
//! the cross-process facts record) are out of the guest's reach by
//! number on every in-guest route, and still serve the whole guest tree.
//!
//! The guest finds each memfd itself, by listing /proc/self/fd and
//! reading each link, then calls fcntl(F_GETFD) on that number. Before
//! the fix every in-guest process held both at numbers it could use
//! (fcntl succeeded); now each process holds exactly one copy of each,
//! at a number the runtime keeps from it (EBADF). The ptrace route hands
//! the guest no copy at all, before and after.
//!
//! The same run is the descendant check: a root, its fork child and that
//! child's fork child each scan; then the grandchild sets the hostname
//! (the shared record) and replaces a symlink the root has already
//! resolved with a real directory (the probe generation). The root must
//! see both.
//!
//! The root opens a file before it forks. Under LiteInst that has the
//! guest's own open() site patched, so a libc open from literoot's
//! runtime in a fork child enters the runtime's hook (and its clock,
//! which closes the inherited copies) instead of trapping: the condition
//! under which a libc reopen in the child lost both memfds. The
//! kill-on-exit variant also has the child's Tool construction read /proc
//! through libc before its thread start.
//!
//! The guest also prints, as an observation only, whether an open by
//! path of each runtime-range descriptor succeeds: Reverie's own sockets
//! and anonymous inodes cannot be reopened by path (ENXIO), and the
//! memfds can (the stated residual).
//!
//! The literoot binary under test uses its embedded preload (no
//! LITEROOT_PRELOAD), as an installed literoot does.

use std::path::{Path, PathBuf};
use std::process::Command;

const GUEST_C: &str = r#"
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *path_open(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        return "ok";
    }
    return errno == ENXIO ? "ENXIO" : errno == EACCES ? "EACCES" : "other";
}

/* Each descriptor whose link names one of literoot's shared memfds:
   what fcntl(F_GETFD) on that number does, then the counts. */
static void scan(const char *who) {
    int numbers[1024];
    int n = 0;
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL) {
        printf("%s scan=ERROR:%d\n", who, errno);
        return;
    }
    int own = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && n < 1024) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && fd != own) numbers[n++] = (int)fd;
    }
    closedir(dir);
    int counts[2] = {0, 0};
    for (int i = 0; i < n; i++) {
        char path[64];
        char link[256];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", numbers[i]);
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len < 0) continue;
        link[len] = '\0';
        int which = strstr(link, "literoot-probe-gen") ? 0
                  : strstr(link, "literoot-shared-record") ? 1 : -1;
        if (which >= 0) {
            const char *name = which ? "shared-record" : "probe-gen";
            counts[which]++;
            errno = 0;
            int flags = fcntl(numbers[i], F_GETFD);
            printf("%s memfd=%s fcntl=%s\n", who, name,
                   flags >= 0 ? "ok" : errno == EBADF ? "EBADF" : "other");
            printf("%s memfd=%s path-open=%s\n", who, name, path_open(path));
        } else if (numbers[i] >= 1000 && strncmp(link, "socket:", 7) == 0) {
            printf("%s runtime-socket path-open=%s\n", who, path_open(path));
        } else if (numbers[i] >= 1000 && strncmp(link, "anon_inode:", 11) == 0) {
            printf("%s runtime-anon-inode path-open=%s\n", who, path_open(path));
        }
    }
    printf("%s count probe-gen=%d shared-record=%d\n", who, counts[0], counts[1]);
}

static int read_text(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t len = read(fd, buf, size - 1);
    close(fd);
    if (len < 0) return -1;
    buf[len] = '\0';
    return 0;
}

static int wait_ok(pid_t pid) {
    int status = 0;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[64];
    /* The root resolves /link (a symlink to /d1) first, so its probe
       cache holds the symlink kind. */
    if (read_text("/link/file", buf, sizeof(buf)) != 0 || strcmp(buf, "from-d1\n") != 0) return 10;
    scan("root");
    pid_t child = fork();
    if (child < 0) return 11;
    if (child == 0) {
        scan("child");
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(21);
        if (grandchild == 0) {
            scan("grandchild");
            if (sethostname("grandchild-set", 14) != 0) _exit(31);
            if (unlink("/link") != 0 || mkdir("/link", 0755) != 0) _exit(32);
            int fd = open("/link/file", O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd < 0 || write(fd, "from-realdir\n", 13) != 13) _exit(33);
            close(fd);
            _exit(0);
        }
        _exit(wait_ok(grandchild) ? 0 : 22);
    }
    if (!wait_ok(child)) return 12;
    struct utsname uts;
    if (uname(&uts) != 0) return 13;
    printf("root uts=%s\n", uts.nodename);
    if (read_text("/link/file", buf, sizeof(buf)) != 0) return 14;
    printf("root link-file=%s", buf);
    return 0;
}
"#;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

/// A fresh rootfs with the guest, the host's libc and loader, and the
/// /link -> /d1 fixture.
fn make_root(label: &str) -> PathBuf {
    for lib in ["/lib64/libc.so.6", "/lib64/ld-linux-x86-64.so.2"] {
        assert!(Path::new(lib).exists(), "fixture library {lib} is missing");
    }
    let dir = std::env::temp_dir().join(format!(
        "literoot-runtime-memfds-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let source = dir.join("src/memfds.c");
    let binary = dir.join("memfds");
    std::fs::write(&source, GUEST_C).unwrap();
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("spawn cc");
    assert!(
        cc.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&cc.stderr)
    );
    let root = dir.join("root");
    for sub in ["bin", "lib64", "dev", "proc", "sys", "d1"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    std::fs::copy(&binary, root.join("bin/memfds")).unwrap();
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        std::fs::copy(format!("/lib64/{lib}"), root.join("lib64").join(lib)).unwrap();
    }
    std::fs::write(root.join("d1/file"), "from-d1\n").unwrap();
    std::os::unix::fs::symlink("/d1", root.join("link")).unwrap();
    root
}

/// Runs the guest under `backend` with fake root (sethostname) and the
/// default binds, and returns its stdout and stderr.
fn run(backend: &str) -> (String, String) {
    run_with(backend, backend, &[])
}

/// `run` with `extra` launcher arguments, in a root named after `label`.
fn run_with(backend: &str, label: &str, extra: &[&str]) -> (String, String) {
    let root = make_root(label);
    let out = Command::new(literoot_bin())
        .args(extra)
        .args(["--backend", backend, "-0", "-R"])
        .arg(&root)
        .arg("/bin/memfds")
        .env_remove("LITEROOT_PRELOAD")
        .env("PATH", "/bin:/usr/bin")
        .output()
        .expect("spawn literoot");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "{backend}: status={} stdout={stdout:?} stderr={stderr:?}",
        out.status
    );
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
    println!("{backend} stdout:\n{stdout}");
    (stdout, stderr)
}

/// Every process of the tree saw `count` copies of each memfd, and every
/// copy it saw refused fcntl by number; the grandchild's hostname and
/// directory reached the root; and literoot reported no lost memfd.
fn check(backend: &str, (stdout, stderr): &(String, String), count: usize) {
    for who in ["root", "child", "grandchild"] {
        let line = format!("{who} count probe-gen={count} shared-record={count}");
        assert!(
            stdout.lines().any(|l| l == line),
            "{backend}: expected {line:?}: {stdout}"
        );
        for memfd in ["probe-gen", "shared-record"] {
            let prefix = format!("{who} memfd={memfd} fcntl=");
            for l in stdout.lines().filter(|l| l.starts_with(&prefix)) {
                assert_eq!(
                    l,
                    format!("{prefix}EBADF"),
                    "{backend}: {who} can use the {memfd} memfd by number: {stdout}"
                );
            }
        }
    }
    assert!(
        stdout.lines().any(|l| l == "root uts=grandchild-set"),
        "{backend}: the grandchild's hostname did not reach the root (shared record): {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l == "root link-file=from-realdir"),
        "{backend}: the grandchild's directory did not reach the root (probe generation): {stdout}"
    );
    assert!(
        !stderr.contains("unavailable in this process"),
        "{backend}: literoot lost a shared memfd: {stderr}"
    );
}

#[cfg(feature = "in-guest")]
#[test]
fn liteinst_tree_holds_each_memfd_once_out_of_reach_by_number() {
    check("liteinst", &run("liteinst"), 1);
}

#[cfg(feature = "in-guest")]
#[test]
fn liteinst_tree_with_kill_on_exit_holds_each_memfd_once() {
    check(
        "liteinst",
        &run_with("liteinst", "liteinst-koe", &["--kill-on-exit"]),
        1,
    );
}

#[cfg(any(feature = "in-guest", feature = "inguest-trap"))]
#[test]
fn trap_tree_holds_each_memfd_once_out_of_reach_by_number() {
    check("trap", &run("trap"), 1);
}

#[cfg(feature = "run")]
#[test]
fn ptrace_tree_holds_no_memfd_copy() {
    check("ptrace", &run("ptrace"), 0);
}
