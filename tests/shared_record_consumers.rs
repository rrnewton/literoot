//! Shared-record consumer wiring through real literoot launches.
//!
//! These tests are the discriminators for the transport's
//! RootfsTool call sites: another process's synthetic
//! `/proc/<pid>/exe` and cmdline, cross-process UTS visibility,
//! and the behavior after the bounded snapshot fills. The
//! unit tests in `src/shared_record.rs` prove the store; this
//! file proves that guests actually publish and consume it.

use std::path::{Path, PathBuf};
use std::process::Command;

const GUEST_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static char fill_arg[100001];
static char victim_arg[129];

static int write_byte(int fd, char byte) {
    return write(fd, &byte, 1) == 1 ? 0 : -1;
}

static int read_byte(int fd) {
    char byte = 0;
    return read(fd, &byte, 1) == 1 ? 0 : -1;
}

static void print_cmdline(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("ERROR:%d", errno);
        return;
    }
    int c;
    while ((c = fgetc(f)) != EOF) {
        putchar(c == '\0' ? '|' : c);
    }
    fclose(f);
}

static void print_observed(pid_t pid) {
    char path[64];
    char exe[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(path, exe, sizeof(exe) - 1);
    if (n < 0) {
        printf("observed exe=ERROR:%d cmdline=", errno);
    } else {
        exe[n] = '\0';
        printf("observed exe=%s cmdline=", exe);
    }
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    print_cmdline(path);
    putchar('\n');
    fflush(stdout);
}

static int child_image(void) {
    if (getenv("SR_FAILED_EXEC") != NULL) {
        char *argv[] = {(char *)"bogus", (char *)"zzz", NULL};
        execve("/bin/nonexist", argv, environ);
    }
    const char *fd_text = getenv("SR_READY_FD");
    if (fd_text != NULL) {
        (void)write_byte(atoi(fd_text), 'R');
    }
    sleep(10);
    return 0;
}

static int observe(int do_exec) {
    int ready[2];
    if (pipe(ready) != 0) return 101;
    pid_t pid = fork();
    if (pid < 0) return 102;
    if (pid == 0) {
        close(ready[0]);
        if (do_exec) {
            char fd_text[32];
            snprintf(fd_text, sizeof(fd_text), "%d", ready[1]);
            setenv("SR_READY_FD", fd_text, 1);
            setenv("SR_CHILD_IMAGE", "1", 1);
            const char *path = getenv("SR_EXEC_PATH");
            char *argv[] = {(char *)"renamed", (char *)"argA", NULL};
            execve(path, argv, environ);
            _exit(111);
        }
        if (write_byte(ready[1], 'R') != 0) _exit(112);
        sleep(10);
        _exit(0);
    }
    close(ready[1]);
    if (read_byte(ready[0]) != 0) return 103;
    print_observed(pid);
    printf("shared_env=%s\n", getenv("LITEROOT_SHARED_RECORD_FD") ? "present" : "absent");
    fflush(stdout);
    kill(pid, SIGKILL);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 104;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 105;
}

static int forkfill(void) {
    const char *seq_text = getenv("SR_SEQ");
    const char *par_text = getenv("SR_PAR");
    int seq = seq_text == NULL ? 0 : atoi(seq_text);
    int par = par_text == NULL ? 0 : atoi(par_text);
    if (seq < 0 || par < 0 || par > 64) return 601;
    for (int i = 0; i < seq; i++) {
        pid_t pid = fork();
        if (pid < 0) return 602;
        if (pid == 0) _exit(0);
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) return 603;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 604;
    }
    pid_t kids[64];
    for (int i = 0; i < par; i++) {
        pid_t pid = fork();
        if (pid < 0) return 605;
        if (pid == 0) {
            usleep(20000);
            _exit(0);
        }
        kids[i] = pid;
    }
    for (int i = 0; i < par; i++) {
        int status = 0;
        if (waitpid(kids[i], &status, 0) < 0) return 606;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 607;
    }
    return 0;
}

static int uts_length(void) {
    char node65[66];
    char domain65[66];
    memset(node65, 'N', 65);
    node65[65] = '\0';
    memset(domain65, 'D', 65);
    domain65[65] = '\0';
    if (sethostname("first", 5) != 0) return 501;
    if (setdomainname("domfirst", 8) != 0) return 502;
    errno = 0;
    int rc_node = sethostname(node65, 65);
    int errno_node = errno;
    errno = 0;
    int rc_domain = setdomainname(domain65, 65);
    int errno_domain = errno;
    struct utsname uts;
    if (uname(&uts) != 0) return 503;
    printf("uts=%s|%s rc_node=%d errno_node=%d rc_domain=%d errno_domain=%d\n",
           uts.nodename, uts.domainname, rc_node, errno_node, rc_domain, errno_domain);
    fflush(stdout);
    return 0;
}

static int uts_observe(void) {
    int ready[2];
    if (pipe(ready) != 0) return 201;
    pid_t pid = fork();
    if (pid < 0) return 202;
    if (pid == 0) {
        close(ready[0]);
        if (sethostname("child-set", 9) != 0) _exit(211);
        if (write_byte(ready[1], 'R') != 0) _exit(212);
        sleep(10);
        _exit(0);
    }
    close(ready[1]);
    if (read_byte(ready[0]) != 0) return 203;
    struct utsname uts;
    if (uname(&uts) != 0) return 204;
    printf("uts=%s\n", uts.nodename);
    print_observed(pid);
    fflush(stdout);
    kill(pid, SIGKILL);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 205;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 206;
}

static int run_filler(size_t len) {
    if (len >= sizeof(fill_arg)) return 301;
    memset(fill_arg, 'F', len);
    fill_arg[len] = '\0';
    pid_t pid = fork();
    if (pid < 0) return 302;
    if (pid == 0) {
        setenv("SR_MODE", "filler", 1);
        char *argv[] = {(char *)"f", fill_arg, NULL};
        execve("/bin/f", argv, environ);
        _exit(311);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 303;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 304;
}

static int capfill(void) {
    memset(victim_arg, 'V', 128);
    victim_arg[128] = '\0';
    if (sethostname("first", 5) != 0) return 401;

    int ready[2];
    int go[2];
    if (pipe(ready) != 0 || pipe(go) != 0) return 402;
    pid_t victims[2];
    for (int i = 0; i < 2; i++) {
        pid_t victim = fork();
        if (victim < 0) return 403;
        if (victim == 0) {
            close(ready[0]);
            close(go[1]);
            if (write_byte(ready[1], 'R') != 0) _exit(411);
            if (read_byte(go[0]) != 0) _exit(412);
            char fd_text[32];
            snprintf(fd_text, sizeof(fd_text), "%d", ready[1]);
            setenv("SR_READY_FD", fd_text, 1);
            setenv("SR_CHILD_IMAGE", "1", 1);
            char *argv[] = {(char *)"BIGEXEC", victim_arg, NULL};
            execve("/bin/h", argv, environ);
            _exit(413);
        }
        victims[i] = victim;
    }
    close(ready[1]);
    close(go[0]);
    if (read_byte(ready[0]) != 0 || read_byte(ready[0]) != 0) return 404;

    for (int i = 0; i < 10; i++) {
        int rc = run_filler(100000);
        if (rc != 0) return rc;
    }
    const char *final_len = getenv("SR_FINAL_FILL_LEN");
    if (final_len == NULL) return 405;
    int rc = run_filler((size_t)atoi(final_len));
    if (rc != 0) return rc;

    if (sethostname("second-longer-name", 18) != 0) return 406;
    if (setdomainname("second-longer-domain", 20) != 0) return 415;
    struct utsname uts;
    if (uname(&uts) != 0) return 407;
    printf("uts=%s|%s\n", uts.nodename, uts.domainname);
    fflush(stdout);

    if (write_byte(go[1], 'G') != 0 || write_byte(go[1], 'G') != 0) return 408;
    if (read_byte(ready[0]) != 0 || read_byte(ready[0]) != 0) return 409;
    for (int i = 0; i < 2; i++) {
        print_observed(victims[i]);
        kill(victims[i], SIGKILL);
        int status = 0;
        if (waitpid(victims[i], &status, 0) < 0) return 410;
        if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 414;
    }
    return 0;
}

int main(void) {
    if (getenv("SR_CHILD_IMAGE") != NULL) return child_image();
    const char *mode = getenv("SR_MODE");
    if (mode == NULL || strcmp(mode, "observe-fork") == 0) return observe(0);
    if (strcmp(mode, "observe-exec") == 0) return observe(1);
    if (strcmp(mode, "forkfill") == 0) return forkfill();
    if (strcmp(mode, "uts-length") == 0) return uts_length();
    if (strcmp(mode, "uts-observe") == 0) return uts_observe();
    if (strcmp(mode, "capfill") == 0) return capfill();
    if (strcmp(mode, "filler") == 0) return 0;
    return 99;
}
"#;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

fn preload_path() -> Option<PathBuf> {
    let preload = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("preload/target/release/libliteroot_preload.so");
    if preload.exists() {
        return Some(preload);
    }
    if std::env::var_os("LITEROOT_ALLOW_SKIP_PRELOAD").is_some() {
        eprintln!("shared_record_consumers: preload not built — skipping in-guest cases");
        return None;
    }
    panic!(
        "shared_record_consumers: preload not built at {} — build it with \
         cargo build -p literoot-preload --release --manifest-path preload/Cargo.toml \
         or set LITEROOT_ALLOW_SKIP_PRELOAD=1",
        preload.display()
    );
}

fn base_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "literoot-shared-consumers-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_guest(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let source = dir.join("src/shared_consumers.c");
    let binary = dir.join("sr");
    std::fs::write(&source, GUEST_C).unwrap();
    let out = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("spawn cc for shared-record guest");
    assert!(
        out.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    binary
}

fn make_root(root: &Path, guest: &Path) {
    let _ = std::fs::remove_dir_all(root);
    for sub in ["bin", "lib64", "dev", "proc"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    for name in ["sr", "h", "f"] {
        std::fs::copy(guest, root.join("bin").join(name)).unwrap();
    }
    std::os::unix::fs::symlink("h", root.join("bin/hlink")).unwrap();
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        std::fs::copy(format!("/lib64/{lib}"), root.join("lib64").join(lib)).unwrap();
    }
}

fn run_literoot(
    root: &Path,
    backend: Option<&str>,
    fake_root: bool,
    guest_args: &[&str],
    envs: &[(&str, &str)],
    preload: Option<&Path>,
) -> (String, String, std::process::ExitStatus) {
    let mut cmd = Command::new(literoot_bin());
    if let Some(backend) = backend {
        cmd.args(["--backend", backend]);
    }
    if fake_root {
        cmd.arg("-0");
    }
    cmd.args(["-R", root.to_str().unwrap()]).args(guest_args);
    if let Some(preload) = preload {
        cmd.env("LITEROOT_PRELOAD", preload);
    }
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("spawn literoot shared-record guest");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status,
    )
}

fn fixture_libs_available() -> bool {
    if Path::new("/lib64/libc.so.6").exists() && Path::new("/lib64/ld-linux-x86-64.so.2").exists() {
        return true;
    }
    eprintln!("shared_record_consumers: host fixture libraries unavailable — skipping");
    false
}

#[test]
fn ptrace_parent_reads_fork_child_shared_exe_and_cmdline() {
    if !fixture_libs_available() {
        return;
    }
    let dir = base_dir("ptrace-fork");
    let guest = build_guest(&dir);
    let root = dir.join("root");
    make_root(&root, &guest);
    let (stdout, stderr, status) = run_literoot(
        &root,
        Some("ptrace"),
        false,
        &["/bin/sr", "argA"],
        &[
            ("SR_MODE", "observe-fork"),
            ("LITEROOT_SHARED_RECORD_FD", "7"),
        ],
        None,
    );
    assert!(
        status.success(),
        "status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("observed exe=/bin/sr cmdline=/bin/sr|argA|"),
        "shared fork row not consumed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("shared_env=absent"),
        "ptrace guest must not receive the shared-record env: stdout={stdout:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ptrace_parent_reads_exec_child_canonical_exe_and_cmdline() {
    if !fixture_libs_available() {
        return;
    }
    let dir = base_dir("ptrace-exec");
    let guest = build_guest(&dir);
    for (name, exec_path) in [("direct", "/bin/h"), ("symlink", "/bin/hlink")] {
        let root = dir.join(format!("root-{name}"));
        make_root(&root, &guest);
        let (stdout, stderr, status) = run_literoot(
            &root,
            Some("ptrace"),
            false,
            &["/bin/sr", "argA"],
            &[("SR_MODE", "observe-exec"), ("SR_EXEC_PATH", exec_path)],
            None,
        );
        assert!(
            status.success(),
            "{name}: status={status} stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains("observed exe=/bin/h cmdline=renamed|argA|"),
            "{name}: canonical shared exec row not consumed: stdout={stdout:?} stderr={stderr:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn inguest_parent_sees_child_hostname_and_shared_row() {
    if !fixture_libs_available() {
        return;
    }
    let Some(preload) = preload_path() else {
        return;
    };
    let dir = base_dir("inguest-uts");
    let guest = build_guest(&dir);
    let root = dir.join("root");
    make_root(&root, &guest);
    let (stdout, stderr, status) = run_literoot(
        &root,
        Some("liteinst"),
        true,
        &["/bin/sr", "argA"],
        &[("SR_MODE", "uts-observe")],
        Some(&preload),
    );
    assert!(
        status.success(),
        "status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("uts=child-set"),
        "shared UTS field not consumed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("observed exe=/bin/sr cmdline=/bin/sr|argA|"),
        "shared fork row not consumed in-guest: stdout={stdout:?} stderr={stderr:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn liteinst_sequential_forks_print_one_publish_refusal() {
    if !fixture_libs_available() {
        return;
    }
    let Some(preload) = preload_path() else {
        return;
    };
    let dir = base_dir("liteinst-forkfill-seq");
    let guest = build_guest(&dir);
    let root = dir.join("root");
    make_root(&root, &guest);
    // The parent row and each fork child's row carry this
    // ~120 KB argv, so the 1 MiB snapshot fills after roughly
    // eight forks; the remaining forks are refused publishes.
    let big_arg = "B".repeat(120_000);
    let (stdout, stderr, status) = run_literoot(
        &root,
        Some("liteinst"),
        true,
        &["/bin/sr", &big_arg],
        &[("SR_MODE", "forkfill"), ("SR_SEQ", "12"), ("SR_PAR", "0")],
        Some(&preload),
    );
    assert!(
        status.success(),
        "status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert_eq!(
        stderr.matches("shared record publish refused").count(),
        1,
        "sequential in-guest forks must print one refusal line: stderr={stderr:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn liteinst_concurrent_forks_print_one_publish_refusal_repeatedly() {
    if !fixture_libs_available() {
        return;
    }
    let Some(preload) = preload_path() else {
        return;
    };
    let dir = base_dir("liteinst-forkfill-par");
    let guest = build_guest(&dir);
    let root = dir.join("root");
    make_root(&root, &guest);
    let big_arg = "B".repeat(120_000);
    for run in 0..10 {
        let (stdout, stderr, status) = run_literoot(
            &root,
            Some("liteinst"),
            true,
            &["/bin/sr", &big_arg],
            &[("SR_MODE", "forkfill"), ("SR_SEQ", "9"), ("SR_PAR", "40")],
            Some(&preload),
        );
        assert!(
            status.success(),
            "run {run}: status={status} stdout={stdout:?} stderr={stderr:?}"
        );
        assert_eq!(
            stderr.matches("shared record publish refused").count(),
            1,
            "run {run}: concurrent in-guest forks must print one refusal line: stderr={stderr:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ptrace_parent_keeps_successful_exec_row_after_failed_exec() {
    if !fixture_libs_available() {
        return;
    }
    let dir = base_dir("ptrace-failed-exec");
    let guest = build_guest(&dir);
    let root = dir.join("root");
    make_root(&root, &guest);
    let (stdout, stderr, status) = run_literoot(
        &root,
        Some("ptrace"),
        false,
        &["/bin/sr", "argA"],
        &[
            ("SR_MODE", "observe-exec"),
            ("SR_EXEC_PATH", "/bin/h"),
            ("SR_FAILED_EXEC", "1"),
        ],
        None,
    );
    assert!(
        status.success(),
        "status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("observed exe=/bin/h cmdline=renamed|argA|"),
        "failed exec must not replace the successful shared row: stdout={stdout:?} stderr={stderr:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn overlong_uts_names_return_einval_and_leave_both_fields_unchanged() {
    if !fixture_libs_available() {
        return;
    }
    let dir = base_dir("uts-length");
    let guest = build_guest(&dir);
    for (name, backend, preload) in [
        ("ptrace", Some("ptrace"), None),
        ("liteinst", Some("liteinst"), preload_path()),
    ] {
        if backend == Some("liteinst") && preload.is_none() {
            continue;
        }
        let root = dir.join(format!("root-{name}"));
        make_root(&root, &guest);
        let (stdout, stderr, status) = run_literoot(
            &root,
            backend,
            true,
            &["/bin/sr"],
            &[("SR_MODE", "uts-length")],
            preload.as_deref(),
        );
        assert!(
            status.success(),
            "{name}: status={status} stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains(
                "uts=first|domfirst rc_node=-1 errno_node=22 rc_domain=-1 errno_domain=22"
            ),
            "{name}: overlong UTS write was not EINVAL/unchanged: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stderr.contains("shared record"),
            "{name}: EINVAL must precede any shared-store write: stderr={stderr:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn snapshot_row_len(exe_len: usize, argv_lens: &[usize]) -> usize {
    12 + 4 + exe_len + 4 + argv_lens.iter().map(|len| 4 + len).sum::<usize>()
}

#[test]
fn cap_filled_shared_record_reports_refusals_without_stale_values() {
    if !fixture_libs_available() {
        return;
    }
    let dir = base_dir("capfill");
    let guest = build_guest(&dir);
    let root = dir.join("root");
    make_root(&root, &guest);

    // Leave exactly two payload bytes of headroom. Parent and
    // both pre-exec victim rows are each /bin/sr with one argv
    // item; each filler row is /bin/f with argv ["f", <bytes>].
    // The first UTS field is the five-byte string "first".
    const MAX_ENCODED_BYTES: usize = 1024 * 1024;
    let header_and_first_uts = 8 + (4 + 5) + 4;
    let parent_row = snapshot_row_len("/bin/sr".len(), &["/bin/sr".len()]);
    let big_filler_row = snapshot_row_len("/bin/f".len(), &[1, 100_000]);
    let final_filler_overhead = snapshot_row_len("/bin/f".len(), &[1, 0]);
    let final_len = MAX_ENCODED_BYTES
        - 2
        - header_and_first_uts
        - (3 * parent_row)
        - (10 * big_filler_row)
        - final_filler_overhead;
    assert!(
        final_len < 100_000,
        "computed final filler length {final_len}"
    );
    let final_len_text = final_len.to_string();

    let (stdout, stderr, status) = run_literoot(
        &root,
        Some("ptrace"),
        true,
        &["/bin/sr"],
        &[
            ("SR_MODE", "capfill"),
            ("SR_FINAL_FILL_LEN", &final_len_text),
        ],
        None,
    );
    assert!(
        status.success(),
        "status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("uts=second-longer-name|second-longer-domain"),
        "refused UTS writes left a stale shared field: stdout={stdout:?} stderr={stderr:?}"
    );
    let expected_victim = format!("observed exe=/bin/h cmdline=BIGEXEC|{}|", "V".repeat(128));
    assert_eq!(
        stdout.matches(&expected_victim).count(),
        2,
        "refused exec publishes left a stale shared row: stdout={stdout:?} stderr={stderr:?}"
    );
    assert_eq!(
        stderr
            .matches("shared record UTS nodename write refused")
            .count(),
        1,
        "UTS refusal must be reported exactly once: stderr={stderr:?}"
    );
    assert_eq!(
        stderr
            .matches("shared record UTS domainname write refused")
            .count(),
        1,
        "domainname refusal must be reported exactly once: stderr={stderr:?}"
    );
    assert_eq!(
        stderr.matches("shared record publish refused").count(),
        1,
        "two refused publishes across exec must print one line: stderr={stderr:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
