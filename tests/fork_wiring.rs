//! Fork-seed wiring through a real literoot launch.
//!
//! The guest prints its synthetic `/proc/self/exe` and
//! `/proc/self/cmdline` in the child first, then in the
//! parent after `waitpid`. The fork child must inherit the
//! *parent image's* exe/argv, not values re-resolved from
//! the cwd at fork time or the launch argv after an exec.

use std::path::{Path, PathBuf};
use std::process::Command;

const FORK_GUEST_C: &str = r#"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void print_pair(const char *label) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) {
        printf("%s exe=ERROR:%d cmdline=\n", label, errno);
    } else {
        exe[n] = '\0';
        printf("%s exe=%s cmdline=", label, exe);
    }
    FILE *f = fopen("/proc/self/cmdline", "rb");
    if (f != NULL) {
        int c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c == '\0' ? '|' : c);
        }
        fclose(f);
    }
    putchar('\n');
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (getenv("FP_DO_EXEC") != NULL && getenv("FP_EXECED") == NULL) {
        char *new_argv[] = {(char *)"renamed", (char *)"extra", NULL};
        setenv("FP_EXECED", "1", 1);
        execve("/bin/other", new_argv, environ);
        printf("exec_failed=%d\n", errno);
        return 111;
    }
    if (getenv("FP_EXECED") == NULL && argc > 1) {
        if (chdir(argv[1]) != 0) {
            printf("chdir_failed=%d\n", errno);
            return 112;
        }
    }
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork_failed=%d\n", errno);
        return 113;
    }
    if (pid == 0) {
        print_pair("child");
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        printf("wait_failed=%d\n", errno);
        return 114;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("child_status=%d\n", status);
        return 115;
    }
    print_pair("parent");
    return 0;
}
"#;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

fn build_guest(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let source = dir.join("src/forkprog.c");
    let binary = dir.join("fp");
    std::fs::write(&source, FORK_GUEST_C).unwrap();
    let out = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("spawn cc for fork guest");
    assert!(
        out.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    binary
}

fn make_root(root: &Path, guest: &Path) {
    let _ = std::fs::remove_dir_all(root);
    for sub in ["bin", "lib64", "work/sub", "dev", "proc"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    std::fs::copy(guest, root.join("work/fp")).unwrap();
    std::fs::copy(guest, root.join("bin/fp")).unwrap();
    std::fs::copy(guest, root.join("bin/other")).unwrap();
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        std::fs::copy(format!("/lib64/{lib}"), root.join("lib64").join(lib)).unwrap();
    }
}

fn run(
    root: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> (String, String, std::process::ExitStatus) {
    let mut cmd = Command::new(literoot_bin());
    cmd.args(["-R", root.to_str().unwrap()]).args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("spawn literoot fork guest");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status,
    )
}

fn pair(stdout: &str, label: &str) -> (String, String) {
    let line = stdout
        .lines()
        .find(|line| line.starts_with(&format!("{label} exe=")))
        .unwrap_or_else(|| panic!("missing {label} line in stdout: {stdout:?}"));
    let rest = line
        .strip_prefix(&format!("{label} exe="))
        .expect("label prefix");
    let (exe, cmdline) = rest
        .split_once(" cmdline=")
        .unwrap_or_else(|| panic!("malformed {label} line: {line:?}"));
    (exe.to_string(), cmdline.to_string())
}

fn base_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "literoot-fork-wiring-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn relative_launch_exe_and_exec_image_survive_fork() {
    if !Path::new("/lib64/libc.so.6").exists() {
        eprintln!("fork_wiring: host fixture libraries unavailable — skipping");
        return;
    }
    let dir = base_dir("relative");
    let guest = build_guest(&dir);

    for (name, launch_args, expected_exe, expected_cmdline) in [
        (
            "dot",
            &["-w", "/work", "./fp", "/bin"][..],
            "/work/fp",
            "./fp|/bin|",
        ),
        (
            "dotdot",
            &["-w", "/bin", "../work/fp", "/work/sub"][..],
            "/work/fp",
            "../work/fp|/work/sub|",
        ),
    ] {
        let root = dir.join(format!("root-{name}"));
        make_root(&root, &guest);
        let (stdout, stderr, status) = run(&root, launch_args, &[]);
        assert!(
            status.success(),
            "{name}: literoot failed status={status} stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stderr.contains("fork seed refused"),
            "{name}: bootstrapped parent refused: {stderr:?}"
        );
        let parent = pair(&stdout, "parent");
        let child = pair(&stdout, "child");
        assert_eq!(
            parent.0, expected_exe,
            "{name}: parent exe (stdout={stdout:?})"
        );
        assert_eq!(
            parent.1, expected_cmdline,
            "{name}: parent cmdline (stdout={stdout:?})"
        );
        assert_eq!(child, parent, "{name}: child exe/cmdline must equal parent");
    }

    let root = dir.join("root-exec");
    make_root(&root, &guest);
    let (stdout, stderr, status) = run(&root, &["/bin/fp"], &[("FP_DO_EXEC", "1")]);
    assert!(
        status.success(),
        "exec case failed status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("fork seed refused"),
        "exec case: bootstrapped parent refused: {stderr:?}"
    );
    let parent = pair(&stdout, "parent");
    let child = pair(&stdout, "child");
    assert_eq!(
        parent,
        ("/bin/other".to_string(), "renamed|extra|".to_string())
    );
    assert_eq!(
        child, parent,
        "exec case: child must inherit post-exec image"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_postexec_fork_proceeds_unstaged_and_logs_refusal() {
    if !Path::new("/lib64/libc.so.6").exists() {
        eprintln!("fork_wiring: host fixture libraries unavailable — skipping");
        return;
    }
    let dir = base_dir("nopostexec");
    let guest = build_guest(&dir);
    let root = dir.join("root-nopostexec");
    make_root(&root, &guest);
    let (stdout, stderr, status) = run(
        &root,
        &["-w", "/work", "./fp", "/bin"],
        &[("LITEROOT_NO_POSTEXEC", "1")],
    );
    assert!(
        status.success(),
        "unstaged clone must proceed: status={status} stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("literoot: fork seed refused: parent not bootstrapped"),
        "named refusal missing from stderr: {stderr:?} stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("fork_failed="),
        "guest fork failed: {stdout:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
