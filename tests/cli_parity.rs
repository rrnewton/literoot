//! The launcher's command line end to end: the refusal-log scan and
//! `parse_cli` together, on the production binary, with `--check` (no
//! guest runs).

mod common;

use std::path::PathBuf;
use std::process::Command;

fn own_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run literoot with `argv` and `--refusal-log` after it; returns the exit
/// code and the log's refusal lines (`Err` when the log is missing or not
/// valid).
fn run(
    dir: &std::path::Path,
    name: &str,
    argv: &[&str],
) -> (Option<i32>, Result<Vec<String>, String>) {
    let log = dir.join(name);
    let mut cmd = Command::new(common::literoot_bin());
    cmd.args(&argv[..argv.len() - 2]);
    cmd.arg("--refusal-log").arg(&log);
    cmd.args(&argv[argv.len() - 2..]);
    let out = common::run_bounded(cmd, name);
    let checked = Command::new(common::literoot_bin())
        .arg("--check-refusal-log")
        .arg(&log)
        .output()
        .expect("run literoot --check-refusal-log");
    let refusals = if checked.status.success() {
        Ok(String::from_utf8_lossy(&checked.stdout)
            .lines()
            .map(str::to_owned)
            .collect())
    } else {
        Err(String::from_utf8_lossy(&checked.stderr).into_owned())
    };
    (out.status.code(), refusals)
}

#[test]
fn proot_long_aliases_keep_a_later_refusal_log() {
    let dir = own_dir("aliases");
    for (name, option, value) in [
        ("pwd", "--pwd", "/tmp"),
        ("change-id", "--change-id", "5:6"),
    ] {
        assert_eq!(
            run(&dir, name, &[option, value, "--check", "/"]),
            (Some(0), Ok(vec![])),
            "{option}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn verbosity_proot_accepts_runs_and_verbosity_it_refuses_is_exempt() {
    let dir = own_dir("verbose");
    // proot's strtol reads level 1 from "1junk": the run goes ahead.
    assert_eq!(
        run(&dir, "junk", &["--verbose=1junk", "--check", "/"]),
        (Some(0), Ok(vec![]))
    );
    // No digits: proot refuses as well, so no refusal is recorded.
    assert_eq!(
        run(&dir, "letters", &["--verbose=x", "--check", "/"]),
        (Some(125), Ok(vec![]))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
