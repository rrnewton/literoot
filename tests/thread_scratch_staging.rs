//! Each guest thread stages its paths in its own scratch page
//! (https://github.com/rrnewton/literoot/issues/8). A static guest in a
//! scratch rootfs starts 4 threads together; each opens its own file 1500
//! times through `openat` and checks what it read. The four names have one
//! length, so their translated host paths do too.
//!
//! On the ptrace backend literoot stages every translated path in guest
//! memory and injects the call with a pointer to it. With one page per
//! process, a second thread's staging could overwrite the first's before
//! the first thread's kernel call read the name, and that thread opened
//! the other thread's file: a wrong-file open. With a page per thread no
//! other thread ever writes the page a call names, so every open reaches
//! the caller's own file.
//!
//! Without the per-thread page the overwrite is a race, not a certainty:
//! whether a run shows it depends on how the host schedules the tracer
//! against the woken guest thread.
//!
//! The ptrace backend is built only with the `run` feature (the default,
//! and ptrace-only); a trap-only build compiles it out and refuses it by
//! name, so there this file is empty.

#![cfg(feature = "run")]

mod common;

use std::process::Command;

use common::fixture_or_skip;
use common::literoot_bin;
use common::run_bounded;

const THREADS: usize = 4;
const ITERS: usize = 1500;

const PROBE_C: &str = r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define THREADS 4
#define ITERS 1500

static pthread_barrier_t start;
static long wrong[THREADS], errors[THREADS];

static void *run(void *arg) {
    long i = (long) arg;
    char path[32], want[32], got[32];
    snprintf(path, sizeof path, "/f%ld", i);
    snprintf(want, sizeof want, "marker-%ld\n", i);
    size_t len = strlen(want);
    pthread_barrier_wait(&start);
    for (int k = 0; k < ITERS; k++) {
        long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY);
        if (fd < 0) {
            errors[i]++;
            continue;
        }
        ssize_t n = read((int) fd, got, sizeof got);
        if (n < 0)
            errors[i]++;
        else if ((size_t) n != len || memcmp(got, want, len) != 0)
            wrong[i]++;
        close((int) fd);
    }
    return NULL;
}

int main(void) {
    pthread_t t[THREADS];
    if (pthread_barrier_init(&start, NULL, THREADS) != 0) return 2;
    for (long i = 0; i < THREADS; i++)
        if (pthread_create(&t[i], NULL, run, (void *) i) != 0) return 2;
    long w = 0, e = 0;
    for (long i = 0; i < THREADS; i++) {
        if (pthread_join(t[i], NULL) != 0) return 2;
        w += wrong[i];
        e += errors[i];
    }
    printf("wrong %ld errors %ld opens %d\n", w, e, THREADS * ITERS);
    return 0;
}
"#;

#[test]
fn threads_never_open_each_others_staged_path() {
    let scratch = std::env::temp_dir().join(format!(
        "literoot-thread-scratch-staging-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    let root = scratch.join("root");
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let probe = root.join("bin/probe");
    let built = Command::new("cc")
        .args(["-O2", "-Wall", "-Werror", "-static", "-pthread", "-o"])
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
    if !fixture_or_skip(&built, "static threaded openat probe") {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    for i in 0..THREADS {
        std::fs::write(root.join(format!("f{i}")), format!("marker-{i}\n")).unwrap();
    }

    let mut cmd = Command::new(literoot_bin());
    cmd.arg("-r").arg(&root).arg("/bin/probe");
    let out = run_bounded(cmd, "threaded openat probe");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout.trim_end();
    println!("probe line: {line}");
    let fields: Vec<&str> = line.split(' ').collect();
    let count = |at: usize| -> usize {
        fields
            .get(at)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("unreadable probe line {line:?}"))
    };
    let (wrong, errors) = (count(1), count(3));
    assert_eq!(
        wrong,
        0,
        "wrong-file opens: {wrong} of {} opens read another thread's file (errors {errors}); \
         probe line {line:?}",
        THREADS * ITERS
    );
    assert_eq!(
        line,
        format!("wrong 0 errors 0 opens {}", THREADS * ITERS),
        "probe line"
    );
    std::fs::remove_dir_all(&scratch).unwrap();
}
