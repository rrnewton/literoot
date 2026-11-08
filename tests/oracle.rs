//! Differential oracle (design §9): identical command lines under
//! literoot and under a reference runner on twin rootfs copies;
//! stdout/stderr/exit-code and the resulting file tree must match
//! byte-for-byte. Failures are retained by name; the comparator is
//! never loosened.
//!
//! Reference runner: real proot when `LITEROOT_REFERENCE=proot:<bin>`
//! is set; otherwise direct execution with cwd inside the rootfs
//! copy and guest paths pre-translated by the harness (the
//! "native-in-rootfs" column — see design §9 for why proot's column
//! starts empty on hosts without a proot binary).
//!
//! Run: `cargo test --test oracle` (skips with a notice when the
//! literoot binary or fixture binaries are unavailable).

use std::path::{Path, PathBuf};
use std::process::Command;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

fn make_rootfs(dir: &Path) {
    for sub in ["bin", "etc", "lib64", "work", "usr/bin", "dev", "proc"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    for bin in ["sh", "ls", "cat", "true"] {
        std::fs::copy(format!("/bin/{bin}"), dir.join("bin").join(bin)).unwrap();
    }
    for bin in ["readlink", "mknod"] {
        let src = format!("/bin/{bin}");
        if Path::new(&src).exists() {
            std::fs::copy(&src, dir.join("bin").join(bin)).unwrap();
        }
    }
    // Shared libraries the fixture binaries need (host ldd set).
    for lib in [
        "libc.so.6",
        "libtinfo.so.6",
        "libcap.so.2",
        "libpcre2-8.so.0",
        "libselinux.so.1",
        "ld-linux-x86-64.so.2",
    ] {
        let src = PathBuf::from(format!("/lib64/{lib}"));
        if src.exists() {
            std::fs::copy(&src, dir.join("lib64").join(lib)).unwrap();
        }
    }
    std::fs::write(dir.join("etc/os-release"), "literoot-test-os 1.0\n").unwrap();
    std::fs::write(dir.join("work/hello.txt"), "hello-from-rootfs\n").unwrap();
}

struct Case {
    name: &'static str,
    argv: &'static [&'static str],
}

/// Tree digest: sorted (relpath, len, first-64-bytes-hash-ish) lines.
fn tree_digest(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            // bwrap mounts fresh /dev and /proc; their contents are
            // reference-runner artifacts, not guest results.
            if rel == "dev" || rel == "proc" {
                out.push(format!("D {rel}"));
                continue;
            }
            if p.is_dir() {
                out.push(format!("D {rel}"));
                walk(root, &p, out);
            } else {
                let data = std::fs::read(&p).unwrap_or_default();
                let sum: u64 = data.iter().map(|b| *b as u64).sum();
                out.push(format!("F {rel} {} {}", data.len(), sum));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn oracle_cases_match_reference() {
    if !Path::new("/bin/sh").exists() || !Path::new("/lib64/libc.so.6").exists() {
        eprintln!("oracle: host fixture binaries unavailable — skipping");
        return;
    }
    let cases = [
        Case { name: "cat-absolute", argv: &["/bin/cat", "/etc/os-release"] },
        Case { name: "ls-root", argv: &["/bin/ls", "/"] },
        Case { name: "true", argv: &["/bin/true"] },
        Case {
            name: "sh-pwd-cat-ls",
            argv: &[
                "/bin/sh",
                "-c",
                "export PATH=/bin:/usr/bin; pwd; cat hello.txt; ls /bin; /bin/cat /etc/os-release",
            ],
        },
        Case {
            name: "sh-write-readback",
            argv: &[
                "/bin/sh",
                "-c",
                "export PATH=/bin; echo written-by-guest > out.txt; cat out.txt",
            ],
        },
    ];

    let tmp = std::env::temp_dir().join(format!("literoot-oracle-{}", std::process::id()));
    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let got_dir = tmp.join(format!("{}-got", case.name));
        let want_dir = tmp.join(format!("{}-want", case.name));
        let _ = std::fs::remove_dir_all(&got_dir);
        let _ = std::fs::remove_dir_all(&want_dir);
        make_rootfs(&got_dir);
        make_rootfs(&want_dir);

        // literoot run.
        let got = Command::new(literoot_bin())
            .args(["-r", got_dir.to_str().unwrap(), "-w", "/work"])
            .args(case.argv)
            .output()
            .expect("spawn literoot");

        // Reference A (always): real proot when LITEROOT_PROOT
        // names a staged binary (design §9 comparator 2); run on
        // its own twin copy so tree digests stay comparable.
        if let Ok(proot) = std::env::var("LITEROOT_PROOT") {
            let proot_dir = tmp.join(format!("{}-proot", case.name));
            let _ = std::fs::remove_dir_all(&proot_dir);
            make_rootfs(&proot_dir);
            let pref = Command::new(&proot)
                .args(["-r", proot_dir.to_str().unwrap(), "-w", "/work"])
                .args(case.argv)
                .env("PATH", "/bin:/usr/bin")
                .output()
                .expect("spawn proot reference");
            let norm = |bytes: &[u8], root: &Path| -> Vec<u8> {
                String::from_utf8_lossy(bytes)
                    .replace(&root.display().to_string(), "<ROOT>")
                    .into_bytes()
            };
            let same = norm(&got.stdout, &got_dir) == norm(&pref.stdout, &proot_dir)
                && got.status.code() == pref.status.code()
                && tree_digest(&got_dir) == tree_digest(&proot_dir);
            if !same {
                failures.push(format!(
                    "{}[vs-proot]: literoot(code={:?}, out={:?}) vs proot(code={:?}, out={:?}, err={:?})",
                    case.name,
                    got.status.code(),
                    String::from_utf8_lossy(&got.stdout),
                    pref.status.code(),
                    String::from_utf8_lossy(&pref.stdout),
                    String::from_utf8_lossy(&pref.stderr),
                ));
            }
        }

        // Reference B: bubblewrap with want_dir bound at / — a true
        // native-in-rootfs run (user namespace, kernel path
        // resolution).
        let want = Command::new("bwrap")
            .args(["--bind", want_dir.to_str().unwrap(), "/", "--dev", "/dev", "--proc", "/proc", "--chdir", "/work"])
            .args(case.argv)
            .env("PATH", "/bin:/usr/bin")
            .output()
            .expect("spawn bwrap reference (is bubblewrap installed?)");

        let mut ok = true;
        // Normalise ONLY the rootfs path prefix (the two runs use
        // different host dirs by construction). Nothing else.
        let norm = |bytes: &[u8], root: &Path| -> Vec<u8> {
            let s = String::from_utf8_lossy(bytes)
                .replace(&root.display().to_string(), "<ROOT>");
            s.into_bytes()
        };
        if norm(&got.stdout, &got_dir) != norm(&want.stdout, &want_dir) {
            ok = false;
        }
        if got.status.code() != want.status.code() {
            ok = false;
        }
        if tree_digest(&got_dir) != tree_digest(&want_dir) {
            ok = false;
        }
        if !ok {
            failures.push(format!(
                "{}: literoot(code={:?}, out={:?}) vs reference(code={:?}, out={:?})",
                case.name,
                got.status.code(),
                String::from_utf8_lossy(&got.stdout),
                want.status.code(),
                String::from_utf8_lossy(&want.stdout),
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        failures.is_empty(),
        "oracle failures (retained by name):\n{}",
        failures.join("\n")
    );
}

#[cfg(target_arch = "x86_64")]
fn require_fixture_tool(path: &Path) -> &Path {
    assert!(
        path.is_file(),
        "missing required fixture tool {}: install coreutils before running this test",
        path.display()
    );
    path
}

#[cfg(target_arch = "x86_64")]
#[test]
#[should_panic(expected = "missing required fixture tool /definitely/missing/readlink")]
fn missing_fixture_tool_fails_loudly() {
    require_fixture_tool(Path::new("/definitely/missing/readlink"));
}

/// Task-B named cases (aarch64 suite flips at integration tip
/// 269f9fe; pinned here so x86 cannot regress them silently):
/// single-file bind, readlink path translation and
/// de-translation, and mknod requiring fake root. The fixture's
/// loader is x86-64-only today, so this stays x86_64-only; the
/// aarch64 `Readlinkat` path is covered by the proot suite.
#[cfg(target_arch = "x86_64")]
#[test]
fn task_b_named_cases() {
    require_fixture_tool(Path::new("/bin/readlink"));
    require_fixture_tool(Path::new("/bin/mknod"));
    let tmp = std::env::temp_dir().join(format!("literoot-taskb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let rootfs = tmp.join("rootfs");
    make_rootfs(&rootfs);
    let run = |extra: &[&str], argv: &[&str]| {
        Command::new(literoot_bin())
            .args(["-r", rootfs.to_str().unwrap(), "-w", "/work"])
            .args(extra)
            .args(argv)
            .output()
            .expect("spawn literoot")
    };

    // test-bind-single-file: a single host file bound at a guest
    // path is readable there, and binding does not create the
    // file inside the rootfs tree.
    let host_file = tmp.join("host-bound.txt");
    std::fs::write(&host_file, "bound-content\n").unwrap();
    let bind_arg = format!("{}:/bound.txt", host_file.display());
    let out = run(&["-b", &bind_arg], &["/bin/cat", "/bound.txt"]);
    assert_eq!(out.status.code(), Some(0), "bind-single-file cat: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "bound-content\n");
    assert!(
        !rootfs.join("bound.txt").exists(),
        "bind must be a view, not a copy into the rootfs"
    );

    // test-readlink-abs-rel-symlink has two distinct halves:
    // an external host-absolute target is returned unchanged
    // (path argument translated, stored target not mangled),
    // while a target stored under the host rootfs path must
    // de-translate back to the guest path. Relative targets
    // pass through unchanged.
    let host_true = std::fs::canonicalize("/bin/true").unwrap();
    std::fs::write(rootfs.join("work/hello"), "hello\n").unwrap();
    std::os::unix::fs::symlink(&host_true, rootfs.join("bin/abs-true")).unwrap();
    std::os::unix::fs::symlink(
        rootfs.join("work/hello"),
        rootfs.join("bin/rootfs-hello"),
    )
    .unwrap();
    std::os::unix::fs::symlink("./true", rootfs.join("bin/rel-true")).unwrap();
    let out = run(&[], &["/bin/readlink", "/bin/abs-true"]);
    assert_eq!(out.status.code(), Some(0), "readlink abs: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        host_true.display().to_string(),
        "external absolute symlink target must pass through unchanged"
    );
    let out = run(&[], &["/bin/readlink", "/bin/rootfs-hello"]);
    assert_eq!(out.status.code(), Some(0), "readlink rootfs: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "/work/hello",
        "rootfs-prefixed symlink target must de-translate to the guest path"
    );
    // Long rootfs-prefixed target: its stored host form
    // outgrows the guest reader's initial readlink buffer at
    // any temp-dir depth (coreutils starts at 64 bytes and
    // doubles while the buffer fills), so de-translation
    // must start from the complete stored target rather
    // than the buffer-truncated host prefix. Regression
    // pin: this returned a truncated guest path whenever a
    // buffer-size step landed between the host rootfs
    // prefix and the full host target.
    let long_name = "h".repeat(64);
    std::fs::write(rootfs.join("work").join(&long_name), "hello\n").unwrap();
    std::os::unix::fs::symlink(
        rootfs.join("work").join(&long_name),
        rootfs.join("bin/rootfs-long"),
    )
    .unwrap();
    let out = run(&[], &["/bin/readlink", "/bin/rootfs-long"]);
    assert_eq!(out.status.code(), Some(0), "readlink rootfs long: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("/work/{long_name}"),
        "long rootfs-prefixed target must de-translate in full, \
         not truncate at a guest readlink buffer step"
    );
    let out = run(&[], &["/bin/readlink", "/bin/rel-true"]);
    assert_eq!(out.status.code(), Some(0), "readlink rel: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "./true");

    // test-mknod-requires-fake-root: block-device mknod must
    // fail without fake root and succeed with -0.
    let out = run(&[], &["/bin/mknod", "/work/dev0", "b", "1", "1"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "mknod without -0 must exit 1: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("EPERM"),
        "mknod without -0 must report EPERM, got stderr: {stderr}"
    );
    assert!(
        !rootfs.join("work/dev0").exists(),
        "failed mknod must not leave a guest file behind"
    );
    let out = run(&["-0"], &["/bin/mknod", "/work/dev0", "b", "1", "1"]);
    assert_eq!(out.status.code(), Some(0), "mknod with -0: {out:?}");
    assert!(
        rootfs.join("work/dev0").exists(),
        "mknod with -0 must create /work/dev0 in the rootfs"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

