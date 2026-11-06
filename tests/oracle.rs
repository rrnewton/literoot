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
