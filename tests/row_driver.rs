//! The per-name row driver's free-space guard (`scripts/proot-suite-row.sh
//! --per-name`), against a one-name fake suite and the real literoot:
//! a floor that is not a number is a usage error; a free-space reading
//! that is not a number, or one below the floor, makes the name not
//! measured, with the keys its log holds (review of g2 38e83d31,
//! finding P2-4). A name with no refusal and a measurable floor
//! is counted, so the guard is not simply always on.

mod common;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use common::literoot_bin;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fake_suite(root: &Path) -> PathBuf {
    let src = root.join("suite");
    std::fs::create_dir_all(src.join("test")).unwrap();
    std::fs::write(src.join("test/test-one.sh"), "").unwrap();
    std::fs::write(
        src.join("test/GNUmakefile"),
        "check-%:\n\t@if $(PROOT) /bin/true; then echo \"CHECK $* ok\"; \
         else echo \"CHECK $* FAILED\"; fi\n",
    )
    .unwrap();
    src
}

/// Run the driver for `label`; `extra` goes after the literoot binary.
fn row(
    root: &Path,
    label: &str,
    env: &[(&str, &str)],
    path: Option<&Path>,
    extra: &[&str],
) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/proot-suite-row.sh");
    let mut cmd = Command::new("bash");
    cmd.arg(script)
        .arg("--per-name")
        .arg(fake_suite(root))
        .arg(root.join("out"))
        .arg(label)
        .arg(literoot_bin())
        .args(extra)
        .envs(env.iter().copied());
    if let Some(dir) = path {
        let old = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{old}", dir.display()));
    }
    cmd.output().expect("run the row driver")
}

fn pername(root: &Path, label: &str) -> String {
    std::fs::read_to_string(root.join(format!("out/{label}.pername"))).unwrap()
}

#[test]
fn the_free_space_guard_refuses_what_it_cannot_measure() {
    let root = std::env::temp_dir().join(format!("literoot-row-driver-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let scratch = Scratch(root);
    let root = &scratch.0;

    let out = row(
        root,
        "control",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "0")],
        None,
        &[],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(pername(root, "control"), "test-one.sh ok\n");

    let out = row(
        root,
        "badfloor",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "1G")],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(64), "{out:?}");

    // The cap is 18 digits, which bash's 64-bit integers always hold: the
    // largest 18-digit floor is accepted (and, being far above any real
    // free space, makes the name not measured); the smallest 19-digit one
    // is a usage error (review of g2 8b480bd0).
    let out = row(
        root,
        "floor18",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "999999999999999999")],
        None,
        &[],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        pername(root, "floor18"),
        "test-one.sh not-measured free-space keys: none\n"
    );
    let out = row(
        root,
        "floor19",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "1000000000000000000")],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(64), "{out:?}");

    // 2^64: all digits, but too large for bash's integers (review of g2
    // 98d28848, F1).
    let out = row(
        root,
        "hugefloor",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "18446744073709551616")],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(64), "{out:?}");

    let out = row(
        root,
        "floor",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "999999999999999")],
        None,
        &["--bogus"],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        pername(root, "floor"),
        "test-one.sh not-measured free-space keys: launcher_other \n"
    );

    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let df = bin.join("df");
    std::fs::write(&df, "#!/bin/sh\necho Filesystem\necho x 1 2 unknown\n").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&df, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = row(
        root,
        "nodf",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "0")],
        Some(&bin),
        &[],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        pername(root, "nodf"),
        "test-one.sh not-measured free-space-unmeasured keys: none\n"
    );

    // A df reading of 2^64 KiB: all digits, but no comparison with the
    // floor can be evaluated, so the name is not measured (F1).
    let huge = root.join("hugebin");
    std::fs::create_dir_all(&huge).unwrap();
    let df = huge.join("df");
    std::fs::write(
        &df,
        "#!/bin/sh\necho Filesystem\necho x 1 2 18446744073709551616\n",
    )
    .unwrap();
    std::fs::set_permissions(&df, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = row(
        root,
        "hugedf",
        &[("LITEROOT_SIDELOG_MIN_FREE_KB", "0")],
        Some(&huge),
        &[],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        pername(root, "hugedf"),
        "test-one.sh not-measured free-space keys: none\n"
    );
}
