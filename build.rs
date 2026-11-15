//! Builds the in-guest preload (preload/) as a nested Cargo build and
//! embeds it, so `cargo install --path` and `cargo install --git` give a
//! literoot whose in-guest backends work with no second build step.
//!
//! Scope: `--path` and `--git` installs. A crates.io package cannot carry
//! preload/ (Cargo excludes sub-packages from a published archive), so this
//! script refuses by name when preload/ is absent.
//!
//! Directory isolation: the child gets `--target-dir <OUT_DIR>/preload-target/<flavour>`
//! and build directory `<OUT_DIR>/preload-build/<flavour>`, so it shares no
//! lock with the waiting parent. The jobserver (CARGO_MAKEFLAGS) is
//! inherited; no fixed -j.
//!
//! Pinned identities, per flavour: the blob is retained at
//! `<OUT_DIR>/preload-embed/<flavour>/libliteroot_preload.so`, and the
//! receipt `<OUT_DIR>/preload-embed/<flavour>.receipt` beside it has
//! exactly the lines `digest=`, `flavour=`, `target=` and `artifact=`.
//!
//! Feature matrix: `run` alone (ptrace-only) skips the nested build and
//! embeds nothing; `in-guest` builds the liteinst flavour; `inguest-trap`
//! builds the traphost flavour; both build both. `exec-watch` selects the
//! preload's own `exec-watch` feature. Under DOCS_RS nothing is built.
//!
//! The nested build is `--locked`. It is offline exactly when the caller's
//! Cargo configuration says so (CARGO_NET_OFFLINE is inherited); the CLI
//! `--offline` flag does not reach build scripts. The preload lockfile is
//! not covered by a root `cargo fetch`: fetch it with
//! `cargo fetch --locked --manifest-path preload/Cargo.toml`.

#[path = "src/preload_stamp.rs"]
mod preload_stamp;

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Every preload input, in Cargo's documented forms (directories are
/// scanned recursively). The stamp's file set is a subset by construction.
const RERUN_PATHS: &[&str] = &[
    "build.rs",
    "Cargo.lock",
    "preload/Cargo.toml",
    "preload/Cargo.lock",
    "preload/build.rs",
    "preload/src",
    "src/arch.rs",
    "src/exec_state.rs",
    "src/fake_creds.rs",
    "src/initial_packet.rs",
    "src/preload_stamp.rs",
    "src/refusal_log.rs",
    "src/rootfs_tool.rs",
    "src/shared_record.rs",
    "src/translate.rs",
];

/// Every variable this script reads or deliberately passes to the child.
const RERUN_ENV: &[&str] = &[
    "DOCS_RS",
    "CARGO_NET_OFFLINE",
    "CARGO_HOME",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
];

/// Variables removed from the child's environment: wrappers, the parent's
/// flags and directories, and the parent build script's own context, which
/// would otherwise leak into the preload's build script (its features
/// above all).
fn strip_from_child(key: &str) -> bool {
    const EXACT: &[&str] = &[
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
        "CARGO_BUILD_TARGET",
        "OUT_DIR",
        "TARGET",
        "HOST",
        "NUM_JOBS",
        "OPT_LEVEL",
        "DEBUG",
        "PROFILE",
        "RUSTC_LINKER",
        "RUSTDOC",
        "CARGO_CRATE_NAME",
        "CARGO_PRIMARY_PACKAGE",
        "CARGO_TARGET_TMPDIR",
        "DOCS_RS",
    ];
    const PREFIXES: &[&str] = &[
        "CARGO_FEATURE_",
        "CARGO_CFG_",
        "CARGO_PKG_",
        "CARGO_MANIFEST_",
        "DEP_",
    ];
    EXACT.contains(&key) || PREFIXES.iter().any(|p| key.starts_with(p))
}

fn fail(message: &str) -> ! {
    panic!("literoot build: {message}")
}

#[derive(Clone, Copy)]
enum Flavour {
    Liteinst,
    TrapHost,
}

impl Flavour {
    fn name(self) -> &'static str {
        match self {
            Flavour::Liteinst => "liteinst",
            Flavour::TrapHost => "traphost",
        }
    }

    fn stamp(self) -> u32 {
        match self {
            Flavour::Liteinst => preload_stamp::FLAVOUR_LITEINST,
            Flavour::TrapHost => preload_stamp::FLAVOUR_TRAPHOST,
        }
    }

    fn constant(self) -> &'static str {
        match self {
            Flavour::Liteinst => "EMBEDDED_LITEINST",
            Flavour::TrapHost => "EMBEDDED_TRAPHOST",
        }
    }
}

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(env::var_os(key).unwrap_or_else(|| fail(&format!("{key} is not set"))))
}

fn main() {
    for path in RERUN_PATHS {
        println!("cargo::rerun-if-changed={path}");
    }
    for key in RERUN_ENV {
        println!("cargo::rerun-if-env-changed={key}");
    }
    let root = env_path("CARGO_MANIFEST_DIR");
    let out = env_path("OUT_DIR");
    let feature = |name: &str| env::var_os(format!("CARGO_FEATURE_{name}")).is_some();
    let tool = feature("TOOL");
    let docs = env::var_os("DOCS_RS").is_some();
    let mut flavours = Vec::new();
    if tool && feature("IN_GUEST") {
        flavours.push(Flavour::Liteinst);
    }
    if feature("INGUEST_TRAP") {
        flavours.push(Flavour::TrapHost);
    }
    if docs {
        flavours.clear();
    }

    let mut generated = String::new();
    let _ = writeln!(generated, "// Generated by literoot's build.rs.");
    let mut embedded: Vec<(Flavour, String, String)> = Vec::new();
    if flavours.is_empty() {
        // Nothing is built or admitted: a ptrace-only build compiles no
        // preload code, and a documentation build is never install evidence.
        let _ = writeln!(generated, "pub(crate) const PROTOCOL_VERSION: u32 = 0;");
    } else {
        let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let target = env::var("TARGET").unwrap_or_else(|_| fail("TARGET is not set"));
        if os != "linux" || target.contains("android") {
            fail(&format!(
                "the in-guest preload is built for Linux only; target {target} is refused at \
                 this pin (build with --no-default-features --features run for ptrace only)"
            ));
        }
        if !root.join("preload/Cargo.toml").is_file() {
            fail(
                "preload/ is absent: install with `cargo install --path` or `cargo install --git`; \
                 crates.io packaging is out of scope",
            );
        }
        preload_stamp::check_lock_agreement(&root).unwrap_or_else(|e| fail(&e));
        let protocol = preload_stamp::protocol_version(&root)
            .unwrap_or_else(|e| fail(&format!("cannot derive the preload stamp: {e}")));
        let _ = writeln!(generated, "pub(crate) const PROTOCOL_VERSION: u32 = {protocol:#010x};");
        let release = match env::var("PROFILE").as_deref() {
            Ok("release") => true,
            Ok("debug") => false,
            other => fail(&format!("unexpected PROFILE {other:?}")),
        };
        for &flavour in &flavours {
            let (artifact, digest) =
                build_flavour(&root, &out, flavour, &target, release, feature("EXEC_WATCH"), protocol);
            embedded.push((flavour, artifact, digest));
        }
    }
    for flavour in [Flavour::Liteinst, Flavour::TrapHost] {
        match embedded.iter().find(|(f, _, _)| f.name() == flavour.name()) {
            Some((_, artifact, digest)) => {
                let _ = writeln!(
                    generated,
                    "pub(crate) static {}: Option<Embedded> = Some(Embedded {{ bytes: include_bytes!({artifact:?}), sha256: {digest:?} }});",
                    flavour.constant()
                );
            }
            None => {
                let _ = writeln!(
                    generated,
                    "pub(crate) static {}: Option<Embedded> = None;",
                    flavour.constant()
                );
            }
        }
    }
    let file = out.join("embedded_preload.rs");
    fs::write(&file, generated).unwrap_or_else(|e| fail(&format!("write {}: {e}", file.display())));
}

/// Build one flavour, check its stamp and markers, retain it and write its
/// receipt. Returns the retained artifact path and its digest.
fn build_flavour(
    root: &Path,
    out: &Path,
    flavour: Flavour,
    target: &str,
    release: bool,
    exec_watch: bool,
    protocol: u32,
) -> (String, String) {
    let name = flavour.name();
    let target_dir = out.join("preload-target").join(name);
    let build_dir = out.join("preload-build").join(name);
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root)
        .arg("build")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(root.join("preload/Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--target")
        .arg(target);
    if release {
        cmd.arg("--release");
    }
    let mut features = Vec::new();
    if let Flavour::TrapHost = flavour {
        cmd.arg("--no-default-features");
        features.push("inguest-trap");
    }
    if exec_watch {
        features.push("exec-watch");
    }
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    for (key, _) in env::vars_os() {
        if key.to_str().is_some_and(strip_from_child) {
            cmd.env_remove(&key);
        }
    }
    cmd.env("CARGO_BUILD_BUILD_DIR", &build_dir);
    // The child's stdout goes to stderr: only this script may print the
    // `cargo::` instructions Cargo reads from build-script stdout.
    cmd.stdout(std::io::stderr());
    let status = cmd.status().unwrap_or_else(|e| fail(&format!("run cargo for the preload: {e}")));
    if !status.success() {
        fail(&format!(
            "the nested preload build ({name}) failed with {status}; if a dependency is missing \
             offline, fetch it with `cargo fetch --locked --manifest-path preload/Cargo.toml`"
        ));
    }
    let profile_dir = if release { "release" } else { "debug" };
    let built = target_dir
        .join(target)
        .join(profile_dir)
        .join("libliteroot_preload.so");
    let blob = fs::read(&built).unwrap_or_else(|e| fail(&format!("read {}: {e}", built.display())));
    if blob
        .windows(preload_stamp::REPORTER_OFF_MARKER.len())
        .any(|w| w == preload_stamp::REPORTER_OFF_MARKER)
    {
        fail("refusing to embed a reporter-off preload (a test fixture only)");
    }
    check_stamp(&blob, flavour, protocol, &built);
    let embed_dir = out.join("preload-embed").join(name);
    fs::create_dir_all(&embed_dir)
        .unwrap_or_else(|e| fail(&format!("create {}: {e}", embed_dir.display())));
    let artifact = embed_dir.join("libliteroot_preload.so");
    fs::write(&artifact, &blob).unwrap_or_else(|e| fail(&format!("write {}: {e}", artifact.display())));
    let digest = preload_stamp::sha256_hex(&blob);
    // The retained artifact is what gets embedded: hash and parse it again.
    let retained =
        fs::read(&artifact).unwrap_or_else(|e| fail(&format!("read {}: {e}", artifact.display())));
    if preload_stamp::sha256_hex(&retained) != digest {
        fail(&format!("{} changed after it was written", artifact.display()));
    }
    check_stamp(&retained, flavour, protocol, &artifact);
    let artifact_text = artifact
        .to_str()
        .unwrap_or_else(|| fail(&format!("{} is not UTF-8", artifact.display())))
        .to_owned();
    let receipt = out.join("preload-embed").join(format!("{name}.receipt"));
    let body = format!("digest={digest}\nflavour={name}\ntarget={target}\nartifact={artifact_text}\n");
    fs::write(&receipt, body).unwrap_or_else(|e| fail(&format!("write {}: {e}", receipt.display())));
    (artifact_text, digest)
}

/// The blob must carry exactly the stamp this launcher expects; a missing
/// note (a linker dropped the section) fails the build here.
fn check_stamp(blob: &[u8], flavour: Flavour, protocol: u32, path: &Path) {
    let stamp = preload_stamp::parse(blob).unwrap_or_else(|e| {
        fail(&format!(
            "{} carries no valid {} note: {e}",
            path.display(),
            preload_stamp::SECTION
        ))
    });
    preload_stamp::check(&stamp, protocol, flavour.stamp())
        .unwrap_or_else(|e| fail(&format!("{}: stamp differs: {e}", path.display())));
}
