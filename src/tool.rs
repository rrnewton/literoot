//! Launcher side: runs `RootfsTool` on a Reverie backend.
//! The Tool itself lives in `rootfs_tool` so the in-guest preload
//! (`preload/`) compiles the identical code into the guest.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::rootfs_tool::{LiterootConfig, RootfsTool, set_config};
use crate::translate::RootConfig;


/// Run `command` (default `/bin/sh`) inside the rootfs under the
/// requested backend. Returns the guest exit code.
pub fn run_guest(
    config: &RootConfig,
    cwd_guest: &Path,
    backend: &str,
    command: &[String],
) -> Result<u8, String> {
    // Backends (design §3): ptrace = reference (Tool in tracer);
    // liteinst = in-guest patched sites + SIGSYS trap net;
    // trap = in-guest trap-only (no site patching). The in-guest
    // backend today refuses guest execve/thread-clone by name
    // (EOPNOTSUPP; stage-1b re-arm outstanding, design §10 item 3)
    // — that refusal surfaces verbatim, never a silent downgrade.
    if !["ptrace", "liteinst", "in-guest", "trap"].contains(&backend) {
        return Err(format!(
            "unknown backend {backend:?} (expected: ptrace | liteinst | trap)"
        ));
    }
    let in_guest = backend != "ptrace";
    // Resolve a relative -w against the host cwd's guest view
    // (proot: `-w .` keeps $PWD), then apply the missing-dir
    // fallback to "/" (proot rule).
    let cwd_owned: PathBuf;
    let cwd_guest: &Path = if cwd_guest.is_absolute() {
        cwd_guest
    } else {
        // proot: the host cwd *path* is the guest cwd spelling
        // (test-cwd-removed-dir pre-creates $ROOTFS/$PWD).
        let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        cwd_owned = {
            let mut p = base;
            p.push(cwd_guest);
            // Lexical normalization via translate round-trip.
            let host = config.translate(&p, Path::new("/"), None);
            config.reverse(&host).unwrap_or(p)
        };
        &cwd_owned
    };
    let cwd_effective: &Path =
        if config.translate(cwd_guest, Path::new("/"), None).is_dir() {
            cwd_guest
        } else {
            Path::new("/")
        };
    let cwd_guest = cwd_effective;
    let cfg = LiterootConfig {
        rootfs: config.rootfs.to_string_lossy().into_owned(),
        binds: config
            .binds
            .iter()
            .map(|b| {
                (
                    b.guest.to_string_lossy().into_owned(),
                    b.host.to_string_lossy().into_owned(),
                    b.no_follow,
                )
            })
            .collect(),
        cwd: cwd_guest.to_string_lossy().into_owned(),
        fake_root: config.fake_root,
        fake_uid: config.fake_ids.map(|(u, _)| u),
        fake_gid: config.fake_ids.map(|(_, g)| g),
        kernel_release: config.kernel_release.clone(),
        initial_exe: String::new(),
        initial_argv: Vec::new(),
    };
    let mut cfg = cfg;
    set_config(cfg.clone());

    // Resolve the guest program through the translated root: the
    // tracer execs the host path, argv[0] stays the guest spelling.
    let guest_prog = command.first().cloned().unwrap_or_else(|| "/bin/sh".into());
    // `guest_found` is the guest path of the program (what the
    // rootfs loader must open); `guest_prog` remains argv[0].
    let (host_prog, guest_found) = if Path::new(&guest_prog).components().count() > 1
        || guest_prog.starts_with('/')
    {
        // Absolute or slash-containing (e.g. ./prog): resolve
        // through the rootfs against the guest cwd.
        (
            resolve_in_rootfs(config, cwd_guest, Path::new(&guest_prog)),
            guest_prog.clone(),
        )
    } else {
        // PATH lookup inside the rootfs (guest PATH dirs).
        let found = find_guest_in_path(config, cwd_guest, &guest_prog)
            .ok_or_else(|| format!("literoot: {guest_prog}: not found in rootfs PATH"))?;
        let host = resolve_in_rootfs(config, cwd_guest, Path::new(&found));
        (host, found)
    };
    cfg.initial_exe = guest_found.clone();
    cfg.initial_argv = command.to_vec();
    set_config(cfg.clone());
    // Execute permission is checked by the kernel on the real
    // execve; our interp/shebang routes would bypass it, so
    // check here (test-rootfs-shebang-exec, execve EACCES).
    {
        use std::os::unix::fs::PermissionsExt as _;
        match std::fs::metadata(&host_prog) {
            Ok(md) if md.is_dir() => {
                return Err(format!("literoot: {guest_prog}: Permission denied"))
            }
            Ok(md) if md.permissions().mode() & 0o111 == 0 => {
                return Err(format!("literoot: {guest_prog}: Permission denied"))
            }
            Ok(_) => {}
            Err(e) => return Err(format!("literoot: {guest_prog}: {e}")),
        }
    }
    // Shebang scripts: exec the guest interpreter with the
    // script's guest path (argv0 fidelity: $0 is the script as
    // spelled, e.g. through a symlink — test-symlink-script-argv0).
    let shebang = std::fs::read(&host_prog)
        .ok()
        .filter(|img| !img.starts_with(b"\x7fELF"))
        .and_then(|img| parse_shebang_pub(&img));
    if let Some((script_interp, script_opt)) = shebang {
        // Self-referential shebang: the kernel would ELOOP.
        if resolve_in_rootfs(config, cwd_guest, Path::new(&script_interp))
            == host_prog
        {
            eprintln!(
                "literoot: {guest_prog}: Too many levels of symbolic links"
            );
            return Err("Too many levels of symbolic links".into());
        }
        let interp_host =
            resolve_in_rootfs(config, cwd_guest, Path::new(&script_interp));
        let interp_interp = std::fs::read(&interp_host)
            .ok()
            .and_then(|img| crate::translate::elf_interp(&img));
        let mut cmd = match interp_interp {
            Some(ld) => {
                let ld_host = resolve_in_rootfs(config, cwd_guest, Path::new(&ld));
                let mut c = reverie::process::Command::new(&ld_host);
                c.arg0(&ld);
                c.arg(&script_interp);
                if let Some(opt) = &script_opt {
                    c.arg(opt);
                }
                c.arg(&guest_found);
                c
            }
            None => {
                let mut c = reverie::process::Command::new(&interp_host);
                c.arg0(&script_interp);
                if let Some(opt) = &script_opt {
                    c.arg(opt);
                }
                c.arg(&guest_found);
                c
            }
        };
        for a in command.iter().skip(1) {
            cmd.arg(a);
        }
        let host_cwd = config.translate(cwd_guest, Path::new("/"), None);
        let host_cwd = if host_cwd.is_dir() { host_cwd } else { config.rootfs.clone() };
        cmd.current_dir(&host_cwd);
        cmd.env("PWD", cwd_guest.to_string_lossy().as_ref());
        return run_backend(cmd, cfg, backend, in_guest);
    }
    // PT_INTERP: run the program through the rootfs's dynamic
    // linker (design §4.7) — the kernel would otherwise open the
    // interp path on the host (absent for e.g. musl rootfses).
    let interp_guest = std::fs::read(&host_prog)
        .ok()
        .and_then(|img| crate::translate::elf_interp(&img))
        // In-guest: when the host interp exists, let the kernel
        // load it and the preload arm inside the program itself.
        // Exec'ing ld.so as the program makes ld.so open the
        // target before the preload constructor arms (measured:
        // ET_EXEC guests then fail to load in-guest).
        .filter(|interp| !in_guest || !Path::new(interp).exists());
    let mut cmd = match &interp_guest {
        Some(interp) => {
            let interp_host =
                resolve_in_rootfs(config, cwd_guest, Path::new(interp));
            let mut c = reverie::process::Command::new(&interp_host);
            c.arg0(interp);
            c.arg(&guest_found);
            c
        }
        None => {
            let mut c = reverie::process::Command::new(&host_prog);
            c.arg0(&guest_prog);
            c
        }
    };
    for a in command.iter().skip(1) {
        cmd.arg(a);
    }
    // Guest starts with host cwd = translated guest cwd so real
    // relative syscalls the Tool passes through still land right
    // during early ld.so execution.
    let host_cwd = config.translate(cwd_guest, Path::new("/"), None);
    // proot falls back to the guest root when -w names a missing
    // directory (test-bind-chdir-getcwd expects cwd "/").
    let host_cwd = if host_cwd.is_dir() {
        host_cwd
    } else {
        config.rootfs.clone()
    };
    cmd.current_dir(&host_cwd);
    // proot rewrites $PWD to the guest cwd at exec (observed:
    // guest env shows PWD=<guest cwd>; bash's pwd builtin then
    // agrees — test-bind-cwd-bash-pwd).
    cmd.env("PWD", cwd_guest.to_string_lossy().as_ref());

    run_backend(cmd, cfg, backend, in_guest)
}

/// Run a fully-built command on the selected backend.
fn run_backend(
    mut cmd: reverie::process::Command,
    cfg: LiterootConfig,
    backend: &str,
    in_guest: bool,
) -> Result<u8, String> {
    // Shared probe-cache generation (memfd inherited by the
    // whole guest tree; translate.rs probe coherence).
    let gen_fd = crate::translate::create_shared_gen_fd();
    if gen_fd >= 0 {
        cmd.env("LITEROOT_PROBE_GEN_FD", gen_fd.to_string());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    if in_guest {
        #[cfg(not(feature = "in-guest"))]
        {
            return Err(format!(
                "backend {backend:?} unavailable: in-guest backends compiled out \
                 (ptrace-only build; rebuild with default features)"
            ));
        }
        #[cfg(feature = "in-guest")]
        {
        // Same Tool, hosted in-guest via the literoot preload.
        cmd.env(
            reverie_liteinst::SITE_PATCHING_ENV,
            if backend == "trap" { "0" } else { "1" },
        );
        let preload = find_preload().ok_or(
            "literoot preload not found (libliteroot_preload.so beside the \
             literoot binary, or LITEROOT_PRELOAD=<path>). Build it with: \
             cargo build --release --manifest-path literoot/preload/Cargo.toml",
        )?;
        let (output, _global) = runtime.block_on(async {
            reverie_liteinst::LiteinstBackend::run_with_output_and_preload_data::<RootfsTool>(
                cmd,
                cfg,
                preload,
                b"literoot".to_vec(),
            )
            .await
            .map_err(|e| format!("in-guest ({backend}) run: {e}"))
        })?;
        std::io::stdout().write_all(&output.stdout).ok();
        std::io::stderr().write_all(&output.stderr).ok();
        use std::os::unix::process::ExitStatusExt;
        let status = output.status;
        return Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8);
        }
    }

    let status = runtime.block_on(async {
        let tracer = reverie_ptrace::TracerBuilder::<RootfsTool>::new(cmd)
            .config(cfg)
            .spawn()
            .await
            .map_err(|e| format!("tracer spawn: {e}"))?;
        let (status, _global) =
            tracer.wait().await.map_err(|e| format!("tracer wait: {e}"))?;
        Ok::<_, String>(status)
    })?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8)
}

/// Locate `libliteroot_preload.so`: `$LITEROOT_PRELOAD`, else beside
/// the running binary, else the slot build output.
#[cfg(feature = "in-guest")]
fn find_preload() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("LITEROOT_PRELOAD") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("libliteroot_preload.so");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// Resolve a guest program path to a host executable, following
/// symlinks *inside* the rootfs (an absolute symlink such as
/// Alpine's `/bin/sh -> /bin/busybox` must restart in the rootfs,
/// never escape to the host — design §4.2).
fn resolve_in_rootfs(config: &RootConfig, cwd_guest: &Path, guest: &Path) -> PathBuf {
    let mut guest = guest.to_path_buf();
    for _ in 0..40 {
        let host = config.translate(&guest, cwd_guest, None);
        match std::fs::read_link(&host) {
            Ok(target) if target.is_absolute() => guest = target,
            Ok(target) => {
                let mut next = guest
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("/"));
                next.push(target);
                guest = next;
            }
            Err(_) => return host,
        }
    }
    config.translate(&guest, cwd_guest, None)
}

fn find_guest_in_path(
    config: &RootConfig,
    cwd_guest: &Path,
    prog: &str,
) -> Option<String> {
    // Guest PATH from the environment (proot semantics: empty
    // PATH finds nothing; unset uses the execvp default).
    // Unset PATH: proot performs no search (test-path-search).
    let path_env = std::env::var("PATH").ok()?;
    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }
        let guest = Path::new(dir).join(prog);
        let cand = config.translate(&guest, cwd_guest, None);
        if cand.is_file() {
            return Some(guest.to_string_lossy().into_owned());
        }
    }
    None
}

/// Minimal shebang parse for the launcher (mirrors the Tool's).
fn parse_shebang_pub(image: &[u8]) -> Option<(String, Option<String>)> {
    if !image.starts_with(b"#!") {
        return None;
    }
    // Kernel reads at most BINPRM_BUF_SIZE (256) bytes for the
    // shebang line; longer lines truncate mid-token.
    let image = &image[..image.len().min(256)];
    let line_end = image.iter().position(|&c| c == b'\n').unwrap_or(image.len());
    let line = std::str::from_utf8(&image[2..line_end]).ok()?.trim();
    let mut parts = line.splitn(2, |c: char| c.is_whitespace());
    let interp = parts.next()?.trim().to_string();
    if interp.is_empty() {
        return None;
    }
    // The kernel passes the remainder as ONE argument.
    let opt = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    Some((interp, opt))
}
