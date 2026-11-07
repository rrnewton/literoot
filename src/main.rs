//! literoot — fast drop-in proot replacement (design: docs/design.md).
//!
//! M1 POC: proot-compatible CLI (`-r/-R/-b/-w/-0/-k`), arch-free path
//! translation (`translate` module), and a Reverie Tool (`tool`
//! module, feature `run`) that rewrites path-taking syscalls. The
//! Tool is backend-neutral: the POC runs it on Reverie's ptrace
//! reference backend (`--backend ptrace`, the differential-oracle
//! harness) — the in-guest liteinst fast path runs the identical
//! Tool once the preload packaging lands (design §3, §10).

mod arch;
#[cfg(feature = "tool")]
mod rootfs_tool;
#[cfg(feature = "tool")]
mod tool;
mod translate;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use translate::{Bind, RootConfig};

pub const VERSION_LINE: &str = "literoot 0.0.1 - early development, not yet usable";

#[derive(Debug)]
struct Cli {
    config: RootConfig,
    cwd_guest: PathBuf,
    backend: String,
    verbose: bool,
    check_paths: Vec<String>,
    command: Vec<String>,
}

fn default_binds() -> Vec<Bind> {
    // proot -R recommended bindings (host == guest).
    ["/dev", "/proc", "/sys"]
        .iter()
        .map(|p| Bind {
            guest: PathBuf::from(p),
            host: PathBuf::from(p),
            no_follow: false,
        })
        .collect()
}

fn absolutize(p: &Path) -> PathBuf {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        let mut base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        base.push(p);
        base
    };
    // Lexical clean of "." and ".." (bind prefixes compare
    // component-wise everywhere downstream).
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for c in joined.components() {
        match c {
            std::path::Component::Normal(s) => out.push(s.to_os_string()),
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    let mut r = PathBuf::from("/");
    for c in out {
        r.push(c);
    }
    r
}

fn parse_bind(spec: &str) -> Result<Bind, String> {
    // proot form: host[:guest][!]; a lone path binds host->same
    // guest; trailing ! = not followed during canonicalization.
    let (spec, no_follow) = match spec.strip_suffix('!') {
        Some(s) => (s, true),
        None => (spec, false),
    };
    match spec.split_once(':') {
        Some((host, guest)) => Ok(Bind {
            guest: absolutize(Path::new(guest)),
            host: absolutize(Path::new(host)),
            no_follow,
        }),
        None => {
            let a = absolutize(Path::new(spec));
            Ok(Bind {
                guest: a.clone(),
                host: a,
                no_follow,
            })
        }
    }
}

fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let mut rootfs: Option<PathBuf> = std::env::var_os("PROOT_ROOTFS").map(PathBuf::from);
    let mut binds: Vec<Bind> = Vec::new();
    let mut root_bind_before_rootfs = false;
    let mut saw_explicit_rootfs = false;
    let mut cwd_explicit = false;
    let mut cwd_guest: PathBuf = std::env::var_os("PROOT_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut fake_root = false;
    let mut fake_ids: Option<(u32, u32)> = None;
    let mut kernel_release: Option<String> = None;
    let mut backend = String::from("ptrace");
    let mut verbose = false;
    let mut check_paths: Vec<String> = Vec::new();
    let mut command: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut take = |i: &mut usize, flag: &str| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("literoot: {flag} requires a value"))
        };
        match a.as_str() {
            "--" => {
                command.extend(args[i + 1..].iter().cloned());
                break;
            }
            "-r" | "--rootfs" => {
                saw_explicit_rootfs = true;
                rootfs = Some(PathBuf::from(take(&mut i, "-r")?));
            }
            "-R" => {
                rootfs = Some(PathBuf::from(take(&mut i, "-R")?));
                binds.extend(default_binds());
            }
            "-b" | "--bind" | "-m" | "--mount" => {
                let b = parse_bind(&take(&mut i, "-b")?)?;
                if b.guest == Path::new("/") && !saw_explicit_rootfs {
                    root_bind_before_rootfs = true;
                }
                binds.push(b);
            }
            "-w" | "--cwd" | "-c" => {
                cwd_explicit = true;
                cwd_guest = PathBuf::from(take(&mut i, "-w")?)
            }
            "-0" | "--root-id" => {
                fake_root = true;
                fake_ids = Some((0, 0));
            }
            "-i" | "--identity" => {
                let v = take(&mut i, "-i")?;
                let (u, g) = v
                    .split_once(':')
                    .ok_or_else(|| format!("literoot: -i expects uid:gid, got {v:?}"))?;
                fake_ids = Some((
                    u.parse().map_err(|_| format!("literoot: -i uid {u:?}"))?,
                    g.parse().map_err(|_| format!("literoot: -i gid {g:?}"))?,
                ));
                fake_root = true;
            }
            "-k" | "--kernel-release" => kernel_release = Some(take(&mut i, "-k")?),
            "--backend" => backend = take(&mut i, "--backend")?,
            "--check" => check_paths.push(take(&mut i, "--check")?),
            "-v" | "--verbose" => {
                // proot's -v requires a level argument; only
                // positive levels print (tests use -v -1 = quiet
                // and compare stderr byte-for-byte).
                match args.get(i + 1) {
                    Some(next) => match next.parse::<i64>() {
                        Ok(level) => {
                            verbose = level > 0;
                            i += 1;
                        }
                        Err(_) => return Err("literoot: -v requires a level argument".into()),
                    },
                    _ => return Err("literoot: -v requires a level argument".into()),
                }
            }
            "-q" => {
                let _ = take(&mut i, "-q")?;
                return Err("literoot: -q/qemu passthrough not supported yet \
                            (foreign-arch emulation is out of scope; design §2)"
                    .into());
            }
            "--extension" => {
                let _ = take(&mut i, "--extension")?;
                return Err("literoot: proot extensions are not supported (design §2)".into());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" => {
                println!("{VERSION_LINE}");
                println!(
                    "backend: reverie-ptrace (POC reference); in-guest liteinst/trap: design §3"
                );
                std::process::exit(0);
            }
            s if s.starts_with('-') && s.len() > 1 => {
                // Combined short flags with attached values, proot-style
                // (e.g. -r<dir>, -b<spec>, -w<dir>, -0).
                if let Some(v) = s.strip_prefix("-r") {
                    rootfs = Some(PathBuf::from(v));
                } else if let Some(v) = s.strip_prefix("-R") {
                    rootfs = Some(PathBuf::from(v));
                    binds.extend(default_binds());
                } else if let Some(v) = s.strip_prefix("-b") {
                    binds.push(parse_bind(v)?);
                } else if let Some(v) = s.strip_prefix("-w") {
                    cwd_explicit = true;
                    cwd_guest = PathBuf::from(v);
                } else if s == "-0" {
                    fake_root = true;
                } else {
                    return Err(format!("literoot: unknown option {s} (try --help)"));
                }
            }
            _ => {
                command.extend(args[i..].iter().cloned());
                break;
            }
        }
        i += 1;
    }

    // proot defaults the rootfs to "/" when -r is absent.
    let rootfs = rootfs.unwrap_or_else(|| PathBuf::from("/"));
    // Binding at guest "/" conflicts with the rootfs itself
    // (proot order rule, test-rootfs-arg-validation): allowed
    // only when declared before an explicit -r / (rootfs wins).
    if binds.iter().any(|b| b.guest == Path::new("/")) {
        let ok = root_bind_before_rootfs && saw_explicit_rootfs && rootfs == Path::new("/");
        if !ok {
            return Err("literoot: binding over / conflicts with the rootfs".into());
        }
        binds.retain(|b| b.guest != Path::new("/"));
    }
    let rootfs = rootfs
        .canonicalize()
        .map_err(|e| format!("literoot: rootfs {}: {e}", rootfs.display()))?;
    // proot preserves the host cwd when -w is absent: the guest
    // cwd is the host cwd seen from inside the rootfs (binds
    // included, e.g. -b . makes it the bind's guest spelling).
    if !cwd_explicit && std::env::var_os("PROOT_CWD").is_none() {
        if let Ok(host_cwd) = std::env::current_dir() {
            let probe = RootConfig::new(rootfs.clone(), binds.clone());
            if let Some(g) = probe.reverse(&host_cwd) {
                cwd_guest = g;
            }
        }
    }
    let mut config = RootConfig::new(rootfs, binds);
    config.fake_root = fake_root;
    config.fake_ids = fake_ids.or(if fake_root { Some((0, 0)) } else { None });
    config.kernel_release = kernel_release;
    Ok(Cli {
        config,
        cwd_guest,
        backend,
        verbose,
        check_paths,
        command,
    })
}

fn print_usage() {
    println!(
        "{VERSION_LINE}\n\
         Usage: literoot [options] [--] [command [args...]]\n\
         \n\
         Options (proot-compatible subset, design §2):\n\
         \x20 -r, --rootfs <dir>     root filesystem (or PROOT_ROOTFS)\n\
         \x20 -R <dir>               -r plus default binds (/dev,/proc,/sys)\n\
         \x20 -b, --bind <h[:g]>     bind host path h at guest path g (repeatable)\n\
         \x20 -w, --cwd <dir>        initial guest cwd (default / or PROOT_CWD)\n\
         \x20 -0, --root-id          fake uid/gid 0\n\
         \x20 -k, --kernel-release <s>  spoof uname release\n\
         \x20 --backend <name>       ptrace (POC reference) | liteinst (design §3)\n\
         \x20 --check <guest-path>   print translation and exit (repeatable)\n\
         \x20 -v, --verbose          report selected mechanism\n\
         \x20 --help, --version"
    );
}

fn main() -> ExitCode {
    // proot's tracer survives SIGTERM sent by the guest to its
    // TracerPid (test-kill-tracer-pid); ignore it in the
    // launcher (guests keep their own disposition via exec).
    #[cfg(feature = "tool")]
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    // proot compat: PROOT_TMP_DIR must be a writable directory
    // when set (proot stages temp files there; literoot only
    // validates it — test-proot-tmp-dir-env).
    if let Ok(tmp) = std::env::var("PROOT_TMP_DIR") {
        let probe = std::path::Path::new(&tmp).join(".literoot-tmp-probe");
        let ok = std::fs::write(&probe, b"").map(|_| {
            let _ = std::fs::remove_file(&probe);
        });
        if ok.is_err() {
            eprintln!("literoot: PROOT_TMP_DIR {tmp:?} is not a writable directory");
            return ExitCode::from(125);
        }
    }
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        println!("{VERSION_LINE}");
        return ExitCode::SUCCESS;
    }
    let cli = match parse_cli(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(125);
        }
    };
    if cli.verbose {
        eprintln!(
            "literoot: rootfs={} binds={:?} cwd={} fake_root={} backend={}",
            cli.config.rootfs.display(),
            cli.config.binds,
            cli.cwd_guest.display(),
            cli.config.fake_root,
            cli.backend
        );
    }
    if !cli.check_paths.is_empty() {
        for p in &cli.check_paths {
            let host = cli.config.translate(Path::new(p), &cli.cwd_guest, None);
            println!("{p} -> {}", host.display());
        }
        return ExitCode::SUCCESS;
    }
    #[cfg(not(feature = "tool"))]
    {
        let _ = &cli;
        eprintln!(
            "literoot: built without a backend feature — translation engine only. \
             Rebuild with default features to execute guests."
        );
        ExitCode::from(125)
    }
    #[cfg(feature = "tool")]
    {
        match tool::run_guest(&cli.config, &cli.cwd_guest, &cli.backend, &cli.command) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("literoot: {e}");
                ExitCode::from(125)
            }
        }
    }
}
