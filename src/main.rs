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
mod exec_stage;
mod refusal_log;
mod side_log;
#[cfg(feature = "tool")]
mod exec_state;
#[cfg(feature = "tool")]
mod rootfs_tool;
#[cfg(all(feature = "private-runtime", feature = "tool"))]
#[cfg_attr(not(test), allow(dead_code))] // Row e/f's launcher is the first non-test caller.
mod initial_packet;
#[cfg(all(test, feature = "private-runtime", feature = "tool"))]
mod initial_packet_host_tests;
#[cfg(feature = "private-runtime")]
#[allow(dead_code)] // Row f's static route is the first production caller.
mod runtime_package;
#[cfg(feature = "tool")]
#[allow(dead_code)] // Future shared-record transports are the first production callers.
mod shared_record;
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
    kill_on_exit: bool,
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

/// An argument error from `parse_cli`, typed by where it was raised: the
/// side-log key follows the variant, never the text, whose words can come
/// from the command line (review of g2 8b480bd0).
#[derive(Debug)]
enum CliError {
    /// One of the closed list of argument errors real proot also raises for
    /// the same argv, each expected by an upstream suite line
    /// (test-rootfs-arg-validation's "no launch" lines): no side-log key.
    /// Built only at those call sites: `-v` without a level, binding over
    /// `/`, and the rootfs canonicalization (narrowing that one by errno is
    /// a separate follow-up).
    ProotAlsoRaises(String),
    /// Every other argument error: keyed by `launcher_token`.
    Other(String),
}

impl From<String> for CliError {
    fn from(error: String) -> Self {
        CliError::Other(error)
    }
}

impl From<&str> for CliError {
    fn from(error: &str) -> Self {
        CliError::Other(error.to_owned())
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::ProotAlsoRaises(e) | CliError::Other(e) => f.write_str(e),
        }
    }
}

fn parse_cli(args: &[String]) -> Result<Cli, CliError> {
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
    let mut kill_on_exit = false;
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
            "--kill-on-exit" => kill_on_exit = true,
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
                        Err(_) => return Err(CliError::ProotAlsoRaises("literoot: -v requires a level argument".into())),
                    },
                    _ => return Err(CliError::ProotAlsoRaises("literoot: -v requires a level argument".into())),
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
                exit_after_parse();
            }
            "--version" => {
                println!("{VERSION_LINE}");
                println!(
                    "backend: reverie-ptrace (POC reference); in-guest liteinst/trap: design §3"
                );
                exit_after_parse();
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
                    return Err(format!("literoot: unknown option {s} (try --help)").into());
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
            return Err(CliError::ProotAlsoRaises(
                "literoot: binding over / conflicts with the rootfs".into(),
            ));
        }
        binds.retain(|b| b.guest != Path::new("/"));
    }
    let rootfs = rootfs
        .canonicalize()
        .map_err(|e| {
            CliError::ProotAlsoRaises(format!("literoot: rootfs {}: {e}", rootfs.display()))
        })?;
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
        kill_on_exit,
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
         \x20 --backend <name>       ptrace (POC reference) | liteinst (design §3); guest ptrace is refused on in-guest backends\n\
         \x20 --kill-on-exit         kill the traced guest tree when the initial guest exits (ptrace backend only; CLONE_UNTRACED children are not traced and escape)\n\
         \x20                        kill-on-exit refusals exit 2 (a guest may also exit 2; the literoot: kill-on-exit: stderr prefix distinguishes)\n\
         \x20 --check <guest-path>   print translation and exit (repeatable)\n\
         \x20 -v, --verbose          report selected mechanism\n\
         \x20 --help, --version"
    );
}

/// Exit code for a launcher-side error. Named
/// --kill-on-exit refusals (the unsupported-backend refusal
/// and the runtime "kill-on-exit: refusing ..." errors)
/// get 2, not the generic launcher-failure 125 (which the
/// upstream proot suite counts as "skipped").
fn launcher_error_exit_code(error: &str) -> u8 {
    if error.starts_with("--kill-on-exit is supported only on the ptrace backend")
        || error.starts_with("kill-on-exit:")
    {
        2
    } else {
        125
    }
}

/// Exit status when the refusal log cannot be opened or a write to it
/// fails: neither 0 nor 125. A driver decides validity from the log's own
/// lines (its `end` line), not from this status, which the suite's shell
/// may hide.
const REFUSAL_LOG_EXIT: u8 = 3;

/// The side-log key for an argument error from `parse_cli`: `None` for the
/// closed list (`CliError::ProotAlsoRaises`), chosen by the variant the call
/// site built, never by the text.
fn launcher_refusal(error: &CliError) -> Option<&'static str> {
    match error {
        CliError::ProotAlsoRaises(_) => None,
        CliError::Other(e) => Some(launcher_token(e)),
    }
}

/// The side-log key for any launcher error that is not one of `parse_cli`'s
/// closed-list argument errors: never `None`. Guest-command exec errors (not
/// found, not executable) are exempt through `tool::command_was_not_runnable`,
/// by their origin, not by their text.
fn launcher_token(error: &str) -> &'static str {
    if error.starts_with("literoot: -q/qemu passthrough") {
        "qemu_passthrough"
    } else if error.starts_with("literoot: proot extensions") {
        "extension"
    } else if error.contains("aarch64 in-guest initial loader-as-main launch") {
        "unlimited_stack_loader"
    } else if error.contains("static executables are not supported by the in-guest backend") {
        "static_floor"
    } else if launcher_error_exit_code(error) == 2 {
        "kill_on_exit"
    } else {
        "other"
    }
}

/// `literoot --check-refusal-log <path>`: exit 0 and print the refused
/// lines when the log is valid for one test name, else exit 1 with the
/// reason. A missing log is not valid.
fn check_refusal_log(args: &[String]) -> ExitCode {
    let [path] = args else {
        eprintln!("literoot: --check-refusal-log takes one path");
        return ExitCode::from(2);
    };
    let checked = std::fs::read(path)
        .map_err(|e| format!("{path}: {e}"))
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| format!("{path}: not UTF-8")))
        .and_then(|text| side_log::validate(&text));
    match checked {
        Ok(refused) => {
            for line in refused {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("literoot: refusal log not valid: {e}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--check-refusal-log") {
        return check_refusal_log(&argv[1..]);
    }
    // The log option is taken before any other option is read: `-q` and
    // `--extension` return from parsing at once, and they are refusals.
    let log = side_log::take_from_args(&mut argv);
    let path = match &log {
        Ok(path) => path.clone(),
        Err((first, _)) if first.is_empty() => {
            eprintln!("literoot: --refusal-log requires a path");
            return ExitCode::from(125);
        }
        Err((first, _)) => Some(first.clone()),
    };
    if let Some(path) = &path {
        if let Err(e) = side_log::open(Path::new(path)) {
            eprintln!("literoot: --refusal-log {path}: {e}");
            return ExitCode::from(REFUSAL_LOG_EXIT);
        }
        side_log::begin();
    }
    let code = match log {
        Err((_, second)) => {
            side_log::refused_launcher("refusal_log_repeated");
            eprintln!("literoot: --refusal-log given twice (also {second:?})");
            ExitCode::from(125)
        }
        Ok(_) => launch(argv),
    };
    if refusal_log::is_open() {
        side_log::end(if launch_failed() {
            Some("launch")
        } else if reporter_missing() {
            Some("reporter")
        } else {
            None
        });
        if side_log::failed() {
            eprintln!("literoot: --refusal-log: a write failed");
            return ExitCode::from(REFUSAL_LOG_EXIT);
        }
    }
    code
}

/// For `--help` and `--version`, which exit from parsing: end the side log
/// and exit 0, or `REFUSAL_LOG_EXIT` when a write to it failed, as `main`
/// does for every other run (C1).
fn exit_after_parse() -> ! {
    if refusal_log::is_open() {
        side_log::end(None);
        if side_log::failed() {
            eprintln!("literoot: --refusal-log: a write failed");
            std::process::exit(REFUSAL_LOG_EXIT.into());
        }
    }
    std::process::exit(0)
}

/// Whether the guest's launch itself failed (see `tool::launch_failed`).
fn launch_failed() -> bool {
    #[cfg(feature = "tool")]
    return tool::launch_failed();
    #[cfg(not(feature = "tool"))]
    return false;
}

/// Whether an in-guest run finished without a reporter (see
/// `tool::reporter_missing`).
fn reporter_missing() -> bool {
    #[cfg(feature = "tool")]
    return tool::reporter_missing();
    #[cfg(not(feature = "tool"))]
    return false;
}

fn launch(argv: Vec<String>) -> ExitCode {
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
            let e = format!("literoot: PROOT_TMP_DIR {tmp:?} is not a writable directory");
            side_log::refused_launcher(launcher_token(&e));
            eprintln!("{e}");
            return ExitCode::from(125);
        }
    }
    if argv.is_empty() {
        println!("{VERSION_LINE}");
        return ExitCode::SUCCESS;
    }
    let cli = match parse_cli(&argv) {
        Ok(c) => c,
        Err(e) => {
            if let Some(key) = launcher_refusal(&e) {
                side_log::refused_launcher(key);
            }
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
        side_log::refused_launcher("other");
        eprintln!(
            "literoot: built without a backend feature — translation engine only. \
             Rebuild with default features to execute guests."
        );
        ExitCode::from(125)
    }
    #[cfg(feature = "tool")]
    {
        match tool::run_guest(&cli.config, &cli.cwd_guest, &cli.backend, &cli.command, cli.kill_on_exit) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                let code = launcher_error_exit_code(&e);
                if !tool::command_was_not_runnable() {
                    side_log::refused_launcher(launcher_token(&e));
                }
                eprintln!("literoot: {e}");
                ExitCode::from(code)
            }
        }
    }
}

#[cfg(test)]
mod kill_on_exit_parse_tests {
    use super::{launcher_error_exit_code, launcher_token, parse_cli};

    #[test]
    fn unlimited_stack_refusal_has_its_own_side_log_key() {
        assert_eq!(
            launcher_token(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution"
            ),
            "unlimited_stack_loader"
        );
        assert_eq!(launcher_token("some other launcher error"), "other");
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn kill_on_exit_flag_accepted_and_default_off() {
        let off = parse_cli(&args(&["/bin/true"])).unwrap();
        assert!(!off.kill_on_exit);
        let on = parse_cli(&args(&["--kill-on-exit", "/bin/true"])).unwrap();
        assert!(on.kill_on_exit);
        assert_eq!(on.command, vec!["/bin/true".to_string()]);
    }

    #[test]
    fn kill_on_exit_refusal_exit_code_is_distinct_from_suite_skip() {
        assert_eq!(
            launcher_error_exit_code(
                "--kill-on-exit is supported only on the ptrace backend (details)"
            ),
            2
        );
        assert_eq!(
            launcher_error_exit_code(
                "kill-on-exit: refusing unaccepted tracer wait error other tracer error: EPERM"
            ),
            2
        );
        assert_eq!(
            launcher_error_exit_code(
                "kill-on-exit: root exit status was not recorded within 2s after root exit"
            ),
            2
        );
        assert_eq!(launcher_error_exit_code("tracer spawn: EPERM"), 125);
    }
}
