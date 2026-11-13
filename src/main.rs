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
mod fake_creds;
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

/// proot's option table gives every long option that takes a value the
/// `=` separator (`--kernel-release=VALUE`); literoot accepts that form as
/// well as the space form. Only the long options below are split, so an
/// `=` in any other argument (a no-value flag, or the guest command and
/// its arguments) is left as it was.
fn split_long_value(arg: &str) -> (&str, Option<String>) {
    const LONG_WITH_VALUE: [&str; 11] = [
        "--rootfs",
        "--bind",
        "--mount",
        "--cwd",
        "--pwd",
        "--kernel-release",
        "--identity",
        "--change-id",
        "--backend",
        "--check",
        "--verbose",
    ];
    if let Some((name, value)) = arg.split_once('=') {
        if LONG_WITH_VALUE.contains(&name) {
            return (name, Some(value.to_owned()));
        }
    }
    (arg, None)
}

/// proot's `parse_integer_option` (`cli.c`): `strtol(value, &end, 10)`
/// stored in an `int`. Leading whitespace and a sign are accepted and
/// trailing text is ignored; only a value with no digits, or one outside
/// `long`'s range, is refused (`None`). `side_log::take_from_args` reads
/// `-v`'s level with it too, so both agree on what is a level.
pub(crate) fn proot_integer(value: &str) -> Option<i32> {
    let s = value.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (negative, rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    // More digits than an i128 holds is out of range as well (ERANGE).
    let magnitude: i128 = rest[..digits].parse().ok()?;
    let long = i64::try_from(if negative { -magnitude } else { magnitude }).ok()?;
    // C's conversion of a long to int keeps the low 32 bits on Linux.
    Some(long as i32)
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
    let mut identity_only = true;
    let mut backend = String::from("ptrace");
    let mut verbose = false;
    let mut kill_on_exit = false;
    let mut check_paths: Vec<String> = Vec::new();
    let mut command: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let (a, inline) = split_long_value(&args[i]);
        let take = |i: &mut usize, flag: &str| -> Result<String, String> {
            if let Some(value) = &inline {
                return Ok(value.clone());
            }
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("literoot: {flag} requires a value"))
        };
        match a {
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
            "-w" | "--cwd" | "--pwd" | "-c" => {
                cwd_explicit = true;
                cwd_guest = PathBuf::from(take(&mut i, "-w")?)
            }
            "-0" | "--root-id" => {
                fake_root = true;
                fake_ids = Some((0, 0));
            }
            "-i" | "--identity" | "--change-id" => {
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
            "--identity-only" => identity_only = true,
            "--no-identity-only" => identity_only = false,
            "--check" => check_paths.push(take(&mut i, "--check")?),
            "-v" | "--verbose" => {
                // proot's -v requires a level argument; only
                // positive levels print (tests use -v -1 = quiet
                // and compare stderr byte-for-byte).
                let level = match &inline {
                    Some(value) => Some(value.as_str()),
                    None => args.get(i + 1).map(String::as_str),
                };
                match level.map(proot_integer) {
                    Some(Some(level)) => {
                        verbose = level > 0;
                        if inline.is_none() {
                            i += 1;
                        }
                    }
                    _ => {
                        return Err(CliError::ProotAlsoRaises(
                            "literoot: -v requires a level argument".into(),
                        ));
                    }
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
    // Requested unless --no-identity-only; the launcher keeps it only for
    // the caller's own non-root ids (`tool::identity_only_applies`), the
    // rule of the Android launcher's patched proot.
    config.identity_only = identity_only;
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
         \x20 -w, --cwd, --pwd <dir> initial guest cwd (default / or PROOT_CWD)\n\
         \x20 -0, --root-id          fake uid/gid 0\n\
         \x20 -i, --change-id <u:g>  fake uid and gid\n\
         \x20                        -i equal to the caller's own non-root ids emulates only\n\
         \x20                        the set*id, setfs*id and setxattr calls (an Android\n\
         \x20                        launcher's patched-proot rule); other ids get every -i rule\n\
         \x20 --no-identity-only     every -i rule, for the caller's own ids too\n\
         \x20 --identity-only        the default rule above, requested explicitly\n\
         \x20 -k, --kernel-release <s>  spoof uname release\n\
         \x20 --backend <name>       ptrace (POC reference) | liteinst (design §3); guest ptrace is refused on in-guest backends\n\
         \x20 --kill-on-exit         kill the traced guest tree when the initial guest exits (ptrace backend only; CLONE_UNTRACED children are not traced and escape)\n\
         \x20                        kill-on-exit refusals exit 2 (a guest may also exit 2; the literoot: kill-on-exit: stderr prefix distinguishes)\n\
         \x20 --check <guest-path>   print translation and exit (repeatable)\n\
         \x20 -v, --verbose <level>  report selected mechanism (level > 0)\n\
         \x20 Long options that take a value also accept --name=value.\n\
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

#[cfg(test)]
mod long_option_value_tests {
    use super::{parse_cli, proot_integer, side_log, Cli, CliError};
    use std::path::PathBuf;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Everything `parse_cli` decides, in a comparable form.
    fn summary(cli: &Cli) -> impl PartialEq + std::fmt::Debug {
        (
            cli.config.rootfs.clone(),
            cli.config.binds.clone(),
            cli.config.fake_root,
            cli.config.fake_ids,
            cli.config.kernel_release.clone(),
            cli.cwd_guest.clone(),
            cli.backend.clone(),
            cli.verbose,
            cli.kill_on_exit,
            cli.check_paths.clone(),
            cli.command.clone(),
        )
    }

    fn parse(v: &[&str]) -> Cli {
        parse_cli(&args(v)).unwrap_or_else(|e| panic!("{v:?}: {e}"))
    }

    fn error(v: &[&str]) -> String {
        match parse_cli(&args(v)) {
            Ok(cli) => panic!("{v:?} parsed: {cli:?}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn launcher_style_argv_parses() {
        // The shape of the argv an Android launcher builds for proot.
        let cli = parse(&[
            "--kill-on-exit",
            "--kernel-release=6.17.0-generic",
            "-i",
            "10123:10123",
            "-r",
            "/",
            "-w",
            "/root",
            "-b",
            "/dev",
            "-b",
            "/proc/self/fd:/dev/fd",
            "/usr/bin/env",
            "-i",
            "HOME=/root",
            "/bin/true",
        ]);
        assert_eq!(cli.config.kernel_release.as_deref(), Some("6.17.0-generic"));
        assert_eq!(cli.config.fake_ids, Some((10123, 10123)));
        assert!(cli.config.identity_only);
        assert!(cli.kill_on_exit);
        assert_eq!(cli.cwd_guest, PathBuf::from("/root"));
        assert_eq!(cli.config.binds.len(), 2);
        assert_eq!(
            cli.command,
            args(&["/usr/bin/env", "-i", "HOME=/root", "/bin/true"])
        );
    }

    #[test]
    fn identity_only_is_requested_unless_turned_off() {
        let on = |v: &[&str]| parse(v).config.identity_only;
        assert!(on(&["-i", "1:1", "/bin/true"]));
        assert!(on(&["--identity-only", "-i", "1:1", "/bin/true"]));
        assert!(!on(&["--no-identity-only", "-i", "1:1", "/bin/true"]));
        // The last of the two wins.
        assert!(!on(&["--identity-only", "--no-identity-only", "/bin/true"]));
        assert!(on(&["--no-identity-only", "--identity-only", "/bin/true"]));
    }

    #[test]
    fn equals_form_matches_space_form() {
        let pairs: [(&[&str], &[&str]); 8] = [
            (
                &["--rootfs=/", "/bin/true"],
                &["--rootfs", "/", "/bin/true"],
            ),
            (
                &["--bind=/dev", "/bin/true"],
                &["--bind", "/dev", "/bin/true"],
            ),
            (
                &["--mount=/tmp:/mnt", "/bin/true"],
                &["--mount", "/tmp:/mnt", "/bin/true"],
            ),
            (&["--cwd=/root", "/bin/true"], &["-w", "/root", "/bin/true"]),
            (
                &["--pwd=/root", "/bin/true"],
                &["--cwd", "/root", "/bin/true"],
            ),
            (
                &["--kernel-release=6.1.0", "/bin/true"],
                &["-k", "6.1.0", "/bin/true"],
            ),
            (
                &["--change-id=5:6", "/bin/true"],
                &["-i", "5:6", "/bin/true"],
            ),
            (&["--verbose=-1", "/bin/true"], &["-v", "-1", "/bin/true"]),
        ];
        for (equals, space) in pairs {
            assert_eq!(
                summary(&parse(equals)),
                summary(&parse(space)),
                "{equals:?} vs {space:?}"
            );
        }
    }

    #[test]
    fn value_keeps_later_equals_signs() {
        let cli = parse(&["--kernel-release=a=b", "/bin/true"]);
        assert_eq!(cli.config.kernel_release.as_deref(), Some("a=b"));
        let cli = parse(&["--check=/x=y"]);
        assert_eq!(cli.check_paths, args(&["/x=y"]));
    }

    #[test]
    fn empty_equals_value_is_a_value() {
        let cli = parse(&["--kernel-release=", "/bin/true"]);
        assert_eq!(cli.config.kernel_release.as_deref(), Some(""));
        assert_eq!(cli.command, args(&["/bin/true"]));
    }

    #[test]
    fn command_arguments_are_not_split() {
        let cli = parse(&["/bin/echo", "--kernel-release=x", "--rootfs=/nope"]);
        assert_eq!(cli.config.kernel_release, None);
        assert_eq!(
            cli.command,
            args(&["/bin/echo", "--kernel-release=x", "--rootfs=/nope"])
        );
        let cli = parse(&["--", "--cwd=/x"]);
        assert_eq!(cli.command, args(&["--cwd=/x"]));
    }

    #[test]
    fn flags_without_a_value_refuse_equals() {
        assert!(
            error(&["--kill-on-exit=1", "/bin/true"]).contains("unknown option --kill-on-exit=1")
        );
        assert!(error(&["--root-id=1", "/bin/true"]).contains("unknown option --root-id=1"));
    }

    #[test]
    fn verbose_equals_needs_a_number() {
        assert!(parse(&["--verbose=1", "/bin/true"]).verbose);
        assert!(!parse(&["--verbose=0", "/bin/true"]).verbose);
        assert!(error(&["--verbose=x", "/bin/true"]).contains("-v requires a level"));
        // The equals form never consumes the next argument as the level.
        let cli = parse(&["--verbose=1", "2"]);
        assert_eq!(cli.command, args(&["2"]));
    }

    #[test]
    fn levels_are_read_as_proots_strtol_reads_them() {
        let cases: [(&str, Option<i32>); 16] = [
            ("1", Some(1)),
            ("-1", Some(-1)),
            ("+2", Some(2)),
            (" \t3", Some(3)),
            ("1junk", Some(1)),
            ("0x10", Some(0)),
            ("4294967297", Some(1)),
            ("9223372036854775807", Some(-1)),
            ("-9223372036854775808", Some(0)),
            ("9223372036854775808", None),
            ("99999999999999999999999999999999999999999", None),
            ("", None),
            ("x", None),
            ("-", None),
            (" ", None),
            ("- 1", None),
        ];
        for (value, level) in cases {
            assert_eq!(proot_integer(value), level, "{value:?}");
        }
    }

    #[test]
    fn a_level_proot_accepts_is_not_a_proot_error() {
        // proot runs `--verbose=1junk` at level 1, so literoot must not
        // classify it as an error proot also raises (which would drop the
        // refusal marker): it is accepted, in both spellings.
        for argv in [
            &["--verbose=1junk", "/bin/true"][..],
            &["-v", "1junk", "/bin/true"][..],
        ] {
            let cli = parse(argv);
            assert!(cli.verbose, "{argv:?}");
            assert_eq!(cli.command, args(&["/bin/true"]), "{argv:?}");
        }
        // A value proot refuses too stays the exempt variant.
        for argv in [
            &["--verbose=x", "/bin/true"][..],
            &["--verbose=", "/bin/true"][..],
            &["-v", "x", "/bin/true"][..],
        ] {
            assert!(
                matches!(parse_cli(&args(argv)), Err(CliError::ProotAlsoRaises(_))),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn every_separate_value_spelling_survives_the_log_scan() {
        // main() takes --refusal-log out first (side_log::take_from_args); an
        // option whose value word it does not skip ends that scan early and
        // leaves the log option to parse_cli, which refuses it.
        let spellings: [(&str, &str); 19] = [
            ("-r", "/"),
            ("--rootfs", "/"),
            ("-R", "/"),
            ("-b", "/dev"),
            ("--bind", "/dev"),
            ("-m", "/dev"),
            ("--mount", "/dev"),
            ("-w", "/"),
            ("--cwd", "/"),
            ("--pwd", "/"),
            ("-c", "/"),
            ("-i", "5:6"),
            ("--identity", "5:6"),
            ("--change-id", "5:6"),
            ("-k", "6.1.0"),
            ("--kernel-release", "6.1.0"),
            ("--backend", "ptrace"),
            ("-v", "1junk"),
            ("--verbose", "1"),
        ];
        for (option, value) in spellings {
            let mut argv = args(&[option, value, "--refusal-log", "/l", "--check", "/"]);
            assert_eq!(
                side_log::take_from_args(&mut argv),
                Ok(Some("/l".to_string())),
                "{option}"
            );
            let cli = parse_cli(&argv).unwrap_or_else(|e| panic!("{option}: {e}"));
            assert_eq!(cli.check_paths, args(&["/"]), "{option}");
        }
    }
}
