//! Launcher side: runs `RootfsTool` on a Reverie backend.
//! The Tool itself lives in `rootfs_tool` so the in-guest preload
//! (`preload/`) compiles the identical code into the guest.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::rootfs_tool::{LiterootConfig, RootfsTool, set_config};
use crate::translate::RootConfig;

/// Whether an initial loader-as-main spawn gets the temporary
/// stack-limit cap. Only the ptrace backend restores before the
/// new image's first instruction; in-guest backends would restore
/// only at the first Tool event, after glibc has cached its
/// default thread stack size.
fn initial_loader_cap_needed(has_loader: bool, in_guest: bool) -> bool {
    has_loader && !in_guest
}

/// Read this launcher process's own initial stack limit.
#[cfg(target_arch = "aarch64")]
fn read_initial_stack_limit() -> Result<libc::rlimit64, String> {
    let mut old: libc::rlimit64 = unsafe { std::mem::zeroed() };
    let get = unsafe {
        libc::prlimit64(0, libc::RLIMIT_STACK, std::ptr::null(), &mut old)
    };
    if get != 0 {
        return Err(format!(
            "literoot: read initial RLIMIT_STACK: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(old)
}

/// Whether an in-guest initial loader-as-main spawn must be
/// refused by name. On AArch64 an unlimited soft stack limit
/// selects the kernel's legacy bottom-up mmap layout, so the
/// loader image's break cannot grow; the in-guest cap cannot be
/// restored before glibc has cached its default thread stack
/// size, so capping is not an option there either. Refusing
/// before any guest instruction runs beats silently launching
/// with a non-growable break (dh-exsg3). Only the stack-limit
/// trigger is covered; ADDR_COMPAT_LAYOUT and
/// vm.legacy_va_layout=1 select the same layout (dh-c1i03h).
fn refuse_unlimited_in_guest_loader(
    has_loader: bool,
    in_guest: bool,
) -> Result<(), String> {
    if !(has_loader && in_guest) {
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    {
        let old = read_initial_stack_limit()?;
        if old.rlim_cur == libc::RLIM64_INFINITY {
            return Err(
                "aarch64 in-guest initial loader-as-main launch \
                 with unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution"
                    .into(),
            );
        }
    }
    Ok(())
}

/// Outcome of inspecting a possible linker target's PT_INTERP.
enum InterpRead {
    /// Not an ELF image, not a regular file, or no PT_INTERP: the
    /// backend cannot admit this as a dynamic target either.
    NotElf,
    /// The file's PT_INTERP string.
    Named(String),
    /// An ELF image whose interpreter could not be determined
    /// within the inspection bounds. Uncertainty is never treated
    /// as "not a linker": the classifier refuses by name instead
    /// of silently exempting a shape the backend might admit.
    Uncertain,
}

/// Read a file's PT_INTERP with bounded, non-blocking I/O. The
/// path comes from a guest-controlled argument: it is opened only
/// as a regular file, with `O_NONBLOCK | O_NOCTTY` and a
/// descriptor re-check (the pinned backend's `open_regular`
/// protocol, which also closes the stat/open replacement race),
/// and only the ELF header, the program-header table (capped at
/// 64 KiB, the kernel's own table bound), and the interpreter
/// string (capped at 4096 bytes) are read — never the whole file.
/// Both ELF classes are read.
fn read_elf_interp_bounded(path: &Path) -> InterpRead {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt as _;

    if !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return InterpRead::NotElf;
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    else {
        return InterpRead::NotElf;
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return InterpRead::NotElf;
    }
    // Read up to a full header; a recognised ELF that is too
    // short to inspect is Uncertain, never NotElf.
    let mut header = [0u8; 64];
    let mut filled = 0usize;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return InterpRead::NotElf,
        }
    }
    if filled < 4 || &header[0..4] != b"\x7fELF" {
        return InterpRead::NotElf;
    }
    let header_needed = match header.get(4) {
        Some(2) => 58,
        Some(1) => 46,
        _ => return InterpRead::Uncertain,
    };
    if filled < header_needed {
        return InterpRead::Uncertain;
    }
    let le = header[5] == 1;
    let rd16 = |b: &[u8]| -> u16 {
        let bytes: [u8; 2] = b[..2].try_into().unwrap();
        if le {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let rd32 = |b: &[u8]| -> u32 {
        let bytes: [u8; 4] = b[..4].try_into().unwrap();
        if le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let rd64 = |b: &[u8]| -> u64 {
        let bytes: [u8; 8] = b[..8].try_into().unwrap();
        if le {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    };
    // ELF64 and ELF32 header/program-header layouts.
    let (phoff, phentsize, phnum, offset_at, filesz_at): (u64, u64, u64, usize, usize) =
        match header[4] {
            2 => (
                rd64(&header[32..40]),
                rd16(&header[54..56]) as u64,
                rd16(&header[56..58]) as u64,
                8,
                32,
            ),
            1 => (
                rd32(&header[28..32]) as u64,
                rd16(&header[42..44]) as u64,
                rd16(&header[44..46]) as u64,
                4,
                16,
            ),
            _ => return InterpRead::Uncertain,
        };
    let entry_min = (filesz_at + 8) as u64;
    if phnum == 0 {
        // No program headers: definitely no PT_INTERP (relocatable
        // objects, kernel modules), matching the backend's reader.
        return InterpRead::NotElf;
    }
    if phoff == 0 || phentsize < entry_min || phentsize > 256 {
        return InterpRead::Uncertain;
    }
    let Some(table_len) = phnum.checked_mul(phentsize) else {
        return InterpRead::Uncertain;
    };
    if table_len > 65536 || file.seek(SeekFrom::Start(phoff)).is_err() {
        return InterpRead::Uncertain;
    }
    let mut table = vec![0u8; table_len as usize];
    if file.read_exact(&mut table).is_err() {
        return InterpRead::Uncertain;
    }
    const PT_INTERP: u32 = 3;
    for i in 0..phnum as usize {
        let off = i * phentsize as usize;
        let Some(entry) = table.get(off..off + phentsize as usize) else {
            return InterpRead::Uncertain;
        };
        if rd32(&entry[0..4]) != PT_INTERP {
            continue;
        }
        let p_offset = if header[4] == 2 {
            rd64(&entry[offset_at..offset_at + 8])
        } else {
            rd32(&entry[offset_at..offset_at + 4]) as u64
        };
        let p_filesz = if header[4] == 2 {
            rd64(&entry[filesz_at..filesz_at + 8])
        } else {
            rd32(&entry[filesz_at..filesz_at + 4]) as u64
        };
        if p_filesz == 0 || p_filesz > 4096 || file.seek(SeekFrom::Start(p_offset)).is_err() {
            return InterpRead::Uncertain;
        }
        let mut raw = vec![0u8; p_filesz as usize];
        if file.read_exact(&mut raw).is_err() {
            return InterpRead::Uncertain;
        }
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        return match String::from_utf8(raw[..end].to_vec()) {
            Ok(interp) => InterpRead::Named(interp),
            Err(_) => InterpRead::Uncertain,
        };
    }
    InterpRead::NotElf
}

/// The target argument of an explicit linker launch, parsed with
/// glibc ld.so's option grammar (mirrors the pinned backend's
/// `linker_target`): only these spellings, each value as the next
/// argument, no `--opt=value` form, and `--` is not an
/// end-of-options marker; an unrecognised `--` token, a value
/// option with no value, or a slashless target (glibc looks those
/// up through its library search, never the working directory)
/// means no target was named.
fn linker_target_arg(args: &[String]) -> Option<&str> {
    const VALUE_OPTIONS: &[&str] = &[
        "--argv0",
        "--audit",
        "--glibc-hwcaps-mask",
        "--glibc-hwcaps-prepend",
        "--inhibit-rpath",
        "--library-path",
        "--preload",
    ];
    const FLAG_OPTIONS: &[&str] = &[
        "--help",
        "--inhibit-cache",
        "--list",
        "--list-diagnostics",
        "--list-tunables",
        "--verify",
        "--version",
    ];
    let mut tokens = args.iter();
    let target = loop {
        let token = tokens.next()?;
        if !token.starts_with("--") {
            break token.as_str();
        }
        if VALUE_OPTIONS.contains(&token.as_str()) {
            tokens.next()?;
        } else if !FLAG_OPTIONS.contains(&token.as_str()) {
            return None;
        }
    };
    if !target.contains('/') {
        return None;
    }
    Some(target)
}

/// Whether a direct-program spawn is really an explicit
/// linker-as-main launch: the program has no PT_INTERP of its own
/// (checked by the caller), and its first non-option argument is a
/// dynamic program whose PT_INTERP names the program. Recognition
/// uses the effective HOST view the pinned in-guest launcher's
/// admission inspects (Reverie's `linker_target`): the host program
/// path, the raw argument resolved only against the command's host
/// current directory, and the target's PT_INTERP compared to the
/// host program (string-equal or canonical-equal). Rootfs and bind
/// translations deliberately do NOT apply here: the backend passes
/// the argument unchanged, so a bind that remaps the guest view of
/// the target cannot hide the launch the backend admits. Ordinary
/// dynamic programs carry their own PT_INTERP and never reach
/// here; a target naming a different linker does not match either.
fn explicit_linker_as_main(
    host_prog: &Path,
    host_cwd: &Path,
    args: &[String],
) -> bool {
    // Both consumers of this classification (the aarch64 refusal
    // and the aarch64 ptrace cap) act only on AArch64 with an
    // unlimited soft stack limit, so the guest-controlled target
    // is not even inspected anywhere else (in particular, never on
    // x86). A failed limit read still classifies: the bounded
    // reader below is safe on any path.
    #[cfg(target_arch = "aarch64")]
    let gate_open = match read_initial_stack_limit() {
        Ok(limits) => limits.rlim_cur == libc::RLIM64_INFINITY,
        Err(_) => true,
    };
    #[cfg(not(target_arch = "aarch64"))]
    let gate_open = false;
    if !gate_open {
        return false;
    }
    let Some(target) = linker_target_arg(args) else {
        return false;
    };
    // The backend resolves the raw target argument only against
    // the command's host current directory (Reverie `resolve_in`);
    // no rootfs or bind translation is applied to it.
    let target_path = Path::new(target);
    let target_host = if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        host_cwd.join(target_path)
    };
    match read_elf_interp_bounded(&target_host) {
        InterpRead::Named(interp) => interp_names_program(&interp, host_prog),
        // Never silently exempt a possible linker launch.
        InterpRead::Uncertain => true,
        InterpRead::NotElf => false,
    }
}

/// The guest-view twin of `explicit_linker_as_main`, used only for
/// the ptrace cap: under ptrace the target that actually loads is
/// the guest-view file after rootfs and bind translation (there is
/// no backend admission step), so a launch the host view misses
/// must still be capped. An extra match here only adds a cap and
/// restore (a different mmap layout for that one exec).
fn explicit_linker_as_main_guest_view(
    config: &RootConfig,
    cwd_guest: &Path,
    host_prog: &Path,
    guest_prog: &str,
    guest_found: &str,
    args: &[String],
) -> bool {
    #[cfg(target_arch = "aarch64")]
    let gate_open = match read_initial_stack_limit() {
        Ok(limits) => limits.rlim_cur == libc::RLIM64_INFINITY,
        Err(_) => true,
    };
    #[cfg(not(target_arch = "aarch64"))]
    let gate_open = false;
    if !gate_open {
        return false;
    }
    let Some(target) = linker_target_arg(args) else {
        return false;
    };
    let target_host = resolve_in_rootfs(config, cwd_guest, Path::new(target));
    match read_elf_interp_bounded(&target_host) {
        InterpRead::Named(interp) => {
            if interp == guest_prog || interp == guest_found {
                return true;
            }
            // Resolve the interpreter through the same guest view
            // (rootfs, binds, symlinks) before comparing: a guest
            // alias of the loader names the same host file.
            let interp_host = resolve_in_rootfs(config, cwd_guest, Path::new(&interp));
            interp_names_program(&interp_host.to_string_lossy(), host_prog)
        }
        InterpRead::Uncertain => true,
        InterpRead::NotElf => false,
    }
}

/// Whether an interpreter string names the program: string-equal
/// to the host program path, or canonical-equal (the pinned
/// backend's `linker_target` equality).
fn interp_names_program(interp: &str, host_prog: &Path) -> bool {
    Path::new(interp) == host_prog
        || matches!(
            (Path::new(interp).canonicalize(), host_prog.canonicalize()),
            (Ok(a), Ok(b)) if a == b
        )
}

/// Cap this launcher process's soft stack limit for one initial
/// loader-as-main spawn, recording the exact original pair in the
/// Tool config for post-exec restore in the guest. AArch64-only
/// for the stack-limit legacy-layout trigger; see
/// `begin_interp_exec_stack_limit`.
fn cap_initial_stack_limit(
    cfg: &mut LiterootConfig,
) -> Result<Option<(u64, u64)>, String> {
    #[cfg(target_arch = "aarch64")]
    {
        let old = read_initial_stack_limit()?;
        if old.rlim_cur != libc::RLIM64_INFINITY {
            return Ok(None);
        }
        let original = (old.rlim_cur, old.rlim_max);
        cfg.initial_stack_limit = Some(original);
        set_config(cfg.clone());
        let capped = libc::rlimit64 {
            rlim_cur: libc::RLIM64_INFINITY - 1,
            rlim_max: old.rlim_max,
        };
        let set = unsafe {
            libc::prlimit64(0, libc::RLIMIT_STACK, &capped, std::ptr::null_mut())
        };
        if set != 0 {
            cfg.initial_stack_limit = None;
            set_config(cfg.clone());
            return Err(format!(
                "literoot: cap initial RLIMIT_STACK: {}",
                std::io::Error::last_os_error()
            ));
        }
        return Ok(Some(original));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = cfg;
        Ok(None)
    }
}

/// Restore this launcher process's own stack limit after the
/// capped initial spawn has completed. The guest's copy is
/// restored separately by `RootfsTool` at post-exec.
fn restore_launcher_stack_limit(limits: Option<(u64, u64)>) -> Result<(), String> {
    #[cfg(target_arch = "aarch64")]
    if let Some((rlim_cur, rlim_max)) = limits {
        let limit = libc::rlimit64 { rlim_cur, rlim_max };
        let set = unsafe {
            libc::prlimit64(0, libc::RLIMIT_STACK, &limit, std::ptr::null_mut())
        };
        if set != 0 {
            return Err(format!(
                "literoot: restore launcher RLIMIT_STACK: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = limits;
    Ok(())
}

/// Set when the guest command cannot be executed at all (not found,
/// not executable, a directory, a self-referential shebang): the exec
/// errors real proot raises for the same argv, which the launcher does not
/// key as a refusal (the suite expects them, e.g. test-rootfs-arg-validation).
static COMMAND_NOT_RUNNABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn command_not_runnable() {
    COMMAND_NOT_RUNNABLE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Whether a failed lookup of the guest command is exempt from a side-log
/// key: only the errors the command path itself causes, which a native
/// execve and real proot also return for the same argv. Any other I/O error
/// (EIO, ENOMEM, EOVERFLOW, ...) is a keyed launcher refusal
/// (`launcher other`).
fn path_error_is_not_runnable(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES | libc::ELOOP | libc::ENAMETOOLONG)
    )
}

/// Whether the launch failed because the guest command cannot be executed.
pub fn command_was_not_runnable() -> bool {
    COMMAND_NOT_RUNNABLE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Set when an in-guest launch returned an error. Reverie's launch returns
/// only after every coordinator connection has closed, and fails when one
/// outlives the root guest past its drain bound, so a guest that may still
/// be running and reporting is one of these errors; the launcher then ends
/// its side log `error launch`, which no test name can count.
static LAUNCH_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(any(feature = "in-guest", feature = "inguest-trap"))]
fn launch_error(backend: &str, error: impl std::fmt::Display) -> String {
    LAUNCH_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
    format!("in-guest ({backend}) run: {error}")
}

/// Whether an in-guest launch returned an error.
pub fn launch_failed() -> bool {
    LAUNCH_FAILED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Set when an in-guest run finished while the side log was open and no
/// preload process had reported (`rootfs_tool::REPORTER_ACKNOWLEDGED`):
/// the preload predates the refusal side log, so the launcher ends its log
/// `error reporter`, which no test name can count.
static REPORTER_MISSING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(feature = "in-guest", feature = "inguest-trap"))]
fn check_reporter(preload: &Path) {
    use std::sync::atomic::Ordering;
    if crate::refusal_log::is_open()
        && !crate::rootfs_tool::REPORTER_ACKNOWLEDGED.load(Ordering::SeqCst)
    {
        REPORTER_MISSING.store(true, Ordering::SeqCst);
        eprintln!(
            "literoot: --refusal-log: the preload {} sent no refusal report; it \
             predates the refusal side log (rebuild it from this literoot)",
            preload.display()
        );
    }
}

/// Whether an in-guest run finished without a reporter.
pub fn reporter_missing() -> bool {
    REPORTER_MISSING.load(std::sync::atomic::Ordering::SeqCst)
}

/// Run `command` (default `/bin/sh`) inside the rootfs under the
/// requested backend. Returns the guest exit code.
pub fn run_guest(
    config: &RootConfig,
    cwd_guest: &Path,
    backend: &str,
    command: &[String],
    kill_on_exit: bool,
) -> Result<u8, String> {
    // Backends (design §3): ptrace = reference (Tool in tracer);
    // liteinst = in-guest patched sites + SIGSYS trap net;
    // trap = in-guest trap-only (no site patching). The in-guest
    // backend today refuses guest execve/thread-clone by name
    // (EOPNOTSUPP; stage-1b re-arm outstanding, design §10 item 3)
    // — that refusal surfaces verbatim, never a silent downgrade.
    refuse_mapped_without_authority(backend, false)?;
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
    let cwd_effective: &Path = if config.translate(cwd_guest, Path::new("/"), None).is_dir() {
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
        kill_on_exit,
        kompat_force: std::env::var_os("PROOT_FORCE_KOMPAT").is_some(),
        post_exec_at_exec_stop: !in_guest,
        refuse_guest_ptrace: in_guest,
        initial_exe: String::new(),
        initial_argv: Vec::new(),
        initial_stack_limit: None,
    };
    let mut cfg = cfg;
    set_config(cfg.clone());

    // Resolve the guest program through the translated root: the
    // tracer execs the host path, argv[0] stays the guest spelling.
    let guest_prog = command.first().cloned().unwrap_or_else(|| "/bin/sh".into());
    // `guest_found` is the guest path of the program (what the
    // rootfs loader must open); `guest_prog` remains argv[0].
    let (host_prog, guest_found) =
        if Path::new(&guest_prog).components().count() > 1 || guest_prog.starts_with('/') {
            // Absolute or slash-containing (e.g. ./prog): resolve
            // through the rootfs against the guest cwd.
            (
                resolve_in_rootfs(config, cwd_guest, Path::new(&guest_prog)),
                guest_prog.clone(),
            )
        } else {
            // PATH lookup inside the rootfs (guest PATH dirs). An
            // unexpected error from a candidate is a keyed launcher
            // refusal, as on the command path below.
            let found = find_guest_in_path(config, cwd_guest, &guest_prog)
                .map_err(|e| format!("literoot: {guest_prog}: rootfs PATH search: {e}"))?
                .ok_or_else(|| {
                    command_not_runnable();
                    format!("literoot: {guest_prog}: not found in rootfs PATH")
                })?;
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
                command_not_runnable();
                return Err(format!("literoot: {guest_prog}: Permission denied"));
            }
            Ok(md) if md.permissions().mode() & 0o111 == 0 => {
                command_not_runnable();
                return Err(format!("literoot: {guest_prog}: Permission denied"));
            }
            Ok(_) => {}
            Err(e) => {
                if path_error_is_not_runnable(&e) {
                    command_not_runnable();
                }
                return Err(format!("literoot: {guest_prog}: {e}"));
            }
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
        if resolve_in_rootfs(config, cwd_guest, Path::new(&script_interp)) == host_prog {
            eprintln!("literoot: {guest_prog}: Too many levels of symbolic links");
            command_not_runnable();
            return Err("Too many levels of symbolic links".into());
        }
        let interp_host = resolve_in_rootfs(config, cwd_guest, Path::new(&script_interp));
        let interp_interp = std::fs::read(&interp_host)
            .ok()
            .and_then(|img| crate::translate::elf_interp(&img));
        let mut has_loader = interp_interp.is_some();
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
        let host_cwd = if host_cwd.is_dir() {
            host_cwd
        } else {
            config.rootfs.clone()
        };
        // A script naming ld.so itself as its interpreter
        // (`#!<ld.so> <dynamic-program>`) is explicit linker-as-main
        // too: classify it in the same host view, over the exact
        // argument vector the backend receives.
        if !has_loader {
            // Read the exact argument vector the backend receives
            // from the built command, not a reconstruction of it.
            let backend_args: Vec<String> = cmd
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            has_loader = explicit_linker_as_main(&interp_host, &host_cwd, &backend_args)
                || (!in_guest
                    && explicit_linker_as_main_guest_view(
                        config,
                        cwd_guest,
                        &interp_host,
                        &script_interp,
                        &script_interp,
                        &backend_args,
                    ));
        }
        cmd.current_dir(&host_cwd);
        cmd.env("PWD", cwd_guest.to_string_lossy().as_ref());
        refuse_unlimited_in_guest_loader(has_loader, in_guest)?;
        let initial_restore = if initial_loader_cap_needed(has_loader, in_guest) {
            cap_initial_stack_limit(&mut cfg)?
        } else {
            None
        };
        let result = run_backend(cmd, cfg, backend, in_guest);
        restore_launcher_stack_limit(initial_restore)?;
        return result;
    }
    // PT_INTERP: run the program through the rootfs's dynamic
    // linker (design §4.7) — the kernel would otherwise open the
    // interp path on the host (absent for e.g. musl rootfses).
    let prog_interp = std::fs::read(&host_prog)
        .ok()
        .and_then(|img| crate::translate::elf_interp(&img));
    // An explicitly supplied linker (`ld.so <dynamic-program>`)
    // has no PT_INTERP of its own, so it lands in the direct arm
    // below; classify it as loader-as-main too (dh-exsg3), in the
    // effective host view the backend admission uses (the host
    // current directory the command below is given).
    let host_cwd = config.translate(cwd_guest, Path::new("/"), None);
    let host_cwd = if host_cwd.is_dir() {
        host_cwd
    } else {
        config.rootfs.clone()
    };
    let explicit_linker = prog_interp.is_none()
        && (explicit_linker_as_main(
            &host_prog,
            &host_cwd,
            command.get(1..).unwrap_or(&[]),
        ) || (!in_guest
            && explicit_linker_as_main_guest_view(
                config,
                cwd_guest,
                &host_prog,
                &guest_prog,
                &guest_found,
                command.get(1..).unwrap_or(&[]),
            )));
    let interp_guest = prog_interp
        // In-guest: when the host interp exists, let the kernel
        // load it and the preload arm inside the program itself.
        // Exec'ing ld.so as the program makes ld.so open the
        // target before the preload constructor arms (measured:
        // ET_EXEC guests then fail to load in-guest).
        .filter(|interp| !in_guest || !Path::new(interp).exists());
    let has_loader = interp_guest.is_some() || explicit_linker;
    let mut cmd = match &interp_guest {
        Some(interp) => {
            let interp_host = resolve_in_rootfs(config, cwd_guest, Path::new(interp));
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
    // Guest starts with the host cwd computed above (the same one
    // the classifier saw) so real relative syscalls the Tool
    // passes through still land right during early ld.so execution.
    cmd.current_dir(&host_cwd);
    // proot rewrites $PWD to the guest cwd at exec (observed:
    // guest env shows PWD=<guest cwd>; bash's pwd builtin then
    // agrees — test-bind-cwd-bash-pwd).
    cmd.env("PWD", cwd_guest.to_string_lossy().as_ref());
    refuse_unlimited_in_guest_loader(has_loader, in_guest)?;
    let initial_restore = if initial_loader_cap_needed(has_loader, in_guest) {
        cap_initial_stack_limit(&mut cfg)?
    } else {
        None
    };
    let result = run_backend(cmd, cfg, backend, in_guest);
    restore_launcher_stack_limit(initial_restore)?;
    result
}

/// Run a fully-built command on the selected backend.
fn run_backend(
    mut cmd: reverie::process::Command,
    cfg: LiterootConfig,
    backend: &str,
    in_guest: bool,
) -> Result<u8, String> {
    let kill_on_exit = cfg.kill_on_exit;
    // Shared probe-cache generation (memfd inherited by the
    // whole guest tree; translate.rs probe coherence).
    let gen_fd = crate::translate::create_shared_gen_fd();
    if gen_fd >= 0 {
        cmd.env("LITEROOT_PROBE_GEN_FD", gen_fd.to_string());
    }
    // Cross-process facts memfd: the launcher owns creation
    // and registers the handle for Tools in this process.
    // Only an in-guest Tool needs the inherited descriptor
    // number in its environment. Under ptrace, keep the store
    // entirely tracer-side: no env var and no inherited copy
    // for the guest. Failure is a named absence: consumers
    // retain today's process-local maps/statics.
    if !in_guest {
        cmd.env_remove(crate::shared_record::SHARED_RECORD_FD_ENV);
    }
    match crate::shared_record::SharedRecordFile::create() {
        Ok(store) => {
            let fd = store.fd();
            if !in_guest {
                if let Err(err) = store.set_close_on_exec() {
                    eprintln!("literoot: shared record close-on-exec unavailable: {err}");
                }
            }
            if crate::shared_record::init_shared_record_file(store) && in_guest {
                cmd.env(crate::shared_record::SHARED_RECORD_FD_ENV, fd.to_string());
            }
        }
        Err(err) => {
            eprintln!("literoot: shared record unavailable: {err}");
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    // The launch route, for the refusal side log: in-guest backends start
    // their initial program through the preload today.
    crate::side_log::route(if in_guest { "preload" } else { "ptrace" });
    if in_guest {
        // --kill-on-exit is ptrace-only today: an in-guest
        // tree kill needs a launcher-side descent proof the
        // guest cannot forge (a guest-writable registry
        // cannot be the authority for SIGKILL), which is a
        // separate design task. Refuse by name rather than
        // silently degrade.
        if kill_on_exit {
            return Err(
                "--kill-on-exit is supported only on the ptrace backend \
                 (in-guest tree kill needs a launcher-side descent proof)"
                    .into(),
            );
        }
        // Watched exec (W6a spawn swap, W-1 gate): no spawn path
        // in this build seizes the guest under a supervisor, so
        // watched mode is never asserted. The W-2 spawn swap is
        // the only writer that may set this, in the same change
        // that actually spawns watched; asserting it here would
        // arm the guest's exec forwarding with no watcher to
        // re-bootstrap successors.
        let watched = false;
        let selector = crate::rootfs_tool::tool_selector(watched).to_vec();
        // Same Tool, hosted in-guest via the literoot preload. The
        // trap backend prefers Reverie's TrapHost launcher when this
        // build has it (inguest-trap): zero ptrace, no site patching.
        // Without it, trap falls back to the liteinst preload with
        // site patching off, exactly as before.
        #[cfg(feature = "inguest-trap")]
        if backend == "trap" {
            let preload = find_preload().ok_or(
                "literoot preload not found (libliteroot_preload.so beside the \
                 literoot binary, or LITEROOT_PRELOAD=<path>). Build it with: \
                 cargo build --release --manifest-path literoot/preload/Cargo.toml \
                 --no-default-features --features inguest-trap",
            )?;
            let (output, _global) = runtime.block_on(async {
                reverie_inguest::launcher::PreloadBackend::run_with_output_and_preload_data::<
                    RootfsTool,
                >(cmd, cfg, preload.clone(), selector.clone())
                .await
                .map_err(|e| launch_error(backend, e))
            })?;
            check_reporter(&preload);
            std::io::stdout().write_all(&output.stdout).ok();
            std::io::stderr().write_all(&output.stderr).ok();
            use std::os::unix::process::ExitStatusExt;
            let status = output.status;
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
                as u8);
        }
        #[cfg(not(feature = "in-guest"))]
        {
            return Err(format!(
                "backend {backend:?} unavailable: in-guest backends compiled out \
                 (ptrace-only build; rebuild with default features)"
            ));
        }
        #[cfg(feature = "in-guest")]
        {
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
                    preload.clone(),
                    selector.clone(),
                )
                .await
                .map_err(|e| launch_error(backend, e))
            })?;
            check_reporter(&preload);
            std::io::stdout().write_all(&output.stdout).ok();
            std::io::stderr().write_all(&output.stderr).ok();
            use std::os::unix::process::ExitStatusExt;
            let status = output.status;
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
                as u8);
        }
    }

    #[cfg(not(feature = "run"))]
    {
        return Err(
            "backend \"ptrace\" unavailable: ptrace backend compiled out \
             (inguest-trap build; rebuild with --features ptrace-only)"
                .into(),
        );
    }
    #[cfg(feature = "run")]
    let status = runtime.block_on(async {
        let tracer = reverie_ptrace::TracerBuilder::<RootfsTool>::new(cmd)
            .config(cfg)
            .spawn()
            .await
            .map_err(|e| format!("tracer spawn: {e}"))?;
        let root_pid = tracer.guest_pid().as_raw();
        let termination = tracer.termination_handle();
        let mut termination_requested = false;
        let wait = tracer.wait();
        if !kill_on_exit {
            let (status, _global) = wait
                .await
                .map_err(|e| format!("tracer wait: {e}"))?;
            return Ok::<_, String>(status);
        }
        // --kill-on-exit (ptrace): the tracer otherwise waits for
        // the whole tracee tree, setsid-detached descendants
        // included. Watch for the root guest's exit; once the
        // Tool has recorded its raw status, SIGKILL every
        // registered guest pid whose start time still matches,
        // then let wait() reap the now-dying tree. Holding the
        // first kill until the status is recorded prevents our
        // own kill from racing ahead of on_exit_process and
        // turning the root's status into a generic launcher
        // error. PTRACE_O_EXITKILL (safeptrace default seize
        // options) backstops anything missed when this launcher
        // itself exits.
        tokio::pin!(wait);
        let mut poll = tokio::time::interval(std::time::Duration::from_millis(20));
        let mut root_gone = false;
        let mut root_gone_since: Option<std::time::Instant> = None;
        let mut root_status_since: Option<std::time::Instant> = None;
        // At least one verified SIGKILL succeeded on some
        // registered pid (pidfd success on a zombie counts).
        // It is not tied to the tracee named in a later
        // tracer error.
        let mut sent_kill = false;
        let mut sweep_attempted = false;
        // Root status snapshot read at the moment our first
        // sweep/terminate fires. Only this snapshot may be
        // returned for an accepted tracer error. It is the
        // same single ROOT_EXIT_RAW store read at sweep
        // time, so it can itself be a status Reverie's
        // cleanup imposed before the tick lands; the
        // SIGKILL-snapshot refusal in kill_wait_decision
        // covers that case (our sweep never signals root).
        let mut sweep_root_raw: Option<i32> = None;
        let status = loop {
            tokio::select! {
                done = &mut wait => {
                    match done {
                        Ok((status, _global)) => break Ok(status),
                        Err(e) => {
                            let class = classify_kill_wait_error(&e);
                            match kill_wait_decision(
                                class,
                                termination_requested,
                                sent_kill,
                                sweep_root_raw,
                            ) {
                                KillWaitDecision::AcceptRootStatus => {
                                    // A kill or termination we
                                    // requested turned the root's
                                    // clean exit into a tracer
                                    // error; return only the
                                    // snapshot taken before that
                                    // action fired.
                                    break Ok(reverie::ExitStatus::from_raw(
                                        sweep_root_raw.unwrap(),
                                    ));
                                }
                                KillWaitDecision::RefuseRootStatusAbsent => {
                                    break Err(format!(
                                        "kill-on-exit: refusing tracer wait error {} \
                                         because no root exit status snapshot was taken \
                                         before our sweep/terminate: {e}",
                                        class.as_str()
                                    ));
                                }
                                KillWaitDecision::RefuseSigkillSnapshot => {
                                    break Err(format!(
                                        "kill-on-exit: refusing tracer wait error {} \
                                         because the root status snapshot is SIGKILL, \
                                         which our sweep never sends to the root: {e}",
                                        class.as_str()
                                    ));
                                }
                                KillWaitDecision::RefuseUnacceptedError => {
                                    break Err(format!(
                                        "kill-on-exit: refusing unaccepted tracer wait error {} \
                                         (termination_requested={termination_requested}, \
                                         sent_kill={sent_kill}, sweep_attempted={sweep_attempted}, \
                                         root_status_snapshot={sweep_root_raw:?}): {e}",
                                        class.as_str()
                                    ));
                                }
                            }
                        }
                    }
                }
                _ = poll.tick() => {
                    prune_registered_guests();
                    if !root_gone && proc_exited(root_pid) {
                        root_gone = true;
                        root_gone_since = Some(std::time::Instant::now());
                    }
                    let root_status_recorded =
                        crate::rootfs_tool::root_exit_raw().is_some();
                    // Bounded refusal: a gone root whose status
                    // is never recorded must not leave the
                    // launcher waiting on detached descendants
                    // forever. Kill the registered tree and
                    // terminate the tracer, then refuse by name.
                    if root_gone
                        && !root_status_recorded
                        && root_gone_since
                            .map(|s| s.elapsed() >= std::time::Duration::from_secs(2))
                            .unwrap_or(false)
                    {
                        sweep_attempted = true;
                        sent_kill |= kill_registered_guests(root_pid);
                        if !termination_requested {
                            if let Some(handle) = &termination {
                                termination_requested |= handle.terminate(
                                    reverie::Error::Errno(
                                        reverie::syscalls::Errno::ECANCELED,
                                    ),
                                );
                            }
                        }
                        break Err(format!(
                            "kill-on-exit: root exit status was not recorded within 2s \
                             after root exit (root pid {root_pid}); refusing to wait \
                             for detached descendants"
                        ));
                    }
                    let sweep_allowed = kill_sweep_allowed(root_gone, root_status_recorded);
                    if sweep_allowed && root_status_since.is_none() {
                        root_status_since = Some(std::time::Instant::now());
                        sweep_root_raw = crate::rootfs_tool::root_exit_raw();
                    }
                    // Termination is the last resort, not the
                    // first move: give the verified sweeps a
                    // grace period to finish the tree (the
                    // common case), and only a session still
                    // wedged after it (e.g. a fork stop that
                    // never clears) is terminated through the
                    // tracer's cleanup owner, which supersedes
                    // fork stops instead of racing external
                    // SIGKILLs into error 125.
                    if sweep_allowed
                        && !termination_requested
                        && root_status_since
                            .map(|s| s.elapsed() >= std::time::Duration::from_millis(500))
                            .unwrap_or(false)
                    {
                        if let Some(handle) = &termination {
                            termination_requested |= handle.terminate(reverie::Error::Errno(
                                reverie::syscalls::Errno::ECANCELED,
                            ));
                        }
                    }
                    if sweep_allowed {
                        // Every tick, not once, as defense in
                        // depth for registration lag. (A single
                        // post-status sweep would be
                        // survival-equivalent for traced guests:
                        // creation stops are tracer-owned and
                        // traced guests are registered at
                        // creation, with the 500 ms termination
                        // and PTRACE_O_EXITKILL behind it.
                        // CLONE_UNTRACED children are neither
                        // registered nor traced and escape every
                        // sweep variant equally; that gap is
                        // named in the usage text.)
                        sweep_attempted = true;
                        sent_kill |= kill_registered_guests(root_pid);
                    }
                }
            }
        };
        if kill_on_exit
            && (sweep_root_raw.is_some()
                || sweep_attempted
                || crate::rootfs_tool::root_exit_raw().is_some())
        {
            // Defense-in-depth sweep on every completed wait
            // path, including tracer-error paths. It is not
            // the survival guarantee for traced guests
            // (removing it, or skipping it on the error path,
            // is survival-equivalent): the per-tick verified
            // sweeps above are primary, the tracer reaps its
            // tree before wait() completes, and
            // PTRACE_O_EXITKILL kills any still-traced
            // remainder when this launcher exits.
            // CLONE_UNTRACED children are neither registered
            // nor traced and escape this sweep too.
            kill_registered_guests(root_pid);
        }
        status
    })?;
    #[cfg(feature = "run")]
    {
        use std::os::unix::process::ExitStatusExt;
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8)
    }
}

/// E2-3c NB1/S3-5 route refusal: selecting the mapped
/// successor route without a configured birth authority refuses
/// by name before any server or guest starts. Until the slice-4
/// host harness stands up the BirthBridge/RpcServer pair, no
/// literoot launch configures one, so every mapped selection
/// refuses here instead of falling through to another backend.
fn refuse_mapped_without_authority(backend: &str, authority_configured: bool) -> Result<(), String> {
    if backend == "mapped" && !authority_configured {
        return Err(
            "literoot: mapped successor route requires a configured birth authority \
             (E2-3c host harness not stood up in this build)"
                .into(),
        );
    }
    Ok(())
}

/// The only tracer-wait error classes kill-on-exit may ever
/// convert back into the root guest's recorded status.
#[cfg(feature = "run")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KillWaitErrorClass {
    /// The typed primary error is the ECANCELED cause passed
    /// to PtraceTerminationHandle::terminate.
    OwnTermination,
    /// Our external SIGKILL raced a queued fork/vfork/clone
    /// stop, which the tracer reports as superseded by the
    /// tracee's exit stop.
    SupersededForkStop,
    /// Our external SIGKILL removed the initial tracee before
    /// a resume completed ("wait after initial tracee resume"
    /// with ENOENT).
    InitialResumeEnoent,
    /// The primary error is ESRCH. Always refused by name:
    /// Reverie can hit ESRCH while the root is still alive
    /// and its cleanup then SIGKILLs the root, so accepting
    /// it would relabel a tracer failure as a guest status.
    TypedEsrch,
    /// Anything else: never relabelled as a guest status.
    Other,
}

#[cfg(feature = "run")]
impl KillWaitErrorClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::OwnTermination => "own ECANCELED termination",
            Self::SupersededForkStop => "superseded fork stop after kill-on-exit SIGKILL",
            Self::InitialResumeEnoent => {
                "initial tracee resume ENOENT after kill-on-exit SIGKILL"
            }
            Self::TypedEsrch => "typed ESRCH tracer failure (refused)",
            Self::Other => "other tracer error",
        }
    }
}

#[cfg(feature = "run")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KillWaitDecision {
    AcceptRootStatus,
    RefuseRootStatusAbsent,
    RefuseSigkillSnapshot,
    RefuseUnacceptedError,
}

/// No external SIGKILL (and no termination backstop) may
/// fire until the Tool has recorded the root's raw status:
/// killing from the /proc root-gone probe alone races
/// on_exit_process and can turn the root's clean exit into
/// a tracer error with no status to return.
#[cfg(feature = "run")]
fn kill_sweep_allowed(root_gone: bool, root_status_recorded: bool) -> bool {
    root_gone && root_status_recorded
}

/// True if a raw wait status is death by SIGKILL. Our
/// sweep never signals the root (kill_registered_guests
/// skips it), so a SIGKILL snapshot can only be a status
/// Reverie's own cleanup imposed; it must never be
/// returned as the guest's exit status.
#[cfg(feature = "run")]
fn root_snapshot_is_sigkill(raw: i32) -> bool {
    reverie::ExitStatus::from_raw(raw).signal() == Some(libc::SIGKILL)
}

/// Pure acceptance rule for a tracer error after the root
/// exited. A recorded termination request is not enough by
/// itself: `class` must prove the returned error's typed
/// primary cause is our ECANCELED termination (Reverie's
/// terminate() returns true even when another failure is
/// already primary). Superseded/resume classes require an
/// actual verified SIGKILL. Typed ESRCH is always refused:
/// it can arrive while the root is alive, before Reverie's
/// cleanup SIGKILLs it. Every accepted class additionally
/// requires the root-status snapshot taken when our first
/// sweep/terminate fired, and a SIGKILL snapshot is
/// refused outright.
#[cfg(feature = "run")]
fn kill_wait_decision(
    class: KillWaitErrorClass,
    termination_requested: bool,
    sent_kill: bool,
    sweep_root_raw: Option<i32>,
) -> KillWaitDecision {
    let class_accepted = match class {
        KillWaitErrorClass::OwnTermination => termination_requested,
        KillWaitErrorClass::SupersededForkStop | KillWaitErrorClass::InitialResumeEnoent => {
            sent_kill
        }
        KillWaitErrorClass::TypedEsrch | KillWaitErrorClass::Other => false,
    };
    if !class_accepted {
        KillWaitDecision::RefuseUnacceptedError
    } else {
        match sweep_root_raw {
            None => KillWaitDecision::RefuseRootStatusAbsent,
            Some(raw) if root_snapshot_is_sigkill(raw) => {
                KillWaitDecision::RefuseSigkillSnapshot
            }
            Some(_) => KillWaitDecision::AcceptRootStatus,
        }
    }
}

/// The typed primary cause inside Reverie's legacy wait
/// error. Legacy waits wrap the complete failure in an
/// anyhow Tool error (LegacyFailureProjection for a
/// completed run, CleanupUnconfirmed for a quarantined
/// cleanup owner); recover its primary instead of trusting
/// the outer display text, which embeds secondaries.
#[cfg(feature = "run")]
fn primary_reverie_error(error: &reverie::Error) -> &reverie::Error {
    if let reverie::Error::Tool(tool_error) = error {
        if let Some(projection) =
            tool_error.downcast_ref::<reverie_ptrace::LegacyFailureProjection>()
        {
            return projection.failure().primary();
        }
        if let Some(cleanup) =
            tool_error.downcast_ref::<reverie_ptrace::CleanupUnconfirmed>()
        {
            return cleanup.primary();
        }
    }
    error
}

/// Display text of the primary error only. A unique Tool
/// primary with cleanup secondaries carries a
/// LegacyCleanupDiagnostics context whose Display embeds
/// the secondaries; the next anyhow chain item is the
/// primary itself.
#[cfg(feature = "run")]
fn primary_error_text(error: &reverie::Error) -> String {
    let primary = primary_reverie_error(error);
    if let reverie::Error::Tool(tool_error) = primary {
        if tool_error
            .downcast_ref::<reverie_ptrace::LegacyCleanupDiagnostics>()
            .is_some()
        {
            if let Some(source) = tool_error.chain().nth(1) {
                return source.to_string();
            }
        }
    }
    primary.to_string()
}

/// Classify from the primary error only: its typed errno
/// (when the primary is a bare errno) and its own display
/// text. Secondary/cleanup text never reaches this
/// function, so a superseded/ENOENT mention in a secondary
/// cannot be accepted.
#[cfg(feature = "run")]
fn classify_primary_error(
    typed_errno: Option<reverie::syscalls::Errno>,
    primary_text: &str,
) -> KillWaitErrorClass {
    match typed_errno {
        Some(reverie::syscalls::Errno::ECANCELED) => {
            return KillWaitErrorClass::OwnTermination;
        }
        Some(reverie::syscalls::Errno::ESRCH) => {
            return KillWaitErrorClass::TypedEsrch;
        }
        _ => {}
    }
    if primary_text.contains("is a fork, vfork or clone stop superseded by the exit stop") {
        KillWaitErrorClass::SupersededForkStop
    } else if primary_text.contains("wait after initial tracee resume")
        && primary_text.contains(": -2 ENOENT")
    {
        KillWaitErrorClass::InitialResumeEnoent
    } else if primary_text.contains("-3 ESRCH") {
        KillWaitErrorClass::TypedEsrch
    } else {
        KillWaitErrorClass::Other
    }
}

#[cfg(feature = "run")]
fn classify_kill_wait_error(error: &reverie::Error) -> KillWaitErrorClass {
    let typed_errno = match primary_reverie_error(error) {
        reverie::Error::Errno(errno) => Some(*errno),
        _ => None,
    };
    classify_primary_error(typed_errno, &primary_error_text(error))
}

/// Locate `libliteroot_preload.so`: `$LITEROOT_PRELOAD`, else beside
/// the running binary, else the slot build output.
#[cfg(any(feature = "in-guest", feature = "inguest-trap"))]
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

/// The first PATH candidate that is a regular file, as its guest path.
/// A candidate that is missing, not a file, or fails with one of the
/// command-path errors (`path_error_is_not_runnable`) is skipped; any other
/// error ends the search with that error, so it is never taken for "not
/// found".
fn find_guest_in_path(
    config: &RootConfig,
    cwd_guest: &Path,
    prog: &str,
) -> std::io::Result<Option<String>> {
    // Guest PATH from the environment (proot semantics: empty
    // PATH finds nothing; unset uses the execvp default).
    // Unset PATH: proot performs no search (test-path-search).
    let Ok(path_env) = std::env::var("PATH") else {
        return Ok(None);
    };
    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }
        let guest = Path::new(dir).join(prog);
        let cand = config.translate(&guest, cwd_guest, None);
        match std::fs::metadata(&cand) {
            Ok(md) if md.is_file() => return Ok(Some(guest.to_string_lossy().into_owned())),
            Ok(_) => {}
            Err(e) if path_error_is_not_runnable(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Minimal shebang parse for the launcher (mirrors the Tool's).
fn parse_shebang_pub(image: &[u8]) -> Option<(String, Option<String>)> {
    if !image.starts_with(b"#!") {
        return None;
    }
    // Kernel reads at most BINPRM_BUF_SIZE (256) bytes for the
    // shebang line; longer lines truncate mid-token.
    let image = &image[..image.len().min(256)];
    let line_end = image
        .iter()
        .position(|&c| c == b'\n')
        .unwrap_or(image.len());
    let line = std::str::from_utf8(&image[2..line_end]).ok()?.trim();
    let mut parts = line.splitn(2, |c: char| c.is_whitespace());
    let interp = parts.next()?.trim().to_string();
    if interp.is_empty() {
        return None;
    }
    // The kernel passes the remainder as ONE argument.
    let opt = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Some((interp, opt))
}

#[cfg(test)]
mod explicit_linker_tests {
    use super::{interp_names_program, linker_target_arg, read_elf_interp_bounded, InterpRead};
    use std::path::PathBuf;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // Independent copies of the pinned grammar: deleting an entry
    // from the classifier's own lists must fail these tests.
    const VALUE_OPTIONS: &[&str] = &[
        "--argv0",
        "--audit",
        "--glibc-hwcaps-mask",
        "--glibc-hwcaps-prepend",
        "--inhibit-rpath",
        "--library-path",
        "--preload",
    ];
    const FLAG_OPTIONS: &[&str] = &[
        "--help",
        "--inhibit-cache",
        "--list",
        "--list-diagnostics",
        "--list-tunables",
        "--verify",
        "--version",
    ];

    #[test]
    fn grammar_value_options_consume_one_argument() {
        for opt in VALUE_OPTIONS {
            assert_eq!(
                linker_target_arg(&args(&[opt, "value", "/tmp/target"])),
                Some("/tmp/target"),
                "{opt} must consume its value"
            );
            assert_eq!(
                linker_target_arg(&args(&[opt])),
                None,
                "{opt} with no value names no target"
            );
        }
    }

    #[test]
    fn grammar_flag_options_take_no_argument() {
        for flag in FLAG_OPTIONS {
            assert_eq!(
                linker_target_arg(&args(&[flag, "/tmp/target"])),
                Some("/tmp/target"),
                "{flag} must not consume the target"
            );
        }
    }

    #[test]
    fn grammar_rejections() {
        assert_eq!(linker_target_arg(&args(&["--unknown", "/tmp/t"])), None);
        assert_eq!(linker_target_arg(&args(&["--"])), None);
        assert_eq!(linker_target_arg(&args(&["--preload=/lib/x.so"])), None);
        assert_eq!(linker_target_arg(&args(&[])), None);
        // Slashless: glibc searches its library paths, never the cwd.
        assert_eq!(linker_target_arg(&args(&["target"])), None);
        assert_eq!(linker_target_arg(&args(&["./target"])), Some("./target"));
        assert_eq!(linker_target_arg(&args(&["/abs/target"])), Some("/abs/target"));
    }

    fn synthetic_elf(interp: &str) -> Vec<u8> {
        synthetic_elf_phnum(interp, 1)
    }

    fn synthetic_elf_phnum(interp: &str, phnum: u16) -> Vec<u8> {
        let phoff = 64usize;
        let table_len = phnum as usize * 56;
        let interp_off = phoff + table_len;
        let mut img = vec![0u8; interp_off + interp.len() + 1];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2; // ELF64
        img[5] = 1; // little-endian
        img[32..40].copy_from_slice(&(phoff as u64).to_le_bytes()); // e_phoff
        img[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        img[56..58].copy_from_slice(&phnum.to_le_bytes()); // e_phnum
        img[64..68].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP (first entry)
        img[72..80].copy_from_slice(&(interp_off as u64).to_le_bytes()); // p_offset
        img[96..104].copy_from_slice(&((interp.len() + 1) as u64).to_le_bytes()); // p_filesz
        img[interp_off..interp_off + interp.len()].copy_from_slice(interp.as_bytes());
        img
    }

    fn synthetic_elf32(interp: &str) -> Vec<u8> {
        let phoff = 52usize;
        let interp_off = phoff + 32;
        let mut img = vec![0u8; interp_off + interp.len() + 1];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 1; // ELF32
        img[5] = 1; // little-endian
        img[28..32].copy_from_slice(&(phoff as u32).to_le_bytes()); // e_phoff
        img[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
        img[44..46].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        img[52..56].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        img[56..60].copy_from_slice(&(interp_off as u32).to_le_bytes()); // p_offset
        img[68..72].copy_from_slice(&((interp.len() + 1) as u32).to_le_bytes()); // p_filesz
        img[interp_off..interp_off + interp.len()].copy_from_slice(interp.as_bytes());
        img
    }

    fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("literoot-linker-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn bounded_reader_reads_synthetic_interp() {
        let target = temp_file("target", &synthetic_elf("/lib64/ld.so"));
        assert!(matches!(
            read_elf_interp_bounded(&target),
            InterpRead::Named(ref s) if s == "/lib64/ld.so"
        ));
        let plain = temp_file("plain", b"not an ELF image");
        assert!(matches!(read_elf_interp_bounded(&plain), InterpRead::NotElf));
    }

    #[test]
    fn bounded_reader_reads_many_headers_and_elf32() {
        let many = temp_file("many", &synthetic_elf_phnum("/lib64/ld.so", 1025));
        assert!(matches!(
            read_elf_interp_bounded(&many),
            InterpRead::Named(ref s) if s == "/lib64/ld.so"
        ));
        let elf32 = temp_file("elf32", &synthetic_elf32("/lib/ld.so"));
        assert!(matches!(
            read_elf_interp_bounded(&elf32),
            InterpRead::Named(ref s) if s == "/lib/ld.so"
        ));
    }

    #[test]
    fn bounded_reader_reads_short_elf32_header() {
        // A 60-byte ELF32 whose program header starts inside the
        // ident-sized prefix: phoff=20, one 32-byte entry,
        // PT_INTERP at offset 48 (11 bytes including the NUL).
        let interp = "/tmp/ld-cx";
        let mut img = vec![0u8; 60];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 1; // ELF32
        img[5] = 1; // little-endian
        img[28..32].copy_from_slice(&20u32.to_le_bytes()); // e_phoff
        img[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
        img[44..46].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        img[20..24].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        img[24..28].copy_from_slice(&48u32.to_le_bytes()); // p_offset
        img[36..40].copy_from_slice(&11u32.to_le_bytes()); // p_filesz
        img[48..48 + interp.len()].copy_from_slice(interp.as_bytes());
        let target = temp_file("short32", &img);
        assert!(matches!(
            read_elf_interp_bounded(&target),
            InterpRead::Named(ref s) if s == interp
        ));
    }

    #[test]
    fn bounded_reader_no_program_headers_is_not_elf() {
        // A full header with e_phnum == 0 (a relocatable object or
        // kernel module shape) has no PT_INTERP: NotElf, never a
        // linker classification.
        let mut img = vec![0u8; 64];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2; // ELF64
        img[5] = 1; // little-endian
        let target = temp_file("no-phdr", &img);
        assert!(matches!(read_elf_interp_bounded(&target), InterpRead::NotElf));
    }

    #[test]
    fn bounded_reader_rejects_non_regular_files() {
        assert!(matches!(
            read_elf_interp_bounded(std::path::Path::new("/dev/null")),
            InterpRead::NotElf
        ));
        assert!(matches!(
            read_elf_interp_bounded(std::path::Path::new("/dev/zero")),
            InterpRead::NotElf
        ));
        assert!(matches!(
            read_elf_interp_bounded(std::path::Path::new("/")),
            InterpRead::NotElf
        ));
        // A FIFO is rejected by metadata/descriptor, never opened
        // in a blocking way. Call the reader on a thread with a
        // deadline so a blocking regression fails this test
        // instead of stalling the suite.
        let fifo = temp_file("fifo-target", b"");
        let _ = std::fs::remove_file(&fifo);
        let mkfifo = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .output()
            .unwrap();
        assert!(mkfifo.status.success());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_elf_interp_bounded(&fifo));
        });
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("bounded reader blocked on a FIFO target");
        assert!(matches!(outcome, InterpRead::NotElf));
    }

    #[test]
    fn interp_equality_string_canonical_and_other() {
        let prog = temp_file("real-ld", b"linker");
        // String equality needs no file at the program path.
        assert!(interp_names_program(
            "/nonexistent/ld.so",
            std::path::Path::new("/nonexistent/ld.so")
        ));
        // Canonical equality through a symlink alias.
        let alias = prog.with_file_name("alias-ld");
        let _ = std::fs::remove_file(&alias);
        std::os::unix::fs::symlink(&prog, &alias).unwrap();
        assert!(interp_names_program(alias.to_str().unwrap(), &prog));
        // A different linker does not name the program.
        assert!(!interp_names_program("/other/ld.so", &prog));
    }
}

#[cfg(test)]
mod not_runnable_tests {
    use super::path_error_is_not_runnable;

    #[test]
    fn only_command_path_errors_are_exempt_from_a_key() {
        let e = std::io::Error::from_raw_os_error;
        for errno in [libc::ENOENT, libc::ENOTDIR, libc::EACCES, libc::ELOOP, libc::ENAMETOOLONG] {
            assert!(path_error_is_not_runnable(&e(errno)), "{errno}");
        }
        for errno in [libc::EIO, libc::ENOMEM, libc::EOVERFLOW, libc::EPERM] {
            assert!(!path_error_is_not_runnable(&e(errno)), "{errno}");
        }
        assert!(!path_error_is_not_runnable(&std::io::Error::other("x")));
    }
}

#[cfg(test)]
mod mapped_route_tests {
    use super::*;

    #[test]
    fn mapped_route_without_authority_refuses_by_name() {
        let error = refuse_mapped_without_authority("mapped", false).unwrap_err();
        assert!(
            error.contains("mapped successor route requires a configured birth authority"),
            "unexpected refusal: {error}"
        );
        assert!(refuse_mapped_without_authority("mapped", true).is_ok());
        assert!(refuse_mapped_without_authority("ptrace", false).is_ok());
        assert!(refuse_mapped_without_authority("trap", false).is_ok());
    }
}

/// True once `pid` has exited (zombie or fully reaped), read
/// from /proc without racing the tracer's own wait.
#[cfg(any(feature = "run", feature = "in-guest", feature = "inguest-trap"))]
fn proc_exited(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let zombie = stat
                .rsplit_once(')')
                .map(|(_, rest)| rest.trim_start().starts_with('Z'))
                .unwrap_or(false);
            // A group leader that called pthread_exit is a
            // zombie while sibling threads still run; that is
            // not process exit. The leader's own zombie task
            // entry does not count as live.
            zombie
                && !std::fs::read_dir(format!("/proc/{pid}/task"))
                    .map(|tasks| {
                        tasks.flatten().any(|task| {
                            std::fs::read_to_string(task.path().join("stat"))
                                .map(|s| {
                                    !s.rsplit_once(')')
                                        .map(|(_, rest)| {
                                            let st = rest.trim_start();
                                            st.starts_with('Z') || st.starts_with('X')
                                        })
                                        .unwrap_or(true)
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
        }
        Err(_) => true,
    }
}






/// Pidfd-kill only if `pid` still names the process with
/// start time `expected`: rechecked immediately before
/// pidfd_open and again after it (once the fd is open the
/// identity is pinned, so a pid reused in between fails the
/// second check instead of being signalled).
fn pidfd_kill_verified(pid: i32, expected_starttime: u64) -> bool {
    if expected_starttime == 0
        || crate::rootfs_tool::proc_starttime(pid) != Some(expected_starttime)
    {
        return false;
    }
    const SYS_PIDFD_OPEN: i64 = 434;
    const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
    // SAFETY: plain syscall wrappers; the fd is closed on every path.
    unsafe {
        let fd = libc::syscall(SYS_PIDFD_OPEN, pid, 0i32) as libc::c_int;
        if fd < 0 {
            return false;
        }
        let same = crate::rootfs_tool::proc_starttime(pid) == Some(expected_starttime);
        let sent = same
            && libc::syscall(SYS_PIDFD_SEND_SIGNAL, fd, libc::SIGKILL, 0usize, 0i32) == 0;
        libc::close(fd);
        sent
    }
}

/// SIGKILL every registered guest pid whose start time was
/// actually verified at registration; unverified entries
/// (starttime unread) are never signalled. Killed and
/// proven-dead entries are forgotten. No ptrace-stop state
/// is skipped: busy tracees live in syscall stops, and the
/// named superseded-fork-stop outcome of killing one is
/// handled by the wait-error acceptance rule above.
#[cfg(feature = "run")]
fn kill_registered_guests(root_pid: i32) -> bool {
    let mut sent_kill = false;
    for (pid, starttime) in crate::rootfs_tool::guest_pid_snapshot() {
        if pid == root_pid {
            crate::rootfs_tool::forget_guest_pid(pid);
            continue;
        }
        if starttime == 0 || crate::rootfs_tool::proc_starttime(pid) != Some(starttime) {
            crate::rootfs_tool::forget_guest_pid(pid);
            continue;
        }
        if pidfd_kill_verified(pid, starttime) {
            sent_kill = true;
            crate::rootfs_tool::forget_guest_pid(pid);
        }
    }
    sent_kill
}

/// Drop registry entries whose process is already gone (or
/// whose start time no longer matches).
#[cfg(feature = "run")]
fn prune_registered_guests() {
    for (pid, starttime) in crate::rootfs_tool::guest_pid_snapshot() {
        if starttime != 0 && crate::rootfs_tool::proc_starttime(pid) != Some(starttime) {
            crate::rootfs_tool::forget_guest_pid(pid);
        }
    }
}

#[cfg(all(test, feature = "run"))]
mod kill_wait_acceptance_tests {
    use super::*;

    #[test]
    fn sweep_waits_for_recorded_root_status() {
        assert!(kill_sweep_allowed(true, true));
        assert!(!kill_sweep_allowed(true, false));
        assert!(!kill_sweep_allowed(false, true));
        assert!(!kill_sweep_allowed(false, false));
    }

    #[test]
    fn own_ecanceled_termination_is_the_only_termination_acceptance() {
        let own = reverie::Error::Errno(reverie::syscalls::Errno::ECANCELED);
        assert_eq!(
            classify_kill_wait_error(&own),
            KillWaitErrorClass::OwnTermination
        );
        assert_eq!(
            kill_wait_decision(
                KillWaitErrorClass::OwnTermination,
                true,
                false,
                Some(7 << 8)
            ),
            KillWaitDecision::AcceptRootStatus
        );
        // ECANCELED typed primary without our recorded request
        // is not ours to relabel.
        assert_eq!(
            kill_wait_decision(
                KillWaitErrorClass::OwnTermination,
                false,
                true,
                Some(7 << 8)
            ),
            KillWaitDecision::RefuseUnacceptedError
        );
        // A recorded request must not launder some other real
        // tracer failure (terminate() can return true while
        // another failure is primary).
        assert_eq!(
            kill_wait_decision(KillWaitErrorClass::Other, true, true, Some(7 << 8)),
            KillWaitDecision::RefuseUnacceptedError
        );
    }

    #[test]
    fn kill_induced_classes_require_sent_kill_and_root_status() {
        for class in [
            KillWaitErrorClass::SupersededForkStop,
            KillWaitErrorClass::InitialResumeEnoent,
        ] {
            assert_eq!(
                kill_wait_decision(class, false, true, Some(7 << 8)),
                KillWaitDecision::AcceptRootStatus,
                "{class:?} after our verified kill"
            );
            assert_eq!(
                kill_wait_decision(class, false, false, Some(7 << 8)),
                KillWaitDecision::RefuseUnacceptedError,
                "{class:?} without our kill"
            );
            assert_eq!(
                kill_wait_decision(class, false, true, None),
                KillWaitDecision::RefuseRootStatusAbsent,
                "{class:?} without a recorded root status"
            );
        }

        // Typed ESRCH is always refused, even after our kill
        // with a snapshot: Reverie can hit it while the root
        // is alive and its cleanup then SIGKILLs the root,
        // so accepting it would relabel a tracer failure
        // as the guest's exit status.
        let esrch = reverie::Error::Errno(reverie::syscalls::Errno::ESRCH);
        assert_eq!(
            classify_kill_wait_error(&esrch),
            KillWaitErrorClass::TypedEsrch
        );
        for (termination_requested, sent_kill, snapshot) in [
            (false, false, None),
            (false, false, Some(7 << 8)),
            (false, true, Some(7 << 8)),
            (true, true, Some(7 << 8)),
        ] {
            assert_eq!(
                kill_wait_decision(
                    KillWaitErrorClass::TypedEsrch,
                    termination_requested,
                    sent_kill,
                    snapshot
                ),
                KillWaitDecision::RefuseUnacceptedError,
                "ESRCH must never be accepted"
            );
        }
        assert_eq!(
            kill_wait_decision(
                KillWaitErrorClass::OwnTermination,
                true,
                false,
                None
            ),
            KillWaitDecision::RefuseRootStatusAbsent
        );
    }

    #[test]
    fn sigkill_snapshot_is_refused() {
        // Raw wait statuses: 9 = SIGKILL, 137 = SIGKILL with
        // coredump bit. Our sweep never signals the root, so
        // either snapshot can only be a status Reverie's
        // cleanup imposed; never return it as the guest exit.
        for raw in [9, 137] {
            assert!(root_snapshot_is_sigkill(raw), "raw {raw}");
            assert_eq!(
                kill_wait_decision(
                    KillWaitErrorClass::SupersededForkStop,
                    false,
                    true,
                    Some(raw)
                ),
                KillWaitDecision::RefuseSigkillSnapshot,
                "raw {raw}"
            );
            assert_eq!(
                kill_wait_decision(
                    KillWaitErrorClass::OwnTermination,
                    true,
                    false,
                    Some(raw)
                ),
                KillWaitDecision::RefuseSigkillSnapshot,
                "raw {raw}"
            );
        }
        assert!(!root_snapshot_is_sigkill(7 << 8));
    }

    #[test]
    fn classifier_matches_primary_text_exactly() {
        // Exact accepted primaries.
        assert_eq!(
            classify_primary_error(
                None,
                "queued wait status 0x1057f is a fork, vfork or clone stop \
                 superseded by the exit stop; its child PID is no longer readable"
            ),
            KillWaitErrorClass::SupersededForkStop
        );
        assert_eq!(
            classify_primary_error(
                None,
                "wait after initial tracee resume failed for tracee 7: \
                 -2 ENOENT (No such file or directory)"
            ),
            KillWaitErrorClass::InitialResumeEnoent
        );
        // "-2" must not widen to -20..-29, and a bare
        // ENOENT token without the exact ": -2 ENOENT"
        // shape must not classify as the resume case.
        for text in [
            "wait after initial tracee resume failed for tracee 7: \
             -22 EINVAL (Invalid argument)",
            "wait after initial tracee resume failed for tracee 7: \
             -28 ENOSPC (No space left on device)",
            "wait after initial tracee resume failed for tracee 7: \
             ENOENT (No such file or directory)",
        ] {
            assert_eq!(
                classify_primary_error(None, text),
                KillWaitErrorClass::Other,
                "{text:?} must not classify as ENOENT"
            );
        }
        // Primary-only input contract: classify_primary_error
        // receives only the resolved primary's text (see
        // primary_reverie_error/primary_error_text, which
        // unwrap LegacyFailureProjection, CleanupUnconfirmed
        // and LegacyCleanupDiagnostics). NAMED GAP: this
        // block does not exercise that wrapper stripping —
        // Reverie's wrapper types have no public constructors
        // (fields are crate-private), so literoot tests
        // cannot build a wrapped error whose secondary
        // mentions superseded/ENOENT, and a full-text
        // classification mutant survives these tests. The
        // strings below pin only that a primary with no
        // trigger text is refused. Tracking issue for a
        // Reverie test constructor:
        // https://github.com/rrnewton/dev-hermit-beads/blob/main/issues/dh-d1lza.md
        for primary_only in [
            "cleanup deadline exceeded",
            "-1 EPERM (Operation not permitted)",
            "ordinary ptrace run already failed",
        ] {
            assert_eq!(
                classify_primary_error(None, primary_only),
                KillWaitErrorClass::Other,
                "primary {primary_only:?} must be refused regardless of secondaries"
            );
        }
    }
}










