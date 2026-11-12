//! Backend smoke gate (2026-11-07 gate-gap ruling after the
//! ec3c0164 merge shipped `--backend liteinst` unable to install):
//! every backend literoot claims must at least start a trivial
//! dynamic guest. The liteinst flavour is the discriminating one:
//! without reverie-liteinst's `liteinst` Cargo feature the preload
//! refuses at install ("built without LiteInst") and every guest
//! aborts before main, which no other gate caught.

use std::path::PathBuf;
use std::process::Command;

fn literoot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_literoot"))
}

// Resolution follows tool.rs's convention: $LITEROOT_PRELOAD wins,
// then $CARGO_TARGET_DIR/release, then the preload-local target.
fn preload_path() -> PathBuf {
    if let Ok(p) = std::env::var("LITEROOT_PRELOAD") {
        return PathBuf::from(p);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        let td = PathBuf::from(td);
        let td = if td.is_absolute() { td } else { root.join(td) };
        let cand = td.join("release/libliteroot_preload.so");
        if cand.exists() {
            return cand;
        }
    }
    root.join("preload/target/release/libliteroot_preload.so")
}

/// Cheap static tripwire: both manifests must request
/// reverie-liteinst's `liteinst` feature, or site patching is
/// compiled out and the liteinst backend is dead on arrival.
#[test]
fn manifests_request_liteinst_feature() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in ["Cargo.toml", "preload/Cargo.toml"] {
        let text =
            std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let ok = text.lines().any(|l| {
            l.contains("reverie-liteinst") && l.contains("features") && l.contains("\"liteinst\"")
        });
        assert!(
            ok,
            "{rel}: reverie-liteinst dep must carry features=[\"liteinst\"] \
             (R1 gates site patching on it; without it every \
             --backend liteinst guest aborts at preload install)"
        );
    }
}

/// The built preload, or `None` after printing the conventional
/// skip message (only when the caller opted in to skipping).
fn preload_or_skip() -> Option<PathBuf> {
    let preload = preload_path();
    if preload.exists() {
        return Some(preload);
    }
    if std::env::var("LITEROOT_ALLOW_SKIP_PRELOAD").as_deref() == Ok("1") {
        eprintln!("backend_smoke: preload not built — skipping (opt-in)");
        return None;
    }
    panic!(
        "backend_smoke: preload not built at {} — build the preload \
         (cargo build -p literoot-preload --release) or set \
         LITEROOT_ALLOW_SKIP_PRELOAD=1 to skip explicitly",
        preload.display()
    );
}

/// `(PT_INTERP, DT_NEEDED)` of an ELF image, read from its own
/// program headers and dynamic section — no library-name list is
/// hard-coded per architecture.
fn elf_interp_and_needed(image: &[u8]) -> (Option<String>, Vec<String>) {
    fn rd16(b: &[u8], little: bool) -> u16 {
        let v: [u8; 2] = b[..2].try_into().unwrap();
        if little {
            u16::from_le_bytes(v)
        } else {
            u16::from_be_bytes(v)
        }
    }
    fn rd32(b: &[u8], little: bool) -> u32 {
        let v: [u8; 4] = b[..4].try_into().unwrap();
        if little {
            u32::from_le_bytes(v)
        } else {
            u32::from_be_bytes(v)
        }
    }
    fn rd64(b: &[u8], little: bool) -> u64 {
        let v: [u8; 8] = b[..8].try_into().unwrap();
        if little {
            u64::from_le_bytes(v)
        } else {
            u64::from_be_bytes(v)
        }
    }
    assert!(&image[0..4] == b"\x7fELF", "guest is not an ELF image");
    let little = image[5] == 1;
    let is64 = image[4] == 2;
    let (phoff, phentsize, phnum): (usize, usize, usize) = if is64 {
        (
            rd64(&image[32..40], little) as usize,
            rd16(&image[54..56], little) as usize,
            rd16(&image[56..58], little) as usize,
        )
    } else {
        (
            rd32(&image[28..32], little) as usize,
            rd16(&image[42..44], little) as usize,
            rd16(&image[44..46], little) as usize,
        )
    };
    let mut interp = None;
    let mut dynamic = None;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let entry = &image[off..off + phentsize];
        let p_type = rd32(&entry[0..4], little);
        let (p_offset, p_vaddr, p_filesz): (u64, u64, u64) = if is64 {
            (
                rd64(&entry[8..16], little),
                rd64(&entry[16..24], little),
                rd64(&entry[32..40], little),
            )
        } else {
            (
                rd32(&entry[4..8], little) as u64,
                rd32(&entry[8..12], little) as u64,
                rd32(&entry[16..20], little) as u64,
            )
        };
        match p_type {
            1 => loads.push((p_vaddr, p_offset, p_filesz)),
            2 => dynamic = Some((p_offset as usize, p_filesz as usize)),
            3 => {
                let raw = &image[p_offset as usize..(p_offset + p_filesz) as usize];
                let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
                interp = Some(String::from_utf8_lossy(&raw[..end]).into_owned());
            }
            _ => {}
        }
    }
    let mut needed = Vec::new();
    if let Some((dyn_off, dyn_size)) = dynamic {
        let v2o = |vaddr: u64| -> usize {
            for (va, off, sz) in &loads {
                if vaddr >= *va && vaddr < va + sz {
                    return (off + (vaddr - va)) as usize;
                }
            }
            vaddr as usize
        };
        let ent = if is64 { 16 } else { 8 };
        let mut strtab = 0usize;
        let mut name_offsets: Vec<usize> = Vec::new();
        for i in 0..dyn_size / ent {
            let e = &image[dyn_off + i * ent..dyn_off + (i + 1) * ent];
            let (tag, val): (i64, u64) = if is64 {
                (rd64(&e[0..8], little) as i64, rd64(&e[8..16], little))
            } else {
                (
                    rd32(&e[0..4], little) as i32 as i64,
                    rd32(&e[4..8], little) as u64,
                )
            };
            match tag {
                0 => break,
                1 => name_offsets.push(val as usize),
                5 => strtab = v2o(val),
                _ => {}
            }
        }
        for noff in name_offsets {
            let raw = &image[strtab + noff..];
            let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            needed.push(String::from_utf8_lossy(&raw[..end]).into_owned());
        }
    }
    (interp, needed)
}

/// Stage a `/bin/true` rootfs from the guest binary's own
/// PT_INTERP and DT_NEEDED, located on the host.
fn stage_true_rootfs(dir: &std::path::Path) -> Vec<String> {
    for sub in ["bin", "lib64", "usr/lib64", "lib", "usr/lib"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let true_host = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("host /bin/true present");
    std::fs::copy(true_host, dir.join("bin/true")).unwrap();
    let image = std::fs::read(true_host).unwrap();
    let (interp, needed) = elf_interp_and_needed(&image);
    if let Some(interp) = &interp {
        let host_interp = std::path::Path::new(interp);
        assert!(
            host_interp.exists(),
            "guest PT_INTERP {interp} absent on host"
        );
        let dest = dir.join(interp.trim_start_matches('/'));
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(host_interp, &dest).unwrap();
    }
    const SEARCH: &[&str] = &[
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ];
    for lib in &needed {
        let host_lib = SEARCH
            .iter()
            .map(|d| std::path::Path::new(d).join(lib))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("guest DT_NEEDED {lib} not found on host"));
        // Both trusted loader directories, whichever the guest's
        // loader consults in the staged rootfs.
        std::fs::copy(&host_lib, dir.join("lib64").join(lib)).unwrap();
        std::fs::copy(&host_lib, dir.join("usr/lib64").join(lib)).unwrap();
    }
    needed
}

fn run_liteinst_true(dir: &std::path::Path, preload: &std::path::Path) -> std::process::Output {
    Command::new(literoot_bin())
        .args(["--backend", "liteinst", "-r"])
        .arg(dir)
        .arg("/bin/true")
        .env("LITEROOT_PRELOAD", preload)
        .output()
        .expect("spawn literoot liteinst /bin/true")
}

/// One dynamic `/bin/true` under `--backend liteinst` must exit 0:
/// the rootfs libraries come from the guest binary's own PT_INTERP
/// and DT_NEEDED, not a hard-coded list. x86_64 only: the in-guest
/// LiteInst runtime refuses aarch64 guests by name ("in-guest
/// LiteInst runtime is not supported on aarch64"), measured on an
/// aarch64 VM. Panics unless the preload is built, or passes
/// explicitly when LITEROOT_ALLOW_SKIP_PRELOAD=1 (opt-in skip).
#[cfg(target_arch = "x86_64")]
#[test]
fn liteinst_true_guest_exits_zero() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("literoot-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    stage_true_rootfs(&dir);
    let out = run_liteinst_true(&dir, &preload);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "liteinst /bin/true failed: status={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The negative fixture: stage the rootfs exactly as the
/// positive test does (interpreter included), prove the intact
/// guest runs, then truncate only the guest binary and require a
/// failure. The control makes the failure attributable to the
/// truncation, not to the backend, preload, or staging.
#[cfg(target_arch = "x86_64")]
#[test]
fn liteinst_true_guest_truncated_guest_fails() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("literoot-smoke-truncated-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    stage_true_rootfs(&dir);
    let intact = run_liteinst_true(&dir, &preload);
    assert!(
        intact.status.success(),
        "control: intact staged guest must run first: {intact:?}"
    );
    std::fs::write(dir.join("bin/true"), b"\x7fELF").unwrap();
    let out = run_liteinst_true(&dir, &preload);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !out.status.success(),
        "liteinst with a truncated guest binary must fail, got success: {out:?}"
    );
}

/// The staging derivation itself (requires binutils: readelf(1)
/// on the host): the guest's PT_INTERP is staged
/// at its exact guest path and every direct DT_NEEDED is staged
/// under both loader directories. (Only the guest's direct
/// DT_NEEDED entries are resolved, from a fixed list of host
/// library directories, and each found file is copied into both
/// directories regardless of its origin directory; transitive
/// dependencies and RUNPATH are not resolved.)
#[test]
fn liteinst_fixture_derives_guest_libraries() {
    let dir = std::env::temp_dir().join(format!("literoot-smoke-derive-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let needed = stage_true_rootfs(&dir);
    // Independent expected values from readelf(1), a separate
    // implementation from the byte parser under test.
    let guest_path = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("host /bin/true present");
    let readelf = Command::new("readelf")
        .args(["-l", "-d", guest_path])
        .env("LC_ALL", "C")
        .output()
        .expect("run readelf on the guest (test environment requirement)");
    assert!(readelf.status.success(), "readelf failed: {readelf:?}");
    let text = String::from_utf8_lossy(&readelf.stdout);
    let expected_interp = text
        .lines()
        .find_map(|l| l.split("Requesting program interpreter: ").nth(1))
        .map(|s| s.trim_end_matches(']').to_string())
        .expect("readelf must report a PT_INTERP for the guest");
    let mut expected_needed: Vec<String> = text
        .lines()
        .filter(|l| l.contains("(NEEDED)"))
        .filter_map(|l| l.split('[').nth(1))
        .map(|s| s.trim_end_matches(']').to_string())
        .collect();
    expected_needed.sort();
    let mut actual_needed = needed.clone();
    actual_needed.sort();
    assert_eq!(actual_needed, expected_needed);
    assert!(
        dir.join(expected_interp.trim_start_matches('/')).exists(),
        "PT_INTERP {expected_interp} must be staged at its exact guest path"
    );
    for lib in &needed {
        assert!(
            dir.join("lib64").join(lib).exists(),
            "{lib} must be staged under lib64"
        );
        assert!(
            dir.join("usr/lib64").join(lib).exists(),
            "{lib} must be staged under usr/lib64"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// On aarch64 the in-guest LiteInst runtime refuses guests by
/// name today. Pin that refusal (exit 125 with its text) so the
/// day ARM support lands, this test flips and the x86_64-only
/// positive tests can be re-scoped.
#[cfg(all(target_arch = "aarch64", feature = "run", feature = "in-guest"))]
#[test]
fn liteinst_true_guest_aarch64_named_refusal() {
    let Some(preload) = preload_or_skip() else {
        return;
    };
    let dir =
        std::env::temp_dir().join(format!("literoot-smoke-armrefusal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    stage_true_rootfs(&dir);
    let out = run_liteinst_true(&dir, &preload);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stderr.contains("in-guest LiteInst runtime is not supported on aarch64"),
        "liteinst on aarch64 must refuse by name today: {out:?}"
    );
}

#[cfg(target_arch = "aarch64")]
const BRK_AFTER_EXEC_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned char sink;

static void *thread_main(void *arg) {
    (void)arg;
    return (void *)7;
}

__attribute__((noinline)) static void dive(size_t remaining) {
    volatile unsigned char frame[65536];
    frame[0] = 1;
    frame[65535] = 2;
    if (remaining > sizeof(frame)) {
        dive(remaining - sizeof(frame));
    }
    sink = (unsigned char)(sink + frame[0] + frame[65535]);
}

int main(int argc, char *argv[]) {
    int set_8mib = getenv("BRK_SET_8MIB") != NULL;
    int fork_8mib = getenv("BRK_FORK_8MIB") != NULL;
    if (argc == 1 && (!getenv("BRK_INITIAL_ONLY") || set_8mib || fork_8mib)) {
        struct rlimit rl;
        char *const next[] = {"test", "stage2", NULL};
        if (getrlimit(RLIMIT_STACK, &rl) != 0) return 10;
        if (fork_8mib) {
            pid_t pid = fork();
            if (pid < 0) return 19;
            if (pid > 0) {
                int status = 0;
                if (waitpid(pid, &status, 0) < 0) return 20;
                return WIFEXITED(status) ? WEXITSTATUS(status) : 21;
            }
            if (getrlimit(RLIMIT_STACK, &rl) != 0) return 10;
        }
        rl.rlim_cur = (set_8mib || fork_8mib) ? 8388608 : rl.rlim_max;
        if (setrlimit(RLIMIT_STACK, &rl) != 0) return 11;
        const char *script = getenv("BRK_SCRIPT_PATH");
        if (script) {
            char *const script_argv[] = {(char *)script, NULL};
            execv(script, script_argv);
            return 12;
        }
        if (getenv("BRK_FAIL_ENV")) {
            errno = 0;
            syscall(SYS_execve, argv[0], next, (char *const *)1);
            int exec_errno = errno;
            if (getrlimit(RLIMIT_STACK, &rl) != 0) return 14;
            printf("exec_errno=%d rlim_cur=%llu rlim_max=%llu\n",
                   exec_errno, (unsigned long long)rl.rlim_cur,
                   (unsigned long long)rl.rlim_max);
            return exec_errno == EFAULT && rl.rlim_cur == rl.rlim_max &&
                           rl.rlim_max == RLIM_INFINITY
                       ? 0
                       : 16;
        }
        execv(argv[0], next);
        return 12;
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) != 0) return 14;
    long brk1 = syscall(SYS_brk, 0);
    long brk2 = syscall(SYS_brk, brk1 + 1024 * 1024);
    printf("rlim_cur=%llu rlim_max=%llu delta=%ld\n",
           (unsigned long long)rl.rlim_cur,
           (unsigned long long)rl.rlim_max, brk2 - brk1);
    {
        unsigned long long expected_cur =
            (getenv("BRK_SET_8MIB") || getenv("BRK_FORK_8MIB"))
                ? 8388608ULL
                : (unsigned long long)rl.rlim_max;
        if ((unsigned long long)rl.rlim_cur != expected_cur ||
            rl.rlim_max != RLIM_INFINITY)
            return 15;
    }
    if (brk2 - brk1 != 1024 * 1024)
        return 13;

    pthread_attr_t attr;
    size_t default_stack = 0;
    if (pthread_attr_init(&attr) != 0) return 19;
    if (pthread_attr_getstacksize(&attr, &default_stack) != 0) return 20;
    printf("default_stack=%zu\n", default_stack);
    pthread_attr_destroy(&attr);

    pthread_t thread;
    void *thread_result = NULL;
    int create_rc = pthread_create(&thread, NULL, thread_main, NULL);
    printf("pthread_create_rc=%d\n", create_rc);
    if (create_rc != 0) {
        if (getenv("BRK_EXPECT_THREAD_REFUSED") && create_rc == EOPNOTSUPP &&
            default_stack != 0) {
            printf("pthread=refused-eopnotsupp\n");
            return 0;
        }
        return 17;
    }
    if (pthread_join(thread, &thread_result) != 0 || thread_result != (void *)7)
        return 18;
    printf("pthread=ok\n");

    const char *stack_env = getenv("BRK_STACK_BYTES");
    size_t stack_bytes = stack_env ? (size_t)atoll(stack_env) : 0;
    if (stack_bytes != 0) {
        dive(stack_bytes);
        printf("stack_touched=%zu sink=%u\n", stack_bytes, sink);
    }
    return 0;
}
"#;

#[cfg(target_arch = "aarch64")]
fn compile_brk_guest(dir: &std::path::Path) -> std::path::PathBuf {
    compile_brk_guest_with_linker(dir, None)
}

#[cfg(target_arch = "aarch64")]
fn compile_brk_guest_with_linker(
    dir: &std::path::Path,
    dynamic_linker: Option<&str>,
) -> std::path::PathBuf {
    let source = dir.join("brk_after_exec.c");
    let guest = dir.join("brk_after_exec");
    std::fs::write(&source, BRK_AFTER_EXEC_C).unwrap();
    let mut cc = Command::new("cc");
    cc.args(["-std=gnu11", "-O2", "-fno-pie", "-no-pie", "-pthread", "-o"])
        .arg(&guest);
    if let Some(linker) = dynamic_linker {
        cc.arg(format!("-Wl,--dynamic-linker,{linker}"));
    }
    let cc = cc
        .arg(&source)
        .output()
        .expect("compile brk-after-exec guest");
    assert!(
        cc.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&cc.stderr)
    );
    guest
}

/// A successor image reached through the rootfs dynamic loader must
/// keep both a growable break and the guest's exact stack limit.
/// Gated on the `run` feature, which compiles the ptrace backend in.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_successor_exec_preserves_brk_growth_and_stack_limit() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-exec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);

    let work = dir.to_string_lossy().into_owned();
    let guest_arg = guest.to_string_lossy().into_owned();
    let native = Command::new(&guest)
        .env("BRK_STACK_BYTES", "134217728")
        .output()
        .expect("run native brk-after-exec guest");
    assert!(
        native.status.success(),
        "native brk-after-exec guest failed: {native:?}"
    );
    let expected = "rlim_cur=18446744073709551615 \
                    rlim_max=18446744073709551615 delta=1048576";
    let native_stdout = String::from_utf8_lossy(&native.stdout);
    assert!(
        native_stdout.contains(expected)
            && native_stdout.contains("pthread=ok")
            && native_stdout.contains("stack_touched=134217728"),
        "native brk-after-exec output: {native:?}"
    );

    let traced = Command::new(literoot_bin())
        .args(["--backend", "ptrace", "-r", "/", "-w", &work, &guest_arg])
        .env("BRK_STACK_BYTES", "134217728")
        .output()
        .expect("run literoot ptrace brk-after-exec guest");
    let traced_stdout = String::from_utf8_lossy(&traced.stdout).into_owned();
    assert!(
        traced.status.success(),
        "literoot ptrace brk-after-exec guest failed: {traced:?}"
    );
    assert!(
        traced_stdout.contains(expected)
            && traced_stdout.contains("pthread=ok")
            && traced_stdout.contains("stack_touched=134217728"),
        "literoot ptrace brk-after-exec output: {traced:?}"
    );

    let failed = Command::new(literoot_bin())
        .args(["--backend", "ptrace", "-r", "/", "-w", &work, &guest_arg])
        .env("BRK_FAIL_ENV", "1")
        .output()
        .expect("run literoot ptrace failed-exec guest");
    assert!(
        failed.status.success()
            && String::from_utf8_lossy(&failed.stdout).contains(
                "exec_errno=14 rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615",
            ),
        "literoot ptrace failed-exec restore output: {failed:?}"
    );

    let script = dir.join("brk-script");
    std::fs::write(&script, format!("#!{}\n", guest.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
    }
    let script_arg = script.to_string_lossy().into_owned();
    let script_traced = Command::new(literoot_bin())
        .args(["--backend", "ptrace", "-r", "/", "-w", &work, &guest_arg])
        .env("BRK_SCRIPT_PATH", &script_arg)
        .env("BRK_STACK_BYTES", "134217728")
        .output()
        .expect("run literoot ptrace brk-after-script guest");
    assert!(
        script_traced.status.success()
            && String::from_utf8_lossy(&script_traced.stdout).contains(expected)
            && String::from_utf8_lossy(&script_traced.stdout).contains("pthread=ok"),
        "literoot ptrace brk-after-script output: {script_traced:?}"
    );

    let literoot = literoot_bin().to_string_lossy().into_owned();
    let expected_8mib = "rlim_cur=8388608 \
                         rlim_max=18446744073709551615 delta=1048576";
    for (env_name, expected, stack_bytes) in [
        ("BRK_INITIAL_ONLY", expected, "134217728"),
        ("BRK_SET_8MIB", expected_8mib, "1048576"),
        ("BRK_FORK_8MIB", expected_8mib, "1048576"),
    ] {
        let initial = Command::new("/bin/bash")
            .args([
                "-c",
                "ulimit -s unlimited; exec \"$@\"",
                "bash",
                &literoot,
                "--backend",
                "ptrace",
                "-r",
                "/",
                "-w",
                &work,
                &guest_arg,
            ])
            .env(env_name, "1")
            .env("BRK_STACK_BYTES", stack_bytes)
            .output()
            .expect("run literoot ptrace initial-loader guest");
        assert!(
            initial.status.success()
                && String::from_utf8_lossy(&initial.stdout).contains(expected)
                && String::from_utf8_lossy(&initial.stdout)
                    .contains(&format!("stack_touched={stack_bytes}"))
                && String::from_utf8_lossy(&initial.stdout).contains("pthread=ok"),
            "literoot ptrace initial-loader output ({env_name}): {initial:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The initial script launch must not cap the in-guest process:
/// its restore cannot run until after glibc has cached the
/// default thread stack size. But an unlimited stack limit on
/// AArch64 selects the kernel's legacy layout, in which the
/// loader image's break cannot grow at all — and silently
/// launching into that layout is worse than not launching. So
/// this shape is refused by name before any guest instruction
/// runs: the launcher must fail, the guest must
/// produce no output, and the refusal must name the shape. The
/// pthread-stack protection that motivated the no-cap rule is
/// preserved by never starting glibc in the broken layout.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_initial_script_unlimited_stack_refused_by_name() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-trap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);
    let script = dir.join("brk-script");
    std::fs::write(&script, format!("#!{}\n", guest.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
    }
    let work = dir.to_string_lossy().into_owned();
    let script_arg = script.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-w",
            &work,
            &script_arg,
        ])
        .output()
        .expect("run literoot trap initial script guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stdout.is_empty()
            && stderr.contains(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution",
            ),
        "literoot trap initial script must be refused by name \
         with no guest output: {out:?}"
    );
}

/// The qualifying case: an in-guest loader-as-main launch with a
/// finite soft stack limit (8 MiB, hard unlimited) must still
/// launch, preserve its exact limit, keep a growable break, and
/// reach the named TrapHost thread refusal. A guard
/// mutant that refuses every in-guest loader-as-main launch,
/// whatever the limit, fails this test.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_initial_script_finite_stack_preserves_pthread_stack() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-finite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);
    let script = dir.join("brk-script");
    std::fs::write(&script, format!("#!{}\n", guest.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
    }
    let work = dir.to_string_lossy().into_owned();
    let script_arg = script.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -H -s unlimited; ulimit -S -s 8192; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-w",
            &work,
            &script_arg,
        ])
        .env("BRK_SET_8MIB", "1")
        .env("BRK_EXPECT_THREAD_REFUSED", "1")
        .output()
        .expect("run literoot trap finite-limit initial script guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=8388608 \
                 rlim_max=18446744073709551615 delta=1048576",
            )
            && stdout.contains("default_stack=")
            && !stdout.contains("default_stack=0\n")
            && stdout.contains("pthread_create_rc=95")
            && stdout.contains("pthread=refused-eopnotsupp")
            && stderr.contains("clone injection requires ptrace fallback"),
        "literoot trap finite-limit initial script output: {out:?}"
    );
}

/// An explicitly supplied linker (`ld.so <dynamic-program>`) is
/// loader-as-main too: the linker has no PT_INTERP, so it lands in
/// the direct-program arm, but its kernel exec is the same
/// loader-as-main exec as the script route above. Under an
/// unlimited stack limit on AArch64 it must get the same named
/// refusal with no guest output.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_explicit_linker_initial_refused_by_name() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-ldso-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);
    let ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    let work = dir.to_string_lossy().into_owned();
    let guest_arg = guest.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-w",
            &work,
            ld,
            &guest_arg,
            "stage2",
        ])
        .output()
        .expect("run literoot trap explicit linker guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stdout.is_empty()
            && stderr.contains(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution",
            ),
        "literoot trap explicit linker launch must be refused by \
         name with no guest output: {out:?}"
    );
}

/// The bind-mapping case: a bind remaps the guest view of the
/// target (`/dev/null` over the fixture path), but the backend
/// passes the target argument unchanged and admits the real host
/// file. Recognition must use that effective host view, so the
/// same named refusal applies.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_explicit_linker_bound_target_refused_by_name() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-ldso-bind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);
    let ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    let work = dir.to_string_lossy().into_owned();
    let guest_arg = guest.to_string_lossy().into_owned();
    let bind = format!("/dev/null:{guest_arg}");
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-b",
            &bind,
            "-w",
            &work,
            ld,
            &guest_arg,
            "stage2",
        ])
        .output()
        .expect("run literoot trap explicit linker bound-target guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stdout.is_empty()
            && stderr.contains(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution",
            ),
        "literoot trap explicit linker launch with a bound target \
         must be refused by name with no guest output: {out:?}"
    );
}

/// Control: an ordinary dynamic program executed directly is not
/// loader-as-main — it carries its own PT_INTERP and the kernel
/// loads its interpreter. Under the same unlimited stack limit it
/// must still launch with a growable break.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_direct_dynamic_initial_still_launches() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-direct-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);
    let work = dir.to_string_lossy().into_owned();
    let guest_arg = guest.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-w",
            &work,
            &guest_arg,
            "stage2",
        ])
        .env("BRK_EXPECT_THREAD_REFUSED", "1")
        .output()
        .expect("run literoot trap direct dynamic guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615 delta=1048576",
            ),
        "literoot trap direct dynamic guest must still launch \
         with a growable break: {out:?}"
    );
}

/// A script naming ld.so itself as interpreter
/// (`#!<ld.so> <dynamic-program>`) is explicit linker-as-main at
/// the shebang site and must get the same named refusal.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_shebang_linker_initial_refused_by_name() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-shebang-ld-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let guest = compile_brk_guest(&dir);
    let ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    let script = dir.join("ld-script");
    std::fs::write(&script, format!("#!{ld} {}\n", guest.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
    }
    let work = dir.to_string_lossy().into_owned();
    let script_arg = script.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-w",
            &work,
            &script_arg,
        ])
        .output()
        .expect("run literoot trap shebang linker guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stdout.is_empty()
            && stderr.contains(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution",
            ),
        "literoot trap shebang linker launch must be refused by \
         name with no guest output: {out:?}"
    );
}

/// The PT_INTERP spawn site: when the guest program's interpreter
/// exists only inside the rootfs (not on the host), literoot
/// synthesizes loader-as-main itself. That site must apply the
/// same named refusal under an unlimited stack limit.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_ptinterp_unlimited_stack_refused_by_name() {
    const GUEST_INTERP: &str = "/opt/literoot-ptinterp/ld.so";
    assert!(
        !std::path::Path::new(GUEST_INTERP).exists(),
        "guest interpreter path must be absent on the host"
    );
    let dir = std::env::temp_dir().join(format!("literoot-brk-ptinterp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rootfs = dir.join("rootfs");
    let interp_dir = rootfs.join("opt/literoot-ptinterp");
    let lib_dir = rootfs.join("lib64");
    let work_dir = rootfs.join("work");
    for sub in [interp_dir.as_path(), lib_dir.as_path(), work_dir.as_path()] {
        std::fs::create_dir_all(sub).unwrap();
    }
    let host_ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    std::fs::copy(host_ld, interp_dir.join("ld.so")).unwrap();
    let host_libc = ["/lib64/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 libc present");
    std::fs::copy(host_libc, lib_dir.join("libc.so.6")).unwrap();
    compile_brk_guest_with_linker(&work_dir, Some(GUEST_INTERP));
    let root_arg = rootfs.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            &root_arg,
            "-w",
            "/work",
            "/work/brk_after_exec",
            "stage2",
        ])
        .output()
        .expect("run literoot trap PT_INTERP guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stdout.is_empty()
            && stderr.contains(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution",
            ),
        "literoot trap PT_INTERP launch must be refused by name \
         with no guest output: {out:?}"
    );
}

/// A target with more than 1024 program headers (table still
/// within the kernel's 64 KiB bound) naming the supplied linker
/// must still be classified: no narrower reader cutoff may
/// silently exempt it.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_explicit_linker_many_headers_refused_by_name() {
    let dir = std::env::temp_dir().join(format!("literoot-brk-phnum-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    // Synthetic ELF64: 1025 program headers, PT_INTERP first.
    let phnum: usize = 1025;
    let interp_off = 64 + phnum * 56;
    let mut img = vec![0u8; interp_off + ld.len() + 1];
    img[0..4].copy_from_slice(b"\x7fELF");
    img[4] = 2;
    img[5] = 1;
    img[32..40].copy_from_slice(&64u64.to_le_bytes());
    img[54..56].copy_from_slice(&56u16.to_le_bytes());
    img[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
    img[64..68].copy_from_slice(&3u32.to_le_bytes());
    img[72..80].copy_from_slice(&(interp_off as u64).to_le_bytes());
    img[96..104].copy_from_slice(&((ld.len() + 1) as u64).to_le_bytes());
    img[interp_off..interp_off + ld.len()].copy_from_slice(ld.as_bytes());
    let target = dir.join("many-headers");
    std::fs::write(&target, &img).unwrap();
    let work = dir.to_string_lossy().into_owned();
    let target_arg = target.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "trap",
            "-r",
            "/",
            "-w",
            &work,
            ld,
            &target_arg,
            "stage2",
        ])
        .output()
        .expect("run literoot trap many-headers linker guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.code() == Some(125)
            && stdout.is_empty()
            && stderr.contains(
                "aarch64 in-guest initial loader-as-main launch with \
                 unlimited RLIMIT_STACK has no growable break; \
                 refusing before guest execution",
            ),
        "literoot trap many-headers linker launch must be refused \
         by name with no guest output: {out:?}"
    );
}

/// Under ptrace there is no backend admission step: the target
/// that loads is the guest-view file. An explicit linker whose
/// target exists only inside the rootfs must still be capped, so
/// the guest keeps a growable break and its exact (unlimited)
/// limit after restore. Gated on the `run` feature:
/// that is the configuration that compiles the ptrace backend in.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_explicit_linker_guest_view_capped() {
    const GUEST_INTERP: &str = "/opt/literoot-ptinterp/ld.so";
    let dir = std::env::temp_dir().join(format!("literoot-ptrace-ldso-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rootfs = dir.join("rootfs");
    let interp_dir = rootfs.join("opt/literoot-ptinterp");
    let lib_dir = rootfs.join("lib64");
    let work_dir = rootfs.join("work");
    for sub in [interp_dir.as_path(), lib_dir.as_path(), work_dir.as_path()] {
        std::fs::create_dir_all(sub).unwrap();
    }
    let host_ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    std::fs::copy(host_ld, interp_dir.join("ld.so")).unwrap();
    let host_libc = ["/lib64/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 libc present");
    std::fs::copy(host_libc, lib_dir.join("libc.so.6")).unwrap();
    compile_brk_guest_with_linker(&work_dir, Some(GUEST_INTERP));
    let root_arg = rootfs.to_string_lossy().into_owned();
    // A remapping bind: the target is named /bound/... in the
    // guest, bound from the rootfs work directory on the host.
    let bind = format!("{}:/bound", work_dir.display());
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "-r",
            &root_arg,
            "-b",
            &bind,
            "-w",
            "/work",
            GUEST_INTERP,
            "/bound/brk_after_exec",
            "stage2",
        ])
        .output()
        .expect("run literoot ptrace explicit linker guest-view guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615 delta=1048576",
            )
            && stdout.contains("pthread=ok"),
        "literoot ptrace explicit linker guest-view launch must \
         be capped with a growable break: {out:?}"
    );
}

/// The alias case of the ptrace guest-view test: the program is
/// invoked through a symlink alias of the loader inside the
/// rootfs, while the target's PT_INTERP names the real loader
/// path. The guest-view comparison must resolve the interpreter
/// through the rootfs so the alias still classifies and caps.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_explicit_linker_guest_alias_capped() {
    const GUEST_INTERP: &str = "/opt/literoot-ptinterp/ld.so";
    const GUEST_ALIAS: &str = "/opt/literoot-ptinterp/ld-alias.so";
    let dir = std::env::temp_dir().join(format!("literoot-ptrace-alias-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rootfs = dir.join("rootfs");
    let interp_dir = rootfs.join("opt/literoot-ptinterp");
    let lib_dir = rootfs.join("lib64");
    let work_dir = rootfs.join("work");
    for sub in [interp_dir.as_path(), lib_dir.as_path(), work_dir.as_path()] {
        std::fs::create_dir_all(sub).unwrap();
    }
    let host_ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    std::fs::copy(host_ld, interp_dir.join("ld.so")).unwrap();
    std::os::unix::fs::symlink("ld.so", interp_dir.join("ld-alias.so")).unwrap();
    let host_libc = ["/lib64/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 libc present");
    std::fs::copy(host_libc, lib_dir.join("libc.so.6")).unwrap();
    compile_brk_guest_with_linker(&work_dir, Some(GUEST_INTERP));
    let root_arg = rootfs.to_string_lossy().into_owned();
    let bind = format!("{}:/bound", work_dir.display());
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "-r",
            &root_arg,
            "-b",
            &bind,
            "-w",
            "/work",
            GUEST_ALIAS,
            "/bound/brk_after_exec",
            "stage2",
        ])
        .output()
        .expect("run literoot ptrace explicit linker alias guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615 delta=1048576",
            )
            && stdout.contains("pthread=ok"),
        "literoot ptrace explicit linker alias launch must be \
         capped with a growable break: {out:?}"
    );
}

/// The shebang-arm twin of the ptrace guest-view test: a script
/// naming the rootfs loader as its interpreter, with the dynamic
/// target named through a remapping bind, must still be capped
/// under ptrace.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_shebang_linker_guest_view_capped() {
    const GUEST_INTERP: &str = "/opt/literoot-ptinterp/ld.so";
    let dir = std::env::temp_dir().join(format!("literoot-ptrace-shebang-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rootfs = dir.join("rootfs");
    let interp_dir = rootfs.join("opt/literoot-ptinterp");
    let lib_dir = rootfs.join("lib64");
    let work_dir = rootfs.join("work");
    for sub in [interp_dir.as_path(), lib_dir.as_path(), work_dir.as_path()] {
        std::fs::create_dir_all(sub).unwrap();
    }
    let host_ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    std::fs::copy(host_ld, interp_dir.join("ld.so")).unwrap();
    let host_libc = ["/lib64/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 libc present");
    std::fs::copy(host_libc, lib_dir.join("libc.so.6")).unwrap();
    compile_brk_guest_with_linker(&work_dir, Some(GUEST_INTERP));
    let script = work_dir.join("ld-script");
    std::fs::write(&script, format!("#!{GUEST_INTERP} /bound/brk_after_exec\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
    }
    let root_arg = rootfs.to_string_lossy().into_owned();
    let bind = format!("{}:/bound", work_dir.display());
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "-r",
            &root_arg,
            "-b",
            &bind,
            "-w",
            "/work",
            "/work/ld-script",
        ])
        .output()
        .expect("run literoot ptrace shebang linker guest-view guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615 delta=1048576",
            )
            && stdout.contains("pthread=ok"),
        "literoot ptrace shebang linker guest-view launch must \
         be capped with a growable break: {out:?}"
    );
}

/// The usrmerge case of the ptrace guest-view test: the loader
/// lives under /usr/lib in the rootfs with /lib as a symlink to
/// it (usrmerge); the target's PT_INTERP uses the /lib spelling
/// while the program is invoked by its /usr/lib spelling. Both
/// sides canonicalise inside the rootfs, so it still classifies
/// and caps.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_explicit_linker_guest_usrmerge_capped() {
    let dir = std::env::temp_dir().join(format!("literoot-ptrace-usrmerge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rootfs = dir.join("rootfs");
    let ld_dir = rootfs.join("usr/lib/literoot-ld");
    let lib_dir = rootfs.join("usr/lib64");
    let work_dir = rootfs.join("work");
    for sub in [ld_dir.as_path(), lib_dir.as_path(), work_dir.as_path()] {
        std::fs::create_dir_all(sub).unwrap();
    }
    std::os::unix::fs::symlink("usr/lib", rootfs.join("lib")).unwrap();
    let host_ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    std::fs::copy(host_ld, ld_dir.join("ld.so")).unwrap();
    let host_libc = ["/lib64/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 libc present");
    std::fs::copy(host_libc, lib_dir.join("libc.so.6")).unwrap();
    std::os::unix::fs::symlink("usr/lib64", rootfs.join("lib64")).unwrap();
    compile_brk_guest_with_linker(&work_dir, Some("/lib/literoot-ld/ld.so"));
    let root_arg = rootfs.to_string_lossy().into_owned();
    let bind = format!("{}:/bound", work_dir.display());
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "-r",
            &root_arg,
            "-b",
            &bind,
            "-w",
            "/work",
            "/usr/lib/literoot-ld/ld.so",
            "/bound/brk_after_exec",
            "stage2",
        ])
        .output()
        .expect("run literoot ptrace explicit linker usrmerge guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615 delta=1048576",
            )
            && stdout.contains("pthread=ok"),
        "literoot ptrace explicit linker usrmerge launch must \
         be capped with a growable break: {out:?}"
    );
}

/// Loader-identity cap: under ptrace the cap also classifies by loader
/// identity. Here the target names a DIFFERENT loader copy than
/// the program invoked, so the exact PT_INTERP match misses; the
/// program's loader SONAME must still cap it, with the guest's
/// exact (unlimited) limit restored after spawn.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_loader_identity_different_loader_capped() {
    let dir = std::env::temp_dir().join(format!("literoot-ptrace-identity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rootfs = dir.join("rootfs");
    let ld_a = rootfs.join("opt/ld-a");
    let ld_b = rootfs.join("opt/ld-b");
    let lib_dir = rootfs.join("lib64");
    let work_dir = rootfs.join("work");
    for sub in [
        ld_a.as_path(),
        ld_b.as_path(),
        lib_dir.as_path(),
        work_dir.as_path(),
    ] {
        std::fs::create_dir_all(sub).unwrap();
    }
    let host_ld = ["/lib64/ld-linux-aarch64.so.1", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 dynamic linker present");
    std::fs::copy(host_ld, ld_a.join("ld.so")).unwrap();
    std::fs::copy(host_ld, ld_b.join("ld.so")).unwrap();
    let host_libc = ["/lib64/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("aarch64 libc present");
    std::fs::copy(host_libc, lib_dir.join("libc.so.6")).unwrap();
    compile_brk_guest_with_linker(&work_dir, Some("/opt/ld-b/ld.so"));
    let root_arg = rootfs.to_string_lossy().into_owned();
    let bind = format!("{}:/bound", work_dir.display());
    let side_log_path = dir.join("refusal.log");
    let side_log = side_log_path.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "--refusal-log",
            &side_log,
            "-r",
            &root_arg,
            "-b",
            &bind,
            "-w",
            "/work",
            "/opt/ld-a/ld.so",
            "/bound/brk_after_exec",
            "stage2",
        ])
        .output()
        .expect("run literoot ptrace loader-identity guest");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let check = Command::new(literoot_bin())
        .args(["--check-refusal-log"])
        .arg(&side_log_path)
        .output()
        .expect("validate capped side log");
    assert!(
        check.status.success() && String::from_utf8_lossy(&check.stdout).is_empty(),
        "capped side log must validate with no refusals: {check:?}"
    );
    let capped = std::fs::read_to_string(&side_log_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success()
            && stdout.contains(
                "rlim_cur=18446744073709551615 \
                 rlim_max=18446744073709551615 delta=1048576",
            )
            && stdout.contains("pthread=ok")
            && capped.contains("capped initial_stack loader_identity"),
        "literoot ptrace loader-identity launch must be capped \
         with limits restored: {out:?} side_log={capped:?}"
    );
}

/// Loader-identity negative: a non-loader ET_DYN program without
/// PT_INTERP (a static-pie guest) is not a loader and must not be
/// capped, even with a positional argument.
#[cfg(all(target_arch = "aarch64", feature = "run"))]
#[test]
fn ptrace_static_pie_not_capped() {
    let dir =
        std::env::temp_dir().join(format!("literoot-ptrace-staticpie-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("brk_after_exec.c");
    std::fs::write(&source, BRK_AFTER_EXEC_C).unwrap();
    let guest = dir.join("brk_after_exec_static");
    let cc = Command::new("cc")
        .args([
            "-std=gnu11",
            "-O2",
            "-fPIE",
            "-static-pie",
            "-pthread",
            "-o",
        ])
        .arg(&guest)
        .arg(&source)
        .output()
        .expect("compile static-pie brk guest");
    assert!(
        cc.status.success(),
        "cc static-pie failed: {}",
        String::from_utf8_lossy(&cc.stderr)
    );
    // The fixture really is ET_DYN with no PT_INTERP.
    let image = std::fs::read(&guest).unwrap();
    assert!(&image[0..4] == b"\x7fELF" && image[4] == 2);
    assert_eq!(
        u16::from_le_bytes(image[16..18].try_into().unwrap()),
        3,
        "guest must be ET_DYN"
    );
    let phoff = u64::from_le_bytes(image[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(image[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(image[56..58].try_into().unwrap()) as usize;
    let mut types: Vec<u32> = Vec::new();
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        types.push(u32::from_le_bytes(image[at..at + 4].try_into().unwrap()));
    }
    assert!(
        types.contains(&1) && !types.contains(&3),
        "guest must be loadable ET segments without PT_INTERP: {types:?}"
    );
    let work = dir.to_string_lossy().into_owned();
    let guest_arg = guest.to_string_lossy().into_owned();
    let side_log_path = dir.join("refusal.log");
    let side_log = side_log_path.to_string_lossy().into_owned();
    // Native control: same guest, same limits, no literoot. It
    // must actually reach the probe (the limit line) before any
    // comparison means anything.
    let native = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &guest_arg,
            "stage2",
        ])
        .output()
        .expect("run native static-pie control");
    assert!(
        String::from_utf8_lossy(&native.stdout).contains("rlim_cur="),
        "native control must reach the measured probe: {native:?}"
    );
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let out = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "--refusal-log",
            &side_log,
            "-r",
            "/",
            "-w",
            &work,
            &guest_arg,
            "stage2",
        ])
        .output()
        .expect("run literoot ptrace static-pie guest");
    let check = Command::new(literoot_bin())
        .args(["--check-refusal-log"])
        .arg(&side_log_path)
        .output()
        .expect("validate static-pie side log");
    assert!(
        check.status.success() && String::from_utf8_lossy(&check.stdout).is_empty(),
        "static-pie side log must validate with no refusals: {check:?}"
    );
    let logged = std::fs::read_to_string(&side_log_path)
        .expect("side log must exist for the uncapped check");
    let _ = std::fs::remove_dir_all(&dir);
    // Uncapped means indistinguishable from native: same exit
    // status, same stdout (the limit pair it prints), a valid
    // side log, and no cap record in it.
    assert!(
        out.status == native.status
            && out.stdout == native.stdout
            && logged.contains("literoot: begin")
            && !logged.contains("capped initial_stack"),
        "literoot ptrace static-pie launch must match the native \
         control uncapped: literoot={out:?} native={native:?} side_log={logged:?}"
    );
}

/// The explicit-linker classifier inspects a guest-controlled
/// argument path. A non-regular target (here a FIFO) must be
/// rejected without a blocking open: opening it would hang the
/// launcher before any guest runs. Runs under an
/// unlimited stack limit so the classifier gate is open where it
/// can be, and under a hard deadline so a blocking regression
/// fails this test instead of stalling the suite.
#[test]
fn explicit_linker_fifo_target_returns_promptly() {
    let dir = std::env::temp_dir().join(format!("literoot-fifo-target-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prog = dir.join("not-an-elf");
    std::fs::write(&prog, "not an ELF image\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&prog).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&prog, permissions).unwrap();
    }
    let fifo = dir.join("target-fifo");
    let mkfifo = Command::new("mkfifo")
        .arg(&fifo)
        .output()
        .expect("create FIFO target");
    assert!(mkfifo.status.success(), "mkfifo failed: {mkfifo:?}");
    let work = dir.to_string_lossy().into_owned();
    let prog_arg = prog.to_string_lossy().into_owned();
    let fifo_arg = fifo.to_string_lossy().into_owned();
    let literoot = literoot_bin().to_string_lossy().into_owned();
    let mut child = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -s unlimited; exec \"$@\"",
            "bash",
            &literoot,
            "--backend",
            "ptrace",
            "-r",
            "/",
            "-w",
            &work,
            &prog_arg,
            &fifo_arg,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn literoot with FIFO target argument");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let status = loop {
        match child.try_wait().expect("poll literoot child") {
            Some(status) => break status,
            None if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("literoot with a FIFO target argument hung past 15s");
            }
        }
    };
    let out = child
        .wait_with_output()
        .expect("collect literoot FIFO-target output");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !status.success() && out.stdout.is_empty(),
        "literoot with a FIFO target argument must return \
         promptly, never hang in the classifier: {out:?}"
    );
}
