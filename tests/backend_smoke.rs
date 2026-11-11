//! Backend smoke gate (coord7 2026-11-07 gate-gap ruling after the
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

/// One dynamic `/bin/true` under `--backend liteinst` must exit 0.
/// Skips (passes) only when the preload DSO was not built next to
/// the manifest, matching probe_coherence's convention.
#[test]
fn liteinst_true_guest_exits_zero() {
    let preload = preload_path();
    if !preload.exists() {
        if std::env::var("LITEROOT_ALLOW_SKIP_PRELOAD").as_deref() == Ok("1") {
            eprintln!("backend_smoke: preload not built — skipping (opt-in)");
            return;
        }
        panic!(
            "backend_smoke: preload not built at {} — build the preload \
             (cargo build -p literoot-preload --release) or set \
             LITEROOT_ALLOW_SKIP_PRELOAD=1 to skip explicitly",
            preload.display()
        );
    }
    let dir = std::env::temp_dir().join(format!("literoot-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["bin", "lib64"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::copy("/bin/true", dir.join("bin/true")).unwrap();
    for lib in ["libc.so.6", "ld-linux-x86-64.so.2"] {
        std::fs::copy(format!("/lib64/{lib}"), dir.join("lib64").join(lib)).unwrap();
    }
    let out = Command::new(literoot_bin())
        .args(["--backend", "liteinst", "-r"])
        .arg(&dir)
        .arg("/bin/true")
        .env("LITEROOT_PRELOAD", &preload)
        .output()
        .expect("spawn literoot liteinst /bin/true");
    assert!(
        out.status.success(),
        "liteinst /bin/true failed: status={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
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
    if (!getenv("BRK_ALLOW_ZERO_DELTA") && brk2 - brk1 != 1024 * 1024)
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
    let source = dir.join("brk_after_exec.c");
    let guest = dir.join("brk_after_exec");
    std::fs::write(&source, BRK_AFTER_EXEC_C).unwrap();
    let cc = Command::new("cc")
        .args(["-std=gnu11", "-O2", "-fno-pie", "-no-pie", "-pthread", "-o"])
        .arg(&guest)
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
#[cfg(target_arch = "aarch64")]
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
/// runs (dh-exsg3): the launcher must fail, the guest must
/// produce no output, and the refusal must name the shape. The
/// pthread-stack protection that motivated the no-cap rule is
/// preserved by never starting glibc in the broken layout.
#[cfg(all(target_arch = "aarch64", feature = "inguest-trap"))]
#[test]
fn trap_initial_script_preserves_pthread_stack() {
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
        !out.status.success()
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
