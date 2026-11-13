//! Identity-only on the ptrace backend. With `-i` equal to the caller's
//! own non-root ids, literoot does what the Android launcher's patched
//! proot does: the set*id and setfs*id calls follow proot's fake_id0 rules
//! (with nothing faked, only the caller's own ids are allowed), the three
//! setxattr calls run on the translated path and report permission errors
//! as success, and everything else, chroot included, is the kernel's on
//! the translated path. Other ids, uid 0, and `--no-identity-only` keep
//! every `-i` rule.
//!
//! The probe prints ids by role (`own`, `other` = own + 1, `root`, `-1`),
//! so the same binary gives comparable output natively, under proot and
//! under literoot.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

const PROBE_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static unsigned own_u, own_g;

static const char *role(unsigned v, unsigned own) {
    if (v == (unsigned) -1) return "-1";
    if (v == own) return "own";
    if (v == own + 1) return "other";
    if (v == 0) return "root";
    return "?";
}

static const char *ename(int e) {
    switch (e) {
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case ENOTDIR: return "ENOTDIR";
    case ENODATA: return "ENODATA";
    default: { static char b[16]; snprintf(b, sizeof b, "errno%d", e); return b; }
    }
}

static void say(const char *what, long r, int e) {
    if (r < 0) printf("%s -1 %s\n", what, ename(e));
    else printf("%s %ld\n", what, r);
}

/* Role codes: 0 = -1, 1 = own, 2 = other, 3 = root. */
static unsigned val(int code, unsigned own) {
    return code == 0 ? (unsigned) -1 : code == 1 ? own : code == 2 ? own + 1 : 0;
}

struct kase { const char *call; long nr; int gid; int n; int a[3]; };
static const struct kase kases[] = {
    {"setuid", SYS_setuid, 0, 1, {1}}, {"setuid", SYS_setuid, 0, 1, {2}},
    {"setuid", SYS_setuid, 0, 1, {3}},
    {"setgid", SYS_setgid, 1, 1, {1}}, {"setgid", SYS_setgid, 1, 1, {2}},
    {"setgid", SYS_setgid, 1, 1, {3}},
    {"setreuid", SYS_setreuid, 0, 2, {0, 0}}, {"setreuid", SYS_setreuid, 0, 2, {1, 1}},
    {"setreuid", SYS_setreuid, 0, 2, {1, 0}}, {"setreuid", SYS_setreuid, 0, 2, {0, 1}},
    {"setreuid", SYS_setreuid, 0, 2, {3, 0}}, {"setreuid", SYS_setreuid, 0, 2, {0, 3}},
    {"setreuid", SYS_setreuid, 0, 2, {2, 1}},
    {"setregid", SYS_setregid, 1, 2, {0, 0}}, {"setregid", SYS_setregid, 1, 2, {1, 1}},
    {"setregid", SYS_setregid, 1, 2, {1, 0}}, {"setregid", SYS_setregid, 1, 2, {0, 1}},
    {"setregid", SYS_setregid, 1, 2, {3, 0}}, {"setregid", SYS_setregid, 1, 2, {0, 3}},
    {"setregid", SYS_setregid, 1, 2, {2, 1}},
    {"setresuid", SYS_setresuid, 0, 3, {0, 0, 0}}, {"setresuid", SYS_setresuid, 0, 3, {1, 1, 1}},
    {"setresuid", SYS_setresuid, 0, 3, {3, 0, 0}}, {"setresuid", SYS_setresuid, 0, 3, {0, 3, 0}},
    {"setresuid", SYS_setresuid, 0, 3, {0, 0, 3}}, {"setresuid", SYS_setresuid, 0, 3, {0, 0, 2}},
    {"setresgid", SYS_setresgid, 1, 3, {0, 0, 0}}, {"setresgid", SYS_setresgid, 1, 3, {1, 1, 1}},
    {"setresgid", SYS_setresgid, 1, 3, {3, 0, 0}}, {"setresgid", SYS_setresgid, 1, 3, {0, 3, 0}},
    {"setresgid", SYS_setresgid, 1, 3, {0, 0, 3}}, {"setresgid", SYS_setresgid, 1, 3, {0, 0, 2}},
};

/* Each set*id case runs in its own child, so every case starts from the
 * same ids. */
static void in_child(void (*body)(int), int i) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) { body(i); fflush(stdout); _exit(0); }
    int st;
    waitpid(p, &st, 0);
}

static void one_case(int i) {
    const struct kase *k = &kases[i];
    unsigned own = k->gid ? own_g : own_u;
    long v[3];
    char name[64];
    int at = snprintf(name, sizeof name, "%s(", k->call);
    for (int j = 0; j < k->n; j++) {
        v[j] = (long) val(k->a[j], own);
        at += snprintf(name + at, sizeof name - at, "%s%s", j ? "," : "",
                       role((unsigned) v[j], own));
    }
    snprintf(name + at, sizeof name - at, ")");
    long r = syscall(k->nr, v[0], v[1], v[2]);
    int e = errno;
    say(name, r, e);
}

/* setfs*id returns the previous id whether or not it changes it; -1 last
 * reads the id back without changing it. */
static void fs_case(int gid) {
    unsigned own = gid ? own_g : own_u;
    long nr = gid ? SYS_setfsgid : SYS_setfsuid;
    const char *call = gid ? "setfsgid" : "setfsuid";
    int codes[] = {1, 3, 2, 0};
    for (int j = 0; j < 4; j++) {
        unsigned a = val(codes[j], own);
        long r = syscall(nr, (long) a);
        printf("%s(%s) -> %s\n", call, role(a, own), role((unsigned) r, own));
    }
}

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    const char *dir = argv[1];
    own_u = (unsigned) strtoul(argv[2], 0, 10);
    own_g = (unsigned) strtoul(argv[3], 0, 10);
    char file[4096], ro[4096], link[4096], missing[4096], fifo[4096];
    snprintf(file, sizeof file, "%s/file", dir);
    snprintf(ro, sizeof ro, "%s/readonly", dir);
    snprintf(link, sizeof link, "%s/link", dir);
    snprintf(missing, sizeof missing, "%s/missing", dir);
    snprintf(fifo, sizeof fifo, "%s/fifo", dir);
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0 || write(fd, "x", 1) != 1) return 3;
    close(fd);
    fd = open(ro, O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (fd < 0) return 4;
    close(fd);
    if (symlink("file", link)) return 5;

    printf("ids %s %s %s %s\n", role(getuid(), own_u), role(geteuid(), own_u),
           role(getgid(), own_g), role(getegid(), own_g));
    /* chroot first, before any set*id call. */
    long r = syscall(SYS_chroot, "/"); int e = errno; say("chroot(/)", r, e);
    r = syscall(SYS_chroot, dir); e = errno; say("chroot(dir)", r, e);
    r = syscall(SYS_chroot, file); e = errno; say("chroot(dir/file)", r, e);

    for (int i = 0; i < (int) (sizeof kases / sizeof kases[0]); i++)
        in_child(one_case, i);
    in_child(fs_case, 0);
    in_child(fs_case, 1);

    r = chown(file, 0, 0); e = errno; say("chown(file,root)", r, e);
    r = mknod(fifo, S_IFIFO | 0644, 0); e = errno;
    struct stat st;
    printf("mknod(fifo) %ld, a fifo %d\n", r, r == 0 && stat(fifo, &st) == 0 && S_ISFIFO(st.st_mode));

    r = setxattr(file, "user.literoot", "v", 1, 0); e = errno; say("setxattr(file,user)", r, e);
    char buf[8] = {0};
    fd = open(file, O_RDONLY);
    r = fgetxattr(fd, "user.literoot", buf, sizeof buf - 1); e = errno;
    if (r < 0) say("fgetxattr(file,user)", r, e); else printf("fgetxattr(file,user) \"%s\"\n", buf);
    r = setxattr(file, "user.literoot", "w", 1, XATTR_CREATE); e = errno;
    say("setxattr(file,user,create)", r, e);
    r = setxattr(missing, "user.literoot", "v", 1, 0); e = errno; say("setxattr(missing,user)", r, e);
    r = setxattr(file, "trusted.literoot", "v", 1, 0); e = errno; say("setxattr(file,trusted)", r, e);
    r = setxattr(ro, "user.literoot", "v", 1, 0); e = errno; say("setxattr(readonly,user)", r, e);
    /* Its own name, so following the link to the file would show. */
    r = lsetxattr(link, "user.literoot.link", "v", 1, 0); e = errno; say("lsetxattr(link,user)", r, e);
    r = fgetxattr(fd, "user.literoot.link", buf, sizeof buf - 1); e = errno;
    say("fgetxattr(file,user.link)", r, e);
    r = fsetxattr(fd, "trusted.literoot", "v", 1, 0); e = errno; say("fsetxattr(file,trusted)", r, e);
    close(fd);
    return 0;
}
"#;

/// The ids-and-effects guest for the full `-i` rules: what the fake ids
/// read back as, and whether setuid(0), chown and mknod are faked.
const FULL_C: &str = r#"
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || chdir(argv[1])) return 2;
    printf("uid %d gid %d\n", (int) getuid(), (int) getgid());
    int r = setuid(0);
    int e = errno;
    printf("setuid(0) %d errno %d, then euid %d\n", r, r ? e : 0, (int) geteuid());
    errno = 0;
    r = chown("file", 0, 0);
    e = errno;
    printf("chown to 0 %d errno %d\n", r, r ? e : 0);
    r = mknod("fifo", S_IFIFO | 0644, 0);
    struct stat st;
    int fifo = r == 0 && stat("fifo", &st) == 0 && S_ISFIFO(st.st_mode);
    printf("mknod fifo %d, is a fifo %d\n", r, fifo);
    return 0;
}
"#;

/// What the probe prints natively for the caller's own non-root ids. Under
/// identity-only only the four permission-error setxattr lines differ.
const NATIVE: &str = "\
ids own own own own
chroot(/) -1 EPERM
chroot(dir) -1 EPERM
chroot(dir/file) -1 ENOTDIR
setuid(own) 0
setuid(other) -1 EPERM
setuid(root) -1 EPERM
setgid(own) 0
setgid(other) -1 EPERM
setgid(root) -1 EPERM
setreuid(-1,-1) 0
setreuid(own,own) 0
setreuid(own,-1) 0
setreuid(-1,own) 0
setreuid(root,-1) -1 EPERM
setreuid(-1,root) -1 EPERM
setreuid(other,own) -1 EPERM
setregid(-1,-1) 0
setregid(own,own) 0
setregid(own,-1) 0
setregid(-1,own) 0
setregid(root,-1) -1 EPERM
setregid(-1,root) -1 EPERM
setregid(other,own) -1 EPERM
setresuid(-1,-1,-1) 0
setresuid(own,own,own) 0
setresuid(root,-1,-1) -1 EPERM
setresuid(-1,root,-1) -1 EPERM
setresuid(-1,-1,root) -1 EPERM
setresuid(-1,-1,other) -1 EPERM
setresgid(-1,-1,-1) 0
setresgid(own,own,own) 0
setresgid(root,-1,-1) -1 EPERM
setresgid(-1,root,-1) -1 EPERM
setresgid(-1,-1,root) -1 EPERM
setresgid(-1,-1,other) -1 EPERM
setfsuid(own) -> own
setfsuid(root) -> own
setfsuid(other) -> own
setfsuid(-1) -> own
setfsgid(own) -> own
setfsgid(root) -> own
setfsgid(other) -> own
setfsgid(-1) -> own
chown(file,root) -1 EPERM
mknod(fifo) 0, a fifo 1
setxattr(file,user) 0
fgetxattr(file,user) \"v\"
setxattr(file,user,create) -1 EEXIST
setxattr(missing,user) -1 ENOENT
setxattr(file,trusted) -1 EPERM
setxattr(readonly,user) -1 EACCES
lsetxattr(link,user) -1 EPERM
fgetxattr(file,user.link) -1 ENODATA
fsetxattr(file,trusted) -1 EPERM
";

/// The real ids of this process, not a file's owner.
fn real_ids() -> (u32, u32) {
    extern "C" {
        fn getuid() -> u32;
        fn getgid() -> u32;
    }
    unsafe { (getuid(), getgid()) }
}

fn own_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-idonly-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).unwrap();
    let bin = dir.join(name);
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc is required to build the identity guests");
    assert!(cc.status.success(), "cc failed: {cc:?}");
    bin
}

fn fresh(dir: &Path, name: &str) -> PathBuf {
    let work = dir.join(name);
    std::fs::create_dir(&work).unwrap();
    work
}

fn stdout(out: std::process::Output, what: &str) -> String {
    assert!(out.status.success(), "{what}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// The probe under literoot with `ids`, its work directory bound at `/w`
/// under `-r /`, so a path left untranslated names a missing host `/w`.
fn probe(dir: &Path, guest: &Path, name: &str, ids: &str, flags: &[&str]) -> String {
    let work = fresh(dir, name);
    let (uid, gid) = real_ids();
    let mut cmd = Command::new(common::literoot_bin());
    cmd.args(flags)
        .args(["-i", ids, "-r", "/", "-b"])
        .arg(format!("{}:/w", work.display()))
        .arg(guest)
        .args(["/w", &uid.to_string(), &gid.to_string()]);
    stdout(common::run_bounded(cmd, name), name)
}

/// The full-rules guest under literoot with `args`, in a fresh directory.
fn full(dir: &Path, guest: &Path, name: &str, args: &[&str]) -> String {
    let work = fresh(dir, name);
    std::fs::write(work.join("file"), "x").unwrap();
    let mut cmd = Command::new(common::literoot_bin());
    cmd.args(args).arg(guest).arg(&work);
    stdout(common::run_bounded(cmd, name), name)
}

fn identity_expected() -> String {
    NATIVE
        .replace(
            "setxattr(file,trusted) -1 EPERM",
            "setxattr(file,trusted) 0",
        )
        .replace(
            "setxattr(readonly,user) -1 EACCES",
            "setxattr(readonly,user) 0",
        )
        .replace("lsetxattr(link,user) -1 EPERM", "lsetxattr(link,user) 0")
        .replace(
            "fsetxattr(file,trusted) -1 EPERM",
            "fsetxattr(file,trusted) 0",
        )
}

#[test]
fn own_ids_get_proots_identity_only_rules() {
    let (uid, gid) = real_ids();
    if uid == 0 || gid == 0 {
        // Not a pass: identity-only cannot apply to root, and the probe's
        // `root` role needs a non-zero own gid. The other test still runs.
        eprintln!("SKIPPED (real uid {uid}, gid {gid}): identity-only needs non-root ids");
        return;
    }
    let dir = own_dir("probe");
    let guest = build(&dir, "probe", PROBE_C);

    // The oracle: the same probe natively.
    let work = fresh(&dir, "native");
    let mut cmd = Command::new(&guest);
    cmd.arg(&work).args([uid.to_string(), gid.to_string()]);
    assert_eq!(stdout(common::run_bounded(cmd, "native"), "native"), NATIVE);

    // No flag needed: own ids switch identity-only on.
    let own = format!("{uid}:{gid}");
    let expected = identity_expected();
    assert_eq!(probe(&dir, &guest, "auto", &own, &[]), expected);
    assert_eq!(
        probe(&dir, &guest, "explicit", &own, &["--identity-only"]),
        expected
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn other_ids_root_and_the_opt_out_keep_every_i_rule() {
    let dir = own_dir("full");
    let guest = build(&dir, "full", FULL_C);
    let (uid, gid) = real_ids();
    let faked = |u: u32, g: u32| {
        format!(
            "uid {u} gid {g}\n\
             setuid(0) 0 errno 0, then euid 0\n\
             chown to 0 0 errno 0\n\
             mknod fifo 0, is a fifo 0\n"
        )
    };
    // uid 0 never gets identity-only, even as the caller's own ids.
    assert_eq!(full(&dir, &guest, "root", &["-i", "0:0"]), faked(0, 0));
    if uid == 0 {
        eprintln!("SKIPPED (real uid 0): the own-id and other-id cases need a non-root caller");
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let (ou, og) = (uid + 1, gid + 1);
    let case = |name: &str, args: &[&str]| full(&dir, &guest, name, args);
    // Own ids with the opt-out.
    assert_eq!(
        case(
            "opt-out",
            &["--no-identity-only", "-i", &format!("{uid}:{gid}")]
        ),
        faked(uid, gid)
    );
    // Other ids, with and without the explicit request.
    assert_eq!(case("other", &["-i", &format!("{ou}:{og}")]), faked(ou, og));
    assert_eq!(
        case(
            "other-explicit",
            &["--identity-only", "-i", &format!("{ou}:{og}")]
        ),
        faked(ou, og)
    );
    // Only the gid differs from the caller's, then only the uid.
    assert_eq!(
        case("gid-only", &["-i", &format!("{uid}:{og}")]),
        faked(uid, og)
    );
    assert_eq!(
        case("uid-only", &["-i", &format!("{ou}:{gid}")]),
        faked(ou, gid)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
