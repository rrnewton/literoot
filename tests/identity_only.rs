//! --identity-only on the ptrace backend: with `-i` equal to the caller's
//! own non-root ids, only the set*id and setxattr calls are emulated, so
//! everything else answers as the kernel does; without the flag, or with
//! other ids, `-i` keeps its full fake-identity rules.

mod common;

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const GUEST_C: &str = r#"
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || chdir(argv[1])) return 2;
    printf("uid %d euid %d\n", (int) getuid(), (int) geteuid());
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

fn own_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("literoot-idonly-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_guest(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("guest.c"), GUEST_C).unwrap();
    let bin = dir.join("guest");
    let cc = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(dir.join("guest.c"))
        .output()
        .expect("cc is required to build the identity guest");
    assert!(cc.status.success(), "cc failed: {cc:?}");
    bin
}

/// Run the guest in a fresh work directory under literoot with `args`.
fn run(dir: &Path, guest: &Path, name: &str, args: &[String]) -> String {
    let work = dir.join(name);
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("file"), "x").unwrap();
    let mut cmd = Command::new(common::literoot_bin());
    cmd.args(args).arg(guest).arg(&work);
    let out = common::run_bounded(cmd, name);
    assert!(out.status.success(), "{name}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn identity_only_emulates_only_the_set_id_calls() {
    let dir = own_dir("modes");
    let guest = build_guest(&dir);
    let me = std::fs::metadata(&guest).unwrap();
    let (uid, gid) = (me.uid(), me.gid());
    if uid == 0 {
        eprintln!("skipped: identity-only never applies to root, and this runs as root");
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let own = format!("{uid}:{gid}");
    let other = format!("{}:{}", uid + 1, gid + 1);
    let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // Identity only: setuid(0) is emulated, but the ids read back, chown
    // and mknod are the kernel's.
    assert_eq!(
        run(
            &dir,
            &guest,
            "identity",
            &args(&["-i", &own, "--identity-only"])
        ),
        format!(
            "uid {uid} euid {uid}\n\
             setuid(0) 0 errno 0, then euid {uid}\n\
             chown to 0 -1 errno 1\n\
             mknod fifo 0, is a fifo 1\n"
        )
    );
    // The full rules, unchanged without the flag: the fake euid becomes 0,
    // chown is faked, mknod makes a regular file.
    let full = format!(
        "uid {uid} euid {uid}\n\
         setuid(0) 0 errno 0, then euid 0\n\
         chown to 0 0 errno 0\n\
         mknod fifo 0, is a fifo 0\n"
    );
    assert_eq!(run(&dir, &guest, "full", &args(&["-i", &own])), full);
    // Ids that are not the caller's own keep the full rules under the flag.
    let other_uid = uid + 1;
    assert_eq!(
        run(
            &dir,
            &guest,
            "other",
            &args(&["-i", &other, "--identity-only"])
        ),
        format!(
            "uid {other_uid} euid {other_uid}\n\
             setuid(0) 0 errno 0, then euid 0\n\
             chown to 0 0 errno 0\n\
             mknod fifo 0, is a fifo 0\n"
        )
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
