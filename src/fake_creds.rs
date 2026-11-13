//! proot's fake_id0 rules for the set*id calls, used under
//! identity-only: `SETXID`, `SETREXID`, `SETRESXID` and `SETFSXID` in
//! proot's src/extension/fake_id0/fake_id0.c (lines 84, 129, 196 and 240
//! at proot 4dba3afb, the version the Android launcher patches).
//!
//! Each rule checks the call against the current fake ids, refuses it with
//! EPERM or applies it, as the kernel does for an unprivileged caller. The
//! caller is privileged when its fake effective uid is 0 (proot's
//! `config->euid == 0`, for the gid calls too). Under identity-only the
//! fake ids are the caller's own non-root ids, so every allowed call leaves
//! them as they are, and a call naming any other id is refused.

use reverie::syscalls::Errno;

/// The id a set*id argument of -1 carries: leave that id unchanged.
const UNSET: u32 = u32::MAX;

/// One family of fake ids, uids or gids: real, effective, saved and
/// filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ids {
    pub r: u32,
    pub e: u32,
    pub s: u32,
    pub fs: u32,
}

impl Ids {
    /// proot's `EQUALS_ANY_ID`: `id` is the real, effective or saved id.
    fn any(&self, id: u32) -> bool {
        id == self.r || id == self.e || id == self.s
    }

    /// setuid(2) and setgid(2) (`SETXID`).
    pub fn set(&mut self, id: u32, privileged: bool) -> Result<(), Errno> {
        if !(privileged || self.any(id)) {
            return Err(Errno::EPERM);
        }
        if privileged {
            self.r = id;
            self.s = id;
        }
        self.e = id;
        self.fs = id;
        Ok(())
    }

    /// setreuid(2) and setregid(2) (`SETREXID`).
    pub fn set_re(&mut self, r: u32, e: u32, privileged: bool) -> Result<(), Errno> {
        let unchanged = |id: u32, current: u32| id == UNSET || id == current;
        let allowed = privileged
            || (unchanged(e, self.e) && unchanged(r, self.r))
            || (r == self.e && (e == self.r || unchanged(e, self.e)))
            || (e == self.r && (r == self.e || unchanged(r, self.r)))
            || (e == self.s && unchanged(r, self.r));
        if !allowed {
            return Err(Errno::EPERM);
        }
        if e != UNSET {
            if e != self.r {
                self.s = e;
            }
            self.e = e;
            self.fs = e;
        }
        // After the effective id: this changes the real id that rule reads.
        if r != UNSET {
            if e != UNSET {
                self.s = e;
            }
            self.r = r;
        }
        Ok(())
    }

    /// setresuid(2) and setresgid(2) (`SETRESXID`).
    pub fn set_res(&mut self, r: u32, e: u32, s: u32, privileged: bool) -> Result<(), Errno> {
        let allowed = privileged || [r, e, s].iter().all(|&id| id == UNSET || self.any(id));
        if !allowed {
            return Err(Errno::EPERM);
        }
        if r != UNSET {
            self.r = r;
        }
        if e != UNSET {
            self.e = e;
            self.fs = e;
        }
        if s != UNSET {
            self.s = s;
        }
        Ok(())
    }

    /// setfsuid(2) and setfsgid(2) (`SETFSXID`): the previous filesystem
    /// id, whether the change is allowed or not.
    pub fn set_fs(&mut self, fs: u32, privileged: bool) -> u32 {
        let old = self.fs;
        if privileged || fs == self.fs || self.any(fs) {
            self.fs = fs;
        }
        old
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 10123;
    const OTHER: u32 = 10124;

    fn ids(r: u32, e: u32, s: u32) -> Ids {
        Ids { r, e, s, fs: e }
    }

    impl Ids {
        fn all(id: u32) -> Self {
            ids(id, id, id)
        }
    }

    /// Under identity-only every id is the caller's own and non-root:
    /// each setter allows exactly the arguments that are -1 or that id,
    /// and leaves the ids unchanged either way.
    #[test]
    fn identity_ids_admit_only_themselves() {
        let start = Ids::all(ME);
        let args = [UNSET, ME, OTHER, 0];
        let ok = |v: &[u32]| v.iter().all(|&a| a == UNSET || a == ME);
        for &a in &args {
            let mut c = start;
            assert_eq!(c.set(a, false).is_ok(), a == ME, "set({a})");
            assert_eq!(c, start);
            for &b in &args {
                let mut c = start;
                assert_eq!(
                    c.set_re(a, b, false).is_ok(),
                    ok(&[a, b]),
                    "set_re({a},{b})"
                );
                assert_eq!(c, start);
                for &s in &args {
                    let mut c = start;
                    let r = c.set_res(a, b, s, false);
                    assert_eq!(r.is_ok(), ok(&[a, b, s]), "set_res({a},{b},{s})");
                    assert_eq!(c, start);
                }
            }
            let mut c = start;
            assert_eq!(c.set_fs(a, false), ME, "set_fs({a})");
            assert_eq!(c, start);
        }
    }

    #[test]
    fn set_follows_setxid() {
        // Unprivileged: the effective and filesystem ids move to the real
        // or saved id; anything else is refused and changes nothing.
        let mut c = ids(1, 2, 3);
        assert_eq!(c.set(4, false), Err(Errno::EPERM));
        assert_eq!(c, ids(1, 2, 3));
        c.set(3, false).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 1,
                e: 3,
                s: 3,
                fs: 3
            }
        );
        // Privileged: real and saved ids move too.
        let mut c = ids(5, 0, 6);
        c.set(7, true).unwrap();
        assert_eq!(c, Ids::all(7));
    }

    #[test]
    fn set_re_follows_setrexid() {
        // Swapping real and effective ids is allowed, and the saved id
        // takes the new effective id because the real id was set.
        let mut c = ids(1, 2, 3);
        c.set_re(2, 1, false).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 2,
                e: 1,
                s: 1,
                fs: 1
            }
        );
        // The effective id to the saved id, the real id unchanged: the saved
        // id takes the new effective id because it differs from the real id.
        let mut c = ids(1, 2, 3);
        c.set_re(UNSET, 3, false).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 1,
                e: 3,
                s: 3,
                fs: 3
            }
        );
        // The effective id to the real id: the saved id stays.
        let mut c = ids(1, 2, 3);
        c.set_re(UNSET, 1, false).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 1,
                e: 1,
                s: 3,
                fs: 1
            }
        );
        // The real id to the saved id is not one of the allowed changes.
        let mut c = ids(1, 2, 3);
        assert_eq!(c.set_re(3, UNSET, false), Err(Errno::EPERM));
        assert_eq!(c.set_re(UNSET, 4, false), Err(Errno::EPERM));
        assert_eq!(c, ids(1, 2, 3));
        // Privileged: anything, with the same saved-id rule.
        let mut c = ids(0, 0, 0);
        c.set_re(8, 9, true).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 8,
                e: 9,
                s: 9,
                fs: 9
            }
        );
    }

    #[test]
    fn set_res_follows_setresxid() {
        let mut c = ids(1, 2, 3);
        c.set_res(3, 1, 2, false).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 3,
                e: 1,
                s: 2,
                fs: 1
            }
        );
        assert_eq!(c.set_res(UNSET, UNSET, 4, false), Err(Errno::EPERM));
        assert_eq!(
            c,
            Ids {
                r: 3,
                e: 1,
                s: 2,
                fs: 1
            }
        );
        // Unset effective id: the filesystem id stays.
        let mut c = Ids {
            r: 1,
            e: 2,
            s: 3,
            fs: 4,
        };
        c.set_res(2, UNSET, UNSET, false).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 2,
                e: 2,
                s: 3,
                fs: 4
            }
        );
        let mut c = ids(0, 0, 0);
        c.set_res(5, 6, 7, true).unwrap();
        assert_eq!(
            c,
            Ids {
                r: 5,
                e: 6,
                s: 7,
                fs: 6
            }
        );
    }

    #[test]
    fn set_fs_returns_the_old_id_either_way() {
        let mut c = Ids {
            r: 1,
            e: 2,
            s: 3,
            fs: 4,
        };
        assert_eq!(c.set_fs(5, false), 4);
        assert_eq!(c.fs, 4);
        assert_eq!(c.set_fs(4, false), 4);
        assert_eq!(c.set_fs(3, false), 4);
        assert_eq!(c.fs, 3);
        assert_eq!(c.set_fs(9, true), 3);
        assert_eq!(c.fs, 9);
    }
}
