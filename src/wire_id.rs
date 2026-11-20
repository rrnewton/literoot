//! The wire identity both builds carry (C5.4, C5d): one digest over the
//! config layout and the refusal schema, checked at the two production
//! barriers before anything is decoded.
//!
//! - The launcher reads the preload library's `.literoot_wire_id` ELF
//!   section before it spawns anything ([`check_preload`]).
//! - The preload checks the identity the launcher appends to the sealed
//!   bootstrap's tool selector before it arms ([`split_selector`]).
//!
//! [`LITEROOT_WIRE_DIGEST`] is the full SHA-256 over the four domains that
//! `initial_packet::literoot_config_wire_fingerprint` hashes (canonical
//! config wire, CONFIG_JSON, refusal revision, refusal wire); the mapped
//! route's fingerprint is its first 8 bytes. The constant is pasted from the
//! computed value, never typed, and `wire_digest_is_pinned` (initial_packet)
//! recomputes it.

/// Bumped with any change to `Refusal` or its nested kinds, as Detcore's
/// `GLOBAL_RPC_REVISION` is; the refusal-wire domain catches what a missed
/// bump would not.
pub const REFUSAL_RPC_REVISION: u32 = 4;

/// The full SHA-256 of this build's config layout and refusal schema.
/// PASTE the value `wire_digest_is_pinned` prints; never type it.
pub const LITEROOT_WIRE_DIGEST: [u8; 32] = [
    0x23, 0x62, 0x93, 0xf5, 0x55, 0x5f, 0xf9, 0xda,
    0x72, 0x91, 0x48, 0x09, 0xcb, 0xfd, 0x0a, 0x4e,
    0x37, 0x0a, 0x92, 0x78, 0xe7, 0xfd, 0x4e, 0x87,
    0x1d, 0x7f, 0x58, 0xb8, 0xd4, 0x53, 0x46, 0x50,
];

/// The `.literoot_wire_id` record's magic.
pub const WIRE_ID_MAGIC: &[u8; 16] = b"LITEROOT-WIREID1";
/// The record's length: magic, revision (u32 LE), digest.
pub const WIRE_ID_LEN: usize = 52;
/// The section that carries the record in the preload library.
pub const WIRE_ID_SECTION: &[u8] = b".literoot_wire_id";

/// This build's record.
#[allow(dead_code)] // The preload's `.literoot_wire_id` static is its user.
pub const WIRE_ID_RECORD: [u8; WIRE_ID_LEN] = {
    let mut out = [0u8; WIRE_ID_LEN];
    let mut i = 0;
    while i < 16 {
        out[i] = WIRE_ID_MAGIC[i];
        i += 1;
    }
    let rev = REFUSAL_RPC_REVISION.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        out[16 + i] = rev[i];
        i += 1;
    }
    let mut i = 0;
    while i < 32 {
        out[20 + i] = LITEROOT_WIRE_DIGEST[i];
        i += 1;
    }
    out
};

/// The separator between the tool selector's name and its identity.
pub const SELECTOR_SEPARATOR: char = '\u{1f}';

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `<rev>/<first 8 hex digits>`, as the named messages print an identity.
fn short(revision: u32, digest: &[u8]) -> String {
    format!("{revision}/{}", hex(&digest[..4]))
}

/// The tool selector the launcher sends: the name, 0x1f, then
/// `wire=<rev>:<64 hex>`.
#[allow(dead_code)] // The launcher is its caller; the preload splits.
pub fn selector_with_identity(name: &str) -> String {
    format!(
        "{name}{SELECTOR_SEPARATOR}wire={REFUSAL_RPC_REVISION}:{}",
        hex(&LITEROOT_WIRE_DIGEST)
    )
}

/// The preload's check of the selector the launcher sent: the name part
/// when its identity equals this build's, else the named failure. A missing
/// identity is never a waiver.
#[allow(dead_code)] // The preload constructor is its caller.
pub fn split_selector(selector: &str) -> Result<&str, String> {
    split_selector_against(selector, REFUSAL_RPC_REVISION, &LITEROOT_WIRE_DIGEST)
}

/// The preload constructor's arming step after it took the bootstrap: the
/// tool data must be UTF-8 and carry this build's identity before
/// `connect_and_install` runs. That closure is the only holder of the
/// coordinator socket and the only path to the config decode
/// (`install_tool_with` / `install_tool_from_bootstrap`), so a refused
/// identity connects nothing and decodes nothing (C5d; the recording seam
/// in `initial_packet`'s `preload_rejects_config_only_mismatch` counts it).
#[allow(dead_code)] // The preload constructor and the launcher's unit are its callers.
pub fn arm_with(
    tool_data: Vec<u8>,
    connect_and_install: impl FnOnce(&str) -> Result<(), String>,
) -> Result<(), String> {
    let selected =
        String::from_utf8(tool_data).map_err(|_| "tool selector is not valid UTF-8".to_owned())?;
    connect_and_install(split_selector(&selected)?)
}

pub(crate) fn split_selector_against<'a>(
    selector: &'a str,
    revision: u32,
    digest: &[u8; 32],
) -> Result<&'a str, String> {
    let Some((name, identity)) = selector.split_once(SELECTOR_SEPARATOR) else {
        return Err(format!(
            "the launcher sent no wire identity; it predates wire revision {revision} \
             (use the literoot launcher built with this preload)"
        ));
    };
    let parsed = identity.strip_prefix("wire=").and_then(|rest| {
        let (rev, hexd) = rest.split_once(':')?;
        let canonical = rev == "0" || (!rev.is_empty() && !rev.starts_with('0'));
        if !canonical || !rev.bytes().all(|b| b.is_ascii_digit()) || hexd.len() != 64 {
            return None;
        }
        if !hexd.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let rev: u32 = rev.parse().ok()?;
        let mut d = [0u8; 32];
        for (i, out) in d.iter_mut().enumerate() {
            *out = u8::from_str_radix(&hexd[2 * i..2 * i + 2], 16).ok()?;
        }
        Some((rev, d))
    });
    match parsed {
        None => Err(format!("the launcher's wire identity is malformed: {identity:?}")),
        Some((rev, d)) if rev == revision && d == *digest => Ok(name),
        Some((rev, d)) => Err(format!(
            "launcher wire {} is not this preload's {}",
            short(rev, &d),
            short(revision, digest)
        )),
    }
}

/// Why a file's wire identity could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// Not a little-endian ELF64 file this reader accepts, or a header
    /// field out of range.
    Malformed(&'static str),
    /// No `.literoot_wire_id` section.
    Absent,
    /// More than one.
    Duplicate,
    /// A section of the wrong size or type, or the wrong magic.
    BadRecord(&'static str),
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// The `.literoot_wire_id` record of an ELF64 little-endian file's bytes,
/// read through its section headers with every offset bounds-checked.
pub fn wire_id_of(file: &[u8]) -> Result<[u8; WIRE_ID_LEN], ElfError> {
    use ElfError::*;
    const SHT_NOBITS: u32 = 8;
    const SHN_XINDEX: u16 = 0xffff;
    if file.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err(Malformed("not an ELF file"));
    }
    if file.get(4) != Some(&2) {
        return Err(Malformed("not ELFCLASS64"));
    }
    if file.get(5) != Some(&1) {
        return Err(Malformed("not little-endian"));
    }
    let shoff = u64_at(file, 0x28).ok_or(Malformed("truncated header"))?;
    let shentsize = u16_at(file, 0x3a).ok_or(Malformed("truncated header"))?;
    let shnum = u16_at(file, 0x3c).ok_or(Malformed("truncated header"))?;
    let shstrndx = u16_at(file, 0x3e).ok_or(Malformed("truncated header"))?;
    if shentsize != 64 {
        return Err(Malformed("section header size is not 64"));
    }
    if shnum == 0 || shstrndx == SHN_XINDEX {
        return Err(Malformed("extended section numbering is not supported"));
    }
    if shstrndx >= shnum {
        return Err(Malformed("section name table index out of range"));
    }
    let header = |i: u16| -> Result<&[u8], ElfError> {
        let at = usize::try_from(shoff)
            .ok()
            .and_then(|o| o.checked_add(usize::from(i) * 64))
            .ok_or(Malformed("section header offset out of range"))?;
        file.get(at..at.checked_add(64).ok_or(Malformed("section header offset out of range"))?)
            .ok_or(Malformed("section header out of range"))
    };
    let body = |h: &[u8]| -> Result<&[u8], ElfError> {
        let off = usize::try_from(u64_at(h, 0x18).unwrap()).map_err(|_| Malformed("section offset out of range"))?;
        let size = usize::try_from(u64_at(h, 0x20).unwrap()).map_err(|_| Malformed("section size out of range"))?;
        let end = off.checked_add(size).ok_or(Malformed("section end overflows"))?;
        file.get(off..end).ok_or(Malformed("section out of range"))
    };
    let names = body(header(shstrndx)?)?;
    let mut found = None;
    for i in 0..shnum {
        let h = header(i)?;
        let name_at = u32_at(h, 0).unwrap() as usize;
        let name = names.get(name_at..).ok_or(Malformed("section name out of range"))?;
        let end = name.iter().position(|&b| b == 0).ok_or(Malformed("unterminated section name"))?;
        if &name[..end] != WIRE_ID_SECTION {
            continue;
        }
        if found.is_some() {
            return Err(Duplicate);
        }
        if u32_at(h, 4).unwrap() == SHT_NOBITS {
            return Err(BadRecord("the section holds no bytes (SHT_NOBITS)"));
        }
        let record = body(h)?;
        let record: [u8; WIRE_ID_LEN] =
            record.try_into().map_err(|_| BadRecord("the section is not 52 bytes"))?;
        if &record[..16] != WIRE_ID_MAGIC {
            return Err(BadRecord("wrong magic"));
        }
        found = Some(record);
    }
    found.ok_or(Absent)
}

/// The launcher's pre-spawn check of the preload library at `path`: its
/// record must equal this build's. The named refusal otherwise. The file is
/// read now and opened again by the guest's loader later: a file swapped in
/// between is not a build mismatch, and the preload's own selector check
/// stops an old library then (§4.9).
#[allow(dead_code)] // The launcher's run path is its caller.
pub fn check_preload(path: &std::path::Path) -> Result<(), String> {
    // A preload library is a few MB; the cap bounds a wrong path.
    const MAX: u64 = 512 << 20;
    let shown = path.display();
    let len = std::fs::metadata(path)
        .map_err(|e| format!("cannot read the preload {shown}: {e}"))?
        .len();
    if len > MAX {
        return Err(format!("the preload {shown} is larger than {MAX} bytes"));
    }
    let file = std::fs::read(path).map_err(|e| format!("cannot read the preload {shown}: {e}"))?;
    check_record(&shown.to_string(), wire_id_of(&file), REFUSAL_RPC_REVISION, &LITEROOT_WIRE_DIGEST)
}

pub(crate) fn check_record(
    shown: &str,
    record: Result<[u8; WIRE_ID_LEN], ElfError>,
    revision: u32,
    digest: &[u8; 32],
) -> Result<(), String> {
    match record {
        Ok(r) => {
            let rev = u32::from_le_bytes(r[16..20].try_into().unwrap());
            if rev == revision && r[20..] == digest[..] {
                Ok(())
            } else {
                Err(format!(
                    "the preload {shown} has wire {}, not this launcher's {}",
                    short(rev, &r[20..]),
                    short(revision, digest)
                ))
            }
        }
        Err(ElfError::Absent) => Err(format!(
            "the preload {shown} carries no wire identity; it predates wire revision {revision} \
             (use the libliteroot_preload.so built with this literoot)"
        )),
        Err(ElfError::Duplicate) => {
            Err(format!("the preload {shown} carries more than one wire identity"))
        }
        Err(ElfError::Malformed(why) | ElfError::BadRecord(why)) => {
            Err(format!("the preload {shown} has an unreadable wire identity: {why}"))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ELF64 LE file: a null section, the name table, and the
    /// given (name, type, bytes) sections.
    pub(crate) fn elf(sections: &[(&[u8], u32, &[u8])]) -> Vec<u8> {
        let mut names = vec![0u8];
        let mut name_at = Vec::new();
        for (name, _, _) in sections {
            name_at.push(names.len() as u32);
            names.extend_from_slice(name);
            names.push(0);
        }
        let shstrtab_name = names.len() as u32;
        names.extend_from_slice(b".shstrtab\0");
        let mut file = vec![0u8; 64];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        let mut bodies = Vec::new();
        for (_, _, bytes) in sections {
            bodies.push((file.len() as u64, bytes.len() as u64));
            file.extend_from_slice(bytes);
        }
        let names_at = file.len() as u64;
        file.extend_from_slice(&names);
        let shoff = file.len() as u64;
        file.extend_from_slice(&[0u8; 64]);
        for (i, (_, ty, _)) in sections.iter().enumerate() {
            let mut h = [0u8; 64];
            h[..4].copy_from_slice(&name_at[i].to_le_bytes());
            h[4..8].copy_from_slice(&ty.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&bodies[i].0.to_le_bytes());
            h[0x20..0x28].copy_from_slice(&bodies[i].1.to_le_bytes());
            file.extend_from_slice(&h);
        }
        let mut h = [0u8; 64];
        h[..4].copy_from_slice(&shstrtab_name.to_le_bytes());
        h[4..8].copy_from_slice(&3u32.to_le_bytes());
        h[0x18..0x20].copy_from_slice(&names_at.to_le_bytes());
        h[0x20..0x28].copy_from_slice(&(names.len() as u64).to_le_bytes());
        file.extend_from_slice(&h);
        let shnum = sections.len() as u16 + 2;
        file[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        file[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        file[0x3c..0x3e].copy_from_slice(&shnum.to_le_bytes());
        file[0x3e..0x40].copy_from_slice(&(shnum - 1).to_le_bytes());
        file
    }

    pub(crate) const PROGBITS: u32 = 1;

    #[test]
    fn wire_id_reader_finds_exactly_one_record() {
        let file = elf(&[(b".text", PROGBITS, b"code"), (WIRE_ID_SECTION, PROGBITS, &WIRE_ID_RECORD)]);
        assert_eq!(wire_id_of(&file), Ok(WIRE_ID_RECORD));
        assert!(check_record("p", wire_id_of(&file), REFUSAL_RPC_REVISION, &LITEROOT_WIRE_DIGEST).is_ok());
        let none = elf(&[(b".text", PROGBITS, b"code")]);
        assert_eq!(wire_id_of(&none), Err(ElfError::Absent));
        let msg = check_record("p", wire_id_of(&none), 2, &LITEROOT_WIRE_DIGEST).unwrap_err();
        assert_eq!(
            msg,
            "the preload p carries no wire identity; it predates wire revision 2 \
             (use the libliteroot_preload.so built with this literoot)"
        );
        let two = elf(&[(WIRE_ID_SECTION, PROGBITS, &WIRE_ID_RECORD), (WIRE_ID_SECTION, PROGBITS, &WIRE_ID_RECORD)]);
        assert_eq!(wire_id_of(&two), Err(ElfError::Duplicate));
    }

    #[test]
    fn wire_id_reader_rejects_bad_records_and_headers() {
        let short = elf(&[(WIRE_ID_SECTION, PROGBITS, &WIRE_ID_RECORD[..51])]);
        assert!(matches!(wire_id_of(&short), Err(ElfError::BadRecord(_))));
        let mut magic = WIRE_ID_RECORD;
        magic[0] ^= 1;
        assert!(matches!(wire_id_of(&elf(&[(WIRE_ID_SECTION, PROGBITS, &magic)])), Err(ElfError::BadRecord(_))));
        let nobits = elf(&[(WIRE_ID_SECTION, 8, &WIRE_ID_RECORD)]);
        assert!(matches!(wire_id_of(&nobits), Err(ElfError::BadRecord(_))));
        let good = elf(&[(WIRE_ID_SECTION, PROGBITS, &WIRE_ID_RECORD)]);
        for cut in [0, 3, 10, 0x3f, good.len() - 1] {
            assert!(wire_id_of(&good[..cut]).is_err(), "cut {cut}");
        }
        let edit = |at: usize, bytes: &[u8]| {
            let mut f = good.clone();
            f[at..at + bytes.len()].copy_from_slice(bytes);
            wire_id_of(&f)
        };
        assert!(matches!(edit(4, &[1]), Err(ElfError::Malformed(_))), "ELFCLASS32");
        assert!(matches!(edit(5, &[2]), Err(ElfError::Malformed(_))), "big-endian");
        assert!(matches!(edit(0x3a, &40u16.to_le_bytes()), Err(ElfError::Malformed(_))));
        assert!(matches!(edit(0x3e, &0xffffu16.to_le_bytes()), Err(ElfError::Malformed(_))));
        assert!(matches!(edit(0x3c, &0u16.to_le_bytes()), Err(ElfError::Malformed(_))));
        assert!(matches!(edit(0x3e, &9u16.to_le_bytes()), Err(ElfError::Malformed(_))));
        assert!(matches!(edit(0x28, &u64::MAX.to_le_bytes()), Err(ElfError::Malformed(_))));
        // A section whose offset plus size overflows.
        let shoff = u64::from_le_bytes(good[0x28..0x30].try_into().unwrap()) as usize;
        let mut f = good.clone();
        let h = shoff + 64;
        f[h + 0x18..h + 0x20].copy_from_slice(&u64::MAX.to_le_bytes());
        f[h + 0x20..h + 0x28].copy_from_slice(&2u64.to_le_bytes());
        assert!(matches!(wire_id_of(&f), Err(ElfError::Malformed(_))));
    }

    #[test]
    fn wire_id_reader_rejects_other_digest() {
        let mut other = WIRE_ID_RECORD;
        other[51] ^= 1;
        let file = elf(&[(WIRE_ID_SECTION, PROGBITS, &other)]);
        let msg = check_record("p", wire_id_of(&file), REFUSAL_RPC_REVISION, &LITEROOT_WIRE_DIGEST)
            .unwrap_err();
        assert!(msg.starts_with(&format!("the preload p has wire {REFUSAL_RPC_REVISION}/")), "{msg}");
        let mut rev = WIRE_ID_RECORD;
        rev[16] = 1;
        let file = elf(&[(WIRE_ID_SECTION, PROGBITS, &rev)]);
        assert!(check_record("p", wire_id_of(&file), REFUSAL_RPC_REVISION, &LITEROOT_WIRE_DIGEST).is_err());
    }

    /// C5a.5: the preload's wire identity comes only from the bootstrap's
    /// tool data: this build's identity arms, another or none is refused.
    /// The environment's part is the source check alone: the identity code
    /// (this file's non-test part) calls no environment reader. Setting
    /// variables that no code reads would show nothing, so the unit does not.
    #[test]
    fn wire_identity_comes_only_from_tool_data() {
        let good = selector_with_identity("literoot");
        let other = format!("literoot{}wire={}:{}", SELECTOR_SEPARATOR, REFUSAL_RPC_REVISION, "00".repeat(32));
        let mut seen = Vec::new();
        for data in [good, other, "literoot".to_owned()] {
            seen.push(arm_with(data.into_bytes(), |name| Err(format!("armed {name}"))));
        }
        assert_eq!(seen[0], Err("armed literoot".to_owned()), "this build's identity arms");
        assert!(seen[1].as_ref().is_err_and(|e| !e.starts_with("armed")), "another identity is refused");
        assert!(seen[2].as_ref().is_err_and(|e| !e.starts_with("armed")), "no identity is refused");
        let source = include_str!("wire_id.rs");
        let code = crate::test_source::without_test_items(source);
        assert!(code.contains("pub(crate) fn check_record("), "production kept");
        assert!(!code.contains("fn wire_identity_comes_only_from_tool_data("), "the test module dropped");
        for reader in ["env::var", "var_os", "getenv", "environ", "env::vars"] {
            assert!(!code.contains(reader), "the identity code reads the environment: {reader}");
        }
    }

    #[test]
    fn selector_identity_round_trips_and_refuses() {
        for name in ["literoot", "literoot-watched"] {
            assert_eq!(split_selector(&selector_with_identity(name)), Ok(name));
        }
        let old = split_selector("literoot").unwrap_err();
        assert!(old.starts_with("the launcher sent no wire identity"), "{old}");
        let mut other = LITEROOT_WIRE_DIGEST;
        other[0] ^= 1;
        let sel = selector_with_identity("literoot");
        let ours = REFUSAL_RPC_REVISION;
        assert!(split_selector_against(&sel, ours, &other).unwrap_err().starts_with(&format!("launcher wire {ours}/")));
        assert!(split_selector_against(&sel, ours + 1, &LITEROOT_WIRE_DIGEST).is_err());
        let identity = sel.split_once(SELECTOR_SEPARATOR).unwrap().1.to_owned();
        for bad in [
            String::from("literoot\u{1f}"),
            String::from("literoot\u{1f}wire="),
            format!("literoot\u{1f}{}", identity.replace("wire=", "wire=0")),
            format!("literoot\u{1f}{}", identity.to_uppercase()),
            format!("literoot\u{1f}{identity}0"),
            format!("literoot\u{1f}{}", &identity[..identity.len() - 1]),
            format!("literoot\u{1f}{}", identity.replacen(':', "", 1)),
        ] {
            assert!(split_selector(&bad).is_err(), "{bad:?}");
        }
    }
}
