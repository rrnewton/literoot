//! The in-guest preload's compatibility stamp: one allocated ELF note,
//! section `.note.literoot.preload`, note name `literoot`, type 0x4c4954,
//! found through PT_NOTE and never by section name.
//!
//! Three users share this file through `#[path]`: the preload's build
//! script, which emits the note; the root build script, which parses the
//! blob it embeds and fails the build when the note is missing or differs;
//! and the launcher, which admits a user-supplied preload
//! (`LITEROOT_PRELOAD`) only when its stamp equals the launcher's record for
//! the selected flavour.
//!
//! The stamp is compatibility, not integrity or authenticity: anyone can
//! copy a valid stamp. Sha256 identity applies only to literoot's own cache
//! (`preload_materialize`).
//!
//! Descriptor, all integers little-endian: magic `LITEROOT\0` (9 bytes),
//! `stamp_version` u32 = 1, `protocol_version` u32, `flavour` u32
//! (1 = liteinst, 2 = traphost). `protocol_version` is derived, so it cannot
//! be forgotten: the first four bytes of a SHA-256 over the fixed set of
//! files both sides compile, the pinned Reverie revisions in the root
//! Cargo.lock, and a layout constant. Any edit to one of those files,
//! comments included, changes it; a separately built preload must then be
//! rebuilt, or it refuses by name.

// Each includer uses its own subset.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::Path;

use sha2::Digest;
use sha2::Sha256;

/// The note name, NUL included, as it appears in the note.
pub const NOTE_NAME: &[u8] = b"literoot\0";
/// The note type.
pub const NOTE_TYPE: u32 = 0x004c_4954;
/// The section the preload emits the note in. Never trusted when reading.
pub const SECTION: &str = ".note.literoot.preload";
/// The descriptor's magic.
pub const MAGIC: &[u8] = b"LITEROOT\0";
/// The only stamp version this code reads or writes.
pub const STAMP_VERSION: u32 = 1;
pub const FLAVOUR_LITEINST: u32 = 1;
pub const FLAVOUR_TRAPHOST: u32 = 2;
/// Descriptor length: magic plus three u32 fields.
pub const DESC_LEN: usize = 9 + 4 + 4 + 4;
/// Whole note: 12-byte header, name padded to 12, descriptor padded to 24.
pub const NOTE_LEN: usize = 12 + 12 + 24;
/// Cap on any preload file read for its stamp.
pub const MAX_FILE: u64 = 64 * 1024 * 1024;
/// Bootstrap and tool-data layout version. Any layout change bumps it.
pub const LAYOUT: &[u8] = b"LAYOUT_V1";
/// The fixed file set, the same on both sides regardless of features,
/// relative to the package root.
pub const STAMP_FILES: [&str; 9] = [
    "src/arch.rs",
    "src/exec_state.rs",
    "src/fake_creds.rs",
    "src/initial_packet.rs",
    "src/refusal_log.rs",
    "src/rootfs_tool.rs",
    "src/shared_record.rs",
    "src/translate.rs",
    "preload/src/lib.rs",
];
/// The Reverie crates whose pinned revision enters the stamp.
pub const REVERIE_CRATES: [&str; 2] = ["reverie-inguest", "reverie-liteinst"];
/// Bytes only a reporter-off test fixture carries. The root build script
/// refuses to embed a blob that contains them.
pub const REPORTER_OFF_MARKER: &[u8] = b"literoot-preload:reporter-off-fixture:v1";

/// A parsed stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub stamp_version: u32,
    pub protocol_version: u32,
    pub flavour: u32,
}

/// The name of a flavour value, for messages and receipts.
pub fn flavour_name(flavour: u32) -> &'static str {
    match flavour {
        FLAVOUR_LITEINST => "liteinst",
        FLAVOUR_TRAPHOST => "traphost",
        _ => "unknown",
    }
}

/// The whole note, as the preload emits it.
pub fn note_bytes(protocol_version: u32, flavour: u32) -> [u8; NOTE_LEN] {
    let mut note = [0u8; NOTE_LEN];
    note[0..4].copy_from_slice(&(NOTE_NAME.len() as u32).to_le_bytes());
    note[4..8].copy_from_slice(&(DESC_LEN as u32).to_le_bytes());
    note[8..12].copy_from_slice(&NOTE_TYPE.to_le_bytes());
    note[12..12 + NOTE_NAME.len()].copy_from_slice(NOTE_NAME);
    let desc = 24;
    note[desc..desc + MAGIC.len()].copy_from_slice(MAGIC);
    note[desc + 9..desc + 13].copy_from_slice(&STAMP_VERSION.to_le_bytes());
    note[desc + 13..desc + 17].copy_from_slice(&protocol_version.to_le_bytes());
    note[desc + 17..desc + 21].copy_from_slice(&flavour.to_le_bytes());
    note
}

fn rd_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(s.try_into().ok()?))
}

fn rd_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(s.try_into().ok()?))
}

fn rd_u64(b: &[u8], at: usize) -> Option<usize> {
    let s = b.get(at..at.checked_add(8)?)?;
    usize::try_from(u64::from_le_bytes(s.try_into().ok()?)).ok()
}

fn align4(n: usize) -> Option<usize> {
    Some(n.checked_add(3)? & !3)
}

/// Parse the stamp from a whole file's bytes. Every offset and length is
/// checked against the file with checked arithmetic; any failure is an
/// error, never a panic, and nothing is loaded or executed.
pub fn parse(bytes: &[u8]) -> Result<Stamp, String> {
    if bytes.len() < 64 || bytes[0..4] != b"\x7fELF"[..] {
        return Err("not an ELF file".into());
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        return Err("not a 64-bit little-endian ELF file".into());
    }
    let phoff = rd_u64(bytes, 0x20).ok_or("program header offset out of range")?;
    let phentsize = usize::from(rd_u16(bytes, 0x36).ok_or("truncated ELF header")?);
    let phnum = usize::from(rd_u16(bytes, 0x38).ok_or("truncated ELF header")?);
    if phnum > 0 && phentsize < 56 {
        return Err("program header entries are too small".into());
    }
    let mut found: Vec<&[u8]> = Vec::new();
    for i in 0..phnum {
        let off = i
            .checked_mul(phentsize)
            .and_then(|v| v.checked_add(phoff))
            .ok_or("program header offset overflows")?;
        let p_type = rd_u32(bytes, off).ok_or("program header out of bounds")?;
        if p_type != 4 {
            continue;
        }
        let p_offset = rd_u64(bytes, off.checked_add(8).ok_or("overflow")?)
            .ok_or("note segment offset out of range")?;
        let p_filesz = rd_u64(bytes, off.checked_add(32).ok_or("overflow")?)
            .ok_or("note segment size out of range")?;
        let end = p_offset
            .checked_add(p_filesz)
            .ok_or("note segment overflows")?;
        if end > bytes.len() {
            return Err("note segment out of bounds".into());
        }
        let mut pos = p_offset;
        while pos.checked_add(12).is_some_and(|header_end| header_end <= end) {
            let namesz = rd_u32(bytes, pos).ok_or("truncated note")? as usize;
            let descsz = rd_u32(bytes, pos + 4).ok_or("truncated note")? as usize;
            let ntype = rd_u32(bytes, pos + 8).ok_or("truncated note")?;
            let name_start = pos + 12;
            let name_end = name_start.checked_add(namesz).ok_or("note overflows")?;
            let desc_start = name_start
                .checked_add(align4(namesz).ok_or("note overflows")?)
                .ok_or("note overflows")?;
            let desc_end = desc_start.checked_add(descsz).ok_or("note overflows")?;
            if name_end > end || desc_end > end {
                return Err("truncated note".into());
            }
            if ntype == NOTE_TYPE && bytes[name_start..name_end] == NOTE_NAME[..] {
                found.push(&bytes[desc_start..desc_end]);
            }
            pos = desc_start
                .checked_add(align4(descsz).ok_or("note overflows")?)
                .ok_or("note overflows")?;
        }
    }
    match found.as_slice() {
        [] => Err("no literoot stamp note".into()),
        [desc] => decode(desc),
        _ => Err(format!(
            "{} literoot stamp notes (exactly one is allowed)",
            found.len()
        )),
    }
}

fn decode(desc: &[u8]) -> Result<Stamp, String> {
    if desc.len() != DESC_LEN {
        return Err(format!(
            "stamp descriptor is {} bytes, expected {DESC_LEN}",
            desc.len()
        ));
    }
    if desc[..9] != MAGIC[..] {
        return Err("stamp magic differs".into());
    }
    let field = |at: usize| rd_u32(desc, at).ok_or("truncated stamp descriptor");
    let stamp_version = field(9)?;
    if stamp_version != STAMP_VERSION {
        return Err(format!(
            "stamp_version {stamp_version} is unknown (this launcher reads {STAMP_VERSION})"
        ));
    }
    Ok(Stamp {
        stamp_version,
        protocol_version: field(13)?,
        flavour: field(17)?,
    })
}

/// Equality with the launcher's record for the selected flavour. The
/// error names the field that differs.
pub fn check(stamp: &Stamp, protocol_version: u32, flavour: u32) -> Result<(), String> {
    if stamp.protocol_version != protocol_version {
        return Err(format!(
            "protocol_version differs: preload {:#010x}, this launcher {:#010x}",
            stamp.protocol_version, protocol_version
        ));
    }
    if stamp.flavour != flavour {
        return Err(format!(
            "flavour differs: preload {} ({}), this launch needs {} ({})",
            stamp.flavour,
            flavour_name(stamp.flavour),
            flavour,
            flavour_name(flavour)
        ));
    }
    Ok(())
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest.iter() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// The single git revision Cargo.lock pins for `krate`, if exactly one.
fn locked_revision(cargo_lock: &str, krate: &str) -> Option<String> {
    let want = format!("name = \"{krate}\"");
    let mut in_package = false;
    let mut revisions: Vec<String> = Vec::new();
    for line in cargo_lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_package = false;
        } else if line == want {
            in_package = true;
        } else if in_package {
            if let Some(source) = line.strip_prefix("source = \"") {
                if let Some((_, rev)) = source.trim_end_matches('"').rsplit_once('#') {
                    revisions.push(rev.to_owned());
                }
                in_package = false;
            }
        }
    }
    revisions.sort();
    revisions.dedup();
    if revisions.len() == 1 {
        revisions.pop()
    } else {
        None
    }
}

/// The pinned Reverie revisions, one `crate=rev` line each.
pub fn reverie_revisions(cargo_lock: &str) -> Result<String, String> {
    let mut out = String::new();
    for krate in REVERIE_CRATES {
        let rev = locked_revision(cargo_lock, krate)
            .ok_or_else(|| format!("Cargo.lock pins no single git revision for {krate}"))?;
        let _ = writeln!(out, "{krate}={rev}");
    }
    Ok(out)
}

/// `protocol_version` over already-read inputs: each file framed as path
/// bytes, NUL, u64 LE length, content; then the Reverie revisions; then
/// the layout constant.
pub fn protocol_version_of(files: &[(&str, Vec<u8>)], cargo_lock: &str) -> Result<u32, String> {
    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.update(reverie_revisions(cargo_lock)?.as_bytes());
    hasher.update(LAYOUT);
    let digest = hasher.finalize();
    Ok(u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]))
}

/// `protocol_version` for the package rooted at `root`.
pub fn protocol_version(root: &Path) -> Result<u32, String> {
    let mut files = Vec::with_capacity(STAMP_FILES.len());
    for rel in STAMP_FILES {
        let bytes = std::fs::read(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))?;
        files.push((rel, bytes));
    }
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|e| format!("read Cargo.lock: {e}"))?;
    protocol_version_of(&files, &lock)
}

/// The root and preload lockfiles must pin the same Reverie revisions.
pub fn check_lock_agreement(root: &Path) -> Result<(), String> {
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))
    };
    let outer = reverie_revisions(&read("Cargo.lock")?)?;
    let inner = reverie_revisions(&read("preload/Cargo.lock")?)
        .map_err(|e| format!("preload/{e}"))?;
    if outer != inner {
        return Err(format!(
            "Cargo.lock and preload/Cargo.lock pin different Reverie revisions:\n{outer}versus\n{inner}"
        ));
    }
    Ok(())
}
