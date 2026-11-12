//! Physical first entry of the mapped successor musl image.
//! The host supervisor selects this symbol only for a successor
//! generation (entry-route selection, never packet-magic
//! sniffing); it consumes the same capture/adoption mechanisms
//! as every mapped image and stops at the observed INT3 after
//! the successor initializer returns. It never resumes guest.

use reverie_inguest::guest::exec_private::NativeControl;
use reverie_inguest::guest::exec_private::mapped_initial;
use reverie_inguest::guest::exec_private::mapped_initial::libc_relay::RelayStorage;

// A target-produced scalar descriptor, never an owner/readiness
// credential. The final ELF must independently prove this exact
// symbol is retained immutable RO.
#[used]
#[unsafe(export_name = "literoot_mapped_layout")]
#[unsafe(link_section = ".rodata.literoot_mapped_layout")]
static MAPPED_LAYOUT: [u64; 12] = [
    u64::from_le_bytes(*b"HLMLAY01"),
    1,
    96,
    mapped_initial::MAPPED_INPUT_VERSION,
    mapped_initial::MAPPED_INPUT_HEADER_BYTES as u64,
    mapped_initial::MAPPED_INPUT_MAX_BYTES as u64,
    core::mem::size_of::<NativeControl>() as u64,
    core::mem::align_of::<NativeControl>() as u64,
    core::mem::size_of::<RelayStorage>() as u64,
    core::mem::align_of::<RelayStorage>() as u64,
    reverie_inguest::trap::FIXED_GATE_BASE,
    reverie_inguest::trap::FIXED_NATIVE_ENTRY,
];

// No raw_syscall selector, diagnostic or libc call before gate
// publication. The existing terminal's control argument is
// unused and grants no authority.
unsafe fn terminal() -> ! {
    // SAFETY: the entry's physical host contract already owns
    // the exact selected gate/filter even before Rust adoption;
    // null is not a NativeControl origin.
    unsafe { reverie_inguest::guest::exec_private::initialization_failed(core::ptr::null_mut()) }
}

/// Numeric slice preconditions only, via the shared
/// `reverie-loader` predicate re-exported through
/// `mapped_initial` (Reverie main; its tests execute on GNU).
fn valid_input_range(address: usize, bytes: usize) -> bool {
    mapped_initial::valid_mapped_input_range(address, bytes)
}

/// Actual C-ABI successor entry before private TLS. It never
/// returns or resumes guest.
///
/// # Safety
/// Only the trusted host of this exact genuinely stopped
/// successor exec may call, having spent its affine generation
/// transition and retained pidfd/ChildOwner kill/wait
/// authority, the exact successful no-replace full reservation,
/// source-qualified sealed loader/runtime and immutable final
/// ELF mappings, independent RO gate reference, selected fixed
/// RX gate and admitted filter. No guest instruction or
/// private constructor has executed. All bootstrap code before
/// TLS must be independently qualified
/// nonallocating/non-TLS/nonunwinding/noninterposable. The
/// host owns an adequately sized guarded key0 private stack,
/// C-ABI entry alignment, accessible state, DF clear and
/// actual memory permissions. Original FS/mask/registrations
/// remain unchanged for capture. `ptr..ptr+len` is one valid
/// immutable retained whole scalar blob for this linked
/// consumer, actually mapped RO in its handoff role for the
/// process lifetime, with header, code/site provenance,
/// original registers/mask/PKRU, env/aux/TLS/PHDR facts and
/// every role/FD lease from this same birth. The host's
/// complete numeric predicate has accepted these same bytes
/// before any child mutation. Errors, panic or abandonment
/// are terminal under the same host; never unwind, retry,
/// reset, fall back to guest libc, or release guest here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn literoot_mapped_successor_entry(ptr: *const u8, len: usize) -> ! {
    if !valid_input_range(ptr as usize, len) {
        unsafe { terminal() }
    }
    // SAFETY: only the physical host contract above establishes
    // actual backing, complete RO lifetime and exclusive source;
    // numeric bounds are insufficient.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(ptr, len) };
    let captured = match unsafe { mapped_initial::capture(bytes) } {
        Ok(value) => value,
        Err(_) => unsafe { terminal() },
    };
    let relay = unsafe { captured.install_libc_relay() };
    let captured = unsafe { relay.initialize_private_libc() };
    let mapped = match unsafe { captured.adopt_region() } {
        Ok(value) => value,
        Err(_) => unsafe { terminal() },
    };
    let mapped = match unsafe { mapped.enable_tool_init() } {
        Ok(value) => value,
        Err(_) => unsafe { terminal() },
    };
    // SAFETY: exact same affine physical owner, actual
    // libc/TLS/FD cleanup and adoption, per the initializer's
    // entry contract.
    if unsafe { crate::literoot_mapped_successor_initialize(mapped) }.is_err() {
        unsafe { terminal() }
    }
    // Reachable only after the initializer returned through its
    // existing successful finish path. The host treats the INT3
    // as observation, not permission to resume guest here.
    unsafe { observe_initializer_return() }
}

// Exact architecture-owned observation cut; no Rust runs after
// its INT3. A mistaken host resume reaches the existing actual
// selected-gate terminal.
#[unsafe(naked)]
unsafe extern "C" fn observe_initializer_return() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        ".global literoot_mapped_successor_entry_observed_int3",
        ".hidden literoot_mapped_successor_entry_observed_int3",
        "literoot_mapped_successor_entry_observed_int3:",
        "int3",
        "xor edi,edi",
        "jmp {terminal}",
        terminal = sym reverie_inguest::guest::exec_private::initialization_failed,
    );
}
core::arch::global_asm!(".protected literoot_mapped_successor_entry");

#[cfg(test)]
mod tests {
    use super::*;

    /// The input cap is Reverie's `handoff::MAX_BYTES`, re-exported as
    /// `MAPPED_INPUT_MAX_BYTES`. Reverie 0134d15cf9e raised it from 1 MiB to
    /// 6_348_827 (header + maximum tables + maximum strings + auxv slack;
    /// reverie-loader handoff.rs). The literal pins that value, so a
    /// change in Reverie fails here and is reviewed rather than followed.
    const INPUT_CAP: usize = 6_348_827;

    #[test]
    fn mapped_entry_input_cap_is_reveries_handoff_bound() {
        assert_eq!(mapped_initial::MAPPED_INPUT_MAX_BYTES, INPUT_CAP);
    }

    #[test]
    fn mapped_entry_bounds_accept_complete_header_and_cap() {
        let address = 0x6000_1000_0000;
        assert!(valid_input_range(address, 960));
        assert!(valid_input_range(address, 1024 * 1024));
        assert!(valid_input_range(address, INPUT_CAP));
    }

    /// HLMLAY01 decoded and checked as Reverie's producer does in
    /// `AuditedRuntimeImage::new` (reverie-inguest
    /// launcher/exec_stop/producer.rs:251-274 at ac8b35c2): twelve
    /// little-endian words from the 96 bytes. Words 3-5 are P's
    /// `handoff::{VERSION, HEADER_BYTES, MAX_BYTES}`, which
    /// `mapped_initial` re-exports under these names; word 10 is P's
    /// `NATIVE_GATE.start`, `RUNTIME_WINDOW.start + PAGE` (producer.rs:99,
    /// reverie-loader artifact.rs:65). The literal P check, on the real
    /// ELF, is d2's `AuditedRuntimeImage::new` acceptance.
    #[test]
    fn the_layout_decodes_as_the_producer_checks_it() {
        let raw: Vec<u8> = MAPPED_LAYOUT.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(raw.len(), 96);
        let mut d = [0u64; 12];
        for (out, row) in d.iter_mut().zip(raw.chunks_exact(8)) {
            *out = u64::from_le_bytes(row.try_into().unwrap());
        }
        assert_eq!(
            d[..6],
            [
                u64::from_le_bytes(*b"HLMLAY01"),
                1,
                96,
                mapped_initial::MAPPED_INPUT_VERSION,
                mapped_initial::MAPPED_INPUT_HEADER_BYTES as u64,
                mapped_initial::MAPPED_INPUT_MAX_BYTES as u64,
            ]
        );
        assert!(d[6] > 0 && d[8] > 0);
        assert!(d[7].is_power_of_two() && d[9].is_power_of_two());
        assert_eq!(d[10], 0x6000_e100_0000 + 4096);
        assert_eq!(d[11], d[10] + 0x7c);
    }

    #[test]
    fn mapped_entry_bounds_refuse_null_alignment_short_excess_and_wrap() {
        let address = 0x6000_1000_0000;
        for (pointer, bytes) in [
            (0, 960),
            (address + 1, 960),
            (address, 0),
            (address, 959),
            (address, INPUT_CAP + 1),
            (usize::MAX - 7, 960),
            ((isize::MAX as usize) & !7, 960),
            (address, usize::MAX),
        ] {
            assert!(!valid_input_range(pointer, bytes));
        }
    }
}
