//! Physical first entry of the mapped first image (the initial generation).
//! The host supervisor selects this symbol only for a first generation
//! (entry-route selection, never packet-magic sniffing); it consumes the same
//! capture/adoption mechanisms as the successor entry in `mapped_entry.rs`
//! and stops at its own observed INT3 after the first-image initializer
//! returns. It never resumes guest.
//!
//! The image's HLMLAY01 layout descriptor is the one in `mapped_entry.rs`:
//! one descriptor per image, shared by both generations.

use reverie_inguest::guest::exec_private::mapped_initial;

// No raw_syscall selector, diagnostic or libc call before gate
// publication. The existing terminal's control argument is
// unused and grants no authority.
//
// The factory finds this generation's terminal by its v0 name, so it
// must stay its own function. Its callers are in the exported entry
// below; `inline(never)` keeps those calls as calls. The empty marker
// gives the body its own IR, so LLVM's function merging cannot fold it
// into the successor's terminal in mapped_entry.rs, whose machine code
// is identical (a build with overflow checks off did exactly that). The
// marker emits no instruction.
#[inline(never)]
unsafe fn terminal() -> ! {
    // SAFETY: an assembler comment only: no instruction, and no memory,
    // stack or flags effect.
    unsafe {
        core::arch::asm!(
            "/* literoot first-image terminal */",
            options(nomem, nostack, preserves_flags)
        )
    };
    // SAFETY: the entry's physical host contract already owns
    // the exact selected gate/filter even before Rust adoption;
    // null is not a NativeControl origin.
    unsafe { reverie_inguest::guest::exec_private::initialization_failed(core::ptr::null_mut()) }
}

/// Actual C-ABI first-image entry before private TLS. It never
/// returns or resumes guest.
///
/// # Safety
/// Only the trusted host of this exact genuinely stopped
/// first-image exec may call, having spent its affine generation
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
pub unsafe extern "C" fn literoot_mapped_initial_entry(ptr: *const u8, len: usize) -> ! {
    if !mapped_initial::valid_mapped_input_range(ptr as usize, len) {
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
    if unsafe { crate::initial_image::literoot_mapped_initial_initialize(mapped) }.is_err() {
        unsafe { terminal() }
    }
    // Reachable only after the initializer returned through its
    // existing successful finish path. The host treats the INT3
    // as observation, not permission to resume guest here.
    unsafe { observe_initializer_return() }
}

// Exact architecture-owned observation cut; no Rust runs after
// its INT3. A mistaken host resume reaches the existing actual
// selected-gate terminal. Its own body and label: one observer
// body carries exactly one label, so the two generations need
// two bodies.
#[unsafe(naked)]
unsafe extern "C" fn observe_initializer_return() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        ".global literoot_mapped_initial_entry_observed_int3",
        ".hidden literoot_mapped_initial_entry_observed_int3",
        "literoot_mapped_initial_entry_observed_int3:",
        "int3",
        "xor edi,edi",
        "jmp {terminal}",
        terminal = sym reverie_inguest::guest::exec_private::initialization_failed,
    );
}
core::arch::global_asm!(".protected literoot_mapped_initial_entry");
