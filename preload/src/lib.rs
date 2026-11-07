//! literoot in-guest preload: compiles the identical `RootfsTool`
//! into the guest. Two hosting flavours, selected by Cargo feature
//! with the same code on every architecture:
//!
//! * `liteinst` (default): Reverie's liteinst backend — patched
//!   syscall sites call the Tool directly; unpatched raw syscalls
//!   reach it through the in-guest SIGSYS (seccomp trap) fallback.
//!   Site patching is selected by the launcher via
//!   `REVERIE_LITEINST_SITE_PATCHING` (1=patched, 0=trap-only).
//! * `inguest-trap`: Reverie's TrapHost API — every trapped syscall
//!   runs through the fallback continuation, zero ptrace and no
//!   reverie-liteinst in the graph at all.

#[path = "../../src/arch.rs"]
mod arch;
#[path = "../../src/exec_state.rs"]
mod exec_state;
#[path = "../../src/translate.rs"]
mod translate;
#[path = "../../src/rootfs_tool.rs"]
mod rootfs_tool;

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

#[cfg(feature = "liteinst")]
reverie_liteinst::declare_legacy_scoped_tool_allocator!();

#[cfg(feature = "inguest-trap")]
#[global_allocator]
static GLOBAL: reverie_inguest::guest::alloc::GuestAllocator =
    reverie_inguest::guest::alloc::GuestAllocator;

#[used]
#[unsafe(link_section = ".init_array")]
static LITEROOT_INIT: unsafe extern "C" fn(
    libc::c_int,
    *mut *mut libc::c_char,
    *mut *mut libc::c_char,
) = initialize;

unsafe fn loaded_as_preload() -> bool {
    let mut info = MaybeUninit::<libc::Dl_info>::uninit();
    let found = unsafe {
        libc::dladdr(
            initialize as *const () as *const libc::c_void,
            info.as_mut_ptr(),
        )
    };
    if found == 0 {
        return false;
    }
    let info = unsafe { info.assume_init() };
    if info.dli_fname.is_null() {
        return false;
    }
    let mapped_name = unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes();
    if mapped_name.is_empty() {
        return false;
    }
    let mapped_path = Path::new(std::ffi::OsStr::from_bytes(mapped_name));
    match (mapped_path.canonicalize(), std::env::current_exe()) {
        (Ok(mapped_path), Ok(executable)) => mapped_path != executable,
        _ => false,
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("literoot-preload: {msg}");
    std::process::abort()
}

unsafe extern "C" fn initialize(
    _argc: libc::c_int,
    _argv: *mut *mut libc::c_char,
    _environment: *mut *mut libc::c_char,
) {
    if !unsafe { loaded_as_preload() } {
        return;
    }
    #[cfg(feature = "inguest-trap")]
    {
        let bootstrap = match unsafe { reverie_inguest::bootstrap::take_preload_bootstrap() } {
            Ok(Some(bootstrap)) => bootstrap,
            Ok(None) => return,
            Err(error) => fail(&format!("invalid preload bootstrap: {error}")),
        };
        let selected = match String::from_utf8(bootstrap.tool_data) {
            Ok(selected) => selected,
            Err(_) => fail("tool selector is not valid UTF-8"),
        };
        let socket = bootstrap.coordinator;
        let result = match selected.as_str() {
            "literoot" => unsafe {
                reverie_inguest::guest::tool_install::install_tool_with::<
                    rootfs_tool::RootfsTool,
                    _,
                >(
                    &socket,
                    false,
                    reverie_inguest::guest::tool_install::TrapHost::new(
                        reverie_inguest::guest::tool_install::TrapOptions::default(),
                    ),
                )
            },
            other => fail(&format!(
                "unknown tool selector {other:?} (expected \"literoot\")"
            )),
        };
        if let Err(error) = result {
            fail(&format!("install literoot tool: {error}"));
        }
    }
    #[cfg(not(feature = "inguest-trap"))]
    {
        let bootstrap = match unsafe { reverie_liteinst::take_preload_bootstrap() } {
            Ok(Some(bootstrap)) => bootstrap,
            Ok(None) => return,
            Err(error) => fail(&format!("invalid preload bootstrap: {error}")),
        };
        let selected = match String::from_utf8(bootstrap.tool_data) {
            Ok(selected) => selected,
            Err(_) => fail("tool selector is not valid UTF-8"),
        };
        let socket = bootstrap.coordinator;
        let result = match selected.as_str() {
            "literoot" => unsafe {
                reverie_liteinst::install_tool_from_bootstrap::<rootfs_tool::RootfsTool>(&socket)
            },
            other => fail(&format!(
                "unknown tool selector {other:?} (expected \"literoot\")"
            )),
        };
        if let Err(error) = result {
            fail(&format!("install literoot tool: {error}"));
        }
    }
}
