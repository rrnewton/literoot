//! The mapped first image's initializer (row d addendum, revision 3).
//!
//! The G2 C-ABI entry (`literoot_mapped_initial_entry`, later work) will live
//! in `mapped_entry.rs` and call this after capture, private libc
//! initialization, region adoption and tool-init enablement. Every decision
//! is in `initial_packet::admit_initial`, which host tests reach; this is a
//! fixed call chain plus the carriage conversion.

use std::os::unix::ffi::OsStrExt as _;

use reverie_inguest::guest::exec_private::mapped_initial::MappedToolPrelude;
use reverie_inguest::guest::exec_private::mapped_initial::mapped_scalar::CoordinatorPathError;
use reverie_inguest::guest::rpc::GuestRpcStream;

use crate::initial_packet;
use crate::initial_packet::Carriage;
use crate::reporting::ReportingTool;

/// Converts the sealed table-4 coordinator carriage. Only `Err(Absent)` is
/// absent; `Duplicate`, `Empty` and `Format` refuse by Reverie's name. No
/// `_` arm and no `.ok()`, so a new Reverie variant must be classified here.
fn carriage(read: &Result<std::path::PathBuf, CoordinatorPathError>) -> Carriage<'_> {
    match read {
        Ok(path) => Carriage::Present(path.as_os_str().as_bytes()),
        Err(CoordinatorPathError::Absent) => Carriage::Absent,
        Err(
            error @ (CoordinatorPathError::Duplicate
            | CoordinatorPathError::Empty
            | CoordinatorPathError::Format(_)),
        ) => Carriage::Malformed(error.name()),
    }
}

/// Initializes the mapped first image from its captured, adopted prelude.
///
/// Order: the straddler selector first (before anything is admitted); then
/// `admit_initial` (packet decode, fingerprint before connect, carriage
/// check, connect and top-band placement, redemption with the packet's
/// digest, Config qualification); then prepare, install, lifecycle, finish.
/// The connection is reserved once, by installation (tool_host.rs:1598).
///
/// # Safety
/// The caller retains every capture and adoption obligation that produced
/// `mapped`, the stopped generation and host terminal owner, and real
/// private libc/TLS/FD cleanup. No guest instruction has run in this image.
/// Errors are terminal for this image; the entry must not fall back.
pub unsafe fn literoot_mapped_initial_initialize(mapped: MappedToolPrelude) -> std::io::Result<()> {
    let straddler = reverie_liteinst::validate_straddler_selector()?;
    let read = mapped.coordinator_path();
    let tid = reverie::Pid::from_raw(mapped.native_tid());
    let admitted = initial_packet::admit_initial(mapped.packet(), carriage(&read), tid, |path| {
        initial_packet::connect_coordinator(path).map(GuestRpcStream::from)
    })
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let initial_packet::Admitted {
        client,
        coordinator,
    } = admitted;
    // The image's own later execs stage through the packet's coordinator.
    crate::exec_stage::set_coordinator_path(coordinator.clone());
    // SAFETY: the straddler token was obtained before the client was
    // redeemed above, and the caller holds every prepare obligation.
    let prepared = unsafe {
        reverie_liteinst::prepare_tool_mapped_initial_image_validated::<ReportingTool>(
            straddler, client, mapped,
        )
    }?;
    // SAFETY: `prepared` holds the same authenticated client and control.
    let installed =
        unsafe { reverie_liteinst::install_tool_initial_image(&coordinator, prepared) }?;
    reverie_liteinst::initialize_initial_image_lifecycle(&installed)?;
    installed.finish()
}
