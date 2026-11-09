//! Launcher-side exec staging seam.
//!
//! The mapped successor mailbox is staged only by the in-guest
//! preload on the mapped route. The host/ptrace build of
//! `RootfsTool` keeps today's pending-slot behavior, so this
//! host-side twin accepts the call and does nothing.

use std::path::PathBuf;

/// Record the coordinator endpoint for mapped staging. The
/// host build never stages to a mailbox, so this is a no-op.
pub fn set_coordinator_path(_path: PathBuf) {}

/// Stage one encoded exec snapshot. Host builds do not use the
/// mapped successor mailbox; the pending slot remains the
/// continuity carrier on those routes.
pub fn stage_snapshot(_encoded: Vec<u8>) -> Result<(), reverie::syscalls::Errno> {
    Ok(())
}

/// Invalidate a staged exec snapshot after a failed inject.
/// Host builds staged nothing, so there is nothing to undo.
pub fn invalidate_snapshot() -> Result<(), reverie::syscalls::Errno> {
    Ok(())
}
