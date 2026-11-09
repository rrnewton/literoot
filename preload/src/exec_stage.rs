//! In-guest mapped-successor staging client.
//!
//! On the mapped route the predecessor stages its framed
//! `ExecState` into the host birth authority's one-slot mailbox
//! over a fresh accepted stage connection and only then injects
//! exec. The guest supplies no birth key, pid, ordinal, or
//! ticket; the server derives the admitted birth from the
//! connection. Staging is enabled only when the mapped entry
//! records the coordinator endpoint; on every other route this
//! module is inert and the pending slot remains the carrier.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

static COORDINATOR: OnceLock<PathBuf> = OnceLock::new();
static STAGED: AtomicBool = AtomicBool::new(false);

/// Record the coordinator endpoint for mapped staging. The
/// first mapped entry wins; a successor image starts fresh, so
/// this is set exactly once per image in production.
pub fn set_coordinator_path(path: PathBuf) {
    let _ = COORDINATOR.set(path);
}

#[cfg(feature = "successor")]
fn map_control_error(
    error: reverie_rpc_transport::exec_ticket::ExecControlError,
) -> reverie::syscalls::Errno {
    use reverie_rpc_transport::exec_ticket::ExecControlError;
    match error {
        ExecControlError::Bounds | ExecControlError::Capacity => reverie::syscalls::Errno::E2BIG,
        ExecControlError::Unavailable | ExecControlError::Transition => {
            reverie::syscalls::Errno::EOPNOTSUPP
        }
        ExecControlError::Identity | ExecControlError::Digest | ExecControlError::Qualification => {
            reverie::syscalls::Errno::EPERM
        }
        ExecControlError::Dead => reverie::syscalls::Errno::EIO,
    }
}

#[cfg(feature = "successor")]
fn invalidate_now() -> Result<(), reverie::syscalls::Errno> {
    client()?.invalidate().map_err(map_control_error)?;
    STAGED.store(false, Ordering::SeqCst);
    Ok(())
}

#[cfg(feature = "successor")]
fn client() -> Result<
    reverie_rpc_transport::birth_authority::StageClient<std::os::unix::net::UnixStream>,
    reverie::syscalls::Errno,
> {
    let path = COORDINATOR
        .get()
        .ok_or(reverie::syscalls::Errno::EOPNOTSUPP)?;
    let stream =
        std::os::unix::net::UnixStream::connect(path).map_err(|_| reverie::syscalls::Errno::EIO)?;
    Ok(reverie_rpc_transport::birth_authority::StageClient::new(
        stream,
    ))
}

/// Stage one encoded exec snapshot and wait for the host ack.
/// Returns `Ok(())` without staging when the mapped route did
/// not record a coordinator endpoint.
pub fn stage_snapshot(encoded: Vec<u8>) -> Result<(), reverie::syscalls::Errno> {
    #[cfg(not(feature = "successor"))]
    {
        let _ = encoded;
        Ok(())
    }
    #[cfg(feature = "successor")]
    {
        if COORDINATOR.get().is_none() {
            return Ok(());
        }
        let framed = reverie_rpc_transport::birth_authority::frame_tool_state(&encoded).map_err(
            |error| {
                if error.raw_os_error() == Some(libc::E2BIG) {
                    reverie::syscalls::Errno::E2BIG
                } else {
                    reverie::syscalls::Errno::EIO
                }
            },
        )?;
        match client()?.stage_snapshot(framed) {
            Ok(()) => {
                STAGED.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                // The ack may have been lost after the host staged
                // the snapshot. Best-effort invalidate on a fresh
                // connection so a failed exec never leaves the
                // mailbox armed; the original refusal still wins.
                let _ = invalidate_now();
                Err(map_control_error(error))
            }
        }
    }
}

/// Invalidate a staged snapshot after a failed exec inject.
/// No-op unless a previous `stage_snapshot` in this image was
/// acked; on failure the staged flag stays set so the caller
/// can fail closed instead of treating the mailbox as clear.
pub fn invalidate_snapshot() -> Result<(), reverie::syscalls::Errno> {
    #[cfg(not(feature = "successor"))]
    {
        Ok(())
    }
    #[cfg(feature = "successor")]
    {
        if !STAGED.load(Ordering::SeqCst) {
            return Ok(());
        }
        invalidate_now()
    }
}

#[cfg(all(test, feature = "successor"))]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;

    use reverie_rpc_transport::Admitted;
    use reverie_rpc_transport::birth_authority::BirthAuthority;
    use reverie_rpc_transport::birth_authority::serve_stage_snapshot;

    use super::*;

    fn temp_socket(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "literoot-exec-stage-{}-{name}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn stages_and_invalidates_through_real_stage_server() {
        let path = temp_socket("stage");
        let listener = UnixListener::bind(&path).unwrap();
        let admitted = Admitted {
            process_id: std::process::id() as i32,
        };
        let authority = Arc::new(
            BirthAuthority::new(admitted, [7; 32], b"initial-redemption".to_vec(), [9; 32])
                .unwrap(),
        );
        authority.record_initial_consumed(admitted).unwrap();
        let server_authority = Arc::clone(&authority);
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                serve_stage_snapshot(stream, &server_authority, admitted).unwrap();
            }
        });
        set_coordinator_path(path.clone());
        stage_snapshot(b"exec-state".to_vec()).unwrap();
        invalidate_snapshot().unwrap();
        // A second invalidate is inert: the staged flag was
        // cleared by the acked invalidate above.
        invalidate_snapshot().unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
    }
}
