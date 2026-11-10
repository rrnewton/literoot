//! The writer half of the refusal side log (`--refusal-log <path>`),
//! shared by the launcher and the in-guest preload. The launcher opens the
//! file (`crate::side_log`, launcher only) and every literoot refusal it
//! hears of is written here as one line of the side log's closed grammar.
//! In a guest process the log is never open: there [`write_line`] does
//! nothing and [`is_open`] is false.

use std::fs::File;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// The launcher's side log, set once by `side_log::open`.
pub(crate) static LOG: OnceLock<File> = OnceLock::new();
/// Set when any write to the side log failed or was short.
pub(crate) static FAILED: AtomicBool = AtomicBool::new(false);

/// Whether this process holds the side log (the launcher, when the option
/// was given).
pub fn is_open() -> bool {
    LOG.get().is_some()
}

/// Append one line (without its `\n`) in a single `write(2)`. Without a
/// log this writes nothing; a short or failed write marks the log failed,
/// which the launcher reports in its `end` line and exit status.
pub fn write_line(line: &str) {
    use std::io::Write as _;
    let Some(mut file) = LOG.get() else {
        return;
    };
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    match file.write(&buf) {
        Ok(n) if n == buf.len() => {}
        _ => FAILED.store(true, Ordering::SeqCst),
    }
}
