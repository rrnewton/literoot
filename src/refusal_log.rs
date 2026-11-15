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

#[cfg(test)]
thread_local! {
    /// Test sink: when set, [`is_open`] is true on the calling thread and
    /// [`write_line`] appends its line here instead of to a file.
    pub(crate) static SINK: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Whether this process holds the side log (the launcher, when the option
/// was given).
pub fn is_open() -> bool {
    #[cfg(test)]
    if SINK.with(|s| s.borrow().is_some()) {
        return true;
    }
    LOG.get().is_some()
}

/// Append one line (without its `\n`) in a single `write(2)`. Without a
/// log this writes nothing; a short or failed write marks the log failed,
/// which the launcher reports in its `end` line and exit status.
pub fn write_line(line: &str) {
    use std::io::Write as _;
    #[cfg(test)]
    if SINK.with(|s| s.borrow_mut().as_mut().map(|lines| lines.push(line.to_owned())).is_some()) {
        return;
    }
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

/// The launcher-assigned receipt ID of one process's exit-summary emission
/// (`receipt_id=` on the summary lines). Unique within the run, because one
/// launcher counter issues it and nothing guest-visible feeds it. It orders
/// receipt only: it is not a creation order and not a kernel identity, so
/// it is compared for equality only (no `PartialOrd`, no accessor to the
/// number). 0 is never issued: it renders an exhausted counter and a reader
/// counts it as identity-unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiptId(u64);

/// The next receipt to issue, starting at 1.
static NEXT_RECEIPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl ReceiptId {
    /// The identity-unknown receipt.
    pub const UNKNOWN: ReceiptId = ReceiptId(0);

    /// Whether this is the identity-unknown receipt.
    #[allow(dead_code)] // The side-log reader (launcher build) is its caller.
    pub fn is_unknown(self) -> bool {
        self == Self::UNKNOWN
    }

    /// The receipt ID of a parsed `receipt_id=` token: decimal, no sign, no
    /// leading zero except "0" itself.
    #[allow(dead_code)] // The side-log reader (launcher build) is its caller.
    pub fn parse(token: &str) -> Option<ReceiptId> {
        let canonical = token == "0" || (!token.starts_with('0') && !token.is_empty());
        if !canonical || !token.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        token.parse().ok().map(ReceiptId)
    }
}

impl std::fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Issue the receipt for one process's exit-summary emission: the single
/// source of `receipt_id` (an in-guest batch at the launcher, a ptrace
/// process at its exit). An exhausted counter gives [`ReceiptId::UNKNOWN`]
/// rather than wrapping.
pub fn next_summary_receipt() -> ReceiptId {
    use std::sync::atomic::Ordering::Relaxed;
    match NEXT_RECEIPT.fetch_update(Relaxed, Relaxed, |n| n.checked_add(1)) {
        Ok(n) if n != 0 => ReceiptId(n),
        _ => ReceiptId::UNKNOWN,
    }
}
