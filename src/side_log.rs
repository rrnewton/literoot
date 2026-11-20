//! The launcher side log (`--refusal-log <path>`): one file
//! the launcher owns, into which refusals and initial-stack cap
//! records are written as one line each of a closed grammar, so a
//! suite driver can tell "nothing was refused" from "something was
//! refused" and from "not measured".
//!
//! The launcher opens the file before anything can refuse or spawn:
//! append and create (`O_WRONLY|O_APPEND|O_CREAT`; std adds `O_CLOEXEC`),
//! never truncated, so several invocations for one test name (and nested
//! literoot runs) append to the same file. The descriptor stays in the
//! launcher-process static of `crate::refusal_log`, which writes each line
//! in one `write(2)` and marks the log failed on a short or failed write;
//! the launcher reports that in its `end` line and its exit status. The
//! path never enters the guest's config or environment.
//!
//! Grammar (ASCII, single spaces, no trailing space, `\n`-terminated):
//! - `literoot: begin <pid>`
//! - `literoot: end <pid> ok` | `literoot: end <pid> error <token>`,
//!   token in [`END_ERRORS`]
//! - `literoot: route <label>`, label in [`ROUTES`]
//! - `literoot: refused exec`
//! - `literoot: refused fork_policy <kind>`, kind in [`FORK_KINDS`]
//! - `literoot: refused signal_action <n>`, n the kernel signal number,
//!   1..=64, in decimal
//! - `literoot: refused alternate_stack`
//! - `literoot: refused unsupported <kind>`, kind in [`UNSUPPORTED`]
//! - `literoot: refused guest <kind>`, kind in [`GUEST`]
//! - `literoot: refused launcher <token>`, token in [`LAUNCHER`]
//! - `literoot: refused path <kind>`, kind in [`PATH`]
//! - `literoot: answered path <kind>`, kind in [`ANSWERED`] (a native
//!   answer literoot gave, not a refusal)
//! - `literoot: refused seccomp_install probes_in_flight in_flight=<k>`, k
//!   in decimal (a guest seccomp filter install refused at once)
//! - `literoot: guest seccomp filter install attempted`,
//!   `literoot: note sud_absent`, `literoot: note
//!   sud_absent_boot_config_advisory` (absent on /boot/config-<release>'s
//!   word: advisory, /boot may be stale), and `literoot: sud config read
//!   unavailable errno=<e>`, e in [`SUD_FALLBACK_ERRNOS`] (notes, not
//!   refusals)
//! - `literoot: guest seccomp filter summary pid=<p> receipt_id=<r>
//!   kernel_id=<k> flag=<f> installs=<n> installs_refused=<n>
//!   translated=<n> refused=<n> unseen_best_effort=<n>`, f in
//!   [`FLAGS`], and `literoot: probe summary pid=<p> receipt_id=<r>
//!   kernel_id=<k> probes=<n> sud_refused=<n> sud_fallback=<n>` (a
//!   process's exit summaries, not refusals). `receipt_id` is the
//!   launcher-assigned receipt ID of the process's one exit-summary
//!   emission: unique within the run, it orders receipt only, not
//!   creation, and is compared for equality only. `pid` is the pid as the
//!   Tool saw it, a diagnostic. `kernel_id` is the pidfs inode (0 when
//!   unavailable): kernel metadata, not authenticated, not the identity.
//!   `unseen_best_effort` counts refusals by a best-effort detector,
//!   defeatable by a guest that jumps to a trusted gate.
//! - `literoot: capped initial_stack <reason> <old_cur> <old_max>
//!   <new_cur> <program>`, reason in [`CAP_REASONS`] (not a refusal)
//! - `literoot: scope <kind> <fixed text>`, one of the two exact lines of
//!   [`ScopeKind`] (C5.6): written once each by the launcher on the trap
//!   and liteinst backends, never on ptrace (not refusals)
//!
//! A log is valid for one test name only if every line parses, there is at
//! least one `begin`, and every `begin` has a matching `end <pid> ok`.

use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;

use crate::refusal_log;

/// `end ... error` tokens: `log_write`, a side-log write failed or was
/// short; `launch`, the in-guest launch returned an error, which includes
/// Reverie's refusal to return while a coordinator connection is still
/// open after the root guest exits. `connections_open` is in the grammar
/// for a launcher that can tell that case apart; this one cannot by type,
/// so it writes `launch`. `reporter`, an in-guest run in which no preload
/// process acknowledged refusal reporting: the launcher fails such a run
/// whether or not this log is open, and writes `reporter` only when the
/// launch itself did not fail (`launch` wins, src/main.rs). `stats_record`,
/// a requested stats record could not be written, or the run's measurement
/// cgroup could not be read or cleaned up (`run_stats`); the run's status
/// is then `STATS_RECORD_EXIT`, and this token outranks the others.
pub const END_ERRORS: &[&str] = &[
    "log_write",
    "connections_open",
    "launch",
    "reporter",
    "stats_record",
];
/// `route` labels.
pub const ROUTES: &[&str] = &["preload", "static_m2", "ptrace"];
/// `fork_policy` kinds: the record's five, `clone` split by `CLONE_THREAD`
/// only, `clone3` unsplit (its flags are not read).
pub const FORK_KINDS: &[&str] = &["clone_thread", "clone_process", "clone3", "fork", "vfork"];
/// `unsupported` kinds: two of Reverie's `UnsupportedOperation` variants
/// by name and `other` for every other variant except `Exec` (which is
/// `refused exec`); the enum is non-exhaustive.
pub const UNSUPPORTED: &[&str] = &["native_exec", "thread_creation", "other"];
/// `guest` kinds: refusals literoot's own Tool makes only in-guest.
pub const GUEST: &[&str] = &[
    "ptrace",
    "self_stop",
    "shared_record_publish",
    "nodename_write",
    "domainname_write",
    "kompat_auxv",
    "fake_id_auxv",
    "syscall_user_dispatch",
];
/// `capped initial_stack` reasons: why the initial stack cap was
/// applied (not a refusal; the run proceeds with the limit
/// restored after spawn).
pub const CAP_REASONS: &[&str] = &["exact_interp", "loader_identity"];
/// `launcher` tokens: launcher errors that refuse a run.
pub const LAUNCHER: &[&str] = &[
    "unlimited_stack_loader",
    "static_floor",
    "qemu_passthrough",
    "extension",
    "route_selection",
    "arming",
    "claim",
    "static_pie",
    "kill_on_exit",
    "refusal_log_repeated",
    // The in-guest preload's named refusals (src/preload_materialize.rs).
    "preload_digest",
    "cache_dir",
    "cache_write",
    "preload_stamp",
    "preload_probe",
    "preload_separator",
    "preload_missing",
    "not_built",
    "interp_not_guest",
    // The stats counter's per-run cgroup admission (src/run_stats.rs).
    "stats_cgroup",
    "other",
];
/// `path` kinds: path refusals by name (docs/design.md §4.9), the tokens
/// of `crate::translate::PathRefusal`.
pub const PATH: &[&str] = &[
    "base_uninspectable",
    "base_outside_root",
    "proc_link_outside_root",
    "proc_link_other_process",
    "base_moved",
    "no_guest_route",
    "probe_unsupported",
];
/// `answered path` kinds: native answers (not refusals), for a path in a
/// deleted directory, and the kernel's own cmdline file when literoot
/// cannot make the one it answers itself (the wire kind
/// `PathRefusal::SyntheticFileUnavailable`, rendered here).
pub const ANSWERED: &[&str] = &["dead_base_name", "dead_base_search", "synthetic_file_unavailable"];
/// The errnos of `sud config read unavailable`: the ptrace backend fell
/// back from the kernel's dispatch config to prctl tracking.
pub const SUD_FALLBACK_ERRNOS: &[&str] = &["EIO", "EINVAL", "ENOSYS"];
/// The seccomp summary's `flag=` tokens.
pub const FLAGS: &[&str] = &["none", "installed", "inherited"];
/// The seccomp summary's counter fields after `flag=`, in line order.
const SECCOMP_COUNTS: &[&str] = &[
    "installs",
    "installs_refused",
    "translated",
    "refused",
    "unseen_best_effort",
];
/// The probe summary's counter fields, in line order.
const PROBE_COUNTS: &[&str] = &["probes", "sud_refused", "sud_fallback"];

/// Open the side log at `path` for this launcher process. Called once,
/// before anything else can refuse or spawn. std opens with `O_CLOEXEC`,
/// so no guest inherits the descriptor.
pub fn open(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(path)?;
    refusal_log::LOG
        .set(file)
        .map_err(|_| io::Error::other("refusal log already open"))
}

/// Whether any write to the side log failed.
pub fn failed() -> bool {
    refusal_log::FAILED.load(Ordering::SeqCst)
}

/// `literoot: begin <pid>`, this launcher's first line.
pub fn begin() {
    refusal_log::write_line(&format!("literoot: begin {}", std::process::id()));
}

/// `literoot: end <pid> ok`, or `error <token>`; `log_write` wins when any
/// write failed (this last write may then fail too, which the exit status
/// still reports).
pub fn end(error: Option<&'static str>) {
    let pid = std::process::id();
    let error = if failed() { Some("log_write") } else { error };
    match error {
        None => refusal_log::write_line(&format!("literoot: end {pid} ok")),
        Some(token) => refusal_log::write_line(&format!("literoot: end {pid} error {token}")),
    }
}

/// `literoot: route <label>`.
pub fn route(label: &'static str) {
    refusal_log::write_line(&format!("literoot: route {label}"));
}

/// The two scope disclosures (C5.6): the best-effort checks of the
/// in-guest backends, with what defeats each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// C3.6's filter-count detector.
    Detector,
    /// The preload constructor's `Threads: 1` check and dispatch OFF call.
    ConstructorChecks,
}

impl ScopeKind {
    pub const ALL: [ScopeKind; 2] = [ScopeKind::Detector, ScopeKind::ConstructorChecks];

    /// The line after `literoot: `.
    pub fn text(self) -> &'static str {
        match self {
            ScopeKind::Detector => {
                "scope detector best-effort; defeatable by a guest that jumps to a trusted gate"
            }
            ScopeKind::ConstructorChecks => {
                "scope constructor-checks best-effort; defeatable by code that runs before the \
                 preload's constructor (LD_PRELOAD window)"
            }
        }
    }
}

/// Both scope lines, once each. The launcher calls this once, on the trap
/// and liteinst backends only.
pub fn scope_lines() {
    for kind in ScopeKind::ALL {
        refusal_log::write_line(&format!("literoot: {}", kind.text()));
    }
}

/// `literoot: refused launcher <token>`.
pub fn refused_launcher(token: &'static str) {
    refusal_log::write_line(&format!("literoot: refused launcher {token}"));
}

/// Percent-encode a program path for the capped record: every
/// byte outside `[A-Za-z0-9._/-]` becomes `%XX`, so a path with
/// spaces, newlines, or non-ASCII bytes stays one ASCII token and
/// can never forge another record. Only the `tool` configuration
/// writes capped records; tests exercise the codec directly.
#[cfg(any(feature = "tool", test))]
fn encode_program(program: &str) -> String {
    use std::os::unix::ffi::OsStrExt as _;
    if program.is_empty() {
        return "%".to_string();
    }
    let mut out = String::new();
    for byte in std::ffi::OsStr::new(program).as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn decode_program(token: &str) -> Option<Vec<u8>> {
    if token == "%" {
        return Some(Vec::new());
    }
    let bytes = token.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes.get(i + 1..i + 3)?;
                if !pair.iter().all(|c| matches!(c, b'0'..=b'9' | b'A'..=b'F')) {
                    return None;
                }
                let hex = std::str::from_utf8(pair).ok()?;
                let byte = u8::from_str_radix(hex, 16).ok()?;
                // Canonical form only: a safe-set byte is never
                // written encoded, so reject its encoded form.
                if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-')
                {
                    return None;
                }
                out.push(byte);
                i += 3;
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-' => {
                out.push(bytes[i]);
                i += 1;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `literoot: capped initial_stack <reason> <old_cur> <old_max>
/// <new_cur> <program>`: an initial stack cap was applied (and is
/// restored after the spawn). The program is percent-encoded.
/// Goes only to the side log, never to the guest's stderr. Only
/// the `tool` configuration applies caps, so only it writes these.
#[cfg(feature = "tool")]
pub fn capped_initial_stack(
    token: &'static str,
    program: &str,
    original: (u64, u64),
    new_cur: u64,
) {
    refusal_log::write_line(&format!(
        "literoot: capped initial_stack {token} {} {} {new_cur} {}",
        original.0,
        original.1,
        encode_program(program)
    ));
}

/// One parsed side-log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Begin(u32),
    End(u32, Option<String>),
    Route(String),
    Refused(String),
    Capped(String),
    Answered(String),
    /// A note (not a refusal).
    Note(String),
    /// A process's exit summary (not a refusal).
    Summary(SummaryLine),
    /// A launcher-written scope disclosure (not a refusal, not a wire tag).
    Scope(ScopeKind),
}

/// The two exit-summary kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryKind {
    Seccomp,
    Probe,
}

impl SummaryKind {
    fn token(self) -> &'static str {
        match self {
            SummaryKind::Seccomp => "seccomp",
            SummaryKind::Probe => "probe",
        }
    }
}

/// One parsed exit-summary line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLine {
    pub kind: SummaryKind,
    /// The emission's receipt ID: compared for equality only.
    pub receipt: refusal_log::ReceiptId,
    pub pid: u32,
    /// The pidfs inode: kernel metadata, not authenticated, not the
    /// identity; tracer-collected on ptrace only; 0 = uncollected.
    pub kernel_id: u64,
    /// The seccomp summary's `flag=` token; None for a probe summary.
    pub flag: Option<&'static str>,
    /// The counters, in line order ([`SECCOMP_COUNTS`], [`PROBE_COUNTS`]).
    pub counts: Vec<u64>,
}

impl SummaryLine {
    /// The record's report form, without its receipt: the sort key and the
    /// printed tuple. The receipt never orders anything.
    fn record_key(&self) -> (SummaryKind, u32, u64, Option<&'static str>, Vec<u64>) {
        (self.kind, self.pid, self.kernel_id, self.flag, self.counts.clone())
    }
}

/// Parse `<name>=<n>`, n a canonical decimal.
fn field<'a>(word: &'a str, name: &str) -> Option<&'a str> {
    let value = word.strip_prefix(name)?.strip_prefix('=')?;
    let canonical = value == "0" || (!value.is_empty() && !value.starts_with('0'));
    (canonical && value.bytes().all(|b| b.is_ascii_digit())).then_some(value)
}

fn field_u64(word: &str, name: &str) -> Option<u64> {
    field(word, name)?.parse().ok()
}

/// Parse a summary's fields after its kind words.
fn summary_line(kind: SummaryKind, words: &[&str]) -> Option<SummaryLine> {
    let names = match kind {
        SummaryKind::Seccomp => SECCOMP_COUNTS,
        SummaryKind::Probe => PROBE_COUNTS,
    };
    let fixed = 3 + usize::from(kind == SummaryKind::Seccomp);
    if words.len() != fixed + names.len() {
        return None;
    }
    let pid = field(words[0], "pid")?.parse::<u32>().ok().filter(|&p| p > 0)?;
    let receipt = refusal_log::ReceiptId::parse(field(words[1], "receipt_id")?)?;
    let kernel_id = field_u64(words[2], "kernel_id")?;
    let flag = match kind {
        SummaryKind::Seccomp => {
            let token = words[3].strip_prefix("flag=")?;
            Some(*FLAGS.iter().find(|f| **f == token)?)
        }
        SummaryKind::Probe => None,
    };
    let counts = names
        .iter()
        .zip(&words[fixed..])
        .map(|(name, word)| field_u64(word, name))
        .collect::<Option<Vec<u64>>>()?;
    Some(SummaryLine {
        kind,
        receipt,
        pid,
        kernel_id,
        flag,
        counts,
    })
}

/// Parse one line (without its `\n`) under the closed grammar. Anything
/// else is an error, never skipped.
pub fn parse(line: &str) -> Result<Line, String> {
    let bad = || Err(format!("not a refusal-log line: {line:?}"));
    let Some(rest) = line.strip_prefix("literoot: ") else {
        return bad();
    };
    if !line.is_ascii() || line.ends_with(' ') || line.contains("  ") {
        return bad();
    }
    if let Some(kind) = ScopeKind::ALL.into_iter().find(|k| rest == k.text()) {
        return Ok(Line::Scope(kind));
    }
    let words: Vec<&str> = rest.split(' ').collect();
    let pid = |w: &str| -> Result<u32, String> {
        match w.parse::<u32>() {
            Ok(p) if p > 0 && w == p.to_string() => Ok(p),
            _ => Err(format!("bad pid in {line:?}")),
        }
    };
    let one_of = |w: &str, set: &[&str]| set.contains(&w);
    match words.as_slice() {
        ["begin", p] => Ok(Line::Begin(pid(p)?)),
        ["end", p, "ok"] => Ok(Line::End(pid(p)?, None)),
        ["end", p, "error", t] if one_of(t, END_ERRORS) => {
            Ok(Line::End(pid(p)?, Some((*t).to_owned())))
        }
        ["route", l] if one_of(l, ROUTES) => Ok(Line::Route((*l).to_owned())),
        ["refused", "exec"] | ["refused", "alternate_stack"] => Ok(Line::Refused(rest.to_owned())),
        ["refused", "fork_policy", k] if one_of(k, FORK_KINDS) => {
            Ok(Line::Refused(rest.to_owned()))
        }
        ["refused", "signal_action", n] => match n.parse::<u8>() {
            Ok(v) if (1..=64).contains(&v) && *n == v.to_string() => {
                Ok(Line::Refused(rest.to_owned()))
            }
            _ => bad(),
        },
        ["refused", "unsupported", k] if one_of(k, UNSUPPORTED) => {
            Ok(Line::Refused(rest.to_owned()))
        }
        ["refused", "guest", k] if one_of(k, GUEST) => Ok(Line::Refused(rest.to_owned())),
        ["refused", "launcher", t] if one_of(t, LAUNCHER) => Ok(Line::Refused(rest.to_owned())),
        ["refused", "path", k] if one_of(k, PATH) => Ok(Line::Refused(rest.to_owned())),
        ["answered", "path", k] if one_of(k, ANSWERED) => Ok(Line::Answered(rest.to_owned())),
        ["refused", "seccomp_install", "probes_in_flight", k]
            if field(k, "in_flight").is_some_and(|v| v.parse::<u32>().is_ok()) =>
        {
            Ok(Line::Refused(rest.to_owned()))
        }
        ["guest", "seccomp", "filter", "install", "attempted"]
        | ["note", "sud_absent"]
        | ["note", "sud_absent_boot_config_advisory"] => Ok(Line::Note(rest.to_owned())),
        ["sud", "config", "read", "unavailable", e]
            if e.strip_prefix("errno=").is_some_and(|e| one_of(e, SUD_FALLBACK_ERRNOS)) =>
        {
            Ok(Line::Note(rest.to_owned()))
        }
        ["guest", "seccomp", "filter", "summary", fields @ ..] => {
            match summary_line(SummaryKind::Seccomp, fields) {
                Some(s) => Ok(Line::Summary(s)),
                None => bad(),
            }
        }
        ["probe", "summary", fields @ ..] => match summary_line(SummaryKind::Probe, fields) {
            Some(s) => Ok(Line::Summary(s)),
            None => bad(),
        },
        ["capped", "initial_stack", t, oc, om, nc, prog]
            if one_of(t, CAP_REASONS)
                && [oc, om, nc]
                    .iter()
                    .all(|n| n.parse::<u64>().is_ok_and(|v| v.to_string() == **n))
                && decode_program(prog).is_some() =>
        {
            Ok(Line::Capped(rest.to_owned()))
        }
        _ => bad(),
    }
}

/// Whether a whole side log is valid for one test name: every line parses,
/// it ends with `\n`, there is at least one `begin`, and every `begin` has
/// a matching `end <pid> ok`. Returns the refused lines when valid.
pub fn validate(contents: &str) -> Result<Vec<String>, String> {
    if contents.is_empty() {
        return Err("empty refusal log".into());
    }
    if !contents.ends_with('\n') {
        return Err("refusal log ends with a partial line".into());
    }
    let mut open: Vec<u32> = Vec::new();
    let mut begins = 0;
    let mut refused = Vec::new();
    // Split on LF alone: `str::lines` would also drop a CR before it, and
    // C3's productions contain no CR, so a CRLF record must fail to parse.
    for line in contents.split_terminator('\n') {
        match parse(line)? {
            Line::Begin(p) => {
                begins += 1;
                open.push(p);
            }
            Line::End(p, error) => {
                let at = open
                    .iter()
                    .position(|&q| q == p)
                    .ok_or_else(|| format!("end without begin for pid {p}"))?;
                open.remove(at);
                if let Some(token) = error {
                    return Err(format!("launcher {p} ended with error {token}"));
                }
            }
            Line::Route(_) => {}
            // A cap record is not a refusal: the run proceeds. Nor is a
            // native answer literoot gave, a note, or an exit summary.
            Line::Capped(_)
            | Line::Answered(_)
            | Line::Note(_)
            | Line::Summary(_)
            | Line::Scope(_) => {}
            Line::Refused(r) => refused.push(r),
        }
    }
    if begins == 0 {
        return Err("no begin line".into());
    }
    if let Some(p) = open.first() {
        return Err(format!("begin without end for pid {p}"));
    }
    Ok(refused)
}

/// The exit-summary report of one launcher run's side log (the gates5
/// entry point's reader). Every received summary is kept as a record and
/// counted in the sums of its class; nothing is merged or dropped.
///
/// Identity is the receipt ID alone: records are grouped by receipt and
/// keyed (receipt, kind). Classes:
/// - `identified`: one emission, a receipt with at most one summary of each
///   kind that agree on pid and kernel_id;
/// - `ambiguous_emission`: a receipt with two summaries of one kind, or
///   whose summaries disagree on pid or kernel_id (counted once per
///   receipt);
/// - `unidentified`: received with receipt 0.
///
/// `suspected_duplicate` warns when identified receipts share a nonzero
/// kernel_id (once per value). kernel_id is unauthenticated metadata, so
/// the warning never merges records or removes counters, and the report
/// counts emissions, never distinct processes. A process that emitted no
/// summary is not visible here: coverage is unknown without a roster of
/// expected emissions. The report never depends on line order or on the
/// receipt numbers.
#[allow(dead_code)] // The gates5 entry point and the units are its callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryReport {
    /// (class, record) for every received summary, sorted by class and the
    /// record's tuple without its receipt.
    pub records: Vec<(&'static str, SummaryLine)>,
    /// Identified receipts.
    pub emissions: u64,
    pub ambiguous_emission: u64,
    pub unidentified: u64,
    pub suspected_duplicate: u64,
}

/// The report's record classes, in report order.
#[allow(dead_code)] // The gates5 entry point and the units are its callers.
pub const SUMMARY_CLASSES: &[&str] = &["identified", "ambiguous_emission", "unidentified"];

#[allow(dead_code)] // The gates5 entry point and the units are its callers.
impl SummaryReport {
    /// Whether a gate must fail on identity grounds alone.
    pub fn has_identity_failure(&self) -> bool {
        self.ambiguous_emission > 0 || self.suspected_duplicate > 0
    }

    /// The Σ fields of one class.
    fn sums(&self, class: &str) -> String {
        let mut flags = [0u64; 3];
        let mut seccomp = [0u64; 5];
        let mut probe = [0u64; 3];
        let mut n = 0u64;
        for (c, r) in &self.records {
            if *c != class {
                continue;
            }
            n += 1;
            let target: &mut [u64] = match r.kind {
                SummaryKind::Seccomp => {
                    if let Some(i) = FLAGS.iter().position(|f| Some(*f) == r.flag) {
                        flags[i] += 1;
                    }
                    &mut seccomp
                }
                SummaryKind::Probe => &mut probe,
            };
            for (t, c) in target.iter_mut().zip(&r.counts) {
                *t = t.saturating_add(*c);
            }
        }
        let mut out = format!(
            "records={n} flag_none={} flag_installed={} flag_inherited={}",
            flags[0], flags[1], flags[2]
        );
        let names = SECCOMP_COUNTS.iter().zip(seccomp).chain(PROBE_COUNTS.iter().zip(probe));
        for (name, v) in names {
            out.push_str(&format!(" {name}={v}"));
        }
        out
    }

    /// The report text: the coverage statement, the counts, one sums line
    /// per class, then one line per record (without its receipt).
    pub fn render(&self) -> String {
        let mut out = format!(
            "coverage=unknown (a process that emitted no summary is not visible in this log)\n\
             emissions={} distinct_processes=not_determined ambiguous_emission={} \
             unidentified={} suspected_duplicate={}\n",
            self.emissions, self.ambiguous_emission, self.unidentified, self.suspected_duplicate
        );
        for class in SUMMARY_CLASSES {
            out.push_str(&format!("sums {class} {}\n", self.sums(class)));
        }
        for (class, r) in &self.records {
            out.push_str(&format!(
                "record {class} {} pid={} kernel_id={}",
                r.kind.token(),
                r.pid,
                r.kernel_id
            ));
            if let Some(flag) = r.flag {
                out.push_str(&format!(" flag={flag}"));
            }
            let names = match r.kind {
                SummaryKind::Seccomp => SECCOMP_COUNTS,
                SummaryKind::Probe => PROBE_COUNTS,
            };
            for (name, c) in names.iter().zip(&r.counts) {
                out.push_str(&format!(" {name}={c}"));
            }
            out.push('\n');
        }
        out
    }
}

/// Build the exit-summary report of one launcher run's side log. The log
/// must be valid ([`validate`]: every line of the grammar, never skipped)
/// and hold exactly one `begin`: receipt IDs restart at 1 per launcher, so
/// two runs in one input would share receipt numbers.
#[allow(dead_code)] // The gates5 entry point and the units are its callers.
pub fn summary_report(contents: &str) -> Result<SummaryReport, String> {
    use std::collections::HashMap;
    validate(contents)?;
    let lines: Vec<Line> = contents
        .split_terminator('\n')
        .map(parse)
        .collect::<Result<_, _>>()?;
    let begins = lines.iter().filter(|l| matches!(l, Line::Begin(_))).count();
    if begins != 1 {
        return Err(format!(
            "{begins} launcher runs in one log: receipt IDs restart at 1 per launcher; \
             report one run per input"
        ));
    }
    let mut by_receipt: HashMap<refusal_log::ReceiptId, Vec<SummaryLine>> = HashMap::new();
    let mut records = Vec::new();
    let mut unidentified = 0;
    for line in lines {
        if let Line::Summary(s) = line {
            if s.receipt.is_unknown() {
                unidentified += 1;
                records.push(("unidentified", s));
            } else {
                by_receipt.entry(s.receipt).or_default().push(s);
            }
        }
    }
    let mut ambiguous_emission = 0;
    let mut emissions = 0;
    let mut per_kernel_id: HashMap<u64, u64> = HashMap::new();
    for (_, group) in by_receipt {
        let kinds_unique = group
            .iter()
            .enumerate()
            .all(|(i, a)| group[..i].iter().all(|b| b.kind != a.kind));
        let consistent = group
            .iter()
            .all(|r| r.pid == group[0].pid && r.kernel_id == group[0].kernel_id);
        let class = if kinds_unique && consistent {
            emissions += 1;
            if group[0].kernel_id != 0 {
                *per_kernel_id.entry(group[0].kernel_id).or_default() += 1;
            }
            "identified"
        } else {
            ambiguous_emission += 1;
            "ambiguous_emission"
        };
        records.extend(group.into_iter().map(|r| (class, r)));
    }
    let suspected_duplicate = per_kernel_id.values().filter(|&&n| n > 1).count() as u64;
    let rank = |class: &str| SUMMARY_CLASSES.iter().position(|c| *c == class);
    records.sort_by(|(ca, a), (cb, b)| {
        (rank(ca), a.record_key()).cmp(&(rank(cb), b.record_key()))
    });
    Ok(SummaryReport {
        records,
        emissions,
        ambiguous_emission,
        unidentified,
        suspected_duplicate,
    })
}

/// Take `--refusal-log <path>` out of `args`, before any other option is
/// read (some options return at once). The first occurrence names the log;
/// a later one is reported as `Err(Some(path))` so the caller can refuse
/// it after opening the first. `Ok(None)` when absent.
pub fn take_from_args(args: &mut Vec<String>) -> Result<Option<String>, (String, String)> {
    let mut found: Option<String> = None;
    let mut i = 0;
    // Only literoot's own options come before the guest command; the
    // command starts at the first non-option word, and nothing after it
    // is literoot's.
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--refusal-log" {
            let Some(path) = args.get(i + 1).cloned() else {
                return Err((found.unwrap_or_default(), String::new()));
            };
            args.drain(i..i + 2);
            match &found {
                None => found = Some(path),
                Some(first) => return Err((first.clone(), path)),
            }
            continue;
        }
        if a == "--" || !a.starts_with('-') || a == "-" {
            break;
        }
        // An option that takes its value as the next word skips it, so the
        // value is never mistaken for the guest command. `-v` takes the
        // next word only when it is a level (`crate::proot_integer`), as
        // `parse_cli` reads it.
        let takes_value = if a == "-v" || a == "--verbose" {
            args.get(i + 1)
                .is_some_and(|next| crate::proot_integer(next).is_some())
        } else {
            VALUE_OPTIONS.contains(&a)
        };
        i += if takes_value { 2 } else { 1 };
    }
    Ok(found)
}

/// The options `parse_cli` (`main.rs`) reads with a separate value word.
/// Keep in step with it: a value-taking option missing here would end the
/// scan early and leave a later `--refusal-log` to `parse_cli`, which
/// refuses it as an unknown option.
const VALUE_OPTIONS: &[&str] = &[
    "-r",
    "--rootfs",
    "-R",
    "-b",
    "--bind",
    "-m",
    "--mount",
    "-w",
    "--cwd",
    "--pwd",
    "-c",
    "-i",
    "--identity",
    "--change-id",
    "-k",
    "--kernel-release",
    "--backend",
    "--check",
    "-v",
    "--verbose",
    "-q",
    "--extension",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_records_round_trip_and_validate() {
        // Whitespace, newline, and non-ASCII bytes encode to one
        // ASCII token that decodes back byte-for-byte, and can
        // never forge a second record.
        let program = "/tmp/weird dir/ld.so\nliteroot: refused exec \u{e9}";
        let encoded = encode_program(program);
        assert!(encoded.is_ascii() && !encoded.contains([' ', '\n']));
        assert_eq!(
            decode_program(&encoded).as_deref(),
            Some(program.as_bytes())
        );
        let line = format!(
            "literoot: capped initial_stack loader_identity 18446744073709551615 18446744073709551615 18446744073709551614 {encoded}"
        );
        assert!(parse(&line).is_ok(), "{line}");
        let log = format!("literoot: begin 42\n{line}\nliteroot: end 42 ok\n");
        assert_eq!(validate(&log), Ok(vec![]));
        // A cap record does not hide a real refusal.
        let log =
            format!("literoot: begin 42\n{line}\nliteroot: refused exec\nliteroot: end 42 ok\n");
        assert_eq!(validate(&log), Ok(vec!["refused exec".to_string()]));
        // Missing/extra fields and malformed numbers are refused.
        for bad in [
            "literoot: capped initial_stack loader_identity 1 2 3",
            "literoot: capped initial_stack loader_identity 1 2 3 /a extra",
            "literoot: capped initial_stack loader_identity 01 2 3 /a",
            "literoot: capped initial_stack loader_identity 1 2 3 %zz",
            "literoot: capped initial_stack other 1 2 3 /a",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn strict_decoder_rejects_noncanonical_forms() {
        // Lowercase hex, an encoded safe-set byte, and truncated
        // or malformed escapes are not the canonical encoding the
        // writer produces, so the decoder refuses them.
        for bad in ["%2f", "%41", "%+F", "a%", "%2", "%zz"] {
            assert_eq!(decode_program(bad), None, "{bad}");
        }
        // Lowercase hex is non-canonical even for bytes outside
        // the safe set, where the safe-byte check cannot reject
        // it; uppercase for the same byte is canonical.
        assert_eq!(decode_program("%0a"), None);
        assert_eq!(decode_program("%ff"), None);
        assert_eq!(decode_program("%e9"), None);
        assert_eq!(decode_program("%0A"), Some(vec![0x0a]));
        assert_eq!(decode_program("%FF"), Some(vec![0xff]));
        assert_eq!(decode_program("%E9"), Some(vec![0xe9]));
        // An encoded byte outside the safe set is canonical.
        assert_eq!(decode_program("%25"), Some(vec![b'%']));
        assert_eq!(decode_program("%20"), Some(vec![b' ']));
        // The capped-record grammar path rejects the lowercase
        // forms and accepts the uppercase ones.
        let bad_line = "literoot: capped initial_stack loader_identity 1 2 1 %0a";
        assert!(parse(bad_line).is_err(), "{bad_line}");
        let good_line = "literoot: capped initial_stack loader_identity 1 2 1 %0A";
        assert!(parse(good_line).is_ok(), "{good_line}");
        let log = format!("literoot: begin 42\n{good_line}\nliteroot: end 42 ok\n");
        assert_eq!(validate(&log), Ok(vec![]));
    }

    #[test]
    fn empty_program_uses_the_percent_sentinel() {
        // The whole token `%` is the empty program's encoding; it
        // is never produced for a non-empty program, and a capped
        // record carrying it parses and validates as a non-refusal.
        assert_eq!(encode_program(""), "%");
        assert_eq!(decode_program("%"), Some(Vec::new()));
        let line = "literoot: capped initial_stack loader_identity 1 2 1 %";
        assert!(parse(line).is_ok(), "{line}");
        let log = format!("literoot: begin 42\n{line}\nliteroot: end 42 ok\n");
        assert_eq!(validate(&log), Ok(vec![]));
    }

    #[test]
    fn the_grammar_accepts_exactly_its_lines() {
        for ok in [
            "literoot: begin 42",
            "literoot: end 42 ok",
            "literoot: end 42 error log_write",
            "literoot: route static_m2",
            "literoot: refused exec",
            "literoot: refused alternate_stack",
            "literoot: refused fork_policy clone3",
            "literoot: refused signal_action 1",
            "literoot: refused signal_action 64",
            "literoot: refused unsupported thread_creation",
            "literoot: refused unsupported native_exec",
            "literoot: refused unsupported other",
            "literoot: refused guest ptrace",
            "literoot: refused guest kompat_auxv",
            "literoot: refused guest fake_id_auxv",
            "literoot: refused launcher static_floor",
        ] {
            assert!(parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "literoot: refused exec /bin/sh",
            "literoot: refused alternate_stack none",
            "literoot: refused alternate_stack ",
            "literoot: refused signal_action 0",
            "literoot: refused signal_action 65",
            "literoot: refused signal_action 010",
            "literoot: refused fork_policy thread",
            "literoot: refused  exec",
            "literoot: refused launcher sometimes",
            "literoot: refused unsupported exec",
            "literoot: refused unsupported parent_death_signal",
            "literoot: begin 0",
            "literoot: begin 7x",
            "literoot: end 7 error oops",
            "literoot: route somewhere",
            "literoot: hello",
            "proot: refused exec",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// Every refusal the Tool side can report is a line of the grammar.
    #[cfg(feature = "tool")]
    #[test]
    fn every_reported_refusal_is_a_grammar_line() {
        use crate::rootfs_tool::ForkKind as F;
        use crate::rootfs_tool::GuestKind as G;
        use crate::rootfs_tool::Refusal as R;
        use crate::rootfs_tool::UnsupportedKind as U;
        let mut all = vec![R::Exec, R::AlternateStack];
        all.extend(
            [
                F::CloneThread,
                F::CloneProcess,
                F::Clone3,
                F::Fork,
                F::Vfork,
            ]
            .map(R::ForkPolicy),
        );
        all.extend((1..=64).map(R::SignalAction));
        all.extend([U::NativeExec, U::ThreadCreation, U::Other].map(R::Unsupported));
        all.extend(
            [
                G::Ptrace,
                G::SelfStop,
                G::SharedRecordPublish,
                G::NodenameWrite,
                G::DomainnameWrite,
                G::KompatAuxv,
                G::FakeIdAuxv,
                G::SyscallUserDispatch,
            ]
            .map(R::Guest),
        );
        all.extend([0, 1, u32::MAX].map(|in_flight| R::InstallRefused { in_flight }));
        for refusal in all {
            let line = refusal.line();
            assert!(matches!(parse(&line), Ok(Line::Refused(_))), "{line}");
        }
        for token in LAUNCHER {
            let line = format!("literoot: refused launcher {token}");
            assert!(matches!(parse(&line), Ok(Line::Refused(_))), "{line}");
        }
        // Path refusals: every kind but the cmdline fallback, and the
        // grammar names exactly them; the fallback is an answered line.
        use crate::translate::PathRefusal as P;
        let tokens: Vec<&str> = crate::translate::PATH_REFUSALS
            .iter()
            .filter(|&&k| k != P::SyntheticFileUnavailable)
            .map(|k| k.token())
            .collect();
        assert_eq!(tokens, PATH);
        for kind in crate::translate::PATH_REFUSALS {
            let line = R::Path(kind).line();
            if kind == P::SyntheticFileUnavailable {
                assert_eq!(line, "literoot: answered path synthetic_file_unavailable");
                assert!(matches!(parse(&line), Ok(Line::Answered(_))), "{line}");
            } else {
                assert!(matches!(parse(&line), Ok(Line::Refused(_))), "{line}");
            }
        }
        use crate::rootfs_tool::PathAnswer as A;
        let answers = [A::DeadBaseName, A::DeadBaseSearch];
        // The whole list: the two native answers, then the cmdline fallback
        // (no stray token may pass).
        let mut answered: Vec<&str> = answers.map(A::token).to_vec();
        answered.push(P::SyntheticFileUnavailable.token());
        assert_eq!(answered, ANSWERED);
        for answer in answers {
            let line = R::Answered(answer).line();
            assert!(matches!(parse(&line), Ok(Line::Answered(_))), "{line}");
        }
        use crate::rootfs_tool::Note as N;
        for note in [N::FilterInstallAttempted, N::SudAbsent, N::SudAbsentBootConfigAdvisory] {
            let line = R::Note(note).line();
            assert!(matches!(parse(&line), Ok(Line::Note(_))), "{line}");
        }
    }

    /// Each summary renders to its production and parses back to its
    /// fields, at 0 and at each type's maximum, with the batch's receipt.
    #[cfg(feature = "tool")]
    #[test]
    fn summaries_round_trip_through_the_grammar() {
        use crate::dead_base::FLAG_STATES;
        use crate::rootfs_tool::Refusal as R;
        use crate::rootfs_tool::Summary as S;
        for (pid, n) in [(1, 0), (i32::MAX, u64::MAX)] {
            for flag in FLAG_STATES {
                let summary = S::Seccomp {
                    pid,
                    kernel_id: n,
                    flag,
                    installs: n,
                    installs_refused: n,
                    translated: n,
                    refused: n,
                    unseen_best_effort: n,
                };
                let mut receipt = None;
                let line = R::Summary(summary).line_in_batch(&mut receipt);
                let Ok(Line::Summary(parsed)) = parse(&line) else {
                    panic!("{line}");
                };
                assert_eq!(Some(parsed.receipt), receipt, "{line}");
                assert_eq!(parsed.kind, SummaryKind::Seccomp);
                assert_eq!((parsed.pid, parsed.kernel_id), (pid as u32, n));
                assert_eq!(parsed.flag, Some(flag.token()));
                assert_eq!(parsed.counts, vec![n; 5]);
                // The batch's second summary takes the same receipt.
                let probe = S::Probe {
                    pid,
                    kernel_id: n,
                    probes: n,
                    sud_refused: n,
                    sud_fallback: n,
                };
                let line = R::Summary(probe).line_in_batch(&mut receipt);
                let Ok(Line::Summary(parsed)) = parse(&line) else {
                    panic!("{line}");
                };
                assert_eq!(Some(parsed.receipt), receipt, "{line}");
                assert_eq!(parsed.kind, SummaryKind::Probe);
                assert_eq!((parsed.flag, parsed.counts), (None, vec![n; 3]));
            }
        }
    }

    /// An answer line is not a refusal, and a path line outside the closed
    /// kinds is not a line.
    #[test]
    fn path_lines_parse_by_closed_kind() {
        let log = "literoot: begin 7\nliteroot: answered path dead_base_name\n\
                   literoot: refused path base_moved\nliteroot: end 7 ok\n";
        assert_eq!(validate(log).unwrap(), vec!["refused path base_moved".to_owned()]);
        for bad in [
            "literoot: refused path",
            "literoot: refused path other",
            "literoot: answered path base_moved",
            "literoot: refused path dead_base_name",
            "literoot: answered path dead_base_name extra",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// C5.6: both scope lines, byte for byte, and their parse. A near miss is
    /// refused, and a log carrying them stays valid with no refusal.
    #[test]
    fn scope_lines_golden() {
        let lines = [
            "literoot: scope detector best-effort; defeatable by a guest that jumps to a trusted gate",
            "literoot: scope constructor-checks best-effort; defeatable by code that runs before the preload's constructor (LD_PRELOAD window)",
        ];
        for (kind, line) in ScopeKind::ALL.into_iter().zip(lines) {
            assert_eq!(format!("literoot: {}", kind.text()), line);
            assert_eq!(parse(line), Ok(Line::Scope(kind)));
        }
        for bad in [
            "literoot: scope detector best-effort",
            "literoot: scope detector best-effort; defeatable by a guest that jumps to a trusted gate.",
            "literoot: scope constructor-checks best-effort; defeatable by code that runs before the preload's constructor",
            "literoot: scope other best-effort; defeatable by a guest that jumps to a trusted gate",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let log = format!("literoot: begin 42\n{}\n{}\nliteroot: end 42 ok\n", lines[0], lines[1]);
        assert_eq!(validate(&log), Ok(Vec::new()));
    }

    /// C5: the install-attempt note's exact bytes, as the Tool emits them,
    /// and its parse; the old text and the near-misses (a trailing space, a
    /// double space, "install attempt") are rejected.
    #[test]
    fn install_note_text_pinned() {
        use crate::rootfs_tool::Note;
        use crate::rootfs_tool::Refusal;
        let line = Refusal::Note(Note::FilterInstallAttempted).line();
        assert_eq!(line.as_bytes(), b"literoot: guest seccomp filter install attempted");
        assert_eq!(parse(&line), Ok(Line::Note("guest seccomp filter install attempted".to_owned())));
        for bad in [
            "literoot: guest seccomp filter installed",
            "literoot: guest seccomp filter install attempted ",
            "literoot: guest seccomp filter install  attempted",
            "literoot:  guest seccomp filter install attempted",
            "literoot: guest seccomp filter install attempt",
            "literoot: guest seccomp filter install attempts",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// C5b.2: the dispatch refusal line's exact bytes, as the Tool emits
    /// them, and its parse to `Line::Refused` with the guest kind.
    #[test]
    fn sud_line_golden() {
        use crate::rootfs_tool::GuestKind;
        use crate::rootfs_tool::Refusal;
        let line = Refusal::Guest(GuestKind::SyscallUserDispatch).line();
        assert_eq!(line.as_bytes(), b"literoot: refused guest syscall_user_dispatch");
        assert_eq!(parse(&line), Ok(Line::Refused("refused guest syscall_user_dispatch".to_owned())));
        for bad in [
            "literoot: refused guest syscall_user_dispatch ",
            "literoot: refused guest sud",
            "literoot: refused guest syscall-user-dispatch",
            "literoot: refused  guest syscall_user_dispatch",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// The new productions accept exactly their lines.
    #[test]
    fn note_install_and_summary_lines_parse_exactly() {
        let seccomp = "literoot: guest seccomp filter summary pid=7 receipt_id=3 kernel_id=0 \
                       flag=installed installs=1 installs_refused=0 translated=2 refused=1 \
                       unseen_best_effort=0";
        let probe = "literoot: probe summary pid=7 receipt_id=3 kernel_id=0 probes=4 \
                     sud_refused=0 sud_fallback=4";
        for ok in [
            "literoot: guest seccomp filter install attempted",
            "literoot: note sud_absent",
            "literoot: note sud_absent_boot_config_advisory",
            "literoot: refused seccomp_install probes_in_flight in_flight=1",
            "literoot: refused seccomp_install probes_in_flight in_flight=0",
            "literoot: refused guest syscall_user_dispatch",
            "literoot: sud config read unavailable errno=EIO",
            "literoot: sud config read unavailable errno=EINVAL",
            "literoot: sud config read unavailable errno=ENOSYS",
            seccomp,
            probe,
        ] {
            assert!(parse(ok).is_ok(), "{ok}");
        }
        let mut bad = vec![
            "literoot: guest seccomp filter installed".to_owned(),
            "literoot: guest seccomp filter install attempted ".to_owned(),
            "literoot: note sud_absent yes".to_owned(),
            "literoot: note sud_absent_boot_config_advisory yes".to_owned(),
            "literoot: sud config read unavailable errno=EPERM".to_owned(),
            "literoot: sud config read unavailable EIO".to_owned(),
            "literoot: sud config read unavailable errno=EIO x".to_owned(),
            "literoot: refused seccomp_install probes_in_flight".to_owned(),
            "literoot: refused seccomp_install probes_in_flight in_flight=01".to_owned(),
            "literoot: refused seccomp_install probes_in_flight in_flight=-1".to_owned(),
            "literoot: refused seccomp_install probes_in_flight in_flight=4294967296".to_owned(),
            "literoot: refused seccomp_install probes_in_flight in_flight=1 extra".to_owned(),
        ];
        // Every summary near-miss: a renamed, dropped, reordered or
        // non-canonical field, a bad flag, a trailing field, pid 0, and the
        // rejected `seq=` spelling.
        for (from, to) in [
            ("receipt_id=3", "seq=3"),
            ("receipt_id=3", "receipt_id=03"),
            ("pid=7", "pid=0"),
            ("pid=7", "pid=-7"),
            ("kernel_id=0", "kernel_id=18446744073709551616"),
            ("flag=installed", "flag=yes"),
            ("installs=1 installs_refused=0", "installs_refused=0 installs=1"),
            (" unseen_best_effort=0", ""),
            ("unseen_best_effort=0", "unseen_best_effort=0 extra=1"),
            ("unseen_best_effort=0", "filters_unseen=0"),
        ] {
            bad.push(seccomp.replace(from, to));
        }
        for (from, to) in [
            ("probes=4", "probes=+4"),
            (" sud_fallback=4", ""),
            ("receipt_id=3 kernel_id=0", "kernel_id=0 receipt_id=3"),
            ("probe summary", "probes summary"),
        ] {
            bad.push(probe.replace(from, to));
        }
        bad.retain(|b| b != seccomp && b != probe);
        for b in &bad {
            assert!(parse(b).is_err(), "{b}");
        }
        // Notes and summaries are not refusals; the install refusal is.
        let log = format!(
            "literoot: begin 7\nliteroot: guest seccomp filter install attempted\n\
             literoot: refused seccomp_install probes_in_flight in_flight=1\n{seccomp}\n\
             {probe}\nliteroot: note sud_absent\nliteroot: end 7 ok\n"
        );
        assert_eq!(
            validate(&log).unwrap(),
            vec!["refused seccomp_install probes_in_flight in_flight=1".to_owned()]
        );
    }

    fn seccomp_line(pid: u32, receipt: u64, kernel_id: u64, installs: u64) -> String {
        format!(
            "literoot: guest seccomp filter summary pid={pid} receipt_id={receipt} \
             kernel_id={kernel_id} flag=installed installs={installs} installs_refused=0 \
             translated=0 refused=0 unseen_best_effort=0\n"
        )
    }

    fn probe_line(pid: u32, receipt: u64, kernel_id: u64, probes: u64) -> String {
        format!(
            "literoot: probe summary pid={pid} receipt_id={receipt} kernel_id={kernel_id} \
             probes={probes} sud_refused=0 sud_fallback=0\n"
        )
    }

    /// One launcher run's log around `lines`.
    fn run(lines: &[String]) -> String {
        format!("literoot: begin 42\n{}literoot: end 42 ok\n", lines.concat())
    }

    fn report(lines: &[String]) -> SummaryReport {
        summary_report(&run(lines)).unwrap()
    }

    fn sums_line(r: &SummaryReport, class: &str) -> String {
        let text = r.render();
        text.lines()
            .find(|l| l.starts_with(&format!("sums {class} ")))
            .unwrap_or_else(|| panic!("{text}"))
            .to_owned()
    }

    #[test]
    fn summary_one_batch_both_kinds_is_one_emission() {
        let r = report(&[seccomp_line(7, 1, 0, 2), probe_line(7, 1, 0, 3)]);
        assert_eq!((r.emissions, r.ambiguous_emission, r.suspected_duplicate), (1, 0, 0));
        assert!(sums_line(&r, "identified").contains(" records=2 "));
        assert!(r.render().starts_with("coverage=unknown "));
        assert!(r.render().contains(" distinct_processes=not_determined "));
    }

    /// Two receipts with the same pid and no kernel_id are two emissions,
    /// and both counters are summed.
    #[test]
    fn summary_same_pid_zero_kernel_id_two_receipts_are_two_emissions() {
        let r = report(&[seccomp_line(7, 1, 0, 2), seccomp_line(7, 2, 0, 5)]);
        assert_eq!((r.emissions, r.suspected_duplicate), (2, 0));
        assert!(sums_line(&r, "identified").contains(" installs=7 "));
    }

    /// Equal nonzero kernel_ids only warn: both records stay identified and
    /// counted.
    #[test]
    fn summary_equal_nonzero_kernel_id_warns_and_keeps_both() {
        let r = report(&[seccomp_line(7, 1, 11, 2), seccomp_line(7, 2, 11, 5), probe_line(8, 3, 12, 1)]);
        assert_eq!((r.emissions, r.suspected_duplicate), (3, 1));
        assert!(r.has_identity_failure());
        assert!(sums_line(&r, "identified").contains(" records=3 "));
        assert!(sums_line(&r, "identified").contains(" installs=7 "));
    }

    /// An ambiguous receipt keeps its counters, in its own sums.
    #[test]
    fn summary_ambiguous_sums_equal_the_records_counters() {
        for lines in [
            [seccomp_line(7, 1, 11, 2), seccomp_line(7, 1, 11, 5)],
            [seccomp_line(7, 1, 11, 2), probe_line(8, 1, 11, 5)],
            [seccomp_line(7, 1, 11, 2), probe_line(7, 1, 12, 5)],
        ] {
            let r = report(&lines);
            assert_eq!((r.emissions, r.ambiguous_emission), (0, 1), "{lines:?}");
            assert!(r.has_identity_failure());
            let sums = sums_line(&r, "ambiguous_emission");
            assert!(sums.contains(" records=2 "), "{sums}");
            assert!(sums.contains(" installs=2 ") || sums.contains(" installs=7 "), "{sums}");
            if sums.contains(" installs=2 ") {
                assert!(sums.contains(" probes=5 "), "{sums}");
            }
        }
    }

    #[test]
    fn summary_receipt_zero_is_unidentified() {
        let r = report(&[seccomp_line(7, 0, 11, 2), seccomp_line(7, 0, 11, 2)]);
        assert_eq!((r.emissions, r.unidentified), (0, 2));
        assert!(!r.has_identity_failure());
        assert!(sums_line(&r, "unidentified").contains(" installs=4 "));
    }

    /// An empty summary set is never an all-clear, and one input is one
    /// launcher run.
    #[test]
    fn summary_report_states_coverage_and_takes_one_run() {
        let r = report(&[]);
        assert_eq!(r.emissions, 0);
        assert!(r.render().starts_with("coverage=unknown "));
        let one = seccomp_line(7, 1, 0, 2);
        let two_runs = run(std::slice::from_ref(&one)) + &run(std::slice::from_ref(&one));
        assert!(summary_report(&two_runs).unwrap_err().contains("one run per input"));
        assert!(summary_report(&one).is_err(), "no begin");
    }

    fn mixed_corpus(n: impl Fn(u64) -> u64) -> Vec<String> {
        vec![
            seccomp_line(7, n(1), 11, 2),
            probe_line(7, n(1), 11, 3),
            seccomp_line(7, n(2), 0, 2),
            seccomp_line(7, n(3), 0, 6),
            seccomp_line(9, n(4), 13, 1),
            seccomp_line(9, n(4), 13, 4),
            probe_line(5, n(5), 14, 1),
            probe_line(5, n(6), 14, 1),
            seccomp_line(4, 0, 0, 1),
        ]
    }

    /// The report does not depend on line order: every rotation and the
    /// reversal render identically.
    #[test]
    fn summary_report_is_order_independent() {
        let lines = mixed_corpus(|k| k);
        let base = report(&lines).render();
        for i in 0..lines.len() {
            let mut rotated = lines.clone();
            rotated.rotate_left(i);
            assert_eq!(report(&rotated).render(), base, "{i}");
            rotated.reverse();
            assert_eq!(report(&rotated).render(), base, "{i}r");
        }
    }

    /// The report does not depend on the receipt numbers: bijections on the
    /// positive receipts (0 stays 0), written as canonical decimals, that
    /// reverse numeric order and that reverse lexical order, give the same
    /// non-ID projection. Every transformed log parses.
    #[test]
    fn summary_report_is_independent_of_receipt_numbers() {
        let base = report(&mixed_corpus(|k| k)).render();
        // 1..=6 is ascending both numerically and lexically.
        let maps: [(&str, [u64; 6]); 3] = [
            // Numeric reversal.
            ("numeric", [1000, 999, 100, 99, 10, 9]),
            // Lexical reversal, numeric order kept: 9 > 80 > 700 ... as
            // strings.
            ("lexical", [9, 80, 700, 6000, 50000, 400000]),
            // Both orders scrambled with 9/10/99/100-style values.
            ("mixed", [99, 10, 100, 9, 1000, 999]),
        ];
        for (name, map) in maps {
            let mut sorted = map.to_vec();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), 6, "{name}: a bijection");
            assert!(map.iter().all(|&n| n > 0), "{name}: positive receipts only");
            let lines = mixed_corpus(|k| map[(k - 1) as usize]);
            for line in &lines {
                assert!(matches!(parse(line.trim_end()), Ok(Line::Summary(_))), "{name}: {line}");
            }
            assert_eq!(report(&lines).render(), base, "{name}");
        }
        let numeric: Vec<String> = maps[0].1.iter().map(u64::to_string).collect();
        assert!(numeric.windows(2).all(|w| w[0].parse::<u64>().unwrap() > w[1].parse().unwrap()));
        let lexical: Vec<String> = maps[1].1.iter().map(u64::to_string).collect();
        assert!(lexical.windows(2).all(|w| w[0] > w[1]), "{lexical:?}");
    }

    #[test]
    fn summary_report_refuses_any_line_outside_the_grammar() {
        let ok = seccomp_line(7, 1, 11, 2);
        assert!(summary_report(&run(std::slice::from_ref(&ok))).is_ok());
        for bad in [ok.replace("receipt_id", "seq"), "x\n".to_owned()] {
            assert!(summary_report(&run(&[ok.clone(), bad.clone()])).is_err(), "{bad}");
        }
    }

    /// The receipt ID is compared for equality only: it implements no
    /// order and gives no number out, and the reader's sort key leaves it
    /// out. A derive or accessor added later fails here.
    #[test]
    fn receipt_id_is_equality_only() {
        use std::marker::PhantomData;
        trait No {
            const ORD: bool = false;
            const PARTIAL_ORD: bool = false;
            const INTO_U64: bool = false;
        }
        struct Probe<T>(PhantomData<T>);
        impl<T> No for Probe<T> {}
        impl<T: Ord> Probe<T> {
            #[allow(dead_code)]
            const ORD: bool = true;
        }
        type R = refusal_log::ReceiptId;
        const { assert!(!<Probe<R>>::ORD) };
        struct Probe2<T>(PhantomData<T>);
        impl<T> No for Probe2<T> {}
        impl<T: PartialOrd> Probe2<T> {
            #[allow(dead_code)]
            const PARTIAL_ORD: bool = true;
        }
        const { assert!(!<Probe2<R>>::PARTIAL_ORD) };
        struct Probe3<T>(PhantomData<T>);
        impl<T> No for Probe3<T> {}
        impl<T: Into<u64>> Probe3<T> {
            #[allow(dead_code)]
            const INTO_U64: bool = true;
        }
        const { assert!(!<Probe3<R>>::INTO_U64) };
        trait NoDeref {
            const DEREF: bool = false;
        }
        struct Probe4<T>(PhantomData<T>);
        impl<T> NoDeref for Probe4<T> {}
        impl<T: std::ops::Deref> Probe4<T> {
            #[allow(dead_code)]
            const DEREF: bool = true;
        }
        const { assert!(!<Probe4<R>>::DEREF) };
        // Positive control: the probe sees an order where there is one.
        const { assert!(<Probe<u64>>::ORD && <Probe2<u64>>::PARTIAL_ORD) };
        const { assert!(<Probe3<u32>>::INTO_U64 && <Probe4<Box<u64>>>::DEREF) };
        // Source tripwire: the derive set, the private field, and a sort
        // key without the receipt.
        let writer = include_str!("refusal_log.rs");
        assert!(writer.contains(
            "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\npub struct ReceiptId(u64);"
        ));
        assert_eq!(writer.matches("ReceiptId(n)").count(), 1, "one issuing site");
        // No accessor: nothing in the writer returns the number, and the
        // inner field is read only by the Display impl (the side-log text).
        let code = crate::test_source::without_test_items(writer);
        assert!(code.contains("pub fn next_summary_receipt("), "production after the test sink kept");
        assert!(!code.contains("static SINK"), "the test sink dropped");
        let code = code.as_str();
        let imp = &code[code.find("impl ReceiptId {").expect("impl")..];
        let imp = &imp[..imp.find("\n}\n").expect("impl end")];
        assert!(!imp.contains("-> u64") && !imp.contains("self.0"), "{imp}");
        assert_eq!(code.matches("self.0").count(), 1, "only Display reads the number");
        let reader = include_str!("side_log.rs");
        let key = reader
            .split("fn record_key")
            .nth(1)
            .and_then(|rest| rest.split("\n    }").next())
            .expect("record_key");
        assert!(!key.contains("receipt"), "{key}");
    }

    #[test]
    fn a_log_is_valid_only_with_matched_begin_and_end_ok() {
        let good = "literoot: begin 7\nliteroot: refused exec\nliteroot: begin 8\n\
                    literoot: end 8 ok\nliteroot: end 7 ok\n";
        assert_eq!(validate(good).unwrap(), vec!["refused exec".to_owned()]);
        for (bad, why) in [
            ("", "empty"),
            ("literoot: begin 7\nliteroot: end 7 ok", "partial"),
            ("literoot: route preload\n", "no begin"),
            ("literoot: begin 7\n", "begin without end"),
            ("literoot: end 7 ok\n", "end without begin"),
            ("literoot: begin 7\nliteroot: end 7 error launch\n", "error"),
            ("literoot: begin 7\nliteroot: end 7 error reporter\n", "error"),
            (
                "literoot: begin 7\nliteroot: refused what\nliteroot: end 7 ok\n",
                "not a",
            ),
            ("literoot: begin 7\r\nliteroot: end 7 ok\r\n", "bad pid"),
            ("literoot: begin 7\nliteroot: end 7 ok\r\n", "not a"),
            (
                "literoot: begin 7\nliteroot: refused exec\r\nliteroot: end 7 ok\n",
                "not a",
            ),
        ] {
            let error = validate(bad).unwrap_err();
            assert!(error.contains(why), "{bad:?}: {error}");
        }
    }

    #[test]
    fn the_option_is_taken_before_any_other_and_only_once() {
        let mut args: Vec<String> = ["--refusal-log", "/l", "-q", "x", "/bin/true"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_from_args(&mut args).unwrap(), Some("/l".into()));
        assert_eq!(args, ["-q", "x", "/bin/true"]);
        let mut args: Vec<String> = ["-r", "/r", "--refusal-log", "/a", "--refusal-log", "/b"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            take_from_args(&mut args).unwrap_err(),
            ("/a".into(), "/b".into())
        );
        // After the guest command starts, nothing is literoot's.
        let mut args: Vec<String> = ["/bin/prog", "--refusal-log", "/x"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_from_args(&mut args).unwrap(), None);
        assert_eq!(args.len(), 3);
        // `-v` takes a level only when the next word is an integer, so a
        // repeated option after a bare `-v` is still found.
        let mut args: Vec<String> = ["--refusal-log", "/a", "-v", "--refusal-log", "/b", "/bin/true"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_from_args(&mut args).unwrap_err(), ("/a".into(), "/b".into()));
        let mut args: Vec<String> = ["-v", "2", "--refusal-log", "/a", "/bin/true"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_from_args(&mut args).unwrap(), Some("/a".into()));
        // Nor after `--`.
        let mut args: Vec<String> = ["--", "--refusal-log", "/x"].map(String::from).to_vec();
        assert_eq!(take_from_args(&mut args).unwrap(), None);
        assert_eq!(args.len(), 3);
        // A value word is skipped even when it looks like an option.
        let mut args: Vec<String> = ["-w", "-r", "--refusal-log", "/a", "/bin/true"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_from_args(&mut args).unwrap(), Some("/a".into()));
        assert_eq!(args, ["-w", "-r", "/bin/true"]);
    }
}
