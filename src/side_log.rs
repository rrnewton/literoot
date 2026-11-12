//! The refusal side log, launcher side (`--refusal-log <path>`): one file
//! the launcher owns, into which every literoot refusal is written as one line of a
//! closed grammar, so a suite driver can tell "nothing was refused" from
//! "something was refused" and from "not measured".
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
//! - `literoot: capped initial_stack <reason> <old_cur> <old_max>
//!   <new_cur> <program>`, reason in [`CAP_REASONS`] (not a refusal)
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
/// process acknowledged refusal reporting (a preload built before this
/// log, which runs the guest but reports nothing).
pub const END_ERRORS: &[&str] = &["log_write", "connections_open", "launch", "reporter"];
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
    "other",
];

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

/// `literoot: refused launcher <token>`.
pub fn refused_launcher(token: &'static str) {
    refusal_log::write_line(&format!("literoot: refused launcher {token}"));
}

/// `literoot: capped initial_stack <reason> <old_cur> <old_max>
/// <new_cur> <program>`: an initial stack cap was applied (and is
/// restored after the spawn). Goes only to the side log, never to
/// the guest's stderr.
pub fn capped_initial_stack(
    token: &'static str,
    program: &str,
    original: (u64, u64),
    new_cur: u64,
) {
    refusal_log::write_line(&format!(
        "literoot: capped initial_stack {token} {} {} {new_cur} {program}",
        original.0, original.1
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
        ["capped", "initial_stack", t, oc, om, nc, ..]
            if one_of(t, CAP_REASONS)
                && [oc, om, nc].iter().all(|n| n.parse::<u64>().is_ok()) =>
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
        // next word only when it is a level (an integer), as `parse_cli`
        // reads it.
        let takes_value = if a == "-v" || a == "--verbose" {
            args.get(i + 1).is_some_and(|next| next.parse::<i64>().is_ok())
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
    "-c",
    "-i",
    "--identity",
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
            ]
            .map(R::Guest),
        );
        for refusal in all {
            let line = refusal.line();
            assert!(matches!(parse(&line), Ok(Line::Refused(_))), "{line}");
        }
        for token in LAUNCHER {
            let line = format!("literoot: refused launcher {token}");
            assert!(matches!(parse(&line), Ok(Line::Refused(_))), "{line}");
        }
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
