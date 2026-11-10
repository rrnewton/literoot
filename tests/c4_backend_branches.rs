//! The C4 gate (plan revision 6): every branch of `src/rootfs_tool.rs` that
//! runs only on an in-guest backend writes a keyed side-log line, through
//! `note_guest_refusal`, or is scoped out here by name, with a reason.
//!
//! A branch is found by its read of a backend-conditioned config field
//! (set by the launcher only for in-guest backends). It is keyed if a
//! `note_guest_refusal(` call follows within `WINDOW` lines.

/// Config fields the launcher sets only for in-guest backends.
const CONDITIONED: &[&str] = &["refuse_guest_ptrace", "post_exec_at_exec_stop"];

/// Branches scoped out of C4: (a substring of the reading line, the reason).
const SCOPED_OUT: &[(&str, &str)] = &[];

const WINDOW: usize = 12;

#[test]
fn every_in_guest_only_branch_is_keyed_or_scoped_out() {
    let source = include_str!("../src/rootfs_tool.rs");
    let lines: Vec<&str> = source.lines().collect();
    let mut reads = 0;
    let mut unkeyed = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        if !CONDITIONED
            .iter()
            .any(|field| code.contains(&format!("config().{field}")))
        {
            continue;
        }
        reads += 1;
        let keyed = lines[i..(i + WINDOW).min(lines.len())]
            .iter()
            .any(|l| l.contains("note_guest_refusal("));
        let scoped = SCOPED_OUT.iter().any(|(anchor, _)| line.contains(anchor));
        if !keyed && !scoped {
            unkeyed.push(format!("src/rootfs_tool.rs:{}: {}", i + 1, line.trim()));
        }
    }
    assert!(
        reads > 0,
        "no backend-conditioned read found: the gate no longer sees the branches"
    );
    assert!(
        unkeyed.is_empty(),
        "in-guest-only branches with no keyed line and not scoped out:\n{}",
        unkeyed.join("\n")
    );
}

/// The guard disjuncts of the initial-stack walk in `handle_post_exec`, and
/// the key each one's in-guest skip writes. The walk finds the auxv from
/// the stack pointer, which is the initial stack only at the ptrace exec
/// stop; in-guest every patch it makes is skipped and must be keyed.
const WALK_PATCH_KEYS: &[(&str, &str)] = &[
    ("fake.is_some()", "FakeIdAuxv"),
    ("zero_hwcap", "KompatAuxv"),
    ("kompat", "KompatAuxv"),
];

/// The index of the line that closes the block opened on line `open`.
fn block_end(lines: &[&str], open: usize) -> usize {
    let mut depth = 0i32;
    let mut opened = false;
    for (i, line) in lines.iter().enumerate().skip(open) {
        let code = line.split("//").next().unwrap_or("");
        depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
        opened |= depth > 0;
        if opened && depth == 0 {
            return i;
        }
    }
    panic!("unbalanced block from line {}", open + 1);
}

#[test]
fn every_exec_stop_only_stack_walk_patch_is_keyed() {
    let source = include_str!("../src/rootfs_tool.rs");
    let lines: Vec<&str> = source.lines().collect();
    let marker = lines
        .iter()
        .position(|l| l.contains("C4: the initial-stack walk (exec stop only)"))
        .expect("the initial-stack walk marker is gone");
    let guard = (marker..lines.len())
        .find(|&i| lines[i].trim_start().starts_with("if "))
        .unwrap();
    let condition = lines[guard].trim().trim_start_matches("if ").trim_end_matches('{').trim();
    let walk_end = block_end(&lines, guard);
    for disjunct in condition.split("||").map(str::trim) {
        assert!(
            WALK_PATCH_KEYS.iter().any(|(d, _)| *d == disjunct),
            "src/rootfs_tool.rs:{}: the walk patches on `{disjunct}`, which has no in-guest key",
            guard + 1
        );
    }
    for (i, line) in lines.iter().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        if code.contains("guest_stack_pointer(") && !code.contains("fn guest_stack_pointer") {
            assert!(
                (guard..=walk_end).contains(&i),
                "src/rootfs_tool.rs:{}: a stack walk outside the keyed initial-stack walk",
                i + 1
            );
        }
    }
    let in_guest = lines
        .iter()
        .position(|l| l.contains("if !guest.config().post_exec_at_exec_stop {"))
        .expect("the in-guest skip branch is gone");
    let branch = lines[in_guest..=block_end(&lines, in_guest)].join("\n");
    for (_, key) in WALK_PATCH_KEYS {
        assert!(
            branch.contains(&format!("note_guest_refusal(GuestKind::{key})")),
            "the in-guest skip branch does not key {key}"
        );
    }
}

/// Every Tool-level key keeps a writer: a direct `note_guest_refusal`, or
/// the shared-record reporter's mapping (which must itself call it).
#[test]
fn every_guest_kind_has_a_writer() {
    let source = include_str!("../src/rootfs_tool.rs");
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains("pub(crate) const GUEST_KINDS"))
        .unwrap();
    let kinds: Vec<String> = lines[start + 1..]
        .iter()
        .take_while(|l| !l.trim_start().starts_with("];"))
        .map(|l| l.trim().trim_start_matches("GuestKind::").trim_end_matches(',').to_owned())
        .collect();
    assert!(kinds.len() >= 7, "{kinds:?}");
    let shared_start = lines
        .iter()
        .position(|l| l.contains("fn report_shared_record_refusal("))
        .unwrap();
    let shared = lines[shared_start..=block_end(&lines, shared_start)].join("\n");
    let shared_writes = shared.contains("note_guest_refusal(");
    for kind in &kinds {
        let direct = source.contains(&format!("note_guest_refusal(GuestKind::{kind})"));
        let mapped = shared_writes && shared.contains(&format!("GuestKind::{kind}"));
        assert!(direct || mapped, "GuestKind::{kind} has no writer");
    }
}
