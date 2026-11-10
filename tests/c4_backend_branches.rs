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
