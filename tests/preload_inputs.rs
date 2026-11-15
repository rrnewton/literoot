//! Every file of src/ that the preload compiles (a `#[path = "../../src/..."]`
//! module in preload/src/lib.rs) is a preload input: build.rs reruns the
//! nested preload build when it changes (RERUN_PATHS), and the compatibility
//! stamp hashes it (STAMP_FILES). A file missing from either would let a
//! stale embedded blob, or a user preload built from other sources, through.

#[path = "../src/preload_stamp.rs"]
#[allow(dead_code)]
mod preload_stamp;

/// The src/ files preload/src/lib.rs compiles, as package-relative paths.
fn preload_src_includes() -> Vec<String> {
    let lib = include_str!("../preload/src/lib.rs");
    let found: Vec<String> = lib
        .lines()
        .filter_map(|l| l.trim().strip_prefix("#[path = \"../../"))
        .filter_map(|rest| rest.strip_suffix("\"]"))
        .map(str::to_owned)
        .collect();
    assert!(found.iter().any(|f| f == "src/wire_id.rs"), "the scan finds the preload's includes: {found:?}");
    found
}

/// build.rs's RERUN_PATHS entries, read from its source.
fn rerun_paths() -> Vec<String> {
    let build = include_str!("../build.rs");
    let start = build.find("const RERUN_PATHS: &[&str] = &[").expect("build.rs: RERUN_PATHS");
    let body = &build[start..];
    let end = body.find("];").expect("build.rs: the end of RERUN_PATHS");
    body[..end]
        .lines()
        .skip(1)
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.strip_suffix("\","))
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_preload_source_reruns_the_embed_and_enters_the_stamp() {
    let rerun = rerun_paths();
    assert!(rerun.iter().any(|p| p == "preload/src"), "the scan reads RERUN_PATHS: {rerun:?}");
    for file in preload_src_includes() {
        assert!(rerun.contains(&file), "build.rs RERUN_PATHS lacks {file}");
        assert!(
            preload_stamp::STAMP_FILES.contains(&file.as_str()),
            "STAMP_FILES lacks {file}"
        );
    }
}
