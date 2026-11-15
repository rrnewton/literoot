//! Source-scanning helpers for the static witness units (test builds only).

/// The source of `text` without its test-only items: a column-0
/// `#[cfg(test)]`, the attribute lines after it, and the item they qualify,
/// which ends at its own line when that line ends with `;` (a module file or
/// a statement-like item) or with `}` (a one-line item such as
/// `fn f() {}`), or else at the next line that is exactly `}` (rustfmt puts
/// a top-level item's closing brace alone in column 0).
/// Braces inside the item, in literals or not, are never counted, so a
/// test module that spells `'{'` cannot swallow the production code after
/// it. A `#[cfg(test)]` indented inside a function stays (it is not an item
/// at column 0).
pub(crate) fn without_test_items(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if lines[i] != "#[cfg(test)]" {
            out.push(lines[i]);
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < lines.len() && lines[j].starts_with("#[") {
            j += 1;
        }
        if j < lines.len() && lines[j].trim_end().ends_with([';', '}']) {
            i = j + 1;
            continue;
        }
        let close = lines[j..]
            .iter()
            .position(|l| *l == "}")
            .unwrap_or_else(|| panic!("a column-0 `}}` closes the test item at line {}", i + 1));
        i = j + close + 1;
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::without_test_items;

    /// The negative control: a test module that spells brace literals (one
    /// more opening than closing, as the old counter's own code did) still
    /// ends at its column-0 `}`, and every production line after it, and
    /// after a module-file item, is kept.
    #[test]
    fn brace_literals_do_not_swallow_production() {
        let text = "fn first() {}\n\
                    #[cfg(test)]\n\
                    mod tests {\n    \
                        const OPEN: char = '{';\n    \
                        const OPEN2: char = '{';\n    \
                        const CLOSE: char = '}';\n    \
                        fn f() { let _ = (OPEN, OPEN2, CLOSE); }\n\
                    }\n\
                    fn production_after() {}\n\
                    #[cfg(test)]\n\
                    #[path = \"x.rs\"]\n\
                    mod seams;\n\
                    #[cfg(test)]\n\
                    thread_local! {\n    \
                        static T: u8 = 0;\n\
                    }\n\
                    fn last() {\n    \
                        #[cfg(test)]\n    \
                        let _kept = 1;\n\
                    }";
        let kept = without_test_items(text);
        for line in ["fn first() {}", "fn production_after() {}", "fn last() {", "    let _kept = 1;"] {
            assert!(kept.lines().any(|l| l == line), "kept {line:?}: {kept}");
        }
        for gone in ["OPEN", "mod tests", "mod seams;", "x.rs", "static T"] {
            assert!(!kept.contains(gone), "stripped {gone:?}: {kept}");
        }
    }

    /// A one-line test item ends at its own line: the production item after
    /// it is kept, up to and including its column-0 `}`.
    #[test]
    fn a_one_line_item_ends_at_its_line() {
        let text = "#[cfg(test)]\n\
                    fn helper() {}\n\
                    #[cfg(test)]\n\
                    impl Probe for u8 {}\n\
                    fn production() {\n    \
                        body();\n\
                    }\n\
                    fn after() {}";
        let kept = without_test_items(text);
        assert_eq!(kept, "fn production() {\n    body();\n}\nfn after() {}", "{kept}");
    }

    /// An unterminated test item is a named failure, never a silent strip to
    /// the end of the file.
    #[test]
    #[should_panic(expected = "closes the test item")]
    fn an_unterminated_item_fails_by_name() {
        let _ = without_test_items("#[cfg(test)]\nmod tests {\n    fn f() {}\n");
    }
}
