//! Docstring text utilities.

/// Tab stop used when expanding tabs, matching Python's `str.expandtabs()`.
const TAB_SIZE: usize = 8;

/// Normalizes raw docstring text following the PEP 257 `trim` algorithm
/// (the semantics of Python's `inspect.cleandoc`).
///
/// - Tabs are expanded to 8-column tab stops.
/// - The first line is stripped of surrounding whitespace.
/// - The smallest indentation of the non-blank continuation lines is removed
///   from every continuation line, and trailing whitespace is stripped.
/// - Leading and trailing blank lines are removed.
///
/// Lines are joined with `\n`, regardless of the input line endings.
pub fn cleandoc(raw: &str) -> String {
    let lines: Vec<String> = raw.lines().map(expand_tabs).collect();
    let Some((first, rest)) = lines.split_first() else {
        return String::new();
    };

    let margin = rest
        .iter()
        .filter_map(|line| {
            let stripped = line.trim_start();
            (!stripped.is_empty()).then(|| line.chars().count() - stripped.chars().count())
        })
        .min();

    let mut trimmed: Vec<&str> = Vec::with_capacity(lines.len());
    trimmed.push(first.trim());
    if let Some(margin) = margin {
        trimmed.extend(rest.iter().map(|line| skip_chars(line, margin).trim_end()));
    }

    let start = trimmed
        .iter()
        .position(|line| !line.is_empty())
        .unwrap_or(trimmed.len());
    let end = trimmed
        .iter()
        .rposition(|line| !line.is_empty())
        .map_or(start, |index| index + 1);
    trimmed[start..end].join("\n")
}

/// Expands tabs to `TAB_SIZE`-column tab stops, like Python's `expandtabs()`.
fn expand_tabs(line: &str) -> String {
    let mut expanded = String::with_capacity(line.len());
    let mut column = 0;
    for ch in line.chars() {
        if ch == '\t' {
            let width = TAB_SIZE - column % TAB_SIZE;
            expanded.extend(std::iter::repeat_n(' ', width));
            column += width;
        } else {
            expanded.push(ch);
            column += 1;
        }
    }
    expanded
}

/// Returns `line` without its first `count` characters (or `""` if shorter).
fn skip_chars(line: &str, count: usize) -> &str {
    line.char_indices()
        .nth(count)
        .map_or("", |(offset, _)| &line[offset..])
}

#[cfg(test)]
mod tests {
    use super::cleandoc;

    #[test]
    fn empty_and_blank_inputs_become_empty() {
        assert_eq!(cleandoc(""), "");
        assert_eq!(cleandoc("   "), "");
        assert_eq!(cleandoc("\n\n  \n"), "");
    }

    #[test]
    fn one_line_docstring_is_stripped() {
        assert_eq!(cleandoc("  Add two shares.  "), "Add two shares.");
    }

    #[test]
    fn pep257_multi_line_example() {
        let raw = "Multi-line docstring.\n\n    Indented body line.\n      Deeper line.\n    ";
        assert_eq!(
            cleandoc(raw),
            "Multi-line docstring.\n\nIndented body line.\n  Deeper line."
        );
    }

    #[test]
    fn summary_on_second_line_is_supported() {
        let raw = "\n  Summary line.\n\n  Body.\n  ";
        assert_eq!(cleandoc(raw), "Summary line.\n\nBody.");
    }

    #[test]
    fn first_line_indentation_does_not_affect_margin() {
        let raw = "Summary.\n        Args:\n          value: x\n";
        assert_eq!(cleandoc(raw), "Summary.\nArgs:\n  value: x");
    }

    #[test]
    fn blank_lines_do_not_count_toward_margin_and_trailing_space_is_removed() {
        let raw = "Summary.\n    a   \n\n  \n    b\n";
        assert_eq!(cleandoc(raw), "Summary.\na\n\n\nb");
    }

    #[test]
    fn tabs_are_expanded_before_measuring_margin() {
        let raw = "Summary.\n\tTabbed.\n        Spaced.";
        assert_eq!(cleandoc(raw), "Summary.\nTabbed.\nSpaced.");
    }

    #[test]
    fn crlf_line_endings_are_normalized() {
        assert_eq!(cleandoc("Summary.\r\n  Body.\r\n"), "Summary.\nBody.");
    }

    #[test]
    fn non_ascii_margin_is_measured_in_chars() {
        let raw = "Résumé.\n    Größe → ü\n      ß";
        assert_eq!(cleandoc(raw), "Résumé.\nGröße → ü\n  ß");
    }
}
