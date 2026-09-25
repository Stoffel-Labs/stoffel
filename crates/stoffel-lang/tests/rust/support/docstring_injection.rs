//! Test support: rewrites StoffelLang source to carry `"""docstrings"""` in
//! every documentable position, and strips them again.
//!
//! Shared by the docstring integration tests and the builtin registry unit
//! tests (included there with `#[path]`). The rewriting is line based and
//! relies on the repository's formatting conventions: one declaration header
//! per line (a `def` header may continue over bracketed lines) and no
//! multi-line string literals.

// Every includer uses only part of this module.
#![allow(dead_code)]

/// Result of [`inject_docstrings`].
pub struct Injected {
    /// The rewritten source.
    pub source: String,
    /// Number of item docstrings inserted (the module docstring excluded).
    pub item_docstrings: usize,
}

/// The shapes of docstring the injector cycles through, so every position is
/// exercised with one-line, indented multi-line and column-0 continuation
/// lines.
#[derive(Clone, Copy)]
enum DocShape {
    OneLine,
    Indented,
    ColumnZeroContinuation,
}

impl DocShape {
    fn for_index(index: usize) -> Self {
        match index % 3 {
            0 => DocShape::OneLine,
            1 => DocShape::Indented,
            _ => DocShape::ColumnZeroContinuation,
        }
    }

    fn render(self, indent: &str, index: usize) -> String {
        match self {
            DocShape::OneLine => format!("{indent}\"\"\"Injected docstring {index}.\"\"\"\n"),
            DocShape::Indented => format!(
                "{indent}\"\"\"Injected docstring {index}.\n\n{indent}Args:\n{indent}  x: with `code`, (brackets] and \\\"quotes\\\".\n{indent}\"\"\"\n"
            ),
            DocShape::ColumnZeroContinuation => format!(
                "{indent}\"\"\"Injected docstring {index}.\n\nExample:\n    def main():\n# not a comment\n{indent}\"\"\"\n"
            ),
        }
    }
}

/// The module docstring placed at the top of every injected source. It
/// mentions `def main():` to make sure docstring text is never code.
pub const MODULE_DOCSTRING: &str =
    "\"\"\"Injected module docstring.\n\nExample:\n  def main():\n    pass\n\"\"\"\n";

/// Which kind of line a declaration header is.
enum Header {
    /// `def`, `object`, `enum` or `builtin object` header ending in `:`; the
    /// docstring goes on the next line.
    Block,
    /// A one-line `type`/`builtin type`/`builtin opaque` declaration; it
    /// gains a trailing `:` and a docstring block.
    OneLine,
}

fn leading_indent(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// Net bracket depth change of a line, ignoring brackets inside strings and
/// comments.
fn bracket_delta(line: &str) -> isize {
    let mut delta = 0;
    let mut in_string = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (in_string, c) {
            (true, '\\') => {
                chars.next();
            }
            (true, '"') => in_string = false,
            (true, _) => {}
            (false, '"') => in_string = true,
            (false, '#') => break,
            (false, '(' | '[' | '{') => delta += 1,
            (false, ')' | ']' | '}') => delta -= 1,
            (false, _) => {}
        }
    }
    delta
}

fn classify(trimmed: &str) -> Option<Header> {
    if trimmed.contains('#') || trimmed.contains("\"\"\"") {
        return None;
    }
    let block_header = ["object ", "enum ", "builtin object "]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
        && trimmed.ends_with(':');
    if block_header {
        return Some(Header::Block);
    }
    let one_line = (trimmed.starts_with("type ") && trimmed.contains('='))
        || trimmed.starts_with("builtin type ")
        || trimmed.starts_with("builtin opaque ");
    if one_line && !trimmed.ends_with(':') {
        return Some(Header::OneLine);
    }
    None
}

/// Adds a module docstring and a docstring to every `def`, `object`,
/// `enum`, `builtin object`, `builtin type`, `builtin opaque` and `type`
/// alias declaration.
pub fn inject_docstrings(source: &str) -> Injected {
    let mut out = String::from(MODULE_DOCSTRING);
    let mut item_docstrings = 0;
    // Indent of a `def` header still waiting for its closing `:` line, and
    // the bracket depth accumulated over its lines.
    let mut open_def: Option<(String, isize)> = None;

    let mut push_doc = |out: &mut String, indent: &str| {
        let nested = format!("{indent}  ");
        out.push_str(&DocShape::for_index(item_docstrings).render(&nested, item_docstrings));
        item_docstrings += 1;
    };

    for line in source.lines() {
        let trimmed = line.trim();

        if open_def.is_none() && trimmed.starts_with("def ") && !trimmed.contains('#') {
            open_def = Some((leading_indent(line).to_string(), 0));
        }

        if let Some((indent, depth)) = open_def.as_mut() {
            *depth += bracket_delta(line);
            out.push_str(line);
            out.push('\n');
            if *depth <= 0 && line.trim_end().ends_with(':') {
                let indent = indent.clone();
                open_def = None;
                push_doc(&mut out, &indent);
            } else if *depth <= 0 {
                // Not a documentable header after all (e.g. a trailing
                // comment); leave it untouched.
                open_def = None;
            }
            continue;
        }

        match classify(trimmed) {
            Some(Header::Block) => {
                out.push_str(line);
                out.push('\n');
                push_doc(&mut out, leading_indent(line));
            }
            Some(Header::OneLine) => {
                out.push_str(line.trim_end());
                out.push_str(":\n");
                push_doc(&mut out, leading_indent(line));
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }

    Injected {
        source: out,
        item_docstrings,
    }
}

/// Removes every `"""docstring"""` from `source`, together with the `:`
/// that introduces a one-line type declaration's docstring block. Only
/// docstrings that start their own line are supported.
pub fn strip_docstrings(source: &str) -> String {
    let mut kept: Vec<String> = Vec::new();
    let mut in_docstring = false;
    for line in source.lines() {
        if in_docstring {
            if line.contains("\"\"\"") {
                in_docstring = false;
            }
            continue;
        }
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("\"\"\"") {
            in_docstring = !rest.contains("\"\"\"");
            if let Some(previous) = kept.last_mut() {
                let header = previous.trim();
                let one_line_type = header.starts_with("type ")
                    || header.starts_with("builtin type ")
                    || header.starts_with("builtin opaque ");
                if one_line_type && header.ends_with(':') {
                    let without_colon = previous.trim_end().trim_end_matches(':').to_string();
                    *previous = without_colon;
                }
            }
            continue;
        }
        kept.push(line.to_string());
    }
    let mut out = kept.join("\n");
    out.push('\n');
    out
}
