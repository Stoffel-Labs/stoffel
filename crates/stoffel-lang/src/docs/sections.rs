//! Google-style docstring sections.
//!
//! A docstring (already normalized with
//! [`cleandoc`](super::text::cleandoc)) is split into:
//!
//! - the **summary**: the first paragraph;
//! - the **body**: everything after the summary up to the first section;
//! - **sections**: a header alone on a line at the base indent (`Args:`,
//!   `Returns:`, `MPC:`, ...) followed by indented content.
//!
//! Known headers are always recognized. Any other `Title:` line becomes an
//! [`Section::Other`] only when the next non-blank line is indented, so prose
//! ending in a colon stays prose. Lines inside a fenced code block in the
//! body are never headers.

/// A docstring split into summary, body and sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDoc {
    /// The normalized docstring text.
    pub raw: String,
    /// The first paragraph, with its lines joined by single spaces.
    pub summary: String,
    /// Text between the summary and the first section, lines preserved.
    pub body: String,
    pub sections: Vec<Section>,
}

/// One documented parameter in an `Args:` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamDoc {
    /// The parameter name, without `*` for variadics.
    pub name: String,
    /// The description; continuation lines are kept on their own lines.
    pub description: String,
}

/// A docstring section. Section text is dedented, with lines preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Section {
    /// `Args:` / `Arguments:` / `Parameters:` / `Params:`.
    Args(Vec<ParamDoc>),
    /// `Returns:` / `Return:`.
    Returns(String),
    /// `Raises:` / `Raise:`.
    Raises(String),
    /// `Example:` / `Examples:`.
    Examples(String),
    /// `MPC:`: rounds, triples and what gets revealed.
    Mpc(String),
    /// `Note:` / `Notes:`.
    Notes(String),
    /// `See Also:`.
    SeeAlso(String),
    /// `Deprecated:`.
    Deprecated(String),
    /// Any other `Title:` section.
    Other { title: String, body: String },
}

impl Section {
    /// The section heading shown to readers.
    pub fn title(&self) -> &str {
        match self {
            Section::Args(_) => "Args",
            Section::Returns(_) => "Returns",
            Section::Raises(_) => "Raises",
            Section::Examples(_) => "Examples",
            Section::Mpc(_) => "MPC",
            Section::Notes(_) => "Notes",
            Section::SeeAlso(_) => "See Also",
            Section::Deprecated(_) => "Deprecated",
            Section::Other { title, .. } => title,
        }
    }

    /// The section's free text; `None` for [`Section::Args`].
    pub fn text(&self) -> Option<&str> {
        match self {
            Section::Args(_) => None,
            Section::Returns(text)
            | Section::Raises(text)
            | Section::Examples(text)
            | Section::Mpc(text)
            | Section::Notes(text)
            | Section::SeeAlso(text)
            | Section::Deprecated(text)
            | Section::Other { body: text, .. } => Some(text),
        }
    }
}

/// The recognized section headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Args,
    Returns,
    Raises,
    Examples,
    Mpc,
    Notes,
    SeeAlso,
    Deprecated,
}

impl SectionKind {
    fn from_title(title: &str) -> Option<Self> {
        let kind = match title.to_ascii_lowercase().as_str() {
            "args" | "arguments" | "parameters" | "params" => SectionKind::Args,
            "returns" | "return" => SectionKind::Returns,
            "raises" | "raise" => SectionKind::Raises,
            "example" | "examples" => SectionKind::Examples,
            "mpc" => SectionKind::Mpc,
            "note" | "notes" => SectionKind::Notes,
            "see also" => SectionKind::SeeAlso,
            "deprecated" => SectionKind::Deprecated,
            _ => return None,
        };
        Some(kind)
    }

    fn into_section(self, title: &str, body: String) -> Section {
        match self {
            SectionKind::Args => match parse_args(&body) {
                Some(params) => Section::Args(params),
                None => Section::Other {
                    title: title.to_string(),
                    body,
                },
            },
            SectionKind::Returns => Section::Returns(body),
            SectionKind::Raises => Section::Raises(body),
            SectionKind::Examples => Section::Examples(body),
            SectionKind::Mpc => Section::Mpc(body),
            SectionKind::Notes => Section::Notes(body),
            SectionKind::SeeAlso => Section::SeeAlso(body),
            SectionKind::Deprecated => Section::Deprecated(body),
        }
    }
}

/// A header line found in the docstring.
enum Header<'a> {
    Known(SectionKind, &'a str),
    Other(&'a str),
}

impl ParsedDoc {
    /// Splits a normalized docstring into summary, body and sections.
    pub fn parse(text: &str) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let headers = find_headers(&lines);

        let first_header = headers.first().map_or(lines.len(), |(index, _)| *index);
        let preamble = &lines[..first_header];
        let summary_end = preamble
            .iter()
            .position(|line| line.trim().is_empty())
            .unwrap_or(preamble.len());
        let summary = preamble[..summary_end]
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join(" ");
        let body = dedent_block(&preamble[summary_end..]);

        let mut sections = Vec::with_capacity(headers.len());
        for (position, (index, header)) in headers.iter().enumerate() {
            let end = headers
                .get(position + 1)
                .map_or(lines.len(), |(next, _)| *next);
            let content = dedent_block(&lines[index + 1..end]);
            sections.push(match header {
                Header::Known(kind, title) => kind.into_section(title, content),
                Header::Other(title) => Section::Other {
                    title: (*title).to_string(),
                    body: content,
                },
            });
        }

        ParsedDoc {
            raw: text.to_string(),
            summary,
            body,
            sections,
        }
    }

    /// The documented parameters, if the docstring has an `Args:` section.
    pub fn args(&self) -> Option<&[ParamDoc]> {
        self.sections.iter().find_map(|section| match section {
            Section::Args(params) => Some(params.as_slice()),
            _ => None,
        })
    }

    /// True when the docstring has a `Returns:` section.
    pub fn has_returns(&self) -> bool {
        self.sections
            .iter()
            .any(|section| matches!(section, Section::Returns(_)))
    }

    /// Every piece of free text in the docstring (summary, body, section
    /// text and parameter descriptions), for scanning code spans.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        let sections = self.sections.iter().flat_map(|section| {
            let params: &[ParamDoc] = match section {
                Section::Args(params) => params,
                _ => &[],
            };
            section
                .text()
                .into_iter()
                .chain(params.iter().map(|param| param.description.as_str()))
        });
        [self.summary.as_str(), self.body.as_str()]
            .into_iter()
            .chain(sections)
    }
}

/// Finds section headers: lines at the base indent that are a title followed
/// by `:`. Lines inside fenced code blocks (```` ``` ````) are skipped.
fn find_headers<'a>(lines: &[&'a str]) -> Vec<(usize, Header<'a>)> {
    let mut headers = Vec::new();
    let mut in_fence = false;
    for (index, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || indent_of(line) != 0 {
            continue;
        }
        let Some(title) = header_title(line) else {
            continue;
        };
        if let Some(kind) = SectionKind::from_title(title) {
            headers.push((index, Header::Known(kind, title)));
        } else if next_content_is_indented(&lines[index + 1..]) {
            headers.push((index, Header::Other(title)));
        }
    }
    headers
}

/// `Title:` alone on a line: the title starts with a letter and holds only
/// letters, digits and spaces (at most three words).
fn header_title(line: &str) -> Option<&str> {
    let title = line.trim_end().strip_suffix(':')?;
    let mut chars = title.chars();
    let first = chars.next()?;
    let well_formed = first.is_ascii_alphabetic()
        && title.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ')
        && !title.ends_with(' ')
        && title.split(' ').filter(|word| !word.is_empty()).count() <= 3;
    well_formed.then_some(title)
}

fn next_content_is_indented(lines: &[&str]) -> bool {
    lines
        .iter()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| indent_of(line) > 0)
}

/// Number of leading whitespace characters.
fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

/// Removes the common indentation of the non-blank lines, trims trailing
/// whitespace and drops leading and trailing blank lines.
fn dedent_block(lines: &[&str]) -> String {
    let start = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .map_or(start, |index| index + 1);
    let lines = &lines[start..end];
    let margin = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| indent_of(line))
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|line| {
            let mut chars = line.chars();
            for _ in 0..margin {
                if chars.clone().next().is_some_and(char::is_whitespace) {
                    chars.next();
                }
            }
            chars.as_str().trim_end()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parses dedented `Args:` content into entries. Each entry starts at the
/// base indent with `name: text` (or `name (type): text`); further lines
/// continue the entry. Returns `None` when the content does not start with
/// an entry, so the caller can keep it as free text.
fn parse_args(content: &str) -> Option<Vec<ParamDoc>> {
    struct Entry<'a> {
        name: &'a str,
        first: &'a str,
        continuation: Vec<&'a str>,
    }

    let mut entries: Vec<Entry<'_>> = Vec::new();
    for line in content.lines() {
        let entry_start = (indent_of(line) == 0)
            .then(|| parse_arg_line(line))
            .flatten();
        match (entry_start, entries.last_mut()) {
            (Some((name, first)), _) => entries.push(Entry {
                name,
                first,
                continuation: Vec::new(),
            }),
            (None, Some(entry)) => entry.continuation.push(line),
            (None, None) => return None,
        }
    }

    Some(
        entries
            .into_iter()
            .map(|entry| {
                let continuation = dedent_block(&entry.continuation);
                let description = match (entry.first.is_empty(), continuation.is_empty()) {
                    (_, true) => entry.first.to_string(),
                    (true, false) => continuation,
                    (false, false) => format!("{}\n{}", entry.first, continuation),
                };
                ParamDoc {
                    name: entry.name.to_string(),
                    description,
                }
            })
            .collect(),
    )
}

/// Splits `*name (type): text` into the bare name and the text.
fn parse_arg_line(line: &str) -> Option<(&str, &str)> {
    let (head, text) = line.split_once(':')?;
    if !text.is_empty() && !text.starts_with(char::is_whitespace) {
        return None;
    }
    let head = head.trim_end();
    let name = match head.split_once('(') {
        Some((name, annotation)) => {
            annotation.trim_end().ends_with(')').then_some(())?;
            name.trim_end()
        }
        None => head,
    };
    let name = name.trim_start_matches('*');
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || c == '_');
    valid.then_some((name, text.trim()))
}

/// The contents of every single-backtick code span in `text`
/// (`` `Share.open` `` gives `Share.open`). An unclosed backtick is ignored.
pub fn code_spans(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        let span = &after[..close];
        if !span.is_empty() {
            spans.push(span);
        }
        rest = &after[close + 1..];
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docs::text::cleandoc;

    fn parse(text: &str) -> ParsedDoc {
        ParsedDoc::parse(&cleandoc(text))
    }

    #[test]
    fn summary_is_the_first_paragraph() {
        let doc =
            parse("Open a secret\n  value to every party.\n\n  More detail.\n  Still body.\n");
        assert_eq!(doc.summary, "Open a secret value to every party.");
        assert_eq!(doc.body, "More detail.\nStill body.");
        assert!(doc.sections.is_empty());
    }

    #[test]
    fn one_line_docstring_has_only_a_summary() {
        let doc = parse("Add two shares.");
        assert_eq!(doc.summary, "Add two shares.");
        assert_eq!(doc.body, "");
        assert!(doc.sections.is_empty());
    }

    #[test]
    fn known_sections_are_parsed() {
        let doc = parse(
            "Reveal.

            Args:
              value: The secret value
                to reconstruct.
              *rest: Extra values.
              index (int64): Position.

            Returns:
              The clear value.

            MPC:
              One opening round.

            See Also:
              `Share.batch_open`
            ",
        );
        assert_eq!(doc.summary, "Reveal.");
        assert_eq!(
            doc.args().unwrap(),
            &[
                ParamDoc {
                    name: "value".into(),
                    description: "The secret value\nto reconstruct.".into()
                },
                ParamDoc {
                    name: "rest".into(),
                    description: "Extra values.".into()
                },
                ParamDoc {
                    name: "index".into(),
                    description: "Position.".into()
                },
            ]
        );
        assert!(doc.has_returns());
        assert_eq!(doc.sections[1], Section::Returns("The clear value.".into()));
        assert_eq!(doc.sections[2], Section::Mpc("One opening round.".into()));
        assert_eq!(
            doc.sections[3],
            Section::SeeAlso("`Share.batch_open`".into())
        );
    }

    #[test]
    fn header_aliases_and_examples_keep_indentation() {
        let doc = parse(
            "Summary.

            Parameters:
              x: X.

            Example:
              def main():
                  print(1)
            ",
        );
        assert_eq!(doc.args().unwrap()[0].name, "x");
        assert_eq!(
            doc.sections[1],
            Section::Examples("def main():\n    print(1)".into())
        );
    }

    #[test]
    fn unknown_headers_become_other_sections() {
        let doc = parse(
            "Summary.

            Security:
              Reveals nothing.
            ",
        );
        assert_eq!(
            doc.sections,
            vec![Section::Other {
                title: "Security".into(),
                body: "Reveals nothing.".into()
            }]
        );
    }

    #[test]
    fn prose_ending_in_a_colon_is_not_a_header() {
        let doc = parse(
            "Summary.

            For instance:
            the next line is not indented.
            ",
        );
        assert!(doc.sections.is_empty());
        assert_eq!(doc.body, "For instance:\nthe next line is not indented.");
    }

    #[test]
    fn headers_inside_fences_are_ignored() {
        let doc = parse(
            "Summary.

            ```
            Returns:
              nope
            ```
            ",
        );
        assert!(doc.sections.is_empty());
    }

    #[test]
    fn args_without_entries_fall_back_to_other() {
        let doc = parse(
            "Summary.

            Args:
              - not an entry
            ",
        );
        assert_eq!(
            doc.sections,
            vec![Section::Other {
                title: "Args".into(),
                body: "- not an entry".into()
            }]
        );
    }

    #[test]
    fn empty_arg_description_uses_continuation() {
        let doc = parse(
            "Summary.

            Args:
              value:
                Described below.
            ",
        );
        assert_eq!(doc.args().unwrap()[0].description, "Described below.");
    }

    #[test]
    fn code_spans_are_extracted() {
        assert_eq!(
            code_spans("Use `Share.open` or `reveal`, not `unclosed"),
            vec!["Share.open", "reveal"]
        );
        assert!(code_spans("``").is_empty());
    }
}
