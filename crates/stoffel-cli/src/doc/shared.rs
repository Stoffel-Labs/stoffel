//! Format-neutral pieces shared by the HTML and Markdown renderers: the
//! site description, output files, item grouping, signatures, anchors and
//! small text helpers.

use std::collections::HashSet;
use std::fmt::Write as _;

use stoffel::docs::{DocItem, DocItemKind, FunctionSignature, ModuleDoc, Section};

/// Signatures longer than this render with one parameter per line.
const SIGNATURE_WRAP_WIDTH: usize = 72;

/// What the site documents; the stdlib gets an "always in scope" banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SiteKind {
    Stdlib,
    User,
}

/// Everything needed to render a documentation site.
pub(super) struct Site<'a> {
    pub title: &'a str,
    pub kind: SiteKind,
    pub modules: &'a [ModuleDoc],
}

/// One generated file, relative to the output directory.
#[derive(Debug)]
pub(super) struct OutputFile {
    pub name: String,
    pub contents: String,
}

/// A JSON string literal that is also safe to embed in a script: `<`, `>`
/// and `&` are escaped so no `</script>` can appear.
pub(super) fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Sections of a module page, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ItemGroup {
    Objects,
    Enums,
    Functions,
    Types,
    Other,
}

impl ItemGroup {
    pub(super) const ALL: [ItemGroup; 5] = [
        ItemGroup::Objects,
        ItemGroup::Enums,
        ItemGroup::Functions,
        ItemGroup::Types,
        ItemGroup::Other,
    ];

    pub(super) fn of(kind: DocItemKind) -> Self {
        match kind {
            DocItemKind::BuiltinObject | DocItemKind::Object => ItemGroup::Objects,
            DocItemKind::Enum => ItemGroup::Enums,
            DocItemKind::Function | DocItemKind::BuiltinFunction | DocItemKind::Method => {
                ItemGroup::Functions
            }
            DocItemKind::BuiltinType | DocItemKind::OpaqueType | DocItemKind::TypeAlias => {
                ItemGroup::Types
            }
            _ => ItemGroup::Other,
        }
    }

    pub(super) fn title(self) -> &'static str {
        match self {
            ItemGroup::Objects => "Objects",
            ItemGroup::Enums => "Enums",
            ItemGroup::Functions => "Functions",
            ItemGroup::Types => "Types",
            ItemGroup::Other => "Other items",
        }
    }

    pub(super) fn id(self) -> &'static str {
        match self {
            ItemGroup::Objects => "objects",
            ItemGroup::Enums => "enums",
            ItemGroup::Functions => "functions",
            ItemGroup::Types => "types",
            ItemGroup::Other => "other-items",
        }
    }
}

pub(super) fn is_deprecated(item: &DocItem) -> bool {
    item.doc.as_ref().is_some_and(|doc| {
        doc.sections
            .iter()
            .any(|section| matches!(section, Section::Deprecated(_)))
    })
}

/// `share1.mul(share2)` for receiver-bound methods.
pub(super) fn receiver_call(item: &DocItem) -> Option<String> {
    if !item.receiver_bound {
        return None;
    }
    let function = item.function.as_ref()?;
    let (receiver, rest) = function.parameters.split_first()?;
    let arguments = rest
        .iter()
        .map(|parameter| {
            if parameter.is_variadic {
                format!("*{}", parameter.name)
            } else {
                parameter.name.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!("{}.{}({arguments})", receiver.name, item.name))
}

/// Tracks ids used on a page so every anchor is unique.
#[derive(Default)]
pub(super) struct AnchorSet {
    used: HashSet<String>,
}

impl AnchorSet {
    pub(super) fn claim(&mut self, anchor: String) -> String {
        if self.used.insert(anchor.clone()) {
            return anchor;
        }
        let mut suffix = 2;
        loop {
            let candidate = format!("{anchor}-{suffix}");
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
            suffix += 1;
        }
    }
}

/// The signature shown in an item's code block: callables get `def` and,
/// when long, one parameter per line.
pub(super) fn display_signature(item: &DocItem) -> String {
    let Some(function) = item.function.as_ref().filter(|_| item.kind.is_callable()) else {
        return item.signature.clone();
    };
    let one_line = format!("def {}", item.signature);
    if one_line.chars().count() <= SIGNATURE_WRAP_WIDTH || function.parameters.is_empty() {
        return one_line;
    }
    wrapped_signature(&item.name, function)
}

fn wrapped_signature(name: &str, function: &FunctionSignature) -> String {
    let mut out = format!("def {name}");
    if !function.type_params.is_empty() {
        let _ = write!(out, "[{}]", function.type_params.join(", "));
    }
    out.push_str("(\n");
    for parameter in &function.parameters {
        out.push_str("    ");
        if parameter.is_variadic {
            out.push('*');
        }
        out.push_str(&parameter.name);
        if let Some(ty) = &parameter.type_annotation {
            let _ = write!(out, ": {ty}");
        }
        if let Some(default) = &parameter.default_value {
            let _ = write!(out, " = {default}");
        }
        out.push_str(",\n");
    }
    out.push(')');
    if let Some(return_type) = &function.return_type {
        let _ = write!(out, " -> {return_type}");
    }
    out
}

/// Number of leading whitespace characters.
pub(super) fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

/// The text of a `- item` or `* item` line (indented by at most 3 spaces).
pub(super) fn bullet_text(line: &str) -> Option<&str> {
    if indent_of(line) > 3 {
        return None;
    }
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix("- ")
        .or_else(|| trimmed.strip_prefix("* "))
        .map(str::trim)
}

/// Removes up to `count` leading whitespace characters.
pub(super) fn strip_indent(line: &str, count: usize) -> &str {
    let mut rest = line;
    for _ in 0..count {
        match rest.chars().next() {
            Some(c) if c.is_whitespace() => rest = &rest[c.len_utf8()..],
            _ => break,
        }
    }
    rest
}
