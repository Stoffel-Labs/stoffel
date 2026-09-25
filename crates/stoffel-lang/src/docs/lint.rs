//! Documentation lint and coverage.
//!
//! Items whose name starts with `_` (and the members of such items) are
//! private: they are neither linted nor counted in coverage.

use std::collections::HashSet;
use std::fmt;

use crate::errors::SourceLocation;

use super::sections::{code_spans, ParsedDoc, Section};
use super::{AliasOf, DocIndex, DocItem, DocItemKind, ModuleDoc};

/// How serious a [`DocWarning`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WarningSeverity {
    /// Informational; does not fail `--deny-missing`.
    Note,
    Warning,
}

/// What a [`DocWarning`] is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DocWarningKind {
    /// A public module or item has no docstring.
    MissingDoc,
    /// `Args:` documents a parameter the function does not have.
    UnknownParam { name: String },
    /// `Args:` exists but leaves out one of the function's parameters.
    UndocumentedParam { name: String },
    /// A function returning nothing has a `Returns:` section.
    ReturnsOnVoid,
    /// A reference does not name a documented item or module.
    BrokenLink { target: String },
}

/// One documentation lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocWarning {
    pub kind: DocWarningKind,
    pub severity: WarningSeverity,
    /// The module the finding is in.
    pub module: String,
    /// The item path, or `None` for the module docstring.
    pub item: Option<String>,
    pub location: SourceLocation,
}

impl fmt::Display for DocWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subject = match &self.item {
            Some(path) => format!("`{path}`"),
            None => format!("module `{}`", self.module),
        };
        write!(f, "{}: ", self.location)?;
        match &self.kind {
            DocWarningKind::MissingDoc => write!(f, "{subject} has no docstring"),
            DocWarningKind::UnknownParam { name } => write!(
                f,
                "{subject} documents parameter `{name}`, which it does not have"
            ),
            DocWarningKind::UndocumentedParam { name } => {
                write!(f, "{subject} does not document parameter `{name}` in Args")
            }
            DocWarningKind::ReturnsOnVoid => write!(
                f,
                "{subject} has a Returns section but does not return a value"
            ),
            DocWarningKind::BrokenLink { target } => write!(
                f,
                "{subject} links to `{target}`, which is not a documented item"
            ),
        }
    }
}

/// Documentation coverage of public items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    /// Public items with a docstring, or aliases whose canonical item has one.
    pub documented: usize,
    /// All public items, builtin object methods included.
    pub total: usize,
}

impl Coverage {
    pub fn undocumented(&self) -> usize {
        self.total - self.documented
    }

    /// Percentage of documented items; 100 when there is nothing to document.
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            self.documented as f64 * 100.0 / self.total as f64
        }
    }

    pub fn is_complete(&self) -> bool {
        self.documented == self.total
    }
}

/// Whether an item counts as documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocStatus {
    Documented,
    /// An undocumented alias of a documented item.
    CoveredByCanonical,
    Missing,
}

fn doc_status(item: &DocItem, index: &DocIndex<'_>) -> DocStatus {
    if item.doc.is_some() {
        return DocStatus::Documented;
    }
    match &item.alias_of {
        Some(AliasOf::Item(target))
            if index
                .resolve(target)
                .is_some_and(|canonical| canonical.item.doc.is_some()) =>
        {
            DocStatus::CoveredByCanonical
        }
        _ => DocStatus::Missing,
    }
}

/// Every public item with its module, containers before their members.
fn public_items(modules: &[ModuleDoc]) -> impl Iterator<Item = (&ModuleDoc, &DocItem)> {
    modules.iter().flat_map(|module| {
        module
            .items
            .iter()
            .filter(|item| !item.is_private())
            .flat_map(move |item| {
                std::iter::once(item)
                    .chain(item.members.iter().filter(|member| !member.is_private()))
                    .map(move |item| (module, item))
            })
    })
}

/// Counts documented public items.
pub fn coverage(modules: &[ModuleDoc]) -> Coverage {
    let index = DocIndex::new(modules);
    public_items(modules).fold(Coverage::default(), |mut coverage, (_, item)| {
        coverage.total += 1;
        if doc_status(item, &index) != DocStatus::Missing {
            coverage.documented += 1;
        }
        coverage
    })
}

/// Lints the documentation of `modules`, which are also the universe of
/// valid link targets.
pub fn lint(modules: &[ModuleDoc]) -> Vec<DocWarning> {
    let index = DocIndex::new(modules);
    let linker = Linker::new(modules, &index);
    let mut warnings = Vec::new();

    for module in modules {
        let module_location = SourceLocation {
            file: module.path.clone(),
            line: 1,
            column: 1,
        };
        let mut push = |kind, severity, item: Option<&DocItem>| {
            warnings.push(DocWarning {
                kind,
                severity,
                module: module.name.clone(),
                item: item.map(|item| item.path.clone()),
                location: item
                    .map_or_else(|| module_location.clone(), |item| item.location.clone()),
            });
        };

        match &module.doc {
            Some(doc) => {
                for target in linker.broken_links(doc) {
                    push(
                        DocWarningKind::BrokenLink { target },
                        WarningSeverity::Warning,
                        None,
                    );
                }
            }
            None => push(DocWarningKind::MissingDoc, WarningSeverity::Warning, None),
        }

        for (_, item) in public_items(std::slice::from_ref(module)) {
            let Some(doc) = &item.doc else {
                let severity = match doc_status(item, &index) {
                    DocStatus::CoveredByCanonical => WarningSeverity::Note,
                    DocStatus::Documented | DocStatus::Missing => WarningSeverity::Warning,
                };
                push(DocWarningKind::MissingDoc, severity, Some(item));
                continue;
            };
            for kind in parameter_warnings(item, doc) {
                push(kind, WarningSeverity::Warning, Some(item));
            }
            for target in linker.broken_links(doc) {
                push(
                    DocWarningKind::BrokenLink { target },
                    WarningSeverity::Warning,
                    Some(item),
                );
            }
        }
    }

    warnings
}

/// `Args:` and `Returns:` checks against a callable's signature.
fn parameter_warnings(item: &DocItem, doc: &ParsedDoc) -> Vec<DocWarningKind> {
    let Some(function) = &item.function else {
        return Vec::new();
    };
    let mut warnings = Vec::new();

    if let Some(documented) = doc.args() {
        let declared: HashSet<&str> = function
            .parameters
            .iter()
            .map(|parameter| parameter.name.as_str())
            .collect();
        let named: HashSet<&str> = documented.iter().map(|param| param.name.as_str()).collect();
        warnings.extend(
            documented
                .iter()
                .filter(|param| !declared.contains(param.name.as_str()))
                .map(|param| DocWarningKind::UnknownParam {
                    name: param.name.clone(),
                }),
        );
        warnings.extend(
            function
                .parameters
                .iter()
                .filter(|parameter| !named.contains(parameter.name.as_str()))
                .map(|parameter| DocWarningKind::UndocumentedParam {
                    name: parameter.name.clone(),
                }),
        );
    }

    if doc.has_returns() && function.returns_void() {
        warnings.push(DocWarningKind::ReturnsOnVoid);
    }

    warnings
}

/// Resolves references in docstrings.
///
/// Two kinds of text are references:
/// - every entry of a `See Also:` section (code spans, or comma- and
///   line-separated names when the section has no code spans);
/// - any code span elsewhere shaped like `Object.member` whose head is a
///   documented builtin object, since that can only mean a method path.
///   (Fields of user objects and enum members are not items, so spans such
///   as `Point.x` are left alone.)
///
/// A reference resolves when it is a documented item path (plain or
/// module-qualified) or a module name.
struct Linker<'a> {
    index: &'a DocIndex<'a>,
    module_names: HashSet<&'a str>,
    containers: HashSet<&'a str>,
}

impl<'a> Linker<'a> {
    fn new(modules: &'a [ModuleDoc], index: &'a DocIndex<'a>) -> Self {
        Linker {
            index,
            module_names: modules.iter().map(|module| module.name.as_str()).collect(),
            containers: modules
                .iter()
                .flat_map(|module| module.items.iter())
                .filter(|item| item.kind == DocItemKind::BuiltinObject)
                .map(|item| item.path.as_str())
                .collect(),
        }
    }

    fn resolves(&self, target: &str) -> bool {
        self.index.resolve(target).is_some() || self.module_names.contains(target)
    }

    fn broken_links(&self, doc: &ParsedDoc) -> Vec<String> {
        let mut references: Vec<&str> = Vec::new();
        for section in &doc.sections {
            if let Section::SeeAlso(text) = section {
                let spans = code_spans(text);
                if spans.is_empty() {
                    references.extend(
                        text.split([',', '\n'])
                            .map(str::trim)
                            .filter(|name| is_item_path(name)),
                    );
                } else {
                    references.extend(spans);
                }
            }
        }
        references.extend(
            doc.texts()
                .flat_map(code_spans)
                .filter(|span| self.looks_like_member_path(span)),
        );

        let mut seen = HashSet::new();
        references
            .into_iter()
            .filter(|target| !self.resolves(target))
            .filter(|target| seen.insert(*target))
            .map(str::to_string)
            .collect()
    }

    fn looks_like_member_path(&self, span: &str) -> bool {
        is_item_path(span)
            && span
                .split_once('.')
                .is_some_and(|(head, _)| self.containers.contains(head))
    }
}

/// Dot-separated identifiers (`Share.open`, `pop`, `std.mpc`).
fn is_item_path(text: &str) -> bool {
    !text.is_empty()
        && text.split('.').all(|segment| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
                && chars.all(|c| c.is_alphanumeric() || c == '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_paths_are_dotted_identifiers() {
        assert!(is_item_path("Share.open"));
        assert!(is_item_path("pop"));
        assert!(!is_item_path("a.mul(b)"));
        assert!(!is_item_path("list[uint8]"));
        assert!(!is_item_path("Share."));
        assert!(!is_item_path(""));
    }

    #[test]
    fn empty_coverage_is_complete() {
        let coverage = coverage(&[]);
        assert!(coverage.is_complete());
        assert_eq!(coverage.percent(), 100.0);
    }
}
