//! Documentation support for StoffelLang `"""docstrings"""`.
//!
//! This module is the home of the `stoffel doc` pipeline:
//!
//! - [`text`]: docstring normalization used by the lexer;
//! - [`extract`]: builds the typed doc model ([`ModuleDoc`], [`DocItem`])
//!   from source, using only the lexer and
//!   [`parse_with_docs`](crate::parser::parse_with_docs);
//! - [`signature`]: prints declarations in their source spelling;
//! - [`sections`]: parses Google-style docstring sections;
//! - [`lint`]: documentation warnings and coverage.
//!
//! The model is unstable: it may change between releases while `stoffel doc`
//! matures, which is why the kind enums are `#[non_exhaustive]`.

pub mod extract;
pub mod lint;
pub mod sections;
pub mod signature;
pub mod text;

pub use crate::parser::DocTable;
pub use extract::{extract_module, extract_stdlib, link_aliases, module_name_from_path};
pub use lint::{coverage, lint, Coverage, DocWarning, DocWarningKind, WarningSeverity};
pub use sections::{code_spans, ParamDoc, ParsedDoc, Section};

use std::collections::HashMap;

use crate::errors::SourceLocation;

/// Documentation of one `.stfl` module.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleDoc {
    /// Dotted module name as used by imports (`std.mpc`, `utils.math`).
    pub name: String,
    /// The path or virtual filename the module was read from.
    pub path: String,
    /// The module docstring.
    pub doc: Option<ParsedDoc>,
    /// Top-level items in declaration order.
    pub items: Vec<DocItem>,
}

impl ModuleDoc {
    /// Every item of the module, including builtin object methods, in
    /// declaration order (each container directly followed by its members).
    pub fn all_items(&self) -> impl Iterator<Item = &DocItem> {
        self.items
            .iter()
            .flat_map(|item| std::iter::once(item).chain(item.members.iter()))
    }
}

/// What kind of declaration a [`DocItem`] documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DocItemKind {
    /// A user `def` with a body.
    Function,
    /// A top-level `def ... {.builtin.}` declaration.
    BuiltinFunction,
    /// A `def ... {.builtin.}` inside a `builtin object`.
    Method,
    /// `builtin object X:`.
    BuiltinObject,
    /// `builtin type N` or `builtin type N = T`.
    BuiltinType,
    /// `builtin opaque N`.
    OpaqueType,
    /// A user `type N = T`.
    TypeAlias,
    /// A user `object X:`.
    Object,
    /// A user `enum X:`.
    Enum,
}

impl DocItemKind {
    /// Human-readable label (`"builtin function"`).
    pub fn label(self) -> &'static str {
        match self {
            DocItemKind::Function => "function",
            DocItemKind::BuiltinFunction => "builtin function",
            DocItemKind::Method => "method",
            DocItemKind::BuiltinObject => "builtin object",
            DocItemKind::BuiltinType => "builtin type",
            DocItemKind::OpaqueType => "opaque type",
            DocItemKind::TypeAlias => "type alias",
            DocItemKind::Object => "object",
            DocItemKind::Enum => "enum",
        }
    }

    /// Prefix of the item's HTML anchor (`fn` in `#fn.pop`). Methods share
    /// their object's prefix (`#obj.Share.mul`).
    pub fn anchor_prefix(self) -> &'static str {
        match self {
            DocItemKind::Function | DocItemKind::BuiltinFunction => "fn",
            DocItemKind::Method | DocItemKind::BuiltinObject | DocItemKind::Object => "obj",
            DocItemKind::BuiltinType | DocItemKind::OpaqueType | DocItemKind::TypeAlias => "type",
            DocItemKind::Enum => "enum",
        }
    }

    /// True for kinds that declare a callable with a [`FunctionSignature`].
    pub fn is_callable(self) -> bool {
        matches!(
            self,
            DocItemKind::Function | DocItemKind::BuiltinFunction | DocItemKind::Method
        )
    }
}

/// What an alias item stands for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AliasOf {
    /// Another documented builtin, by item path (`Share.open`).
    Item(String),
    /// A VM builtin that has no StoffelLang declaration (`create_array`).
    VmBuiltin(String),
    /// A type expression in source spelling (`list[uint8]`), for type aliases.
    Type(String),
}

impl AliasOf {
    /// The alias target as written (item path, VM symbol or type).
    pub fn target(&self) -> &str {
        match self {
            AliasOf::Item(target) | AliasOf::VmBuiltin(target) | AliasOf::Type(target) => target,
        }
    }
}

/// One parameter of a [`FunctionSignature`], in source spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSignature {
    pub name: String,
    pub type_annotation: Option<String>,
    pub default_value: Option<String>,
    pub is_variadic: bool,
}

/// The parts of a callable's signature, in source spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
    pub type_params: Vec<String>,
    pub parameters: Vec<ParamSignature>,
    /// `None` when the function declares no return type (or `-> None`).
    pub return_type: Option<String>,
}

impl FunctionSignature {
    /// True when the function returns nothing (`-> void`, `-> None` or no
    /// return type).
    pub fn returns_void(&self) -> bool {
        self.return_type.as_deref().is_none_or(|ty| ty == "void")
    }
}

/// Documentation of one declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct DocItem {
    pub kind: DocItemKind,
    /// The declared name (`mul`).
    pub name: String,
    /// The path used for links and anchors (`Share.mul`, `pop`).
    pub path: String,
    /// The declaration printed in source spelling, without the body.
    pub signature: String,
    /// Parameters and return type, for callable kinds.
    pub function: Option<FunctionSignature>,
    /// The VM symbol a builtin is bound to, explicit (`{.builtin: "X".}`) or
    /// implicit (the item path).
    pub vm_symbol: Option<String>,
    /// Set when the item is another name for something else.
    pub alias_of: Option<AliasOf>,
    /// For builtin object methods: the first parameter has the object's
    /// type, so the method can be called on a value (`a.mul(b)`).
    pub receiver_bound: bool,
    pub doc: Option<ParsedDoc>,
    /// Location of the declaration header.
    pub location: SourceLocation,
    /// Methods of a builtin object.
    pub members: Vec<DocItem>,
}

impl DocItem {
    /// Names starting with `_` are private: hidden by default and not linted.
    pub fn is_private(&self) -> bool {
        self.name.starts_with('_')
    }

    /// The item's HTML anchor (`fn.pop`, `obj.Share.mul`).
    pub fn anchor(&self) -> String {
        format!("{}.{}", self.kind.anchor_prefix(), self.path)
    }

    /// The docstring summary, if documented.
    pub fn summary(&self) -> Option<&str> {
        self.doc.as_ref().map(|doc| doc.summary.as_str())
    }
}

/// A reference to a documented item, found through a [`DocIndex`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ItemRef<'a> {
    pub module: &'a ModuleDoc,
    pub item: &'a DocItem,
}

/// Lookup from item paths to documented items, for links.
///
/// Items are found by path (`Share.mul`) and by module-qualified path
/// (`std.mpc.Share.mul`). When two modules declare the same path, the plain
/// path resolves to the first one.
#[derive(Debug, Clone)]
pub struct DocIndex<'a> {
    entries: HashMap<String, ItemRef<'a>>,
}

impl<'a> DocIndex<'a> {
    pub fn new(modules: &'a [ModuleDoc]) -> Self {
        let mut entries = HashMap::new();
        for module in modules {
            for item in module.all_items() {
                let item_ref = ItemRef { module, item };
                entries.entry(item.path.clone()).or_insert(item_ref);
                entries
                    .entry(format!("{}.{}", module.name, item.path))
                    .or_insert(item_ref);
            }
        }
        DocIndex { entries }
    }

    /// Resolves an item path, plain or module-qualified.
    pub fn resolve(&self, path: &str) -> Option<ItemRef<'a>> {
        self.entries.get(path).copied()
    }
}
