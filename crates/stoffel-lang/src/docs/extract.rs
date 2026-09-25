//! Builds the doc model from StoffelLang source.
//!
//! Extraction runs only the lexer and
//! [`parse_with_docs`](crate::parser::parse_with_docs): no UFCS rewriting,
//! semantic analysis or optimization, so the AST is exactly what the author
//! wrote and the [`DocTable`](crate::parser::DocTable) keys still match it.
//! Only top-level declarations and builtin object methods are documented;
//! `def`s nested inside function bodies are local helpers and are skipped.

use std::collections::HashSet;
use std::path::{Component, Path};

use crate::ast::{AstNode, Parameter, Pragma};
use crate::builtin_registry::{builtin_vm_symbol, has_builtin_pragma, stdlib_sources};
use crate::errors::{CompilerError, SourceLocation};
use crate::lexer::tokenize;
use crate::parser::{parse_with_docs, DocTable};

use super::sections::ParsedDoc;
use super::signature::{
    format_enum, format_function, format_object, format_type_declaration, function_signature,
    type_to_source,
};
use super::{AliasOf, DocItem, DocItemKind, ModuleDoc};

/// The dotted module name for a `.stfl` path relative to its source root,
/// matching import syntax: `utils/math.stfl` gives `utils.math`, and the
/// stdlib's virtual `std/mpc.stfl` gives `std.mpc`.
pub fn module_name_from_path(relative: impl AsRef<Path>) -> String {
    let relative = relative.as_ref();
    let without_extension = if relative.extension().is_some_and(|ext| ext == "stfl") {
        relative.with_extension("")
    } else {
        relative.to_path_buf()
    };
    without_extension
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Extracts the documentation of one module.
///
/// `name` is the dotted module name (see [`module_name_from_path`]) and
/// `path` the file name used in locations. Any lexer or parser error fails
/// the extraction: partial docs could attach docstrings to the wrong
/// declaration. Builtin aliases are resolved within this module only; use
/// [`link_aliases`] to resolve them across several modules.
pub fn extract_module(
    name: &str,
    path: &str,
    source: &str,
) -> Result<ModuleDoc, Vec<CompilerError>> {
    let tokens = tokenize(source, path).map_err(|error| vec![error])?;
    let (ast, docs) = parse_with_docs(&tokens, path).map_err(|error| vec![error])?;

    let top_level = match &ast {
        AstNode::Block(nodes) => nodes.as_slice(),
        node => std::slice::from_ref(node),
    };
    let items = top_level
        .iter()
        .filter_map(|node| extract_item(node, &docs))
        .collect();

    let mut module = ModuleDoc {
        name: name.to_string(),
        path: path.to_string(),
        doc: docs.module_doc().map(ParsedDoc::parse),
        items,
    };
    link_aliases(std::slice::from_mut(&mut module));
    Ok(module)
}

/// Extracts the documentation of the embedded standard library, one
/// [`ModuleDoc`] per stdlib file (`std.core`, `std.mpc`, ...), with builtin
/// aliases resolved across all of them.
pub fn extract_stdlib() -> Result<Vec<ModuleDoc>, Vec<CompilerError>> {
    let mut modules = stdlib_sources()
        .iter()
        .map(|(path, source)| extract_module(&module_name_from_path(path), path, source))
        .collect::<Result<Vec<_>, _>>()?;
    link_aliases(&mut modules);
    Ok(modules)
}

/// Sets [`DocItem::alias_of`] on every builtin whose VM symbol is not its own
/// path.
///
/// A builtin is canonical for a VM symbol when the symbol is its own path,
/// whether written out or implicit (a bare `{.builtin.}` binds `name` or
/// `Object.method`). Another builtin bound to that symbol is an alias of the
/// canonical item (`Share.reveal` of `Share.open`); one bound to a symbol no
/// declaration owns is an alias of that VM builtin (`list` of
/// `create_array`). Type aliases are left untouched.
pub fn link_aliases(modules: &mut [ModuleDoc]) {
    let canonical: HashSet<String> = modules
        .iter()
        .flat_map(ModuleDoc::all_items)
        .filter(|item| item.vm_symbol.as_deref() == Some(item.path.as_str()))
        .map(|item| item.path.clone())
        .collect();

    for module in modules.iter_mut() {
        for item in module.items.iter_mut() {
            resolve_alias(item, &canonical);
            for member in item.members.iter_mut() {
                resolve_alias(member, &canonical);
            }
        }
    }
}

fn resolve_alias(item: &mut DocItem, canonical: &HashSet<String>) {
    let Some(vm_symbol) = &item.vm_symbol else {
        return;
    };
    item.alias_of = if *vm_symbol == item.path {
        None
    } else if canonical.contains(vm_symbol) {
        Some(AliasOf::Item(vm_symbol.clone()))
    } else {
        Some(AliasOf::VmBuiltin(vm_symbol.clone()))
    };
}

fn extract_item(node: &AstNode, docs: &DocTable) -> Option<DocItem> {
    let doc_at = |location| docs.item_doc(location).map(ParsedDoc::parse);
    match node {
        AstNode::FunctionDefinition { .. } => {
            FunctionParts::of(node).map(|parts| parts.into_item(None, docs))
        }
        AstNode::BuiltinObjectDefinition {
            name,
            methods,
            location,
        } => Some(DocItem {
            kind: DocItemKind::BuiltinObject,
            name: name.clone(),
            path: name.clone(),
            signature: format!("object {name}"),
            function: None,
            vm_symbol: None,
            alias_of: None,
            receiver_bound: false,
            doc: doc_at(location),
            location: location.clone(),
            members: methods
                .iter()
                .filter_map(FunctionParts::of)
                .map(|parts| parts.into_item(Some(name), docs))
                .collect(),
        }),
        AstNode::BuiltinTypeDefinition {
            name,
            target_type,
            is_opaque_object,
            location,
        } => {
            let (kind, signature) = if *is_opaque_object {
                (DocItemKind::OpaqueType, format!("opaque {name}"))
            } else {
                (
                    DocItemKind::BuiltinType,
                    format_type_declaration(name, target_type.as_deref()),
                )
            };
            Some(type_item(
                kind,
                name,
                signature,
                target_type.as_deref(),
                doc_at(location),
                location,
            ))
        }
        AstNode::TypeAlias {
            name,
            target_type,
            location,
            ..
        } => Some(type_item(
            DocItemKind::TypeAlias,
            name,
            format_type_declaration(name, Some(target_type)),
            Some(target_type),
            doc_at(location),
            location,
        )),
        AstNode::ObjectDefinition {
            name,
            base_type,
            fields,
            location,
            ..
        } => Some(type_item(
            DocItemKind::Object,
            name,
            format_object(name, base_type.as_deref(), fields),
            None,
            doc_at(location),
            location,
        )),
        AstNode::EnumDefinition {
            name,
            members,
            location,
            ..
        } => Some(type_item(
            DocItemKind::Enum,
            name,
            format_enum(name, members),
            None,
            doc_at(location),
            location,
        )),
        _ => None,
    }
}

fn type_item(
    kind: DocItemKind,
    name: &str,
    signature: String,
    alias_target: Option<&AstNode>,
    doc: Option<ParsedDoc>,
    location: &SourceLocation,
) -> DocItem {
    DocItem {
        kind,
        name: name.to_string(),
        path: name.to_string(),
        signature,
        function: None,
        vm_symbol: None,
        alias_of: alias_target.map(|target| AliasOf::Type(type_to_source(target))),
        receiver_bound: false,
        doc,
        location: location.clone(),
        members: Vec::new(),
    }
}

/// The parts of a `def` node that documentation needs.
struct FunctionParts<'a> {
    name: &'a str,
    type_params: &'a [String],
    parameters: &'a [Parameter],
    return_type: Option<&'a AstNode>,
    pragmas: &'a [Pragma],
    location: &'a SourceLocation,
}

impl<'a> FunctionParts<'a> {
    /// The parts of a named `def`, or `None` for any other node.
    fn of(node: &'a AstNode) -> Option<Self> {
        match node {
            AstNode::FunctionDefinition {
                name: Some(name),
                type_params,
                parameters,
                return_type,
                pragmas,
                location,
                ..
            } => Some(FunctionParts {
                name,
                type_params,
                parameters,
                return_type: return_type.as_deref(),
                pragmas,
                location,
            }),
            _ => None,
        }
    }

    /// Builds the item for a top-level `def` or, with `object`, a builtin
    /// object method.
    fn into_item(self, object: Option<&str>, docs: &DocTable) -> DocItem {
        let path = match object {
            Some(object) => format!("{object}.{}", self.name),
            None => self.name.to_string(),
        };
        let is_builtin = has_builtin_pragma(self.pragmas);
        let kind = match (object, is_builtin) {
            (Some(_), _) => DocItemKind::Method,
            (None, true) => DocItemKind::BuiltinFunction,
            (None, false) => DocItemKind::Function,
        };
        let vm_symbol =
            is_builtin.then(|| builtin_vm_symbol(self.pragmas).unwrap_or_else(|| path.clone()));
        // Mirrors `BuiltinRegistry::is_receiver_bound_method`: the first
        // parameter has the object's own type.
        let receiver_bound = object.is_some_and(|object| {
            self.parameters.first().is_some_and(|parameter| {
                matches!(
                    parameter.type_annotation.as_deref(),
                    Some(AstNode::Identifier(type_name, _)) if type_name == object
                )
            })
        });
        let function = function_signature(self.type_params, self.parameters, self.return_type);

        DocItem {
            kind,
            name: self.name.to_string(),
            signature: format_function(self.name, &function),
            path,
            function: Some(function),
            vm_symbol,
            alias_of: None,
            receiver_bound,
            doc: docs.item_doc(self.location).map(ParsedDoc::parse),
            location: self.location.clone(),
            members: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_names_follow_import_syntax() {
        assert_eq!(module_name_from_path("std/mpc.stfl"), "std.mpc");
        assert_eq!(module_name_from_path("utils/math.stfl"), "utils.math");
        assert_eq!(module_name_from_path("./main.stfl"), "main");
        assert_eq!(module_name_from_path("notes.txt"), "notes.txt");
    }
}
