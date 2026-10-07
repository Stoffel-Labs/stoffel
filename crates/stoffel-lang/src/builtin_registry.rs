use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::ast::{AstNode, Parameter, Pragma, Value};
use crate::lexer;
use crate::parser;
use crate::symbol_table::{BuiltinObjectInfo, ObjectMethodInfo, SymbolType};

const BUILTIN_DECLARATIONS: &[(&str, &str)] = &[
    ("std/core.stfl", include_str!("../stdlib/std/core.stfl")),
    ("std/mpc.stfl", include_str!("../stdlib/std/mpc.stfl")),
    (
        "std/protocols.stfl",
        include_str!("../stdlib/std/protocols.stfl"),
    ),
    ("std/crypto.stfl", include_str!("../stdlib/std/crypto.stfl")),
    ("std/avss.stfl", include_str!("../stdlib/std/avss.stfl")),
];

#[derive(Debug, Clone)]
pub struct BuiltinFunctionInfo {
    pub parameters: Vec<SymbolType>,
    pub parameter_details: Vec<BuiltinParameterInfo>,
    pub return_type: SymbolType,
    pub vm_symbol: String,
}

#[derive(Debug, Clone)]
pub struct BuiltinParameterInfo {
    pub ty: SymbolType,
    pub has_default: bool,
    pub is_variadic: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BuiltinRegistry {
    pub functions: HashMap<String, BuiltinFunctionInfo>,
    pub objects: HashMap<String, BuiltinObjectInfo>,
    pub type_aliases: HashMap<String, SymbolType>,
    pub type_names: HashSet<String>,
    pub object_type_names: HashSet<String>,
}

impl BuiltinRegistry {
    pub fn known_call_names(&self) -> HashSet<String> {
        let mut names = HashSet::new();

        for (name, info) in &self.functions {
            names.insert(name.clone());
            names.insert(info.vm_symbol.clone());
        }

        for object in self.objects.values() {
            for method in object.methods.values() {
                names.insert(method.qualified_name.clone());
            }
        }

        names
    }

    pub fn resolve_type_name(&self, name: &str) -> Option<SymbolType> {
        if let Some(alias) = self.type_aliases.get(name) {
            return Some(alias.clone());
        }

        if self.object_type_names.contains(name) {
            return Some(SymbolType::Object(name.to_string()));
        }

        None
    }

    pub fn vm_symbol_for_call(&self, name: &str) -> Option<&str> {
        if let Some(function) = self.functions.get(name) {
            return Some(function.vm_symbol.as_str());
        }

        let (object_name, method_name) = name.split_once('.')?;
        self.objects
            .get(object_name)
            .and_then(|object| object.methods.get(method_name))
            .map(|method| method.qualified_name.as_str())
    }

    pub fn is_receiver_bound_method(&self, object_name: &str, method_name: &str) -> bool {
        let Some(method) = self
            .objects
            .get(object_name)
            .and_then(|object| object.methods.get(method_name))
        else {
            return false;
        };

        matches!(
            method.parameters.first(),
            Some(SymbolType::Object(parameter_type)) if parameter_type == object_name
        )
    }
}

pub fn builtin_registry() -> &'static BuiltinRegistry {
    static REGISTRY: OnceLock<BuiltinRegistry> = OnceLock::new();
    REGISTRY.get_or_init(build_builtin_registry)
}

pub fn resolve_builtin_type_name(name: &str) -> Option<SymbolType> {
    builtin_registry().resolve_type_name(name)
}

/// The embedded standard library declaration files, as
/// `(virtual filename, source)` pairs (`("std/mpc.stfl", ...)`).
pub fn stdlib_sources() -> &'static [(&'static str, &'static str)] {
    BUILTIN_DECLARATIONS
}

fn build_builtin_registry() -> BuiltinRegistry {
    build_registry_from(BUILTIN_DECLARATIONS)
}

/// Builds a registry from `(virtual filename, source)` declaration files.
fn build_registry_from(sources: &[(&str, &str)]) -> BuiltinRegistry {
    let declarations = parse_declarations(sources);
    let mut registry = BuiltinRegistry::default();

    for node in &declarations {
        match node {
            AstNode::BuiltinTypeDefinition {
                name,
                target_type: None,
                is_opaque_object,
                ..
            } => {
                registry.type_names.insert(name.clone());
                if *is_opaque_object {
                    registry.object_type_names.insert(name.clone());
                }
            }
            AstNode::BuiltinObjectDefinition { name, .. } => {
                registry.type_names.insert(name.clone());
                registry.object_type_names.insert(name.clone());
            }
            _ => {}
        }
    }

    for node in &declarations {
        if let AstNode::BuiltinTypeDefinition {
            name,
            target_type: Some(target_type),
            ..
        } = node
        {
            let target = type_from_ast(target_type, &registry, &[]);
            registry.type_aliases.insert(name.clone(), target);
            registry.type_names.insert(name.clone());
        }
    }

    for node in &declarations {
        match node {
            AstNode::FunctionDefinition {
                name: Some(name),
                type_params,
                parameters,
                return_type,
                pragmas,
                location,
                ..
            } if has_builtin_pragma(pragmas) => {
                let vm_symbol = builtin_vm_symbol(pragmas).unwrap_or_else(|| name.clone());
                let info = BuiltinFunctionInfo {
                    parameters: parameter_types(parameters, &registry, type_params),
                    parameter_details: parameter_details(parameters, &registry, type_params),
                    return_type: return_type
                        .as_deref()
                        .map(|node| type_from_ast(node, &registry, type_params))
                        .unwrap_or(SymbolType::Void),
                    vm_symbol,
                };

                if registry.functions.insert(name.clone(), info).is_some() {
                    panic!(
                        "Duplicate builtin function '{}' declared at {}",
                        name, location
                    );
                }
            }
            AstNode::BuiltinObjectDefinition {
                name,
                methods,
                location,
            } => {
                let mut object_methods = HashMap::new();

                for method in methods {
                    let AstNode::FunctionDefinition {
                        name: Some(method_name),
                        type_params,
                        parameters,
                        return_type,
                        pragmas,
                        location: method_location,
                        ..
                    } = method
                    else {
                        panic!(
                            "Invalid builtin object method in '{}' at {}",
                            name, location
                        );
                    };

                    if !has_builtin_pragma(pragmas) {
                        panic!(
                            "Builtin object method '{}.{}' is missing {{.builtin.}} at {}",
                            name, method_name, method_location
                        );
                    }

                    let qualified_name = builtin_vm_symbol(pragmas)
                        .unwrap_or_else(|| format!("{}.{}", name, method_name));
                    let info = ObjectMethodInfo {
                        parameters: parameter_types(parameters, &registry, type_params),
                        parameter_details: parameter_details(parameters, &registry, type_params),
                        return_type: return_type
                            .as_deref()
                            .map(|node| type_from_ast(node, &registry, type_params))
                            .unwrap_or(SymbolType::Void),
                        qualified_name,
                    };

                    if object_methods.insert(method_name.clone(), info).is_some() {
                        panic!(
                            "Duplicate builtin object method '{}.{}' declared at {}",
                            name, method_name, method_location
                        );
                    }
                }

                let info = BuiltinObjectInfo {
                    name: name.clone(),
                    methods: object_methods,
                };

                if registry.objects.insert(name.clone(), info).is_some() {
                    panic!(
                        "Duplicate builtin object '{}' declared at {}",
                        name, location
                    );
                }
            }
            _ => {}
        }
    }

    registry
}

fn parse_declarations(sources: &[(&str, &str)]) -> Vec<AstNode> {
    let mut nodes = Vec::new();

    for (filename, source) in sources {
        let tokens = lexer::tokenize(source, filename).unwrap_or_else(|error| {
            panic!(
                "Failed to tokenize builtin declarations '{}': {}",
                filename, error
            )
        });
        let ast = parser::parse(&tokens, filename).unwrap_or_else(|error| {
            panic!(
                "Failed to parse builtin declarations '{}': {}",
                filename, error
            )
        });
        collect_top_level_nodes(ast, &mut nodes);
    }

    nodes
}

fn collect_top_level_nodes(node: AstNode, nodes: &mut Vec<AstNode>) {
    match node {
        AstNode::Block(statements) => {
            for statement in statements {
                nodes.push(statement);
            }
        }
        node => nodes.push(node),
    }
}

/// True when the pragmas include `{.builtin.}` or `{.builtin: "symbol".}`.
pub(crate) fn has_builtin_pragma(pragmas: &[Pragma]) -> bool {
    pragmas.iter().any(|pragma| match pragma {
        Pragma::Simple(name, _) | Pragma::KeyValue(name, _, _) => name == "builtin",
    })
}

/// The VM symbol written out in `{.builtin: "symbol".}`, if any. A bare
/// `{.builtin.}` binds the declaration's own (qualified) name instead.
pub(crate) fn builtin_vm_symbol(pragmas: &[Pragma]) -> Option<String> {
    pragmas.iter().find_map(|pragma| match pragma {
        Pragma::KeyValue(name, value, _) if name == "builtin" => match value.as_ref() {
            AstNode::Literal {
                value: Value::String(value),
                ..
            } => Some(value.clone()),
            _ => None,
        },
        _ => None,
    })
}

fn parameter_types(
    parameters: &[Parameter],
    registry: &BuiltinRegistry,
    type_params: &[String],
) -> Vec<SymbolType> {
    parameters
        .iter()
        .map(|parameter| {
            parameter
                .type_annotation
                .as_deref()
                .map(|node| type_from_ast(node, registry, type_params))
                .unwrap_or(SymbolType::Unknown)
        })
        .collect()
}

fn parameter_details(
    parameters: &[Parameter],
    registry: &BuiltinRegistry,
    type_params: &[String],
) -> Vec<BuiltinParameterInfo> {
    parameters
        .iter()
        .map(|parameter| BuiltinParameterInfo {
            ty: parameter
                .type_annotation
                .as_deref()
                .map(|node| type_from_ast(node, registry, type_params))
                .unwrap_or(SymbolType::Unknown),
            has_default: parameter.default_value.is_some(),
            is_variadic: parameter.is_variadic,
        })
        .collect()
}

fn type_from_ast(node: &AstNode, registry: &BuiltinRegistry, type_params: &[String]) -> SymbolType {
    match node {
        AstNode::Identifier(name, _) => type_from_name(name, registry, type_params),
        AstNode::SecretType(inner) => {
            SymbolType::Secret(Box::new(type_from_ast(inner, registry, type_params)))
        }
        AstNode::ListType(element_type) => {
            SymbolType::List(Box::new(type_from_ast(element_type, registry, type_params)))
        }
        AstNode::DictType {
            key_type,
            value_type,
            ..
        } => SymbolType::Dict(
            Box::new(type_from_ast(key_type, registry, type_params)),
            Box::new(type_from_ast(value_type, registry, type_params)),
        ),
        AstNode::GenericType {
            base_name,
            type_params: generic_args,
            ..
        } => SymbolType::Generic(
            base_name.clone(),
            generic_args
                .iter()
                .map(|param| type_from_ast(param, registry, type_params))
                .collect(),
        ),
        _ => SymbolType::Unknown,
    }
}

fn type_from_name(name: &str, registry: &BuiltinRegistry, type_params: &[String]) -> SymbolType {
    match name {
        "i64" | "int64" | "int" => SymbolType::Int64,
        "i32" | "int32" => SymbolType::Int32,
        "i16" | "int16" => SymbolType::Int16,
        "i8" | "int8" => SymbolType::Int8,
        "u64" | "uint64" => SymbolType::UInt64,
        "u32" | "uint32" => SymbolType::UInt32,
        "u16" | "uint16" => SymbolType::UInt16,
        "u8" | "uint8" => SymbolType::UInt8,
        "float" | "float64" | "f64" => SymbolType::Float,
        "fixed" | "fixed64" | "fix64" => SymbolType::Fixed { bits: 64 },
        "fixed32" | "fix32" => SymbolType::Fixed { bits: 32 },
        "string" => SymbolType::String,
        "bool" => SymbolType::Bool,
        "bytes" | "ByteArray" => SymbolType::List(Box::new(SymbolType::UInt8)),
        "void" => SymbolType::Void,
        "None" => SymbolType::Nil,
        _ if type_params.iter().any(|param| param == name) => SymbolType::TypeVar(name.to_string()),
        _ => registry
            .resolve_type_name(name)
            .unwrap_or_else(|| SymbolType::TypeName(name.to_string())),
    }
}

#[cfg(test)]
#[path = "../tests/rust/support/docstring_injection.rs"]
mod docstring_injection;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::docstring_injection::{inject_docstrings, strip_docstrings};
    use super::*;

    /// Order-independent rendering of everything a registry holds.
    #[derive(Debug, PartialEq)]
    struct RegistrySnapshot {
        functions: BTreeMap<String, String>,
        objects: BTreeMap<String, BTreeMap<String, String>>,
        type_aliases: BTreeMap<String, String>,
        type_names: BTreeSet<String>,
        object_type_names: BTreeSet<String>,
    }

    impl RegistrySnapshot {
        fn of(registry: &BuiltinRegistry) -> Self {
            RegistrySnapshot {
                functions: registry
                    .functions
                    .iter()
                    .map(|(name, info)| (name.clone(), format!("{info:?}")))
                    .collect(),
                objects: registry
                    .objects
                    .iter()
                    .map(|(name, object)| {
                        let methods = object
                            .methods
                            .iter()
                            .map(|(method, info)| (method.clone(), format!("{info:?}")))
                            .collect();
                        (name.clone(), methods)
                    })
                    .collect(),
                type_aliases: registry
                    .type_aliases
                    .iter()
                    .map(|(name, ty)| (name.clone(), format!("{ty:?}")))
                    .collect(),
                type_names: registry.type_names.iter().cloned().collect(),
                object_type_names: registry.object_type_names.iter().cloned().collect(),
            }
        }
    }

    /// Number of documentable declarations in a declaration file: every
    /// top-level declaration plus every builtin object method.
    fn declaration_count(ast: &AstNode) -> usize {
        let nodes = match ast {
            AstNode::Block(nodes) => nodes.as_slice(),
            node => std::slice::from_ref(node),
        };
        nodes
            .iter()
            .map(|node| match node {
                AstNode::BuiltinObjectDefinition { methods, .. } => 1 + methods.len(),
                _ => 1,
            })
            .sum()
    }

    #[test]
    fn stdlib_registry_builds() {
        let registry = builtin_registry();
        assert!(!registry.functions.is_empty());
        assert!(registry.objects.contains_key("Share"));
        assert!(registry.type_aliases.contains_key("bytes"));
    }

    /// Docstrings in every stdlib position must parse (the registry panics
    /// on a parse error, which would break every compile) and must not
    /// change a single registry entry. The stdlib's own docstrings are
    /// stripped first so that every position gets exactly one injected
    /// docstring of each shape.
    #[test]
    fn documented_stdlib_builds_an_identical_registry() {
        let documented: Vec<(&str, String)> = BUILTIN_DECLARATIONS
            .iter()
            .map(|(filename, source)| {
                (
                    *filename,
                    inject_docstrings(&strip_docstrings(source)).source,
                )
            })
            .collect();

        for (filename, source) in &documented {
            let tokens = lexer::tokenize(source, filename).expect("documented stdlib lexes");
            let (ast, docs) =
                parser::parse_with_docs(&tokens, filename).expect("documented stdlib parses");
            assert!(docs.module_doc().is_some(), "{filename}: no module doc");
            assert_eq!(
                docs.item_count(),
                declaration_count(&ast),
                "{filename}: not every declaration got a docstring"
            );
        }

        let sources: Vec<(&str, &str)> = documented
            .iter()
            .map(|(filename, source)| (*filename, source.as_str()))
            .collect();
        assert_eq!(
            RegistrySnapshot::of(&build_registry_from(&sources)),
            RegistrySnapshot::of(builtin_registry())
        );
    }
}
