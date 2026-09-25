//! Prints declarations back in their source spelling.
//!
//! This deliberately works on the raw AST instead of going through
//! [`SymbolType`](crate::symbol_table::SymbolType)'s `Display`, which
//! normalizes spellings (`bytes` becomes `list[uint8]`, `int` becomes
//! `int64`). Nodes that cannot appear in a declaration print as `…`; the
//! printer never panics.

use std::fmt::Write as _;

use crate::ast::{AstNode, EnumMember, FieldDefinition, IntKind, IntWidth, Parameter, Value};

use super::{FunctionSignature, ParamSignature};

/// Placeholder printed for nodes the printer does not understand.
pub const UNKNOWN: &str = "…";

/// Prints a type annotation (`secret list[int64]`, `dict[string, T]`).
pub fn type_to_source(node: &AstNode) -> String {
    match node {
        AstNode::Identifier(name, _) => name.clone(),
        AstNode::SecretType(inner) => format!("secret {}", type_to_source(inner)),
        AstNode::ListType(element) => format!("list[{}]", type_to_source(element)),
        AstNode::DictType {
            key_type,
            value_type,
            ..
        } => format!(
            "dict[{}, {}]",
            type_to_source(key_type),
            type_to_source(value_type)
        ),
        AstNode::GenericType {
            base_name,
            type_params,
            ..
        } => format!("{}[{}]", base_name, join(type_params, type_to_source)),
        AstNode::TupleType(elements) => format!("({})", join(elements, type_to_source)),
        AstNode::FunctionType {
            parameter_types,
            return_type,
            ..
        } => format!(
            "({}) -> {}",
            join(parameter_types, type_to_source),
            type_to_source(return_type)
        ),
        AstNode::FieldAccess {
            object, field_name, ..
        } => format!("{}.{}", type_to_source(object), field_name),
        _ => UNKNOWN.to_string(),
    }
}

/// Prints a parameter default value (`-1`, `"assertion failed"`, `True`).
pub fn default_to_source(node: &AstNode) -> String {
    match node {
        AstNode::Literal { value, .. } => literal_to_source(value),
        AstNode::Identifier(name, _) => name.clone(),
        AstNode::UnaryOperation { op, operand, .. } => {
            let separator = if op.chars().all(|c| c.is_alphabetic()) {
                " "
            } else {
                ""
            };
            format!("{op}{separator}{}", default_to_source(operand))
        }
        AstNode::FieldAccess {
            object, field_name, ..
        } => format!("{}.{}", default_to_source(object), field_name),
        _ => UNKNOWN.to_string(),
    }
}

fn literal_to_source(value: &Value) -> String {
    match value {
        Value::Int { value, kind } => match kind {
            Some(kind) => format!("{value}{}", int_suffix(kind)),
            None => value.to_string(),
        },
        Value::Float(bits) => format!("{:?}", f64::from_bits(*bits)),
        Value::String(text) => quote_string(text),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Nil => "None".to_string(),
    }
}

fn int_suffix(kind: &IntKind) -> &'static str {
    match kind {
        IntKind::Signed(IntWidth::W8) => "i8",
        IntKind::Signed(IntWidth::W16) => "i16",
        IntKind::Signed(IntWidth::W32) => "i32",
        IntKind::Signed(IntWidth::W64) => "i64",
        IntKind::Unsigned(IntWidth::W8) => "u8",
        IntKind::Unsigned(IntWidth::W16) => "u16",
        IntKind::Unsigned(IntWidth::W32) => "u32",
        IntKind::Unsigned(IntWidth::W64) => "u64",
    }
}

/// Quotes a string with the lexer's escapes (`\n \t \\ \"`). A carriage
/// return, which source strings cannot contain, prints as `\r`.
fn quote_string(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            '\r' => quoted.push_str("\\r"),
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// Builds the structured signature of a `def`.
pub fn function_signature(
    type_params: &[String],
    parameters: &[Parameter],
    return_type: Option<&AstNode>,
) -> FunctionSignature {
    FunctionSignature {
        type_params: type_params.to_vec(),
        parameters: parameters
            .iter()
            .map(|parameter| ParamSignature {
                name: parameter.name.clone(),
                type_annotation: parameter.type_annotation.as_deref().map(type_to_source),
                default_value: parameter.default_value.as_deref().map(default_to_source),
                is_variadic: parameter.is_variadic,
            })
            .collect(),
        return_type: return_type.map(type_to_source),
    }
}

/// Prints a callable signature: `pop[T](array: list[T], index: int64 = -1) -> T`.
pub fn format_function(name: &str, signature: &FunctionSignature) -> String {
    let mut out = String::from(name);
    if !signature.type_params.is_empty() {
        let _ = write!(out, "[{}]", signature.type_params.join(", "));
    }
    out.push('(');
    for (index, parameter) in signature.parameters.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
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
    }
    out.push(')');
    if let Some(return_type) = &signature.return_type {
        let _ = write!(out, " -> {return_type}");
    }
    out
}

/// Prints `object Name(Base):` followed by one indented line per field.
pub fn format_object(
    name: &str,
    base_type: Option<&AstNode>,
    fields: &[FieldDefinition],
) -> String {
    let mut out = format!("object {name}");
    if let Some(base) = base_type {
        let _ = write!(out, "({})", type_to_source(base));
    }
    out.push(':');
    for field in fields {
        let _ = write!(
            out,
            "\n  {}: {}",
            field.name,
            type_to_source(&field.type_annotation)
        );
    }
    out
}

/// Prints `enum Name:` followed by one indented line per member.
pub fn format_enum(name: &str, members: &[EnumMember]) -> String {
    let mut out = format!("enum {name}:");
    for member in members {
        let _ = write!(out, "\n  {}", member.name);
        if let Some(value) = &member.value {
            let _ = write!(out, " = {}", default_to_source(value));
        }
    }
    out
}

/// Prints a type declaration: `type bytes = list[uint8]`, `type int64`.
pub fn format_type_declaration(name: &str, target: Option<&AstNode>) -> String {
    match target {
        Some(target) => format!("type {name} = {}", type_to_source(target)),
        None => format!("type {name}"),
    }
}

fn join(nodes: &[AstNode], print: fn(&AstNode) -> String) -> String {
    nodes.iter().map(print).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SourceLocation;

    fn ident(name: &str) -> AstNode {
        AstNode::Identifier(name.to_string(), SourceLocation::default())
    }

    #[test]
    fn unknown_nodes_print_a_placeholder() {
        assert_eq!(type_to_source(&AstNode::Break), UNKNOWN);
        assert_eq!(default_to_source(&AstNode::Continue), UNKNOWN);
    }

    #[test]
    fn types_keep_their_source_spelling() {
        let node = AstNode::SecretType(Box::new(AstNode::ListType(Box::new(ident("bytes")))));
        assert_eq!(type_to_source(&node), "secret list[bytes]");
        let node = AstNode::TupleType(vec![ident("int"), ident("fix64")]);
        assert_eq!(type_to_source(&node), "(int, fix64)");
    }

    #[test]
    fn defaults_print_like_source() {
        let minus_one = AstNode::UnaryOperation {
            op: "-".to_string(),
            operand: Box::new(AstNode::Literal {
                value: Value::Int {
                    value: 1,
                    kind: None,
                },
                location: SourceLocation::default(),
            }),
            location: SourceLocation::default(),
        };
        assert_eq!(default_to_source(&minus_one), "-1");
        let not_flag = AstNode::UnaryOperation {
            op: "not".to_string(),
            operand: Box::new(ident("flag")),
            location: SourceLocation::default(),
        };
        assert_eq!(default_to_source(&not_flag), "not flag");
        let text = AstNode::Literal {
            value: Value::String("a \"b\"\n".to_string()),
            location: SourceLocation::default(),
        };
        assert_eq!(default_to_source(&text), "\"a \\\"b\\\"\\n\"");
        let byte = AstNode::Literal {
            value: Value::Int {
                value: 7,
                kind: Some(IntKind::Unsigned(IntWidth::W8)),
            },
            location: SourceLocation::default(),
        };
        assert_eq!(default_to_source(&byte), "7u8");
        let float = AstNode::Literal {
            value: Value::Float(1.5f64.to_bits()),
            location: SourceLocation::default(),
        };
        assert_eq!(default_to_source(&float), "1.5");
    }
}
