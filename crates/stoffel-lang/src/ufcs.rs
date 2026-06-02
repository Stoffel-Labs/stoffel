use crate::ast::AstNode;

/// Checks if a name is a builtin object that uses qualified method names
fn is_builtin_object(name: &str) -> bool {
    crate::builtin_registry::builtin_registry()
        .objects
        .contains_key(name)
}

/// Transforms the AST to support Uniform Function Call Syntax (UFCS)
/// This allows for multiple calling styles:
/// 1. Traditional method call: obj.method(arg1, arg2)
/// 2. Function call with object as first argument: method(obj, arg1, arg2)
/// 3. Command-style call: obj method arg1 arg2 (without parentheses)
/// 4. Infix operator style: arg1.op(arg2) equivalent to op(arg1, arg2)
///
/// Special handling for builtin objects (like ClientStore):
/// - ClientStore.method(args) is transformed to call "ClientStore.method" directly
/// - The object is NOT prepended as an argument (VM doesn't expect it)
pub fn transform_ufcs(node: AstNode) -> AstNode {
    match node {
        AstNode::FunctionCall {
            function,
            arguments,
            location,
            resolved_return_type,
        } => {
            // Style 1: Transform obj.method(arg1, arg2)
            if let AstNode::FieldAccess {
                object,
                field_name,
                location: fa_location,
            } = *function
            {
                // Check if this is a builtin object method call
                if let AstNode::Identifier(obj_name, _) = &*object {
                    if is_builtin_object(obj_name) {
                        // For builtin objects, use qualified method name and don't prepend object
                        let qualified_name = format!("{}.{}", obj_name, field_name);
                        return AstNode::FunctionCall {
                            function: Box::new(AstNode::Identifier(
                                qualified_name,
                                fa_location.clone(),
                            )),
                            arguments: arguments.into_iter().map(transform_ufcs).collect(),
                            location: fa_location,
                            resolved_return_type,
                        };
                    }
                }

                // For regular objects, use standard UFCS: prepend object as first argument
                let mut new_args = vec![transform_ufcs(*object)];
                new_args.extend(arguments.into_iter().map(transform_ufcs));
                return AstNode::FunctionCall {
                    function: Box::new(AstNode::Identifier(field_name, location)),
                    arguments: new_args,
                    location: fa_location,
                    resolved_return_type,
                };
            }
            // Recursively transform arguments and the function expression itself
            AstNode::FunctionCall {
                function: Box::new(transform_ufcs(*function)),
                arguments: arguments.into_iter().map(transform_ufcs).collect(),
                location,
                resolved_return_type,
            }
        }
        // Style 3: Transform command-style calls: obj method arg1 arg2
        AstNode::CommandCall {
            command,
            arguments,
            location,
            resolved_return_type,
        } => {
            // If the command is an identifier, transform to a regular function call
            // with the first argument as the object
            if !arguments.is_empty() {
                let first_arg = transform_ufcs(arguments[0].clone());
                let remaining_args = arguments
                    .into_iter()
                    .skip(1)
                    .map(transform_ufcs)
                    .collect::<Vec<_>>();

                let mut new_args = vec![first_arg];
                new_args.extend(remaining_args);

                return AstNode::FunctionCall {
                    function: Box::new(transform_ufcs(*command)),
                    arguments: new_args,
                    location,
                    resolved_return_type, // Pass the resolved type along
                };
            }
            // If no arguments, just transform the command part
            AstNode::CommandCall {
                command: Box::new(transform_ufcs(*command)),
                arguments: arguments.into_iter().map(transform_ufcs).collect(),
                location,
                resolved_return_type, // Keep type even if no args
            }
        }
        AstNode::FieldAccess {
            object,
            field_name,
            location,
        } => {
            // Style 4: Transform infix operator calls: a.op(b) into op(a, b)
            // Check if this field access is followed by a function call (handled in FunctionCall case)
            // Otherwise, leave it as is
            AstNode::FieldAccess {
                object: Box::new(transform_ufcs(*object)),
                field_name,
                location,
            }
        }
        // Recursively transform other node types
        AstNode::VariableDeclaration {
            name,
            type_annotation,
            value,
            is_mutable,
            is_secret,
            location,
        } => AstNode::VariableDeclaration {
            name,
            type_annotation,
            value: value.map(|v| Box::new(transform_ufcs(*v))),
            is_mutable,
            is_secret,
            location,
        },
        AstNode::Assignment {
            target,
            value,
            location,
        } => AstNode::Assignment {
            target: Box::new(transform_ufcs(*target)),
            value: Box::new(transform_ufcs(*value)),
            location,
        },
        AstNode::Block(nodes) => AstNode::Block(nodes.into_iter().map(transform_ufcs).collect()),
        AstNode::FunctionDefinition {
            name,
            type_params,
            parameters,
            return_type,
            body,
            is_secret,
            pragmas,
            location,
            node_id,
        } => AstNode::FunctionDefinition {
            name,
            type_params,
            parameters,
            return_type,
            body: Box::new(transform_ufcs(*body)),
            is_secret,
            pragmas,
            location,
            node_id,
        },
        AstNode::BuiltinObjectDefinition {
            name,
            methods,
            location,
        } => AstNode::BuiltinObjectDefinition {
            name,
            methods: methods.into_iter().map(transform_ufcs).collect(),
            location,
        },
        AstNode::IfExpression {
            condition,
            then_branch,
            else_branch,
        } => AstNode::IfExpression {
            condition: Box::new(transform_ufcs(*condition)),
            then_branch: Box::new(transform_ufcs(*then_branch)),
            else_branch: else_branch.map(|e| Box::new(transform_ufcs(*e))),
        },
        AstNode::WhileLoop {
            condition,
            body,
            location,
        } => AstNode::WhileLoop {
            condition: Box::new(transform_ufcs(*condition)),
            body: Box::new(transform_ufcs(*body)),
            location,
        },
        AstNode::ForLoop {
            variables,
            iterable,
            body,
            location,
        } => AstNode::ForLoop {
            variables,
            iterable: Box::new(transform_ufcs(*iterable)),
            body: Box::new(transform_ufcs(*body)),
            location,
        },
        AstNode::Return { value, location } => AstNode::Return {
            value: value.map(|v| Box::new(transform_ufcs(*v))),
            location,
        },
        AstNode::BinaryOperation {
            op,
            left,
            right,
            location,
        } => AstNode::BinaryOperation {
            op,
            left: Box::new(transform_ufcs(*left)),
            right: Box::new(transform_ufcs(*right)),
            location,
        },
        AstNode::UnaryOperation {
            op,
            operand,
            location,
        } => AstNode::UnaryOperation {
            op,
            operand: Box::new(transform_ufcs(*operand)),
            location,
        },
        AstNode::DiscardStatement {
            expression,
            location,
        } => AstNode::DiscardStatement {
            expression: Box::new(transform_ufcs(*expression)),
            location,
        },
        AstNode::NamedArgument {
            name,
            value,
            location,
        } => AstNode::NamedArgument {
            name,
            value: Box::new(transform_ufcs(*value)),
            location,
        },
        _ => node,
    }
}
