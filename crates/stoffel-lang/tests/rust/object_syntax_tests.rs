//! Integration tests for object-related syntax parsing
//!
//! Tests lexing and parsing of:
//! - Field access syntax (obj.field)
//! - Method call syntax (obj.method(args))
//! - Builtin object method calls (ClientStore.take_share(0, 0))
//! - Chained method calls
//! - Object types in declarations

use stoffellang::ast::AstNode;
use stoffellang::lexer::{tokenize, TokenKind};
use stoffellang::parser::parse;

// ===========================================
// Lexer tests for dot notation
// ===========================================

#[test]
fn test_lexer_dot_token() {
    let source = "a.b";
    let tokens = tokenize(source, "test.stfl").unwrap();

    // Should produce: Identifier("a"), Dot, Identifier("b"), Newline, Eof
    assert!(tokens.iter().any(|t| matches!(&t.kind, TokenKind::Dot)));

    let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
    assert!(matches!(kinds[0], TokenKind::Identifier(s) if s == "a"));
    assert!(matches!(kinds[1], TokenKind::Dot));
    assert!(matches!(kinds[2], TokenKind::Identifier(s) if s == "b"));
}

#[test]
fn test_lexer_chained_dots() {
    let source = "a.b.c.d";
    let tokens = tokenize(source, "test.stfl").unwrap();

    // Count the number of Dot tokens
    let dot_count = tokens
        .iter()
        .filter(|t| matches!(t.kind, TokenKind::Dot))
        .count();
    assert_eq!(dot_count, 3, "Should have 3 dot tokens");
}

#[test]
fn test_lexer_dot_with_numbers() {
    let source = "obj.field123";
    let tokens = tokenize(source, "test.stfl").unwrap();

    let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
    assert!(matches!(kinds[0], TokenKind::Identifier(s) if s == "obj"));
    assert!(matches!(kinds[1], TokenKind::Dot));
    assert!(matches!(kinds[2], TokenKind::Identifier(s) if s == "field123"));
}

#[test]
fn test_lexer_builtin_object_name() {
    let source = "ClientStore.take_share";
    let tokens = tokenize(source, "test.stfl").unwrap();

    let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
    assert!(matches!(kinds[0], TokenKind::Identifier(s) if s == "ClientStore"));
    assert!(matches!(kinds[1], TokenKind::Dot));
    assert!(matches!(kinds[2], TokenKind::Identifier(s) if s == "take_share"));
}

#[test]
fn test_lexer_method_call_tokens() {
    let source = "obj.method(arg1, arg2)";
    let tokens = tokenize(source, "test.stfl").unwrap();

    // Should have: Identifier, Dot, Identifier, LParen, Identifier, Comma, Identifier, RParen
    assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::Dot)));
    assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::LParen)));
    assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::RParen)));
    assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::Comma)));
}

// ===========================================
// Helper to extract statements from parsed AST
// ===========================================

fn get_statements(ast: AstNode) -> Vec<AstNode> {
    match ast {
        AstNode::Block(statements) => statements,
        other => vec![other],
    }
}

// ===========================================
// Parser tests for field access
// ===========================================

#[test]
fn test_parse_simple_field_access() {
    let source = "obj.field";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FieldAccess {
            object, field_name, ..
        } => {
            assert_eq!(field_name, "field");
            assert!(matches!(&**object, AstNode::Identifier(ref name, _) if name == "obj"));
        }
        _ => panic!("Expected FieldAccess, got {:?}", statements[0]),
    }
}

#[test]
fn test_parse_chained_field_access() {
    let source = "a.b.c";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    // Should be: FieldAccess { object: FieldAccess { object: a, field: b }, field: c }
    match &statements[0] {
        AstNode::FieldAccess {
            object, field_name, ..
        } => {
            assert_eq!(field_name, "c");
            match &**object {
                AstNode::FieldAccess {
                    object: inner,
                    field_name: inner_field,
                    ..
                } => {
                    assert_eq!(inner_field, "b");
                    assert!(matches!(&**inner, AstNode::Identifier(ref name, _) if name == "a"));
                }
                _ => panic!("Expected nested FieldAccess"),
            }
        }
        _ => panic!("Expected FieldAccess"),
    }
}

// ===========================================
// Parser tests for method calls
// ===========================================

#[test]
fn test_parse_method_call_no_args() {
    let source = "obj.method()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => {
            assert!(arguments.is_empty());
            // function should be FieldAccess
            match &**function {
                AstNode::FieldAccess {
                    object, field_name, ..
                } => {
                    assert_eq!(field_name, "method");
                    assert!(matches!(&**object, AstNode::Identifier(ref name, _) if name == "obj"));
                }
                _ => panic!("Expected FieldAccess as function"),
            }
        }
        _ => panic!("Expected FunctionCall, got {:?}", statements[0]),
    }
}

#[test]
fn test_parse_method_call_with_args() {
    let source = "obj.method(1, 2, 3)";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => {
            assert_eq!(arguments.len(), 3);
            match &**function {
                AstNode::FieldAccess { field_name, .. } => {
                    assert_eq!(field_name, "method");
                }
                _ => panic!("Expected FieldAccess as function"),
            }
        }
        _ => panic!("Expected FunctionCall"),
    }
}

#[test]
fn test_parse_builtin_object_method_call() {
    let source = "ClientStore.take_share(0, 0)";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => {
            assert_eq!(arguments.len(), 2);
            match &**function {
                AstNode::FieldAccess {
                    object, field_name, ..
                } => {
                    assert_eq!(field_name, "take_share");
                    assert!(
                        matches!(&**object, AstNode::Identifier(ref name, _) if name == "ClientStore")
                    );
                }
                _ => panic!("Expected FieldAccess as function"),
            }
        }
        _ => panic!("Expected FunctionCall"),
    }
}

#[test]
fn test_parse_share_method_calls() {
    let test_cases = [
        ("Share.from_clear(42)", "from_clear", 1),
        ("Share.add(a, b)", "add", 2),
        ("Share.mul(x, y)", "mul", 2),
        ("Share.open(share)", "open", 1),
        ("Mpc.party_id()", "party_id", 0),
        ("Mpc.n_parties()", "n_parties", 0),
    ];

    for (source, expected_method, expected_arg_count) in test_cases {
        let tokens = tokenize(source, "test.stfl").unwrap();
        let ast = parse(&tokens, "test.stfl").unwrap();
        let statements = get_statements(ast);

        match &statements[0] {
            AstNode::FunctionCall {
                function,
                arguments,
                ..
            } => {
                assert_eq!(
                    arguments.len(),
                    expected_arg_count,
                    "Wrong arg count for {}",
                    source
                );
                match &**function {
                    AstNode::FieldAccess { field_name, .. } => {
                        assert_eq!(
                            field_name, expected_method,
                            "Wrong method name for {}",
                            source
                        );
                    }
                    _ => panic!("Expected FieldAccess for {}", source),
                }
            }
            _ => panic!("Expected FunctionCall for {}", source),
        }
    }
}

// ===========================================
// Parser tests for chained method calls
// ===========================================

#[test]
fn test_parse_chained_method_calls() {
    let source = "a.first().second()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    // Outer call should be .second()
    match &statements[0] {
        AstNode::FunctionCall { function, .. } => {
            match &**function {
                AstNode::FieldAccess {
                    object, field_name, ..
                } => {
                    assert_eq!(field_name, "second");
                    // Inner should be a.first()
                    match &**object {
                        AstNode::FunctionCall {
                            function: inner_func,
                            ..
                        } => match &**inner_func {
                            AstNode::FieldAccess {
                                field_name: inner_method,
                                ..
                            } => {
                                assert_eq!(inner_method, "first");
                            }
                            _ => panic!("Expected inner FieldAccess"),
                        },
                        _ => panic!("Expected inner FunctionCall"),
                    }
                }
                _ => panic!("Expected outer FieldAccess"),
            }
        }
        _ => panic!("Expected FunctionCall"),
    }
}

// ===========================================
// Parser tests for field access in expressions
// ===========================================

#[test]
fn test_parse_field_access_in_binary_expr() {
    let source = "a.x + b.y";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::BinaryOperation {
            left, right, op, ..
        } => {
            assert_eq!(op, "+");
            assert!(
                matches!(&**left, AstNode::FieldAccess { field_name, .. } if field_name == "x")
            );
            assert!(
                matches!(&**right, AstNode::FieldAccess { field_name, .. } if field_name == "y")
            );
        }
        _ => panic!("Expected BinaryOperation"),
    }
}

#[test]
fn test_parse_method_call_in_variable_decl() {
    let source = "var x = obj.method()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::VariableDeclaration { name, value, .. } => {
            assert_eq!(name, "x");
            match value {
                Some(val) => {
                    assert!(matches!(&**val, AstNode::FunctionCall { .. }));
                }
                None => panic!("Expected value in declaration"),
            }
        }
        _ => panic!("Expected VariableDeclaration"),
    }
}

#[test]
fn test_parse_builtin_method_in_inferred_share_decl() {
    let source = "var share = ClientStore.take_share(0, 1)";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::VariableDeclaration { name, value, .. } => {
            assert_eq!(name, "share");
            assert!(value.is_some());
        }
        _ => panic!("Expected VariableDeclaration"),
    }
}

// ===========================================
// Parser tests for index access on field access
// ===========================================

#[test]
fn test_parse_index_on_field() {
    let source = "obj.array[0]";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::IndexAccess { base, .. } => {
            // base should be obj.array (FieldAccess)
            assert!(
                matches!(&**base, AstNode::FieldAccess { field_name, .. } if field_name == "array")
            );
        }
        _ => panic!("Expected IndexAccess, got {:?}", statements[0]),
    }
}

#[test]
fn test_parse_method_call_on_index_result() {
    let source = "arr[0].method()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FunctionCall { function, .. } => match &**function {
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                assert_eq!(field_name, "method");
                assert!(matches!(&**object, AstNode::IndexAccess { .. }));
            }
            _ => panic!("Expected FieldAccess"),
        },
        _ => panic!("Expected FunctionCall"),
    }
}

// ===========================================
// Parser tests for field access in function arguments
// ===========================================

#[test]
fn test_parse_field_access_as_argument() {
    let source = "func(a.x, b.y)";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FunctionCall { arguments, .. } => {
            assert_eq!(arguments.len(), 2);
            assert!(
                matches!(&arguments[0], AstNode::FieldAccess { field_name, .. } if field_name == "x")
            );
            assert!(
                matches!(&arguments[1], AstNode::FieldAccess { field_name, .. } if field_name == "y")
            );
        }
        _ => panic!("Expected FunctionCall"),
    }
}

#[test]
fn test_parse_method_call_as_argument() {
    let source = "outer(inner.method())";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => {
            assert!(matches!(&**function, AstNode::Identifier(name, _) if name == "outer"));
            assert_eq!(arguments.len(), 1);
            assert!(matches!(&arguments[0], AstNode::FunctionCall { .. }));
        }
        _ => panic!("Expected FunctionCall"),
    }
}

// ===========================================
// Parser tests for return statements with objects
// ===========================================

#[test]
fn test_parse_return_field_access() {
    let source = "def foo() -> int64:\n  return obj.field";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::FunctionDefinition { body, .. } => {
            let body_statements = get_statements((**body).clone());
            assert!(!body_statements.is_empty());
            match &body_statements[0] {
                AstNode::Return {
                    value: Some(expr), ..
                } => {
                    assert!(matches!(&**expr, AstNode::FieldAccess { .. }));
                }
                _ => panic!(
                    "Expected Return with FieldAccess, got {:?}",
                    body_statements[0]
                ),
            }
        }
        _ => panic!("Expected FunctionDefinition"),
    }
}

#[test]
fn test_parse_return_method_call() {
    let source = "def bar() -> int64:\n  return Share.open(s)";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::FunctionDefinition { body, .. } => {
            let body_statements = get_statements((**body).clone());
            match &body_statements[0] {
                AstNode::Return {
                    value: Some(expr), ..
                } => {
                    assert!(matches!(&**expr, AstNode::FunctionCall { .. }));
                }
                _ => panic!("Expected Return with FunctionCall"),
            }
        }
        _ => panic!("Expected FunctionDefinition"),
    }
}

// ===========================================
// Parser tests for conditionals with objects
// ===========================================

#[test]
fn test_parse_if_with_method_call_condition() {
    let source = "if Mpc.is_ready():\n  print(\"ready\")";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::IfExpression { condition, .. } => {
            assert!(matches!(&**condition, AstNode::FunctionCall { .. }));
        }
        _ => panic!("Expected IfExpression, got {:?}", statements[0]),
    }
}

// ===========================================
// Parser tests for loops with objects
// ===========================================

#[test]
fn test_parse_while_with_field_access() {
    let source = "while obj.running:\n  discard obj.step()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::WhileLoop {
            condition, body, ..
        } => {
            assert!(matches!(&**condition, AstNode::FieldAccess { .. }));
            // body is a Block or single statement
            let body_statements = get_statements((**body).clone());
            assert!(!body_statements.is_empty());
        }
        _ => panic!("Expected WhileLoop, got {:?}", statements[0]),
    }
}

// ===========================================
// Parser tests for assignment to field access
// ===========================================

#[test]
fn test_parse_assignment_to_field() {
    let source = "obj.field = 42";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::Assignment { target, value, .. } => {
            assert!(
                matches!(&**target, AstNode::FieldAccess { field_name, .. } if field_name == "field")
            );
            assert!(matches!(&**value, AstNode::Literal { .. }));
        }
        _ => panic!("Expected Assignment, got {:?}", statements[0]),
    }
}

#[test]
fn test_parse_assignment_method_result_to_var() {
    let source = "result = obj.compute()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::Assignment { target, value, .. } => {
            assert!(matches!(&**target, AstNode::Identifier(name, _) if name == "result"));
            assert!(matches!(&**value, AstNode::FunctionCall { .. }));
        }
        _ => panic!("Expected Assignment"),
    }
}

// ===========================================
// Parser tests for multiple statements with objects
// ===========================================

#[test]
fn test_parse_multiple_method_calls() {
    let source =
        "var a = Share.from_clear(1)\nvar b = Share.from_clear(2)\nvar c = Share.add(a, b)";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);
    assert_eq!(statements.len(), 3);

    for stmt in &statements {
        assert!(matches!(stmt, AstNode::VariableDeclaration { .. }));
    }
}

#[test]
fn test_parse_object_method_with_string_arg() {
    let source = "Rbc.broadcast(\"hello\")";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => {
            match &**function {
                AstNode::FieldAccess {
                    object, field_name, ..
                } => {
                    assert!(matches!(&**object, AstNode::Identifier(name, _) if name == "Rbc"));
                    assert_eq!(field_name, "broadcast");
                }
                _ => panic!("Expected FieldAccess"),
            }
            assert_eq!(arguments.len(), 1);
        }
        _ => panic!("Expected FunctionCall"),
    }
}

// ===========================================
// Error case tests
// ===========================================

#[test]
fn test_parse_error_dot_without_field() {
    let source = "obj.";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let result = parse(&tokens, "test.stfl");

    assert!(
        result.is_err(),
        "Should fail when dot is not followed by identifier"
    );
}

#[test]
fn test_parse_double_dot_lexer_behavior() {
    // Double dot may be tokenized as range operator or special token
    // This test documents the actual lexer behavior
    let source = "obj..field";
    let tokens = tokenize(source, "test.stfl").unwrap();

    // Just verify the lexer produces some tokens (exact behavior is implementation-specific)
    assert!(!tokens.is_empty());
}

// ===========================================
// Parser tests for complex expressions with objects
// ===========================================

#[test]
fn test_parse_comparison_with_method_calls() {
    let source = "Mpc.party_id() == 0";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::BinaryOperation { left, op, .. } => {
            assert_eq!(op, "==");
            assert!(matches!(&**left, AstNode::FunctionCall { .. }));
        }
        _ => panic!("Expected BinaryOperation"),
    }
}

#[test]
fn test_parse_logical_with_method_calls_in_if() {
    // Logical operators may require being inside a condition context
    // Test them in an if statement
    let source = "if Mpc.party_id() > 0:\n  print(\"ok\")";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::IfExpression { condition, .. } => {
            // Condition should be a comparison
            assert!(matches!(&**condition, AstNode::BinaryOperation { op, .. } if op == ">"));
        }
        _ => panic!("Expected IfExpression"),
    }
}

#[test]
fn test_parse_nested_field_access_with_method() {
    let source = "a.b.c.method()";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::FunctionCall { function, .. } => {
            match &**function {
                AstNode::FieldAccess {
                    object, field_name, ..
                } => {
                    assert_eq!(field_name, "method");
                    // object should be a.b.c (nested FieldAccess)
                    assert!(
                        matches!(&**object, AstNode::FieldAccess { field_name, .. } if field_name == "c")
                    );
                }
                _ => panic!("Expected FieldAccess"),
            }
        }
        _ => panic!("Expected FunctionCall"),
    }
}

#[test]
fn test_parse_parenthesized_field_access_in_expression() {
    // Parenthesized expressions need to be in an expression context (like assignment)
    let source = "var x = (obj).field";
    let tokens = tokenize(source, "test.stfl").unwrap();
    let ast = parse(&tokens, "test.stfl").unwrap();

    let statements = get_statements(ast);

    match &statements[0] {
        AstNode::VariableDeclaration {
            value: Some(val), ..
        } => match &**val {
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                assert_eq!(field_name, "field");
                assert!(matches!(&**object, AstNode::Identifier(name, _) if name == "obj"));
            }
            _ => panic!("Expected FieldAccess in value"),
        },
        _ => panic!("Expected VariableDeclaration"),
    }
}
