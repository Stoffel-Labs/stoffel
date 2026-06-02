#[cfg(test)]
mod tests {
    use crate::ast::{AstNode, Value};
    use crate::errors::SourceLocation;
    use crate::ufcs::transform_ufcs;

    // Helper function to create an identifier node
    fn ident(name: &str, location: SourceLocation) -> AstNode {
        AstNode::Identifier(name.to_string(), location)
    }

    // Helper function to create a literal node
    fn lit_int(value: i64) -> AstNode {
        AstNode::Literal(Value::Int { value: value as u128, kind: None })
    }

    #[test]
    fn test_method_call_style() {
        // Test style 1: obj.method(arg)
        let input = AstNode::FunctionCall {
            function: Box::new(AstNode::FieldAccess {
                object: Box::new(ident("obj", Default::default())),
                field_name: "method".to_string(),
                location: Default::default(),
            }),
            arguments: vec![lit_int(42)],
            location: Default::default(),
        };

        let expected = AstNode::FunctionCall {
            function: Box::new(ident("method", Default::default())),
            arguments: vec![ident("obj", Default::default()), lit_int(42)],
            location: Default::default(),
        };

        let result = transform_ufcs(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_command_style() {
        // Test style 3: obj method arg
        let input = AstNode::CommandCall {
            command: Box::new(ident("method", Default::default())),
            arguments: vec![ident("obj", Default::default()), lit_int(42)],
        };

        let expected = AstNode::FunctionCall {
            function: Box::new(ident("method", Default::default())),
            arguments: vec![ident("obj", Default::default()), lit_int(42)],
        };

        let result = transform_ufcs(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_nested_ufcs() {
        // Test nested UFCS: a.b(c).d(e)
        let input = AstNode::FunctionCall {
            function: Box::new(AstNode::FieldAccess {
                object: Box::new(AstNode::FunctionCall {
                    function: Box::new(AstNode::FieldAccess {
                        object: Box::new(ident("a")),
                        field_name: "b".to_string(),
                    }),
                    arguments: vec![ident("c")],
                }),
                field_name: "d".to_string(),
            }),
            arguments: vec![ident("e")],
        };

        // Expected: d(b(a, c), e)
        let expected = AstNode::FunctionCall {
            function: Box::new(ident("d")),
            arguments: vec![
                AstNode::FunctionCall {
                    function: Box::new(ident("b")),
                    arguments: vec![ident("a"), ident("c")],
                },
                ident("e"),
            ],
        };

        let result = transform_ufcs(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_infix_operator_style() {
        // Test style 4: a.add(b) -> add(a, b)
        let input = AstNode::FunctionCall {
            function: Box::new(AstNode::FieldAccess {
                object: Box::new(ident("a")),
                field_name: "add".to_string(),
            }),
            arguments: vec![ident("b")],
        };

        let expected = AstNode::FunctionCall {
            function: Box::new(ident("add")),
            arguments: vec![ident("a"), ident("b")],
        };

        let result = transform_ufcs(input);
        assert_eq!(result, expected);
    }
}
