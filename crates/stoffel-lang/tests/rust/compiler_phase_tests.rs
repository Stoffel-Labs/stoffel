//! Integration tests that run the full compiler phases
//!
//! These tests exercise the lexer, parser, UFCS transformer, and semantic analyzer
//! as a unit, testing real code snippets rather than manually constructed ASTs.

use stoffel_vm_types::compiled_binary::{MpcBackend, MpcCurve};
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::DEFAULT_SECRET_REGISTER_START;
use stoffellang::ast::AstNode;
use stoffellang::compiler::{compile, CompilerOptions};
use stoffellang::convert_to_binary;
use stoffellang::errors::{CompilerError, ErrorReporter};
use stoffellang::lexer::tokenize;
use stoffellang::parser::parse;
use stoffellang::semantic::analyze;
use stoffellang::symbol_table::SymbolType;
use stoffellang::ufcs::transform_ufcs;

// ===========================================
// Helper functions
// ===========================================

fn default_options() -> CompilerOptions {
    CompilerOptions {
        optimize: false,
        optimization_level: 0,
        print_ir: false,
        mpc_backend: MpcBackend::HoneyBadger,
        mpc_curve: MpcCurve::default(),
    }
}

/// Runs lexer + parser and returns success/failure
fn parse_source(source: &str) -> Result<(), String> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| e.message)?;
    parse(&tokens, "test.stfl").map_err(|e| e.message)?;
    Ok(())
}

/// Runs full semantic analysis pipeline and returns success/failure
fn analyze_source(source: &str) -> Result<(), Vec<String>> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| vec![e.message])?;
    let ast = parse(&tokens, "test.stfl").map_err(|e| vec![e.message])?;
    let transformed = transform_ufcs(ast);
    let mut reporter = ErrorReporter::new();
    analyze(transformed, &mut reporter, "test.stfl").map_err(|_| {
        reporter
            .get_all()
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
    })?;
    Ok(())
}

fn analyze_source_errors(source: &str) -> Vec<CompilerError> {
    let tokens = tokenize(source, "test.stfl").expect("test source should lex");
    let ast = parse(&tokens, "test.stfl").expect("test source should parse");
    let transformed = transform_ufcs(ast);
    let mut reporter = ErrorReporter::new();
    analyze(transformed, &mut reporter, "test.stfl").expect_err("test source should fail");
    reporter.get_all().into_iter().cloned().collect()
}

fn analyze_source_ast(source: &str) -> Result<AstNode, Vec<String>> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| vec![e.message])?;
    let ast = parse(&tokens, "test.stfl").map_err(|e| vec![e.message])?;
    let transformed = transform_ufcs(ast);
    let mut reporter = ErrorReporter::new();
    analyze(transformed, &mut reporter, "test.stfl").map_err(|_| {
        reporter
            .get_all()
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
    })
}

fn collect_call_return_types(node: &AstNode, function_name: &str, out: &mut Vec<SymbolType>) {
    match node {
        AstNode::Block(statements) => {
            for statement in statements {
                collect_call_return_types(statement, function_name, out);
            }
        }
        AstNode::VariableDeclaration {
            value: Some(value), ..
        } => {
            collect_call_return_types(value, function_name, out);
        }
        AstNode::VariableDeclaration { value: None, .. } => {}
        AstNode::Assignment { target, value, .. } => {
            collect_call_return_types(target, function_name, out);
            collect_call_return_types(value, function_name, out);
        }
        AstNode::FunctionCall {
            function,
            arguments,
            resolved_return_type,
            ..
        } => {
            if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == function_name) {
                out.push(resolved_return_type.clone().unwrap_or(SymbolType::Unknown));
            }
            collect_call_return_types(function, function_name, out);
            for argument in arguments {
                collect_call_return_types(argument, function_name, out);
            }
        }
        AstNode::CommandCall {
            command, arguments, ..
        } => {
            collect_call_return_types(command, function_name, out);
            for argument in arguments {
                collect_call_return_types(argument, function_name, out);
            }
        }
        AstNode::FunctionDefinition { body, .. } => {
            collect_call_return_types(body, function_name, out);
        }
        AstNode::Return { value, .. } | AstNode::Yield(value) => {
            if let Some(value) = value {
                collect_call_return_types(value, function_name, out);
            }
        }
        AstNode::IfExpression {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_call_return_types(condition, function_name, out);
            collect_call_return_types(then_branch, function_name, out);
            if let Some(else_branch) = else_branch {
                collect_call_return_types(else_branch, function_name, out);
            }
        }
        AstNode::WhileLoop {
            condition, body, ..
        } => {
            collect_call_return_types(condition, function_name, out);
            collect_call_return_types(body, function_name, out);
        }
        AstNode::ForLoop { iterable, body, .. } => {
            collect_call_return_types(iterable, function_name, out);
            collect_call_return_types(body, function_name, out);
        }
        AstNode::BinaryOperation { left, right, .. } => {
            collect_call_return_types(left, function_name, out);
            collect_call_return_types(right, function_name, out);
        }
        AstNode::UnaryOperation { operand, .. } => {
            collect_call_return_types(operand, function_name, out);
        }
        AstNode::FieldAccess { object, .. } => {
            collect_call_return_types(object, function_name, out);
        }
        AstNode::IndexAccess { base, index, .. } => {
            collect_call_return_types(base, function_name, out);
            collect_call_return_types(index, function_name, out);
        }
        AstNode::ListLiteral { elements, .. }
        | AstNode::TupleLiteral(elements)
        | AstNode::SetLiteral(elements) => {
            for element in elements {
                collect_call_return_types(element, function_name, out);
            }
        }
        AstNode::DictLiteral { pairs, .. } => {
            for (key, value) in pairs {
                collect_call_return_types(key, function_name, out);
                collect_call_return_types(value, function_name, out);
            }
        }
        AstNode::NamedArgument { value, .. }
        | AstNode::DiscardStatement {
            expression: value, ..
        } => {
            collect_call_return_types(value, function_name, out);
        }
        _ => {}
    }
}

fn list_of(element_type: SymbolType) -> SymbolType {
    SymbolType::List(Box::new(element_type))
}

/// Runs full compilation and returns success/failure
fn compile_source(source: &str) -> Result<(), Vec<String>> {
    compile(source, "test.stfl", &default_options())
        .map(|_| ())
        .map_err(|errors| errors.iter().map(|e| e.message.clone()).collect())
}

fn compile_source_errors(source: &str) -> Vec<CompilerError> {
    compile(source, "test.stfl", &default_options()).expect_err("test source should fail")
}

fn assert_client_io_manifest(source: &str, expected: &[(u64, Vec<ShareType>, Vec<ShareType>)]) {
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.clients.len(), expected.len());
    for (schema, (client_slot, inputs, outputs)) in
        binary.client_io_manifest.clients.iter().zip(expected)
    {
        assert_eq!(schema.client_slot, *client_slot);
        assert_eq!(&schema.inputs, inputs);
        assert_eq!(&schema.outputs, outputs);
    }
}

fn instruction_registers(instruction: &Instruction) -> Vec<usize> {
    match instruction {
        Instruction::LD(reg, _)
        | Instruction::LDI(reg, _)
        | Instruction::RET(reg)
        | Instruction::PUSHARG(reg) => vec![*reg],
        Instruction::MOV(dest, src) | Instruction::NOT(dest, src) | Instruction::CMP(dest, src) => {
            vec![*dest, *src]
        }
        Instruction::ADD(dest, left, right)
        | Instruction::SUB(dest, left, right)
        | Instruction::MUL(dest, left, right)
        | Instruction::DIV(dest, left, right)
        | Instruction::MOD(dest, left, right)
        | Instruction::AND(dest, left, right)
        | Instruction::OR(dest, left, right)
        | Instruction::XOR(dest, left, right)
        | Instruction::SHL(dest, left, right)
        | Instruction::SHR(dest, left, right) => vec![*dest, *left, *right],
        Instruction::NOP
        | Instruction::JMP(_)
        | Instruction::JMPEQ(_)
        | Instruction::JMPNEQ(_)
        | Instruction::JMPLT(_)
        | Instruction::JMPGT(_)
        | Instruction::CALL(_) => Vec::new(),
    }
}

fn collect_call_names(instructions: &[Instruction]) -> Vec<String> {
    instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Instruction::CALL(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn assert_no_unit_moves_into_secret_register(instructions: &[Instruction]) {
    let mut unit_registers = std::collections::HashSet::new();

    for instruction in instructions {
        match instruction {
            Instruction::LDI(register, Value::Unit) => {
                unit_registers.insert(*register);
            }
            Instruction::LDI(register, _) => {
                unit_registers.remove(register);
            }
            Instruction::MOV(dest, src)
                if *dest >= DEFAULT_SECRET_REGISTER_START && unit_registers.contains(src) =>
            {
                panic!(
                    "unit value from r{src} was moved into secret register r{dest}: {instructions:?}"
                );
            }
            Instruction::MOV(dest, src) => {
                if unit_registers.contains(src) {
                    unit_registers.insert(*dest);
                } else {
                    unit_registers.remove(dest);
                }
            }
            _ => {}
        }
    }
}

/// Checks if compilation produces an error containing the given substring
fn expect_error_containing(source: &str, expected_substring: &str) -> bool {
    match compile(source, "test.stfl", &default_options()) {
        Ok(_) => false,
        Err(errors) => errors
            .iter()
            .any(|e| e.message.contains(expected_substring)),
    }
}

// ===========================================
// Lexer Phase Tests
// ===========================================

#[test]
fn test_lexer_valid_identifiers() {
    let source = "var myVar = 42\nvar _private = 1\nvar camelCase = 2";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_valid_literals() {
    let source = r#"
var a = 42
var b = 3.14
var c = "hello"
var d = True
var e = False
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_valid_operators() {
    let source = r#"
var a = 1 + 2
var b = 3 - 4
var c = 5 * 6
var d = 7 / 8
var e = 9 % 10
var f = a == b
var g = a != b
var h = a < b
var i = a > b
var j = a <= b
var k = a >= b
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_hex_literals() {
    let source = "var x = 0xFF\nvar y = 0x1A2B";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_binary_literals() {
    let source = "var x = 0b1010\nvar y = 0b11110000";
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Parser Phase Tests - Object Syntax
// ===========================================

#[test]
fn test_parser_field_access() {
    let source = "var x = obj.field";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_method_call() {
    let source = "var x = obj.method(1, 2)";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_chained_method_calls() {
    let source = "var x = a.first().second().third()";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_builtin_object_calls() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
var id = Mpc.party_id()
var n = Mpc.n_parties()
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_field_access_in_expressions() {
    let source = "var sum = a.x + b.y * c.z";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_index_and_field_combined() {
    let source = r#"
var x = arr[0].field
var y = obj.array[1]
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Parser Phase Tests - Functions
// ===========================================

#[test]
fn test_parser_function_definition() {
    let source = r#"
def add(a: int64, b: int64) -> int64:
  return a + b
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_function_no_return_type() {
    let source = r#"
def greet(name: string):
  print(name)
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_function_no_params() {
    let source = r#"
def get_value() -> int64:
  return 42
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_function_with_secret_types() {
    let source = r#"
def compute(x: secret int64) -> secret int64:
  return x * 2
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_secret_function_modifier_is_rejected() {
    let source = r#"
secret def compute(x: int64) -> int64:
  return x * 2
"#;
    assert!(expect_error_containing(
        source,
        "The 'secret' descriptor is only valid in type annotations"
    ));
}

// ===========================================
// Parser Phase Tests - Control Flow
// ===========================================

#[test]
fn test_parser_if_statement() {
    let source = r#"
if x > 0:
  print("positive")
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_if_else() {
    let source = r#"
if x > 0:
  print("positive")
else:
  print("non-positive")
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_if_elif_else() {
    let source = r#"
if x > 0:
  print("positive")
elif x < 0:
  print("negative")
else:
  print("zero")
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_while_loop() {
    let source = r#"
while x > 0:
  x = x - 1
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_for_loop() {
    // For loop syntax requires a range with ".." operator (no spaces around it)
    let source = r#"
for i in 0..10:
  print(i)
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_for_loop_list_iteration() {
    // For loop can iterate over a list variable
    let source = r#"
var items = [1, 2, 3]
for item in items:
  print(item)
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_for_loop_list_literal() {
    // For loop can iterate directly over a list literal
    let source = r#"
for x in [10, 20, 30]:
  print(x)
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Parser Phase Tests - Declarations
// ===========================================

#[test]
fn test_parser_variable_declaration() {
    let source = "var x = 42";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_typed_variable() {
    let source = "var x: int64 = 42";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_secret_variable_modifier_is_rejected() {
    let source = "secret var x = 42";
    assert!(expect_error_containing(
        source,
        "The 'secret' descriptor is only valid in type annotations"
    ));
}

#[test]
fn test_parser_secret_typed_variable() {
    let source = "var x: secret int64 = 42";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_secret_field_modifier_is_rejected() {
    let source = r#"
object SecretRecord:
  secret value: int64
"#;
    assert!(expect_error_containing(
        source,
        "The 'secret' descriptor is only valid in type annotations"
    ));
}

#[test]
fn test_parser_array_literal() {
    let source = "var arr = [1, 2, 3, 4, 5]";
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Semantic Analysis Tests - Valid Programs
// ===========================================

#[test]
fn test_semantic_simple_program() {
    let source = r#"
var x = 10
var y = 20
var z = x + y
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_function_call() {
    let source = r#"
def double(n: int64) -> int64:
  return n * 2

var result = double(21)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_print() {
    // print is a statement, test in proper context
    let source = r#"
var msg = "Hello, World!"
print(msg)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_print_accepts_multiple_mixed_arguments() {
    let source = r#"
var label = "answer"
var value = 42
print(label, "=", value, True)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_print_rejects_untyped_share_random_argument() {
    let source = r#"
print("random", Share.random())
"#;
    let errors = analyze_source_errors(source);
    assert!(
        errors.iter().any(|error| error
            .message
            .contains("Share.random() requires an expected secret integer type")),
        "expected untyped Share.random() error, got: {errors:?}"
    );
}

#[test]
fn test_semantic_array_operations() {
    let source = r#"
var arr = []
arr.append(1)
var arr_len = len(arr)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_generic_function_binds_type_parameter() {
    let source = r#"
def identity[T](value: T) -> T:
  return value

var number: int64 = identity(42)
var label: string = identity("ok")
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_generic_return_type_is_substituted_in_analyzed_ast() {
    let source = r#"
def identity[T](value: T) -> T:
  return value

var number: int64 = identity(42)
var label: string = identity("ok")
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "identity", &mut return_types);

    assert_eq!(return_types, vec![SymbolType::Int64, SymbolType::String]);
}

#[test]
fn test_semantic_generic_list_element_return_type_is_substituted() {
    let source = r#"
def first[T](items: list[T]) -> T:
  return items[0]

var number: int64 = first([1, 2])
var label: string = first(["a", "b"])
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first", &mut return_types);

    assert_eq!(return_types, vec![SymbolType::Int64, SymbolType::String]);
}

#[test]
fn test_semantic_generic_type_parameter_can_bind_to_list() {
    let source = r#"
def first[T](items: list[T]) -> T:
  return items[0]

var rows: list[list[int64]] = [[1, 2], [3, 4]]
var row: list[int64] = first(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first", &mut return_types);

    assert_eq!(
        return_types,
        vec![SymbolType::List(Box::new(SymbolType::Int64))]
    );
}

#[test]
fn test_semantic_nested_list_generic_substitution() {
    let source = r#"
def first_row[T](rows: list[list[T]]) -> list[T]:
  return rows[0]

var rows: list[list[int64]] = [[1, 2], [3, 4]]
var row: list[int64] = first_row(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first_row", &mut return_types);

    assert_eq!(return_types, vec![list_of(SymbolType::Int64)]);
}

#[test]
fn test_semantic_nested_list_generic_can_bind_t_to_list() {
    let source = r#"
def first_row[T](rows: list[list[T]]) -> list[T]:
  return rows[0]

var rows: list[list[list[int64]]] = [[[1, 2]], [[3, 4]]]
var row: list[list[int64]] = first_row(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first_row", &mut return_types);

    assert_eq!(return_types, vec![list_of(list_of(SymbolType::Int64))]);
}

#[test]
fn test_semantic_nested_list_generic_can_bind_t_to_nested_list() {
    let source = r#"
def first_row[T](rows: list[list[T]]) -> list[T]:
  return rows[0]

var rows: list[list[list[list[int64]]]] = [[[[1, 2]]], [[[3, 4]]]]
var row: list[list[list[int64]]] = first_row(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first_row", &mut return_types);

    assert_eq!(
        return_types,
        vec![list_of(list_of(list_of(SymbolType::Int64)))]
    );
}

#[test]
fn test_semantic_nested_list_generic_binding_is_consistent_when_t_is_list() {
    let source = r#"
def choose_nested[T](left: list[list[T]], right: list[T]) -> list[T]:
  return right

var left: list[list[list[int64]]] = [[[1]], [[2]]]
var right: list[list[int64]] = [[3], [4]]
var selected: list[list[int64]] = choose_nested(left, right)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "choose_nested", &mut return_types);

    assert_eq!(return_types, vec![list_of(list_of(SymbolType::Int64))]);
}

#[test]
fn test_semantic_return_only_generic_is_refined_from_assignment_type() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var shares: list[Share] = [s1, s2]
var opened_ints: list[int64] = Share.batch_open_fixed(shares)
var opened_floats: list[float] = Share.batch_open_fixed(shares)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "Share.batch_open_fixed", &mut return_types);

    assert_eq!(
        return_types,
        vec![list_of(SymbolType::Int64), list_of(SymbolType::Float)]
    );
}

#[test]
fn test_semantic_return_only_generic_is_refined_from_index_assignment_type() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var shares: list[Share] = [s1, s2]
var opened: list[list[float]]
opened[0] = Share.batch_open_fixed(shares)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "Share.batch_open_fixed", &mut return_types);

    assert_eq!(return_types, vec![list_of(SymbolType::Float)]);
}

#[test]
fn test_semantic_return_only_generic_is_refined_from_function_return_type() {
    let source = r#"
def open_as_floats(shares: list[Share]) -> list[float]:
  return Share.batch_open_fixed(shares)

var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var shares: list[Share] = [s1, s2]
var opened: list[float] = open_as_floats(shares)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "Share.batch_open_fixed", &mut return_types);

    assert_eq!(return_types, vec![list_of(SymbolType::Float)]);
}

#[test]
fn test_compile_batch_open_fixed_generic_alias_lowers_to_vm_batch_open() {
    let source = r#"
def main() -> int64:
  var s1 = Share.from_clear(10)
  var s2 = Share.from_clear(20)
  var shares: list[Share] = [s1, s2]
  var opened: list[int64] = Share.batch_open_fixed(shares)
  return opened[0]
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("batch_open_fixed should compile with contextual return type");
    let call_names = collect_call_names(&program.main_chunk.instructions);

    assert!(
        call_names.iter().any(|name| name == "Share.batch_open"),
        "batch_open_fixed should lower to VM Share.batch_open, got {call_names:?}"
    );
    assert!(
        call_names
            .iter()
            .all(|name| !name.contains('[') && !name.contains("unknown")),
        "generic source types must not leak into VM call names: {call_names:?}"
    );
}

#[test]
fn test_compile_share_reveal_method_lowers_to_vm_open() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
var revealed: uint64 = share.reveal()
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.open"),
        "Share reveal method should lower to VM Share.open, got {call_names:?}"
    );
}

#[test]
fn test_compile_secret_uint64_reveal_method_lowers_to_vm_open() {
    let source = r#"
var share: secret uint64 = ClientStore.take_share(0, 0)
var revealed: uint64 = share.reveal()
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.open"),
        "secret uint64 reveal method should lower to VM Share.open, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_contextual_secret_int64_lowers_to_typed_random() {
    let source = r#"
def main() -> secret int64:
  var s: secret int64 = Share.random()
  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "typed Share.random should lower to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_contextual_secret_bool_lowers_to_one_bit_random() {
    let source = r#"
def main() -> secret bool:
  var test: secret bool = Share.random()
  return test
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let instructions = &program.main_chunk.instructions;
    let call_names = collect_call_names(instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "secret bool Share.random should lower to VM Share.random_int, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed secret bool context must not leave raw Share.random calls, got {call_names:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::LDI(_, Value::I64(1)))),
        "secret bool Share.random should request a 1-bit random int, got {instructions:?}"
    );
}

#[test]
fn test_compile_share_random_contextual_secret_uint8_lowers_to_typed_random() {
    let source = r#"
def main() -> secret uint8:
  var s: secret uint8 = Share.random()
  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "typed Share.random should lower to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_explicit_share_random_int_can_initialize_secret_int64() {
    let source = r#"
def main() -> secret int64:
  var s: secret int64 = Share.random_int(31)
  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "explicit Share.random_int should lower to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_in_secret_int_list_index_assignment() {
    let source = r#"
def main() -> secret int64:
  var values: list[secret int64]
  values[0] = Share.random()
  return values[0]
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "indexed assignment context should lower Share.random to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_untyped_requires_secret_integer_context() {
    let source = r#"
var s = Share.random()
"#;
    assert!(expect_error_containing(
        source,
        "Share.random() requires an expected secret integer type"
    ));
}

#[test]
fn test_compile_share_random_in_secret_int_list_append_lowers_to_typed_random() {
    let source = r#"
def main() -> secret int64:
  var values: list[secret int64]
  values.append(Share.random())
  return values[0]
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "Share.random in list append should lower to VM Share.random_int, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed list append context must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_share_random_in_secret_int_function_argument() {
    let source = r#"
def id_secret(value: secret int64) -> secret int64:
  return value

def main() -> secret int64:
  return id_secret(Share.random())
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "secret int64 function parameter should contextualize Share.random, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed function argument context must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_share_random_in_secret_int_list_literal() {
    let source = r#"
def main() -> secret int64:
  var values: list[secret int64] = [Share.random()]
  return values[0]
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "secret int64 list literal should contextualize Share.random, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed list literal context must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_empty_list_literal_in_function_argument() {
    let source = r#"
def count(values: list[int64]) -> int64:
  return 0

def main() -> int64:
  return count([])
"#;
    assert!(compile(source, "test.stfl", &default_options()).is_ok());
}

#[test]
fn test_compile_share_random_share_annotation_is_rejected() {
    let source = r#"
var s: Share = Share.random()
"#;
    assert!(expect_error_containing(
        source,
        "Share.random() requires an expected secret integer type"
    ));
}

#[test]
fn test_compile_share_random_rejects_secret_float_context() {
    let source = r#"
var s: secret float = Share.random()
"#;
    assert!(expect_error_containing(
        source,
        "Share.random() requires an expected secret integer type"
    ));
}

#[test]
fn test_compile_additive_share_program_uses_contextual_share_random() {
    let source = r#"
object AdditiveShare:
  player: int64
  share: secret int64

def main(a: secret int64, b: secret int64) -> secret int64:
  var s: secret int64 = Share.random()
  var acc: secret int64

  var additive_shares: list[AdditiveShare]

  for i in 0..ClientStore.get_number_clients():
    var additive_share: AdditiveShare
    additive_share.player = i
    var sub_share: secret int64 = 0
    if i == ClientStore.get_number_clients()-1:
      sub_share = s - acc
    else:
      sub_share = Share.random()
      acc += sub_share
    MpcOutput.send_to_client(i, sub_share)
    additive_share.share = sub_share
    additive_shares.append(additive_share)

  for i in additive_shares:
    var sub_share: secret int64 = ClientStore.take_share(i.player, 0)
    var acc: secret int64 = 0
    if i.share.reveal() == sub_share.reveal():
      print("additive shares match")
      acc += sub_share

    print(s.reveal())
    print(acc.reveal())

  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "additive share program should use typed random, got {call_names:?}"
    );
    assert_no_unit_moves_into_secret_register(&program.main_chunk.instructions);
}

#[test]
fn test_semantic_secret_uint64_requires_explicit_reveal() {
    let source = r#"
var share: secret uint64 = ClientStore.take_share(0, 0)
var revealed: uint64 = share
"#;
    let errors = analyze_source(source).expect_err("implicit reveal should fail");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("Cannot implicitly reveal")),
        "expected implicit reveal rejection, got {errors:?}"
    );
}

#[test]
fn test_compile_reveal_method_inside_list_literal() {
    let source = r#"
var share: secret uint64 = ClientStore.take_share(0, 0)
var revealed: list[uint64] = [share.reveal()]
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_semantic_nested_list_generic_rejects_inconsistent_t_list_binding() {
    let source = r#"
def choose_nested[T](left: list[list[T]], right: list[T]) -> list[T]:
  return right

var left: list[list[list[int64]]] = [[[1]], [[2]]]
var right: list[int64] = [3, 4]
var selected = choose_nested(left, right)
"#;
    let errors =
        analyze_source(source).expect_err("inconsistent nested generic binding should fail");
    assert!(
        errors.iter().any(|error| error.contains("Type mismatch")),
        "expected type mismatch error, got {errors:?}"
    );
}

#[test]
fn test_semantic_nested_list_generic_rejects_inconsistent_t_element_binding() {
    let source = r#"
def pair_rows[T](left: list[list[T]], right: list[list[T]]) -> list[T]:
  return left[0]

var left: list[list[int64]] = [[1], [2]]
var right: list[list[string]] = [["bad"]]
var selected = pair_rows(left, right)
"#;
    let errors = analyze_source(source)
        .expect_err("inconsistent nested generic element binding should fail");
    assert!(
        errors.iter().any(|error| error.contains("Type mismatch")),
        "expected type mismatch error, got {errors:?}"
    );
}

#[test]
fn test_semantic_nested_list_append_accepts_matching_nested_element() {
    let source = r#"
var rows: list[list[int64]] = []
rows.append([1, 2])

var cubes: list[list[list[int64]]] = []
cubes.append([[1], [2]])
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_nested_list_append_rejects_wrong_nested_element_shape() {
    let source = r#"
var rows: list[list[int64]] = []
rows.append(1)
"#;
    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_nested_list_append_rejects_wrong_nested_element_type() {
    let source = r#"
var rows: list[list[int64]] = []
rows.append(["bad"])
"#;
    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_variable_index_access_for_lists_and_strings() {
    let source = r#"
def at[T](items: list[T], index: int64) -> T:
  return items[index]

var index: int64 = 1
var items: list[int64] = [10, 20, 30]
var item: int64 = at(items, index)

var rows: list[list[int64]] = [[1, 2], [3, 4]]
var row: list[int64] = at(rows, index)

var text: string = "abc"
var letter: string = text[index]
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "at", &mut return_types);

    assert_eq!(
        return_types,
        vec![SymbolType::Int64, list_of(SymbolType::Int64)]
    );
}

#[test]
fn test_compile_variable_index_access_lowers_to_get_field() {
    let source = r#"
def at[T](items: list[T], index: int64) -> T:
  return items[index]

def main() -> int64:
  var index: int64 = 1
  var items: list[int64] = [10, 20, 30]
  var nested: list[list[int64]] = [[1, 2], [3, 4]]
  var row: list[int64] = nested[index]
  return at(items, index) + row[index]
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("variable index access should compile");

    let at_chunk = program
        .function_chunks
        .get("at")
        .expect("generic index helper should be emitted");
    let at_calls = collect_call_names(&at_chunk.instructions);
    assert!(
        at_calls.iter().any(|name| name == "get_field"),
        "items[index] should lower to VM get_field, got {at_calls:?}"
    );

    let entry_calls = collect_call_names(&program.main_chunk.instructions);
    assert!(
        entry_calls.iter().any(|name| name == "get_field"),
        "nested[index] should lower to VM get_field, got {entry_calls:?}"
    );
    assert!(
        entry_calls.iter().any(|name| name == "at"),
        "entry bytecode should call generic at helper, got {entry_calls:?}"
    );
}

#[test]
fn test_compile_local_nested_generics_example_bytecode_shape() {
    let source = include_str!("../../examples/local_nested_generics/main.stfl");
    let program = compile(
        source,
        "examples/local_nested_generics/main.stfl",
        &default_options(),
    )
    .expect("local nested generics example should compile");

    assert!(
        program.function_chunks.contains_key("first_row"),
        "generic helper should be emitted as a VM function"
    );
    assert!(
        program.function_chunks.contains_key("first_cell"),
        "generic helper should be emitted as a VM function"
    );
    assert!(
        program.function_chunks.contains_key("choose_nested"),
        "generic helper should be emitted as a VM function"
    );
    assert!(
        program.function_chunks.contains_key("at"),
        "generic index helper should be emitted as a VM function"
    );

    let call_names = collect_call_names(&program.main_chunk.instructions);

    assert!(
        call_names.iter().any(|name| name == "first_row"),
        "entry bytecode should call first_row, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "first_cell"),
        "entry bytecode should call first_cell, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "choose_nested"),
        "entry bytecode should call choose_nested, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "at"),
        "entry bytecode should call generic at helper, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "append"),
        "list method syntax should lower to VM append, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "len"),
        "list len method syntax should lower to VM len, got {call_names:?}"
    );
    assert!(
        call_names
            .iter()
            .all(|name| !name.contains('[') && !name.contains("unknown")),
        "generic source types must not leak into VM call names: {call_names:?}"
    );
}

#[test]
fn test_compile_matrix_average_fixed_point_uses_nested_generic_bytecode() {
    let source = include_str!("../stfl/matrix_average_fixed_point.stfl");
    let program = compile(
        source,
        "tests/stfl/matrix_average_fixed_point.stfl",
        &default_options(),
    )
    .expect("matrix average fixed-point fixture should compile");

    for helper in [
        "matrix_get",
        "matrix_row",
        "append_matrix_row",
        "reshape_2x3",
    ] {
        assert!(
            program.function_chunks.contains_key(helper),
            "expected helper function '{helper}' to be emitted"
        );
    }

    let average_chunk = program
        .function_chunks
        .get("federated_average_2x3")
        .expect("average helper should be emitted");
    let average_calls = collect_call_names(&average_chunk.instructions);

    assert!(
        !average_calls
            .iter()
            .any(|name| name == "load_client_matrix_2x3"),
        "average bytecode should not rebuild full client matrices per element, got {average_calls:?}"
    );
    assert!(
        average_calls
            .iter()
            .any(|name| name == "ClientStore.take_share_fixed"),
        "average bytecode should load each flat matrix element directly, got {average_calls:?}"
    );
    assert!(
        average_calls.iter().any(|name| name == "Share.batch_open"),
        "average bytecode should batch-open all flat sums before clear division, got {average_calls:?}"
    );
    assert!(
        average_calls.iter().any(|name| name == "reshape_2x3"),
        "average bytecode should reshape flat averages into a matrix, got {average_calls:?}"
    );
    assert!(
        average_calls.iter().any(|name| name == "append"),
        "row construction should lower .append() to VM append, got {average_calls:?}"
    );
    assert!(
        average_calls
            .iter()
            .all(|name| !name.contains('[') && !name.contains("unknown")),
        "generic source types must not leak into VM call names: {average_calls:?}"
    );

    let main_calls = collect_call_names(&program.main_chunk.instructions);
    assert!(
        main_calls.iter().any(|name| name == "matrix_get"),
        "main bytecode should call matrix_get with T = float, got {main_calls:?}"
    );
    assert!(
        main_calls.iter().any(|name| name == "matrix_row"),
        "main bytecode should call matrix_row with T = float, got {main_calls:?}"
    );
}

#[test]
fn test_semantic_generic_binding_is_consistent_across_parameters() {
    let source = r#"
def choose[T](left: T, right: T) -> T:
  return left

var value = choose(1, "bad")
"#;
    let errors = analyze_source(source).expect_err("mixed generic binding should fail");
    assert!(
        errors.iter().any(|error| error.contains("Type mismatch")),
        "expected type mismatch error, got {errors:?}"
    );
}

#[test]
fn test_semantic_generic_append_rejects_wrong_element_type() {
    let source = r#"
var items: list[int64] = []
items.append("bad")
"#;
    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_unknown_is_not_a_source_type() {
    let source = r#"
var value: unknown = 1
"#;
    assert!(expect_error_containing(source, "Undefined type 'unknown'"));
}

#[test]
fn test_semantic_nested_function_calls() {
    let source = r#"
def inner(x: int64) -> int64:
  return x + 1

def outer(x: int64) -> int64:
  return inner(x) * 2

var result = outer(5)
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Semantic Analysis Tests - Object Methods
// ===========================================

#[test]
fn test_semantic_client_store_take_share() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_mpc_methods() {
    let source = r#"
var party = Mpc.party_id()
var total = Mpc.n_parties()
var thresh = Mpc.threshold()
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_operations() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var sum = Share.add(s1, s2)
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Semantic Analysis Tests - Error Detection
// ===========================================

#[test]
fn test_semantic_error_undefined_variable() {
    let source = "var x = undefined_var + 1";
    assert!(expect_error_containing(source, "undefined_var"));
}

#[test]
fn test_semantic_error_undefined_function() {
    let source = "var x = undefined_function(42)";
    assert!(expect_error_containing(source, "undefined_function"));
}

#[test]
fn test_semantic_error_duplicate_variable() {
    let source = r#"
var x = 10
var x = 20
"#;
    let result = analyze_source(source);
    assert!(result.is_err(), "Should detect duplicate variable");
}

#[test]
fn test_semantic_error_wrong_argument_count() {
    let source = r#"
def foo(a: int64, b: int64) -> int64:
  return a + b

var x = foo(1)
"#;
    assert!(expect_error_containing(source, "argument"));
}

#[test]
fn test_semantic_error_literal_condition_has_source_location() {
    let source = "def main():\n  if 123:\n    var value = 1\n";
    let errors = analyze_source_errors(source);
    let error = errors
        .iter()
        .find(|error| error.message.contains("If-condition"))
        .expect("expected if-condition error");

    assert_eq!(error.location.file, "test.stfl");
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.column, 6);
}

#[test]
fn test_semantic_error_empty_list_condition_has_source_location() {
    let source = "def main():\n  if []:\n    var value = 1\n";
    let errors = analyze_source_errors(source);
    let error = errors
        .iter()
        .find(|error| error.message.contains("If-condition"))
        .expect("expected if-condition error");

    assert_eq!(error.location.file, "test.stfl");
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.column, 6);
}

#[test]
fn test_compile_recovers_from_capitalized_list_and_reports_later_errors() {
    let source = r#"
def main():
  var xs: List[int64] = []
  var a: int64 = "nope"
  if []:
    var value = 1
"#;
    let errors = compile_source_errors(source);
    let messages = errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>();

    assert!(
        messages
            .iter()
            .any(|message| message.contains("Unknown generic type: List")),
        "expected recoverable parse error, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Expected 'int64', found 'string'")),
        "expected later type mismatch, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("If-condition must be of type 'bool'")),
        "expected later if-condition error, got {messages:?}"
    );
}

#[test]
fn test_compile_recovers_at_statement_boundary_after_missing_expression() {
    let source = r#"
def main():
  var broken =
  var a: int64 = "nope"
  if 123:
    var value = 1
  var ok = 1
  unknown_call(ok)
"#;
    let errors = compile_source_errors(source);
    let messages = errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>();

    assert!(
        messages
            .iter()
            .any(|message| message.contains("Expected expression, found Newline")),
        "expected missing expression parse error, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Expected 'int64', found 'string'")),
        "expected next statement type mismatch, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("If-condition must be of type 'bool'")),
        "expected later if-condition error, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("unknown_call")),
        "expected later unknown function error, got {messages:?}"
    );
}

// ===========================================
// Semantic Analysis Tests - Type Checking
// ===========================================

#[test]
fn test_semantic_secret_assignment_valid() {
    let source = r#"
var share: Share = ClientStore.take_share(0, 0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_can_assign_to_secret_int() {
    let source = r#"
var share: secret int64 = ClientStore.take_share(0, 0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_can_flow_to_secret_int_parameter() {
    let source = r#"
def process(value: secret int64) -> secret int64:
  return value

var share = ClientStore.take_share(0, 0)
var processed = process(share)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_can_initialize_secret_int_list() {
    let source = r#"
var first = ClientStore.take_share(0, 0)
var second = ClientStore.take_share(0, 1)
var shares: list[secret int64] = [first, second]
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_secret_in_function() {
    let source = r#"
def process(s: secret int64) -> secret int64:
  return s * 2
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Semantic Phase Tests - List Iteration
// ===========================================

#[test]
fn test_semantic_for_loop_list_iteration() {
    let source = r#"
var items: list[int64] = [1, 2, 3]
var sum = 0
for item in items:
  sum = sum + item
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_list_literal() {
    let source = r#"
var total = 0
for x in [10, 20, 30]:
  total = total + x
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_element_type_inferred() {
    // The loop variable should have the same type as list elements
    let source = r#"
var numbers: list[int64] = [1, 2, 3]
var total = 0
for n in numbers:
  total = total + n
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_range_still_works() {
    // Ensure range-based iteration still works
    let source = r#"
var sum = 0
for i in 0..10:
  sum = sum + i
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_error_iterate_non_iterable() {
    // Cannot iterate over a non-iterable type
    let source = r#"
var x = 42
for item in x:
  print(item)
"#;
    assert!(analyze_source(source).is_err());
}

// ===========================================
// Semantic Phase Tests - String Iteration
// ===========================================

#[test]
fn test_semantic_for_loop_string_iteration() {
    // Iterate over characters in a string
    let source = r#"
var text = "hello"
for ch in text:
  print(ch)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_string_literal() {
    // Iterate directly over a string literal
    let source = r#"
for ch in "world":
  print(ch)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_string_element_is_string() {
    // The loop variable should be a string (character)
    // so we can concatenate it with another string
    let source = r#"
var text = "abc"
var result = ""
for ch in text:
  result = result + ch
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Full Compilation Tests - Valid Programs
// ===========================================

#[test]
fn test_compile_hello_world() {
    let source = r#"
print("Hello, World!")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_arithmetic() {
    let source = r#"
var a = 10
var b = 20
var sum = a + b
var diff = a - b
var prod = a * b
var quot = b / a
print(sum)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_function_definition_and_call() {
    let source = r#"
def double(n: int64) -> int64:
  return n * 2

var result = double(5)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_conditionals() {
    let source = r#"
var x = 10
if x > 5:
  print("big")
else:
  print("small")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_loops() {
    let source = r#"
var i = 0
while i < 10:
  i = i + 1
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_arrays() {
    let source = r#"
var arr = []
arr.append(10)
arr.append(20)
var first = arr[0]
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_list_iteration() {
    let source = r#"
var items: list[int64] = [1, 2, 3, 4, 5]
var total = 0
for item in items:
  total = total + item
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_list_literal() {
    let source = r#"
var sum = 0
for x in [10, 20, 30]:
  sum = sum + x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_range() {
    let source = r#"
var sum = 0
for i in 0..5:
  sum = sum + i
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_nested_with_list() {
    let source = r#"
var matrix: list[int64] = [1, 2, 3]
var total = 0
for i in 0..3:
  for val in matrix:
    total = total + val
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_string_iteration() {
    let source = r#"
var text = "hello"
for ch in text:
  print(ch)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_string_literal() {
    let source = r#"
for ch in "world":
  print(ch)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_string_concatenation() {
    let source = r#"
var text = "abc"
var result = ""
for ch in text:
  result = result + ch
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_type_builtin_and_boolean_ops() {
    let source = r#"
var name = type("invoice")
var accepted = (name == "string") and not False
if accepted or False:
  print(name)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_clear_collection_loops_stay_in_clear_registers() {
    let source = r#"
var total = 0
for value in [3, 4, 5]:
  total += value
for ch in "risk":
  discard ch
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let max_register = program
        .main_chunk
        .instructions
        .iter()
        .flat_map(instruction_registers)
        .max()
        .unwrap_or(0);

    assert!(
        max_register < DEFAULT_SECRET_REGISTER_START,
        "clear collection loops should not allocate secret registers; max register was {max_register}"
    );
}

#[test]
fn test_binary_preserves_function_parameter_names_and_upvalues() {
    let source = r#"
def increment_counter(amount: int64) -> int64:
  var saved_amount = amount
  var current = get_upvalue("start")
  var updated = current + saved_amount
  discard set_upvalue("start", updated)
  return updated

def create_counter(start: int64) -> Closure:
  return create_closure_with_upvalue("increment_counter", "start")

def main() -> int64:
  var counter = create_counter(10)
  return call_closure_with_arg(counter, 5)
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);

    let create_counter = binary
        .functions
        .iter()
        .find(|function| function.name == "create_counter")
        .expect("create_counter function exists");
    assert_eq!(create_counter.parameters, vec!["start".to_string()]);

    let increment_counter = binary
        .functions
        .iter()
        .find(|function| function.name == "increment_counter")
        .expect("increment_counter function exists");
    assert_eq!(increment_counter.parameters, vec!["amount".to_string()]);
    assert_eq!(increment_counter.upvalues, vec!["start".to_string()]);
}

#[test]
fn test_def_main_with_return_type_is_entry_chunk() {
    let source = r#"
def main() -> int64:
  return 42
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");

    assert!(
        !program
            .main_chunk
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::CALL(name) if name == "main")),
        "def main should be promoted to the entry chunk, not called through a wrapper"
    );
    assert!(
        !program.function_chunks.contains_key("main"),
        "entry def main should not also be emitted as a normal function"
    );
}

#[test]
fn test_main_keyword_entry_form_is_rejected() {
    let source = r#"
main main() -> int64:
  return 42
"#;

    assert!(expect_error_containing(
        source,
        "The 'main <name>(...)' entry form is no longer supported"
    ));
}

// ===========================================
// Full Compilation Tests - Builtin Objects
// ===========================================

#[test]
fn test_compile_client_store() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_client_io_manifest_in_stflb_binary() {
    let source = r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share_fixed(0, 1)
  MpcOutput.send_to_client(0, [left, right])
  return 0
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.clients.len(), 1);
    let schema = &binary.client_io_manifest.clients[0];
    assert_eq!(schema.client_slot, 0);
    assert_eq!(
        schema.inputs,
        vec![
            ShareType::default_secret_int(),
            ShareType::default_secret_fixed_point()
        ]
    );
    assert_eq!(
        schema.outputs,
        vec![
            ShareType::default_secret_int(),
            ShareType::default_secret_fixed_point()
        ]
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_output_list_variables() {
    let source = r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share_fixed(0, 1)
  var outputs = [left, right]
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);
    let schema = &binary.client_io_manifest.clients[0];

    assert_eq!(
        schema.outputs,
        vec![
            ShareType::default_secret_int(),
            ShareType::default_secret_fixed_point()
        ]
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_multiple_literal_clients() {
    let source = r#"
def main() -> int64:
  var client0_score = ClientStore.take_share(0, 0)
  var client1_weight = ClientStore.take_share_fixed(1, 0)
  MpcOutput.send_to_client(0, [client0_score])
  MpcOutput.send_to_client(1, [client1_weight])
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[
            (
                0,
                vec![ShareType::default_secret_int()],
                vec![ShareType::default_secret_int()],
            ),
            (
                1,
                vec![ShareType::default_secret_fixed_point()],
                vec![ShareType::default_secret_fixed_point()],
            ),
        ],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_sparse_input_ordinals() {
    let source = r#"
def main() -> int64:
  var first = ClientStore.take_share(2, 0)
  var third = ClientStore.take_share_fixed(2, 2)
  MpcOutput.send_to_client(2, [first, third])
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            2,
            vec![
                ShareType::default_secret_int(),
                ShareType::default_secret_int(),
                ShareType::default_secret_fixed_point(),
            ],
            vec![
                ShareType::default_secret_int(),
                ShareType::default_secret_fixed_point(),
            ],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_appended_output_lists() {
    let source = r#"
def main() -> int64:
  var fixed_value = ClientStore.take_share_fixed(0, 0)
  var int_value = ClientStore.take_share(0, 1)
  var outputs: list[Share] = []
  outputs.append(fixed_value)
  outputs.append(int_value)
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![
                ShareType::default_secret_fixed_point(),
                ShareType::default_secret_int(),
            ],
            vec![
                ShareType::default_secret_fixed_point(),
                ShareType::default_secret_int(),
            ],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_direct_share_send_to_client() {
    let source = r#"
def main() -> int64:
  var fixed_value = ClientStore.take_share_fixed(0, 0)
  var int_value = ClientStore.take_share(1, 0)
  fixed_value.send_to_client(0)
  int_value.send_to_client(1)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[
            (
                0,
                vec![ShareType::default_secret_fixed_point()],
                vec![ShareType::default_secret_fixed_point()],
            ),
            (
                1,
                vec![ShareType::default_secret_int()],
                vec![ShareType::default_secret_int()],
            ),
        ],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_static_loop_literal_bound_inputs_and_outputs() {
    let source = r#"
def main() -> int64:
  var outputs: list[Share] = []
  var element_index: int64 = 0
  while element_index < 3:
    var value = ClientStore.take_share_fixed(0, element_index)
    outputs.append(value)
    element_index = element_index + 1
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![ShareType::default_secret_fixed_point(); 3],
            vec![ShareType::default_secret_fixed_point(); 3],
        )],
    );
}

#[test]
fn test_compile_mpc_output_send_to_client_accepts_single_secret_share() {
    let source = r#"
def main() -> int64:
  var share: secret int64 = ClientStore.take_share(0, 0)
  MpcOutput.send_to_client(0, share)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![ShareType::default_secret_int()],
            vec![ShareType::default_secret_int()],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_static_loop_fixed_client_io() {
    let source = include_str!("../../examples/mpc_client_federated_average/main.stfl");
    let program = compile(
        source,
        "mpc_client_federated_average.stfl",
        &default_options(),
    )
    .expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.clients.len(), 1);
    let schema = &binary.client_io_manifest.clients[0];
    assert_eq!(schema.client_slot, 0);
    assert_eq!(
        schema.inputs,
        vec![ShareType::default_secret_fixed_point(); 6]
    );
    assert_eq!(
        schema.outputs,
        vec![ShareType::default_secret_fixed_point(); 6]
    );
}

#[test]
fn test_compile_records_mpc_backend_in_stflb_binary() {
    let source = r#"
def main() -> int64:
  return 0
"#;
    let mut options = default_options();
    options.mpc_backend = MpcBackend::Avss;

    let program = compile(source, "test.stfl", &options).expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.mpc_backend, MpcBackend::Avss);
}

#[test]
fn test_compile_mpc_operations() {
    let source = r#"
var my_id = Mpc.party_id()
var parties = Mpc.n_parties()
if my_id == 0:
  print("I am the leader")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_share_creation() {
    let source = r#"
var s = Share.from_clear(42)
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Full Compilation Tests - Complex Programs
// ===========================================

#[test]
fn test_compile_nested_conditionals() {
    let source = r#"
var x = 10
var y = 20
if x > 5:
  if y > 15:
    print("both big")
  else:
    print("x big, y small")
else:
  print("x small")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_multiple_functions() {
    let source = r#"
def add(a: int64, b: int64) -> int64:
  return a + b

def multiply(a: int64, b: int64) -> int64:
  return a * b

var sum = add(3, 4)
var prod = multiply(sum, 2)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_recursive_function() {
    let source = r#"
def fib(n: int64) -> int64:
  if n <= 1:
    return n
  return fib(n - 1) + fib(n - 2)

var result = fib(10)
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Syntax Error Tests
// ===========================================

#[test]
fn test_syntax_error_unclosed_paren() {
    let source = "var x = (1 + 2";
    assert!(compile_source(source).is_err());
}

#[test]
fn test_syntax_error_missing_expression() {
    let source = "var x =";
    assert!(compile_source(source).is_err());
}

#[test]
fn test_syntax_error_invalid_field_access() {
    let source = "var x = obj.";
    assert!(compile_source(source).is_err());
}

// ===========================================
// Edge Cases
// ===========================================

#[test]
fn test_empty_program() {
    let source = "";
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_only_comments() {
    let source = r#"
# This is a comment
# Another comment
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_deeply_nested_expressions() {
    let source = "var x = ((((1 + 2) * 3) - 4) / 5)";
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_long_identifier() {
    let source = "var this_is_a_very_long_variable_name_that_should_still_work = 42";
    assert!(compile_source(source).is_ok());
}

// ===========================================
// UFCS Transformation Tests
// ===========================================

#[test]
fn test_ufcs_builtin_object_preserved() {
    let source = "var s = ClientStore.take_share(0, 0)";
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_ufcs_share_methods() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var result = Share.add(s1, s2)
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Import Syntax Tests (Parser Only)
// ===========================================

#[test]
fn test_import_syntax() {
    let source = "import foo.bar";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_import_with_alias() {
    let source = "import foo.bar as baz";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_multiple_imports() {
    let source = r#"
import module1
import module2.submodule
import module3 as m3
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Compound Assignment Operator Tests - Lexer
// ===========================================

#[test]
fn test_lexer_compound_plus_equals() {
    let source = "var x = 10\nx += 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_minus_equals() {
    let source = "var x = 10\nx -= 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_times_equals() {
    let source = "var x = 10\nx *= 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_divide_equals() {
    let source = "var x = 10\nx /= 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_modulo_equals() {
    let source = "var x = 10\nx %= 3";
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Compound Assignment Operator Tests - Parser
// ===========================================

#[test]
fn test_parser_compound_assignment_simple_variable() {
    let source = r#"
var x = 10
x += 5
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_assignment_with_expression() {
    let source = r#"
var x = 10
var y = 3
x += y * 2
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_assignment_in_loop() {
    let source = r#"
var sum = 0
for i in 0..10:
  sum += i
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_assignment_array_element() {
    let source = r#"
var arr = [1, 2, 3]
arr[0] += 10
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_all_operators() {
    let source = r#"
var a = 100
a += 10
a -= 5
a *= 2
a /= 10
a %= 7
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Compound Assignment - Semantic Analysis
// ===========================================

#[test]
fn test_semantic_compound_plus_equals() {
    let source = r#"
var x = 10
x += 5
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_minus_equals() {
    let source = r#"
var x = 10
x -= 3
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_times_equals() {
    let source = r#"
var x = 10
x *= 2
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_divide_equals() {
    let source = r#"
var x = 10
x /= 2
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_modulo_equals() {
    let source = r#"
var x = 10
x %= 3
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_assignment_in_function() {
    let source = r#"
def accumulate(n: int64) -> int64:
  var sum = 0
  for i in 0..n:
    sum += i
  return sum

var result = accumulate(10)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_assignment_with_expression_rhs() {
    let source = r#"
var x = 100
var y = 10
x += y * 2 + 5
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_error_undefined_variable() {
    let source = r#"
undefined_var += 5
"#;
    assert!(analyze_source(source).is_err());
}

// ===========================================
// Compound Assignment - Full Compilation
// ===========================================
// Note: We avoid using print() with integer variables directly
// due to a pre-existing type inference issue where print expects String.
// Instead, we verify compilation succeeds by checking the final value.

#[test]
fn test_compile_compound_plus_equals() {
    let source = r#"
var x = 10
x += 5
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_minus_equals() {
    let source = r#"
var x = 10
x -= 3
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_times_equals() {
    let source = r#"
var x = 10
x *= 2
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_divide_equals() {
    let source = r#"
var x = 10
x /= 2
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_modulo_equals() {
    let source = r#"
var x = 10
x %= 3
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_accumulator() {
    let source = r#"
var sum = 0
for i in 1..11:
  sum += i
var result = sum
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_factorial_style() {
    let source = r#"
var result = 1
for i in 1..6:
  result *= i
var final = result
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_countdown() {
    let source = r#"
var count = 100
while count > 0:
  count -= 10
var final = count
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_in_nested_loops() {
    let source = r#"
var total = 0
for i in 0..3:
  for j in 0..3:
    total += i * j
var result = total
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_mixed_operations() {
    let source = r#"
var x = 100
x += 50
x -= 30
x *= 2
x /= 4
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_with_function_call() {
    let source = r#"
def double(n: int64) -> int64:
  return n * 2

var x = 10
x += double(5)
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_array_element() {
    let source = r#"
var arr = [10, 20, 30]
arr[0] += 5
arr[1] -= 10
arr[2] *= 2
var a = arr[0]
var b = arr[1]
var c = arr[2]
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Pythonic Array Syntax Tests
// ===========================================

#[test]
fn test_empty_array_literal() {
    // Empty array literal [] is now supported (type inferred from context)
    let source = r#"
var items: list[int64] = []
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_literal_with_elements() {
    let source = r#"
var items = [1, 2, 3, 4, 5]
var first = items[0]
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_append_method() {
    // Pythonic .append() method syntax
    let source = r#"
var items: list[int64] = []
items.append(1)
items.append(2)
items.append(3)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_push_method() {
    // JavaScript-style .push() is intentionally not part of the Python-shaped surface.
    let source = r#"
var items = [1, 2]
items.push(3)
items.push(4)
"#;
    assert!(compile_source(source).is_err());
}

#[test]
fn test_array_length_method() {
    // Pythonic .len() method syntax
    let source = r#"
var items = [1, 2, 3, 4, 5]
var n = items.len()
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_len_method() {
    // Python-style .len() or len(arr) syntax
    let source = r#"
var items = [1, 2, 3, 4, 5]
var n = len(items)
var m = items.len()
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_pythonic_array_loop() {
    // Complete Pythonic array workflow
    let source = r#"
var result: list[int64] = []
for i in 1..6:
  result.append(i * 10)
var n = result.len()
"#;
    assert!(compile_source(source).is_ok());
}
