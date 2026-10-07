//! Docstring (`"""..."""`) syntax tests.

use std::fs;
use std::path::{Path, PathBuf};

use stoffellang::ast::AstNode;
use stoffellang::errors::{CompilerError, SourceLocation};
use stoffellang::lexer::tokenize;
use stoffellang::parser::{parse, parse_recovering, parse_with_docs, DocTable};
use stoffellang::{compile, CompilerOptions};

#[path = "support/docstring_injection.rs"]
mod docstring_injection;
use docstring_injection::{inject_docstrings, strip_docstrings};

const STRAY_DOCSTRING: &str =
    "docstrings may only appear as the first item of a module, def, object, enum or type body";

fn parse_error(source: &str) -> CompilerError {
    let tokens = tokenize(source, "test.stfl").expect("source should lex");
    match parse(&tokens, "test.stfl") {
        Ok(ast) => panic!("expected a parse error for {source:?}, got {ast:?}"),
        Err(err) => err,
    }
}

fn assert_stray_docstring(source: &str, line: usize, column: usize) {
    let err = parse_error(source);
    assert_eq!(err.code, "E001", "{source:?}");
    assert_eq!(err.message, STRAY_DOCSTRING, "{source:?}");
    assert_eq!(
        (err.location.line, err.location.column),
        (line, column),
        "{source:?}"
    );
}

#[test]
fn docstring_as_an_expression_is_rejected() {
    assert_stray_docstring("var x = \"\"\"a\"\"\"\n", 1, 9);
}

#[test]
fn docstring_as_a_call_argument_is_rejected() {
    assert_stray_docstring("print(\"\"\"a\nb\"\"\")\n", 1, 7);
}

#[test]
fn docstring_as_a_pragma_value_is_rejected() {
    assert_stray_docstring("def f() -> int64 {.builtin: \"\"\"X\"\"\".}\n", 1, 29);
}

#[test]
fn docstring_statement_is_rejected() {
    assert_stray_docstring("def f():\n  pass\n  \"\"\"Late doc.\"\"\"\n", 3, 3);
}

#[test]
fn triple_quoted_f_string_is_rejected() {
    let err = parse_error("var x = f\"\"\"a {1}\"\"\"\n");
    assert_eq!(err.code, "E001");
    assert!(err.message.contains("f-strings cannot use triple quotes"));
}

#[test]
fn recovering_parse_reports_stray_docstrings_and_continues() {
    let source = "var x = \"\"\"a\"\"\"\nvar y = \"\"\"b\"\"\"\n";
    let tokens = tokenize(source, "test.stfl").expect("source should lex");
    let output = parse_recovering(&tokens, "test.stfl");
    let stray: Vec<_> = output
        .errors
        .iter()
        .filter(|err| err.message == STRAY_DOCSTRING)
        .map(|err| err.location.line)
        .collect();
    assert_eq!(stray, vec![1, 2]);
}

#[test]
fn compile_reports_unterminated_string_instead_of_hanging() {
    let errors = compile(
        "def main() -> int64:\n  print(\"abc)\n  return 0\n",
        "t.stfl",
        &CompilerOptions::default(),
    )
    .expect_err("unterminated string must fail");
    assert!(errors
        .iter()
        .any(|err| err.message == "Unterminated string literal" && err.location.line == 2));
}

fn collect_stfl_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_stfl_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "stfl") {
            out.push(path);
        }
    }
}

/// `"""` was not valid syntax before docstrings existed, so no existing
/// program can change meaning. Keep it that way: only fixtures dedicated to
/// docstrings (file name containing `docstring`) may use triple quotes.
#[test]
fn only_docstring_fixtures_contain_triple_quotes() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["tests/stfl", "examples"] {
        collect_stfl_files(&manifest_dir.join(dir), &mut files);
    }
    assert!(!files.is_empty(), "no .stfl fixtures found");

    let offenders: Vec<_> = files
        .iter()
        .filter(|path| {
            !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains("docstring"))
        })
        .filter(|path| {
            fs::read_to_string(path)
                .expect("read fixture")
                .contains("\"\"\"")
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "unexpected triple quotes in: {offenders:?}"
    );
}

// --- Docstring positions (M2) ---------------------------------------------

fn parse_docs(source: &str) -> (AstNode, DocTable) {
    let tokens = tokenize(source, "test.stfl").expect("source should lex");
    parse_with_docs(&tokens, "test.stfl")
        .unwrap_or_else(|err| panic!("expected {source:?} to parse, got {err}"))
}

fn at(line: usize, column: usize) -> SourceLocation {
    SourceLocation {
        file: "test.stfl".to_string(),
        line,
        column,
    }
}

/// Debug rendering of an AST with every `line`/`column` zeroed, so ASTs of
/// sources that differ only in docstring lines can be compared.
fn normalized(ast: &AstNode) -> String {
    let text = format!("{ast:#?}");
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(index) = ["line: ", "column: "]
        .iter()
        .filter_map(|key| rest.find(key).map(|index| index + key.len()))
        .min()
    {
        out.push_str(&rest[..index]);
        rest = rest[index..].trim_start_matches(|c: char| c.is_ascii_digit());
        out.push('0');
    }
    out.push_str(rest);
    out
}

/// Parses `source`, checks the AST equals the AST of the same source without
/// docstrings, and returns the doc table.
fn assert_docs_are_transparent(source: &str) -> DocTable {
    let (ast, docs) = parse_docs(source);
    let stripped = strip_docstrings(source);
    let (stripped_ast, stripped_docs) = parse_docs(&stripped);
    assert!(
        stripped_docs.is_empty(),
        "stripped source still has docs:\n{stripped}"
    );
    assert_eq!(
        normalized(&ast),
        normalized(&stripped_ast),
        "docstrings changed the AST of:\n{source}"
    );
    docs
}

#[test]
fn module_docstring_is_recorded() {
    let source =
        "\n\"\"\"Module summary.\n\n  Details.\n\"\"\"\n\ndef main() -> int64:\n  return 0\n";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(docs.module_doc(), Some("Module summary.\n\nDetails."));
    assert_eq!(docs.item_count(), 0);
}

#[test]
fn module_docstring_alone_is_an_empty_program() {
    let (ast, docs) = parse_docs("\"\"\"Only docs.\"\"\"\n");
    assert_eq!(ast, AstNode::Block(Vec::new()));
    assert_eq!(docs.module_doc(), Some("Only docs."));
}

#[test]
fn user_def_docstring_is_removed_from_the_body() {
    let source = "def add(a: int64, b: int64) -> int64:\n  \"\"\"Add two numbers.\n\n  Args:\n    a: left\n  \"\"\"\n  return a + b\n";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(
        docs.item_doc(&at(1, 1)),
        Some("Add two numbers.\n\nArgs:\n  a: left")
    );
    let (ast, _) = parse_docs(source);
    match ast {
        AstNode::FunctionDefinition { body, .. } => match *body {
            AstNode::Block(statements) => {
                assert_eq!(statements.len(), 1);
                assert!(matches!(statements[0], AstNode::Return { .. }));
            }
            other => panic!("expected a block body, got {other:?}"),
        },
        other => panic!("expected a function, got {other:?}"),
    }
}

#[test]
fn docstring_only_void_def_has_an_empty_body() {
    let (ast, docs) = parse_docs("def noop() -> void:\n  \"\"\"Does nothing.\"\"\"\n");
    match ast {
        AstNode::FunctionDefinition { body, .. } => {
            assert_eq!(*body, AstNode::Block(Vec::new()))
        }
        other => panic!("expected a function, got {other:?}"),
    }
    assert_eq!(docs.item_doc(&at(1, 1)), Some("Does nothing."));
}

#[test]
fn nested_def_docstrings_are_keyed_by_their_own_def() {
    let source = "def outer() -> int64:\n  \"\"\"Outer.\"\"\"\n  def inner() -> int64:\n    \"\"\"Inner.\"\"\"\n    return 1\n  return inner()\n";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(docs.item_doc(&at(1, 1)), Some("Outer."));
    assert_eq!(docs.item_doc(&at(3, 3)), Some("Inner."));
}

#[test]
fn builtin_def_takes_an_optional_doc_block() {
    let source = "def first() -> int64 {.builtin.}:\n  \"\"\"First.\"\"\"\ndef second() -> int64 {.builtin: \"Other.second\".}:\n\n  \"\"\"Second, after a blank line.\"\"\"\ndef third() -> int64 {.builtin.}:\ndef fourth() -> int64 {.builtin.}:\n  \"\"\"Fourth at EOF.\"\"\"";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(docs.item_doc(&at(1, 1)), Some("First."));
    assert_eq!(
        docs.item_doc(&at(3, 1)),
        Some("Second, after a blank line.")
    );
    assert_eq!(docs.item_doc(&at(6, 1)), None);
    assert_eq!(docs.item_doc(&at(7, 1)), Some("Fourth at EOF."));
    assert_eq!(docs.item_count(), 3);
}

#[test]
fn builtin_object_and_its_methods_take_docstrings() {
    let source = "builtin object Share:\n  \"\"\"A share.\"\"\"\n  def mul(a: Share, b: Share) -> Share {.builtin.}:\n    \"\"\"Multiply.\n\n    MPC:\n      One round.\n    \"\"\"\n  def add(a: Share, b: Share) -> Share {.builtin.}:\n  def open(a: Share) -> int64 {.builtin.}:\n    \"\"\"Open.\"\"\"\ndef after() -> int64 {.builtin.}:\n";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(docs.item_doc(&at(1, 1)), Some("A share."));
    assert_eq!(
        docs.item_doc(&at(3, 3)),
        Some("Multiply.\n\nMPC:\n  One round.")
    );
    assert_eq!(docs.item_doc(&at(9, 3)), None);
    assert_eq!(docs.item_doc(&at(10, 3)), Some("Open."));
    assert_eq!(docs.item_count(), 3);
}

#[test]
fn object_and_enum_docstrings_precede_their_members() {
    let source = "object Point:\n  \"\"\"A point.\"\"\"\n  x: int64\n  y: int64\n\nenum Color:\n  \"\"\"\n  Colors.\n  \"\"\"\n  Red\n  Green = 2\n";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(docs.item_doc(&at(1, 1)), Some("A point."));
    assert_eq!(docs.item_doc(&at(6, 1)), Some("Colors."));
}

#[test]
fn one_line_type_declarations_take_a_colon_doc_block() {
    let source = "builtin type int = int64:\n  \"\"\"Alias.\"\"\"\nbuiltin type string:\n  \"\"\"Text.\"\"\"\nbuiltin opaque Closure:\n  \"\"\"Handle.\"\"\"\ntype Pair = list[int64]:\n  \"\"\"Two ints.\"\"\"\nbuiltin type bool\ntype Plain = int64\n";
    let docs = assert_docs_are_transparent(source);
    assert_eq!(docs.item_doc(&at(1, 1)), Some("Alias."));
    assert_eq!(docs.item_doc(&at(3, 1)), Some("Text."));
    assert_eq!(docs.item_doc(&at(5, 1)), Some("Handle."));
    assert_eq!(docs.item_doc(&at(7, 1)), Some("Two ints."));
    assert_eq!(docs.item_count(), 4);
}

#[test]
fn parse_without_docs_accepts_every_position() {
    let source = "\"\"\"Module.\"\"\"\ndef f() -> void:\n  \"\"\"F.\"\"\"\n  pass\n";
    let tokens = tokenize(source, "test.stfl").expect("lex");
    let (with_docs, _) = parse_with_docs(&tokens, "test.stfl").expect("parse_with_docs");
    assert_eq!(parse(&tokens, "test.stfl").expect("parse"), with_docs);
    let output = parse_recovering(&tokens, "test.stfl");
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    assert_eq!(output.ast, with_docs);
    assert_eq!(output.docs.module_doc(), Some("Module."));
    assert_eq!(output.docs.item_doc(&at(2, 1)), Some("F."));
}

#[test]
fn inject_and_strip_round_trip_every_position() {
    let source = "builtin type int = int64\nbuiltin opaque Closure\nbuiltin object Share:\n  def add(a: Share, b: Share) -> Share {.builtin.}:\ndef ext(\n  a: int64,\n  b: int64\n) -> int64 {.builtin.}:\nobject P:\n  x: int64\nenum E:\n  A\ntype T = int64\ndef main() -> int64:\n  return 0\n";
    let injected = inject_docstrings(source);
    assert_eq!(injected.item_docstrings, 9);
    let docs = assert_docs_are_transparent(&injected.source);
    assert_eq!(docs.item_count(), 9);
    assert!(docs.module_doc().is_some());
    assert_eq!(strip_docstrings(&injected.source), source);
}

// --- Misplaced docstrings --------------------------------------------------

fn assert_parse_error(source: &str, message: &str, line: usize, column: usize) {
    let err = parse_error(source);
    assert_eq!(err.code, "E001", "{source:?}");
    assert_eq!(err.message, message, "{source:?}");
    assert_eq!(
        (err.location.line, err.location.column),
        (line, column),
        "{source:?}"
    );
}

const BUILTIN_BODY: &str = "builtin functions may only contain a docstring";
const TYPE_BODY: &str = "type declarations may only contain a docstring";

#[test]
fn second_docstring_in_a_def_body_is_rejected() {
    assert_stray_docstring(
        "def f() -> void:\n  \"\"\"One.\"\"\"\n  \"\"\"Two.\"\"\"\n  pass\n",
        3,
        3,
    );
}

#[test]
fn second_module_docstring_is_rejected() {
    assert_stray_docstring("\"\"\"One.\"\"\"\n\"\"\"Two.\"\"\"\n", 2, 1);
}

#[test]
fn docstring_in_a_control_flow_body_is_rejected() {
    assert_stray_docstring(
        "def f() -> void:\n  if true:\n    \"\"\"No.\"\"\"\n    pass\n",
        3,
        5,
    );
}

#[test]
fn docstring_after_the_first_member_is_rejected() {
    assert_stray_docstring("object P:\n  x: int64\n  \"\"\"Late.\"\"\"\n", 3, 3);
    assert_stray_docstring("enum E:\n  A\n  \"\"\"Late.\"\"\"\n", 3, 3);
    assert_stray_docstring(
        "builtin object B:\n  def m() -> int64 {.builtin.}:\n  \"\"\"Late.\"\"\"\n",
        3,
        3,
    );
}

#[test]
fn code_after_a_docstring_on_the_same_line_is_rejected() {
    assert_parse_error(
        "def f() -> int64:\n  \"\"\"Doc.\"\"\" return 1\n",
        "Expected a newline after the docstring",
        2,
        14,
    );
}

#[test]
fn builtin_doc_block_rejects_code() {
    assert_parse_error(
        "def f() -> int64 {.builtin.}:\n  \"\"\"Doc.\"\"\"\n  return 1\n",
        BUILTIN_BODY,
        3,
        3,
    );
    assert_parse_error(
        "def f() -> int64 {.builtin.}:\n  return 1\n",
        BUILTIN_BODY,
        2,
        3,
    );
    assert_stray_docstring(
        "def f() -> int64 {.builtin.}:\n  \"\"\"One.\"\"\"\n  \"\"\"Two.\"\"\"\n",
        3,
        3,
    );
}

#[test]
fn plain_strings_are_not_docstrings_in_declaration_blocks() {
    assert_parse_error(
        "def f() -> int64 {.builtin.}:\n  \"Doc.\"\n",
        BUILTIN_BODY,
        2,
        3,
    );
    assert_parse_error("type T = int64:\n  \"Doc.\"\n", TYPE_BODY, 2, 3);
    for source in [
        "\"Module doc.\"\ndef f() -> void:\n  pass\n",
        "def f() -> void:\n  \"Doc.\"\n  pass\n",
        "object P:\n  \"Doc.\"\n  x: int64\n",
        "enum E:\n  \"Doc.\"\n  A\n",
        "builtin object B:\n  \"Doc.\"\n  def m() -> int64 {.builtin.}:\n",
    ] {
        let err = parse_error(source);
        assert_eq!(err.code, "E001", "{source:?}");
        assert_eq!(err.message, PLAIN_STRING_DOC, "{source:?}");
        let expected = if source.starts_with('"') {
            (1, 1)
        } else {
            (2, 3)
        };
        assert_eq!((err.location.line, err.location.column), expected);
    }
    // After a real docstring, a string statement is the generic error.
    let err = parse_error("def f() -> void:\n  \"\"\"Doc.\"\"\"\n  \"x\"\n");
    assert!(err
        .message
        .starts_with("Unexpected token at start of statement"));
}

const PLAIN_STRING_DOC: &str = "docstrings must use triple quotes: \"\"\"...\"\"\"";

#[test]
fn type_declaration_colon_requires_a_docstring() {
    assert_parse_error("builtin type int = int64:\n  bool\n", TYPE_BODY, 2, 3);
    let err = parse_error("type T = int64:\ndef f() -> int64 {.builtin.}:\n");
    assert_eq!(err.code, "E001");
    assert!(err
        .message
        .contains("Expected an indented docstring after ':'"));
    let err = parse_error("builtin opaque Closure: \"\"\"Doc.\"\"\"\n");
    assert!(err
        .message
        .contains("Expected a newline and an indented docstring"));
}

#[test]
fn type_declaration_without_colon_mentions_the_doc_form() {
    let err = parse_error("builtin type int = int64 bool\n");
    assert!(
        err.message
            .contains("':' followed by an indented docstring after builtin type definition"),
        "{}",
        err.message
    );
}

// --- Recovery ----------------------------------------------------------------

#[test]
fn recovering_parse_reports_a_malformed_doc_block_and_continues() {
    let source = "def bad() -> int64 {.builtin.}:\n  \"\"\"Doc.\"\"\"\n  return 1\n  if true:\n    pass\ndef good() -> int64:\n  \"\"\"Good.\"\"\"\n  return 1\ndef broken() -> int64:\n  return )\n";
    let tokens = tokenize(source, "test.stfl").expect("lex");
    let output = parse_recovering(&tokens, "test.stfl");
    let messages: Vec<_> = output
        .errors
        .iter()
        .map(|err| (err.message.as_str(), err.location.line))
        .collect();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert_eq!(messages[0], (BUILTIN_BODY, 3));
    assert_eq!(messages[1].1, 10, "{messages:?}");
    assert_eq!(output.docs.item_doc(&at(1, 1)), Some("Doc."));
    assert_eq!(output.docs.item_doc(&at(6, 1)), Some("Good."));
    let AstNode::Block(statements) = &output.ast else {
        panic!("expected a block, got {:?}", output.ast);
    };
    let names: Vec<_> = statements
        .iter()
        .filter_map(|statement| match statement {
            AstNode::FunctionDefinition { name, .. } => name.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["bad", "good", "broken"]);
}

#[test]
fn recovering_parse_reports_a_malformed_body_docstring_and_continues() {
    let source = "def f() -> int64:\n  \"\"\"Doc.\"\"\" 1\n  return 1\ndef g() -> int64:\n  \"\"\"G.\"\"\"\n  return )\n";
    let tokens = tokenize(source, "test.stfl").expect("lex");
    let output = parse_recovering(&tokens, "test.stfl");
    let lines: Vec<_> = output.errors.iter().map(|err| err.location.line).collect();
    assert_eq!(lines, [2, 6], "{:?}", output.errors);
    assert_eq!(output.docs.item_doc(&at(4, 1)), Some("G."));
}

// --- Compilation ---------------------------------------------------------------

#[test]
fn docstring_only_void_function_compiles_at_every_level() {
    let source = "\"\"\"Module.\"\"\"\ndef noop() -> void:\n  \"\"\"Only a docstring.\"\"\"\n\ndef main() -> int64:\n  \"\"\"Entry.\"\"\"\n  noop()\n  return 0\n";
    for level in 0..=3 {
        let options = CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            ..CompilerOptions::default()
        };
        compile(source, "t.stfl", &options)
            .unwrap_or_else(|errors| panic!("-O{level} failed: {errors:?}"));
    }
}

#[test]
fn docstring_only_non_void_function_reports_missing_return() {
    let errors = compile(
        "def answer() -> int64:\n  \"\"\"Only a docstring.\"\"\"\ndef main() -> int64:\n  return answer()\n",
        "t.stfl",
        &CompilerOptions::default(),
    )
    .expect_err("non-void docstring-only body must fail");
    assert!(
        errors.iter().any(|err| err.message
            == "Function 'answer' declares return type 'int64' but not all paths return a value"),
        "{errors:?}"
    );
}
