//! Tests for `stoffellang::docs`: extraction, signatures, aliases, lint and
//! coverage, including a snapshot of the embedded stdlib.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use stoffellang::builtin_registry::builtin_registry;
use stoffellang::docs::{
    coverage, extract_module, extract_stdlib, lint, AliasOf, DocItem, DocItemKind, DocWarning,
    DocWarningKind, ModuleDoc, Section, WarningSeverity,
};

fn stdlib() -> Vec<ModuleDoc> {
    extract_stdlib().expect("the embedded stdlib extracts")
}

fn find<'a>(modules: &'a [ModuleDoc], path: &str) -> &'a DocItem {
    modules
        .iter()
        .flat_map(ModuleDoc::all_items)
        .find(|item| item.path == path)
        .unwrap_or_else(|| panic!("no documented item `{path}`"))
}

fn extract(source: &str) -> ModuleDoc {
    extract_module("app.main", "main.stfl", source).expect("source extracts")
}

/// One line per item: enough to pin kinds, paths, source-spelled
/// signatures, VM bindings and alias resolution.
fn snapshot(modules: &[ModuleDoc]) -> String {
    let mut out = String::new();
    for module in modules {
        writeln!(out, "module {} ({})", module.name, module.path).unwrap();
        for item in module.all_items() {
            let indent = if item.kind == DocItemKind::Method {
                "    "
            } else {
                "  "
            };
            write!(
                out,
                "{indent}{} {} :: {}",
                item.kind.label(),
                item.path,
                item.signature.replace('\n', " / ")
            )
            .unwrap();
            if let Some(vm_symbol) = &item.vm_symbol {
                write!(out, " [vm {vm_symbol}]").unwrap();
            }
            match &item.alias_of {
                Some(AliasOf::Item(target)) => write!(out, " [alias of {target}]").unwrap(),
                Some(AliasOf::VmBuiltin(target)) => {
                    write!(out, " [alias of VM builtin {target}]").unwrap()
                }
                Some(AliasOf::Type(target)) => write!(out, " [alias of type {target}]").unwrap(),
                Some(_) | None => {}
            }
            if item.receiver_bound {
                out.push_str(" [receiver]");
            }
            out.push('\n');
        }
    }
    out
}

/// Compares the stdlib extraction with `tests/rust/snapshots/stdlib_doc_items.txt`.
/// Set `UPDATE_SNAPSHOTS=1` to rewrite the file after an intended change.
#[test]
fn stdlib_extraction_matches_snapshot() {
    let actual = snapshot(&stdlib());
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/rust/snapshots/stdlib_doc_items.txt");
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    assert_eq!(
        actual, expected,
        "stdlib doc items changed; rerun with UPDATE_SNAPSHOTS=1 if intended"
    );
}

#[test]
fn stdlib_modules_are_named_like_imports() {
    let names: Vec<_> = stdlib().into_iter().map(|module| module.name).collect();
    assert_eq!(
        names,
        [
            "std.core",
            "std.mpc",
            "std.protocols",
            "std.crypto",
            "std.avss"
        ]
    );
}

/// Every builtin the registry knows is documented exactly once, bound to the
/// same VM symbol, and nothing else is.
#[test]
fn stdlib_extraction_covers_the_registry() {
    let modules = stdlib();
    let registry = builtin_registry();

    let mut functions = BTreeMap::new();
    let mut methods = BTreeMap::new();
    let mut objects = BTreeSet::new();
    let mut types = BTreeSet::new();
    for item in modules.iter().flat_map(ModuleDoc::all_items) {
        let vm_symbol = item.vm_symbol.clone();
        let duplicate = match item.kind {
            DocItemKind::BuiltinFunction => functions.insert(item.path.clone(), vm_symbol),
            DocItemKind::Method => methods.insert(item.path.clone(), vm_symbol),
            DocItemKind::BuiltinObject => (!objects.insert(item.path.clone())).then_some(None),
            DocItemKind::BuiltinType | DocItemKind::OpaqueType => {
                (!types.insert(item.path.clone())).then_some(None)
            }
            other => panic!("unexpected {} `{}` in the stdlib", other.label(), item.path),
        };
        assert!(duplicate.is_none(), "`{}` documented twice", item.path);
    }

    let expected_functions: BTreeMap<_, _> = registry
        .functions
        .iter()
        .map(|(name, info)| (name.clone(), Some(info.vm_symbol.clone())))
        .collect();
    assert_eq!(functions, expected_functions);

    let expected_methods: BTreeMap<_, _> = registry
        .objects
        .iter()
        .flat_map(|(object, info)| {
            info.methods.iter().map(move |(method, method_info)| {
                (
                    format!("{object}.{method}"),
                    Some(method_info.qualified_name.clone()),
                )
            })
        })
        .collect();
    assert_eq!(methods, expected_methods);

    let expected_objects: BTreeSet<_> = registry.objects.keys().cloned().collect();
    assert_eq!(objects, expected_objects);

    // Builtin object names are type names too; every other type name is a
    // `builtin type` or `builtin opaque` declaration.
    let expected_types: BTreeSet<_> = registry
        .type_names
        .difference(&registry.objects.keys().cloned().collect())
        .cloned()
        .collect();
    assert_eq!(types, expected_types);
}

#[test]
fn stdlib_signatures_use_source_spelling() {
    let modules = stdlib();
    let signature = |path| find(&modules, path).signature.as_str();

    assert_eq!(
        signature("pop"),
        "pop[T](array: list[T], index: int64 = -1) -> T"
    );
    assert_eq!(signature("print"), "print(*values) -> void");
    assert_eq!(signature("reveal"), "reveal[T](value: secret T) -> T");
    assert_eq!(
        signature("assert"),
        "assert(condition: bool, message: string = \"assertion failed\") -> void"
    );
    assert_eq!(
        signature("index"),
        "index[T](array: list[T], value: T, start: int64 = 0, stop: int64 = 9223372036854775807) -> int64"
    );
    assert_eq!(
        signature("Crypto.sha256"),
        "sha256(message: bytes) -> bytes"
    );
    assert_eq!(
        signature("Share.from_clear_fixed"),
        "from_clear_fixed(value: fix64, total_bits: int64, frac_bits: int64) -> Share"
    );
    assert_eq!(signature("bytes"), "type bytes = list[uint8]");
    assert_eq!(signature("int64"), "type int64");
    assert_eq!(signature("Closure"), "opaque Closure");
    assert_eq!(signature("Share"), "object Share");
}

#[test]
fn stdlib_aliases_resolve_to_canonical_items() {
    let modules = stdlib();
    let item_alias = |target: &str| Some(AliasOf::Item(target.to_string()));
    let type_alias = |target: &str| Some(AliasOf::Type(target.to_string()));

    let expected: BTreeMap<&str, Option<AliasOf>> = [
        ("reveal", item_alias("Share.open")),
        ("Share.reveal", item_alias("Share.open")),
        ("Share.open_fixed", item_alias("Share.open")),
        ("Share.add_scalar", item_alias("Share.add_constant")),
        ("Share.batch_open_fixed", item_alias("Share.batch_open")),
        ("create_closure_with_upvalue", item_alias("create_closure")),
        ("call_closure_with_arg", item_alias("call_closure")),
        ("LocalStorage.load_share", item_alias("LocalStorage.load")),
        ("list", Some(AliasOf::VmBuiltin("create_array".to_string()))),
        ("int", type_alias("int64")),
        ("float64", type_alias("float")),
        ("f64", type_alias("float")),
        ("fix32", type_alias("fixed32")),
        ("fix64", type_alias("fixed64")),
        ("bytes", type_alias("list[uint8]")),
        ("ByteArray", type_alias("list[uint8]")),
    ]
    .into_iter()
    .collect();

    let actual: BTreeMap<&str, Option<AliasOf>> = modules
        .iter()
        .flat_map(ModuleDoc::all_items)
        .filter(|item| item.alias_of.is_some())
        .map(|item| (item.path.as_str(), item.alias_of.clone()))
        .collect();
    assert_eq!(actual, expected);

    // Explicit self-mapping symbols and implicit symbols are not aliases.
    for path in [
        "pop",
        "len",
        "append",
        "Share.open",
        "create_closure",
        "range",
    ] {
        let item = find(&modules, path);
        assert_eq!(item.alias_of, None, "`{path}`");
        assert_eq!(item.vm_symbol.as_deref(), Some(path), "`{path}`");
    }
}

#[test]
fn receiver_bound_methods_are_flagged() {
    let modules = stdlib();
    let registry = builtin_registry();
    for object in modules
        .iter()
        .flat_map(|module| module.items.iter())
        .filter(|item| item.kind == DocItemKind::BuiltinObject)
    {
        for method in &object.members {
            assert_eq!(
                method.receiver_bound,
                registry.is_receiver_bound_method(&object.name, &method.name),
                "`{}`",
                method.path
            );
        }
    }
    assert!(find(&modules, "Share.mul").receiver_bound);
    assert!(!find(&modules, "Share.from_clear").receiver_bound);
    assert!(!find(&modules, "Crypto.sha256").receiver_bound);
}

/// CI gate: every stdlib module and item carries a docstring, and the lint
/// has nothing to say (no missing docs, notes, broken links or Args drift).
/// A new builtin declared in `stdlib/std/*.stfl` without a docstring fails
/// here; `stoffel doc --std --check` shows the details.
#[test]
fn stdlib_is_fully_documented_with_no_lint_findings() {
    let modules = stdlib();
    let warnings = lint(&modules);
    let report: Vec<String> = warnings.iter().map(ToString::to_string).collect();
    assert!(
        warnings.is_empty(),
        "stdlib doc lint findings:\n{report:#?}"
    );

    let undocumented_modules: Vec<&str> = modules
        .iter()
        .filter(|module| module.doc.is_none())
        .map(|module| module.name.as_str())
        .collect();
    assert!(
        undocumented_modules.is_empty(),
        "modules without a docstring: {undocumented_modules:?}"
    );

    let coverage = coverage(&modules);
    let item_count = modules.iter().flat_map(ModuleDoc::all_items).count();
    assert_eq!(coverage.total, item_count);
    assert!(
        coverage.is_complete(),
        "{} of {} stdlib items are undocumented",
        coverage.undocumented(),
        coverage.total
    );
}

const USER_MODULE: &str = r#""""Geometry helpers.

Everything here works on `Point`.
"""

object Point:
  """A point in the plane."""
  x: int64
  y: secret int64

enum Color:
  """Colors."""
  Red
  Green = 2

type Coord = list[int]:
  """A coordinate list."""

def manhattan(a: Point, b: Point, scale: int = 1) -> int64:
  """Manhattan distance.

  Args:
    a: First point.
    b: Second point.
    scale: Multiplier.

  Returns:
    The distance.

  See Also:
    `Point`, `std.core`
  """
  def absolute(value: int64) -> int64:
    """Nested helpers are not documented."""
    if value < 0:
      return 0 - value
    return value
  return absolute(a.x - b.x) * scale

def _helper() -> void:
  pass

def main() -> void:
  print("hi")
"#;

#[test]
fn user_module_extraction() {
    let module = extract(USER_MODULE);
    assert_eq!(module.name, "app.main");
    assert_eq!(module.path, "main.stfl");
    let module_doc = module.doc.as_ref().expect("module docstring");
    assert_eq!(module_doc.summary, "Geometry helpers.");
    assert_eq!(module_doc.body, "Everything here works on `Point`.");

    let paths: Vec<_> = module.items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(
        paths,
        ["Point", "Color", "Coord", "manhattan", "_helper", "main"],
        "nested defs are skipped"
    );

    let point = &module.items[0];
    assert_eq!(point.kind, DocItemKind::Object);
    assert_eq!(
        point.signature,
        "object Point:\n  x: int64\n  y: secret int64"
    );
    assert_eq!(point.summary(), Some("A point in the plane."));
    assert_eq!(point.anchor(), "obj.Point");

    let color = &module.items[1];
    assert_eq!(color.kind, DocItemKind::Enum);
    assert_eq!(color.signature, "enum Color:\n  Red\n  Green = 2");

    let coord = &module.items[2];
    assert_eq!(coord.kind, DocItemKind::TypeAlias);
    assert_eq!(coord.signature, "type Coord = list[int]");
    assert_eq!(coord.alias_of, Some(AliasOf::Type("list[int]".into())));

    let manhattan = &module.items[3];
    assert_eq!(manhattan.kind, DocItemKind::Function);
    assert_eq!(
        manhattan.signature,
        "manhattan(a: Point, b: Point, scale: int = 1) -> int64"
    );
    assert_eq!(manhattan.vm_symbol, None);
    assert_eq!(manhattan.anchor(), "fn.manhattan");
    assert_eq!(manhattan.location.line, 19);
    let doc = manhattan.doc.as_ref().unwrap();
    assert_eq!(doc.args().unwrap().len(), 3);
    assert!(matches!(doc.sections.last(), Some(Section::SeeAlso(_))));

    assert!(module.items[4].is_private());
    assert!(module.items[5].doc.is_none());
}

#[test]
fn user_module_lint() {
    let modules = [extract(USER_MODULE)];
    let warnings = lint(&modules);
    let summary: Vec<(Option<&str>, &DocWarningKind)> = warnings
        .iter()
        .map(|warning| (warning.item.as_deref(), &warning.kind))
        .collect();
    // `_helper` is private; `std.core` is not a module of this doc set.
    assert_eq!(
        summary,
        [
            (
                Some("manhattan"),
                &DocWarningKind::BrokenLink {
                    target: "std.core".into()
                }
            ),
            (Some("main"), &DocWarningKind::MissingDoc),
        ]
    );
    assert_eq!(warnings[1].location.line, 43);
    assert!(warnings[1].to_string().contains("`main` has no docstring"));

    let coverage = coverage(&modules);
    assert_eq!((coverage.documented, coverage.total), (4, 5));
}

#[test]
fn lint_reports_every_warning_kind() {
    let source = r#"def f(a: int64, b: int64) -> void:
  """Does things.

  Reads `Thing.value`; `Thing` is not a builtin object, so field paths are
  not links.

  Args:
    a: First.
    c: Not a parameter.

  Returns:
    Nothing, really.

  See Also:
    `missing_item`, `f`
  """
  pass

object Thing:
  """A thing."""
  value: int64
"#;
    let modules = [extract(source)];
    let kinds: Vec<DocWarningKind> = lint(&modules)
        .into_iter()
        .map(|warning| warning.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            DocWarningKind::MissingDoc,
            DocWarningKind::UnknownParam { name: "c".into() },
            DocWarningKind::UndocumentedParam { name: "b".into() },
            DocWarningKind::ReturnsOnVoid,
            DocWarningKind::BrokenLink {
                target: "missing_item".into()
            },
        ]
    );
}

#[test]
fn lint_skips_private_items_and_members() {
    let source = r#""""Private things."""
builtin object _Hidden:
  def secret_method(x: int64) -> int64 {.builtin.}:
def _private(x: int64) -> void:
  """Args:
    y: Wrong name, but private.
  """
  pass
"#;
    let modules = [extract(source)];
    assert_eq!(lint(&modules), Vec::<DocWarning>::new());
    assert_eq!(coverage(&modules).total, 0);
}

#[test]
fn undocumented_aliases_of_documented_items_are_notes() {
    let source = r#""""Aliases."""
builtin object Box:
  """A box."""
  def open(value: Box) -> int64 {.builtin.}:
    """Open it."""
  def reveal(value: Box) -> int64 {.builtin: "Box.open".}:
  def close(value: Box) -> int64 {.builtin.}:
  def shut(value: Box) -> int64 {.builtin: "Box.close".}:
def make() -> Box {.builtin: "create_box".}:
  """Make a box."""
"#;
    let modules = [extract(source)];
    let warnings = lint(&modules);
    let found: Vec<(&str, WarningSeverity)> = warnings
        .iter()
        .map(|warning| (warning.item.as_deref().unwrap(), warning.severity))
        .collect();
    assert_eq!(
        found,
        [
            ("Box.reveal", WarningSeverity::Note),
            ("Box.close", WarningSeverity::Warning),
            ("Box.shut", WarningSeverity::Warning),
        ]
    );
    assert!(warnings
        .iter()
        .all(|warning| warning.kind == DocWarningKind::MissingDoc));

    let make = find(&modules, "make");
    assert_eq!(
        make.alias_of,
        Some(AliasOf::VmBuiltin("create_box".into())),
        "undeclared VM symbols are VM builtins, not broken links"
    );

    // Box, open, reveal (via its canonical item) and make are documented.
    let coverage = coverage(&modules);
    assert_eq!((coverage.documented, coverage.total), (4, 6));
}

#[test]
fn extraction_fails_on_parse_errors() {
    let errors = extract_module("broken", "broken.stfl", "def f(:\n  pass\n")
        .expect_err("a parse error must fail extraction");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].location.file, "broken.stfl");

    let errors = extract_module("broken", "broken.stfl", "var s = \"unterminated\n")
        .expect_err("a lexer error must fail extraction");
    assert_eq!(errors.len(), 1);
}

#[test]
fn builtin_docstrings_are_attached() {
    let source = r#"builtin type bytes = list[uint8]:
  """Byte string."""
builtin opaque Closure:
  """A closure handle."""
def pop[T](array: list[T], index: int64 = -1) -> T {.builtin: "pop".}:
  """Remove and return an element.

  MPC:
    Local; no communication.
  """
"#;
    let module = extract(source);
    assert_eq!(module.items[0].summary(), Some("Byte string."));
    assert_eq!(module.items[1].kind, DocItemKind::OpaqueType);
    assert_eq!(module.items[1].summary(), Some("A closure handle."));
    let pop = &module.items[2];
    assert_eq!(pop.kind, DocItemKind::BuiltinFunction);
    assert_eq!(pop.anchor(), "fn.pop");
    assert_eq!(
        pop.doc.as_ref().unwrap().sections,
        [Section::Mpc("Local; no communication.".into())]
    );
}
