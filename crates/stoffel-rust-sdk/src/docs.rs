//! Documentation model for Stoffel-Lang `"""docstrings"""` (**unstable**).
//!
//! This module is a thin SDK boundary over `stoffellang::docs`, the pipeline
//! behind `stoffel doc`. It re-exports the typed doc model, lint and coverage
//! helpers, and wraps extraction so compiler errors become SDK
//! [`Error::Compilation`] values.
//!
//! The model is **unstable**: its types may change in any release while
//! `stoffel doc` matures. Its kind enums are `#[non_exhaustive]`, so match on
//! them with a wildcard arm. The module is deliberately not part of the
//! [`prelude`](crate::prelude); import it explicitly.
//!
//! ```
//! # fn main() -> stoffel::Result<()> {
//! let module = stoffel::docs::extract_module(
//!     "math",
//!     "math.stfl",
//!     "\"\"\"Math helpers.\"\"\"\n\ndef double(x: int64) -> int64:\n  \"\"\"Double `x`.\"\"\"\n  return x * 2\n",
//! )?;
//! assert_eq!(module.items[0].signature, "double(x: int64) -> int64");
//! assert_eq!(module.items[0].summary(), Some("Double `x`."));
//! # Ok(())
//! # }
//! ```

pub use stoffellang::docs::{
    code_spans, coverage, link_aliases, lint, module_name_from_path, AliasOf, Coverage, DocIndex,
    DocItem, DocItemKind, DocWarning, DocWarningKind, FunctionSignature, ItemRef, ModuleDoc,
    ParamDoc, ParamSignature, ParsedDoc, Section, WarningSeverity,
};

use crate::error::{format_compiler_errors, Error, Result};

/// Extracts the documentation of one `.stfl` module.
///
/// `name` is the dotted module name (see [`module_name_from_path`]) and
/// `path` the file name shown in source locations. Any lexer or parser error
/// fails the extraction with [`Error::Compilation`]; partial docs are never
/// returned.
pub fn extract_module(name: &str, path: &str, source: &str) -> Result<ModuleDoc> {
    stoffellang::docs::extract_module(name, path, source)
        .map_err(|errors| Error::Compilation(format_compiler_errors(&errors)))
}

/// Extracts the documentation of the embedded standard library, one
/// [`ModuleDoc`] per stdlib file (`std.core`, `std.mpc`, ...).
pub fn extract_stdlib() -> Result<Vec<ModuleDoc>> {
    stoffellang::docs::extract_stdlib()
        .map_err(|errors| Error::Compilation(format_compiler_errors(&errors)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_errors_become_compilation_errors() {
        let error = extract_module("broken", "broken.stfl", "def main(:\n  pass\n").unwrap_err();
        assert!(matches!(error, Error::Compilation(message) if message.contains("broken.stfl")));
    }

    #[test]
    fn stdlib_extracts_through_the_sdk() {
        let modules = extract_stdlib().unwrap();
        assert!(modules.iter().any(|module| module.name == "std.mpc"));
    }
}
