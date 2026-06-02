use edit_distance::edit_distance;

use crate::symbol_table::SymbolTable;

/// Core fuzzy matching function using Levenshtein distance.
/// Returns the best match if within threshold (40% of input length, min 2).
fn suggest_identifier(misspelled: &str, valid_identifiers: &[String]) -> Option<String> {
    if valid_identifiers.is_empty() {
        return None;
    }

    let mut best_match = &valid_identifiers[0];
    let mut min_distance = edit_distance(misspelled, &valid_identifiers[0]);

    for identifier in valid_identifiers.iter().skip(1) {
        let distance = edit_distance(misspelled, identifier);
        if distance < min_distance {
            min_distance = distance;
            best_match = identifier;
        }
    }

    let threshold = (misspelled.len() as f64 * 0.4).max(2.0) as usize;
    if min_distance <= threshold {
        Some(best_match.clone())
    } else {
        None
    }
}

/// Suggests similar identifier from symbol table using fuzzy matching.
/// Uses actual declared symbols from the current scope chain.
pub fn suggest_from_symbols(misspelled: &str, symbol_table: &SymbolTable) -> Option<String> {
    let candidates = symbol_table.get_visible_symbol_names();
    suggest_identifier(misspelled, &candidates)
}

/// Suggests similar function name from symbol table.
/// Includes user-defined functions, builtins, and object methods.
pub fn suggest_function_from_symbols(
    misspelled: &str,
    symbol_table: &SymbolTable,
) -> Option<String> {
    let candidates = symbol_table.get_callable_names();
    suggest_identifier(misspelled, &candidates)
}

/// Suggests the function equivalent for common method-style calls.
/// Stoffel-Lang uses functions instead of methods for collection operations.
/// Uses the method suggestions registered in the symbol table.
pub fn suggest_method_to_function(method: &str, symbol_table: &SymbolTable) -> Option<String> {
    symbol_table.get_method_suggestion(method).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SourceLocation;
    use crate::symbol_table::{SymbolInfo, SymbolKind, SymbolType};

    fn make_loc() -> SourceLocation {
        SourceLocation::default()
    }

    fn make_variable(name: &str) -> SymbolInfo {
        SymbolInfo {
            name: name.to_string(),
            kind: SymbolKind::Variable { is_mutable: false },
            symbol_type: SymbolType::Int64,
            is_secret: false,
            defined_at: make_loc(),
        }
    }

    fn make_function(name: &str) -> SymbolInfo {
        SymbolInfo {
            name: name.to_string(),
            kind: SymbolKind::Function {
                parameters: vec![],
                return_type: SymbolType::Void,
            },
            symbol_type: SymbolType::Void,
            is_secret: false,
            defined_at: make_loc(),
        }
    }

    // ===========================================
    // Tests for suggest_identifier (core fuzzy matching)
    // ===========================================

    #[test]
    fn test_suggest_identifier_exact_match() {
        let candidates = vec!["counter".to_string(), "total".to_string()];
        let result = suggest_identifier("counter", &candidates);
        assert_eq!(result, Some("counter".to_string()));
    }

    #[test]
    fn test_suggest_identifier_single_typo() {
        let candidates = vec!["counter".to_string(), "total".to_string()];
        // "couter" is missing 'n' - distance of 1
        let result = suggest_identifier("couter", &candidates);
        assert_eq!(result, Some("counter".to_string()));
    }

    #[test]
    fn test_suggest_identifier_transposition() {
        let candidates = vec!["counter".to_string(), "total".to_string()];
        // "cuonter" has transposed letters
        let result = suggest_identifier("cuonter", &candidates);
        assert_eq!(result, Some("counter".to_string()));
    }

    #[test]
    fn test_suggest_identifier_no_match_too_different() {
        let candidates = vec!["counter".to_string(), "total".to_string()];
        // "xyz" is completely different
        let result = suggest_identifier("xyz", &candidates);
        assert_eq!(result, None);
    }

    #[test]
    fn test_suggest_identifier_empty_candidates() {
        let candidates: Vec<String> = vec![];
        let result = suggest_identifier("anything", &candidates);
        assert_eq!(result, None);
    }

    #[test]
    fn test_suggest_identifier_chooses_closest() {
        let candidates = vec![
            "count".to_string(),
            "counter".to_string(),
            "counting".to_string(),
        ];
        // "count" is closest to "count" (distance 1)
        let result = suggest_identifier("conut", &candidates);
        assert_eq!(result, Some("count".to_string()));
    }

    #[test]
    fn test_suggest_identifier_threshold_calculation() {
        // Threshold is max(len * 0.4, 2)
        // For "ab" (len 2): threshold = max(0.8, 2) = 2
        let candidates = vec!["ab".to_string(), "cd".to_string()];
        // "ac" has distance 1 from "ab", within threshold
        let result = suggest_identifier("ac", &candidates);
        assert_eq!(result, Some("ab".to_string()));

        // "xyz" has distance 3 from "ab", outside threshold of 2
        let result = suggest_identifier("xyz", &candidates);
        assert_eq!(result, None);
    }

    #[test]
    fn test_suggest_identifier_longer_names() {
        let candidates = vec!["calculate_total_amount".to_string()];
        // For longer names, threshold is higher (len * 0.4)
        // len=22, threshold = 8.8 -> 8
        // "calculate_totl_amount" has distance 2 (missing 'a' twice? no, missing 'al')
        let result = suggest_identifier("calculate_totl_amount", &candidates);
        assert_eq!(result, Some("calculate_total_amount".to_string()));
    }

    // ===========================================
    // Tests for suggest_from_symbols
    // ===========================================

    #[test]
    fn test_suggest_from_symbols_finds_variable() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_variable("counter"));
        table.declare_symbol(make_variable("total"));

        let result = suggest_from_symbols("couter", &table);
        assert_eq!(result, Some("counter".to_string()));
    }

    #[test]
    fn test_suggest_from_symbols_finds_function() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_function("calculate"));

        let result = suggest_from_symbols("calculte", &table);
        assert_eq!(result, Some("calculate".to_string()));
    }

    #[test]
    fn test_suggest_from_symbols_finds_builtin() {
        let table = SymbolTable::new();

        // "prnt" should suggest "print"
        let result = suggest_from_symbols("prnt", &table);
        assert_eq!(result, Some("print".to_string()));
    }

    #[test]
    fn test_suggest_from_symbols_nested_scope() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_variable("outer_var"));

        table.enter_scope();
        table.declare_symbol(make_variable("inner_var"));

        // Should find variables from both scopes
        let result = suggest_from_symbols("outer_vr", &table);
        assert_eq!(result, Some("outer_var".to_string()));

        let result = suggest_from_symbols("inner_vr", &table);
        assert_eq!(result, Some("inner_var".to_string()));
    }

    // ===========================================
    // Tests for suggest_function_from_symbols
    // ===========================================

    #[test]
    fn test_suggest_function_finds_user_function() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_function("process_data"));

        let result = suggest_function_from_symbols("process_dta", &table);
        assert_eq!(result, Some("process_data".to_string()));
    }

    #[test]
    fn test_suggest_function_finds_builtin_function() {
        let table = SymbolTable::new();

        let result = suggest_function_from_symbols("apend", &table);
        assert_eq!(result, Some("append".to_string()));
    }

    #[test]
    fn test_suggest_function_finds_builtin_object_method() {
        let table = SymbolTable::new();

        // "Share.opn" should suggest "Share.open"
        let result = suggest_function_from_symbols("Share.opn", &table);
        assert_eq!(result, Some("Share.open".to_string()));
    }

    #[test]
    fn test_suggest_function_excludes_variables() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_variable("my_variable"));
        // No function similar to "my_variabe"

        let result = suggest_function_from_symbols("my_variabe", &table);
        // Should not suggest "my_variable" because it's not callable
        assert_ne!(result, Some("my_variable".to_string()));
    }

    // ===========================================
    // Tests for suggest_method_to_function
    // ===========================================

    #[test]
    fn test_method_to_function_length() {
        // Note: length, len are now actual functions (UFCS aliases) so they work directly
        // via arr.length() -> length(arr). Only 'size' remains as a suggestion since
        // it's not a standard alias.
        let table = SymbolTable::new();
        // length and len now work directly via UFCS - no longer need suggestions
        assert_eq!(
            suggest_method_to_function("length", &table),
            None // Now works directly as a function
        );
        assert_eq!(
            suggest_method_to_function("len", &table),
            None // Now works directly as a function
        );
    }

    #[test]
    fn test_method_to_function_append() {
        // Note: append and push are now actual functions (UFCS aliases) so they work directly
        // via arr.append(x) -> append(arr, x)
        let table = SymbolTable::new();
        // append and push now work directly via UFCS - no longer need suggestions
        assert_eq!(
            suggest_method_to_function("append", &table),
            None // Now works directly as a function
        );
        assert_eq!(
            suggest_method_to_function("push", &table),
            None // Now works directly as a function
        );
    }

    #[test]
    fn test_method_to_function_pop() {
        let table = SymbolTable::new();
        assert_eq!(
            suggest_method_to_function("pop", &table),
            Some("array_pop(arr)".to_string())
        );
    }

    #[test]
    fn test_method_to_function_reveal() {
        let table = SymbolTable::new();
        let result = suggest_method_to_function("reveal", &table);
        assert!(result.is_some());
        assert!(result.unwrap().contains("clear"));
    }

    #[test]
    fn test_method_to_function_unknown() {
        let table = SymbolTable::new();
        assert_eq!(suggest_method_to_function("unknown_method", &table), None);
        assert_eq!(suggest_method_to_function("foo", &table), None);
    }
}
