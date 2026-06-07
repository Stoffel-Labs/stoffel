use std::collections::HashMap;

use crate::ast::{AstNode, Pragma, Value};
use crate::errors::{CompilerError, ErrorReporter, SourceLocation};
use crate::suggestions::{
    suggest_from_symbols, suggest_function_from_symbols, suggest_method_to_function,
};
use crate::symbol_table::{
    SymbolDeclarationError, SymbolInfo, SymbolKind, SymbolTable, SymbolType, UserObjectInfo,
};

/// Performs semantic analysis (symbol checking, type checking) on the AST.
pub struct SemanticAnalyzer<'a> {
    symbol_table: SymbolTable,
    error_reporter: &'a mut ErrorReporter,
    current_function_return_type: Option<SymbolType>, // Track expected return type
    /// Imported symbols from other modules, keyed by their qualified name
    imported_symbols: HashMap<String, SymbolInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticError;

impl<'a> SemanticAnalyzer<'a> {
    pub fn new(error_reporter: &'a mut ErrorReporter, _filename: &'a str) -> Self {
        SemanticAnalyzer {
            symbol_table: SymbolTable::new(),
            error_reporter,
            current_function_return_type: None,
            imported_symbols: HashMap::new(),
        }
    }

    /// Creates a new analyzer with pre-populated imported symbols.
    pub fn with_imports(
        error_reporter: &'a mut ErrorReporter,
        _filename: &'a str,
        imported_symbols: HashMap<String, SymbolInfo>,
    ) -> Self {
        SemanticAnalyzer {
            symbol_table: SymbolTable::new(),
            error_reporter,
            current_function_return_type: None,
            imported_symbols,
        }
    }

    /// Adds imported symbols to the global scope.
    fn register_imported_symbols(&mut self) {
        for (name, info) in &self.imported_symbols {
            // Add the simple name (without module prefix) for convenience
            // This allows calling `add(a, b)` instead of `utils.math.add(a, b)`
            let simple_name = name.rsplit('.').next().unwrap_or(name);
            self.symbol_table.declare_symbol(SymbolInfo {
                name: simple_name.to_string(),
                kind: info.kind.clone(),
                symbol_type: info.symbol_type.clone(),
                is_secret: info.is_secret,
                defined_at: info.defined_at.clone(),
            });
            // Also add the qualified name for explicit module.func() calls
            self.symbol_table.declare_symbol(info.clone());
        }
    }

    fn int_literal_value(node: &AstNode) -> Option<i128> {
        if let AstNode::Literal {
            value: Value::Int { value, .. },
            ..
        } = node
        {
            if *value <= i128::MAX as u128 {
                Some(*value as i128)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Checks if two types are compatible, allowing Unknown to match any type.
    /// This enables type refinement where a concrete type annotation can refine
    /// an Unknown type from inference (e.g., `List[float]` refines `List[<unknown>]`).
    fn types_compatible(src: &SymbolType, dst: &SymbolType) -> bool {
        // Unknown is compatible with anything
        if *src == SymbolType::Unknown || *dst == SymbolType::Unknown {
            return true;
        }

        if Self::requires_explicit_reveal(src, dst) {
            return false;
        }

        if Self::share_to_secret_compatible(src, dst) {
            return true;
        }
        if Self::secret_to_share_compatible(src, dst) {
            return true;
        }

        match (src.underlying_type(), dst.underlying_type()) {
            // List types: compatible if element types are compatible
            (SymbolType::List(src_elem), SymbolType::List(dst_elem)) => {
                Self::types_compatible(src_elem, dst_elem)
            }
            // Dict types: compatible if both key and value types are compatible
            (SymbolType::Dict(src_k, src_v), SymbolType::Dict(dst_k, dst_v)) => {
                Self::types_compatible(src_k, dst_k) && Self::types_compatible(src_v, dst_v)
            }
            // Generic types: compatible if name matches and all params are compatible
            (
                SymbolType::Generic(src_name, src_params),
                SymbolType::Generic(dst_name, dst_params),
            ) => {
                src_name == dst_name
                    && src_params.len() == dst_params.len()
                    && src_params
                        .iter()
                        .zip(dst_params.iter())
                        .all(|(s, d)| Self::types_compatible(s, d))
            }
            // User object annotations parse as TypeName, while constructors
            // and inferred values carry Object.
            (SymbolType::TypeName(src_name), SymbolType::Object(dst_name))
            | (SymbolType::Object(src_name), SymbolType::TypeName(dst_name)) => {
                src_name == dst_name
            }
            // Secret types: compare underlying types
            (SymbolType::Secret(src_inner), SymbolType::Secret(dst_inner)) => {
                Self::types_compatible(src_inner, dst_inner)
            }
            // Type variables are resolved per call by `check_generic_compat`.
            // Outside that context they behave like placeholders.
            (SymbolType::TypeVar(_), _) | (_, SymbolType::TypeVar(_)) => true,
            // For all other types, require exact match
            (s, d) => s == d,
        }
    }

    fn is_share_alias_type(ty: &SymbolType) -> bool {
        matches!(
            ty.underlying_type(),
            SymbolType::Object(name) | SymbolType::TypeName(name) if name == "Share"
        )
    }

    fn share_to_secret_compatible(src: &SymbolType, dst: &SymbolType) -> bool {
        Self::is_share_alias_type(src) && matches!(dst, SymbolType::Secret(_))
    }

    fn secret_to_share_compatible(src: &SymbolType, dst: &SymbolType) -> bool {
        matches!(src, SymbolType::Secret(_)) && Self::is_share_alias_type(dst)
    }

    fn is_variadic_builtin(name: &str) -> bool {
        matches!(name, "print")
    }

    fn is_typed_assignment_target(node: &AstNode) -> bool {
        matches!(
            node,
            AstNode::Identifier(_, _) | AstNode::FieldAccess { .. } | AstNode::IndexAccess { .. }
        )
    }

    fn share_expr_can_initialize_secret(expr: Option<&AstNode>, dst: &SymbolType) -> bool {
        let Some(AstNode::FunctionCall { function, .. }) = expr else {
            return false;
        };
        let AstNode::Identifier(name, _) = function.as_ref() else {
            return false;
        };

        match name.as_str() {
            "Share.random" => Self::share_random_expected_type(dst),
            "ClientStore.take_share" | "Share.from_clear" | "Share.from_clear_int" => {
                dst.is_secret() && dst.is_integer()
            }
            "ClientStore.take_share_fixed" | "Share.from_clear_fixed" => {
                matches!(dst, SymbolType::Secret(inner) if inner.underlying_type() == &SymbolType::Float)
            }
            _ => false,
        }
    }

    fn share_random_expected_type(ty: &SymbolType) -> bool {
        ty.is_secret() && (ty.is_integer() || ty.underlying_type() == &SymbolType::Bool)
    }

    fn is_unrefined_share_random_call(node: &AstNode) -> bool {
        matches!(
            node,
            AstNode::FunctionCall {
                function,
                resolved_return_type,
                ..
            } if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "Share.random")
                && !resolved_return_type
                    .as_ref()
                    .is_some_and(Self::share_random_expected_type)
        )
    }

    fn contains_unrefined_share_random_call(node: &AstNode) -> bool {
        if Self::is_unrefined_share_random_call(node) {
            return true;
        }
        match node {
            AstNode::FunctionCall { arguments, .. } | AstNode::CommandCall { arguments, .. } => {
                arguments
                    .iter()
                    .any(Self::contains_unrefined_share_random_call)
            }
            AstNode::NamedArgument { value, .. } => {
                Self::contains_unrefined_share_random_call(value)
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => elements
                .iter()
                .any(Self::contains_unrefined_share_random_call),
            AstNode::DictLiteral { pairs, .. } => pairs.iter().any(|(key, value)| {
                Self::contains_unrefined_share_random_call(key)
                    || Self::contains_unrefined_share_random_call(value)
            }),
            AstNode::Assignment { target, value, .. } => {
                Self::contains_unrefined_share_random_call(target)
                    || Self::contains_unrefined_share_random_call(value)
            }
            AstNode::VariableDeclaration { value, .. } | AstNode::Return { value, .. } => value
                .as_deref()
                .is_some_and(Self::contains_unrefined_share_random_call),
            AstNode::BinaryOperation { left, right, .. } => {
                Self::contains_unrefined_share_random_call(left)
                    || Self::contains_unrefined_share_random_call(right)
            }
            AstNode::UnaryOperation { operand, .. } => {
                Self::contains_unrefined_share_random_call(operand)
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                Self::contains_unrefined_share_random_call(condition)
                    || Self::contains_unrefined_share_random_call(then_branch)
                    || else_branch
                        .as_deref()
                        .is_some_and(Self::contains_unrefined_share_random_call)
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                Self::contains_unrefined_share_random_call(condition)
                    || Self::contains_unrefined_share_random_call(body)
            }
            AstNode::Block(statements) => statements
                .iter()
                .any(Self::contains_unrefined_share_random_call),
            AstNode::FieldAccess { object, .. } => {
                Self::contains_unrefined_share_random_call(object)
            }
            AstNode::IndexAccess { base, index, .. } => {
                Self::contains_unrefined_share_random_call(base)
                    || Self::contains_unrefined_share_random_call(index)
            }
            _ => false,
        }
    }

    fn requires_explicit_reveal(src: &SymbolType, dst: &SymbolType) -> bool {
        matches!(src, SymbolType::Secret(_))
            && !matches!(dst, SymbolType::Secret(_) | SymbolType::Unknown)
            && !Self::is_share_alias_type(dst)
    }

    fn substitute_type_vars(ty: &SymbolType, bindings: &HashMap<String, SymbolType>) -> SymbolType {
        match ty {
            SymbolType::TypeVar(name) => bindings.get(name).cloned().unwrap_or(SymbolType::Unknown),
            SymbolType::Secret(inner) => {
                SymbolType::Secret(Box::new(Self::substitute_type_vars(inner, bindings)))
            }
            SymbolType::List(elem) => {
                SymbolType::List(Box::new(Self::substitute_type_vars(elem, bindings)))
            }
            SymbolType::Dict(key, value) => SymbolType::Dict(
                Box::new(Self::substitute_type_vars(key, bindings)),
                Box::new(Self::substitute_type_vars(value, bindings)),
            ),
            SymbolType::Generic(name, params) => SymbolType::Generic(
                name.clone(),
                params
                    .iter()
                    .map(|param| Self::substitute_type_vars(param, bindings))
                    .collect(),
            ),
            _ => ty.clone(),
        }
    }

    fn refine_type_with_expected(inferred: &SymbolType, expected: &SymbolType) -> SymbolType {
        match (inferred, expected) {
            (SymbolType::Unknown, expected) | (SymbolType::TypeVar(_), expected) => {
                expected.clone()
            }
            (SymbolType::List(inferred_elem), SymbolType::List(expected_elem)) => {
                SymbolType::List(Box::new(Self::refine_type_with_expected(
                    inferred_elem,
                    expected_elem,
                )))
            }
            (
                SymbolType::Dict(inferred_key, inferred_value),
                SymbolType::Dict(expected_key, expected_value),
            ) => SymbolType::Dict(
                Box::new(Self::refine_type_with_expected(inferred_key, expected_key)),
                Box::new(Self::refine_type_with_expected(
                    inferred_value,
                    expected_value,
                )),
            ),
            (SymbolType::Secret(inferred_inner), SymbolType::Secret(expected_inner)) => {
                SymbolType::Secret(Box::new(Self::refine_type_with_expected(
                    inferred_inner,
                    expected_inner,
                )))
            }
            (
                SymbolType::Generic(inferred_name, inferred_params),
                SymbolType::Generic(expected_name, expected_params),
            ) if inferred_name == expected_name
                && inferred_params.len() == expected_params.len() =>
            {
                SymbolType::Generic(
                    inferred_name.clone(),
                    inferred_params
                        .iter()
                        .zip(expected_params.iter())
                        .map(|(inferred, expected)| {
                            Self::refine_type_with_expected(inferred, expected)
                        })
                        .collect(),
                )
            }
            _ => inferred.clone(),
        }
    }

    fn refine_expression_type_with_expected(
        expr: AstNode,
        inferred_type: &SymbolType,
        expected_type: &SymbolType,
    ) -> (AstNode, SymbolType) {
        let refined_type = match (&expr, inferred_type, expected_type) {
            (AstNode::FunctionCall { function, .. }, inferred, expected)
                if (Self::is_share_alias_type(inferred)
                    || matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "Share.random"))
                    && Self::share_expr_can_initialize_secret(Some(&expr), expected) =>
            {
                expected.clone()
            }
            _ => Self::refine_type_with_expected(inferred_type, expected_type),
        };

        let refined_expr = match expr {
            AstNode::FunctionCall {
                function,
                arguments,
                location,
                ..
            } => AstNode::FunctionCall {
                function,
                arguments,
                location,
                resolved_return_type: Some(refined_type.clone()),
            },
            AstNode::CommandCall {
                command,
                arguments,
                location,
                ..
            } => AstNode::CommandCall {
                command,
                arguments,
                location,
                resolved_return_type: Some(refined_type.clone()),
            },
            AstNode::ListLiteral { elements, location } => {
                let elements = if let SymbolType::List(expected_elem) = expected_type {
                    elements
                        .into_iter()
                        .map(|element| {
                            let (refined_element, _) = Self::refine_expression_type_with_expected(
                                element,
                                &SymbolType::Unknown,
                                expected_elem,
                            );
                            refined_element
                        })
                        .collect()
                } else {
                    elements
                };
                AstNode::ListLiteral { elements, location }
            }
            AstNode::DictLiteral { pairs, location } => {
                let pairs = if let SymbolType::Dict(expected_key, expected_value) = expected_type {
                    pairs
                        .into_iter()
                        .map(|(key, value)| {
                            let (refined_key, _) = Self::refine_expression_type_with_expected(
                                key,
                                &SymbolType::Unknown,
                                expected_key,
                            );
                            let (refined_value, _) = Self::refine_expression_type_with_expected(
                                value,
                                &SymbolType::Unknown,
                                expected_value,
                            );
                            (refined_key, refined_value)
                        })
                        .collect()
                } else {
                    pairs
                };
                AstNode::DictLiteral { pairs, location }
            }
            other => other,
        };

        (refined_expr, refined_type)
    }

    fn contains_type_var(ty: &SymbolType) -> bool {
        match ty {
            SymbolType::TypeVar(_) => true,
            SymbolType::Secret(inner) | SymbolType::List(inner) => Self::contains_type_var(inner),
            SymbolType::Dict(key, value) => {
                Self::contains_type_var(key) || Self::contains_type_var(value)
            }
            SymbolType::Generic(_, params) => params.iter().any(Self::contains_type_var),
            _ => false,
        }
    }

    fn refine_argument_with_expected(
        argument: &mut AstNode,
        argument_type: &mut SymbolType,
        expected_type: &SymbolType,
    ) {
        if Self::contains_type_var(expected_type) {
            return;
        }
        let (refined_arg, refined_type) = Self::refine_expression_type_with_expected(
            argument.clone(),
            argument_type,
            expected_type,
        );
        *argument = refined_arg;
        *argument_type = refined_type;
    }

    fn check_generic_compat(
        &mut self,
        src_node: Option<&AstNode>,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        bindings: &mut HashMap<String, SymbolType>,
        location: SourceLocation,
    ) -> Result<(), ()> {
        match dst_type {
            SymbolType::TypeVar(name) => {
                if let Some(bound) = bindings.get(name).cloned() {
                    self.check_integer_compat(src_node, src_type, &bound, location)
                } else {
                    bindings.insert(name.clone(), src_type.clone());
                    Ok(())
                }
            }
            SymbolType::Secret(dst_inner) => {
                if let SymbolType::Secret(src_inner) = src_type.underlying_type() {
                    self.check_generic_compat(src_node, src_inner, dst_inner, bindings, location)
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            SymbolType::List(dst_elem) => {
                if let SymbolType::List(src_elem) = src_type.underlying_type() {
                    self.check_generic_compat(src_node, src_elem, dst_elem, bindings, location)
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            SymbolType::Dict(dst_key, dst_value) => {
                if let SymbolType::Dict(src_key, src_value) = src_type.underlying_type() {
                    self.check_generic_compat(
                        src_node,
                        src_key,
                        dst_key,
                        bindings,
                        location.clone(),
                    )?;
                    self.check_generic_compat(src_node, src_value, dst_value, bindings, location)
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            SymbolType::Generic(dst_name, dst_params) => {
                if let SymbolType::Generic(src_name, src_params) = src_type.underlying_type() {
                    if src_name == dst_name && src_params.len() == dst_params.len() {
                        for (src_param, dst_param) in src_params.iter().zip(dst_params.iter()) {
                            self.check_generic_compat(
                                src_node,
                                src_param,
                                dst_param,
                                bindings,
                                location.clone(),
                            )?;
                        }
                        Ok(())
                    } else {
                        self.check_integer_compat(src_node, src_type, dst_type, location)
                    }
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            _ => self.check_integer_compat(src_node, src_type, dst_type, location),
        }
    }

    fn check_integer_compat(
        &mut self,
        src_node: Option<&AstNode>,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        location: crate::errors::SourceLocation,
    ) -> Result<(), ()> {
        if Self::requires_explicit_reveal(src_type, dst_type) {
            self.error_reporter.add_error(
                CompilerError::type_error(
                    format!(
                        "Cannot implicitly reveal '{}' as '{}'",
                        declared_type_to_string(src_type),
                        declared_type_to_string(dst_type)
                    ),
                    location,
                )
                .with_hint("Call .reveal() to explicitly reveal a secret value"),
            );
            return Err(());
        }

        // Only enforce special rules if destination is integer
        if dst_type.is_integer() {
            // 1) Literal fits check
            if let Some(val) = src_node.and_then(Self::int_literal_value) {
                if !dst_type.fits_literal_i128(val) {
                    let min = dst_type.min_value_i128().unwrap();
                    let max = dst_type.max_value_i128().unwrap();
                    self.error_reporter.add_error(CompilerError::type_error(
                        format!(
                            "Integer literal {} does not fit in '{}' (allowed range {}..={})",
                            val,
                            declared_type_to_string(dst_type),
                            min,
                            max
                        ),
                        location,
                    ));
                    return Err(());
                }
                return Ok(());
            }
            // 2) Type-to-type compatibility
            if src_type.is_integer() {
                if src_type.underlying_type() == dst_type.underlying_type() {
                    return Ok(());
                }
                if src_type.can_widen_to(dst_type) {
                    return Ok(());
                }
                self.error_reporter.add_error(CompilerError::type_error(
                    format!(
                        "Cannot implicitly convert from '{}' to '{}'",
                        declared_type_to_string(src_type),
                        declared_type_to_string(dst_type)
                    ),
                    location,
                ));
                return Err(());
            }
        }
        // Fallback: check type compatibility (handles Unknown in collections)
        let share_random_in_bad_context = matches!(
            src_node,
            Some(AstNode::FunctionCall { function, .. })
                if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "Share.random")
                    && !Self::share_random_expected_type(dst_type)
        );
        if Self::is_share_alias_type(src_type) && share_random_in_bad_context {
            self.error_reporter.add_error(CompilerError::type_error(
                format!(
                    "Type mismatch. Expected '{}', found '{}'",
                    declared_type_to_string(dst_type),
                    declared_type_to_string(src_type)
                ),
                location,
            ));
            return Err(());
        }

        if !Self::types_compatible(src_type, dst_type) {
            self.error_reporter.add_error(CompilerError::type_error(
                format!(
                    "Type mismatch. Expected '{}', found '{}'",
                    declared_type_to_string(dst_type),
                    declared_type_to_string(src_type)
                ),
                location,
            ));
            return Err(());
        }
        Ok(())
    }

    fn resolve_type_aliases(&self, sym_type: &SymbolType) -> SymbolType {
        self.resolve_type_aliases_inner(sym_type, 0)
    }

    fn resolve_type_aliases_inner(&self, sym_type: &SymbolType, depth: usize) -> SymbolType {
        if depth > 32 {
            return sym_type.clone();
        }

        match sym_type {
            SymbolType::TypeName(name) => {
                if let Some(info) = self.symbol_table.lookup_symbol(name) {
                    if matches!(&info.kind, SymbolKind::Type) {
                        return self.resolve_type_aliases_inner(&info.symbol_type, depth + 1);
                    }
                }
                sym_type.clone()
            }
            SymbolType::Secret(inner) => {
                SymbolType::Secret(Box::new(self.resolve_type_aliases_inner(inner, depth + 1)))
            }
            SymbolType::List(inner) => {
                SymbolType::List(Box::new(self.resolve_type_aliases_inner(inner, depth + 1)))
            }
            SymbolType::Dict(key, value) => SymbolType::Dict(
                Box::new(self.resolve_type_aliases_inner(key, depth + 1)),
                Box::new(self.resolve_type_aliases_inner(value, depth + 1)),
            ),
            SymbolType::Generic(name, params) => SymbolType::Generic(
                name.clone(),
                params
                    .iter()
                    .map(|param| self.resolve_type_aliases_inner(param, depth + 1))
                    .collect(),
            ),
            _ => sym_type.clone(),
        }
    }

    /// Performs semantic analysis (declaration and resolution passes).
    /// Returns the potentially annotated AST or errors.
    pub fn analyze(&mut self, node: AstNode) -> Result<AstNode, SemanticError> {
        // Register any imported symbols before analysis
        self.register_imported_symbols();

        // Perform the combined analysis traversal
        let (analyzed_node, _node_type) = self.analyze_node(node).map_err(|_| SemanticError)?;
        if !self.symbol_table.errors.is_empty() {
            for (error, location) in &self.symbol_table.errors {
                match error {
                    SymbolDeclarationError::AlreadyDeclared {
                        name,
                        original_location,
                    } => {
                        self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!("Symbol '{}' already declared in this scope", name),
                                location.clone(), // Location of the second declaration attempt
                            )
                            .with_hint(format!(
                                "Original declaration was here: {}",
                                original_location
                            )),
                        );
                    } // Handle other symbol table errors if added later
                }
            }
            return Err(SemanticError); // Stop if declaration errors occurred
        }

        if self.error_reporter.has_errors() {
            Err(SemanticError)
        } else {
            Ok(analyzed_node) // Return the analyzed node
        }
    }

    /// Recursively analyzes a node, handling symbol declaration, resolution, and type checking.
    /// Returns the (potentially modified) node and its determined type.
    fn analyze_node(&mut self, node: AstNode) -> Result<(AstNode, SymbolType), ()> {
        match node {
            // --- Leaf Nodes ---
            AstNode::Literal { value, location } => Ok((
                AstNode::Literal {
                    value: value.clone(),
                    location,
                },
                match value {
                    Value::Int { kind, .. } => match kind {
                        Some(crate::ast::IntKind::Signed(w)) => match w {
                            crate::ast::IntWidth::W8 => SymbolType::Int8,
                            crate::ast::IntWidth::W16 => SymbolType::Int16,
                            crate::ast::IntWidth::W32 => SymbolType::Int32,
                            crate::ast::IntWidth::W64 => SymbolType::Int64,
                        },
                        Some(crate::ast::IntKind::Unsigned(w)) => match w {
                            crate::ast::IntWidth::W8 => SymbolType::UInt8,
                            crate::ast::IntWidth::W16 => SymbolType::UInt16,
                            crate::ast::IntWidth::W32 => SymbolType::UInt32,
                            crate::ast::IntWidth::W64 => SymbolType::UInt64,
                        },
                        None => SymbolType::Int64,
                    },
                    Value::Float(_) => SymbolType::Float,
                    Value::String(_) => SymbolType::String,
                    Value::Bool(_) => SymbolType::Bool,
                    Value::Nil => SymbolType::Nil,
                },
            )),
            AstNode::Identifier(name, location) => {
                // First check for qualified builtin method names (e.g., "ClientStore.take_share")
                // These are valid when used as function identifiers in FunctionCall
                if let Some(dot_pos) = name.find('.') {
                    let obj_name = &name[..dot_pos];
                    let method_name = &name[dot_pos + 1..];

                    if let Some(method_info) = self
                        .symbol_table
                        .lookup_builtin_method(obj_name, method_name)
                    {
                        // Return the method's return type (the identifier is valid as a callable)
                        return Ok((
                            AstNode::Identifier(name.clone(), location.clone()),
                            method_info.return_type.clone(),
                        ));
                    }
                }

                // Regular symbol lookup
                if let Some(info) = self.symbol_table.lookup_symbol(name.as_str()) {
                    // TODO: Mark symbol as used (for warnings)
                    // Return the type stored in the symbol table
                    Ok((
                        AstNode::Identifier(name.clone(), location.clone()),
                        info.symbol_type.clone(),
                    ))
                } else {
                    // Check if this looks like a method name that should be a function
                    // The parser transforms obj.method(args) into method(obj, args) via UFCS,
                    // so we catch method-like identifiers here
                    if let Some(suggestion) = suggest_method_to_function(&name, &self.symbol_table)
                    {
                        self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!("'{}' is not a valid function name", name),
                                location.clone(),
                            )
                            .with_hint(format!(
                                "Stoffel-Lang uses functions instead of methods. Use {} instead",
                                suggestion
                            )),
                        );
                    } else {
                        // Semantic-aware suggestion using actual symbols in scope
                        let mut error = CompilerError::semantic_error(
                            format!("Use of undeclared identifier '{}'", name),
                            location.clone(),
                        );
                        if let Some(suggestion) = suggest_from_symbols(&name, &self.symbol_table) {
                            error = error.with_hint(format!("Did you mean '{}'?", suggestion));
                        }
                        self.error_reporter.add_error(error);
                    }
                    Err(())
                }
            }

            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } => {
                let (checked_operand, operand_ty) = self.analyze_node(*operand)?;
                let operand_under = operand_ty.underlying_type().clone();

                let result_ty = match op.as_str() {
                    "-" => {
                        if operand_under.is_integer()
                            || operand_under == SymbolType::Float
                            || operand_under == SymbolType::Unknown
                        {
                            operand_ty.clone()
                        } else {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Unary '-' requires a numeric operand, found '{}'",
                                    declared_type_to_string(&operand_ty)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                    }
                    "not" => {
                        if operand_under == SymbolType::Bool || operand_under == SymbolType::Unknown
                        {
                            if operand_ty.is_secret() {
                                SymbolType::Secret(Box::new(SymbolType::Bool))
                            } else {
                                SymbolType::Bool
                            }
                        } else {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Unary 'not' requires a bool operand, found '{}'",
                                    declared_type_to_string(&operand_ty)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                    }
                    _ => {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!("Unsupported unary operator '{}'", op),
                            location.clone(),
                        ));
                        return Err(());
                    }
                };

                Ok((
                    AstNode::UnaryOperation {
                        op,
                        operand: Box::new(checked_operand),
                        location,
                    },
                    result_ty,
                ))
            }

            // --- Declarations and Statements ---
            AstNode::Assignment {
                target,
                value,
                location,
            } => {
                // Analyze target and value to get types
                let (checked_target, target_type) = self.analyze_node(*target)?;
                let (checked_value, value_type) = self.analyze_node(*value)?;
                let (checked_value, value_type) =
                    if Self::is_typed_assignment_target(&checked_target)
                        && target_type != SymbolType::Unknown
                    {
                        Self::refine_expression_type_with_expected(
                            checked_value,
                            &value_type,
                            &target_type,
                        )
                    } else {
                        (checked_value, value_type)
                    };

                if Self::contains_unrefined_share_random_call(&checked_value) {
                    self.error_reporter.add_error(
                        CompilerError::type_error(
                            "Share.random() requires an expected secret integer type".to_string(),
                            location.clone(),
                        )
                        .with_hint(
                            "Add a typed secret integer context such as 'var s: secret int64 = Share.random()'",
                        ),
                    );
                    return Err(());
                }

                // Type check assignments when the target has a known static type.
                let loc = location.clone();
                if Self::is_typed_assignment_target(&checked_target)
                    && target_type != SymbolType::Unknown
                {
                    // Enforce integer compatibility (includes literal range check)
                    if self
                        .check_integer_compat(
                            Some(&checked_value),
                            &value_type,
                            &target_type,
                            loc.clone(),
                        )
                        .is_err()
                    {
                        return Err(());
                    }
                    Ok((
                        AstNode::Assignment {
                            target: Box::new(checked_target),
                            value: Box::new(checked_value),
                            location,
                        },
                        SymbolType::Void,
                    ))
                } else {
                    // For non-identifier targets, keep previous basic behavior (no type enforcement yet)
                    Ok((
                        AstNode::Assignment {
                            target: Box::new(checked_target),
                            value: Box::new(checked_value),
                            location,
                        },
                        SymbolType::Void,
                    ))
                }
            }

            AstNode::VariableDeclaration {
                name,
                type_annotation,
                value,
                is_mutable,
                is_secret,
                location,
            } => {
                // 1. Analyze the value expression first (if it exists)
                let mut checked_value_node = None;
                let mut value_type = if let Some(val_expr) = value {
                    let (checked_val, val_type) = self.analyze_node(*val_expr)?;

                    checked_value_node = Some(Box::new(checked_val));
                    val_type
                } else {
                    SymbolType::Unknown // No value provided
                };

                // 2. Determine the declared type (from annotation or inferred from value)
                let declared_type = type_annotation
                    .as_ref()
                    .map(|tn| SymbolType::from_ast(tn))
                    .unwrap_or_else(|| value_type.clone()); // Infer if no annotation

                // Validate the type annotation if present - ensure it refers to an actual type
                if let Some(tn) = &type_annotation {
                    self.validate_type_annotation(&declared_type, tn.location())?;
                }

                let declared_type = self.resolve_type_aliases(&declared_type);

                if type_annotation.is_some() {
                    if let Some(checked_val) = checked_value_node.take() {
                        let (refined_value, refined_type) =
                            Self::refine_expression_type_with_expected(
                                *checked_val,
                                &value_type,
                                &declared_type,
                            );
                        checked_value_node = Some(Box::new(refined_value));
                        value_type = refined_type;
                    }
                }

                if checked_value_node
                    .as_deref()
                    .is_some_and(Self::contains_unrefined_share_random_call)
                {
                    self.error_reporter.add_error(
                        CompilerError::type_error(
                            "Share.random() requires an expected secret integer type".to_string(),
                            location.clone(),
                        )
                        .with_hint(
                            "Add a type annotation such as 'var s: secret int64 = Share.random()'",
                        ),
                    );
                    return Err(());
                }

                // 3. Check for type consistency (with integer width/range rules)
                if type_annotation.is_some()
                    && value_type != SymbolType::Unknown
                    && self
                        .check_integer_compat(
                            checked_value_node.as_deref(),
                            &value_type,
                            &declared_type,
                            location.clone(),
                        )
                        .is_err()
                {
                    return Err(());
                }

                // 4. Handle 'secret' keyword and type secrecy
                let final_type = if declared_type.is_secret() || is_secret {
                    declared_type.with_secret_modifier()
                } else {
                    declared_type
                };
                let calculated_is_secret = final_type.is_secret();

                // 5. Declare the symbol in the current scope
                let info = SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Variable { is_mutable },
                    symbol_type: final_type,
                    is_secret: is_secret || calculated_is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(info); // Errors are collected internally

                // 6. Reconstruct the node with the checked value
                let reconstructed_node = AstNode::VariableDeclaration {
                    name,
                    type_annotation, // Keep original annotation node
                    value: checked_value_node,
                    is_mutable,
                    is_secret,
                    location,
                };
                Ok((reconstructed_node, SymbolType::Void)) // Declaration is a statement
            }

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
            } => {
                let func_name = name.as_ref().cloned().unwrap_or_else(|| {
                    format!("<anonymous_{}:{}>", location.line, location.column)
                });

                // 1. Determine parameter and return types for symbol table entry
                let param_types: Vec<SymbolType> = parameters
                    .iter()
                    .map(|p| {
                        let param_type = p
                            .type_annotation
                            .as_ref()
                            .map(|tn| SymbolType::from_ast_with_type_params(tn, &type_params))
                            .unwrap_or(SymbolType::Unknown);
                        self.resolve_type_aliases(&param_type)
                    })
                    .collect();

                let ret_type_annotation = return_type
                    .as_ref()
                    .map(|rt| SymbolType::from_ast_with_type_params(rt, &type_params))
                    .unwrap_or(SymbolType::Void); // None or '-> nil' means Void
                let ret_type_annotation = self.resolve_type_aliases(&ret_type_annotation);

                // Handle 'secret proc' and secret return type annotation
                let final_return_type = if ret_type_annotation.is_secret() || is_secret {
                    ret_type_annotation.with_secret_modifier()
                } else {
                    ret_type_annotation
                };

                // Validate parameter types - ensure they refer to actual types, not functions
                for (param, param_type) in parameters.iter().zip(param_types.iter()) {
                    let param_loc = param
                        .type_annotation
                        .as_ref()
                        .map_or_else(|| location.clone(), |n| n.location());
                    self.validate_type_annotation(param_type, param_loc)?;
                }

                // Validate return type
                if let Some(rt_node) = &return_type {
                    self.validate_type_annotation(&final_return_type, rt_node.location())?;
                }

                // Check for pragmas like 'builtin'
                let mut is_builtin = false;
                for pragma in &pragmas {
                    if let Pragma::Simple(pragma_name, _) = pragma {
                        if pragma_name == "builtin" {
                            is_builtin = true;
                            break;
                        }
                    }
                }

                // 2. Declare the function symbol in the *current* (outer) scope
                //    (Unless it's a builtin, builtins are pre-declared)
                if !is_builtin {
                    let info = SymbolInfo {
                        name: func_name.clone(),
                        kind: SymbolKind::Function {
                            parameters: param_types.clone(),
                            return_type: final_return_type.clone(),
                        },
                        symbol_type: final_return_type.clone(), // Type of symbol is its return type
                        is_secret: is_secret || final_return_type.is_secret(),
                        defined_at: location.clone(),
                    };
                    self.symbol_table.declare_symbol(info);
                }

                // 3. Analyze function body in a new scope (if not builtin)
                let checked_body = if !is_builtin {
                    self.symbol_table.enter_scope();
                    let previous_return_type = self
                        .current_function_return_type
                        .replace(final_return_type.clone());

                    // Declare parameters within the function's scope
                    for (param, param_type) in parameters.iter().zip(param_types.iter()) {
                        let param_info = SymbolInfo {
                            name: param.name.clone(),
                            kind: SymbolKind::Variable { is_mutable: false }, // Params are immutable
                            symbol_type: param_type.clone(),
                            is_secret: param_type.is_secret(),
                            defined_at: param
                                .type_annotation
                                .as_ref()
                                .map_or_else(|| location.clone(), |n| n.location()),
                        };
                        self.symbol_table.declare_symbol(param_info);
                    }

                    // Recursively analyze the body
                    let (checked_body_node, _body_type) = self.analyze_node(*body)?;
                    // TODO: Check if all code paths return the correct type (more complex analysis)

                    self.current_function_return_type = previous_return_type;
                    self.symbol_table.exit_scope();
                    Box::new(checked_body_node)
                } else {
                    body // Keep original body for builtins (it's not analyzed)
                };

                // 4. Reconstruct the node
                let reconstructed_node = AstNode::FunctionDefinition {
                    name,
                    type_params,
                    parameters,
                    return_type,
                    body: checked_body,
                    is_secret,
                    pragmas,
                    location,
                    node_id,
                };
                Ok((reconstructed_node, SymbolType::Void)) // Definition is a statement
            }

            AstNode::ObjectDefinition {
                name,
                base_type,
                fields,
                is_secret,
                location,
            } => {
                // 1. Register the object type in the symbol table
                let object_type = SymbolType::Object(name.clone());

                // Build field type map for the object
                let mut field_types: std::collections::HashMap<String, SymbolType> =
                    std::collections::HashMap::new();

                if let Some(base_node) = &base_type {
                    let base_type_symbol = SymbolType::from_ast(base_node);
                    self.validate_type_annotation(&base_type_symbol, base_node.location())?;
                    let base_type_symbol = self.resolve_type_aliases(&base_type_symbol);

                    let base_name = match base_type_symbol.underlying_type() {
                        SymbolType::Object(name) | SymbolType::TypeName(name) => Some(name),
                        _ => None,
                    };

                    if let Some(base_name) = base_name {
                        if let Some(base_info) = self.symbol_table.lookup_user_object(base_name) {
                            field_types.extend(base_info.fields.clone());
                        }
                    }
                }

                for field in &fields {
                    let mut field_type = SymbolType::from_ast(&field.type_annotation);
                    // Apply the `secret` modifier from field definition
                    if field.is_secret && !field_type.is_secret() {
                        field_type = field_type.with_secret_modifier();
                    }
                    // Validate field type refers to a valid type
                    self.validate_type_annotation(&field_type, field.type_annotation.location())?;
                    field_type = self.resolve_type_aliases(&field_type);
                    field_types.insert(field.name.clone(), field_type);
                }

                self.symbol_table.register_user_object(UserObjectInfo {
                    name: name.clone(),
                    fields: field_types,
                });

                // Declare the object type as a type symbol
                let info = SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Type, // User-defined type
                    symbol_type: object_type.clone(),
                    is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(info);

                // Return the node as-is (no transformation needed)
                Ok((
                    AstNode::ObjectDefinition {
                        name,
                        base_type,
                        fields,
                        is_secret,
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            AstNode::TypeAlias {
                name,
                target_type,
                is_secret,
                location,
            } => {
                let mut alias_type = SymbolType::from_ast(&target_type);
                if is_secret && !alias_type.is_secret() {
                    alias_type = alias_type.with_secret_modifier();
                }

                self.validate_type_annotation(&alias_type, target_type.location())?;
                alias_type = self.resolve_type_aliases(&alias_type);

                let info = SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Type,
                    symbol_type: alias_type,
                    is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(info);

                Ok((
                    AstNode::TypeAlias {
                        name,
                        target_type,
                        is_secret,
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            AstNode::BuiltinTypeDefinition {
                name,
                target_type,
                is_opaque_object,
                location,
            } => Ok((
                AstNode::BuiltinTypeDefinition {
                    name,
                    target_type,
                    is_opaque_object,
                    location,
                },
                SymbolType::Void,
            )),

            AstNode::BuiltinObjectDefinition {
                name,
                methods,
                location,
            } => Ok((
                AstNode::BuiltinObjectDefinition {
                    name,
                    methods,
                    location,
                },
                SymbolType::Void,
            )),

            // --- Expressions and Control Flow ---
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                // Analyze condition and enforce that branching on secret is not supported
                let (checked_condition, cond_type) = self.analyze_node(*condition)?;
                if cond_type.is_secret() {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "Branching with secret values isn't supported yet (secret condition in 'if')",
                        checked_condition.location(),
                    ));
                    return Err(());
                }
                // Optional: ensure condition is bool (underlying type)
                if cond_type.underlying_type() != &SymbolType::Bool {
                    self.error_reporter.add_error(CompilerError::type_error(
                        "If-condition must be of type 'bool'",
                        checked_condition.location(),
                    ));
                    return Err(());
                }

                // Analyze branches
                let (checked_then, _then_ty) = self.analyze_node(*then_branch)?;
                let checked_else = if let Some(eb) = else_branch {
                    let (c_eb, _else_ty) = self.analyze_node(*eb)?;
                    Some(Box::new(c_eb))
                } else {
                    None
                };

                Ok((
                    AstNode::IfExpression {
                        condition: Box::new(checked_condition),
                        then_branch: Box::new(checked_then),
                        else_branch: checked_else,
                    },
                    SymbolType::Unknown,
                ))
            }
            AstNode::WhileLoop {
                condition,
                body,
                location,
            } => {
                // Analyze condition and error if it's secret
                let (checked_condition, cond_type) = self.analyze_node(*condition)?;
                if cond_type.is_secret() {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "Branching with secret values isn't supported yet (secret condition in 'while')",
                        checked_condition.location(),
                    ));
                    return Err(());
                }
                if cond_type.underlying_type() != &SymbolType::Bool {
                    self.error_reporter.add_error(CompilerError::type_error(
                        "While-condition must be of type 'bool'",
                        checked_condition.location(),
                    ));
                    return Err(());
                }
                let (checked_body, _body_ty) = self.analyze_node(*body)?;
                Ok((
                    AstNode::WhileLoop {
                        condition: Box::new(checked_condition),
                        body: Box::new(checked_body),
                        location,
                    },
                    SymbolType::Void,
                ))
            }
            AstNode::Block(statements) => {
                // Blocks don't create scopes by default in this design.
                // Scopes are handled by functions, loops (if needed), etc.
                let mut checked_statements = Vec::new();
                let mut last_type = SymbolType::Void; // Default for empty block
                                                      // Important: continue analyzing all statements even if some have errors
                for stmt in statements {
                    match self.analyze_node(stmt) {
                        Ok((checked_stmt, stmt_type)) => {
                            last_type = stmt_type; // Type of block is type of last successful statement
                            checked_statements.push(checked_stmt);
                        }
                        Err(()) => {
                            // Preserve the original statement to keep AST shape and continue
                            // We purposely do not update last_type here.
                            // Note: We cannot reconstruct the original `stmt` here because it's moved by match,
                            // so we push a placeholder no-op statement to maintain block length.
                            // If a proper NoOp node exists, prefer that; otherwise use an empty literal.
                            checked_statements.push(AstNode::Literal {
                                value: Value::Nil,
                                location: SourceLocation::default(),
                            });
                        }
                    }
                }
                Ok((AstNode::Block(checked_statements), last_type))
            }

            AstNode::ForLoop {
                variables,
                iterable,
                body,
                location,
            } => {
                // Support single variable iteration over ranges or collections
                if variables.len() != 1 {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "For-loop with multiple variables not supported yet",
                        location.clone(),
                    ));
                    return Err(());
                }

                // Analyze iterable to determine its type
                let (checked_iterable, iter_type) = self.analyze_node(*iterable)?;

                // Determine the loop variable type based on the iterable
                let (loop_var_type, is_secret) = match &checked_iterable {
                    // Range iteration: for i in a..b
                    AstNode::BinaryOperation { op, .. } if op == ".." => (SymbolType::Int64, false),
                    // Collection iteration: infer element type from iterable type
                    _ => {
                        match iter_type.underlying_type() {
                            SymbolType::List(elem_type) => {
                                // Derive secrecy from the element (loop variable) type,
                                // not from the iterable's top-level type.
                                let elem_ty = elem_type.as_ref().clone();
                                let is_secret = elem_ty.is_secret();
                                (elem_ty, is_secret)
                            }
                            SymbolType::String => {
                                // Iterating over a string yields characters (as strings)
                                (SymbolType::String, false)
                            }
                            _ => {
                                self.error_reporter.add_error(CompilerError::semantic_error(
                                    format!(
                                        "Cannot iterate over type '{}'; expected a range (a..b) or a List",
                                        declared_type_to_string(&iter_type)
                                    ),
                                    checked_iterable.location(),
                                ));
                                return Err(());
                            }
                        }
                    }
                };

                // Enter loop scope and declare the loop variable with inferred type
                self.symbol_table.enter_scope();
                let var_name = variables[0].clone();
                let var_info = SymbolInfo {
                    name: var_name.clone(),
                    kind: SymbolKind::Variable { is_mutable: false },
                    symbol_type: loop_var_type,
                    is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(var_info);

                // Analyze body within scope
                let (checked_body, _body_type) = self.analyze_node(*body)?;

                // Exit loop scope
                self.symbol_table.exit_scope();

                Ok((
                    AstNode::ForLoop {
                        variables: vec![var_name],
                        iterable: Box::new(checked_iterable),
                        body: Box::new(checked_body),
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            AstNode::Return {
                value: ref maybe_expr,
                location: ref ret_loc,
            } => {
                let (mut checked_expr_node, mut return_value_type) = match maybe_expr {
                    Some(expr) => {
                        let (checked_expr, expr_type) = self.analyze_node(*expr.clone())?;
                        (Some(Box::new(checked_expr)), expr_type)
                    }
                    None => (None, SymbolType::Void),
                };

                let expected_ret = self.current_function_return_type.clone();
                match expected_ret {
                    Some(expected) => {
                        if let Some(checked_expr) = checked_expr_node.take() {
                            let (refined_expr, refined_type) =
                                Self::refine_expression_type_with_expected(
                                    *checked_expr,
                                    &return_value_type,
                                    &expected,
                                );
                            checked_expr_node = Some(Box::new(refined_expr));
                            return_value_type = refined_type;
                        }
                        // Integer-aware compatibility (includes literal range check)
                        let loc = node.location();
                        if checked_expr_node
                            .as_deref()
                            .is_some_and(Self::contains_unrefined_share_random_call)
                        {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    "Share.random() requires an expected secret integer type"
                                        .to_string(),
                                    loc.clone(),
                                )
                                .with_hint(
                                    "Add a typed secret integer context such as 'var s: secret int64 = Share.random()'",
                                ),
                            );
                            return Err(());
                        }
                        if self
                            .check_integer_compat(
                                checked_expr_node.as_deref(),
                                &return_value_type,
                                &expected,
                                loc,
                            )
                            .is_err()
                        {
                            return Err(());
                        }
                        // TODO: Check secrecy compatibility (cannot return clear from secret context, etc.)
                    }
                    None => {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            "'return' statement outside of function",
                            node.location(),
                        ));
                        return Err(());
                    }
                }
                Ok((
                    AstNode::Return {
                        value: checked_expr_node,
                        location: ret_loc.clone(),
                    },
                    SymbolType::Void,
                )) // Return is a statement
            }

            AstNode::FunctionCall {
                function,
                arguments,
                location,
                resolved_return_type: _,
            } => {
                // Ignore existing resolved_return_type
                // 1. Preserve simple call targets for call resolution. Unqualified
                // receiver-bound methods like `open(s)` cannot be validated until
                // the arguments have been analyzed.
                let checked_function_node = match *function {
                    AstNode::Identifier(name, location) => AstNode::Identifier(name, location),
                    other => {
                        let (checked, _function_expr_type) = self.analyze_node(other)?;
                        checked
                    }
                };

                if let AstNode::Identifier(name, loc) = &checked_function_node {
                    let object_info = self.symbol_table.lookup_symbol(name).and_then(|info| {
                        if matches!(&info.kind, SymbolKind::Type)
                            && matches!(&info.symbol_type, SymbolType::Object(_))
                        {
                            self.symbol_table.lookup_user_object(name).cloned()
                        } else {
                            None
                        }
                    });

                    if let Some(object_info) = object_info {
                        let mut checked_arguments = Vec::with_capacity(arguments.len());
                        let mut seen_fields = std::collections::HashSet::new();

                        for arg_node in arguments {
                            match arg_node {
                                AstNode::NamedArgument {
                                    name: field_name,
                                    value,
                                    location: arg_loc,
                                } => {
                                    if !seen_fields.insert(field_name.clone()) {
                                        self.error_reporter.add_error(
                                            CompilerError::semantic_error(
                                                format!(
                                                    "Duplicate field '{}' in constructor for '{}'",
                                                    field_name, object_info.name
                                                ),
                                                arg_loc,
                                            ),
                                        );
                                        return Err(());
                                    }

                                    let field_type =
                                        match object_info.fields.get(&field_name).cloned() {
                                            Some(field_type) => field_type,
                                            None => {
                                                self.error_reporter.add_error(
                                                    CompilerError::semantic_error(
                                                        format!(
                                                            "Unknown field '{}' for object '{}'",
                                                            field_name, object_info.name
                                                        ),
                                                        arg_loc,
                                                    ),
                                                );
                                                return Err(());
                                            }
                                        };

                                    let (checked_value, value_type) = self.analyze_node(*value)?;
                                    let (checked_value, value_type) =
                                        Self::refine_expression_type_with_expected(
                                            checked_value,
                                            &value_type,
                                            &field_type,
                                        );
                                    if self
                                        .check_integer_compat(
                                            Some(&checked_value),
                                            &value_type,
                                            &field_type,
                                            checked_value.location(),
                                        )
                                        .is_err()
                                    {
                                        return Err(());
                                    }

                                    checked_arguments.push(AstNode::NamedArgument {
                                        name: field_name,
                                        value: Box::new(checked_value),
                                        location: arg_loc,
                                    });
                                }
                                other => {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!(
                                                "Constructor for '{}' expects named field arguments",
                                                object_info.name
                                            ),
                                            other.location(),
                                        )
                                        .with_hint(format!(
                                            "Use {}(field: value) syntax",
                                            object_info.name
                                        )),
                                    );
                                    return Err(());
                                }
                            }
                        }

                        let object_type = SymbolType::Object(object_info.name);
                        return Ok((
                            AstNode::FunctionCall {
                                function: Box::new(AstNode::Identifier(name.clone(), loc.clone())),
                                arguments: checked_arguments,
                                location,
                                resolved_return_type: Some(object_type.clone()),
                            },
                            object_type,
                        ));
                    }
                }

                // 2. Analyze arguments
                let mut checked_arguments = Vec::with_capacity(arguments.len());
                let mut argument_types = Vec::with_capacity(arguments.len());
                for arg_node in arguments {
                    if let AstNode::NamedArgument { location, .. } = &arg_node {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            "Named arguments are only supported for object constructors",
                            location.clone(),
                        ));
                        return Err(());
                    }
                    let (checked_arg, arg_type) = self.analyze_node(arg_node)?;
                    checked_arguments.push(checked_arg);
                    argument_types.push(arg_type);
                }

                // 3. Determine the actual function symbol and its type
                let (function_name, expected_param_types, return_type) =
                    match &checked_function_node {
                        AstNode::Identifier(name, loc) => {
                            // Check if this is a qualified builtin object method call (e.g., "ClientStore.take_share")
                            if let Some(dot_pos) = name.find('.') {
                                let obj_name = &name[..dot_pos];
                                let method_name = &name[dot_pos + 1..];

                                if let Some(method_info) = self
                                    .symbol_table
                                    .lookup_builtin_method(obj_name, method_name)
                                {
                                    let call_name = if crate::builtin_registry::builtin_registry()
                                        .is_receiver_bound_method(obj_name, method_name)
                                    {
                                        method_name.to_string()
                                    } else {
                                        name.clone()
                                    };
                                    (
                                        call_name,
                                        method_info.parameters.clone(),
                                        method_info.return_type.clone(),
                                    )
                                } else {
                                    self.error_reporter.add_error(CompilerError::semantic_error(
                                        format!(
                                            "Unknown method '{}' on builtin object '{}'",
                                            method_name, obj_name
                                        ),
                                        loc.clone(),
                                    ));
                                    return Err(());
                                }
                            } else if let Some(info) = self.symbol_table.lookup_symbol(name) {
                                // Regular function lookup
                                match &info.kind {
                                    SymbolKind::Function {
                                        parameters,
                                        return_type,
                                    }
                                    | SymbolKind::BuiltinFunction {
                                        parameters,
                                        return_type,
                                    } => (name.clone(), parameters.clone(), return_type.clone()),
                                    _ => {
                                        self.error_reporter.add_error(CompilerError::type_error(
                                            format!("'{}' is not a function", name),
                                            loc.clone(),
                                        ));
                                        return Err(());
                                    }
                                }
                            } else if let Some(receiver_type) = argument_types.first() {
                                if let Some(method_info) = self
                                    .symbol_table
                                    .lookup_builtin_method_for_receiver(receiver_type, name)
                                {
                                    (
                                        name.clone(),
                                        method_info.parameters.clone(),
                                        method_info.return_type.clone(),
                                    )
                                } else if let Some(suggestion) =
                                    suggest_method_to_function(name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", name),
                                            loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                    return Err(());
                                } else {
                                    // Semantic-aware suggestion using actual functions in scope
                                    let mut error = CompilerError::semantic_error(
                                        format!("Use of undeclared function '{}'", name),
                                        loc.clone(),
                                    );
                                    if let Some(suggestion) =
                                        suggest_function_from_symbols(name, &self.symbol_table)
                                    {
                                        error = error
                                            .with_hint(format!("Did you mean '{}'?", suggestion));
                                    }
                                    self.error_reporter.add_error(error);
                                    return Err(());
                                }
                            } else {
                                // Semantic-aware suggestion using actual functions in scope
                                if let Some(suggestion) =
                                    suggest_method_to_function(name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", name),
                                            loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                    return Err(());
                                }
                                let mut error = CompilerError::semantic_error(
                                    format!("Use of undeclared function '{}'", name),
                                    loc.clone(),
                                );
                                if let Some(suggestion) =
                                    suggest_function_from_symbols(name, &self.symbol_table)
                                {
                                    error =
                                        error.with_hint(format!("Did you mean '{}'?", suggestion));
                                }
                                self.error_reporter.add_error(error);
                                return Err(());
                            }
                        }
                        // Handle field access: could be a qualified function call (module.func)
                        // or an unsupported method-style call (obj.method)
                        AstNode::FieldAccess {
                            object,
                            field_name,
                            location: field_loc,
                        } => {
                            // Try to resolve as a qualified function call (e.g., module.func)
                            if let AstNode::Identifier(obj_name, _) = object.as_ref() {
                                let qualified_name = format!("{}.{}", obj_name, field_name);
                                if let Some(info) = self.symbol_table.lookup_symbol(&qualified_name)
                                {
                                    match &info.kind {
                                        SymbolKind::Function {
                                            parameters,
                                            return_type,
                                        }
                                        | SymbolKind::BuiltinFunction {
                                            parameters,
                                            return_type,
                                        } => (
                                            qualified_name,
                                            parameters.clone(),
                                            return_type.clone(),
                                        ),
                                        _ => {
                                            self.error_reporter.add_error(
                                                CompilerError::type_error(
                                                    format!(
                                                        "'{}' is not a function",
                                                        qualified_name
                                                    ),
                                                    field_loc.clone(),
                                                ),
                                            );
                                            return Err(());
                                        }
                                    }
                                } else if let Some(suggestion) =
                                    suggest_method_to_function(field_name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", field_name),
                                            field_loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                    return Err(());
                                } else {
                                    self.error_reporter.add_error(CompilerError::type_error(
                                    format!("Method calls like '.{}()' are not supported", field_name),
                                    field_loc.clone(),
                                ).with_hint("Stoffel-Lang uses functions instead of methods. Try using a function call."));
                                    return Err(());
                                }
                            } else {
                                // Object is not a simple identifier — unsupported method call
                                if let Some(suggestion) =
                                    suggest_method_to_function(field_name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", field_name),
                                            field_loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                } else {
                                    self.error_reporter.add_error(CompilerError::type_error(
                                    format!("Method calls like '.{}()' are not supported", field_name),
                                    field_loc.clone(),
                                ).with_hint("Stoffel-Lang uses functions instead of methods. Try using a function call."));
                                }
                                return Err(());
                            }
                        }
                        // Other non-callable expressions
                        _ => {
                            self.error_reporter.add_error(CompilerError::type_error(
                                "Expression is not callable",
                                checked_function_node.location(),
                            ));
                            return Err(());
                        }
                    };

                // 4. Validate argument count
                if !Self::is_variadic_builtin(&function_name)
                    && expected_param_types.len() != argument_types.len()
                {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        format!(
                            "Function '{}' expects {} arguments, but {} were provided",
                            function_name,
                            expected_param_types.len(),
                            argument_types.len()
                        ),
                        location.clone(),
                    ));
                    return Err(());
                }

                // 5. Validate arguments, binding any function-level type parameters per call
                let mut generic_bindings = HashMap::new();
                let arg_check_len = if Self::is_variadic_builtin(&function_name) {
                    argument_types.len()
                } else {
                    expected_param_types.len()
                };
                for idx in 0..arg_check_len {
                    let expected_fallback;
                    let expected_ty = if Self::is_variadic_builtin(&function_name) {
                        expected_fallback = SymbolType::Unknown;
                        &expected_fallback
                    } else {
                        &expected_param_types[idx]
                    };
                    let mut arg_loc = checked_arguments[idx].location();
                    if arg_loc.line == 0 {
                        arg_loc = location.clone();
                    }

                    let expected_after_bindings =
                        Self::substitute_type_vars(expected_ty, &generic_bindings);
                    Self::refine_argument_with_expected(
                        &mut checked_arguments[idx],
                        &mut argument_types[idx],
                        &expected_after_bindings,
                    );

                    if Self::contains_unrefined_share_random_call(&checked_arguments[idx]) {
                        self.error_reporter.add_error(
                            CompilerError::type_error(
                                "Share.random() requires an expected secret integer type"
                                    .to_string(),
                                arg_loc,
                            )
                            .with_hint(
                                "Assign it to a typed secret integer before passing it, such as 'var s: secret int64 = Share.random()'",
                            ),
                        );
                        return Err(());
                    }

                    if !Self::is_variadic_builtin(&function_name) {
                        if self
                            .check_generic_compat(
                                Some(&checked_arguments[idx]),
                                &argument_types[idx],
                                expected_ty,
                                &mut generic_bindings,
                                arg_loc,
                            )
                            .is_err()
                        {
                            return Err(());
                        }
                    }
                }

                // 6. Reconstruct the node with checked parts and resolved return type
                let resolved_function_node = match &checked_function_node {
                    AstNode::Identifier(_, loc) => {
                        AstNode::Identifier(function_name.clone(), loc.clone())
                    }
                    AstNode::FieldAccess { location, .. } => {
                        AstNode::Identifier(function_name.clone(), location.clone())
                    }
                    _ => checked_function_node,
                };
                let resolved_return_type =
                    Self::substitute_type_vars(&return_type, &generic_bindings);
                let reconstructed_node = AstNode::FunctionCall {
                    function: Box::new(resolved_function_node),
                    arguments: checked_arguments,
                    location,
                    resolved_return_type: Some(resolved_return_type.clone()), // Store the resolved type
                };

                Ok((reconstructed_node, resolved_return_type)) // Type of the call is the function's return type
            }

            AstNode::CommandCall {
                command,
                arguments,
                location,
                resolved_return_type: _,
            } => {
                // 1. Analyze the command expression (usually an identifier)
                let (checked_command_node, _command_expr_type) = self.analyze_node(*command)?;

                // 2. Analyze arguments
                let mut checked_arguments = Vec::with_capacity(arguments.len());
                let mut argument_types = Vec::with_capacity(arguments.len());
                for arg_node in arguments {
                    let (checked_arg, arg_type) = self.analyze_node(arg_node)?;
                    checked_arguments.push(checked_arg);
                    argument_types.push(arg_type);
                }

                // 3. Determine the actual function symbol and its type from the command
                let (function_name, function_info) = match &checked_command_node {
                    AstNode::Identifier(name, loc) => {
                        if let Some(info) = self.symbol_table.lookup_symbol(name) {
                            (name.clone(), info.clone())
                        } else {
                            let mut error = CompilerError::semantic_error(
                                format!("Use of undeclared function '{}' in command call", name),
                                loc.clone(),
                            );
                            if let Some(suggestion) =
                                suggest_function_from_symbols(name, &self.symbol_table)
                            {
                                error = error.with_hint(format!("Did you mean '{}'?", suggestion));
                            }
                            self.error_reporter.add_error(error);
                            return Err(());
                        }
                    }
                    _ => {
                        self.error_reporter.add_error(CompilerError::type_error(
                            "Command expression is not callable",
                            checked_command_node.location(),
                        ));
                        return Err(());
                    }
                };

                // 4. Check if the symbol is a function and validate arguments (similar to FunctionCall)
                let (expected_param_types, return_type) = match &function_info.kind {
                    SymbolKind::Function {
                        parameters,
                        return_type,
                    }
                    | SymbolKind::BuiltinFunction {
                        parameters,
                        return_type,
                    } => {
                        // TODO: Implement proper argument count/type checking for command calls (UFCS context)
                        (parameters.clone(), return_type.clone())
                    }
                    _ => {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "'{}' is not a function (used in command call)",
                                function_name
                            ),
                            checked_command_node.location(),
                        ));
                        return Err(());
                    }
                };

                if !Self::is_variadic_builtin(&function_name)
                    && expected_param_types.len() != argument_types.len()
                {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        format!(
                            "Function '{}' expects {} arguments, but {} were provided",
                            function_name,
                            expected_param_types.len(),
                            argument_types.len()
                        ),
                        location.clone(),
                    ));
                    return Err(());
                }

                // 5. Validate arguments, binding any function-level type parameters per call
                let mut generic_bindings = HashMap::new();
                let arg_check_len = if Self::is_variadic_builtin(&function_name) {
                    argument_types.len()
                } else {
                    expected_param_types.len()
                };
                for idx in 0..arg_check_len {
                    let expected_fallback;
                    let expected_ty = if Self::is_variadic_builtin(&function_name) {
                        expected_fallback = SymbolType::Unknown;
                        &expected_fallback
                    } else {
                        &expected_param_types[idx]
                    };
                    let arg_loc = checked_arguments[idx].location();
                    let expected_after_bindings =
                        Self::substitute_type_vars(expected_ty, &generic_bindings);
                    Self::refine_argument_with_expected(
                        &mut checked_arguments[idx],
                        &mut argument_types[idx],
                        &expected_after_bindings,
                    );

                    if Self::contains_unrefined_share_random_call(&checked_arguments[idx]) {
                        self.error_reporter.add_error(
                            CompilerError::type_error(
                                "Share.random() requires an expected secret integer type"
                                    .to_string(),
                                arg_loc.clone(),
                            )
                            .with_hint(
                                "Assign it to a typed secret integer before passing it, such as 'var s: secret int64 = Share.random()'",
                            ),
                        );
                        return Err(());
                    }

                    if !Self::is_variadic_builtin(&function_name) {
                        if self
                            .check_generic_compat(
                                Some(&checked_arguments[idx]),
                                &argument_types[idx],
                                expected_ty,
                                &mut generic_bindings,
                                arg_loc,
                            )
                            .is_err()
                        {
                            return Err(());
                        }
                    }
                }

                // 6. Reconstruct the node with checked parts and resolved return type
                let resolved_return_type =
                    Self::substitute_type_vars(&return_type, &generic_bindings);
                let reconstructed_node = AstNode::CommandCall {
                    command: Box::new(checked_command_node),
                    arguments: checked_arguments,
                    location,
                    resolved_return_type: Some(resolved_return_type.clone()), // Store the resolved type
                };
                Ok((reconstructed_node, resolved_return_type)) // Type of the call is the function's return type
            }

            // --- Binary operations (comparisons etc.) ---
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } => {
                // Analyze both sides first
                let (checked_left, left_ty) = self.analyze_node(*left)?;
                let (checked_right, right_ty) = self.analyze_node(*right)?;

                // Helper: are these comparison operators?
                let is_cmp = matches!(op.as_str(), "==" | "!=" | "<" | "<=" | ">" | ">=");

                if is_cmp {
                    // Validate operand types. Equality also supports booleans.
                    let l_under = left_ty.underlying_type().clone();
                    let r_under = right_ty.underlying_type().clone();
                    let is_left_numeric = l_under.is_integer() || l_under == SymbolType::Float;
                    let is_right_numeric = r_under.is_integer() || r_under == SymbolType::Float;
                    let is_same_clear_comparable = l_under == r_under
                        && matches!(l_under, SymbolType::Bool | SymbolType::String);

                    if (!is_left_numeric || !is_right_numeric)
                        && !is_same_clear_comparable
                        && !matches!(l_under, SymbolType::Unknown)
                        && !matches!(r_under, SymbolType::Unknown)
                    {
                        // If both are known and not numeric, error out
                        let err_loc = match (&checked_left, &checked_right) {
                            (l, _) if !is_left_numeric => l.location(),
                            (_, r) => r.location(),
                        };
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!("Operands to '{}' must be numeric (ints or float), or matching bool/string values, found '{}' and '{}'",
                                    op,
                                    declared_type_to_string(&left_ty),
                                    declared_type_to_string(&right_ty)),
                            err_loc,
                        ).with_hint("Cast or adjust operand types to be comparable"));
                        return Err(());
                    }

                    // Result type of comparison:
                    // - public bool when both operands are public
                    // - secret bool when any operand is secret
                    let result_ty = if left_ty.is_secret() || right_ty.is_secret() {
                        SymbolType::Secret(Box::new(SymbolType::Bool))
                    } else {
                        SymbolType::Bool
                    };

                    return Ok((
                        AstNode::BinaryOperation {
                            op,
                            left: Box::new(checked_left),
                            right: Box::new(checked_right),
                            location,
                        },
                        result_ty,
                    ));
                }

                if matches!(op.as_str(), "and" | "or" | "xor") {
                    let l_under = left_ty.underlying_type().clone();
                    let r_under = right_ty.underlying_type().clone();
                    let both_bool = l_under == SymbolType::Bool && r_under == SymbolType::Bool;
                    let both_unknown_or_bool =
                        matches!(l_under, SymbolType::Unknown | SymbolType::Bool)
                            && matches!(r_under, SymbolType::Unknown | SymbolType::Bool);

                    if !both_unknown_or_bool {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "Operands to '{}' must both be bool, found '{}' and '{}'",
                                op,
                                declared_type_to_string(&left_ty),
                                declared_type_to_string(&right_ty)
                            ),
                            location.clone(),
                        ));
                        return Err(());
                    }

                    let result_ty = if left_ty.is_secret() || right_ty.is_secret() {
                        SymbolType::Secret(Box::new(SymbolType::Bool))
                    } else if both_bool || both_unknown_or_bool {
                        SymbolType::Bool
                    } else {
                        SymbolType::Unknown
                    };

                    return Ok((
                        AstNode::BinaryOperation {
                            op,
                            left: Box::new(checked_left),
                            right: Box::new(checked_right),
                            location,
                        },
                        result_ty,
                    ));
                }

                // For other binary ops we don't handle here; pass through as Unknown type.
                Ok((
                    AstNode::BinaryOperation {
                        op,
                        left: Box::new(checked_left),
                        right: Box::new(checked_right),
                        location,
                    },
                    SymbolType::Unknown,
                ))
            }

            // --- Collection Literals and Access ---
            AstNode::ListLiteral { elements, location } => {
                let mut checked_elements = Vec::with_capacity(elements.len());
                let mut element_type = SymbolType::Unknown;

                for elem in elements {
                    let (checked_elem, elem_ty) = self.analyze_node(elem)?;
                    // Infer element type from first element, check consistency
                    if matches!(element_type, SymbolType::Unknown) {
                        element_type = elem_ty.clone();
                    }
                    // TODO: Add type consistency checking between elements
                    checked_elements.push(checked_elem);
                }

                Ok((
                    AstNode::ListLiteral {
                        elements: checked_elements,
                        location,
                    },
                    SymbolType::List(Box::new(element_type)),
                ))
            }

            AstNode::DictLiteral { pairs, location } => {
                let mut checked_pairs = Vec::with_capacity(pairs.len());
                let mut key_type = SymbolType::Unknown;
                let mut value_type = SymbolType::Unknown;

                for (key, value) in pairs {
                    let (checked_key, key_ty) = self.analyze_node(key)?;
                    let (checked_value, val_ty) = self.analyze_node(value)?;
                    // Infer types from first pair
                    if matches!(key_type, SymbolType::Unknown) {
                        key_type = key_ty.clone();
                    }
                    if matches!(value_type, SymbolType::Unknown) {
                        value_type = val_ty.clone();
                    }
                    // TODO: Add type consistency checking between pairs
                    checked_pairs.push((checked_key, checked_value));
                }

                Ok((
                    AstNode::DictLiteral {
                        pairs: checked_pairs,
                        location,
                    },
                    SymbolType::Dict(Box::new(key_type), Box::new(value_type)),
                ))
            }

            AstNode::IndexAccess {
                base,
                index,
                location,
            } => {
                let (checked_base, base_type) = self.analyze_node(*base)?;
                let (checked_index, _index_type) = self.analyze_node(*index)?;

                // Determine element type based on base type
                let element_type = match base_type.underlying_type() {
                    SymbolType::List(elem) => elem.as_ref().clone(),
                    SymbolType::String => SymbolType::String, // String indexing returns string (single char)
                    SymbolType::Dict(_, val) => val.as_ref().clone(),
                    _ => SymbolType::Unknown, // Allow dynamic access for unknown types
                };

                // TODO: Verify index type is appropriate (integer for lists, key type for dicts)

                Ok((
                    AstNode::IndexAccess {
                        base: Box::new(checked_base),
                        index: Box::new(checked_index),
                        location,
                    },
                    element_type,
                ))
            }

            AstNode::FieldAccess {
                object,
                field_name,
                location,
            } => {
                let (checked_object, object_type) = self.analyze_node(*object)?;

                // Check if this looks like a method call attempt on a list or primitive type
                // and provide helpful suggestions
                let is_builtin_type = matches!(
                    object_type.underlying_type(),
                    SymbolType::List(_)
                        | SymbolType::Int64
                        | SymbolType::Int32
                        | SymbolType::Int16
                        | SymbolType::Int8
                        | SymbolType::Float
                        | SymbolType::String
                        | SymbolType::Bool
                );

                if is_builtin_type {
                    // Check if this is a common method name that should be a function
                    if let Some(suggestion) =
                        suggest_method_to_function(&field_name, &self.symbol_table)
                    {
                        self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!("Method '.{}' is not supported on this type", field_name),
                                location.clone(),
                            )
                            .with_hint(format!("Use {} instead", suggestion)),
                        );
                        return Err(());
                    }
                }

                let field_type = match object_type.underlying_type() {
                    SymbolType::Object(object_name) => {
                        if let Some(object_info) = self.symbol_table.lookup_user_object(object_name)
                        {
                            match object_info.fields.get(&field_name) {
                                Some(field_type) => field_type.clone(),
                                None => {
                                    self.error_reporter.add_error(CompilerError::semantic_error(
                                        format!(
                                            "Unknown field '{}' for object '{}'",
                                            field_name, object_name
                                        ),
                                        location.clone(),
                                    ));
                                    return Err(());
                                }
                            }
                        } else {
                            SymbolType::Unknown
                        }
                    }
                    _ => SymbolType::Unknown,
                };

                Ok((
                    AstNode::FieldAccess {
                        object: Box::new(checked_object),
                        field_name,
                        location,
                    },
                    field_type,
                ))
            }

            AstNode::DiscardStatement {
                expression,
                location,
            } => {
                let (checked_expr, _expr_type) = self.analyze_node(*expression)?;
                Ok((
                    AstNode::DiscardStatement {
                        expression: Box::new(checked_expr),
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            // Fallback for unhandled nodes
            _ => {
                // For now, just return the node as is with Unknown type.
                Ok((node, SymbolType::Unknown))
            }
        }
    }

    // --- Helper Functions ---

    /// Validates that a SymbolType doesn't contain invalid type references.
    /// Returns an error if a TypeName refers to a function or undeclared identifier.
    fn validate_type_annotation(
        &mut self,
        sym_type: &SymbolType,
        location: SourceLocation,
    ) -> Result<(), ()> {
        match sym_type {
            SymbolType::TypeName(name) => {
                // Check if the name refers to something in the symbol table
                if let Some(info) = self.symbol_table.lookup_symbol(name) {
                    match &info.kind {
                        SymbolKind::Type => Ok(()), // Valid type reference
                        SymbolKind::Function { .. } | SymbolKind::BuiltinFunction { .. } => {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    format!("'{}' is a function, not a type", name),
                                    location,
                                ).with_hint(format!("'{}' is defined as a function. To use a custom type, define it with 'type' or 'object' (type aliases not yet supported)", name))
                            );
                            Err(())
                        }
                        SymbolKind::Variable { .. } => {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    format!("'{}' is a variable, not a type", name),
                                    location,
                                )
                                .with_hint("Variable names cannot be used as types"),
                            );
                            Err(())
                        }
                        SymbolKind::BuiltinObject { .. } => {
                            // Builtin objects are valid types (e.g., Share, ClientStore)
                            Ok(())
                        }
                        SymbolKind::Module => {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!("'{}' is a module, not a type", name),
                                location,
                            ));
                            Err(())
                        }
                    }
                } else {
                    // Not found in symbol table - undefined type
                    let mut error =
                        CompilerError::type_error(format!("Undefined type '{}'", name), location);
                    // Try to suggest a similar type name
                    if let Some(suggestion) = suggest_from_symbols(name, &self.symbol_table) {
                        error = error.with_hint(format!("Did you mean '{}'?", suggestion));
                    }
                    self.error_reporter.add_error(error);
                    Err(())
                }
            }
            SymbolType::TypeVar(_) => Ok(()),
            // Recursively validate nested types
            SymbolType::List(elem) => self.validate_type_annotation(elem, location),
            SymbolType::Dict(key, val) => {
                self.validate_type_annotation(key, location.clone())?;
                self.validate_type_annotation(val, location)
            }
            SymbolType::Secret(inner) => self.validate_type_annotation(inner, location),
            SymbolType::Generic(name, params) => {
                // Validate the base name as a TypeName
                self.validate_type_annotation(
                    &SymbolType::TypeName(name.clone()),
                    location.clone(),
                )?;
                // Validate each type parameter
                for param in params {
                    self.validate_type_annotation(param, location.clone())?;
                }
                Ok(())
            }
            // All other types are primitives or Unknown - valid
            _ => Ok(()),
        }
    }
}

// Helper to get a string representation of a SymbolType for error messages
// TODO: Move this into SymbolType impl or a dedicated formatter module
fn declared_type_to_string(sym_type: &SymbolType) -> String {
    match sym_type {
        // Signed integers
        SymbolType::Int64 => "int64".to_string(),
        SymbolType::Int32 => "int32".to_string(),
        SymbolType::Int16 => "int16".to_string(),
        SymbolType::Int8 => "int8".to_string(),
        // Unsigned integers
        SymbolType::UInt64 => "uint64".to_string(),
        SymbolType::UInt32 => "uint32".to_string(),
        SymbolType::UInt16 => "uint16".to_string(),
        SymbolType::UInt8 => "uint8".to_string(),
        SymbolType::Float => "float".to_string(),
        SymbolType::String => "string".to_string(),
        SymbolType::Bool => "bool".to_string(),
        SymbolType::Nil => "None".to_string(),
        SymbolType::Void => "void".to_string(),
        SymbolType::Secret(inner) => format!("secret {}", declared_type_to_string(inner)),
        SymbolType::TypeName(name) => name.clone(),
        SymbolType::TypeVar(name) => name.clone(),
        SymbolType::Unknown => "<unknown>".to_string(),
        // Collection types
        SymbolType::List(elem) => format!("list[{}]", declared_type_to_string(elem)),
        SymbolType::Dict(key, val) => format!(
            "dict[{}, {}]",
            declared_type_to_string(key),
            declared_type_to_string(val)
        ),
        SymbolType::Object(name) => name.clone(),
        SymbolType::Generic(name, params) => {
            let params_str: Vec<String> = params.iter().map(declared_type_to_string).collect();
            format!("{}[{}]", name, params_str.join(", "))
        }
    }
}

/// Public entry point for semantic analysis
pub fn analyze(
    ast: AstNode,
    error_reporter: &mut ErrorReporter,
    filename: &str,
) -> Result<AstNode, SemanticError> {
    let mut analyzer = SemanticAnalyzer::new(error_reporter, filename);
    analyzer.analyze(ast)
}

/// Analyzes an AST with pre-imported symbols from other modules.
pub fn analyze_with_imports(
    ast: AstNode,
    error_reporter: &mut ErrorReporter,
    filename: &str,
    imported_symbols: HashMap<String, SymbolInfo>,
) -> Result<AstNode, SemanticError> {
    let mut analyzer = SemanticAnalyzer::with_imports(error_reporter, filename, imported_symbols);
    analyzer.analyze(ast)
}
