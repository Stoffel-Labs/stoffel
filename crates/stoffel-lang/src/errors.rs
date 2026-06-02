use std::fmt;

/// Represents the location in source code where an error occurred
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

impl Default for SourceLocation {
    fn default() -> Self {
        SourceLocation {
            file: "<unknown>".to_string(),
            line: 0,
            column: 0,
        }
    }
}

/// Represents the severity of an error
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Warning,
    Error,
    Fatal,
}

/// Represents the category of an error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Syntax,
    Type,
    Semantic,
    Internal,
}

/// Represents a compiler error with detailed information
#[derive(Debug, Clone)]
pub struct CompilerError {
    pub message: String,
    pub location: SourceLocation,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub code: &'static str,
    pub hint: Option<Box<str>>,
    pub source_snippet: Option<Box<str>>,
}

impl CompilerError {
    /// Creates a new syntax error
    pub fn syntax_error(message: impl Into<String>, location: SourceLocation) -> Self {
        CompilerError {
            message: message.into(),
            location,
            severity: ErrorSeverity::Error,
            category: ErrorCategory::Syntax,
            code: "E001",
            hint: None,
            source_snippet: None,
        }
    }

    /// Creates a new type error
    pub fn type_error(message: impl Into<String>, location: SourceLocation) -> Self {
        CompilerError {
            message: message.into(),
            location,
            severity: ErrorSeverity::Error,
            category: ErrorCategory::Type,
            code: "E101",
            hint: None,
            source_snippet: None,
        }
    }

    /// Creates a new semantic error
    pub fn semantic_error(message: impl Into<String>, location: SourceLocation) -> Self {
        CompilerError {
            message: message.into(),
            location,
            severity: ErrorSeverity::Error,
            category: ErrorCategory::Semantic,
            code: "E201",
            hint: None,
            source_snippet: None,
        }
    }

    /// Creates a new internal error
    pub fn internal_error(message: impl Into<String>) -> Self {
        CompilerError {
            message: message.into(),
            location: SourceLocation::default(),
            severity: ErrorSeverity::Fatal,
            category: ErrorCategory::Internal,
            code: "E901",
            hint: None,
            source_snippet: None,
        }
    }

    /// Adds a hint to the error
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into().into_boxed_str());
        self
    }

    /// Adds a source code snippet to the error
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.source_snippet = Some(snippet.into().into_boxed_str());
        self
    }

    /// Formats the error message with ANSI color codes for terminal output
    pub fn format_with_colors(&self) -> String {
        use colored::*;

        let severity = match self.severity {
            ErrorSeverity::Warning => "Warning".yellow(),
            ErrorSeverity::Error => "Error".red(),
            ErrorSeverity::Fatal => "Fatal Error".bright_red(),
        };

        let category = match self.category {
            ErrorCategory::Syntax => "Syntax".cyan(),
            ErrorCategory::Type => "Type".cyan(),
            ErrorCategory::Semantic => "Semantic".cyan(),
            ErrorCategory::Internal => "Internal".cyan(),
        };

        let mut result = format!(
            "{} [{}] {}: {}\n  --> {}\n",
            severity,
            self.code.white(),
            category,
            self.message,
            self.location.to_string().bright_blue()
        );

        if let Some(snippet) = &self.source_snippet {
            result.push_str(&format!("\n{}\n", snippet));
        }

        if let Some(hint) = &self.hint {
            result.push_str(&format!("\nHint: {}\n", hint.bright_green()));
        }

        result
    }
}

impl fmt::Display for CompilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {}: {} at {}",
            match self.severity {
                ErrorSeverity::Warning => "Warning",
                ErrorSeverity::Error => "Error",
                ErrorSeverity::Fatal => "Fatal Error",
            },
            self.code,
            match self.category {
                ErrorCategory::Syntax => "Syntax",
                ErrorCategory::Type => "Type",
                ErrorCategory::Semantic => "Semantic",
                ErrorCategory::Internal => "Internal",
            },
            self.message,
            self.location
        )?;

        if let Some(hint) = &self.hint {
            write!(f, "\nHint: {}", hint)?;
        }

        Ok(())
    }
}

impl std::error::Error for CompilerError {}

/// A collection of compiler errors
#[derive(Debug, Default)]
pub struct ErrorReporter {
    errors: Vec<CompilerError>,
    warnings: Vec<CompilerError>,
    has_errors: bool,
}

impl ErrorReporter {
    /// Creates a new error reporter
    pub fn new() -> Self {
        ErrorReporter {
            errors: Vec::new(),
            warnings: Vec::new(),
            has_errors: false,
        }
    }

    /// Adds an error to the reporter
    pub fn add_error(&mut self, error: CompilerError) {
        match error.severity {
            ErrorSeverity::Warning => self.warnings.push(error),
            ErrorSeverity::Error | ErrorSeverity::Fatal => {
                self.has_errors = true;
                self.errors.push(error);
            }
        }
    }

    /// Returns true if any errors have been reported
    pub fn has_errors(&self) -> bool {
        self.has_errors
    }

    /// Returns all errors and warnings
    pub fn get_all(&self) -> Vec<&CompilerError> {
        let mut all = Vec::new();
        all.extend(self.errors.iter());
        all.extend(self.warnings.iter());
        all
    }

    /// Prints all errors and warnings to stderr
    pub fn print_all(&self) {
        for error in &self.errors {
            eprintln!("{}", error.format_with_colors());
        }
        for warning in &self.warnings {
            eprintln!("{}", warning.format_with_colors());
        }
    }
}

/// Formats the header line for compilation errors.
pub fn format_error_header(count: usize) -> String {
    use colored::*;
    let s = if count == 1 { "" } else { "s" };
    format!(
        "Compilation failed with {} error{}:",
        count.to_string().red().bold(),
        s.red().bold()
    )
}

/// Helper function to extract source code snippet around an error location
pub fn extract_source_snippet(
    file: &str,
    location: &SourceLocation,
    context_lines: usize,
) -> String {
    let lines: Vec<&str> = file.lines().collect();

    if location.line == 0 || location.line > lines.len() || location.file == "<unknown>" {
        return String::new();
    }

    let line_idx = location.line - 1;
    let start_line = line_idx.saturating_sub(context_lines);
    let end_line = std::cmp::min(line_idx + context_lines, lines.len() - 1);

    let mut result = String::new();

    for (i, line) in lines.iter().enumerate().take(end_line + 1).skip(start_line) {
        let line_num = i + 1;
        let prefix = if i == line_idx { " > " } else { "   " };
        result.push_str(&format!("{}{:4} | {}\n", prefix, line_num, line));

        if i == line_idx {
            // Add a pointer to the exact column
            let mut pointer = String::from("     | ");
            for _ in 0..location.column.saturating_sub(1) {
                pointer.push(' ');
            }
            pointer.push('^');
            result.push_str(&pointer);
            result.push('\n');
        }
    }

    result
}

/// Result type for compiler operations that can fail with a CompilerError
pub type CompilerResult<T> = Result<T, CompilerError>;
