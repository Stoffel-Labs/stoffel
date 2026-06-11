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
            ErrorSeverity::Warning => "warning".yellow().bold(),
            ErrorSeverity::Error => "error".red().bold(),
            ErrorSeverity::Fatal => "error".red().bold(),
        };

        let message = if matches!(self.severity, ErrorSeverity::Fatal)
            && matches!(self.category, ErrorCategory::Internal)
        {
            format!("internal compiler error: {}", self.message)
        } else {
            self.message.clone()
        };

        let mut result = format!("{}[{}]: {}\n", severity, self.code.white().bold(), message);

        if self.location.line != 0 && self.location.file != "<unknown>" {
            result.push_str(&format!(
                "  {} {}\n",
                "-->".bright_blue().bold(),
                self.location.to_string().bright_blue()
            ));
        }

        if let Some(snippet) = &self.source_snippet {
            if !snippet.is_empty() {
                result.push_str(snippet);
            }
        }

        if let Some(hint) = &self.hint {
            result.push_str(&format!(
                "{} {}\n",
                "help:".green().bold(),
                hint.bright_green()
            ));
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

    /// Returns the number of reported errors, excluding warnings.
    pub fn error_count(&self) -> usize {
        self.errors.len()
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
    if count == 1 {
        format!("{} aborting due to previous error", "error:".red().bold())
    } else {
        format!(
            "{} aborting due to {} previous errors",
            "error:".red().bold(),
            count.to_string().red().bold()
        )
    }
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
    let line_num_width = (end_line + 1).to_string().len();

    let mut result = String::new();
    result.push_str(&format!("{:>width$} |\n", "", width = line_num_width));

    for (i, line) in lines.iter().enumerate().take(end_line + 1).skip(start_line) {
        let line_num = i + 1;
        result.push_str(&format!(
            "{:>width$} | {}\n",
            line_num,
            line,
            width = line_num_width
        ));

        if i == line_idx {
            // Add a pointer to the exact column
            let mut pointer = format!("{:>width$} | ", "", width = line_num_width);
            for _ in 0..location.column.saturating_sub(1) {
                pointer.push(' ');
            }
            pointer.push('^');
            result.push_str(&pointer);
            result.push('\n');
        }
    }
    result.push_str(&format!("{:>width$} |\n", "", width = line_num_width));

    result
}

/// Result type for compiler operations that can fail with a CompilerError
pub type CompilerResult<T> = Result<T, CompilerError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(line: usize, column: usize) -> SourceLocation {
        SourceLocation {
            file: "main.stfl".to_string(),
            line,
            column,
        }
    }

    #[test]
    fn diagnostic_formats_like_rust_error() {
        colored::control::set_override(false);
        let source = "def main():\n  var xs: List[int64] = []\n";
        let location = loc(2, 11);
        let snippet = extract_source_snippet(source, &location, 1);
        let error = CompilerError::syntax_error("Unknown generic type: List", location)
            .with_hint("Did you mean 'list'?")
            .with_snippet(snippet);

        assert_eq!(
            error.format_with_colors(),
            concat!(
                "error[E001]: Unknown generic type: List\n",
                "  --> main.stfl:2:11\n",
                "  |\n",
                "1 | def main():\n",
                "2 |   var xs: List[int64] = []\n",
                "  |           ^\n",
                "  |\n",
                "help: Did you mean 'list'?\n"
            )
        );
    }

    #[test]
    fn abort_summary_uses_rust_singular_and_plural_wording() {
        colored::control::set_override(false);
        assert_eq!(
            format_error_header(1),
            "error: aborting due to previous error"
        );
        assert_eq!(
            format_error_header(3),
            "error: aborting due to 3 previous errors"
        );
    }
}
