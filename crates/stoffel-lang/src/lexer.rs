use crate::docs::text::cleandoc;
use crate::errors::{extract_source_snippet, CompilerError, CompilerResult, SourceLocation};
use std::collections::HashMap;
use std::iter::Peekable;
use std::str::Chars;

#[derive(Debug, Clone, PartialEq)]
pub struct TokenInfo {
    pub kind: TokenKind,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Identifier(String),
    Keyword(String),
    Operator(String),
    Arrow, // ->
    // Literals
    IntLiteral {
        value: u128,
        radix: u32,
        kind: Option<crate::ast::IntKind>,
    }, // includes bases and optional suffix
    FloatLiteral(u64), // raw f64 bits
    StringLiteral(String),
    /// A `"""..."""` docstring. The text has already been normalized with
    /// [`cleandoc`](crate::docs::text::cleandoc); consumers must not
    /// normalize it again (cleandoc is not idempotent). The token location is
    /// the opening `"""`. Docstrings are not expressions.
    DocString(String),
    BoolLiteral(bool),
    NilLiteral,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Dot,
    LPragma,   // {.
    RPragma,   // .}
    PragmaDot, // . inside pragma
    Colon,
    Assign,
    // Indentation
    Newline,
    Indent,
    Dedent,
    // End of File
    Eof,
}

fn is_operator_char(c: char) -> bool {
    "+-*/%=<>&|^!~?:.".contains(c)
}

fn get_keywords() -> HashMap<String, TokenKind> {
    let mut keywords = HashMap::new();
    keywords.insert("var".to_string(), TokenKind::Keyword("var".to_string()));
    keywords.insert("def".to_string(), TokenKind::Keyword("def".to_string()));
    keywords.insert("main".to_string(), TokenKind::Keyword("main".to_string()));
    keywords.insert(
        "builtin".to_string(),
        TokenKind::Keyword("builtin".to_string()),
    );
    keywords.insert("type".to_string(), TokenKind::Keyword("type".to_string()));
    keywords.insert(
        "object".to_string(),
        TokenKind::Keyword("object".to_string()),
    );
    keywords.insert("enum".to_string(), TokenKind::Keyword("enum".to_string()));
    keywords.insert("if".to_string(), TokenKind::Keyword("if".to_string()));
    keywords.insert("else".to_string(), TokenKind::Keyword("else".to_string()));
    keywords.insert("elif".to_string(), TokenKind::Keyword("elif".to_string())); // Or 'elsif'/'elif'? Nim uses 'elif'
    keywords.insert("and".to_string(), TokenKind::Operator("and".to_string()));
    keywords.insert("or".to_string(), TokenKind::Operator("or".to_string()));
    keywords.insert("xor".to_string(), TokenKind::Operator("xor".to_string()));
    keywords.insert("not".to_string(), TokenKind::Operator("not".to_string()));
    keywords.insert("while".to_string(), TokenKind::Keyword("while".to_string()));
    keywords.insert("for".to_string(), TokenKind::Keyword("for".to_string()));
    keywords.insert("in".to_string(), TokenKind::Keyword("in".to_string()));
    keywords.insert("break".to_string(), TokenKind::Keyword("break".to_string()));
    keywords.insert(
        "continue".to_string(),
        TokenKind::Keyword("continue".to_string()),
    );
    keywords.insert("pass".to_string(), TokenKind::Keyword("pass".to_string()));
    keywords.insert("shl".to_string(), TokenKind::Operator("shl".to_string()));
    keywords.insert("shr".to_string(), TokenKind::Operator("shr".to_string()));
    // 'mod' is the floored modulo keyword (result follows the divisor's
    // sign); '%' stays the truncating remainder (result follows the dividend).
    keywords.insert("mod".to_string(), TokenKind::Operator("mod".to_string()));
    keywords.insert(
        "return".to_string(),
        TokenKind::Keyword("return".to_string()),
    );
    keywords.insert("True".to_string(), TokenKind::BoolLiteral(true));
    keywords.insert("False".to_string(), TokenKind::BoolLiteral(false));
    keywords.insert("None".to_string(), TokenKind::NilLiteral);
    keywords.insert(
        "secret".to_string(),
        TokenKind::Keyword("secret".to_string()),
    ); // The special keyword
    keywords.insert(
        "discard".to_string(),
        TokenKind::Keyword("discard".to_string()),
    );
    // Import system keywords
    keywords.insert(
        "import".to_string(),
        TokenKind::Keyword("import".to_string()),
    );
    keywords.insert("as".to_string(), TokenKind::Keyword("as".to_string()));
    // Note: 'let' intentionally not added as a keyword anymore. It will be tokenized
    // as an Identifier to allow targeted parse-time diagnostics and potential use as a name.
    keywords
}

/// The kind of quoted literal being lexed; selects the diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotedLiteral {
    /// A single-line `"..."` string.
    String,
    /// A multi-line `"""..."""` docstring.
    DocString,
}

impl QuotedLiteral {
    fn unterminated_error(self, source: &str, open: &SourceLocation) -> CompilerError {
        let (message, hint) = match self {
            QuotedLiteral::String => (
                "Unterminated string literal",
                "Close the string with '\"' on the same line; use \"\"\"...\"\"\" for multi-line docstrings",
            ),
            QuotedLiteral::DocString => (
                "Unterminated docstring",
                "Close the docstring with \"\"\"",
            ),
        };
        CompilerError::syntax_error(message, open.clone())
            .with_snippet(extract_source_snippet(source, open, 2))
            .with_hint(hint)
    }
}

/// Decodes the character following a `\` inside a quoted literal.
///
/// `escaped` is the character after the backslash (`None` at end of input) and
/// `escape_location` is the location of the backslash itself.
fn decode_escape(
    escaped: Option<char>,
    literal: QuotedLiteral,
    source: &str,
    open: &SourceLocation,
    escape_location: SourceLocation,
) -> CompilerResult<char> {
    match escaped {
        Some('n') => Ok('\n'),
        Some('t') => Ok('\t'),
        Some('\\') => Ok('\\'),
        Some('"') => Ok('"'),
        None => Err(literal.unterminated_error(source, open)),
        Some('\n') if literal == QuotedLiteral::String => {
            Err(literal.unterminated_error(source, open))
        }
        Some(other) => {
            let shown = match other {
                '\n' => "'\\' before a line break".to_string(),
                other => format!("\\{}", other),
            };
            let snippet = extract_source_snippet(source, &escape_location, 2);
            Err(CompilerError::syntax_error(
                format!("Invalid escape sequence: {}", shown),
                escape_location,
            )
            .with_snippet(snippet)
            .with_hint("Valid escape sequences are: \\n, \\t, \\\", and \\\\"))
        }
    }
}

/// Lexes the rest of a single-line `"..."` string after its opening quote.
///
/// A raw line break or the end of input before the closing quote is an
/// "Unterminated string literal" error reported at the opening quote.
fn lex_string_body(
    iter: &mut Peekable<Chars<'_>>,
    source: &str,
    open: &SourceLocation,
    line: usize,
    column: &mut usize,
) -> CompilerResult<String> {
    let mut text = String::new();
    loop {
        match iter.next() {
            Some('"') => {
                *column += 1;
                return Ok(text);
            }
            Some('\\') => {
                let escape_location = SourceLocation {
                    column: *column,
                    line,
                    ..open.clone()
                };
                *column += 2;
                text.push(decode_escape(
                    iter.next(),
                    QuotedLiteral::String,
                    source,
                    open,
                    escape_location,
                )?);
            }
            Some('\n') | None => return Err(QuotedLiteral::String.unterminated_error(source, open)),
            Some(ch) => {
                text.push(ch);
                *column += 1;
            }
        }
    }
}

/// Lexes the rest of a `"""..."""` docstring after its opening `"""`.
///
/// Raw line breaks are kept and advance `line`; columns are counted in chars.
/// The docstring is consumed within a single token, so its continuation lines
/// take no part in indentation or comment handling. Reaching the end of input
/// before the closing `"""` is an "Unterminated docstring" error reported at
/// the opening quotes.
fn lex_docstring_body(
    iter: &mut Peekable<Chars<'_>>,
    source: &str,
    open: &SourceLocation,
    line: &mut usize,
    column: &mut usize,
) -> CompilerResult<String> {
    let mut text = String::new();
    loop {
        match iter.next() {
            Some('"') => {
                let mut quotes = 1;
                while quotes < 3 && iter.peek() == Some(&'"') {
                    iter.next();
                    quotes += 1;
                }
                *column += quotes;
                if quotes == 3 {
                    return Ok(text);
                }
                text.extend(std::iter::repeat_n('"', quotes));
            }
            Some('\\') => {
                let escape_location = SourceLocation {
                    line: *line,
                    column: *column,
                    ..open.clone()
                };
                *column += 2;
                text.push(decode_escape(
                    iter.next(),
                    QuotedLiteral::DocString,
                    source,
                    open,
                    escape_location,
                )?);
            }
            Some('\n') => {
                text.push('\n');
                *line += 1;
                *column = 1;
            }
            Some(ch) => {
                text.push(ch);
                *column += 1;
            }
            None => return Err(QuotedLiteral::DocString.unterminated_error(source, open)),
        }
    }
}

const SPACES_PER_INDENT: usize = 2;
pub fn tokenize(source: &str, filename: &str) -> CompilerResult<Vec<TokenInfo>> {
    let mut tokens = Vec::new();
    let keywords = get_keywords();
    let mut iter = source.chars().peekable();
    let mut line = 1;
    let mut column = 1;
    let mut indent_stack: Vec<usize> = vec![0]; // Stack to keep track of indentation levels
    let mut at_line_start = true;
    // Depth of open (), [] and {} groups. Newlines inside brackets are
    // implicitly joined (Python-style), so multi-line literals and call
    // argument lists lex as a single logical line.
    let mut bracket_depth: usize = 0;

    let make_location = |current_line: usize, current_column: usize| -> SourceLocation {
        SourceLocation {
            file: filename.to_string(),
            line: current_line,
            column: current_column,
        }
    };
    let mut push_token = |kind: TokenKind, loc: SourceLocation| {
        tokens.push(TokenInfo {
            kind,
            location: loc,
        });
    };

    // Note: 'main' is reserved as a keyword to denote the entry function declaration
    // or the legacy 'main' function header. It is not available as a general identifier.
    // The parser decides its role based on context.

    loop {
        if at_line_start {
            // --- Indentation Handling ---
            let mut indent_level = 0;
            let col_at_indent_start = column;

            // 1. Consume leading whitespace and calculate indent_level
            while let Some(&peek_char) = iter.peek() {
                if peek_char == ' ' {
                    iter.next(); // Consume space
                    indent_level += 1;
                    column += 1;
                } else if peek_char == '\t' {
                    // Error: Tabs not allowed
                    let location = SourceLocation {
                        file: filename.to_string(),
                        line,
                        column,
                    };
                    let snippet = extract_source_snippet(source, &location, 2);
                    return Err(CompilerError::syntax_error(
                        "Tabs are not allowed for indentation",
                        location,
                    )
                    .with_snippet(snippet)
                    .with_hint("Use spaces for indentation instead of tabs"));
                } else {
                    break; // Found non-whitespace or EOF
                }
            }

            // 2. Peek at the first non-whitespace character
            let first_char = iter.peek().copied();

            // 3. Check if it's an empty line or comment line
            let is_empty_or_comment = matches!(first_char, Some('\n') | Some('#') | None);

            // 4. Apply Indent/Dedent logic ONLY for non-empty/non-comment lines
            if !is_empty_or_comment {
                at_line_start = false; // Processed indent for this line's content
                let last_indent = *indent_stack.last().unwrap(); // Safe unwrap: stack always has 0

                if indent_level > last_indent {
                    // --- Enforce 2-space indentation ---
                    if indent_level == last_indent + SPACES_PER_INDENT {
                        indent_stack.push(indent_level);
                        push_token(TokenKind::Indent, make_location(line, column));
                    } else {
                        let location = SourceLocation {
                            file: filename.to_string(),
                            line,
                            column: col_at_indent_start, // Use column where indent started
                        };
                        let snippet = extract_source_snippet(source, &location, 2);
                        return Err(CompilerError::syntax_error(
                            format!("Invalid indentation. Expected an indent of exactly {} spaces, found {}",
                                    SPACES_PER_INDENT, indent_level - last_indent),
                            location
                        ).with_snippet(snippet).with_hint(format!("Use exactly {} spaces per indentation level.", SPACES_PER_INDENT)));
                    }
                } else if indent_level < last_indent {
                    while indent_level < *indent_stack.last().unwrap() {
                        indent_stack.pop();
                        push_token(TokenKind::Dedent, make_location(line, column));
                        // Location might be slightly off here
                    }
                    // After popping, check if the level matches exactly
                    if indent_level != *indent_stack.last().unwrap() {
                        let location = SourceLocation {
                            file: filename.to_string(),
                            line,
                            column: col_at_indent_start, // Use column where indent started
                        };
                        let snippet = extract_source_snippet(source, &location, 2);
                        return Err(CompilerError::syntax_error(
                            format!(
                                "Inconsistent dedentation. Expected indent level {}, got {}",
                                *indent_stack.last().unwrap(),
                                indent_level
                            ),
                            location,
                        )
                        .with_snippet(snippet)
                        .with_hint("Make sure all indentation levels are consistent"));
                    }
                }
                // If indent_level == last_indent, do nothing.
            } else {
                // For empty or comment lines, just mark indent as processed
                // The actual newline or comment will be handled below
                at_line_start = false;
            }
        }

        // --- Consume and process the *next* character ---
        let c = match iter.next() {
            Some(ch) => ch,
            None => break, // End of file
        };

        // --- Main Token Matching Logic ---
        match c {
            // Ignore non-leading whitespace
            ' ' | '\t' => {
                column += 1;
            }
            '\n' => {
                if bracket_depth > 0 {
                    // Implicit line joining: inside brackets a newline is just
                    // whitespace; no Newline token and no indent processing.
                    line += 1;
                    column = 1;
                } else {
                    // Emit Newline, reset state for next line
                    push_token(TokenKind::Newline, make_location(line, column));
                    line += 1;
                    column = 1;
                    at_line_start = true;
                }
            }
            '#' => {
                // Comments
                // Consume until newline or EOF
                while let Some(&peek_char) = iter.peek() {
                    if peek_char == '\n' {
                        break;
                    }
                    iter.next(); // Consume comment character
                                 // Column will be reset by the newline handler
                }
                // Don't add a comment token, just consume the characters
            }
            '(' => {
                push_token(TokenKind::LParen, make_location(line, column));
                bracket_depth += 1;
                column += 1;
            }
            ')' => {
                push_token(TokenKind::RParen, make_location(line, column));
                bracket_depth = bracket_depth.saturating_sub(1);
                column += 1;
            }
            '{' => {
                if iter.peek() == Some(&'.') {
                    iter.next(); // Consume '.'
                    push_token(TokenKind::LPragma, make_location(line, column));
                    column += 2;
                } else {
                    push_token(TokenKind::LBrace, make_location(line, column));
                    bracket_depth += 1;
                    column += 1;
                }
            }
            '}' => {
                push_token(TokenKind::RBrace, make_location(line, column));
                bracket_depth = bracket_depth.saturating_sub(1);
                column += 1;
            }
            '[' => {
                push_token(TokenKind::LBracket, make_location(line, column));
                bracket_depth += 1;
                column += 1;
            }
            ']' => {
                push_token(TokenKind::RBracket, make_location(line, column));
                bracket_depth = bracket_depth.saturating_sub(1);
                column += 1;
            }
            ',' => {
                push_token(TokenKind::Comma, make_location(line, column));
                column += 1;
            }
            '.' => {
                // --- Check for RPragma first ---
                if iter.peek() == Some(&'}') {
                    iter.next(); // Consume '}'
                    push_token(TokenKind::RPragma, make_location(line, column));
                    column += 2; // Account for both '.' and '}'
                                 // --- Check for float literal starting with '.' ---
                } else if iter.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                    // Likely start of a float like .5
                    let mut num_str = "0.".to_string(); // Prepend 0
                    column += 1; // Account for the initial '.'
                    while let Some(&next_c) = iter.peek() {
                        if next_c.is_ascii_digit() {
                            num_str.push(iter.next().unwrap());
                            column += 1;
                        } else {
                            break;
                        }
                    }
                    // Parse the float literal
                    match num_str.parse::<f64>() {
                        Ok(f) => {
                            push_token(
                                TokenKind::FloatLiteral(f.to_bits()),
                                make_location(line, column - num_str.len() + 1),
                            ); // Adjust location
                        }
                        Err(_) => { /* Error handling */ }
                    }
                // --- Check for '..' operator ---
                } else if iter.peek() == Some(&'.') {
                    iter.next(); // Consume second dot
                    push_token(
                        TokenKind::Operator("..".to_string()),
                        make_location(line, column),
                    );
                    column += 2;
                } else {
                    push_token(TokenKind::Dot, make_location(line, column));
                    column += 1;
                }
            }
            ':' => {
                push_token(TokenKind::Colon, make_location(line, column));
                column += 1;
            }
            '=' => {
                // Allow '==' as equality; single '=' is assignment token (used in expressions only now)
                if iter.peek() == Some(&'=') {
                    iter.next(); // Consume second '='
                    push_token(
                        TokenKind::Operator("==".to_string()),
                        make_location(line, column),
                    );
                    column += 2;
                } else {
                    push_token(TokenKind::Assign, make_location(line, column));
                    column += 1;
                }
            }
            '-' => {
                // Support '->' arrow
                if iter.peek() == Some(&'>') {
                    iter.next();
                    push_token(TokenKind::Arrow, make_location(line, column));
                    column += 2;
                } else if iter.peek() == Some(&'=') {
                    // Compound assignment -= operator
                    iter.next(); // consume '='
                    push_token(
                        TokenKind::Operator("-=".to_string()),
                        make_location(line, column),
                    );
                    column += 2;
                } else {
                    // Fallback to operator collection (e.g., '-', '->' handled above)
                    let start_col = column;
                    let mut op = "-".to_string();
                    while let Some(&next_c) = iter.peek() {
                        if is_operator_char(next_c) && next_c != '>' && next_c != '=' {
                            // avoid swallowing '>' or '='
                            op.push(iter.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    column += op.len();
                    push_token(TokenKind::Operator(op), make_location(line, start_col));
                }
            }
            // Other operators (handle multi-char ones like !=, <=, >=)
            c if is_operator_char(c) => {
                let start_col = column;
                let mut op = c.to_string();
                while let Some(&next_c) = iter.peek() {
                    if is_operator_char(next_c) {
                        // Simple approach: combine adjacent operator chars
                        // Needs refinement for specific operators (e.g., ->, //, **)
                        op.push(iter.next().unwrap());
                    } else {
                        break;
                    }
                }

                column += op.len(); // Update column based on operator length
                push_token(TokenKind::Operator(op), make_location(line, start_col));
            }
            // Numbers (Int, Float)
            c if c.is_ascii_digit() => {
                let start_col = column;
                let mut consumed: usize = 1; // we already consumed 'c'
                let mut radix: u32 = 10;
                let mut is_float = false;
                let mut digits = String::new();

                // Detect radix prefixes like 0x, 0b, 0o
                if c == '0' {
                    if let Some(&next_c) = iter.peek() {
                        match next_c {
                            'x' | 'X' => {
                                iter.next();
                                consumed += 1;
                                radix = 16;
                            }
                            'b' | 'B' => {
                                iter.next();
                                consumed += 1;
                                radix = 2;
                            }
                            'o' | 'O' => {
                                iter.next();
                                consumed += 1;
                                radix = 8;
                            }
                            _ => {
                                digits.push('0');
                            }
                        }
                    } else {
                        digits.push('0');
                    }
                } else {
                    digits.push(c);
                }

                // Helper to check valid digit for radix
                let is_valid_digit = |ch: char| -> bool {
                    match radix {
                        2 => ch == '0' || ch == '1',
                        8 => ch.is_ascii_digit() && ch <= '7',
                        10 => ch.is_ascii_digit(),
                        16 => ch.is_ascii_digit() || ('a'..='f').contains(&ch.to_ascii_lowercase()),
                        _ => false,
                    }
                };

                // Collect digits (and underscores)
                while let Some(&next_c) = iter.peek() {
                    if next_c == '_' {
                        iter.next();
                        consumed += 1; // skip underscore
                    } else if is_valid_digit(next_c) {
                        digits.push(iter.next().unwrap());
                        consumed += 1;
                    } else if next_c == '.' && radix == 10 && !is_float {
                        // Float like 123.45 (only in decimal)
                        // Check not '..' and that a digit follows
                        let mut peek_ahead = iter.clone();
                        peek_ahead.next();
                        if peek_ahead.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                            is_float = true;
                            digits.push('.');
                            iter.next();
                            consumed += 1; // consume '.'
                                           // collect fractional digits
                            while let Some(&frac_c) = iter.peek() {
                                if frac_c.is_ascii_digit() {
                                    digits.push(iter.next().unwrap());
                                    consumed += 1;
                                } else {
                                    break;
                                }
                            }
                        }
                        break;
                    } else {
                        break;
                    }
                }

                // Optional exponent for decimal literals: 1e3, 2.5e-2, 4E+6
                if radix == 10 {
                    if let Some(&exp_c) = iter.peek() {
                        if exp_c == 'e' || exp_c == 'E' {
                            let mut probe = iter.clone();
                            probe.next(); // consume 'e'
                            let mut exp_str = String::new();
                            if let Some(&sign_c) = probe.peek() {
                                if sign_c == '+' || sign_c == '-' {
                                    exp_str.push(sign_c);
                                    probe.next();
                                }
                            }
                            let mut has_exp_digits = false;
                            while let Some(&d) = probe.peek() {
                                if d.is_ascii_digit() {
                                    exp_str.push(d);
                                    probe.next();
                                    has_exp_digits = true;
                                } else {
                                    break;
                                }
                            }
                            // Only treat as exponent when digits follow; otherwise
                            // leave the 'e' for identifier lexing (e.g. suffixes).
                            if has_exp_digits {
                                digits.push('e');
                                digits.push_str(&exp_str);
                                let commit_len = 1 + exp_str.len();
                                for _ in 0..commit_len {
                                    iter.next();
                                }
                                consumed += commit_len;
                                is_float = true;
                            }
                        }
                    }
                }

                // Optional integer suffix: i8/i16/i32/i64/u8/u16/u32/u64
                let mut kind: Option<crate::ast::IntKind> = None;
                if !is_float {
                    if let Some(&peek_c) = iter.peek() {
                        if peek_c == 'i' || peek_c == 'u' {
                            let mut probe = iter.clone();
                            let mut suffix = String::new();
                            // Consume up to 3 characters for i/u and digits
                            while let Some(&ch) = probe.peek() {
                                if ch.is_ascii_alphanumeric() {
                                    suffix.push(ch);
                                    probe.next();
                                } else {
                                    break;
                                }
                                if suffix.len() > 3 {
                                    break;
                                }
                            }
                            let matched = match suffix.as_str() {
                                "i8" => Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W8)),
                                "i16" => {
                                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W16))
                                }
                                "i32" => {
                                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W32))
                                }
                                "i64" => {
                                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W64))
                                }
                                "u8" => {
                                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W8))
                                }
                                "u16" => {
                                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W16))
                                }
                                "u32" => {
                                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W32))
                                }
                                "u64" => {
                                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W64))
                                }
                                _ => None,
                            };
                            if let Some(k) = matched {
                                // Commit consumption
                                for _ in 0..suffix.len() {
                                    iter.next();
                                    consumed += 1;
                                }
                                kind = Some(k);
                            }
                        }
                    }
                }

                column += consumed; // update column by how many chars we consumed including first

                if is_float {
                    match digits.parse::<f64>() {
                        Ok(f) => {
                            push_token(
                                TokenKind::FloatLiteral(f.to_bits()),
                                make_location(line, start_col),
                            );
                        }
                        Err(_) => {
                            return Err(CompilerError::syntax_error(
                                format!("Invalid float literal '{}'", digits),
                                make_location(line, start_col),
                            ));
                        }
                    }
                } else {
                    // convert digits (without underscores) in given radix
                    let clean: String = digits.chars().filter(|&ch| ch != '_').collect();
                    match u128::from_str_radix(&clean, radix) {
                        Ok(val) => push_token(
                            TokenKind::IntLiteral {
                                value: val,
                                radix,
                                kind,
                            },
                            make_location(line, start_col),
                        ),
                        Err(_) => {
                            return Err(CompilerError::syntax_error(
                                format!("Integer literal '{}' is too large (max 128 bits)", digits),
                                make_location(line, start_col),
                            ));
                        }
                    }
                }
            }
            // Strings and docstrings
            '"' => {
                let open = make_location(line, column);
                if iter.peek() == Some(&'"') {
                    iter.next(); // Second quote
                    if iter.peek() == Some(&'"') {
                        iter.next(); // Third quote: this is a `"""docstring"""`
                        column += 3;
                        let raw =
                            lex_docstring_body(&mut iter, source, &open, &mut line, &mut column)?;
                        push_token(TokenKind::DocString(cleandoc(&raw)), open);
                    } else {
                        // `""` is an empty string literal.
                        column += 2;
                        push_token(TokenKind::StringLiteral(String::new()), open);
                    }
                } else {
                    column += 1; // Opening quote
                    let s = lex_string_body(&mut iter, source, &open, line, &mut column)?;
                    push_token(TokenKind::StringLiteral(s), open);
                }
            }
            // Identifiers and Keywords
            c if c.is_alphabetic() || c == '_' => {
                let start_col = column;
                let mut ident = c.to_string();
                while let Some(&next_c) = iter.peek() {
                    if next_c.is_alphanumeric() || next_c == '_' {
                        ident.push(iter.next().unwrap());
                    } else {
                        break;
                    }
                }
                column += ident.len(); // Update column based on identifier length
                if let Some(token) = keywords.get(&ident) {
                    push_token(token.clone(), make_location(line, start_col));
                } else {
                    push_token(TokenKind::Identifier(ident), make_location(line, start_col));
                }
            }
            _ => {
                // Error: Unexpected character
                let location = SourceLocation {
                    file: filename.to_string(),
                    line,
                    column,
                };
                let snippet = extract_source_snippet(source, &location, 2);
                let error = if c == '\'' {
                    CompilerError::syntax_error("Single-quoted strings are not supported", location)
                        .with_hint("Use double quotes: \"text\"")
                } else {
                    CompilerError::syntax_error(format!("Unexpected character: {}", c), location)
                };
                return Err(error.with_snippet(snippet));
            }
        }
    }

    // Handle any remaining dedents at the end of the file
    while *indent_stack.last().unwrap() > 0 {
        indent_stack.pop();
        push_token(TokenKind::Dedent, make_location(line, column)); // Location is end of file here
    }

    push_token(TokenKind::Eof, make_location(line, column));
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::{tokenize, TokenInfo, TokenKind};
    use crate::errors::CompilerResult;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Upper bound for a single tokenize call. Unterminated literals used to
    /// loop forever, so every test lexes on a worker thread under a deadline.
    const LEX_TIMEOUT: Duration = Duration::from_secs(5);

    fn lex(source: &str) -> CompilerResult<Vec<TokenInfo>> {
        let (sender, receiver) = mpsc::channel();
        let source = source.to_owned();
        thread::spawn(move || {
            // The receiver may be gone after a timeout; ignore send failures.
            let _ = sender.send(tokenize(&source, "test.stfl"));
        });
        receiver
            .recv_timeout(LEX_TIMEOUT)
            .expect("tokenize did not finish within the timeout (lexer hang)")
    }

    fn kinds(source: &str) -> Vec<TokenKind> {
        lex(source)
            .unwrap_or_else(|err| panic!("unexpected lex error for {source:?}: {err}"))
            .into_iter()
            .map(|token| token.kind)
            .collect()
    }

    fn lex_error(source: &str) -> crate::errors::CompilerError {
        match lex(source) {
            Ok(tokens) => panic!("expected a lex error for {source:?}, got {tokens:?}"),
            Err(err) => err,
        }
    }

    fn string(text: &str) -> TokenKind {
        TokenKind::StringLiteral(text.to_owned())
    }

    fn doc(text: &str) -> TokenKind {
        TokenKind::DocString(text.to_owned())
    }

    fn ident(name: &str) -> TokenKind {
        TokenKind::Identifier(name.to_owned())
    }

    // --- M0: unterminated plain strings ---

    #[test]
    fn unterminated_string_at_eof_is_an_error() {
        let err = lex_error("x = \"abc");
        assert_eq!(err.message, "Unterminated string literal");
        assert_eq!((err.location.line, err.location.column), (1, 5));
        assert!(err.hint.as_deref().unwrap_or("").contains("\"\"\""));
        assert!(err.source_snippet.is_some());
    }

    #[test]
    fn trailing_backslash_at_eof_is_an_unterminated_string() {
        let err = lex_error("x = \"abc\\");
        assert_eq!(err.message, "Unterminated string literal");
        assert_eq!((err.location.line, err.location.column), (1, 5));
    }

    #[test]
    fn raw_newline_inside_string_is_an_error() {
        let err = lex_error("x = \"abc\ndef\"\n");
        assert_eq!(err.message, "Unterminated string literal");
        assert_eq!((err.location.line, err.location.column), (1, 5));
    }

    #[test]
    fn backslash_before_newline_inside_string_is_an_error() {
        let err = lex_error("x = \"abc\\\ndef\"\n");
        assert_eq!(err.message, "Unterminated string literal");
    }

    #[test]
    fn lone_quote_at_eof_is_an_error() {
        assert_eq!(lex_error("\"").message, "Unterminated string literal");
    }

    #[test]
    fn invalid_escape_is_still_reported_at_the_backslash() {
        let err = lex_error("x = \"a\\qb\"");
        assert_eq!(err.message, "Invalid escape sequence: \\q");
        assert_eq!((err.location.line, err.location.column), (1, 7));
    }

    #[test]
    fn string_escapes_are_decoded() {
        assert_eq!(kinds("\"a\\n\\t\\\\\\\"b\"")[0], string("a\n\t\\\"b"),);
    }

    #[test]
    fn lines_after_a_string_keep_correct_locations() {
        let tokens = lex("x = \"abc\"\ny = 1\n").unwrap();
        let y = tokens.iter().find(|t| t.kind == ident("y")).unwrap();
        assert_eq!((y.location.line, y.location.column), (2, 1));
    }

    // --- Empty string vs docstring ---

    #[test]
    fn empty_string_stays_a_string_literal() {
        assert_eq!(
            kinds("x = \"\""),
            vec![ident("x"), TokenKind::Assign, string(""), TokenKind::Eof]
        );
    }

    #[test]
    fn empty_string_concatenation_is_unchanged() {
        let kinds = kinds("\"\" + \"x\"");
        assert_eq!(kinds[0], string(""));
        assert_eq!(kinds[1], TokenKind::Operator("+".to_owned()));
        assert_eq!(kinds[2], string("x"));
    }

    #[test]
    fn empty_string_columns_are_tracked() {
        let tokens = lex("\"\" + y").unwrap();
        let y = tokens.iter().find(|t| t.kind == ident("y")).unwrap();
        assert_eq!(y.location.column, 6);
    }

    // --- M1: docstrings ---

    #[test]
    fn one_line_docstring_is_a_docstring_token() {
        assert_eq!(kinds("\"\"\"Doc.\"\"\""), vec![doc("Doc."), TokenKind::Eof]);
    }

    #[test]
    fn empty_docstring() {
        assert_eq!(kinds("\"\"\"\"\"\"")[0], doc(""));
    }

    #[test]
    fn docstring_location_is_the_opening_quotes() {
        let tokens = lex("def f():\n  \"\"\"Doc.\"\"\"\n").unwrap();
        let docstring = tokens
            .iter()
            .find(|t| matches!(t.kind, TokenKind::DocString(_)))
            .unwrap();
        assert_eq!((docstring.location.line, docstring.location.column), (2, 3));
    }

    #[test]
    fn multi_line_docstring_is_cleandoced_and_lines_are_tracked() {
        let source = "\
def f():
  \"\"\"Summary line.

  Args:
    x: The value.
  \"\"\"
  y = 1
";
        let tokens = lex(source).unwrap();
        let docstring = tokens
            .iter()
            .find(|t| matches!(t.kind, TokenKind::DocString(_)))
            .unwrap();
        assert_eq!(
            docstring.kind,
            doc("Summary line.\n\nArgs:\n  x: The value.")
        );
        let y = tokens.iter().find(|t| t.kind == ident("y")).unwrap();
        assert_eq!((y.location.line, y.location.column), (7, 3));
    }

    #[test]
    fn tokens_after_closing_quotes_on_the_same_line_have_char_columns() {
        // "é" and "→" are multi-byte; columns count chars.
        let tokens = lex("\"\"\"é\n→ x\"\"\" y").unwrap();
        let y = tokens.iter().find(|t| t.kind == ident("y")).unwrap();
        assert_eq!((y.location.line, y.location.column), (2, 8));
    }

    #[test]
    fn docstring_escapes_use_the_string_escape_table() {
        assert_eq!(
            kinds("\"\"\"a\\tb\\\\c\\\"d\\ne\"\"\"")[0],
            // cleandoc expands tabs (like Python), so `\t` becomes spaces.
            doc("a       b\\c\"d\ne")
        );
    }

    #[test]
    fn invalid_escape_inside_docstring_reports_its_line() {
        let err = lex_error("\"\"\"ok\n  bad \\q\n\"\"\"");
        assert_eq!(err.message, "Invalid escape sequence: \\q");
        assert_eq!((err.location.line, err.location.column), (2, 7));
    }

    #[test]
    fn embedded_quotes_inside_docstring_are_kept() {
        assert_eq!(
            kinds("\"\"\"say \"hi\" and \"\"twice\"\" \"\"\"")[0],
            doc("say \"hi\" and \"\"twice\"\"")
        );
    }

    #[test]
    fn four_quotes_close_then_start_a_new_string() {
        // Like Python, the first `"""` closes; the fourth quote opens a string.
        let err = lex_error("\"\"\"a\"\"\"\"");
        assert_eq!(err.message, "Unterminated string literal");
        assert_eq!(err.location.column, 8);
    }

    #[test]
    fn unterminated_docstring_is_reported_at_the_opening_quotes() {
        let err = lex_error("def f():\n  \"\"\"Never closed.\n\n  More text\n");
        assert_eq!(err.message, "Unterminated docstring");
        assert_eq!((err.location.line, err.location.column), (2, 3));
        assert!(err.source_snippet.is_some());
    }

    #[test]
    fn docstring_with_trailing_backslash_at_eof_is_unterminated() {
        assert_eq!(lex_error("\"\"\"abc\\").message, "Unterminated docstring");
    }

    #[test]
    fn docstring_continuation_lines_skip_indentation_and_comments() {
        let source = "\
def f():
  \"\"\"Summary.
# not a comment
      deeper
back at zero
  \"\"\"
  pass
";
        let kinds = kinds(source);
        let indents = kinds.iter().filter(|k| **k == TokenKind::Indent).count();
        let dedents = kinds.iter().filter(|k| **k == TokenKind::Dedent).count();
        assert_eq!((indents, dedents), (1, 1));
        assert!(kinds.contains(&doc(
            "Summary.\n# not a comment\n      deeper\nback at zero"
        )));
        assert!(kinds.contains(&TokenKind::Keyword("pass".to_owned())));
    }

    #[test]
    fn docstring_inside_brackets_does_not_affect_bracket_depth() {
        let kinds = kinds("f(\"\"\"a\nb\"\"\")\nx\n");
        assert_eq!(
            kinds,
            vec![
                ident("f"),
                TokenKind::LParen,
                doc("a\nb"),
                TokenKind::RParen,
                TokenKind::Newline,
                ident("x"),
                TokenKind::Newline,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn docstring_opening_at_the_wrong_depth_is_invalid_indentation() {
        let err = lex_error("def f():\n   \"\"\"Doc.\"\"\"\n");
        assert!(
            err.message.starts_with("Invalid indentation"),
            "{}",
            err.message
        );
    }

    #[test]
    fn triple_single_quotes_remain_an_error() {
        assert_eq!(
            lex_error("'''doc'''").message,
            "Single-quoted strings are not supported"
        );
    }
}
