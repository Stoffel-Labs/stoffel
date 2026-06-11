use crate::errors::{extract_source_snippet, CompilerError, CompilerResult, SourceLocation};
use std::collections::HashMap;

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

const SPACES_PER_INDENT: usize = 2;
pub fn tokenize(source: &str, filename: &str) -> CompilerResult<Vec<TokenInfo>> {
    let mut tokens = Vec::new();
    let keywords = get_keywords();
    let mut iter = source.chars().peekable();
    let mut line = 1;
    let mut column = 1;
    let mut indent_stack: Vec<usize> = vec![0]; // Stack to keep track of indentation levels
    let mut at_line_start = true;

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
                // Emit Newline, reset state for next line
                push_token(TokenKind::Newline, make_location(line, column));
                line += 1;
                column = 1;
                at_line_start = true;
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
                column += 1;
            }
            ')' => {
                push_token(TokenKind::RParen, make_location(line, column));
                column += 1;
            }
            '{' => {
                if iter.peek() == Some(&'.') {
                    iter.next(); // Consume '.'
                    push_token(TokenKind::LPragma, make_location(line, column));
                    column += 2;
                } else {
                    push_token(TokenKind::LBrace, make_location(line, column));
                    column += 1;
                }
            }
            '}' => {
                push_token(TokenKind::RBrace, make_location(line, column));
                column += 1;
            }
            '[' => {
                push_token(TokenKind::LBracket, make_location(line, column));
                column += 1;
            }
            ']' => {
                push_token(TokenKind::RBracket, make_location(line, column));
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
            // Strings
            '"' => {
                let start_col = column;
                let mut s = String::new();
                column += 1; // Account for opening quote
                loop {
                    match iter.next() {
                        Some('"') => {
                            column += 1;
                            break;
                        }
                        Some('\\') => {
                            // Handle escape sequences
                            let escape_col = column; // Column of the escape character
                            column += 1;
                            match iter.next() {
                                Some('n') => {
                                    s.push('\n');
                                    column += 1;
                                }
                                Some('t') => {
                                    s.push('\t');
                                    column += 1;
                                }
                                Some('\\') => {
                                    s.push('\\');
                                    column += 1;
                                }
                                Some('"') => {
                                    s.push('"');
                                    column += 1;
                                }
                                Some(esc_c) => {
                                    // Invalid escape sequence
                                    let location = SourceLocation {
                                        file: filename.to_string(),
                                        line,
                                        column: escape_col,
                                    };
                                    let snippet = extract_source_snippet(source, &location, 2);
                                    return Err(CompilerError::syntax_error(
                                        format!("Invalid escape sequence: \\{}", esc_c),
                                        location,
                                    )
                                    .with_snippet(snippet)
                                    .with_hint(
                                        "Valid escape sequences are: \\n, \\t, \\\", and \\\\",
                                    ));
                                }
                                None => { /* Unterminated escape error */ }
                            }
                        }
                        Some('\n') => { /* Unterminated string error (newline) */ }
                        Some(str_c) => {
                            s.push(str_c);
                            column += 1;
                        }
                        None => { /* Unterminated string error (EOF) */ }
                    }
                }
                push_token(TokenKind::StringLiteral(s), make_location(line, start_col));
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
