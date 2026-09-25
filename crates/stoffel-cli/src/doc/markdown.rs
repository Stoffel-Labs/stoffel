//! Mintlify-compatible Markdown (MDX) renderer for `stoffel doc`.
//!
//! The output is a folder of `.mdx` pages meant to be dropped into a
//! Mintlify docs repository:
//!
//! - `overview.mdx`: the landing page, with a card per module;
//! - one page per module, nested by its dotted name (`std.mpc` becomes
//!   `std/mpc.mdx`);
//! - `navigation.json`: a `docs.json` navigation group listing every page.
//!
//! Mintlify resolves links from the docs root, so every link is
//! root-relative and starts with the base path (the output folder's
//! location under the directory holding `docs.json`).
//!
//! Docstrings are plain text, not Markdown. Everything outside code spans
//! and code blocks is escaped so MDX never interprets it as Markdown syntax,
//! JSX or an expression; the only links generated point at documented items
//! and modules.

use std::fmt::Write as _;

use stoffel::docs::{
    code_spans, AliasOf, DocIndex, DocItem, ModuleDoc, ParamDoc, ParsedDoc, Section,
};

use super::shared::{
    bullet_text, display_signature, indent_of, is_deprecated, json_string, receiver_call,
    strip_indent, AnchorSet, ItemGroup, OutputFile, Site, SiteKind,
};

/// Page (without extension) of the landing page.
pub(super) const OVERVIEW_PAGE: &str = "overview";
/// File listing the pages as a Mintlify `docs.json` navigation group.
pub(super) const NAVIGATION_FILE: &str = "navigation.json";
/// Extension of generated pages.
const PAGE_EXTENSION: &str = "mdx";
/// Fence language for StoffelLang code. Mintlify highlights with Shiki,
/// which has no StoffelLang grammar; Python is the closest match.
const STOFFEL_FENCE_LANGUAGE: &str = "python";

/// The page (a `/`-separated path without extension) of a module:
/// `std.mpc` gives `std/mpc`. Each dotted segment keeps `[A-Za-z0-9_-]` and
/// maps anything else to `_`, and a module whose page would shadow the
/// landing page gets a `_` suffix.
pub(super) fn module_page_path(module: &str) -> String {
    let segments: Vec<String> = module
        .split('.')
        .map(|segment| {
            let segment: String = segment
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            if segment.is_empty() {
                "_".to_string()
            } else {
                segment
            }
        })
        .collect();
    let mut page = segments.join("/");
    if page.eq_ignore_ascii_case(OVERVIEW_PAGE) {
        page.push('_');
    }
    page
}

/// Renders every page plus the navigation file.
pub(super) fn render_site(site: &Site<'_>, base_path: &str) -> Vec<OutputFile> {
    let ctx = RenderContext::new(site, base_path);
    let mut files = Vec::with_capacity(site.modules.len() + 2);
    files.push(OutputFile {
        name: format!("{OVERVIEW_PAGE}.{PAGE_EXTENSION}"),
        contents: render_overview(&ctx),
    });
    for module in site.modules {
        files.push(OutputFile {
            name: format!("{}.{PAGE_EXTENSION}", module_page_path(&module.name)),
            contents: render_module(&ctx, module),
        });
    }
    files.push(OutputFile {
        name: NAVIGATION_FILE.to_string(),
        contents: render_navigation(&ctx),
    });
    files
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

struct RenderContext<'a> {
    site: &'a Site<'a>,
    index: DocIndex<'a>,
    /// Docs-root-relative folder of the pages, without leading or trailing
    /// `/` (empty for the docs root).
    base_path: &'a str,
}

impl<'a> RenderContext<'a> {
    fn new(site: &'a Site<'a>, base_path: &'a str) -> Self {
        RenderContext {
            site,
            index: DocIndex::new(site.modules),
            base_path,
        }
    }

    /// A page as listed in `docs.json` (`reference/std/mpc`).
    fn nav_page(&self, page: &str) -> String {
        if self.base_path.is_empty() {
            page.to_string()
        } else {
            format!("{}/{page}", self.base_path)
        }
    }

    /// The root-relative URL of a page (`/reference/std/mpc`).
    fn page_url(&self, page: &str) -> String {
        format!("/{}", self.nav_page(page))
    }

    fn module_url(&self, module: &ModuleDoc) -> String {
        self.page_url(&module_page_path(&module.name))
    }

    fn item_url(&self, module: &ModuleDoc, item: &DocItem) -> String {
        format!("{}#{}", self.module_url(module), item_anchor(item))
    }

    /// The link for a reference in docstring text: an item path (plain or
    /// module-qualified, optionally followed by `()`) or a module name.
    fn resolve(&self, target: &str) -> Option<String> {
        let target = target.strip_suffix("()").unwrap_or(target);
        if let Some(found) = self.index.resolve(target) {
            return Some(self.item_url(found.module, found.item));
        }
        self.site
            .modules
            .iter()
            .find(|module| module.name == target)
            .map(|module| self.module_url(module))
    }
}

/// The heading id of an item: its HTML anchor (`obj.Share.mul`) lowercased
/// with everything outside `[a-z0-9_-]` mapped to `-` (`obj-share-mul`).
fn item_anchor(item: &DocItem) -> String {
    item.anchor()
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Where inline text is written; table cells also escape `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InlineContext {
    Block,
    TableCell,
}

/// Appends plain text with every character MDX or Markdown could interpret
/// escaped: emphasis, links, JSX (`<`), expressions (`{`), tables and
/// character references.
fn push_escaped(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '{' | '}' | '|' | '~' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            '&' => out.push_str("&amp;"),
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
}

/// Escapes a line start that Markdown would read as a list, heading or
/// quote marker. Only `+ ` and ordered-list markers remain after
/// [`push_escaped`] (which already escapes `#`, `>`, `*` and `|`).
fn escape_line_start(line: &str) -> String {
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 && matches!(line[digits..].chars().next(), Some('.' | ')')) {
        return format!("{}\\{}", &line[..digits], &line[digits..]);
    }
    if let Some(rest) = line.strip_prefix('+').or_else(|| line.strip_prefix('-')) {
        if rest.is_empty() || rest.starts_with(' ') {
            return format!("\\{}{rest}", &line[..1]);
        }
    }
    if line.starts_with('=') {
        return format!("\\{line}");
    }
    line.to_string()
}

/// A JSX string attribute value (`"..."`): quotes and ampersands become
/// character references and line breaks become spaces.
fn attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A code span that can hold any text: the fence is one backtick longer
/// than the longest backtick run inside, padded when the text touches a
/// backtick.
fn code_span(text: &str, context: InlineContext) -> String {
    let longest = longest_backtick_run(text);
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    let text = match context {
        InlineContext::TableCell => text.replace('|', "\\|"),
        InlineContext::Block => text.replace(['\n', '\r'], " "),
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}

fn longest_backtick_run(text: &str) -> usize {
    text.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// Inline docstring text: backtick spans become code (linked when they name
/// a documented item or module), everything else is escaped.
fn inline(ctx: &RenderContext<'_>, text: &str, context: InlineContext) -> String {
    inline_with(text, |out, span| match ctx.resolve(span) {
        Some(url) => {
            let _ = write!(out, "[{}]({url})", code_span(span, context));
        }
        None => out.push_str(&code_span(span, context)),
    })
}

/// Like [`inline`] but never links (for text inside link components).
fn inline_plain(text: &str, context: InlineContext) -> String {
    inline_with(text, |out, span| out.push_str(&code_span(span, context)))
}

fn inline_with(text: &str, mut code: impl FnMut(&mut String, &str)) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        let span = &after[..close];
        push_escaped(&mut out, &rest[..open]);
        if span.is_empty() {
            out.push_str("\\`\\`");
        } else {
            code(&mut out, span);
        }
        rest = &after[close + 1..];
    }
    push_escaped(&mut out, rest);
    escape_line_start(&out)
}

/// Text with code spans unwrapped, for frontmatter descriptions.
fn plain_text(text: &str) -> String {
    text.replace('`', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

fn frontmatter(out: &mut String, title: &str, description: Option<&str>) {
    // JSON strings are valid YAML double-quoted scalars.
    let _ = writeln!(out, "---\ntitle: {}", json_string(title));
    if let Some(description) = description.map(plain_text).filter(|text| !text.is_empty()) {
        let _ = writeln!(out, "description: {}", json_string(&description));
    }
    let _ = write!(
        out,
        "---\n\n{{/* Generated by `stoffel doc` {}. Edit the .stfl docstrings, not this file. */}}\n\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn stdlib_banner(out: &mut String, module: Option<&ModuleDoc>) {
    let import = match module {
        Some(module) => format!(
            "{} is optional",
            code_span(&format!("import {}", module.name), InlineContext::Block)
        ),
        None => "importing `std.*` modules is optional".to_string(),
    };
    let _ = write!(
        out,
        "<Info>\n**Always in scope.** Standard library builtins are available in every program; {import}.\n</Info>\n\n"
    );
}

fn render_overview(ctx: &RenderContext<'_>) -> String {
    let mut out = String::new();
    let item_count: usize = ctx
        .site
        .modules
        .iter()
        .map(|module| module.all_items().count())
        .sum();
    let description = match ctx.site.kind {
        SiteKind::Stdlib => "Reference for the StoffelLang standard library.",
        SiteKind::User => "API reference generated from StoffelLang docstrings.",
    };
    frontmatter(&mut out, ctx.site.title, Some(description));
    let _ = write!(
        out,
        "{} {}, {} {}.\n\n",
        ctx.site.modules.len(),
        if ctx.site.modules.len() == 1 {
            "module"
        } else {
            "modules"
        },
        item_count,
        if item_count == 1 { "item" } else { "items" },
    );
    if ctx.site.kind == SiteKind::Stdlib {
        stdlib_banner(&mut out, None);
    }
    out.push_str("## Modules\n\n<CardGroup cols={2}>\n");
    for module in ctx.site.modules {
        let count = module.all_items().count();
        let _ = writeln!(
            out,
            "<Card title={} href={}>",
            attribute(&module.name),
            attribute(&ctx.module_url(module))
        );
        match module.doc.as_ref().map(|doc| doc.summary.as_str()) {
            // Cards are links, so summaries render code spans unlinked.
            Some(summary) if !summary.is_empty() => {
                let _ = writeln!(out, "{}", inline_plain(summary, InlineContext::Block));
            }
            _ => out.push_str("No module documentation.\n"),
        }
        let _ = write!(
            out,
            "\n{count} {}\n</Card>\n",
            if count == 1 { "item" } else { "items" }
        );
    }
    out.push_str("</CardGroup>\n");
    out
}

fn render_module(ctx: &RenderContext<'_>, module: &ModuleDoc) -> String {
    let mut out = String::new();
    let summary = module.doc.as_ref().map(|doc| doc.summary.as_str());
    frontmatter(&mut out, &module.name, summary);
    if ctx.site.kind == SiteKind::Stdlib {
        stdlib_banner(&mut out, Some(module));
    }
    let _ = write!(
        out,
        "Source: {}\n\n",
        code_span(&module.path, InlineContext::Block)
    );
    match &module.doc {
        Some(doc) => render_doc(&mut out, ctx, doc, None),
        None => out.push_str("*No module documentation.*\n\n"),
    }

    let groups: Vec<(ItemGroup, Vec<&DocItem>)> = ItemGroup::ALL
        .into_iter()
        .map(|group| {
            let items = module
                .items
                .iter()
                .filter(|item| ItemGroup::of(item.kind) == group)
                .collect::<Vec<_>>();
            (group, items)
        })
        .filter(|(_, items)| !items.is_empty())
        .collect();
    if groups.is_empty() {
        out.push_str("*This module declares no public items.*\n");
    }

    let mut anchors = AnchorSet::default();
    for group in ItemGroup::ALL {
        anchors.claim(group.id().to_string());
    }
    for (group, items) in &groups {
        let _ = write!(out, "## {} {{#{}}}\n\n", group.title(), group.id());
        render_summary_table(&mut out, ctx, items.iter().copied(), None);
        for item in items {
            render_item(&mut out, ctx, &mut anchors, item, false);
        }
    }
    out
}

fn render_navigation(ctx: &RenderContext<'_>) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\n  \"group\": {},\n  \"pages\": [\n    {}",
        json_string(ctx.site.title),
        json_string(&ctx.nav_page(OVERVIEW_PAGE))
    );
    for module in ctx.site.modules {
        let _ = write!(
            out,
            ",\n    {}",
            json_string(&ctx.nav_page(&module_page_path(&module.name)))
        );
    }
    out.push_str("\n  ]\n}\n");
    out
}

/// A table of item names and summaries.
fn render_summary_table<'i>(
    out: &mut String,
    ctx: &RenderContext<'_>,
    items: impl Iterator<Item = &'i DocItem>,
    container: Option<&DocItem>,
) {
    out.push_str("| Name | Summary |\n| --- | --- |\n");
    for item in items {
        let label = match container {
            Some(_) => item.name.as_str(),
            None => item.path.as_str(),
        };
        let _ = write!(
            out,
            "| [{}](#{})",
            code_span(label, InlineContext::TableCell),
            item_anchor(item)
        );
        if matches!(
            item.alias_of,
            Some(AliasOf::Item(_) | AliasOf::VmBuiltin(_))
        ) {
            out.push_str(" *alias*");
        }
        if is_deprecated(item) {
            out.push_str(" *deprecated*");
        }
        out.push_str(" | ");
        match item.summary() {
            Some(summary) if !summary.is_empty() => {
                out.push_str(&inline(ctx, summary, InlineContext::TableCell));
            }
            _ => out.push_str("*Undocumented*"),
        }
        out.push_str(" |\n");
    }
    out.push('\n');
}

fn render_item(
    out: &mut String,
    ctx: &RenderContext<'_>,
    anchors: &mut AnchorSet,
    item: &DocItem,
    is_member: bool,
) {
    let anchor = anchors.claim(item_anchor(item));
    let heading = if is_member { "####" } else { "###" };
    let _ = write!(
        out,
        "{heading} {} {{#{anchor}}}\n\n",
        code_span(&item.name, InlineContext::Block)
    );

    let mut meta = vec![format!("*{}*", item.kind.label())];
    if item.is_private() {
        meta.push("*private*".to_string());
    }
    if is_deprecated(item) {
        meta.push("**deprecated**".to_string());
    }
    meta.push(format!(
        "declared at {}",
        code_span(
            &format!("{}:{}", item.location.file, item.location.line),
            InlineContext::Block
        )
    ));
    let _ = write!(out, "{}\n\n", meta.join(" · "));

    push_code_block(out, &display_signature(item), STOFFEL_FENCE_LANGUAGE);
    render_item_facts(out, ctx, item);

    match &item.doc {
        Some(doc) => render_doc(out, ctx, doc, Some(item)),
        None => out.push_str("*No documentation.*\n\n"),
    }

    if !item.members.is_empty() {
        let _ = write!(out, "**Methods** ({})\n\n", item.members.len());
        render_summary_table(out, ctx, item.members.iter(), Some(item));
        for member in &item.members {
            render_item(out, ctx, anchors, member, true);
        }
    }
}

/// Alias, VM binding and UFCS facts shown under the signature.
fn render_item_facts(out: &mut String, ctx: &RenderContext<'_>, item: &DocItem) {
    let mut facts: Vec<String> = Vec::new();
    match &item.alias_of {
        Some(AliasOf::Item(target)) => {
            let target = inline(ctx, &format!("`{target}`"), InlineContext::Block);
            facts.push(format!("**Alias of** {target}"));
        }
        Some(AliasOf::VmBuiltin(symbol)) => facts.push(format!(
            "**Alias of VM builtin** {}",
            code_span(symbol, InlineContext::Block)
        )),
        Some(other) => facts.push(format!(
            "**Alias of** {}",
            code_span(other.target(), InlineContext::Block)
        )),
        None => {}
    }
    let shows_vm_symbol = !matches!(
        item.alias_of,
        Some(AliasOf::VmBuiltin(_)) | Some(AliasOf::Item(_))
    );
    if let (Some(symbol), true) = (&item.vm_symbol, shows_vm_symbol) {
        facts.push(format!(
            "**VM builtin:** {}",
            code_span(symbol, InlineContext::Block)
        ));
    }
    if let Some(call) = receiver_call(item) {
        facts.push(format!(
            "**Callable as** {}",
            code_span(&call, InlineContext::Block)
        ));
    }
    if facts.is_empty() {
        return;
    }
    for fact in facts {
        let _ = writeln!(out, "- {fact}");
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Docstrings
// ---------------------------------------------------------------------------

fn render_doc(out: &mut String, ctx: &RenderContext<'_>, doc: &ParsedDoc, item: Option<&DocItem>) {
    if !doc.summary.is_empty() {
        let _ = write!(
            out,
            "{}\n\n",
            inline(ctx, &doc.summary, InlineContext::Block)
        );
    }
    render_blocks(out, ctx, &doc.body);
    for section in &doc.sections {
        render_section(out, ctx, section, item);
    }
}

fn render_section(
    out: &mut String,
    ctx: &RenderContext<'_>,
    section: &Section,
    item: Option<&DocItem>,
) {
    match section {
        Section::Args(params) => render_args(out, ctx, params, item),
        Section::Mpc(text) => render_callout(out, ctx, "Info", "MPC cost", text),
        Section::Notes(text) => render_callout(out, ctx, "Note", "Note", text),
        Section::Deprecated(text) => render_callout(out, ctx, "Warning", "Deprecated", text),
        Section::Examples(text) => {
            out.push_str("**Examples**\n\n");
            render_examples(out, ctx, text);
        }
        Section::SeeAlso(text) => {
            out.push_str("**See also**\n\n");
            render_see_also(out, ctx, text);
        }
        Section::Returns(text) => {
            let return_type = item
                .and_then(|item| item.function.as_ref())
                .and_then(|function| function.return_type.as_deref());
            match return_type {
                Some(return_type) => {
                    let _ = write!(
                        out,
                        "**Returns** {}\n\n",
                        code_span(return_type, InlineContext::Block)
                    );
                }
                None => out.push_str("**Returns**\n\n"),
            }
            render_blocks(out, ctx, text);
        }
        other => {
            out.push_str("**");
            push_escaped(out, other.title());
            out.push_str("**\n\n");
            if let Some(text) = other.text() {
                render_blocks(out, ctx, text);
            }
        }
    }
}

/// A Mintlify callout component (`<Info>`, `<Note>`, `<Warning>`).
fn render_callout(
    out: &mut String,
    ctx: &RenderContext<'_>,
    component: &str,
    title: &str,
    text: &str,
) {
    let _ = write!(out, "<{component}>\n**{title}**\n\n");
    render_blocks(out, ctx, text);
    let _ = write!(out, "</{component}>\n\n");
}

/// Arguments as Mintlify `<ResponseField>` components, which show a name,
/// type and default without adding an API playground (as `<ParamField>`
/// would).
fn render_args(
    out: &mut String,
    ctx: &RenderContext<'_>,
    params: &[ParamDoc],
    item: Option<&DocItem>,
) {
    out.push_str("**Arguments**\n\n");
    let declared = item.and_then(|item| item.function.as_ref());
    for param in params {
        let signature = declared.and_then(|function| {
            function
                .parameters
                .iter()
                .find(|parameter| parameter.name == param.name)
        });
        let variadic = signature.is_some_and(|parameter| parameter.is_variadic);
        let name = format!("{}{}", if variadic { "*" } else { "" }, param.name);
        let _ = write!(out, "<ResponseField name={}", attribute(&name));
        if let Some(ty) = signature.and_then(|parameter| parameter.type_annotation.as_deref()) {
            let _ = write!(out, " type={}", attribute(ty));
        }
        if let Some(default) = signature.and_then(|parameter| parameter.default_value.as_deref()) {
            let _ = write!(out, " default={}", attribute(default));
        }
        out.push_str(">\n");
        render_blocks(out, ctx, &param.description);
        out.push_str("</ResponseField>\n\n");
    }
}

/// Examples are code unless they contain a fence or start with an indented
/// block (see the HTML renderer's `render_examples`).
fn render_examples(out: &mut String, ctx: &RenderContext<'_>, text: &str) {
    let has_fence = text
        .lines()
        .any(|line| line.trim_start().starts_with("```"));
    let starts_indented = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| indent_of(line) >= 4);
    if has_fence || starts_indented {
        render_blocks(out, ctx, text);
    } else {
        push_code_block(out, text, STOFFEL_FENCE_LANGUAGE);
    }
}

fn render_see_also(out: &mut String, ctx: &RenderContext<'_>, text: &str) {
    if !code_spans(text).is_empty() {
        render_blocks(out, ctx, text);
        return;
    }
    for name in text
        .split([',', '\n'])
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let _ = writeln!(
            out,
            "- {}",
            inline(ctx, &format!("`{name}`"), InlineContext::Block)
        );
    }
    out.push('\n');
}

/// The fence language for a docstring code block's info string.
fn fence_language(info: &str) -> &'static str {
    match info.trim().to_ascii_lowercase().as_str() {
        "" | "stoffel" | "stfl" | "stoffellang" | "python" | "py" => STOFFEL_FENCE_LANGUAGE,
        _ => "text",
    }
}

/// Converts block-level docstring text: paragraphs, bullet lists, fenced
/// code blocks and code indented by four or more spaces (MDX has no
/// indented code blocks, so those become fenced).
fn render_blocks(out: &mut String, ctx: &RenderContext<'_>, text: &str) {
    let lines: Vec<&str> = text.lines().collect();
    let mut paragraph: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();

        if let Some(info) = trimmed.strip_prefix("```") {
            flush_paragraph(out, ctx, &mut paragraph);
            let language = fence_language(info);
            let fence_indent = indent_of(line);
            let mut code = Vec::new();
            index += 1;
            while index < lines.len() && !lines[index].trim_start().starts_with("```") {
                code.push(strip_indent(lines[index], fence_indent));
                index += 1;
            }
            index += 1; // closing fence (or end of text)
            push_code_block(out, &code.join("\n"), language);
            continue;
        }

        if trimmed.is_empty() {
            flush_paragraph(out, ctx, &mut paragraph);
            index += 1;
            continue;
        }

        if paragraph.is_empty() && indent_of(line) >= 4 {
            let start = index;
            while index < lines.len()
                && (lines[index].trim().is_empty() || indent_of(lines[index]) >= 4)
            {
                index += 1;
            }
            let mut block = &lines[start..index];
            while block.last().is_some_and(|line| line.trim().is_empty()) {
                block = &block[..block.len() - 1];
            }
            let margin = block
                .iter()
                .filter(|line| !line.trim().is_empty())
                .map(|line| indent_of(line))
                .min()
                .unwrap_or(0);
            let code = block
                .iter()
                .map(|line| strip_indent(line, margin))
                .collect::<Vec<_>>()
                .join("\n");
            push_code_block(out, &code, STOFFEL_FENCE_LANGUAGE);
            continue;
        }

        if bullet_text(line).is_some() {
            flush_paragraph(out, ctx, &mut paragraph);
            while index < lines.len() {
                let Some(first) = bullet_text(lines[index]) else {
                    break;
                };
                let mut entry = vec![first];
                index += 1;
                while index < lines.len()
                    && !lines[index].trim().is_empty()
                    && bullet_text(lines[index]).is_none()
                    && indent_of(lines[index]) > 0
                {
                    entry.push(lines[index].trim());
                    index += 1;
                }
                let _ = writeln!(
                    out,
                    "- {}",
                    inline(ctx, &entry.join(" "), InlineContext::Block)
                );
            }
            out.push('\n');
            continue;
        }

        paragraph.push(trimmed.trim_end());
        index += 1;
    }
    flush_paragraph(out, ctx, &mut paragraph);
}

fn flush_paragraph(out: &mut String, ctx: &RenderContext<'_>, paragraph: &mut Vec<&str>) {
    if paragraph.is_empty() {
        return;
    }
    let _ = write!(
        out,
        "{}\n\n",
        inline(ctx, &paragraph.join(" "), InlineContext::Block)
    );
    paragraph.clear();
}

/// A fenced code block whose fence is longer than any backtick run inside.
fn push_code_block(out: &mut String, code: &str, language: &str) {
    let fence = "`".repeat(longest_backtick_run(code).max(2) + 1);
    let _ = write!(out, "{fence}{language}\n{}\n{fence}\n\n", code.trim_end());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_pages_nest_by_dotted_name() {
        assert_eq!(module_page_path("std.mpc"), "std/mpc");
        assert_eq!(module_page_path("utils.math ops"), "utils/math_ops");
        assert_eq!(module_page_path("a..b"), "a/_/b");
        assert_eq!(module_page_path("overview"), "overview_");
        assert_eq!(module_page_path("Overview"), "Overview_");
    }

    #[test]
    fn escaping_neutralizes_mdx_and_markdown_syntax() {
        let mut out = String::new();
        push_escaped(
            &mut out,
            "<script>alert(1)</script> {props.x} *a* _b_ [c](d) a|b & ~x~ ![i]",
        );
        assert_eq!(
            out,
            "\\<script\\>alert(1)\\</script\\> \\{props.x\\} \\*a\\* \\_b\\_ \\[c\\](d) a\\|b &amp; \\~x\\~ \\!\\[i\\]"
        );
    }

    #[test]
    fn line_starts_that_would_become_blocks_are_escaped() {
        assert_eq!(escape_line_start("1. one"), "1\\. one");
        assert_eq!(escape_line_start("12) two"), "12\\) two");
        assert_eq!(escape_line_start("+ plus"), "\\+ plus");
        assert_eq!(escape_line_start("- minus"), "\\- minus");
        assert_eq!(escape_line_start("-1 is negative"), "-1 is negative");
        assert_eq!(escape_line_start("=== rule"), "\\=== rule");
        assert_eq!(escape_line_start("plain"), "plain");
    }

    #[test]
    fn code_spans_survive_backticks_and_table_pipes() {
        assert_eq!(code_span("a`b", InlineContext::Block), "``a`b``");
        assert_eq!(code_span("`x", InlineContext::Block), "`` `x ``");
        assert_eq!(code_span("a | b", InlineContext::TableCell), "`a \\| b`");
    }

    #[test]
    fn attributes_escape_quotes_and_ampersands() {
        assert_eq!(
            attribute("say \"hi\" & bye"),
            "\"say &quot;hi&quot; &amp; bye\""
        );
    }

    #[test]
    fn code_blocks_outgrow_inner_fences() {
        let mut out = String::new();
        push_code_block(&mut out, "```\ninner\n```", "text");
        assert!(out.starts_with("````text\n"), "{out}");
        assert!(out.ends_with("\n````\n\n"), "{out}");
    }
}
