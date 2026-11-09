//! Static HTML renderer for `stoffel doc`.
//!
//! The site is self-contained: every page inlines its CSS and JavaScript,
//! and the only other file is `search-index.js`, loaded with a plain
//! `<script src>` so search also works from `file://`. Nothing is fetched
//! from a CDN.
//!
//! All text from sources and docstrings is HTML-escaped; raw HTML is never
//! passed through. The only links generated from docstring text point at
//! documented items or modules of this site.

use std::collections::HashSet;
use std::fmt::{self, Write as _};

use stoffel::docs::{
    code_spans, AliasOf, DocIndex, DocItem, DocItemKind, ModuleDoc, ParamDoc, ParsedDoc, Section,
};

use super::shared::{
    bullet_text, display_signature, indent_of, is_deprecated, json_string, receiver_call,
    strip_indent, AnchorSet, ItemGroup, OutputFile, Site, SiteKind,
};

/// File name of the site's landing page.
pub(super) const INDEX_PAGE: &str = "index.html";
/// File name of the generated client-side search index.
pub(super) const SEARCH_INDEX_FILE: &str = "search-index.js";

/// Keywords highlighted in signatures and code blocks.
const KEYWORDS: &[&str] = &[
    "and", "as", "assert", "break", "builtin", "continue", "def", "discard", "elif", "else",
    "enum", "for", "if", "import", "in", "mod", "not", "object", "opaque", "or", "pass", "return",
    "secret", "shl", "shr", "type", "var", "while", "xor",
];

/// Literal constants highlighted like keywords.
const CONSTANTS: &[&str] = &["True", "False", "None"];

/// Built-in type names that are always highlighted as types, even when the
/// site does not document them.
const PRIMITIVE_TYPES: &[&str] = &[
    "int", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "bool",
    "string", "float", "float64", "f64", "fixed", "fixed32", "fixed64", "fix32", "fix64", "bytes",
    "list", "dict", "void",
];

/// The page file name of a module: `std.mpc` gives `std.mpc.html`.
/// Characters outside `[A-Za-z0-9._-]` become `_`, and a module named
/// `index` does not overwrite the landing page.
pub(super) fn module_page_name(module: &str) -> String {
    let mut stem: String = module
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() || stem.starts_with('.') {
        stem.insert(0, '_');
    }
    if stem.eq_ignore_ascii_case("index") {
        stem.push('_');
    }
    format!("{stem}.html")
}

/// Renders the whole site: the index, one page per module and the search
/// index.
pub(super) fn render_site(site: &Site<'_>) -> Vec<OutputFile> {
    let ctx = RenderContext::new(site);
    let mut files = Vec::with_capacity(site.modules.len() + 2);
    files.push(OutputFile {
        name: INDEX_PAGE.to_string(),
        contents: render_index(&ctx),
    });
    for module in site.modules {
        files.push(OutputFile {
            name: module_page_name(&module.name),
            contents: render_module(&ctx, module),
        });
    }
    files.push(OutputFile {
        name: SEARCH_INDEX_FILE.to_string(),
        contents: render_search_index(&ctx),
    });
    files
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Displays text HTML-escaped, for both element content and attribute values.
struct Escaped<'a>(&'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0;
        while let Some(position) = rest.find(['&', '<', '>', '"', '\'']) {
            f.write_str(&rest[..position])?;
            let replacement = match rest.as_bytes()[position] {
                b'&' => "&amp;",
                b'<' => "&lt;",
                b'>' => "&gt;",
                b'"' => "&quot;",
                _ => "&#39;",
            };
            f.write_str(replacement)?;
            rest = &rest[position + 1..];
        }
        f.write_str(rest)
    }
}

// ---------------------------------------------------------------------------
// Rendering context and links
// ---------------------------------------------------------------------------

struct RenderContext<'a> {
    site: &'a Site<'a>,
    index: DocIndex<'a>,
    /// Names highlighted as types in signatures and code.
    type_names: HashSet<&'a str>,
}

impl<'a> RenderContext<'a> {
    fn new(site: &'a Site<'a>) -> Self {
        let type_names = PRIMITIVE_TYPES
            .iter()
            .copied()
            .chain(
                site.modules
                    .iter()
                    .flat_map(ModuleDoc::all_items)
                    .filter(|item| !item.kind.is_callable())
                    .map(|item| item.name.as_str()),
            )
            .collect();
        RenderContext {
            site,
            index: DocIndex::new(site.modules),
            type_names,
        }
    }

    fn item_href(module: &ModuleDoc, item: &DocItem) -> String {
        format!("{}#{}", module_page_name(&module.name), item.anchor())
    }

    fn module(&self, name: &str) -> Option<&'a ModuleDoc> {
        self.site.modules.iter().find(|module| module.name == name)
    }

    /// The link for a reference in docstring text: an item path (plain or
    /// module-qualified, optionally followed by `()`) or a module name.
    fn resolve(&self, target: &str) -> Option<String> {
        let target = target.strip_suffix("()").unwrap_or(target);
        if let Some(found) = self.index.resolve(target) {
            return Some(Self::item_href(found.module, found.item));
        }
        self.module(target)
            .map(|module| module_page_name(&module.name))
    }

    /// The link for a name used as a type: only non-callable items qualify.
    fn resolve_type(&self, name: &str) -> Option<String> {
        self.index
            .resolve(name)
            .filter(|found| !found.item.kind.is_callable())
            .map(|found| Self::item_href(found.module, found.item))
    }

    /// The link for a name used as a call.
    fn resolve_callable(&self, name: &str) -> Option<String> {
        self.index
            .resolve(name)
            .filter(|found| found.item.kind.is_callable())
            .map(|found| Self::item_href(found.module, found.item))
    }

    fn is_type_name(&self, name: &str) -> bool {
        self.type_names.contains(name) || name.starts_with(|c: char| c.is_ascii_uppercase())
    }
}

// ---------------------------------------------------------------------------
// Item grouping and labels
// ---------------------------------------------------------------------------

/// CSS class suffix for an item's kind badge.
fn kind_class(kind: DocItemKind) -> &'static str {
    match kind {
        DocItemKind::Function | DocItemKind::BuiltinFunction => "fn",
        DocItemKind::Method => "method",
        DocItemKind::BuiltinObject | DocItemKind::Object => "obj",
        DocItemKind::BuiltinType | DocItemKind::OpaqueType | DocItemKind::TypeAlias => "type",
        DocItemKind::Enum => "enum",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// Page shell
// ---------------------------------------------------------------------------

/// Which page is being rendered, for the sidebar.
enum Page<'a> {
    Index,
    Module(&'a ModuleDoc),
}

fn render_page(ctx: &RenderContext<'_>, page: &Page<'_>, page_title: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + STYLE.len() + SCRIPT.len() + 4096);
    let _ = write!(
        out,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n\
         <meta name=\"generator\" content=\"stoffel doc {version}\">\n\
         <title>{title}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n\
         <a class=\"skip-link\" href=\"#main\">Skip to content</a>\n<div class=\"layout\">\n",
        version = env!("CARGO_PKG_VERSION"),
        title = Escaped(page_title),
    );
    render_sidebar(&mut out, ctx, page);
    let _ = write!(
        out,
        "<main id=\"main\" tabindex=\"-1\">\n\
         <div id=\"search-results\" class=\"search-results\" hidden aria-live=\"polite\"></div>\n\
         <div id=\"page-content\">\n{body}</div>\n\
         <footer class=\"page-footer\">Generated by <code>stoffel doc</code> {version}</footer>\n\
         </main>\n</div>\n<script src=\"{SEARCH_INDEX_FILE}\"></script>\n<script>{SCRIPT}</script>\n\
         </body>\n</html>\n",
        version = env!("CARGO_PKG_VERSION"),
    );
    out
}

fn render_sidebar(out: &mut String, ctx: &RenderContext<'_>, page: &Page<'_>) {
    let subtitle = match ctx.site.kind {
        SiteKind::Stdlib => "Standard library reference",
        SiteKind::User => "API documentation",
    };
    let _ = write!(
        out,
        "<nav class=\"sidebar\" id=\"sidebar\" aria-label=\"Documentation\">\n\
         <div class=\"sidebar-top\">\n\
         <a class=\"brand\" href=\"{INDEX_PAGE}\"><span class=\"brand-mark\" aria-hidden=\"true\">S</span>\
         <span class=\"brand-text\"><span class=\"brand-title\">{title}</span>\
         <span class=\"brand-sub\">{subtitle}</span></span></a>\n\
         <button class=\"menu-toggle\" id=\"menu-toggle\" type=\"button\" aria-controls=\"sidebar-nav\" \
         aria-expanded=\"false\" aria-label=\"Toggle navigation\"><span></span><span></span><span></span></button>\n\
         </div>\n\
         <div class=\"search-box\"><input id=\"search\" type=\"search\" placeholder=\"Search docs  ( / )\" \
         autocomplete=\"off\" spellcheck=\"false\" aria-label=\"Search documentation\"></div>\n\
         <div class=\"sidebar-nav\" id=\"sidebar-nav\">\n",
        title = Escaped(ctx.site.title),
    );

    if let Page::Module(module) = page {
        let _ = writeln!(
            out,
            "<h2 class=\"nav-heading\">Module <a href=\"#\">{}</a></h2>",
            Escaped(&module.name)
        );
        for group in ItemGroup::ALL {
            let items: Vec<&DocItem> = module
                .items
                .iter()
                .filter(|item| ItemGroup::of(item.kind) == group)
                .collect();
            if items.is_empty() {
                continue;
            }
            let _ = write!(
                out,
                "<h3 class=\"nav-group\"><a href=\"#{}\">{}</a></h3>\n<ul class=\"nav-items\">\n",
                group.id(),
                group.title()
            );
            for item in items {
                if item.members.is_empty() {
                    let _ = writeln!(
                        out,
                        "<li><a href=\"#{}\">{}</a></li>",
                        Escaped(&item.anchor()),
                        Escaped(&item.name)
                    );
                } else {
                    let _ = write!(
                        out,
                        "<li><details><summary><a href=\"#{}\">{}</a> <span class=\"nav-count\">{}</span></summary>\n<ul>\n",
                        Escaped(&item.anchor()),
                        Escaped(&item.name),
                        item.members.len()
                    );
                    for member in &item.members {
                        let _ = writeln!(
                            out,
                            "<li><a href=\"#{}\">{}</a></li>",
                            Escaped(&member.anchor()),
                            Escaped(&member.name)
                        );
                    }
                    out.push_str("</ul></details></li>\n");
                }
            }
            out.push_str("</ul>\n");
        }
    }

    out.push_str("<h2 class=\"nav-heading\">Modules</h2>\n<ul class=\"nav-modules\">\n");
    for module in ctx.site.modules {
        let current = matches!(page, Page::Module(current) if current.name == module.name);
        let _ = writeln!(
            out,
            "<li><a href=\"{}\"{}>{}</a></li>",
            Escaped(&module_page_name(&module.name)),
            if current {
                " class=\"current\" aria-current=\"page\""
            } else {
                ""
            },
            Escaped(&module.name)
        );
    }
    out.push_str("</ul>\n</div>\n</nav>\n");
}

fn stdlib_banner(out: &mut String, module: Option<&ModuleDoc>) {
    let import = match module {
        Some(module) => format!("<code>import {}</code> is optional", Escaped(&module.name)),
        None => "importing <code>std.*</code> modules is optional".to_string(),
    };
    let _ = writeln!(
        out,
        "<div class=\"banner\"><strong>Always in scope.</strong> Standard library builtins are \
         available in every program; {import}.</div>"
    );
}

// ---------------------------------------------------------------------------
// Index page
// ---------------------------------------------------------------------------

fn render_index(ctx: &RenderContext<'_>) -> String {
    let mut body = String::new();
    let item_count: usize = ctx
        .site
        .modules
        .iter()
        .map(|module| module.all_items().count())
        .sum();
    let _ = write!(
        body,
        "<header class=\"page-head\">\n<div class=\"eyebrow\">{kind}</div>\n<h1>{title}</h1>\n\
         <p class=\"stats\">{modules} {module_word} &middot; {items} {item_word}</p>\n</header>\n",
        kind = match ctx.site.kind {
            SiteKind::Stdlib => "Standard library",
            SiteKind::User => "Documentation",
        },
        title = Escaped(ctx.site.title),
        modules = ctx.site.modules.len(),
        module_word = if ctx.site.modules.len() == 1 {
            "module"
        } else {
            "modules"
        },
        items = item_count,
        item_word = if item_count == 1 { "item" } else { "items" },
    );
    if ctx.site.kind == SiteKind::Stdlib {
        stdlib_banner(&mut body, None);
    }

    body.push_str(
        "<h2 class=\"section-heading\" id=\"modules\">Modules</h2>\n<div class=\"module-grid\">\n",
    );
    for module in ctx.site.modules {
        let count = module.all_items().count();
        let _ = write!(
            body,
            "<a class=\"module-card\" href=\"{page}\">\n<span class=\"module-card-head\">\
             <span class=\"module-name\">{name}</span><span class=\"module-count\">{count} {word}</span></span>\n",
            page = Escaped(&module_page_name(&module.name)),
            name = Escaped(&module.name),
            word = if count == 1 { "item" } else { "items" },
        );
        match module.doc.as_ref().map(|doc| doc.summary.as_str()) {
            Some(summary) if !summary.is_empty() => {
                // Card links cannot contain links, so summaries render code
                // spans without resolving them.
                body.push_str("<span class=\"module-summary\">");
                render_inline_plain(&mut body, summary);
                body.push_str("</span>\n");
            }
            _ => body
                .push_str("<span class=\"module-summary muted\">No module documentation.</span>\n"),
        }
        let _ = writeln!(
            body,
            "<span class=\"module-path\">{}</span>\n</a>",
            Escaped(&module.path)
        );
    }
    body.push_str("</div>\n");

    render_page(ctx, &Page::Index, ctx.site.title, &body)
}

// ---------------------------------------------------------------------------
// Module pages
// ---------------------------------------------------------------------------

fn render_module(ctx: &RenderContext<'_>, module: &ModuleDoc) -> String {
    let mut body = String::new();
    let _ = write!(
        body,
        "<nav class=\"breadcrumbs\" aria-label=\"Breadcrumb\"><a href=\"{INDEX_PAGE}\">{title}</a>\
         <span aria-hidden=\"true\">/</span><span>{name}</span></nav>\n\
         <header class=\"page-head\">\n<div class=\"eyebrow\">Module</div>\n\
         <h1 class=\"module-title\">{name}</h1>\n<p class=\"source-ref\">{path}</p>\n</header>\n",
        title = Escaped(ctx.site.title),
        name = Escaped(&module.name),
        path = Escaped(&module.path),
    );
    if ctx.site.kind == SiteKind::Stdlib {
        stdlib_banner(&mut body, Some(module));
    }
    match &module.doc {
        Some(doc) => render_doc(&mut body, ctx, doc, None),
        None => body.push_str("<p class=\"muted\">No module documentation.</p>\n"),
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
        body.push_str("<p class=\"muted\">This module declares no public items.</p>\n");
    }

    let mut anchors = AnchorSet::default();
    for group in ItemGroup::ALL {
        anchors.claim(group.id().to_string());
    }
    for (group, items) in &groups {
        let _ = write!(
            body,
            "<section class=\"item-group\">\n<h2 class=\"section-heading\" id=\"{id}\">{title}\
             <a class=\"heading-anchor\" href=\"#{id}\" aria-label=\"Link to {title}\">#</a></h2>\n",
            id = group.id(),
            title = group.title(),
        );
        render_summary_table(&mut body, items.iter().copied(), None);
        for item in items {
            render_item(&mut body, ctx, &mut anchors, item, None);
        }
        body.push_str("</section>\n");
    }

    let page_title = format!("{} - {}", module.name, ctx.site.title);
    render_page(ctx, &Page::Module(module), &page_title, &body)
}

/// A compact table of item names and summaries.
fn render_summary_table<'i>(
    out: &mut String,
    items: impl Iterator<Item = &'i DocItem>,
    container: Option<&DocItem>,
) {
    out.push_str("<div class=\"table-wrap\"><table class=\"summary-table\">\n<tbody>\n");
    for item in items {
        let label = match container {
            Some(_) => item.name.as_str(),
            None => item.path.as_str(),
        };
        let _ = write!(
            out,
            "<tr><td class=\"summary-name\"><a href=\"#{}\"><code>{}</code></a>",
            Escaped(&item.anchor()),
            Escaped(label)
        );
        if let Some(alias) = &item.alias_of {
            if !matches!(alias, AliasOf::Type(_)) {
                out.push_str(" <span class=\"tag tag-alias\">alias</span>");
            }
        }
        if is_deprecated(item) {
            out.push_str(" <span class=\"tag tag-deprecated\">deprecated</span>");
        }
        out.push_str("</td><td class=\"summary-doc\">");
        match item.summary() {
            Some(summary) if !summary.is_empty() => render_inline_plain(out, summary),
            _ => out.push_str("<span class=\"muted\">Undocumented</span>"),
        }
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody>\n</table></div>\n");
}

fn render_item(
    out: &mut String,
    ctx: &RenderContext<'_>,
    anchors: &mut AnchorSet,
    item: &DocItem,
    container: Option<&DocItem>,
) {
    let anchor = anchors.claim(item.anchor());
    let classes = if container.is_some() {
        "item item-member"
    } else {
        "item"
    };
    let heading = if container.is_some() { "h4" } else { "h3" };
    let _ = write!(
        out,
        "<article class=\"{classes}\" id=\"{anchor}\">\n<div class=\"item-head\">\n\
         <span class=\"badge badge-{kind_class}\">{kind}</span>\n\
         <{heading} class=\"item-name\"><a href=\"#{anchor}\">{name}</a></{heading}>\n",
        anchor = Escaped(&anchor),
        kind_class = kind_class(item.kind),
        kind = Escaped(item.kind.label()),
        name = Escaped(&item.name),
    );
    if item.is_private() {
        out.push_str("<span class=\"tag tag-private\">private</span>\n");
    }
    if is_deprecated(item) {
        out.push_str("<span class=\"tag tag-deprecated\">deprecated</span>\n");
    }
    let _ = write!(
        out,
        "<span class=\"source-ref item-source\" title=\"Declared at\">{}:{}</span>\n</div>\n",
        Escaped(&item.location.file),
        item.location.line
    );

    let _ = writeln!(
        out,
        "<pre class=\"signature\"><code>{}</code></pre>",
        highlight(
            ctx,
            &display_signature(item),
            HighlightMode::Signature { name: &item.name }
        )
    );

    render_item_facts(out, ctx, item);

    match &item.doc {
        Some(doc) => render_doc(out, ctx, doc, Some(item)),
        None => out.push_str("<p class=\"muted undocumented\">No documentation.</p>\n"),
    }

    if !item.members.is_empty() {
        let _ = write!(
            out,
            "<div class=\"members\">\n<h4 class=\"members-heading\">Methods <span class=\"nav-count\">{}</span></h4>\n",
            item.members.len()
        );
        render_summary_table(out, item.members.iter(), Some(item));
        for member in &item.members {
            render_item(out, ctx, anchors, member, Some(item));
        }
        out.push_str("</div>\n");
    }
    out.push_str("</article>\n");
}

/// Alias, VM binding and UFCS facts shown under the signature.
fn render_item_facts(out: &mut String, ctx: &RenderContext<'_>, item: &DocItem) {
    let mut facts: Vec<String> = Vec::new();
    match &item.alias_of {
        Some(AliasOf::Item(target)) => facts.push(format!(
            "<span class=\"fact-label\">Alias of</span> {}",
            code_link(ctx.resolve(target).as_deref(), target)
        )),
        Some(AliasOf::VmBuiltin(symbol)) => facts.push(format!(
            "<span class=\"fact-label\">Alias of VM builtin</span> <code>{}</code>",
            Escaped(symbol)
        )),
        Some(AliasOf::Type(target)) => facts.push(format!(
            "<span class=\"fact-label\">Alias of</span> <code>{}</code>",
            highlight(ctx, target, HighlightMode::Code)
        )),
        Some(other) => facts.push(format!(
            "<span class=\"fact-label\">Alias of</span> <code>{}</code>",
            Escaped(other.target())
        )),
        None => {}
    }
    let shows_vm_symbol = !matches!(
        item.alias_of,
        Some(AliasOf::VmBuiltin(_)) | Some(AliasOf::Item(_))
    );
    if let (Some(symbol), true) = (&item.vm_symbol, shows_vm_symbol) {
        facts.push(format!(
            "<span class=\"fact-label\">VM builtin:</span> <code>{}</code>",
            Escaped(symbol)
        ));
    }
    if let Some(call) = receiver_call(item) {
        facts.push(format!(
            "<span class=\"fact-label\">Callable as</span> <code>{}</code>",
            highlight(ctx, &call, HighlightMode::Code)
        ));
    }
    if facts.is_empty() {
        return;
    }
    out.push_str("<ul class=\"facts\">\n");
    for fact in facts {
        let _ = writeln!(out, "<li>{fact}</li>");
    }
    out.push_str("</ul>\n");
}

fn code_link(href: Option<&str>, text: &str) -> String {
    match href {
        Some(href) => format!(
            "<a class=\"code-link\" href=\"{}\"><code>{}</code></a>",
            Escaped(href),
            Escaped(text)
        ),
        None => format!("<code>{}</code>", Escaped(text)),
    }
}

// ---------------------------------------------------------------------------
// Docstrings
// ---------------------------------------------------------------------------

fn render_doc(out: &mut String, ctx: &RenderContext<'_>, doc: &ParsedDoc, item: Option<&DocItem>) {
    out.push_str("<div class=\"docblock\">\n");
    if !doc.summary.is_empty() {
        out.push_str("<p class=\"summary\">");
        render_inline(out, ctx, &doc.summary);
        out.push_str("</p>\n");
    }
    render_blocks(out, ctx, &doc.body);
    for section in &doc.sections {
        render_section(out, ctx, section, item);
    }
    out.push_str("</div>\n");
}

fn render_section(
    out: &mut String,
    ctx: &RenderContext<'_>,
    section: &Section,
    item: Option<&DocItem>,
) {
    match section {
        Section::Args(params) => render_args(out, ctx, params, item),
        Section::Mpc(text) => render_callout(out, ctx, "mpc", "MPC cost", MPC_ICON, text),
        Section::Notes(text) => render_callout(out, ctx, "note", "Note", NOTE_ICON, text),
        Section::Deprecated(text) => {
            render_callout(out, ctx, "deprecated", "Deprecated", WARNING_ICON, text)
        }
        Section::Examples(text) => {
            section_heading(out, "Examples");
            render_examples(out, ctx, text);
        }
        Section::SeeAlso(text) => {
            section_heading(out, "See also");
            render_see_also(out, ctx, text);
        }
        Section::Returns(text) => {
            section_heading(out, "Returns");
            if let Some(return_type) = item
                .and_then(|item| item.function.as_ref())
                .and_then(|function| function.return_type.as_deref())
            {
                let _ = writeln!(
                    out,
                    "<p class=\"returns-type\"><code>{}</code></p>",
                    highlight(ctx, return_type, HighlightMode::Code)
                );
            }
            render_blocks(out, ctx, text);
        }
        other => {
            section_heading(out, other.title());
            if let Some(text) = other.text() {
                render_blocks(out, ctx, text);
            }
        }
    }
}

fn section_heading(out: &mut String, title: &str) {
    let _ = writeln!(out, "<h5 class=\"doc-section\">{}</h5>", Escaped(title));
}

fn render_callout(
    out: &mut String,
    ctx: &RenderContext<'_>,
    class: &str,
    title: &str,
    icon: &str,
    text: &str,
) {
    let _ = write!(
        out,
        "<aside class=\"callout callout-{class}\">\n<div class=\"callout-title\">{icon}<span>{}</span></div>\n",
        Escaped(title)
    );
    render_blocks(out, ctx, text);
    out.push_str("</aside>\n");
}

fn render_args(
    out: &mut String,
    ctx: &RenderContext<'_>,
    params: &[ParamDoc],
    item: Option<&DocItem>,
) {
    section_heading(out, "Arguments");
    let declared = item.and_then(|item| item.function.as_ref());
    out.push_str(
        "<div class=\"table-wrap\"><table class=\"args-table\">\n<thead><tr><th scope=\"col\">Name</th>\
         <th scope=\"col\">Type</th><th scope=\"col\">Description</th></tr></thead>\n<tbody>\n",
    );
    for param in params {
        let signature = declared.and_then(|function| {
            function
                .parameters
                .iter()
                .find(|parameter| parameter.name == param.name)
        });
        let variadic = signature.is_some_and(|parameter| parameter.is_variadic);
        let _ = write!(
            out,
            "<tr><td class=\"arg-name\"><code>{}{}</code></td><td class=\"arg-type\">",
            if variadic { "*" } else { "" },
            Escaped(&param.name)
        );
        match signature.and_then(|parameter| parameter.type_annotation.as_deref()) {
            Some(ty) => {
                let _ = write!(
                    out,
                    "<code>{}</code>",
                    highlight(ctx, ty, HighlightMode::Code)
                );
            }
            None => out.push_str("<span class=\"muted\">&mdash;</span>"),
        }
        if let Some(default) = signature.and_then(|parameter| parameter.default_value.as_deref()) {
            let _ = write!(
                out,
                "<div class=\"arg-default\">default <code>{}</code></div>",
                highlight(ctx, default, HighlightMode::Code)
            );
        }
        out.push_str("</td><td class=\"arg-doc\">");
        render_blocks(out, ctx, &param.description);
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody>\n</table></div>\n");
}

/// Examples are code. The section is only treated as structured text (prose
/// plus fenced or indented code blocks) when it contains a ``` fence or when
/// its first line is itself an indented code block. Otherwise the whole
/// section renders as one highlighted code block, however deeply the example
/// nests: an unindented first line followed by deeper lines is one program,
/// not a paragraph followed by code.
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
        render_code_block(out, ctx, text, CodeLanguage::Stoffel);
    }
}

/// `See Also:` entries: with code spans the text renders normally (spans
/// become links); otherwise comma- or line-separated names become links.
fn render_see_also(out: &mut String, ctx: &RenderContext<'_>, text: &str) {
    if !code_spans(text).is_empty() {
        render_blocks(out, ctx, text);
        return;
    }
    let names: Vec<&str> = text
        .split([',', '\n'])
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    out.push_str("<ul class=\"see-also\">\n");
    for name in names {
        let _ = writeln!(
            out,
            "<li>{}</li>",
            code_link(ctx.resolve(name).as_deref(), name)
        );
    }
    out.push_str("</ul>\n");
}

/// Language of a code block, from its fence info string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeLanguage {
    /// StoffelLang (the default), highlighted.
    Stoffel,
    /// Anything else, shown as plain text.
    Plain,
}

impl CodeLanguage {
    fn from_info(info: &str) -> Self {
        match info.trim().to_ascii_lowercase().as_str() {
            "" | "stoffel" | "stfl" | "stoffellang" | "python" | "py" => CodeLanguage::Stoffel,
            _ => CodeLanguage::Plain,
        }
    }
}

/// Renders block-level text: paragraphs, bullet lists, fenced code blocks
/// and code indented by four or more spaces.
fn render_blocks(out: &mut String, ctx: &RenderContext<'_>, text: &str) {
    let lines: Vec<&str> = text.lines().collect();
    let mut paragraph: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();

        if let Some(info) = trimmed.strip_prefix("```") {
            flush_paragraph(out, ctx, &mut paragraph);
            let language = CodeLanguage::from_info(info);
            let fence_indent = indent_of(line);
            let mut code = Vec::new();
            index += 1;
            while index < lines.len() && !lines[index].trim_start().starts_with("```") {
                code.push(strip_indent(lines[index], fence_indent));
                index += 1;
            }
            index += 1; // closing fence (or end of text)
            render_code_block(out, ctx, &code.join("\n"), language);
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
            render_code_block(out, ctx, &code, CodeLanguage::Stoffel);
            continue;
        }

        if bullet_text(line).is_some() {
            flush_paragraph(out, ctx, &mut paragraph);
            out.push_str("<ul>\n");
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
                out.push_str("<li>");
                render_inline(out, ctx, &entry.join(" "));
                out.push_str("</li>\n");
            }
            out.push_str("</ul>\n");
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
    out.push_str("<p>");
    render_inline(out, ctx, &paragraph.join(" "));
    out.push_str("</p>\n");
    paragraph.clear();
}

fn render_code_block(
    out: &mut String,
    ctx: &RenderContext<'_>,
    code: &str,
    language: CodeLanguage,
) {
    out.push_str("<pre class=\"code-block\"><code>");
    match language {
        CodeLanguage::Stoffel => out.push_str(&highlight(ctx, code, HighlightMode::Code)),
        CodeLanguage::Plain => {
            let _ = write!(out, "{}", Escaped(code));
        }
    }
    out.push_str("</code></pre>\n");
}

/// Renders inline text: backtick spans become `<code>`, and spans naming a
/// documented item or module become links. Everything else is escaped.
fn render_inline(out: &mut String, ctx: &RenderContext<'_>, text: &str) {
    render_inline_with(out, text, |out, span| {
        out.push_str(&code_link(ctx.resolve(span).as_deref(), span));
    });
}

/// Like [`render_inline`] but never links (for text inside links).
fn render_inline_plain(out: &mut String, text: &str) {
    render_inline_with(out, text, |out, span| {
        let _ = write!(out, "<code>{}</code>", Escaped(span));
    });
}

fn render_inline_with(out: &mut String, text: &str, mut code: impl FnMut(&mut String, &str)) {
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        let span = &after[..close];
        let _ = write!(out, "{}", Escaped(&rest[..open]));
        if span.is_empty() {
            out.push_str("``");
        } else {
            code(out, span);
        }
        rest = &after[close + 1..];
    }
    let _ = write!(out, "{}", Escaped(rest));
}

// ---------------------------------------------------------------------------
// Syntax highlighting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HighlightMode<'a> {
    /// Code blocks, type expressions and defaults.
    Code,
    /// An item signature; the first occurrence of `name` is the item name.
    Signature { name: &'a str },
}

/// Token classes, mapped to CSS classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenClass {
    Keyword,
    Constant,
    Type,
    Function,
    ItemName,
    Param,
    String,
    Number,
    Comment,
}

impl TokenClass {
    fn css(self) -> &'static str {
        match self {
            TokenClass::Keyword => "kw",
            TokenClass::Constant => "cn",
            TokenClass::Type => "ty",
            TokenClass::Function => "fn",
            TokenClass::ItemName => "nm",
            TokenClass::Param => "pa",
            TokenClass::String => "st",
            TokenClass::Number => "nu",
            TokenClass::Comment => "cm",
        }
    }
}

fn push_token(out: &mut String, class: TokenClass, text: &str, href: Option<&str>) {
    match href {
        Some(href) => {
            let _ = write!(
                out,
                "<a class=\"{} tok-link\" href=\"{}\">{}</a>",
                class.css(),
                Escaped(href),
                Escaped(text)
            );
        }
        None => {
            let _ = write!(
                out,
                "<span class=\"{}\">{}</span>",
                class.css(),
                Escaped(text)
            );
        }
    }
}

/// Lightweight StoffelLang highlighter. It never fails: anything it does not
/// recognize is emitted as escaped text.
fn highlight(ctx: &RenderContext<'_>, text: &str, mode: HighlightMode<'_>) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    let mut name_pending = matches!(mode, HighlightMode::Signature { .. });
    let mut position = 0;
    while position < text.len() {
        let rest = &text[position..];
        let Some(c) = rest.chars().next() else {
            break;
        };

        if c == '#' && mode == HighlightMode::Code {
            let end = rest.find('\n').unwrap_or(rest.len());
            push_token(&mut out, TokenClass::Comment, &rest[..end], None);
            position += end;
            continue;
        }

        if c == '"' {
            let end = string_literal_end(rest);
            push_token(&mut out, TokenClass::String, &rest[..end], None);
            position += end;
            continue;
        }

        if c.is_ascii_digit() {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(rest.len());
            push_token(&mut out, TokenClass::Number, &rest[..end], None);
            position += end;
            continue;
        }

        if c.is_alphabetic() || c == '_' {
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let word = &rest[..end];
            let after = rest[end..].trim_start_matches(' ');
            let before = text[..position].trim_end_matches(' ');
            let (class, href) = classify_word(ctx, mode, word, before, after, &mut name_pending);
            match class {
                Some(class) => push_token(&mut out, class, word, href.as_deref()),
                None => {
                    let _ = write!(out, "{}", Escaped(word));
                }
            }
            position += end;
            continue;
        }

        let mut buffer = [0u8; 4];
        let _ = write!(out, "{}", Escaped(c.encode_utf8(&mut buffer)));
        position += c.len_utf8();
    }
    out
}

fn classify_word(
    ctx: &RenderContext<'_>,
    mode: HighlightMode<'_>,
    word: &str,
    before: &str,
    after: &str,
    name_pending: &mut bool,
) -> (Option<TokenClass>, Option<String>) {
    if let HighlightMode::Signature { name } = mode {
        // The item name wins over keywords (`def type[T](...)`), except as
        // the first token, which is the declaration keyword itself.
        if *name_pending && word == name && !before.is_empty() {
            *name_pending = false;
            return (Some(TokenClass::ItemName), None);
        }
    }
    if KEYWORDS.contains(&word) {
        return (Some(TokenClass::Keyword), None);
    }
    if CONSTANTS.contains(&word) {
        return (Some(TokenClass::Constant), None);
    }
    if matches!(mode, HighlightMode::Signature { .. })
        && after.starts_with(':')
        && !before.ends_with(':')
    {
        return (Some(TokenClass::Param), None);
    }
    let member_access = before.ends_with('.');
    if !member_access && ctx.is_type_name(word) {
        return (Some(TokenClass::Type), ctx.resolve_type(word));
    }
    if after.starts_with('(') {
        let href = match (mode, member_access) {
            (HighlightMode::Code, false) => ctx.resolve_callable(word),
            _ => None,
        };
        return (Some(TokenClass::Function), href);
    }
    (None, None)
}

/// Byte length of the string literal at the start of `text` (which starts
/// with `"`), including its quotes. Handles `"""` and escapes; an
/// unterminated literal ends at the line end.
fn string_literal_end(text: &str) -> usize {
    if let Some(body) = text.strip_prefix("\"\"\"") {
        return body.find("\"\"\"").map_or(text.len(), |close| close + 6);
    }
    let mut escaped = false;
    for (offset, c) in text.char_indices().skip(1) {
        match c {
            '\n' => return offset,
            '"' if !escaped => return offset + 1,
            '\\' if !escaped => escaped = true,
            _ => escaped = false,
        }
    }
    text.len()
}

// ---------------------------------------------------------------------------
// Search index
// ---------------------------------------------------------------------------

fn render_search_index(ctx: &RenderContext<'_>) -> String {
    let mut out = String::from("window.STOFFEL_DOC_INDEX = [\n");
    for module in ctx.site.modules {
        let page = module_page_name(&module.name);
        let summary = module
            .doc
            .as_ref()
            .map(|doc| doc.summary.as_str())
            .unwrap_or("");
        push_search_entry(
            &mut out,
            &module.name,
            &module.name,
            "module",
            "",
            summary,
            &page,
        );
        for item in module.all_items() {
            push_search_entry(
                &mut out,
                &item.name,
                &item.path,
                item.kind.label(),
                &module.name,
                item.summary().unwrap_or(""),
                &RenderContext::item_href(module, item),
            );
        }
    }
    out.push_str("];\n");
    out
}

fn push_search_entry(
    out: &mut String,
    name: &str,
    path: &str,
    kind: &str,
    module: &str,
    summary: &str,
    url: &str,
) {
    let _ = writeln!(
        out,
        "{{\"n\":{},\"p\":{},\"k\":{},\"m\":{},\"s\":{},\"u\":{}}},",
        json_string(name),
        json_string(path),
        json_string(kind),
        json_string(module),
        json_string(summary),
        json_string(url)
    );
}

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

const MPC_ICON: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"5\" r=\"2.5\"/><circle cx=\"5\" cy=\"18\" r=\"2.5\"/><circle cx=\"19\" cy=\"18\" r=\"2.5\"/><path d=\"M12 7.5 6.3 15.8M12 7.5l5.7 8.3M7.5 18h9\" fill=\"none\"/></svg>";
const NOTE_ICON: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"9\" fill=\"none\"/><path d=\"M12 11v6M12 7.5v.5\" fill=\"none\"/></svg>";
const WARNING_ICON: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 3 2.5 20h19z\" fill=\"none\"/><path d=\"M12 10v4.5M12 17v.5\" fill=\"none\"/></svg>";

const STYLE: &str = r#"
:root{
  --bg:#ffffff;--bg-soft:#f7f8fa;--sidebar:#f3f4f7;--fg:#1b2130;--fg-soft:#3b4456;--muted:#667085;
  --border:#e3e6ec;--border-strong:#cfd4dc;--link:#2f5bd3;--link-hover:#1d3fa3;--accent:#6b4eff;
  --code-bg:#f1f3f7;--code-fg:#1b2130;--sig-bg:#f6f7fb;--target:#fff6d6;--target-border:#e8b600;
  --kw:#8f2fb8;--cn:#b3421f;--ty:#0f7a6a;--fn:#9a5b00;--nm:#2f5bd3;--pa:#3b4456;--st:#23802f;--nu:#b3421f;--cm:#8a93a3;
  --b-fn-bg:#e6edff;--b-fn-fg:#2447a8;--b-method-bg:#e8f1ff;--b-method-fg:#1f5c9e;--b-obj-bg:#efe8ff;--b-obj-fg:#5a36c9;
  --b-type-bg:#e1f5f0;--b-type-fg:#0b6b5c;--b-enum-bg:#fff0de;--b-enum-fg:#9a4f00;--b-other-bg:#eceef2;--b-other-fg:#475064;
  --mpc-bg:#f4f0ff;--mpc-border:#7b5cff;--mpc-fg:#4a2fc0;--note-bg:#eef5ff;--note-border:#3d7be0;--note-fg:#1f4f9c;
  --dep-bg:#fff6e5;--dep-border:#e39a00;--dep-fg:#8a5500;--banner-bg:#eef8f4;--banner-border:#2f9e74;
  --shadow:0 1px 2px rgba(16,24,40,.05);
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#12151c;--bg-soft:#181c25;--sidebar:#161a22;--fg:#e4e7ee;--fg-soft:#c3c9d5;--muted:#8d96a8;
  --border:#262c38;--border-strong:#343c4c;--link:#8fb0ff;--link-hover:#b7cbff;--accent:#a390ff;
  --code-bg:#1d222d;--code-fg:#e4e7ee;--sig-bg:#181d27;--target:#2b2716;--target-border:#b89412;
  --kw:#d49cf5;--cn:#f5a97f;--ty:#6fd6c2;--fn:#f0c674;--nm:#8fb0ff;--pa:#c3c9d5;--st:#9bd88f;--nu:#f5a97f;--cm:#6f788b;
  --b-fn-bg:#1f2a4a;--b-fn-fg:#a9c1ff;--b-method-bg:#1c2b43;--b-method-fg:#9cc4f5;--b-obj-bg:#2a2145;--b-obj-fg:#c7b6ff;
  --b-type-bg:#15332d;--b-type-fg:#7fdcc9;--b-enum-bg:#3a2a14;--b-enum-fg:#f3c07a;--b-other-bg:#262b36;--b-other-fg:#b5bdcc;
  --mpc-bg:#211c38;--mpc-border:#8d74ff;--mpc-fg:#c8baff;--note-bg:#172338;--note-border:#4f8ae8;--note-fg:#a9c8ff;
  --dep-bg:#2d2412;--dep-border:#d69a1c;--dep-fg:#f3cf85;--banner-bg:#15291f;--banner-border:#3bb487;
  --shadow:none;
}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-padding-top:16px}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 var(--sans)}
a{color:var(--link);text-decoration:none}
a:hover{color:var(--link-hover);text-decoration:underline}
a.code-link code{color:var(--link);background:color-mix(in srgb,var(--link) 9%,var(--code-bg))}
a.code-link:hover code{text-decoration:underline}
code,pre{font-family:var(--mono);font-size:.9em}
code{background:var(--code-bg);color:var(--code-fg);padding:.1em .35em;border-radius:4px;overflow-wrap:anywhere}
pre code{background:none;padding:0;border-radius:0;overflow-wrap:normal}
.skip-link{position:absolute;left:-999px;top:8px;background:var(--bg);padding:6px 10px;border:1px solid var(--border);border-radius:6px;z-index:50}
.skip-link:focus{left:8px}
.layout{display:grid;grid-template-columns:290px minmax(0,1fr);min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;overflow-y:auto;background:var(--sidebar);border-right:1px solid var(--border);padding:20px 16px 32px}
.sidebar-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.brand{display:flex;align-items:center;gap:10px;color:var(--fg);min-width:0}
.brand:hover{text-decoration:none;color:var(--fg)}
.brand-mark{flex:none;display:inline-grid;place-items:center;width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--accent),var(--link));color:#fff;font-weight:700;font-size:17px}
.brand-text{display:flex;flex-direction:column;min-width:0}
.brand-title{font-weight:650;line-height:1.25;overflow-wrap:anywhere}
.brand-sub{font-size:12px;color:var(--muted)}
.menu-toggle{display:none;flex:none;flex-direction:column;justify-content:center;gap:4px;width:38px;height:38px;border:1px solid var(--border-strong);border-radius:8px;background:var(--bg);cursor:pointer;padding:0 9px}
.menu-toggle span{display:block;height:2px;background:var(--fg-soft);border-radius:2px}
.search-box{margin:16px 0 8px}
.search-box input{width:100%;font:inherit;font-size:14px;padding:8px 11px;border:1px solid var(--border-strong);border-radius:8px;background:var(--bg);color:var(--fg);outline:none}
.search-box input:focus{border-color:var(--link);box-shadow:0 0 0 3px color-mix(in srgb,var(--link) 22%,transparent)}
.nav-heading{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:22px 0 6px;font-weight:650}
.nav-heading a{color:var(--fg);text-transform:none;letter-spacing:0;font-size:14px;font-family:var(--mono)}
.nav-group{font-size:13px;margin:14px 0 4px;font-weight:650}
.nav-group a{color:var(--fg-soft)}
.sidebar ul{list-style:none;margin:0;padding:0}
.sidebar li a{display:block;padding:2px 8px;border-radius:6px;font-family:var(--mono);font-size:13px;color:var(--fg-soft);overflow-wrap:anywhere}
.sidebar li a:hover{background:var(--bg-soft);text-decoration:none;color:var(--link)}
.sidebar li a.current{background:var(--bg);color:var(--link);font-weight:600;box-shadow:inset 3px 0 0 var(--link)}
.sidebar details summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:4px;border-radius:6px}
.sidebar details summary::-webkit-details-marker{display:none}
.sidebar details summary::before{content:"";flex:none;width:6px;height:6px;margin:0 3px 0 4px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:rotate(-45deg);transition:transform .15s}
.sidebar details[open] summary::before{transform:rotate(45deg)}
.sidebar details summary a{flex:1}
.sidebar details ul{margin-left:14px;border-left:1px solid var(--border);padding-left:4px}
.nav-count{font-size:11px;color:var(--muted);font-family:var(--sans);font-weight:500;background:var(--bg-soft);border:1px solid var(--border);border-radius:10px;padding:0 6px}
main{padding:36px 56px 64px;max-width:1040px;width:100%;outline:none}
.breadcrumbs{font-size:13px;color:var(--muted);display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.page-head{margin-bottom:20px}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);font-weight:650}
h1{font-size:30px;line-height:1.2;margin:4px 0 6px;overflow-wrap:anywhere}
.module-title{font-family:var(--mono);font-size:28px}
.stats,.source-ref{color:var(--muted);font-size:13px;margin:0;font-family:var(--mono);overflow-wrap:anywhere}
.stats{font-family:var(--sans)}
.muted{color:var(--muted)}
.banner{background:var(--banner-bg);border:1px solid color-mix(in srgb,var(--banner-border) 35%,transparent);border-left:4px solid var(--banner-border);border-radius:8px;padding:10px 14px;margin:16px 0 20px;font-size:14px}
.section-heading{font-size:21px;margin:40px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border);display:flex;align-items:baseline;gap:8px}
.heading-anchor{font-size:16px;color:var(--muted);opacity:0}
.section-heading:hover .heading-anchor{opacity:1}
.module-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.module-card{display:flex;flex-direction:column;gap:6px;padding:16px 18px;border:1px solid var(--border);border-radius:12px;background:var(--bg);color:var(--fg);box-shadow:var(--shadow);transition:border-color .15s,transform .15s}
.module-card:hover{text-decoration:none;color:var(--fg);border-color:var(--link);transform:translateY(-1px)}
.module-card-head{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.module-name{font-family:var(--mono);font-weight:650;color:var(--link);overflow-wrap:anywhere}
.module-count{font-size:12px;color:var(--muted);white-space:nowrap}
.module-summary{font-size:14px;color:var(--fg-soft)}
.module-path{font-size:12px;color:var(--muted);font-family:var(--mono);margin-top:auto}
.table-wrap{overflow-x:auto;margin:8px 0 16px}
table{border-collapse:collapse;width:100%;font-size:14px}
.summary-table td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
.summary-table tr:last-child td{border-bottom:0}
.summary-name{width:32%;overflow-wrap:anywhere}
.summary-name code{background:none;padding:0;color:var(--link);font-weight:600}
.summary-doc{color:var(--fg-soft)}
.item{border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin:18px 0;background:var(--bg);box-shadow:var(--shadow);scroll-margin-top:16px}
.item:target,.item-member:target{border-color:var(--target-border);background:var(--target);box-shadow:0 0 0 3px color-mix(in srgb,var(--target-border) 25%,transparent)}
.item-member{margin:14px 0 0;padding:14px 16px;border-radius:10px;background:var(--bg-soft);box-shadow:none}
.item-head{display:flex;align-items:center;flex-wrap:wrap;gap:8px 10px}
.item-name{margin:0;font-family:var(--mono);font-size:18px;font-weight:650;overflow-wrap:anywhere}
.item-member .item-name{font-size:16px}
.item-name a{color:var(--fg)}
.item-name a:hover{color:var(--link)}
.item-source{margin-left:auto;font-size:12px}
.badge{display:inline-block;font-size:11px;font-weight:650;letter-spacing:.02em;padding:2px 8px;border-radius:999px;white-space:nowrap}
.badge-fn{background:var(--b-fn-bg);color:var(--b-fn-fg)}
.badge-method{background:var(--b-method-bg);color:var(--b-method-fg)}
.badge-obj{background:var(--b-obj-bg);color:var(--b-obj-fg)}
.badge-type{background:var(--b-type-bg);color:var(--b-type-fg)}
.badge-enum{background:var(--b-enum-bg);color:var(--b-enum-fg)}
.badge-other{background:var(--b-other-bg);color:var(--b-other-fg)}
.tag{font-size:11px;font-weight:600;padding:1px 7px;border-radius:6px;border:1px solid var(--border-strong);color:var(--muted);white-space:nowrap}
.tag-deprecated{border-color:var(--dep-border);color:var(--dep-fg);background:var(--dep-bg)}
.tag-alias{border-color:var(--border-strong)}
.signature{margin:12px 0 10px;padding:12px 14px;background:var(--sig-bg);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.5;font-size:14px}
.code-block{margin:10px 0 14px;padding:12px 14px;background:var(--code-bg);border:1px solid var(--border);border-radius:8px;overflow-x:auto;line-height:1.5}
.kw{color:var(--kw);font-weight:600}.cn{color:var(--cn)}.ty{color:var(--ty)}.fn{color:var(--fn)}.nm{color:var(--nm);font-weight:700}
.pa{color:var(--pa)}.st{color:var(--st)}.nu{color:var(--nu)}.cm{color:var(--cm);font-style:italic}
a.tok-link{text-decoration:underline dotted;text-underline-offset:3px}
a.tok-link:hover{text-decoration:underline}
.facts{list-style:none;display:flex;flex-wrap:wrap;gap:6px 18px;margin:0 0 8px;padding:0;font-size:13px;color:var(--fg-soft)}
.fact-label{color:var(--muted)}
.docblock{margin-top:6px}
.docblock p{margin:8px 0}
.docblock .summary{font-size:15.5px;color:var(--fg)}
.docblock ul{padding-left:22px;margin:8px 0}
.doc-section{font-size:12px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin:18px 0 6px;font-weight:700}
.returns-type{margin:4px 0}
.args-table th{text-align:left;font-size:12px;color:var(--muted);font-weight:650;padding:6px 10px;border-bottom:1px solid var(--border-strong)}
.args-table td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
.args-table td p{margin:0 0 4px}
.args-table td p:last-child{margin-bottom:0}
.arg-name{white-space:nowrap;width:1%}
.arg-name code{font-weight:650}
.arg-type{width:1%;white-space:nowrap}
.arg-default{font-size:12px;color:var(--muted);margin-top:2px}
.args-table code,.facts code{overflow-wrap:normal}
.callout{border-radius:8px;padding:10px 14px;margin:14px 0;border:1px solid;border-left-width:4px}
.callout p{margin:4px 0}
.callout-title{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:2px}
.callout-title svg{width:16px;height:16px;stroke:currentColor;stroke-width:2;stroke-linecap:round;fill:currentColor}
.callout-title svg path,.callout-title svg circle[fill=none]{fill:none}
.callout-mpc{background:var(--mpc-bg);border-color:color-mix(in srgb,var(--mpc-border) 35%,transparent);border-left-color:var(--mpc-border)}
.callout-mpc .callout-title{color:var(--mpc-fg)}
.callout-note{background:var(--note-bg);border-color:color-mix(in srgb,var(--note-border) 35%,transparent);border-left-color:var(--note-border)}
.callout-note .callout-title{color:var(--note-fg)}
.callout-deprecated{background:var(--dep-bg);border-color:color-mix(in srgb,var(--dep-border) 35%,transparent);border-left-color:var(--dep-border)}
.callout-deprecated .callout-title{color:var(--dep-fg)}
.see-also{padding-left:20px}
.members{margin-top:18px;padding-top:6px;border-top:1px dashed var(--border-strong)}
.members-heading{font-size:15px;margin:10px 0 4px;display:flex;align-items:center;gap:8px}
.search-results h2{font-size:20px;margin:0 0 12px}
.result-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:6px}
.result{display:grid;grid-template-columns:auto auto 1fr;align-items:baseline;gap:4px 10px;padding:10px 14px;border:1px solid var(--border);border-radius:10px;color:var(--fg)}
.result:hover,.result:focus{text-decoration:none;border-color:var(--link);background:var(--bg-soft);outline:none}
.result-path{font-family:var(--mono);font-weight:650;color:var(--link);overflow-wrap:anywhere}
.result-module{font-size:12px;color:var(--muted);font-family:var(--mono);justify-self:end}
.result-summary{grid-column:1/-1;font-size:13.5px;color:var(--fg-soft)}
.page-footer{margin-top:56px;padding-top:16px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
@media (max-width:860px){
  .layout{grid-template-columns:minmax(0,1fr);grid-template-rows:auto 1fr}
  .sidebar{position:sticky;top:0;z-index:20;height:auto;max-height:100vh;border-right:0;border-bottom:1px solid var(--border);padding:10px 16px}
  .menu-toggle{display:inline-flex}
  .search-box{margin:10px 0 4px}
  .js .sidebar:not(.open) .sidebar-nav{display:none}
  .sidebar.open{overflow-y:auto}
  main{padding:20px 16px 48px}
  h1{font-size:24px}
  .module-title{font-size:22px}
  .item{padding:14px;scroll-margin-top:140px}
  .item-member{padding:12px}
  .item-source{margin-left:0;flex-basis:100%}
  .arg-type{white-space:normal}
  .result{grid-template-columns:1fr}
  .result-module,.result .badge{justify-self:start}
}
@media print{.sidebar,.search-results{display:none}.layout{display:block}main{padding:0}}
"#;

const SCRIPT: &str = r#"
(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.add("js");
  var sidebar = document.getElementById("sidebar");
  var toggle = document.getElementById("menu-toggle");
  var input = document.getElementById("search");
  var results = document.getElementById("search-results");
  var content = document.getElementById("page-content");

  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      var open = sidebar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    sidebar.addEventListener("click", function (event) {
      if (event.target.closest && event.target.closest(".sidebar-nav a") && sidebar.classList.contains("open")) {
        sidebar.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }
  if (!input || !results || !content) { return; }

  function score(entry, query) {
    var name = entry.n.toLowerCase();
    var path = entry.p.toLowerCase();
    if (name === query || path === query) { return 0; }
    if (name.indexOf(query) === 0) { return 1; }
    if (path.indexOf(query) === 0) { return 2; }
    if (path.indexOf(query) !== -1) { return 3; }
    if (entry.s.toLowerCase().indexOf(query) !== -1) { return 4; }
    return -1;
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text) { node.textContent = text; }
    return node;
  }

  function clearSearch() {
    results.hidden = true;
    results.textContent = "";
    content.hidden = false;
  }

  function render(raw) {
    var query = raw.trim().toLowerCase();
    if (!query) { clearSearch(); return; }
    results.textContent = "";
    results.appendChild(element("h2", "", "Results for \u201c" + raw.trim() + "\u201d"));
    var index = window.STOFFEL_DOC_INDEX;
    if (!index) {
      results.appendChild(element("p", "muted", "The search index (search-index.js) could not be loaded."));
    } else {
      var hits = [];
      for (var i = 0; i < index.length; i++) {
        var rank = score(index[i], query);
        if (rank >= 0) { hits.push([rank, i, index[i]]); }
      }
      hits.sort(function (a, b) {
        return a[0] - b[0] || a[2].p.length - b[2].p.length || a[1] - b[1];
      });
      if (!hits.length) {
        results.appendChild(element("p", "muted", "No matching items."));
      } else {
        var list = element("ul", "result-list");
        hits.slice(0, 100).forEach(function (hit) {
          var entry = hit[2];
          var item = element("li");
          var link = element("a", "result");
          link.href = entry.u;
          link.appendChild(element("span", "result-path", entry.p));
          link.appendChild(element("span", "badge badge-other", entry.k));
          link.appendChild(element("span", "result-module", entry.m));
          if (entry.s) { link.appendChild(element("span", "result-summary", entry.s)); }
          link.addEventListener("click", function () { input.value = ""; clearSearch(); });
          item.appendChild(link);
          list.appendChild(item);
        });
        results.appendChild(list);
      }
    }
    results.hidden = false;
    content.hidden = true;
  }

  input.addEventListener("input", function () { render(input.value); });
  input.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      input.value = "";
      clearSearch();
      input.blur();
    } else if (event.key === "ArrowDown" || event.key === "Enter") {
      var first = results.querySelector("a");
      if (first) {
        event.preventDefault();
        if (event.key === "Enter") { first.click(); } else { first.focus(); }
      }
    }
  });
  results.addEventListener("keydown", function (event) {
    var links = Array.prototype.slice.call(results.querySelectorAll("a"));
    var at = links.indexOf(document.activeElement);
    if (event.key === "ArrowDown" && at >= 0 && at < links.length - 1) {
      event.preventDefault();
      links[at + 1].focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (at > 0) { links[at - 1].focus(); } else { input.focus(); }
    } else if (event.key === "Escape") {
      input.focus();
    }
  });
  document.addEventListener("keydown", function (event) {
    var active = document.activeElement;
    var typing = active && /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName);
    if ((event.key === "/" || event.key === "s") && !typing && !event.metaKey && !event.ctrlKey && !event.altKey) {
      event.preventDefault();
      if (sidebar && !sidebar.classList.contains("open") && window.matchMedia("(max-width: 860px)").matches) {
        sidebar.classList.add("open");
        if (toggle) { toggle.setAttribute("aria-expanded", "true"); }
      }
      input.focus();
      input.select();
    }
  });

  var initial = null;
  try { initial = new URLSearchParams(window.location.search).get("search"); } catch (error) { initial = null; }
  if (initial) { input.value = initial; render(initial); }
})();
"#;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const LINKED_SOURCE: &str = r#""""Linked module; see `Share.mul`, `helper` and `linked`."""

builtin object Share:
  """Shares."""
  def mul(share1: Share, share2: Share) -> Share {.builtin.}:
    """Multiply; compare `Share.add`."""
  def add(share1: Share, share2: Share) -> Share {.builtin.}:
    """Add.

    See Also:
      Share.mul, missing_item
    """
  def times(share1: Share, share2: Share) -> Share {.builtin: "Share.mul".}:

def helper(x: int64 = -1) -> int64:
  """Call `helper()` or `Share.mul`.

  Examples:
    var s = Share.mul(a, b)
    helper(3)
  """
  return x
"#;

    fn linked_site_files() -> Vec<OutputFile> {
        let module = stoffel::docs::extract_module("linked", "linked.stfl", LINKED_SOURCE)
            .expect("fixture extracts");
        let modules = [module];
        let site = Site {
            title: "Links",
            kind: SiteKind::User,
            modules: &modules,
        };
        render_site(&site)
    }

    /// The anchors and internal links found in a rendered site.
    struct SiteRefs<'a> {
        /// Page name to the ids declared on that page.
        ids: HashMap<&'a str, Vec<&'a str>>,
        /// `(page, anchor)` for every internal link; the anchor may be empty.
        links: Vec<(String, String)>,
    }

    /// Every `id="..."` in each page, and every internal `href` target.
    fn ids_and_links(files: &[OutputFile]) -> SiteRefs<'_> {
        let mut ids = HashMap::new();
        let mut links = Vec::new();
        for file in files.iter().filter(|file| file.name.ends_with(".html")) {
            let page_ids = file
                .contents
                .split("id=\"")
                .skip(1)
                .filter_map(|rest| rest.split('"').next())
                .collect::<Vec<_>>();
            ids.insert(file.name.as_str(), page_ids);
            for rest in file.contents.split("href=\"").skip(1) {
                let target = rest.split('"').next().unwrap_or_default();
                if target == "#" || target.starts_with("#main") {
                    continue;
                }
                let (page, anchor) = target.split_once('#').unwrap_or((target, ""));
                let page = if page.is_empty() {
                    file.name.as_str()
                } else {
                    page
                };
                links.push((page.to_string(), anchor.to_string()));
            }
        }
        SiteRefs { ids, links }
    }

    #[test]
    fn internal_links_point_at_existing_anchors() {
        let files = linked_site_files();
        let SiteRefs { ids, links } = ids_and_links(&files);
        assert!(links.len() > 10, "expected many links, got {links:?}");
        for (page, anchor) in &links {
            let page_ids = ids
                .get(page.as_str())
                .unwrap_or_else(|| panic!("link to missing page {page}"));
            if !anchor.is_empty() {
                assert!(
                    page_ids.contains(&anchor.as_str()),
                    "{page}#{anchor} has no matching id"
                );
            }
        }
        for (page, page_ids) in &ids {
            let unique: HashSet<&&str> = page_ids.iter().collect();
            assert_eq!(unique.len(), page_ids.len(), "duplicate ids on {page}");
        }
    }

    #[test]
    fn docstring_references_become_links() {
        let files = linked_site_files();
        let page = &files
            .iter()
            .find(|file| file.name == "linked.html")
            .unwrap()
            .contents;
        assert!(page.contains(
            "<a class=\"code-link\" href=\"linked.html#obj.Share.mul\"><code>Share.mul</code></a>"
        ));
        assert!(page.contains("href=\"linked.html#fn.helper\"><code>helper()</code></a>"));
        assert!(page.contains("href=\"linked.html\"><code>linked</code></a>"));
        // Unknown See Also names stay plain code.
        assert!(page.contains("<li><code>missing_item</code></li>"));
        // Aliases, VM bindings and UFCS are surfaced.
        assert!(page.contains(
            "Alias of</span> <a class=\"code-link\" href=\"linked.html#obj.Share.mul\">"
        ));
        assert!(page.contains("Callable as</span> <code>"));
        // Examples render as highlighted code with links to documented calls.
        assert!(page.contains("<pre class=\"code-block\"><code><span class=\"kw\">var</span>"));
        assert!(page.contains("<a class=\"fn tok-link\" href=\"linked.html#fn.helper\">helper</a>"));
    }

    #[test]
    fn stdlib_site_links_resolve() {
        let modules = stoffel::docs::extract_stdlib().unwrap();
        let site = Site {
            title: "Stoffel standard library",
            kind: SiteKind::Stdlib,
            modules: &modules,
        };
        let files = render_site(&site);
        assert_eq!(files.len(), modules.len() + 2);
        let SiteRefs { ids, links } = ids_and_links(&files);
        for (page, anchor) in &links {
            let page_ids = ids.get(page.as_str()).expect("linked page exists");
            assert!(
                anchor.is_empty() || page_ids.contains(&anchor.as_str()),
                "{page}#{anchor}"
            );
        }
    }

    #[test]
    fn long_signatures_wrap_one_parameter_per_line() {
        let module = stoffel::docs::extract_module(
            "wide",
            "wide.stfl",
            "def wide(first_argument: int64, second_argument: int64, third_argument: string = \"x\") -> int64:\n  return first_argument\n",
        )
        .unwrap();
        assert_eq!(
            display_signature(&module.items[0]),
            "def wide(\n    first_argument: int64,\n    second_argument: int64,\n    third_argument: string = \"x\",\n) -> int64"
        );
    }

    fn render_single_module_page(name: &str, source: &str) -> String {
        let module = stoffel::docs::extract_module(name, &format!("{name}.stfl"), source)
            .expect("fixture extracts");
        let modules = [module];
        let site = Site {
            title: "Examples",
            kind: SiteKind::User,
            modules: &modules,
        };
        let page_name = module_page_name(name);
        render_site(&site)
            .into_iter()
            .find(|file| file.name == page_name)
            .expect("module page is rendered")
            .contents
    }

    #[test]
    fn deeply_nested_examples_render_as_one_code_block() {
        let page = render_single_module_page(
            "nested",
            concat!(
                "def run() -> void:\n",
                "  \"\"\"Run the loop.\n",
                "\n",
                "  Examples:\n",
                "      def main() -> void:\n",
                "          for i in 0..3:\n",
                "              print(i)\n",
                "  \"\"\"\n",
            ),
        );
        let examples = page
            .split("<h5 class=\"doc-section\">Examples</h5>")
            .nth(1)
            .expect("examples section is rendered");
        let block = examples
            .strip_prefix("\n<pre class=\"code-block\"><code>")
            .unwrap_or_else(|| panic!("examples start with a code block: {examples}"));
        let code = block.split("</code></pre>").next().unwrap();
        assert!(
            code.contains("\n    <span class=\"kw\">for</span>"),
            "{code}"
        );
        assert!(
            code.contains("\n        "),
            "third level keeps its indent: {code}"
        );
        assert!(!examples
            .split("</code></pre>")
            .next()
            .unwrap()
            .contains("<p>"));
    }

    #[test]
    fn examples_with_prose_and_fences_stay_structured() {
        let page = render_single_module_page(
            "fenced",
            concat!(
                "def run() -> void:\n",
                "  \"\"\"Run it.\n",
                "\n",
                "  Examples:\n",
                "    Call it from main:\n",
                "\n",
                "    ```\n",
                "    run()\n",
                "    ```\n",
                "  \"\"\"\n",
            ),
        );
        let examples = page
            .split("<h5 class=\"doc-section\">Examples</h5>")
            .nth(1)
            .expect("examples section is rendered");
        assert!(
            examples
                .trim_start()
                .starts_with("<p>Call it from main:</p>"),
            "{examples}"
        );
        assert!(examples.contains("<pre class=\"code-block\"><code>"));
    }

    #[test]
    fn escaping_covers_markup_and_quotes() {
        assert_eq!(
            Escaped("<img src=x onerror=\"a('b')\">&").to_string(),
            "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;"
        );
    }

    #[test]
    fn json_strings_cannot_close_a_script() {
        assert_eq!(
            json_string("</script>\"\\\n"),
            "\"\\u003c/script\\u003e\\\"\\\\\\n\""
        );
    }

    #[test]
    fn page_names_are_sanitized_and_never_the_index() {
        assert_eq!(module_page_name("std.mpc"), "std.mpc.html");
        assert_eq!(module_page_name("index"), "index_.html");
        assert_eq!(module_page_name("my mod/<x>"), "my_mod__x_.html");
        assert_eq!(module_page_name(""), "_.html");
    }

    #[test]
    fn string_literals_end_at_their_closing_quote() {
        assert_eq!(string_literal_end("\"a\\\"b\" + 1"), 6);
        assert_eq!(string_literal_end("\"\"\"doc\"\"\" x"), 9);
        assert_eq!(string_literal_end("\"open\nnext"), 5);
    }
}
