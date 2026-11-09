//! `stoffel doc`: API documentation from `.stfl` docstrings.
//!
//! The command resolves its inputs (the embedded stdlib, explicit files and
//! directories, or the current project), extracts the doc model through the
//! SDK's unstable [`stoffel::docs`] module, lints it, and renders either a
//! self-contained HTML site ([`html::render_site`], the default) or
//! Mintlify-compatible MDX pages ([`markdown::render_site`]). Extraction and
//! rendering finish before anything is written, so a failure never leaves a
//! partial site behind.

mod html;
mod markdown;
mod shared;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use stoffel::docs::{self, DocWarning, DocWarningKind, ModuleDoc, WarningSeverity};

use crate::project::{stfl_files_under, validate_project_controlled_path, Project};

use self::shared::{OutputFile, Site, SiteKind};

/// Environment variable that turns `--open` into a no-op (for CI and tests).
const NO_OPEN_ENV: &str = "STOFFEL_NO_OPEN";

/// Files that mark the root of a Mintlify docs repository.
const MINTLIFY_CONFIG_FILES: [&str; 2] = ["docs.json", "mint.json"];

/// What `stoffel doc` generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DocFormat {
    /// A self-contained static HTML site.
    Html,
    /// Mintlify-compatible Markdown (MDX) pages plus a navigation group.
    #[value(aliases = ["md", "mdx", "mintlify"])]
    Markdown,
}

#[derive(Debug, Args)]
pub(crate) struct DocArgs {
    /// .stfl files or directories to document. Defaults to the current project's sources.
    #[arg(value_name = "PATHS")]
    paths: Vec<PathBuf>,
    /// Document the embedded standard library instead of project sources.
    #[arg(long = "std", conflicts_with = "paths")]
    stdlib: bool,
    /// Output format: `html` (default) or `markdown` (Mintlify-compatible MDX).
    #[arg(long, value_enum, default_value_t = DocFormat::Html)]
    format: DocFormat,
    /// Directory for the generated docs. Defaults to target/doc.
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
    /// Markdown only: where the pages live relative to the Mintlify docs root
    /// (the folder with docs.json), used for links and navigation. Detected
    /// from a docs.json above the output directory when omitted.
    #[arg(long, value_name = "PATH")]
    base_path: Option<String>,
    /// Open the generated index.html in a browser (HTML only; skipped when STOFFEL_NO_OPEN is set).
    #[arg(long)]
    open: bool,
    /// Include items whose names start with `_`.
    #[arg(long)]
    include_private: bool,
    /// Report documentation coverage and warnings without writing any files.
    #[arg(long, conflicts_with_all = ["open", "output"])]
    check: bool,
    /// Exit with an error when any public item is undocumented or any doc warning is found.
    #[arg(long)]
    deny_missing: bool,
    /// Title shown on every generated page.
    #[arg(long, value_name = "TEXT")]
    title: Option<String>,
}

/// Where the documented modules come from.
enum DocInput {
    /// The standard library embedded in the compiler.
    Stdlib,
    /// The sources of the project in (or above) the current directory.
    Project(Box<Project>),
    /// Explicit `.stfl` files and directories; no `Stoffel.toml` needed.
    Paths(Vec<PathBuf>),
}

impl DocInput {
    fn site_kind(&self) -> SiteKind {
        match self {
            DocInput::Stdlib => SiteKind::Stdlib,
            DocInput::Project(_) | DocInput::Paths(_) => SiteKind::User,
        }
    }
}

/// One `.stfl` file to document.
struct SourceFile {
    /// Absolute path on disk.
    path: PathBuf,
    /// Dotted module name, matching import syntax (`utils.math`).
    module: String,
    /// Path shown in source references (relative to the current directory
    /// when possible).
    display: String,
}

/// Extracted modules plus how many files they came from.
struct LoadedDocs {
    modules: Vec<ModuleDoc>,
    file_count: usize,
}

/// Runs `stoffel doc`.
pub(crate) fn doc(args: DocArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read the current directory")?;
    validate_format_flags(&args)?;
    let input = resolve_input(&args)?;
    let context_project = match &input {
        DocInput::Project(project) => Some(Project::clone(project)),
        DocInput::Stdlib | DocInput::Paths(_) => Project::discover(None).ok(),
    };

    let output = if args.check {
        None
    } else {
        let output = resolve_output_dir(args.output.as_deref(), context_project.as_ref(), &cwd);
        validate_output_dir(&output, context_project.as_ref(), &cwd)?;
        Some(output)
    };

    let LoadedDocs {
        mut modules,
        file_count,
    } = load_modules(&input, &cwd, args.format)?;
    if !args.include_private {
        strip_private_items(&mut modules);
    }

    let warnings = lint_modules(&modules, &input)?;
    report(&args, &modules, file_count, &warnings);
    let denied = warnings
        .iter()
        .filter(|warning| warning.severity == WarningSeverity::Warning)
        .count();
    if args.deny_missing && denied > 0 {
        anyhow::bail!(
            "documentation check failed: {denied} {} (--deny-missing)",
            plural(denied, "warning", "warnings")
        );
    }

    let Some(output) = output else {
        println!("Checked documentation; no files written (--check)");
        return Ok(());
    };

    let title = args.title.clone().unwrap_or_else(|| default_title(&input));
    let site = Site {
        title: &title,
        kind: input.site_kind(),
        modules: &modules,
    };
    match args.format {
        DocFormat::Html => {
            let files = html::render_site(&site);
            write_site(&output, &files)?;
            let index = output.join(html::INDEX_PAGE);
            println!("Generated {}", index.display());
            if args.open {
                open_in_browser(&index);
            }
        }
        DocFormat::Markdown => {
            let base_path = match &args.base_path {
                Some(base_path) => normalize_base_path(base_path)?,
                None => detect_base_path(&output),
            };
            let files = markdown::render_site(&site, &base_path.path);
            write_site(&output, &files)?;
            println!(
                "Generated {} Mintlify pages in {}",
                files.len() - 1,
                output.display()
            );
            match (&base_path.docs_root, args.base_path.is_some()) {
                (_, true) => println!("Links use the base path /{}", base_path.path),
                (Some(root), false) => println!(
                    "Links use the base path /{} (relative to {})",
                    base_path.path,
                    root.display()
                ),
                (None, false) => println!(
                    "No docs.json found above {}; links assume the pages sit at the docs root (pass --base-path to change)",
                    output.display()
                ),
            }
            println!(
                "Add the group in {} to the navigation in your docs.json",
                output.join(markdown::NAVIGATION_FILE).display()
            );
        }
    }
    Ok(())
}

/// Rejects flags that do not apply to the chosen format.
fn validate_format_flags(args: &DocArgs) -> Result<()> {
    match args.format {
        DocFormat::Html if args.base_path.is_some() => {
            anyhow::bail!("--base-path only applies to --format markdown")
        }
        DocFormat::Markdown if args.open => {
            anyhow::bail!(
                "--open only applies to --format html; preview Mintlify pages with `mint dev`"
            )
        }
        DocFormat::Html | DocFormat::Markdown => Ok(()),
    }
}

/// Where Markdown pages live under the Mintlify docs root.
#[derive(Debug, PartialEq, Eq)]
struct BasePath {
    /// `/`-separated, without leading or trailing `/` (empty for the root).
    path: String,
    /// The detected docs root, when the path came from a docs.json.
    docs_root: Option<PathBuf>,
}

/// Cleans an explicit `--base-path`: surrounding slashes are dropped, and
/// only plain path segments of URL-safe characters are accepted.
fn normalize_base_path(raw: &str) -> Result<BasePath> {
    let segments: Vec<&str> = raw
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    for segment in &segments {
        let valid = !matches!(*segment, "." | "..")
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid {
            anyhow::bail!(
                "invalid --base-path `{raw}`: use /-separated segments of letters, digits, `-`, `_` and `.` (for example reference/stdlib)"
            );
        }
    }
    Ok(BasePath {
        path: segments.join("/"),
        docs_root: None,
    })
}

/// The output directory relative to the nearest ancestor holding a Mintlify
/// config file, or the docs root itself when there is none.
fn detect_base_path(output: &Path) -> BasePath {
    let docs_root = output.ancestors().find(|dir| {
        MINTLIFY_CONFIG_FILES
            .iter()
            .any(|file| dir.join(file).is_file())
    });
    let Some(docs_root) = docs_root else {
        return BasePath {
            path: String::new(),
            docs_root: None,
        };
    };
    let path = output
        .strip_prefix(docs_root)
        .unwrap_or(Path::new(""))
        .components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(segment.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    BasePath {
        path,
        docs_root: Some(docs_root.to_path_buf()),
    }
}

fn resolve_input(args: &DocArgs) -> Result<DocInput> {
    if args.stdlib {
        return Ok(DocInput::Stdlib);
    }
    if !args.paths.is_empty() {
        return Ok(DocInput::Paths(args.paths.clone()));
    }
    let project = Project::discover(None)
        .context("no Stoffel project found; pass a .stfl file or directory, or use --std")?;
    Ok(DocInput::Project(Box::new(project)))
}

fn default_title(input: &DocInput) -> String {
    match input {
        DocInput::Stdlib => "Stoffel standard library".to_string(),
        DocInput::Project(project) if !project.config().package.name.trim().is_empty() => {
            project.config().package.name.clone()
        }
        DocInput::Project(_) | DocInput::Paths(_) => "Stoffel documentation".to_string(),
    }
}

/// `--output` (relative to the current directory), else the project's
/// `target/doc`, else `./target/doc`.
fn resolve_output_dir(output: Option<&Path>, project: Option<&Project>, cwd: &Path) -> PathBuf {
    match (output, project) {
        (Some(output), _) => cwd.join(output),
        (None, Some(project)) => project.target_dir().join("doc"),
        (None, None) => cwd.join("target").join("doc"),
    }
}

/// Rejects output directories that would scatter generated HTML over
/// sources: the current directory or project root (or any of their
/// ancestors), anything under `src/`, paths with `..`, and paths that
/// traverse symlinks inside the project.
fn validate_output_dir(output: &Path, project: Option<&Project>, cwd: &Path) -> Result<()> {
    if output
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!(
            "--output must not contain parent-directory segments (`..`); got {}",
            output.display()
        );
    }
    if output.exists() && !output.is_dir() {
        anyhow::bail!(
            "--output {} is a file; pass a directory for the generated HTML",
            output.display()
        );
    }
    if cwd.starts_with(output) {
        anyhow::bail!(
            "refusing to write documentation into {}, which contains the current directory; pass a dedicated directory such as target/doc",
            output.display()
        );
    }
    match project {
        Some(project) => {
            let root = project.root();
            if root.starts_with(output) {
                anyhow::bail!(
                    "refusing to write documentation into the project root {}; pass a dedicated directory such as target/doc",
                    output.display()
                );
            }
            // A root-level `build.source` (`source = "main.stfl"`) makes the
            // source dir the root itself; that case is covered by the root
            // check above and must not reject every path in the project.
            // The project's own target dir is always an acceptable home.
            let source_dir = project.source_dir();
            let under_sources = (!root.starts_with(&source_dir) && output.starts_with(&source_dir))
                || output.starts_with(root.join("src"));
            if under_sources && !output.starts_with(project.target_dir()) {
                anyhow::bail!(
                    "--output must not write documentation under src/; use a path under target/ instead"
                );
            }
            if output.starts_with(root) {
                validate_project_controlled_path(root, output, false)?;
            }
        }
        None if output.starts_with(cwd) => validate_project_controlled_path(cwd, output, false)?,
        None => {}
    }
    Ok(())
}

fn load_modules(input: &DocInput, cwd: &Path, format: DocFormat) -> Result<LoadedDocs> {
    let sources = match input {
        DocInput::Stdlib => {
            let modules = docs::extract_stdlib()
                .context("failed to extract documentation from the embedded standard library")?;
            let file_count = modules.len();
            return Ok(LoadedDocs {
                modules,
                file_count,
            });
        }
        DocInput::Project(project) => {
            let base = project.source_dir();
            project
                .source_files()?
                .into_iter()
                .map(|path| SourceFile::new(path, &base, cwd))
                .collect()
        }
        DocInput::Paths(paths) => collect_sources(paths, cwd)?,
    };
    ensure_unique_pages(&sources, format)?;

    let mut modules = Vec::with_capacity(sources.len());
    for source in &sources {
        let text = fs::read_to_string(&source.path)
            .with_context(|| format!("failed to read {}", source.display))?;
        let module =
            docs::extract_module(&source.module, &source.display, &text).with_context(|| {
                format!(
                    "failed to extract docs from {}; run `stoffel check {}` for details",
                    source.display, source.display
                )
            })?;
        modules.push(module);
    }
    docs::link_aliases(&mut modules);
    Ok(LoadedDocs {
        modules,
        file_count: sources.len(),
    })
}

/// Expands explicit paths into source files. A path inside a project's
/// source directory is named relative to it (so names match imports);
/// otherwise a directory argument is its own module root and a file is named
/// after itself.
fn collect_sources(paths: &[PathBuf], cwd: &Path) -> Result<Vec<SourceFile>> {
    let mut sources = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        let absolute = cwd.join(path);
        if !absolute.exists() {
            anyhow::bail!(
                "{} does not exist; pass a .stfl file or directory, or use --std",
                path.display()
            );
        }
        let project_source_dir = Project::discover(Some(&absolute))
            .ok()
            .map(|project| project.source_dir())
            .filter(|dir| absolute.starts_with(dir));
        let (files, base) = if absolute.is_dir() {
            let files = stfl_files_under(&absolute)
                .with_context(|| format!("failed to read {}", path.display()))?;
            if files.is_empty() {
                anyhow::bail!("no .stfl files found under {}", path.display());
            }
            (
                files,
                project_source_dir.unwrap_or_else(|| absolute.clone()),
            )
        } else {
            ensure_doc_source_path(path)?;
            let parent = absolute
                .parent()
                .map_or_else(|| cwd.to_path_buf(), Path::to_path_buf);
            (vec![absolute.clone()], project_source_dir.unwrap_or(parent))
        };
        for file in files {
            if seen.insert(file.clone()) {
                sources.push(SourceFile::new(file, &base, cwd));
            }
        }
    }
    Ok(sources)
}

fn ensure_doc_source_path(path: &Path) -> Result<()> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("stfl") => Ok(()),
        Some("toml") => anyhow::bail!(
            "got TOML config {}; stoffel doc expects .stfl files or directories (run it without paths to document the current project)",
            path.display()
        ),
        _ => anyhow::bail!(
            "expected a .stfl source file or directory; got {}",
            path.display()
        ),
    }
}

impl SourceFile {
    fn new(path: PathBuf, base: &Path, cwd: &Path) -> Self {
        let module = path
            .strip_prefix(base)
            .ok()
            .map(docs::module_name_from_path)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "module".to_string())
            });
        let display = path
            .strip_prefix(cwd)
            .unwrap_or(&path)
            .display()
            .to_string();
        SourceFile {
            path,
            module,
            display,
        }
    }
}

/// Two files must not render to the same page. Page names are compared
/// case-insensitively because common filesystems are case-insensitive.
fn ensure_unique_pages(sources: &[SourceFile], format: DocFormat) -> Result<()> {
    let mut pages: HashMap<String, &SourceFile> = HashMap::new();
    for source in sources {
        let page = match format {
            DocFormat::Html => html::module_page_name(&source.module),
            DocFormat::Markdown => markdown::module_page_path(&source.module),
        };
        if let Some(previous) = pages.insert(page.to_ascii_lowercase(), source) {
            anyhow::bail!(
                "{} and {} both document module `{}` (page {page}); document them in separate runs with different --output directories",
                previous.display,
                source.display,
                source.module
            );
        }
    }
    Ok(())
}

/// Drops `_private` items and methods from the rendered site.
fn strip_private_items(modules: &mut [ModuleDoc]) {
    for module in modules {
        module.items.retain(|item| !item.is_private());
        for item in &mut module.items {
            item.members.retain(|member| !member.is_private());
        }
    }
}

/// Lints the documented modules. User docs may link to stdlib items, so the
/// stdlib joins the link universe, but only findings in the documented
/// modules are kept.
fn lint_modules(modules: &[ModuleDoc], input: &DocInput) -> Result<Vec<DocWarning>> {
    match input {
        DocInput::Stdlib => Ok(docs::lint(modules)),
        DocInput::Project(_) | DocInput::Paths(_) => {
            let documented: HashSet<&str> =
                modules.iter().map(|module| module.name.as_str()).collect();
            let mut universe = modules.to_vec();
            universe.extend(
                docs::extract_stdlib()
                    .context("failed to load the standard library for link checking")?,
            );
            Ok(docs::lint(&universe)
                .into_iter()
                .filter(|warning| documented.contains(warning.module.as_str()))
                .collect())
        }
    }
}

/// Prints coverage and warnings. Real problems (broken links, wrong `Args`)
/// always print; missing docs print with `--check` or `--deny-missing`, and
/// notes only with `--check`.
fn report(args: &DocArgs, modules: &[ModuleDoc], file_count: usize, warnings: &[DocWarning]) {
    for warning in warnings {
        let show = match (warning.severity, &warning.kind) {
            (WarningSeverity::Note, _) => args.check,
            (WarningSeverity::Warning, DocWarningKind::MissingDoc) => {
                args.check || args.deny_missing
            }
            (WarningSeverity::Warning, _) => true,
        };
        if show {
            let label = match warning.severity {
                WarningSeverity::Note => "note",
                WarningSeverity::Warning => "warning",
            };
            eprintln!("{label}: {warning}");
        }
    }

    let coverage = docs::coverage(modules);
    println!(
        "Documented {}/{} items ({} undocumented) from {file_count} {}",
        coverage.documented,
        coverage.total,
        coverage.undocumented(),
        plural(file_count, "file", "files")
    );
    let other = warnings
        .iter()
        .filter(|warning| {
            warning.severity == WarningSeverity::Warning
                && warning.kind != DocWarningKind::MissingDoc
        })
        .count();
    if other > 0 {
        println!(
            "Found {other} documentation {}",
            plural(other, "warning", "warnings")
        );
    }
}

fn plural<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 {
        one
    } else {
        many
    }
}

fn write_site(output: &Path, files: &[OutputFile]) -> Result<()> {
    fs::create_dir_all(output).with_context(|| format!("failed to create {}", output.display()))?;
    for file in files {
        let path = output.join(&file.name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&path, &file.contents)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

fn open_in_browser(path: &Path) {
    if std::env::var_os(NO_OPEN_ENV).is_some() {
        println!("Skipping --open because {NO_OPEN_ENV} is set");
        return;
    }
    let mut command = if cfg!(target_os = "macos") {
        ProcessCommand::new("open")
    } else if cfg!(windows) {
        let mut command = ProcessCommand::new("cmd");
        command.args(["/C", "start", ""]);
        command
    } else {
        ProcessCommand::new("xdg-open")
    };
    let opened = command
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !opened {
        println!("Could not open a browser; open {} manually", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_path_is_normalized_and_validated() {
        let base = normalize_base_path("/reference//stdlib/").unwrap();
        assert_eq!(base.path, "reference/stdlib");
        assert_eq!(normalize_base_path("/").unwrap().path, "");
        for invalid in ["../up", "a/./b", "has space", "x?y=1", "a#b"] {
            assert!(normalize_base_path(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn base_path_is_detected_from_the_nearest_docs_json() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("site");
        let output = root.join("reference").join("stdlib");
        fs::create_dir_all(&output).unwrap();
        assert_eq!(detect_base_path(&output).docs_root, None);
        fs::write(root.join("mint.json"), "{}").unwrap();
        let base = detect_base_path(&output);
        assert_eq!(base.path, "reference/stdlib");
        assert_eq!(base.docs_root.as_deref(), Some(root.as_path()));
        fs::write(output.join("docs.json"), "{}").unwrap();
        assert_eq!(detect_base_path(&output).path, "");
    }

    #[test]
    fn output_dir_rejects_parent_segments_and_cwd() {
        let cwd = Path::new("/work/project");
        let error = validate_output_dir(Path::new("/work/project/target/../x"), None, cwd)
            .unwrap_err()
            .to_string();
        assert!(error.contains("parent-directory"), "{error}");
        let error = validate_output_dir(Path::new("/work/project/."), None, cwd)
            .unwrap_err()
            .to_string();
        assert!(error.contains("contains the current directory"), "{error}");
        let error = validate_output_dir(Path::new("/work"), None, cwd)
            .unwrap_err()
            .to_string();
        assert!(error.contains("contains the current directory"), "{error}");
    }

    #[test]
    fn module_names_follow_the_source_root() {
        let cwd = Path::new("/work");
        let file = SourceFile::new(
            PathBuf::from("/work/src/utils/math.stfl"),
            Path::new("/work/src"),
            cwd,
        );
        assert_eq!(file.module, "utils.math");
        assert_eq!(file.display, "src/utils/math.stfl");
        let outside = SourceFile::new(
            PathBuf::from("/elsewhere/lib.stfl"),
            Path::new("/work/src"),
            cwd,
        );
        assert_eq!(outside.module, "lib");
        assert_eq!(outside.display, "/elsewhere/lib.stfl");
    }
}
