use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use stoffel::prelude::{MpcBackend, MpcConfig as SdkMpcConfig};

const CONFIG_FILE: &str = "Stoffel.toml";

#[derive(Debug, Clone, Copy)]
pub enum Template {
    Stoffel,
    Python,
    Rust,
    TypeScript,
    SolidityFoundry,
    SolidityHardhat,
}

#[derive(Debug, Clone)]
pub struct Project {
    root: PathBuf,
    source: PathBuf,
    config: ProjectConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfig {
    pub package: PackageConfig,
    pub mpc: MpcConfig,
    pub build: BuildConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageConfig {
    pub name: String,
    pub version: String,
    pub authors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MpcConfig {
    #[serde(alias = "protocol")]
    pub backend: Option<MpcBackend>,
    #[serde(alias = "field")]
    pub curve: Option<stoffel::prelude::Curve>,
    pub parties: Option<usize>,
    pub threshold: Option<usize>,
    pub instance_id: Option<u64>,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            backend: Some(MpcBackend::HoneyBadger),
            curve: None,
            parties: Some(5),
            threshold: Some(1),
            instance_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuildConfig {
    pub source: PathBuf,
    #[serde(alias = "output_dir")]
    pub target_dir: PathBuf,
    pub optimization_level: Option<u8>,
}

impl Default for PackageConfig {
    fn default() -> Self {
        Self {
            name: "stoffel-app".to_owned(),
            version: "0.1.0".to_owned(),
            authors: Vec::new(),
        }
    }
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            source: PathBuf::from("src/main.stfl"),
            target_dir: PathBuf::from("target"),
            optimization_level: None,
        }
    }
}

impl Project {
    pub fn init(path: &Path, template: Template, force: bool) -> Result<()> {
        if path.exists() && !path.is_dir() {
            anyhow::bail!(
                "{} is a file; pass a directory path for the new Stoffel project",
                path.display()
            );
        }
        if path.exists() && !force && fs::read_dir(path)?.next().is_some() {
            anyhow::bail!("{}", init_target_not_empty_message(path));
        }
        fs::create_dir_all(path)?;
        match template {
            Template::Stoffel => init_stoffel_project(path),
            Template::Python => init_python_project(path),
            Template::Rust => init_rust_project(path),
            Template::TypeScript => init_typescript_project(path),
            Template::SolidityFoundry => init_solidity_foundry_project(path),
            Template::SolidityHardhat => init_solidity_hardhat_project(path),
        }
    }

    pub fn discover(path: Option<&Path>) -> Result<Self> {
        if let Some(path) = path {
            if !path.exists() {
                anyhow::bail!("{}", missing_path_message(path));
            }
        }
        let start = match path {
            Some(path) if path.is_dir() => path.to_path_buf(),
            Some(path) => path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
            None => std::env::current_dir()?,
        };
        let root = find_root(&start)?;
        let mut config = read_config(&root.join(CONFIG_FILE))?;
        if config.package.name.trim().is_empty() {
            config.package.name = root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("stoffel-app")
                .to_owned();
        }
        let source = root.join(&config.build.source);
        Ok(Self {
            root,
            source,
            config,
        })
    }

    pub fn source_path(&self) -> &Path {
        &self.source
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join(".stoffel").join("cache")
    }

    pub fn target_dir(&self) -> PathBuf {
        self.root.join(&self.config.build.target_dir)
    }

    pub fn default_bytecode_path(&self, release: bool) -> PathBuf {
        let profile = if release { "release" } else { "debug" };
        self.target_dir()
            .join(profile)
            .join(format!("{}.stfb", self.config.package.name))
    }

    pub fn config(&self) -> &ProjectConfig {
        &self.config
    }

    pub fn test_files(&self) -> Result<Vec<PathBuf>> {
        let tests_dir = self.root.join("tests");
        if !tests_dir.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        collect_stfl_files(&tests_dir, &mut files)?;
        files.sort();
        Ok(files)
    }

    pub fn source_files(&self) -> Result<Vec<PathBuf>> {
        let source_dir = self.source_dir();
        if !source_dir.exists() {
            if self.configured_source_is_dir() {
                anyhow::bail!(
                    "configured build.source {} does not exist",
                    self.config.build.source.display()
                );
            }
            if !self.source.exists() {
                anyhow::bail!(
                    "configured build.source {} does not exist",
                    self.config.build.source.display()
                );
            }
            return Ok(vec![self.source.clone()]);
        }
        let mut files = Vec::new();
        collect_stfl_files(&source_dir, &mut files)?;
        files.sort();
        if files.is_empty() {
            if self.configured_source_is_dir() {
                anyhow::bail!(
                    "no .stfl source files found under configured build.source {}",
                    self.config.build.source.display()
                );
            }
            if !self.source.exists() {
                anyhow::bail!(
                    "configured build.source {} does not exist",
                    self.config.build.source.display()
                );
            }
            files.push(self.source.clone());
        }
        Ok(files)
    }

    pub fn source_files_under(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let dir = absolutize(dir)?;
        let mut files = Vec::new();
        collect_stfl_files(&dir, &mut files)?;
        files.sort();
        Ok(files)
    }

    pub fn watch_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = vec![self.config_path()];
        files.extend(self.source_files()?);
        files.sort();
        files.dedup();
        Ok(files)
    }

    fn source_dir(&self) -> PathBuf {
        if self.configured_source_is_dir() {
            self.root.join(&self.config.build.source)
        } else {
            self.root.join(
                self.config
                    .build
                    .source
                    .parent()
                    .unwrap_or(Path::new("src")),
            )
        }
    }

    fn configured_source_is_dir(&self) -> bool {
        self.config
            .build
            .source
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("stfl")
    }

    pub fn default_bytecode_path_for_source(&self, source: &Path, release: bool) -> PathBuf {
        let profile = if release { "release" } else { "debug" };
        let source_path = if source.is_absolute() {
            source.to_path_buf()
        } else {
            self.root.join(source)
        };
        let stem = source_path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("main");
        if source_path == self.source_path() && stem == "main" {
            return self
                .target_dir()
                .join(profile)
                .join(format!("{}.stfb", self.config.package.name));
        }
        if let Ok(relative) = source_path.strip_prefix(self.source_dir()) {
            if relative
                .parent()
                .is_some_and(|parent| !parent.as_os_str().is_empty())
            {
                return self
                    .target_dir()
                    .join(profile)
                    .join(relative)
                    .with_extension("stfb");
            }
        }
        let name = if stem == "main" {
            self.config.package.name.as_str()
        } else {
            stem
        };
        self.target_dir().join(profile).join(format!("{name}.stfb"))
    }

    pub fn find_bytecode(&self, release: bool) -> Result<Option<PathBuf>> {
        let profile = if release { "release" } else { "debug" };
        let dir = self.target_dir().join(profile);
        let preferred = self.default_bytecode_path(release);
        if self.is_fresh_bytecode(&preferred)? {
            return Ok(Some(preferred));
        }
        let legacy_preferred = preferred.with_extension("stflb");
        if self.is_fresh_bytecode(&legacy_preferred)? {
            return Ok(Some(legacy_preferred));
        }
        if !dir.exists() {
            return Ok(None);
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "stflb" | "stfb"))
            {
                files.push(path);
            }
        }
        files.sort();
        for file in files {
            if self.is_fresh_bytecode(&file)? {
                return Ok(Some(file));
            }
        }
        Ok(None)
    }

    fn is_fresh_bytecode(&self, bytecode: &Path) -> Result<bool> {
        if !bytecode.exists() {
            return Ok(false);
        }
        let bytecode_modified = fs::metadata(bytecode)
            .and_then(|metadata| metadata.modified())
            .with_context(|| format!("failed to inspect {}", bytecode.display()))?;
        for input in self.watch_files()? {
            let Ok(metadata) = fs::metadata(&input) else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if modified > bytecode_modified {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn missing_path_message(path: &Path) -> String {
    let mut message = format!("{} does not exist", path.display());
    if is_stoffel_source_path(path) {
        if let Some(suggestion) = nearest_stoffel_source(path) {
            message.push_str(&format!("; did you mean {}?", suggestion.display()));
        }
    }
    message
}

fn nearest_stoffel_source(path: &Path) -> Option<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let wanted = path.file_name()?.to_string_lossy();
    let mut best = None::<(usize, PathBuf)>;
    for entry in fs::read_dir(parent).ok()?.flatten() {
        let candidate = entry.path();
        if !candidate.is_file() || !is_stoffel_source_path(&candidate) {
            continue;
        }
        let Some(name) = candidate.file_name() else {
            continue;
        };
        let distance = levenshtein(&wanted, &name.to_string_lossy());
        if distance <= 3
            && best
                .as_ref()
                .is_none_or(|(best_distance, _)| distance < *best_distance)
        {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, path)| path)
}

fn is_stoffel_source_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "stfl")
}

fn levenshtein(left: &str, right: &str) -> usize {
    let mut costs = (0..=right.chars().count()).collect::<Vec<_>>();
    for (left_index, left_char) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = left_index + 1;
        for (right_index, right_char) in right.chars().enumerate() {
            let insert = costs[right_index + 1] + 1;
            let delete = costs[right_index] + 1;
            let replace = previous + usize::from(left_char != right_char);
            previous = costs[right_index + 1];
            costs[right_index + 1] = insert.min(delete).min(replace);
        }
    }
    costs[right.chars().count()]
}

fn init_stoffel_project(path: &Path) -> Result<()> {
    write_new(
        path.join(CONFIG_FILE),
        &default_config_text(project_name(path)),
    )?;
    write_new(
        path.join("src/main.stfl"),
        "def main(a: Share, b: Share) -> int64:\n  var sum = Share.add(a, b)\n  return sum.open()\n",
    )?;
    write_new(
        path.join("README.md"),
        &default_readme_text("Stoffel Project"),
    )?;
    Ok(())
}

pub fn init_library_project(path: &Path) -> Result<()> {
    write_new(
        path.join(CONFIG_FILE),
        &default_library_config_text(project_name(path)),
    )?;
    write_new(
        path.join("src/lib.stfl"),
        "def add(a: int64, b: int64) -> int64:\n  return a + b\n",
    )?;
    write_new(
        path.join("README.md"),
        "# Stoffel Library\n\nValidate the library source:\n\n```sh\nstoffel check\n```\n\nBuild bytecode when you need an artifact:\n\n```sh\nstoffel build\n```\n",
    )?;
    Ok(())
}

fn init_python_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(path.join("requirements.txt"), "stoffel-python-sdk\n")?;
    write_new(
        path.join("app.py"),
        "print(\"Stoffel Python SDK project\")\n",
    )?;
    write_new(
        path.join("README.md"),
        &format!(
            "{}\nPython wrapper files are included for SDK integration. Install Python dependencies with:\n\n```sh\npython3 -m pip install -r requirements.txt\n```\n",
            default_readme_text("Stoffel Python Project")
        ),
    )?;
    Ok(())
}

fn init_rust_project(path: &Path) -> Result<()> {
    write_new(
        path.join("stoffel/Stoffel.toml"),
        &config_text(project_name(path), "src/program.stfl"),
    )?;
    write_new(
        path.join("stoffel/src/program.stfl"),
        "def main(a: int64, b: int64) -> int64:\n  return a + b\n",
    )?;
    write_new(
        path.join("Cargo.toml"),
        &format!(
            "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstoffel-rust-sdk = {{ git = \"https://github.com/Stoffel-Labs/StoffelVM\" }}\n",
            project_name(path)
        ),
    )?;
    write_new(
        path.join("src/main.rs"),
        "use stoffel::prelude::*;\n\nfn main() -> stoffel::Result<()> {\n    let result = Stoffel::compile(include_str!(\"../stoffel/src/program.stfl\"))?\n        .with_inputs(&[(\"a\", 40_i64), (\"b\", 2_i64)])\n        .execute_clear()?;\n    println!(\"{}\", result[0]);\n    Ok(())\n}\n",
    )?;
    write_new(
        path.join("README.md"),
        "# Stoffel Rust Project\n\nThe Stoffel program lives in `stoffel/src/program.stfl` and has its own `stoffel/Stoffel.toml`.\n\nValidate the Stoffel program:\n\n```sh\nstoffel check stoffel\n```\n\nRun the Rust wrapper:\n\n```sh\ncargo run\n```\n",
    )?;
    Ok(())
}

fn init_typescript_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(
        path.join("package.json"),
        &format!(
            "{{\n  \"name\": \"{}\",\n  \"version\": \"0.1.0\",\n  \"type\": \"module\",\n  \"scripts\": {{\n    \"build:stoffel\": \"stoffel build\"\n  }}\n}}\n",
            project_name(path)
        ),
    )?;
    write_new(
        path.join("src/index.ts"),
        "console.log(\"Stoffel TypeScript project\");\n",
    )?;
    write_new(
        path.join("README.md"),
        &format!(
            "{}\nTypeScript wrapper files are included for SDK integration. The package script builds the Stoffel bytecode:\n\n```sh\nnpm run build:stoffel\n```\n",
            default_readme_text("Stoffel TypeScript Project")
        ),
    )?;
    Ok(())
}

fn init_solidity_foundry_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(
        path.join("foundry.toml"),
        "[profile.default]\nsrc = \"contracts\"\nout = \"out\"\nlibs = [\"lib\"]\n",
    )?;
    write_new(
        path.join("contracts/StoffelApp.sol"),
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\ncontract StoffelApp {}\n",
    )?;
    write_new(
        path.join("README.md"),
        &format!(
            "{}\nFoundry contract files are included under `contracts/`. Build the Solidity project with:\n\n```sh\nforge build\n```\n",
            default_readme_text("Stoffel Foundry Project")
        ),
    )?;
    Ok(())
}

fn init_solidity_hardhat_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(
        path.join("package.json"),
        &format!(
            "{{\n  \"name\": \"{}\",\n  \"version\": \"0.1.0\",\n  \"devDependencies\": {{\n    \"hardhat\": \"^2.22.0\"\n  }}\n}}\n",
            project_name(path)
        ),
    )?;
    write_new(
        path.join("hardhat.config.js"),
        "module.exports = { solidity: \"0.8.20\" };\n",
    )?;
    write_new(
        path.join("contracts/StoffelApp.sol"),
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\ncontract StoffelApp {}\n",
    )?;
    write_new(
        path.join("README.md"),
        &format!(
            "{}\nHardhat contract files are included under `contracts/`. Install JavaScript dependencies, then compile contracts:\n\n```sh\nnpm install\nnpx hardhat compile\n```\n",
            default_readme_text("Stoffel Hardhat Project")
        ),
    )?;
    Ok(())
}

fn init_target_not_empty_message(path: &Path) -> String {
    if path.join(CONFIG_FILE).exists() {
        return format!(
            "{} already contains Stoffel.toml; use `stoffel status {}` or `stoffel run {}` for this project, or pass --force to refresh template files",
            path.display(),
            path.display(),
            path.display()
        );
    }
    format!(
        "{} already exists and is not empty; pass --force to write Stoffel template files while preserving unrelated files",
        path.display()
    )
}

fn find_root(start: &Path) -> Result<PathBuf> {
    let mut dir = absolutize(start)?;
    let original = dir.clone();
    loop {
        if dir.join(CONFIG_FILE).exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            let nested = nested_config_paths(&original)?;
            if !nested.is_empty() {
                let paths = nested
                    .iter()
                    .map(|path| path.parent().unwrap_or(path).display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "could not find {CONFIG_FILE} in {} or any parent directory; found nested Stoffel project(s) at {paths}. Pass one of those project paths instead",
                    original.display()
                );
            }
            anyhow::bail!(
                "could not find {CONFIG_FILE} in {} or any parent directory; run `stoffel init` first or pass a project path",
                original.display()
            );
        }
    }
}

fn nested_config_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut configs = Vec::new();
    collect_nested_config_paths(root, 0, &mut configs)?;
    configs.sort();
    Ok(configs)
}

fn collect_nested_config_paths(
    root: &Path,
    depth: usize,
    configs: &mut Vec<PathBuf>,
) -> Result<()> {
    if depth >= 3 || !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            let config = path.join(CONFIG_FILE);
            if config.exists() {
                configs.push(config);
            } else {
                collect_nested_config_paths(&path, depth + 1, configs)?;
            }
        }
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<ProjectConfig> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut config: ProjectConfig =
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    if config.build.source.as_os_str().is_empty() {
        config.build.source = BuildConfig::default().source;
    }
    validate_source_config(&config.build.source)?;
    if config.build.target_dir.as_os_str().is_empty() {
        config.build.target_dir = BuildConfig::default().target_dir;
    }
    validate_target_dir(
        path.parent().unwrap_or(Path::new(".")),
        &config.build.target_dir,
    )?;
    validate_optimization_level(config.build.optimization_level)?;
    validate_mpc_config(&config.mpc)?;
    Ok(config)
}

fn validate_source_config(source: &Path) -> Result<()> {
    if source == Path::new(".") {
        anyhow::bail!(
            "invalid build.source .; choose a source file like src/main.stfl or a source directory like src"
        );
    }
    if source.is_absolute() {
        anyhow::bail!(
            "invalid build.source {}; expected a relative path inside the project",
            source.display()
        );
    }
    if source
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!(
            "invalid build.source {}; source paths must stay inside the project",
            source.display()
        );
    }
    if source
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension != "stfl")
    {
        anyhow::bail!(
            "invalid build.source {}; expected a .stfl source file or source directory",
            source.display()
        );
    }
    Ok(())
}

fn validate_mpc_config(config: &MpcConfig) -> Result<()> {
    if matches!(config.threshold, Some(0)) {
        anyhow::bail!("invalid [mpc] config: threshold must be greater than zero");
    }
    let mut builder = SdkMpcConfig::builder()
        .parties(config.parties.unwrap_or(5))
        .threshold(config.threshold.unwrap_or(1))
        .backend(config.backend.unwrap_or_default());
    if let Some(instance_id) = config.instance_id {
        builder = builder.instance_id(instance_id);
    }
    builder
        .build()
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("invalid [mpc] config: {error}"))
}

fn validate_optimization_level(level: Option<u8>) -> Result<()> {
    if let Some(level) = level {
        if level > 3 {
            anyhow::bail!(
                "invalid build.optimization_level {level}; expected an optimization level from 0 to 3"
            );
        }
    }
    Ok(())
}

fn validate_target_dir(root: &Path, target_dir: &Path) -> Result<()> {
    if target_dir.is_absolute() {
        anyhow::bail!(
            "invalid build.target_dir {}; expected a relative directory inside the project",
            target_dir.display()
        );
    }
    if target_dir
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!(
            "invalid build.target_dir {}; build artifacts must stay inside the project",
            target_dir.display()
        );
    }
    if target_dir == Path::new(".") {
        anyhow::bail!("invalid build.target_dir .; choose a dedicated build directory like target");
    }
    if target_dir.starts_with("src") {
        anyhow::bail!(
            "invalid build.target_dir {}; build artifacts must not be written under src/",
            target_dir.display()
        );
    }
    if target_dir.extension().is_some() {
        anyhow::bail!(
            "invalid build.target_dir {}; expected a directory path, not a file path",
            target_dir.display()
        );
    }
    let absolute = if target_dir.is_absolute() {
        target_dir.to_path_buf()
    } else {
        root.join(target_dir)
    };
    if absolute.is_file() {
        anyhow::bail!(
            "invalid build.target_dir {}; {} is an existing file",
            target_dir.display(),
            absolute.display()
        );
    }
    Ok(())
}

fn collect_stfl_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_stfl_files(&path, files)?;
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension == "stfl")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn write_new(path: PathBuf, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn default_config_text(name: String) -> String {
    config_text(name, "src/main.stfl")
}

fn default_readme_text(title: &str) -> String {
    format!(
        "# {title}\n\nValidate the Stoffel source:\n\n```sh\nstoffel check\n```\n\nRun the default local MPC example:\n\n```sh\nstoffel run --input a=40 --input b=2\n```\n\nRun the default example once with the development command:\n\n```sh\nstoffel dev --once --input a=40 --input b=2\n```\n\nBuild bytecode:\n\n```sh\nstoffel build\n```\n"
    )
}

fn config_text(name: String, source: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n[mpc]\nbackend = \"honeybadger\"\nparties = 5\nthreshold = 1\n\n[build]\nsource = \"{source}\"\ntarget_dir = \"target\"\n"
    )
}

fn default_library_config_text(name: String) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n[mpc]\nbackend = \"honeybadger\"\nparties = 5\nthreshold = 1\n\n[build]\nsource = \"src/lib.stfl\"\ntarget_dir = \"target\"\n"
    )
}

fn project_name(path: &Path) -> String {
    let mut name = String::new();
    let mut last_was_dash = false;
    for ch in path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != ".")
        .unwrap_or("stoffel-app")
        .chars()
    {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            name.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            name.push('-');
            last_was_dash = true;
        }
    }
    let name = name.trim_matches('-').to_owned();
    if name.is_empty() {
        "stoffel-app".to_owned()
    } else {
        name
    }
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
