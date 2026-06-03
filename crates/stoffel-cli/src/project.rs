use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use stoffel::prelude::MpcBackend;

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
#[serde(default)]
pub struct ProjectConfig {
    pub package: PackageConfig,
    pub mpc: MpcConfig,
    pub build: BuildConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PackageConfig {
    pub name: String,
    pub version: String,
    pub authors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
        if path.exists() && !force && fs::read_dir(path)?.next().is_some() {
            anyhow::bail!(
                "{} already exists and is not empty; pass --force to write project files",
                path.display()
            );
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
        let source = match path {
            Some(path) if path.is_file() => absolutize(path)?,
            Some(path) if path.extension().is_some() => absolutize(path)?,
            _ => root.join(&config.build.source),
        };
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
        for entry in fs::read_dir(&tests_dir)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "stfl")
            {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    pub fn source_files(&self) -> Result<Vec<PathBuf>> {
        let source_dir = self.source_dir();
        if !source_dir.exists() {
            return Ok(vec![self.source.clone()]);
        }
        let mut files = Vec::new();
        collect_stfl_files(&source_dir, &mut files)?;
        files.sort();
        if files.is_empty() {
            files.push(self.source.clone());
        }
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
        self.root.join(
            self.config
                .build
                .source
                .parent()
                .unwrap_or(Path::new("src")),
        )
    }

    pub fn default_bytecode_path_for_source(&self, source: &Path, release: bool) -> PathBuf {
        let profile = if release { "release" } else { "debug" };
        let stem = source
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("main");
        let name = if source == self.source_path() && stem == "main" {
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
        if preferred.exists() {
            return Ok(Some(preferred));
        }
        let legacy_preferred = preferred.with_extension("stflb");
        if legacy_preferred.exists() {
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
        Ok(files.into_iter().next())
    }
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
        "# Stoffel Project\n\nRun `stoffel run --input a=40 --input b=2` to execute through the local MPC coordinator.\n",
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
        "# Stoffel Library\n\nRun `stoffel check` to compile the library source.\n",
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
        "# Stoffel Rust Project\n\nThe Stoffel program lives in `stoffel/src/program.stfl`.\n",
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
    Ok(())
}

fn find_root(start: &Path) -> Result<PathBuf> {
    let mut dir = absolutize(start)?;
    loop {
        if dir.join(CONFIG_FILE).exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            anyhow::bail!("could not find {CONFIG_FILE}; run `stoffel init` first");
        }
    }
}

fn read_config(path: &Path) -> Result<ProjectConfig> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut config: ProjectConfig =
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    if config.build.source.as_os_str().is_empty() {
        config.build.source = BuildConfig::default().source;
    }
    if config.build.target_dir.as_os_str().is_empty() {
        config.build.target_dir = BuildConfig::default().target_dir;
    }
    Ok(config)
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
    if path.exists() {
        return Ok(());
    }
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn default_config_text(name: String) -> String {
    config_text(name, "src/main.stfl")
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
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != ".")
        .unwrap_or("stoffel-app")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
