use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use stoffel::prelude::MpcBackend;

const CONFIG_FILE: &str = "Stoffel.toml";

#[derive(Debug, Clone, Copy)]
pub enum Template {
    Stoffel,
    Rust,
}

#[derive(Debug, Clone)]
pub struct Project {
    root: PathBuf,
    source: PathBuf,
    config: ProjectConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MpcConfig {
    pub backend: Option<MpcBackend>,
    pub parties: Option<usize>,
    pub threshold: Option<usize>,
    pub instance_id: Option<u64>,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            backend: Some(MpcBackend::HoneyBadger),
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
    pub target_dir: PathBuf,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            package: PackageConfig::default(),
            mpc: MpcConfig::default(),
            build: BuildConfig::default(),
        }
    }
}

impl Default for PackageConfig {
    fn default() -> Self {
        Self {
            name: "stoffel-app".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            source: PathBuf::from("src/main.stfl"),
            target_dir: PathBuf::from("target"),
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
            Template::Rust => init_rust_project(path),
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

    pub fn target_dir(&self) -> PathBuf {
        self.root.join(&self.config.build.target_dir)
    }

    pub fn default_bytecode_path(&self, release: bool) -> PathBuf {
        let profile = if release { "release" } else { "debug" };
        self.target_dir()
            .join(profile)
            .join(format!("{}.stflb", self.config.package.name))
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
}

fn init_stoffel_project(path: &Path) -> Result<()> {
    write_new(
        path.join(CONFIG_FILE),
        &default_config_text(project_name(path)),
    )?;
    write_new(
        path.join("src/main.stfl"),
        "def main(a: int64, b: int64) -> int64:\n  return a + b\n",
    )?;
    write_new(
        path.join("README.md"),
        "# Stoffel Project\n\nRun `stoffel run --input a=40 --input b=2`.\n",
    )?;
    Ok(())
}

fn init_rust_project(path: &Path) -> Result<()> {
    init_stoffel_project(&path.join("stoffel"))?;
    write_new(
        path.join("Cargo.toml"),
        &format!(
            "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstoffel-rust-sdk = {{ git = \"https://github.com/Stoffel-Labs/StoffelVM\" }}\n",
            project_name(path)
        ),
    )?;
    write_new(
        path.join("src/main.rs"),
        "fn main() {\n    println!(\"Stoffel Rust SDK project\");\n}\n",
    )?;
    write_new(
        path.join("README.md"),
        "# Stoffel Rust Project\n\nThe Stoffel program lives in `stoffel/`.\n",
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
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n[mpc]\nbackend = \"honeybadger\"\nparties = 5\nthreshold = 1\n\n[build]\nsource = \"src/main.stfl\"\ntarget_dir = \"target\"\n"
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
