mod project;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use stoffel::prelude::*;

use crate::project::{Project, Template};

#[derive(Debug, Parser)]
#[command(
    name = "stoffel",
    version,
    about = "Develop, build, and run Stoffel projects"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new Stoffel project.
    Init(InitArgs),
    /// Compile source without writing bytecode.
    Check(BuildArgs),
    /// Compile a program into Stoffel bytecode.
    Compile(BuildArgs),
    /// Compile the current project into target bytecode.
    Build(BuildArgs),
    /// Compile and run a program.
    Run(RunArgs),
    /// Compile and run the current project with local MPC nodes.
    Dev(DevArgs),
    /// Run Stoffel source files under tests/.
    Test(TestArgs),
    /// Remove generated build artifacts.
    Clean(CleanArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Directory to create. Defaults to the current directory.
    path: Option<PathBuf>,
    /// Project template to create.
    #[arg(long, value_enum, default_value_t = TemplateArg::Stoffel)]
    template: TemplateArg,
    /// Create files in an existing non-empty directory.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TemplateArg {
    Stoffel,
    Rust,
}

#[derive(Debug, Args, Clone)]
struct BuildArgs {
    /// Source file to compile. Defaults to src/main.stfl from Stoffel.toml.
    path: Option<PathBuf>,
    /// Output bytecode path. Defaults to target/{debug,release}/{name}.stflb.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Build with release output path.
    #[arg(long)]
    release: bool,
    /// MPC backend: honeybadger, avss, or avss:bls12_381.
    #[arg(long)]
    backend: Option<MpcBackend>,
    /// Number of MPC parties.
    #[arg(long)]
    parties: Option<usize>,
    /// Byzantine threshold.
    #[arg(long)]
    threshold: Option<usize>,
    /// MPC instance id.
    #[arg(long)]
    instance_id: Option<u64>,
    /// Print a compact program summary after compiling.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    build: BuildArgs,
    /// Function entrypoint to run.
    #[arg(long, default_value = "main")]
    entry: String,
    /// Named clear/local function input, written as name=value.
    #[arg(long = "input", value_name = "NAME=VALUE")]
    inputs: Vec<InputArg>,
    /// Run through local MPC nodes instead of the embedded clear VM.
    #[arg(long)]
    local: bool,
    /// Path to stoffel-run for local MPC execution.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Local MPC timeout in seconds.
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
}

#[derive(Debug, Args)]
struct DevArgs {
    /// Source file to compile. Defaults to src/main.stfl from Stoffel.toml.
    path: Option<PathBuf>,
    /// Function entrypoint to run.
    #[arg(long, default_value = "main")]
    entry: String,
    /// Named local function input, written as name=value.
    #[arg(long = "input", value_name = "NAME=VALUE")]
    inputs: Vec<InputArg>,
    /// Path to stoffel-run for local MPC execution.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Number of MPC parties.
    #[arg(long)]
    parties: Option<usize>,
    /// Byzantine threshold.
    #[arg(long)]
    threshold: Option<usize>,
    /// MPC backend: honeybadger, avss, or avss:bls12_381.
    #[arg(long)]
    backend: Option<MpcBackend>,
    /// Local MPC timeout in seconds.
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Specific test file to run. Defaults to all tests/*.stfl files.
    path: Option<PathBuf>,
    /// Run tests through local MPC nodes instead of clear execution.
    #[arg(long)]
    local: bool,
    /// Path to stoffel-run for local MPC execution.
    #[arg(long)]
    runner: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CleanArgs {
    /// Also remove release artifacts.
    #[arg(long)]
    release: bool,
}

#[derive(Debug, Clone)]
struct InputArg {
    name: String,
    value: Value,
}

impl std::str::FromStr for InputArg {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (name, value) = raw
            .split_once('=')
            .with_context(|| format!("input '{raw}' must be written as name=value"))?;
        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("input name cannot be empty");
        }
        Ok(Self {
            name: name.to_owned(),
            value: parse_value(value.trim()),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init(args) => init(args),
        Command::Check(args) => check(args),
        Command::Compile(args) | Command::Build(args) => build(args),
        Command::Run(args) => run(args).await,
        Command::Dev(args) => dev(args).await,
        Command::Test(args) => test(args).await,
        Command::Clean(args) => clean(args),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let template = match args.template {
        TemplateArg::Stoffel => Template::Stoffel,
        TemplateArg::Rust => Template::Rust,
    };
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    Project::init(&path, template, args.force)?;
    println!("Created Stoffel project at {}", path.display());
    Ok(())
}

fn check(args: BuildArgs) -> Result<()> {
    let project = Project::discover(args.path.as_deref())?;
    let runtime = configured_builder(&project, &args)?.build()?;
    println!(
        "Checked {} ({})",
        project.source_path().display(),
        function_list(runtime.program())
    );
    Ok(())
}

fn build(args: BuildArgs) -> Result<()> {
    let project = Project::discover(args.path.as_deref())?;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| project.default_bytecode_path(args.release));
    let runtime = configured_builder(&project, &args)?.build()?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    runtime.save_bytecode(&output)?;
    println!("Built {}", output.display());
    if args.summary {
        print_program_summary(runtime.program());
    }
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    let builder = apply_inputs(run_builder(&args.build)?, &args.inputs);
    if args.local {
        let mut runtime = builder.build()?;
        if let Some(path) = args.runner {
            runtime = runtime.local_runner_path(path);
        }
        let result = runtime
            .local_network()
            .entry(args.entry)
            .timeout(Duration::from_secs(args.timeout_secs))
            .run()
            .await?;
        print_values(&result);
    } else {
        let runtime = builder.build()?;
        let result = runtime.execute_clear_function(&args.entry)?;
        print_values(&result);
    }
    Ok(())
}

async fn dev(args: DevArgs) -> Result<()> {
    let build = BuildArgs {
        path: args.path,
        output: None,
        release: false,
        backend: args.backend,
        parties: args.parties,
        threshold: args.threshold,
        instance_id: None,
        summary: false,
    };
    let project = Project::discover(build.path.as_deref())?;
    let mut runtime = apply_inputs(configured_builder(&project, &build)?, &args.inputs).build()?;
    if let Some(path) = args.runner {
        runtime = runtime.local_runner_path(path);
    }
    let result = runtime
        .local_network()
        .entry(args.entry)
        .timeout(Duration::from_secs(args.timeout_secs))
        .run()
        .await?;
    print_values(&result);
    Ok(())
}

async fn test(args: TestArgs) -> Result<()> {
    let project = Project::discover(None)?;
    let files = match args.path {
        Some(path) => vec![path],
        None => project.test_files()?,
    };
    if files.is_empty() {
        println!("No Stoffel tests found");
        return Ok(());
    }

    let mut failures = 0;
    for file in &files {
        let builder = Stoffel::compile_file(file)?;
        let result = if args.local {
            let mut runtime = builder.build()?;
            if let Some(path) = &args.runner {
                runtime = runtime.local_runner_path(path);
            }
            runtime.execute_local().await
        } else {
            builder.execute_clear()
        };
        match result {
            Ok(values) => {
                print!("ok {}", file.display());
                if !values.is_empty() {
                    print!(" => ");
                    print_inline_values(&values);
                }
                println!();
            }
            Err(error) => {
                failures += 1;
                eprintln!("FAILED {}: {error}", file.display());
            }
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} Stoffel test(s) failed");
    }
    Ok(())
}

fn clean(args: CleanArgs) -> Result<()> {
    let project = Project::discover(None)?;
    let debug = project.target_dir().join("debug");
    remove_dir_if_exists(&debug)?;
    if args.release {
        remove_dir_if_exists(&project.target_dir().join("release"))?;
    }
    println!("Removed Stoffel build artifacts");
    Ok(())
}

fn configured_builder(project: &Project, args: &BuildArgs) -> Result<Stoffel> {
    let builder = Stoffel::compile_file(project.source_path())?;
    Ok(apply_build_config(builder, project, args))
}

fn run_builder(args: &BuildArgs) -> Result<Stoffel> {
    if let Some(path) = &args.path {
        if is_bytecode_path(path) {
            let builder = Stoffel::load_file(path)
                .with_context(|| format!("failed to load bytecode {}", path.display()))?;
            return Ok(apply_inline_build_config(builder, args));
        }
    }
    let project = Project::discover(args.path.as_deref())?;
    configured_builder(&project, args)
}

fn apply_build_config(builder: Stoffel, project: &Project, args: &BuildArgs) -> Stoffel {
    let mut builder = builder;
    let config = project.config();
    let backend = args.backend.or(config.mpc.backend);
    if let Some(backend) = backend {
        builder = builder.backend(backend);
    }
    if let Some(parties) = args.parties.or(config.mpc.parties) {
        builder = builder.parties(parties);
    }
    if let Some(threshold) = args.threshold.or(config.mpc.threshold) {
        builder = builder.threshold(threshold);
    }
    if let Some(instance_id) = args.instance_id.or(config.mpc.instance_id) {
        builder = builder.instance_id(instance_id);
    }
    builder
}

fn apply_inline_build_config(mut builder: Stoffel, args: &BuildArgs) -> Stoffel {
    if let Some(backend) = args.backend {
        builder = builder.backend(backend);
    }
    if let Some(parties) = args.parties {
        builder = builder.parties(parties);
    }
    if let Some(threshold) = args.threshold {
        builder = builder.threshold(threshold);
    }
    if let Some(instance_id) = args.instance_id {
        builder = builder.instance_id(instance_id);
    }
    builder
}

fn is_bytecode_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "stflb" | "stfb"))
}

fn apply_inputs(mut builder: Stoffel, inputs: &[InputArg]) -> Stoffel {
    for input in inputs {
        builder = builder.with_input(input.name.clone(), input.value.clone());
    }
    builder
}

fn parse_value(value: &str) -> Value {
    if let Ok(value) = value.parse::<i64>() {
        return Value::I64(value);
    }
    if let Ok(value) = value.parse::<u64>() {
        return Value::U64(value);
    }
    if let Ok(value) = value.parse::<bool>() {
        return Value::Bool(value);
    }
    if let Ok(value) = value.parse::<f64>() {
        return Value::Float(value);
    }
    Value::String(value.to_owned())
}

fn print_values(values: &[Value]) {
    print_inline_values(values);
    println!();
}

fn print_inline_values(values: &[Value]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            print!(" ");
        }
        print!("{value}");
    }
}

fn function_list(program: &Program) -> String {
    program.function_names().collect::<Vec<_>>().join(", ")
}

fn print_program_summary(program: &Program) {
    let summary = program.summary();
    println!("Functions: {}", summary.function_count);
    println!("Instructions: {}", summary.total_instruction_count);
    println!("Backend: {}", summary.bytecode_backend);
    if !summary.client_slots.is_empty() {
        println!("Client slots: {:?}", summary.client_slots);
    }
}

fn remove_dir_if_exists(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}
