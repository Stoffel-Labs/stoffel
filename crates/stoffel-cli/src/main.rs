mod project;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use stoffel::prelude::*;

use crate::project::{init_library_project, Project, Template};

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
    /// Show project health and environment status.
    Status(StatusArgs),
    /// Remove generated build artifacts.
    Clean(CleanArgs),
    /// Update the CLI and project dependencies.
    Update(UpdateArgs),
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
    /// Create a library-style Stoffel project.
    #[arg(long)]
    lib: bool,
    /// Accept default answers for interactive setup.
    #[arg(long)]
    interactive: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TemplateArg {
    Stoffel,
    Python,
    Rust,
    Typescript,
    SolidityFoundry,
    SolidityHardhat,
}

#[derive(Debug, Args, Clone)]
struct BuildArgs {
    /// Source file to compile. Defaults to all src/*.stfl files from Stoffel.toml.
    path: Option<PathBuf>,
    /// Output bytecode path. Only valid when compiling one source file.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Generate VM-compatible bytecode. This is the default for build/compile.
    #[arg(short = 'b', long)]
    binary: bool,
    /// Disassemble a compiled Stoffel bytecode file.
    #[arg(long)]
    disassemble: bool,
    /// Print compiler intermediate representations.
    #[arg(long)]
    print_ir: bool,
    /// Set optimization level (0-3). Accepts `-O3` or `-O 3`.
    #[arg(
        short = 'O',
        long = "opt-level",
        value_parser = clap::value_parser!(u8).range(0..=3),
        value_name = "N"
    )]
    opt_level: Option<u8>,
    /// Enable optimizations with the default level O2.
    #[arg(long, conflicts_with = "opt_level")]
    optimize: bool,
    /// Build with release output path.
    #[arg(long)]
    release: bool,
    /// MPC backend: honeybadger, avss, or avss:bls12_381.
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Cryptographic field/curve. Non-default values select AVSS.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
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
    /// Local ClientStore input, written as client_slot=value.
    #[arg(long = "client-input", value_name = "SLOT=VALUE")]
    client_inputs: Vec<ClientInputArg>,
    /// Run through local MPC nodes. This is the default unless --network/--config is set.
    #[arg(long, conflicts_with = "network")]
    local: bool,
    /// Run against a real MPC network using --config.
    #[arg(long, conflicts_with = "local")]
    network: bool,
    /// Network/off-chain client TOML config for local or networked execution.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Client id/client slot for networked execution.
    #[arg(long)]
    client_id: Option<u64>,
    /// Network connection timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    connect_timeout_ms: u64,
    /// Path to stoffel-run for local MPC execution.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Local MPC timeout in seconds.
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
}

#[derive(Debug, Args, Clone)]
struct DevArgs {
    /// Source file to compile. Defaults to src/main.stfl from Stoffel.toml.
    path: Option<PathBuf>,
    /// Function entrypoint to run.
    #[arg(long, default_value = "main")]
    entry: String,
    /// Named local function input, written as name=value.
    #[arg(long = "input", value_name = "NAME=VALUE")]
    inputs: Vec<InputArg>,
    /// Local ClientStore input, written as client_slot=value.
    #[arg(long = "client-input", value_name = "SLOT=VALUE")]
    client_inputs: Vec<ClientInputArg>,
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
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Cryptographic field/curve. Non-default values select AVSS.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
    /// Local MPC timeout in seconds.
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
    /// Run once and exit instead of watching for changes.
    #[arg(long)]
    once: bool,
    /// Polling interval for hot reload file watching.
    #[arg(long, default_value_t = 500)]
    poll_ms: u64,
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Specific test file to run. Defaults to all tests/*.stfl files.
    path: Option<PathBuf>,
    /// Run tests through local MPC nodes instead of clear execution.
    #[arg(long)]
    local: bool,
    /// Run a specific test function or file stem.
    #[arg(long = "test")]
    test: Option<String>,
    /// Run integration tests only.
    #[arg(long)]
    integration: bool,
    /// Print detailed test output.
    #[arg(long, short)]
    verbose: bool,
    /// Path to stoffel-run for local MPC execution.
    #[arg(long)]
    runner: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Also show detailed dependency and network diagnostics.
    #[arg(long, short)]
    verbose: bool,
}

#[derive(Debug, Args)]
struct CleanArgs {
    /// Also remove release artifacts. Kept for compatibility; clean removes target by default.
    #[arg(long)]
    release: bool,
    /// Deep clean target, local Stoffel cache, and known ecosystem build caches.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct UpdateArgs {
    /// Only check what would be updated.
    #[arg(long)]
    check: bool,
    /// Skip updating/reinstalling the Stoffel CLI.
    #[arg(long)]
    no_self: bool,
    /// Skip project dependency updates.
    #[arg(long)]
    no_project: bool,
}

#[derive(Debug, Clone)]
struct InputArg {
    name: String,
    value: Value,
}

#[derive(Debug, Clone)]
struct ClientInputArg {
    client_slot: u64,
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

impl std::str::FromStr for ClientInputArg {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (client_slot, value) = raw.split_once('=').with_context(|| {
            format!("client input '{raw}' must be written as client_slot=value")
        })?;
        Ok(Self {
            client_slot: client_slot
                .trim()
                .parse()
                .with_context(|| format!("invalid client slot '{}'", client_slot.trim()))?,
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
        Command::Status(args) => status(args),
        Command::Clean(args) => clean(args),
        Command::Update(args) => update(args),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let template = match args.template {
        TemplateArg::Stoffel => Template::Stoffel,
        TemplateArg::Python => Template::Python,
        TemplateArg::Rust => Template::Rust,
        TemplateArg::Typescript => Template::TypeScript,
        TemplateArg::SolidityFoundry => Template::SolidityFoundry,
        TemplateArg::SolidityHardhat => Template::SolidityHardhat,
    };
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let _interactive = args.interactive;
    if args.lib {
        ensure_writable_project_dir(&path, args.force)?;
        init_library_project(&path)?;
    } else {
        Project::init(&path, template, args.force)?;
    }
    println!("Created Stoffel project at {}", path.display());
    Ok(())
}

fn check(args: BuildArgs) -> Result<()> {
    if args.disassemble {
        return disassemble(args);
    }
    let project = Project::discover(args.path.as_deref())?;
    for source in selected_sources(&project, &args)? {
        let runtime = configured_builder_for_source(&project, &args, &source)?.build()?;
        println!(
            "Checked {} ({})",
            source.display(),
            function_list(runtime.program())
        );
    }
    Ok(())
}

fn build(args: BuildArgs) -> Result<()> {
    if args.disassemble {
        return disassemble(args);
    }
    let project = Project::discover(args.path.as_deref())?;
    let sources = selected_sources(&project, &args)?;
    if args.output.is_some() && sources.len() > 1 {
        anyhow::bail!("--output can only be used when compiling one source file");
    }
    for source in sources {
        let output = args
            .output
            .clone()
            .unwrap_or_else(|| project.default_bytecode_path_for_source(&source, args.release));
        let runtime = configured_builder_for_source(&project, &args, &source)?.build()?;
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        runtime.save_bytecode(&output)?;
        print_build_stats(&output, runtime.program(), &project, &args)?;
        if args.summary {
            print_program_summary(runtime.program());
        }
    }
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    if args.network || args.config.is_some() {
        return run_network(args).await;
    }

    let mut builder =
        apply_run_inputs(run_builder(&args.build)?, &args.inputs, &args.client_inputs)?;
    if let Some(path) = args.runner {
        builder = builder.local_runner_path(path);
    }
    let result = builder
        .execute_local_function_with_timeout(&args.entry, Duration::from_secs(args.timeout_secs))
        .await?;
    print_values(&result);
    Ok(())
}

async fn run_network(args: RunArgs) -> Result<()> {
    let config_path = args
        .config
        .as_ref()
        .context("network execution requires --config")?;
    let builder = run_builder(&args.build)?;
    let runtime = builder.build()?;
    let inputs = args
        .inputs
        .iter()
        .map(|input| input.value.clone())
        .collect::<Vec<_>>();
    if !args.client_inputs.is_empty() {
        anyhow::bail!("network execution accepts --input values for the configured client slot; --client-input is only used for local ClientStore runs");
    }

    match read_run_network_config(config_path)? {
        RunNetworkConfig::OffChain(config) => {
            let client_id = client_id_from_u64(args.client_id.unwrap_or(config.client_slot))?;
            let client = runtime
                .client()
                .client_id(client_id)
                .offchain_io(config)
                .build()?;
            println!("Connected to off-chain MPC coordinator configuration");
            let result = client.run_function(&args.entry, &inputs).await?;
            print_values(&result);
        }
        RunNetworkConfig::Network(config) => {
            let summary = config.summary()?;
            let client_id = client_id_from_u64(args.client_id.unwrap_or(0))?;
            let client = runtime
                .client()
                .client_id(client_id)
                .network_config(&config)
                .connection_timeout(Duration::from_millis(args.connect_timeout_ms))
                .connect()
                .await?;
            let client_summary = client.summary();
            println!(
                "Connected to MPC network ({} servers, backend {}, threshold {})",
                client_summary.server_count, summary.backend, summary.threshold
            );
            anyhow::bail!(
                "network config establishes transport connectivity, but computation submission requires an off-chain client config with coordinator/node RPC and client identity"
            );
        }
    }
    Ok(())
}

fn client_id_from_u64(value: u64) -> Result<ClientId> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("client id {value} does not fit on this platform"))
}

async fn dev(args: DevArgs) -> Result<()> {
    if args.once {
        return run_dev_once(&args).await;
    }

    println!("Starting Stoffel dev server. Press Ctrl-C to stop.");
    let mut snapshot = WatchSnapshot::capture(args.path.as_deref())?;
    loop {
        if let Err(error) = run_dev_once(&args).await {
            eprintln!("dev run failed: {error:#}");
        }
        println!("Watching for changes...");
        snapshot
            .wait_for_change(args.path.as_deref(), Duration::from_millis(args.poll_ms))
            .await?;
        println!("Change detected. Reloading...");
    }
}

async fn run_dev_once(args: &DevArgs) -> Result<()> {
    let build = BuildArgs {
        path: args.path.clone(),
        output: None,
        binary: true,
        disassemble: false,
        print_ir: false,
        opt_level: None,
        optimize: false,
        release: false,
        backend: args.backend,
        field: args.field,
        parties: args.parties,
        threshold: args.threshold,
        instance_id: None,
        summary: false,
    };
    let project = Project::discover(build.path.as_deref())?;
    let mut runtime = apply_run_inputs(
        configured_builder(&project, &build)?,
        &args.inputs,
        &args.client_inputs,
    )?
    .build()?;
    if let Some(path) = &args.runner {
        runtime = runtime.local_runner_path(path);
    }
    let result = runtime
        .local_network()
        .entry(args.entry.clone())
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
        None => select_test_files(&project, args.test.as_deref(), args.integration)?,
    };
    if files.is_empty() {
        println!("No Stoffel tests found");
        return Ok(());
    }

    let mut failures = 0;
    for file in &files {
        let builder = Stoffel::compile_file(file)?;
        let entry = args
            .test
            .as_deref()
            .filter(|name| !test_name_matches_file(file, name))
            .unwrap_or("main");
        let result = if args.local {
            let mut runtime = builder.build()?;
            if let Some(path) = &args.runner {
                runtime = runtime.local_runner_path(path);
            }
            runtime.execute_local_function(entry).await
        } else {
            builder.execute_clear_function(entry)
        };
        match result {
            Ok(values) => {
                print!("ok {}", file.display());
                if args.verbose || !values.is_empty() {
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
    remove_dir_if_exists(&project.target_dir())?;
    remove_dir_if_exists(&project.cache_dir())?;
    if args.all {
        for path in deep_clean_paths(&project) {
            remove_dir_if_exists(&path)?;
        }
    } else if args.release {
        remove_dir_if_exists(&project.target_dir().join("release"))?;
    }
    println!("Removed Stoffel build artifacts");
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    let project = Project::discover(None)?;
    println!("Project: {}", project.config().package.name);
    println!("Root: {}", project.root().display());

    println!("Config: ok ({})", project.config_path().display());
    let mpc = MpcConfig::builder()
        .parties(project.config().mpc.parties.unwrap_or(5))
        .threshold(project.config().mpc.threshold.unwrap_or(1))
        .backend(project.config().mpc.backend.unwrap_or_default())
        .build();
    match mpc {
        Ok(config) => {
            let summary = config.summary()?;
            println!(
                "MPC: ok (backend {}, parties {}, threshold {})",
                summary.backend, summary.parties, summary.threshold
            );
        }
        Err(error) => println!("MPC: invalid ({error})"),
    }

    let dependencies = dependency_statuses(&project);
    if dependencies.is_empty() {
        println!("Dependencies: none detected");
    } else {
        let ready = dependencies.iter().filter(|dep| dep.ready).count();
        println!("Dependencies: {ready}/{} ready", dependencies.len());
        if args.verbose {
            for dep in &dependencies {
                println!(
                    "  {}: {}",
                    dep.name,
                    if dep.ready {
                        dep.detail.as_str()
                    } else {
                        "missing expected files"
                    }
                );
            }
        }
    }

    let sources = project.source_files()?;
    let mut compile_failures = 0;
    for source in &sources {
        let build = default_build_for_status(source.clone());
        match configured_builder_for_source(&project, &build, source).and_then(|builder| {
            builder
                .build()
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        }) {
            Ok(runtime) => {
                println!(
                    "Compile: ok {} ({})",
                    source.display(),
                    function_list(runtime.program())
                );
            }
            Err(error) => {
                compile_failures += 1;
                println!("Compile: failed {} ({error})", source.display());
            }
        }
    }
    if sources.is_empty() {
        println!("Compile: no source files found");
    }

    match network_status(&project) {
        Some(status) => println!("Network: {status}"),
        None => println!("Network: not configured"),
    }

    if compile_failures > 0 {
        anyhow::bail!("{compile_failures} source file(s) failed to compile");
    }
    Ok(())
}

fn update(args: UpdateArgs) -> Result<()> {
    println!("Stoffel CLI: {}", env!("CARGO_PKG_VERSION"));
    if args.check {
        println!("Update check: online version discovery is not configured for this source build");
    }

    if !args.no_self {
        update_self(args.check)?;
    }

    if !args.no_project {
        let project = Project::discover(None)?;
        update_project_dependencies(&project, args.check)?;
    }
    Ok(())
}

fn configured_builder(project: &Project, args: &BuildArgs) -> Result<Stoffel> {
    configured_builder_for_source(project, args, project.source_path())
}

fn configured_builder_for_source(
    project: &Project,
    args: &BuildArgs,
    source: &Path,
) -> Result<Stoffel> {
    let builder = Stoffel::compile_file(source)?;
    Ok(apply_build_config(builder, project, args))
}

fn run_builder(args: &BuildArgs) -> Result<Stoffel> {
    if let Some(path) = &args.path {
        if is_bytecode_path(path) {
            let builder = Stoffel::load_file(path)
                .with_context(|| format!("failed to load bytecode {}", path.display()))?;
            return Ok(apply_inline_build_config(builder, args));
        }
        let project = Project::discover(Some(path))?;
        return configured_builder_for_source(&project, args, path);
    }

    let project = Project::discover(None)?;
    if let Some(bytecode) = project.find_bytecode(args.release)? {
        let builder = Stoffel::load_file(&bytecode)
            .with_context(|| format!("failed to load bytecode {}", bytecode.display()))?;
        return Ok(apply_inline_build_config(builder, args));
    }
    configured_builder(&project, args)
}

fn apply_build_config(builder: Stoffel, project: &Project, args: &BuildArgs) -> Stoffel {
    let mut builder = builder;
    let config = project.config();
    let mut backend = args.backend.or(config.mpc.backend);
    if let Some(field) = args.field.or(config.mpc.curve) {
        if !matches!(backend, Some(MpcBackend::HoneyBadger)) || field != Curve::Bls12_381 {
            backend = Some(MpcBackend::Avss { curve: field });
        }
    }
    if let Some(backend) = backend {
        builder = builder.backend(backend);
    }
    let opt_level = effective_opt_level(args, config.build.optimization_level);
    builder = builder
        .optimization_level(opt_level)
        .optimize(args.optimize || opt_level > 0)
        .print_ir(args.print_ir);
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
    if let Some(field) = args.field {
        builder = builder.curve(field);
    }
    let opt_level = effective_opt_level(args, None);
    builder = builder
        .optimization_level(opt_level)
        .optimize(args.optimize || opt_level > 0)
        .print_ir(args.print_ir);
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

fn effective_opt_level(args: &BuildArgs, configured: Option<u8>) -> u8 {
    args.opt_level.or(configured).unwrap_or(if args.release {
        3
    } else if args.optimize {
        2
    } else {
        2
    })
}

fn selected_sources(project: &Project, args: &BuildArgs) -> Result<Vec<PathBuf>> {
    if let Some(path) = &args.path {
        Ok(vec![path.clone()])
    } else {
        project.source_files()
    }
}

fn disassemble(args: BuildArgs) -> Result<()> {
    let path = args
        .path
        .as_ref()
        .context("--disassemble requires a bytecode path")?;
    let runtime = Stoffel::load_file(path)?.build()?;
    print!("{}", runtime.program().disassemble());
    Ok(())
}

enum RunNetworkConfig {
    OffChain(OffChainClientConfig),
    Network(NetworkConfig),
}

fn read_run_network_config(path: &Path) -> Result<RunNetworkConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if let Ok(config) = toml::from_str::<OffChainClientConfig>(&raw) {
        config
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        return Ok(RunNetworkConfig::OffChain(config));
    }
    NetworkConfig::from_toml_str(&raw)
        .map(RunNetworkConfig::Network)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to parse {} as off-chain or network config: {error}",
                path.display()
            )
        })
}

fn select_test_files(
    project: &Project,
    test: Option<&str>,
    integration: bool,
) -> Result<Vec<PathBuf>> {
    let mut files = project.test_files()?;
    if integration {
        files.retain(|path| is_integration_test_file(path));
    }
    if let Some(name) = test {
        let matching_files = files
            .iter()
            .filter(|path| test_name_matches_file(path, name))
            .cloned()
            .collect::<Vec<_>>();
        if !matching_files.is_empty() {
            return Ok(matching_files);
        }
    }
    Ok(files)
}

fn test_name_matches_file(path: &Path, name: &str) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem == name)
}

fn is_integration_test_file(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.contains("integration"))
}

fn ensure_writable_project_dir(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force && std::fs::read_dir(path)?.next().is_some() {
        anyhow::bail!(
            "{} already exists and is not empty; pass --force to write project files",
            path.display()
        );
    }
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn is_bytecode_path(path: &Path) -> bool {
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

fn apply_run_inputs(
    builder: Stoffel,
    inputs: &[InputArg],
    client_inputs: &[ClientInputArg],
) -> Result<Stoffel> {
    let mut builder = apply_inputs(builder, inputs);
    let mut grouped = BTreeMap::<u64, Vec<Value>>::new();
    for input in client_inputs {
        grouped
            .entry(input.client_slot)
            .or_default()
            .push(input.value.clone());
    }
    for (client_slot, values) in grouped {
        builder = builder.with_client_input(client_slot, &values);
    }
    Ok(builder)
}

fn default_build_for_status(path: PathBuf) -> BuildArgs {
    BuildArgs {
        path: Some(path),
        output: None,
        binary: true,
        disassemble: false,
        print_ir: false,
        opt_level: None,
        optimize: false,
        release: false,
        backend: None,
        field: None,
        parties: None,
        threshold: None,
        instance_id: None,
        summary: false,
    }
}

#[derive(Debug)]
struct DependencyStatus {
    name: &'static str,
    ready: bool,
    detail: String,
}

fn dependency_statuses(project: &Project) -> Vec<DependencyStatus> {
    let root = project.root();
    let mut statuses = Vec::new();
    if root.join("Cargo.toml").exists() {
        statuses.push(DependencyStatus {
            name: "cargo",
            ready: command_exists("cargo"),
            detail: "Cargo.toml detected".to_owned(),
        });
    }
    if root.join("package.json").exists() {
        statuses.push(DependencyStatus {
            name: "npm",
            ready: command_exists("npm"),
            detail: "package.json detected".to_owned(),
        });
    }
    if root.join("requirements.txt").exists() || root.join("pyproject.toml").exists() {
        statuses.push(DependencyStatus {
            name: "python",
            ready: command_exists("python3") || command_exists("python"),
            detail: "Python dependency manifest detected".to_owned(),
        });
    }
    if root.join("foundry.toml").exists() {
        statuses.push(DependencyStatus {
            name: "foundry",
            ready: command_exists("forge"),
            detail: "foundry.toml detected".to_owned(),
        });
    }
    if root.join("hardhat.config.js").exists() || root.join("hardhat.config.ts").exists() {
        statuses.push(DependencyStatus {
            name: "hardhat",
            ready: command_exists("npm"),
            detail: "Hardhat config detected".to_owned(),
        });
    }
    statuses
}

fn network_status(project: &Project) -> Option<String> {
    let config = project.config();
    let backend = config.mpc.backend.unwrap_or_default();
    let parties = config.mpc.parties.unwrap_or(5);
    let threshold = config.mpc.threshold.unwrap_or(1);
    if parties == 0 {
        return Some("invalid (parties is 0)".to_owned());
    }
    let required = threshold.saturating_mul(3).saturating_add(1);
    if parties < required {
        return Some(format!(
            "invalid (parties {parties} must be >= 3 * threshold {threshold} + 1)"
        ));
    }
    Some(format!(
        "configured for local {backend} development ({parties} parties, threshold {threshold}); no live network probe configured"
    ))
}

fn update_self(check: bool) -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if check {
        println!(
            "CLI self-update: source checkout detected at {}",
            manifest_dir.display()
        );
        return Ok(());
    }
    println!("Updating Stoffel CLI from local source...");
    run_command(
        manifest_dir,
        "cargo",
        &["install", "--path", ".", "--force"],
    )
}

fn update_project_dependencies(project: &Project, check: bool) -> Result<()> {
    let root = project.root();
    let mut detected = false;

    if root.join("Cargo.toml").exists() {
        detected = true;
        if check {
            println!("Project update: cargo dependencies detected");
        } else {
            run_command(root, "cargo", &["update"])?;
        }
    }
    if root.join("package.json").exists() {
        detected = true;
        if check {
            println!("Project update: npm dependencies detected");
        } else {
            run_command(root, "npm", &["update"])?;
        }
    }
    if root.join("requirements.txt").exists() {
        detected = true;
        if check {
            println!("Project update: requirements.txt detected");
        } else if command_exists("python3") {
            run_command(
                root,
                "python3",
                &[
                    "-m",
                    "pip",
                    "install",
                    "--upgrade",
                    "-r",
                    "requirements.txt",
                ],
            )?;
        } else {
            run_command(
                root,
                "python",
                &[
                    "-m",
                    "pip",
                    "install",
                    "--upgrade",
                    "-r",
                    "requirements.txt",
                ],
            )?;
        }
    }
    if root.join("foundry.toml").exists() && command_exists("forge") {
        detected = true;
        if check {
            println!("Project update: Foundry project detected");
        } else {
            run_command(root, "forge", &["update"])?;
        }
    }

    if !detected {
        println!("Project update: no dependency manifests detected");
    }
    Ok(())
}

fn run_command(cwd: &Path, program: &str, args: &[&str]) -> Result<()> {
    if !command_exists(program) {
        anyhow::bail!("required command '{program}' was not found in PATH");
    }
    println!("Running: {} {}", program, args.join(" "));
    let status = ProcessCommand::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to start {program}"))?;
    if !status.success() {
        anyhow::bail!(
            "command '{program} {}' failed with {status}",
            args.join(" ")
        );
    }
    Ok(())
}

fn command_exists(program: &str) -> bool {
    ProcessCommand::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn deep_clean_paths(project: &Project) -> Vec<PathBuf> {
    [
        ".stoffel",
        "node_modules",
        ".pytest_cache",
        "__pycache__",
        "out",
        "cache",
        "artifacts",
    ]
    .into_iter()
    .map(|path| project.root().join(path))
    .collect()
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
    println!("Curve: {}", summary.bytecode_curve);
    if !summary.client_slots.is_empty() {
        println!("Client slots: {:?}", summary.client_slots);
    }
}

fn print_build_stats(
    output: &Path,
    program: &Program,
    project: &Project,
    args: &BuildArgs,
) -> Result<()> {
    let bytecode = program.bytecode_summary()?;
    let summary = &bytecode.program;
    let opt_level = effective_opt_level(args, project.config().build.optimization_level);
    println!("Built {}", output.display());
    println!("Bytecode size: {} bytes", bytecode.byte_len);
    println!(
        "Optimization: O{} ({})",
        opt_level,
        if opt_level > 0 { "enabled" } else { "disabled" }
    );
    println!(
        "Profile: {}",
        if args.release { "release" } else { "debug" }
    );
    println!("Functions: {}", summary.function_count);
    println!("Instructions: {}", summary.total_instruction_count);
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchSnapshot {
    files: BTreeMap<PathBuf, Option<FileFingerprint>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    modified: Option<SystemTime>,
    len: u64,
}

impl WatchSnapshot {
    fn capture(path: Option<&Path>) -> Result<Self> {
        let project = Project::discover(path)?;
        let mut files = BTreeMap::new();
        for file in project.watch_files()? {
            files.insert(file.clone(), file_fingerprint(&file));
        }
        Ok(Self { files })
    }

    async fn wait_for_change(&mut self, path: Option<&Path>, interval: Duration) -> Result<()> {
        let interval = if interval.is_zero() {
            Duration::from_millis(500)
        } else {
            interval
        };
        loop {
            tokio::time::sleep(interval).await;
            let next = Self::capture(path)?;
            if next != *self {
                *self = next;
                return Ok(());
            }
        }
    }
}

fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileFingerprint {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}
