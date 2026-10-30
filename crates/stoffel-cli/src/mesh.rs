//! `stoffel start-mesh`, `stoffel stop-mesh` and `stoffel run --mesh`.
//!
//! A mesh is named, and everything about it lives in
//! `$STOFFEL_HOME/meshes/<name>/` (default `~/.stoffel/meshes/<name>/`). While it
//! runs, `mesh.toml` there says how to reach it; `stoffel run --mesh <name>`
//! reads that file, so any number of runs can share the mesh at once.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use stoffel::mesh::{StandingMesh, StandingMeshConfig, StandingMeshInfo, StandingMeshLayout};
use stoffel::prelude::*;

use crate::{run_builder, BuildArgs};

const INFO_FILE: &str = "mesh.toml";
const DETACHED_LOG: &str = "start-mesh.log";
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Args, Clone)]
pub(crate) struct StartMeshArgs {
    /// Directory of programs (.stfl sources or .stflb bytecode) the mesh serves.
    /// The set is fixed while the mesh runs; restart the mesh to change it.
    programs: PathBuf,
    /// Name to refer to the mesh by, e.g. in `stoffel run --mesh <NAME>`.
    #[arg(long, value_parser = parse_mesh_name)]
    name: String,
    /// Number of MPC parties.
    #[arg(long, default_value_t = 5, value_parser = crate::parse_positive_usize_arg)]
    parties: usize,
    /// Corruption threshold.
    #[arg(long, default_value_t = 1, value_parser = crate::parse_positive_usize_arg)]
    threshold: usize,
    /// Create at least this many client identities. By default the mesh has one
    /// per client slot its programs declare.
    #[arg(long, default_value_t = 0)]
    clients: usize,
    /// Preprocessing bundles each party keeps ready per program.
    #[arg(long, default_value_t = 9, value_parser = crate::parse_positive_usize_arg)]
    reservoir_burst_capacity: usize,
    /// Accept programs whose preprocessing demand is only bounded at run time.
    #[arg(long)]
    allow_dynamic_preprocessing: bool,
    /// How long the parties may take to form the mesh and prepare preprocessing.
    #[arg(long, default_value_t = 600, value_parser = crate::parse_positive_u64_arg)]
    startup_timeout_secs: u64,
    /// Path to the stoffel-run binary the parties run.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Start the mesh in the background and return once it is ready.
    #[arg(long)]
    detach: bool,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct StopMeshArgs {
    /// Name of the mesh to stop.
    #[arg(value_parser = parse_mesh_name)]
    name: String,
}

fn parse_mesh_name(value: &str) -> std::result::Result<String, String> {
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        Ok(value.to_owned())
    } else {
        Err("mesh names use letters, digits, '-' and '_'".to_owned())
    }
}

/// `$STOFFEL_HOME/meshes/<name>`, or `~/.stoffel/meshes/<name>`.
fn mesh_dir(name: &str) -> Result<PathBuf> {
    let home = match std::env::var_os("STOFFEL_HOME") {
        Some(home) => PathBuf::from(home),
        None => std::env::home_dir()
            .context("cannot find the home directory; set STOFFEL_HOME")?
            .join(".stoffel"),
    };
    Ok(home.join("meshes").join(name))
}

/// How to reach mesh `name` if it is running.
fn running_mesh(name: &str) -> Result<Option<StandingMeshInfo>> {
    let path = mesh_dir(name)?.join(INFO_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let info: StandingMeshInfo =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    // A mesh that was killed leaves its info file behind; its coordinator no
    // longer answers.
    Ok(reachable(info.coordinator).then_some(info))
}

fn reachable(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok()
}

pub(crate) async fn start_mesh(args: StartMeshArgs) -> Result<()> {
    if args.threshold >= args.parties {
        anyhow::bail!(
            "--threshold must be smaller than --parties (got {} parties, threshold {})",
            args.parties,
            args.threshold
        );
    }
    let root = mesh_dir(&args.name)?;
    if let Some(info) = running_mesh(&args.name)? {
        anyhow::bail!(
            "mesh `{}` is already running (pid {}); stop it with `stoffel stop-mesh {}`",
            args.name,
            info.pid,
            args.name
        );
    }
    let _ = std::fs::remove_file(root.join(INFO_FILE));
    if args.detach {
        return start_detached(&args, &root).await;
    }

    let layout = StandingMeshLayout::new(&root);
    install_programs(&layout, &args.programs)?;
    let runner = stoffel::vm::resolve_runner_binary(args.runner.as_deref())?;
    let mut config = StandingMeshConfig::new(runner, layout.clone());
    config.parties = args.parties;
    config.threshold = args.threshold;
    config.min_clients = args.clients;
    config.reservoir_burst_capacity = args.reservoir_burst_capacity;
    config.allow_dynamic_preprocessing = args.allow_dynamic_preprocessing;
    config.startup_timeout = Duration::from_secs(args.startup_timeout_secs);

    println!(
        "Starting mesh `{}` with {} parties (threshold {}) in {}",
        args.name,
        args.parties,
        args.threshold,
        root.display()
    );
    let mut mesh = StandingMesh::start(config).await?;
    let info = mesh.info().clone();
    let info_path = root.join(INFO_FILE);
    std::fs::write(&info_path, toml::to_string(&info)?)
        .with_context(|| format!("write {}", info_path.display()))?;
    println!(
        "Mesh `{}` is ready: coordinator {}, {} program(s), client slots {:?}",
        args.name,
        info.coordinator,
        info.programs.len(),
        info.client_slots
    );
    println!(
        "Run programs on it with `stoffel run <PROGRAM> --mesh {}`. Party logs: {}",
        args.name,
        root.join("nodes").display()
    );

    let outcome = tokio::select! {
        error = mesh.wait_for_failure() => Err(anyhow::Error::from(error)),
        signal = shutdown_signal() => signal,
    };
    println!("Stopping mesh `{}`", args.name);
    let _ = std::fs::remove_file(&info_path);
    mesh.shutdown().await;
    outcome
}

/// Replace the mesh's programs with the ones in `directory`, compiled exactly
/// as `stoffel run` compiles them, so that runs find them.
fn install_programs(layout: &StandingMeshLayout, directory: &Path) -> Result<()> {
    let mut paths = std::fs::read_dir(directory)
        .with_context(|| format!("read program directory {}", directory.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "stfl" || extension == "stflb")
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        anyhow::bail!(
            "{} contains no .stfl or .stflb programs",
            directory.display()
        );
    }
    let programs_dir = layout.programs_dir();
    let _ = std::fs::remove_dir_all(&programs_dir);
    for path in paths {
        let runtime = run_builder(&BuildArgs::for_path(path.clone()))?
            .builder
            .build()
            .with_context(|| format!("compile or load {}", path.display()))?;
        let bytes = stoffel::vm::standing_program_bytes(&runtime)?;
        let program_id = layout.install_program(&bytes)?;
        println!(
            "  {} -> program {}",
            path.display(),
            hex_prefix(&program_id)
        );
    }
    Ok(())
}

fn hex_prefix(program_id: &[u8; 32]) -> String {
    program_id[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Run `stoffel start-mesh` again without `--detach` in its own process group,
/// logging to the mesh directory, and wait until it reports the mesh ready.
async fn start_detached(args: &StartMeshArgs, root: &Path) -> Result<()> {
    std::fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    let log_path = root.join(DETACHED_LOG);
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("create {}", log_path.display()))?;
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .arg("start-mesh")
        .arg(&args.programs)
        .args(["--name", &args.name])
        .args(["--parties", &args.parties.to_string()])
        .args(["--threshold", &args.threshold.to_string()])
        .args(["--clients", &args.clients.to_string()])
        .args([
            "--reservoir-burst-capacity",
            &args.reservoir_burst_capacity.to_string(),
        ])
        .args([
            "--startup-timeout-secs",
            &args.startup_timeout_secs.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    if let Some(runner) = &args.runner {
        command.arg("--runner").arg(runner);
    }
    if args.allow_dynamic_preprocessing {
        command.arg("--allow-dynamic-preprocessing");
    }
    #[cfg(unix)]
    {
        // Keep the mesh out of the terminal's process group, so that Ctrl-C in
        // the shell that started it does not stop it.
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .context("start the mesh in the background")?;
    println!(
        "Starting mesh `{}` in the background (pid {}), logging to {}",
        args.name,
        child.id(),
        log_path.display()
    );
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(args.startup_timeout_secs + 30);
    loop {
        if let Some(info) = running_mesh(&args.name)? {
            println!(
                "Mesh `{}` is ready: coordinator {}, {} program(s), client slots {:?}",
                args.name,
                info.coordinator,
                info.programs.len(),
                info.client_slots
            );
            println!("Stop it with `stoffel stop-mesh {}`.", args.name);
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the mesh exited ({status}) before it was ready:\n{}",
                log_tail(&log_path)
            );
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("the mesh was not ready in time; see {}", log_path.display());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn log_tail(path: &Path) -> String {
    let log = std::fs::read_to_string(path).unwrap_or_default();
    let lines = log.lines().collect::<Vec<_>>();
    lines[lines.len().saturating_sub(30)..].join("\n")
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

pub(crate) async fn stop_mesh(args: StopMeshArgs) -> Result<()> {
    let Some(info) = running_mesh(&args.name)? else {
        println!("Mesh `{}` is not running", args.name);
        return Ok(());
    };
    let status = std::process::Command::new("kill")
        .args(["-TERM", &info.pid.to_string()])
        .status()
        .context("run kill")?;
    if !status.success() {
        anyhow::bail!("could not signal mesh `{}` (pid {})", args.name, info.pid);
    }
    let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
    while reachable(info.coordinator) {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "mesh `{}` (pid {}) did not stop within {:?}",
                args.name,
                info.pid,
                STOP_TIMEOUT
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!("Stopped mesh `{}`", args.name);
    Ok(())
}

/// Run `entry` of the program `builder` holds once on mesh `name`.
pub(crate) async fn run_on_mesh(
    name: &str,
    builder: Stoffel,
    entry: &str,
    timeout: Duration,
) -> Result<()> {
    let info = running_mesh(name)?.with_context(|| {
        format!("mesh `{name}` is not running; start it with `stoffel start-mesh <PROGRAMS> --name {name}`")
    })?;
    let runtime = builder.build()?;
    let output = stoffel::vm::execute_on_standing_mesh(&runtime, entry, &info, timeout).await?;
    eprintln!("[stoffel] execution {}", output.execution_id);
    crate::print_values(&output.values);
    for client in &output.client_outputs {
        print!("client {}: ", client.client_slot);
        crate::print_values(&client.values);
    }
    Ok(())
}
