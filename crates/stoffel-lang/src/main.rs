use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser as ClapParser; // Alias to avoid name clash with our parser module
use stoffel_vm_types::compiled_binary::{MpcBackend, MpcCurve};
use stoffellang::{binary_converter, bytecode, compiler, core_types, errors};

const SRC_EXT: &str = "stfl";
const BIN_EXT: &str = "stflb";

/// Stoffel Language Compiler
#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// The source file to compile or the binary to disassemble
    #[arg(required = true)]
    filename: String,

    /// Output binary file path
    #[arg(short, long)]
    output: Option<String>,

    /// Generate VM-compatible binary
    #[arg(short = 'b', long)]
    binary: bool,

    /// Disassemble a compiled Stoffel binary (.stflb) instead of compiling source
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disassemble: bool,

    /// Print intermediate representations (Tokens, AST)
    #[arg(long)]
    print_ir: bool,

    /// Set optimization level (0-3). Accepts `-O3` or `-O 3`.
    #[arg(short = 'O', long = "opt-level",
          default_value_t = 0,
          value_parser = clap::value_parser!(u8).range(0..=3),
          value_name = "N")]
    opt_level: u8,

    /// Enable optimizations (shorthand for -O2)
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "opt_level")]
    optimize: bool,

    /// MPC backend to record in generated .stflb metadata: honeybadger or avss
    #[arg(long, default_value = "honeybadger")]
    mpc_backend: String,

    /// MPC curve to record in generated .stflb AVSS metadata.
    #[arg(long, default_value = "bls12_381")]
    mpc_curve: String,
}

fn dedupe_constants_for_display(constants: &[bytecode::Constant]) -> Vec<bytecode::Constant> {
    use std::collections::HashSet;
    let mut seen: HashSet<core_types::Value> = HashSet::new();
    let mut out = Vec::with_capacity(constants.len());
    for c in constants.iter().cloned() {
        let v = core_types::Value::from(c.clone());
        if seen.insert(v) {
            out.push(c);
        }
    }
    out
}

fn main() {
    let args = CliArgs::parse();

    let filename = &args.filename;

    // Small helpers for extension enforcement and output path shaping
    let has_ext = |p: &str, ext: &str| Path::new(p).extension().map(|e| e == ext).unwrap_or(false);
    let ensure_output_ext = |mut p: PathBuf, required_ext: &str| -> (PathBuf, Option<String>) {
        let mut warning: Option<String> = None;
        match p.extension().map(|e| e.to_string_lossy().to_string()) {
            Some(ext) if ext == required_ext => {}
            Some(other) => {
                p.set_extension(required_ext);
                warning = Some(format!(
                    "--output had extension '.{}'; adjusted to '.{}' to match required binary format",
                    other, required_ext
                ));
            }
            None => {
                p.set_extension(required_ext);
            }
        }
        (p, warning)
    };

    // Disassemble mode: read binary and print human-readable disassembly
    if args.disassemble {
        // Enforce .stflb input for disassembly
        if !has_ext(filename, BIN_EXT) {
            eprintln!(
                "Error: Disassembly expects a .{} file. Got '{}'\nHint: Use files like 'program.{}'",
                BIN_EXT, filename, BIN_EXT
            );
            process::exit(2);
        }
        match binary_converter::load_from_file(filename) {
            Ok(bin) => {
                let text = binary_converter::disassemble(&bin);
                println!("{}", text);
                return;
            }
            Err(e) => {
                eprintln!("Error loading binary '{}': {:?}", filename, e);
                process::exit(1);
            }
        }
    }

    // Compile mode: enforce .stfl source files
    if !has_ext(filename, SRC_EXT) {
        eprintln!(
            "Error: Source files must have .{} extension. Got '{}'\nHint: Rename to something like 'program.{}'",
            SRC_EXT, filename, SRC_EXT
        );
        process::exit(2);
    }

    let source = match fs::read_to_string(filename) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading file '{}': {}", filename, e);
            process::exit(1);
        }
    };

    let file_path = Path::new(filename);
    let _file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mpc_backend = match args.mpc_backend.as_str() {
        "honeybadger" | "hb" => MpcBackend::HoneyBadger,
        "avss" => MpcBackend::Avss,
        other => {
            eprintln!(
                "Error: unsupported --mpc-backend '{}'. Expected 'honeybadger' or 'avss'",
                other
            );
            process::exit(2);
        }
    };
    let mpc_curve = match args.mpc_curve.as_str() {
        "bls12_381" | "bls12-381" | "bls12381" => MpcCurve::Bls12_381,
        "bn254" => MpcCurve::Bn254,
        "curve25519" | "curve-25519" => MpcCurve::Curve25519,
        "ed25519" | "ed-25519" => MpcCurve::Ed25519,
        "secp256k1" | "secp256-k1" => MpcCurve::Secp256k1,
        "p-256" | "p256" | "nist-p256" | "secp256r1" | "secp256-r1" => MpcCurve::Secp256r1,
        other => {
            eprintln!(
                "Error: unsupported --mpc-curve '{}'. Expected 'bls12_381', 'bn254', 'curve25519', 'ed25519', 'secp256k1', or 'p-256'",
                other
            );
            process::exit(2);
        }
    };

    let options = compiler::CompilerOptions {
        optimize: args.optimize || args.opt_level > 0,
        optimization_level: if args.optimize { 2 } else { args.opt_level },
        print_ir: args.print_ir,
        mpc_backend,
        mpc_curve,
    };

    println!("Compiling {}...", filename);

    // Use compile_file to automatically handle multi-file projects with imports
    match compiler::compile_file(file_path, &source, &options) {
        Ok(compiled_program) => {
            println!("Compilation successful!");

            if args.print_ir {
                println!("\n--- Generated Bytecode ---");
                println!("Main Chunk:");
                println!(
                    "  Constants: {:?}",
                    dedupe_constants_for_display(&compiled_program.main_chunk.constants)
                );
                println!("  Instructions:");
                for (i, instruction) in compiled_program.main_chunk.instructions.iter().enumerate()
                {
                    println!("{:04}: {:?}", i, instruction);
                }
                println!("  Labels: {:?}", compiled_program.main_chunk.labels);

                if !compiled_program.function_chunks.is_empty() {
                    println!("\nCompiled Functions:");

                    // Sort function names for deterministic output
                    let mut names: Vec<_> =
                        compiled_program.function_chunks.keys().cloned().collect();
                    names.sort();
                    for name in names {
                        if let Some(chunk) = compiled_program.function_chunks.get(&name) {
                            println!("  Function '{}':", name);
                            println!(
                                "    Constants: {:?}",
                                dedupe_constants_for_display(&chunk.constants)
                            );
                            println!("    Instructions:");
                            for (i, instruction) in chunk.instructions.iter().enumerate() {
                                println!("    {:04}: {:?}", i, instruction);
                            }
                            println!("    Labels: {:?}", chunk.labels);
                        }
                    }
                }
                println!("------------------------");
            }

            // Generate VM-compatible binary if requested
            if args.binary {
                // Determine output file path
                let output_path: String = {
                    let chosen = match &args.output {
                        Some(path) => PathBuf::from(path),
                        None => {
                            // Default to source filename with .stflb extension
                            file_path.with_extension(BIN_EXT)
                        }
                    };
                    let (fixed, warn) = ensure_output_ext(chosen, BIN_EXT);
                    if let Some(w) = warn {
                        eprintln!("Warning: {}", w);
                    } else if args.output.is_none() {
                        println!(
                            "No output file specified, using default: {}",
                            fixed.to_string_lossy()
                        );
                    }
                    fixed.to_string_lossy().to_string()
                };

                // Convert to VM binary format
                println!("Generating VM-compatible binary...");
                let binary = binary_converter::convert_to_binary(&compiled_program);

                // Save to file
                match binary_converter::save_to_file(&binary, &output_path) {
                    Ok(_) => println!("Binary saved to {}", output_path),
                    Err(e) => eprintln!("Error saving binary: {:?}", e),
                }
            }
        }
        Err(errors) => {
            eprintln!("\n{}", errors::format_error_header(errors.len())); // Use helper for consistent header
            for error in errors {
                // Create a mutable copy to add the snippet
                let mut error_with_snippet = error.clone();
                // Generate the snippet using the actual source code
                let snippet_str = errors::extract_source_snippet(&source, &error.location, 2);
                error_with_snippet.source_snippet = Some(snippet_str.into_boxed_str());
                // Print the error using the enhanced formatter
                eprintln!("{}", error_with_snippet.format_with_colors());
            }
            process::exit(1);
        }
    }
}
