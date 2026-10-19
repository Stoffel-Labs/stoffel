//! Prints a compiled binary's client-I/O manifest.
//!
//! The client path refuses a program whose manifest declares no clients, and a
//! node refuses a registration whose per-slot input count disagrees with the
//! manifest, so the slot table a deployment registers has to be read off the
//! program rather than guessed.
//!
//! Run with:
//!   cargo run -p stoffel-vm-types --example inspect_client_io_manifest -- <program.stflb>

use std::io::BufReader;

use stoffel_vm_types::compiled_binary::CompiledBinary;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: inspect_client_io_manifest <program.stflb>");
        std::process::exit(2);
    });
    let file = std::fs::File::open(&path).expect("open program");
    let binary =
        CompiledBinary::deserialize(&mut BufReader::new(file)).expect("deserialize program");
    let manifest = &binary.client_io_manifest;

    println!("backend: {:?}", manifest.mpc_backend);
    println!("curve:   {:?}", manifest.mpc_curve);
    println!("clients: {}", manifest.clients.len());
    for schema in &manifest.clients {
        println!(
            "  slot {}: {} input(s) {:?}, {} output(s) {:?}",
            schema.client_slot,
            schema.inputs.len(),
            schema.inputs,
            schema.outputs.len(),
            schema.outputs
        );
    }
    println!(
        "dynamic input templates: {}",
        manifest.dynamic_client_inputs.len()
    );
    for template in &manifest.dynamic_client_inputs {
        println!("  {template:?}");
    }
    println!(
        "slot table for this program: {}",
        manifest
            .clients
            .iter()
            .map(|s| format!("{}:{}", s.inputs.len(), s.outputs.len()))
            .collect::<Vec<_>>()
            .join(",")
    );
}
