use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // INTEGRATION STEP 3: bytecode is the contract shared by clients and nodes.
    // Build it first; Cargo intentionally does not compile Stoffel source here.
    println!("cargo:rerun-if-changed=artifacts/program.stflb");
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let bytecode = root.join("artifacts/program.stflb");
    if !bytecode.is_file() {
        return Err("build bytecode first: stoffel build --output artifacts/program.stflb".into());
    }
    // Generate typed client IO and ProgramManifest from that exact artifact.
    // Guide: https://docs.stoffelmpc.com/developer-skills/stoffel-typed-client-io-bindings
    stoffel_bindgen::generate_bindings(
        bytecode,
        PathBuf::from(std::env::var("OUT_DIR")?).join("stoffel_bindings.rs"),
    )?;
    Ok(())
}
