use std::path::PathBuf;

use stoffel_bindgen::{BindingsConfig, EntrypointBinding, ShareType};

fn bools(count: usize) -> Vec<ShareType> {
    vec![ShareType::boolean(); count]
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=main.stfl");

    let out_file = PathBuf::from(std::env::var("OUT_DIR")?).join("stoffel_bindings.rs");

    stoffel_bindgen::generate_bindings_from_source(
        "main.stfl",
        out_file,
        BindingsConfig {
            entrypoints: vec![
                EntrypointBinding::new("encrypt")
                    .input(0, "plaintext", "Plaintext")
                    .input(1, "key", "Aes128Key")
                    .output(0, "Ciphertext", bools(128)),
                EntrypointBinding::new("decrypt")
                    .input(0, "ciphertext", "Ciphertext")
                    .input(1, "key", "Aes128Key")
                    .output(0, "Plaintext", bools(128)),
            ],
            ..BindingsConfig::default()
        },
    )?;

    Ok(())
}
