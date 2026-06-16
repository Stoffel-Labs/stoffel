//! End-to-end client-I/O demo for AES-128 CBC over MPC, driven by the Rust SDK.
//!
//! Feeds the NIST SP 800-38A plaintext + key as secret **client inputs**
//! (client 0 = data owner, client 1 = key holder), runs the program in the
//! local 5-party simulator, and validates the resulting ciphertext against the
//! NIST vector. The program also delivers the ciphertext block back to client 0
//! via `send_to_client` (client output).
//!
//! Run:
//!   cargo run --release -p stoffel-rust-sdk --example aes_cbc_client_io
//! (set STOFFEL_RUN_BIN to a built `stoffel-run` if it is not auto-discovered).

use stoffel::prelude::*;

const PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../stoffel-lang/examples/mpc_aes128_cbc_client_io/main.stfl"
);
const PLAINTEXT_HEX: &str = "6bc1bee22e409f96e93d7e117393172a";
const KEY_HEX: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const EXPECTED_C0: &str = "7649abac8119b246cee98e9b12e9197d";

/// AES feeds each byte as 8 secret bits in little-endian (LSB-first) order.
fn bits_lsb_first(hex: &str) -> Vec<bool> {
    let mut bits = Vec::with_capacity(hex.len() * 4);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex");
        for b in 0..8 {
            bits.push((byte >> b) & 1 == 1);
        }
    }
    bits
}

/// Reassemble a 16-byte block from 128 client-output bits (LSB-first per byte).
fn block_from_bits(bits: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    for (idx, bit) in bits.iter().enumerate() {
        if *bit != 0 {
            bytes[idx / 8] |= 1 << (idx % 8);
        }
    }
    bytes
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> stoffel::Result<()> {
    let plaintext = bits_lsb_first(PLAINTEXT_HEX);
    let key = bits_lsb_first(KEY_HEX);

    println!("Running AES-128 CBC over MPC (client 0 = plaintext, client 1 = key)...");
    let (_returned, client_outputs) = Stoffel::compile_file(PROGRAM)?
        .parties(5)
        .threshold(1)
        // Declaring output clients enables the client-output capability, so the
        // program's `send_to_client` path runs (delivering the ciphertext to
        // client 0). Must cover the full input-client roster (slots 0 and 1).
        .expected_output_clients(2)
        .with_client_input(0, &plaintext) // data owner: 128 plaintext bits
        .with_client_input(1, &key) // key holder: 128 key bits
        .execute_local_capturing_client_outputs()
        .await?;

    // The ciphertext is what client 0 actually RECEIVES via send_to_client,
    // reconstructed off the output shares — never revealed to the nodes.
    let client0 = client_outputs
        .iter()
        .find(|o| o.client_slot == 0)
        .expect("client 0 should receive a client output");
    assert_eq!(
        client0.values.len(),
        128,
        "expected 128 output bits, got {}",
        client0.values.len()
    );
    let bytes = block_from_bits(&client0.values);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    println!("client-received ciphertext = {hex}");
    println!("NIST C0                    = {EXPECTED_C0}");
    assert_eq!(
        hex, EXPECTED_C0,
        "client-received AES-128 CBC ciphertext must match the NIST SP 800-38A vector"
    );
    println!("PASS: client received the correct ciphertext (no reveal to nodes)");
    Ok(())
}
