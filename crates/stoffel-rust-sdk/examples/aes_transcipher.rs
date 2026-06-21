//! AES-128 transciphering over MPC, driven by the Rust SDK.
//!
//! The client supplies a **clear (public) AES-128-CTR ciphertext** and a
//! **secret key**. The MPC nodes decrypt it inside MPC (CTR is self-inverse —
//! secure decryption, plaintext never revealed), uppercase the recovered text,
//! re-encrypt it under the same key+counter, and return the **new ciphertext**
//! to client 0. Only ciphertexts cross the public boundary.
//!
//! The clear ciphertext rides the SDK's named-input local adapter: the program
//! entry `main(ciphertext: list[int64], key: list[secret bool])` takes the
//! ciphertext as a non-secret parameter (fed as a public value) and the key as
//! a `secret bool` parameter (loaded as secret shares).
//!
//! Run:
//!   cargo run --release -p stoffel-rust-sdk --example aes_transcipher
//! (set STOFFEL_RUN_BIN to a built `stoffel-run` if it is not auto-discovered).

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use stoffel::prelude::*;

const PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../stoffel-lang/examples/mpc_aes128_transcipher/main.stfl"
);
const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
/// The program's public CTR counter block (`public_block([240..255])`).
const CTR0: [u8; 16] = [
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
];
const MESSAGE: &[u8; 16] = b"hello stoffel vm";
const EXPECTED_PLAINTEXT: &[u8; 16] = b"HELLO STOFFEL VM";

/// AES-128-CTR keystream for the single counter block (= AES_enc(CTR0)).
fn ctr_keystream() -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let mut keystream = GenericArray::clone_from_slice(&CTR0);
    cipher.encrypt_block(&mut keystream);
    keystream.into()
}

/// CTR over one block: ciphertext = plaintext XOR keystream (self-inverse, so
/// the same function both encrypts and decrypts).
fn ctr_xor(block: &[u8; 16]) -> [u8; 16] {
    let keystream = ctr_keystream();
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = block[i] ^ keystream[i];
    }
    out
}

/// AES feeds each byte as 8 secret bits in little-endian (LSB-first) order.
fn bits_lsb_first(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for b in 0..8 {
            bits.push((byte >> b) & 1 == 1);
        }
    }
    bits
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> stoffel::Result<()> {
    let ciphertext = ctr_xor(MESSAGE);
    // Clear (public) ciphertext bits, as a list[int64] of 0/1 values.
    let ciphertext_bits: Vec<Value> = bits_lsb_first(&ciphertext)
        .into_iter()
        .map(|b| Value::I64(b as i64))
        .collect();
    // Secret key bits, as a list[secret bool].
    let key_bits: Vec<Value> = bits_lsb_first(&KEY).into_iter().map(Value::Bool).collect();

    println!(
        "Client plaintext    = {:?}",
        std::str::from_utf8(MESSAGE).unwrap()
    );
    println!("Clear input ct       = {}", hex(&ciphertext));
    println!("Running AES-128 transciphering over MPC (clear ct in, secret key, new ct out)...");

    let (_returned, client_outputs) = Stoffel::compile_file(PROGRAM)?
        .parties(5)
        .threshold(1)
        .expected_output_clients(1)
        // Named inputs route through the local adapter by parameter type:
        // `ciphertext: list[int64]` -> public value, `key: list[secret bool]` -> shares.
        .with_input("ciphertext", Value::List(ciphertext_bits))
        .with_input("key", Value::List(key_bits))
        .execute_local_capturing_client_outputs()
        .await?;

    let client0 = client_outputs
        .iter()
        .find(|o| o.client_slot == 0)
        .expect("client 0 should receive the new ciphertext");
    assert_eq!(
        client0.values.len(),
        128,
        "expected 128 new-ciphertext bits, got {}",
        client0.values.len()
    );
    let new_ciphertext: [u8; 16] = client0
        .bytes()
        .try_into()
        .expect("client output should be 16 bytes");

    // The client decrypts the returned ciphertext with its key to read the
    // modified message back.
    let recovered = ctr_xor(&new_ciphertext);
    let recovered_text = String::from_utf8_lossy(&recovered);

    println!("client-received ct   = {}", hex(&new_ciphertext));
    println!("client decrypts to   = {recovered_text:?}");
    println!(
        "expected plaintext   = {:?}",
        std::str::from_utf8(EXPECTED_PLAINTEXT).unwrap()
    );

    // Validate two ways: the new ciphertext is exactly CTR(uppercased message),
    // and decrypting it yields the uppercased text.
    assert_eq!(
        new_ciphertext,
        ctr_xor(EXPECTED_PLAINTEXT),
        "client should receive a fresh CTR encryption of the uppercased message"
    );
    assert_eq!(
        recovered.as_slice(),
        EXPECTED_PLAINTEXT.as_slice(),
        "decrypting the returned ciphertext should yield the uppercased plaintext"
    );
    println!("PASS: clear ct in -> secure decrypt -> modify -> re-encrypt -> new ct out");
    Ok(())
}
