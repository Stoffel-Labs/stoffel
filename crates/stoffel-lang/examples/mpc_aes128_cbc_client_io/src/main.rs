#[allow(dead_code, unused_mut, unused_variables)]
mod stoffel_bindings {
    include!(concat!(env!("OUT_DIR"), "/stoffel_bindings.rs"));
}

use stoffel_bindings::ProgramClient;

const PROGRAM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/main.stfl");
const PLAINTEXT_HEX: &str = "6bc1bee22e409f96e93d7e117393172a";
const KEY_HEX: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CIPHERTEXT_HEX: &str = "7649abac8119b246cee98e9b12e9197d";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> stoffel::Result<()> {
    println!("Compiling {PROGRAM}");

    let program = ProgramClient::new(PROGRAM).local_runner_path_from_env("STOFFEL_RUN_BIN");

    let ciphertext = program.encrypt(PLAINTEXT_HEX, KEY_HEX).await?;
    let ciphertext = ciphertext.to_hex();
    println!("encrypt({PLAINTEXT_HEX}) = {ciphertext}");
    assert_eq!(
        ciphertext, CIPHERTEXT_HEX,
        "AES-128 CBC encryption must match the NIST SP 800-38A vector"
    );

    let plaintext = program.decrypt(CIPHERTEXT_HEX, KEY_HEX).await?;
    let plaintext = plaintext.to_hex();
    println!("decrypt({CIPHERTEXT_HEX}) = {plaintext}");
    assert_eq!(
        plaintext, PLAINTEXT_HEX,
        "AES-128 CBC decryption must recover the NIST SP 800-38A plaintext"
    );

    println!("PASS: encrypt and decrypt both validated through generated SDK bindings");
    Ok(())
}
