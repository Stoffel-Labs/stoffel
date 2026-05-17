//! AVSS certificate program generators.
//!
//! These fixtures are intended for the AVSS/local-store path, not the
//! coordinator client path. The keygen program writes a persistent CA signing
//! share, and the signing program loads that share and signs a placeholder TBS
//! digest. When the CA can feed real TBS digests into AVSS runs, the digest
//! source in the signing program can be swapped without changing the threshold
//! signing flow.
//!
//! The signing program returns raw threshold Schnorr-style material:
//! `R || s || pk`. It does not emit an X.509 signatureAlgorithm wrapper or a
//! DER-encoded ECDSA signature.

use std::collections::HashMap;

use stoffel_vm_types::{
    compiled_binary::utils::{from_vm_functions, load_from_file, save_to_file, try_to_vm_functions},
    core_types::Value,
    functions::VMFunction,
    instructions::Instruction,
};

const SIGNING_KEY_STORAGE_KEY: &str = "avss:ca:signing-key:v1";
const PLACEHOLDER_TBS_DIGEST_INPUT: &str = "stoffel-avss-ca-tbs-digest-placeholder-v1";

/// Build a program that creates and persists the AVSS CA signing key share.
///
/// Result: `pk`, the compressed commitment[0] public key bytes.
pub fn build_avss_certificate_keygen_program() -> (Vec<Instruction>, HashMap<String, usize>) {
    let instructions = vec![
        // r1 = storage key
        Instruction::LDI(1, Value::String(SIGNING_KEY_STORAGE_KEY.to_owned())),
        // r4 = Share.random() -- cooperative DKG for the CA signing key
        Instruction::CALL("Share.random".to_owned()),
        Instruction::MOV(4, 0),
        // LocalStorage.store(key, sk)
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(4),
        Instruction::CALL("LocalStorage.store".to_owned()),
        // Return commitment[0] as the public key.
        Instruction::LDI(5, Value::I64(0)),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.get_commitment".to_owned()),
        Instruction::RET(0),
    ];

    (instructions, HashMap::new())
}

/// Build a program that loads the persisted AVSS CA key and signs a TBS digest.
///
/// Current digest source: SHA-256 of `PLACEHOLDER_TBS_DIGEST_INPUT`.
/// Result: `R || s || pk`, where:
/// - `pk = commitment[0](sk)`
/// - `R = commitment[0](k)`
/// - `e = H(R || pk || tbs_digest) mod curve_order`
/// - `s = k + e * sk`
pub fn build_avss_certificate_sign_program() -> (Vec<Instruction>, HashMap<String, usize>) {
    let instructions = vec![
        // r1 = storage key
        Instruction::LDI(1, Value::String(SIGNING_KEY_STORAGE_KEY.to_owned())),
        // r4 = LocalStorage.load(key) -- persisted CA signing share
        Instruction::PUSHARG(1),
        Instruction::CALL("LocalStorage.load".to_owned()),
        Instruction::MOV(4, 0),
        // r6 = pk = commitment[0](sk)
        Instruction::LDI(5, Value::I64(0)),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.get_commitment".to_owned()),
        Instruction::MOV(6, 0),
        // r7 = Share.random() -- fresh cooperative nonce
        Instruction::CALL("Share.random".to_owned()),
        Instruction::MOV(7, 0),
        // r8 = R = commitment[0](k)
        Instruction::PUSHARG(7),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.get_commitment".to_owned()),
        Instruction::MOV(8, 0),
        // r9 = runtime curve name for Crypto.hash_to_field
        Instruction::CALL("Mpc.curve".to_owned()),
        Instruction::MOV(9, 0),
        // r11 = placeholder TBS digest bytes.
        Instruction::LDI(10, Value::String(PLACEHOLDER_TBS_DIGEST_INPUT.to_owned())),
        Instruction::PUSHARG(10),
        Instruction::CALL("Bytes.from_string".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::CALL("Crypto.sha256".to_owned()),
        Instruction::MOV(11, 0),
        // e = hash_to_field(sha256(R || pk || tbs_digest), curve)
        Instruction::PUSHARG(8),
        Instruction::PUSHARG(6),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::MOV(12, 0),
        Instruction::PUSHARG(12),
        Instruction::PUSHARG(11),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::CALL("Crypto.sha256".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(9),
        Instruction::CALL("Crypto.hash_to_field".to_owned()),
        Instruction::MOV(13, 0),
        // s = k + e * sk
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(13),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(14, 0),
        Instruction::PUSHARG(7),
        Instruction::PUSHARG(14),
        Instruction::CALL("Share.add".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::CALL("Share.open_field".to_owned()),
        Instruction::MOV(15, 0),
        // return R || s || pk
        Instruction::PUSHARG(8),
        Instruction::PUSHARG(15),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(6),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::RET(0),
    ];

    (instructions, HashMap::new())
}

fn certificate_function(
    instructions: Vec<Instruction>,
    labels: HashMap<String, usize>,
    register_count: usize,
) -> VMFunction {
    VMFunction::new(
        "main".to_owned(),
        vec![],
        vec![],
        None,
        register_count,
        instructions,
        labels,
    )
}

fn write_and_validate_bytecode(name: &str, function: VMFunction, expected_len: usize) {
    let binary = from_vm_functions(&[function]);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/tests/binaries")
        .join(name);

    save_to_file(&binary, &path).expect("failed to save AVSS certificate bytecode");

    let loaded = load_from_file(&path).expect("failed to reload AVSS certificate bytecode");
    let functions =
        try_to_vm_functions(&loaded).expect("generated certificate bytecode should be executable");

    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].name(), "main");
    assert_eq!(functions[0].instructions().len(), expected_len);
}

#[test]
fn generate_avss_certificate_bytecode() {
    let (keygen_instructions, keygen_labels) = build_avss_certificate_keygen_program();
    let keygen_len = keygen_instructions.len();
    write_and_validate_bytecode(
        "avss_certificate_keygen.stflb",
        certificate_function(keygen_instructions, keygen_labels, 8),
        keygen_len,
    );

    let (sign_instructions, sign_labels) = build_avss_certificate_sign_program();
    let sign_len = sign_instructions.len();
    write_and_validate_bytecode(
        "avss_certificate_sign.stflb",
        certificate_function(sign_instructions, sign_labels, 16),
        sign_len,
    );
}
