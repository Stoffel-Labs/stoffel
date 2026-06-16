# MPC AES-128 CBC: Client Input + Client Output

A full client-I/O AES-128 CBC encryption of one block over MPC, validated
end-to-end through the Rust SDK:

- **Client 0 (data owner)** supplies a secret plaintext block (128 secret bits)
  as client input.
- **Client 1 (key holder)** supplies the 128-bit AES key as client input.
- The public CBC IV (NIST 000102..0f) is built in the program.
- The 128-bit ciphertext is delivered **only to client 0** via `send_to_client`.
  It is **never opened/revealed**, so the compute nodes never learn it — the
  client reconstructs it from the output shares it receives.

Inputs are read and the output is sent at **literal client slots**, so the
client-IO manifest statically records 128 inputs per client and 128 outputs for
client 0; the local runner reads the output count from the manifest (no manual
count needed).

## Run + validate through the Rust SDK

The SDK harness feeds the NIST SP 800-38A plaintext and key as secret client
inputs, runs the program in the local 5-party simulator, and reconstructs the
**client-received** ciphertext (via the off-chain client's `obtain_outputs`,
not a public reveal), asserting it equals the NIST vector `C0 = 7649abac8119b246cee98e9b12e9197d`:

```sh
STOFFEL_RUN_BIN=target/release/stoffel-run \
  cargo run --release -p stoffel-rust-sdk --example aes_cbc_client_io
```

The harness uses
`Stoffel::compile_file(...).expected_output_clients(2)
.with_client_input(0, plaintext_bits).with_client_input(1, key_bits)
.execute_local_capturing_client_outputs()` — the new SDK entry point that
returns the reconstructed client outputs.
