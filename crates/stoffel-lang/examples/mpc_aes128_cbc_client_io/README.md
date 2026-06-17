# MPC AES-128 CBC: Rust Client-IO Example

A standalone Rust SDK example, in the shape produced by `stoffel init`, that
validates AES-128 CBC encryption and decryption of one block over MPC.

- **Client 0 (data owner)** supplies a secret plaintext block (128 secret bits)
  for `encrypt`, or a secret ciphertext block for `decrypt`.
- **Client 1 (key holder)** supplies the 128-bit AES key as client input.
- The public CBC IV (NIST 000102..0f) is built in the program.
- The 128-bit result is delivered **only to client 0** via `send_to_client`.
  `encrypt` sends the secret ciphertext block; `decrypt` sends the recovered
  secret plaintext block. Neither result is opened/revealed to the compute
  nodes.

Inputs are read at **literal client slots**, so the client-IO manifest records
128 inputs for client 0 and 128 inputs for client 1. The Rust harness declares
client 0 as an output-capable client and supplies `client_output_count(0, 128)`
because both entrypoints route their output through a shared helper.

## Run + validate through the Rust SDK

The Rust harness feeds the NIST SP 800-38A plaintext/ciphertext and key as
secret client inputs, runs both entrypoints in the local 5-party runner, and
reconstructs only the **client-received** output shares:

```sh
STOFFEL_RUN_BIN=../../../../target/release/stoffel-run cargo run --release
```

From the repository root, the same example can be run with:

```sh
STOFFEL_RUN_BIN=target/release/stoffel-run \
  cargo run --release --manifest-path crates/stoffel-lang/examples/mpc_aes128_cbc_client_io/Cargo.toml
```

The harness asserts:

- `encrypt(6bc1bee22e409f96e93d7e117393172a) == 7649abac8119b246cee98e9b12e9197d`
- `decrypt(7649abac8119b246cee98e9b12e9197d) == 6bc1bee22e409f96e93d7e117393172a`
