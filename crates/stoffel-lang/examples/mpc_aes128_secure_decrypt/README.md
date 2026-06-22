# MPC AES-128: Secure Decryption + In-MPC Text Manipulation

Computation over a **client-supplied ciphertext**: the nodes decrypt an
AES-128-CTR ciphertext *inside* MPC, transform the recovered plaintext, and
return the changed text to the client — the plaintext is never revealed to the
compute nodes. This is the "secure decryption / transciphering" pattern,
validated end-to-end through the Rust SDK.

- **Client 0 (data owner)** supplies a secret AES-128-CTR ciphertext block
  (128 secret bits) as client input.
- **Client 1 (key holder)** supplies the 128-bit AES key as client input.
- The public CTR counter block is built in the program.
- CTR is self-inverse, so re-running the keystream against the secret
  ciphertext recovers the plaintext as **secret shares** (no inverse cipher
  needed, and nothing opened).
- The recovered plaintext is transformed in MPC by **uppercasing its ASCII
  letters** (`to_upper_byte` clears bit 5 of each lowercase letter; spaces and
  other non-letters are left untouched). This is a few AND/XOR gates per byte.
- The 128 transformed bits are delivered **only to client 0** via
  `send_to_client`. They are **never opened/revealed**; the client reconstructs
  the result from the output shares it receives.

Inputs are read and the output is sent at **literal client slots**, so the
client-IO manifest statically records 128 inputs per client and 128 outputs for
client 0; the local runner reads the output count from the manifest (no manual
count needed).

## Run + validate through the Rust SDK

The SDK harness encrypts the message `"hello stoffel vm"` under the NIST
SP 800-38A key, feeds the resulting ciphertext + key as secret client inputs,
runs the program in the local 5-party simulator, and reconstructs the
**client-received** transformed plaintext (via the off-chain client's
`obtain_outputs`, not a public reveal), asserting it equals `"HELLO STOFFEL VM"`:

```sh
STOFFEL_RUN_BIN=target/release/stoffel-run \
  cargo run --release -p stoffel-rust-sdk --example aes_secure_decrypt
```

The harness uses
`Stoffel::compile_file(...).expected_output_clients(2)
.with_client_input(0, ciphertext_bits).with_client_input(1, key_bits)
.execute_local_capturing_client_outputs()`, then decodes the client output with
`client0.bytes()` — the SDK decodes each output through the program's client-IO
manifest, so the 128 secret bits come back as typed booleans packed LSB-first
into the 16-byte result.
