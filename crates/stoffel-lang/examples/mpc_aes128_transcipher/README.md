# MPC AES-128 Transciphering: Clear Ciphertext In → New Ciphertext Out

The full transciphering round-trip over MPC: a client supplies a **clear
(public) AES-128-CTR ciphertext** and a **secret key**; the nodes decrypt it
inside MPC, modify the recovered content, re-encrypt it, and return the **new
ciphertext** to the client. Only ciphertexts ever cross the public boundary —
the plaintext is never revealed to the compute nodes.

- **`ciphertext: list[int64]` (clear)** — 128 public ciphertext bits. Because the
  parameter is not `secret`, the SDK's local named-input adapter feeds it as a
  **public** value (no per-bit masked-input protocol — the transciphering cost
  win), and the program lifts it into the secret-bool domain locally (free).
- **`key: list[secret bool]` (secret)** — the 128-bit AES key, loaded as secret
  shares via `ClientStore.take_share_bool`.
- Inside MPC the nodes: (1) recover the plaintext (CTR is self-inverse — secure
  decryption, nothing opened), (2) uppercase the recovered ASCII letters, (3)
  re-encrypt under the same key+counter, and (4) deliver the new 128-bit
  ciphertext to client 0 via `send_to_client`.

This pairs two SDK capabilities that previously could not be combined:
client-provided **clear** inputs (typed function parameters → public constants)
and client **outputs** (`send_to_client`). The local input adapter now routes
`secret bool` parameters through `take_share_bool` and preserves the program's
output schema through wrapping.

## Run + validate through the Rust SDK

The harness encrypts `"hello stoffel vm"` under the NIST SP 800-38A key, feeds
that ciphertext as the **clear** `ciphertext` input and the key as the secret
`key` input, then checks that the client-received new ciphertext decrypts to
`"HELLO STOFFEL VM"` (equivalently, equals the CTR encryption of the uppercased
text):

```sh
STOFFEL_RUN_BIN=target/release/stoffel-run \
  cargo run --release -p stoffel-rust-sdk --example aes_transcipher
```

The harness uses `Stoffel::compile_file(...).expected_output_clients(1)
.with_input("ciphertext", &ct_bits).with_input("key", &key_bits)
.execute_local_capturing_client_outputs()`, then decodes the client output with
`client0.bytes()`.
