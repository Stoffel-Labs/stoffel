# Threshold-key AES-128 with a client-supplied secret plaintext

This is the [`mpc_aes128_circuit`](../mpc_aes128_circuit) AES-128 circuit, rewired so
**nothing is a program constant**:

| Input | Source | Visibility |
|-------|--------|------------|
| Plaintext (128 bits) | client slot **0** (data owner), secret input | secret-shared; no MPC party sees it |
| Key (128 bits) | client slot **1** (key holder), secret input | **threshold key** — secret-shared, no MPC party sees it |
| Ciphertext (128 bits) | revealed output | public |

The 5 MPC parties run AES-128 entirely over secret shares — they jointly hold the
key and plaintext as Shamir shares (any `t+1 = 2` reconstruct, no single party
learns either) and only the final ciphertext is opened.

It runs both directions: it **encrypts** the client plaintext under the threshold
key (revealing the ciphertext), then **decrypts** the still-secret ciphertext with
the same threshold key and reveals the recovered plaintext — which equals the
original, proving the inverse cipher.

## Decryption (inverse cipher)

`aes128_decrypt` is the standard inverse cipher (InvShiftRows / InvSubBytes /
AddRoundKey / InvMixColumns, round keys applied in reverse). The inverse S-box
reuses the forward one via the identity

```
InvSBox(y) = InvAffine( aes_sbox( InvAffine(y) ) )
```

(`aes_sbox(x) = Affine(GFInverse(x))`, and the AES affine map is invertible), so
there is no second hand-written S-box netlist to get wrong — only the small linear
`inv_affine`. `InvShiftRows` is a byte permutation and `InvMixColumns` uses
`xtime`-based GF(2^8) constant multiplies (9/11/13/14), all linear (no extra
multiplication rounds); the only non-linear cost is the shared S-box inversion.

## How inputs are wired

Each AES byte is 8 secret bits in **little-endian** order (bit `i` carries weight
`2^i`, matching `reveal_byte`). A client supplies one secret bit per
`ClientStore.take_share(slot, idx)` call, so a 16-byte block is 128 secret inputs:

```
def take_client_byte(client_slot, byte_index):   # 8 bits, LSB-first
  for bit_index in 0..8:
    ClientStore.take_share(client_slot, byte_index * 8 + bit_index)
```

`main` reads the plaintext from slot 0 and the key from slot 1, runs
`aes128_encrypt`, and reveals the result.

## Running it

`./run.sh` generates the 256 `--client-input` bit flags from the FIPS-197 AES-128
known-answer vectors and runs the 5-party local simulator:

```
Plaintext  : 00112233445566778899aabbccddeeff   (client 0)
Key        : 000102030405060708090a0b0c0d0e0f   (client 1, threshold key)
Ciphertext : 69c4e0d86a7b0430d8cdb78070b4c55a
           = [105,196,224,216,106,123,4,48,216,205,183,128,112,180,197,90]
```

```bash
# build the runner once
cargo build --release -p stoffel-vm --bin stoffel-run

# from this directory
./run.sh
```

The program prints two decimal byte lists: first the revealed **ciphertext** (must
equal the vector above), then the **recovered plaintext** from decrypting it (must
equal `[0,17,34,...,255]`, i.e. the input `00112233...ff`). To encrypt your own
data, change `PLAINTEXT_HEX` / `KEY_HEX` in `run.sh`.

## Notes

- Swapping the FIPS vectors for random values makes this a genuine private
  encryption: the data owner learns nothing about the key, the key holder learns
  nothing about the plaintext, and the parties learn neither — only the
  ciphertext is public.
- The key is a *threshold* key in the cryptographic sense: it exists only as
  shares distributed across the parties via the MPC input protocol.
