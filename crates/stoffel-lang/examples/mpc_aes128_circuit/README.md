# MPC AES-128 Circuit

This example implements AES-128 block encryption over `secret bool` circuits.
Bytes are `list[secret bool]` values in little-endian bit order.

The S-box uses a Boyar-Peralta-style bitsliced circuit rather than repeated
GF(2^8) exponentiation. Its intermediates are ordinary local temporaries; when
the S-box exceeds the scalar register budget, the compiler is expected to spill
those registers into VM objects automatically.

The included `main` encrypts the NIST AES-128 known-answer vector:

- Plaintext: `00112233445566778899aabbccddeeff`
- Key: `000102030405060708090a0b0c0d0e0f`
- Expected ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a`

Run it with:

```sh
stoffel run
```

The program returns the ciphertext as decimal byte values:

```text
[105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
```

Performance note: with the current arithmetic-share encoding, XOR over secret
bits is implemented as `a + b - 2ab`, so XOR is still a multiplication. Native
binary-share XOR or a first-class `secret byte`/`GF(2^8)` lowering would make
this circuit much faster.
