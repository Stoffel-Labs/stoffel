# Secret Modular Inverse Verification (secret uint64)

Holds a value as a secret `uint64` share, reveals it to compute its inverse modulo a public prime with extended Euclid, then re-checks a·a^{-1} = 1 (mod p) by multiplying shares under MPC.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
