# Xorshift PRNG and Its Inverse (uint64)

Marsaglia's xorshift64 generator built from shl/shr/xor steps. Each step is a linear bijection, so the example also derives the exact inverse cascade and walks the generator backwards to recover the seed.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
