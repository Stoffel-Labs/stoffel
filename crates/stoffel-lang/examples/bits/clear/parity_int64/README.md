# XOR-Fold Parity (int64)

Computes the parity of `int64` bit patterns by folding the word onto itself with `xor` shifts, and validates the result against a naive set-bit counter, including for negative (sign-extended) values.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
