# Modular Inverse and CRT (int64)

Uses the extended Euclidean algorithm to compute modular inverses in `int64`, solves linear congruences a·x = b (mod m), and combines two congruences with the Chinese Remainder Theorem.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
