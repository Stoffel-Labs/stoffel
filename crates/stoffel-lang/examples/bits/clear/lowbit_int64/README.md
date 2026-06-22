# Lowest-Set-Bit Tricks (int64)

Classic two's-complement bit tricks on `int64`: isolating the lowest set bit with `n and -n`, stripping it with `n and (n - 1)`, and detecting powers of two — validated against loop-based reference implementations.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
