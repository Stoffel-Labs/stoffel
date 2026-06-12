# Lagrange Interpolation (fix64)

Interpolates a quadratic through three `fix64` points with Lagrange basis polynomials, asserting it reproduces the nodes exactly and matches the generating polynomial between them.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
