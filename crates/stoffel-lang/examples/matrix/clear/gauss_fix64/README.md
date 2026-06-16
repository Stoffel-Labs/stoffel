# Gaussian Elimination Solver (fix64)

Solves a 3x3 linear system in `fix64` with forward elimination, partial pivoting by magnitude, and back substitution. Asserts the residual of every equation is within fixed-point tolerance.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
