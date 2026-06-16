# Determinants by Cofactor Expansion (int64)

Computes 2x2 and 3x3 `int64` determinants via cofactor expansion and validates the multiplicativity law det(A·B) = det(A)·det(B), plus singular-matrix detection.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
