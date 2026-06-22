# Matrix Multiplication (int64)

Triple-loop `int64` matrix multiplication on nested lists. Checks identity-matrix neutrality and the associativity law (A·B)·v = A·(B·v) on a worked example.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
