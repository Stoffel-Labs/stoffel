# 2D Rotation Matrices (fix64)

Applies fixed-point 2D rotation matrices to vectors: rotating by 30 degrees twice matches rotating by 60 degrees once, and vector length is preserved within fixed-point tolerance.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
