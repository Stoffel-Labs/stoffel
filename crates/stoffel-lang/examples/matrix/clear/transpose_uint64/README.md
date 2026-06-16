# Matrix Transpose (uint64)

Transposes a rectangular 2x4 `uint64` matrix, asserting the involution property (transpose twice returns the original) and that row sums become column sums.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
