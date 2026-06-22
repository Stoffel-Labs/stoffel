# Fibonacci via Matrix Exponentiation (int64)

Raises the [[1,1],[1,0]] matrix to the n-th power by repeated squaring to compute Fibonacci numbers in O(log n) multiplications, and verifies against a plain iterative loop.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
