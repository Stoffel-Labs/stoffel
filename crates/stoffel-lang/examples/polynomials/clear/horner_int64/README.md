# Horner Evaluation (int64)

Evaluates `int64` polynomials with Horner's rule and cross-checks a naive power-accumulation evaluator at several points, including negative inputs and negative coefficients.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
