# Polynomial Calculus (fix64)

Differentiates and antidifferentiates `fix64` coefficient lists, checks that the derivative of the antiderivative returns the original polynomial, and evaluates a definite integral exactly representable in binary fixed point.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
