# Chebyshev Polynomials (fix64)

Generates Chebyshev coefficients with the recurrence T(n) = 2x*T(n-1) - T(n-2), verifies them against the closed forms, and checks the defining identity T(n)(cos a) = cos(n*a) at exact fixed-point angles.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
