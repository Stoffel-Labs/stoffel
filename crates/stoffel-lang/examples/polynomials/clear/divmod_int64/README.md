# Polynomial Long Division (int64)

Divides `int64` polynomials with classic long division, producing quotient and remainder, and asserts the division identity p = q·d + r together with the remainder degree bound.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
