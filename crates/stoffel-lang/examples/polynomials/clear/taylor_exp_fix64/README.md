# Taylor Series for exp (fix64)

Sums the Taylor series of e^x in fixed point with factorial-divided terms, asserting convergence to e within tolerance, the exp addition law e^0.5 * e^0.5 = e, and monotone partial sums.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
