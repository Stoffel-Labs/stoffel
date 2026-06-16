# Binomial Expansion via Pascal's Triangle (uint64)

Builds the coefficients of (1 + x)^n from Pascal's triangle in `uint64`, then validates them by evaluating at x = 1 and x = 2 against independently computed powers of 2 and 3.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
