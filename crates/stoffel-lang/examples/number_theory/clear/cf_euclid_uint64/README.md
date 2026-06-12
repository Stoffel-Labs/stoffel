# Continued Fractions from Euclid's Quotients (uint64)

The quotient sequence of the Euclidean algorithm is the continued-fraction expansion of a rational. Expands 1071/462 and a Fibonacci ratio in uint64, folds the convergents back together, and recovers the fraction in lowest terms.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
