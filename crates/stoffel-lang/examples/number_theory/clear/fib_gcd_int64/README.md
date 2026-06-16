# Fibonacci GCD Identity (int64)

Checks the classical identity gcd(F(m), F(n)) = F(gcd(m, n)) across a grid of indices, plus the coprimality of consecutive Fibonacci numbers that makes them Euclid's worst case.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
