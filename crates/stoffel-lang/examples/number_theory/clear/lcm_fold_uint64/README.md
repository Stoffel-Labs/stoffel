# LCM and GCD Folds (uint64)

Computes lcm via overflow-safe (a / gcd)·b on `uint64`, folds gcd and lcm across a list of values, and asserts absorption laws like gcd(a, lcm(a, b)) = a.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
