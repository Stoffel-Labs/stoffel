# Extended Euclidean Algorithm, Iterative (int64)

Iterative extended Euclid maintaining Bezout coefficient rows in `int64`, asserting a·x + b·y = gcd(a, b) at every tested pair, including signed inputs.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
