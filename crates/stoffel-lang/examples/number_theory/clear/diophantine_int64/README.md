# Linear Diophantine Equations via Extended Euclid (int64)

Solves a*x + b*y = c in integers: extended Euclid produces a particular solution when gcd(a, b) divides c, and the full solution family x = x0 + t*b/g, y = y0 - t*a/g is generated and verified for a sweep of t, including an unsolvable case.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
