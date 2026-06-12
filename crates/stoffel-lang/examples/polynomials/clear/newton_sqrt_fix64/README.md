# Newton Root Finding on x^2 - a (fix64)

Finds the positive root of the polynomial x^2 - a with Newton's method in `fix64`, demonstrating quadratic convergence in a handful of iterations and asserting |root^2 - a| stays within tolerance.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
