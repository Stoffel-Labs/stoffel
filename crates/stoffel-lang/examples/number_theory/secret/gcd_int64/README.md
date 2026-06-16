# Secret-Input GCD with Bezout Check (secret int64)

Takes secret `int64` inputs, reveals them to run Euclid in the clear, then verifies the Bezout identity a·x + b·y = g back under MPC with share-by-share multiplication before revealing only the zero difference.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
