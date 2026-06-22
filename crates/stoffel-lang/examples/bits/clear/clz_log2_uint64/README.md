# Leading/Trailing Zeros and log2 (uint64)

Counts leading and trailing zeros of `uint64` values by binary descent over half-width probes, derives floor(log2), and asserts the bracketing property between successive powers of two.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
