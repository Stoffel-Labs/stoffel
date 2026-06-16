# Popcount Three Ways (uint64)

Counts set bits in `uint64` values with three independent algorithms — a naive shift-and-test loop, Kernighan's clear-lowest-bit trick, and a SWAR-style halving fold — and cross-checks that all three agree on a spread of inputs.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
