# Bit Reversal (uint64)

Reverses the 64-bit pattern of `uint64` values twice over: once with a bit-at-a-time loop and once with logarithmic mask-and-swap steps using hex mask constants. Asserts both methods agree and that reversal is an involution.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
