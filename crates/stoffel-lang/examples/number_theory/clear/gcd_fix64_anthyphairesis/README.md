# Euclid's Anthyphairesis on Magnitudes (fix64)

Euclid's original subtraction-based algorithm run directly on commensurate `fix64` magnitudes (exact binary fractions), finding the greatest common measure of quantities like 2.25 and 1.5.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
