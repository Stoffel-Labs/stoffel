# Permission Flag Masks (int64)

Models a permission system as an `int64` bitmask: set, clear, toggle, and test flags, exercising all four bitwise keywords including the integer `not` complement. Asserts the full lifecycle of a permission word.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
