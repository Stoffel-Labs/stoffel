# Finite Difference Tables (int64)

Builds forward-difference tables of `int64` polynomial sequences, asserts the k-th differences of a degree-k polynomial are the constant k!·lead, and extends the sequence Babbage-style from differences alone.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
