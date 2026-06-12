# Secret Matrix-Vector Product (secret int64)

Multiplies a secret `int64` matrix by a secret vector using share-by-share multiply-accumulate, revealing only the final result vector and checking it against the clear computation.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
