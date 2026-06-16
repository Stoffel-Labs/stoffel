# Gray Code Round Trip (uint64)

Converts `uint64` binary values to reflected Gray code and back (xor-shift cascade), asserting the round trip is lossless and that consecutive Gray codes differ in exactly one bit.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
