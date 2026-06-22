# Binary GCD / Stein's Algorithm (uint64)

Stein's binary GCD on `uint64`, replacing division with `shr`/`shl` shifts and subtraction — factoring out common twos, halving evens, subtracting odds — checked against the remainder-based Euclid.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
