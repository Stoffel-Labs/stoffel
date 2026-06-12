# Bit Rotation (uint64)

Implements rotate-left and rotate-right on `uint64` out of `shl`/`shr`/`or`, then checks round-trip identities, composition of rotations, and full-width rotation being the identity.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
