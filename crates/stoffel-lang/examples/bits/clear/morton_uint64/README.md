# Morton Z-Order Interleaving (uint64)

Interleaves two 32-bit coordinates into a 64-bit Morton code with logarithmic mask-spread steps, checks known codes against a loop-based reference, and inverts the spread to recover the coordinates.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
