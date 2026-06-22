# Secret Ripple-Carry Adder (secret bool)

Adds two 4-bit numbers entirely as `secret bool` gate logic — XOR/AND/OR full adders chained through a ripple carry — then reveals only the sum bits and checks them against clear addition.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
