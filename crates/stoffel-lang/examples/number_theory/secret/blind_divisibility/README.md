# Blind Divisibility Proofs

Each client proves its private number is divisible by 7 by submitting the quotient witness; only zero/nonzero verdicts are revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=91 --client-input 0=13 --client-input 1=80 --client-input 1=11
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
