# Pooled Power Sums

Two clients' measurements are pooled into S1 and S2 (squares are share products); Newton's identities derive e2 and the variance from the two revealed sums.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=4 --client-input 0=10 --client-input 1=6 --client-input 1=8
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
