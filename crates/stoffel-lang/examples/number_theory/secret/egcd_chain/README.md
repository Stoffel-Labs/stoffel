# Three-Party Extended Euclid Chain

Folding xgcd across three clients' values yields gcd(a,b,c) and a three-term Bezout certificate re-verified against the original shares.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=210 --client-input 1=126 --client-input 2=350
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
