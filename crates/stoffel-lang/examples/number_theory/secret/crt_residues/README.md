# CRT Combination on Shares

Clients hold residues mod 5 and mod 7; public Bezout-derived basis weights combine them on shares into the residue mod 35 with no runtime Euclid.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=2 --client-input 1=3
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
