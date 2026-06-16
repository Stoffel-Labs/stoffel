# Blind Root Knowledge Check

One client commits a secret monic quadratic, another submits secret candidates; share-by-share evaluation reveals only per-candidate root verdicts.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=10 --client-input 0=-7 --client-input 0=1 --client-input 1=2 --client-input 1=5 --client-input 1=6
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
