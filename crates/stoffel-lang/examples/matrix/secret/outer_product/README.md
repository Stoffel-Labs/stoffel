# Rank-1 Interaction Table

Row weights from one client, column weights from another: the revealed outer product satisfies the rank-1 determinant identity.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=3 --client-input 0=5 --client-input 1=2 --client-input 1=7
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
