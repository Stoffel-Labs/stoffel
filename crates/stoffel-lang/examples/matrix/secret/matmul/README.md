# Secret 2x2 Matrix Product

Each client holds one 2x2 factor; every product entry needs cross-owner share multiplications, and the product matrix is revealed and checked.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=1 --client-input 0=2 --client-input 0=3 --client-input 0=4 --client-input 1=5 --client-input 1=6 --client-input 1=7 --client-input 1=8
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
