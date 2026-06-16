# Symbolic Derivative of a Combined Model

Two analysts' private cubics are summed and formally differentiated on shares (index scalings); only the combined marginal curve is revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=7 --client-input 0=4 --client-input 0=1 --client-input 0=2 --client-input 1=3 --client-input 1=2 --client-input 1=5 --client-input 1=1
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
