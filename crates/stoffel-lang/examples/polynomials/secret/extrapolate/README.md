# Private Trend Extrapolation

Three bureaus' confidential samples p(0..2) extrapolate p(3) with public binomial weights; the forecast and curvature are revealed, the figures are not.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=12 --client-input 1=15 --client-input 2=22
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
