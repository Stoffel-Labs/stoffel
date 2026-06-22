# Split-Data Covariance

Client 0 holds the x series, client 1 the y series; the scaled covariance n*sum(xy) - sum(x)sum(y) is computed across owners and revealed alone.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=2 --client-input 0=4 --client-input 0=6 --client-input 0=8 --client-input 1=10 --client-input 1=14 --client-input 1=22 --client-input 1=26
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
