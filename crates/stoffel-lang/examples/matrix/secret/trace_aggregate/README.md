# Aggregate Trace Reporting

Three clients' private load-matrix diagonals are summed under MPC; trace linearity lets the total system load be revealed without any per-client trace.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=5 --client-input 0=2 --client-input 0=9 --client-input 1=1 --client-input 1=7 --client-input 1=3 --client-input 2=4 --client-input 2=6 --client-input 2=8
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
