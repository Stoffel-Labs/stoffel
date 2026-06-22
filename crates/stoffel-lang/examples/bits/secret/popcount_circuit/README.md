# Secret Popcount Circuit

One client's 8 private flags are tallied by a half-adder counter into a 4-bit count; the count is revealed, the positions are not.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=true --client-input 0=false
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
