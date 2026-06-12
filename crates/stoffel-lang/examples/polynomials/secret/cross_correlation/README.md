# Private Signal Correlation

Polynomial multiplication as convolution: a private template slides across a private signal, revealing only the per-lag correlation scores.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=1 --client-input 0=3 --client-input 0=2 --client-input 0=4 --client-input 1=1 --client-input 1=2 --client-input 1=0 --client-input 1=0
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
