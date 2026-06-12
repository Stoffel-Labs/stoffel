# Shamir Sharing In-Language

A dealer client's secret and blinding coefficients define p(x); evaluating at public points deals five shares, and any three reconstruct the secret by exact Lagrange interpolation.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=42 --client-input 0=5 --client-input 0=3
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
