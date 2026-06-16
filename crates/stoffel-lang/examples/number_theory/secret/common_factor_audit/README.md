# RSA Common-Factor Audit

Three parties' moduli are audited pairwise with the Euclidean algorithm; shared prime factors flag the broken key pairs.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=391 --client-input 1=323 --client-input 2=299
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
