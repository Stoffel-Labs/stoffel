# Blinded Private Equality Test

Whether two clients hold the same value is revealed by opening the randomly blinded difference (a-b)*r — zero iff equal, noise otherwise.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=777 --client-input 1=777
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
