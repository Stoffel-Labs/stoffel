# Diophantine Settlement of a Private Amount

The client's settlement target arrives as a share; 240x + 46y = c is solved after reveal and the solution is verified against the committed share.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=14
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
