# Reed-Solomon Encoding of a Private Message

The client's message coefficients are evaluated over public Vandermonde points into a 5-symbol codeword; two erasures are recovered by exact interpolation.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=9 --client-input 0=2 --client-input 0=4
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
