# Oblivious Polynomial Evaluation

A public tariff polynomial is evaluated at the client's private point with Horner's rule on shares; only the price is revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=3
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
