# Fully Private GCD Certificate

Bezout identity plus divisibility witnesses checked entirely on shares with share-by-share products: validity is proven and nothing else leaks.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=240 --client-input 0=46 --client-input 0=2 --client-input 0=-9 --client-input 0=47 --client-input 0=120 --client-input 0=23
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
