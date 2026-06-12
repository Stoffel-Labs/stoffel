# Five-Client Majority Vote (secret bool)

Five clients cast one private ballot each; half-adders accumulate a 3-bit secret tally and only the count>=3 majority verdict is revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 1=false --client-input 2=true --client-input 3=true --client-input 4=false
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
