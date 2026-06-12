# Millionaires' Comparison Circuit

Two clients' 4-bit amounts run through an MSB-first comparator; only the greater-than and tie verdict bits are revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=true --client-input 1=false --client-input 1=true --client-input 1=true --client-input 1=false
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
