# Oblivious Per-Bit Multiplexer

Two providers' private nibbles are blended by a third client's private selection mask using mux gates, without revealing who supplied what.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=true --client-input 1=false --client-input 1=false --client-input 1=true --client-input 1=false --client-input 2=true --client-input 2=true --client-input 2=true --client-input 2=true
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
