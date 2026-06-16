# Blind Substring Search

Client 0's bit stream is scanned for client 1's pattern with XNOR/AND windows OR-folded into a single found/not-found bit.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=false --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=true --client-input 0=false --client-input 0=false --client-input 0=true --client-input 1=true --client-input 1=false --client-input 1=true --client-input 1=true --client-input 1=true --client-input 1=false --client-input 1=true --client-input 1=true
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
