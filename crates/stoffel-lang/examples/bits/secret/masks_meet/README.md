# Permission Mask Intersection and Union

Two departments' private 8-bit permission masks meet under AND/OR gates; only the aggregate masks are revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=false --client-input 0=false --client-input 0=true --client-input 0=false --client-input 1=true --client-input 1=false --client-input 1=false --client-input 1=true --client-input 1=true --client-input 1=false --client-input 1=true --client-input 1=true
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
