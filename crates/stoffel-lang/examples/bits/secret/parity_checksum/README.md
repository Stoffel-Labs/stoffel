# Private Parity Checksums

Each client's 8-bit codeword (7 data + parity) is checked by an XOR fold; only per-client validity verdicts are revealed, and a parity flip repairs the bad word in-circuit.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=false --client-input 0=false --client-input 0=true --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=false --client-input 1=true --client-input 1=true --client-input 1=false --client-input 1=true --client-input 1=false --client-input 1=false --client-input 1=true --client-input 1=true
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
