# Secret Code Equality (client bits)

Two clients submit private 6-bit access codes as boolean shares. An XNOR/AND fold reveals only the single equality verdict, plus a tampered re-check inside the circuit.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=false --client-input 0=true --client-input 0=true --client-input 0=false --client-input 0=true --client-input 1=true --client-input 1=false --client-input 1=true --client-input 1=true --client-input 1=false --client-input 1=true
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
