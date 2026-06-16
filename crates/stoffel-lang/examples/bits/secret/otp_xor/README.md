# One-Time Pad over Bool Shares

Client 0 holds the message bits, client 1 the pad. XOR gates encrypt without MPC rounds; only the ciphertext is revealed, and the decryption round trip is verified in-circuit so neither the message nor the pad ever opens.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=true --client-input 0=false --client-input 0=false --client-input 0=true --client-input 0=true --client-input 0=true --client-input 0=false --client-input 0=true --client-input 1=false --client-input 1=true --client-input 1=true --client-input 1=true --client-input 1=false --client-input 1=true --client-input 1=false --client-input 1=false
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
