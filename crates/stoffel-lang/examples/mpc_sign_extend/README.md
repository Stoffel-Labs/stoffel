# MPC Signed Reinterpret / Sign Extension

Reinterpret a secret unsigned `l`-bit value as a signed two's-complement number:
`signed = u − 2ˡ · bit_{l-1}` (subtract `2ˡ` exactly when the top bit is set).
Recovers the sign without revealing the value.

The example reinterprets `200 → −56` and `50 → 50` for `l = 8`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_sign_extend --client-input 0=200 --expected-output-clients 1
```
