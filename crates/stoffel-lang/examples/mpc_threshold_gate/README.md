# MPC Threshold Gate (k-of-n)

Does the number of set secret bits reach a public threshold `k`? Sum the bits and
test `[count ≥ k]`. With `k = ⌊n/2⌋+1` this is a majority gate. Returns a secret bit.

The example checks 3-of-5 (majority, → 1) and 4-of-5 (→ 0) over `[1,1,0,1,0]`. `κ`
is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_threshold_gate --client-input 0=1 --client-input 1=1 --client-input 2=0 --client-input 3=1 --client-input 4=0 --expected-output-clients 5
```
