# MPC Set Membership

Test whether a secret `x` equals any element of a **public** set `S`, returning
the verdict as a secret bit — `x` itself is never revealed.

`[x ∈ S] = ⋁_{s∈S} [x == s]`, where each equality is `¬[x<s] ∧ ¬[s<x]` (secure
comparison) and the OR is accumulated as `acc + eq − acc·eq`.

The example checks `30 ∈ {10,30,50}` (→ 1) and `25 ∈ {10,30,50}` (→ 0). `κ` is
small for speed; production uses `κ ≈ 40`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_set_membership --client-input 0=30 --expected-output-clients 1
```
