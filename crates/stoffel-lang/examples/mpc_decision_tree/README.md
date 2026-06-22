# MPC Decision Tree

Private evaluation of a complete depth-4 decision tree (15 internal nodes, 16
leaves) over a 32-feature input. The client's feature vector is secret-shared;
the thresholds and leaf values are public.

Because the routing path is secret, **every** internal node is evaluated: each
computes a bit `[x[feature] < threshold]` with the carry-based secure
comparison, and the tree is collapsed bottom-up (`16 -> 8 -> 4 -> 2 -> 1`) with
oblivious `select`. The MPC cost is the 15 node comparisons (≈35s on the local
simulator); a deeper tree doubles the node count per added level.

Leaves are valued `100..115`. With every feature `= 1` and every threshold
`= 5`, all node bits are `1` (route left), so the input reaches the leftmost
leaf, value `100`.

Run it from the repository root (32 secret features for client 0):

```sh
stoffel run crates/stoffel-lang/examples/mpc_decision_tree --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --expected-output-clients 1
```
