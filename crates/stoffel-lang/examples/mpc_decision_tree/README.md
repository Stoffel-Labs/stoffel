# MPC Decision Tree

Evaluate a small decision tree on secret features. Each internal node compares a
feature to a public threshold (secure comparison); oblivious `select` routes the
result to one of the (secret) leaves. Every node is evaluated regardless of the
path, so the traversal is data-oblivious.

The example evaluates a depth-2 tree and routes to leaf `200`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_decision_tree
```
