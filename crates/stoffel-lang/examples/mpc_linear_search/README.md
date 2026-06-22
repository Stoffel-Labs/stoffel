# MPC Linear Search

Search a secret list for a secret `target`, returning a secret found-flag and the
first matching index. A running `found_so_far` flag ensures only the *first* match
sets the index (`is_new = eq ∧ ¬found`), and `found` is OR-accumulated.

The example searches `[7,3,9,3]` for `9` (found = 1, index = 2). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_linear_search --client-input 0=7 --client-input 0=3 --client-input 0=9 --client-input 0=3 --client-input 0=9 --expected-output-clients 1
```
