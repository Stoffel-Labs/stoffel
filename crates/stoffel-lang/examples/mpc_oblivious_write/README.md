# MPC Oblivious Array Write

Set `arr[i] = v` for a **secret** index `i` without revealing which cell changed.
Each cell is updated to `select([i == j], v, arr[j])`, so only the matching entry
takes the new value and the access pattern leaks nothing.

The example writes `99` to index 1 of `[10,20,30,40]` and checks the result is
`[10,99,30,40]`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_oblivious_write
```
