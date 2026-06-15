# MPC Comparison Family

The full ordering toolkit derived from one primitive `less_than`:
`greater_than(a,b) = [b<a]`, `leq(a,b) = ¬[b<a]`, `geq(a,b) = ¬[a<b]`, and
comparison to a public constant. Each returns a secret bit.

The example checks `>`, `≤`, `≥` and `< constant`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_compare_family --client-input 0=5 --client-input 0=8 --expected-output-clients 1
```
