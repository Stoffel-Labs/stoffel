# MPC Select / Min / Max / Equal

Branching on secret conditions, the foundation for most higher-level MPC logic.
All four operations return secret shares; nothing is revealed except the final
demo results.

- **`select(c, a, b)`** — oblivious multiplexer, `b + c·(a − b)` for a secret bit
  `c` (one multiply). Returns `a` if `c = 1`, else `b`.
- **`minimum` / `maximum`** — `select` driven by `[a < b]` (the secure comparison
  from `mpc_secure_comparison`).
- **`equal`** — `[a == b] = ¬[a < b] · ¬[b < a]` (two comparisons, one multiply).

The example checks `min`, `max`, and equality (both directions) and asserts the
results. `κ` is small for speed; production uses `κ ≈ 40`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_select_minmax --client-input 0=100 --client-input 1=150 --expected-output-clients 2
```
