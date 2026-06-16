# MPC ReLU / Sign / Abs

Sign extraction and the ReLU nonlinearity on signed secret values
`x ∈ (−2ˡ⁻¹, 2ˡ⁻¹)` — the core building blocks for private ML inference.

- **`is_negative(x)`** — map `x` to `u = x + 2ˡ⁻¹ ∈ (0, 2ˡ)` and test `u < 2ˡ⁻¹`
  with the secure comparison; that bit is the sign.
- **`relu(x)`** — `select(x ≥ 0, x, 0)`.
- **`abs_val(x)`** — `select(x ≥ 0, x, −x)`.

Everything stays secret-shared. `κ` is small for speed; production uses `κ ≈ 40`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_relu_sign
```
