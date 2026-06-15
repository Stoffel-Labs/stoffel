# MPC Mean

Mean of a secret list = `⌊(Σ xᵢ) / n⌋` — a local sum followed by division by the
public count `n` (`mpc_secure_division`). Only the mean is revealed.

The example averages `[10,20,30,40]` (→ 25). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_mean
```
