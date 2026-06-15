# MPC Random Bit

Joint random bit sharing: the parties jointly produce a secret-shared uniformly
random bit `a ∈ {0, 1}` that no single party learns, following Damgård, Fitzi,
Kiltz, Nielsen and Toft.

The construction draws a full-field random `[r]`, reveals `r²`, and sets
`[a] = 2⁻¹·(r'⁻¹·[r] + 1)` where `r' = √(r²)` is the canonical root in `(0, p/2)`.
Since `r'⁻¹·r ∈ {-1, +1}` with equal probability, `a` is a uniform bit.

The public field math on the revealed `r²` (square root, inverse, constants) uses
the `Field.*` builtins, and the results are folded back into the share locally
with `Share.mul_field` / `Share.add_field`.

`r` must be uniform over the whole field, so it uses **`Share.random_field()`**.
A bounded `secret int64` random would always be `< p/2`, which collapses the
result to the constant bit `1`.

Run it through the local MPC CLI from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_random_bit --expected-output-clients 1
```

Each run reveals a fresh `0` or `1`; the program asserts the result is a valid
bit.
