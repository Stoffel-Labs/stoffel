# MPC Polynomial Unbounded OR

This example computes an OR over an arbitrary-length `list[secret bool]` using
the polynomial identity:

```text
OR(bits) = 1 - product(1 - bit)
```

The constant `1` is created as a one-bit share with `Share.from_clear_int(1, 1)`,
so the intermediate values stay in the `secret bool` representation.

Run it through the local MPC CLI from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_polynomial_unbounded_or --input 'a=[false,false,true,false]'
```
