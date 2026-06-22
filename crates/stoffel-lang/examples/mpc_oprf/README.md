# MPC Oblivious PRF (OPRF)

A threshold **Oblivious PRF**: `F_k(x) = H(x)^k` evaluated over the BLS12-381 G1
curve. The servers jointly hold the PRF key `k` as a secret share and never
reveal it; evaluation hashes the input to a curve point (`Crypto.hash_to_g1`)
and raises it to the shared key with open-in-exponent
(`Share.open_exp_custom`). The 48-byte result is deterministic for a fixed key
and pseudorandom to anyone without `k`.

This is the building block for [`mpc_dh_psi`](../mpc_dh_psi) (private set
intersection) and private keyword search.

The example evaluates the same input twice and asserts the outputs match
(determinism), and evaluates a different input and asserts the output differs
(pseudorandomness). The client supplies the input as a field share.

> A production OPRF also has the **client** blind the input — send `H(x)^r`,
> then unblind the `H(x)^{rk}` response to `H(x)^k` — so the servers never learn
> `x`. That blinding/unblinding is client-side and wraps this server-side
> evaluation core.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_oprf --client-input 0=42
```
