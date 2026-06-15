# MPC Secure Shuffle

Oblivious random permutation of secret values: attach a fresh secret random tag to
each element (`Share.random_int`) and sort the (value, tag) pairs by tag with a
sorting network. The resulting order is independent of the values, so it is a
uniform shuffle (no party learns the permutation).

The example shuffles `[10,20,30,40]` and asserts the output is a permutation of the
input (multiset preserved). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_secure_shuffle --client-input 0=10 --client-input 0=20 --client-input 0=30 --client-input 0=40 --expected-output-clients 1
```
