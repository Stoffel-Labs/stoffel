# MPC MLP Inference

Private inference through a realistic feed-forward neural network:
`32 -> 16 -> 8 -> 2` with ReLU activations and an argmax over the two output
logits. The client's 32-dimensional input is secret-shared; the weight matrices
are public.

Because the weights are public, every affine layer is free local scaling
(`mul_scalar`, no beaver triples). The MPC cost is the activations and the
output decision: `16 + 8 = 24` ReLU comparisons plus the final argmax. (A wider
or deeper net simply adds more ReLU comparisons.)

With all-ones weights and all-ones input the pre-activations are
`32 -> 512`, the output logits are `o0 = 4096` and `o1 = 8192`, so the argmax
is class `1`.

Run it from the repository root (32 secret inputs for client 0):

```sh
stoffel run crates/stoffel-lang/examples/mpc_mlp_inference --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --expected-output-clients 1
```
