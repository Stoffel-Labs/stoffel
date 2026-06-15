# MPC MLP Inference

A small multilayer-perceptron forward pass on secret inputs: `linear → ReLU →
linear → argmax`, composing affine layers (public weights via `mul_scalar`), the
ReLU nonlinearity, and an argmax over the output logits. End-to-end private ML
classification — only the predicted class is revealed.

The example runs a 2-2-2 network and predicts class 0. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_mlp_inference --client-input 0=2 --client-input 0=3 --expected-output-clients 1
```
