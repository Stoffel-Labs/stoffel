# MPC Modular Inverse

Modular inverse of a secret `a` modulo a public prime `p`, via Fermat's little
theorem: `a⁻¹ ≡ a^{p-2} (mod p)`. Uses public-exponent modular exponentiation
(square-and-multiply with reduction `mod p`).

The example computes `3⁻¹ mod 7 = 5` (since `3·5 = 15 ≡ 1`). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_modinv --client-input 0=3 --expected-output-clients 1
```
