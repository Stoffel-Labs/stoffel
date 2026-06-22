# Secure Mean with On-Share Division (secret fix64)

Three clients submit one private `fix64` value each; the sum is divided by the public headcount with secure fixed-point division by a constant, so only the mean is ever opened — even the sum stays secret.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=98304 --client-input 1=163840 --client-input 2=131072
```

Fixed-point client inputs are raw 2^16-scaled integers (98304 = 1.5). Secure
division is approximate (probabilistic truncation), so the result is correct to
within fixed-point tolerance. The program asserts its own result.
