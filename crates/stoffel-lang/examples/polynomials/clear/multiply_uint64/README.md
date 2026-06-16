# Polynomial Product and Sum (uint64)

Adds and multiplies `uint64` polynomials held as coefficient lists (the product is a convolution), then verifies the ring homomorphism property p(x)·q(x) = (p·q)(x) at sample points.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
