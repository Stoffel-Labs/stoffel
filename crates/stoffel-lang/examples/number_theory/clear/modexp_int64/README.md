# Modular Exponentiation and Fermat Tests (int64)

Square-and-multiply modular exponentiation in int64, used to run Fermat primality tests: primes pass, composites fail, and the Carmichael number 561 famously fools every coprime base.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
