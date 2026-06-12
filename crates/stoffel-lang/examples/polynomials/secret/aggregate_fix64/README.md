# Secret Polynomial Aggregation (secret fix64)

Sums three parties' secret `fix64` polynomials coefficient-by-coefficient under MPC, opens only the aggregate coefficients, and evaluates the revealed average polynomial in the clear.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
