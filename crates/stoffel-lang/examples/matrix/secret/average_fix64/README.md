# Secret Matrix Averaging (secret fix64)

Element-wise averages three parties' secret `fix64` matrices: shares are summed under MPC, only the sums are opened, and the division by the client count happens on the opened values.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
