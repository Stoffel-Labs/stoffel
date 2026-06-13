# Secret Matrix Averaging (secret fix64)

Element-wise averages three parties' secret `fix64` matrices: each cell is summed and divided by the client count entirely under MPC (secure fixed-point division by a public constant), so only the averages are opened — even the per-cell sums stay secret. Three contributors keep any one client from deriving another's matrix from the aggregate.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
