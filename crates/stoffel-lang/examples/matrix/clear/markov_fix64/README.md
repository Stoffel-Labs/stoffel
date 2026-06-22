# Markov Chain Steady State (fix64)

Iterates a 2-state stochastic matrix in fix64 until the distribution converges to the analytic steady state, checking row-stochasticity is preserved and that the limit is a fixed point.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
