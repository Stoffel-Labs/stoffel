# MPC k-Nearest-Neighbor (1-NN)

Private nearest-neighbor classification against a realistic reference set: 40
public reference points in 4 dimensions. The client's query vector is
secret-shared; the protocol returns the label of the closest reference point
without revealing the query.

For each reference point it computes the squared L2 distance to the query
(`Σ (q_i - p_i)^2`, one secret multiply per dimension) and keeps a running
argmin via the carry-based secure comparison and oblivious `select`. The cost is
linear in the number of reference points: `N - 1 = 39` comparisons here (≈40s on
the local simulator); a larger reference set adds proportionally more.

Reference point `i` is `[i, i, i, i]` with label `i`; the query `[0,0,0,0]` is
nearest to point `0`, so the returned label is `0`.

Run it from the repository root (4 secret query features for client 0):

```sh
stoffel run crates/stoffel-lang/examples/mpc_knn --client-input 0=0 --client-input 0=0 --client-input 0=0 --client-input 0=0 --expected-output-clients 1
```
