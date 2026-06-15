# MPC Weighted Voting

Weighted vote tally with secret weights: does `Σ wᵢ·voteᵢ` reach a public
threshold? A batched secure multiply forms the weighted sum, then one comparison
gives the decision bit. Votes and weights stay private.

The example checks weighted total `3` (votes `[1,0,1]`, weights `[2,3,1]`) against
thresholds 3 (→ pass) and 4 (→ fail). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_weighted_voting
```
