# MPC Voting Tally

Tally secret yes/no votes and reveal only whether the count meets a public
threshold `τ`: sum the vote bits, then `[tally ≥ τ]` via one secure comparison.
Individual votes stay private.

The example tallies `[1,0,1,1,0]` (3 yes) against thresholds 3 (→ pass) and 4
(→ fail). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_voting_tally --client-input 0=1 --client-input 1=0 --client-input 2=1 --client-input 3=1 --client-input 4=0 --expected-output-clients 5
```
