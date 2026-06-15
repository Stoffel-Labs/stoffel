# MPC Diffie-Hellman PSI

Private set intersection via the Diffie-Hellman / OPRF construction. Two clients
each contribute a set; every element is mapped through the same
threshold-shared-key OPRF tag `H(e)^k` (see [`mpc_oprf`](../mpc_oprf)). Equal
elements produce equal tags, so the intersection is found by comparing tags —
and because the tags are pseudorandom, comparing them reveals nothing beyond the
matches themselves.

This scales better than the bit-decomposition `mpc_set_intersection`: each
element costs one curve exponentiation rather than a per-bit comparison circuit.

The example intersects `{10, 20, 30}` (client 0) with `{20, 30, 40}` (client 1),
returns the cardinality `2` to both clients, and asserts it.

> As with `mpc_oprf`, a production deployment blinds elements client-side so the
> servers never see them; this example demonstrates the tag-and-match mechanism.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_dh_psi --client-input 0=10 --client-input 0=20 --client-input 0=30 --client-input 1=20 --client-input 1=30 --client-input 1=40 --expected-output-clients 2
```
