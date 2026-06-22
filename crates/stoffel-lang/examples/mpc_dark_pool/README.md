# MPC Dark-Pool Order Matching

A private dark-pool match between a buyer and a seller. Each submits a secret
limit order and learns only their own fill — never the counterparty's price or
quantity.

- Client 0 (buyer) submits `(bid_price, bid_qty)`.
- Client 1 (seller) submits `(ask_price, ask_qty)`.

The orders cross iff `ask_price <= bid_price`; the matched quantity is then
`min(bid_qty, ask_qty)`, otherwise `0`. The crossing test and the minimum use
the carry-based secure comparison from
[`mpc_secure_comparison`](../mpc_secure_comparison), and the resulting fill is
delivered to both clients.

The example crosses a bid of `100 × 10` against an ask of `90 × 7`, yielding a
fill of `min(10, 7) = 7`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_dark_pool --client-input 0=100 --client-input 0=10 --client-input 1=90 --client-input 1=7 --expected-output-clients 2
```
