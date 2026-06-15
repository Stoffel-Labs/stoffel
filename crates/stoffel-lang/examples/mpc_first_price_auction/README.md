# MPC First-Price Auction

Sealed-bid first-price auction over secret bids: a single pass tracks the running
maximum bid and its index, yielding the winner index and the winning price (both
secret shares; reveal only what the mechanism requires).

The example runs bids `[30,70,50]` → winner index 1, price 70. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_first_price_auction
```
