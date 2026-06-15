# MPC Second-Price (Vickrey) Auction

Sealed-bid second-price auction over secret bids: the winner is the argmax bidder,
but the clearing price is the **second-highest** bid. The winner index comes from a
max scan; the second price is `sorted[n−2]` from a small sorting network. Both stay
secret until revealed.

The example runs bids `[30,70,50]` → winner index 1, clearing price 50. `κ` is
small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_second_price_auction
```
