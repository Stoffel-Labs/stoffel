# MPC Lookup Table

Oblivious key→value lookup over a public table for a **secret** key:
`value = Σⱼ [key == keyⱼ] · valⱼ`. Which entry matched is never revealed.

The example looks up key `20` in `{10→100, 20→200, 30→300}` (→ 200). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_lookup_table
```
