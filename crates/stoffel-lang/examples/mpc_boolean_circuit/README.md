# MPC Boolean Circuit

This example bootstraps boolean gates from `secret bool` values. `Share.random()`
is contextualized by the compiler as a one-bit random share, so each input is a
private bit.

The gates use arithmetic over 1-bit shares instead of secret-control-flow or
secret bitwise bytecode:

- `AND(a, b) = a * b`
- `NOT(a) = 1 - a`
- `OR(a, b) = a + b - (a * b)`
- `XOR(a, b) = a + b - 2 * (a * b)`

The circuit computes:

```text
((x AND y) OR (NOT z)) XOR (x AND (NOT y))
```

Run it through the local MPC CLI:

```sh
stoffel run
```
