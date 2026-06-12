# Bitwise Share Example

This example demonstrates `not`, `and`, `or`, and `xor` on `list[secret bool]`
inputs represented as a small `bitwise_share` object.

Validate the source:

```sh
stoffel check examples/bitwise_share
```

Run it with sample secret boolean vectors:

```sh
stoffel run examples/bitwise_share --input 'a=[true,false,true,false]' --input 'b=[true,true,false,false]'
```

The local MPC run should show boolean shares backed by `SecretInt { bit_length: 1 }`.
