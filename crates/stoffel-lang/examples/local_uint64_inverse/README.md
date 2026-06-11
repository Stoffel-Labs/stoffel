# Local uint64 inverse

Demonstrates an unsigned modular multiplicative inverse using only `uint64`
arithmetic. The example avoids signed Bezout coefficients by tracking the
coefficient modulo `mod` and using overflow-safe modular addition,
subtraction, and multiplication helpers.

The expected return value is `4u64`, because `3 * 4 % 11 == 1`.
