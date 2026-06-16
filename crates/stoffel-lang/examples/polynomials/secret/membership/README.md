# Secret Set Membership via Polynomial Roots (secret int64)

Proves a secret value belongs to a public set by evaluating the set's root polynomial prod(x - c) on shares: every factor and product stays secret, and only the single is-zero verdict is revealed. Includes the classic vote-validity check v*(v-1) = 0.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
