# Carter-Wegman MAC under MPC

Tags t = k1*m + k2 are computed with the key and messages held by different clients as shares; tags are published, secrets are not.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=1234 --client-input 0=5678 --client-input 1=37 --client-input 1=911
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
