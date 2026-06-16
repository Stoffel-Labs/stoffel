# Consent-Masked Disclosure

A private data matrix times a private 0/1 consent mask, elementwise: exactly the consented cells are disclosed, the rest open as zero.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=12 --client-input 0=34 --client-input 0=56 --client-input 0=78 --client-input 1=1 --client-input 1=0 --client-input 1=0 --client-input 1=1
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
