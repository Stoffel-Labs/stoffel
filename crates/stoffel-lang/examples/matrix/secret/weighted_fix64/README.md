# Weighted Fixed-Point Sensor Fusion

Three stations' private fix64 readings are fused with public reliability weights (local share scalings); only the weighted totals are opened.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=65536 --client-input 0=131072 --client-input 1=98304 --client-input 1=32768 --client-input 2=163840 --client-input 2=65536
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
