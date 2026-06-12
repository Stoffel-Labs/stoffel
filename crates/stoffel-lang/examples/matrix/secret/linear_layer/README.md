# Private Inference Linear Layer

A client's secret feature vector passes through public weights W and bias b using share-by-public scalings; only the logits emerge.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=4 --client-input 0=7
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
