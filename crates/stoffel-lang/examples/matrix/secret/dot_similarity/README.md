# Private Dot-Product Similarity

Two clients' preference vectors meet in a share-by-share inner product; only the similarity scores are revealed.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=3 --client-input 0=-1 --client-input 0=4 --client-input 0=2 --client-input 1=2 --client-input 1=5 --client-input 1=-1 --client-input 1=3
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
