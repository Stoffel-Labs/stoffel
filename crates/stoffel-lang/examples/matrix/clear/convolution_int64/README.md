# 2D Convolution (int64)

Convolves an `int64` grid with 3x3 kernels (box blur and edge detector) using zero padding, asserting known outputs at interior and border positions.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
