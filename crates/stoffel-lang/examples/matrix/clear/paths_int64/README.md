# Walk Counting with Adjacency Powers (int64)

Powers of a graph's adjacency matrix count walks: the example checks 2- and 3-step walk counts on a directed graph by hand, and counts triangles in an undirected graph via trace(A^3) = 6 * triangles.

Validate and run from this directory:

```sh
stoffel check .
stoffel run .
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
