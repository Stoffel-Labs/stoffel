# MPC Share Toolkit

This example is a reusable secure scoring flow. It creates clear integer and
fixed-point shares, combines and opens them, checks share metadata and
commitments, sends output shares to a client, and exercises the scalar, batch,
field, random, and open-in-exponent builtins.

Run it under a configured MPC runtime. Some operations depend on backend
capabilities such as multiplication, client output, commitments, and
open-in-exponent. The share batch is typed as `list[Share]`, so this also
serves as the broad strict-Share API example.
