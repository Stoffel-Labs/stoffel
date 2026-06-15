# MPC Protocol Coordination

This example coordinates a protocol round with reliable broadcast (RBC). Every
party broadcasts and confirms it has reached the same phase before opening or
exporting results. It is useful for MPC workflows that need a shared phase
checkpoint.

Run it under a VM configured with the RBC protocol service.
