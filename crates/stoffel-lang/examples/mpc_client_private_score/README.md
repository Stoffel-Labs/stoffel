# MPC Client Private Score

This example is an end-to-end client I/O program. Clients submit private integer
features as input shares, the MPC parties compute a simple eligibility score on
shares, and the result share is sent back to the requesting client without
opening it to every party. The normalization step is factored into a helper
that works on strictly typed `Share` values.

It is useful as a template for private scoring, private risk checks, and
client-facing MPC services that return encrypted/share-based results.
