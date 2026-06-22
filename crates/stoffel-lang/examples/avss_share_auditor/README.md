# AVSS Share Auditor

This example inspects AVSS shares for a certificate or keygen flow. It exposes a
helper that takes a runtime-provided `AvssShare`, verifies metadata, and hashes a
commitment into the curve field. The `main` function is safe to run without an
AVSS share and demonstrates the type guard.
