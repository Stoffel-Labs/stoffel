#!/usr/bin/env bash
# Run the threshold-key / client-secret-input AES-128 example.
#
# Two clients feed secret inputs (nothing is a program constant):
#   * slot 0 (data owner): the 16-byte plaintext, 8 secret bits per byte
#   * slot 1 (key holder): the 16-byte AES key,   8 secret bits per byte
#
# Each byte is supplied LSB-first (bit i carries weight 2^i), matching the
# circuit's `reveal_byte`. We use the FIPS-197 AES-128 known-answer vectors so
# the revealed ciphertext can be checked against a published value.
#
# Plaintext  : 00112233445566778899aabbccddeeff
# Key        : 000102030405060708090a0b0c0d0e0f
# Ciphertext : 69c4e0d86a7b0430d8cdb78070b4c55a
#              = [105,196,224,216,106,123,4,48,216,205,183,128,112,180,197,90]
#
# Usage: ./run.sh   (run from this directory, repo built with stoffel-run)
set -euo pipefail

PLAINTEXT_HEX="00112233445566778899aabbccddeeff"
KEY_HEX="000102030405060708090a0b0c0d0e0f"

# Emit one `--client-input <slot>=<bit>` per bit, LSB-first per byte.
# Bits MUST be supplied as booleans (true/false) so the input protocol produces
# `secret bool` (boolean) shares — the AES gates (NOT/AND/XOR) reject arithmetic
# shares, which is what integer inputs (0/1) would produce.
emit_bits() {
  local slot="$1" hex="$2" i byte bit val
  for ((i = 0; i < ${#hex}; i += 2)); do
    byte=$((16#${hex:i:2}))
    for ((bit = 0; bit < 8; bit++)); do
      if (((byte >> bit) & 1)); then val="true"; else val="false"; fi
      printf -- '--client-input %s=%s ' "$slot" "$val"
    done
  done
}

ARGS="$(emit_bits 0 "$PLAINTEXT_HEX")$(emit_bits 1 "$KEY_HEX")"

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
RUNNER="${STOFFEL_RUN_BIN:-$REPO_ROOT/target/release/stoffel-run}"
STOFFEL="${STOFFEL_BIN:-$REPO_ROOT/target/release/stoffel}"

# shellcheck disable=SC2086
STOFFEL_RUN_BIN="$RUNNER" "$STOFFEL" run "$(dirname "$0")" \
  --local --runner "$RUNNER" --timeout-secs 1100 $ARGS
