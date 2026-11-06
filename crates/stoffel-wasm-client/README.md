# Stoffel WASM client

The WASM client keeps clear client values inside the browser while exchanging
mask shares and encrypted output shares through the coordinator's browser RPC.

## Persistent and concurrent executions

Create one long-lived `StoffelWasmClient` for the browser identity, then open a
handle for every execution admitted by a standing Stoffel node:

```js
const client = new StoffelWasmClient(pkcs8Key, 5, 1);
const deal = client.open_execution(dealExecutionId);
const action = client.open_execution(actionExecutionId);

// Each signed request carries its own random nonce and `created` timestamp,
// so handles share no state; opening the same ID twice is harmless.
const dealRequest = deal.sign_request("browser_execution_status", jsonBody({}));
const actionRequest = action.sign_request("browser_execution_status", jsonBody({}));
```

Pass the returned signed request to the browser RPC together with the handle's
execution ID. After a page reload, just call `client.open_execution(id)` again;
there is no nonce counter to save or restore.

## Typed inputs and outputs

`execution.mask_inputs` accepts the same scalar value families as the native
Rust client. Signed and unsigned 64-bit values cross the JS boundary as
`BigInt`s:

```js
const inputs = [
  {
    share_type: { kind: "boolean" },
    value: { kind: "boolean", value: true },
  },
  {
    share_type: { kind: "signed_integer", bit_length: 64 },
    value: { kind: "signed_integer", value: -42n },
  },
  {
    share_type: { kind: "unsigned_integer", bit_length: 32 },
    value: { kind: "unsigned_integer", value: 4_000_000_000n },
  },
  {
    share_type: {
      kind: "fixed_point",
      total_bits: 64,
      fractional_bits: 16,
    },
    value: { kind: "fixed_point", value: 12.75 },
  },
];

const masked = execution.mask_inputs(firstReservedIndex, inputs, nodeShares);
```

For full-width protocol inputs, use `{ kind: "field", value: bytes }`, where
`bytes` is one canonical 32-byte, big-endian BLS12-381 scalar. Field inputs are
valid for signed integers wider than one bit and for unsigned integers.

Typed output schemas use the same `share_type` objects without the wrapper:

```js
const values = execution.decrypt_outputs(
  [
    { kind: "boolean" },
    { kind: "unsigned_integer", bit_length: 32 },
    { kind: "fixed_point", total_bits: 64, fractional_bits: 16 },
  ],
  encryptedShares,
);
```

The result is an array of tagged values. Integer results contain JavaScript
`BigInt`s; booleans and fixed-point results contain normal JS primitives.

All request signing, input masking, and output decryption is execution-bound.
The client object only owns identity, topology, and execution lifecycle state.
