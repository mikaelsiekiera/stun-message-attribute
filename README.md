# stun-attr

Parses and serialises STUN message attribute TLVs (RFC 5389 §15), with first-class support for `XOR-MAPPED-ADDRESS` used in NAT-traversal reflection.

```js
import {
  serializeXorMappedAddress,
  parseXorMappedAddress,
  parseAttributes,
  serializeAttributes,
  ATTRIBUTE_TYPES,
} from './src/index.js';

// 12-byte transaction ID copied out of the STUN message header.
const txnId = new Uint8Array(12); // fill with your real txn id

const value = serializeXorMappedAddress(0x01, '192.0.2.1', 32853, txnId);
const { address, port } = parseXorMappedAddress(value, txnId);

const body = serializeAttributes(
  [{ type: ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS,
     parsed: { family: 0x01, address: '192.0.2.1', port: 32853 } }],
  txnId,
);
const attrs = parseAttributes(body, txnId);
```

## Why

STUN clients usually pull in a full message parser to read a single reflected address. This library does only the attribute layer: given the 12-byte transaction ID and the message body bytes, it decodes `XOR-MAPPED-ADDRESS` (and the non-XOR `MAPPED-ADDRESS`) and round-trips unknown attributes as raw bytes so callers can log them without a second dependency. The trade-off is that you, the caller, are responsible for the 20-byte STUN header and the transaction ID inside it; this library does not parse or verify the header.

## Edge cases worth knowing

- IPv6 `XOR-MAPPED-ADDRESS` requires the 12-byte transaction ID because the XOR mask spans the magic cookie **and** the transaction ID. IPv4 ignores it but accepts the argument so callers don't branch.
- IPv6 addresses are returned in **expanded** form (`2001:db8:0:0:0:0:0:1`), not compressed (`2001:db8::1`). Compressing canonically is fiddly; callers comparing addresses should normalise both sides rather than string-compare.
- IPv4-in-IPv6 forms ("`::ffff:1.2.3.4`") are not supported. STUN servers do not emit them for `XOR-MAPPED-ADDRESS` in practice.
- Attribute values are padded to a 4-byte boundary on the wire; `parseAttributes` advances by the padded size, but the `length` field and the `value` slice both hold the unpadded size.

## Exports

`MAGIC_COOKIE`, `ATTRIBUTE_TYPES`, `isXorAttribute`, `xorBytes`, `writeAttributeHeader`, `readAttributeHeader`, `parseXorMappedAddress`, `serializeXorMappedAddress`, `parseMappedAddress`, `serializeMappedAddress`, `parseAttribute`, `serializeAttribute`, `parseAttributes`, `serializeAttributes`.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

