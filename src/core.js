/**
 * STUN message attribute parsing and serialization.
 *
 * Implements RFC 5389 §15 (attribute TLV structure) and §15.2
 * (XOR-MAPPED-ADDRESS), plus the non-XOR MAPPED-ADDRESS from RFC 5389
 * §15.1 for completeness. Only the attributes needed for NAT-traversal
 * reflection are modelled; unknown attributes round-trip as raw bytes so
 * callers can inspect them without this library having to know every type.
 */

/**
 * Fixed 32-bit cookie placed at byte offset 4 of every RFC 5389 STUN message.
 * XOR attributes mix this into their value so that fixed-line NAT boxes do not
 * rewrite the IP address they see embedded in the packet.
 */
export const MAGIC_COOKIE = 0x2112a442;

/**
 * Attribute type codes we understand. Kept as a plain object (not an enum) so
 * the value space is open: callers can pass arbitrary 16-bit numbers for types
 * this library does not name.
 */
export const ATTRIBUTE_TYPES = Object.freeze({
  MAPPED_ADDRESS: 0x0001,
  XOR_MAPPED_ADDRESS: 0x0020,
  ERROR_CODE: 0x0009,
  MESSAGE_INTEGRITY: 0x0008,
  FINGERPRINT: 0x8028,
});

/**
 * RFC 5389 §15.2: any attribute type whose top bit (0x8000) is set is a
 * "comprehension-optional" attribute. We do not special-case it, but exposing
 * the test makes round-tripping safer for callers who want to log unknowns.
 */
export function isXorAttribute(type) {
  // Only XOR-MAPPED-ADDRESS is actually XOR-processed by this library.
  // The name is kept narrow on purpose.
  return type === ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS;
}

/**
 * XOR a byte slice with the repeating pattern [magic-cookie high, magic-cookie
 * low, transaction-id]. For XOR-MAPPED-ADDRESS only the cookie portion is used
 * (the address is too short to reach the transaction ID), but we accept the
 * full key so the same helper can be reused if future attributes need it.
 *
 * Returns a new Uint8Array; inputs are not mutated.
 */
export function xorBytes(data, key) {
  if (data.length === 0) return new Uint8Array();
  if (key.length === 0) {
    throw new TypeError('xorBytes: key must be non-empty');
  }
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ key[i % key.length];
  }
  return out;
}

/**
 * Write a 16-bit big-endian value into a Uint8Array at the given offset.
 * Returns the offset advanced by 2.
 */
function writeU16(view, offset, value) {
  view.setUint16(offset, value, false);
  return offset + 2;
}

/**
 * Write a 32-bit big-endian value. Returns the offset advanced by 4.
 */
function writeU32(view, offset, value) {
  view.setUint32(offset, value >>> 0, false);
  return offset + 4;
}

/**
 * Build the 4-byte attribute header (type + length) at the given offset.
 * `length` is the value-length only, not including the header or any padding.
 */
export function writeAttributeHeader(view, offset, type, length) {
  if (type < 0 || type > 0xffff) {
    throw new RangeError(`attribute type out of range: ${type}`);
  }
  if (length < 0 || length > 0xffff) {
    throw new RangeError(`attribute length out of range: ${length}`);
  }
  let o = writeU16(view, offset, type);
  o = writeU16(view, o, length);
  return o;
}

/**
 * Read a 4-byte attribute header. Returns `{ type, length, next }` where `next`
 * is the offset of the value bytes. Throws on truncation.
 */
export function readAttributeHeader(view, offset) {
  if (offset + 4 > view.byteLength) {
    throw new RangeError('attribute header truncated');
  }
  const type = view.getUint16(offset, false);
  const length = view.getUint16(offset + 2, false);
  return { type, length, next: offset + 4 };
}

/**
 * Round `n` up to the next multiple of 4. STUN pads attribute values to a
 * 4-byte boundary, but the `length` field holds the unpadded size, so callers
 * must advance by the padded size when iterating.
 */
function pad4(n) {
  return (n + 3) & ~3;
}

/**
 * Serialise a MAPPED-ADDRESS (RFC 5389 §15.1). Exposed because some servers
 * still emit it alongside the XOR form, and a client that wants to log both
 * shouldn't need a second library.
 *
 * `family` is 0x01 for IPv4 or 0x02 for IPv6.
 */
export function serializeMappedAddress(family, address, port) {
  const ipBytes = parseIpAddress(address, family);
  // 1 reserved + 1 family + 2 port + address bytes
  const value = new Uint8Array(4 + ipBytes.length);
  const view = new DataView(value.buffer);
  value[0] = 0x00; // reserved, must be ignored on read
  value[1] = family;
  writeU16(view, 2, port);
  value.set(ipBytes, 4);
  return value;
}

/**
 * Parse a MAPPED-ADDRESS value. Returns `{ family, address, port }` where
 * `address` is the dotted-quad / colon-hex string form.
 */
export function parseMappedAddress(value) {
  if (value.length < 4) {
    throw new RangeError('MAPPED-ADDRESS too short');
  }
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const family = value[1];
  const port = view.getUint16(2, false);
  const addrBytes = value.subarray(4);
  const address = formatIpAddress(addrBytes, family);
  return { family, address, port };
}

/**
 * Serialise an XOR-MAPPED-ADDRESS (RFC 5389 §15.2). The port is XORed with the
 * high 16 bits of the magic cookie; the address is XORed with the full 32-bit
 * cookie (IPv4) or cookie-plus-transaction-id (IPv6).
 *
 * `transactionId` is the 12-byte transaction ID from the STUN header. It is
 * required for IPv6 because the XOR mask spans cookie + txn-id. For IPv4 it is
 * ignored but accepted so callers don't need a branch.
 */
export function serializeXorMappedAddress(family, address, port, transactionId) {
  const ipBytes = parseIpAddress(address, family);
  const value = new Uint8Array(4 + ipBytes.length);
  const view = new DataView(value.buffer);
  value[0] = 0x00;
  value[1] = family;

  // Port: top 16 bits of the magic cookie.
  const xPort = port ^ (MAGIC_COOKIE >>> 16);
  writeU16(view, 2, xPort);

  // Address: XOR with the cookie (and, for IPv6, the transaction ID).
  const key = buildXorKey(family, transactionId);
  const xAddr = xorBytes(ipBytes, key);
  value.set(xAddr, 4);
  return value;
}

/**
 * Parse an XOR-MAPPED-ADDRESS value. Inverse of `serializeXorMappedAddress`.
 * `transactionId` is the 12-byte transaction ID from the STUN header.
 */
export function parseXorMappedAddress(value, transactionId) {
  if (value.length < 4) {
    throw new RangeError('XOR-MAPPED-ADDRESS too short');
  }
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const family = value[1];
  const xPort = view.getUint16(2, false);
  const port = xPort ^ (MAGIC_COOKIE >>> 16);

  const addrBytes = value.subarray(4);
  const key = buildXorKey(family, transactionId);
  const rawAddr = xorBytes(addrBytes, key);
  const address = formatIpAddress(rawAddr, family);
  return { family, address, port };
}

/**
 * Build the XOR key for the address portion of an XOR-MAPPED-ADDRESS.
 *
 * IPv4: the 4-byte magic cookie. The address is exactly 4 bytes, so the key is
 * exactly 4 bytes and no transaction ID is needed.
 *
 * IPv6: the 4-byte cookie followed by the 12-byte transaction ID, giving a
 * 16-byte key matching the 16-byte address. We require the transaction ID
 * here; passing the wrong length is a caller bug, not a recoverable parse
 * error, so we throw.
 */
function buildXorKey(family, transactionId) {
  const cookieBytes = new Uint8Array(4);
  new DataView(cookieBytes.buffer).setUint32(0, MAGIC_COOKIE, false);

  if (family === 0x01) {
    return cookieBytes;
  }
  if (family === 0x02) {
    if (!transactionId || transactionId.length !== 12) {
      throw new TypeError(
        'IPv6 XOR-MAPPED-ADDRESS requires a 12-byte transaction ID',
      );
    }
    const key = new Uint8Array(16);
    key.set(cookieBytes, 0);
    key.set(transactionId, 4);
    return key;
  }
  throw new RangeError(`unknown address family: ${family}`);
}

/**
 * Parse a dotted-quad or colon-hex string into bytes. Used by both serialisers.
 * `family` is checked so that a caller passing an IPv6 string with family=IPv4
 * gets a clear error rather than a silently wrong encoding.
 */
function parseIpAddress(address, family) {
  if (family === 0x01) {
    const parts = address.split('.');
    if (parts.length !== 4) {
      throw new TypeError(`invalid IPv4 address: ${address}`);
    }
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const octet = Number(parts[i]);
      if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
        throw new TypeError(`invalid IPv4 octet: ${parts[i]}`);
      }
      out[i] = octet;
    }
    return out;
  }
  if (family === 0x02) {
    // Handle the common :: shorthand by expanding it. We do not handle IPv4
    // embedded in IPv6 ("::ffff:1.2.3.4") because STUN NAT-traversal servers
    // do not emit that form for XOR-MAPPED-ADDRESS; adding it would mean
    // carrying a second parser for a case that does not arise in practice.
    const full = expandIpv6(address);
    const groups = full.split(':');
    if (groups.length !== 8) {
      throw new TypeError(`invalid IPv6 address: ${address}`);
    }
    const out = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      const word = parseInt(groups[i], 16);
      if (!Number.isInteger(word) || word < 0 || word > 0xffff) {
        throw new TypeError(`invalid IPv6 group: ${groups[i]}`);
      }
      out[i * 2] = (word >> 8) & 0xff;
      out[i * 2 + 1] = word & 0xff;
    }
    return out;
  }
  throw new RangeError(`unknown address family: ${family}`);
}

/**
 * Expand an IPv6 string with `::` into 8 colon-separated hex groups. Throws if
 * the address is malformed. Leading/trailing `::` are handled.
 */
function expandIpv6(address) {
  if (!address.includes('::')) {
    return address;
  }
  // Only one `::` is legal.
  const parts = address.split('::');
  if (parts.length !== 2) {
    throw new TypeError(`invalid IPv6 address (multiple ::): ${address}`);
  }
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 1) {
    throw new TypeError(`invalid IPv6 address (too many groups): ${address}`);
  }
  const fill = new Array(missing).fill('0');
  return [...left, ...fill, ...right].join(':');
}

/**
 * Format raw address bytes back into a string. Inverse of `parseIpAddress`.
 */
function formatIpAddress(bytes, family) {
  if (family === 0x01) {
    if (bytes.length !== 4) {
      throw new RangeError(`IPv4 address must be 4 bytes, got ${bytes.length}`);
    }
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  }
  if (family === 0x02) {
    if (bytes.length !== 16) {
      throw new RangeError(`IPv6 address must be 16 bytes, got ${bytes.length}`);
    }
    const groups = [];
    for (let i = 0; i < 8; i++) {
      const word = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
      groups.push(word.toString(16));
    }
    // We do not compress runs of zeros back to `::`. The canonical form from a
    // STUN server is already compressed, but round-tripping through this
    // library produces the expanded form. That is a deliberate trade-off:
    // compression is fiddly to do canonically, and callers comparing addresses
    // for equality should normalise both sides, not string-compare.
    return groups.join(':');
  }
  throw new RangeError(`unknown address family: ${family}`);
}

/**
 * Parse a single attribute value given its type. Returns a structured object
 * for known types, or `{ raw: Uint8Array }` for unknown ones so nothing is lost.
 *
 * `transactionId` is the 12-byte transaction ID from the STUN header; it is
 * only consulted for XOR-MAPPED-ADDRESS but is required for that case.
 */
export function parseAttribute(type, value, transactionId) {
  switch (type) {
    case ATTRIBUTE_TYPES.MAPPED_ADDRESS:
      return parseMappedAddress(value);
    case ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS:
      return parseXorMappedAddress(value, transactionId);
    default:
      return { raw: value };
  }
}

/**
 * Serialise a structured attribute value back into bytes (the value only, no
 * header). Inverse of `parseAttribute` for the known types; for unknown types
 * the input must be `{ raw: Uint8Array }`.
 */
export function serializeAttribute(type, parsed, transactionId) {
  switch (type) {
    case ATTRIBUTE_TYPES.MAPPED_ADDRESS:
      return serializeMappedAddress(parsed.family, parsed.address, parsed.port);
    case ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS:
      return serializeXorMappedAddress(
        parsed.family,
        parsed.address,
        parsed.port,
        transactionId,
      );
    default:
      if (!parsed || !(parsed.raw instanceof Uint8Array)) {
        throw new TypeError('unknown attribute requires { raw: Uint8Array }');
      }
      return parsed.raw;
  }
}

/**
 * Parse every attribute in a STUN message body. `body` is the bytes after the
 * 20-byte STUN header. Returns an array of `{ type, value, parsed }` objects.
 *
 * `transactionId` is the 12-byte transaction ID from the STUN header; pass it
 * through so XOR-MAPPED-ADDRESS can be decoded.
 */
export function parseAttributes(body, transactionId) {
  const view = new DataView(
    body.buffer,
    body.byteOffset,
    body.byteLength,
  );
  const out = [];
  let offset = 0;
  while (offset < body.length) {
    const { type, length, next } = readAttributeHeader(view, offset);
    if (next + length > body.length) {
      throw new RangeError(`attribute value truncated: type=0x${type.toString(16)}`);
    }
    const value = body.subarray(next, next + length);
    const parsed = parseAttribute(type, value, transactionId);
    out.push({ type, value, parsed });
    offset = next + pad4(length);
  }
  return out;
}

/**
 * Serialise an array of attributes into a single `Uint8Array` body. Each entry
 * is `{ type, parsed }`; unknown types use `{ type, parsed: { raw: Uint8Array } }`.
 * `transactionId` is passed through to the XOR serialiser.
 */
export function serializeAttributes(attrs, transactionId) {
  // First pass: compute total size so we allocate once.
  let total = 0;
  const encoded = [];
  for (const attr of attrs) {
    const value = serializeAttribute(attr.type, attr.parsed, transactionId);
    encoded.push({ type: attr.type, value });
    total += 4 + pad4(value.length);
  }

  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const { type, value } of encoded) {
    offset = writeAttributeHeader(view, offset, type, value.length);
    out.set(value, offset);
    offset += pad4(value.length);
  }
  return out;
}
