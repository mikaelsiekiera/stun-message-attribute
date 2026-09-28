import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MAGIC_COOKIE,
  ATTRIBUTE_TYPES,
  isXorAttribute,
  xorBytes,
  writeAttributeHeader,
  readAttributeHeader,
  parseXorMappedAddress,
  serializeXorMappedAddress,
  parseMappedAddress,
  serializeMappedAddress,
  parseAttribute,
  serializeAttribute,
  parseAttributes,
  serializeAttributes,
} from '../src/index.js';

/**
 * Build a 12-byte transaction ID from a 24-char hex string. Deterministic so
 * tests don't depend on `crypto.randomBytes`.
 */
function txnId(hex) {
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

const TXN = txnId('00112233445566778899aabb');

test('MAGIC_COOKIE matches RFC 5389', () => {
  assert.equal(MAGIC_COOKIE, 0x2112a442);
});

test('ATTRIBUTE_TYPES is frozen', () => {
  assert.ok(Object.isFrozen(ATTRIBUTE_TYPES));
});

test('isXorAttribute is true only for XOR-MAPPED-ADDRESS', () => {
  assert.equal(isXorAttribute(ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS), true);
  assert.equal(isXorAttribute(ATTRIBUTE_TYPES.MAPPED_ADDRESS), false);
  assert.equal(isXorAttribute(0x8028), false);
});

test('xorBytes XORs with a repeating key and does not mutate input', () => {
  const data = Uint8Array.of(0x01, 0x02, 0x03, 0x04, 0x05);
  const key = Uint8Array.of(0xff, 0x00);
  const out = xorBytes(data, key);
  assert.deepEqual(Array.from(out), [0xfe, 0x02, 0xfc, 0x04, 0xfa]);
  // input untouched
  assert.deepEqual(Array.from(data), [0x01, 0x02, 0x03, 0x04, 0x05]);
});

test('xorBytes on empty input returns empty', () => {
  const out = xorBytes(new Uint8Array(0), Uint8Array.of(1));
  assert.equal(out.length, 0);
});

test('xorBytes throws on empty key', () => {
  assert.throws(() => xorBytes(Uint8Array.of(1), new Uint8Array(0)), TypeError);
});

test('writeAttributeHeader then readAttributeHeader round-trips', () => {
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer);
  writeAttributeHeader(view, 0, 0x0020, 12);
  const hdr = readAttributeHeader(view, 0);
  assert.equal(hdr.type, 0x0020);
  assert.equal(hdr.length, 12);
  assert.equal(hdr.next, 4);
});

test('writeAttributeHeader rejects out-of-range type and length', () => {
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer);
  assert.throws(() => writeAttributeHeader(view, 0, -1, 0), RangeError);
  assert.throws(() => writeAttributeHeader(view, 0, 0x10000, 0), RangeError);
  assert.throws(() => writeAttributeHeader(view, 0, 0, -1), RangeError);
  assert.throws(() => writeAttributeHeader(view, 0, 0, 0x10000), RangeError);
});

test('readAttributeHeader throws on truncation', () => {
  const buf = new Uint8Array(3);
  const view = new DataView(buf.buffer);
  assert.throws(() => readAttributeHeader(view, 0), RangeError);
});

test('serializeXorMappedAddress IPv4 then parseXorMappedAddress round-trips', () => {
  const value = serializeXorMappedAddress(0x01, '192.0.2.1', 32853, TXN);
  // 1 reserved + 1 family + 2 port + 4 addr
  assert.equal(value.length, 8);
  const parsed = parseXorMappedAddress(value, TXN);
  assert.equal(parsed.family, 0x01);
  assert.equal(parsed.address, '192.0.2.1');
  assert.equal(parsed.port, 32853);
});

test('serializeXorMappedAddress IPv6 round-trips and needs the transaction ID', () => {
  const value = serializeXorMappedAddress(
    0x02,
    '2001:db8::1',
    41234,
    TXN,
  );
  assert.equal(value.length, 20);
  const parsed = parseXorMappedAddress(value, TXN);
  assert.equal(parsed.family, 0x02);
  // expanded form (no :: compression) — see formatIpAddress docstring
  assert.equal(parsed.address, '2001:db8:0:0:0:0:0:1');
  assert.equal(parsed.port, 41234);
});

test('parseXorMappedAddress IPv6 throws without a transaction ID', () => {
  const value = serializeXorMappedAddress(0x02, '2001:db8::1', 41234, TXN);
  assert.throws(
    () => parseXorMappedAddress(value, undefined),
    TypeError,
  );
  assert.throws(
    () => parseXorMappedAddress(value, new Uint8Array(11)),
    TypeError,
  );
});

test('parseXorMappedAddress throws on too-short value', () => {
  assert.throws(
    () => parseXorMappedAddress(new Uint8Array(3), TXN),
    RangeError,
  );
});

test('serializeXorMappedAddress rejects a bad IPv4 string', () => {
  assert.throws(
    () => serializeXorMappedAddress(0x01, '300.0.0.1', 1, TXN),
    TypeError,
  );
  assert.throws(
    () => serializeXorMappedAddress(0x01, '1.2.3', 1, TXN),
    TypeError,
  );
});

test('serializeXorMappedAddress rejects an unknown family', () => {
  assert.throws(
    () => serializeXorMappedAddress(0x03, '1.2.3.4', 1, TXN),
    RangeError,
  );
});

test('serializeMappedAddress / parseMappedAddress round-trip IPv4', () => {
  const value = serializeMappedAddress(0x01, '203.0.113.42', 5000);
  assert.equal(value.length, 8);
  const parsed = parseMappedAddress(value);
  assert.equal(parsed.family, 0x01);
  assert.equal(parsed.address, '203.0.113.42');
  assert.equal(parsed.port, 5000);
});

test('parseMappedAddress throws on too-short value', () => {
  assert.throws(() => parseMappedAddress(new Uint8Array(3)), RangeError);
});

test('parseAttribute returns { raw } for unknown types', () => {
  const raw = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const parsed = parseAttribute(0x8000, raw, TXN);
  assert.ok(parsed.raw instanceof Uint8Array);
  assert.deepEqual(Array.from(parsed.raw), [0xde, 0xad, 0xbe, 0xef]);
});

test('serializeAttribute round-trips unknown types via { raw }', () => {
  const raw = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const out = serializeAttribute(0x8000, { raw }, TXN);
  assert.deepEqual(Array.from(out), [0xde, 0xad, 0xbe, 0xef]);
});

test('serializeAttribute throws for unknown type without { raw }', () => {
  assert.throws(
    () => serializeAttribute(0x8000, { something: 'else' }, TXN),
    TypeError,
  );
});

test('parseAttributes walks a body with padding', () => {
  // Two attributes: a 5-byte unknown (padded to 8) and an 8-byte XOR-MAPPED-ADDRESS.
  const xorVal = serializeXorMappedAddress(0x01, '192.0.2.1', 32853, TXN);
  const unknownVal = Uint8Array.of(0x01, 0x02, 0x03, 0x04, 0x05);

  const body = serializeAttributes(
    [
      { type: 0x8000, parsed: { raw: unknownVal } },
      { type: ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS,
        parsed: { family: 0x01, address: '192.0.2.1', port: 32853 } },
    ],
    TXN,
  );

  const attrs = parseAttributes(body, TXN);
  assert.equal(attrs.length, 2);
  assert.equal(attrs[0].type, 0x8000);
  assert.deepEqual(Array.from(attrs[0].parsed.raw), [0x01, 0x02, 0x03, 0x04, 0x05]);
  assert.equal(attrs[1].type, ATTRIBUTE_TYPES.XOR_MAPPED_ADDRESS);
  assert.equal(attrs[1].parsed.address, '192.0.2.1');
  assert.equal(attrs[1].parsed.port, 32853);
});

test('parseAttributes throws on a truncated attribute value', () => {
  // Header claims 16 bytes but only 4 follow.
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  writeAttributeHeader(view, 0, 0x0020, 16);
  buf[4] = 0; buf[5] = 0; buf[6] = 0; buf[7] = 0;
  assert.throws(() => parseAttributes(buf, TXN), RangeError);
});

test('parseAttributes handles an empty body', () => {
  const attrs = parseAttributes(new Uint8Array(0), TXN);
  assert.deepEqual(attrs, []);
});

test('serializeAttributes pads each value to a 4-byte boundary', () => {
  const body = serializeAttributes(
    [{ type: 0x8000, parsed: { raw: Uint8Array.of(1, 2, 3) } }],
    TXN,
  );
  // 4 header + 3 value + 1 pad
  assert.equal(body.length, 8);
});

test('XOR-MAPPED-ADDRESS port is XORed with the cookie high half', () => {
  // Spot-check the wire bytes against the RFC formula.
  const value = serializeXorMappedAddress(0x01, '192.0.2.1', 32853, TXN);
  const view = new DataView(value.buffer);
  const xPort = view.getUint16(2, false);
  assert.equal(xPort, 32853 ^ (MAGIC_COOKIE >>> 16));
});

test('XOR-MAPPED-ADDRESS IPv4 address is XORed with the full cookie', () => {
  const value = serializeXorMappedAddress(0x01, '192.0.2.1', 32853, TXN);
  const cookieBytes = new Uint8Array(4);
  new DataView(cookieBytes.buffer).setUint32(0, MAGIC_COOKIE, false);
  const expected = xorBytes(Uint8Array.of(192, 0, 2, 1), cookieBytes);
  assert.deepEqual(Array.from(value.subarray(4)), Array.from(expected));
});
