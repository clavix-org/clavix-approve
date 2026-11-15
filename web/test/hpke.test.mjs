import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { b64u, hex, utf8 } from '../lib/bytes.js';
import { generateKeyPair, open, publicKeyBytes, seal } from '../lib/hpke.js';

const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const vector = JSON.parse(readFileSync(new URL('../../testdata/hpke-rfc9180-a3.json', import.meta.url), 'utf8'));

// A P-256 key pair from the RFC's raw private scalar and public point.
async function keyPair(skHex, pkHex) {
  const pk = unhex(pkHex);
  const jwk = { kty: 'EC', crv: 'P-256', d: b64u(unhex(skHex)), x: b64u(pk.subarray(1, 33)), y: b64u(pk.subarray(33)) };
  const algorithm = { name: 'ECDH', namedCurve: 'P-256' };
  return {
    privateKey: await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['deriveBits']),
    publicKey: await crypto.subtle.importKey('raw', pk, algorithm, true, []),
  };
}

test('seal reproduces RFC 9180 vector A.3.1', async () => {
  const ephemeral = await keyPair(vector.skEm, vector.pkEm);
  const { enc, ct } = await seal(unhex(vector.pkRm), unhex(vector.info), unhex(vector.aad), unhex(vector.pt), ephemeral);
  assert.equal(hex(enc), vector.enc);
  assert.equal(hex(ct), vector.ct);
});

test('open decrypts RFC 9180 vector A.3.1', async () => {
  const recipient = await keyPair(vector.skRm, vector.pkRm);
  const pt = await open(recipient, unhex(vector.info), unhex(vector.aad), unhex(vector.enc), unhex(vector.ct));
  assert.equal(hex(pt), vector.pt);
});

test('a fresh message opens only with the right key, info and aad', async () => {
  const recipient = await generateKeyPair();
  const raw = await publicKeyBytes(recipient.publicKey);
  const [info, aad, pt] = [utf8('info'), utf8('aad'), utf8('attack at dawn')];
  const { enc, ct } = await seal(raw, info, aad, pt);
  assert.deepEqual(await open(recipient, info, aad, enc, ct), pt);

  const again = await seal(raw, info, aad, pt);
  assert.notEqual(hex(again.ct), hex(ct), 'a new ephemeral key each time');

  await assert.rejects(open(await generateKeyPair(), info, aad, enc, ct));
  await assert.rejects(open(recipient, utf8('other'), aad, enc, ct));
  await assert.rejects(open(recipient, info, utf8('other'), enc, ct));
  const tampered = Uint8Array.from(ct);
  tampered[0] ^= 1;
  await assert.rejects(open(recipient, info, aad, enc, tampered));
  await assert.rejects(open(recipient, info, aad, enc.subarray(1), ct));
});
