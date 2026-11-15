import assert from 'node:assert/strict';
import { test } from 'node:test';

import { concat, utf8 } from '../lib/bytes.js';
import {
  fingerprint, p256SignatureBlob, parseUserAuthRequest, publicKeyLine, Reader, sshString, verifySignature,
} from '../lib/ssh.js';
import { clientKey, hostKey, userAuth } from './helpers.mjs';

test('Reader reads what sshString writes and refuses truncated input', () => {
  const r = new Reader(concat(sshString(utf8('first')), sshString(new Uint8Array(0)), Uint8Array.of(0, 0, 1, 2, 9)));
  assert.equal(r.text(), 'first');
  assert.equal(r.string().length, 0);
  assert.equal(r.u32(), 258);
  assert.equal(r.done, false);
  assert.equal(r.u8(), 9);
  assert.equal(r.done, true);
  assert.throws(() => new Reader(Uint8Array.of(0, 0, 0, 10, 1, 2)).string());
  assert.throws(() => new Reader(Uint8Array.of(0xff, 0xff, 0xff, 0xff)).string());
  assert.throws(() => new Reader(Uint8Array.of(0, 0, 1)).u32());
});

test('parseUserAuthRequest accepts only public-key requests', () => {
  const sessionId = utf8('session');
  const keyBlob = utf8('key');
  const plain = parseUserAuthRequest(userAuth({ sessionId, keyBlob }));
  assert.deepEqual([...plain.sessionId], [...sessionId]);
  assert.deepEqual([...plain.user], [...utf8('deploy')]);
  assert.equal(plain.service, 'ssh-connection');
  assert.equal(plain.algorithm, 'ecdsa-sha2-nistp256');
  assert.deepEqual([...plain.keyBlob], [...keyBlob]);
  assert.equal(plain.hostKey, null);

  const bound = parseUserAuthRequest(userAuth({ sessionId, keyBlob, hostKey: utf8('hk') }));
  assert.deepEqual([...bound.hostKey], [...utf8('hk')]);

  assert.equal(parseUserAuthRequest(concat(userAuth({ sessionId, keyBlob }), Uint8Array.of(0))), null);
  assert.equal(parseUserAuthRequest(utf8('SSHSIG')), null);
  assert.equal(parseUserAuthRequest(new Uint8Array(0)), null);
  // A key query (no signature will follow) and another auth method.
  const query = userAuth({ sessionId, keyBlob, hasSignature: false });
  assert.equal(parseUserAuthRequest(query), null);
  assert.equal(parseUserAuthRequest(userAuth({ sessionId, keyBlob, method: 'password' })), null);
});

for (const type of ['ed25519', 'P-256', 'P-384', 'P-521', 'rsa']) {
  test(`verifySignature checks a ${type} host key`, async () => {
    const host = await hostKey(type);
    const other = await hostKey(type);
    const data = utf8('exchange hash');
    const sig = await host.sign(data);
    assert.equal(await verifySignature(host.blob, data, sig), true);
    assert.equal(await verifySignature(host.blob, utf8('another hash'), sig), false);
    assert.equal(await verifySignature(other.blob, data, sig), false);
    assert.equal(await verifySignature(host.blob, data, await other.sign(data)), false);
    const tampered = Uint8Array.from(sig);
    tampered[tampered.length - 1] ^= 1;
    assert.equal(await verifySignature(host.blob, data, tampered), false);
    assert.equal(await verifySignature(host.blob, data, concat(sig, Uint8Array.of(0))), false);
    assert.equal(await verifySignature(host.blob.subarray(0, 20), data, sig), false);
  });
}

test('verifySignature refuses SHA-1 RSA signatures and mismatched types', async () => {
  const rsa = await hostKey('rsa');
  const data = utf8('exchange hash');
  assert.equal(await verifySignature(rsa.blob, data, await rsa.sign(data, 'rsa-sha2-512')), true);
  // Same signature bytes, announced as the legacy SHA-1 algorithm.
  assert.equal(await verifySignature(rsa.blob, data, await rsa.sign(data, 'ssh-rsa')), false);
  const ed = await hostKey('ed25519');
  const p256 = await hostKey('P-256');
  assert.equal(await verifySignature(ed.blob, data, await p256.sign(data)), false);
  assert.equal(await verifySignature(utf8('junk'), data, await ed.sign(data)), false);
});

test('our own signatures are valid SSH signatures, whatever the leading bytes', async () => {
  const key = await clientKey();
  const data = utf8('user-auth request');
  // Enough rounds to meet r or s values with a high bit or a leading zero.
  for (let i = 0; i < 300; i++) {
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, data));
    assert.equal(await verifySignature(key.blob, data, p256SignatureBlob(raw)), true);
  }
  assert.throws(() => p256SignatureBlob(new Uint8Array(63)));
});

test('fingerprint and public key line follow OpenSSH conventions', async () => {
  // Value printed by `ssh-keygen -lf` for this key.
  const b64 = 'AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti';
  const blob = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  assert.equal(await fingerprint(blob), 'SHA256:UCUiLr7Pjs9wFFJMDByLgc3NrtdU344OgUM45wZPcIQ');
  assert.equal(publicKeyLine(blob, 'phone'), `ssh-ed25519 ${b64} phone`);
});
