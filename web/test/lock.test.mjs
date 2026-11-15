import assert from 'node:assert/strict';
import { test } from 'node:test';

import { randomBytes, utf8 } from '../lib/bytes.js';
import { createPasskey, createWrappedKey, signWithWrappedKey, unlock } from '../lib/lock.js';
import { verifySignature } from '../lib/ssh.js';

// A stand-in for navigator.credentials: one passkey with a PRF secret.
function fakeAuthenticator({ prfAtCreation = false, prf = true } = {}) {
  const secret = randomBytes(32);
  const id = randomBytes(16);
  const calls = [];
  const results = { results: { first: secret.buffer.slice(0) } };
  return {
    secret,
    id,
    calls,
    create: async (options) => {
      calls.push(options.publicKey);
      const ext = !prf ? {} : { prf: prfAtCreation ? { enabled: true, ...results } : { enabled: true } };
      return { rawId: id.buffer.slice(0), getClientExtensionResults: () => ext };
    },
    get: async (options) => {
      calls.push(options.publicKey);
      return { getClientExtensionResults: () => (prf ? { prf: results } : {}) };
    },
  };
}

test('the passkey is created without assuming a kind of authenticator', async () => {
  const authenticator = fakeAuthenticator();
  const created = await createPasskey(authenticator, 'approve.example');
  assert.deepEqual(created.credentialId, authenticator.id);
  assert.equal(created.secret, null);

  const [options] = authenticator.calls;
  assert.equal(options.rp.id, 'approve.example');
  assert.equal(options.authenticatorSelection.userVerification, 'required');
  assert.equal('authenticatorAttachment' in options.authenticatorSelection, false);
  assert.ok(options.extensions.prf);

  // Some authenticators hand the secret over at creation already.
  const eager = fakeAuthenticator({ prfAtCreation: true });
  assert.deepEqual((await createPasskey(eager, 'approve.example')).secret, eager.secret);
  // One that cannot do PRF is refused at once, not at the first signature.
  await assert.rejects(createPasskey(fakeAuthenticator({ prf: false }), 'approve.example'), /PRF/);
});

test('unlock asks for user verification and returns the secret', async () => {
  const authenticator = fakeAuthenticator();
  const secret = await unlock(authenticator, 'approve.example', authenticator.id);
  assert.deepEqual(secret, authenticator.secret);
  const [options] = authenticator.calls;
  assert.equal(options.userVerification, 'required');
  assert.equal(options.rpId, 'approve.example');
  assert.deepEqual(options.allowCredentials[0].id, authenticator.id);
  await assert.rejects(unlock(fakeAuthenticator({ prf: false }), 'approve.example', authenticator.id), /secret/);
});

test('the wrapped key signs only with the secret that wrapped it', async () => {
  const secret = randomBytes(32);
  const wrapped = await createWrappedKey(secret);
  const data = utf8('user-auth request');
  const signature = await signWithWrappedKey(secret, wrapped, data);
  assert.equal(await verifySignature(wrapped.keyBlob, data, signature), true);

  await assert.rejects(signWithWrappedKey(randomBytes(32), wrapped, data), /does not open/);
  // The stored public key cannot be swapped: it is bound to the ciphertext.
  const other = await createWrappedKey(secret);
  await assert.rejects(signWithWrappedKey(secret, { ...wrapped, keyBlob: other.keyBlob }, data), /does not open/);
  const tampered = Uint8Array.from(wrapped.ct);
  tampered[5] ^= 1;
  await assert.rejects(signWithWrappedKey(secret, { ...wrapped, ct: tampered }, data), /does not open/);
});
