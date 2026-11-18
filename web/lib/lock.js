// The SSH signing key and its lock.
//
// The key is an ordinary ECDSA P-256 key, stored encrypted under a secret
// that only a passkey can produce (WebAuthn PRF extension). Every use
// therefore needs the passkey's own user verification — biometrics, or a
// PIN and a touch on a security key. Nothing here assumes which kind of
// authenticator holds the passkey.
//
// Weaker than a hardware-held key: the private key exists in this page's
// memory for the duration of one signature.

import { randomBytes, unb64u, utf8 } from './bytes.js';
import { ed25519KeyBlob, ed25519SignatureBlob, p256KeyBlob, p256SignatureBlob } from './ssh.js';

const PRF_SALT = utf8('clavix-approve/v1/ssh-key');
const WRAP_INFO = utf8('clavix-approve/v1/key-wrap');
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const ED25519 = { name: 'Ed25519' };

// ---- passkey ---------------------------------------------------------------

// Create the passkey. Returns { credentialId, secret } where `secret` is
// the PRF output when the authenticator already gave it at creation, else
// null (ask for it with unlock()).
export async function createPasskey(credentials, rpId) {
  const cred = await credentials.create({
    publicKey: {
      rp: { name: 'Clavix Approve', id: rpId },
      user: { id: randomBytes(16), name: 'clavix-approve', displayName: 'Clavix Approve' },
      challenge: randomBytes(32),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      // No authenticatorAttachment: a platform passkey and a security key
      // are both welcome, as long as they verify the user.
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const prf = cred.getClientExtensionResults().prf;
  if (!prf || (prf.enabled !== true && !prf.results)) {
    throw new Error('this passkey cannot protect a key (no PRF support)');
  }
  const first = prf.results?.first;
  return { credentialId: new Uint8Array(cred.rawId), secret: first ? new Uint8Array(first) : null };
}

// Ask the passkey for its secret. This is the user-verification step; it
// must be called from a user gesture.
export async function unlock(credentials, rpId, credentialId) {
  const assertion = await credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId,
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const first = assertion.getClientExtensionResults().prf?.results?.first;
  if (!first) throw new Error('the passkey did not return its secret');
  return new Uint8Array(first);
}

// ---- wrapped key --------------------------------------------------------------

async function wrappingKey(secret, info = WRAP_INFO) {
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function wrap(secret, info, keyBlob, pkcs8) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: keyBlob }, await wrappingKey(secret, info), pkcs8));
  pkcs8.fill(0);
  return { keyBlob, iv, ct };
}

async function unwrap(secret, info, { keyBlob, iv, ct }, what) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: keyBlob }, await wrappingKey(secret, info), ct));
  } catch (_) {
    throw new Error(`this passkey does not open the ${what}`);
  }
}

// ---- approval key (approve mode) ----------------------------------------------

// Approve mode signs approvals with a key of its own, Ed25519, wrapped like
// the SSH key under the same passkey secret (one user verification opens
// either) but with its own label. PROTOCOL.md, "Approval key".
const APPROVE_WRAP_INFO = utf8('clavix-approve/v1/approve-key-wrap');

// Generate the approval key and return it wrapped under `secret`:
// { keyBlob, iv, ct }, `keyBlob` being its SSH public key blob.
export async function createWrappedApproveKey(secret) {
  const pair = await crypto.subtle.generateKey(ED25519, true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return wrap(secret, APPROVE_WRAP_INFO, ed25519KeyBlob(raw), pkcs8);
}

// Unwrap the approval key with `secret`, sign `data`, forget the key.
// Returns an SSH signature blob.
export async function approveWithWrappedKey(secret, wrapped, data) {
  const pkcs8 = await unwrap(secret, APPROVE_WRAP_INFO, wrapped, 'approval key');
  try {
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, ED25519, false, ['sign']);
    return ed25519SignatureBlob(new Uint8Array(await crypto.subtle.sign(ED25519, key, data)));
  } finally {
    pkcs8.fill(0);
  }
}

// Generate the SSH key and return it wrapped under `secret`:
// { keyBlob, iv, ct }. The public key blob is authenticated with the
// ciphertext, so a stored key cannot be swapped for another one.
export async function createWrappedKey(secret) {
  const pair = await crypto.subtle.generateKey(ECDSA, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const keyBlob = p256KeyBlob(unb64u(jwk.x), unb64u(jwk.y));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: keyBlob }, await wrappingKey(secret), pkcs8));
  pkcs8.fill(0);
  return { keyBlob, iv, ct };
}

// Unwrap the key with `secret`, sign `data`, forget the key. Returns an
// SSH signature blob. Throws if the secret is not the one that wrapped it.
export async function signWithWrappedKey(secret, { keyBlob, iv, ct }, data) {
  let pkcs8;
  try {
    pkcs8 = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: keyBlob }, await wrappingKey(secret), ct));
  } catch (_) {
    throw new Error('this passkey does not open the signing key');
  }
  try {
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, ECDSA, false, ['sign']);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data));
    return p256SignatureBlob(raw);
  } finally {
    pkcs8.fill(0);
  }
}
