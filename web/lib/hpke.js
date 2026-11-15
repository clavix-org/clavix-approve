// HPKE (RFC 9180), base mode, single-shot, one fixed suite:
//
//   DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM   (0x0010/0x0001/0x0001)
//
// Written directly on WebCrypto so the page that signs loads no
// third-party code. Checked against the RFC's own vector (A.3.1) and
// against the Rust `hpke` crate used by the agent; see web/test.

import { concat, utf8 } from './bytes.js';

const KEM_SUITE = concat(utf8('KEM'), Uint8Array.of(0x00, 0x10));
const HPKE_SUITE = concat(utf8('HPKE'), Uint8Array.of(0x00, 0x10, 0x00, 0x01, 0x00, 0x01));
const VERSION = utf8('HPKE-v1');
const EMPTY = new Uint8Array(0);
const ZERO_SALT = new Uint8Array(32); // HKDF: an absent salt is HashLen zeros
const P256 = { name: 'ECDH', namedCurve: 'P-256' };
export const ENC_LENGTH = 65; // an uncompressed P-256 point

async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

function labeledExtract(suite, salt, label, ikm) {
  return hmac(salt.length ? salt : ZERO_SALT, concat(VERSION, suite, utf8(label), ikm));
}

// One HMAC block is enough: no output here exceeds 32 bytes.
async function labeledExpand(suite, prk, label, info, length) {
  if (length > 32) throw new Error('unsupported length');
  const labeled = concat(Uint8Array.of(length >> 8, length & 255), VERSION, suite, utf8(label), info);
  return (await hmac(prk, concat(labeled, Uint8Array.of(1)))).subarray(0, length);
}

function importPublic(raw) {
  return crypto.subtle.importKey('raw', raw, P256, true, []);
}

async function sharedSecret(privateKey, publicKey, enc, recipientRaw) {
  const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
  const prk = await labeledExtract(KEM_SUITE, EMPTY, 'eae_prk', dh);
  return labeledExpand(KEM_SUITE, prk, 'shared_secret', concat(enc, recipientRaw), 32);
}

async function aeadKey(secret, info) {
  const context = concat(
    Uint8Array.of(0), // mode_base
    await labeledExtract(HPKE_SUITE, EMPTY, 'psk_id_hash', EMPTY),
    await labeledExtract(HPKE_SUITE, EMPTY, 'info_hash', info));
  const prk = await labeledExtract(HPKE_SUITE, secret, 'secret', EMPTY);
  const key = await labeledExpand(HPKE_SUITE, prk, 'key', context, 16);
  const nonce = await labeledExpand(HPKE_SUITE, prk, 'base_nonce', context, 12);
  return {
    key: await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']),
    // Single-shot: sequence number 0, so the nonce is the base nonce.
    params: (aad) => ({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }),
  };
}

// A recipient key pair. The private key is not extractable unless asked.
export function generateKeyPair(extractable = false) {
  return crypto.subtle.generateKey(P256, extractable, ['deriveBits']);
}

export async function publicKeyBytes(publicKey) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
}

// Encrypt `plaintext` to the raw public key `recipientRaw`.
// Returns { enc, ct }. `ephemeral` exists for the test vectors only.
export async function seal(recipientRaw, info, aad, plaintext, ephemeral = null) {
  const recipient = await importPublic(recipientRaw);
  const eph = ephemeral ?? await crypto.subtle.generateKey(P256, false, ['deriveBits']);
  const enc = await publicKeyBytes(eph.publicKey);
  const { key, params } = await aeadKey(await sharedSecret(eph.privateKey, recipient, enc, recipientRaw), info);
  return { enc, ct: new Uint8Array(await crypto.subtle.encrypt(params(aad), key, plaintext)) };
}

// Decrypt with our key pair ({ privateKey, publicKey }); throws on failure.
export async function open(recipient, info, aad, enc, ct) {
  if (enc.length !== ENC_LENGTH) throw new Error('bad encapsulated key');
  const recipientRaw = await publicKeyBytes(recipient.publicKey);
  const secret = await sharedSecret(recipient.privateKey, await importPublic(enc), enc, recipientRaw);
  const { key, params } = await aeadKey(secret, info);
  return new Uint8Array(await crypto.subtle.decrypt(params(aad), key, ct));
}
