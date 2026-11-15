// Test doubles: server host keys of every supported type, and the bytes
// an SSH client would ask an agent to sign.

import { concat, utf8, b64u, unb64u } from '../lib/bytes.js';
import { sshString, p256KeyBlob } from '../lib/ssh.js';

function mpint(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  const v = bytes.subarray(i);
  return sshString(v.length && v[0] & 0x80 ? concat(Uint8Array.of(0), v) : v);
}

const ECDSA = {
  'P-256': { name: 'ecdsa-sha2-nistp256', id: 'nistp256', hash: 'SHA-256', size: 32 },
  'P-384': { name: 'ecdsa-sha2-nistp384', id: 'nistp384', hash: 'SHA-384', size: 48 },
  'P-521': { name: 'ecdsa-sha2-nistp521', id: 'nistp521', hash: 'SHA-512', size: 66 },
};

// A host key: { blob, sign(data) -> SSH signature blob }.
export async function hostKey(type = 'ed25519') {
  if (type === 'ed25519') {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    return {
      blob: concat(sshString(utf8('ssh-ed25519')), sshString(pub)),
      sign: async (data) => concat(
        sshString(utf8('ssh-ed25519')),
        sshString(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, data)))),
    };
  }
  if (ECDSA[type]) {
    const p = ECDSA[type];
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: type }, true, ['sign', 'verify']);
    const point = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    return {
      blob: concat(sshString(utf8(p.name)), sshString(utf8(p.id)), sshString(point)),
      sign: async (data) => {
        const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: p.hash }, pair.privateKey, data));
        return concat(sshString(utf8(p.name)),
          sshString(concat(mpint(raw.subarray(0, p.size)), mpint(raw.subarray(p.size)))));
      },
    };
  }
  if (type === 'rsa') {
    const params = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-512' };
    const pair = await crypto.subtle.generateKey(params, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    return {
      blob: concat(sshString(utf8('ssh-rsa')), mpint(unb64u(jwk.e)), mpint(unb64u(jwk.n))),
      sign: async (data, sigType = 'rsa-sha2-512') => concat(
        sshString(utf8(sigType)),
        sshString(new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, pair.privateKey, data)))),
    };
  }
  throw new Error(`unknown host key type ${type}`);
}

// The signer's own key: { blob, privateKey }.
export async function clientKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { blob: p256KeyBlob(unb64u(jwk.x), unb64u(jwk.y)), privateKey: pair.privateKey };
}

// The data to sign for a public-key login (RFC 4252 §7).
export function userAuth({ sessionId, keyBlob, hostKey: host = null, user = 'deploy', service = 'ssh-connection',
  algorithm = 'ecdsa-sha2-nistp256', method = null, hasSignature = true }) {
  const name = method ?? (host ? 'publickey-hostbound-v00@openssh.com' : 'publickey');
  return concat(
    sshString(sessionId), Uint8Array.of(50), sshString(utf8(user)), sshString(utf8(service)),
    sshString(utf8(name)), Uint8Array.of(hasSignature ? 1 : 0),
    sshString(utf8(algorithm)), sshString(keyBlob), host ? sshString(host) : new Uint8Array(0));
}

// One session binding as the agent forwards it.
export async function bind(host, sessionId, forwarded = false) {
  return { hostkey: b64u(host.blob), sid: b64u(sessionId), sig: b64u(await host.sign(sessionId)), fwd: forwarded };
}
