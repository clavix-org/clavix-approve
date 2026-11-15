// SSH wire format: just enough to read a user-auth request, verify a
// server host key's signature and encode our own ECDSA signature.

import { b64, b64u, concat, fromUtf8, sha256, utf8 } from './bytes.js';

const SSH_MSG_USERAUTH_REQUEST = 50;

export class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  u8() {
    if (this.pos + 1 > this.bytes.length) throw new Error('truncated');
    return this.bytes[this.pos++];
  }

  u32() {
    if (this.pos + 4 > this.bytes.length) throw new Error('truncated');
    const b = this.bytes;
    const n = b[this.pos] * 0x1000000 + (b[this.pos + 1] << 16) + (b[this.pos + 2] << 8) + b[this.pos + 3];
    this.pos += 4;
    return n;
  }

  string() {
    const len = this.u32();
    if (this.pos + len > this.bytes.length) throw new Error('truncated');
    const out = this.bytes.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  text() {
    return fromUtf8(this.string());
  }

  get done() {
    return this.pos === this.bytes.length;
  }
}

export function sshString(bytes) {
  const n = bytes.length;
  return concat(Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255), bytes);
}

// A non-negative big-endian integer as an SSH mpint.
function mpint(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  const v = bytes.subarray(i);
  return sshString(v.length && v[0] & 0x80 ? concat(Uint8Array.of(0), v) : v);
}

// An SSH mpint as exactly `size` big-endian bytes; throws if it does not fit.
function fixedWidth(mp, size) {
  let i = 0;
  while (i < mp.length && mp[i] === 0) i++;
  const v = mp.subarray(i);
  if (v.length > size) throw new Error('integer too large');
  const out = new Uint8Array(size);
  out.set(v, size - v.length);
  return out;
}

function stripZeros(mp) {
  let i = 0;
  while (i < mp.length - 1 && mp[i] === 0) i++;
  return mp.subarray(i);
}

// "SHA256:…" as printed by `ssh-keygen -l`.
export async function fingerprint(keyBlob) {
  return 'SHA256:' + b64(await sha256(keyBlob)).replace(/=+$/, '');
}

// Parse the data an SSH client asks an agent to sign for public-key
// authentication (RFC 4252 §7, plus OpenSSH's host-bound variant).
// Returns null for anything else, including trailing bytes.
export function parseUserAuthRequest(data) {
  try {
    const r = new Reader(data);
    const sessionId = r.string();
    if (r.u8() !== SSH_MSG_USERAUTH_REQUEST) return null;
    const user = r.string();
    const service = r.text();
    const method = r.text();
    if (method !== 'publickey' && method !== 'publickey-hostbound-v00@openssh.com') return null;
    if (r.u8() !== 1) return null;
    const algorithm = r.text();
    const keyBlob = r.string();
    const hostKey = method === 'publickey' ? null : r.string();
    if (!r.done) return null;
    return { sessionId, user, service, algorithm, keyBlob, hostKey };
  } catch (_) {
    return null;
  }
}

const ECDSA = {
  'ecdsa-sha2-nistp256': { curve: 'P-256', hash: 'SHA-256', size: 32, id: 'nistp256' },
  'ecdsa-sha2-nistp384': { curve: 'P-384', hash: 'SHA-384', size: 48, id: 'nistp384' },
  'ecdsa-sha2-nistp521': { curve: 'P-521', hash: 'SHA-512', size: 66, id: 'nistp521' },
};
const RSA_HASH = { 'rsa-sha2-256': 'SHA-256', 'rsa-sha2-512': 'SHA-512' };

// Does `sigBlob` (SSH wire signature) verify as a signature of `data`
// under the public key `keyBlob`? False for anything unsupported or
// malformed: Ed25519, ECDSA P-256/384/521 and RSA with SHA-2 only.
export async function verifySignature(keyBlob, data, sigBlob) {
  try {
    const key = new Reader(keyBlob);
    const keyType = key.text();
    const sig = new Reader(sigBlob);
    const sigType = sig.text();
    const sigBody = sig.string();
    if (!sig.done) return false;

    if (keyType === 'ssh-ed25519') {
      const pub = key.string();
      if (!key.done || sigType !== keyType || pub.length !== 32 || sigBody.length !== 64) return false;
      const k = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, k, sigBody, data);
    }

    if (ECDSA[keyType]) {
      const p = ECDSA[keyType];
      const curveId = key.text();
      const point = key.string();
      if (!key.done || sigType !== keyType || curveId !== p.id) return false;
      const rs = new Reader(sigBody);
      const raw = concat(fixedWidth(rs.string(), p.size), fixedWidth(rs.string(), p.size));
      if (!rs.done) return false;
      const k = await crypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: p.curve }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'ECDSA', hash: p.hash }, k, raw, data);
    }

    if (keyType === 'ssh-rsa') {
      const e = stripZeros(key.string());
      const n = stripZeros(key.string());
      const hash = RSA_HASH[sigType]; // SHA-1 `ssh-rsa` signatures are refused
      if (!key.done || !hash || n.length < 256) return false;
      const k = await crypto.subtle.importKey(
        'jwk', { kty: 'RSA', n: b64u(n), e: b64u(e) },
        { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, k, fixedWidth(sigBody, n.length), data);
    }
    return false;
  } catch (_) {
    return false;
  }
}

// Public key blob of a P-256 key from its JWK coordinates.
export function p256KeyBlob(x, y) {
  if (x.length !== 32 || y.length !== 32) throw new Error('not a P-256 point');
  return concat(
    sshString(utf8('ecdsa-sha2-nistp256')), sshString(utf8('nistp256')),
    sshString(concat(Uint8Array.of(4), x, y)));
}

// WebCrypto's raw ECDSA P-256 signature (r || s) as an SSH signature blob.
export function p256SignatureBlob(raw) {
  if (raw.length !== 64) throw new Error('not a P-256 signature');
  return concat(
    sshString(utf8('ecdsa-sha2-nistp256')),
    sshString(concat(mpint(raw.subarray(0, 32)), mpint(raw.subarray(32)))));
}

// One line for `authorized_keys`.
export function publicKeyLine(keyBlob, comment) {
  const type = new Reader(keyBlob).text();
  return `${type} ${b64(keyBlob)} ${comment}`;
}
