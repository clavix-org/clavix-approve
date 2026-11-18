// Generates testdata/approve-proof.json: one approval proof (PROTOCOL.md,
// "Approve mode") per approval key type, from fixed keys.
//
//   node tools/approve-vectors.mjs > testdata/approve-proof.json
//
// Ed25519 signatures are deterministic, so that vector comes out the same
// every time. ECDSA is not: a new run gives another, equally valid, P-256
// signature. Implementations must verify `proof`, not reproduce it.
// Checked independently with OpenSSL by tools/approve-vectors-check.sh.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';

const b64u = (b) => Buffer.from(b).toString('base64url');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const string = (x) => Buffer.concat([u32(x.length), Buffer.from(x)]);
const mpint = (x) => {
  let b = Buffer.from(x);
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return string(b);
};

// The request as the relay lists it: the `msg` text is opaque here.
const channel = '00112233445566778899aabbccddeeff';
const signer = '0123456789abcdef';
const id = 'fedcba9876543210fedcba9876543210';
const msg = 'example-sealed-request-msg_as-listed-by-the-relay';
const req = createHash('sha256').update(Buffer.from(msg, 'ascii')).digest();

const signed = Buffer.concat([
  Buffer.from('clavix-approve/v1 approve', 'ascii'),
  string(channel), string(signer), string(id), string(req),
]);

function ed25519() {
  const seed = Buffer.alloc(32, 0x11);
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8',
  });
  const raw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
  const key = Buffer.concat([string('ssh-ed25519'), string(raw)]);
  const sig = sign(null, signed, priv);
  return { type: 'ssh-ed25519', private: seed.toString('hex'), approve: b64u(key),
    proof: b64u(Buffer.concat([string('ssh-ed25519'), string(sig)])) };
}

function p256() {
  const d = Buffer.alloc(32, 0x22);
  const priv = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: b64u(d),
    ...pointOf(d) }, format: 'jwk' });
  const jwk = createPublicKey(priv).export({ format: 'jwk' });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const key = Buffer.concat([string('ecdsa-sha2-nistp256'), string('nistp256'), string(point)]);
  const rs = sign('sha256', signed, { key: priv, dsaEncoding: 'ieee-p1363' });
  const blob = Buffer.concat([mpint(rs.subarray(0, 32)), mpint(rs.subarray(32))]);
  return { type: 'ecdsa-sha2-nistp256', private: d.toString('hex'), approve: b64u(key),
    proof: b64u(Buffer.concat([string('ecdsa-sha2-nistp256'), string(blob)])) };
}

// Node wants x and y with d in a JWK: derive them through a PKCS#8 import.
function pointOf(d) {
  const der = Buffer.concat([
    Buffer.from('3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420', 'hex'), d,
  ]);
  const jwk = createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).export({ format: 'jwk' });
  return { x: jwk.x, y: jwk.y };
}

console.log(JSON.stringify({
  source: 'tools/approve-vectors.mjs; see PROTOCOL.md, "Approve mode"',
  channel, signer, id,
  msg,
  req: b64u(req),
  signed: signed.toString('hex'),
  keys: [ed25519(), p256()],
}, null, 2));
