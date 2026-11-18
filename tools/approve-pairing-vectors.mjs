// Generates testdata/approve-pairing.json: the hello MAC, the answer MACs
// and the six digits of a pairing in approve mode (PROTOCOL.md, "Pairing
// in approve mode"), from fixed keys, for both approval key types.
//
//   node tools/approve-pairing-vectors.mjs > testdata/approve-pairing.json
//
// Everything here is deterministic. The approval keys are the ones of
// testdata/approve-proof.json. Checked independently (Python standard
// library and OpenSSL) by tools/approve-vectors-check.sh.

import { createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

const b64u = (b) => Buffer.from(b).toString('base64url');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const string = (x) => Buffer.concat([u32(x.length), Buffer.from(x)]);
const transcript = (kind, ...fields) => Buffer.concat([string(Buffer.from(kind, 'utf8')), ...fields.map(string)]);

// HPKE (P-256) public key, uncompressed point, from a fixed scalar.
function p256Public(d) {
  const der = Buffer.concat([
    Buffer.from('3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420', 'hex'), d,
  ]);
  const jwk = createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

// Ed25519 identity public key, raw 32 bytes, from a fixed seed.
function ed25519Public(seed) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }))
    .export({ format: 'der', type: 'spki' }).subarray(-32);
}

const secret = Buffer.alloc(16, 0x33);
const channel = '00112233445566778899aabbccddeeff';
const signer = '0123456789abcdef';
const label = 'workstation';
const agent = { kemPrivate: Buffer.alloc(32, 0x44), sigPrivate: Buffer.alloc(32, 0x55) };
const phone = { kemPrivate: Buffer.alloc(32, 0x66), sigPrivate: Buffer.alloc(32, 0x77) };
for (const side of [agent, phone]) {
  side.kem = p256Public(side.kemPrivate);
  side.sig = ed25519Public(side.sigPrivate);
}

const macKey = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), 'clavix-approve/v1/pair-mac', 32));
const hmac = (data) => createHmac('sha256', macKey).update(data).digest();

const helloT = transcript('approve-hello', Buffer.from(channel), agent.kem, agent.sig, Buffer.from(label, 'utf8'));

const proofs = JSON.parse(readFileSync(new URL('../testdata/approve-proof.json', import.meta.url), 'utf8'));
const answers = proofs.keys.map(({ type, approve }) => {
  const blob = Buffer.from(approve, 'base64url');
  const answerT = transcript('approve-answer', Buffer.from(channel), Buffer.from(signer),
    phone.kem, phone.sig, blob, agent.kem, agent.sig);
  const fpT = transcript('clavix-approve/v1/approve-fingerprint', agent.kem, agent.sig, phone.kem, phone.sig, blob);
  const digest = createHash('sha256').update(fpT).digest();
  const digits = String(digest.readUInt32BE(0) % 1_000_000).padStart(6, '0');
  return {
    type,
    approve,
    answer_transcript: answerT.toString('hex'),
    answer_mac: b64u(hmac(answerT)),
    fingerprint_transcript: fpT.toString('hex'),
    digits: `${digits.slice(0, 3)} ${digits.slice(3)}`,
  };
});

const hex = (b) => b.toString('hex');
console.log(JSON.stringify({
  source: 'tools/approve-pairing-vectors.mjs; see PROTOCOL.md, "Pairing in approve mode"',
  secret: hex(secret),
  code: `cva1-${b64u(Buffer.concat([Buffer.from(channel, 'hex'), secret]))}`,
  channel, signer, label,
  agent: { kem_private: hex(agent.kemPrivate), kem: hex(agent.kem), sig_seed: hex(agent.sigPrivate), sig: hex(agent.sig) },
  signer_keys: { kem_private: hex(phone.kemPrivate), kem: hex(phone.kem), sig_seed: hex(phone.sigPrivate), sig: hex(phone.sig) },
  mac_key: hex(macKey),
  hello_transcript: hex(helloT),
  hello_mac: b64u(hmac(helloT)),
  answers,
}, null, 2));
