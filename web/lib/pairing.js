// Pairing, signer side.
//
// The user enters a code shown by the agent: a channel id and a one-time
// secret. The relay only ever sees a token derived from that secret; a
// MAC keyed by another derivation authenticates the keys both sides
// exchange through it. The six digits shown at the end are a last check
// by eye that both ends hold the same keys.

import { b64u, concat, fromUtf8, hex, sha256, unb64u, utf8 } from './bytes.js';
import { pairHeader, peer, sealIntroduction } from './channel.js';
import { sshString } from './ssh.js';

export const PAIR_CODE_PREFIX = 'cva1-';

// "cva1-" + base64url(channel id (16 bytes) || pairing secret (16 bytes)).
export function parsePairingCode(code) {
  const text = String(code).trim();
  if (!text.startsWith(PAIR_CODE_PREFIX)) throw new Error('not a pairing code');
  const raw = unb64u(text.slice(PAIR_CODE_PREFIX.length));
  if (raw.length !== 32) throw new Error('not a pairing code');
  return { ch: hex(raw.subarray(0, 16)), secret: raw.subarray(16) };
}

async function derive(secret, purpose) {
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const params = { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(`clavix-approve/v1/${purpose}`) };
  return new Uint8Array(await crypto.subtle.deriveBits(params, ikm, 256));
}

// What the relay sees of the pairing secret: a token derived from it.
export async function pairToken(secret) {
  return b64u(await derive(secret, 'relay-pair'));
}

async function macKey(secret) {
  return crypto.subtle.importKey('raw', await derive(secret, 'pair-mac'), { name: 'HMAC', hash: 'SHA-256' }, false,
    ['sign', 'verify']);
}

const transcript = (kind, ...fields) => concat(sshString(utf8(kind)), ...fields.map(sshString));

// A channel is in one mode for good, set at pairing: "sign" (the signer
// holds the SSH key) or "approve" (it only approves; PROTOCOL.md, "Approve
// mode"). Each mode has its own labels, so that a relay flipping the mode
// breaks a MAC or the digits.
const LABELS = {
  sign: { hello: 'hello', answer: 'answer', fingerprint: 'clavix-approve/v1/fingerprint', field: 'key' },
  approve: {
    hello: 'approve-hello', answer: 'approve-answer', fingerprint: 'clavix-approve/v1/approve-fingerprint',
    field: 'approve',
  },
};

function labels(mode) {
  if (!Object.hasOwn(LABELS, mode)) throw new Error(`unknown pairing mode ${mode}`);
  return LABELS[mode];
}

// The field of the answer that carries the key, after the mode.
export const answerKeyField = (mode) => labels(mode).field;

// The hello's MAC. `agent` holds the agent's public keys as raw bytes.
export async function helloMac(secret, mode, ch, agent, label) {
  const t = transcript(labels(mode).hello, utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label));
  return new Uint8Array(await crypto.subtle.sign('HMAC', await macKey(secret), t));
}

// The answer's MAC; `blob` is the SSH key (sign mode) or the approval key
// (approve mode), as an SSH public key blob.
export async function answerMac(secret, mode, ch, signer, me, blob, agent) {
  const t = transcript(labels(mode).answer, utf8(ch), utf8(signer), me.kemPublic, me.sigPublic, blob,
    agent.kemPublic, agent.sigPublic);
  return new Uint8Array(await crypto.subtle.sign('HMAC', await macKey(secret), t));
}

// Read the agent's hello and authenticate its keys with the pairing
// secret. Returns { label, agent, mode } where `agent` is a channel peer.
// A hello without `mode` is a sign-mode one, as before approve mode.
export async function readHello(helloMsg, ch, secret) {
  const hello = JSON.parse(fromUtf8(unb64u(helloMsg)));
  if (hello.mode !== undefined && hello.mode !== 'approve') throw new Error('this pairing code is for an unknown mode');
  const mode = hello.mode ?? 'sign';
  const agent = peer(unb64u(hello.kem), unb64u(hello.sig));
  const label = typeof hello.label === 'string' ? hello.label : '';
  const expected = transcript(labels(mode).hello, utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label));
  if (!(await crypto.subtle.verify('HMAC', await macKey(secret), unb64u(hello.mac), expected))) {
    throw new Error('the pairing code does not match this agent');
  }
  return { label, agent, mode };
}

// Our answer: public keys and the key of the mode, sealed to the agent.
export async function buildAnswer({ ch, signer, secret, me, agent, keyBlob, comment, mode = 'sign' }) {
  const mac = await answerMac(secret, mode, ch, signer, me, keyBlob, agent);
  return sealIntroduction(me, agent, pairHeader(ch, signer), {
    t: 'pair',
    [answerKeyField(mode)]: b64u(keyBlob),
    comment,
    kem: b64u(me.kemPublic),
    mac: b64u(mac),
  });
}

// Six digits both ends display once paired, e.g. "042 917".
export async function pairingFingerprint(agent, me, keyBlob, mode = 'sign') {
  const digest = await sha256(transcript(
    labels(mode).fingerprint, agent.kemPublic, agent.sigPublic, me.kemPublic, me.sigPublic, keyBlob));
  const n = ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
  const digits = String(n % 1_000_000).padStart(6, '0');
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}
