// Pairing, protocol version 2 (PROTOCOL.md, "Pairing").
//
// The user enters a code shown by the agent: a channel id and a one-time
// secret. The relay only ever sees a token derived from that secret; a
// MAC keyed by another derivation authenticates the keys both sides
// exchange through it. The six digits shown at the end are a short
// authentication string: the agent's hello commits to a nonce, the device
// answers with its keys and a nonce of its own, then the agent reveals
// its nonce. Neither side can pick its keys after seeing the other's, so
// a relay that learnt the secret still has one chance in a million.

import { b64u, concat, equal, fromUtf8, hex, sha256, unb64u, utf8 } from './bytes.js';
import { pairHeader, peer, sealIntroduction } from './channel.js';
import { sshString } from './ssh.js';

export const PAIR_CODE_PREFIX = 'cva2-';
export const PAIRING_VERSION = 2;
export const NONCE_LENGTH = 32;
const OLD_CODE_PREFIX = 'cva1-';

const LABELS = {
  hello: 'clavix-approve/v2/pair-hello',
  answer: 'clavix-approve/v2/pair-answer',
  commit: 'clavix-approve/v2/pair-commit',
  digits: 'clavix-approve/v2/pair-digits',
};

// "cva2-" + base64url(channel id (16 bytes) || pairing secret (16 bytes)).
export function parsePairingCode(code) {
  const text = String(code).trim();
  if (text.startsWith(OLD_CODE_PREFIX)) {
    throw new Error('this pairing code is from an older version: update clavix-agent or Clavix, then pair again');
  }
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

const MODES = ['sign', 'approve'];

function checkMode(mode) {
  if (!MODES.includes(mode)) throw new Error(`unknown pairing mode ${mode}`);
  return mode;
}

// The field of the answer that carries the key, after the mode: the SSH
// key in sign mode, the approval key in approve mode.
export const answerKeyField = (mode) => (checkMode(mode) === 'sign' ? 'key' : 'approve');

// The commitment to the agent's nonce, carried by the hello.
export async function commitment(nonce) {
  return sha256(transcript(LABELS.commit, nonce));
}

// The hello's MAC. `agent` holds the agent's public keys as raw bytes.
export async function helloMac(secret, mode, ch, agent, label, commit) {
  const t = transcript(LABELS.hello, utf8(checkMode(mode)), utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label),
    commit);
  return new Uint8Array(await crypto.subtle.sign('HMAC', await macKey(secret), t));
}

// The answer's MAC; `blob` is the SSH key (sign mode) or the approval key
// (approve mode), as an SSH public key blob.
export async function answerMac(secret, mode, ch, signer, me, blob, nonce, agent, commit) {
  const t = transcript(LABELS.answer, utf8(checkMode(mode)), utf8(ch), utf8(signer), me.kemPublic, me.sigPublic,
    blob, nonce, agent.kemPublic, agent.sigPublic, commit);
  return new Uint8Array(await crypto.subtle.sign('HMAC', await macKey(secret), t));
}

// Read the agent's hello and authenticate it with the pairing secret.
// Returns { label, agent, mode, commit } where `agent` is a channel peer.
// A hello of the first protocol version is refused with a clear message.
export async function readHello(helloMsg, ch, secret) {
  const hello = JSON.parse(fromUtf8(unb64u(helloMsg)));
  if (hello.v !== PAIRING_VERSION) {
    throw new Error('this machine uses an older pairing protocol: update clavix-agent or Clavix, then pair again');
  }
  if (!MODES.includes(hello.mode)) throw new Error('this pairing code is for an unknown mode');
  const { mode } = hello;
  const agent = peer(unb64u(hello.kem), unb64u(hello.sig));
  const label = typeof hello.label === 'string' ? hello.label : '';
  const commit = unb64u(hello.commit);
  if (commit.length !== 32) throw new Error('malformed hello');
  const expected = transcript(LABELS.hello, utf8(mode), utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label),
    commit);
  if (!(await crypto.subtle.verify('HMAC', await macKey(secret), unb64u(hello.mac), expected))) {
    throw new Error('the pairing code does not match this agent');
  }
  return { label, agent, mode, commit };
}

// Our answer: public keys, our nonce and the key of the mode, sealed to
// the agent.
export async function buildAnswer({ ch, signer, secret, me, agent, keyBlob, comment, mode, nonce, commit }) {
  const mac = await answerMac(secret, mode, ch, signer, me, keyBlob, nonce, agent, commit);
  return sealIntroduction(me, agent, pairHeader(ch, signer), {
    t: 'pair',
    v: PAIRING_VERSION,
    [answerKeyField(mode)]: b64u(keyBlob),
    comment,
    kem: b64u(me.kemPublic),
    nonce: b64u(nonce),
    mac: b64u(mac),
  });
}

// Check the nonce the agent revealed against the hello's commitment.
export async function checkReveal(nonce, commit) {
  if (nonce.length !== NONCE_LENGTH || !equal(await commitment(nonce), commit)) {
    throw new Error('the machine revealed a value that does not match its pairing code: someone is in between');
  }
}

// The six digits both ends display, e.g. "042 917". `agent` and `device`
// hold public keys as raw bytes.
export async function pairingDigits({ mode, ch, signer, agent, device, keyBlob, agentNonce, signerNonce }) {
  const digest = await sha256(transcript(LABELS.digits, utf8(checkMode(mode)), utf8(ch), utf8(signer),
    agent.kemPublic, agent.sigPublic, device.kemPublic, device.sigPublic, keyBlob, agentNonce, signerNonce));
  const n = ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
  const digits = String(n % 1_000_000).padStart(6, '0');
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}
