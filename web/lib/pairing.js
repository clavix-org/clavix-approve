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

// Read the agent's hello and authenticate its keys with the pairing
// secret. Returns { label, agent } where `agent` is a channel peer.
export async function readHello(helloMsg, ch, secret) {
  const hello = JSON.parse(fromUtf8(unb64u(helloMsg)));
  const agent = peer(unb64u(hello.kem), unb64u(hello.sig));
  const label = typeof hello.label === 'string' ? hello.label : '';
  const expected = transcript('hello', utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label));
  if (!(await crypto.subtle.verify('HMAC', await macKey(secret), unb64u(hello.mac), expected))) {
    throw new Error('the pairing code does not match this agent');
  }
  return { label, agent };
}

// Our answer: public keys and the SSH key, sealed to the agent.
export async function buildAnswer({ ch, signer, secret, me, agent, keyBlob, comment }) {
  const mac = await crypto.subtle.sign('HMAC', await macKey(secret), transcript(
    'answer', utf8(ch), utf8(signer), me.kemPublic, me.sigPublic, keyBlob, agent.kemPublic, agent.sigPublic));
  return sealIntroduction(me, agent, pairHeader(ch, signer), {
    t: 'pair',
    key: b64u(keyBlob),
    comment,
    kem: b64u(me.kemPublic),
    mac: b64u(new Uint8Array(mac)),
  });
}

// Six digits both ends display once paired, e.g. "042 917".
export async function pairingFingerprint(agent, me, keyBlob) {
  const digest = await sha256(transcript(
    'clavix-approve/v1/fingerprint', agent.kemPublic, agent.sigPublic, me.kemPublic, me.sigPublic, keyBlob));
  const n = ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
  const digits = String(n % 1_000_000).padStart(6, '0');
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}
