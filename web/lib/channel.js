// The end-to-end channel between the agent and the signer.
//
// Every message is encrypted to the recipient's static key (HPKE, RFC
// 9180) and signed by the sender's (Ed25519). The relay in between sees
// sizes and timing only, and cannot forge, alter or redirect a message:
// what it could tamper with (channel, request id, expiry) is bound to the
// ciphertext through the header.
//
//   msg       = base64url( signature(64) || enc(65) || ciphertext )
//   info      = "clavix-approve/v1 hpke" || sender signing key || recipient HPKE key
//   signature = Ed25519( "clavix-approve/v1 sig" || string(header) || string(enc) || string(ciphertext) )
//
// where string() is the SSH length-prefixed encoding.

import { b64u, concat, fromUtf8, unb64u, utf8 } from './bytes.js';
import * as hpke from './hpke.js';
import { sshString } from './ssh.js';

const LABEL = 'clavix-approve/v1';
const SIG_LENGTH = 64;
export const SIG_KEY_LENGTH = 32;
const ED25519 = { name: 'Ed25519' };

// ---- identities --------------------------------------------------------------

// Our long-term keys. Not extractable unless asked (the command-line
// stand-in keeps them in a file; the page keeps the CryptoKey objects).
export async function generateIdentity(extractable = false) {
  const kem = await hpke.generateKeyPair(extractable);
  const sig = await crypto.subtle.generateKey(ED25519, extractable, ['sign', 'verify']);
  return withPublicBytes(kem, sig);
}

export async function withPublicBytes(kem, sig) {
  return {
    kem,
    sig,
    kemPublic: await hpke.publicKeyBytes(kem.publicKey),
    sigPublic: new Uint8Array(await crypto.subtle.exportKey('raw', sig.publicKey)),
  };
}

// The other side's public keys, as raw bytes.
export function peer(kemPublic, sigPublic) {
  if (kemPublic.length !== hpke.ENC_LENGTH || kemPublic[0] !== 4 || sigPublic.length !== SIG_KEY_LENGTH) {
    throw new Error('invalid peer keys');
  }
  return { kemPublic, sigPublic };
}

// ---- headers -----------------------------------------------------------------

function header(kind, ...fields) {
  return concat(sshString(utf8(LABEL)), sshString(utf8(kind)), ...fields.map((f) => sshString(utf8(f))));
}

function integer(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('not an integer');
  return String(n);
}

export const requestHeader = (ch, signer, id, exp) => header('request', ch, signer, id, integer(exp));
export const responseHeader = (ch, signer, id) => header('response', ch, signer, id);
export const pairHeader = (ch, signer) => header('pair', ch, signer);

// ---- seal / open ---------------------------------------------------------------

const hpkeInfo = (senderSig, recipientKem) => concat(utf8(`${LABEL} hpke`), senderSig, recipientKem);
const signedBytes = (hdr, enc, ct) => concat(utf8(`${LABEL} sig`), sshString(hdr), sshString(enc), sshString(ct));

async function sealBytes(me, to, hdr, obj) {
  const { enc, ct } = await hpke.seal(to.kemPublic, hpkeInfo(me.sigPublic, to.kemPublic), hdr, utf8(JSON.stringify(obj)));
  const sig = new Uint8Array(await crypto.subtle.sign(ED25519, me.sig.privateKey, signedBytes(hdr, enc, ct)));
  return concat(sig, enc, ct);
}

async function openBytes(me, fromSigPublic, hdr, raw) {
  if (raw.length < SIG_LENGTH + hpke.ENC_LENGTH + 16) throw new Error('message too short');
  const sig = raw.subarray(0, SIG_LENGTH);
  const enc = raw.subarray(SIG_LENGTH, SIG_LENGTH + hpke.ENC_LENGTH);
  const ct = raw.subarray(SIG_LENGTH + hpke.ENC_LENGTH);
  const key = await crypto.subtle.importKey('raw', fromSigPublic, ED25519, false, ['verify']);
  if (!(await crypto.subtle.verify(ED25519, key, sig, signedBytes(hdr, enc, ct)))) {
    throw new Error('bad signature');
  }
  const plain = await hpke.open(me.kem, hpkeInfo(fromSigPublic, me.kemPublic), hdr, enc, ct);
  const obj = JSON.parse(fromUtf8(plain));
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('not a message');
  return obj;
}

// Seal `obj` for `to` (a peer), bound to `hdr`.
export async function sealMessage(me, to, hdr, obj) {
  return b64u(await sealBytes(me, to, hdr, obj));
}

// Open a message from the known peer `from`; throws unless it is
// authentic, meant for us and bound to `hdr`.
export async function openMessage(me, from, hdr, msg) {
  return openBytes(me, from.sigPublic, hdr, unb64u(msg));
}

// Pairing only: the sender is not known yet, so its signing key travels
// in front of the message. Whoever opens it must then authenticate that
// key by other means (the pairing secret).
export async function sealIntroduction(me, to, hdr, obj) {
  return b64u(concat(me.sigPublic, await sealBytes(me, to, hdr, obj)));
}
