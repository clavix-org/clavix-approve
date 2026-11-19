// The requester's side of approve mode: what Clavix desktop will do,
// written here as the reference the page is tested against (the
// command-line stand-in tools/fake-desktop.mjs runs it). The page itself
// never loads this module.
//
// The requester holds the SSH key. It pairs like an agent, with a hello
// that says `mode: "approve"`, sends approval requests, and signs only
// after a proof from the device's approval key. PROTOCOL.md, "Approve mode".

import { b64u, equal, hex, randomBytes, sha256, unb64u, utf8 } from './bytes.js';
import { openIntroduction, openMessage, pairHeader, peer, requestHeader, responseHeader, sealMessage } from './channel.js';
import {
  answerKeyField, answerMac, commitment, helloMac, NONCE_LENGTH, PAIR_CODE_PREFIX, PAIRING_VERSION, pairingDigits,
  pairToken,
} from './pairing.js';
import { APPROVE_KEY_TYPES, approvalBytes, tokenAuth, verifyApproval } from './protocol.js';
import { RelayClient } from './relay.js';
import { keyType } from './ssh.js';

// A new pairing offer: channel id, pairing secret, our bearer token, and
// the nonce the hello commits to (revealed once the device has answered).
export function newOffer() {
  const ch = randomBytes(16);
  const secret = randomBytes(16);
  return {
    ch: hex(ch), secret, token: b64u(randomBytes(32)), nonce: randomBytes(NONCE_LENGTH),
    code: `${PAIR_CODE_PREFIX}${b64u(new Uint8Array([...ch, ...secret]))}`,
  };
}

// The hello, as the relay stores it: b64u(JSON).
export async function buildHello({ ch, secret, me, label, nonce, mode = 'approve' }) {
  const commit = await commitment(nonce);
  const mac = await helloMac(secret, mode, ch, me, label, commit);
  const hello = {
    v: PAIRING_VERSION, mode, label, kem: b64u(me.kemPublic), sig: b64u(me.sigPublic), commit: b64u(commit),
    mac: b64u(mac),
  };
  return b64u(utf8(JSON.stringify(hello)));
}

// Body of POST /api/channels.
export async function channelBody(offer, hello) {
  return {
    ch: offer.ch,
    agent_auth: await tokenAuth(offer.token),
    pair_auth: await tokenAuth(await pairToken(offer.secret)),
    hello,
  };
}

// Read the device's answer ({ signer, msg } from the relay) and
// authenticate it with the pairing secret. Returns { signer, device,
// blob, comment, fingerprint }; throws on anything else. In approve mode
// the answer must carry an approval key of an accepted type. Once it has
// returned, and only then, reveal `nonce` to the device
// (RequesterRelay.reveal).
export async function readAnswer({ ch, secret, me, answer, nonce, mode = 'approve' }) {
  const { signer, msg } = answer;
  if (typeof signer !== 'string' || !/^[0-9a-f]{16}$/.test(signer)) throw new Error('bad signer id');
  const { sigPublic, obj } = await openIntroduction(me, pairHeader(ch, signer), msg);
  if (obj.t !== 'pair') throw new Error('not a pairing answer');
  if (obj.v !== PAIRING_VERSION) {
    throw new Error('the device uses an older pairing protocol: update the Clavix Approve app, then pair again');
  }
  const field = answerKeyField(mode);
  if (typeof obj[field] !== 'string') throw new Error(`the answer carries no ${field} key: not a ${mode}-mode device`);
  const blob = unb64u(obj[field]);
  const signerNonce = typeof obj.nonce === 'string' ? unb64u(obj.nonce) : new Uint8Array(0);
  if (signerNonce.length !== NONCE_LENGTH) throw new Error('the answer carries no valid nonce');
  const device = peer(unb64u(obj.kem), sigPublic);
  const expected = await answerMac(secret, mode, ch, signer, device, blob, signerNonce, me, await commitment(nonce));
  if (!equal(expected, unb64u(obj.mac))) throw new Error('the answer is not from the device that got the code');
  const accepted = mode === 'approve' ? APPROVE_KEY_TYPES : ['ecdsa-sha2-nistp256'];
  if (!accepted.includes(keyType(blob))) throw new Error(`key type ${keyType(blob)} not accepted`);
  return {
    signer,
    device,
    blob,
    comment: typeof obj.comment === 'string' ? obj.comment : '',
    fingerprint: await pairingDigits({
      mode, ch, signer, agent: me, device, keyBlob: blob, agentNonce: nonce, signerNonce,
    }),
  };
}

// The relay calls the requester makes, with its own token.
export class RequesterRelay extends RelayClient {
  static async createChannel(base, enrollSecret, body, fetchFn = (...a) => fetch(...a)) {
    const res = await fetchFn(`${base.replace(/\/+$/, '')}/api/channels`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${enrollSecret}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`relay answered HTTP ${res.status}`);
    return (await res.json()).state;
  }

  pairAnswer(wait = 20) {
    return this.call('GET', `pair/answer?wait=${wait}`);
  }

  // Hand the device our nonce, once its answer has been read (readAnswer).
  async reveal(signer, nonce) {
    return (await this.call('POST', 'pair/reveal', { signer, nonce: b64u(nonce) })).state;
  }

  postRequest(envelope) {
    return this.call('POST', 'requests', envelope);
  }

  response(id, wait = 20) {
    return this.call('GET', `responses/${id}?wait=${wait}`);
  }

  cancel(id) {
    return this.call('POST', `requests/${id}/cancel`, {});
  }
}

// Seal an approval request for `device` ({ signer, device }). `fields` is
// the content after `t` and the ids: key, keyName, data, flags, binds,
// caller, agent, hints. Returns the relay envelope { id, to, exp, msg }.
export async function approvalRequest({ ch, me, device, ttl = 90, fields, t = 'approve' }) {
  const id = hex(randomBytes(16));
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttl;
  const msg = await sealMessage(me, device.device, requestHeader(ch, device.signer, id, exp), {
    t, id, iat, exp, ...fields,
  });
  return { id, to: device.signer, exp, msg };
}

// Read the answer to `envelope`. Returns { ok: true } for an approval
// whose proof verifies under the device's approval key, { ok: false,
// denied: reason } for a refusal, and throws for anything not authentic or
// not about this request.
export async function readApproval({ ch, me, device, envelope, msg }) {
  const obj = await openMessage(me, device.device, responseHeader(ch, device.signer, envelope.id), msg);
  if (obj.id !== envelope.id) throw new Error('an answer to another request');
  if (obj.req !== b64u(await sha256(utf8(envelope.msg)))) throw new Error('an answer to another version of the request');
  if (obj.t === 'denied') return { ok: false, denied: typeof obj.reason === 'string' ? obj.reason : 'unknown' };
  if (obj.t !== 'approved' || typeof obj.proof !== 'string') throw new Error('not an approval');
  const bytes = await approvalBytes(ch, device.signer, envelope.id, envelope.msg);
  if (!(await verifyApproval(device.blob, bytes, unb64u(obj.proof)))) throw new Error('the proof does not verify');
  return { ok: true };
}
