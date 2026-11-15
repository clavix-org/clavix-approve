// Content of the messages between the agent and the signer (they travel
// sealed, see channel.js), and the checks the signer makes before
// anything is shown or signed. See PROTOCOL.md.
//
// The machine that runs the agent may be compromised: nothing it says
// about the destination is believed. Everything displayed comes out of
// checkSignRequest(), which re-derives it from the bytes to sign and from
// the server's own signature.

import { b64u, equal, fromUtf8, hex, sha256, unb64u, utf8 } from './bytes.js';
import { fingerprint, parseUserAuthRequest, verifySignature } from './ssh.js';

export const KEY_ALGORITHM = 'ecdsa-sha2-nistp256';
const MAX_HOPS = 16;

// The relay stores only the SHA-256 of a bearer token.
export async function tokenAuth(token) {
  return hex(await sha256(utf8(token)));
}

// ---- display hygiene ----------------------------------------------------------

// Text from the other side, made safe to show: one line, printable, bounded.
export function label(value, max = 64) {
  if (typeof value !== 'string') return null;
  const cleaned = Array.from(value).filter((c) => !/[\p{C}\p{Zl}\p{Zp}]/u.test(c)).slice(0, max).join('').trim();
  return cleaned || null;
}

function bytesLabel(bytes, max) {
  try {
    return label(fromUtf8(bytes), max);
  } catch (_) {
    return null;
  }
}

// ---- the sign request -----------------------------------------------------------

// Check a decoded sign request. `id` is the request id the relay gave,
// `keyBlob` our own SSH public key, `now` the current time in seconds.
//
// Returns { ok: false, reason } or { ok: true, data, user, hops, … } where
// `hops` is the verified chain, outermost first, the last one being the
// host to authenticate to. A hop carries the host key and its fingerprint,
// never a name: naming is done by the caller from its own pinned list.
export async function checkSignRequest(inner, { id, keyBlob, now }) {
  const refuse = (reason) => ({ ok: false, reason });
  if (!inner || inner.t !== 'sign' || inner.id !== id) return refuse('malformed');
  if (typeof inner.exp !== 'number' || !(inner.exp > now)) return refuse('expired');

  let key, data, binds;
  try {
    key = unb64u(inner.key);
    data = unb64u(inner.data);
    if (!Array.isArray(inner.binds) || inner.binds.length < 1 || inner.binds.length > MAX_HOPS) {
      return refuse('unverified');
    }
    binds = inner.binds.map((b) => {
      if (typeof b.fwd !== 'boolean') throw new Error('malformed bind');
      return { hostKey: unb64u(b.hostkey), sessionId: unb64u(b.sid), signature: unb64u(b.sig), forwarded: b.fwd };
    });
  } catch (_) {
    return refuse('malformed');
  }
  if (!equal(key, keyBlob)) return refuse('unknown-key');

  // 1. The bytes to sign are a public-key login made with our key.
  const request = parseUserAuthRequest(data);
  if (!request || request.service !== 'ssh-connection' || request.algorithm !== KEY_ALGORITHM
      || !equal(request.keyBlob, keyBlob)) {
    return refuse('unverified');
  }

  // 2. Every hop is a session its host key really signed. Only the last
  //    one is for authentication; the ones before carry a forwarded agent.
  const hops = [];
  for (const [i, b] of binds.entries()) {
    const last = i === binds.length - 1;
    if (b.forwarded === last) return refuse('unverified');
    if (!(await verifySignature(b.hostKey, b.sessionId, b.signature))) return refuse('unverified');
    hops.push({ hostKey: b.hostKey, fingerprint: await fingerprint(b.hostKey), forwarded: b.forwarded });
  }

  // 3. The login is for that last session — and, when the client says
  //    which host it believes it talks to, for that very host key.
  const dest = binds[binds.length - 1];
  if (!equal(request.sessionId, dest.sessionId)) return refuse('unverified');
  if (request.hostKey && !equal(request.hostKey, dest.hostKey)) return refuse('unverified');

  // Unverified, for display only.
  const caller = inner.caller && typeof inner.caller === 'object'
    ? { pid: Number.isInteger(inner.caller.pid) ? inner.caller.pid : null, name: label(inner.caller.name, 32) }
    : null;
  const hints = {};
  if (inner.hints && typeof inner.hints === 'object') {
    for (const hop of hops) {
      const name = label(inner.hints[hop.fingerprint]);
      if (name) hints[hop.fingerprint] = name;
    }
  }

  return {
    ok: true,
    data,
    exp: inner.exp,
    user: bytesLabel(request.user, 64),
    hops,
    caller,
    agent: label(inner.agent),
    hints,
  };
}

// ---- the response -----------------------------------------------------------------

// `requestMsg` is the request exactly as received from the relay: the
// response names its hash, so it cannot be replayed against another one.
// `signatureBlob` is a complete SSH signature, which names its algorithm.
async function response(requestMsg, id, fields) {
  return { id, req: b64u(await sha256(utf8(requestMsg))), ...fields };
}

export function signedResponse(requestMsg, id, signatureBlob) {
  return response(requestMsg, id, { t: 'signed', sig: b64u(signatureBlob) });
}

export function deniedResponse(requestMsg, id, reason) {
  return response(requestMsg, id, { t: 'denied', reason });
}
