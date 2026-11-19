// Content of the messages between the agent and the signer (they travel
// sealed, see channel.js), and the checks the signer makes before
// anything is shown or signed. See PROTOCOL.md.
//
// The machine that runs the agent may be compromised: nothing it says
// about the destination is believed. Everything displayed comes out of
// checkSignRequest(), which re-derives it from the bytes to sign and from
// the server's own signature.

import { b64u, concat, equal, fromUtf8, hex, sha256, unb64u, utf8 } from './bytes.js';
import {
  fingerprint, keyType, parseUserAuthRequest, signatureAlgorithms, sshString, verifySignature,
} from './ssh.js';

export const KEY_ALGORITHM = 'ecdsa-sha2-nistp256';
// Approval keys a requester accepts (PROTOCOL.md, "Approval key").
export const APPROVE_KEY_TYPES = ['ssh-ed25519', 'ecdsa-sha2-nistp256'];
const APPROVE_PREFIX = 'clavix-approve/v1 approve';
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

// ---- the requests ---------------------------------------------------------------

// Check a decoded sign request. `id` is the request id the relay gave,
// `keyBlob` our own SSH public key, `now` the current time in seconds.
//
// Returns { ok: false, reason } or { ok: true, data, user, hops, … } where
// `hops` is the verified chain, outermost first, the last one being the
// host to authenticate to. A hop carries the host key and its fingerprint,
// never a name: naming is done by the caller from its own pinned list.
export function checkSignRequest(inner, { id, keyBlob, now }) {
  return checkRequest(inner, {
    id, now, t: 'sign',
    // Only our own key, with the one algorithm we sign with.
    algorithms: (key) => (equal(key, keyBlob) ? [KEY_ALGORITHM] : null),
  });
}

// Check a decoded approval request (approve mode). The requester signs
// with its own key, named in `key`: the same checks as for a sign request,
// made with that key. The result also carries the key, its fingerprint and
// the name the requester gives it (unverified).
export async function checkApproveRequest(inner, { id, now }) {
  const view = await checkRequest(inner, { id, now, t: 'approve', algorithms: signatureAlgorithms });
  if (!view.ok) return view;
  return {
    ...view,
    keyType: keyType(view.key),
    keyFingerprint: await fingerprint(view.key),
    keyName: label(inner.keyName),
  };
}

async function checkRequest(inner, { id, now, t, algorithms }) {
  const refuse = (reason) => ({ ok: false, reason });
  if (!inner || inner.t !== t || inner.id !== id) return refuse('malformed');
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
  const allowed = algorithms(key);
  if (!allowed) return refuse('unknown-key');

  // 1. The bytes to sign are a host-bound public-key login made with that
  //    key (plain "publickey" is refused by the parser).
  const request = parseUserAuthRequest(data);
  if (!request || request.service !== 'ssh-connection' || !allowed.includes(request.algorithm)
      || !equal(request.keyBlob, key)) {
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

  // 3. The login is for that last session and names that very host key.
  //    Without the second check, whoever holds a pinned host key could
  //    bind a session it opened with another server under its own key.
  const dest = binds[binds.length - 1];
  if (!equal(request.sessionId, dest.sessionId)) return refuse('unverified');
  if (!request.hostKey || !equal(request.hostKey, dest.hostKey)) return refuse('unverified');

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
    key,
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

export function approvedResponse(requestMsg, id, proofBlob) {
  return response(requestMsg, id, { t: 'approved', proof: b64u(proofBlob) });
}

// ---- approve mode -------------------------------------------------------------------

// What the approval key signs (PROTOCOL.md, "Approval response"): a bare
// prefix, then the channel, the signer id, the request id and the raw
// SHA-256 of the request's `msg` as the relay lists it.
export async function approvalBytes(ch, signer, id, requestMsg) {
  return concat(utf8(APPROVE_PREFIX), sshString(utf8(ch)), sshString(utf8(signer)), sshString(utf8(id)),
    sshString(await sha256(utf8(requestMsg))));
}

// Does `proofBlob` approve those bytes under `approveBlob`, an approval
// key of an accepted type?
export async function verifyApproval(approveBlob, bytes, proofBlob) {
  if (!APPROVE_KEY_TYPES.includes(keyType(approveBlob))) return false;
  return verifySignature(approveBlob, bytes, proofBlob);
}
