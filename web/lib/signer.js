// What a signer does, independent of where its keys live and of how the
// user is asked: pair, read a request, answer it. Used by the approval
// page and by the command-line stand-in.
//
// A pairing is in one of two modes, set by the agent's hello: "sign" (we
// hold the SSH key and sign the login) or "approve" (the requester holds
// the SSH key; we return a proof made with our approval key). PROTOCOL.md,
// "Approve mode".

import { b64u, hex, randomBytes } from './bytes.js';
import { openMessage, requestHeader, responseHeader, sealMessage } from './channel.js';
import { buildAnswer, pairingFingerprint, pairToken, parsePairingCode, readHello } from './pairing.js';
import {
  approvalBytes, approvedResponse, checkApproveRequest, checkSignRequest, deniedResponse, label, signedResponse,
  tokenAuth,
} from './protocol.js';
import { RelayClient } from './relay.js';

// First half of a pairing: read and authenticate the agent's hello.
// Returns { ch, secret, client, hello: { label, agent, mode } }; nothing is
// sent yet, so the caller can still prepare the key the mode needs.
export async function openPairing({ base, code, fetchFn }) {
  const { ch, secret } = parsePairingCode(code);
  const client = new RelayClient(base, ch, await pairToken(secret), fetchFn);
  const hello = await readHello((await client.hello()).hello, ch, secret);
  return { ch, secret, client, hello };
}

// Second half: answer with our keys. `keyBlob` is the key of the hello's
// mode (the SSH key, or the approval key). Returns what must be stored:
// { ch, signer, token, agent, label, mode, fingerprint }, `agent` being the
// peer's public keys and `fingerprint` the six digits to compare with the
// agent's display.
export async function completePairing({ ch, secret, client, hello }, { me, keyBlob, comment }) {
  const { mode } = hello;
  const signer = hex(randomBytes(8));
  const token = b64u(randomBytes(32));
  const msg = await buildAnswer({ ch, signer, secret, me, agent: hello.agent, keyBlob, comment, mode });
  const res = await client.pair(signer, await tokenAuth(token), msg);
  if (res.state !== 'paired') throw new Error(`the relay refused the pairing (${res.state})`);

  return {
    ch,
    signer,
    token,
    agent: hello.agent,
    label: label(hello.label) ?? '',
    mode,
    fingerprint: await pairingFingerprint(hello.agent, me, keyBlob, mode),
  };
}

// Pair with the agent that displayed `code`, in one go.
//
// `me` is our channel identity. `keyFor(mode)` gives the key blob for the
// mode the agent asks for; `keyBlob` alone is the SSH key, and pairs in
// sign mode only.
export async function pairWithAgent({ base, code, me, keyBlob, keyFor, comment, fetchFn }) {
  const opening = await openPairing({ base, code, fetchFn });
  const blob = keyFor ? await keyFor(opening.hello.mode) : opening.hello.mode === 'sign' ? keyBlob : null;
  if (!blob) throw new Error(`no key for a pairing in ${opening.hello.mode} mode`);
  return completePairing(opening, { me, keyBlob: blob, comment });
}

// Open and check one entry of the relay's request list ({ id, exp, msg }).
// `ctx` is { ch, signer, me, agent, mode, keyBlob }, `keyBlob` being our
// SSH key in sign mode. Never throws: the result is { ok: false, reason }
// or the verified view of checkSignRequest() / checkApproveRequest(). A
// request of the other mode is refused as malformed.
export async function readRequest(ctx, entry, now) {
  let inner;
  try {
    const hdr = requestHeader(ctx.ch, ctx.signer, entry.id, entry.exp);
    inner = await openMessage(ctx.me, ctx.agent, hdr, entry.msg);
  } catch (_) {
    // Not from our agent, altered on the way, or not for us.
    return { ok: false, reason: 'unauthentic' };
  }
  if (ctx.mode === 'approve') return checkApproveRequest(inner, { id: entry.id, now });
  return checkSignRequest(inner, { id: entry.id, keyBlob: ctx.keyBlob, now });
}

async function respond(ctx, relay, entry, inner) {
  const msg = await sealMessage(ctx.me, ctx.agent, responseHeader(ctx.ch, ctx.signer, entry.id), inner);
  return (await relay.respond(entry.id, msg)).state;
}

// Sign mode: `signatureBlob` is the SSH signature of the request's data.
export async function approve(ctx, relay, entry, signatureBlob) {
  return respond(ctx, relay, entry, await signedResponse(entry.msg, entry.id, signatureBlob));
}

// Approve mode: the bytes the approval key must sign for this request.
export function approvalData(ctx, entry) {
  return approvalBytes(ctx.ch, ctx.signer, entry.id, entry.msg);
}

// Approve mode: `proofBlob` is the approval key's SSH signature of
// approvalData().
export async function sendApproval(ctx, relay, entry, proofBlob) {
  return respond(ctx, relay, entry, await approvedResponse(entry.msg, entry.id, proofBlob));
}

// `reason` is "user" for a human refusal, else the reason of readRequest().
// An unauthentic request gets no answer: there is nobody to answer to.
export async function deny(ctx, relay, entry, reason) {
  if (reason === 'unauthentic') return 'ignored';
  return respond(ctx, relay, entry, await deniedResponse(entry.msg, entry.id, reason));
}
