// What a signer does, independent of where its keys live and of how the
// user is asked: pair, read a request, answer it. Used by the approval
// page and by the command-line stand-in.

import { b64u, hex, randomBytes } from './bytes.js';
import { openMessage, requestHeader, responseHeader, sealMessage } from './channel.js';
import { buildAnswer, pairingFingerprint, pairToken, parsePairingCode, readHello } from './pairing.js';
import { checkSignRequest, deniedResponse, label, signedResponse, tokenAuth } from './protocol.js';
import { RelayClient } from './relay.js';

// Pair with the agent that displayed `code`.
//
// `me` is our channel identity, `keyBlob` the SSH public key we will sign
// with. Returns what must be stored: { ch, signer, token, agent, label,
// fingerprint }, `agent` being the peer's public keys and `fingerprint`
// the six digits to compare with the agent's display.
export async function pairWithAgent({ base, code, me, keyBlob, comment, fetchFn }) {
  const { ch, secret } = parsePairingCode(code);
  const pairing = new RelayClient(base, ch, await pairToken(secret), fetchFn);
  const hello = await readHello((await pairing.hello()).hello, ch, secret);

  const signer = hex(randomBytes(8));
  const token = b64u(randomBytes(32));
  const msg = await buildAnswer({ ch, signer, secret, me, agent: hello.agent, keyBlob, comment });
  const res = await pairing.pair(signer, await tokenAuth(token), msg);
  if (res.state !== 'paired') throw new Error(`the relay refused the pairing (${res.state})`);

  return {
    ch,
    signer,
    token,
    agent: hello.agent,
    label: label(hello.label) ?? '',
    fingerprint: await pairingFingerprint(hello.agent, me, keyBlob),
  };
}

// Open and check one entry of the relay's request list ({ id, exp, msg }).
// `ctx` is { ch, signer, me, agent, keyBlob }. Never throws: the result is
// { ok: false, reason } or the verified view of checkSignRequest().
export async function readRequest(ctx, entry, now) {
  let inner;
  try {
    const hdr = requestHeader(ctx.ch, ctx.signer, entry.id, entry.exp);
    inner = await openMessage(ctx.me, ctx.agent, hdr, entry.msg);
  } catch (_) {
    // Not from our agent, altered on the way, or not for us.
    return { ok: false, reason: 'unauthentic' };
  }
  return checkSignRequest(inner, { id: entry.id, keyBlob: ctx.keyBlob, now });
}

async function respond(ctx, relay, entry, inner) {
  const msg = await sealMessage(ctx.me, ctx.agent, responseHeader(ctx.ch, ctx.signer, entry.id), inner);
  return (await relay.respond(entry.id, msg)).state;
}

// `signatureBlob` is the SSH signature of the request's data.
export async function approve(ctx, relay, entry, signatureBlob) {
  return respond(ctx, relay, entry, await signedResponse(entry.msg, entry.id, signatureBlob));
}

// `reason` is "user" for a human refusal, else the reason of readRequest().
// An unauthentic request gets no answer: there is nobody to answer to.
export async function deny(ctx, relay, entry, reason) {
  if (reason === 'unauthentic') return 'ignored';
  return respond(ctx, relay, entry, await deniedResponse(entry.msg, entry.id, reason));
}
