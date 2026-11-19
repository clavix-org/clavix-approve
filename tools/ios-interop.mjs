#!/usr/bin/env node
// Interoperability between the page's modules (web/lib) and the native
// app's (ios/ClavixCore), in both directions:
//
//   ios-interop.mjs make  FILE   write what the page produces: keys, a
//                                sealed sign request, a pairing hello and
//                                answer, the six digits
//   ios-interop.mjs check FILE OUT
//                                open what the Swift tests wrote to OUT
//                                (a sealed response and a pairing answer)
//                                as the agent would, with the keys of FILE
//
// The Swift tests read FILE from $CLAVIX_JS_VECTORS and write OUT to
// $CLAVIX_SWIFT_OUT. See .github/workflows/ci.yml, job "ios".

import { readFileSync, writeFileSync } from 'node:fs';

import { b64u, concat, sha256, unb64u, utf8 } from '../web/lib/bytes.js';
import {
  generateIdentity, openMessage, pairHeader, peer, requestHeader, responseHeader, sealMessage,
} from '../web/lib/channel.js';
import { answerMac, buildAnswer, commitment, pairingDigits } from '../web/lib/pairing.js';
import { fingerprint, sshString, verifySignature } from '../web/lib/ssh.js';
import { bind, clientKey, hostKey, userAuth } from '../web/test/helpers.mjs';

const jwk = (key) => crypto.subtle.exportKey('jwk', key);

async function exportIdentity(id) {
  return { kem: (await jwk(id.kem.privateKey)).d, sig: (await jwk(id.sig.privateKey)).d,
    kemPublic: b64u(id.kemPublic), sigPublic: b64u(id.sigPublic) };
}

async function importIdentity(e) {
  const kemPublic = unb64u(e.kemPublic), sigPublic = unb64u(e.sigPublic);
  const x = b64u(kemPublic.subarray(1, 33)), y = b64u(kemPublic.subarray(33));
  const kemPriv = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x, y, d: e.kem }, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const sigPriv = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: b64u(sigPublic), d: e.sig }, { name: 'Ed25519' }, false, ['sign']);
  return { kem: { privateKey: kemPriv, publicKey: await crypto.subtle.importKey('raw', kemPublic, { name: 'ECDH', namedCurve: 'P-256' }, true, []) },
    sig: { privateKey: sigPriv }, kemPublic, sigPublic };
}

// The agent's hello (protocol version 2, sign mode), built as
// core/src/pairing.rs does.
async function hello(ch, secret, agent, label, commit) {
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const macKey = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8('clavix-approve/v1/pair-mac') }, ikm, 256));
  const k = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const transcript = concat(...[utf8('clavix-approve/v2/pair-hello'), utf8('sign'), utf8(ch), agent.kemPublic,
    agent.sigPublic, utf8(label), commit].map(sshString));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, transcript));
  return b64u(utf8(JSON.stringify({
    v: 2, mode: 'sign', label, kem: b64u(agent.kemPublic), sig: b64u(agent.sigPublic), commit: b64u(commit),
    mac: b64u(mac),
  })));
}

async function make(file) {
  const agent = await generateIdentity(true);
  const phone = await generateIdentity(true);
  const ssh = await clientKey();
  const host = await hostKey('ed25519');
  const ch = 'c'.repeat(32), signer = '0123456789abcdef', id = 'ab'.repeat(16);
  const now = 1_800_000_000, exp = now + 90;
  const sid = utf8('exchange-hash-of-the-session');

  const inner = {
    t: 'sign', id, iat: now, exp,
    key: b64u(ssh.blob),
    data: b64u(userAuth({ sessionId: sid, keyBlob: ssh.blob, hostKey: host.blob })),
    flags: 0,
    binds: [await bind(host, sid)],
    caller: { pid: 4242, name: 'ssh' },
    agent: 'build-box',
    hints: { [await fingerprint(host.blob)]: 'prod.example' },
  };
  const request = await sealMessage(agent, peer(phone.kemPublic, phone.sigPublic), requestHeader(ch, signer, id, exp), inner);

  const secret = crypto.getRandomValues(new Uint8Array(16));
  const agentNonce = crypto.getRandomValues(new Uint8Array(32));
  const signerNonce = crypto.getRandomValues(new Uint8Array(32));
  const commit = await commitment(agentNonce);
  const agentPeer = peer(agent.kemPublic, agent.sigPublic);
  const answer = await buildAnswer({ ch, signer, secret, me: phone, agent: agentPeer,
    keyBlob: ssh.blob, comment: 'page', mode: 'sign', nonce: signerNonce, commit });

  writeFileSync(file, JSON.stringify({
    agent: await exportIdentity(agent),
    phone: await exportIdentity(phone),
    sshKey: (await jwk(ssh.privateKey)).d,
    keyBlob: b64u(ssh.blob),
    hostFingerprint: await fingerprint(host.blob),
    ch, signer, id, exp, now,
    request,
    secret: b64u(secret),
    hello: await hello(ch, secret, agent, 'build-box', commit),
    agentNonce: b64u(agentNonce),
    signerNonce: b64u(signerNonce),
    answer,
    digits: await pairingDigits({
      mode: 'sign', ch, signer, agent: agentPeer, device: phone, keyBlob: ssh.blob, agentNonce, signerNonce,
    }),
  }, null, 1));
  console.log(`wrote ${file}`);
}

async function check(file, out) {
  const v = JSON.parse(readFileSync(file, 'utf8'));
  const swift = JSON.parse(readFileSync(out, 'utf8'));
  const agent = await importIdentity(v.agent);
  const fail = (what) => { console.error(`interop: ${what}`); process.exit(1); };

  // The response the Swift signer sealed, opened as the agent opens it.
  const phone = peer(unb64u(swift.phoneKem), unb64u(swift.phoneSig));
  const res = await openMessage(agent, phone, responseHeader(v.ch, v.signer, v.id), swift.response);
  if (res.t !== 'signed' || res.id !== v.id) fail('response is not a signature for the request');
  if (res.req !== b64u(await sha256(utf8(v.request)))) fail('response names another request');
  const data = unb64u(JSON.parse(swift.requestInner).data);
  if (!(await verifySignature(unb64u(swift.keyBlob), data, unb64u(res.sig)))) fail('SSH signature does not verify');

  // The Swift pairing answer: signing key in front, then a sealed message.
  const raw = unb64u(swift.answer);
  const introKey = raw.subarray(0, 32);
  const sealed = b64u(raw.subarray(32));
  const pair = await openMessage(agent, { sigPublic: introKey, kemPublic: agent.kemPublic }, pairHeader(v.ch, 'swift-signer'), sealed);
  if (pair.t !== 'pair' || pair.v !== 2 || pair.key !== swift.keyBlob) fail('pairing answer does not carry the SSH key');
  if (b64u(introKey) !== swift.phoneSig || pair.kem !== swift.phoneKem) fail('pairing answer carries other keys');
  const expectedMac = await answerMac(unb64u(v.secret), 'sign', v.ch, 'swift-signer', phone, unb64u(swift.keyBlob),
    unb64u(pair.nonce), peer(agent.kemPublic, agent.sigPublic), await commitment(unb64u(v.agentNonce)));
  if (b64u(expectedMac) !== pair.mac) fail('pairing answer MAC differs');
  const digits = await pairingDigits({
    mode: 'sign', ch: v.ch, signer: 'swift-signer', agent: peer(agent.kemPublic, agent.sigPublic), device: phone,
    keyBlob: unb64u(swift.keyBlob), agentNonce: unb64u(v.agentNonce), signerNonce: unb64u(pair.nonce),
  });
  if (digits !== swift.digits) fail(`six digits differ: page ${digits}, app ${swift.digits}`);

  console.log('interop: the page opens what the app sealed');
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'make' && args.length === 1) await make(args[0]);
else if (cmd === 'check' && args.length === 2) await check(...args);
else {
  console.error('usage: ios-interop.mjs make FILE | check FILE OUT');
  process.exit(2);
}
