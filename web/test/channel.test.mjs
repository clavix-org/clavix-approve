import assert from 'node:assert/strict';
import { test } from 'node:test';

import { b64u, concat, unb64u, utf8 } from '../lib/bytes.js';
import {
  generateIdentity, openMessage, pairHeader, peer, requestHeader, responseHeader, sealIntroduction, sealMessage,
} from '../lib/channel.js';
import { buildAnswer, pairingFingerprint, readHello } from '../lib/pairing.js';
import { approve, deny, readRequest } from '../lib/signer.js';
import { sshString } from '../lib/ssh.js';
import { bind, clientKey, hostKey, userAuth } from './helpers.mjs';

const peerOf = (id) => peer(id.kemPublic, id.sigPublic);
const CH = 'ab'.repeat(16);
const SIGNER = 'cd'.repeat(8);
const ID = 'ef'.repeat(16);

test('a sealed message opens for its recipient, from its sender, under its header', async () => {
  const [agent, phone, other] = await Promise.all([generateIdentity(), generateIdentity(), generateIdentity()]);
  const hdr = requestHeader(CH, SIGNER, ID, 1_800_000_000);
  const msg = await sealMessage(agent, peerOf(phone), hdr, { t: 'sign', n: 1 });

  assert.deepEqual(await openMessage(phone, peerOf(agent), hdr, msg), { t: 'sign', n: 1 });
  await assert.rejects(openMessage(other, peerOf(agent), hdr, msg));
  await assert.rejects(openMessage(phone, peerOf(other), hdr, msg), /bad signature/);
  // The relay changes what it can see: the expiry, the id, the direction.
  await assert.rejects(openMessage(phone, peerOf(agent), requestHeader(CH, SIGNER, ID, 1_800_000_999), msg));
  await assert.rejects(openMessage(phone, peerOf(agent), requestHeader(CH, SIGNER, '00'.repeat(16), 1_800_000_000), msg));
  await assert.rejects(openMessage(phone, peerOf(agent), responseHeader(CH, SIGNER, ID), msg));

  const raw = unb64u(msg);
  for (const at of [0, 64, 129, raw.length - 1]) {
    const bad = Uint8Array.from(raw);
    bad[at] ^= 1;
    await assert.rejects(openMessage(phone, peerOf(agent), hdr, b64u(bad)));
  }
  await assert.rejects(openMessage(phone, peerOf(agent), hdr, b64u(raw.subarray(0, 100))));
});

test('headers and peers reject malformed input', async () => {
  assert.throws(() => requestHeader(CH, SIGNER, ID, 1.5));
  assert.throws(() => requestHeader(CH, SIGNER, ID, '1800000000'));
  const id = await generateIdentity();
  assert.throws(() => peer(id.kemPublic.subarray(1), id.sigPublic));
  assert.throws(() => peer(id.kemPublic, id.sigPublic.subarray(1)));
});

// The agent's side of the pairing, as agent/src/pairing.rs does it.
async function agentHello(agent, secret, label = 'build-box') {
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const raw = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8('clavix-approve/v1/pair-mac') }, ikm, 256);
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const transcript = concat(...[utf8('hello'), utf8(CH), agent.kemPublic, agent.sigPublic, utf8(label)].map(sshString));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, transcript));
  return b64u(utf8(JSON.stringify({ label, kem: b64u(agent.kemPublic), sig: b64u(agent.sigPublic), mac: b64u(mac) })));
}

test('the hello is accepted only with the pairing secret it was made with', async () => {
  const agent = await generateIdentity();
  const secret = new Uint8Array(16).fill(9);
  const hello = await agentHello(agent, secret);
  const read = await readHello(hello, CH, secret);
  assert.equal(read.label, 'build-box');
  assert.deepEqual(read.agent, peerOf(agent));

  // A relay substituting its own keys does not know the secret.
  const relayKeys = await generateIdentity();
  await assert.rejects(readHello(await agentHello(relayKeys, new Uint8Array(16)), CH, secret), /pairing code/);
  await assert.rejects(readHello(hello, 'ff'.repeat(16), secret), /pairing code/);
  await assert.rejects(readHello(await agentHello(agent, secret, 'other-label'), CH, new Uint8Array(16)));
});

test('the pairing answer is an introduction sealed to the agent', async () => {
  const [agent, phone] = await Promise.all([generateIdentity(), generateIdentity()]);
  const key = await clientKey();
  const msg = await buildAnswer({
    ch: CH, signer: SIGNER, secret: new Uint8Array(16).fill(9), me: phone, agent: peerOf(agent),
    keyBlob: key.blob, comment: 'phone',
  });
  const raw = unb64u(msg);
  assert.deepEqual(raw.subarray(0, 32), phone.sigPublic);
  const inner = await openMessage(agent, peerOf(phone), pairHeader(CH, SIGNER), b64u(raw.subarray(32)));
  assert.equal(inner.t, 'pair');
  assert.equal(inner.key, b64u(key.blob));
  assert.equal(inner.kem, b64u(phone.kemPublic));
  assert.equal(await sealIntroduction(phone, peerOf(agent), pairHeader(CH, SIGNER), {}).then((m) => unb64u(m).length > 32), true);

  const digits = await pairingFingerprint(peerOf(agent), phone, key.blob);
  assert.match(digits, /^\d{3} \d{3}$/);
  assert.equal(await pairingFingerprint(peerOf(agent), phone, key.blob), digits);
  assert.notEqual(await pairingFingerprint(peerOf(await generateIdentity()), phone, key.blob), digits);
});

test('a signer reads, approves and denies requests through the channel', async () => {
  const [agent, phone, stranger] = await Promise.all([generateIdentity(), generateIdentity(), generateIdentity()]);
  const key = await clientKey();
  const host = await hostKey('ed25519');
  const sid = utf8('session');
  const exp = Math.floor(Date.now() / 1000) + 60;
  const inner = {
    t: 'sign', id: ID, iat: exp - 60, exp, key: b64u(key.blob), flags: 0,
    data: b64u(userAuth({ sessionId: sid, keyBlob: key.blob, hostKey: host.blob })),
    binds: [await bind(host, sid)], caller: null, agent: 'build-box', hints: {},
  };
  const ctx = { ch: CH, signer: SIGNER, me: phone, agent: peerOf(agent), keyBlob: key.blob };
  const entry = { id: ID, exp, msg: await sealMessage(agent, ctx.agent, requestHeader(CH, SIGNER, ID, exp), inner) };
  entry.msg = await sealMessage(agent, peerOf(phone), requestHeader(CH, SIGNER, ID, exp), inner);

  const view = await readRequest(ctx, entry, exp - 30);
  assert.equal(view.ok, true);
  assert.equal(view.user, 'deploy');

  // Not from our agent, or with relay-visible fields changed: nothing to show.
  const forged = { ...entry, msg: await sealMessage(stranger, peerOf(phone), requestHeader(CH, SIGNER, ID, exp), inner) };
  assert.deepEqual(await readRequest(ctx, forged, exp - 30), { ok: false, reason: 'unauthentic' });
  assert.deepEqual(await readRequest(ctx, { ...entry, exp: exp + 600 }, exp - 30), { ok: false, reason: 'unauthentic' });
  assert.deepEqual(await readRequest(ctx, { ...entry, msg: 'garbage' }, exp - 30), { ok: false, reason: 'unauthentic' });
  // Authentic but stale.
  assert.deepEqual(await readRequest(ctx, entry, exp + 1), { ok: false, reason: 'expired' });

  // Answers go back sealed to the agent, under the response header.
  const sent = [];
  const relay = { respond: async (id, msg) => { sent.push({ id, msg }); return { state: 'accepted' }; } };
  assert.equal(await approve(ctx, relay, entry, utf8('ssh-signature')), 'accepted');
  assert.equal(await deny(ctx, relay, entry, 'user'), 'accepted');
  assert.equal(await deny(ctx, relay, forged, 'unauthentic'), 'ignored');
  assert.equal(sent.length, 2);
  const [signed, denied] = await Promise.all(
    sent.map(({ msg }) => openMessage(agent, peerOf(phone), responseHeader(CH, SIGNER, ID), msg)));
  assert.equal(signed.t, 'signed');
  assert.equal(signed.sig, b64u(utf8('ssh-signature')));
  assert.deepEqual([denied.t, denied.reason, denied.req], ['denied', 'user', signed.req]);
});
