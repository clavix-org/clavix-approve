// Approve mode (PROTOCOL.md, "Approve mode"): the shared vectors, the
// approval key, the checks of an approval request, and a whole exchange
// between the requester's code and the signer's.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { b64u, concat, hex, utf8 } from '../lib/bytes.js';
import { generateIdentity, pairHeader, sealIntroduction } from '../lib/channel.js';
import { approveWithWrappedKey, createWrappedApproveKey, createWrappedKey, signWithWrappedKey } from '../lib/lock.js';
import {
  answerMac, buildAnswer, checkReveal, commitment, helloMac, pairingDigits, parsePairingCode, readHello,
} from '../lib/pairing.js';
import { approvalBytes, checkApproveRequest, checkSignRequest, verifyApproval } from '../lib/protocol.js';
import { approvalRequest, buildHello, newOffer, readAnswer, readApproval } from '../lib/requester.js';
import { approvalData, deny, readRequest, sendApproval } from '../lib/signer.js';
import { fingerprint, sshString, verifySignature } from '../lib/ssh.js';
import { bind, clientKey, hostKey, userAuth } from './helpers.mjs';

const vector = (name) => JSON.parse(readFileSync(new URL(`../../testdata/${name}`, import.meta.url), 'utf8'));
const unhex = (s) => Uint8Array.from(s.match(/../g), (b) => parseInt(b, 16));
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));

// ---- the vectors --------------------------------------------------------------------

test('the page reproduces the pairing vectors, in both modes', async () => {
  const v = vector('pairing.json');
  const secret = unhex(v.secret);
  const agent = { kemPublic: unhex(v.agent.kem), sigPublic: unhex(v.agent.sig) };
  const phone = { kemPublic: unhex(v.signer_keys.kem), sigPublic: unhex(v.signer_keys.sig) };
  const agentNonce = unhex(v.agent_nonce), signerNonce = unhex(v.signer_nonce);
  const commit = await commitment(agentNonce);
  assert.equal(b64u(commit), v.commit);
  assert.deepEqual(parsePairingCode(v.code), { ch: v.channel, secret });
  await checkReveal(agentNonce, commit);
  await assert.rejects(checkReveal(signerNonce, commit), /someone is in between/);

  for (const c of v.modes) {
    assert.equal(b64u(await helloMac(secret, c.mode, v.channel, agent, v.label, commit)), c.hello_mac, c.mode);
    const hello = (extra) => b64u(utf8(JSON.stringify({
      v: 2, mode: c.mode, label: v.label, kem: b64u(agent.kemPublic), sig: b64u(agent.sigPublic), commit: v.commit,
      mac: c.hello_mac, ...extra,
    })));
    const read = await readHello(hello({}), v.channel, secret);
    assert.equal(read.mode, c.mode);
    assert.equal(read.label, v.label);
    // A relay that flips the mode or swaps the commitment breaks the MAC.
    const other = c.mode === 'sign' ? 'approve' : 'sign';
    await assert.rejects(readHello(hello({ mode: other }), v.channel, secret), /does not match/);
    await assert.rejects(readHello(hello({ commit: b64u(new Uint8Array(32)) }), v.channel, secret), /does not match/);
    await assert.rejects(readHello(hello({ mode: 'other' }), v.channel, secret), /unknown mode/);
    // A hello of the first version is refused, with a reason.
    await assert.rejects(readHello(hello({ v: undefined }), v.channel, secret), /older pairing protocol/);

    for (const a of c.answers) {
      const blob = unb64u(a.key);
      assert.equal(b64u(await answerMac(secret, c.mode, v.channel, v.signer, phone, blob, signerNonce, agent, commit)),
        a.answer_mac, `${c.mode} ${a.type}`);
      const digits = await pairingDigits({
        mode: c.mode, ch: v.channel, signer: v.signer, agent, device: phone, keyBlob: blob, agentNonce, signerNonce,
      });
      assert.equal(digits, a.digits, `${c.mode} ${a.type}`);
      assert.notEqual(await pairingDigits({
        mode: other, ch: v.channel, signer: v.signer, agent, device: phone, keyBlob: blob, agentNonce, signerNonce,
      }), a.digits);
    }
  }
  assert.throws(() => parsePairingCode(`cva1-${v.code.slice(5)}`), /older version/);
});

test('the page reproduces the approval bytes and verifies both proof vectors', async () => {
  const v = vector('approve-proof.json');
  const bytes = await approvalBytes(v.channel, v.signer, v.id, v.msg);
  assert.equal(hex(bytes), v.signed);
  for (const k of v.keys) {
    assert.equal(await verifyApproval(unb64u(k.approve), bytes, unb64u(k.proof)), true, k.type);
    const other = await approvalBytes(v.channel, v.signer, v.id, `${v.msg}x`);
    assert.equal(await verifyApproval(unb64u(k.approve), other, unb64u(k.proof)), false, k.type);
  }
});

test('only Ed25519 and P-256 approval keys are accepted', async () => {
  const p384 = await hostKey('P-384');
  const data = utf8('anything');
  assert.equal(await verifySignature(p384.blob, data, await p384.sign(data)), true);
  assert.equal(await verifyApproval(p384.blob, data, await p384.sign(data)), false);
});

// ---- the approval key -------------------------------------------------------------------

test('the approval key is wrapped under the passkey secret, apart from the SSH key', async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await createWrappedApproveKey(secret);
  assert.match(new TextDecoder().decode(wrapped.keyBlob.subarray(4, 15)), /^ssh-ed25519$/);
  const data = utf8('clavix-approve/v1 approve…');
  const proof = await approveWithWrappedKey(secret, wrapped, data);
  assert.equal(await verifyApproval(wrapped.keyBlob, data, proof), true);
  await assert.rejects(approveWithWrappedKey(crypto.getRandomValues(new Uint8Array(32)), wrapped, data), /approval key/);
  // Its own wrapping label: it does not open as the SSH key, nor the other way.
  await assert.rejects(signWithWrappedKey(secret, wrapped, data), /signing key/);
  await assert.rejects(approveWithWrappedKey(secret, await createWrappedKey(secret), data), /approval key/);
});

// ---- the approval request -------------------------------------------------------------------

const NOW = 1_800_000_000;
const ID = 'cd'.repeat(16);
const SID = utf8('exchange-hash-of-the-session');

// The requester's own key, of any type the agent protocol allows.
async function requesterKey(type) {
  const key = await hostKey(type);
  const algorithm = { ed25519: 'ssh-ed25519', 'P-256': 'ecdsa-sha2-nistp256', 'P-384': 'ecdsa-sha2-nistp384',
    'P-521': 'ecdsa-sha2-nistp521', rsa: 'rsa-sha2-512' }[type];
  return { ...key, algorithm };
}

async function approveScene(type = 'ed25519', overrides = {}) {
  const key = await requesterKey(type);
  const host = await hostKey('ed25519');
  const inner = {
    t: 'approve', id: ID, iat: NOW - 1, exp: NOW + 90,
    key: b64u(key.blob), keyName: 'user@workstation',
    data: b64u(userAuth({ sessionId: SID, keyBlob: key.blob, hostKey: host.blob, algorithm: key.algorithm })),
    flags: 0,
    binds: [await bind(host, SID)],
    caller: { pid: 7, name: 'ssh' },
    agent: 'workstation',
    hints: {},
    ...overrides,
  };
  return { key, host, inner, check: (i = inner) => checkApproveRequest(i, { id: ID, now: NOW }) };
}

test('an approval request is checked with the key it names, of any agent key type', async () => {
  for (const type of ['ed25519', 'P-256', 'P-384', 'P-521', 'rsa']) {
    const { key, host, check } = await approveScene(type);
    const view = await check();
    assert.equal(view.ok, true, type);
    assert.equal(view.user, 'deploy');
    assert.equal(view.hops[0].fingerprint, await fingerprint(host.blob));
    assert.equal(view.keyFingerprint, await fingerprint(key.blob));
    assert.equal(view.keyName, 'user@workstation');
  }
  // RSA with SHA-256 too, never SHA-1.
  const rsa = await approveScene('rsa');
  rsa.inner.data = b64u(userAuth({ sessionId: SID, keyBlob: rsa.key.blob, hostKey: rsa.host.blob, algorithm: 'rsa-sha2-256' }));
  assert.equal((await rsa.check()).ok, true);
  rsa.inner.data = b64u(userAuth({ sessionId: SID, keyBlob: rsa.key.blob, hostKey: rsa.host.blob, algorithm: 'ssh-rsa' }));
  assert.deepEqual(await rsa.check(), { ok: false, reason: 'unverified' });
});

test('an approval request is refused like a sign request when it does not hold up', async () => {
  const { key, host, inner, check } = await approveScene();
  const other = await requesterKey('ed25519');
  // Data signed for another key than the one named.
  assert.deepEqual(await check({ ...inner, data: b64u(userAuth({ sessionId: SID, keyBlob: other.blob, hostKey: host.blob, algorithm: 'ssh-ed25519' })) }),
    { ok: false, reason: 'unverified' });
  // A session the host did not sign.
  assert.deepEqual(await check({ ...inner, binds: [await bind(host, utf8('another'))] }), { ok: false, reason: 'unverified' });
  // A key type the agent protocol does not have.
  const dsa = concat(sshString(utf8('ssh-dss')), sshString(new Uint8Array(8)));
  assert.deepEqual(await check({ ...inner, key: b64u(dsa) }), { ok: false, reason: 'unknown-key' });
  assert.deepEqual(await check({ ...inner, exp: NOW }), { ok: false, reason: 'expired' });
  assert.deepEqual(await check({ ...inner, id: 'ef'.repeat(16) }), { ok: false, reason: 'malformed' });
  assert.ok(key);
});

test('each mode acts only on its own requests', async () => {
  const { inner } = await approveScene();
  assert.deepEqual(await checkApproveRequest({ ...inner, t: 'sign' }, { id: ID, now: NOW }), { ok: false, reason: 'malformed' });
  const own = await clientKey();
  assert.deepEqual(await checkSignRequest(inner, { id: ID, keyBlob: own.blob, now: NOW }), { ok: false, reason: 'malformed' });
});

// ---- a whole exchange, requester code against signer code ---------------------------------

// Stands for the relay: the signer's answers land here.
function fakeRelay() {
  const sent = [];
  return { sent, respond: async (id, msg) => { sent.push({ id, msg }); return { state: 'accepted' }; } };
}

test('requester and signer pair in approve mode, and an approval goes through', async () => {
  const desktop = await generateIdentity();
  const phone = await generateIdentity();
  const offer = newOffer();
  const secret = offer.secret;

  // Pairing: the hello says approve; the page answers with its approval key.
  const built = await buildHello({ ch: offer.ch, secret, me: desktop, label: 'workstation', nonce: offer.nonce });
  const hello = await readHello(built, offer.ch, secret);
  assert.equal(hello.mode, 'approve');
  const passkeySecret = crypto.getRandomValues(new Uint8Array(32));
  const approveKey = await createWrappedApproveKey(passkeySecret);
  const signer = '0123456789abcdef';
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const { commit } = hello;
  const msg = await buildAnswer({ ch: offer.ch, signer, secret, me: phone, agent: hello.agent,
    keyBlob: approveKey.keyBlob, comment: 'clavix-approve', mode: 'approve', nonce, commit });
  const device = await readAnswer({ ch: offer.ch, secret, me: desktop, answer: { signer, msg }, nonce: offer.nonce });
  assert.equal(hex(device.blob), hex(approveKey.keyBlob));
  // The device checks the nonce revealed after its answer, and both ends
  // derive the same digits.
  await checkReveal(offer.nonce, commit);
  assert.equal(device.fingerprint, await pairingDigits({
    mode: 'approve', ch: offer.ch, signer, agent: hello.agent, device: phone, keyBlob: approveKey.keyBlob,
    agentNonce: offer.nonce, signerNonce: nonce,
  }));

  // A sign-mode answer is refused by the requester…
  const signModeAnswer = await buildAnswer({ ch: offer.ch, signer, secret, me: phone, agent: hello.agent,
    keyBlob: (await clientKey()).blob, comment: 'old', mode: 'sign', nonce, commit });
  await assert.rejects(readAnswer({ ch: offer.ch, secret, me: desktop, answer: { signer, msg: signModeAnswer },
    nonce: offer.nonce }), /no approve key/);
  // … and so is an approve-mode answer under the sign-mode MAC.
  const forged = await sealIntroduction(phone, hello.agent, pairHeader(offer.ch, signer), {
    t: 'pair', v: 2, approve: b64u(approveKey.keyBlob), comment: '', kem: b64u(phone.kemPublic), nonce: b64u(nonce),
    mac: b64u(await answerMac(secret, 'sign', offer.ch, signer, phone, approveKey.keyBlob, nonce, hello.agent, commit)),
  });
  await assert.rejects(readAnswer({ ch: offer.ch, secret, me: desktop, answer: { signer, msg: forged },
    nonce: offer.nonce }), /not from the device/);
  // … and an answer of the first protocol version, with a reason.
  const old = await sealIntroduction(phone, hello.agent, pairHeader(offer.ch, signer), {
    t: 'pair', approve: b64u(approveKey.keyBlob), comment: '', kem: b64u(phone.kemPublic), mac: b64u(nonce),
  });
  await assert.rejects(readAnswer({ ch: offer.ch, secret, me: desktop, answer: { signer, msg: old },
    nonce: offer.nonce }), /older pairing protocol/);

  // A request for `ssh deploy@host` with the requester's own key.
  const key = await requesterKey('ed25519');
  const host = await hostKey('P-256');
  const sid = utf8('session');
  const data = userAuth({ sessionId: sid, keyBlob: key.blob, hostKey: host.blob, algorithm: 'ssh-ed25519' });
  const envelope = await approvalRequest({ ch: offer.ch, me: desktop, device, fields: {
    key: b64u(key.blob), keyName: 'user@workstation', data: b64u(data), flags: 0,
    binds: [await bind(host, sid)], caller: { pid: 1, name: 'ssh' }, agent: 'workstation', hints: {},
  } });

  const ctx = { ch: offer.ch, signer, me: phone, agent: hello.agent, mode: 'approve' };
  const view = await readRequest(ctx, envelope, Date.now() / 1000);
  assert.equal(view.ok, true);
  assert.equal(view.keyFingerprint, await fingerprint(key.blob));

  const relay = fakeRelay();
  const proof = await approveWithWrappedKey(passkeySecret, approveKey, await approvalData(ctx, envelope));
  assert.equal(await sendApproval(ctx, relay, envelope, proof), 'accepted');
  assert.deepEqual(await readApproval({ ch: offer.ch, me: desktop, device, envelope, msg: relay.sent[0].msg }), { ok: true });

  // Only then does the requester sign, with its own key.
  const signature = await key.sign(data);
  assert.equal(await verifySignature(key.blob, data, signature), true);

  // A refusal is read as one.
  await deny(ctx, relay, envelope, 'user');
  assert.deepEqual(await readApproval({ ch: offer.ch, me: desktop, device, envelope, msg: relay.sent[1].msg }),
    { ok: false, denied: 'user' });

  // A proof for another request does not pass for this one.
  const second = await approvalRequest({ ch: offer.ch, me: desktop, device, fields: { key: b64u(key.blob), data: b64u(data),
    flags: 0, binds: [await bind(host, sid)] } });
  await sendApproval(ctx, relay, second, proof);
  await assert.rejects(readApproval({ ch: offer.ch, me: desktop, device, envelope: second, msg: relay.sent[2].msg }),
    /does not verify/);

  // A sign request on this approve-mode channel is refused as malformed.
  const signRequest = await approvalRequest({ ch: offer.ch, me: desktop, device, t: 'sign', fields: { key: b64u(key.blob),
    data: b64u(data), flags: 0, binds: [await bind(host, sid)] } });
  assert.deepEqual(await readRequest(ctx, signRequest, Date.now() / 1000), { ok: false, reason: 'malformed' });
});
