#!/usr/bin/env node
// Command-line stand-in for Clavix desktop in approve mode, for tests.
//
// Plays the requester of PROTOCOL.md, "Approve mode": it holds the SSH key
// itself and asks a paired device only for an approval. It runs
// web/lib/requester.js, the reference the page is checked against, until
// the shared Rust crate of DESKTOP_APPROVAL.md step 2 exists.
//
//   CLAVIX_ENROLL_SECRET=… fake-desktop.mjs pair --relay URL --state FILE [--label NAME]
//   fake-desktop.mjs request --state FILE [--key-type ed25519|rsa] [--user NAME]
//                            [--withdraw-after SECONDS] [--t sign] [--ttl SECONDS]
//
// `pair` prints the code, waits for a device, and saves it without asking
// (the digits are printed for the test to compare). `request` makes up an
// SSH login (its own key, a host key, a signed session), asks the device,
// and on an approval checks the proof, then signs and checks the signature.
// `--withdraw-after` withdraws the request after that many seconds, as
// when the local dialog answered first; `--t sign` sends a request of the
// wrong mode. Each prints one JSON line per event on standard output.

import { readFileSync, writeFileSync } from 'node:fs';

import { b64u, unb64u } from '../web/lib/bytes.js';
import { generateIdentity, peer, withPublicBytes } from '../web/lib/channel.js';
import {
  approvalRequest, buildHello, channelBody, newOffer, readAnswer, readApproval, RequesterRelay,
} from '../web/lib/requester.js';
import { fingerprint, keyType, verifySignature } from '../web/lib/ssh.js';
import { bind, hostKey, userAuth } from '../web/test/helpers.mjs';

const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const ED25519 = { name: 'Ed25519' };
const PAIR_WINDOW_S = 15 * 60;

function options(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) throw new Error(`unexpected argument ${argv[i]}`);
    out[argv[i].slice(2)] = argv[++i];
  }
  return out;
}

const say = (event) => console.log(JSON.stringify(event));
const save = (file, state) => writeFileSync(file, JSON.stringify(state), { mode: 0o600 });
const exportJwk = (key) => crypto.subtle.exportKey('jwk', key);

async function pair({ relay, state: file, label = 'fake-desktop' }) {
  const enroll = process.env.CLAVIX_ENROLL_SECRET;
  if (!relay || !file) throw new Error('pair needs --relay and --state');
  if (!enroll) throw new Error('set CLAVIX_ENROLL_SECRET to the relay\'s enrolment secret');
  const me = await generateIdentity(true);
  const offer = newOffer();
  const hello = await buildHello({ ch: offer.ch, secret: offer.secret, me, label, nonce: offer.nonce });
  const created = await RequesterRelay.createChannel(relay, enroll, await channelBody(offer, hello));
  if (created !== 'created') throw new Error(`the relay did not create the channel (${created})`);
  say({ event: 'code', code: offer.code, link: `clavix-approve://pair?relay=${relay.replace(/\/+$/, '')}#${offer.code}` });

  const client = new RequesterRelay(relay, offer.ch, offer.token);
  const deadline = Date.now() + PAIR_WINDOW_S * 1000;
  let answer = null;
  while (!answer) {
    if (Date.now() > deadline) throw new Error('no device answered in time');
    answer = await client.pairAnswer(20);
  }
  const device = await readAnswer({ ch: offer.ch, secret: offer.secret, me, answer, nonce: offer.nonce });
  const revealed = await client.reveal(device.signer, offer.nonce);
  if (revealed !== 'revealed') throw new Error(`the relay did not pass the nonce on (${revealed})`);
  save(file, {
    relay,
    ch: offer.ch,
    token: offer.token,
    kem: await exportJwk(me.kem.privateKey),
    sig: await exportJwk(me.sig.privateKey),
    device: {
      signer: device.signer, kem: b64u(device.device.kemPublic), sig: b64u(device.device.sigPublic),
      approve: b64u(device.blob), comment: device.comment,
    },
  });
  say({
    event: 'paired', signer: device.signer, fingerprint: device.fingerprint,
    approveKeyType: keyType(device.blob), comment: device.comment,
  });
}

async function load(file) {
  const state = JSON.parse(readFileSync(file, 'utf8'));
  const publicOf = ({ d, ...jwk }, algorithm, usages) => crypto.subtle.importKey('jwk', jwk, algorithm, true, usages);
  const me = await withPublicBytes(
    {
      privateKey: await crypto.subtle.importKey('jwk', state.kem, ECDH, false, ['deriveBits']),
      publicKey: await publicOf(state.kem, ECDH, []),
    },
    {
      privateKey: await crypto.subtle.importKey('jwk', state.sig, ED25519, false, ['sign']),
      publicKey: await publicOf({ ...state.sig, key_ops: ['verify'] }, ED25519, ['verify']),
    });
  const d = state.device;
  const device = { signer: d.signer, device: peer(unb64u(d.kem), unb64u(d.sig)), blob: unb64u(d.approve) };
  return { state, me, device };
}

// The SSH key the requester signs with, and the algorithm it signs with.
async function ownKey(type) {
  if (type === 'ed25519') return { ...(await hostKey('ed25519')), algorithm: 'ssh-ed25519' };
  if (type === 'rsa') return { ...(await hostKey('rsa')), algorithm: 'rsa-sha2-512' };
  throw new Error(`unknown key type ${type}`);
}

async function request({
  state: file, 'key-type': type = 'ed25519', user = 'deploy', 'withdraw-after': withdrawAfter, t = 'approve',
  ttl = '90',
}) {
  if (!file) throw new Error('request needs --state');
  const { state, me, device } = await load(file);
  const client = new RequesterRelay(state.relay, state.ch, state.token);

  // An SSH login as a client would ask an agent to sign it: our key, for a
  // session the server's host key signed.
  const key = await ownKey(type);
  const host = await hostKey('ed25519');
  const sid = crypto.getRandomValues(new Uint8Array(32));
  const data = userAuth({ sessionId: sid, keyBlob: key.blob, hostKey: host.blob, user, algorithm: key.algorithm });
  const hostFingerprint = await fingerprint(host.blob);
  const envelope = await approvalRequest({
    ch: state.ch, me, device, ttl: Number(ttl), t,
    fields: {
      key: b64u(key.blob), keyName: `${type} key of fake-desktop`, data: b64u(data), flags: 0,
      binds: [await bind(host, sid)], caller: { pid: process.pid, name: 'ssh' }, agent: 'fake-desktop',
      hints: { [hostFingerprint]: 'banc-de-test' },
    },
  });
  const queued = await client.postRequest(envelope);
  say({ event: 'queued', id: envelope.id, state: queued.state, host: hostFingerprint, key: await fingerprint(key.blob) });
  if (queued.state !== 'queued') return;

  let withdrawn = null;
  if (withdrawAfter !== undefined) {
    withdrawn = setTimeout(async () => {
      say({ event: 'withdrawn', id: envelope.id, state: (await client.cancel(envelope.id)).state });
    }, Number(withdrawAfter) * 1000);
  }

  for (;;) {
    const res = await client.response(envelope.id, 20);
    if (!res) continue;
    clearTimeout(withdrawn);
    if (res.state !== 'answered') {
      say({ event: res.state, id: envelope.id });
      return;
    }
    let outcome;
    try {
      outcome = await readApproval({ ch: state.ch, me, device, envelope, msg: res.msg });
    } catch (e) {
      say({ event: 'rejected', id: envelope.id, error: e.message });
      return;
    }
    if (!outcome.ok) {
      say({ event: 'denied', id: envelope.id, reason: outcome.denied });
      return;
    }
    // Approved, and the proof holds: now, and only now, sign.
    const signature = await key.sign(data, key.algorithm === 'rsa-sha2-512' ? 'rsa-sha2-512' : undefined);
    say({
      event: 'approved', id: envelope.id, keyType: keyType(key.blob),
      signatureVerified: await verifySignature(key.blob, data, signature),
    });
    return;
  }
}

const [command, ...rest] = process.argv.slice(2);
const commands = { pair, request };
if (!commands[command]) {
  console.error('usage: fake-desktop.mjs pair|request [options]  (see the header of this file)');
  process.exit(2);
}
commands[command](options(rest)).catch((e) => {
  console.error(`fake-desktop: ${e.message}`);
  process.exit(1);
});
