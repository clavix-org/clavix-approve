#!/usr/bin/env node
// Command-line stand-in for the phone, for tests without an iPhone.
//
// It runs the very modules the approval page runs (web/lib), but keeps
// its keys in a plain file and approves without asking anyone. It is a
// test tool: never use it with a key that opens a real server.
//
//   fake-phone.mjs pair --relay URL --state FILE --code CODE
//   fake-phone.mjs run  --state FILE [--deny] [--once]
//   fake-phone.mjs revoke --state FILE
//
// Each prints one JSON line per event on standard output. `run` ends with
// a `revoked` event when the relay no longer knows the pairing.

import { readFileSync, writeFileSync } from 'node:fs';

import { b64u, unb64u } from '../web/lib/bytes.js';
import { generateIdentity, peer, withPublicBytes } from '../web/lib/channel.js';
import { RelayClient, RelayError } from '../web/lib/relay.js';
import { approve, deny, pairWithAgent, readRequest } from '../web/lib/signer.js';
import { p256KeyBlob, p256SignatureBlob, publicKeyLine } from '../web/lib/ssh.js';

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const ED25519 = { name: 'Ed25519' };

function options(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) throw new Error(`unexpected argument ${argv[i]}`);
    const name = argv[i].slice(2);
    if (name === 'deny' || name === 'once') out[name] = true;
    else out[name] = argv[++i];
  }
  return out;
}

const say = (event) => console.log(JSON.stringify(event));
const save = (file, state) => writeFileSync(file, JSON.stringify(state), { mode: 0o600 });
const exportJwk = (key) => crypto.subtle.exportKey('jwk', key);

async function pair({ relay, state: file, code }) {
  if (!relay || !file || !code) throw new Error('pair needs --relay, --state and --code');
  const me = await generateIdentity(true);
  const ssh = await crypto.subtle.generateKey(ECDSA, true, ['sign']);
  const sshJwk = await exportJwk(ssh.privateKey);
  const keyBlob = p256KeyBlob(unb64u(sshJwk.x), unb64u(sshJwk.y));

  const paired = await pairWithAgent({ base: relay, code, me, keyBlob, comment: 'fake-phone' });
  save(file, {
    relay,
    ch: paired.ch,
    signer: paired.signer,
    token: paired.token,
    agent: { kem: b64u(paired.agent.kemPublic), sig: b64u(paired.agent.sigPublic) },
    kem: await exportJwk(me.kem.privateKey),
    sig: await exportJwk(me.sig.privateKey),
    ssh: sshJwk,
    key: b64u(keyBlob),
    pins: {},
  });
  say({
    event: 'paired', agent: paired.label, fingerprint: paired.fingerprint,
    publicKey: publicKeyLine(keyBlob, 'fake-phone'),
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
  return {
    state,
    sshKey: await crypto.subtle.importKey('jwk', state.ssh, ECDSA, false, ['sign']),
    ctx: {
      ch: state.ch,
      signer: state.signer,
      me,
      agent: peer(unb64u(state.agent.kem), unb64u(state.agent.sig)),
      keyBlob: unb64u(state.key),
    },
  };
}

async function run({ state: file, deny: denyAll, once }) {
  if (!file) throw new Error('run needs --state');
  const { state, sshKey, ctx } = await load(file);
  const relay = new RelayClient(state.relay, state.ch, state.token);
  say({ event: 'ready' });

  // Requests left unanswered (unauthentic ones) stay pending at the relay:
  // name them so the long-poll does not return them in a loop.
  const ignored = new Set();
  for (;;) {
    let pending;
    try {
      pending = await relay.requests(20, undefined, [...ignored]);
    } catch (e) {
      if (e instanceof RelayError && e.status === 401) {
        say({ event: 'revoked' });
        return;
      }
      throw e;
    }
    for (const entry of pending) {
      const { id } = entry;
      if (ignored.has(id)) continue;
      const view = await readRequest(ctx, entry, Date.now() / 1000);
      if (!view.ok) {
        const state = await deny(ctx, relay, entry, view.reason);
        if (state === 'ignored') ignored.add(id);
        say({ event: 'refused', id, reason: view.reason, state });
      } else if (denyAll) {
        await deny(ctx, relay, entry, 'user');
        say({ event: 'denied', id });
      } else {
        // Trust on first use, as the page does after an explicit tap.
        const dest = view.hops[view.hops.length - 1];
        const known = Object.hasOwn(state.pins, dest.fingerprint);
        if (!known) {
          state.pins[dest.fingerprint] = view.hints[dest.fingerprint] ?? 'unnamed';
          save(file, state);
        }
        const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sshKey, view.data));
        say({
          event: 'signed', id, state: await approve(ctx, relay, entry, p256SignatureBlob(raw)),
          user: view.user, host: dest.fingerprint, known,
          chain: view.hops.map((h) => ({ host: h.fingerprint, forwarded: h.forwarded })),
          caller: view.caller, agent: view.agent,
        });
      }
      if (once) return;
    }
  }
}

async function revoke({ state: file }) {
  if (!file) throw new Error('revoke needs --state');
  const state = JSON.parse(readFileSync(file, 'utf8'));
  const relay = new RelayClient(state.relay, state.ch, state.token);
  say({ event: 'revoked', deleted: await relay.revoke() });
}

const [command, ...rest] = process.argv.slice(2);
const commands = { pair, run, revoke };
if (!commands[command]) {
  console.error('usage: fake-phone.mjs pair|run|revoke [options]  (see the header of this file)');
  process.exit(2);
}
commands[command](options(rest)).catch((e) => {
  console.error(`fake-phone: ${e.message}`);
  process.exit(1);
});
