import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { b64u, hex, sha256, utf8 } from '../lib/bytes.js';
import { pairToken, parsePairingCode } from '../lib/pairing.js';
import { checkApproveRequest, checkSignRequest, deniedResponse, label, signedResponse, tokenAuth } from '../lib/protocol.js';
import { fingerprint } from '../lib/ssh.js';
import { bind, clientKey, hostKey, userAuth } from './helpers.mjs';

const NOW = 1_800_000_000;
const ID = 'ab'.repeat(16);
const SID = utf8('exchange-hash-of-the-session');

// A request an honest agent would send for `ssh deploy@host`.
async function scene(overrides = {}) {
  const key = await clientKey();
  const host = await hostKey('ed25519');
  const inner = {
    t: 'sign', id: ID, iat: NOW - 1, exp: NOW + 90,
    key: b64u(key.blob),
    data: b64u(userAuth({ sessionId: SID, keyBlob: key.blob, hostKey: host.blob })),
    flags: 0,
    binds: [await bind(host, SID)],
    caller: { pid: 4242, name: 'ssh' },
    agent: 'build-box',
    hints: {},
    ...overrides,
  };
  return { key, host, inner, check: (i = inner) => checkSignRequest(i, { id: ID, keyBlob: key.blob, now: NOW }) };
}

test('an honest request yields the verified destination', async () => {
  const { host, inner, check } = await scene();
  inner.hints[await fingerprint(host.blob)] = 'prod.example';
  const result = await check();
  assert.equal(result.ok, true);
  assert.equal(result.user, 'deploy');
  assert.equal(result.hops.length, 1);
  assert.equal(result.hops[0].fingerprint, await fingerprint(host.blob));
  assert.equal(result.hops[0].forwarded, false);
  assert.deepEqual(result.caller, { pid: 4242, name: 'ssh' });
  assert.equal(result.agent, 'build-box');
  assert.deepEqual(result.hints, { [await fingerprint(host.blob)]: 'prod.example' });
  assert.equal(b64u(result.data), inner.data);
});

test('a request without host-bound data is refused, even for the bound session', async () => {
  const { key, inner, check } = await scene();
  inner.data = b64u(userAuth({ sessionId: SID, keyBlob: key.blob }));
  assert.deepEqual(await check(), { ok: false, reason: 'unverified' });
});

// testdata/hostbound.json, shared with the agent and the iOS tests: the
// two audit scenarios (a forwarded hostile host, a compromised agent
// holding a pinned host key) and the valid host-bound cases, checked in
// both modes.
test('the shared host-bound vectors', async () => {
  const v = JSON.parse(readFileSync(new URL('../../testdata/hostbound.json', import.meta.url), 'utf8'));
  const keyBlob = new Uint8Array(Buffer.from(v.key, 'base64url'));
  for (const c of v.cases) {
    const inner = { t: 'sign', id: v.id, iat: v.now - 1, exp: v.exp, key: v.key, data: c.data, flags: 0,
      binds: c.binds, caller: null, agent: 'vector', hints: {} };
    for (const view of [
      await checkSignRequest(inner, { id: v.id, keyBlob, now: v.now }),
      await checkApproveRequest({ ...inner, t: 'approve' }, { id: v.id, now: v.now }),
    ]) {
      if (c.ok) {
        assert.equal(view.ok, true, c.name);
        assert.equal(view.hops.at(-1).fingerprint, c.destination, c.name);
        assert.equal(view.hops.length, c.binds.length, c.name);
      } else {
        assert.deepEqual(view, { ok: false, reason: 'unverified' }, c.name);
      }
    }
  }
});

test('a forwarding chain is shown whole, outermost first', async () => {
  const { host, inner, check } = await scene();
  const jump = await hostKey('P-256');
  inner.binds = [await bind(jump, utf8('jump-session'), true), await bind(host, SID)];
  const result = await check();
  assert.equal(result.ok, true);
  assert.deepEqual(result.hops.map((h) => h.forwarded), [true, false]);
  assert.equal(result.hops[0].fingerprint, await fingerprint(jump.blob));
});

// The agent's machine is compromised and wants a signature for a server
// the user is not looking at.
test('a falsified destination is refused', async (t) => {
  const forged = async (name, mutate) => {
    await t.test(name, async () => {
      const s = await scene();
      await mutate(s);
      assert.deepEqual(await s.check(), { ok: false, reason: 'unverified' });
    });
  };

  await forged('binding signed by another key than the one named', async ({ inner }) => {
    const impostor = await hostKey('ed25519');
    inner.binds[0].sig = b64u(await impostor.sign(SID));
  });
  await forged('host key swapped for a friendly-looking one', async ({ inner }) => {
    inner.binds[0].hostkey = b64u((await hostKey('ed25519')).blob);
  });
  await forged('real binding of a trusted host, login data of another session', async ({ key, host, inner }) => {
    inner.data = b64u(userAuth({ sessionId: utf8('session-with-the-real-target'), keyBlob: key.blob, hostKey: host.blob }));
  });
  await forged('login data naming another host key than the binding', async ({ key, inner }) => {
    const other = await hostKey('ed25519');
    inner.data = b64u(userAuth({ sessionId: SID, keyBlob: key.blob, hostKey: other.blob }));
  });
  await forged('a trusted binding appended after the real one', async ({ host, inner }) => {
    const trusted = await hostKey('ed25519');
    inner.binds = [await bind(host, SID), await bind(trusted, utf8('other'))];
  });
  await forged('a forwarding binding passed off as the destination', async ({ host, inner }) => {
    inner.binds = [await bind(host, SID, true)];
  });
  await forged('no binding at all', async ({ inner }) => {
    inner.binds = [];
  });
  await forged('more hops than any real chain', async ({ host, inner }) => {
    const hop = await bind(host, utf8('h'), true);
    inner.binds = [...Array(16).fill(hop), await bind(host, SID)];
  });
  await forged('data that is not a login (commit signing)', async ({ inner }) => {
    inner.data = b64u(utf8('SSHSIG\0\0\0\x01'));
  });
  await forged('a login for another service', async ({ key, host, inner }) => {
    inner.data = b64u(userAuth({ sessionId: SID, keyBlob: key.blob, hostKey: host.blob, service: 'ssh-userauth' }));
  });
  await forged('a login made with another client key', async ({ host, inner }) => {
    const other = await clientKey();
    inner.data = b64u(userAuth({ sessionId: SID, keyBlob: other.blob, hostKey: host.blob }));
  });
});

test('other refusals carry their own reason', async () => {
  const other = await clientKey();
  let s = await scene({ key: b64u(other.blob) });
  assert.deepEqual(await s.check(), { ok: false, reason: 'unknown-key' });
  s = await scene({ exp: NOW });
  assert.deepEqual(await s.check(), { ok: false, reason: 'expired' });
  s = await scene({ id: 'cd'.repeat(16) });
  assert.deepEqual(await s.check(), { ok: false, reason: 'malformed' });
  s = await scene({ t: 'pair' });
  assert.deepEqual(await s.check(), { ok: false, reason: 'malformed' });
  s = await scene({ data: 'not base64 !' });
  assert.deepEqual(await s.check(), { ok: false, reason: 'malformed' });
  s = await scene();
  s.inner.binds[0].fwd = 0;
  assert.deepEqual(await s.check(), { ok: false, reason: 'malformed' });
  assert.deepEqual(await s.check(null), { ok: false, reason: 'malformed' });
});

test('text from the agent is cleaned before display, and hints are limited to the chain', async () => {
  const { host, inner, check } = await scene();
  const fp = await fingerprint(host.blob);
  inner.caller = { pid: 'x', name: 'ssh\n‮evil\u0007' };
  inner.agent = 'a'.repeat(200);
  inner.hints = { [fp]: 'prod\r\nApprove!', 'SHA256:somethingelse': 'bank' };
  const result = await check();
  assert.deepEqual(result.caller, { pid: null, name: 'sshevil' });
  assert.equal(result.agent.length, 64);
  assert.deepEqual(result.hints, { [fp]: 'prodApprove!' });

  assert.equal(label('  plain  '), 'plain');
  assert.equal(label('​\n'), null);
  assert.equal(label(42), null);
});

test('responses name the request they answer', async () => {
  const request = 'the request exactly as the relay delivered it';
  const req = b64u(await sha256(utf8(request)));
  assert.deepEqual(await signedResponse(request, ID, utf8('sig')), { id: ID, req, t: 'signed', sig: b64u(utf8('sig')) });
  assert.deepEqual(await deniedResponse(request, ID, 'user'), { id: ID, req, t: 'denied', reason: 'user' });
});

test('pairing code and tokens match the agent side', async () => {
  const raw = new Uint8Array(32).fill(0xab, 0, 16).fill(0xcd, 16);
  const { ch, secret } = parsePairingCode(` cva1-${b64u(raw)}\n`);
  assert.equal(ch, 'ab'.repeat(16));
  assert.equal(hex(secret), 'cd'.repeat(16));
  assert.throws(() => parsePairingCode(b64u(raw)));
  assert.throws(() => parsePairingCode('cva1-AAAA'));
  assert.throws(() => parsePairingCode('cva1-not base64'));

  // Same vector as the Rust test (agent/src/pairing.rs).
  const vector = readFileSync(new URL('../../testdata/pair-token-07.txt', import.meta.url), 'utf8').trim();
  assert.equal(await pairToken(new Uint8Array(16).fill(7)), vector);
  assert.equal(await tokenAuth('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
