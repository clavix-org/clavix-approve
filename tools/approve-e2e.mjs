#!/usr/bin/env node
// End-to-end test of approve mode without a phone or Clavix desktop: the
// real relay, tools/fake-desktop.mjs as the requester, tools/fake-phone.mjs
// as the device (both run the page's modules).
//
//   pair in approve mode → approve (Ed25519 and RSA requester keys) →
//   refuse → withdraw while the device waits → a request of the wrong mode
//
//   node tools/approve-e2e.mjs        (needs: python3 with cryptography)

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('..', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'clavix-approve-e2e-'));
const children = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function start(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
  child.output = '';
  child.stdout.on('data', (d) => { child.output += d; });
  child.stderr.on('data', (d) => { child.output += d; });
  child.done = new Promise((resolve) => child.on('close', resolve));
  children.push(child);
  return child;
}

const node = (tool, args, env = process.env) => start(process.execPath, [join(repo, 'tools', tool), ...args], { env });

// The JSON events a tool printed, and the first of a kind.
const events = (child) => child.output.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l));
const event = (child, kind) => events(child).find((e) => e.event === kind);

function freePort() {
  return new Promise((resolve) => {
    const server = createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function until(what, probe, seconds = 30) {
  const deadline = Date.now() + seconds * 1000;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}

function check(condition, message) {
  if (!condition) throw new Error(`check failed: ${message}`);
  console.log(`ok - ${message}`);
}

async function main() {
  const port = await freePort();
  const relay = `http://127.0.0.1:${port}`;
  start('python3', [join(repo, 'relay/relay.py')], {
    env: { ...process.env, RELAY_PORT: String(port), RELAY_STATE_DIR: join(dir, 'relay'),
      RELAY_ENROLL_SECRET: 'approve-e2e', RELAY_PUSH: 'off' },
  });
  await until('relay', () => fetch(`${relay}/healthz`).then((r) => r.ok, () => false));

  const desk = join(dir, 'desktop.json');
  const phone = join(dir, 'phone.json');

  // 1. Pairing in approve mode.
  const pairing = node('fake-desktop.mjs', ['pair', '--relay', relay, '--state', desk, '--label', 'desktop20'],
    { ...process.env, CLAVIX_ENROLL_SECRET: 'approve-e2e' });
  const { code } = await until('the pairing code', () => event(pairing, 'code'));
  const device = node('fake-phone.mjs', ['pair', '--relay', relay, '--state', phone, '--code', code]);
  await device.done;
  const devicePaired = event(device, 'paired');
  check(devicePaired?.mode === 'approve', `the device pairs in the mode the code asks for (${device.output.trim()})`);
  await pairing.done;
  const deskPaired = event(pairing, 'paired');
  check(deskPaired?.fingerprint === devicePaired.fingerprint, `both ends show the same digits (${deskPaired?.fingerprint})`);
  check(deskPaired.approveKeyType === 'ssh-ed25519', 'the requester records an Ed25519 approval key');
  check(devicePaired.publicKey.startsWith('ssh-ed25519 '), 'the device names its approval key, not an SSH key');

  // Ask once: the device runs for one request, the desktop waits for the answer.
  async function round(phoneArgs, requestArgs) {
    const signer = node('fake-phone.mjs', ['run', '--state', phone, '--once', ...phoneArgs]);
    await until('the device', () => event(signer, 'ready'));
    const asker = node('fake-desktop.mjs', ['request', '--state', desk, ...requestArgs]);
    await Promise.all([signer.done, asker.done]);
    return { signer, asker };
  }

  // 2. Approvals, with the two kinds of key the desktop signs with.
  for (const type of ['ed25519', 'rsa']) {
    const { signer, asker } = await round([], ['--key-type', type]);
    const shown = event(signer, 'approved');
    const queued = event(asker, 'queued');
    check(shown?.state === 'accepted' && shown.key === queued.key, `the device shows the requester's ${type} key and approves`);
    check(shown.host === queued.host && shown.user === 'deploy', 'and the verified destination');
    const done = event(asker, 'approved');
    check(done?.signatureVerified === true, `the requester checks the proof, then signs with its ${type} key (${asker.output.trim()})`);
  }

  // 3. A refusal.
  {
    const { asker } = await round(['--deny'], []);
    check(event(asker, 'denied')?.reason === 'user', 'a refusal on the device reaches the requester as one');
  }

  // 4. Withdrawn while the device takes its time: the late approval is
  //    refused by the relay, and the requester never signs.
  {
    const { signer, asker } = await round(['--delay', '3'], ['--withdraw-after', '1']);
    check(event(asker, 'withdrawn')?.state === 'cancelled', 'the requester withdraws the request');
    check(event(asker, 'expired') !== undefined && !event(asker, 'approved'), 'and gets no approval for it');
    check(event(signer, 'approved')?.state === 'expired', 'the late approval gets "expired" from the relay');
  }

  // 5. A sign request on an approve-mode channel.
  {
    const { signer, asker } = await round([], ['--t', 'sign']);
    check(event(signer, 'refused')?.reason === 'malformed', 'the device refuses a request of the other mode');
    check(event(asker, 'denied')?.reason === 'malformed', 'and says so to the requester');
  }

  console.log('\napprove-e2e: all checks passed');
}

let failed = false;
try {
  await main();
} catch (e) {
  failed = true;
  console.error(`\napprove-e2e FAILED: ${e.message}`);
  for (const child of children) console.error(`--- ${child.spawnargs.slice(1).join(' ')}\n${child.output.slice(-1500)}`);
} finally {
  for (const child of children) child.kill();
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch (_) { /* a temporary directory left behind */ }
}
process.exit(failed ? 1 : 0);
