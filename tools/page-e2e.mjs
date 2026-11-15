#!/usr/bin/env node
// End-to-end test of the approval page without a phone.
//
// Drives the real page in headless Chrome, with a virtual passkey that
// supports the PRF extension (Chrome DevTools Protocol), against the real
// relay, agent, sshd and ssh:
//
//   set up the key → pair with `clavix-agent pair` → `ssh` asks for a
//   signature → the page shows the verified destination → approve → ssh
//   logs in. Then a second login to the now-known host, and a refusal.
//
// Not covered: Web Push and anything specific to iOS.
//
//   node tools/page-e2e.mjs        (needs: cargo build, google-chrome, sshd)

import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('..', import.meta.url));
const AGENT = join(repo, 'agent/target/debug/clavix-agent');
const CHROME = process.env.CHROME ?? 'google-chrome';
const dir = mkdtempSync(join(tmpdir(), 'clavix-page-e2e-'));
const children = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function start(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
  child.output = '';
  child.stdout.on('data', (d) => { child.output += d; });
  child.stderr.on('data', (d) => { child.output += d; });
  children.push(child);
  return child;
}

function freePort() {
  return new Promise((resolve) => {
    const server = createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function until(what, probe, seconds = 20) {
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

// ---- Chrome DevTools Protocol ---------------------------------------------------

class Browser {
  static async launch() {
    const chrome = start(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=0',
      `--user-data-dir=${join(dir, 'chrome')}`, 'about:blank']);
    const url = await until('Chrome', () => /DevTools listening on (ws:\S+)/.exec(chrome.output)?.[1]);
    const browser = new Browser();
    browser.socket = new WebSocket(url);
    browser.pending = new Map();
    browser.console = [];
    browser.next = 1;
    await new Promise((resolve, reject) => {
      browser.socket.onopen = resolve;
      browser.socket.onerror = reject;
    });
    browser.socket.onmessage = ({ data }) => {
      const msg = JSON.parse(data);
      if (msg.id && browser.pending.has(msg.id)) {
        const { resolve, reject } = browser.pending.get(msg.id);
        browser.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message}`));
        else resolve(msg.result);
      } else if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(msg.params.type)) {
        browser.console.push(msg.params.args.map((a) => a.value ?? a.description).join(' '));
      } else if (msg.method === 'Runtime.exceptionThrown') {
        browser.console.push(msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text);
      } else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
        browser.console.push(msg.params.entry.text);
      }
    };
    return browser;
  }

  send(method, params = {}) {
    const id = this.next++;
    this.socket.send(JSON.stringify({ id, method, params, sessionId: this.session }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  async open(url) {
    const { targetId } = await this.send('Target.createTarget', { url: 'about:blank' });
    this.session = (await this.send('Target.attachToTarget', { targetId, flatten: true })).sessionId;
    await this.send('Runtime.enable');
    await this.send('Log.enable');
    await this.send('Page.enable');
    await this.send('WebAuthn.enable');
    await this.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
      },
    });
    await this.send('Page.navigate', { url });
  }

  // Evaluate an expression in the page, as if from a user gesture.
  async eval(expression) {
    const res = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (res.exceptionDetails) throw new Error(res.exceptionDetails.exception?.description ?? 'page exception');
    return res.result.value;
  }

  text(selector) {
    return this.eval(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? null`);
  }

  click(selector) {
    return this.eval(`document.querySelector(${JSON.stringify(selector)}).click()`);
  }

  type(selector, value) {
    return this.eval(`document.querySelector(${JSON.stringify(selector)}).value = ${JSON.stringify(value)}`);
  }
}

// ---- the bench --------------------------------------------------------------------

function sshd(authorizedKey) {
  const hostKey = join(dir, 'host_key');
  spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', hostKey]);
  const fingerprint = spawnSync('ssh-keygen', ['-lf', `${hostKey}.pub`]).stdout.toString().split(' ')[1];
  writeFileSync(join(dir, 'authorized_keys'), `${authorizedKey}\n`, { mode: 0o600 });
  return freePort().then(async (port) => {
    writeFileSync(join(dir, 'sshd_config'), [
      `Port ${port}`, 'ListenAddress 127.0.0.1', `HostKey ${hostKey}`, 'PidFile none',
      `AuthorizedKeysFile ${join(dir, 'authorized_keys')}`, 'StrictModes no', 'UsePAM no',
      'PasswordAuthentication no', 'KbdInteractiveAuthentication no', '',
    ].join('\n'));
    const daemon = start('/usr/sbin/sshd', ['-D', '-e', '-f', join(dir, 'sshd_config')]);
    await until('sshd', () => /Server listening/.test(daemon.output));
    return { port, fingerprint };
  });
}

// Run ssh in the background; resolves with { ok, stdout } when it ends.
function ssh(socket, port) {
  const child = start('ssh', ['-F', 'none', '-p', String(port), '-o', 'BatchMode=yes', '-o', 'IdentityFile=none',
    '-o', 'PreferredAuthentications=publickey', '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null', '-o', `IdentityAgent=${socket}`, '127.0.0.1', 'echo', 'signed-in']);
  return new Promise((resolve) => child.on('close', (code) => resolve({ ok: code === 0, output: child.output })));
}

async function main() {
  const relayPort = await freePort();
  const origin = `http://localhost:${relayPort}`; // "localhost": a valid passkey domain
  const relayEnv = {
    ...process.env, RELAY_PORT: String(relayPort), RELAY_STATE_DIR: join(dir, 'relay'),
    RELAY_ENROLL_SECRET: 'page-e2e', RELAY_PUSH: 'off',
  };
  start('python3', [join(repo, 'relay/relay.py')], { env: relayEnv });
  await until('relay', () => fetch(`${origin}/healthz`).then((r) => r.ok, () => false));

  const browser = await Browser.launch();
  await browser.open(origin);
  await until('the page', async () => (await browser.text('#status'))?.startsWith('Commencez'));
  check(true, 'the page loads and asks for a key first');

  // 1. Key: one click, the virtual passkey answers both ceremonies.
  await browser.click('#create-key');
  await until('the key', async () => (await browser.text('#key-result'))?.startsWith('Clé créée'));
  const publicKey = await browser.text('#public-key');
  check(/^ecdsa-sha2-nistp256 AAAA\S+ clavix-approve$/.test(publicKey), 'a P-256 public key is displayed');

  // 2. Pairing: the agent prints a code, the page takes it.
  const agentEnv = { ...process.env, CLAVIX_AGENT_DIR: join(dir, 'agent'), CLAVIX_ENROLL_SECRET: 'page-e2e' };
  const pairing = start(AGENT, ['pair', '--yes', '--relay', `http://127.0.0.1:${relayPort}`, '--label', 'banc-de-test'],
    { env: agentEnv });
  const code = await until('the pairing code', () => /cva1-\S+/.exec(pairing.output)?.[0]);
  await browser.type('#pair-code', code);
  await browser.click('#pair');
  const pairResult = await until('the pairing', async () => {
    const text = await browser.text('#pair-result');
    return text && !text.startsWith('Appairage en cours') ? text : null;
  });
  const digits = /(\d{3} \d{3})$/.exec(pairResult)?.[1];
  check(Boolean(digits), `the page is paired (${pairResult})`);
  await until('the agent', () => pairing.output.includes('Paired.'));
  check(pairing.output.includes(digits), 'the agent shows the same verification digits');
  check(pairing.output.includes(publicKey), 'the agent shows the same public key');

  // 3. A login: the page shows what it verified, not what it was told.
  const server = await sshd(publicKey);
  const socket = join(dir, 'agent.sock');
  const agent = start(AGENT, ['run', '--timeout', '30', '--socket', socket], { env: agentEnv });
  await until('the agent socket', () => agent.output.includes('listening'));

  let login = ssh(socket, server.port);
  await until('a request on the page', () => browser.text('.request'));
  const user = userInfo().username;
  check((await browser.text('.request .destination')) === `${user}@ hôte inconnu`, 'the unknown host is announced as such');
  check((await browser.text('.request .fingerprint')) === server.fingerprint, "the fingerprint is the server's own");
  check((await browser.eval("document.querySelector('.request').classList.contains('unknown')")), 'with the warning style');
  check((await browser.text('.request .facts')).includes('ssh') && (await browser.text('.request .facts')).includes('banc-de-test'),
    'caller and machine are shown, labelled unverified');

  // Approving an unknown host requires naming it.
  await browser.click('.request .actions button:last-child');
  await until('the refusal to approve unnamed', async () => (await browser.text('.request .progress'))?.includes('donnez un nom'));
  await browser.type('.request input', 'serveur-de-test');
  await browser.click('.request .actions button:last-child');
  let outcome = await login;
  check(outcome.ok && outcome.output.includes('signed-in'), 'ssh logs in after the approval');
  await until('the card to go', async () => (await browser.text('.request')) === null);
  check((await browser.text('#pins')).includes('serveur-de-test'), 'the host is now pinned under the chosen name');

  // 4. Same host again: named, no warning.
  login = ssh(socket, server.port);
  await until('a second request', () => browser.text('.request'));
  check((await browser.text('.request .destination')) === `${user}@serveur-de-test`, 'the known host is shown by its pinned name');
  check(!(await browser.eval("document.querySelector('.request').classList.contains('unknown')")), 'without warning');
  await browser.click('.request .actions button:last-child');
  outcome = await login;
  check(outcome.ok, 'ssh logs in again');

  // 5. A refusal (after the agent's back-off window following… none yet).
  await until('the card to go', async () => (await browser.text('.request')) === null);
  login = ssh(socket, server.port);
  await until('a third request', () => browser.text('.request'));
  await browser.click('.request .actions button:first-child');
  outcome = await login;
  check(!outcome.ok, 'ssh fails when the request is refused');
  await until('the journal', async () => (await browser.text('#journal'))?.includes('Refusé'));
  const journal = await browser.text('#journal');
  check(journal.includes('Approuvé') && journal.includes('Refusé'), 'the journal records approvals and the refusal');

  // 6. State survives a reload (tapping a notification may reload the page).
  await browser.send('Page.reload');
  await until('the page after reload', async () => (await browser.text('#status'))?.startsWith('Prêt'));
  check((await browser.text('#public-key')) === publicKey, 'key, pairing and pins survive a reload');

  // 7. The relay lost its state, or the agent was reinstalled: pairing
  //    again keeps the SSH key, so servers need no change.
  const again = start(AGENT, ['pair', '--yes', '--relay', `http://127.0.0.1:${relayPort}`], { env: agentEnv });
  const secondCode = await until('a second pairing code', () => /cva1-\S+/.exec(again.output)?.[0]);
  await browser.click('#pair-again');
  await browser.type('#pair-code', secondCode);
  await browser.click('#pair');
  await until('the second pairing', () => again.output.includes('Paired.'));
  check(again.output.includes(publicKey), 'pairing again keeps the same SSH public key');
  await until('the page after pairing again', async () => (await browser.text('#status'))?.startsWith('Prêt'));

  const noise = browser.console.filter((line) => !/apple-mobile-web-app-capable/.test(line));
  check(noise.length === 0, `no console error or CSP violation${noise.length ? `: ${noise.join(' | ')}` : ''}`);
  console.log('\npage-e2e: all checks passed');
}

let failed = false;
try {
  await main();
} catch (e) {
  failed = true;
  console.error(`\npage-e2e FAILED: ${e.message}`);
  for (const child of children) {
    if (child.output && /relay|clavix-agent|sshd/.test(child.spawnfile)) console.error(`--- ${child.spawnfile}\n${child.output.slice(-1500)}`);
  }
} finally {
  for (const child of children) child.kill();
  await sleep(200);
  rmSync(dir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
