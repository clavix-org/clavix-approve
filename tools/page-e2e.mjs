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
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('..', import.meta.url));
const AGENT = join(repo, 'target/debug/clavix-agent');
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
    browser.requests = [];
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
      } else if (msg.method === 'Network.requestWillBeSent') {
        browser.requests.push({ at: Date.now(), url: msg.params.request.url });
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
    await this.send('Network.enable');
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
    // The machine knows this server, under a hashed name as on Debian:
    // the agent can only name it from what `ssh` is asked to reach.
    const knownHosts = join(dir, 'home/.ssh/known_hosts');
    mkdirSync(join(dir, 'home/.ssh'), { recursive: true });
    const [type, key] = readFileSync(`${hostKey}.pub`, 'utf8').split(' ');
    writeFileSync(knownHosts, `[127.0.0.1]:${port} ${type} ${key}\n`);
    spawnSync('ssh-keygen', ['-H', '-f', knownHosts]);
    rmSync(`${knownHosts}.old`, { force: true });
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
  await until('the version', async () => (await browser.text('#version')) === 'Version dev');
  check(true, 'the page loads and asks for a key first');
  // The digits of a pairing answered but not confirmed yet, once shown.
  const pendingDigits = async () => ((await browser.eval("document.querySelector('#pair-check').hidden")) === false
    ? browser.text('#pair-digits') : null);

  // 1. Key: one click, the virtual passkey answers both ceremonies.
  await browser.click('#create-key');
  await until('the key', async () => (await browser.text('#key-result'))?.startsWith('Clé créée'));
  const publicKey = await browser.text('#public-key');
  check(/^ecdsa-sha2-nistp256 AAAA\S+ clavix-approve$/.test(publicKey), 'a P-256 public key is displayed');

  // 2. Pairing: the agent prints a code, the page takes it.
  const agentEnv = { ...process.env, HOME: join(dir, 'home'), CLAVIX_AGENT_DIR: join(dir, 'agent'), CLAVIX_ENROLL_SECRET: 'page-e2e' };
  const pairing = start(AGENT, ['pair', '--yes', '--relay', `http://127.0.0.1:${relayPort}`, '--label', 'banc-de-test'],
    { env: agentEnv });
  const code = await until('the pairing code', () => /cva2-\S+/.exec(pairing.output)?.[0]);
  check(pairing.output.includes(`clavix-approve://pair?relay=http://127.0.0.1:${relayPort}#${code}`),
    'the link for the QR code opens the app, never a page of the relay');
  await browser.type('#pair-code', code);
  await browser.click('#pair');
  const digits = await until('the digits to compare', pendingDigits);
  check(/^\d{3} \d{3}$/.test(digits), `the page shows six digits (${digits})`);
  await until('the agent', () => pairing.output.includes('Paired.'));
  check(pairing.output.includes(digits), 'the agent shows the same verification digits');
  check(pairing.output.includes(publicKey), 'the agent shows the same public key');
  check(!(await browser.text('#status'))?.startsWith('Prêt'), 'unconfirmed, the pairing is not in use yet');
  await browser.click('#pair-confirm');
  const pairResult = await until('the pairing', async () => {
    const text = await browser.text('#pair-result');
    return text?.startsWith('Appairé') ? text : null;
  });
  check(pairResult.endsWith(digits), `the page is paired once the digits are confirmed (${pairResult})`);

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

  // A request left on screen must not make the page hammer the relay
  // (a proxy in front would throttle it, then ban the phone).
  const since = Date.now();
  await sleep(4000);
  const polls = browser.requests.filter((r) => r.at >= since && r.url.includes('/requests')).length;
  check(polls <= 2, `the page stays quiet while a request waits (${polls} polls in 4 s)`);

  // Approving an unknown host requires naming it.
  await browser.click('.request .actions button:last-child');
  await until('the refusal to approve unnamed', async () => (await browser.text('.request .progress'))?.includes('donnez un nom'));
  // The machine's name for it is offered, and taken only on request.
  const suggested = `[127.0.0.1]:${server.port}`;
  check((await browser.text('.request .suggestion')).includes(suggested), 'the name from the hashed known_hosts is suggested');
  check((await browser.eval("document.querySelector('.request input').value")) === '', 'but not filled in');
  await browser.click('.request .suggestion button');
  check((await browser.eval("document.querySelector('.request input').value")) === suggested, 'one tap takes the suggestion');
  await browser.eval("document.querySelector('.request input').value = ''");
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
  const secondCode = await until('a second pairing code', () => /cva2-\S+/.exec(again.output)?.[0]);
  await browser.click('#pair-again');
  check(!(await browser.eval("document.querySelector('#setup').hidden")), 'the pairing step is shown again');
  await browser.type('#pair-code', secondCode);
  await browser.click('#pair');
  const secondDigits = await until('the second digits', pendingDigits);
  await until('the second pairing', () => again.output.includes('Paired.'));
  check(again.output.includes(secondDigits), 'the agent shows the same digits again');
  check(again.output.includes(publicKey), 'pairing again keeps the same SSH public key');
  await browser.click('#pair-confirm');
  await until('the page after pairing again', async () => (await browser.text('#status'))?.startsWith('Prêt'));

  const api = browser.requests.filter((r) => r.url.includes('/api/'));
  const windows = api.map((r) => api.filter((o) => o.at >= r.at && o.at < r.at + 1000));
  const peak = windows.reduce((a, b) => (b.length > a.length ? b : a), []);
  check(peak.length <= 4, `never more than 4 API calls in any second (peak ${peak.length}${
    peak.length > 4 ? `: ${peak.map((r) => `${r.at - peak[0].at}ms ${new URL(r.url).pathname.replace(/[0-9a-f]{32}/g, '…')}`).join(', ')}` : ''})`);

  // 9. Revocation from the machine: the page says so, and forgetting the
  //    machine there clears the pairing but keeps the key.
  await until('the agent to revoke the replaced pairing', () => again.output.includes('The previous pairing was revoked.')
    || again.output.includes('could not revoke the previous pairing'));
  check(again.output.includes('The previous pairing was revoked.'), 'pairing again revokes the replaced pairing');
  const unpair = start(AGENT, ['unpair'], { env: agentEnv });
  await until('the agent to unpair', () => unpair.output.includes('Pairing forgotten'));
  check(unpair.output.includes('Pairing revoked on the relay.'), 'clavix-agent unpair revokes the pairing on the relay');
  await until('the page to notice', async () => (await browser.text('#status'))?.includes('a été retirée'));
  check(true, 'the page says the machine was removed');
  check(!(await browser.eval("document.querySelector('#forget').hidden")), 'and offers to forget it');
  await browser.click('#forget');
  check((await browser.text('#forget')) === 'Toucher encore pour confirmer', 'forgetting asks for a second touch');
  await browser.click('#forget');
  await until('the pairing to be forgotten', async () => (await browser.eval("document.querySelector('#forget').hidden")) === true);
  check((await browser.text('#journal')).includes('déjà révoqué'), 'the journal records that it was already revoked');
  check((await browser.text('#public-key')) === publicKey, 'the SSH key stays after forgetting the machine');
  check((await browser.text('#status')).startsWith('Clé prête'), 'and the page asks for a new pairing');

  // 10. Approve mode, with tools/fake-desktop.mjs in Clavix desktop's place.
  //     A page set up before approve mode has no approval key: drop it to
  //     go through that path, where the passkey makes one when first needed.
  await browser.eval(`new Promise((resolve, reject) => {
    const open = indexedDB.open('clavix-approve', 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('kv', 'readwrite');
      tx.objectStore('kv').delete('approveKey');
      tx.oncomplete = () => { open.result.close(); resolve(true); };
      tx.onerror = () => reject(tx.error);
    };
  })`);
  await browser.send('Page.reload');
  await until('the page without an approval key', async () => (await browser.text('#status'))?.startsWith('Clé prête'));
  const desktopState = join(dir, 'fake-desktop.json');
  const tool = (name, args, env = process.env) => start(process.execPath, [join(repo, 'tools', name), ...args], { env });
  const jsonEvent = (child, kind) => child.output.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l))
    .find((e) => e.event === kind);
  const closed = (child) => new Promise((resolve) => (child.exitCode !== null ? resolve() : child.on('close', resolve)));
  const desktop = tool('fake-desktop.mjs', ['pair', '--relay', `http://127.0.0.1:${relayPort}`, '--state', desktopState,
    '--label', 'bureau-de-test'], { ...process.env, CLAVIX_ENROLL_SECRET: 'page-e2e' });
  const approveCode = (await until('an approve-mode code', () => jsonEvent(desktop, 'code'))).code;
  await browser.type('#pair-code', approveCode);
  await browser.click('#pair');
  await until('the offer of an approval key', async () => (await browser.eval("document.querySelector('#approve-key').hidden")) === false);
  check((await browser.text('#pair-result')).includes('validation seulement'), 'an approve-mode code asks for an approval key first');
  await browser.click('#approve-key');
  const approveDigits = await until('the approve-mode digits', pendingDigits);
  await closed(desktop);
  const desktopPaired = jsonEvent(desktop, 'paired');
  check(desktopPaired && approveDigits === desktopPaired.fingerprint,
    `page and requester show the same digits (${desktopPaired?.fingerprint})`);
  await browser.click('#pair-confirm');
  await until('the approve-mode pairing', async () => (await browser.text('#pair-result'))?.startsWith('Appairé'));
  check(desktopPaired.approveKeyType === 'ssh-ed25519', 'the page answers with an Ed25519 approval key');
  check((await browser.text('#journal')).includes('Clé de validation créée'), 'made under the passkey when first needed');
  check((await browser.text('#pairing-info')).includes('validation seulement'), 'the pairing is shown as approve mode');

  const ask = (...args) => tool('fake-desktop.mjs', ['request', '--state', desktopState, ...args]);
  let asking = ask('--key-type', 'rsa');
  await until('an approval request on the page', () => browser.text('.request'));
  const queued = await until('the request', () => jsonEvent(asking, 'queued'));
  check((await browser.text('.request .destination')) === 'deploy@ hôte inconnu', 'the page shows the verified destination');
  check((await browser.text('.request .facts')).includes(`Clé de la machine, d’après elle : rsa key of fake-desktop (${queued.key})`),
    "and the machine's own key, labelled as the machine's word");
  await browser.type('.request input', 'serveur-du-bureau');
  await browser.click('.request .actions button:last-child');
  await closed(asking);
  check(jsonEvent(asking, 'approved')?.signatureVerified === true,
    `the requester checks the page's proof, then signs with its own key (${asking.output.trim()})`);
  await until('the card to go', async () => (await browser.text('.request')) === null);

  // A request withdrawn on the machine leaves the page by itself.
  asking = ask('--withdraw-after', '3');
  await until('a request to withdraw', () => browser.text('.request'));
  await until('the withdrawn request to leave', async () => (await browser.text('.request')) === null);
  await closed(asking);
  check(jsonEvent(asking, 'withdrawn')?.state === 'cancelled' && !jsonEvent(asking, 'approved'),
    'a withdrawn request leaves the page unanswered');

  // A sign request on this channel is refused without asking anyone.
  asking = ask('--t', 'sign');
  await closed(asking);
  check(jsonEvent(asking, 'denied')?.reason === 'malformed', 'a request of the other mode is refused as malformed');
  check((await browser.text('#journal')).includes('Demande écartée (malformed'), 'and the journal says so');

  // 8. A code in the page's address is not taken: pairing secrets never
  //    reach a page the relay serves by a link.
  const main = browser.session;
  browser.session = undefined; // browser-level commands
  const { browserContextId } = await browser.send('Target.createBrowserContext');
  const { targetId } = await browser.send('Target.createTarget', { url: `${origin}/#cva2-${'A'.repeat(43)}`, browserContextId });
  browser.session = (await browser.send('Target.attachToTarget', { targetId, flatten: true })).sessionId;
  await browser.send('Runtime.enable');
  await until('the page in another browser', async () => (await browser.text('#status'))?.startsWith('Commencez'));
  check((await browser.eval("document.querySelector('#pair-code').value")) === '', 'a code in the address is ignored');
  browser.session = main;

  // The 401s are step 9's: a revoked pairing is told by the relay that way
  // (the long-poll, forgetting an already revoked machine, and the replaced
  // channel the agent revoked first). Chrome logs each failed load.
  const noise = browser.console.filter((line) => !/apple-mobile-web-app-capable/.test(line)
    && !/status of 401 \(Unauthorized\)/.test(line));
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
  // Chrome may still be writing its profile after the kill: retry, and never
  // let the cleanup turn a passing run into a failure.
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch (e) {
    console.error(`page-e2e: could not remove ${dir}: ${e.message}`);
  }
}
process.exit(failed ? 1 : 0);
