// The approval page: set-up, then one screen per signature request.
//
// Everything security-relevant is in lib/ (and tested there under Node).
// This file only stores state, calls the passkey and draws.

import { equal, unb64u } from './lib/bytes.js';
import { generateIdentity, peer, withPublicBytes } from './lib/channel.js';
import { createPasskey, createWrappedKey, signWithWrappedKey, unlock } from './lib/lock.js';
import { PAIR_CODE_PREFIX } from './lib/pairing.js';
import { RelayClient, RelayError } from './lib/relay.js';
import { approve, deny, pairWithAgent, readRequest } from './lib/signer.js';
import { publicKeyLine } from './lib/ssh.js';
import * as store from './lib/store.js';

const $ = (id) => document.getElementById(id);
const RP_ID = location.hostname;
const COMMENT = 'clavix-approve';
const JOURNAL_SIZE = 60;

// Persistent state, loaded from the store at start.
const state = {
  identity: null,   // { kem, sig } CryptoKey pairs, non-extractable
  credentialId: null,
  sshKey: null,     // { keyBlob, iv, ct }
  pairing: null,    // { ch, signer, token, agentKem, agentSig, label, fingerprint }
  pins: {},         // host key fingerprint -> name chosen on this device
  journal: [],      // [{ at, text }]
};
// Derived at start and after pairing.
let ctx = null;     // what lib/signer.js needs
let relay = null;
const cards = new Map(); // request id -> { entry, view, element, busy }
let polling = null;      // AbortController of the running long-poll
let repairing = false;   // the user asked to pair again

// ---- small helpers -----------------------------------------------------------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function status(text, isError = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', isError);
}

function result(id, text, kind = '') {
  $(id).textContent = text;
  $(id).className = `result ${kind}`;
}

function describe(error) {
  if (error instanceof RelayError) {
    return error.status === 401 ? 'le relais ne reconnaît pas cet appareil' : `le relais a répondu ${error.status}`;
  }
  if (error && error.name === 'NotAllowedError') return 'validation annulée ou refusée';
  return (error && error.message) || String(error);
}

async function journal(text) {
  state.journal.unshift({ at: Date.now(), text });
  state.journal.length = Math.min(state.journal.length, JOURNAL_SIZE);
  await store.set('journal', state.journal);
  drawDetails();
}

// Run `fn` on click, with the button disabled meanwhile.
function onClick(id, fn) {
  $(id).addEventListener('click', async () => {
    $(id).disabled = true;
    try {
      await fn();
    } finally {
      $(id).disabled = false;
    }
  });
}

const standalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const hostName = (fingerprint) => (Object.hasOwn(state.pins, fingerprint) ? state.pins[fingerprint] : null);

// ---- set-up -------------------------------------------------------------------

async function finishKey(secret) {
  const wrapped = await createWrappedKey(secret);
  secret.fill(0);
  state.sshKey = wrapped;
  await store.set('sshKey', wrapped);
  await journal('Clé de signature créée');
}

async function createKey() {
  try {
    result('key-result', 'En attente de la passkey…');
    const created = await createPasskey(navigator.credentials, RP_ID);
    state.credentialId = created.credentialId;
    await store.set('credentialId', created.credentialId);
    // Most authenticators only give the secret on a later request.
    const secret = created.secret ?? await unlock(navigator.credentials, RP_ID, created.credentialId);
    await finishKey(secret);
    result('key-result', 'Clé créée et verrouillée par la passkey.', 'ok');
  } catch (e) {
    result('key-result', state.credentialId
      ? `Passkey créée, clé pas encore protégée : ${describe(e)}.`
      : `Échec : ${describe(e)}.`, 'error');
  }
  draw();
}

async function protectKey() {
  try {
    result('key-result', 'En attente de la passkey…');
    await finishKey(await unlock(navigator.credentials, RP_ID, state.credentialId));
    result('key-result', 'Clé créée et verrouillée par la passkey.', 'ok');
  } catch (e) {
    result('key-result', `Échec : ${describe(e)}.`, 'error');
  }
  draw();
}

async function pair() {
  try {
    result('pair-result', 'Appairage en cours…');
    if (!state.identity) {
      const id = await generateIdentity();
      state.identity = { kem: id.kem, sig: id.sig };
      await store.set('identity', state.identity);
    }
    const me = await withPublicBytes(state.identity.kem, state.identity.sig);
    const paired = await pairWithAgent({
      base: '', code: $('pair-code').value, me, keyBlob: state.sshKey.keyBlob, comment: COMMENT,
    });
    state.pairing = {
      ch: paired.ch,
      signer: paired.signer,
      token: paired.token,
      agentKem: paired.agent.kemPublic,
      agentSig: paired.agent.sigPublic,
      label: paired.label,
      fingerprint: paired.fingerprint,
    };
    await store.set('pairing', state.pairing);
    repairing = false;
    stopWatching();
    cards.forEach((_, id) => removeCard(id));
    $('pair-code').value = '';
    await journal(`Appairé avec ${paired.label || 'un agent'}`);
    await connect();
    result('pair-result', `Appairé. Chiffres à comparer avec ceux de l’agent : ${paired.fingerprint}`, 'ok');
  } catch (e) {
    result('pair-result', `Échec : ${describe(e)}.`, 'error');
  }
  draw();
}

async function subscription() {
  const registration = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  const { key } = await (await fetch('/api/vapid-public-key', { cache: 'no-store' })).json();
  const serverKey = unb64u(key);
  const existing = await registration.pushManager.getSubscription();
  if (existing) {
    // A subscription is tied to the relay's push key: if the relay lost
    // its state and made a new one, the old subscription is dead.
    const boundTo = existing.options && existing.options.applicationServerKey;
    if (!boundTo || equal(new Uint8Array(boundTo), serverKey)) return existing;
    await existing.unsubscribe();
  }
  return registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: serverKey });
}

async function enableNotifications() {
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
      throw new Error('indisponibles ici ; ouvrez la page depuis l’icône de l’écran d’accueil');
    }
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') throw new Error('autorisation refusée');
    await relay.subscribe((await subscription()).toJSON());
    await store.set('notified', true);
    result('notify-result', 'Notifications activées.', 'ok');
    await journal('Notifications activées');
  } catch (e) {
    result('notify-result', `Échec : ${describe(e)}.`, 'error');
  }
  draw();
}

// The subscription may change without notice: send it again at each start.
async function refreshSubscription() {
  if (!relay || !('Notification' in window) || Notification.permission !== 'granted'
      || !('serviceWorker' in navigator) || !('PushManager' in window)) return;
  try {
    await relay.subscribe((await subscription()).toJSON());
  } catch (_) { /* tried again at the next start */ }
}

// ---- requests -----------------------------------------------------------------

async function connect() {
  if (!state.pairing || !state.sshKey || !state.identity) return;
  const me = await withPublicBytes(state.identity.kem, state.identity.sig);
  ctx = {
    ch: state.pairing.ch,
    signer: state.pairing.signer,
    me,
    agent: peer(state.pairing.agentKem, state.pairing.agentSig),
    keyBlob: state.sshKey.keyBlob,
  };
  relay = new RelayClient('', state.pairing.ch, state.pairing.token);
  watch();
}

// Whatever happens, never more than one call per second to the relay: a
// proxy in front may throttle, and ban a client that keeps hitting it.
const MIN_GAP_MS = 1000;
let lastCall = 0;

async function paced(signal) {
  const due = lastCall + MIN_GAP_MS - Date.now();
  if (due > 0) await new Promise((r) => setTimeout(r, due));
  if (signal.aborted) throw new DOMException('aborted', 'AbortError');
  lastCall = Date.now();
}

// 4xx other than "slow down" means our pairing is gone: stop for good.
const isFatal = (e) => e instanceof RelayError && e.status >= 400 && e.status < 500 && e.status !== 429;

// Long-poll the relay while the page is visible; stop when it is hidden.
async function watch() {
  if (polling || !relay || document.visibilityState !== 'visible') return;
  const controller = new AbortController();
  polling = controller;
  let wait = 0;    // the first call returns at once
  let backoff = 0; // seconds, grows on consecutive failures
  while (!controller.signal.aborted) {
    try {
      await paced(controller.signal);
      // Tell the relay what we already show, so it only answers on news.
      await show(await relay.requests(wait, controller.signal, [...cards.keys()]));
      status(cards.size ? '' : 'Prêt. En attente de demandes.');
      wait = 20;
      backoff = 0;
    } catch (e) {
      if (controller.signal.aborted) break;
      if (isFatal(e)) {
        status(`Arrêt : ${describe(e)}. Si cela persiste, appairez à nouveau.`, true);
        break;
      }
      // Throttled, proxy error or network trouble: wait longer each time.
      // Requests already on screen stay usable meanwhile.
      backoff = Math.min(backoff ? backoff * 2 : 5, 60);
      status(e instanceof RelayError && e.status === 429
        ? `Trop de requêtes, reprise dans ${backoff} s.`
        : `Relais injoignable, nouvel essai dans ${backoff} s.`, true);
      await new Promise((r) => setTimeout(r, backoff * 1000));
    }
  }
  if (polling === controller) polling = null;
}

function stopWatching() {
  if (polling) polling.abort();
  polling = null;
}

async function show(entries) {
  const now = Date.now() / 1000;
  const live = new Set(entries.map((e) => e.id));
  for (const [id, card] of cards) {
    if (!live.has(id) && !card.busy) removeCard(id);
  }
  for (const entry of entries) {
    if (cards.has(entry.id)) continue;
    const view = await readRequest(ctx, entry, now);
    if (!view.ok) {
      // Nothing trustworthy to show: refuse without asking.
      cards.set(entry.id, { entry, view, element: null, busy: false });
      const sent = await deny(ctx, relay, entry, view.reason).catch(() => 'not sent');
      await journal(`Demande écartée (${view.reason}, ${sent})`);
      continue;
    }
    const card = { entry, view, element: null, busy: false };
    card.element = drawRequest(card);
    cards.set(entry.id, card);
    $('request-list').append(card.element);
  }
  $('no-request').hidden = [...cards.values()].some((c) => c.element);
}

function removeCard(id) {
  const card = cards.get(id);
  if (card && card.element) card.element.remove();
  cards.delete(id);
  $('no-request').hidden = [...cards.values()].some((c) => c.element);
}

function hostLine(hop) {
  return hostName(hop.fingerprint) ?? `hôte inconnu ${hop.fingerprint}`;
}

function drawRequest(card) {
  const { view, entry } = card;
  const dest = view.hops[view.hops.length - 1];
  const known = hostName(dest.fingerprint);
  const user = view.user ?? '(utilisateur illisible)';
  const box = el('article', known ? 'request' : 'request unknown');

  box.append(el('span', 'countdown'));
  box.append(el('p', 'destination', known ? `${user}@${known}` : `${user}@ hôte inconnu`));
  box.append(el('p', 'fingerprint', dest.fingerprint));

  let nameInput = null;
  if (!known) {
    const warning = el('div', 'warning');
    warning.append(el('strong', '', 'Ce téléphone n’a jamais approuvé ce serveur.'));
    warning.append(el('p', '', 'Vérifiez l’empreinte ci-dessus avant de continuer. '
      + 'Si vous approuvez, ce serveur sera retenu sous le nom que vous lui donnez.'));
    const label = el('label', '', 'Nom à retenir pour ce serveur');
    nameInput = el('input');
    nameInput.type = 'text';
    nameInput.maxLength = 64;
    nameInput.autocapitalize = 'off';
    nameInput.autocomplete = 'off';
    nameInput.spellcheck = false;
    const hint = view.hints[dest.fingerprint];
    if (hint) {
      // Offered, never filled in: taking the machine's word stays a gesture.
      const suggestion = el('p', 'unverified suggestion', `Nom indiqué par la machine (non vérifié) : ${hint}`);
      const use = el('button', 'secondary', 'Utiliser ce nom');
      use.type = 'button';
      use.addEventListener('click', () => { nameInput.value = hint.slice(0, 64); });
      suggestion.append(use);
      warning.append(suggestion);
    }
    label.append(nameInput);
    warning.append(label);
    box.append(warning);
  }

  const facts = el('ul', 'facts');
  for (const hop of view.hops.slice(0, -1)) {
    facts.append(el('li', '', `Via l’agent transféré à ${hostLine(hop)}`));
  }
  const caller = view.caller && (view.caller.name || view.caller.pid !== null)
    ? `${view.caller.name ?? 'processus'}${view.caller.pid !== null ? ` (pid ${view.caller.pid})` : ''}`
    : 'inconnu';
  facts.append(el('li', 'unverified', `Demandé par ${caller}, sur ${view.agent ?? 'machine sans nom'} — non vérifié`));
  box.append(facts);

  const progress = el('p', 'progress');
  const actions = el('div', 'actions');
  const no = el('button', 'secondary', 'Refuser');
  const yes = el('button', '', known ? 'Approuver' : 'Faire confiance et approuver');
  no.type = 'button';
  yes.type = 'button';
  actions.append(no, yes);
  box.append(progress, actions);

  const settle = async (work) => {
    card.busy = true;
    no.disabled = true;
    yes.disabled = true;
    try {
      await work();
      removeCard(entry.id);
    } catch (e) {
      progress.textContent = `Échec : ${describe(e)}.`;
      no.disabled = false;
      yes.disabled = false;
    } finally {
      card.busy = false;
    }
  };

  no.addEventListener('click', () => settle(async () => {
    await deny(ctx, relay, entry, 'user');
    await journal(`Refusé : ${user}@${known ?? dest.fingerprint}`);
  }));

  yes.addEventListener('click', () => settle(async () => {
    const name = known ?? (nameInput.value.trim().slice(0, 64));
    if (!name) throw new Error('donnez un nom à ce serveur');
    const started = performance.now();
    progress.textContent = 'En attente de la passkey…';
    // The user verification: nothing is signed without it.
    const secret = await unlock(navigator.credentials, RP_ID, state.credentialId);
    let signature;
    try {
      signature = await signWithWrappedKey(secret, state.sshKey, view.data);
    } finally {
      secret.fill(0);
    }
    const outcome = await approve(ctx, relay, entry, signature);
    if (!known) {
      state.pins[dest.fingerprint] = name;
      await store.set('pins', state.pins);
    }
    const seconds = ((performance.now() - started) / 1000).toFixed(1);
    await journal(outcome === 'accepted'
      ? `Approuvé : ${user}@${name} (${seconds} s)`
      : `Approuvé trop tard : ${user}@${name} (${outcome})`);
  }));

  return box;
}

function tick() {
  const now = Date.now() / 1000;
  for (const [id, card] of cards) {
    const left = Math.ceil(card.entry.exp - now);
    if (left <= 0 && !card.busy) {
      if (card.element) journal('Demande expirée sans réponse');
      removeCard(id);
    } else if (card.element) {
      card.element.querySelector('.countdown').textContent = `${Math.max(left, 0)} s`;
    }
  }
}

// ---- details --------------------------------------------------------------------

function drawDetails() {
  if (state.sshKey) $('public-key').textContent = publicKeyLine(state.sshKey.keyBlob, COMMENT);
  $('pairing-info').textContent = state.pairing
    ? `Agent : ${state.pairing.label || 'sans nom'} — chiffres de vérification : ${state.pairing.fingerprint}`
    : 'Pas encore appairé.';

  const pins = $('pins');
  pins.replaceChildren();
  for (const [fingerprint, name] of Object.entries(state.pins)) {
    const item = el('li');
    item.append(el('strong', '', name), el('div', 'small muted', fingerprint));
    const forget = el('button', 'secondary', 'Oublier');
    forget.type = 'button';
    forget.addEventListener('click', async () => {
      delete state.pins[fingerprint];
      await store.set('pins', state.pins);
      await journal(`Hôte oublié : ${name}`);
    });
    item.append(forget);
    pins.append(item);
  }
  $('no-pin').hidden = pins.childElementCount > 0;

  const list = $('journal');
  list.replaceChildren();
  for (const { at, text } of state.journal) {
    list.append(el('li', '', `${new Date(at).toLocaleString('fr-FR')} — ${text}`));
  }
}

// Checks of what this device supports; the result is meant to be read
// aloud or copied during the trial.
async function diagnose() {
  const lines = [];
  const check = async (name, fn) => {
    try {
      lines.push(`${name} : ${await fn()}`);
    } catch (e) {
      lines.push(`${name} : ÉCHEC (${(e && e.name) || ''} ${(e && e.message) || e})`);
    }
    $('diagnostic').textContent = lines.join('\n');
  };
  await check('appareil', () => navigator.userAgent.replace(/^Mozilla\/5\.0 \(([^)]+)\).*$/, '$1'));
  await check('écran d’accueil', () => (standalone() ? 'oui' : 'non'));
  await check('passkeys', () => (window.PublicKeyCredential ? 'oui' : 'non'));
  await check('PRF annoncé', async () => {
    if (!window.PublicKeyCredential || !PublicKeyCredential.getClientCapabilities) return 'inconnu';
    return String((await PublicKeyCredential.getClientCapabilities())['extension:prf']);
  });
  await check('Ed25519', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    const data = new Uint8Array(8);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, data);
    return (await crypto.subtle.verify({ name: 'Ed25519' }, pair.publicKey, sig, data)) ? 'oui' : 'signature invalide';
  });
  await check('clé non extractible conservée', async () => {
    const algorithm = { name: 'ECDH', namedCurve: 'P-256' };
    const mine = await crypto.subtle.generateKey(algorithm, false, ['deriveBits']);
    const theirs = await crypto.subtle.generateKey(algorithm, false, ['deriveBits']);
    await store.set('diagnostic', mine);
    const back = await store.get('diagnostic');
    await store.remove('diagnostic');
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs.publicKey }, back.privateKey, 256);
    return bits.byteLength === 32 && back.privateKey.extractable === false ? 'oui' : 'non';
  });
  await check('notifications', () => (('PushManager' in window) && ('Notification' in window)
    ? `disponibles, autorisation ${Notification.permission}` : 'indisponibles dans ce mode'));
  await check('stockage persistant', async () => (navigator.storage && navigator.storage.persisted
    ? ((await navigator.storage.persisted()) ? 'oui' : 'non garanti') : 'inconnu'));
}

let resetArmed = false;
async function reset() {
  if (!resetArmed) {
    resetArmed = true;
    $('reset').textContent = 'Toucher encore pour confirmer';
    setTimeout(() => {
      resetArmed = false;
      $('reset').textContent = 'Tout effacer';
    }, 5000);
    return;
  }
  stopWatching();
  await store.clear();
  location.reload();
}

// ---- drawing ----------------------------------------------------------------------

function draw() {
  const hasKey = Boolean(state.sshKey);
  const paired = Boolean(state.pairing);
  const notified = 'Notification' in window && Notification.permission === 'granted';

  $('install-text').textContent = standalone()
    ? 'Page ouverte depuis l’écran d’accueil.'
    : 'Ajoutez cette page à l’écran d’accueil (Partager → Sur l’écran d’accueil), puis ouvrez-la depuis son icône : '
      + 'les notifications n’existent que là, et ce qui est créé ici ne s’y retrouve pas.';
  $('step-install').classList.toggle('done', standalone());
  $('step-key').classList.toggle('done', hasKey);
  $('step-pair').classList.toggle('done', paired);
  $('step-notify').classList.toggle('done', notified && paired);

  $('create-key').hidden = hasKey || Boolean(state.credentialId);
  $('protect-key').hidden = hasKey || !state.credentialId;
  $('pair').disabled = !hasKey;
  $('pair-code').disabled = !hasKey;
  $('notify').disabled = !paired;

  $('setup').hidden = hasKey && paired && notified && !repairing;
  $('requests').hidden = !(hasKey && paired);
  $('details').hidden = !hasKey;
  drawDetails();
  if (!hasKey) status('Commencez par créer la clé de signature.');
  else if (!paired) status('Clé prête. Il reste à appairer une machine.');
}

// A pairing code can arrive in the URL fragment, from the QR code the
// agent displays. The fragment never reaches the server; it is removed
// from the address at once so it does not linger there.
function takeCodeFromAddress() {
  const code = decodeURIComponent(location.hash.slice(1));
  if (!code.startsWith(PAIR_CODE_PREFIX) || !/^[A-Za-z0-9_-]+$/.test(code)) return null;
  history.replaceState(null, '', location.pathname);
  return code;
}

function offerCode(code) {
  $('pair-code').value = code;
  if (state.sshKey) {
    // The key is here: go straight to the pairing step.
    repairing = Boolean(state.pairing);
    return;
  }
  if (!standalone()) {
    // Opened by the camera in the browser, whose storage is not the
    // installed app's: all we can do here is hand the code over.
    $('handoff-code').textContent = code;
    $('handoff').hidden = false;
  }
}

// The version of the relay that served this page, i.e. of the page itself.
async function showVersion() {
  try {
    const { version } = await (await fetch('/api/version', { cache: 'no-store' })).json();
    $('version').textContent = `Version ${version}`;
  } catch {
    // Not worth an error: the line simply stays empty.
  }
}

async function start() {
  showVersion();
  state.identity = (await store.get('identity')) ?? null;
  state.credentialId = (await store.get('credentialId')) ?? null;
  state.sshKey = (await store.get('sshKey')) ?? null;
  state.pairing = (await store.get('pairing')) ?? null;
  state.pins = (await store.get('pins')) ?? {};
  state.journal = (await store.get('journal')) ?? [];

  onClick('create-key', createKey);
  onClick('protect-key', protectKey);
  onClick('pair', pair);
  onClick('notify', enableNotifications);
  onClick('pair-again', async () => {
    repairing = true;
    draw();
    $('step-pair').scrollIntoView();
  });
  onClick('diagnose', diagnose);
  onClick('reset', reset);
  onClick('copy-key', async () => {
    try {
      await navigator.clipboard.writeText($('public-key').textContent);
      $('copy-key').textContent = 'Clé copiée';
    } catch (_) {
      $('copy-key').textContent = 'Copie impossible : sélectionnez le texte';
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') watch();
    else stopWatching();
  });
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', () => watch());
  }
  setInterval(tick, 1000);

  onClick('handoff-copy', async () => {
    try {
      await navigator.clipboard.writeText($('handoff-code').textContent);
      $('handoff-copy').textContent = 'Code copié — ouvrez Clavix';
    } catch (_) {
      $('handoff-copy').textContent = 'Copie impossible : sélectionnez le code';
    }
  });
  // At start, and when the link is opened in a tab that already shows
  // the page (which changes the fragment without reloading).
  const receiveCode = () => {
    const code = takeCodeFromAddress();
    if (!code) return;
    offerCode(code);
    draw();
    if (state.sshKey) $('step-pair').scrollIntoView();
  };
  window.addEventListener('hashchange', receiveCode);

  draw();
  receiveCode();
  await connect();
  await refreshSubscription();
}

start().catch((e) => status(`Erreur au démarrage : ${describe(e)}`, true));
