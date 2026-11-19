// The approval page: set-up, then one screen per signature request.
//
// Everything security-relevant is in lib/ (and tested there under Node).
// This file only stores state, calls the passkey and draws.
//
// A pairing is in sign mode (this page signs the SSH login with its own
// key) or in approve mode (the machine holds the SSH key, this page only
// approves, with its approval key). The agent's code says which.

import { equal, unb64u } from './lib/bytes.js';
import { generateIdentity, peer, withPublicBytes } from './lib/channel.js';
import {
  approveWithWrappedKey, createPasskey, createWrappedApproveKey, createWrappedKey, signWithWrappedKey, unlock,
} from './lib/lock.js';
import { label } from './lib/protocol.js';
import { RelayClient, RelayError } from './lib/relay.js';
import {
  approvalData, approve, completePairing, deny, openPairing, readRequest, sendApproval,
} from './lib/signer.js';
import { publicKeyLine } from './lib/ssh.js';
import * as store from './lib/store.js';

const $ = (id) => document.getElementById(id);
const RP_ID = location.hostname;
const COMMENT = 'clavix-approve';
const JOURNAL_SIZE = 60;
const TOO_LATE_MS = 6000; // how long "trop tard" stays on a card

// Persistent state, loaded from the store at start.
const state = {
  identity: null,   // { kem, sig } CryptoKey pairs, non-extractable
  credentialId: null,
  sshKey: null,     // { keyBlob, iv, ct }
  approveKey: null, // { keyBlob, iv, ct }, approve mode; made with the SSH key, or when first needed
  pairing: null,    // { ch, signer, token, agentKem, agentSig, label, mode, fingerprint }, confirmed
  pending: null,    // the same, answered but not confirmed yet: accepts no request
  pins: {},        // host key fingerprint -> name chosen on this device
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

// The approval key comes with the SSH key, under the same passkey secret:
// pairing in approve mode then needs no second verification.
async function finishKey(secret) {
  const wrapped = await createWrappedKey(secret);
  const approveKey = await createWrappedApproveKey(secret);
  secret.fill(0);
  state.sshKey = wrapped;
  state.approveKey = approveKey;
  await store.set('sshKey', wrapped);
  await store.set('approveKey', approveKey);
  await journal('Clé de signature créée');
}

// A page set up before approve mode has no approval key: made on demand,
// from its own tap, since it needs the passkey.
async function createApproveKey() {
  try {
    result('pair-result', 'En attente de la passkey…');
    const secret = await unlock(navigator.credentials, RP_ID, state.credentialId);
    try {
      state.approveKey = await createWrappedApproveKey(secret);
    } finally {
      secret.fill(0);
    }
    await store.set('approveKey', state.approveKey);
    await journal('Clé de validation créée');
    $('approve-key').hidden = true;
  } catch (e) {
    result('pair-result', `Échec : ${describe(e)}.`, 'error');
    return;
  }
  await pair();
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
    const opening = await openPairing({ base: '', code: $('pair-code').value });
    const approveMode = opening.hello.mode === 'approve';
    if (approveMode && !state.approveKey) {
      // Nothing sent yet: the code stays good for the next tap.
      $('approve-key').hidden = false;
      result('pair-result', 'Ce code demande une validation seulement (la machine garde sa clé SSH). '
        + 'Il faut une clé de validation, protégée par la même passkey.');
      return;
    }
    result('pair-result', `Machine « ${label(opening.hello.label) || 'sans nom'} », mode ${
      approveMode ? 'validation' : 'signature'} : en attente de ses chiffres…`);
    const paired = await completePairing(opening, {
      me, keyBlob: approveMode ? state.approveKey.keyBlob : state.sshKey.keyBlob, comment: COMMENT,
    });
    // Held aside, unconfirmed: it accepts no request, and the pairing in
    // place keeps working, until the user says the digits match.
    await dropPending();
    state.pending = {
      v: 2,
      ch: paired.ch,
      signer: paired.signer,
      token: paired.token,
      agentKem: paired.agent.kemPublic,
      agentSig: paired.agent.sigPublic,
      label: paired.label,
      mode: paired.mode,
      fingerprint: paired.fingerprint,
    };
    await store.set('pendingPairing', state.pending);
    $('pair-code').value = '';
    $('approve-key').hidden = true;
    result('pair-result', '');
  } catch (e) {
    result('pair-result', `Échec : ${describe(e)}.`, 'error');
  }
  draw();
}

// The user saw the same digits on the machine: the pending pairing
// replaces the one in place, which is revoked (best effort).
async function confirmPairing() {
  const paired = state.pending;
  if (!paired) return;
  const previous = state.pairing;
  state.pairing = paired;
  state.pending = null;
  await store.set('pairing', state.pairing);
  await store.remove('pendingPairing');
  repairing = false;
  stopWatching();
  cards.forEach((_, id) => removeCard(id));
  await journal(`Appairé avec ${paired.label || 'un agent'}${paired.mode === 'approve' ? ' (validation seulement)' : ''}`);
  if (previous && previous.ch !== paired.ch) {
    // Best effort: the old channel is dead to us either way.
    try {
      await new RelayClient('', previous.ch, previous.token).revoke();
      await journal(`Appairage précédent (${previous.label || 'sans nom'}) révoqué`);
    } catch (_) { /* left on the relay, harmless */ }
  }
  await connect();
  result('pair-result', `Appairé. Chiffres confirmés : ${paired.fingerprint}`, 'ok');
  draw();
}

// The digits differ, or the pairing is abandoned: take this device off
// that channel and forget it.
async function dropPending() {
  const pending = state.pending;
  if (!pending) return;
  state.pending = null;
  await store.remove('pendingPairing');
  try {
    await new RelayClient('', pending.ch, pending.token).revoke();
  } catch (_) { /* the machine revokes it too when its user refuses */ }
}

async function rejectPairing() {
  const label = state.pending?.label || 'sans nom';
  await dropPending();
  await journal(`Appairage avec ${label} refusé : les chiffres différaient`);
  result('pair-result', 'Appairage refusé. Refusez-le aussi sur la machine.', 'error');
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
    mode: state.pairing.mode ?? 'sign', // pairings from before approve mode are sign-mode ones
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

// How long a long-poll may outlive its `wait` before it is taken for dead.
const POLL_GRACE_S = 10;
// When the current call to the relay started (0: none under way).
let pollSince = 0;

// A call bounded in time, also stopped by `signal`. Without the bound, a
// connection that died while the phone slept would hang until the system
// gives up on it, and new requests would wait as long.
function bounded(signal, seconds) {
  if (typeof AbortSignal.any !== 'function' || typeof AbortSignal.timeout !== 'function') return signal;
  return AbortSignal.any([signal, AbortSignal.timeout(seconds * 1000)]);
}

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
      pollSince = Date.now();
      // Tell the relay what we already show, so it only answers on news.
      const signal = bounded(controller.signal, wait + POLL_GRACE_S);
      await show(await relay.requests(wait, signal, [...cards.keys()]));
      status(cards.size ? '' : 'Prêt. En attente de demandes.');
      wait = 20;
      backoff = 0;
    } catch (e) {
      if (controller.signal.aborted) break;
      if (e && e.name === 'TimeoutError') {
        // A dead connection, not a refusal: ask again at once.
        wait = 0;
        continue;
      }
      if (isFatal(e)) {
        status(e.status === 401
          ? 'Cette machine a été retirée : le relais ne connaît plus cet appairage. '
            + 'Touchez « Oublier cette machine » plus bas, ou appairez à nouveau.'
          : `Arrêt : ${describe(e)}. Si cela persiste, appairez à nouveau.`, true);
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
  if (polling === controller) {
    polling = null;
    pollSince = 0;
  }
}

function stopWatching() {
  if (polling) polling.abort();
  polling = null;
  pollSince = 0;
}

// The page comes back to the front, or a notification was tapped. iOS
// may have frozen the page before it could stop its long-poll, leaving a
// call that will only end after its full wait (or never): drop it and ask
// the relay now. A call started just before is fresh, and kept.
function watchAfresh() {
  if (polling && Date.now() - pollSince < 2000) return;
  stopWatching();
  watch();
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
  if (ctx.mode === 'approve') {
    // The machine signs with its own key: name and fingerprint as it gives them.
    facts.append(el('li', 'unverified key',
      `Clé de la machine, d’après elle : ${view.keyName ?? 'sans nom'} (${view.keyFingerprint})`));
  }
  box.append(facts);

  const progress = el('p', 'progress');
  const actions = el('div', 'actions');
  const no = el('button', 'secondary', 'Refuser');
  const yes = el('button', '', known ? 'Approuver' : 'Faire confiance et approuver');
  no.type = 'button';
  yes.type = 'button';
  actions.append(no, yes);
  box.append(progress, actions);

  // `work` returns the relay's verdict on our answer. Anything but
  // "accepted" means the request was settled elsewhere or withdrawn
  // meanwhile (the machine's own dialog answered first, or it expired):
  // the card says so for a moment instead of vanishing.
  const settle = async (work) => {
    card.busy = true;
    no.disabled = true;
    yes.disabled = true;
    let outcome;
    try {
      outcome = await work();
    } catch (e) {
      progress.textContent = `Échec : ${describe(e)}.`;
      no.disabled = false;
      yes.disabled = false;
      card.busy = false;
      return;
    }
    if (outcome === 'accepted') {
      card.busy = false;
      removeCard(entry.id);
      return;
    }
    progress.textContent = 'Trop tard : la demande a déjà été réglée ou retirée.';
    box.classList.add('late');
    setTimeout(() => {
      card.busy = false;
      removeCard(entry.id);
    }, TOO_LATE_MS);
  };

  no.addEventListener('click', () => settle(async () => {
    const outcome = await deny(ctx, relay, entry, 'user');
    await journal(`Refusé : ${user}@${known ?? dest.fingerprint}`);
    return outcome;
  }));

  yes.addEventListener('click', () => settle(async () => {
    const name = known ?? (nameInput.value.trim().slice(0, 64));
    if (!name) throw new Error('donnez un nom à ce serveur');
    const started = performance.now();
    progress.textContent = 'En attente de la passkey…';
    // The user verification: nothing is signed without it. In approve mode
    // what is signed is the approval, with the approval key.
    const approveMode = ctx.mode === 'approve';
    const toSign = approveMode ? await approvalData(ctx, entry) : view.data;
    const secret = await unlock(navigator.credentials, RP_ID, state.credentialId);
    let signature;
    try {
      signature = approveMode
        ? await approveWithWrappedKey(secret, state.approveKey, toSign)
        : await signWithWrappedKey(secret, state.sshKey, toSign);
    } finally {
      secret.fill(0);
    }
    const outcome = approveMode
      ? await sendApproval(ctx, relay, entry, signature)
      : await approve(ctx, relay, entry, signature);
    if (!known) {
      state.pins[dest.fingerprint] = name;
      await store.set('pins', state.pins);
    }
    const seconds = ((performance.now() - started) / 1000).toFixed(1);
    await journal(outcome === 'accepted'
      ? `Approuvé : ${user}@${name} (${seconds} s)`
      : `Approuvé trop tard : ${user}@${name} (${outcome})`);
    return outcome;
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
    ? `Agent : ${state.pairing.label || 'sans nom'}${state.pairing.mode === 'approve'
      ? ' — validation seulement : la machine signe avec sa propre clé' : ''} — chiffres de vérification : ${
      state.pairing.fingerprint}`
    : 'Pas encore appairé.';
  $('forget').hidden = !state.pairing;

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

// Revoke the pairing on the relay, then forget it here. Keeps the SSH key
// and the known hosts: pairing another machine needs nothing new on the
// servers. Touched twice, like "Tout effacer"; when the relay cannot be
// reached, a third touch forgets it here anyway.
let forgetStep = 0;   // 0 idle, 1 armed, 2 relay unreachable, local only next
let forgetTimer = null;
function armForget(step, label) {
  forgetStep = step;
  $('forget').textContent = label;
  clearTimeout(forgetTimer);
  forgetTimer = setTimeout(() => {
    forgetStep = 0;
    $('forget').textContent = 'Oublier cette machine';
  }, 8000);
}

async function forget() {
  if (!state.pairing) return;
  if (forgetStep === 0) {
    armForget(1, 'Toucher encore pour confirmer');
    return;
  }
  const label = state.pairing.label || 'sans nom';
  if (forgetStep === 1) {
    try {
      const deleted = await new RelayClient('', state.pairing.ch, state.pairing.token).revoke();
      await journal(deleted ? `Appairage avec ${label} révoqué` : `${label} : appairage déjà révoqué`);
    } catch (e) {
      result('forget-result', `Relais injoignable (${describe(e)}). L’appairage y reste tant qu’il n’est pas `
        + 'révoqué depuis la machine (clavix-agent unpair).', 'error');
      armForget(2, 'Oublier quand même sur cet appareil');
      return;
    }
  } else {
    await journal(`${label} oubliée sur cet appareil seulement`);
  }
  clearTimeout(forgetTimer);
  forgetStep = 0;
  $('forget').textContent = 'Oublier cette machine';
  stopWatching();
  cards.forEach((_, id) => removeCard(id));
  state.pairing = null;
  relay = null;
  ctx = null;
  await store.remove('pairing');
  result('forget-result', `${label} est oubliée.`, 'ok');
  draw();
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
  const pending = state.pending;
  $('pair-check').hidden = !pending;
  if (pending) {
    $('pair-check-text').textContent = `Machine « ${pending.label || 'sans nom'} », mode ${
      pending.mode === 'approve' ? 'validation' : 'signature'}. Elle affiche six chiffres : ce doivent être ceux-ci. `
      + 'Tant que vous ne les avez pas confirmés, elle ne peut rien demander à cet appareil.';
    $('pair-digits').textContent = pending.fingerprint;
  }

  $('setup').hidden = hasKey && paired && notified && !repairing && !pending;
  $('requests').hidden = !(hasKey && paired);
  $('details').hidden = !hasKey;
  drawDetails();
  if (!hasKey) status('Commencez par créer la clé de signature.');
  else if (!paired) status('Clé prête. Il reste à appairer une machine.');
}

// A pairing code is only ever pasted here. The agent's QR code opens the
// Clavix Approve app (clavix-approve://), never this page: a page served
// by the relay must not be handed pairing secrets from a link.

async function start() {
  state.identity = (await store.get('identity')) ?? null;
  state.credentialId = (await store.get('credentialId')) ?? null;
  state.sshKey = (await store.get('sshKey')) ?? null;
  state.approveKey = (await store.get('approveKey')) ?? null;
  state.pairing = (await store.get('pairing')) ?? null;
  state.pending = (await store.get('pendingPairing')) ?? null;
  state.pins = (await store.get('pins')) ?? {};
  state.journal = (await store.get('journal')) ?? [];
  if (state.pairing && state.pairing.v !== 2) {
    // Made with the first pairing protocol, whose digits a relay could
    // steer: dropped, to be made again.
    state.pairing = null;
    await store.remove('pairing');
    await journal('Appairage d’une version précédente retiré : appairez à nouveau');
  }

  onClick('create-key', createKey);
  onClick('protect-key', protectKey);
  onClick('pair', pair);
  onClick('pair-confirm', confirmPairing);
  onClick('pair-reject', rejectPairing);
  onClick('approve-key', createApproveKey);
  onClick('notify', enableNotifications);
  onClick('pair-again', async () => {
    repairing = true;
    draw();
    $('step-pair').scrollIntoView();
  });
  onClick('diagnose', diagnose);
  onClick('forget', forget);
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
    if (document.visibilityState === 'visible') watchAfresh();
    else stopWatching();
  });
  // A page frozen while still "visible" gets no visibilitychange on its
  // return; these still fire.
  window.addEventListener('pageshow', watchAfresh);
  window.addEventListener('focus', watchAfresh);
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', watchAfresh);
  }
  setInterval(tick, 1000);

  draw();
  await connect();
  await refreshSubscription();
}

start().catch((e) => status(`Erreur au démarrage : ${describe(e)}`, true));
