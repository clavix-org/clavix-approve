// Page d'essai : passkey + extension PRF pour protéger une clé de signature
// ordinaire (ECDSA P-256), et notifications Web Push sur l'écran d'accueil.
'use strict';

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const PRF_SALT = enc.encode('essai-approbation-ssh/v1');
const bilan = {};

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64u = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));

function store(k, v) {
  try {
    if (v === undefined) return JSON.parse(localStorage.getItem(k));
    localStorage.setItem(k, JSON.stringify(v));
  } catch (_) { /* stockage indisponible */ }
  return null;
}

function etat(id, cls, msg) {
  const el = $(id);
  el.className = 'etat ' + cls;
  el.textContent = msg;
}

function note(k, v) {
  bilan[k] = v;
  $('bilan').textContent = Object.entries(bilan).map(([a, b]) => `${a}: ${b}`).join('\n');
}

const standalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

// ---- Étape 2 : passkey --------------------------------------------------
async function creerPasskey() {
  etat('e-passkey', 'attente', 'En attente de Face ID…');
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Essai approbation SSH', id: location.hostname },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'essai-ssh', displayName: 'Essai SSH' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { prf: {} },
    },
  });
  const ext = cred.getClientExtensionResults();
  store('credId', b64u(cred.rawId));
  const prf = ext.prf && ext.prf.enabled === true;
  note('passkey', 'créée');
  note('prf à la création', prf ? 'oui' : 'non annoncé (' + JSON.stringify(ext) + ')');
  etat('e-passkey', prf ? 'ok' : 'attente',
    prf ? 'Passkey créée, verrou PRF disponible.' : 'Passkey créée, mais le verrou PRF n\'est pas annoncé. Essaie quand même l\'étape 3.');
}

// Demande Face ID et renvoie la clé AES dérivée du secret PRF de la passkey.
async function cleDeVerrou() {
  const credId = store('credId');
  if (!credId) throw new Error('Crée d\'abord la passkey (étape 2).');
  const t0 = performance.now();
  const a = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      allowCredentials: [{ type: 'public-key', id: unb64u(credId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const res = a.getClientExtensionResults();
  if (!res.prf || !res.prf.results || !res.prf.results.first) {
    throw new Error('La passkey n\'a pas renvoyé de secret PRF (' + JSON.stringify(res) + ').');
  }
  const ikm = await crypto.subtle.importKey('raw', res.prf.results.first, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('verrou-cle-ssh') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { key, ms: Math.round(performance.now() - t0) };
}

// ---- Étape 3 : clé SSH protégée -----------------------------------------
function ligneSsh(jwk) {
  const str = (b) => [...new Uint8Array(new Uint32Array([b.length]).buffer).reverse(), ...b];
  const q = [4, ...unb64u(jwk.x), ...unb64u(jwk.y)];
  const blob = [...str(enc.encode('ecdsa-sha2-nistp256')), ...str(enc.encode('nistp256')), ...str(q)];
  return 'ecdsa-sha2-nistp256 ' + b64(new Uint8Array(blob)) + ' essai-iphone';
}

async function creerCle() {
  etat('e-cle', 'attente', 'En attente de Face ID…');
  const { key } = await cleDeVerrou();
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pkcs8);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  store('cle', { iv: b64(iv), ct: b64(ct), pub: jwk });
  note('clé protégée par PRF', 'oui');
  etat('e-cle', 'ok', 'Clé créée et chiffrée. Clé publique SSH :\n' + ligneSsh(jwk));
}

// ---- Étape 4 : signer ---------------------------------------------------
let signatures = 0;
async function signer() {
  const c = store('cle');
  if (!c) throw new Error('Crée d\'abord la clé (étape 3).');
  etat('e-signer', 'attente', 'En attente de Face ID…');
  const { key, ms } = await cleDeVerrou();
  const pkcs8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(c.iv) }, key, unb64(c.ct));
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const pub = await crypto.subtle.importKey('jwk', c.pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const demande = crypto.getRandomValues(new Uint8Array(64));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, demande);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, demande);
  if (!ok) throw new Error('Signature produite mais invalide.');
  signatures += 1;
  note('signatures valides', signatures);
  note('durée Face ID + signature', ms + ' ms');
  etat('e-signer', 'ok', `Signature n° ${signatures} valide (${ms} ms, Face ID compris).`);
}

// ---- Étape 5 : notifications --------------------------------------------
async function activerNotifs() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    note('notifications', 'non disponibles dans ce mode');
    throw new Error('Notifications indisponibles ici. Ouvre la page depuis l\'icône de l\'écran d\'accueil (étape 1).');
  }
  etat('e-notif', 'attente', 'Demande d\'autorisation…');
  const perm = await Notification.requestPermission();
  note('autorisation', perm);
  if (perm !== 'granted') throw new Error('Autorisation refusée : ' + perm);
  const reg = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  const { key } = await (await fetch('/vapid-public-key')).json();
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: unb64u(key) });
  const r = await fetch('/subscribe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sub) });
  if (!r.ok) throw new Error('Le serveur a refusé l\'abonnement (HTTP ' + r.status + ').');
  note('abonnement push', new URL(sub.endpoint).hostname);
  etat('e-notif', 'ok', 'Notifications activées. Demande maintenant un envoi.');
}

async function envoyer() {
  const r = await fetch('/push', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ delay: 10 }) });
  if (!r.ok) throw new Error(r.status === 409 ? 'Active d\'abord les notifications.' : 'Envoi refusé (HTTP ' + r.status + ').');
  note('envoi demandé', new Date().toLocaleTimeString('fr-FR'));
  etat('e-notif', 'attente', 'Envoi dans 10 s. Verrouille l\'iPhone maintenant.');
  setTimeout(async () => {
    try {
      const { journal } = await (await fetch('/journal')).json();
      if (journal.length) note('réponse du service de push', journal[journal.length - 1]);
    } catch (_) { /* page en arrière-plan */ }
  }, 14000);
}

function notifTouchee(quand) {
  note('notification touchée', 'oui, envoyée à ' + quand);
  etat('e-notif', 'ok', 'Notification reçue et touchée : la page s\'est rouverte.');
}

// ---- Câblage ------------------------------------------------------------
function brancher(bouton, zone, fn) {
  $(bouton).addEventListener('click', async () => {
    $(bouton).disabled = true;
    try { await fn(); } catch (e) {
      etat(zone, 'ko', (e && e.name ? e.name + ' : ' : '') + (e && e.message ? e.message : e));
      note('erreur ' + zone, (e && e.name) || 'inconnue');
    }
    $(bouton).disabled = false;
  });
}

brancher('b-passkey', 'e-passkey', creerPasskey);
brancher('b-cle', 'e-cle', creerCle);
brancher('b-signer', 'e-signer', signer);
brancher('b-notif', 'e-notif', activerNotifs);
brancher('b-push', 'e-notif', envoyer);
$('b-copier').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('bilan').textContent); $('b-copier').textContent = 'Bilan copié'; }
  catch (_) { $('b-copier').textContent = 'Copie impossible : sélectionne le texte'; }
});

(async () => {
  note('appareil', navigator.userAgent.replace(/^Mozilla\/5\.0 \(([^)]+)\).*$/, '$1'));
  note('écran d\'accueil', standalone() ? 'oui' : 'non');
  etat('e-install', standalone() ? 'ok' : 'attente',
    standalone() ? 'Page ouverte depuis l\'écran d\'accueil.' : 'Page ouverte dans le navigateur : les étapes 2 à 4 marchent, pas la 5.');
  if (!window.PublicKeyCredential) { note('passkeys', 'non prises en charge'); return; }
  if (PublicKeyCredential.getClientCapabilities) {
    try {
      const caps = await PublicKeyCredential.getClientCapabilities();
      note('prf annoncé par le navigateur', caps['extension:prf'] === true ? 'oui' : String(caps['extension:prf']));
    } catch (_) { /* non bloquant */ }
  }
  if (store('credId')) etat('e-passkey', 'ok', 'Une passkey existe déjà pour cette page.');
  if (store('cle')) etat('e-cle', 'ok', 'Une clé existe déjà. Clé publique SSH :\n' + ligneSsh(store('cle').pub));
  const d = new URLSearchParams(location.search).get('demande');
  if (d) notifTouchee(d);
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => { if (e.data && e.data.demande) notifTouchee(e.data.demande); });
  }
})();
