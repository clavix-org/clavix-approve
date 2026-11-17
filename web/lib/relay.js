// Client of the relay's HTTP API, signer side.

export class RelayError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Calls are spaced out, whatever triggers them: a reverse proxy in front
// of the relay may throttle a client, and ban one that insists. With this
// gap between two call starts, no second sees more than three.
const MIN_GAP_MS = 350;
let nextSlot = 0;

async function slot() {
  const now = Date.now();
  const at = Math.max(now, nextSlot);
  nextSlot = at + MIN_GAP_MS;
  if (at > now) await new Promise((resolve) => setTimeout(resolve, at - now));
}

export class RelayClient {
  // `base` is '' in the page (same origin) and a URL for the stand-in.
  constructor(base, ch, token, fetchFn = (...args) => fetch(...args)) {
    this.base = base.replace(/\/+$/, '');
    this.ch = ch;
    this.token = token;
    this.fetch = fetchFn;
  }

  async call(method, path, body, signal) {
    await slot();
    const res = await this.fetch(`${this.base}/api/ch/${this.ch}/${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
      signal,
    });
    if (res.status === 204) return null;
    // A proxy in front may answer with its own HTML error page.
    const text = await res.text();
    if (!res.ok) throw new RelayError(res.status, `relay answered HTTP ${res.status}`);
    try {
      return JSON.parse(text);
    } catch (_) {
      throw new RelayError(res.status, 'relay answer is not JSON');
    }
  }

  // Pairing (the token is the one derived from the pairing secret).
  hello() {
    return this.call('GET', 'pair');
  }

  pair(signer, signerAuth, msg) {
    return this.call('POST', 'pair', { signer, signer_auth: signerAuth, msg });
  }

  // Normal operation (the token is the signer's own).
  subscribe(subscription) {
    return this.call('POST', 'subscription', subscription);
  }

  // Pending requests. With `wait`, the relay holds the call until the
  // pending set differs from `known` (ids we already hold): a request
  // that stays on screen must not make this return at once, in a loop.
  async requests(wait = 0, signal, known = []) {
    const query = wait ? `?wait=${wait}&known=${known.join(',')}` : '';
    const res = await this.call('GET', `requests${query}`, undefined, signal);
    return res.requests;
  }

  respond(id, msg) {
    return this.call('POST', `responses/${id}`, { msg });
  }

  // Delete the pairing on the relay. True when this call deleted it,
  // false when the relay no longer knew it (already revoked elsewhere).
  async revoke() {
    try {
      return (await this.call('POST', 'revoke', {})).state === 'revoked';
    } catch (e) {
      if (e instanceof RelayError && e.status === 401) return false;
      throw e;
    }
  }
}
