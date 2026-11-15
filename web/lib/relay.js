// Client of the relay's HTTP API, signer side.

export class RelayError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
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

  async requests(wait = 0, signal) {
    const res = await this.call('GET', `requests${wait ? `?wait=${wait}` : ''}`, undefined, signal);
    return res.requests;
  }

  respond(id, msg) {
    return this.call('POST', `responses/${id}`, { msg });
  }
}
