import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RelayClient, RelayError } from '../lib/relay.js';

// A fetch that answers with `status` and `body`, recording each call.
function fakeFetch(status, body) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, ...init });
    return new Response(status === 204 ? null : JSON.stringify(body), { status });
  };
  return { fn, calls };
}

const CH = 'a'.repeat(32);

test('revoke posts to the channel with the signer token', async () => {
  const { fn, calls } = fakeFetch(200, { state: 'revoked' });
  const relay = new RelayClient('https://relay.example', CH, 'tok', fn);
  assert.equal(await relay.revoke(), true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://relay.example/api/ch/${CH}/revoke`);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].headers.Authorization, 'Bearer tok');
  assert.equal(calls[0].body, '{}');
});

test('revoke reports an already unknown pairing as false', async () => {
  const { fn } = fakeFetch(401, { error: 'unauthorized' });
  assert.equal(await new RelayClient('', CH, 'tok', fn).revoke(), false);
});

test('revoke lets other failures through', async () => {
  const { fn } = fakeFetch(502, { error: 'bad gateway' });
  await assert.rejects(new RelayClient('', CH, 'tok', fn).revoke(),
    (e) => e instanceof RelayError && e.status === 502);
});
