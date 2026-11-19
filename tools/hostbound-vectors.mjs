// Generates testdata/hostbound.json: sign requests that the agent and
// both signers (web/lib, ios/ClavixCore) must accept or refuse alike
// (PROTOCOL.md, "What the signer checks"; audit finding H1).
//
//   node tools/hostbound-vectors.mjs > testdata/hostbound.json
//
// Every key is fixed and Ed25519 signatures are deterministic, so a new
// run gives the same file.
//
// Only `publickey-hostbound-v00@openssh.com` names the server in the
// signed bytes. A plain `publickey` login is refused, even when its
// session is bound: whoever holds a pinned host key (a hostile server
// with a forwarded agent, or a compromised agent machine holding that
// key) can sign a binding for a session it opened with another server.

import { createECDH, createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';

const b64u = (b) => Buffer.from(b).toString('base64url');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const string = (x) => Buffer.concat([u32(x.length), Buffer.from(x)]);
const sha256 = (s) => createHash('sha256').update(s).digest();

function ed25519(seedByte) {
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seedByte)]),
    format: 'der', type: 'pkcs8',
  });
  const raw = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
  return {
    blob: Buffer.concat([string('ssh-ed25519'), string(raw)]),
    sign: (data) => Buffer.concat([string('ssh-ed25519'), string(sign(null, data, priv))]),
  };
}

// The signer's own key (sign mode signs with ecdsa-sha2-nistp256). Only
// its public half is needed: nothing here is signed with it.
const ecdh = createECDH('prime256v1');
ecdh.setPrivateKey(Buffer.alloc(32, 0x42));
const clientKey = Buffer.concat([string('ecdsa-sha2-nistp256'), string('nistp256'), string(ecdh.getPublicKey())]);

const honest = ed25519(0x01); // a server the user pinned and really logs in to
const jump = ed25519(0x02); // a jump host the agent is forwarded through
const pinned = ed25519(0x03); // a pinned host whose private key the attacker holds
const target = ed25519(0x04); // the server the attacker really wants a login to

const sid = (name) => sha256(`clavix-approve hostbound vector: ${name}`);
const S_HONEST = sid('honest session');
const S_JUMP = sid('session with the jump host');
const S_USER = sid('user session with the pinned host');
const S_TARGET = sid('attacker session with the target');

function userAuth(sessionId, hostKey) {
  return Buffer.concat([
    string(sessionId), Buffer.from([50]), string('deploy'), string('ssh-connection'),
    string(hostKey ? 'publickey-hostbound-v00@openssh.com' : 'publickey'), Buffer.from([1]),
    string('ecdsa-sha2-nistp256'), string(clientKey), hostKey ? string(hostKey) : Buffer.alloc(0),
  ]);
}

const bind = (host, sessionId, fwd) => ({
  hostkey: b64u(host.blob), sid: b64u(sessionId), sig: b64u(host.sign(sessionId)), fwd,
});

const fingerprint = (blob) => 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');

const cases = [
  {
    name: 'host-bound login, direct',
    data: userAuth(S_HONEST, honest.blob),
    binds: [bind(honest, S_HONEST, false)],
    destination: fingerprint(honest.blob),
  },
  {
    name: 'host-bound login, through a forwarded agent',
    data: userAuth(S_HONEST, honest.blob),
    binds: [bind(jump, S_JUMP, true), bind(honest, S_HONEST, false)],
    destination: fingerprint(honest.blob),
  },
  {
    name: 'plain publickey login for a bound session',
    data: userAuth(S_HONEST, null),
    binds: [bind(honest, S_HONEST, false)],
    refused: 'not host-bound',
  },
  {
    // Scenario A: `ssh -A pinned`, the pinned host is hostile. It opens its
    // own session with the target and binds it with its own key on the
    // forwarded agent connection.
    name: 'forwarded hostile host, plain publickey for its own session with another server',
    data: userAuth(S_TARGET, null),
    binds: [bind(pinned, S_USER, true), bind(pinned, S_TARGET, false)],
    refused: 'not host-bound',
  },
  {
    name: 'forwarded hostile host, host-bound login naming the real server',
    data: userAuth(S_TARGET, target.blob),
    binds: [bind(pinned, S_USER, true), bind(pinned, S_TARGET, false)],
    refused: 'host key differs from the last binding',
  },
  {
    // Scenario B: the agent machine is compromised and holds the private
    // key of a host the phone has pinned.
    name: 'compromised agent with a pinned host key, plain publickey',
    data: userAuth(S_TARGET, null),
    binds: [bind(pinned, S_TARGET, false)],
    refused: 'not host-bound',
  },
  {
    name: 'compromised agent with a pinned host key, host-bound login naming the real server',
    data: userAuth(S_TARGET, target.blob),
    binds: [bind(pinned, S_TARGET, false)],
    refused: 'host key differs from the last binding',
  },
];

const out = {
  source: 'tools/hostbound-vectors.mjs; see PROTOCOL.md, "What the signer checks"',
  id: 'fedcba9876543210fedcba9876543210',
  now: 1800000000,
  exp: 1800000090,
  key: b64u(clientKey),
  cases: cases.map((c) => ({
    name: c.name,
    data: b64u(c.data),
    binds: c.binds,
    ...(c.destination ? { ok: true, destination: c.destination } : { ok: false, refused: c.refused }),
  })),
};
process.stdout.write(JSON.stringify(out, null, 2) + '\n');
