#!/usr/bin/env python3
"""clavix-approve relay.

Carries opaque messages between a key-less SSH agent and the phone that
signs, wakes the phone with a content-free Web Push (the page) or APNs
notification (the iOS app), and serves the approval page from the same
origin (the passkey is bound to that host).

The relay is untrusted: it never sees a key or a destination, it can only
delay or drop. It needs nothing but the standard library and
python3-cryptography; APNs, which is HTTP/2 only, also needs
httpx[http2], imported only when APNs is configured.

Meant to run behind a TLS-terminating reverse proxy. Conventions that
follow from that:

- a normal situation never answers 4xx (a proxy may ban a client after a
  burst of them): "nothing yet" is 204, "expired" or "unknown" is 200 with
  a `state` field; 4xx is kept for real errors (bad token, bad request);
- identifiers in URLs are lowercase hexadecimal, nothing free-form;
- the service sends its own Content-Security-Policy and Permissions-Policy.

Configuration (environment):
  RELAY_ENROLL_SECRET  required; allows an agent to create a channel
  RELAY_STATE_DIR      required; the only directory written to
  RELAY_BIND           listen address, default 127.0.0.1
  RELAY_PORT           default 8765
  RELAY_WEB_DIR        approval page, default ../web next to this file
  RELAY_VAPID_SUB      VAPID contact, default mailto:webpush@example.com
  RELAY_PUSH           "on" (default) or "off" (log instead of sending)
  RELAY_APNS_KEY_FILE  APNs auth key (.p8) from the Apple developer account;
                       APNs is off without it
  RELAY_APNS_KEY_ID    its key id (10 characters)
  RELAY_APNS_TEAM_ID   the developer team id (10 characters)
  RELAY_APNS_TOPIC     the app's bundle id, default org.clavix.approve

Usage: relay.py              run the service
       relay.py --selftest   check the push encryption offline
       relay.py --healthcheck  exit 0 when the local service answers
"""
import base64
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))

CHANNEL_RE = re.compile(r"^[0-9a-f]{32}$")
REQUEST_RE = re.compile(r"^[0-9a-f]{32}$")
SIGNER_RE = re.compile(r"^[0-9a-f]{16}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
KNOWN_RE = re.compile(r"^([0-9a-f]{32}(,[0-9a-f]{32}){0,31})?$")
# An APNs device token: 32 bytes today, Apple says the length may grow.
APNS_TOKEN_RE = re.compile(r"^(?:[0-9a-f]{2}){32,100}$")
APNS_ID_RE = re.compile(r"^[0-9A-Z]{10}$")

MAX_BODY = 64 * 1024        # one HTTP request body
MAX_BLOB = 8 * 1024         # pairing hello / answer
MAX_PENDING = 8             # sign requests waiting on one channel
MAX_TTL = 300               # seconds a sign request may ask to live
MAX_WAIT = 25               # long-poll cap, under usual proxy read timeouts
MAX_CHANNELS = 1000
MAX_SIGNERS = 4             # devices paired on one channel
PAIR_WINDOW = 900           # seconds to complete a pairing
KEEP_AFTER_EXPIRY = 60      # an agent can still learn "expired" that long

# Only known push services are contacted: the subscription comes from a client.
PUSH_HOSTS = (".push.apple.com", "fcm.googleapis.com", ".push.services.mozilla.com",
              ".notify.windows.com")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'none'",
    "Permissions-Policy": "publickey-credentials-get=(self), publickey-credentials-create=(self), "
                          "camera=(), microphone=(), geolocation=()",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
# What the page shows as its version: the release tag, set when the image is
# built. Anything else (a checkout, a local build) says "dev". It is written
# into the page when it is loaded, so showing it costs no request.
VERSION = os.environ.get("RELAY_VERSION", "")
if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,31}", VERSION):
    VERSION = "dev"

VERSION_MARK = b"@VERSION@"

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), msg, flush=True)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


# ---- Web Push (RFC 8291 / 8292) -------------------------------------------

def raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def load_vapid_key(state_dir):
    p = os.path.join(state_dir, "vapid.pem")
    if os.path.exists(p):
        with open(p, "rb") as f:
            return serialization.load_pem_private_key(f.read(), None)
    k = ec.generate_private_key(ec.SECP256R1())
    with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    return k


def es256_jwt(key, header, claims):
    def part(obj):
        return b64u(json.dumps(obj, separators=(",", ":")).encode())
    signed = f"{part({'alg': 'ES256', **header})}.{part(claims)}"
    r, s = decode_dss_signature(key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signed}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def vapid_header(key, endpoint, sub):
    u = urllib.parse.urlsplit(endpoint)
    jwt = es256_jwt(key, {"typ": "JWT"}, {"aud": f"{u.scheme}://{u.netloc}",
                                          "exp": int(time.time()) + 3600, "sub": sub})
    return f"vapid t={jwt}, k={b64u(raw_pub(key))}"


def push_encrypt(payload, p256dh, auth, as_key=None, salt=None):
    """aes128gcm encryption of one Web Push message (RFC 8291)."""
    as_key = as_key or ec.generate_private_key(ec.SECP256R1())
    salt = salt or os.urandom(16)
    ua_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
    as_pub = raw_pub(as_key)
    ikm = HKDF(hashes.SHA256(), 32, auth, b"WebPush: info\x00" + p256dh + as_pub).derive(
        as_key.exchange(ec.ECDH(), ua_pub))
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    ct = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + struct.pack(">IB", 4096, len(as_pub)) + as_pub + ct


def push_host_allowed(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
        return False
    host = urllib.parse.urlsplit(endpoint).hostname or ""
    return any(host == h or host.endswith(h) for h in PUSH_HOSTS)


class WebPush:
    """Sends the wake-up. Returns (outcome text, subscription_is_gone)."""

    def __init__(self, state_dir, contact, enabled=True):
        self.key = load_vapid_key(state_dir)
        self.contact = contact
        self.enabled = enabled

    def public_key(self):
        return b64u(raw_pub(self.key))

    def send(self, sub, payload):
        endpoint = sub["endpoint"]
        host = urllib.parse.urlsplit(endpoint).hostname or ""
        if not self.enabled:
            return f"push disabled, not sent to {host}", False
        body = push_encrypt(json.dumps(payload).encode(), unb64u(sub["keys"]["p256dh"]),
                            unb64u(sub["keys"]["auth"]))
        req = urllib.request.Request(endpoint, data=body, method="POST", headers={
            "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
            "TTL": "120", "Urgency": "high",
            "Authorization": vapid_header(self.key, endpoint, self.contact)})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return f"push accepted by {host} (HTTP {r.status})", False
        except urllib.error.HTTPError as e:
            # 404/410: the subscription no longer exists (RFC 8030 §7.3).
            return f"push rejected by {host} (HTTP {e.code})", e.code in (404, 410)
        except Exception as e:  # network
            return f"push to {host} failed: {type(e).__name__}", False


# ---- APNs (the iOS app) -----------------------------------------------------

APNS_HOSTS = {False: "https://api.push.apple.com", True: "https://api.sandbox.push.apple.com"}
APNS_TTL = 90               # seconds Apple keeps trying: a request expires in 90 s
APNS_TOKEN_LIFETIME = 40 * 60   # Apple wants a new one after 20 to 60 minutes
# Content-free, like the Web Push: the app fetches the request itself.
APNS_PAYLOAD = json.dumps({"aps": {
    "alert": {"title": "Clavix", "body": "Une demande de signature attend"},
    "sound": "default", "interruption-level": "time-sensitive"}},
    ensure_ascii=False, separators=(",", ":")).encode()


class ApnsPush:
    """Sends the wake-up to the iOS app. Same contract as WebPush.send."""

    def __init__(self, key_pem, key_id, team_id, topic, enabled=True, client=None,
                 now=time.time):
        if not (APNS_ID_RE.match(key_id or "") and APNS_ID_RE.match(team_id or "")):
            raise ValueError("RELAY_APNS_KEY_ID and RELAY_APNS_TEAM_ID must be 10-character ids")
        self.key = serialization.load_pem_private_key(key_pem, None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise ValueError("the APNs key must be an EC (.p8) key")
        self.key_id, self.team_id, self.topic = key_id, team_id, topic
        self.enabled = enabled
        self.now = now
        self.lock = threading.Lock()
        self.jwt, self.jwt_at = None, 0
        if client is None and enabled:
            import httpx   # only here: the page alone does not need it
            client = httpx.Client(http2=True, timeout=15)
        self.client = client

    def _token(self):
        """The provider token, reused: Apple refuses one renewed too often."""
        now = self.now()
        if self.jwt is None or now - self.jwt_at > APNS_TOKEN_LIFETIME:
            self.jwt_at = now
            self.jwt = es256_jwt(self.key, {"kid": self.key_id},
                                 {"iss": self.team_id, "iat": int(now)})
        return self.jwt

    def send(self, sub, payload):
        """`payload` is the Web Push one; APNs always gets APNS_PAYLOAD."""
        where = "APNs sandbox" if sub["sandbox"] else "APNs"
        if not self.enabled:
            return f"push disabled, not sent to {where}", False
        url = f"{APNS_HOSTS[bool(sub['sandbox'])]}/3/device/{sub['apns']}"
        with self.lock:   # one HTTP/2 connection per host, shared; pushes are rare
            headers = {"authorization": f"bearer {self._token()}",
                       "apns-topic": self.topic, "apns-push-type": "alert",
                       "apns-priority": "10",
                       "apns-expiration": str(int(self.now()) + APNS_TTL)}
            try:
                r = self.client.post(url, content=APNS_PAYLOAD, headers=headers)
            except Exception as e:  # network
                return f"push to {where} failed: {type(e).__name__}", False
            try:
                reason = r.json().get("reason", "")
            except ValueError:
                reason = ""
            if r.status_code == 403 and reason in ("ExpiredProviderToken",
                                                   "InvalidProviderToken"):
                self.jwt = None   # the next push signs a new one
        if r.status_code == 200:
            return f"push accepted by {where} (HTTP 200)", False
        # 410: the app is gone from the device; BadDeviceToken: never valid
        # for this environment. Either way the subscription is dead.
        gone = r.status_code == 410 or reason == "BadDeviceToken"
        return f"push rejected by {where} (HTTP {r.status_code} {reason})".rstrip(), gone


class Pushers:
    """Routes a wake-up to Web Push or APNs, after the subscription's kind."""

    def __init__(self, webpush, apns=None):
        self.webpush, self.apns = webpush, apns

    @property
    def supports_apns(self):
        return self.apns is not None

    def public_key(self):
        return self.webpush.public_key()

    def send(self, sub, payload):
        if "apns" in sub:
            if self.apns is None:
                return "APNs not configured, not sent", False
            return self.apns.send(sub, payload)
        return self.webpush.send(sub, payload)


# ---- Relay logic (HTTP-independent) ---------------------------------------

class Relay:
    """Channels, pairing slots and pending requests.

    Every public method returns (HTTP status, JSON body or None). Message
    bodies (`hello`, `msg`) are opaque here.
    """

    def __init__(self, state_dir, enroll_secret, push=None, now=time.time):
        if not enroll_secret:
            raise ValueError("an enrolment secret is required")
        self.state_file = os.path.join(state_dir, "state.json")
        self.enroll_auth = digest(enroll_secret)
        self.push = push
        self.now = now
        self.cond = threading.Condition()
        self.channels = {}
        self.pending = {}   # channel -> {request id -> entry}; memory only
        if os.path.exists(self.state_file):
            with open(self.state_file, encoding="utf-8") as f:
                self.channels = json.load(f)["channels"]

    # -- helpers (call with self.cond held) --

    def _save(self):
        tmp = self.state_file + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w",
                  encoding="utf-8") as f:
            json.dump({"channels": self.channels}, f)
        os.replace(tmp, self.state_file)

    def _purge(self):
        now = self.now()
        for ch, entries in list(self.pending.items()):
            for rid, e in list(entries.items()):
                if e["exp"] + KEEP_AFTER_EXPIRY < now:
                    del entries[rid]
            if not entries:
                del self.pending[ch]
        stale = [ch for ch, c in self.channels.items()
                 if not c["signers"] and c["created"] + PAIR_WINDOW < now]
        for ch in stale:
            del self.channels[ch]
        if stale:
            self._save()

    def _channel(self, ch, token, role):
        """The channel if `token` holds `role` on it, plus the signer id."""
        c = self.channels.get(ch) if isinstance(ch, str) else None
        if c is None or not token:
            return None, None
        given = digest(token)
        if role == "signer":
            for sid, s in c["signers"].items():
                if hmac.compare_digest(given, s["auth"]):
                    return c, sid
            return None, None
        if role == "pair" and c.get("pair_until", float("inf")) < self.now():
            return None, None
        expected = c.get(role + "_auth")
        if expected and hmac.compare_digest(given, expected):
            return c, None
        return None, None

    def _wait(self, ready, wait, ch=None, c=None, sid=None):
        """Block until ready() is truthy or `wait` seconds passed.

        Given the channel the caller holds (and, for a signer, its id),
        returns GONE as soon as that channel or signer is revoked, so a
        long-poll does not outlive its pairing.
        """
        deadline = time.monotonic() + max(0.0, min(float(wait or 0), MAX_WAIT))
        while True:
            if c is not None and (self.channels.get(ch) is not c
                                  or (sid is not None and sid not in c["signers"])):
                return self.GONE
            result = ready()
            remaining = deadline - time.monotonic()
            if result or remaining <= 0:
                return result
            self.cond.wait(remaining)

    DENIED = (401, {"error": "unauthorized"})
    GONE = object()
    BAD = (400, {"error": "bad request"})

    # -- pairing --

    def create_channel(self, token, body):
        if not token or not hmac.compare_digest(digest(token), self.enroll_auth):
            return self.DENIED
        ch, hello = body.get("ch"), body.get("hello")
        auths = (body.get("agent_auth"), body.get("pair_auth"))
        if not (isinstance(ch, str) and CHANNEL_RE.match(ch)
                and all(isinstance(a, str) and HASH_RE.match(a) for a in auths)
                and isinstance(hello, str) and len(hello) <= MAX_BLOB):
            return self.BAD
        with self.cond:
            self._purge()
            if ch in self.channels:
                return 200, {"state": "exists"}
            if len(self.channels) >= MAX_CHANNELS:
                return 200, {"state": "full"}
            self.channels[ch] = {"agent_auth": auths[0], "pair_auth": auths[1], "hello": hello,
                                 "answer": None, "created": int(self.now()), "signers": {},
                                 "pair_until": int(self.now()) + PAIR_WINDOW}
            self._save()
        log(f"channel {ch[:8]} created")
        return 200, {"state": "created"}

    def open_pairing(self, ch, token, body):
        """Let one more device pair with an existing channel.

        The agent sends a fresh pairing secret's token and a new hello; the
        window and the one-time rule are those of a first pairing.
        """
        pair_auth, hello = body.get("pair_auth"), body.get("hello")
        if not (isinstance(pair_auth, str) and HASH_RE.match(pair_auth)
                and isinstance(hello, str) and len(hello) <= MAX_BLOB):
            return self.BAD
        with self.cond:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            if len(c["signers"]) >= MAX_SIGNERS:
                return 200, {"state": "full"}
            c.update(pair_auth=pair_auth, hello=hello, answer=None,
                     pair_until=int(self.now()) + PAIR_WINDOW)
            self._save()
        log(f"channel {ch[:8]} open for one more device")
        return 200, {"state": "open"}

    def get_hello(self, ch, token):
        with self.cond:
            c, _ = self._channel(ch, token, "pair")
            if c is None:
                return self.DENIED
            return 200, {"hello": c["hello"]}

    def post_pair(self, ch, token, body):
        signer, auth, msg = body.get("signer"), body.get("signer_auth"), body.get("msg")
        if not (isinstance(signer, str) and SIGNER_RE.match(signer)
                and isinstance(auth, str) and HASH_RE.match(auth)
                and isinstance(msg, str) and len(msg) <= MAX_BLOB):
            return self.BAD
        with self.cond:
            c, _ = self._channel(ch, token, "pair")
            if c is None:
                return self.DENIED
            if len(c["signers"]) >= MAX_SIGNERS or signer in c["signers"]:
                return 200, {"state": "full"}
            c["signers"][signer] = {"auth": auth, "sub": None}
            c["answer"] = {"signer": signer, "msg": msg}
            c["pair_auth"] = None   # the pairing secret works once
            self._save()
            self.cond.notify_all()
        log(f"channel {ch[:8]} paired with signer {signer[:4]}")
        return 200, {"state": "paired"}

    def get_pair_answer(self, ch, token, wait=0):
        with self.cond:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            answer = self._wait(lambda: c["answer"], wait, ch, c)
            if answer is self.GONE:
                return self.DENIED
            if not answer:
                return 204, None
            return 200, {"state": "answered", **answer}

    def revoke(self, ch, token, body=None):
        """Revoke a pairing, or one device of it.

        The agent's token revokes the whole channel, or with `signer` in
        the body only that device. A signer's token revokes that signer.
        A channel left without any device goes too. What goes with a
        device: its push subscription and the requests addressed to it;
        long-polls on what was revoked return 401. A channel that no longer
        exists answers 401 like a wrong token: the relay does not tell who
        asks whether a channel exists.
        """
        target = (body or {}).get("signer")
        if target is not None and not (isinstance(target, str) and SIGNER_RE.match(target)):
            return self.BAD
        with self.cond:
            c, _ = self._channel(ch, token, "agent")
            by = "agent"
            if c is None:
                if target is not None:
                    return self.DENIED
                c, target = self._channel(ch, token, "signer")
                by = "signer"
            if c is None:
                return self.DENIED
            if target is not None:
                if target not in c["signers"]:
                    return 200, {"state": "unknown-signer"}
                del c["signers"][target]
                for rid, e in list(self.pending.get(ch, {}).items()):
                    if e["to"] == target:
                        del self.pending[ch][rid]
            if target is None or not c["signers"]:
                del self.channels[ch]
                self.pending.pop(ch, None)
                what = "channel"
            else:
                what = f"signer {target[:4]}"
            self._save()
            self.cond.notify_all()
        log(f"channel {ch[:8]}: {what} revoked by the {by}")
        return 200, {"state": "revoked"}

    # -- signer side --

    def put_subscription(self, ch, token, body):
        """Store how to wake this signer: a Web Push subscription
        `{endpoint, keys: {p256dh, auth}}` or an APNs device token
        `{apns: hex, sandbox: bool}`. A relay without APNs answers
        `unsupported` to the latter and keeps what it had."""
        if "apns" in body:
            if not (isinstance(body["apns"], str) and APNS_TOKEN_RE.match(body["apns"])
                    and isinstance(body.get("sandbox"), bool)):
                return self.BAD
            sub = {"apns": body["apns"], "sandbox": body["sandbox"]}
        else:
            keys = body.get("keys")
            if not (push_host_allowed(body.get("endpoint")) and isinstance(keys, dict)
                    and isinstance(keys.get("p256dh"), str) and isinstance(keys.get("auth"), str)):
                return self.BAD
            sub = {"endpoint": body["endpoint"],
                   "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]}}
        with self.cond:
            c, sid = self._channel(ch, token, "signer")
            if c is None:
                return self.DENIED
            if "apns" in sub and not getattr(self.push, "supports_apns", False):
                return 200, {"state": "unsupported"}
            c["signers"][sid]["sub"] = sub
            self._save()
        return 200, {"state": "stored"}

    def get_requests(self, ch, token, wait=0, known=None):
        """Pending requests of this signer.

        With `wait`, blocks until there is something the caller has not
        seen: `known` is the set of request ids it already holds, and the
        call returns as soon as the pending set differs from it. Without
        `known`, any pending request counts as news.
        """
        with self.cond:
            c, sid = self._channel(ch, token, "signer")
            if c is None:
                return self.DENIED

            def waiting():
                now = self.now()
                return [{"id": rid, "exp": e["exp"], "msg": e["msg"]}
                        for rid, e in self.pending.get(ch, {}).items()
                        if e["to"] == sid and e["response"] is None and e["exp"] > now]

            def news():
                current = waiting()
                if known is None:
                    return current
                return [current] if {r["id"] for r in current} != known else None
            if self._wait(news, wait, ch, c, sid) is self.GONE:
                return self.DENIED
            current = waiting()
            for r in current:   # the agent may ask whether its request was picked up
                self.pending[ch][r["id"]]["seen"] = True
            return 200, {"requests": current}

    def post_response(self, ch, token, rid, body):
        msg = body.get("msg")
        if not (isinstance(msg, str) and len(msg) <= MAX_BODY):
            return self.BAD
        with self.cond:
            c, sid = self._channel(ch, token, "signer")
            if c is None:
                return self.DENIED
            e = self.pending.get(ch, {}).get(rid)
            if e is None or e["to"] != sid:
                return 200, {"state": "unknown"}
            if e["response"] is not None:
                return 200, {"state": "duplicate"}
            if e["exp"] <= self.now():
                return 200, {"state": "expired"}
            e["response"] = msg
            self.cond.notify_all()
        return 200, {"state": "accepted"}

    # -- agent side --

    def post_request(self, ch, token, body):
        rid, to, exp, msg = body.get("id"), body.get("to"), body.get("exp"), body.get("msg")
        if not (isinstance(rid, str) and REQUEST_RE.match(rid) and isinstance(to, str)
                and isinstance(exp, (int, float)) and not isinstance(exp, bool)
                and isinstance(msg, str)):
            return self.BAD
        with self.cond:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            self._purge()
            now = self.now()
            signer = c["signers"].get(to)
            if signer is None:
                return 200, {"state": "unknown-signer"}
            if not now < exp <= now + MAX_TTL:
                return 200, {"state": "expired"}
            entries = self.pending.setdefault(ch, {})
            if rid in entries:
                return 200, {"state": "duplicate"}
            live = sum(1 for e in entries.values() if e["response"] is None and e["exp"] > now)
            if live >= MAX_PENDING:
                return 200, {"state": "busy"}
            entries[rid] = {"to": to, "exp": exp, "msg": msg, "response": None, "seen": False}
            sub = signer["sub"]
            self.cond.notify_all()
        if sub and self.push:
            threading.Thread(target=self._wake, args=(ch, to, sub), daemon=True).start()
        return 200, {"state": "queued", "push": bool(sub and self.push)}

    def cancel(self, ch, token, rid):
        """The agent gave up on a request: the device no longer offers it."""
        with self.cond:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            e = self.pending.get(ch, {}).get(rid)
            if e is None or e["response"] is not None:
                return 200, {"state": "unknown"}
            e["exp"] = min(e["exp"], self.now())
            self.cond.notify_all()
        return 200, {"state": "cancelled"}

    def _wake(self, ch, sid, sub):
        outcome, gone = self.push.send(sub, {"t": "sign"})   # content-free
        log(f"channel {ch[:8]}: {outcome}")
        if gone:
            with self.cond:
                signer = self.channels.get(ch, {}).get("signers", {}).get(sid)
                if signer and signer["sub"] == sub:
                    signer["sub"] = None
                    self._save()

    def get_response(self, ch, token, rid, wait=0, report_seen=False):
        """The answer to a request. "Nothing yet" is 204, or with
        `report_seen` 200 `pending` saying whether the device has fetched
        the request: an agent with another device to fall back on gives up
        on one that never picked it up."""
        with self.cond:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED

            def settled():
                e = self.pending.get(ch, {}).get(rid)
                if e is None:
                    return {"state": "unknown"}
                if e["response"] is not None:
                    return {"state": "answered", "msg": e["response"]}
                if e["exp"] <= self.now():
                    return {"state": "expired"}
                return None
            # Do not sleep past the expiry: the agent's client is waiting.
            e = self.pending.get(ch, {}).get(rid)
            if e is not None:
                wait = min(float(wait or 0), max(0.0, e["exp"] - self.now()) + 0.05)
            result = self._wait(settled, wait, ch, c)
            if result is self.GONE:
                return self.DENIED
            if result:
                return 200, result
            if report_seen:
                e = self.pending.get(ch, {}).get(rid)
                return 200, {"state": "pending", "seen": bool(e and e.get("seen"))}
            return 204, None


# ---- HTTP ------------------------------------------------------------------

def load_static(web_dir):
    """Map URL paths to (content type, bytes), read once at start.

    Only top-level files and `lib/` are served; tests and tools are not.
    """
    files = {}
    for sub in ("", "lib"):
        folder = os.path.join(web_dir, sub)
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            ctype = STATIC_TYPES.get(os.path.splitext(name)[1])
            path = os.path.join(folder, name)
            if ctype and os.path.isfile(path):
                with open(path, "rb") as f:
                    files["/" + (sub + "/" if sub else "") + name] = (ctype, f.read())
    if "/index.html" in files:
        ctype, page = files["/index.html"]
        files["/index.html"] = (ctype, page.replace(VERSION_MARK, VERSION.encode()))
        files["/"] = files["/index.html"]
    return files


# Paths browsers request on their own, whatever the page declares: iOS
# when a page is added to the home screen or a notification is shown,
# every browser for the tab icon, and installations made before the icon
# files were renamed. Answering 404 would count against the client at a
# proxy that bans on repeated errors, so they all get the main icon.
ICON_ALIAS = re.compile(r"^/(apple-touch-icon[0-9a-z-]*\.png|favicon\.ico|icon\.png)$")
MAIN_ICON = "/clavix-icon-180.png"


ROUTE = re.compile(r"^/api/ch/([0-9a-f]{32})/(pair|pair/answer|pair/open|subscription|requests|revoke|"
                   r"responses/([0-9a-f]{32})|requests/([0-9a-f]{32})/cancel)$")


def make_handler(relay, static, vapid_public):
    class Handler(BaseHTTPRequestHandler):
        server_version = "clavix-relay"
        sys_version = ""

        def reply(self, code, body=None, ctype="application/json", cache="no-store"):
            try:
                self.send_reply(code, body, ctype, cache)
            except (BrokenPipeError, ConnectionResetError):
                # The client left during a long-poll: nothing to report.
                self.close_connection = True

        def send_reply(self, code, body, ctype, cache):
            if body is not None and not isinstance(body, bytes):
                body = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(code)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Cache-Control", cache)
            if body is not None:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body or b"")))
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def token(self):
            auth = self.headers.get("Authorization") or ""
            return auth[7:] if auth.startswith("Bearer ") else None

        def json_body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None
            if not 0 < n <= MAX_BODY:
                return None
            try:
                data = json.loads(self.rfile.read(n))
            except ValueError:
                return None
            return data if isinstance(data, dict) else None

        def wait(self, query):
            try:
                return float(urllib.parse.parse_qs(query).get("wait", ["0"])[0])
            except ValueError:
                return 0.0

        def known(self, query):
            """The `known` parameter: None when absent, else a set of ids."""
            values = urllib.parse.parse_qs(query, keep_blank_values=True).get("known")
            if values is None:
                return None
            if not KNOWN_RE.match(values[0]):
                raise ValueError("known")
            return set(filter(None, values[0].split(",")))

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path in static:
                ctype, data = static[url.path]
                return self.reply(200, data, ctype, cache="no-cache")
            if ICON_ALIAS.match(url.path) and MAIN_ICON in static:
                ctype, data = static[MAIN_ICON]
                return self.reply(200, data, ctype, cache="max-age=86400")
            if url.path == "/healthz":
                return self.reply(200, {"ok": True})
            if url.path == "/api/vapid-public-key":
                return self.reply(200, {"key": vapid_public})
            m = ROUTE.match(url.path)
            if not m:
                return self.reply(404, {"error": "not found"})
            ch, what, rid = m.group(1), m.group(2), m.group(3)
            if what == "pair":
                return self.reply(*relay.get_hello(ch, self.token()))
            if what == "pair/answer":
                return self.reply(*relay.get_pair_answer(ch, self.token(), self.wait(url.query)))
            if what == "requests":
                try:
                    known = self.known(url.query)
                except ValueError:
                    return self.reply(400, {"error": "bad request"})
                return self.reply(*relay.get_requests(ch, self.token(), self.wait(url.query), known))
            if rid and what.startswith("responses/"):
                seen = urllib.parse.parse_qs(url.query).get("seen") == ["1"]
                return self.reply(*relay.get_response(ch, self.token(), rid, self.wait(url.query), seen))
            return self.reply(404, {"error": "not found"})

        do_HEAD = do_GET

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            body = self.json_body()
            if body is None:
                return self.reply(400, {"error": "bad request"})
            if path == "/api/channels":
                return self.reply(*relay.create_channel(self.token(), body))
            m = ROUTE.match(path)
            if not m:
                return self.reply(404, {"error": "not found"})
            ch, what, rid = m.group(1), m.group(2), m.group(3)
            if what == "pair":
                return self.reply(*relay.post_pair(ch, self.token(), body))
            if what == "subscription":
                return self.reply(*relay.put_subscription(ch, self.token(), body))
            if what == "revoke":
                return self.reply(*relay.revoke(ch, self.token(), body))
            if what == "pair/open":
                return self.reply(*relay.open_pairing(ch, self.token(), body))
            if m.group(4):
                return self.reply(*relay.cancel(ch, self.token(), m.group(4)))
            if what == "requests":
                return self.reply(*relay.post_request(ch, self.token(), body))
            if rid and what.startswith("responses/"):
                return self.reply(*relay.post_response(ch, self.token(), rid, body))
            return self.reply(404, {"error": "not found"})

        def log_message(self, fmt, *args):
            pass   # request lines would carry nothing useful; errors are logged by Relay

    return Handler


def load_apns(env, enabled):
    """An ApnsPush from the environment, or None when no key is given."""
    path = env.get("RELAY_APNS_KEY_FILE")
    if not path:
        return None
    with open(path, "rb") as f:
        pem = f.read()
    return ApnsPush(pem, env.get("RELAY_APNS_KEY_ID"), env.get("RELAY_APNS_TEAM_ID"),
                    env.get("RELAY_APNS_TOPIC", "org.clavix.approve"), enabled)


def serve(bind, port, state_dir, enroll_secret, web_dir, contact, push_enabled, apns=None):
    os.makedirs(state_dir, exist_ok=True)
    push = Pushers(WebPush(state_dir, contact, push_enabled), apns)
    relay = Relay(state_dir, enroll_secret, push)
    static = load_static(web_dir)
    server = ThreadingHTTPServer((bind, port), make_handler(relay, static, push.public_key()))
    server.daemon_threads = True
    return server


def selftest():
    """Encrypt, then decrypt as a browser would, to validate push_encrypt()."""
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    body = push_encrypt(b'{"ok":1}', raw_pub(ua), auth)
    salt, (rs, idlen) = body[:16], struct.unpack(">IB", body[16:21])
    as_pub, ct = body[21:21 + idlen], body[21 + idlen:]
    shared = ua.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
    ikm = HKDF(hashes.SHA256(), 32, auth, b"WebPush: info\x00" + raw_pub(ua) + as_pub).derive(shared)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    assert AESGCM(cek).decrypt(nonce, ct, None) == b'{"ok":1}\x02' and rs == 4096
    key = ec.generate_private_key(ec.SECP256R1())
    assert vapid_header(key, "https://web.push.apple.com/x", "mailto:a@example.com").count(".") >= 2
    print("selftest OK")


def main():
    if "--selftest" in sys.argv:
        return selftest()
    port = int(os.environ.get("RELAY_PORT", "8765"))
    if "--healthcheck" in sys.argv:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
            return None if r.status == 200 else sys.exit(1)
    secret = os.environ.get("RELAY_ENROLL_SECRET")
    state_dir = os.environ.get("RELAY_STATE_DIR")
    if not secret or not state_dir:
        sys.exit("RELAY_ENROLL_SECRET and RELAY_STATE_DIR must be set")
    bind = os.environ.get("RELAY_BIND", "127.0.0.1")
    push_enabled = os.environ.get("RELAY_PUSH", "on") != "off"
    apns = load_apns(os.environ, push_enabled)
    server = serve(bind, port, state_dir, secret,
                   os.environ.get("RELAY_WEB_DIR", os.path.join(HERE, "..", "web")),
                   os.environ.get("RELAY_VAPID_SUB", "mailto:webpush@example.com"),
                   push_enabled, apns)
    log(f"listening on {bind}:{port}, APNs {'on' if apns else 'off'}")
    server.serve_forever()


if __name__ == "__main__":
    main()
