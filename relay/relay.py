#!/usr/bin/env python3
"""clavix-approve relay.

Carries opaque messages between a key-less SSH agent and the phone that
signs, wakes the phone with a content-free Web Push (the page) or APNs
notification (the iOS app), and can serve the approval page from the same
origin (the passkey is bound to that host).

The relay is untrusted: it never sees a key or a destination, it can only
delay or drop. It needs nothing but the standard library and
python3-cryptography; APNs, which is HTTP/2 only, also needs
httpx[http2], imported only when APNs is configured.

Meant to run behind a TLS-terminating reverse proxy. Conventions that
follow from that:

- a normal situation never answers 4xx (a proxy may ban a client after a
  burst of them): "nothing yet" is 204, "expired" or "unknown" is 200 with
  a `state` field; 4xx is kept for real errors (bad token, bad request)
  and for a client over its limits (429, with Retry-After), or without
  the subscription a hosted relay requires (402, which clients do not
  retry);
- identifiers in URLs are lowercase hexadecimal, nothing free-form;
- the service sends its own Content-Security-Policy and Permissions-Policy.

Configuration (environment):
  RELAY_STATE_DIR      required; the only directory written to
  RELAY_ENROLL_SECRET  optional; when set, an agent needs it to create a
                       channel (closed enrolment)
  RELAY_ENROLL         "open" forces open enrolment (no secret checked),
                       "closed" requires RELAY_ENROLL_SECRET; default:
                       closed when a secret is set, open otherwise
  RELAY_BIND           listen address, default 127.0.0.1
  RELAY_PORT           default 8765
  RELAY_SERVE_WEB      "on" (default) serves the approval page; "off" serves
                       the API only (a public relay keeps the page that
                       handles keys on another origin)
  RELAY_WEB_DIR        approval page, default ../web next to this file
  RELAY_VAPID_SUB      VAPID contact, default mailto:webpush@example.com
  RELAY_PUSH           "on" (default) or "off" (log instead of sending)
  RELAY_APNS_KEY_FILE  APNs auth key (.p8) from the Apple developer account;
                       APNs is off without it
  RELAY_APNS_KEY_ID    its key id (10 characters)
  RELAY_APNS_TEAM_ID   the developer team id (10 characters)
  RELAY_APNS_TOPIC     the app's bundle id, default org.clavix.approve

Subscriptions (a hosted relay serves paying or trialling users only;
everything is off by default, so a self-hosted relay stays free):
  RELAY_ENTITLEMENT    "on" makes a request need a subscription linked to
                       its channel (402 otherwise); "off" (default)
  RELAY_APPSTORE_BUNDLE_ID  the app's bundle id, default org.clavix.approve
  RELAY_APPSTORE_PRODUCTS   comma-separated product ids accepted, default
                       org.clavix.approve.personal.monthly,
                       org.clavix.approve.personal.yearly
  RELAY_APPSTORE_SANDBOX    "on" also accepts Sandbox transactions
                       (TestFlight); "off" (default)
  RELAY_MACHINES_PER_SUBSCRIPTION  channels one subscription covers (10)
  RELAY_ENTITLEMENT_GRACE_HOURS    hours a request is still served after
                       the subscription's expiry, for a renewal the
                       phone has not re-sent yet (48; 0 for none)

Client address (what the per-address limits count against):
  RELAY_CLIENT_IP_HEADER      a header set by the reverse proxy to the
                              client's address, overwriting what the client
                              sent (e.g. X-Real-IP); when set, it is the only
                              source. Missing, malformed, private, loopback
                              or link-local values all count as one shared
                              address ("unknown"): never a way around limits
  RELAY_TRUSTED_PROXIES       without that header: reverse proxies in front
                              that append to X-Forwarded-For, read from the
                              right; 0 (default) uses the peer address

Limits (environment, positive integers; see Limits below for each default):
  RELAY_CHANNELS_PER_IP_HOUR  channels one client address may create per
  RELAY_CHANNELS_PER_IP_DAY   hour (10) and per day (30); IPv6 by /64
  RELAY_MAX_CHANNELS          global safety cap on channels (100000)
  RELAY_CHANNEL_IDLE_DAYS     a channel unused that long is deleted (90)
  RELAY_MAX_DEVICES           devices paired on one channel (4)
  RELAY_CHANNELS_PER_DEVICE   channels one device's push token serves: one
                              phone paired with that many machines (32)
  RELAY_REQUESTS_PER_MINUTE   requests one channel may post per minute (60)
  RELAY_MAX_PENDING           live requests waiting on one channel (8)
  RELAY_MAX_ENTRIES           requests stored on one channel, answered,
                              cancelled and expired ones included (32)
  RELAY_MAX_MSG               bytes of one request or response msg (16384)
  RELAY_MAX_BODY              bytes of one HTTP request body (32768)
  RELAY_PENDING_BUDGET        bytes of request and response data held in
                              memory across all channels (67108864)
  RELAY_PUSH_INTERVAL         seconds between two pushes to one channel or
                              one device (10)
  RELAY_PUSH_PER_DAY          pushes to one channel or one device per day (100)
  RELAY_PUSH_WORKERS          threads sending pushes (4)
  RELAY_PUSH_QUEUE            pushes waiting to be sent; more are dropped (1000)
  RELAY_POLLS_PER_TOKEN       concurrent long-polls per token (8)
  RELAY_POLLS_PER_IP          concurrent long-polls per client address (64)
  RELAY_MAX_CONNECTIONS       concurrent connections; more get 503 (512)
  RELAY_SOCKET_TIMEOUT        seconds a client may stay silent mid-request (30)

State: RELAY_STATE_DIR/state.db (SQLite, WAL), one row per channel,
written when that channel changes, plus the subscriptions (one row per
App Store original transaction id) and which channel uses which. A state.json left by an older version
is imported on first start and renamed state.json.migrated. Pending
requests live in memory only.

Usage: relay.py              run the service
       relay.py --selftest   check the push encryption offline
       relay.py --healthcheck  exit 0 when the local service answers
"""
import base64
import binascii
import collections
import dataclasses
import datetime
import hashlib
import hmac
import ipaddress
import json
import math
import os
import queue
import re
import sqlite3
import struct
import sys
import signal
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))

CHANNEL_RE = re.compile(r"^[0-9a-f]{32}$")
REQUEST_RE = re.compile(r"^[0-9a-f]{32}$")
SIGNER_RE = re.compile(r"^[0-9a-f]{16}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")   # 32 bytes, base64url
KNOWN_RE = re.compile(r"^([0-9a-f]{32}(,[0-9a-f]{32}){0,31})?$")
# An APNs device token: 32 bytes today, Apple says the length may grow.
APNS_TOKEN_RE = re.compile(r"^(?:[0-9a-f]{2}){32,100}$")
APNS_ID_RE = re.compile(r"^[0-9A-Z]{10}$")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

# Fixed by the protocol. The tunable limits are in Limits.
MAX_BODY = 32 * 1024        # one HTTP request body (default of RELAY_MAX_BODY)
MAX_MSG = 16 * 1024         # one request or response (default of RELAY_MAX_MSG)
MAX_BLOB = 8 * 1024         # pairing hello / answer
MAX_PENDING = 8             # live sign requests on one channel (default)
MAX_SIGNERS = 4             # devices paired on one channel (default)
MAX_TTL = 300               # seconds a sign request may ask to live
MAX_WAIT = 25               # long-poll cap, under usual proxy read timeouts
MAX_ENDPOINT = 1024         # a Web Push endpoint URL
PAIR_WINDOW = 900           # seconds to complete a pairing
KEEP_AFTER_EXPIRY = 60      # an agent can still learn "expired" that long
ACTIVITY_GRAIN = 3600       # last activity is written to disk at most this often
SWEEP_EVERY = 60            # seconds between two sweeps of expired state

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


# ---- Limits -----------------------------------------------------------------

@dataclasses.dataclass
class Limits:
    """Every tunable limit. Field `x` is read from RELAY_X (upper case)."""
    trusted_proxies: int = 0
    channels_per_ip_hour: int = 10
    channels_per_ip_day: int = 30
    max_channels: int = 100_000
    channel_idle_days: int = 90
    max_devices: int = MAX_SIGNERS
    channels_per_device: int = 32
    requests_per_minute: int = 60
    max_pending: int = MAX_PENDING
    max_entries: int = 32
    max_msg: int = MAX_MSG
    max_body: int = MAX_BODY
    pending_budget: int = 64 * 1024 * 1024
    push_interval: int = 10
    push_per_day: int = 100
    push_workers: int = 4
    push_queue: int = 1000
    polls_per_token: int = 8
    polls_per_ip: int = 64
    max_connections: int = 512
    socket_timeout: int = 30

    @classmethod
    def from_env(cls, env):
        values = {}
        for f in dataclasses.fields(cls):
            raw = env.get("RELAY_" + f.name.upper())
            if raw is None or raw == "":
                continue
            try:
                value = int(raw)
            except ValueError:
                raise ValueError(f"RELAY_{f.name.upper()} must be an integer") from None
            if value < (0 if f.name == "trusted_proxies" else 1):
                raise ValueError(f"RELAY_{f.name.upper()} is out of range")
            values[f.name] = value
        return cls(**values)


class RateLimit:
    """At most `limit` events per `period` seconds and key (sliding log).

    Not thread-safe on its own: the relay calls it with its lock held.
    """

    def __init__(self, limit, period, now):
        self.limit, self.period, self.now = limit, period, now
        self.log = {}
        self.swept = now()

    def retry_after(self, key):
        """0 when one more event is allowed, else the seconds to wait."""
        now = self.now()
        q = self.log.get(key)
        if not q:
            return 0
        while q and q[0] <= now - self.period:
            q.popleft()
        if len(q) < self.limit:
            return 0
        return max(1, math.ceil(q[0] + self.period - now))

    def hit(self, key):
        now = self.now()
        self.log.setdefault(key, collections.deque()).append(now)
        if now - self.swept > self.period:   # forget keys with nothing recent
            self.swept = now
            for k in [k for k, q in self.log.items() if not q or q[-1] <= now - self.period]:
                del self.log[k]

    def take(self, key):
        """Count one event if allowed; returns what retry_after returned."""
        wait = self.retry_after(key)
        if not wait:
            self.hit(key)
        return wait


class Slots:
    """At most `limit` concurrent holders per key."""

    def __init__(self, limit):
        self.limit = limit
        self.held = {}
        self.lock = threading.Lock()

    def acquire(self, key):
        with self.lock:
            n = self.held.get(key, 0)
            if n >= self.limit:
                return False
            self.held[key] = n + 1
            return True

    def release(self, key):
        with self.lock:
            n = self.held.get(key, 0) - 1
            if n > 0:
                self.held[key] = n
            else:
                self.held.pop(key, None)


class PushQueue:
    """A bounded queue served by a few threads, instead of one thread per
    push. A push that does not fit is dropped: the device's long-poll, or
    the next request, still finds the request."""

    def __init__(self, workers, size):
        self.workers = workers
        self.q = queue.Queue(size)
        self.started = False
        self.lock = threading.Lock()

    def submit(self, fn, *args):
        with self.lock:
            if not self.started:
                self.started = True
                for _ in range(self.workers):
                    threading.Thread(target=self._run, daemon=True).start()
        try:
            self.q.put_nowait((fn, args))
            return True
        except queue.Full:
            return False

    def _run(self):
        while True:
            fn, args = self.q.get()
            try:
                fn(*args)
            except Exception as e:  # a push must never take a worker down
                log(f"push worker: {type(e).__name__}: {e}")


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
APNS_ALERT = {"title": "Clavix", "body": "Une demande de signature attend"}


def apns_group(ch):
    """The notification group of a channel, sent as apns-collapse-id and
    thread-id: a new push replaces the one shown instead of piling up, so a
    device shows at most one "a request waits" per channel. Derived, so
    Apple never sees the channel id itself."""
    return hashlib.sha256(b"clavix-approve/apns-group\0" + ch.encode()).hexdigest()[:32]


def apns_payload(group=None):
    aps = {"alert": APNS_ALERT, "sound": "default", "interruption-level": "time-sensitive"}
    if group:
        aps["thread-id"] = group
    return json.dumps({"aps": aps}, ensure_ascii=False, separators=(",", ":")).encode()


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

    def send(self, sub, payload, group=None):
        """`payload` is the Web Push one; APNs always gets the constant
        alert, grouped by `group` (see apns_group) when given."""
        where = "APNs sandbox" if sub["sandbox"] else "APNs"
        if not self.enabled:
            return f"push disabled, not sent to {where}", False
        url = f"{APNS_HOSTS[bool(sub['sandbox'])]}/3/device/{sub['apns']}"
        with self.lock:   # one HTTP/2 connection per host, shared; pushes are rare
            headers = {"authorization": f"bearer {self._token()}",
                       "apns-topic": self.topic, "apns-push-type": "alert",
                       "apns-priority": "10",
                       "apns-expiration": str(int(self.now()) + APNS_TTL)}
            if group:
                headers["apns-collapse-id"] = group
            try:
                r = self.client.post(url, content=apns_payload(group), headers=headers)
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

    def send(self, sub, payload, group=None):
        if "apns" in sub:
            if self.apns is None:
                return "APNs not configured, not sent", False
            return self.apns.send(sub, payload, apns_group(group) if group else None)
        return self.webpush.send(sub, payload)


def valid_webpush_keys(keys):
    """A subscription's p256dh is a P-256 point, its auth 16 bytes (RFC 8291)."""
    if not isinstance(keys, dict):
        return False
    p256dh, auth = keys.get("p256dh"), keys.get("auth")
    if not (isinstance(p256dh, str) and isinstance(auth, str) and len(p256dh) <= 100
            and len(auth) <= 32 and B64U_RE.match(p256dh) and B64U_RE.match(auth)):
        return False
    try:
        raw, secret = unb64u(p256dh.rstrip("=")), unb64u(auth.rstrip("="))
        if len(raw) != 65 or len(secret) != 16:
            return False
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except (ValueError, binascii.Error):
        return False
    return True


def sub_key(sub):
    """What identifies one device to the push service, across channels."""
    return "apns:" + sub["apns"] if "apns" in sub else "web:" + sub["endpoint"]


# ---- Subscriptions (App Store, StoreKit 2) ----------------------------------
#
# The phone sends the JWS StoreKit 2 gives it for its subscription
# (Transaction.jwsRepresentation). It is verified here, offline: signed
# ES256 by the leaf of an x5c chain that ends at Apple Root CA - G3,
# pinned below (it is public). What is kept: the original transaction id,
# the product, the expiry and the environment; nothing about the person.
#
# An entitlement is keyed "<kind>:<id>". The App Store is the only kind
# for now ("appstore:<originalTransactionId>"); team licences sold on the
# website would be another kind ("licence:<key id>") with its own seat
# count, linked to channels the same way.

# Apple Root CA - G3, https://www.apple.com/certificateauthority/
# SHA-256 63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79
APPLE_ROOT_CA_G3_PEM = b"""-----BEGIN CERTIFICATE-----
MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517
IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA
MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4
at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM
6BgD56KyKA==
-----END CERTIFICATE-----
"""
# Marker extensions Apple puts on the certificates that sign App Store data.
APPLE_LEAF_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.11.1")
APPLE_INTERMEDIATE_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.2.1")
APPSTORE_PRODUCTS = ("org.clavix.approve.personal.monthly", "org.clavix.approve.personal.yearly")
CLOCK_SKEW = 300            # seconds a signedDate may be ahead of our clock
MAX_JWS = 64 * 1024         # one JWS, x5c included
MAX_X5C = 8 * 1024          # one certificate of it, base64
NOTIFICATION_BODY = 128 * 1024   # an App Store notification nests three JWS
OTID_RE = re.compile(r"^[0-9A-Za-z._-]{1,64}$")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9.-]{1,155}$")
ENDED_KEEP_DAYS = 30        # an entitlement no channel uses is forgotten that long after it ended


class JwsError(ValueError):
    """A JWS that is not one Apple signed for this app; the message is a
    short reason, safe to return to the client."""


def _utc(cert, field):
    value = getattr(cert, field + "_utc", None)   # cryptography >= 42
    if value is None:
        value = getattr(cert, field).replace(tzinfo=datetime.timezone.utc)
    return value


def _has_extension(cert, oid):
    try:
        cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return False
    return True


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def load_apple_root():
    return x509.load_pem_x509_certificate(APPLE_ROOT_CA_G3_PEM)


def verify_apple_jws(token, root, now):
    """The payload of a JWS signed by Apple, or JwsError.

    ES256 only; the header's x5c is [leaf, intermediate(, root)]. The leaf
    must be issued by the intermediate and the intermediate by `root` (our
    pinned copy: an x5c root, if present, must be that same certificate),
    each signature checked, each certificate valid at the payload's
    signedDate, which may not be in the future. That is the date Apple's
    own library checks against when it verifies offline: a transaction
    signed while the chain was valid stays verifiable after its leaf
    expires. The leaf and intermediate carry Apple's marker extensions,
    the intermediate is a CA, the leaf key is P-256.
    """
    if not isinstance(token, str) or len(token) > MAX_JWS:
        raise JwsError("format")
    parts = token.split(".")
    if len(parts) != 3 or not all(p and B64U_RE.match(p) for p in parts):
        raise JwsError("format")
    try:
        header = json.loads(unb64u(parts[0]))
        payload = json.loads(unb64u(parts[1]))
        signature = unb64u(parts[2])
    except (ValueError, binascii.Error):
        raise JwsError("format") from None
    if not (isinstance(header, dict) and isinstance(payload, dict)):
        raise JwsError("format")
    if header.get("alg") != "ES256":
        raise JwsError("algorithm")
    x5c = header.get("x5c")
    if not (isinstance(x5c, list) and len(x5c) in (2, 3)
            and all(isinstance(c, str) and len(c) <= MAX_X5C for c in x5c)):
        raise JwsError("chain")
    try:
        certs = [x509.load_der_x509_certificate(base64.b64decode(c, validate=True)) for c in x5c]
    except (ValueError, binascii.Error):
        raise JwsError("chain") from None
    leaf, intermediate = certs[0], certs[1]
    if len(certs) == 3 and certs[2] != root:
        raise JwsError("chain")
    for cert, issuer in ((leaf, intermediate), (intermediate, root)):
        try:
            cert.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature):
            raise JwsError("chain") from None
    if not (_is_ca(intermediate) and _has_extension(intermediate, APPLE_INTERMEDIATE_OID)
            and _has_extension(leaf, APPLE_LEAF_OID) and not _is_ca(leaf)):
        raise JwsError("chain")
    key = leaf.public_key()
    if not (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
        raise JwsError("chain")
    if len(signature) != 64:
        raise JwsError("signature")
    try:
        key.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                        int.from_bytes(signature[32:], "big")),
                   f"{parts[0]}.{parts[1]}".encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise JwsError("signature") from None
    signed = payload.get("signedDate")
    if not (isinstance(signed, int) and not isinstance(signed, bool) and signed > 0):
        raise JwsError("format")
    if signed / 1000 > now + CLOCK_SKEW:
        raise JwsError("date")
    at = datetime.datetime.fromtimestamp(signed / 1000, datetime.timezone.utc)
    for cert in (leaf, intermediate, root):
        if not _utc(cert, "not_valid_before") <= at <= _utc(cert, "not_valid_after"):
            raise JwsError("validity")
    return payload


@dataclasses.dataclass
class Transaction:
    """What the relay keeps of one App Store transaction."""
    otid: str           # originalTransactionId: the same across renewals
    product: str
    expires: int        # seconds since the epoch
    environment: str    # Production or Sandbox
    revoked: bool       # refunded, or revoked by Apple
    signed_at: int      # the JWS's signedDate, milliseconds

    @property
    def eid(self):
        return "appstore:" + self.otid


def _ms(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


@dataclasses.dataclass
class Entitlements:
    """Subscription settings. Off: no check at all, as before."""
    enabled: bool = False
    bundle_id: str = "org.clavix.approve"
    products: tuple = APPSTORE_PRODUCTS
    sandbox: bool = False
    machines: int = 10
    grace_hours: int = 48
    root: object = None   # Apple Root CA - G3; tests inject their own

    def __post_init__(self):
        if self.root is None:
            self.root = load_apple_root()

    @property
    def grace(self):
        return self.grace_hours * 3600

    def environment_allowed(self, environment):
        return environment == "Production" or (self.sandbox and environment == "Sandbox")

    def transaction(self, payload, signed_at=None):
        """The Transaction a verified JWS payload describes, for this app,
        or JwsError. Its expiry and revocation are not judged here."""
        if payload.get("bundleId") != self.bundle_id:
            raise JwsError("bundle")
        product = payload.get("productId")
        if product not in self.products:
            raise JwsError("product")
        if not self.environment_allowed(payload.get("environment")):
            raise JwsError("environment")
        otid = payload.get("originalTransactionId")
        expires = _ms(payload.get("expiresDate"))
        if not (isinstance(otid, str) and OTID_RE.match(otid)) or expires is None:
            raise JwsError("format")
        return Transaction(otid, product, expires // 1000, payload["environment"],
                           payload.get("revocationDate") is not None,
                           payload["signedDate"] if signed_at is None else signed_at)

    @classmethod
    def from_env(cls, env, root=None):
        def switch(name):
            raw = env.get(name, "").strip().lower()
            if raw in ("", "off", "0", "false", "no"):
                return False
            if raw in ("on", "1", "true", "yes"):
                return True
            raise ValueError(f"{name} must be on or off")

        def number(name, default, minimum):
            raw = env.get(name, "")
            if raw == "":
                return default
            try:
                value = int(raw)
            except ValueError:
                raise ValueError(f"{name} must be an integer") from None
            if value < minimum:
                raise ValueError(f"{name} is out of range")
            return value

        bundle = env.get("RELAY_APPSTORE_BUNDLE_ID", "") or cls.bundle_id
        if not BUNDLE_RE.match(bundle):
            raise ValueError("RELAY_APPSTORE_BUNDLE_ID is not a bundle id")
        raw = env.get("RELAY_APPSTORE_PRODUCTS", "")
        products = tuple(p.strip() for p in raw.split(",") if p.strip()) if raw else APPSTORE_PRODUCTS
        if not products or not all(BUNDLE_RE.match(p) for p in products):
            raise ValueError("RELAY_APPSTORE_PRODUCTS must list product ids")
        return cls(enabled=switch("RELAY_ENTITLEMENT"), bundle_id=bundle, products=products,
                   sandbox=switch("RELAY_APPSTORE_SANDBOX"),
                   machines=number("RELAY_MACHINES_PER_SUBSCRIPTION", cls.machines, 1),
                   grace_hours=number("RELAY_ENTITLEMENT_GRACE_HOURS", cls.grace_hours, 0),
                   root=root)


# ---- Storage ----------------------------------------------------------------

class Store:
    """Channels in SQLite, one row each, written when that channel changes.

    Used with the relay's lock held, from any thread.
    """

    def __init__(self, state_dir):
        path = os.path.join(state_dir, "state.db")
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))   # never world-readable
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS channels (ch TEXT PRIMARY KEY, data TEXT NOT NULL)")
        # Subscriptions, keyed "<kind>:<id>" (see Entitlements), and which
        # channel uses which one.
        self.db.execute("CREATE TABLE IF NOT EXISTS entitlements (eid TEXT PRIMARY KEY, "
                        "product TEXT NOT NULL, expires INTEGER NOT NULL, "
                        "environment TEXT NOT NULL, status TEXT NOT NULL, "
                        "signed_at INTEGER NOT NULL, updated INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS channel_entitlements "
                        "(ch TEXT PRIMARY KEY, eid TEXT NOT NULL)")
        self._migrate(os.path.join(state_dir, "state.json"))

    def _migrate(self, legacy):
        """Import the state.json of an older version, once."""
        if not os.path.exists(legacy):
            return
        with open(legacy, encoding="utf-8") as f:
            channels = json.load(f).get("channels", {})
        now = int(time.time())
        with self.db:
            self.db.execute("BEGIN")
            for ch, c in channels.items():
                c.setdefault("last_active", now)
                self.db.execute("INSERT OR IGNORE INTO channels VALUES (?, ?)", (ch, json.dumps(c)))
        os.replace(legacy, legacy + ".migrated")
        log(f"imported {len(channels)} channels from state.json")

    def load(self):
        return {ch: json.loads(data) for ch, data in self.db.execute("SELECT ch, data FROM channels")}

    def put(self, ch, c):
        self.db.execute("INSERT OR REPLACE INTO channels VALUES (?, ?)", (ch, json.dumps(c)))

    def delete(self, ch):
        self.db.execute("DELETE FROM channels WHERE ch = ?", (ch,))
        self.db.execute("DELETE FROM channel_entitlements WHERE ch = ?", (ch,))

    ENTITLEMENT_FIELDS = ("product", "expires", "environment", "status", "signed_at", "updated")

    def load_entitlements(self):
        """({eid: row}, {ch: eid})"""
        rows = {eid: dict(zip(self.ENTITLEMENT_FIELDS, rest)) for eid, *rest in self.db.execute(
            "SELECT eid, " + ", ".join(self.ENTITLEMENT_FIELDS) + " FROM entitlements")}
        links = dict(self.db.execute("SELECT ch, eid FROM channel_entitlements"))
        return rows, links

    def put_entitlement(self, eid, row):
        self.db.execute("INSERT OR REPLACE INTO entitlements VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (eid, *(row[f] for f in self.ENTITLEMENT_FIELDS)))

    def delete_entitlement(self, eid):
        self.db.execute("DELETE FROM entitlements WHERE eid = ?", (eid,))

    def link(self, ch, eid):
        self.db.execute("INSERT OR REPLACE INTO channel_entitlements VALUES (?, ?)", (ch, eid))

    def close(self):
        self.db.close()


# ---- Relay logic (HTTP-independent) ---------------------------------------

def limited(wait):
    """The answer to a client over a limit."""
    return 429, {"error": "rate limited", "retry_after": int(wait)}


class Relay:
    """Channels, pairing slots and pending requests.

    Every public method returns (HTTP status, JSON body or None). Message
    bodies (`hello`, `msg`) are opaque here.

    One lock guards the state; each channel has its own condition on that
    lock, so an event wakes the long-polls of its channel only.
    """

    def __init__(self, state_dir, enroll_secret=None, push=None, now=time.time, limits=None,
                 entitlements=None):
        self.enroll_auth = digest(enroll_secret) if enroll_secret else None
        self.limits = limits = limits or Limits()
        self.entitlements = entitlements or Entitlements()
        self.push = push
        self.now = now
        self.lock = threading.Lock()
        self.conds = {}
        self.store = Store(state_dir)
        self.channels = self.store.load()
        self.saved_active = {ch: c.get("last_active", 0) for ch, c in self.channels.items()}
        self.pending = {}   # channel -> {request id -> entry}; memory only
        self.pending_bytes = 0
        # sub_key -> {(channel, signer): None}, oldest registration first:
        # one phone paired with several machines is woken for each of them.
        self.subs = {}
        for ch, c in self.channels.items():
            for sid, s in c["signers"].items():
                if s.get("sub"):
                    self.subs.setdefault(sub_key(s["sub"]), {})[(ch, sid)] = None
        # Subscriptions: eid -> row, channel -> eid, and channels per eid.
        self.ents, self.links = self.store.load_entitlements()
        self.linked = collections.Counter(self.links.values())
        self.swept = 0
        self.created_hour = RateLimit(limits.channels_per_ip_hour, 3600, now)
        self.created_day = RateLimit(limits.channels_per_ip_day, 86400, now)
        self.request_rate = RateLimit(limits.requests_per_minute, 60, now)
        self.push_rates = (RateLimit(1, limits.push_interval, now),
                           RateLimit(limits.push_per_day, 86400, now))
        self.polls_token = Slots(limits.polls_per_token)
        self.polls_ip = Slots(limits.polls_per_ip)
        self.push_queue = PushQueue(limits.push_workers, limits.push_queue)

    @property
    def open_enrolment(self):
        return self.enroll_auth is None

    def close(self):
        self.store.close()

    # -- helpers (call with self.lock held) --

    def _cond(self, ch):
        cond = self.conds.get(ch)
        if cond is None:
            cond = self.conds[ch] = threading.Condition(self.lock)
        return cond

    def _notify(self, ch):
        cond = self.conds.get(ch)
        if cond is not None:
            cond.notify_all()

    def _save(self, ch):
        c = self.channels.get(ch)
        if c is None:
            self.store.delete(ch)
            self.saved_active.pop(ch, None)
        else:
            self.store.put(ch, c)
            self.saved_active[ch] = c["last_active"]

    def _touch(self, ch, c):
        """Note activity; written to disk at most once per ACTIVITY_GRAIN."""
        now = int(self.now())
        c["last_active"] = now
        if now - self.saved_active.get(ch, 0) >= ACTIVITY_GRAIN:
            self._save(ch)

    def _set(self, e, field, value):
        """Change an entry's msg or response, keeping the byte count."""
        self.pending_bytes += len(value or "") - len(e[field] or "")
        e[field] = value

    def _forget_entries(self, ch, keep=lambda e: False):
        entries = self.pending.get(ch, {})
        for rid, e in list(entries.items()):
            if not keep(e):
                self._set(e, "msg", None)
                self._set(e, "response", None)
                del entries[rid]
        if not entries:
            self.pending.pop(ch, None)

    def _set_sub(self, ch, sid, sub):
        """Give a signer its subscription. One device (one push token) may
        serve several channels, one per machine it is paired with, up to
        `channels_per_device`: past it, the oldest registration loses it.
        The push budget stays per device across them (`_push_allowed`)."""
        signer = self.channels[ch]["signers"][sid]
        old = signer.get("sub")
        if old:
            holders = self.subs.get(sub_key(old), {})
            holders.pop((ch, sid), None)
            if not holders:
                self.subs.pop(sub_key(old), None)
        signer["sub"] = sub
        if sub:
            holders = self.subs.setdefault(sub_key(sub), {})
            holders[(ch, sid)] = None   # (re)registered: now the newest
            while len(holders) > self.limits.channels_per_device:
                och, osid = next(iter(holders))
                del holders[(och, osid)]
                prev = self.channels.get(och, {}).get("signers", {}).get(osid)
                if prev is not None:
                    prev["sub"] = None
                    self._save(och)
                log(f"channel {och[:8]}: push target dropped, its device serves too many channels")

    def _drop_channel(self, ch):
        c = self.channels.get(ch)
        if c is None:
            return
        for sid in list(c["signers"]):
            self._set_sub(ch, sid, None)
        del self.channels[ch]
        self._forget_entries(ch)
        eid = self.links.pop(ch, None)   # frees a machine of its subscription
        if eid is not None:
            self.linked[eid] -= 1
            if self.linked[eid] <= 0:
                del self.linked[eid]
        self._save(ch)
        self._notify(ch)
        self.conds.pop(ch, None)

    def _purge_pending(self, ch):
        now = self.now()
        for e in self.pending.get(ch, {}).values():
            if e["exp"] <= now and e["msg"] is not None:
                self._set(e, "msg", None)   # no longer offered: no need to hold it
        self._forget_entries(ch, keep=lambda e: e["exp"] + KEEP_AFTER_EXPIRY >= now)

    def _sweep(self):
        """Expire what time has made useless; at most once per SWEEP_EVERY."""
        now = self.now()
        if now - self.swept < SWEEP_EVERY:
            return
        self.swept = now
        for ch in list(self.pending):
            self._purge_pending(ch)
        idle = self.limits.channel_idle_days * 86400
        for ch, c in list(self.channels.items()):
            if (not c["signers"] and c["created"] + PAIR_WINDOW < now) \
                    or c.get("last_active", c["created"]) + idle < now:
                self._drop_channel(ch)
                log(f"channel {ch[:8]} expired")
            elif c.get("pair_until", 0) < now and (c["hello"] or c["answer"] or c["pair_auth"]):
                c.update(hello=None, answer=None, pair_auth=None)   # pairing over
                self._save(ch)
        # A subscription no channel uses, ended long enough ago that any
        # JWS of it would be refused as expired anyway (a revoked one is
        # kept until then, so that an older JWS cannot bring it back).
        for eid, row in list(self.ents.items()):
            if eid not in self.linked and row["expires"] + ENDED_KEEP_DAYS * 86400 < now:
                del self.ents[eid]
                self.store.delete_entitlement(eid)

    def _channel(self, ch, token, role):
        """The channel if `token` holds `role` on it, plus the signer id."""
        c = self.channels.get(ch) if isinstance(ch, str) else None
        if c is None or not token:
            return None, None
        given = digest(token)
        if role == "signer":
            for sid, s in c["signers"].items():
                if hmac.compare_digest(given, s["auth"]):
                    self._touch(ch, c)
                    return c, sid
            return None, None
        if role == "pair" and c.get("pair_until", float("inf")) < self.now():
            return None, None
        expected = c.get(role + "_auth")
        if expected and hmac.compare_digest(given, expected):
            self._touch(ch, c)
            return c, None
        return None, None

    def _wait(self, ready, wait, ch, c=None, sid=None):
        """Block until ready() is truthy or `wait` seconds passed.

        Given the channel the caller holds (and, for a signer, its id),
        returns GONE as soon as that channel or signer is revoked, so a
        long-poll does not outlive its pairing.
        """
        cond = self._cond(ch)
        deadline = time.monotonic() + max(0.0, min(float(wait or 0), MAX_WAIT))
        while True:
            if c is not None and (self.channels.get(ch) is not c
                                  or (sid is not None and sid not in c["signers"])):
                return self.GONE
            result = ready()
            remaining = deadline - time.monotonic()
            if result or remaining <= 0:
                return result
            cond.wait(remaining)

    DENIED = (401, {"error": "unauthorized"})
    GONE = object()
    BAD = (400, {"error": "bad request"})
    SUBSCRIPTION_REQUIRED = (402, {"error": "subscription_required"})

    # -- long-poll slots (used by the HTTP layer around a call with wait > 0) --

    def acquire_poll(self, token, ip):
        """Reserve a long-poll slot for this token and client address.
        Returns a release function, or None when either is at its limit."""
        tkey = digest(token or "")
        if not self.polls_token.acquire(tkey):
            return None
        if ip is not None and not self.polls_ip.acquire(ip):
            self.polls_token.release(tkey)
            return None

        def release():
            self.polls_token.release(tkey)
            if ip is not None:
                self.polls_ip.release(ip)
        return release

    # -- pairing --

    def create_channel(self, token, body, ip=None):
        """Open enrolment takes any token, or none; closed enrolment needs
        the secret. `ip` is the client address the per-address limits
        count against (None: not counted, for tests and tools)."""
        if self.enroll_auth is not None and not (
                token and hmac.compare_digest(digest(token), self.enroll_auth)):
            return self.DENIED
        ch, hello = body.get("ch"), body.get("hello")
        auths = (body.get("agent_auth"), body.get("pair_auth"))
        if not (isinstance(ch, str) and CHANNEL_RE.match(ch)
                and all(isinstance(a, str) and HASH_RE.match(a) for a in auths)
                and isinstance(hello, str) and len(hello) <= MAX_BLOB):
            return self.BAD
        with self.lock:
            self._sweep()
            if ch in self.channels:
                return 200, {"state": "exists"}
            if len(self.channels) >= self.limits.max_channels:
                log("channel cap reached")
                return 200, {"state": "full"}
            if ip is not None:
                wait = max(self.created_hour.retry_after(ip), self.created_day.retry_after(ip))
                if wait:
                    return limited(wait)
                self.created_hour.hit(ip)
                self.created_day.hit(ip)
            now = int(self.now())
            self.channels[ch] = {"agent_auth": auths[0], "pair_auth": auths[1], "hello": hello,
                                 "answer": None, "created": now, "signers": {},
                                 "pair_until": now + PAIR_WINDOW, "last_active": now}
            self._save(ch)
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
        with self.lock:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            if len(c["signers"]) >= self.limits.max_devices:
                return 200, {"state": "full"}
            c.update(pair_auth=pair_auth, hello=hello, answer=None,
                     pair_until=int(self.now()) + PAIR_WINDOW)
            self._save(ch)
        log(f"channel {ch[:8]} open for one more device")
        return 200, {"state": "open"}

    def get_hello(self, ch, token):
        with self.lock:
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
        with self.lock:
            c, _ = self._channel(ch, token, "pair")
            if c is None:
                return self.DENIED
            if len(c["signers"]) >= self.limits.max_devices or signer in c["signers"]:
                return 200, {"state": "full"}
            c["signers"][signer] = {"auth": auth, "sub": None}
            c["answer"] = {"signer": signer, "msg": msg}
            c["pair_auth"] = None   # the pairing secret works once
            self._save(ch)
            self._notify(ch)
        log(f"channel {ch[:8]} paired with signer {signer[:4]}")
        return 200, {"state": "paired"}

    def get_pair_answer(self, ch, token, wait=0):
        with self.lock:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            answer = self._wait(lambda: c["answer"], wait, ch, c)
            if answer is self.GONE:
                return self.DENIED
            if not answer:
                return 204, None
            return 200, {"state": "answered", **answer}

    def post_reveal(self, ch, token, body):
        """The agent hands a device the nonce its hello committed to.

        Opaque here: the device checks it against the commitment. Accepted
        once per device; the device fetches it with its own token.
        """
        signer, nonce = body.get("signer"), body.get("nonce")
        if not (isinstance(signer, str) and SIGNER_RE.match(signer)
                and isinstance(nonce, str) and NONCE_RE.match(nonce)):
            return self.BAD
        with self.lock:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            s = c["signers"].get(signer)
            if s is None:
                return 200, {"state": "unknown-signer"}
            if s.get("reveal") is not None:
                return 200, {"state": "exists"}
            s["reveal"] = nonce
            self._save(ch)
            self._notify(ch)
        return 200, {"state": "revealed"}

    def get_reveal(self, ch, token, wait=0):
        """The agent's nonce, for the device that holds `token`. With
        `wait`, a long-poll on this channel's condition."""
        with self.lock:
            c, sid = self._channel(ch, token, "signer")
            if c is None:
                return self.DENIED
            nonce = self._wait(lambda: c["signers"][sid].get("reveal")
                               if sid in c["signers"] else None, wait, ch, c, sid)
            if nonce is self.GONE:
                return self.DENIED
            if not nonce:
                return 204, None
            return 200, {"nonce": nonce}

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
        with self.lock:
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
                self._set_sub(ch, target, None)
                del c["signers"][target]
                self._forget_entries(ch, keep=lambda e: e["to"] != target)
            if target is None or not c["signers"]:
                self._drop_channel(ch)
                what = "channel"
            else:
                what = f"signer {target[:4]}"
                self._save(ch)
                self._notify(ch)
        log(f"channel {ch[:8]}: {what} revoked by the {by}")
        return 200, {"state": "revoked"}

    # -- signer side --

    def put_subscription(self, ch, token, body):
        """Store how to wake this signer: a Web Push subscription
        `{endpoint, keys: {p256dh, auth}}` or an APNs device token
        `{apns: hex, sandbox: bool}`. A relay without APNs answers
        `unsupported` to the latter and keeps what it had. One device
        (endpoint or token) wakes for one channel only: the latest one."""
        if "apns" in body:
            if not (isinstance(body["apns"], str) and APNS_TOKEN_RE.match(body["apns"])
                    and isinstance(body.get("sandbox"), bool)):
                return self.BAD
            sub = {"apns": body["apns"], "sandbox": body["sandbox"]}
        else:
            endpoint, keys = body.get("endpoint"), body.get("keys")
            if not (push_host_allowed(endpoint) and len(endpoint) <= MAX_ENDPOINT
                    and valid_webpush_keys(keys)):
                return self.BAD
            sub = {"endpoint": endpoint, "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]}}
        with self.lock:
            c, sid = self._channel(ch, token, "signer")
            if c is None:
                return self.DENIED
            if "apns" in sub and not getattr(self.push, "supports_apns", False):
                return 200, {"state": "unsupported"}
            self._set_sub(ch, sid, sub)
            self._save(ch)
        return 200, {"state": "stored"}

    def get_requests(self, ch, token, wait=0, known=None):
        """Pending requests of this signer.

        With `wait`, blocks until there is something the caller has not
        seen: `known` is the set of request ids it already holds, and the
        call returns as soon as the pending set differs from it. Without
        `known`, any pending request counts as news.
        """
        with self.lock:
            c, sid = self._channel(ch, token, "signer")
            if c is None:
                return self.DENIED

            def waiting():
                now = self.now()
                return [{"id": rid, "exp": e["exp"], "msg": e["msg"]}
                        for rid, e in self.pending.get(ch, {}).items()
                        if e["to"] == sid and e["response"] is None and e["exp"] > now
                        and e["msg"] is not None]

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
        if not (isinstance(msg, str) and len(msg) <= self.limits.max_msg):
            return self.BAD
        with self.lock:
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
            self._set(e, "msg", None)   # answered: the request is no longer offered
            self._set(e, "response", msg)
            self._notify(ch)
        return 200, {"state": "accepted"}

    # -- agent side --

    def post_request(self, ch, token, body):
        rid, to, exp, msg = body.get("id"), body.get("to"), body.get("exp"), body.get("msg")
        if not (isinstance(rid, str) and REQUEST_RE.match(rid) and isinstance(to, str)
                and isinstance(exp, (int, float)) and not isinstance(exp, bool)
                and isinstance(msg, str) and len(msg) <= self.limits.max_msg):
            return self.BAD
        with self.lock:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            wait = self.request_rate.take(ch)
            if wait:
                return limited(wait)
            if self.entitlements.enabled and not self._entitled(ch):
                return self.SUBSCRIPTION_REQUIRED
            self._sweep()
            self._purge_pending(ch)
            now = self.now()
            signer = c["signers"].get(to)
            if signer is None:
                return 200, {"state": "unknown-signer"}
            if not now < exp <= now + MAX_TTL:
                return 200, {"state": "expired"}
            entries = self.pending.setdefault(ch, {})
            if rid in entries:
                return 200, {"state": "duplicate"}
            # Every stored entry counts, cancelled and answered ones too:
            # a cancel or answer loop cannot grow the queue.
            live = sum(1 for e in entries.values() if e["response"] is None and e["exp"] > now)
            if len(entries) >= self.limits.max_entries or live >= self.limits.max_pending:
                return 200, {"state": "busy"}
            if self.pending_bytes + len(msg) > self.limits.pending_budget:
                log("pending budget exhausted")
                return 503, {"error": "relay busy", "retry_after": 5}
            e = entries[rid] = {"to": to, "exp": exp, "msg": None, "response": None, "seen": False}
            self._set(e, "msg", msg)
            sub = signer["sub"]
            pushed = bool(sub and self.push) and self._push_allowed(ch, sub) \
                and self.push_queue.submit(self._wake, ch, to, sub)
            self._notify(ch)
        return 200, {"state": "queued", "push": pushed}

    def _push_allowed(self, ch, sub):
        """At most one push per interval and so many a day, both per
        channel and per device: a channel cannot buzz a device at will,
        nor make the relay hammer the push service with a junk token."""
        keys = ("ch:" + ch, sub_key(sub))
        if any(rate.retry_after(k) for rate in self.push_rates for k in keys):
            return False
        for rate in self.push_rates:
            for k in keys:
                rate.hit(k)
        return True

    def cancel(self, ch, token, rid):
        """The agent gave up on a request: the device no longer offers it."""
        with self.lock:
            c, _ = self._channel(ch, token, "agent")
            if c is None:
                return self.DENIED
            e = self.pending.get(ch, {}).get(rid)
            if e is None or e["response"] is not None:
                return 200, {"state": "unknown"}
            e["exp"] = min(e["exp"], self.now())
            self._set(e, "msg", None)
            self._notify(ch)
        return 200, {"state": "cancelled"}

    def _wake(self, ch, sid, sub):
        outcome, gone = self.push.send(sub, {"t": "sign"}, group=ch)   # content-free
        log(f"channel {ch[:8]}: {outcome}")
        if gone:
            with self.lock:
                signer = self.channels.get(ch, {}).get("signers", {}).get(sid)
                if signer and signer["sub"] == sub:
                    self._set_sub(ch, sid, None)
                    self._save(ch)

    def get_response(self, ch, token, rid, wait=0, report_seen=False):
        """The answer to a request. "Nothing yet" is 204, or with
        `report_seen` 200 `pending` saying whether the device has fetched
        the request: an agent with another device to fall back on gives up
        on one that never picked it up."""
        with self.lock:
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

    # -- subscriptions --

    def _active(self, row, grace=0):
        """Whether an entitlement row entitles, `grace` seconds past its
        expiry. A subscription Apple said has ended gets no grace."""
        if row is None or row["status"] == "revoked":
            return False
        if row["status"] == "ended":
            grace = 0
        return row["expires"] + grace > self.now()

    def _entitled(self, ch):
        row = self.ents.get(self.links.get(ch))
        return self._active(row, self.entitlements.grace)

    def _record(self, tx, status, now):
        """Store what a verified transaction says, unless what is stored was
        signed later (an older JWS must not undo a renewal or a refund).
        Returns the row now stored."""
        row = self.ents.get(tx.eid)
        if row is not None and tx.signed_at < row["signed_at"]:
            return row
        row = {"product": tx.product, "expires": tx.expires, "environment": tx.environment,
               "status": status, "signed_at": tx.signed_at, "updated": int(now)}
        self.ents[tx.eid] = row
        self.store.put_entitlement(tx.eid, row)
        return row

    def post_entitlement(self, ch, dev, token, body):
        """The device `dev` hands over the JWS of its App Store subscription
        (StoreKit 2 Transaction.jwsRepresentation). Verified offline; when
        it is current, its channel is linked to it, within the machines one
        subscription covers. A relay that does not check subscriptions
        answers `required: false` without looking at it."""
        jws = body.get("jws")
        if not (isinstance(dev, str) and SIGNER_RE.match(dev)
                and isinstance(jws, str) and len(jws) <= MAX_JWS):
            return self.BAD
        with self.lock:
            c, sid = self._channel(ch, token, "signer")
            if c is None or sid != dev:
                return self.DENIED
        cfg = self.entitlements
        if not cfg.enabled:
            return 200, {"ok": True, "expires": None, "required": False}
        now = self.now()
        try:   # outside the lock: a few signature checks
            tx = cfg.transaction(verify_apple_jws(jws, cfg.root, now))
        except JwsError as e:
            log(f"channel {ch[:8]}: subscription refused ({e})")
            return 403, {"error": "invalid_transaction", "reason": str(e)}
        with self.lock:
            if self.channels.get(ch) is not c or dev not in c["signers"]:
                return self.DENIED
            row = self._record(tx, "revoked" if tx.revoked else "active", now)
            if not self._active(row):
                state = "revoked" if row["status"] == "revoked" else "expired"
                return 402, {"error": "subscription_required", "state": state,
                             "expires": row["expires"]}
            if self.links.get(ch) != tx.eid:
                if self.linked[tx.eid] >= cfg.machines:
                    log(f"channel {ch[:8]}: subscription at its machine limit")
                    return 403, {"error": "machine_limit", "limit": cfg.machines}
                old = self.links.get(ch)
                if old is not None:
                    self.linked[old] -= 1
                    if self.linked[old] <= 0:
                        del self.linked[old]
                self.links[ch] = tx.eid
                self.linked[tx.eid] += 1
                self.store.link(ch, tx.eid)
                log(f"channel {ch[:8]}: subscription linked ({tx.environment})")
        return 200, {"ok": True, "expires": row["expires"], "required": True}

    # App Store Server Notifications v2 that change an entitlement.
    NOTIFICATION_STATUS = {"DID_RENEW": "active", "EXPIRED": "ended",
                           "GRACE_PERIOD_EXPIRED": "ended", "REFUND": "revoked",
                           "REVOKE": "revoked"}

    def appstore_notification(self, body):
        """An App Store Server Notification v2 (`{signedPayload}`), sent by
        Apple. Verified like the phone's JWS, the transaction inside too.
        Only updates a subscription some phone already sent; everything
        else verified is acknowledged (200) so that Apple does not retry."""
        cfg = self.entitlements
        if not cfg.enabled:
            return 404, {"error": "not found"}
        now = self.now()
        try:
            payload = verify_apple_jws(body.get("signedPayload"), cfg.root, now)
            data = payload.get("data")
            if not isinstance(data, dict) or data.get("bundleId") != cfg.bundle_id:
                raise JwsError("bundle")
        except JwsError as e:
            log(f"App Store notification refused ({e})")
            return 400, {"error": "bad request"}
        kind = payload.get("notificationType")
        status = self.NOTIFICATION_STATUS.get(kind)
        if status is None or not cfg.environment_allowed(data.get("environment")) \
                or "signedTransactionInfo" not in data:
            return 200, {"ok": True, "state": "ignored"}
        try:
            tx = cfg.transaction(verify_apple_jws(data["signedTransactionInfo"], cfg.root, now),
                                 signed_at=payload["signedDate"])
        except JwsError as e:
            log(f"App Store notification {kind}: transaction refused ({e})")
            return 400, {"error": "bad request"}
        with self.lock:
            row = self.ents.get(tx.eid)
            if row is None:
                return 200, {"ok": True, "state": "unknown"}
            if tx.signed_at < row["signed_at"]:
                return 200, {"ok": True, "state": "stale"}
            if status == "ended":   # keep the expiry; only the grace goes
                tx.expires = min(tx.expires, row["expires"])
            self._record(tx, status, now)
        log(f"App Store notification {kind}: subscription {status}")
        return 200, {"ok": True, "state": status}


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


ROUTE = re.compile(r"^/api/ch/([0-9a-f]{32})/(pair|pair/answer|pair/open|pair/reveal|subscription|requests|revoke|"
                   r"responses/([0-9a-f]{32})|requests/([0-9a-f]{32})/cancel|"
                   r"dev/([0-9a-f]{16})/entitlement)$")
APPSTORE_NOTIFICATIONS = "/api/appstore/notifications"


UNKNOWN_CLIENT = "unknown"
POLL_RETRY_AFTER = 10   # seconds, for a long-poll over its limits


def header_address(value):
    """The client address from a header the proxy sets, failing closed:
    anything that is not a public address is the one shared bucket."""
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return UNKNOWN_CLIENT
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return UNKNOWN_CLIENT
    return client_address(str(ip), None, 0)


def client_address(peer, forwarded, trusted_proxies):
    """The address limits count against, as a string; an IPv6 client by
    its /64. With N trusted proxies, the client is the Nth address from
    the right of X-Forwarded-For (each proxy appends what it saw)."""
    addr = peer
    if trusted_proxies and forwarded:
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if hops:
            addr = hops[max(0, len(hops) - trusted_proxies)]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        try:
            ip = ipaddress.ip_address(peer)
        except ValueError:
            return peer
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def make_handler(relay, static, vapid_public, ip_header=None):
    limits = relay.limits

    class Handler(BaseHTTPRequestHandler):
        server_version = "clavix-relay"
        sys_version = ""
        timeout = limits.socket_timeout   # a silent client mid-request is dropped

        def reply(self, code, body=None, ctype="application/json", cache="no-store"):
            try:
                self.send_reply(code, body, ctype, cache)
            except (BrokenPipeError, ConnectionResetError):
                # The client left during a long-poll: nothing to report.
                self.close_connection = True

        def send_reply(self, code, body, ctype, cache):
            retry = body.get("retry_after") if isinstance(body, dict) else None
            if body is not None and not isinstance(body, bytes):
                body = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(code)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Cache-Control", cache)
            if retry is not None:
                self.send_header("Retry-After", str(retry))
            if body is not None:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body or b"")))
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def token(self):
            auth = self.headers.get("Authorization") or ""
            return auth[7:] if auth.startswith("Bearer ") else None

        def ip(self):
            if ip_header:
                return header_address(self.headers.get(ip_header))
            return client_address(self.client_address[0], self.headers.get("X-Forwarded-For"),
                                  limits.trusted_proxies)

        def json_body(self, cap=None):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if not 0 < n <= (cap or limits.max_body):
                self.close_connection = True   # the body, if any, stays unread
                return None
            try:
                raw = self.rfile.read(n)
            except OSError:   # timeout: the client went silent mid-body
                self.close_connection = True
                return False
            try:
                data = json.loads(raw)
            except ValueError:
                return None
            return data if isinstance(data, dict) else None

        def wait(self, query):
            try:
                value = float(urllib.parse.parse_qs(query).get("wait", ["0"])[0])
            except ValueError:
                return 0.0
            return value if math.isfinite(value) else 0.0

        def known(self, query):
            """The `known` parameter: None when absent, else a set of ids."""
            values = urllib.parse.parse_qs(query, keep_blank_values=True).get("known")
            if values is None:
                return None
            if not KNOWN_RE.match(values[0]):
                raise ValueError("known")
            return set(filter(None, values[0].split(",")))

        def long_poll(self, wait, call):
            """Run a call that may block, within the long-poll limits."""
            if wait <= 0:
                return self.reply(*call(0))
            release = relay.acquire_poll(self.token(), self.ip())
            if release is None:
                # A pause long enough that a client honouring Retry-After
                # stays far from a proxy's ban threshold on 4xx bursts.
                return self.reply(*limited(POLL_RETRY_AFTER))
            try:
                result = call(wait)
            finally:
                release()
            return self.reply(*result)

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
            token, wait = self.token(), self.wait(url.query)
            if what == "pair":
                return self.reply(*relay.get_hello(ch, token))
            if what == "pair/answer":
                return self.long_poll(wait, lambda w: relay.get_pair_answer(ch, token, w))
            if what == "pair/reveal":
                return self.long_poll(wait, lambda w: relay.get_reveal(ch, token, w))
            if what == "requests":
                try:
                    known = self.known(url.query)
                except ValueError:
                    return self.reply(400, {"error": "bad request"})
                return self.long_poll(wait, lambda w: relay.get_requests(ch, token, w, known))
            if rid and what.startswith("responses/"):
                seen = urllib.parse.parse_qs(url.query).get("seen") == ["1"]
                return self.long_poll(wait, lambda w: relay.get_response(ch, token, rid, w, seen))
            return self.reply(404, {"error": "not found"})

        do_HEAD = do_GET

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            # Apple's notifications nest three JWS, each with its chain.
            body = self.json_body(max(limits.max_body, NOTIFICATION_BODY)
                                  if path == APPSTORE_NOTIFICATIONS else None)
            if body is False:
                return None   # dropped without an answer
            if body is None:
                return self.reply(400, {"error": "bad request"})
            if path == "/api/channels":
                return self.reply(*relay.create_channel(self.token(), body, self.ip()))
            if path == APPSTORE_NOTIFICATIONS:
                return self.reply(*relay.appstore_notification(body))
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
            if what == "pair/reveal":
                return self.reply(*relay.post_reveal(ch, self.token(), body))
            if m.group(4):
                return self.reply(*relay.cancel(ch, self.token(), m.group(4)))
            if m.group(5):
                return self.reply(*relay.post_entitlement(ch, m.group(5), self.token(), body))
            if what == "requests":
                return self.reply(*relay.post_request(ch, self.token(), body))
            if rid and what.startswith("responses/"):
                return self.reply(*relay.post_response(ch, self.token(), rid, body))
            return self.reply(404, {"error": "not found"})

        def log_message(self, fmt, *args):
            pass   # request lines would carry nothing useful; errors are logged by Relay

    return Handler


BUSY = (b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\n"
        b"Connection: close\r\n\r\n")


class Server(ThreadingHTTPServer):
    """One thread per connection, but at most `max_connections` of them:
    past that a connection gets an immediate 503 and is closed."""
    daemon_threads = True

    def __init__(self, address, handler, max_connections):
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(BUSY)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def load_apns(env, enabled):
    """An ApnsPush from the environment, or None when no key is given."""
    path = env.get("RELAY_APNS_KEY_FILE")
    if not path:
        return None
    with open(path, "rb") as f:
        pem = f.read()
    return ApnsPush(pem, env.get("RELAY_APNS_KEY_ID"), env.get("RELAY_APNS_TEAM_ID"),
                    env.get("RELAY_APNS_TOPIC", "org.clavix.approve"), enabled)


def serve(bind, port, state_dir, enroll_secret, web_dir, contact, push_enabled, apns=None,
          serve_web=True, limits=None, ip_header=None, entitlements=None):
    os.makedirs(state_dir, exist_ok=True)
    push = Pushers(WebPush(state_dir, contact, push_enabled), apns)
    relay = Relay(state_dir, enroll_secret, push, limits=limits, entitlements=entitlements)
    static = load_static(web_dir) if serve_web else {}
    server = Server((bind, port), make_handler(relay, static, push.public_key(), ip_header),
                    relay.limits.max_connections)
    server.relay = relay
    return server


def enrolment_secret(env):
    """The enrolment secret, or None for open enrolment."""
    mode = env.get("RELAY_ENROLL", "")
    secret = env.get("RELAY_ENROLL_SECRET") or None
    if mode == "open":
        return None
    if mode == "closed" and not secret:
        raise ValueError("RELAY_ENROLL=closed needs RELAY_ENROLL_SECRET")
    if mode not in ("", "closed"):
        raise ValueError("RELAY_ENROLL must be open or closed")
    return secret


def on_off(env, name):
    """A switch that is on unless set to "off" (or 0, false, no)."""
    return env.get(name, "on").strip().lower() not in ("off", "0", "false", "no")


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
    state_dir = os.environ.get("RELAY_STATE_DIR")
    if not state_dir:
        sys.exit("RELAY_STATE_DIR must be set")
    try:
        secret = enrolment_secret(os.environ)
        limits = Limits.from_env(os.environ)
        entitlements = Entitlements.from_env(os.environ)
    except ValueError as e:
        sys.exit(str(e))
    push_enabled = on_off(os.environ, "RELAY_PUSH")
    serve_web = on_off(os.environ, "RELAY_SERVE_WEB")
    bind = os.environ.get("RELAY_BIND", "127.0.0.1")
    apns = load_apns(os.environ, push_enabled)
    server = serve(bind, port, state_dir, secret,
                   os.environ.get("RELAY_WEB_DIR", os.path.join(HERE, "..", "web")),
                   os.environ.get("RELAY_VAPID_SUB", "mailto:webpush@example.com"),
                   push_enabled, apns, serve_web, limits,
                   os.environ.get("RELAY_CLIENT_IP_HEADER") or None, entitlements)
    log(f"listening on {bind}:{port}, enrolment {'closed' if secret else 'open'}, "
        f"page {'served' if serve_web else 'not served'}, APNs {'on' if apns else 'off'}, "
        f"subscriptions {'required' if entitlements.enabled else 'not checked'}"
        f"{' (Sandbox accepted)' if entitlements.enabled and entitlements.sandbox else ''}")
    # As PID 1 in a container, SIGTERM has no default action: without a
    # handler `docker stop` waits its grace period, then SIGKILLs (exit 137).
    # shutdown() blocks until serve_forever() returns, hence the thread.
    def stop(signum, _frame):
        log(f"{signal.Signals(signum).name}: stopping")
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.serve_forever()
    server.server_close()
    server.relay.close()
    log("stopped")


if __name__ == "__main__":
    main()
