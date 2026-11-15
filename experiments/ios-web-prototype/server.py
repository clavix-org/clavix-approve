#!/usr/bin/env python3
"""Serveur de la page d'essai « approbation SSH sur iPhone ».

Sert la page statique et envoie une notification Web Push de test
(VAPID + chiffrement aes128gcm, RFC 8291/8292) sans dépendance autre que
python3-cryptography. Écoute en local uniquement : le HTTPS est fourni
par ce qui est placé devant (tunnel ou proxy).

Usage : server.py [port]        (défaut 8765)
        server.py --selftest    (vérifie le chiffrement, sans réseau)
"""
import base64
import json
import os
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state")
# Adresse de contact exigée par VAPID ; à remplacer si le service de push la refuse.
VAPID_SUB = os.environ.get("VAPID_SUB", "mailto:webpush@example.com")
# Seuls les services de push connus sont contactés (la page est publique).
PUSH_HOSTS = (".push.apple.com", "fcm.googleapis.com", ".push.services.mozilla.com",
              ".notify.windows.com")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
}
subscription = None
journal = []


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def vapid_key():
    os.makedirs(STATE, exist_ok=True)
    p = os.path.join(STATE, "vapid.pem")
    if os.path.exists(p):
        return serialization.load_pem_private_key(open(p, "rb").read(), None)
    k = ec.generate_private_key(ec.SECP256R1())
    with open(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    return k


def vapid_header(endpoint):
    k = vapid_key()
    u = urllib.parse.urlsplit(endpoint)
    head = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    body = b64u(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 3600,
                            "sub": VAPID_SUB}, separators=(",", ":")).encode())
    r, s = decode_dss_signature(k.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    sig = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"vapid t={head}.{body}.{sig}, k={b64u(raw_pub(k))}"


def encrypt(payload, p256dh, auth, as_key=None, salt=None):
    """Chiffrement aes128gcm d'un message Web Push (RFC 8291)."""
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


def send_push(sub, payload):
    endpoint = sub["endpoint"]
    host = urllib.parse.urlsplit(endpoint).hostname or ""
    if not endpoint.startswith("https://") or not any(
            host == h or host.endswith(h) for h in PUSH_HOSTS):
        return f"refusé : service de push inconnu ({host})"
    body = encrypt(json.dumps(payload).encode(), unb64u(sub["keys"]["p256dh"]),
                   unb64u(sub["keys"]["auth"]))
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
        "TTL": "120", "Urgency": "high", "Authorization": vapid_header(endpoint)})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return f"accepté par {host} (HTTP {r.status})"
    except urllib.error.HTTPError as e:
        return f"rejeté par {host} : HTTP {e.code} {e.read()[:200].decode(errors='replace')}"
    except Exception as e:  # réseau
        return f"erreur d'envoi vers {host} : {e}"


def icon_png(size=180):
    row = b"\x00" + bytes((0x1F, 0x3A, 0x5F)) * size
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(row * size)) + chunk(b"IEND", b""))


def later(delay, sub):
    time.sleep(delay)
    n = time.strftime("%H:%M:%S")
    res = send_push(sub, {"title": "Demande de signature SSH (essai)",
                          "body": f"root@serveur-de-test — envoyée à {n}", "sent": n})
    journal.append(f"{n} {res}")
    print(journal[-1], flush=True)


class H(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in STATIC:
            name, ctype = STATIC[path]
            self.reply(200, open(os.path.join(HERE, name), "rb").read(), ctype)
        elif path == "/icon.png":
            self.reply(200, icon_png(), "image/png")
        elif path == "/vapid-public-key":
            self.reply(200, {"key": b64u(raw_pub(vapid_key()))})
        elif path == "/journal":
            self.reply(200, {"journal": journal[-5:]})
        else:
            self.reply(404, {"error": "introuvable"})

    def do_POST(self):
        global subscription
        n = int(self.headers.get("Content-Length") or 0)
        if n > 8192:
            return self.reply(413, {"error": "trop gros"})
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "JSON invalide"})
        if self.path == "/subscribe":
            if not (isinstance(data.get("endpoint"), str) and isinstance(data.get("keys"), dict)):
                return self.reply(400, {"error": "abonnement invalide"})
            subscription = data
            self.reply(200, {"ok": True})
        elif self.path == "/push":
            if not subscription:
                return self.reply(409, {"error": "pas d'abonnement"})
            delay = max(0, min(int(data.get("delay", 10)), 60))
            threading.Thread(target=later, args=(delay, subscription), daemon=True).start()
            self.reply(200, {"ok": True, "delay": delay})
        else:
            self.reply(404, {"error": "introuvable"})

    def log_message(self, fmt, *args):
        print(self.address_string(), fmt % args, flush=True)


def selftest():
    """Chiffre puis déchiffre côté « navigateur » pour valider encrypt()."""
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    body = encrypt(b'{"ok":1}', raw_pub(ua), auth)
    salt, (rs, idlen) = body[:16], struct.unpack(">IB", body[16:21])
    as_pub, ct = body[21:21 + idlen], body[21 + idlen:]
    shared = ua.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
    ikm = HKDF(hashes.SHA256(), 32, auth, b"WebPush: info\x00" + raw_pub(ua) + as_pub).derive(shared)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    assert AESGCM(cek).decrypt(nonce, ct, None) == b'{"ok":1}\x02' and rs == 4096
    assert vapid_header("https://web.push.apple.com/x").count(".") >= 2
    print("selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        STATE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "pk-selftest-state")
        selftest()
    else:
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
        vapid_key()
        print(f"écoute sur 127.0.0.1:{port}", flush=True)
        ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
