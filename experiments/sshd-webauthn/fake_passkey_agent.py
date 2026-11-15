#!/usr/bin/env python3
"""Agent SSH de test : simule une passkey (WebAuthn) côté logiciel.

Il expose UNE clé sk-ecdsa-sha2-nistp256@openssh.com dont l'« application »
est un RP ID web (domaine), et répond aux demandes de signature exactement
comme le ferait navigator.credentials.get() dans un navigateur :
authenticatorData + clientDataJSON, emballés au format
webauthn-sk-ecdsa-sha2-nistp256@openssh.com (PROTOCOL.u2f).

Usage : fake_passkey_agent.py <dossier> <rp_id> [init|serve]
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

KEYTYPE = b"sk-ecdsa-sha2-nistp256@openssh.com"
SIGTYPE = b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
FLAGS = 0x1D  # UP | UV | BE | BS : ce que renvoie une passkey synchronisée


def s(b):
    return struct.pack(">I", len(b)) + b


def mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return s(b)


def load_or_create(d):
    p = os.path.join(d, "passkey.pem")
    if os.path.exists(p):
        return serialization.load_pem_private_key(open(p, "rb").read(), None)
    k = ec.generate_private_key(ec.SECP256R1())
    with open(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    return k


def pub_blob(k, rp_id):
    q = k.public_key().public_bytes(serialization.Encoding.X962,
                                    serialization.PublicFormat.UncompressedPoint)
    return s(KEYTYPE) + s(b"nistp256") + s(q) + s(rp_id.encode())


def webauthn_sign(k, rp_id, data, counter):
    challenge = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    origin = "https://" + rp_id
    # Ordre et forme des champs imposés par la spec WebAuthn (sérialisation
    # du clientDataJSON) — c'est ce préfixe que sshd compare.
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": origin,
         "crossOrigin": False}, separators=(",", ":")).encode()
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([FLAGS]) + struct.pack(">I", counter)
    der = k.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    r, sv = decode_dss_signature(der)
    return (s(SIGTYPE) + s(mpint(r) + mpint(sv)) + bytes([FLAGS]) + struct.pack(">I", counter)
            + s(origin.encode()) + s(client_data) + s(b""))


def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(d, rp_id):
    k = load_or_create(d)
    blob = pub_blob(k, rp_id)
    path = os.environ.get("PK_SOCK", os.path.join(d, "agent.sock"))
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(8)
    counter = 0
    print("agent prêt :", path, flush=True)
    while True:
        c, _ = srv.accept()
        while True:
            hdr = recv_exact(c, 4)
            if not hdr:
                break
            body = recv_exact(c, struct.unpack(">I", hdr)[0])
            t = body[0]
            if t == 11:  # REQUEST_IDENTITIES
                out = bytes([12]) + struct.pack(">I", 1) + s(blob) + s(b"passkey-test")
            elif t == 13:  # SIGN_REQUEST
                klen = struct.unpack(">I", body[1:5])[0]
                kb = body[5:5 + klen]
                dlen = struct.unpack(">I", body[5 + klen:9 + klen])[0]
                data = body[9 + klen:9 + klen + dlen]
                if kb == blob:
                    counter += 1
                    out = bytes([14]) + s(webauthn_sign(k, rp_id, data, counter))
                    print("signature WebAuthn émise, compteur", counter, flush=True)
                else:
                    out = bytes([5])
            else:
                out = bytes([5])  # SSH_AGENT_FAILURE (session-bind compris)
            c.sendall(s(out))
        c.close()


if __name__ == "__main__":
    d, rp_id = sys.argv[1], sys.argv[2]
    if len(sys.argv) > 3 and sys.argv[3] == "init":
        k = load_or_create(d)
        line = KEYTYPE.decode() + " " + base64.b64encode(pub_blob(k, rp_id)).decode() + " passkey-test"
        open(os.path.join(d, "passkey.pub"), "w").write(line + "\n")
        print(line)
    else:
        serve(d, rp_id)
