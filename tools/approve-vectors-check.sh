#!/bin/sh
# Verifies testdata/approve-proof.json with OpenSSL, independently of the
# Node code that generated it: the SSH blobs are taken apart by Python's
# standard library, the signatures checked by `openssl`.
#
#   tools/approve-vectors-check.sh [testdata/approve-proof.json]
set -eu
vectors=${1:-testdata/approve-proof.json}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 -I - "$vectors" "$work" <<'EOF'
import base64, hashlib, json, struct, sys

v = json.load(open(sys.argv[1]))
work = sys.argv[2]
unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def strings(b):
    out = []
    while b:
        (n,) = struct.unpack(">I", b[:4])
        out.append(b[4:4 + n]); b = b[4 + n:]
    return out

def string(x):
    return struct.pack(">I", len(x)) + x

req = hashlib.sha256(v["msg"].encode("ascii")).digest()
assert base64.urlsafe_b64encode(req).rstrip(b"=").decode() == v["req"], "req"
signed = (b"clavix-approve/v1 approve" + string(v["channel"].encode()) + string(v["signer"].encode())
          + string(v["id"].encode()) + string(req))
assert signed.hex() == v["signed"], "signed"
open(f"{work}/signed", "wb").write(signed)

def der_len(n):
    return bytes([n]) if n < 128 else bytes([0x81, n])

def der_int(x):
    x = x.lstrip(b"\0") or b"\0"
    if x[0] & 0x80: x = b"\0" + x
    return b"\x02" + der_len(len(x)) + x

for k in v["keys"]:
    key, proof = strings(unb64u(k["approve"])), strings(unb64u(k["proof"]))
    assert key[0].decode() == k["type"] == proof[0].decode(), "type"
    t = k["type"]
    if t == "ssh-ed25519":
        spki = bytes.fromhex("302a300506032b6570032100") + key[1]
        sig = proof[1]
    elif t == "ecdsa-sha2-nistp256":
        assert key[1] == b"nistp256"
        spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + key[2]
        r, s = strings(proof[1])
        body = der_int(r) + der_int(s)
        sig = b"\x30" + der_len(len(body)) + body
    open(f"{work}/{t}.pub.der", "wb").write(spki)
    open(f"{work}/{t}.sig", "wb").write(sig)
EOF

openssl pkey -pubin -inform DER -in "$work/ssh-ed25519.pub.der" -out "$work/ed.pem"
openssl pkeyutl -verify -pubin -inkey "$work/ed.pem" -rawin -in "$work/signed" -sigfile "$work/ssh-ed25519.sig"
openssl pkey -pubin -inform DER -in "$work/ecdsa-sha2-nistp256.pub.der" -out "$work/p256.pem"
openssl dgst -sha256 -verify "$work/p256.pem" -signature "$work/ecdsa-sha2-nistp256.sig" "$work/signed"
