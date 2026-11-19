#!/bin/sh
# Verifies testdata/approve-proof.json and pairing.json, independently of the
# Node code that generated it: the SSH blobs are taken apart by Python's
# standard library, the signatures checked by `openssl`.
#
#   tools/approve-vectors-check.sh [testdata/approve-proof.json [testdata/pairing.json]]
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

# ---- testdata/pairing.json: MACs and digits, recomputed --------------
pairing=${2:-testdata/pairing.json}
python3 -I - "$pairing" "$vectors" "$work" <<'EOF'
import base64, hashlib, hmac, json, struct, sys

v = json.load(open(sys.argv[1]))
proofs = json.load(open(sys.argv[2]))
work = sys.argv[3]
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
string = lambda x: struct.pack(">I", len(x)) + x
transcript = lambda kind, *fields: string(kind.encode()) + b"".join(string(f) for f in fields)

# HKDF-SHA256 (RFC 5869), empty salt = HashLen zero bytes, one block.
def hkdf(ikm, info):
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

secret = bytes.fromhex(v["secret"])
assert v["version"] == 2, "version"
raw = unb64u(v["code"][len("cva2-"):])
assert v["code"].startswith("cva2-") and raw[:16].hex() == v["channel"] and raw[16:] == secret, "code"
key = hkdf(secret, b"clavix-approve/v1/pair-mac")
assert key.hex() == v["mac_key"], "mac key"
ch, signer, label = v["channel"].encode(), v["signer"].encode(), v["label"].encode()
akem, asig = bytes.fromhex(v["agent"]["kem"]), bytes.fromhex(v["agent"]["sig"])
skem, ssig = bytes.fromhex(v["signer_keys"]["kem"]), bytes.fromhex(v["signer_keys"]["sig"])
assert len(akem) == len(skem) == 65 and akem[0] == skem[0] == 4 and len(asig) == len(ssig) == 32, "key sizes"
na, nb = bytes.fromhex(v["agent_nonce"]), bytes.fromhex(v["signer_nonce"])
assert len(na) == len(nb) == 32, "nonce sizes"

t = transcript("clavix-approve/v2/pair-commit", na)
assert t.hex() == v["commit_transcript"], "commit transcript"
commit = hashlib.sha256(t).digest()
assert b64u(commit) == v["commit"], "commit"

keys = {k["type"]: k["approve"] for k in proofs["keys"]}
assert [c["mode"] for c in v["modes"]] == ["sign", "approve"], "modes"
for c in v["modes"]:
    mode = c["mode"].encode()
    t = transcript("clavix-approve/v2/pair-hello", mode, ch, akem, asig, label, commit)
    assert t.hex() == c["hello_transcript"], c["mode"] + " hello transcript"
    assert b64u(hmac.new(key, t, hashlib.sha256).digest()) == c["hello_mac"], c["mode"] + " hello mac"
    for a in c["answers"]:
        what = c["mode"] + " " + a["type"]
        assert a["key"] == keys[a["type"]], what + " key blob"
        blob = unb64u(a["key"])
        t = transcript("clavix-approve/v2/pair-answer", mode, ch, signer, skem, ssig, blob, nb, akem, asig, commit)
        assert t.hex() == a["answer_transcript"], what + " answer transcript"
        assert b64u(hmac.new(key, t, hashlib.sha256).digest()) == a["answer_mac"], what + " answer mac"
        t = transcript("clavix-approve/v2/pair-digits", mode, ch, signer, akem, asig, skem, ssig, blob, na, nb)
        assert t.hex() == a["digits_transcript"], what + " digits transcript"
        n = struct.unpack(">I", hashlib.sha256(t).digest()[:4])[0] % 1_000_000
        assert f"{n // 1000:03d} {n % 1000:03d}" == a["digits"], what + " digits"

# The public keys must come from the fixed private keys: OpenSSL derives them.
p256 = bytes.fromhex("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420")
ed = bytes.fromhex("302e020100300506032b657004220420")
for side, name in ((v["agent"], "agent"), (v["signer_keys"], "signer")):
    open(f"{work}/{name}-kem.der", "wb").write(p256 + bytes.fromhex(side["kem_private"]))
    open(f"{work}/{name}-kem.expect", "w").write(side["kem"])
    open(f"{work}/{name}-sig.der", "wb").write(ed + bytes.fromhex(side["sig_seed"]))
    open(f"{work}/{name}-sig.expect", "w").write(side["sig"])
print("pairing: MACs and digits recomputed")
EOF
for k in agent-kem signer-kem agent-sig signer-sig; do
  got=$(openssl pkey -inform DER -in "$work/$k.der" -pubout -outform DER | od -An -v -tx1 | tr -d ' \n')
  case $k in *-kem) got=$(printf %s "$got" | tail -c 130) ;; *) got=$(printf %s "$got" | tail -c 64) ;; esac
  [ "$got" = "$(cat "$work/$k.expect")" ] || { echo "public key mismatch: $k" >&2; exit 1; }
done
echo "pairing: public keys match their private keys"
