// Test doubles, as web/test/helpers.mjs: server host keys of every
// supported type, the bytes an SSH client asks an agent to sign, and an
// agent side to talk to.

import CryptoKit
import Foundation
import Security
@testable import ClavixCore

struct HostKey {
    let blob: Data
    let sign: (Data) throws -> Data
}

enum HostKeyType { case ed25519, p256, p384, p521, rsa }

func hostKey(_ type: HostKeyType = .ed25519) throws -> HostKey {
    switch type {
    case .ed25519:
        let k = Curve25519.Signing.PrivateKey()
        return HostKey(blob: sshString("ssh-ed25519") + sshString(k.publicKey.rawRepresentation)) { data in
            sshString("ssh-ed25519") + sshString(try k.signature(for: data))
        }
    case .p256:
        let k = P256.Signing.PrivateKey()
        return ecdsa("nistp256", k.publicKey.x963Representation, 32) { try k.signature(for: $0).rawRepresentation }
    case .p384:
        let k = P384.Signing.PrivateKey()
        return ecdsa("nistp384", k.publicKey.x963Representation, 48) { try k.signature(for: $0).rawRepresentation }
    case .p521:
        let k = P521.Signing.PrivateKey()
        return ecdsa("nistp521", k.publicKey.x963Representation, 66) { try k.signature(for: $0).rawRepresentation }
    case .rsa:
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        let priv = SecKeyCreateRandomKey(attrs as CFDictionary, nil)!
        let der = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(priv)!, nil)! as Data
        // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        var r = DERReader(der)
        r.enter()
        let n = r.integer(), e = r.integer()
        return HostKey(blob: sshString("ssh-rsa") + SSH.mpint(e) + SSH.mpint(n)) { data in
            let sig = SecKeyCreateSignature(priv, .rsaSignatureMessagePKCS1v15SHA512, data as CFData, nil)! as Data
            return sshString("rsa-sha2-512") + sshString(sig)
        }
    }
}

private func ecdsa(_ curve: String, _ point: Data, _ size: Int, _ raw: @escaping (Data) throws -> Data) -> HostKey {
    let name = "ecdsa-sha2-" + curve
    return HostKey(blob: sshString(name) + sshString(curve) + sshString(point)) { data in
        let rs = try raw(data)
        return sshString(name) + sshString(SSH.mpint(rs.prefix(size)) + SSH.mpint(rs.suffix(size)))
    }
}

struct DERReader {
    let b: [UInt8]
    var pos = 0
    init(_ d: Data) { b = [UInt8](d) }
    mutating func length() -> Int {
        let first = Int(b[pos]); pos += 1
        if first < 128 { return first }
        var n = 0
        for _ in 0..<(first & 0x7f) { n = n << 8 | Int(b[pos]); pos += 1 }
        return n
    }
    mutating func enter() { pos += 1; _ = length() }
    mutating func integer() -> Data {
        pos += 1
        let n = length()
        defer { pos += n }
        return Data(b[pos..<pos + n])
    }
}

/// The signer's own key, held in software here (the app uses the Secure Enclave).
struct ClientKey {
    let key = P256.Signing.PrivateKey()
    var blob: Data { try! SSH.p256KeyBlob(point: key.publicKey.x963Representation) }
}

/// The data to sign for a public-key login (RFC 4252 §7).
func userAuth(sessionId: Data, keyBlob: Data, hostKey host: Data? = nil, user: String = "deploy",
              service: String = "ssh-connection", algorithm: String = "ecdsa-sha2-nistp256") -> Data {
    let method = host == nil ? "publickey" : "publickey-hostbound-v00@openssh.com"
    var out = sshString(sessionId)
    out.append(50)
    out.append(sshString(user))
    out.append(sshString(service))
    out.append(sshString(method))
    out.append(1)
    out.append(sshString(algorithm))
    out.append(sshString(keyBlob))
    if let host { out.append(sshString(host)) }
    return out
}

/// One session binding as the agent forwards it.
func sessionBind(_ host: HostKey, _ sessionId: Data, forwarded: Bool = false) throws -> [String: Any] {
    ["hostkey": host.blob.b64u, "sid": sessionId.b64u, "sig": try host.sign(sessionId).b64u, "fwd": forwarded]
}

func softwareIdentity() -> Identity {
    Identity(kem: P256.KeyAgreement.PrivateKey(), sig: Curve25519.Signing.PrivateKey())
}

func peer(of id: Identity) -> Peer {
    try! Peer(kemPublic: id.kemPublic, sigPublic: id.sigPublic)
}

/// A file of the repository's shared `testdata/`, also read by web/test.
func vector(_ name: String) throws -> Data {
    let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../../../testdata").standardized
    return try Data(contentsOf: repo.appendingPathComponent(name))
}
