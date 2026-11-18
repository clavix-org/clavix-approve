// SSH wire format, as in web/lib/ssh.js: read a user-auth request,
// verify a server host key's signature, encode our own ECDSA signature.

import CryptoKit
import Foundation
import Security

public enum SSH {
    static let userAuthRequest: UInt8 = 50

    public struct UserAuthRequest {
        public let sessionId: Data
        public let user: Data
        public let service: String
        public let algorithm: String
        public let keyBlob: Data
        public let hostKey: Data?
    }

    /// "SHA256:…" as printed by `ssh-keygen -l`.
    public static func fingerprint(_ keyBlob: Data) -> String {
        "SHA256:" + keyBlob.sha256.b64NoPadding
    }

    /// The data an SSH client asks an agent to sign for public-key
    /// authentication (RFC 4252 §7, plus OpenSSH's host-bound variant).
    /// Nil for anything else, including trailing bytes.
    public static func parseUserAuthRequest(_ data: Data) -> UserAuthRequest? {
        var r = Reader(data)
        do {
            let sessionId = try r.string()
            guard try r.u8() == userAuthRequest else { return nil }
            let user = try r.string()
            let service = try r.text()
            let method = try r.text()
            guard method == "publickey" || method == "publickey-hostbound-v00@openssh.com" else { return nil }
            guard try r.u8() == 1 else { return nil }
            let algorithm = try r.text()
            let keyBlob = try r.string()
            let hostKey = method == "publickey" ? nil : try r.string()
            guard r.done else { return nil }
            return UserAuthRequest(sessionId: sessionId, user: user, service: service, algorithm: algorithm,
                                   keyBlob: keyBlob, hostKey: hostKey)
        } catch {
            return nil
        }
    }

    /// Does `sigBlob` (SSH wire signature) verify as a signature of `data`
    /// under the public key `keyBlob`? False for anything unsupported or
    /// malformed: Ed25519, ECDSA P-256/384/521 and RSA with SHA-2 only.
    public static func verifySignature(keyBlob: Data, data: Data, sigBlob: Data) -> Bool {
        do {
            var key = Reader(keyBlob)
            let keyType = try key.text()
            var sig = Reader(sigBlob)
            let sigType = try sig.text()
            let body = try sig.string()
            guard sig.done else { return false }

            switch keyType {
            case "ssh-ed25519":
                let pub = try key.string()
                guard key.done, sigType == keyType, pub.count == 32, body.count == 64 else { return false }
                return try Curve25519.Signing.PublicKey(rawRepresentation: pub).isValidSignature(body, for: data)

            case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
                let curveId = try key.text()
                let point = try key.string()
                guard key.done, sigType == keyType, "ecdsa-sha2-" + curveId == keyType else { return false }
                var rs = Reader(body)
                let r = try rs.string(), s = try rs.string()
                guard rs.done else { return false }
                switch curveId {
                case "nistp256":
                    let raw = try fixedWidth(r, 32) + fixedWidth(s, 32)
                    return try P256.Signing.PublicKey(x963Representation: point)
                        .isValidSignature(.init(rawRepresentation: raw), for: data)
                case "nistp384":
                    let raw = try fixedWidth(r, 48) + fixedWidth(s, 48)
                    return try P384.Signing.PublicKey(x963Representation: point)
                        .isValidSignature(.init(rawRepresentation: raw), for: data)
                default:
                    let raw = try fixedWidth(r, 66) + fixedWidth(s, 66)
                    return try P521.Signing.PublicKey(x963Representation: point)
                        .isValidSignature(.init(rawRepresentation: raw), for: data)
                }

            case "ssh-rsa":
                let e = stripZeros(try key.string())
                let n = stripZeros(try key.string())
                // SHA-1 `ssh-rsa` signatures are refused.
                let algorithm: SecKeyAlgorithm
                switch sigType {
                case "rsa-sha2-256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
                case "rsa-sha2-512": algorithm = .rsaSignatureMessagePKCS1v15SHA512
                default: return false
                }
                guard key.done, n.count >= 256 else { return false }
                return try verifyRSA(n: n, e: e, algorithm: algorithm, data: data, signature: fixedWidth(body, n.count))

            default:
                return false
            }
        } catch {
            return false
        }
    }

    private static func verifyRSA(n: Data, e: Data, algorithm: SecKeyAlgorithm, data: Data, signature: Data) throws -> Bool {
        // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }.
        let der = DER.sequence(DER.integer(n) + DER.integer(e))
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else { return false }
        return SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, nil)
    }

    /// Public key blob of a P-256 key, from its uncompressed point.
    public static func p256KeyBlob(point: Data) throws -> Data {
        guard point.count == 65, point.first == 4 else { throw CoreError.malformed("not a P-256 point") }
        return sshString("ecdsa-sha2-nistp256") + sshString("nistp256") + sshString(point)
    }

    /// The type named at the start of a key blob, nil if it has none.
    public static func keyType(_ keyBlob: Data) -> String? {
        var r = Reader(keyBlob)
        return (try? r.string()).flatMap { String(data: $0, encoding: .utf8) }
    }

    /// The signature algorithms that may go with a key type in a user-auth
    /// request; nil for a key type not handled.
    public static func signatureAlgorithms(_ keyBlob: Data) -> [String]? {
        switch keyType(keyBlob) {
        case "ssh-ed25519": return ["ssh-ed25519"]
        case "ecdsa-sha2-nistp256": return ["ecdsa-sha2-nistp256"]
        case "ecdsa-sha2-nistp384": return ["ecdsa-sha2-nistp384"]
        case "ecdsa-sha2-nistp521": return ["ecdsa-sha2-nistp521"]
        case "ssh-rsa": return ["rsa-sha2-256", "rsa-sha2-512"]
        default: return nil
        }
    }

    /// A raw ECDSA P-256 signature (r || s) as an SSH signature blob.
    public static func p256SignatureBlob(raw: Data) throws -> Data {
        guard raw.count == 64 else { throw CoreError.malformed("not a P-256 signature") }
        return sshString("ecdsa-sha2-nistp256") + sshString(mpint(raw.prefix(32)) + mpint(raw.suffix(32)))
    }

    /// One line for `authorized_keys`.
    public static func publicKeyLine(keyBlob: Data, comment: String) -> String {
        var r = Reader(keyBlob)
        let type = (try? r.text()) ?? "?"
        return "\(type) \(keyBlob.base64EncodedString()) \(comment)"
    }

    // ---- integers ----

    /// A non-negative big-endian integer as an SSH mpint.
    static func mpint(_ bytes: Data) -> Data {
        let v = Data(bytes.drop(while: { $0 == 0 }))
        return sshString(v.first.map { $0 & 0x80 != 0 } == true ? Data([0]) + v : v)
    }

    /// An SSH mpint as exactly `size` big-endian bytes; throws if it does not fit.
    static func fixedWidth(_ mp: Data, _ size: Int) throws -> Data {
        let v = Data(mp.drop(while: { $0 == 0 }))
        guard v.count <= size else { throw CoreError.malformed("integer too large") }
        return Data(count: size - v.count) + v
    }

    static func stripZeros(_ mp: Data) -> Data {
        var v = Data(mp.drop(while: { $0 == 0 }))
        if v.isEmpty && !mp.isEmpty { v = Data([0]) }
        return v
    }
}

/// Just enough DER to hand an RSA public key to the Security framework.
enum DER {
    static func length(_ n: Int) -> Data {
        if n < 128 { return Data([UInt8(n)]) }
        var bytes = [UInt8]()
        var m = n
        while m > 0 { bytes.insert(UInt8(m & 255), at: 0); m >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    static func integer(_ magnitude: Data) -> Data {
        var v = Data(magnitude.drop(while: { $0 == 0 }))
        if v.isEmpty || v.first! & 0x80 != 0 { v = Data([0]) + v }
        return Data([0x02]) + length(v.count) + v
    }

    static func sequence(_ content: Data) -> Data {
        Data([0x30]) + length(content.count) + content
    }
}
