// HPKE (RFC 9180), base mode, single-shot, one fixed suite:
//
//   DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM   (0x0010/0x0001/0x0001)
//
// Written on CryptoKit primitives, step for step like web/lib/hpke.js, so
// that the recipient key may live in the Secure Enclave (only its
// Diffie-Hellman is needed) and the RFC's own vector can be replayed.

import CryptoKit
import Foundation

/// A recipient key: anything that does a P-256 Diffie-Hellman.
public protocol ChannelKEMKey {
    /// Uncompressed point, 65 bytes.
    var publicKeyRaw: Data { get }
    /// The x coordinate of our key times `peer`.
    func diffieHellman(with peer: P256.KeyAgreement.PublicKey) throws -> Data
}

extension SharedSecret {
    var bytes: Data { withUnsafeBytes { Data($0) } }
}

extension P256.KeyAgreement.PrivateKey: ChannelKEMKey {
    public var publicKeyRaw: Data { publicKey.x963Representation }
    public func diffieHellman(with peer: P256.KeyAgreement.PublicKey) throws -> Data {
        try sharedSecretFromKeyAgreement(with: peer).bytes
    }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: ChannelKEMKey {
    public var publicKeyRaw: Data { publicKey.x963Representation }
    public func diffieHellman(with peer: P256.KeyAgreement.PublicKey) throws -> Data {
        try sharedSecretFromKeyAgreement(with: peer).bytes
    }
}

enum HPKE {
    static let encLength = 65

    private static let kemSuite = utf8("KEM") + Data([0x00, 0x10])
    private static let hpkeSuite = utf8("HPKE") + Data([0x00, 0x10, 0x00, 0x01, 0x00, 0x01])
    private static let version = utf8("HPKE-v1")

    private static func hmac(_ key: Data, _ data: Data) -> Data {
        // An empty key and HashLen zero bytes are the same HMAC key.
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    private static func labeledExtract(_ suite: Data, _ salt: Data, _ label: String, _ ikm: Data) -> Data {
        hmac(salt, version + suite + utf8(label) + ikm)
    }

    /// One HMAC block is enough: no output here exceeds 32 bytes.
    private static func labeledExpand(_ suite: Data, _ prk: Data, _ label: String, _ info: Data, _ length: Int) -> Data {
        precondition(length <= 32)
        let labeled = Data([UInt8(length >> 8), UInt8(length & 255)]) + version + suite + utf8(label) + info
        return hmac(prk, labeled + Data([1])).prefix(length)
    }

    private static func sharedSecret(dh: Data, enc: Data, recipientRaw: Data) -> Data {
        let prk = labeledExtract(kemSuite, Data(), "eae_prk", dh)
        return labeledExpand(kemSuite, prk, "shared_secret", enc + recipientRaw, 32)
    }

    private static func keySchedule(_ secret: Data, _ info: Data) -> (SymmetricKey, AES.GCM.Nonce) {
        let context = Data([0]) // mode_base
            + labeledExtract(hpkeSuite, Data(), "psk_id_hash", Data())
            + labeledExtract(hpkeSuite, Data(), "info_hash", info)
        let prk = labeledExtract(hpkeSuite, secret, "secret", Data())
        let key = labeledExpand(hpkeSuite, prk, "key", context, 16)
        let nonce = labeledExpand(hpkeSuite, prk, "base_nonce", context, 12)
        // Single-shot: sequence number 0, so the nonce is the base nonce.
        return (SymmetricKey(data: key), try! AES.GCM.Nonce(data: nonce))
    }

    /// Encrypt to the raw public key `recipientRaw`. Returns (enc, ct).
    /// `ephemeral` exists for the test vector only.
    static func seal(to recipientRaw: Data, info: Data, aad: Data, plaintext: Data,
                     ephemeral: P256.KeyAgreement.PrivateKey = .init()) throws -> (enc: Data, ct: Data) {
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: recipientRaw)
        let enc = ephemeral.publicKeyRaw
        let secret = sharedSecret(dh: try ephemeral.diffieHellman(with: recipient), enc: enc, recipientRaw: recipientRaw)
        let (key, nonce) = keySchedule(secret, info)
        let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        return (enc, box.ciphertext + box.tag)
    }

    /// Decrypt with our key; throws on any failure.
    static func open(with recipient: ChannelKEMKey, info: Data, aad: Data, enc: Data, ct: Data) throws -> Data {
        guard enc.count == encLength, ct.count >= 16 else { throw CoreError.crypto("bad encapsulated key") }
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: enc)
        let secret = sharedSecret(dh: try recipient.diffieHellman(with: ephemeral), enc: enc,
                                  recipientRaw: recipient.publicKeyRaw)
        let (key, nonce) = keySchedule(secret, info)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16))
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }
}
