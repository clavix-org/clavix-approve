// Pairing, signer side, as in web/lib/pairing.js and PROTOCOL.md,
// "Pairing". The relay only sees a token derived from the one-time secret;
// a MAC keyed by another derivation authenticates the keys exchanged
// through it; six digits are the last check, by eye.

import CryptoKit
import Foundation

public struct PairingCode: Equatable {
    public static let prefix = "cva1-"

    /// Channel id, 32 hex digits.
    public let ch: String
    public let secret: Data
    /// The relay, when the code came as the agent's link `<relay>/#cva1-…`.
    public let relay: URL?

    /// Accepts the bare code, or the link the agent prints as a QR code.
    public init(_ input: String) throws {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var code = text
        var relay: URL? = nil
        if let hash = text.range(of: "#" + Self.prefix) {
            var base = String(text[..<hash.lowerBound])
            while base.hasSuffix("/") { base.removeLast() }
            guard let url = URL(string: base), url.scheme == "https" || url.scheme == "http", url.host != nil else {
                throw CoreError.malformed("not a pairing code")
            }
            relay = url
            code = String(text[text.index(after: hash.lowerBound)...])
        }
        guard code.hasPrefix(Self.prefix) else { throw CoreError.malformed("not a pairing code") }
        let raw = try Data(b64u: String(code.dropFirst(Self.prefix.count)))
        guard raw.count == 32 else { throw CoreError.malformed("not a pairing code") }
        self.ch = raw.prefix(16).hex
        self.secret = raw.suffix(16)
        self.relay = relay
    }
}

public enum Pairing {
    static func derive(_ secret: Data, _ purpose: String) -> Data {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: Data(),
                                        info: utf8("\(protocolLabel)/\(purpose)"), outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    /// What the relay sees of the pairing secret.
    public static func pairToken(_ secret: Data) -> String {
        derive(secret, "relay-pair").b64u
    }

    private static func mac(_ secret: Data, _ data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: derive(secret, "pair-mac"))))
    }

    private static func transcript(_ kind: String, _ fields: [Data]) -> Data {
        fields.reduce(sshString(kind)) { $0 + sshString($1) }
    }

    /// Read the agent's hello and authenticate its keys with the secret.
    public static func readHello(_ helloMsg: String, ch: String, secret: Data) throws -> (label: String, agent: Peer) {
        guard let hello = try JSONSerialization.jsonObject(with: Data(b64u: helloMsg)) as? [String: Any],
              let kem = hello["kem"] as? String, let sig = hello["sig"] as? String,
              let macText = hello["mac"] as? String else {
            throw CoreError.malformed("malformed hello")
        }
        let agent = try Peer(kemPublic: Data(b64u: kem), sigPublic: Data(b64u: sig))
        let label = hello["label"] as? String ?? ""
        let expected = mac(secret, transcript("hello", [utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label)]))
        guard equal(try Data(b64u: macText), expected) else {
            throw CoreError.crypto("the pairing code does not match this agent")
        }
        return (label, agent)
    }

    /// Our answer: public keys and the SSH key, sealed to the agent.
    public static func buildAnswer(ch: String, signer: String, secret: Data, me: Identity, agent: Peer,
                                   keyBlob: Data, comment: String) throws -> String {
        let tag = mac(secret, transcript("answer", [utf8(ch), utf8(signer), me.kemPublic, me.sigPublic, keyBlob,
                                                    agent.kemPublic, agent.sigPublic]))
        return try Channel.sealIntroduction(me, to: agent, header: Header.pair(ch: ch, signer: signer), [
            "t": "pair",
            "key": keyBlob.b64u,
            "comment": comment,
            "kem": me.kemPublic.b64u,
            "mac": tag.b64u,
        ])
    }

    /// Six digits both ends display once paired, e.g. "042 917".
    public static func fingerprint(agent: Peer, me: Identity, keyBlob: Data) -> String {
        let digest = [UInt8](transcript("\(protocolLabel)/fingerprint",
                                        [agent.kemPublic, agent.sigPublic, me.kemPublic, me.sigPublic, keyBlob]).sha256)
        let n = UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])
        let digits = String(format: "%06u", n % 1_000_000)
        return "\(digits.prefix(3)) \(digits.suffix(3))"
    }
}
