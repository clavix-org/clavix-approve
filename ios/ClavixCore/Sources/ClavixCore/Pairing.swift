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

/// A channel is in one mode for good, set at pairing: `sign` (the signer
/// holds the SSH key) or `approve` (it only approves; PROTOCOL.md,
/// "Approve mode"). Each mode has its own labels, so that a relay flipping
/// the mode breaks a MAC or the digits.
public enum PairingMode: String, Codable, Sendable {
    case sign, approve

    var helloLabel: String { self == .sign ? "hello" : "approve-hello" }
    var answerLabel: String { self == .sign ? "answer" : "approve-answer" }
    var fingerprintLabel: String { self == .sign ? "\(protocolLabel)/fingerprint" : "\(protocolLabel)/approve-fingerprint" }
    /// The field of the answer that carries the key.
    var answerField: String { self == .sign ? "key" : "approve" }
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

    static func mac(_ secret: Data, _ data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: derive(secret, "pair-mac"))))
    }

    static func transcript(_ kind: String, _ fields: [Data]) -> Data {
        fields.reduce(sshString(kind)) { $0 + sshString($1) }
    }

    /// Read the agent's hello and authenticate its keys with the secret.
    /// A hello without `mode` is a sign-mode one, as before approve mode;
    /// any mode but "approve" is refused.
    public static func readHello(_ helloMsg: String, ch: String, secret: Data) throws
        -> (label: String, agent: Peer, mode: PairingMode) {
        guard let hello = try JSONSerialization.jsonObject(with: Data(b64u: helloMsg)) as? [String: Any],
              let kem = hello["kem"] as? String, let sig = hello["sig"] as? String,
              let macText = hello["mac"] as? String else {
            throw CoreError.malformed("malformed hello")
        }
        let mode: PairingMode
        if hello["mode"] == nil {
            mode = .sign
        } else if hello["mode"] as? String == "approve" {
            mode = .approve
        } else {
            throw CoreError.malformed("this pairing code is for an unknown mode")
        }
        let agent = try Peer(kemPublic: Data(b64u: kem), sigPublic: Data(b64u: sig))
        let label = hello["label"] as? String ?? ""
        let expected = mac(secret, transcript(mode.helloLabel, [utf8(ch), agent.kemPublic, agent.sigPublic, utf8(label)]))
        guard equal(try Data(b64u: macText), expected) else {
            throw CoreError.crypto("the pairing code does not match this agent")
        }
        return (label, agent, mode)
    }

    /// The answer's MAC; `keyBlob` is the SSH key (sign mode) or the
    /// approval key (approve mode), as an SSH public key blob.
    static func answerMac(secret: Data, mode: PairingMode, ch: String, signer: String, me: Identity,
                          keyBlob: Data, agent: Peer) -> Data {
        mac(secret, transcript(mode.answerLabel, [utf8(ch), utf8(signer), me.kemPublic, me.sigPublic, keyBlob,
                                                  agent.kemPublic, agent.sigPublic]))
    }

    /// Our answer: public keys and the key of the mode, sealed to the agent.
    public static func buildAnswer(ch: String, signer: String, secret: Data, me: Identity, agent: Peer,
                                   keyBlob: Data, comment: String, mode: PairingMode = .sign) throws -> String {
        let tag = answerMac(secret: secret, mode: mode, ch: ch, signer: signer, me: me, keyBlob: keyBlob, agent: agent)
        return try Channel.sealIntroduction(me, to: agent, header: Header.pair(ch: ch, signer: signer), [
            "t": "pair",
            mode.answerField: keyBlob.b64u,
            "comment": comment,
            "kem": me.kemPublic.b64u,
            "mac": tag.b64u,
        ])
    }

    /// Six digits both ends display once paired, e.g. "042 917".
    public static func fingerprint(agent: Peer, me: Identity, keyBlob: Data, mode: PairingMode = .sign) -> String {
        fingerprint(agentKem: agent.kemPublic, agentSig: agent.sigPublic, kem: me.kemPublic, sig: me.sigPublic,
                    keyBlob: keyBlob, mode: mode)
    }

    static func fingerprint(agentKem: Data, agentSig: Data, kem: Data, sig: Data, keyBlob: Data, mode: PairingMode) -> String {
        let digest = [UInt8](transcript(mode.fingerprintLabel, [agentKem, agentSig, kem, sig, keyBlob]).sha256)
        let n = UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])
        let digits = String(format: "%06u", n % 1_000_000)
        return "\(digits.prefix(3)) \(digits.suffix(3))"
    }
}
