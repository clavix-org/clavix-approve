// Pairing, signer side, protocol version 2, as in web/lib/pairing.js and
// PROTOCOL.md, "Pairing". The relay only sees a token derived from the
// one-time secret; a MAC keyed by another derivation authenticates the
// keys exchanged through it. The six digits are a short authentication
// string: the hello commits to the agent's nonce, we answer with our keys
// and a nonce of ours, then the agent reveals its nonce, which we check
// against the commitment. A relay that learnt the secret still has one
// chance in a million.

import CryptoKit
import Foundation

/// The relay address a pairing may use: https, or http to a loopback
/// address (tests), as core/src/relay.rs. Bearer tokens travel in a
/// header, so never in clear over a network.
public enum RelayAddress {
    /// The hosted relay. Any other needs an explicit step from the user.
    public static let official = URL(string: "https://approve.clavix.org")!

    /// `text` may lack its scheme: https is then assumed.
    public static func parse(_ text: String) throws -> URL {
        var base = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if !base.contains("://") { base = "https://" + base }
        while base.hasSuffix("/") { base.removeLast() }
        guard let url = URL(string: base), let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
            throw CoreError.malformed("not a relay address")
        }
        let scheme = url.scheme?.lowercased()
        let loopback = ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host.lowercased())
        guard scheme == "https" || (scheme == "http" && loopback) else {
            throw CoreError.malformed("the relay address must use https")
        }
        return url
    }

    /// Whether `url` is the hosted relay.
    public static func isOfficial(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && url.host?.lowercased() == official.host && url.port == nil
            && (url.path.isEmpty || url.path == "/")
    }
}

public struct PairingCode: Equatable {
    public static let prefix = "cva2-"
    static let oldPrefix = "cva1-"
    /// The app's URL scheme: `clavix-approve://pair?relay=<url>#cva2-…`.
    public static let scheme = "clavix-approve"

    /// Channel id, 32 hex digits.
    public let ch: String
    public let secret: Data
    /// The relay, when the code came as the agent's link.
    public let relay: URL?

    /// Accepts the bare code, or the `clavix-approve://pair?relay=…#code`
    /// link that the agent prints as a QR code.
    public init(_ input: String) throws {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var code = text
        var relay: URL? = nil
        if text.lowercased().hasPrefix(Self.scheme + ":") {
            guard let parts = URLComponents(string: text), parts.scheme?.lowercased() == Self.scheme,
                  parts.host?.lowercased() == "pair",
                  let relayText = parts.queryItems?.first(where: { $0.name == "relay" })?.value,
                  let fragment = parts.fragment else {
                throw CoreError.malformed("not a pairing link")
            }
            relay = try RelayAddress.parse(relayText)
            code = fragment
        }
        if code.hasPrefix(Self.oldPrefix) {
            throw CoreError.malformed("this code comes from an older clavix-agent or Clavix: update it, then pair again")
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
/// "Approve mode"). The mode is in every MAC and in the digits.
public enum PairingMode: String, Codable, Sendable {
    case sign, approve

    /// The field of the answer that carries the key.
    var answerField: String { self == .sign ? "key" : "approve" }
}

/// What the agent's hello says, once authenticated.
public struct PairingHello: Equatable {
    /// The machine's name, as the agent gives it (unverified).
    public let label: String
    public let agent: Peer
    public let mode: PairingMode
    /// The commitment to the nonce the agent reveals after our answer.
    public let commit: Data
}

public enum Pairing {
    public static let version = 2
    public static let nonceLength = 32

    static let helloLabel = "clavix-approve/v2/pair-hello"
    static let answerLabel = "clavix-approve/v2/pair-answer"
    static let commitLabel = "clavix-approve/v2/pair-commit"
    static let digitsLabel = "clavix-approve/v2/pair-digits"

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

    /// The commitment to the agent's nonce, carried by the hello.
    public static func commitment(_ nonce: Data) -> Data {
        transcript(commitLabel, [nonce]).sha256
    }

    static func helloMac(secret: Data, mode: PairingMode, ch: String, agent: Peer, label: String, commit: Data) -> Data {
        mac(secret, transcript(helloLabel, [utf8(mode.rawValue), utf8(ch), agent.kemPublic, agent.sigPublic,
                                            utf8(label), commit]))
    }

    /// Read the agent's hello and authenticate it with the secret. A hello
    /// of the first protocol version is refused, saying why.
    public static func readHello(_ helloMsg: String, ch: String, secret: Data) throws -> PairingHello {
        guard let hello = try JSONSerialization.jsonObject(with: Data(b64u: helloMsg)) as? [String: Any] else {
            throw CoreError.malformed("malformed hello")
        }
        guard let v = hello["v"] as? NSNumber, CFGetTypeID(v) != CFBooleanGetTypeID(), v.intValue == version else {
            throw CoreError.malformed("this machine uses an older pairing protocol: update clavix-agent or Clavix, then pair again")
        }
        guard let kem = hello["kem"] as? String, let sig = hello["sig"] as? String,
              let commitText = hello["commit"] as? String, let macText = hello["mac"] as? String else {
            throw CoreError.malformed("malformed hello")
        }
        guard let modeText = hello["mode"] as? String, let mode = PairingMode(rawValue: modeText) else {
            throw CoreError.malformed("this pairing code is for an unknown mode")
        }
        let agent = try Peer(kemPublic: Data(b64u: kem), sigPublic: Data(b64u: sig))
        let label = hello["label"] as? String ?? ""
        let commit = try Data(b64u: commitText)
        guard commit.count == 32 else { throw CoreError.malformed("malformed hello") }
        let expected = helloMac(secret: secret, mode: mode, ch: ch, agent: agent, label: label, commit: commit)
        guard equal(try Data(b64u: macText), expected) else {
            throw CoreError.crypto("the pairing code does not match this agent")
        }
        return PairingHello(label: label, agent: agent, mode: mode, commit: commit)
    }

    /// The answer's MAC; `keyBlob` is the SSH key (sign mode) or the
    /// approval key (approve mode), as an SSH public key blob.
    static func answerMac(secret: Data, mode: PairingMode, ch: String, signer: String, me: Identity,
                          keyBlob: Data, nonce: Data, agent: Peer, commit: Data) -> Data {
        mac(secret, transcript(answerLabel, [utf8(mode.rawValue), utf8(ch), utf8(signer), me.kemPublic, me.sigPublic,
                                             keyBlob, nonce, agent.kemPublic, agent.sigPublic, commit]))
    }

    /// Our answer: public keys, our nonce and the key of the mode, sealed
    /// to the agent.
    public static func buildAnswer(ch: String, signer: String, secret: Data, me: Identity, hello: PairingHello,
                                   keyBlob: Data, nonce: Data, comment: String) throws -> String {
        let tag = answerMac(secret: secret, mode: hello.mode, ch: ch, signer: signer, me: me, keyBlob: keyBlob,
                            nonce: nonce, agent: hello.agent, commit: hello.commit)
        return try Channel.sealIntroduction(me, to: hello.agent, header: Header.pair(ch: ch, signer: signer), [
            "t": "pair",
            "v": version,
            hello.mode.answerField: keyBlob.b64u,
            "comment": comment,
            "kem": me.kemPublic.b64u,
            "nonce": nonce.b64u,
            "mac": tag.b64u,
        ])
    }

    /// Check the nonce the agent revealed against its hello's commitment.
    public static func checkReveal(_ nonce: Data, commit: Data) throws {
        guard nonce.count == nonceLength, equal(commitment(nonce), commit) else {
            throw CoreError.crypto("the machine revealed a value that does not match its pairing code: someone is in between")
        }
    }

    /// The six digits both ends display, e.g. "042 917".
    public static func digits(mode: PairingMode, ch: String, signer: String, agent: Peer, me: Identity, keyBlob: Data,
                              agentNonce: Data, signerNonce: Data) -> String {
        digits(mode: mode, ch: ch, signer: signer, agentKem: agent.kemPublic, agentSig: agent.sigPublic,
               kem: me.kemPublic, sig: me.sigPublic, keyBlob: keyBlob, agentNonce: agentNonce, signerNonce: signerNonce)
    }

    static func digits(mode: PairingMode, ch: String, signer: String, agentKem: Data, agentSig: Data, kem: Data,
                       sig: Data, keyBlob: Data, agentNonce: Data, signerNonce: Data) -> String {
        let t = transcript(digitsLabel, [utf8(mode.rawValue), utf8(ch), utf8(signer), agentKem, agentSig, kem, sig,
                                         keyBlob, agentNonce, signerNonce])
        let digest = [UInt8](t.sha256)
        let n = UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])
        let digits = String(format: "%06u", n % 1_000_000)
        return "\(digits.prefix(3)) \(digits.suffix(3))"
    }
}
