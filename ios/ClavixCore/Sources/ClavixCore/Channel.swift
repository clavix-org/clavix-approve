// The end-to-end channel between the agent and the signer, as in
// web/lib/channel.js and PROTOCOL.md, "The sealed channel".
//
//   msg       = base64url( signature(64) || enc(65) || ciphertext )
//   info      = "clavix-approve/v1 hpke" || sender signing key || recipient HPKE key
//   signature = Ed25519( "clavix-approve/v1 sig" || string(header) || string(enc) || string(ciphertext) )

import CryptoKit
import Foundation

let protocolLabel = "clavix-approve/v1"
private let sigLength = 64

/// Our long-term channel keys.
public struct Identity {
    public let kem: ChannelKEMKey
    public let sig: Curve25519.Signing.PrivateKey

    public init(kem: ChannelKEMKey, sig: Curve25519.Signing.PrivateKey) {
        self.kem = kem
        self.sig = sig
    }

    public var kemPublic: Data { kem.publicKeyRaw }
    public var sigPublic: Data { sig.publicKey.rawRepresentation }
}

/// The other side's public keys, as raw bytes.
public struct Peer: Equatable, Codable {
    public let kemPublic: Data
    public let sigPublic: Data

    public init(kemPublic: Data, sigPublic: Data) throws {
        guard kemPublic.count == HPKE.encLength, kemPublic.first == 4, sigPublic.count == 32 else {
            throw CoreError.malformed("invalid peer keys")
        }
        self.kemPublic = kemPublic
        self.sigPublic = sigPublic
    }
}

public enum Header {
    static func make(_ kind: String, _ fields: [String]) -> Data {
        fields.reduce(sshString(protocolLabel) + sshString(kind)) { $0 + sshString($1) }
    }

    public static func request(ch: String, signer: String, id: String, exp: Int) -> Data {
        make("request", [ch, signer, id, String(exp)])
    }

    public static func response(ch: String, signer: String, id: String) -> Data {
        make("response", [ch, signer, id])
    }

    public static func pair(ch: String, signer: String) -> Data {
        make("pair", [ch, signer])
    }
}

public enum Channel {
    private static func hpkeInfo(senderSig: Data, recipientKem: Data) -> Data {
        utf8("\(protocolLabel) hpke") + senderSig + recipientKem
    }

    private static func signedBytes(_ hdr: Data, _ enc: Data, _ ct: Data) -> Data {
        utf8("\(protocolLabel) sig") + sshString(hdr) + sshString(enc) + sshString(ct)
    }

    static func sealBytes(_ me: Identity, to: Peer, header hdr: Data, _ obj: [String: Any]) throws -> Data {
        let json = try JSONSerialization.data(withJSONObject: obj)
        let (enc, ct) = try HPKE.seal(to: to.kemPublic, info: hpkeInfo(senderSig: me.sigPublic, recipientKem: to.kemPublic),
                                      aad: hdr, plaintext: json)
        let signature = try me.sig.signature(for: signedBytes(hdr, enc, ct))
        return signature + enc + ct
    }

    static func openBytes(_ me: Identity, fromSig: Data, header hdr: Data, _ raw: Data) throws -> [String: Any] {
        guard raw.count >= sigLength + HPKE.encLength + 16 else { throw CoreError.crypto("message too short") }
        let raw = Data(raw)
        let signature = raw.prefix(sigLength)
        let enc = raw.subdata(in: sigLength..<sigLength + HPKE.encLength)
        let ct = raw.suffix(from: sigLength + HPKE.encLength)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: fromSig)
        guard key.isValidSignature(signature, for: signedBytes(hdr, enc, Data(ct))) else {
            throw CoreError.crypto("bad signature")
        }
        let plain = try HPKE.open(with: me.kem, info: hpkeInfo(senderSig: fromSig, recipientKem: me.kemPublic),
                                  aad: hdr, enc: enc, ct: Data(ct))
        guard let obj = try JSONSerialization.jsonObject(with: plain) as? [String: Any] else {
            throw CoreError.malformed("not a message")
        }
        return obj
    }

    /// Seal `obj` for `to`, bound to `header`.
    public static func seal(_ me: Identity, to: Peer, header: Data, _ obj: [String: Any]) throws -> String {
        try sealBytes(me, to: to, header: header, obj).b64u
    }

    /// Open a message from the known peer `from`; throws unless it is
    /// authentic, meant for us and bound to `header`.
    public static func open(_ me: Identity, from: Peer, header: Data, _ msg: String) throws -> [String: Any] {
        try openBytes(me, fromSig: from.sigPublic, header: header, Data(b64u: msg))
    }

    /// Pairing only: our signing key travels in front of the message.
    public static func sealIntroduction(_ me: Identity, to: Peer, header: Data, _ obj: [String: Any]) throws -> String {
        (me.sigPublic + (try sealBytes(me, to: to, header: header, obj))).b64u
    }
}
