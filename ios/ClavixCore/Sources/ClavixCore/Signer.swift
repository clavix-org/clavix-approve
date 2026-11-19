// What a signer does, independent of where its keys live and of how the
// user is asked: pair, read a request, answer it. As in web/lib/signer.js.

import Foundation

/// What a pairing leaves to store.
public struct PairingRecord: Codable, Equatable {
    public let relay: URL
    public let ch: String
    public let signer: String
    public let token: String
    public let agent: Peer
    public let label: String
    /// The six digits to compare with the agent's display.
    public let fingerprint: String
    /// Set at pairing, for good. Records made before approve mode have none:
    /// they are in sign mode.
    public let mode: PairingMode
    /// The pairing protocol version it was made with. Records of the first
    /// version have none: they are obsolete, and must be made again.
    public let version: Int
    /// Whether the user said the machine shows the same digits. Until then
    /// the pairing accepts no request.
    public var confirmed: Bool

    public init(relay: URL, ch: String, signer: String, token: String, agent: Peer, label: String,
                fingerprint: String, mode: PairingMode, version: Int = Pairing.version, confirmed: Bool = false) {
        (self.relay, self.ch, self.signer, self.token, self.agent, self.label, self.fingerprint, self.mode)
            = (relay, ch, signer, token, agent, label, fingerprint, mode)
        (self.version, self.confirmed) = (version, confirmed)
    }

    enum CodingKeys: String, CodingKey { case relay, ch, signer, token, agent, label, fingerprint, mode, version, confirmed }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        relay = try c.decode(URL.self, forKey: .relay)
        ch = try c.decode(String.self, forKey: .ch)
        signer = try c.decode(String.self, forKey: .signer)
        token = try c.decode(String.self, forKey: .token)
        agent = try c.decode(Peer.self, forKey: .agent)
        label = try c.decode(String.self, forKey: .label)
        fingerprint = try c.decode(String.self, forKey: .fingerprint)
        mode = try c.decodeIfPresent(PairingMode.self, forKey: .mode) ?? .sign
        version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
        confirmed = try c.decodeIfPresent(Bool.self, forKey: .confirmed) ?? false
    }

    /// Made with the current protocol: a record of the first version was
    /// paired with digits a relay could steer, and is not used.
    public var isCurrent: Bool { version >= Pairing.version }

    /// May this pairing's requests be shown and answered?
    public var isActive: Bool { isCurrent && confirmed }
}

/// A hello read and authenticated, nothing sent yet: what the user must
/// see before the phone answers (relay, machine, mode).
public struct PairingOffer {
    public let relay: URL
    public let code: PairingCode
    public let hello: PairingHello

    /// The machine's name, cleaned for display (unverified).
    public var label: String { ClavixCore.label(hello.label) ?? "" }
    public var mode: PairingMode { hello.mode }
    public var isOfficialRelay: Bool { RelayAddress.isOfficial(relay) }
}

public struct SignerContext {
    public let record: PairingRecord
    public let me: Identity
    /// Our SSH key in sign mode, our approval key in approve mode.
    public let keyBlob: Data

    public init(record: PairingRecord, me: Identity, keyBlob: Data) {
        self.record = record
        self.me = me
        self.keyBlob = keyBlob
    }

    public var relay: RelayClient { RelayClient(base: record.relay, ch: record.ch, token: record.token) }
}

public enum Signer {
    /// How long to wait for the agent's nonce after answering: it reveals
    /// it as soon as it has read the answer.
    static let revealWait: TimeInterval = 60

    /// First half of a pairing: fetch and authenticate the agent's hello.
    /// Nothing is sent: the caller shows the relay, the machine and the
    /// mode, and answers only once the user agrees.
    public static func open(relay: URL, code: PairingCode) async throws -> PairingOffer {
        let pairing = RelayClient(base: relay, ch: code.ch, token: Pairing.pairToken(code.secret))
        let hello = try Pairing.readHello(try await pairing.hello(), ch: code.ch, secret: code.secret)
        return PairingOffer(relay: relay, code: code, hello: hello)
    }

    /// Second half: answer with our keys and a fresh nonce, wait for the
    /// agent's nonce and check it against the hello's commitment.
    /// `keyBlob` is the key of the offer's mode (the SSH key, or the
    /// approval key). The record comes back unconfirmed: it accepts no
    /// request until the user has said the machine shows the same digits.
    public static func answer(_ offer: PairingOffer, me: Identity, keyBlob: Data,
                              comment: String) async throws -> PairingRecord {
        let code = offer.code
        let pairing = RelayClient(base: offer.relay, ch: code.ch, token: Pairing.pairToken(code.secret))
        let signer = Data.random(8).hex
        let token = Data.random(32).b64u
        let nonce = Data.random(Pairing.nonceLength)
        let msg = try Pairing.buildAnswer(ch: code.ch, signer: signer, secret: code.secret, me: me, hello: offer.hello,
                                          keyBlob: keyBlob, nonce: nonce, comment: comment)
        let state = try await pairing.pair(signer: signer, signerAuth: tokenAuth(token), msg: msg)
        guard state == "paired" else { throw RelayError(status: 0, message: "the relay refused the pairing (\(state))") }

        let own = RelayClient(base: offer.relay, ch: code.ch, token: token)
        let deadline = Date().addingTimeInterval(revealWait)
        var revealed: Data?
        while revealed == nil {
            guard Date() < deadline else {
                _ = try? await own.revoke()
                throw RelayError(status: 0, message: "the machine did not finish the pairing")
            }
            revealed = try await own.reveal(wait: 20)
        }
        do {
            try Pairing.checkReveal(revealed!, commit: offer.hello.commit)
        } catch {
            // Someone in between: take this device off the channel at once.
            _ = try? await own.revoke()
            throw error
        }

        return PairingRecord(relay: offer.relay, ch: code.ch, signer: signer, token: token, agent: offer.hello.agent,
                             label: offer.label,
                             fingerprint: Pairing.digits(mode: offer.mode, ch: code.ch, signer: signer,
                                                         agent: offer.hello.agent, me: me, keyBlob: keyBlob,
                                                         agentNonce: revealed!, signerNonce: nonce),
                             mode: offer.mode, version: Pairing.version, confirmed: false)
    }

    /// Open and check one entry of the relay's request list. Never throws.
    /// A pairing the user has not confirmed answers nothing.
    public static func read(_ ctx: SignerContext, _ entry: RequestEntry, now: Double) -> Result<VerifiedRequest, Refusal> {
        guard ctx.record.isActive else { return .failure(.unauthentic) }
        let inner: [String: Any]
        do {
            let hdr = Header.request(ch: ctx.record.ch, signer: ctx.record.signer, id: entry.id, exp: entry.exp)
            inner = try Channel.open(ctx.me, from: ctx.record.agent, header: hdr, entry.msg)
        } catch {
            // Not from our agent, altered on the way, or not for us.
            return .failure(.unauthentic)
        }
        // A request of the other mode is refused as malformed.
        switch ctx.record.mode {
        case .sign: return checkSignRequest(inner, id: entry.id, keyBlob: ctx.keyBlob, now: now)
        case .approve: return checkApproveRequest(inner, id: entry.id, now: now)
        }
    }

    private static func respond(_ ctx: SignerContext, _ entry: RequestEntry, _ inner: [String: Any]) async throws -> String {
        let hdr = Header.response(ch: ctx.record.ch, signer: ctx.record.signer, id: entry.id)
        return try await ctx.relay.respond(id: entry.id, msg: Channel.seal(ctx.me, to: ctx.record.agent, header: hdr, inner))
    }

    /// `signatureBlob` is the SSH signature of the request's data.
    public static func approve(_ ctx: SignerContext, _ entry: RequestEntry, signatureBlob: Data) async throws -> String {
        try await respond(ctx, entry, signedResponse(requestMsg: entry.msg, id: entry.id, signatureBlob: signatureBlob))
    }

    /// Approve mode: the bytes the approval key must sign for this request.
    public static func approvalData(_ ctx: SignerContext, _ entry: RequestEntry) -> Data {
        approvalBytes(ch: ctx.record.ch, signer: ctx.record.signer, id: entry.id, requestMsg: entry.msg)
    }

    /// Approve mode: `proofBlob` is the approval key's SSH signature of
    /// approvalData().
    public static func sendApproval(_ ctx: SignerContext, _ entry: RequestEntry, proofBlob: Data) async throws -> String {
        try await respond(ctx, entry, approvedResponse(requestMsg: entry.msg, id: entry.id, proofBlob: proofBlob))
    }

    /// `reason` is "user" for a human refusal, else the refusal of read().
    /// An unauthentic request gets no answer: there is nobody to answer to.
    public static func deny(_ ctx: SignerContext, _ entry: RequestEntry, reason: String) async throws -> String {
        if reason == Refusal.unauthentic.rawValue { return "ignored" }
        return try await respond(ctx, entry, deniedResponse(requestMsg: entry.msg, id: entry.id, reason: reason))
    }
}
