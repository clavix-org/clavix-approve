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

    public init(relay: URL, ch: String, signer: String, token: String, agent: Peer, label: String,
                fingerprint: String, mode: PairingMode) {
        (self.relay, self.ch, self.signer, self.token, self.agent, self.label, self.fingerprint, self.mode)
            = (relay, ch, signer, token, agent, label, fingerprint, mode)
    }

    enum CodingKeys: String, CodingKey { case relay, ch, signer, token, agent, label, fingerprint, mode }

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
    }
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
    /// Pair with the agent that displayed `code`. `keyFor(mode)` gives the
    /// key blob for the mode the agent asks for (the SSH key, or the
    /// approval key), made then if need be.
    public static func pair(relay: URL, code: PairingCode, me: Identity, comment: String,
                            keyFor: (PairingMode) throws -> Data) async throws -> PairingRecord {
        let pairing = RelayClient(base: relay, ch: code.ch, token: Pairing.pairToken(code.secret))
        let hello = try Pairing.readHello(try await pairing.hello(), ch: code.ch, secret: code.secret)
        let keyBlob = try keyFor(hello.mode)

        let signer = Data.random(8).hex
        let token = Data.random(32).b64u
        let msg = try Pairing.buildAnswer(ch: code.ch, signer: signer, secret: code.secret, me: me, agent: hello.agent,
                                          keyBlob: keyBlob, comment: comment, mode: hello.mode)
        let state = try await pairing.pair(signer: signer, signerAuth: tokenAuth(token), msg: msg)
        guard state == "paired" else { throw RelayError(status: 0, message: "the relay refused the pairing (\(state))") }

        return PairingRecord(relay: relay, ch: code.ch, signer: signer, token: token, agent: hello.agent,
                             label: label(hello.label) ?? "",
                             fingerprint: Pairing.fingerprint(agent: hello.agent, me: me, keyBlob: keyBlob, mode: hello.mode),
                             mode: hello.mode)
    }

    /// Open and check one entry of the relay's request list. Never throws.
    public static func read(_ ctx: SignerContext, _ entry: RequestEntry, now: Double) -> Result<VerifiedRequest, Refusal> {
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
