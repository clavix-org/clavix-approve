// The checks the signer makes before anything is shown or signed, as in
// web/lib/protocol.js and PROTOCOL.md, "Sign request".
//
// The machine that runs the agent may be compromised: nothing it says
// about the destination is believed. Everything displayed comes out of
// checkSignRequest(), which re-derives it from the bytes to sign and from
// the server's own signature.

import Foundation

public let keyAlgorithm = "ecdsa-sha2-nistp256"
private let maxHops = 16

/// The relay stores only the SHA-256 of a bearer token.
public func tokenAuth(_ token: String) -> String { utf8(token).sha256.hex }

/// Text from the other side, made safe to show: one line, printable, bounded.
public func label(_ value: Any?, max: Int = 64) -> String? {
    guard let value = value as? String else { return nil }
    let kept = value.unicodeScalars.filter { c in
        switch c.properties.generalCategory {
        case .control, .format, .surrogate, .privateUse, .unassigned, .lineSeparator, .paragraphSeparator: return false
        default: return true
        }
    }
    var s = String.UnicodeScalarView()
    s.append(contentsOf: kept.prefix(max))
    let cleaned = String(s).trimmingCharacters(in: .whitespacesAndNewlines)
    return cleaned.isEmpty ? nil : cleaned
}

public enum Refusal: String, Error {
    case malformed, expired, unverified, unauthentic
    case unknownKey = "unknown-key"
}

public struct Hop: Equatable {
    public let hostKey: Data
    public let fingerprint: String
    public let forwarded: Bool
}

public struct Caller: Equatable {
    public let pid: Int?
    public let name: String?
}

/// A request that passed every check. `hops` is the verified chain,
/// outermost first, the last one being the host to authenticate to. A hop
/// carries the host key and its fingerprint, never a name: naming is done
/// from the signer's own pinned list.
public struct VerifiedRequest {
    public let data: Data
    public let exp: Double
    public let user: String?
    public let hops: [Hop]
    /// Unverified, for display only.
    public let caller: Caller?
    public let agent: String?
    public let hints: [String: String]

    public var destination: Hop { hops[hops.count - 1] }
}

/// A JSON boolean, not a number (JSONSerialization makes both NSNumber).
private func jsonBool(_ v: Any?) -> Bool? {
    guard let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
    return n.boolValue
}

/// A JSON number, not a boolean.
private func jsonNumber(_ v: Any?) -> Double? {
    guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
    return n.doubleValue
}

private func jsonInteger(_ v: Any?) -> Int? {
    guard let d = jsonNumber(v), d == d.rounded(), abs(d) <= 9_007_199_254_740_991 else { return nil }
    return Int(d)
}

/// Check a decoded sign request. `id` is the request id the relay gave,
/// `keyBlob` our own SSH public key, `now` the current time in seconds.
public func checkSignRequest(_ inner: [String: Any], id: String, keyBlob: Data, now: Double) -> Result<VerifiedRequest, Refusal> {
    guard inner["t"] as? String == "sign", inner["id"] as? String == id else { return .failure(.malformed) }
    guard let exp = jsonNumber(inner["exp"]), exp > now else { return .failure(.expired) }

    let key: Data, data: Data
    var binds: [(hostKey: Data, sessionId: Data, signature: Data, forwarded: Bool)] = []
    do {
        key = try Data(b64u: inner["key"] as? String ?? "!")
        data = try Data(b64u: inner["data"] as? String ?? "!")
        guard let list = inner["binds"] as? [Any], (1...maxHops).contains(list.count) else {
            return .failure(.unverified)
        }
        for item in list {
            guard let b = item as? [String: Any], let fwd = jsonBool(b["fwd"]) else { return .failure(.malformed) }
            binds.append((try Data(b64u: b["hostkey"] as? String ?? "!"), try Data(b64u: b["sid"] as? String ?? "!"),
                          try Data(b64u: b["sig"] as? String ?? "!"), fwd))
        }
    } catch {
        return .failure(.malformed)
    }
    guard equal(key, keyBlob) else { return .failure(.unknownKey) }

    // 1. The bytes to sign are a public-key login made with our key.
    guard let request = SSH.parseUserAuthRequest(data), request.service == "ssh-connection",
          request.algorithm == keyAlgorithm, equal(request.keyBlob, keyBlob) else {
        return .failure(.unverified)
    }

    // 2. Every hop is a session its host key really signed. Only the last
    //    one is for authentication; the ones before carry a forwarded agent.
    var hops: [Hop] = []
    for (i, b) in binds.enumerated() {
        let last = i == binds.count - 1
        guard b.forwarded != last else { return .failure(.unverified) }
        guard SSH.verifySignature(keyBlob: b.hostKey, data: b.sessionId, sigBlob: b.signature) else {
            return .failure(.unverified)
        }
        hops.append(Hop(hostKey: b.hostKey, fingerprint: SSH.fingerprint(b.hostKey), forwarded: b.forwarded))
    }

    // 3. The login is for that last session — and, when the client says
    //    which host it believes it talks to, for that very host key.
    let dest = binds[binds.count - 1]
    guard equal(request.sessionId, dest.sessionId) else { return .failure(.unverified) }
    if let hostKey = request.hostKey, !equal(hostKey, dest.hostKey) { return .failure(.unverified) }

    // Unverified, for display only.
    var caller: Caller? = nil
    if let c = inner["caller"] as? [String: Any] {
        caller = Caller(pid: jsonInteger(c["pid"]), name: label(c["name"], max: 32))
    }
    var hints: [String: String] = [:]
    if let h = inner["hints"] as? [String: Any] {
        for hop in hops {
            if let name = label(h[hop.fingerprint]) { hints[hop.fingerprint] = name }
        }
    }

    return .success(VerifiedRequest(
        data: data, exp: exp, user: String(data: request.user, encoding: .utf8).flatMap { label($0) },
        hops: hops, caller: caller, agent: label(inner["agent"]), hints: hints))
}

/// The response names the hash of the request exactly as received, so it
/// cannot be replayed against another one.
private func response(_ requestMsg: String, _ id: String, _ fields: [String: Any]) -> [String: Any] {
    fields.merging(["id": id, "req": utf8(requestMsg).sha256.b64u]) { a, _ in a }
}

/// `signatureBlob` is a complete SSH signature, which names its algorithm.
public func signedResponse(requestMsg: String, id: String, signatureBlob: Data) -> [String: Any] {
    response(requestMsg, id, ["t": "signed", "sig": signatureBlob.b64u])
}

public func deniedResponse(requestMsg: String, id: String, reason: String) -> [String: Any] {
    response(requestMsg, id, ["t": "denied", "reason": reason])
}
