// Client of the relay's HTTP API, signer side, as in web/lib/relay.js.
// See PROTOCOL.md, "Relay API".

import Foundation

public struct RelayError: Error, CustomStringConvertible {
    /// HTTP status, or 0 when the relay was not reached or did not answer JSON.
    public let status: Int
    public let message: String
    /// The call outlived its bound: a connection that died, not a refusal.
    public var timedOut = false
    /// The `error` field of the relay's JSON answer, when it gave one
    /// (`machine_limit`, …).
    public var code: String? = nil

    public var description: String { message }

    /// 4xx other than "slow down": our pairing is gone or the call is wrong.
    public var isFatal: Bool { status >= 400 && status < 500 && status != 429 }
}

/// One entry of the relay's request list.
public struct RequestEntry: Equatable, Sendable {
    public let id: String
    public let exp: Int
    public let msg: String
}

/// Calls are spaced out, whatever triggers them: a reverse proxy in front
/// of the relay may throttle a client, and ban one that insists.
actor Pacer {
    static let shared = Pacer()
    private static let gap: TimeInterval = 0.35
    private var next = Date.distantPast

    func slot() async {
        let now = Date()
        let at = max(now, next)
        next = at.addingTimeInterval(Self.gap)
        let delay = at.timeIntervalSince(now)
        if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1e9)) }
    }
}

public struct RelayClient: Sendable {
    public let base: URL
    public let ch: String
    let token: String
    let session: URLSession

    public init(base: URL, ch: String, token: String, session: URLSession = .shared) {
        self.base = base
        self.ch = ch
        self.token = token
        self.session = session
    }

    func call(_ method: String, _ path: String, body: [String: Any]? = nil, timeout: TimeInterval = 30) async throws -> [String: Any]? {
        await Pacer.shared.slot()
        var url = base.absoluteString
        while url.hasSuffix("/") { url.removeLast() }
        guard let target = URL(string: "\(url)/api/ch/\(ch)/\(path)") else {
            throw RelayError(status: 0, message: "bad relay address")
        }
        var req = URLRequest(url: target, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw RelayError(status: 0, message: "relay unreachable (\(error.localizedDescription))",
                             timedOut: (error as? URLError)?.code == .timedOut)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 204 { return nil }
        // A proxy in front may answer with its own HTML error page.
        guard (200..<300).contains(status) else {
            let code = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw RelayError(status: status, message: "relay answered HTTP \(status)" + (code.map { " (\($0))" } ?? ""),
                             code: code)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RelayError(status: status, message: "relay answer is not JSON")
        }
        return obj
    }

    private func state(_ obj: [String: Any]?) -> String { obj?["state"] as? String ?? "" }

    // ---- pairing (the token is the one derived from the pairing secret) ----

    public func hello() async throws -> String {
        guard let hello = try await call("GET", "pair")?["hello"] as? String else {
            throw RelayError(status: 0, message: "no pairing waits on this code")
        }
        return hello
    }

    public func pair(signer: String, signerAuth: String, msg: String) async throws -> String {
        state(try await call("POST", "pair", body: ["signer": signer, "signer_auth": signerAuth, "msg": msg]))
    }

    /// The agent's nonce, once it has read our answer (the token is the
    /// signer's own, just enrolled). With `wait`, a long-poll; nil: not yet.
    public func reveal(wait: Int = 0) async throws -> Data? {
        let query = wait > 0 ? "?wait=\(wait)" : ""
        guard let text = try await call("GET", "pair/reveal\(query)", timeout: TimeInterval(wait + 10))?["nonce"] as? String else {
            return nil
        }
        return try Data(b64u: text)
    }

    // ---- normal operation (the token is the signer's own) ----

    /// Register this device's push token. `sandbox` for a development build.
    public func subscribeAPNs(deviceToken: Data, sandbox: Bool) async throws -> String {
        state(try await call("POST", "subscription", body: ["apns": deviceToken.hex, "sandbox": sandbox]))
    }

    /// Pending requests. With `wait`, the relay holds the call until the
    /// pending set differs from `known` (ids we already hold).
    public func requests(wait: Int = 0, known: [String] = []) async throws -> [RequestEntry] {
        let query = wait > 0 ? "?wait=\(wait)&known=\(known.joined(separator: ","))" : ""
        // A connection that died while the phone slept must not hang: the
        // call is bounded a little past its wait.
        let list = try await call("GET", "requests\(query)", timeout: TimeInterval(wait + 10))?["requests"] as? [Any] ?? []
        return list.compactMap { item in
            guard let e = item as? [String: Any], let id = e["id"] as? String, let msg = e["msg"] as? String,
                  let exp = e["exp"] as? NSNumber, CFGetTypeID(exp) != CFBooleanGetTypeID() else { return nil }
            return RequestEntry(id: id, exp: exp.intValue, msg: msg)
        }
    }

    public func respond(id: String, msg: String) async throws -> String {
        state(try await call("POST", "responses/\(id)", body: ["msg": msg]))
    }

    /// Hand the hosted relay the App Store's signed transaction of this
    /// device's subscription (`Transaction.jwsRepresentation`). Returns the
    /// time up to which the relay serves this device, when it says.
    /// `403` with code `machine_limit`: the subscription already covers
    /// `RelaySubscription.machineLimit` machines.
    public func postEntitlement(signer: String, jws: String) async throws -> Date? {
        let obj = try await call("POST", "dev/\(signer)/entitlement", body: ["jws": jws])
        guard let n = obj?["expires"] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        return Date(timeIntervalSince1970: n.doubleValue)
    }

    /// Delete this device's pairing on the relay. True when this call did
    /// it, false when the relay no longer knew it (already revoked).
    public func revoke() async throws -> Bool {
        do {
            return state(try await call("POST", "revoke", body: [:])) == "revoked"
        } catch let e as RelayError where e.status == 401 {
            return false
        }
    }
}
