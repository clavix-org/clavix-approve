// The subscription to the hosted relay: the status shown, which pairings
// receive the proof, and the relay's answers to it.

import Foundation
import XCTest
@testable import ClavixCore

final class SubscriptionTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let day: TimeInterval = 86_400

    private func purchase(_ id: UInt64, _ product: String = RelaySubscription.monthly, expires: TimeInterval?,
                          revoked: TimeInterval? = nil, trial: Bool = false, entitled: Bool = true) -> SubscriptionPurchase {
        SubscriptionPurchase(productID: product, transactionID: id, expires: expires.map { now.addingTimeInterval($0) },
                 revoked: revoked.map { now.addingTimeInterval($0) }, isTrial: trial, entitled: entitled, jws: "jws\(id)")
    }

    private func pairing(_ relay: String, signer: String = "0011223344556677", confirmed: Bool = true) -> PairingRecord {
        PairingRecord(relay: URL(string: relay)!, ch: String(repeating: "0f", count: 16), signer: signer, token: "t",
                      agent: peer(of: softwareIdentity()), label: "box", fingerprint: "123 456", mode: .approve,
                      confirmed: confirmed)
    }

    // ---- status ----

    func testStatus() {
        XCTAssertEqual(RelaySubscription.status([], now: now), .never)
        XCTAssertEqual(RelaySubscription.status([purchase(1, expires: 14 * day, trial: true)], now: now),
                       .trial(until: now.addingTimeInterval(14 * day)))
        XCTAssertEqual(RelaySubscription.status([purchase(1, RelaySubscription.yearly, expires: 300 * day)], now: now),
                       .active(until: now.addingTimeInterval(300 * day)))
        // Only the latest transaction of a plan, no longer entitled.
        XCTAssertEqual(RelaySubscription.status([purchase(1, expires: -3 * day, entitled: false)], now: now),
                       .expired(since: now.addingTimeInterval(-3 * day)))
        // Refunded: expired from the revocation, though the period runs on.
        XCTAssertEqual(RelaySubscription.status([purchase(1, expires: 20 * day, revoked: -day)], now: now),
                       .expired(since: now.addingTimeInterval(-day)))
        // Billing grace period: still entitled, period over, no end shown.
        XCTAssertEqual(RelaySubscription.status([purchase(1, expires: -day)], now: now), .active(until: nil))
        // Another app's product is not ours.
        XCTAssertEqual(RelaySubscription.status([purchase(1, "org.example.other", expires: 9 * day)], now: now), .never)
    }

    func testCurrentIsTheLongestInForce() {
        let trialEnded = purchase(1, expires: -day, trial: true, entitled: false)
        let monthly = purchase(2, expires: 20 * day)
        let yearly = purchase(3, RelaySubscription.yearly, expires: 340 * day)
        XCTAssertEqual(RelaySubscription.current([trialEnded, monthly, yearly], now: now), yearly)
        XCTAssertEqual(RelaySubscription.current([trialEnded, monthly], now: now), monthly)
        XCTAssertNil(RelaySubscription.current([trialEnded], now: now))
        XCTAssertEqual(RelaySubscription.status([trialEnded, monthly], now: now), .active(until: now.addingTimeInterval(20 * day)))
    }

    // ---- the hosted relay only ----

    func testOnlyTheHostedRelayNeedsIt() {
        let hosted = pairing("https://approve.clavix.org")
        let own = pairing("https://relay.example")
        XCTAssertTrue(RelaySubscription.needed(by: hosted))
        XCTAssertFalse(RelaySubscription.needed(by: own))
        XCTAssertFalse(RelaySubscription.needed(by: pairing("https://approve.clavix.org:8443")))

        // No prompt before StoreKit answered, with a subscription, or
        // without a machine on the hosted relay.
        XCTAssertFalse(RelaySubscription.shouldPrompt(status: nil, pairings: [hosted]))
        XCTAssertFalse(RelaySubscription.shouldPrompt(status: .active(until: nil), pairings: [hosted]))
        XCTAssertFalse(RelaySubscription.shouldPrompt(status: .never, pairings: [own]))
        XCTAssertFalse(RelaySubscription.shouldPrompt(status: .expired(since: nil), pairings: []))
        XCTAssertTrue(RelaySubscription.shouldPrompt(status: .never, pairings: [own, hosted]))
        XCTAssertTrue(RelaySubscription.shouldPrompt(status: .expired(since: nil), pairings: [hosted]))
    }

    // ---- which pairings get the proof ----

    func testPendingPairings() {
        let a = pairing("https://approve.clavix.org", signer: "aaaaaaaaaaaaaaaa")
        let b = pairing("https://approve.clavix.org", signer: "bbbbbbbbbbbbbbbb")
        let unconfirmed = pairing("https://approve.clavix.org", signer: "cccccccccccccccc", confirmed: false)
        let own = pairing("https://relay.example", signer: "dddddddddddddddd")
        let all = [a, b, unconfirmed, own]
        let sub = purchase(7, expires: 20 * day)
        let key = EntitlementSync.key

        XCTAssertEqual(EntitlementSync.pending(all, current: nil, delivered: [:]), [])
        XCTAssertEqual(EntitlementSync.pending(all, current: sub, delivered: [:]), [a, b])

        // Settled answers for this transaction are not sent again; a failure is.
        var delivered = [key(a): EntitlementDelivery(transactionID: 7, outcome: .accepted(expires: nil)),
                         key(b): EntitlementDelivery(transactionID: 7, outcome: .failed)]
        XCTAssertEqual(EntitlementSync.pending(all, current: sub, delivered: delivered), [b])
        delivered[key(b)] = EntitlementDelivery(transactionID: 7, outcome: .machineLimit)
        XCTAssertEqual(EntitlementSync.pending(all, current: sub, delivered: delivered), [])

        // A renewal is a new transaction: due everywhere again.
        XCTAssertEqual(EntitlementSync.pending(all, current: purchase(8, expires: 50 * day), delivered: delivered), [a, b])
    }

    // ---- the relay's answers ----

    func testOutcomes() {
        let expires = Date(timeIntervalSince1970: 1_900_000_000)
        XCTAssertEqual(EntitlementOutcome(.success(expires)), .accepted(expires: expires))
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 403, message: "", code: "machine_limit"))), .machineLimit)
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 403, message: ""))), .refused(status: 403))
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 401, message: ""))), .refused(status: 401))
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 400, message: "", code: "bad_jws"))), .refused(status: 400))
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 429, message: ""))), .failed)
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 502, message: ""))), .failed)
        XCTAssertEqual(EntitlementOutcome(.failure(RelayError(status: 0, message: "unreachable"))), .failed)
        XCTAssertEqual(EntitlementOutcome(.failure(CoreError.malformed("x"))), .failed)
        XCTAssertTrue(EntitlementOutcome.machineLimit.isSettled)
        XCTAssertFalse(EntitlementOutcome.failed.isSettled)
    }

    func testPostEntitlementCall() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubRelay.self]
        let client = RelayClient(base: URL(string: "https://approve.clavix.org/")!, ch: "ab12", token: "tok",
                                 session: URLSession(configuration: config))

        StubRelay.answer = (200, #"{"ok":true,"expires":1900000000}"#)
        let expires = try await client.postEntitlement(signer: "0011223344556677", jws: "a.b.c")
        XCTAssertEqual(expires, Date(timeIntervalSince1970: 1_900_000_000))
        let seen = try XCTUnwrap(StubRelay.seen)
        XCTAssertEqual(seen.method, "POST")
        XCTAssertEqual(seen.url, "https://approve.clavix.org/api/ch/ab12/dev/0011223344556677/entitlement")
        XCTAssertEqual(seen.authorization, "Bearer tok")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: seen.body) as? [String: String], ["jws": "a.b.c"])

        StubRelay.answer = (403, #"{"error":"machine_limit"}"#)
        do {
            _ = try await client.postEntitlement(signer: "0011223344556677", jws: "a.b.c")
            XCTFail("a refusal passed")
        } catch let e as RelayError {
            XCTAssertEqual(e.status, 403)
            XCTAssertEqual(e.code, "machine_limit")
            XCTAssertEqual(EntitlementOutcome(.failure(e)), .machineLimit)
        }

        // A proxy's HTML page: no code.
        StubRelay.answer = (502, "<html>bad gateway</html>")
        do {
            _ = try await client.postEntitlement(signer: "0011223344556677", jws: "a.b.c")
            XCTFail("a proxy error passed")
        } catch let e as RelayError {
            XCTAssertEqual(e.status, 502)
            XCTAssertNil(e.code)
        }
    }
}

/// Answers every call with `answer` and keeps the last request.
final class StubRelay: URLProtocol {
    struct Seen {
        let method: String
        let url: String
        let authorization: String?
        let body: Data
    }

    nonisolated(unsafe) static var answer: (Int, String) = (200, "{}")
    nonisolated(unsafe) static var seen: Seen?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                body.append(buffer, count: n)
            }
            stream.close()
        }
        Self.seen = Seen(method: request.httpMethod ?? "", url: request.url?.absoluteString ?? "",
                         authorization: request.value(forHTTPHeaderField: "Authorization"), body: body)
        let (status, text) = Self.answer
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(text.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
