// The signer's checks, ported from web/test/protocol.test.mjs.

import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

private let NOW: Double = 1_800_000_000
private let ID = String(repeating: "ab", count: 16)
private let SID = Data("exchange-hash-of-the-session".utf8)

private struct Scene {
    let key = ClientKey()
    let host: HostKey
    var inner: [String: Any]

    init() throws {
        host = try hostKey(.ed25519)
        inner = [
            "t": "sign", "id": ID, "iat": NOW - 1, "exp": NOW + 90,
            "key": key.blob.b64u,
            "data": userAuth(sessionId: SID, keyBlob: key.blob, hostKey: host.blob).b64u,
            "flags": 0,
            "binds": [try sessionBind(host, SID)],
            "caller": ["pid": 4242, "name": "ssh"],
            "agent": "build-box",
            "hints": [String: Any](),
        ]
    }

    func check() -> Result<VerifiedRequest, Refusal> {
        // Through JSON, as it arrives: booleans and numbers must stay apart.
        let json = try! JSONSerialization.data(withJSONObject: inner)
        let parsed = try! JSONSerialization.jsonObject(with: json) as! [String: Any]
        return checkSignRequest(parsed, id: ID, keyBlob: key.blob, now: NOW)
    }
}

private func refusal(_ r: Result<VerifiedRequest, Refusal>) -> Refusal? {
    if case .failure(let f) = r { return f }
    return nil
}

final class ProtocolTests: XCTestCase {
    func testHonestRequestYieldsTheVerifiedDestination() throws {
        var s = try Scene()
        s.inner["hints"] = [SSH.fingerprint(s.host.blob): "prod.example"]
        let v = try s.check().get()
        XCTAssertEqual(v.user, "deploy")
        XCTAssertEqual(v.hops.count, 1)
        XCTAssertEqual(v.destination.fingerprint, SSH.fingerprint(s.host.blob))
        XCTAssertFalse(v.destination.forwarded)
        XCTAssertEqual(v.caller, Caller(pid: 4242, name: "ssh"))
        XCTAssertEqual(v.agent, "build-box")
        XCTAssertEqual(v.hints, [SSH.fingerprint(s.host.blob): "prod.example"])
        XCTAssertEqual(v.data.b64u, s.inner["data"] as? String)
    }

    func testEveryHostKeyTypeVerifies() throws {
        for type in [HostKeyType.ed25519, .p256, .p384, .p521, .rsa] {
            var s = try Scene()
            let host = try hostKey(type)
            s.inner["data"] = userAuth(sessionId: SID, keyBlob: s.key.blob, hostKey: host.blob).b64u
            s.inner["binds"] = [try sessionBind(host, SID)]
            XCTAssertNoThrow(try s.check().get(), "\(type)")
            // … and a signature by another key of the same type does not.
            s.inner["binds"] = [["hostkey": host.blob.b64u, "sid": SID.b64u, "sig": try hostKey(type).sign(SID).b64u, "fwd": false]]
            XCTAssertEqual(refusal(s.check()), .unverified, "\(type)")
        }
    }

    func testRequestWithoutHostBoundDataIsStillTiedToTheSession() throws {
        var s = try Scene()
        s.inner["data"] = userAuth(sessionId: SID, keyBlob: s.key.blob).b64u
        XCTAssertNoThrow(try s.check().get())
        s.inner["binds"] = [try sessionBind(s.host, Data("another-session".utf8))]
        XCTAssertEqual(refusal(s.check()), .unverified)
    }

    func testForwardingChainIsShownWholeOutermostFirst() throws {
        var s = try Scene()
        let jump = try hostKey(.p256)
        s.inner["binds"] = [try sessionBind(jump, Data("jump-session".utf8), forwarded: true), try sessionBind(s.host, SID)]
        let v = try s.check().get()
        XCTAssertEqual(v.hops.map(\.forwarded), [true, false])
        XCTAssertEqual(v.hops[0].fingerprint, SSH.fingerprint(jump.blob))
    }

    /// The agent's machine is compromised and wants a signature for a
    /// server the user is not looking at.
    func testFalsifiedDestinationsAreRefused() throws {
        let impostor = try hostKey(.ed25519)
        let cases: [(String, (inout Scene) throws -> Void)] = [
            ("binding signed by another key", { s in
                var b = (s.inner["binds"] as! [[String: Any]])[0]
                b["sig"] = try impostor.sign(SID).b64u
                s.inner["binds"] = [b]
            }),
            ("binding claims another host key", { s in
                var b = (s.inner["binds"] as! [[String: Any]])[0]
                b["hostkey"] = impostor.blob.b64u
                s.inner["binds"] = [b]
            }),
            ("host-bound request names another host", { s in
                s.inner["data"] = userAuth(sessionId: SID, keyBlob: s.key.blob, hostKey: impostor.blob).b64u
            }),
            ("last hop marked forwarded", { s in s.inner["binds"] = [try sessionBind(s.host, SID, forwarded: true)] }),
            ("middle hop not marked forwarded", { s in
                s.inner["binds"] = [try sessionBind(impostor, Data("x".utf8)), try sessionBind(s.host, SID)]
            }),
            ("no binding", { s in s.inner["binds"] = [Any]() }),
            ("seventeen bindings", { s in
                s.inner["binds"] = try (0..<16).map { _ in try sessionBind(impostor, Data("x".utf8), forwarded: true) }
                    + [try sessionBind(s.host, SID)]
            }),
            ("not a login", { s in s.inner["data"] = (Data([0, 0, 0, 1, 0]) + Data("x".utf8)).b64u }),
            ("another service", { s in
                s.inner["data"] = userAuth(sessionId: SID, keyBlob: s.key.blob, service: "other").b64u
            }),
            ("another algorithm", { s in
                s.inner["data"] = userAuth(sessionId: SID, keyBlob: s.key.blob, algorithm: "ssh-ed25519").b64u
            }),
            ("login made with another key", { s in
                s.inner["data"] = userAuth(sessionId: SID, keyBlob: ClientKey().blob).b64u
            }),
            ("trailing bytes", { s in
                s.inner["data"] = (userAuth(sessionId: SID, keyBlob: s.key.blob) + Data([0])).b64u
            }),
        ]
        for (name, mutate) in cases {
            var s = try Scene()
            try mutate(&s)
            XCTAssertEqual(refusal(s.check()), .unverified, name)
        }
    }

    func testOtherRefusals() throws {
        var s = try Scene()
        s.inner["exp"] = NOW
        XCTAssertEqual(refusal(s.check()), .expired)

        s = try Scene()
        s.inner["exp"] = true
        XCTAssertEqual(refusal(s.check()), .expired)

        s = try Scene()
        s.inner["id"] = "cd"
        XCTAssertEqual(refusal(s.check()), .malformed)

        s = try Scene()
        s.inner["t"] = "pair"
        XCTAssertEqual(refusal(s.check()), .malformed)

        s = try Scene()
        s.inner["key"] = ClientKey().blob.b64u
        XCTAssertEqual(refusal(s.check()), .unknownKey)

        s = try Scene()
        s.inner["data"] = "not base64url!"
        XCTAssertEqual(refusal(s.check()), .malformed)

        s = try Scene()
        var b = (s.inner["binds"] as! [[String: Any]])[0]
        b["fwd"] = 0 // a number is not a boolean
        s.inner["binds"] = [b]
        XCTAssertEqual(refusal(s.check()), .malformed)
    }

    func testWhatTheMachineSaysIsCleanedAndBounded() throws {
        var s = try Scene()
        s.inner["agent"] = "evil\u{202E}box\nnext"
        s.inner["caller"] = ["pid": "12", "name": String(repeating: "x", count: 50)]
        s.inner["hints"] = ["SHA256:not-a-hop": "elsewhere"]
        let v = try s.check().get()
        XCTAssertEqual(v.agent, "evilboxnext")
        XCTAssertEqual(v.caller, Caller(pid: nil, name: String(repeating: "x", count: 32)))
        XCTAssertEqual(v.hints, [:])
        XCTAssertNil(label("  \u{0007} "))
        XCTAssertNil(label(42))
    }

    func testOurSignatureBlobVerifies() throws {
        let k = ClientKey()
        let data = Data("to sign".utf8)
        for _ in 0..<8 { // r or s with the high bit set needs a leading zero
            let blob = try SSH.p256SignatureBlob(raw: try k.key.signature(for: data).rawRepresentation)
            XCTAssertTrue(SSH.verifySignature(keyBlob: k.blob, data: data, sigBlob: blob))
            XCTAssertFalse(SSH.verifySignature(keyBlob: k.blob, data: Data("other".utf8), sigBlob: blob))
        }
        XCTAssertTrue(SSH.publicKeyLine(keyBlob: k.blob, comment: "phone").hasPrefix("ecdsa-sha2-nistp256 AAAA"))
    }

    func testResponsesNameTheRequest() throws {
        let r = signedResponse(requestMsg: "abc", id: ID, signatureBlob: Data([1, 2]))
        XCTAssertEqual(r["t"] as? String, "signed")
        XCTAssertEqual(r["req"] as? String, Data(SHA256.hash(data: Data("abc".utf8))).b64u)
        XCTAssertEqual(r["sig"] as? String, "AQI")
        XCTAssertEqual(deniedResponse(requestMsg: "abc", id: ID, reason: "user")["reason"] as? String, "user")
    }
}
