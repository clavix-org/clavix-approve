// Against the page's own modules: tools/ios-interop.mjs writes what the
// page produces ($CLAVIX_JS_VECTORS); this test reads it, and writes what
// the app produces ($CLAVIX_SWIFT_OUT) for the script to open in turn.
// Skipped when the variables are unset, unless CLAVIX_REQUIRE_INTEROP=1.

import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

final class InteropTests: XCTestCase {
    func testWithThePagesModules() throws {
        let env = ProcessInfo.processInfo.environment
        guard let path = env["CLAVIX_JS_VECTORS"] else {
            if env["CLAVIX_REQUIRE_INTEROP"] == "1" { XCTFail("CLAVIX_JS_VECTORS is not set") }
            throw XCTSkip("run tools/ios-interop.mjs make FILE and set CLAVIX_JS_VECTORS=FILE")
        }
        let v = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String: Any]
        func s(_ k: String) -> String { v[k] as! String }
        func identity(_ k: String) throws -> Identity {
            let e = v[k] as! [String: String]
            return Identity(kem: try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(b64u: e["kem"]!)),
                            sig: try Curve25519.Signing.PrivateKey(rawRepresentation: Data(b64u: e["sig"]!)))
        }
        let agent = try identity("agent"), phone = try identity("phone")
        XCTAssertEqual(phone.kemPublic.b64u, (v["phone"] as! [String: String])["kemPublic"])
        let sshKey = try P256.Signing.PrivateKey(rawRepresentation: Data(b64u: s("sshKey")))
        let keyBlob = try SSH.p256KeyBlob(point: sshKey.publicKey.x963Representation)
        XCTAssertEqual(keyBlob.b64u, s("keyBlob"))
        let ch = s("ch"), signer = s("signer"), id = s("id")
        let exp = v["exp"] as! Int, now = v["now"] as! Double

        // 1. A request sealed by the page's channel, checked here.
        let record = PairingRecord(relay: URL(string: "https://relay.invalid")!, ch: ch, signer: signer, token: "t",
                                   agent: peer(of: agent), label: "build-box", fingerprint: "", mode: .sign,
                                   confirmed: true)
        let ctx = SignerContext(record: record, me: phone, keyBlob: keyBlob)
        let entry = RequestEntry(id: id, exp: exp, msg: s("request"))
        let view = try Signer.read(ctx, entry, now: now).get()
        XCTAssertEqual(view.user, "deploy")
        XCTAssertEqual(view.destination.fingerprint, s("hostFingerprint"))
        XCTAssertEqual(view.hints[s("hostFingerprint")], "prod.example")
        XCTAssertEqual(view.agent, "build-box")
        XCTAssertEqual(try Signer.read(ctx, RequestEntry(id: id, exp: exp + 1, msg: s("request")), now: now),
                       .failure(.unauthentic))

        // 2. The page's pairing: hello read here, answer opened as the agent would, same six digits.
        let secret = try Data(b64u: s("secret"))
        let hello = try Pairing.readHello(s("hello"), ch: ch, secret: secret)
        XCTAssertEqual(hello.agent, peer(of: agent))
        XCTAssertEqual(hello.mode, .sign)
        let agentNonce = try Data(b64u: s("agentNonce")), signerNonce = try Data(b64u: s("signerNonce"))
        XCTAssertNoThrow(try Pairing.checkReveal(agentNonce, commit: hello.commit))
        let raw = try Data(b64u: s("answer"))
        let pair = try Channel.openBytes(agent, fromSig: raw.prefix(32), header: Header.pair(ch: ch, signer: signer),
                                         raw.dropFirst(32))
        XCTAssertEqual(pair["key"] as? String, keyBlob.b64u)
        XCTAssertEqual(pair["nonce"] as? String, signerNonce.b64u)
        XCTAssertEqual(pair["mac"] as? String,
                       Pairing.answerMac(secret: secret, mode: .sign, ch: ch, signer: signer, me: phone, keyBlob: keyBlob,
                                         nonce: signerNonce, agent: hello.agent, commit: hello.commit).b64u)
        XCTAssertEqual(Pairing.digits(mode: .sign, ch: ch, signer: signer, agent: hello.agent, me: phone, keyBlob: keyBlob,
                                      agentNonce: agentNonce, signerNonce: signerNonce), s("digits"))

        // 3. What the app produces, for the page to open.
        guard let out = env["CLAVIX_SWIFT_OUT"] else { return }
        let signature = try SSH.p256SignatureBlob(raw: try sshKey.signature(for: view.data).rawRepresentation)
        let response = try Channel.seal(phone, to: peer(of: agent), header: Header.response(ch: ch, signer: signer, id: id),
                                        signedResponse(requestMsg: entry.msg, id: id, signatureBlob: signature))
        let inner = try Channel.open(phone, from: peer(of: agent), header: Header.request(ch: ch, signer: signer, id: id, exp: exp),
                                     entry.msg)
        let swiftNonce = Data.random(Pairing.nonceLength)
        let answer = try Pairing.buildAnswer(ch: ch, signer: "swift-signer", secret: secret, me: phone, hello: hello,
                                             keyBlob: keyBlob, nonce: swiftNonce, comment: "app")
        let written: [String: Any] = [
            "phoneKem": phone.kemPublic.b64u, "phoneSig": phone.sigPublic.b64u, "keyBlob": keyBlob.b64u,
            "response": response,
            "requestInner": String(decoding: try JSONSerialization.data(withJSONObject: inner), as: UTF8.self),
            "answer": answer,
            "digits": Pairing.digits(mode: .sign, ch: ch, signer: "swift-signer", agent: hello.agent, me: phone,
                                     keyBlob: keyBlob, agentNonce: agentNonce, signerNonce: swiftNonce),
        ]
        try JSONSerialization.data(withJSONObject: written).write(to: URL(fileURLWithPath: out))
    }
}

extension VerifiedRequest: Equatable {
    public static func == (a: VerifiedRequest, b: VerifiedRequest) -> Bool { a.data == b.data && a.exp == b.exp }
}
