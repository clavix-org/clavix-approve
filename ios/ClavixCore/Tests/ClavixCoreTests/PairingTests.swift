import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

final class PairingTests: XCTestCase {
    private let ch = String(repeating: "0f", count: 16)
    private let secret = Data(repeating: 7, count: 16)
    private var code: String { "cva1-" + (Data(hex: ch)! + secret).b64u }

    func testCodeAloneOrInTheAgentsLink() throws {
        let bare = try PairingCode(" \(code)\n")
        XCTAssertEqual(bare.ch, ch)
        XCTAssertEqual(bare.secret, secret)
        XCTAssertNil(bare.relay)

        let linked = try PairingCode("https://relay.example/#\(code)")
        XCTAssertEqual(linked.ch, ch)
        XCTAssertEqual(linked.relay?.absoluteString, "https://relay.example")
        XCTAssertEqual(try PairingCode("https://relay.example/sub/#\(code)").relay?.absoluteString,
                       "https://relay.example/sub")

        XCTAssertThrowsError(try PairingCode("cva2-" + code.dropFirst(5)))
        XCTAssertThrowsError(try PairingCode(String(code.dropLast(2))))
        XCTAssertThrowsError(try PairingCode("ftp://relay.example/#\(code)"))
    }

    /// The whole exchange, with the agent's part written here as in
    /// agent/src/pairing.rs.
    func testExchangeAuthenticatesBothSides() throws {
        let agent = softwareIdentity(), phone = softwareIdentity()
        let macKey = SymmetricKey(data: Pairing.derive(secret, "pair-mac"))
        func mac(_ kind: String, _ fields: [Data]) -> Data {
            Data(HMAC<SHA256>.authenticationCode(for: fields.reduce(sshString(kind)) { $0 + sshString($1) }, using: macKey))
        }
        let label = "build-box"
        let helloJSON = try JSONSerialization.data(withJSONObject: [
            "label": label, "kem": agent.kemPublic.b64u, "sig": agent.sigPublic.b64u,
            "mac": mac("hello", [Data(ch.utf8), agent.kemPublic, agent.sigPublic, Data(label.utf8)]).b64u,
        ])

        let hello = try Pairing.readHello(helloJSON.b64u, ch: ch, secret: secret)
        XCTAssertEqual(hello.label, label)
        XCTAssertEqual(hello.agent, peer(of: agent))
        // Another secret, or keys swapped by the relay: refused.
        XCTAssertThrowsError(try Pairing.readHello(helloJSON.b64u, ch: ch, secret: Data(repeating: 8, count: 16)))
        XCTAssertThrowsError(try Pairing.readHello(helloJSON.b64u, ch: String(repeating: "aa", count: 16), secret: secret))

        let keyBlob = ClientKey().blob
        let answer = try Pairing.buildAnswer(ch: ch, signer: "s1", secret: secret, me: phone, agent: hello.agent,
                                             keyBlob: keyBlob, comment: "iphone")
        // Agent side: the signing key in front, then a sealed message.
        let raw = try Data(b64u: answer)
        let sig = raw.prefix(32)
        let inner = try Channel.openBytes(agent, fromSig: sig, header: Header.pair(ch: ch, signer: "s1"), raw.dropFirst(32))
        XCTAssertEqual(inner["t"] as? String, "pair")
        XCTAssertEqual(inner["key"] as? String, keyBlob.b64u)
        XCTAssertEqual(inner["comment"] as? String, "iphone")
        let kem = try Data(b64u: inner["kem"] as! String)
        XCTAssertEqual(inner["mac"] as? String,
                       mac("answer", [Data(ch.utf8), Data("s1".utf8), kem, sig, keyBlob, agent.kemPublic, agent.sigPublic]).b64u)

        let digits = Pairing.fingerprint(agent: hello.agent, me: phone, keyBlob: keyBlob)
        XCTAssertNotNil(digits.range(of: #"^\d{3} \d{3}$"#, options: .regularExpression))
        XCTAssertNotEqual(digits, Pairing.fingerprint(agent: hello.agent, me: phone, keyBlob: ClientKey().blob))
    }
}
