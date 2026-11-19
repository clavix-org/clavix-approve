// Pairing, protocol version 2 (PROTOCOL.md, "Pairing"), against the
// vectors the agent, the page and the Python check share:
// testdata/pairing.json.

import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

final class PairingTests: XCTestCase {
    private let ch = String(repeating: "0f", count: 16)
    private let secret = Data(repeating: 7, count: 16)
    private var code: String { "cva2-" + (Data(hex: ch)! + secret).b64u }

    func testCodeAloneOrInTheAppLink() throws {
        let bare = try PairingCode(" \(code)\n")
        XCTAssertEqual(bare.ch, ch)
        XCTAssertEqual(bare.secret, secret)
        XCTAssertNil(bare.relay)

        let linked = try PairingCode("clavix-approve://pair?relay=https://relay.example#\(code)")
        XCTAssertEqual(linked.ch, ch)
        XCTAssertEqual(linked.relay?.absoluteString, "https://relay.example")
        XCTAssertEqual(try PairingCode("clavix-approve://pair?relay=https%3A%2F%2Frelay.example%2Fsub%2F#\(code)")
                        .relay?.absoluteString, "https://relay.example/sub")
        XCTAssertEqual(try PairingCode("clavix-approve://pair?relay=http://127.0.0.1:8765#\(code)").relay?.port, 8765)

        // The first version's code, said so.
        XCTAssertThrowsError(try PairingCode("cva1-" + code.dropFirst(5))) { error in
            XCTAssertTrue("\(error)".contains("older"))
        }
        XCTAssertThrowsError(try PairingCode(String(code.dropLast(2))))
        // No more links to a page on the relay's origin.
        XCTAssertThrowsError(try PairingCode("https://relay.example/#\(code)"))
        // A relay in clear over the network, or of another scheme: refused.
        XCTAssertThrowsError(try PairingCode("clavix-approve://pair?relay=http://relay.example#\(code)"))
        XCTAssertThrowsError(try PairingCode("clavix-approve://pair?relay=ftp://relay.example#\(code)"))
        XCTAssertThrowsError(try PairingCode("clavix-approve://other?relay=https://relay.example#\(code)"))
        XCTAssertThrowsError(try PairingCode("clavix-approve://pair#\(code)"))
    }

    func testRelayAddresses() throws {
        XCTAssertEqual(try RelayAddress.parse("approve.clavix.org").absoluteString, "https://approve.clavix.org")
        XCTAssertEqual(try RelayAddress.parse(" https://relay.example/ ").absoluteString, "https://relay.example")
        XCTAssertNoThrow(try RelayAddress.parse("http://localhost:8765"))
        XCTAssertNoThrow(try RelayAddress.parse("http://[::1]:8765"))
        XCTAssertThrowsError(try RelayAddress.parse("http://relay.example"))
        XCTAssertThrowsError(try RelayAddress.parse("http://127.0.0.1.relay.example"))
        XCTAssertThrowsError(try RelayAddress.parse("ftp://relay.example"))
        XCTAssertThrowsError(try RelayAddress.parse("https://user@relay.example"))

        XCTAssertTrue(RelayAddress.isOfficial(try RelayAddress.parse("approve.clavix.org")))
        XCTAssertFalse(RelayAddress.isOfficial(try RelayAddress.parse("approve.clavix.org.example")))
        XCTAssertFalse(RelayAddress.isOfficial(try RelayAddress.parse("https://approve.clavix.org:8443")))
        XCTAssertFalse(RelayAddress.isOfficial(try RelayAddress.parse("https://relay.example")))
    }

    func testVectors() throws {
        let v = try JSONSerialization.jsonObject(with: vector("pairing.json")) as! [String: Any]
        XCTAssertEqual(v["version"] as? Int, Pairing.version)
        let code = try PairingCode(v["code"] as! String)
        XCTAssertEqual(code.ch, v["channel"] as? String)
        XCTAssertEqual(code.secret.hex, v["secret"] as? String)
        XCTAssertEqual(Pairing.derive(code.secret, "pair-mac").hex, v["mac_key"] as? String)

        let a = v["agent"] as! [String: String], s = v["signer_keys"] as! [String: String]
        let agentKem = Data(hex: a["kem"]!)!, agentSig = Data(hex: a["sig"]!)!
        let ch = code.ch, signer = v["signer"] as! String, label = v["label"] as! String
        let agentNonce = Data(hex: v["agent_nonce"] as! String)!, signerNonce = Data(hex: v["signer_nonce"] as! String)!
        let commit = Pairing.commitment(agentNonce)
        XCTAssertEqual(commit.b64u, v["commit"] as? String)
        XCTAssertNoThrow(try Pairing.checkReveal(agentNonce, commit: commit))
        XCTAssertThrowsError(try Pairing.checkReveal(signerNonce, commit: commit))

        let me = Identity(kem: try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: s["kem_private"]!)!),
                          sig: try Curve25519.Signing.PrivateKey(rawRepresentation: Data(hex: s["sig_seed"]!)!))
        XCTAssertEqual(me.kemPublic, Data(hex: s["kem"]!)!)
        XCTAssertEqual(me.sigPublic, Data(hex: s["sig"]!)!)

        for c in v["modes"] as! [[String: Any]] {
            let mode = PairingMode(rawValue: c["mode"] as! String)!
            let other: PairingMode = mode == .sign ? .approve : .sign
            let helloMac = c["hello_mac"] as! String
            func hello(_ fields: [String: Any]) throws -> String {
                try JSONSerialization.data(withJSONObject: fields.merging([
                    "v": 2, "mode": mode.rawValue, "label": label, "kem": agentKem.b64u, "sig": agentSig.b64u,
                    "commit": commit.b64u, "mac": helloMac,
                ]) { a, _ in a }).b64u
            }
            let read = try Pairing.readHello(hello([:]), ch: ch, secret: code.secret)
            XCTAssertEqual(read.mode, mode)
            XCTAssertEqual(read.label, label)
            XCTAssertEqual(read.commit, commit)
            // The relay flips the mode or swaps the commitment: refused.
            XCTAssertThrowsError(try Pairing.readHello(hello(["mode": other.rawValue]), ch: ch, secret: code.secret))
            XCTAssertThrowsError(try Pairing.readHello(hello(["commit": Data(count: 32).b64u]), ch: ch, secret: code.secret))
            // The first protocol version, said so.
            XCTAssertThrowsError(try Pairing.readHello(hello(["v": 1]), ch: ch, secret: code.secret)) { error in
                XCTAssertTrue("\(error)".contains("older pairing protocol"))
            }

            for answer in c["answers"] as! [[String: String]] {
                let blob = try Data(b64u: answer["key"]!)
                XCTAssertEqual(SSH.keyType(blob), answer["type"])
                let mac = Pairing.answerMac(secret: code.secret, mode: mode, ch: ch, signer: signer, me: me,
                                            keyBlob: blob, nonce: signerNonce, agent: read.agent, commit: commit)
                XCTAssertEqual(mac.b64u, answer["answer_mac"], answer["type"]!)
                XCTAssertEqual(Pairing.digits(mode: mode, ch: ch, signer: signer, agent: read.agent, me: me, keyBlob: blob,
                                              agentNonce: agentNonce, signerNonce: signerNonce),
                               answer["digits"], answer["type"]!)
                // A flipped mode, or another agent nonce, gives other digits.
                XCTAssertNotEqual(Pairing.digits(mode: other, ch: ch, signer: signer, agent: read.agent, me: me,
                                                 keyBlob: blob, agentNonce: agentNonce, signerNonce: signerNonce),
                                  answer["digits"])
                XCTAssertNotEqual(Pairing.digits(mode: mode, ch: ch, signer: signer, agent: read.agent, me: me,
                                                 keyBlob: blob, agentNonce: signerNonce, signerNonce: signerNonce),
                                  answer["digits"])
            }
        }
    }

    /// The answer, opened as the agent opens it.
    func testAnswerIsSealedToTheAgentAndCarriesTheNonce() throws {
        let agent = softwareIdentity(), phone = softwareIdentity()
        let commit = Pairing.commitment(Data(repeating: 1, count: 32))
        let hello = PairingHello(label: "build-box", agent: peer(of: agent), mode: .sign, commit: commit)
        let keyBlob = ClientKey().blob
        let nonce = Data(repeating: 2, count: 32)
        let answer = try Pairing.buildAnswer(ch: ch, signer: "s1", secret: secret, me: phone, hello: hello,
                                             keyBlob: keyBlob, nonce: nonce, comment: "iphone")
        let raw = try Data(b64u: answer)
        let sig = raw.prefix(32)
        let inner = try Channel.openBytes(agent, fromSig: sig, header: Header.pair(ch: ch, signer: "s1"), raw.dropFirst(32))
        XCTAssertEqual(inner["t"] as? String, "pair")
        XCTAssertEqual(inner["v"] as? Int, 2)
        XCTAssertEqual(inner["key"] as? String, keyBlob.b64u)
        XCTAssertEqual(inner["nonce"] as? String, nonce.b64u)
        XCTAssertEqual(inner["comment"] as? String, "iphone")
        XCTAssertEqual(inner["mac"] as? String,
                       Pairing.answerMac(secret: secret, mode: .sign, ch: ch, signer: "s1", me: phone, keyBlob: keyBlob,
                                         nonce: nonce, agent: hello.agent, commit: commit).b64u)
    }

    /// A pairing the user has not confirmed reads no request.
    func testAnUnconfirmedPairingIsNotActive() throws {
        let agent = softwareIdentity(), phone = softwareIdentity()
        var record = PairingRecord(relay: URL(string: "https://relay.invalid")!, ch: ch, signer: "0011223344556677",
                                   token: "t", agent: peer(of: agent), label: "box", fingerprint: "123 456", mode: .sign)
        XCTAssertFalse(record.confirmed)
        XCTAssertFalse(record.isActive)
        let ctx = SignerContext(record: record, me: phone, keyBlob: ClientKey().blob)
        let entry = RequestEntry(id: String(repeating: "ab", count: 16), exp: 2_000_000_000, msg: "x")
        if case .success = Signer.read(ctx, entry, now: 1_800_000_000) { XCTFail("an unconfirmed pairing read a request") }
        record.confirmed = true
        XCTAssertTrue(record.isActive)
        let saved = try JSONDecoder().decode(PairingRecord.self, from: JSONEncoder().encode(record))
        XCTAssertTrue(saved.isActive)
        XCTAssertEqual(saved.version, 2)
    }
}
