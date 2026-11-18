// Approve mode (PROTOCOL.md, "Approve mode"), against the vectors the page
// and the Python check share: testdata/approve-pairing.json and
// testdata/approve-proof.json.

import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

final class ApproveTests: XCTestCase {
    private func json(_ name: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: vector(name)) as! [String: Any]
    }

    func testPairingVectors() throws {
        let v = try json("approve-pairing.json")
        let code = try PairingCode(v["code"] as! String)
        XCTAssertEqual(code.ch, v["channel"] as? String)
        XCTAssertEqual(code.secret.hex, v["secret"] as? String)
        XCTAssertEqual(Pairing.derive(code.secret, "pair-mac").hex, v["mac_key"] as? String)

        let a = v["agent"] as! [String: String], s = v["signer_keys"] as! [String: String]
        let agentKem = Data(hex: a["kem"]!)!, agentSig = Data(hex: a["sig"]!)!
        let kem = Data(hex: s["kem"]!)!, sig = Data(hex: s["sig"]!)!
        let ch = code.ch, signer = v["signer"] as! String, label = v["label"] as! String

        // The hello, as the agent sends it, read by readHello().
        let helloTranscript = Pairing.transcript(PairingMode.approve.helloLabel,
                                                 [utf8(ch), agentKem, agentSig, utf8(label)])
        XCTAssertEqual(helloTranscript.hex, v["hello_transcript"] as? String)
        let helloMac = v["hello_mac"] as! String
        func hello(_ fields: [String: Any]) throws -> String {
            try JSONSerialization.data(withJSONObject: fields.merging([
                "label": label, "kem": agentKem.b64u, "sig": agentSig.b64u, "mac": helloMac,
            ]) { a, _ in a }).b64u
        }
        let read = try Pairing.readHello(hello(["mode": "approve"]), ch: ch, secret: code.secret)
        XCTAssertEqual(read.mode, .approve)
        XCTAssertEqual(read.label, label)
        // The relay strips the mode, or names another: refused.
        XCTAssertThrowsError(try Pairing.readHello(hello([:]), ch: ch, secret: code.secret))
        XCTAssertThrowsError(try Pairing.readHello(hello(["mode": "sign"]), ch: ch, secret: code.secret))

        // The answer's MAC and the six digits, for each approval key type.
        let me = Identity(kem: try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(hex: s["kem_private"]!)!),
                          sig: try Curve25519.Signing.PrivateKey(rawRepresentation: Data(hex: s["sig_seed"]!)!))
        XCTAssertEqual(me.kemPublic, kem)
        XCTAssertEqual(me.sigPublic, sig)
        for answer in v["answers"] as! [[String: String]] {
            let blob = try Data(b64u: answer["approve"]!)
            XCTAssertEqual(SSH.keyType(blob), answer["type"])
            let mac = Pairing.answerMac(secret: code.secret, mode: .approve, ch: ch, signer: signer, me: me,
                                        keyBlob: blob, agent: read.agent)
            XCTAssertEqual(mac.b64u, answer["answer_mac"], answer["type"]!)
            XCTAssertEqual(Pairing.fingerprint(agent: read.agent, me: me, keyBlob: blob, mode: .approve),
                           answer["digits"], answer["type"]!)
            // The sign-mode labels give other digits: a flipped mode shows.
            XCTAssertNotEqual(Pairing.fingerprint(agent: read.agent, me: me, keyBlob: blob, mode: .sign), answer["digits"])
        }
    }

    func testProofVectors() throws {
        let v = try json("approve-proof.json")
        let bytes = approvalBytes(ch: v["channel"] as! String, signer: v["signer"] as! String,
                                  id: v["id"] as! String, requestMsg: v["msg"] as! String)
        XCTAssertEqual(bytes.hex, v["signed"] as? String)
        XCTAssertEqual(utf8(v["msg"] as! String).sha256.b64u, v["req"] as? String)
        for k in v["keys"] as! [[String: String]] {
            let key = try Data(b64u: k["approve"]!), proof = try Data(b64u: k["proof"]!)
            XCTAssertTrue(verifyApproval(approveBlob: key, bytes: bytes, proofBlob: proof), k["type"]!)
            XCTAssertFalse(verifyApproval(approveBlob: key, bytes: bytes + Data([0]), proofBlob: proof), k["type"]!)
        }
    }

    /// A proof made as the app makes it (P-256, raw signature turned into
    /// an SSH blob) passes the requester's check.
    func testP256ProofAsTheAppMakesIt() throws {
        let key = P256.Signing.PrivateKey()
        let blob = try SSH.p256KeyBlob(point: key.publicKey.x963Representation)
        let bytes = approvalBytes(ch: String(repeating: "ab", count: 16), signer: "0011223344556677",
                                  id: String(repeating: "cd", count: 16), requestMsg: "msg")
        let proof = try SSH.p256SignatureBlob(raw: key.signature(for: bytes).rawRepresentation)
        XCTAssertTrue(verifyApproval(approveBlob: blob, bytes: bytes, proofBlob: proof))
    }

    /// The requester's own key, of any type it holds; a sign request is
    /// refused in approve mode and the other way round.
    func testApproveRequestChecks() throws {
        let host = try hostKey()
        let sid = Data.random(32)
        let requester = Curve25519.Signing.PrivateKey()
        let keyBlob = sshString("ssh-ed25519") + sshString(requester.publicKey.rawRepresentation)
        let data = userAuth(sessionId: sid, keyBlob: keyBlob, hostKey: host.blob, algorithm: "ssh-ed25519")
        var inner: [String: Any] = [
            "t": "approve", "id": "r1", "iat": 1000, "exp": 1090,
            "key": keyBlob.b64u, "keyName": "vault key\u{202E}", "data": data.b64u,
            "binds": [try sessionBind(host, sid)],
        ]
        guard case .success(let view) = checkApproveRequest(inner, id: "r1", now: 1010) else {
            return XCTFail("refused")
        }
        XCTAssertEqual(view.requesterKey?.type, "ssh-ed25519")
        XCTAssertEqual(view.requesterKey?.fingerprint, SSH.fingerprint(keyBlob))
        XCTAssertEqual(view.requesterKey?.name, "vault key")
        XCTAssertEqual(view.destination.hostKey, host.blob)

        // The login made with another key than the one named.
        let other = ClientKey().blob
        inner["data"] = userAuth(sessionId: sid, keyBlob: other, hostKey: host.blob).b64u
        XCTAssertEqual(refusal(checkApproveRequest(inner, id: "r1", now: 1010)), .unverified)
        // An algorithm that does not go with the key.
        inner["data"] = userAuth(sessionId: sid, keyBlob: keyBlob, hostKey: host.blob, algorithm: "rsa-sha2-256").b64u
        XCTAssertEqual(refusal(checkApproveRequest(inner, id: "r1", now: 1010)), .unverified)
        // Modes kept apart.
        inner["data"] = data.b64u
        XCTAssertEqual(refusal(checkSignRequest(inner, id: "r1", keyBlob: keyBlob, now: 1010)), .malformed)
        inner["t"] = "sign"
        XCTAssertEqual(refusal(checkApproveRequest(inner, id: "r1", now: 1010)), .malformed)
    }

    func testOldRecordsAreInSignMode() throws {
        let old = """
        {"relay":"https://relay.example","ch":"\(String(repeating: "0", count: 32))","signer":"0011223344556677",
         "token":"t","agent":\(String(data: try JSONEncoder().encode(peer(of: softwareIdentity())), encoding: .utf8)!),
         "label":"box","fingerprint":"123 456"}
        """
        XCTAssertEqual(try JSONDecoder().decode(PairingRecord.self, from: Data(old.utf8)).mode, .sign)
    }

    private func refusal(_ r: Result<VerifiedRequest, Refusal>) -> Refusal? {
        if case .failure(let e) = r { return e }
        return nil
    }
}
