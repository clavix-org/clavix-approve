// Approve mode (PROTOCOL.md, "Approve mode"), against the vectors the page
// and the Python check share: testdata/approve-proof.json (the pairing vectors are in
// PairingTests).

import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

final class ApproveTests: XCTestCase {
    private func json(_ name: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: vector(name)) as! [String: Any]
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

    /// Records of the first pairing protocol still decode, in sign mode,
    /// but are obsolete: never active, whatever they say.
    func testOldRecordsAreInSignModeAndObsolete() throws {
        let old = """
        {"relay":"https://relay.example","ch":"\(String(repeating: "0", count: 32))","signer":"0011223344556677",
         "token":"t","agent":\(String(data: try JSONEncoder().encode(peer(of: softwareIdentity())), encoding: .utf8)!),
         "label":"box","fingerprint":"123 456","confirmed":true}
        """
        let record = try JSONDecoder().decode(PairingRecord.self, from: Data(old.utf8))
        XCTAssertEqual(record.mode, .sign)
        XCTAssertEqual(record.version, 1)
        XCTAssertFalse(record.isCurrent)
        XCTAssertFalse(record.isActive)
    }

    private func refusal(_ r: Result<VerifiedRequest, Refusal>) -> Refusal? {
        if case .failure(let e) = r { return e }
        return nil
    }
}
