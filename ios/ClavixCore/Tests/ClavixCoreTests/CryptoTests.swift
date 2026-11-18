import CryptoKit
import Foundation
import XCTest
@testable import ClavixCore

final class CryptoTests: XCTestCase {
    func testHPKEMatchesRFC9180Vector() throws {
        let v = try JSONSerialization.jsonObject(with: vector("hpke-rfc9180-a3.json")) as! [String: String]
        func h(_ k: String) -> Data { Data(hex: v[k]!)! }
        let eph = try P256.KeyAgreement.PrivateKey(rawRepresentation: h("skEm"))
        let (enc, ct) = try HPKE.seal(to: h("pkRm"), info: h("info"), aad: h("aad"), plaintext: h("pt"), ephemeral: eph)
        XCTAssertEqual(enc.hex, v["enc"])
        XCTAssertEqual(ct.hex, v["ct"])

        let recipient = try P256.KeyAgreement.PrivateKey(rawRepresentation: h("skRm"))
        XCTAssertEqual(try HPKE.open(with: recipient, info: h("info"), aad: h("aad"), enc: enc, ct: ct), h("pt"))
        XCTAssertThrowsError(try HPKE.open(with: recipient, info: h("info"), aad: Data("other".utf8), enc: enc, ct: ct))
    }

    /// Apple's own HPKE, same suite, as a second, independent implementation.
    func testHPKEInteroperatesWithCryptoKit() throws {
        let suite = CryptoKit.HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
        let recipient = P256.KeyAgreement.PrivateKey()
        let info = Data("clavix".utf8), aad = Data("header".utf8), pt = Data("{\"t\":\"sign\"}".utf8)

        var sender = try CryptoKit.HPKE.Sender(recipientKey: recipient.publicKey, ciphersuite: suite, info: info)
        let ct = try sender.seal(pt, authenticating: aad)
        XCTAssertEqual(try HPKE.open(with: recipient, info: info, aad: aad, enc: sender.encapsulatedKey, ct: ct), pt)

        let (enc, ours) = try HPKE.seal(to: recipient.publicKey.x963Representation, info: info, aad: aad, plaintext: pt)
        var receiver = try CryptoKit.HPKE.Recipient(privateKey: recipient, ciphersuite: suite, info: info, encapsulatedKey: enc)
        XCTAssertEqual(try receiver.open(ours, authenticating: aad), pt)
    }

    func testPairTokenAndTokenAuthMatchThePage() throws {
        let expected = String(decoding: try vector("pair-token-07.txt"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(Pairing.pairToken(Data(repeating: 7, count: 16)), expected)
        XCTAssertEqual(tokenAuth("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    func testBase64url() throws {
        XCTAssertEqual(Data([0xfb, 0xff]).b64u, "-_8")
        XCTAssertEqual(try Data(b64u: "-_8"), Data([0xfb, 0xff]))
        XCTAssertThrowsError(try Data(b64u: "+/8="))
        XCTAssertThrowsError(try Data(b64u: "abcde"))
        XCTAssertEqual(try Data(b64u: ""), Data())
    }

    func testChannelRoundTripAndBinding() throws {
        let agent = softwareIdentity(), phone = softwareIdentity()
        let hdr = Header.request(ch: "c", signer: "s", id: "i", exp: 100)
        let msg = try Channel.seal(agent, to: peer(of: phone), header: hdr, ["t": "sign", "n": 1])
        let opened = try Channel.open(phone, from: peer(of: agent), header: hdr, msg)
        XCTAssertEqual(opened["t"] as? String, "sign")

        // Another expiry, another sender, another recipient: refused.
        XCTAssertThrowsError(try Channel.open(phone, from: peer(of: agent),
                                              header: Header.request(ch: "c", signer: "s", id: "i", exp: 101), msg))
        XCTAssertThrowsError(try Channel.open(phone, from: peer(of: softwareIdentity()), header: hdr, msg))
        XCTAssertThrowsError(try Channel.open(softwareIdentity(), from: peer(of: agent), header: hdr, msg))
        // One flipped bit anywhere.
        var raw = try Data(b64u: msg)
        raw[raw.count - 1] ^= 1
        XCTAssertThrowsError(try Channel.open(phone, from: peer(of: agent), header: hdr, raw.b64u))
    }

    func testSecureEnclaveStyleKEMIsPluggable() throws {
        // Any ChannelKEMKey works; the app passes a Secure Enclave key.
        struct Wrapped: ChannelKEMKey {
            let inner = P256.KeyAgreement.PrivateKey()
            var publicKeyRaw: Data { inner.publicKeyRaw }
            func diffieHellman(with peer: P256.KeyAgreement.PublicKey) throws -> Data { try inner.diffieHellman(with: peer) }
        }
        let phone = Identity(kem: Wrapped(), sig: .init())
        let agent = softwareIdentity()
        let hdr = Header.response(ch: "c", signer: "s", id: "i")
        let msg = try Channel.seal(agent, to: peer(of: phone), header: hdr, ["ok": true])
        XCTAssertEqual(try Channel.open(phone, from: peer(of: agent), header: hdr, msg)["ok"] as? Bool, true)
    }
}
