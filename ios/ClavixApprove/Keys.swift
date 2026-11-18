// Where the app's keys live.
//
// - The SSH key is a P-256 key in the Secure Enclave. Each signature needs
//   the device's biometric lock, as enrolled when the key was made: a new
//   enrolment makes the key unusable (pair again and install the new key).
//   It never leaves the chip; the keychain only holds the chip's own
//   encrypted handle, useless on any other device.
// - The approval key (approve mode, for Clavix desktop) is another P-256
//   key in the Secure Enclave, under the same biometric control: a key per
//   purpose, so that an approval can never pass for an SSH login.
// - The channel's HPKE key is in the Secure Enclave too, usable without a
//   prompt once the device has been unlocked after a restart: a request
//   must be decrypted before it can be shown.
// - The channel's Ed25519 key cannot live in the Secure Enclave; it is a
//   keychain item of this device only.
//
// On the simulator there is no Secure Enclave: software keys stand in, and
// the app says so.

import ClavixCore
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum Keychain {
    private static let service = "org.clavix.approve"

    static func read(_ account: String) -> Data? {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                      kSecAttrAccount: account, kSecReturnData: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    static func write(_ account: String, _ data: Data) throws {
        delete(account)
        let item: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                     kSecAttrAccount: account, kSecValueData: data,
                                     kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeyError.keychain(status) }
    }

    static func delete(_ account: String) {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                      kSecAttrAccount: account]
        SecItemDelete(query as CFDictionary)
    }
}

enum KeyError: LocalizedError {
    case keychain(OSStatus)
    case noKey
    case cancelled

    var errorDescription: String? {
        switch self {
        case .keychain(let s): return "trousseau indisponible (\(s))"
        case .noKey: return "aucune clé de signature sur cet appareil"
        case .cancelled: return "verrou non validé"
        }
    }
}

enum Keys {
    static var simulated: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    // ---- the SSH key ----

    /// The public key blob, nil before the key exists.
    static var sshKeyBlob: Data? { Keychain.read("ssh-public") }

    /// Make the SSH key; replaces any previous one.
    static func createSSHKey() throws -> Data { try createLockedKey("ssh") }

    /// Sign `data` with the SSH key after the device's lock; `reason` is
    /// shown with the prompt. Blocks while the prompt is up: call it off
    /// the main thread.
    static func sign(_ data: Data, reason: String) throws -> Data { try signLocked("ssh", data, reason: reason) }

    // ---- the approval key ----

    static var approveKeyBlob: Data? { Keychain.read("approve-public") }

    static func createApproveKey() throws -> Data { try createLockedKey("approve") }

    /// The proof of approve mode: the approval key's SSH signature of `data`.
    static func approve(_ data: Data, reason: String) throws -> Data { try signLocked("approve", data, reason: reason) }

    // ---- keys behind the biometric lock ----

    /// A P-256 key behind the biometric lock as enrolled now; its handle is
    /// kept as "<name>-key", its public blob as "<name>-public".
    private static func createLockedKey(_ name: String) throws -> Data {
        let point: Data
        let handle: Data
        if simulated {
            let k = P256.Signing.PrivateKey()
            (point, handle) = (k.publicKey.x963Representation, k.rawRepresentation)
        } else {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error)
            else { throw error!.takeRetainedValue() as Error }
            let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            (point, handle) = (k.publicKey.x963Representation, k.dataRepresentation)
        }
        let blob = try SSH.p256KeyBlob(point: point)
        try Keychain.write("\(name)-key", handle)
        try Keychain.write("\(name)-public", blob)
        return blob
    }

    private static func signLocked(_ name: String, _ data: Data, reason: String) throws -> Data {
        guard let handle = Keychain.read("\(name)-key") else { throw KeyError.noKey }
        let raw: Data
        if simulated {
            raw = try P256.Signing.PrivateKey(rawRepresentation: handle).signature(for: data).rawRepresentation
        } else {
            let context = LAContext()
            context.localizedReason = reason
            context.localizedCancelTitle = "Annuler"
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle, authenticationContext: context)
            do {
                raw = try key.signature(for: data).rawRepresentation
            } catch {
                // Cancelled or failed: the chip reports it through LocalAuthentication or Security.
                let e = error as NSError
                if e.domain == LAErrorDomain || e.code == Int(errSecUserCanceled) || e.code == Int(errSecAuthFailed) {
                    throw KeyError.cancelled
                }
                throw error
            }
        }
        return try SSH.p256SignatureBlob(raw: raw)
    }

    // ---- the channel identity ----

    /// Our channel keys, made on first use and kept across pairings.
    static func identity() throws -> Identity {
        if let kem = Keychain.read("channel-kem"), let sig = Keychain.read("channel-sig") {
            let kemKey: ChannelKEMKey = simulated
                ? try P256.KeyAgreement.PrivateKey(rawRepresentation: kem)
                : try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: kem)
            return Identity(kem: kemKey, sig: try Curve25519.Signing.PrivateKey(rawRepresentation: sig))
        }
        let kemKey: ChannelKEMKey
        let kemHandle: Data
        if simulated {
            let k = P256.KeyAgreement.PrivateKey()
            (kemKey, kemHandle) = (k, k.rawRepresentation)
        } else {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &error)
            else { throw error!.takeRetainedValue() as Error }
            let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            (kemKey, kemHandle) = (k, k.dataRepresentation)
        }
        let sig = Curve25519.Signing.PrivateKey()
        try Keychain.write("channel-kem", kemHandle)
        try Keychain.write("channel-sig", sig.rawRepresentation)
        return Identity(kem: kemKey, sig: sig)
    }

    // ---- the pairings ----

    /// Every machine this device is paired with. A record kept by a version
    /// that had a single pairing is taken over.
    static var pairings: [PairingRecord] {
        if let data = Keychain.read("pairings") {
            return (try? JSONDecoder().decode([PairingRecord].self, from: data)) ?? []
        }
        return Keychain.read("pairing").flatMap { try? JSONDecoder().decode(PairingRecord.self, from: $0) }.map { [$0] } ?? []
    }

    static func save(pairings: [PairingRecord]) throws {
        try Keychain.write("pairings", try JSONEncoder().encode(pairings))
        Keychain.delete("pairing")
    }
}
