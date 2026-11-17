// The app's state and its conversation with the relay: the same behaviour
// as web/app.js. Long-poll while the app is in front, check every request
// with ClavixCore before showing it, refuse without asking what cannot be
// verified, and sign only after the device's lock.

import ClavixCore
import Foundation
import SwiftUI

struct PendingRequest: Identifiable {
    let entry: RequestEntry
    let view: VerifiedRequest
    var id: String { entry.id }
}

@MainActor
final class Model: ObservableObject {
    @Published private(set) var keyBlob: Data? = Keys.sshKeyBlob
    @Published private(set) var pairing: PairingRecord? = Keys.pairing
    @Published private(set) var remembered = Store.load()
    @Published private(set) var requests: [PendingRequest] = []
    @Published private(set) var busy: Set<String> = []
    @Published var status = ""
    @Published var statusIsError = false
    /// Set by a pairing just made, until the user has compared the digits.
    @Published var justPaired: PairingRecord?
    @Published private(set) var now = Date()

    private var seen: Set<String> = [] // every request id already handled or shown
    private var polling: Task<Void, Never>?
    private var ticker: Task<Void, Never>?
    var pushToken: Data? { didSet { Task { await registerPush() } } }

    static let comment = "clavix-approve-iphone"

    var publicKeyLine: String? { keyBlob.map { SSH.publicKeyLine(keyBlob: $0, comment: Self.comment) } }

    func name(of fingerprint: String) -> String? { remembered.pins[fingerprint] }

    // ---- journal and memory ----

    func journal(_ text: String) {
        remembered.journal.insert(JournalEntry(at: Date(), text: text), at: 0)
        remembered.journal = Array(remembered.journal.prefix(Store.journalSize))
        Store.save(remembered)
    }

    func forget(pin fingerprint: String) {
        guard let name = remembered.pins.removeValue(forKey: fingerprint) else { return }
        Store.save(remembered)
        journal("Hôte oublié : \(name)")
    }

    private func say(_ text: String, error: Bool = false) {
        status = text
        statusIsError = error
    }

    // ---- pairing ----

    /// Pair with the agent that shows `input` (code or link). `relayText`
    /// is used when the input is a bare code.
    func pair(input: String, relayText: String) async throws {
        let code = try PairingCode(input)
        var relay = code.relay
        if relay == nil {
            let text = relayText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let url = URL(string: text.contains("://") ? text : "https://" + text), url.host != nil else {
                throw AppError("indiquez l’adresse du relais, ou collez le lien complet")
            }
            relay = url
        }
        let identity = try Keys.identity()
        let blob = try keyBlob ?? Keys.createSSHKey()
        keyBlob = blob
        let previous = pairing
        let record = try await Signer.pair(relay: relay!, code: code, me: identity, keyBlob: blob, comment: Self.comment)
        try Keys.save(pairing: record)
        pairing = record
        justPaired = record
        remembered.lastRelay = relay
        Store.save(remembered)
        journal("Appairé avec \(record.label.isEmpty ? "une machine sans nom" : record.label)")
        // The pairing this one replaces: revoked, best effort.
        if let previous, previous.ch != record.ch || previous.signer != record.signer {
            let old = RelayClient(base: previous.relay, ch: previous.ch, token: previous.token)
            _ = try? await old.revoke()
        }
        requests = []
        seen = []
        await registerPush()
        start()
    }

    /// Revoke this device on the relay, then forget the pairing. The SSH
    /// key and the named hosts stay.
    func forgetMachine() async {
        guard let p = pairing else { return }
        stop()
        do {
            let deleted = try await RelayClient(base: p.relay, ch: p.ch, token: p.token).revoke()
            journal(deleted ? "Machine oubliée, appareil retiré du relais" : "Machine oubliée (le relais ne la connaissait plus)")
        } catch {
            journal("Machine oubliée sans joindre le relais : \(describe(error))")
        }
        try? Keys.save(pairing: nil)
        pairing = nil
        requests = []
        say("")
    }

    // ---- push ----

    private func registerPush() async {
        guard let token = pushToken, let p = pairing else { return }
        #if DEBUG
        let sandbox = true
        #else
        let sandbox = false
        #endif
        do {
            _ = try await RelayClient(base: p.relay, ch: p.ch, token: p.token).subscribeAPNs(deviceToken: token, sandbox: sandbox)
        } catch let e as RelayError where e.status == 400 {
            journal("Ce relais ne sait pas encore réveiller l’appli : ouvrez-la pour voir les demandes")
        } catch {
            journal("Notifications non enregistrées : \(describe(error))")
        }
    }

    // ---- watching the relay ----

    /// The app comes to the front, or a notification was tapped.
    func start() {
        if ticker == nil {
            ticker = Task { [weak self] in
                while !Task.isCancelled {
                    self?.tick()
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                }
            }
        }
        // A call left from before the app went to the background may be
        // dead: drop it and ask again.
        polling?.cancel()
        guard let p = pairing, let blob = keyBlob, let identity = try? Keys.identity() else { return }
        let ctx = SignerContext(record: p, me: identity, keyBlob: blob)
        polling = Task { [weak self] in await self?.watch(ctx) }
    }

    func stop() {
        polling?.cancel()
        polling = nil
        ticker?.cancel()
        ticker = nil
    }

    private func watch(_ ctx: SignerContext) async {
        var wait = 0      // the first call returns at once
        var backoff = 0   // seconds, grows on consecutive failures
        while !Task.isCancelled {
            do {
                let entries = try await ctx.relay.requests(wait: wait, known: requests.map(\.id))
                if Task.isCancelled { return }
                await show(entries, ctx)
                say(requests.isEmpty ? "Prêt. En attente de demandes." : "")
                wait = 20
                backoff = 0
            } catch let e as RelayError where e.isFatal {
                if Task.isCancelled { return }
                say(e.status == 401
                    ? "Cette machine a été retirée : le relais ne connaît plus cet appairage. Oubliez-la dans Réglages, ou appairez à nouveau."
                    : "Arrêt : \(describe(e)). Si cela persiste, appairez à nouveau.", error: true)
                return
            } catch {
                if Task.isCancelled { return }
                if (error as? RelayError)?.timedOut == true {
                    // A dead connection rather than a refusal: ask again at once.
                    wait = 0
                    continue
                }
                backoff = min(backoff > 0 ? backoff * 2 : 5, 60)
                say((error as? RelayError)?.status == 429
                    ? "Trop de requêtes, reprise dans \(backoff) s."
                    : "Relais injoignable, nouvel essai dans \(backoff) s.", error: true)
                try? await Task.sleep(nanoseconds: UInt64(backoff) * 1_000_000_000)
            }
        }
    }

    private func show(_ entries: [RequestEntry], _ ctx: SignerContext) async {
        let live = Set(entries.map(\.id))
        requests.removeAll { !live.contains($0.id) && !busy.contains($0.id) }
        let t = Date().timeIntervalSince1970
        for entry in entries where !seen.contains(entry.id) {
            seen.insert(entry.id)
            switch Signer.read(ctx, entry, now: t) {
            case .success(let view):
                requests.append(PendingRequest(entry: entry, view: view))
            case .failure(let reason):
                // Nothing trustworthy to show: refuse without asking.
                let sent = (try? await Signer.deny(ctx, entry, reason: reason.rawValue)) ?? "non envoyé"
                journal("Demande écartée (\(reason.rawValue), \(sent))")
            }
        }
    }

    private func tick() {
        now = Date()
        let t = now.timeIntervalSince1970
        let expired = requests.filter { Double($0.entry.exp) <= t && !busy.contains($0.id) }
        for r in expired {
            requests.removeAll { $0.id == r.id }
            journal("Demande expirée sans réponse")
        }
    }

    // ---- answering ----

    func deny(_ r: PendingRequest) async throws {
        guard let ctx = context() else { return }
        try await settle(r) {
            _ = try await Signer.deny(ctx, r.entry, reason: "user")
            self.journal("Refusé : \(r.view.user ?? "?")@\(self.name(of: r.view.destination.fingerprint) ?? r.view.destination.fingerprint)")
        }
    }

    /// `newName` is required when the destination is not pinned yet; it is
    /// pinned only once the lock has been passed and the answer sent.
    func approve(_ r: PendingRequest, newName: String?) async throws {
        guard let ctx = context() else { return }
        let fp = r.view.destination.fingerprint
        let known = name(of: fp)
        let chosen = known ?? newName?.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64).description ?? ""
        guard !chosen.isEmpty else { throw AppError("donnez un nom à ce serveur") }
        let user = r.view.user ?? "?"
        try await settle(r) {
            let started = Date()
            let data = r.view.data
            let reason = "Approuver la connexion à \(user)@\(chosen)"
            let signature = try await Task.detached { try Keys.sign(data, reason: reason) }.value
            let outcome = try await Signer.approve(ctx, r.entry, signatureBlob: signature)
            if known == nil {
                self.remembered.pins[fp] = chosen
                Store.save(self.remembered)
            }
            let seconds = String(format: "%.1f", Date().timeIntervalSince(started))
            self.journal(outcome == "accepted"
                ? "Approuvé : \(user)@\(chosen) (\(seconds) s)"
                : "Approuvé trop tard : \(user)@\(chosen) (\(outcome))")
        }
    }

    private func context() -> SignerContext? {
        guard let p = pairing, let blob = keyBlob, let identity = try? Keys.identity() else { return nil }
        return SignerContext(record: p, me: identity, keyBlob: blob)
    }

    private func settle(_ r: PendingRequest, _ work: @escaping () async throws -> Void) async throws {
        busy.insert(r.id)
        defer { busy.remove(r.id) }
        try await work()
        requests.removeAll { $0.id == r.id }
    }
}

struct AppError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

func describe(_ error: Error) -> String {
    if let e = error as? RelayError {
        if e.status == 401 { return "le relais ne reconnaît pas cet appareil" }
        if e.status == 0 { return e.message }
        return "le relais a répondu \(e.status)"
    }
    if let e = error as? CoreError { return e.description }
    return (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
}
