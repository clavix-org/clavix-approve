// The app's state and its conversation with the relay: the same behaviour
// as web/app.js. Long-poll every paired machine while the app is in front,
// check every request with ClavixCore before showing it, refuse without
// asking what cannot be verified, and answer only after the device's lock.
//
// A machine is paired in one of two modes, for good:
// - sign (clavix-agent): the iPhone's SSH key signs the login;
// - approve (Clavix desktop): the desktop holds the key and signs once the
//   iPhone's approval key has said yes.

import ClavixCore
import Foundation
import SwiftUI
import UserNotifications

struct PendingRequest: Identifiable {
    let entry: RequestEntry
    let view: VerifiedRequest
    let record: PairingRecord
    var id: String { record.id + entry.id }
}

struct MachineState {
    var text = ""
    var isError = false
}

@MainActor
final class Model: ObservableObject {
    @Published private(set) var keyBlob: Data? = Keys.sshKeyBlob
    @Published private(set) var pairings: [PairingRecord] = Keys.pairings
    @Published private(set) var remembered = Store.load()
    @Published private(set) var requests: [PendingRequest] = []
    @Published private(set) var busy: Set<String> = []
    @Published private(set) var states: [String: MachineState] = [:]
    /// Set by a pairing just made, until the user has compared the digits.
    @Published var justPaired: PairingRecord?
    @Published private(set) var now = Date()

    private var seen: Set<String> = [] // every request already handled or shown
    private var polling: [String: Task<Void, Never>] = [:]
    private var ticker: Task<Void, Never>?
    var pushToken: Data? { didSet { Task { await registerPush() } } }

    static let comment = "clavix-approve-iphone"

    var publicKeyLine: String? { keyBlob.map { SSH.publicKeyLine(keyBlob: $0, comment: Self.comment) } }

    func name(of fingerprint: String) -> String? { remembered.pins[fingerprint] }

    func state(of record: PairingRecord) -> MachineState { states[record.id] ?? MachineState() }

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

    private func say(_ record: PairingRecord, _ text: String, error: Bool = false) {
        states[record.id] = MachineState(text: text, isError: error)
    }

    static func machineName(_ record: PairingRecord) -> String {
        record.label.isEmpty ? "machine sans nom" : record.label
    }

    // ---- pairing ----

    /// Pair with the agent that shows `input` (code or link). `relayText`
    /// is used when the input is a bare code. The mode is the agent's: the
    /// key it needs is made then if this device has none yet.
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
        let record = try await Signer.pair(relay: relay!, code: code, me: identity, comment: Self.comment) { mode in
            switch mode {
            case .sign: return try Keys.sshKeyBlob ?? Keys.createSSHKey()
            case .approve: return try Keys.approveKeyBlob ?? Keys.createApproveKey()
            }
        }
        keyBlob = Keys.sshKeyBlob
        // The same channel paired again replaces its entry, whose device id
        // is revoked (best effort); any other machine stays.
        let replaced = pairings.filter { $0.ch == record.ch }
        var next = pairings.filter { $0.ch != record.ch }
        next.append(record)
        try Keys.save(pairings: next)
        pairings = next
        justPaired = record
        remembered.lastRelay = relay
        Store.save(remembered)
        journal(record.mode == .approve
                ? "Appairé en validation avec \(Self.machineName(record))"
                : "Appairé avec \(Self.machineName(record))")
        for old in replaced where old.signer != record.signer {
            stopWatching(old)
            _ = try? await RelayClient(base: old.relay, ch: old.ch, token: old.token).revoke()
        }
        AppDelegate.askForPush()
        await registerPush()
        start()
    }

    /// Revoke this device on the relay for that machine, then forget it.
    /// The keys and the named hosts stay.
    func forget(machine p: PairingRecord) async {
        stopWatching(p)
        do {
            let deleted = try await RelayClient(base: p.relay, ch: p.ch, token: p.token).revoke()
            journal(deleted ? "\(Self.machineName(p)) oubliée, appareil retiré du relais"
                            : "\(Self.machineName(p)) oubliée (le relais ne la connaissait plus)")
        } catch {
            journal("\(Self.machineName(p)) oubliée sans joindre le relais : \(describe(error))")
        }
        let next = pairings.filter { $0.id != p.id }
        try? Keys.save(pairings: next)
        pairings = next
        requests.removeAll { $0.record.id == p.id }
        states[p.id] = nil
    }

    // ---- push ----

    private func registerPush() async {
        guard let token = pushToken else { return }
        #if DEBUG
        let sandbox = true
        #else
        let sandbox = false
        #endif
        for p in pairings {
            do {
                let state = try await RelayClient(base: p.relay, ch: p.ch, token: p.token)
                    .subscribeAPNs(deviceToken: token, sandbox: sandbox)
                if state == "unsupported" {
                    // The relay has no APNs key: not an error, and not worth retrying.
                    journal("Le relais de \(Self.machineName(p)) n’envoie pas de notifications à l’appli : ouvrez-la pour voir les demandes")
                }
            } catch let e as RelayError where e.status == 400 {
                journal("Le relais de \(Self.machineName(p)) ne sait pas encore réveiller l’appli : ouvrez-la pour voir les demandes")
            } catch {
                journal("Notifications non enregistrées pour \(Self.machineName(p)) : \(describe(error))")
            }
        }
    }

    // ---- watching the relay ----

    /// The app comes to the front, or a notification was tapped.
    func start() {
        // The relay keeps at most one notification per channel; once the
        // app is in front they are stale.
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
        if ticker == nil {
            ticker = Task { [weak self] in
                while !Task.isCancelled {
                    self?.tick()
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                }
            }
        }
        guard let identity = try? Keys.identity() else { return }
        for p in pairings {
            // A call left from before the app went to the background may be
            // dead: drop it and ask again.
            polling[p.id]?.cancel()
            guard let ctx = context(p, identity) else { continue }
            polling[p.id] = Task { [weak self] in await self?.watch(ctx) }
        }
    }

    func stop() {
        polling.values.forEach { $0.cancel() }
        polling = [:]
        ticker?.cancel()
        ticker = nil
    }

    private func stopWatching(_ p: PairingRecord) {
        polling[p.id]?.cancel()
        polling[p.id] = nil
    }

    private func watch(_ ctx: SignerContext) async {
        let p = ctx.record
        var wait = 0      // the first call returns at once
        var backoff = 0   // seconds, grows on consecutive failures
        while !Task.isCancelled {
            do {
                let known = requests.filter { $0.record.id == p.id }.map(\.entry.id)
                let entries = try await ctx.relay.requests(wait: wait, known: known)
                if Task.isCancelled { return }
                await show(entries, ctx)
                if state(of: p).isError || wait == 0 { say(p, "") }
                wait = 20
                backoff = 0
            } catch let e as RelayError where e.isFatal {
                if Task.isCancelled { return }
                say(p, e.status == 401
                    ? "Retirée : le relais ne connaît plus cet appairage. Oubliez-la dans Réglages, ou appairez à nouveau."
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
                say(p, (error as? RelayError)?.status == 429
                    ? "Trop de requêtes, reprise dans \(backoff) s."
                    : "Relais injoignable, nouvel essai dans \(backoff) s.", error: true)
                try? await Task.sleep(nanoseconds: UInt64(backoff) * 1_000_000_000)
            }
        }
    }

    private func show(_ entries: [RequestEntry], _ ctx: SignerContext) async {
        let p = ctx.record
        let live = Set(entries.map(\.id))
        // Gone from the relay: answered elsewhere, expired, or withdrawn by
        // the requester (approve mode, when the desktop answered first).
        requests.removeAll { $0.record.id == p.id && !live.contains($0.entry.id) && !busy.contains($0.id) }
        let t = Date().timeIntervalSince1970
        for entry in entries where !seen.contains(p.id + entry.id) {
            seen.insert(p.id + entry.id)
            switch Signer.read(ctx, entry, now: t) {
            case .success(let view):
                requests.append(PendingRequest(entry: entry, view: view, record: p))
                if !state(of: p).isError { say(p, "") }
            case .failure(let reason):
                // Nothing trustworthy to show: refuse without asking.
                let sent = (try? await Signer.deny(ctx, entry, reason: reason.rawValue)) ?? "non envoyé"
                journal("Demande de \(Self.machineName(p)) écartée (\(reason.rawValue), \(sent))")
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
        guard let ctx = context(r.record) else { return }
        try await settle(r) {
            _ = try await Signer.deny(ctx, r.entry, reason: "user")
            self.journal("Refusé : \(r.view.user ?? "?")@\(self.name(of: r.view.destination.fingerprint) ?? r.view.destination.fingerprint)")
        }
    }

    /// `newName` is required when the destination is not pinned yet; it is
    /// pinned only once the lock has been passed and the answer sent.
    func approve(_ r: PendingRequest, newName: String?) async throws {
        guard let ctx = context(r.record) else { throw AppError("la clé de cet appairage manque sur cet iPhone") }
        let fp = r.view.destination.fingerprint
        let known = name(of: fp)
        let chosen = known ?? newName?.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64).description ?? ""
        guard !chosen.isEmpty else { throw AppError("donnez un nom à ce serveur") }
        let user = r.view.user ?? "?"
        let mode = r.record.mode
        try await settle(r) {
            let started = Date()
            let outcome: String
            switch mode {
            case .sign:
                let data = r.view.data
                let reason = "Approuver la connexion à \(user)@\(chosen)"
                let signature = try await Task.detached { try Keys.sign(data, reason: reason) }.value
                outcome = try await Signer.approve(ctx, r.entry, signatureBlob: signature)
            case .approve:
                let data = Signer.approvalData(ctx, r.entry)
                let reason = "Valider la connexion de \(Self.machineName(r.record)) à \(user)@\(chosen)"
                let proof = try await Task.detached { try Keys.approve(data, reason: reason) }.value
                outcome = try await Signer.sendApproval(ctx, r.entry, proofBlob: proof)
            }
            if known == nil {
                self.remembered.pins[fp] = chosen
                Store.save(self.remembered)
            }
            let seconds = String(format: "%.1f", Date().timeIntervalSince(started))
            let verb = mode == .approve ? "Validé" : "Approuvé"
            if outcome == "accepted" {
                self.journal("\(verb) : \(user)@\(chosen) (\(seconds) s)")
            } else {
                // Expired, or withdrawn because the desktop answered first.
                self.journal("\(verb) trop tard : \(user)@\(chosen) (\(outcome))")
                self.say(r.record, "Trop tard : la demande n’attendait plus de réponse.")
            }
        }
    }

    private func context(_ p: PairingRecord, _ identity: Identity? = nil) -> SignerContext? {
        guard let identity = identity ?? (try? Keys.identity()) else { return nil }
        let blob = p.mode == .sign ? Keys.sshKeyBlob : Keys.approveKeyBlob
        guard let blob else { return nil }
        return SignerContext(record: p, me: identity, keyBlob: blob)
    }

    private func settle(_ r: PendingRequest, _ work: @escaping () async throws -> Void) async throws {
        busy.insert(r.id)
        defer { busy.remove(r.id) }
        try await work()
        requests.removeAll { $0.id == r.id }
    }
}

extension PairingRecord: @retroactive Identifiable {
    public var id: String { ch + signer }
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
