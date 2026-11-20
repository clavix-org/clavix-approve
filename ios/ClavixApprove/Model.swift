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
    /// The pairing sheet: what the user must accept before the phone
    /// answers, then the digits to compare.
    @Published var pairingSheet: PairingSheet?
    /// A pairing link that could not be opened (from the camera or another app).
    @Published var linkError: String?
    @Published private(set) var now = Date()
    /// The hosted relay's last answer to the subscription proof, per
    /// pairing (`EntitlementSync.key`).
    @Published private(set) var deliveries: [String: EntitlementDelivery] = [:]

    private var seen: Set<String> = [] // every request already handled or shown
    private var polling: [String: Task<Void, Never>] = [:]
    private var ticker: Task<Void, Never>?
    var pushToken: Data? { didSet { Task { await registerPush() } } }
    private weak var subscriptions: Subscriptions?
    private var sendingEntitlement = false
    private var entitlementAgain = false
    private var entitlementRetry: Task<Void, Never>?
    private var entitlementBackoff: UInt64 = 0 // seconds

    static let comment = "clavix-approve-iphone"

    init() {
        // Pairings of the first protocol version were confirmed with digits
        // a relay could steer: they are dropped, and must be made again.
        let current = pairings.filter(\.isCurrent)
        if current.count != pairings.count {
            try? Keys.save(pairings: current)
            pairings = current
            journal("Appairages d’une version précédente retirés : appairez à nouveau ces machines")
        }
    }

    var publicKeyLine: String? { keyBlob.map { SSH.publicKeyLine(keyBlob: $0, comment: Self.comment) } }

    func name(of fingerprint: String) -> String? { remembered.pins[fingerprint] }

    func state(of record: PairingRecord) -> MachineState { states[record.id] ?? MachineState() }

    // ---- journal and memory ----

    func journal(_ text: String) {
        remembered.journal.insert(JournalEntry(at: Date(), text: text), at: 0)
        remembered.journal = Array(remembered.journal.prefix(Store.journalSize))
        Store.save(remembered)
    }

    /// Give a remembered server another name. The fingerprint, which is
    /// what the app checks, does not change.
    func rename(pin fingerprint: String, to newName: String) {
        let name = String(newName.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        guard !name.isEmpty, let old = remembered.pins[fingerprint], old != name else { return }
        remembered.pins[fingerprint] = name
        Store.save(remembered)
        journal("Hôte renommé : \(old) → \(name)")
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

    /// First step of a pairing: read the hello of the agent that shows
    /// `input` (a bare code, or the `clavix-approve://` link). `relayText`
    /// is used for a bare code. Nothing is sent: the pairing sheet asks the
    /// user to accept the relay, the machine and the mode first.
    func open(input: String, relayText: String) async throws {
        let code = try PairingCode(input)
        let relay: URL
        if let linked = code.relay {
            relay = linked
        } else {
            let text = relayText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else { throw AppError("indiquez l’adresse du relais, ou scannez le QR code") }
            relay = try RelayAddress.parse(text)
        }
        pairingSheet = .consent(try await Signer.open(relay: relay, code: code))
    }

    /// A `clavix-approve://pair?…` link, from the system camera.
    func open(link: URL) async {
        guard link.scheme?.lowercased() == PairingCode.scheme else { return }
        do {
            try await open(input: link.absoluteString, relayText: "")
        } catch {
            linkError = describe(error)
        }
    }

    /// Second step, once the user accepted: answer with the key of the
    /// agent's mode (made then if this device has none yet), receive the
    /// agent's nonce, show the digits. The pairing is stored unconfirmed:
    /// it accepts no request until the user says the digits match.
    func accept(_ offer: PairingOffer) async throws {
        let identity = try Keys.identity()
        let blob: Data
        switch offer.mode {
        case .sign: blob = try Keys.sshKeyBlob ?? Keys.createSSHKey()
        case .approve: blob = try Keys.approveKeyBlob ?? Keys.createApproveKey()
        }
        keyBlob = Keys.sshKeyBlob
        let record = try await Signer.answer(offer, me: identity, keyBlob: blob, comment: Self.comment)
        var next = pairings
        next.append(record)
        try Keys.save(pairings: next)
        pairings = next
        remembered.lastRelay = offer.relay
        Store.save(remembered)
        pairingSheet = .digits(record)
    }

    /// The user saw the same digits on the machine: the pairing goes live.
    /// The same channel paired before is replaced, its device id revoked
    /// (best effort); any other machine stays.
    func confirm(_ record: PairingRecord) async {
        guard let i = pairings.firstIndex(where: { $0.id == record.id }) else { return }
        var confirmed = pairings[i]
        confirmed.confirmed = true
        let replaced = pairings.filter { $0.ch == record.ch && $0.id != record.id }
        var next = pairings.filter { $0.ch != record.ch }
        next.append(confirmed)
        do {
            try Keys.save(pairings: next)
        } catch {
            linkError = describe(error)
            return
        }
        pairings = next
        pairingSheet = .digits(confirmed)
        journal(record.mode == .approve
                ? "Appairé en validation avec \(Self.machineName(record))"
                : "Appairé avec \(Self.machineName(record))")
        for old in replaced {
            stopWatching(old)
            states[old.id] = nil
            _ = try? await RelayClient(base: old.relay, ch: old.ch, token: old.token).revoke()
        }
        AppDelegate.askForPush()
        await registerPush()
        start()
        await sendEntitlement()
    }

    /// The digits differ: someone is in between. This device is taken off
    /// the channel and the pairing forgotten.
    func reject(_ record: PairingRecord) async {
        pairingSheet = nil
        journal("Appairage avec \(Self.machineName(record)) refusé : les chiffres différaient")
        await forget(machine: record)
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
        deliveries[EntitlementSync.key(p)] = nil
        if RelaySubscription.needed(by: p) {
            // A place freed under the machine limit: those refused for it
            // are tried again.
            deliveries = deliveries.filter { if case .machineLimit = $0.value.outcome { return false } else { return true } }
            await sendEntitlement()
        }
    }

    // ---- push ----

    private func registerPush() async {
        guard let token = pushToken else { return }
        #if DEBUG
        let sandbox = true
        #else
        let sandbox = false
        #endif
        // A pairing not confirmed yet gets no push token: it may be a relay
        // the user turns down.
        for p in pairings where p.isActive {
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

    // ---- subscription (hosted relay only) ----

    func attach(_ s: Subscriptions) {
        guard subscriptions !== s else { return }
        subscriptions = s
        s.onChange = { [weak self] in Task { await self?.sendEntitlement() } }
        Task { await sendEntitlement() }
    }

    /// Pairings whose relay answered that it checks no subscription: never
    /// counted, never prompted for.
    var notRequired: Set<String> { remembered.notRequired ?? [] }

    /// The machine limit the relay last stated, else the usual one.
    var machineLimit: Int {
        for d in deliveries.values { if case .machineLimit(let limit?) = d.outcome { return limit } }
        return RelaySubscription.machineLimit
    }

    /// Why this pairing is not served under the subscription, if its relay
    /// said so for the current one.
    func entitlementIssue(of p: PairingRecord) -> String? {
        guard let current = subscriptions?.current, let d = deliveries[EntitlementSync.key(p)],
              d.transactionID == current.transactionID else { return nil }
        switch d.outcome {
        case .machineLimit(let limit):
            return "Non couverte : l’abonnement couvre déjà \(limit ?? RelaySubscription.machineLimit) machines. Oubliez-en une dans Réglages pour couvrir celle-ci."
        case .ended(let revoked):
            return revoked
                ? "Abonnement révoqué : le relais Clavix ne transmet plus les demandes de cette machine."
                : "Abonnement expiré : le relais Clavix ne transmet plus les demandes de cette machine."
        default:
            return nil
        }
    }

    /// Posts the current subscription's proof to every confirmed pairing on
    /// the hosted relay that does not hold it yet; without a subscription,
    /// asks once whether its relay checks one at all (an empty proof, see
    /// `EntitlementSync.pending`). Quiet and best effort: approvals never
    /// wait for it, network failures are retried later, every other answer
    /// is final until the subscription changes.
    func sendEntitlement() async {
        guard !sendingEntitlement else { entitlementAgain = true; return }
        sendingEntitlement = true
        defer { sendingEntitlement = false }
        var failed = false
        repeat {
            entitlementAgain = false
            failed = false
            // Not before StoreKit has answered: the probe is for when there
            // is truly no subscription.
            guard let subscriptions, subscriptions.status != nil else { break }
            let current = subscriptions.current
            for p in EntitlementSync.pending(pairings, current: current, delivered: deliveries) {
                let result: Result<EntitlementGrant, Error>
                do {
                    result = .success(try await RelayClient(base: p.relay, ch: p.ch, token: p.token)
                        .postEntitlement(signer: p.signer, jws: current?.jws ?? EntitlementSync.probe))
                } catch {
                    result = .failure(error)
                }
                // Forgotten meanwhile: nothing to remember.
                guard pairings.contains(where: { $0.id == p.id }) else { continue }
                let outcome = EntitlementOutcome(result)
                let key = EntitlementSync.key(p)
                if current != nil && outcome != deliveries[key]?.outcome {
                    note(outcome, for: p)
                }
                deliveries[key] = EntitlementDelivery(transactionID: current?.transactionID, outcome: outcome)
                if let required = outcome.requiresSubscription, required == notRequired.contains(key) {
                    var keys = notRequired
                    if required { keys.remove(key) } else { keys.insert(key) }
                    remembered.notRequired = keys
                    Store.save(remembered)
                }
                if outcome == .failed { failed = true }
            }
        } while entitlementAgain
        if failed {
            scheduleEntitlementRetry()
        } else {
            entitlementBackoff = 0
        }
    }

    /// One journal line per new refusal of a real proof.
    private func note(_ outcome: EntitlementOutcome, for p: PairingRecord) {
        let name = Self.machineName(p)
        switch outcome {
        case .machineLimit(let limit):
            journal("Abonnement : \(name) n’est pas couverte, limite de \(limit ?? RelaySubscription.machineLimit) machines atteinte")
        case .ended(let revoked):
            journal("Abonnement \(revoked ? "révoqué" : "expiré") selon le relais de \(name)")
        case .invalidTransaction(let reason):
            // Expected for a purchase made with Xcode's StoreKit testing.
            journal("Preuve d’achat refusée par le relais de \(name)" + (reason.map { " (\($0))" } ?? ""))
        case .refused(status: 400):
            journal("Abonnement non transmis pour \(name) : le relais a refusé la requête")
        default:
            // Accepted, not required, a failure retried later, or a 401
            // (the pairing is gone, which its card already says).
            break
        }
    }

    private func scheduleEntitlementRetry() {
        guard entitlementRetry == nil else { return }
        entitlementBackoff = min(entitlementBackoff > 0 ? entitlementBackoff * 2 : 60, 1800)
        let delay = entitlementBackoff
        entitlementRetry = Task { [weak self] in
            try? await Task.sleep(nanoseconds: delay * 1_000_000_000)
            guard !Task.isCancelled else { return }
            self?.entitlementRetry = nil
            await self?.sendEntitlement()
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
        // Back in front: a proof that did not reach the relay is tried again.
        Task { await sendEntitlement() }
        guard let identity = try? Keys.identity() else { return }
        // An unconfirmed pairing accepts no request: it is not even polled.
        for p in pairings where p.isActive {
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

/// What the pairing sheet shows.
enum PairingSheet: Identifiable {
    /// The hello was read; nothing sent yet.
    case consent(PairingOffer)
    /// Answered: the digits to compare (and, once confirmed, what next).
    case digits(PairingRecord)

    var id: String {
        switch self {
        case .consent(let offer): return "consent" + offer.code.ch
        case .digits(let record): return "digits" + record.id
        }
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
