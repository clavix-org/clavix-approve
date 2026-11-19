// The subscription to the hosted relay, as far as it can be decided
// without StoreKit: which purchase is in force, what the app shows of it,
// which pairings must receive its proof, and what the relay's answer to
// that proof means. The app maps StoreKit's transactions to `SubscriptionPurchase`
// and keeps every StoreKit call to itself.
//
// Only the hosted relay (`RelayAddress.official`) asks for a
// subscription. A machine paired through any other relay never needs one,
// and the app never mentions it for them.

import Foundation

public enum RelaySubscription {
    public static let monthly = "org.clavix.approve.personal.monthly"
    public static let yearly = "org.clavix.approve.personal.yearly"
    /// Both plans, in one subscription group.
    public static let productIDs = [monthly, yearly]
    /// Machines one subscription covers on the hosted relay; the relay
    /// enforces it and answers `403 {"error":"machine_limit"}` past it.
    public static let machineLimit = 10

    /// Whether this pairing goes through the hosted relay, hence needs the
    /// subscription.
    public static func needed(by record: PairingRecord) -> Bool {
        RelayAddress.isOfficial(record.relay)
    }

    /// The pairings that count against the machine limit: confirmed, on
    /// the hosted relay.
    public static func covered(_ pairings: [PairingRecord]) -> [PairingRecord] {
        pairings.filter { $0.isActive && needed(by: $0) }
    }

    /// Whether the main screen should say a subscription is required: the
    /// status is known, nothing is in force, and a machine is paired on the
    /// hosted relay. `status` is nil until StoreKit has answered.
    public static func shouldPrompt(status: SubscriptionStatus?, pairings: [PairingRecord]) -> Bool {
        guard let status, !status.isActive else { return false }
        return pairings.contains { needed(by: $0) }
    }

    /// The purchase whose proof the relay must hold: the subscription in
    /// force that runs longest, or nil.
    public static func current(_ purchases: [SubscriptionPurchase], now: Date) -> SubscriptionPurchase? {
        purchases
            .filter { productIDs.contains($0.productID) && $0.inForce(now: now) }
            .max { ($0.expires ?? .distantPast, $0.transactionID) < ($1.expires ?? .distantPast, $1.transactionID) }
    }

    /// What the app shows. `purchases` holds StoreKit's current
    /// entitlements and the latest transaction of each plan, verified.
    public static func status(_ purchases: [SubscriptionPurchase], now: Date) -> SubscriptionStatus {
        let ours = purchases.filter { productIDs.contains($0.productID) }
        if let p = current(ours, now: now) {
            // In the billing grace period StoreKit still lists the
            // subscription though its period is over: in force, no end shown.
            let until = p.expires.flatMap { $0 > now ? $0 : nil }
            return p.isTrial ? .trial(until: until) : .active(until: until)
        }
        guard !ours.isEmpty else { return .never }
        let ended = ours.compactMap { $0.revoked ?? $0.expires }.max()
        return .expired(since: ended)
    }
}

/// A verified App Store transaction of one of the plans, as the app reads
/// it from StoreKit.
public struct SubscriptionPurchase: Equatable, Sendable {
    public let productID: String
    public let transactionID: UInt64
    public let expires: Date?
    public let revoked: Date?
    /// Bought through the introductory offer: the free trial.
    public let isTrial: Bool
    /// Listed by StoreKit's current entitlements, rather than only as the
    /// latest transaction of its plan.
    public let entitled: Bool
    /// The App Store's signed transaction, as the relay checks it.
    public let jws: String

    public init(productID: String, transactionID: UInt64, expires: Date?, revoked: Date?,
                isTrial: Bool, entitled: Bool, jws: String) {
        (self.productID, self.transactionID, self.expires, self.revoked) = (productID, transactionID, expires, revoked)
        (self.isTrial, self.entitled, self.jws) = (isTrial, entitled, jws)
    }

    /// StoreKit's word, unless the transaction was revoked since: a
    /// refund, or Family Sharing withdrawn.
    public func inForce(now: Date) -> Bool {
        entitled && (revoked.map { $0 > now } ?? true)
    }
}

public enum SubscriptionStatus: Equatable, Sendable {
    /// Never subscribed on this Apple ID.
    case never
    /// The free trial, up to that date (nil: in force, end unknown).
    case trial(until: Date?)
    /// Paid, renewed up to that date (nil: in force, end unknown).
    case active(until: Date?)
    /// Subscribed before, no longer.
    case expired(since: Date?)

    public var isActive: Bool {
        switch self {
        case .trial, .active: return true
        case .never, .expired: return false
        }
    }
}

/// The relay's answer to `POST …/dev/{dev}/entitlement`.
public enum EntitlementOutcome: Equatable, Sendable {
    /// Recorded; the relay serves this device up to `expires`.
    case accepted(expires: Date?)
    /// This subscription already covers `RelaySubscription.machineLimit` machines.
    case machineLimit
    /// Refused for good with this proof (400, 401, or a relay that does
    /// not know the call): not sent again before the proof changes.
    case refused(status: Int)
    /// Not reached, throttled, or a server error: sent again later.
    case failed

    public init(_ result: Result<Date?, Error>) {
        switch result {
        case .success(let expires):
            self = .accepted(expires: expires)
        case .failure(let error):
            guard let e = error as? RelayError, e.isFatal else { self = .failed; return }
            self = e.status == 403 && e.code == "machine_limit" ? .machineLimit : .refused(status: e.status)
        }
    }

    /// Whether the relay has decided, for this proof.
    public var isSettled: Bool { self != .failed }
}

/// The last answer one pairing got, and for which transaction.
public struct EntitlementDelivery: Equatable, Sendable {
    public let transactionID: UInt64
    public let outcome: EntitlementOutcome

    public init(transactionID: UInt64, outcome: EntitlementOutcome) {
        (self.transactionID, self.outcome) = (transactionID, outcome)
    }
}

public enum EntitlementSync {
    /// The key of a pairing in `delivered`.
    public static func key(_ record: PairingRecord) -> String { record.ch + record.signer }

    /// The pairings `current`'s proof must be posted to: confirmed, on the
    /// hosted relay, and without a settled answer for this transaction. A
    /// failed attempt is due again; a new transaction (a renewal, another
    /// plan) is due everywhere.
    public static func pending(_ pairings: [PairingRecord], current: SubscriptionPurchase?,
                               delivered: [String: EntitlementDelivery]) -> [PairingRecord] {
        guard let current else { return [] }
        return RelaySubscription.covered(pairings).filter { p in
            guard let last = delivered[key(p)], last.transactionID == current.transactionID else { return true }
            return !last.outcome.isSettled
        }
    }
}
