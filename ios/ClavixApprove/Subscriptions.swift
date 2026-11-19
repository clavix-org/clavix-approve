// The subscription to the hosted relay, with StoreKit 2. Only machines
// paired through approve.clavix.org need it; the decisions themselves
// (status, which pairings get the proof) are in ClavixCore, RelaySubscription.swift.
//
// App Store Connect sets the prices: the app shows StoreKit's
// `displayPrice` and never a price of its own.

import ClavixCore
import Combine
import StoreKit

@MainActor
final class Subscriptions: ObservableObject {
    /// The two plans, cheapest first; empty until the App Store answered.
    @Published private(set) var products: [Product] = []
    /// Nil until StoreKit has been read once.
    @Published private(set) var status: SubscriptionStatus?
    /// The purchase whose proof the hosted relay must hold.
    @Published private(set) var current: SubscriptionPurchase?
    /// Whether this Apple ID may still take the free trial.
    @Published private(set) var trialEligible = false
    @Published private(set) var productsError: String?

    /// Called once the entitlement may have changed: at launch, after a
    /// purchase or a restore, on every transaction update. The model then
    /// posts the proof to the hosted relay.
    var onChange: (@MainActor () -> Void)?

    /// Runs for the app's lifetime.
    private var updates: Task<Void, Never>?

    init() {
        // As early as possible: a renewal, a purchase approved by a parent
        // or made on another device arrives here, even before any screen.
        updates = Task { [weak self] in
            for await result in StoreKit.Transaction.updates {
                await self?.deliver(result)
            }
        }
        Task { [weak self] in
            await self?.refresh()
            self?.onChange?()
            await self?.loadProducts()
        }
    }

    // ---- products ----

    func loadProducts() async {
        do {
            let found = try await Product.products(for: RelaySubscription.productIDs)
            products = found.sorted { $0.price < $1.price }
            productsError = found.isEmpty ? "Offres indisponibles pour le moment." : nil
            if let info = found.first?.subscription {
                trialEligible = await info.isEligibleForIntroOffer
            }
        } catch {
            productsError = "Offres indisponibles : \(error.localizedDescription)"
        }
    }

    // ---- purchases ----

    /// The outcome of SwiftUI's `purchase` action. Returns a message for
    /// the user, or nil when there is nothing to say.
    func handle(_ result: Product.PurchaseResult) async -> String? {
        switch result {
        case .success(let verification):
            guard case .verified = verification else {
                return "Achat non vérifié par l’App Store : il n’a pas été pris en compte."
            }
            await deliver(verification)
            return nil
        case .pending:
            return "Achat en attente d’approbation. Il sera pris en compte dès qu’il sera accepté."
        case .userCancelled:
            return nil
        @unknown default:
            return nil
        }
    }

    /// « Restaurer les achats »: asks the App Store for this Apple ID's
    /// transactions (it may ask for the password).
    func restore() async -> String? {
        do {
            try await AppStore.sync()
        } catch StoreKitError.userCancelled {
            return nil
        } catch {
            return "Restauration impossible : \(error.localizedDescription)"
        }
        await refresh()
        onChange?()
        return status?.isActive == true ? nil : "Aucun abonnement en cours sur cet identifiant Apple."
    }

    /// A transaction, verified or not. Only a verified one counts; it is
    /// finished once the app has taken it into account.
    private func deliver(_ result: VerificationResult<StoreKit.Transaction>) async {
        guard case .verified(let transaction) = result else { return }
        await refresh()
        await transaction.finish()
        onChange?()
    }

    // ---- entitlement ----

    /// Reads StoreKit: the current entitlements, and the latest
    /// transaction of each plan to tell « Expiré » from « Aucun ».
    func refresh() async {
        var found: [UInt64: SubscriptionPurchase] = [:]
        for await result in StoreKit.Transaction.currentEntitlements {
            guard case .verified(let t) = result, RelaySubscription.productIDs.contains(t.productID) else { continue }
            found[t.id] = Self.purchase(t, jws: result.jwsRepresentation, entitled: true)
        }
        for id in RelaySubscription.productIDs {
            guard let result = await StoreKit.Transaction.latest(for: id), case .verified(let t) = result,
                  found[t.id] == nil else { continue }
            found[t.id] = Self.purchase(t, jws: result.jwsRepresentation, entitled: false)
        }
        let all = Array(found.values)
        let now = Date()
        status = RelaySubscription.status(all, now: now)
        current = RelaySubscription.current(all, now: now)
        if let info = products.first?.subscription {
            trialEligible = await info.isEligibleForIntroOffer
        }
    }

    private static func purchase(_ t: StoreKit.Transaction, jws: String, entitled: Bool) -> SubscriptionPurchase {
        SubscriptionPurchase(productID: t.productID, transactionID: t.id, expires: t.expirationDate, revoked: t.revocationDate,
                 isTrial: t.offer?.type == .introductory, entitled: entitled, jws: jws)
    }
}

// ---- wording ----

extension Product {
    /// « par mois », « par an », from the plan's own period.
    var periodText: String {
        guard let period = subscription?.subscriptionPeriod else { return "" }
        return "par " + period.frenchText(single: true)
    }

    /// The free trial this plan offers, when it offers one: « 14 jours d’essai gratuit ».
    var trialText: String? {
        guard let offer = subscription?.introductoryOffer, offer.paymentMode == .freeTrial else { return nil }
        return "\(offer.period.frenchText(single: false)) d’essai gratuit"
    }
}

extension Product.SubscriptionPeriod {
    /// `single`: « mois », « an » for one unit (« par mois »); otherwise
    /// with the count (« 14 jours », « 1 mois »).
    /// Weeks are said in days: a two-week trial is « 14 jours ».
    func frenchText(single: Bool) -> String {
        if unit == .week { return "\(value * 7) jours" }
        let word: (singular: String, plural: String)
        switch unit {
        case .day: word = ("jour", "jours")
        case .week: word = ("semaine", "semaines")
        case .month: word = ("mois", "mois")
        case .year: word = ("an", "ans")
        @unknown default: word = ("période", "périodes")
        }
        if single && value == 1 { return word.singular }
        return "\(value) \(value > 1 ? word.plural : word.singular)"
    }
}
