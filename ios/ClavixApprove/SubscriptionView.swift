// The subscription screens: the « Abonnement » sections of Réglages and
// the banner of the main screen. Only the hosted relay asks for a
// subscription; the banner never shows for machines paired through
// another relay.

import ClavixCore
import StoreKit
import SwiftUI

/// The « Abonnement » sections of Réglages.
struct SubscriptionSection: View {
    /// The id of the « Abonnement » section, which the main screen's banner
    /// scrolls to: its status, then the plans just below.
    static let sectionID = "subscription"

    @EnvironmentObject private var model: Model
    @EnvironmentObject private var subscriptions: Subscriptions
    @Environment(\.purchase) private var purchase
    /// The product being bought, or `restoring`.
    @State private var working: String?
    @State private var message: String?
    @State private var managing = false

    private static let restoring = "restore"

    private var covered: [PairingRecord] { RelaySubscription.covered(model.pairings, notRequired: model.notRequired) }
    /// Machines on the hosted relay, but for those whose relay checks no subscription.
    private var hostedCount: Int {
        model.pairings.filter { RelaySubscription.needed(by: $0) && !model.notRequired.contains(EntitlementSync.key($0)) }.count
    }
    private var isActive: Bool { subscriptions.status?.isActive == true }
    /// The relay refuses the requests of a paired machine: same test as the main screen's banner.
    private var refused: Bool {
        RelaySubscription.shouldPrompt(status: subscriptions.status, pairings: model.pairings,
                                       notRequired: model.notRequired)
    }
    /// « 14 jours d’essai gratuit », as App Store Connect sets it, when this Apple ID may still take it.
    private var trial: String? {
        guard subscriptions.trialEligible, !isActive else { return nil }
        return subscriptions.products.lazy.compactMap(\.trialText).first
    }

    var body: some View {
        Section {
            LabeledContent("État") {
                if refused {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                        Text(statusText)
                    }
                    .bold()
                    .foregroundStyle(.red)
                    .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(statusText) : le relais refuse les demandes")
                } else {
                    Text(statusText).bold()
                }
            }
            if hostedCount > 0 {
                LabeledContent("Machines sur le relais Clavix") {
                    Text("\(covered.count) / \(model.machineLimit)").monospacedDigit()
                }
            }
            ForEach(model.pairings) { p in
                if let issue = model.entitlementIssue(of: p) {
                    Label("\(Model.machineName(p)) — \(issue)", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            if isActive {
                Button {
                    managing = true
                } label: {
                    Label("Gérer l’abonnement", systemImage: "gearshape")
                }
                .manageSubscriptionsSheet(isPresented: $managing)
            }
        } header: {
            Text("Abonnement")
        } footer: {
            Text(hostedCount == 0 && !isActive
                 ? "Inutile pour les machines appairées avec votre propre relais : seul le relais Clavix (approve.clavix.org) demande un abonnement. \(model.machineLimit) machines max par abonnement."
                 : "Requis pour les machines appairées via le relais Clavix (approve.clavix.org), pas pour celles de votre propre relais. \(model.machineLimit) machines max par abonnement.")
        }
        .id(Self.sectionID)

        Section {
            if subscriptions.products.isEmpty {
                if let error = subscriptions.productsError {
                    Text(error).foregroundStyle(.secondary)
                    Button("Réessayer") { Task { await subscriptions.loadProducts() } }
                } else {
                    HStack { Text("Chargement des offres…").foregroundStyle(.secondary); Spacer(); ProgressView() }
                }
            }
            ForEach(subscriptions.products, id: \.id) { product in
                plan(product)
            }
            Button {
                run(Self.restoring) { await subscriptions.restore() }
            } label: {
                HStack {
                    Text("Restaurer les achats")
                    if working == Self.restoring { Spacer(); ProgressView() }
                }
            }
            .disabled(working != nil)
        } header: {
            Text(trial.map { "Formules — \($0)" } ?? "Formules")
        } footer: {
            VStack(alignment: .leading, spacing: 8) {
                if let message {
                    Label(message, systemImage: "info.circle")
                }
                Text(legalText)
                // One link per line: side by side, each wrapped on two lines.
                Link("Politique de confidentialité", destination: Links.privacy)
                Link("Conditions d’utilisation (CLUF)", destination: Links.appleEULA)
            }
        }

    }

    @ViewBuilder private func plan(_ product: Product) -> some View {
        let isCurrent = subscriptions.current?.productID == product.id
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(product.displayName).bold()
                Text("\(product.displayPrice) \(product.periodText)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                if !isActive, subscriptions.trialEligible, let trial = product.trialText {
                    Text(trial).font(.caption).foregroundStyle(Color.accentColor)
                }
            }
            Spacer()
            if isCurrent {
                Label("Formule actuelle", systemImage: "checkmark.circle.fill")
                    .labelStyle(.iconOnly)
                    .foregroundStyle(Color.accentColor)
                    .accessibilityLabel("Formule actuelle")
            } else {
                Button {
                    run(product.id) {
                        let result = try await purchase(product)
                        return await subscriptions.handle(result)
                    }
                } label: {
                    if working == product.id {
                        ProgressView()
                    } else {
                        Text("S’abonner").foregroundStyle(.white)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(working != nil)
            }
        }
        .padding(.vertical, 2)
    }

    private var statusText: String {
        switch subscriptions.status {
        case nil: return "…"
        case .never: return "Aucun"
        case .expired: return "Expiré"
        case .trial(let until):
            return until.map { "Essai gratuit jusqu’au \(Self.day($0))" } ?? "Essai gratuit"
        case .active(let until):
            return until.map { "Actif jusqu’au \(Self.day($0))" } ?? "Actif"
        }
    }

    private static func day(_ date: Date) -> String { date.formatted(date: .long, time: .omitted) }

    private var legalText: String {
        "Abonnement à renouvellement automatique, payé avec votre compte Apple à la confirmation de l’achat, ou à la fin de l’essai gratuit s’il y en a un. "
            + "Il se renouvelle au même prix pour la même durée, sauf résiliation au moins 24 heures avant la fin de la période en cours. "
            + "Résiliable à tout moment dans Réglages > Identifiant Apple > Abonnements."
    }

    private func run(_ id: String, _ work: @escaping () async throws -> String?) {
        working = id
        message = nil
        Task {
            do {
                message = try await work()
            } catch StoreKitError.userCancelled {
                message = nil
            } catch {
                message = "Achat impossible : \(error.localizedDescription)"
            }
            working = nil
        }
    }
}

/// Shown on the main screen when nothing is in force and a machine is
/// paired through the hosted relay: the relay refuses its requests (402)
/// before they reach this iPhone, so ssh fails on the machine.
struct SubscriptionBanner: View {
    @EnvironmentObject private var subscriptions: Subscriptions
    /// Set by « Voir les formules »: the main screen then opens Réglages on
    /// the plans. A NavigationLink in a list row would add a chevron.
    @Binding var showPlans: Bool

    private var offersTrial: Bool { subscriptions.status == .never || subscriptions.trialEligible }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label {
                Text("Abonnement requis : le relais refuse les demandes de vos machines")
                    .font(.subheadline.weight(.semibold))
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            Text("Sans abonnement, les machines appairées via approve.clavix.org n’envoient pas de demandes à cet iPhone. Celles de votre propre relais n’en ont pas besoin."
                 + (offersTrial ? " 14 jours d’essai gratuit." : ""))
                .font(.footnote)
                .opacity(0.9)
            Button {
                showPlans = true
            } label: {
                Text("Voir les formules")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.red)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 7)
                    .background(.white, in: Capsule())
            }
            .buttonStyle(.plain)
        }
        .foregroundStyle(.white)
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }
}
