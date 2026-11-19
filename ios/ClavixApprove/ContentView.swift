import ClavixCore
import SwiftUI

enum Links {
    static let site = URL(string: "https://clavix.org")!
    static let source = URL(string: "https://github.com/clavix-org/clavix-approve")!
    static let threatModel = URL(string: "https://github.com/clavix-org/clavix-approve/blob/master/THREAT_MODEL.md")!
    static let privacy = URL(string: "https://clavix.org/approve/privacy/")!
    static let appleEULA = URL(string: "https://www.apple.com/legal/internet-services/itunes/dev/stdeula/")!
}

struct ContentView: View {
    @EnvironmentObject private var model: Model
    @State private var addingMachine = false

    var body: some View {
        NavigationStack {
            Group {
                if model.pairings.isEmpty {
                    PairView()
                } else {
                    RequestsView()
                }
            }
            .toolbar {
                ToolbarItem(placement: .principal) {
                    HStack(spacing: 8) {
                        Logo(size: 24)
                        Text("Clavix Approve").font(.headline)
                    }
                }
                if !model.pairings.isEmpty {
                    ToolbarItem(placement: .topBarLeading) {
                        Button { addingMachine = true } label: { Image(systemName: "plus") }
                            .accessibilityLabel("Appairer une autre machine")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { SettingsView() } label: { Image(systemName: "gearshape") }
                        .accessibilityLabel("Réglages")
                }
            }
            .navigationBarTitleDisplayMode(.inline)
        }
        .sheet(isPresented: $addingMachine) {
            NavigationStack {
                PairView()
                    .navigationTitle("Autre machine")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar { Button("Annuler") { addingMachine = false } }
            }
        }
        .sheet(item: $model.pairingSheet) { sheet in
            switch sheet {
            case .consent(let offer): PairingConsentView(offer: offer)
            case .digits(let record): PairedView(record: record)
            }
        }
        .onChange(of: model.pairingSheet?.id) { _, id in if id != nil { addingMachine = false } }
        .alert("Appairage impossible", isPresented: Binding(get: { model.linkError != nil },
                                                             set: { if !$0 { model.linkError = nil } })) {
            Button("OK", role: .cancel) { model.linkError = nil }
        } message: {
            Text(model.linkError.map { "\($0)." } ?? "")
        }
    }
}

// ---- brand ----

struct Logo: View {
    var size: CGFloat
    var body: some View {
        Image("Logo")
            .resizable()
            .interpolation(.high)
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

struct BrandHeader: View {
    var subtitle: String

    var body: some View {
        VStack(spacing: 10) {
            Logo(size: 84)
                .shadow(color: .black.opacity(0.15), radius: 8, y: 4)
            Text("Clavix Approve").font(.title.weight(.bold))
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }
}

// ---- pairing ----

struct PairView: View {
    @EnvironmentObject private var model: Model
    @State private var code = ""
    @State private var relay = ""
    @State private var working = false
    @State private var error: String?
    @State private var scanning = false

    private var needsRelay: Bool { !code.lowercased().hasPrefix(PairingCode.scheme + ":") }

    var body: some View {
        Form {
            Section {
                BrandHeader(subtitle: "Vos connexions SSH, approuvées une à une sur cet iPhone. La clé ne quitte jamais l’appareil.")
            }
            .listRowBackground(Color.clear)

            Section {
                Step(number: 1, text: "Sur la machine, lancez :")
                CommandBox(text: "clavix-agent pair --add")
                Text("Sans `--add`, l’appairage remplace l’appareil déjà appairé. Pour Clavix sur l’ordinateur, ouvrez plutôt l’appairage dans ses réglages.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: {
                Text("Appairer une machine")
            }

            Section {
                Step(number: 2, text: "Scannez le QR code qu’elle affiche, ici ou avec l’appareil photo.")
                if QRScanner.isAvailable {
                    Button {
                        scanning = true
                    } label: {
                        Label("Scanner le QR code", systemImage: "qrcode.viewfinder")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(working)
                    .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                }
            }

            Section {
                HStack(alignment: .top) {
                    TextField("cva2-…", text: $code, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                    Button {
                        code = UIPasteboard.general.string ?? code
                    } label: {
                        Image(systemName: "doc.on.clipboard")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Coller")
                }
                if needsRelay && !code.isEmpty {
                    TextField("Adresse du relais", text: $relay)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                }
                Button {
                    Task { await pair() }
                } label: {
                    HStack {
                        Text("Appairer")
                        if working { Spacer(); ProgressView() }
                    }
                }
                .disabled(working || code.isEmpty)
            } header: {
                Text("Ou collez le code")
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                    if Keys.simulated {
                        Text("Simulateur : la clé est logicielle, pas dans la Secure Enclave. Pour essai seulement.")
                            .foregroundStyle(.orange)
                    } else {
                        Text("Les clés sont créées dans la puce sécurisée de cet iPhone et ne la quittent jamais. Chaque réponse demande le verrou de l’appareil.")
                    }
                }
            }
        }
        .onAppear {
            if relay.isEmpty {
                relay = (model.remembered.lastRelay ?? RelayAddress.official).absoluteString
            }
        }
        .sheet(isPresented: $scanning) {
            ScanSheet { link in
                code = link
                Task { await pair() }
            }
        }
    }

    /// Reads the machine's hello; the pairing sheet then asks the user to
    /// accept before anything is sent.
    private func pair() async {
        working = true
        error = nil
        defer { working = false }
        do {
            try await model.open(input: code, relayText: relay)
            code = ""
        } catch {
            self.error = "Échec : \(describe(error))."
        }
    }
}

/// Shown once the machine's hello is read, before the phone answers: the
/// relay, the machine and the mode. Any relay but the official one needs
/// an explicit extra step.
struct PairingConsentView: View {
    @EnvironmentObject private var model: Model
    @Environment(\.dismiss) private var dismiss
    let offer: PairingOffer
    @State private var trustRelay = false
    @State private var working = false
    @State private var error: String?

    private var host: String {
        let h = offer.relay.host ?? offer.relay.absoluteString
        return offer.relay.port.map { "\(h):\($0)" } ?? h
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Machine") {
                        Text(offer.label.isEmpty ? "sans nom" : offer.label).bold()
                    }
                    LabeledContent("Mode") {
                        Text(offer.mode == .approve ? "Validation" : "Signature").bold()
                    }
                    Text(offer.mode == .approve
                         ? "L’ordinateur garde sa clé SSH et signe lui-même, une fois que cet iPhone a validé."
                         : "Cet iPhone signera les connexions SSH de cette machine avec sa propre clé.")
                        .font(.footnote).foregroundStyle(.secondary)
                } header: {
                    Text("Appairer cet iPhone ?")
                } footer: {
                    Text("Le nom est celui que la machine se donne : vérifiez qu’il s’agit bien de la machine devant vous.")
                }

                Section {
                    LabeledContent("Relais") {
                        Text(host).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    }
                    if offer.isOfficialRelay {
                        Label("Relais officiel de Clavix", systemImage: "checkmark.shield.fill")
                            .foregroundStyle(Color.accentColor)
                    } else {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Ce n’est pas le relais officiel de Clavix.", systemImage: "exclamationmark.triangle.fill")
                                .font(.subheadline.weight(.semibold))
                            Text("Ce relais verra quand cet iPhone est sollicité et pourra lui envoyer des notifications. N’acceptez que s’il est le vôtre ou celui de votre équipe. Si quelqu’un vous a envoyé ce code ou ce QR code, refusez.")
                                .font(.footnote)
                            Toggle("Je connais ce relais et je lui fais confiance", isOn: $trustRelay)
                                .font(.footnote.weight(.semibold))
                        }
                        .padding(12)
                        .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
                    }
                }

                Section {
                    Button {
                        Task { await accept() }
                    } label: {
                        HStack {
                            Text("Appairer").bold()
                            if working { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(working || !(offer.isOfficialRelay || trustRelay))
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        if let error {
                            Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                        }
                        Text("Six chiffres s’afficheront ensuite, ici et sur la machine : ils doivent être les mêmes.")
                    }
                }
            }
            .navigationTitle("Nouvelle machine")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Annuler") { model.pairingSheet = nil; dismiss() }.disabled(working) }
            .interactiveDismissDisabled(working)
        }
    }

    private func accept() async {
        working = true
        error = nil
        defer { working = false }
        do {
            try await model.accept(offer)
        } catch {
            self.error = "Échec : \(describe(error))."
        }
    }
}

struct Step: View {
    let number: Int
    let text: String

    var body: some View {
        HStack(spacing: 12) {
            Text("\(number)")
                .font(.subheadline.weight(.bold))
                .foregroundStyle(.background)
                .frame(width: 26, height: 26)
                .background(Circle().fill(Color.accentColor))
            Text(text)
        }
    }
}

struct CommandBox: View {
    let text: String
    @State private var copied = false

    var body: some View {
        HStack {
            Text(text)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            Button {
                UIPasteboard.general.string = text
                copied = true
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Copier la commande")
        }
        .padding(10)
        .background(Color(.tertiarySystemFill), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// The digits of a pairing just answered. Until the user says the machine
/// shows the same ones, the pairing accepts no request; once confirmed,
/// what comes next for its mode.
struct PairedView: View {
    @EnvironmentObject private var model: Model
    @Environment(\.dismiss) private var dismiss
    let record: PairingRecord
    @State private var working = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 8) {
                        Image(systemName: record.confirmed ? "checkmark.seal.fill" : "questionmark.diamond")
                            .font(.system(size: 44))
                            .foregroundStyle(Color.accentColor)
                        Text(record.fingerprint)
                            .font(.system(size: 44, weight: .semibold, design: .monospaced))
                            .accessibilityLabel(record.fingerprint.map { String($0) }.joined(separator: " "))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                } header: {
                    Text("Chiffres de vérification")
                } footer: {
                    Text(record.confirmed
                         ? "Confirmés. Confirmez-les aussi sur la machine."
                         : "La machine affiche six chiffres. Comparez-les : s’ils diffèrent, quelqu’un s’est placé entre les deux. Refusez alors ici et sur la machine.")
                }
                if !record.confirmed {
                    Section {
                        Button {
                            run { await model.confirm(record) }
                        } label: {
                            Label("Ce sont les mêmes chiffres", systemImage: "checkmark")
                                .font(.headline)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.borderedProminent)
                        .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 4, trailing: 16))
                        Button(role: .destructive) {
                            run {
                                await model.reject(record)
                                dismiss()
                            }
                        } label: {
                            Text("Les chiffres diffèrent").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 8, trailing: 16))
                    } footer: {
                        Text("Tant que vous n’avez pas confirmé, cette machine ne peut rien demander à cet iPhone.")
                    }
                    .disabled(working)
                } else if record.mode == .approve {
                    Section {
                        Label("Validation seulement", systemImage: "checkmark.shield")
                            .font(.headline)
                        Text("L’ordinateur garde ses clés et signe lui-même, une fois que cet iPhone a validé. Rien à installer sur les serveurs.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Section {
                        if let line = model.publicKeyLine { PublicKeyView(line: line) }
                    } header: {
                        Text("Clé à installer sur les serveurs")
                    } footer: {
                        Text("Ajoutez cette ligne au fichier authorized_keys de chaque compte que cet iPhone doit ouvrir.")
                    }
                }
            }
            .navigationTitle(record.label.isEmpty ? "Appairage" : "Appairage avec \(record.label)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if record.confirmed {
                    Button("Terminé") { model.pairingSheet = nil; dismiss() }.bold()
                } else {
                    // Left for later: the pairing stays unconfirmed, and
                    // its card offers to compare the digits again.
                    Button("Plus tard") { model.pairingSheet = nil; dismiss() }.disabled(working)
                }
            }
            .interactiveDismissDisabled(!record.confirmed)
        }
    }

    private func run(_ work: @escaping () async -> Void) {
        working = true
        Task {
            await work()
            working = false
        }
    }
}

struct PublicKeyView: View {
    let line: String
    @State private var copied = false

    var body: some View {
        // The whole line, never truncated: it is what goes in authorized_keys.
        Text(line)
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        HStack {
            Button {
                UIPasteboard.general.string = line
                withAnimation { copied = true }
                Task {
                    try? await Task.sleep(for: .seconds(2))
                    withAnimation { copied = false }
                }
            } label: {
                Label(copied ? "Copiée" : "Copier", systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.bordered)
            .sensoryFeedback(.success, trigger: copied) { _, new in new }
            .accessibilityHint(copied ? "Clé copiée dans le presse-papiers" : "")
            Spacer()
            ShareLink(item: line) { Label("Partager", systemImage: "square.and.arrow.up") }
                .buttonStyle(.bordered)
        }
    }
}

// ---- requests ----

struct RequestsView: View {
    @EnvironmentObject private var model: Model
    @EnvironmentObject private var subscriptions: Subscriptions

    var body: some View {
        List {
            if RelaySubscription.shouldPrompt(status: subscriptions.status, pairings: model.pairings) {
                Section { SubscriptionBanner() }
                    .listRowBackground(Color.accentColor.opacity(0.12))
            }
            Section {
                ForEach(model.pairings) { p in MachineCard(pairing: p) }
            }
            if model.requests.isEmpty {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 48, weight: .light))
                            .foregroundStyle(Color.accentColor)
                        Text("Aucune demande en attente").font(.headline)
                        Text("Les demandes de vos machines apparaîtront ici, et ne passeront qu’avec le verrou de cet iPhone.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 24)
                }
                .listRowBackground(Color.clear)
            }
            ForEach(model.requests) { r in
                Section { RequestCard(request: r) }
            }
        }
        .listSectionSpacing(.compact)
        .refreshable { model.start() }
    }
}

struct MachineCard: View {
    @EnvironmentObject private var model: Model
    let pairing: PairingRecord

    private var state: MachineState { model.state(of: pairing) }
    private var waiting: Int { model.requests.filter { $0.record.id == pairing.id }.count }
    private var stateText: String {
        if !pairing.confirmed { return "À confirmer : comparez les chiffres" }
        if !state.text.isEmpty { return state.text }
        return waiting == 0 ? "Prêt" : waiting == 1 ? "1 demande en attente" : "\(waiting) demandes en attente"
    }
    private var dotColor: Color { !pairing.confirmed ? .orange : state.isError ? .red : .green }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: pairing.mode == .approve ? "macbook.and.iphone" : "desktopcomputer")
                .font(.title2)
                .foregroundStyle(Color.accentColor)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 4) {
                Text(pairing.label.isEmpty ? "Machine sans nom" : pairing.label).font(.headline)
                Text(pairing.mode == .approve ? "Clavix — validation des signatures" : "clavix-agent — signature par cet iPhone")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Circle()
                        .fill(dotColor)
                        .frame(width: 8, height: 8)
                    Text(stateText)
                        .font(.subheadline)
                        .foregroundStyle(state.isError && pairing.confirmed ? .red : .secondary)
                }
                if let issue = model.entitlementIssue(of: pairing) {
                    Label(issue, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                if !pairing.confirmed {
                    Button("Voir les chiffres") { model.pairingSheet = .digits(pairing) }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct RequestCard: View {
    @EnvironmentObject private var model: Model
    let request: PendingRequest
    @State private var newName = ""
    @State private var error: String?

    private var view: VerifiedRequest { request.view }
    private var dest: Hop { view.destination }
    private var known: String? { model.name(of: dest.fingerprint) }
    private var user: String { view.user ?? "(utilisateur illisible)" }
    private var busy: Bool { model.busy.contains(request.id) }
    private var remaining: Double { max(0, Double(request.entry.exp) - model.now.timeIntervalSince1970) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: known == nil ? "questionmark.diamond.fill" : "server.rack")
                    .font(.title2)
                    .foregroundStyle(known == nil ? Color.orange : Color.accentColor)
                    .frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(request.record.mode == .approve
                         ? "Connexion SSH depuis Clavix — \(Model.machineName(request.record))"
                         : "Connexion SSH — \(Model.machineName(request.record))")
                        .font(.caption).foregroundStyle(.secondary)
                    Text(known.map { "\(user)@\($0)" } ?? "\(user)@ hôte inconnu")
                        .font(.title3.weight(.semibold))
                        .lineLimit(2)
                }
                Spacer()
                Countdown(remaining: remaining)
            }

            Text(dest.fingerprint)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            if let key = view.requesterKey {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Clé : \(key.name ?? "sans nom") (\(key.type))", systemImage: "key.horizontal")
                    Text(key.fingerprint).font(.system(.caption2, design: .monospaced))
                    Text("Indiquée par l’ordinateur, qui signera lui-même après votre validation.")
                        .foregroundStyle(.secondary)
                }
                .font(.footnote)
            }

            if known == nil { unknownHost }

            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(view.hops.dropLast().enumerated()), id: \.offset) { _, hop in
                    Label("Via l’agent transféré à \(model.name(of: hop.fingerprint) ?? "hôte inconnu \(hop.fingerprint)")",
                          systemImage: "arrow.triangle.branch")
                }
                Label("\(callerText), sur \(view.agent ?? "machine sans nom") — non vérifié", systemImage: "terminal")
                    .foregroundStyle(.secondary)
            }
            .font(.footnote)

            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill").font(.footnote).foregroundStyle(.red)
            }

            HStack(spacing: 12) {
                Button(role: .destructive) {
                    run { try await model.deny(request) }
                } label: {
                    // Unknown host: the approve title is long, so "Refuser"
                    // keeps its natural width and leaves it the room.
                    Text("Refuser").lineLimit(1).frame(maxWidth: known == nil ? nil : .infinity)
                }
                .buttonStyle(.bordered)
                Button {
                    run { try await model.approve(request, newName: newName) }
                } label: {
                    // Explicit icon and colour: left to the button style, the
                    // symbol took the tint and vanished into the background.
                    HStack(spacing: 6) {
                        Image(systemName: "lock.open.fill")
                        Text(approveTitle).lineLimit(1).minimumScaleFactor(0.8)
                    }
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
            .controlSize(.large)
            .disabled(busy)
        }
        .padding(.vertical, 6)
    }

    private var approveTitle: String {
        let verb = request.record.mode == .approve ? "Valider" : "Approuver"
        return known == nil ? "\(verb) et retenir" : verb
    }

    private var callerText: String {
        guard let c = view.caller, c.name != nil || c.pid != nil else { return "Demandé par un processus inconnu" }
        return "Demandé par " + (c.name ?? "un processus") + (c.pid.map { " (pid \($0))" } ?? "")
    }

    @ViewBuilder private var unknownHost: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Cet iPhone n’a jamais approuvé ce serveur.", systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline.weight(.semibold))
            Text("Vérifiez l’empreinte ci-dessus avant de continuer. Si vous approuvez, ce serveur sera retenu sous le nom que vous lui donnez.")
                .font(.footnote)
            if let hint = view.hints[dest.fingerprint] {
                // Offered, never filled in: taking the machine's word stays a gesture.
                HStack {
                    Text("Nom indiqué par la machine (non vérifié) : \(hint)").font(.footnote).foregroundStyle(.secondary)
                    Spacer()
                    Button("Utiliser") { newName = String(hint.prefix(64)) }.buttonStyle(.bordered).controlSize(.small)
                }
            }
            TextField("Nom à retenir pour ce serveur", text: $newName)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
        }
        .padding(12)
        .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
    }

    private func run(_ work: @escaping () async throws -> Void) {
        error = nil
        Task {
            do { try await work() } catch { self.error = "Échec : \(describe(error))." }
        }
    }
}

/// Seconds left before the request expires. The ring is drawn against
/// the agent's default expiry, 90 s.
struct Countdown: View {
    let remaining: Double
    private var fraction: Double { min(1, remaining / 90) }

    var body: some View {
        ZStack {
            Circle().stroke(Color(.tertiarySystemFill), lineWidth: 4)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(remaining < 15 ? Color.red : Color.accentColor, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
            Text("\(Int(remaining.rounded(.up)))")
                .font(.caption.weight(.semibold))
                .monospacedDigit()
        }
        .frame(width: 40, height: 40)
        .accessibilityLabel("\(Int(remaining.rounded(.up))) secondes restantes")
    }
}

// ---- settings ----

struct SettingsView: View {
    @EnvironmentObject private var model: Model
    @State private var forgetting: PairingRecord?

    var body: some View {
        Form {
            if let line = model.publicKeyLine {
                Section {
                    PublicKeyView(line: line)
                } header: {
                    Text("Clé SSH de cet iPhone")
                } footer: {
                    Text(Keys.simulated
                         ? "Clé logicielle (simulateur)."
                         : "Dans la puce sécurisée de l’iPhone ; chaque signature demande le verrou de l’appareil.")
                }
            }
            Section {
                if model.pairings.isEmpty { Text("Aucune.").foregroundStyle(.secondary) }
                ForEach(model.pairings) { p in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(Model.machineName(p)).bold()
                        Text(p.mode == .approve ? "Validation (Clavix)" : "Signature (clavix-agent)")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("Chiffres \(p.fingerprint)\(p.confirmed ? "" : " (non confirmés)") · relais \(p.relay.host ?? p.relay.absoluteString)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .swipeActions { Button("Oublier", role: .destructive) { forgetting = p } }
                    .contextMenu { Button("Oublier cette machine", role: .destructive) { forgetting = p } }
                }
            } header: {
                Text("Machines appairées")
            } footer: {
                Text("Glissez vers la gauche pour oublier une machine : cet iPhone est retiré du relais et n’en reçoit plus de demandes. En mode signature, la clé reste valable sur les serveurs qui la listent ; retirez-la aussi de leur authorized_keys.")
            }
            SubscriptionSection()
            Section("Serveurs retenus") {
                if model.remembered.pins.isEmpty { Text("Aucun.").foregroundStyle(.secondary) }
                ForEach(model.remembered.pins.sorted(by: { $0.value < $1.value }), id: \.key) { fp, name in
                    VStack(alignment: .leading) {
                        Label(name, systemImage: "server.rack").bold()
                        Text(fp).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    .swipeActions { Button("Oublier", role: .destructive) { model.forget(pin: fp) } }
                }
            }
            Section("Journal") {
                if model.remembered.journal.isEmpty { Text("Vide.").foregroundStyle(.secondary) }
                ForEach(model.remembered.journal) { e in
                    VStack(alignment: .leading) {
                        Text(e.text)
                        Text(e.at.formatted(date: .abbreviated, time: .standard)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Section {
                HStack(spacing: 14) {
                    Logo(size: 52)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Clavix Approve").font(.headline)
                        Text(versionText).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
                Link(destination: Links.site) { Label("Site de Clavix", systemImage: "globe") }
                Link(destination: Links.source) { Label("Code source", systemImage: "chevron.left.forwardslash.chevron.right") }
                Link(destination: Links.threatModel) { Label("Modèle de menace", systemImage: "shield.lefthalf.filled") }
            } header: {
                Text("À propos")
            } footer: {
                Text("Clavix Approve fait partie de Clavix, client de bureau pour Vaultwarden et Bitwarden.")
            }
        }
        .navigationTitle("Réglages")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Oublier \(forgetting.map(Model.machineName) ?? "cette machine") ?",
                            isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
                            titleVisibility: .visible) {
            Button("Oublier", role: .destructive) {
                if let p = forgetting { Task { await model.forget(machine: p) } }
            }
        } message: {
            Text("Elle ne pourra plus rien demander à cet iPhone. Pour la retrouver, il faudra appairer à nouveau.")
        }
    }

    private var versionText: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "Version \(v) (\(b))" + (Keys.simulated ? " — simulateur" : "")
    }
}
