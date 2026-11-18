import ClavixCore
import SwiftUI

enum Links {
    static let site = URL(string: "https://clavix.org")!
    static let source = URL(string: "https://github.com/clavix-org/clavix-approve")!
    static let threatModel = URL(string: "https://github.com/clavix-org/clavix-approve/blob/master/THREAT_MODEL.md")!
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
        .sheet(item: $model.justPaired) { record in PairedView(record: record) }
        .onChange(of: model.justPaired?.id) { _, id in if id != nil { addingMachine = false } }
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

    private var needsRelay: Bool { !code.contains("#" + PairingCode.prefix) }

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
                Step(number: 2, text: "Scannez le QR code qu’elle affiche.")
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
                    TextField("cva1-…", text: $code, axis: .vertical)
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
        .onAppear { if relay.isEmpty { relay = model.remembered.lastRelay?.absoluteString ?? "" } }
        .sheet(isPresented: $scanning) {
            ScanSheet { link in
                code = link
                Task { await pair() }
            }
        }
    }

    private func pair() async {
        working = true
        error = nil
        defer { working = false }
        do {
            try await model.pair(input: code, relayText: relay)
            code = ""
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

struct PairedView: View {
    @EnvironmentObject private var model: Model
    @Environment(\.dismiss) private var dismiss
    let record: PairingRecord

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 8) {
                        Image(systemName: "checkmark.seal.fill")
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
                    Text("La machine doit afficher les mêmes six chiffres. S’ils diffèrent, refusez sur la machine : quelqu’un s’est placé entre les deux.")
                }
                if record.mode == .approve {
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
            .navigationTitle(record.label.isEmpty ? "Appairé" : "Appairé à \(record.label)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Terminé") { model.justPaired = nil; dismiss() }.bold() }
        }
    }
}

struct PublicKeyView: View {
    let line: String

    var body: some View {
        Text(line)
            .font(.system(.footnote, design: .monospaced))
            .textSelection(.enabled)
            .lineLimit(4)
        HStack {
            Button {
                UIPasteboard.general.string = line
            } label: {
                Label("Copier", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)
            Spacer()
            ShareLink(item: line) { Label("Partager", systemImage: "square.and.arrow.up") }
                .buttonStyle(.bordered)
        }
    }
}

// ---- requests ----

struct RequestsView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        List {
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
        if !state.text.isEmpty { return state.text }
        return waiting == 0 ? "Prêt" : waiting == 1 ? "1 demande en attente" : "\(waiting) demandes en attente"
    }

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
                        .fill(state.isError ? Color.red : Color.green)
                        .frame(width: 8, height: 8)
                    Text(stateText)
                        .font(.subheadline)
                        .foregroundStyle(state.isError ? .red : .secondary)
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
                    Text("Refuser").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                Button {
                    run { try await model.approve(request, newName: newName) }
                } label: {
                    Label(approveTitle, systemImage: "lock.open.fill")
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
                        Text("Chiffres \(p.fingerprint) · relais \(p.relay.host ?? p.relay.absoluteString)")
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
