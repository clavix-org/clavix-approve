import ClavixCore
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        NavigationStack {
            Group {
                if model.pairing == nil {
                    PairView()
                } else {
                    RequestsView()
                }
            }
            .navigationTitle("Clavix")
            .toolbar {
                NavigationLink { SettingsView() } label: { Image(systemName: "gearshape") }
                    .accessibilityLabel("Réglages")
            }
        }
        .sheet(item: $model.justPaired) { record in PairedView(record: record) }
    }
}

extension PairingRecord: @retroactive Identifiable {
    public var id: String { ch + signer }
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
                Text("Sur la machine, lancez `clavix-agent pair` (ou `pair --add` pour garder la page web comme second appareil), puis scannez le QR code qu’il affiche, ou collez le code.")
                    .font(.callout)
                if QRScanner.isAvailable {
                    Button {
                        scanning = true
                    } label: {
                        Label("Scanner le QR code", systemImage: "qrcode.viewfinder")
                    }
                }
            }
            Section("Code d’appairage") {
                TextField("cva1-… ou https://…/#cva1-…", text: $code, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                Button("Coller") { code = UIPasteboard.general.string ?? code }
            }
            if needsRelay {
                Section {
                    TextField("relais.example.org", text: $relay)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("Adresse du relais")
                } footer: {
                    Text("Inutile si vous collez le lien complet.")
                }
            }
            Section {
                Button {
                    Task { await pair() }
                } label: {
                    HStack {
                        Text(model.keyBlob == nil ? "Créer la clé et appairer" : "Appairer")
                        if working { Spacer(); ProgressView() }
                    }
                }
                .disabled(working || code.isEmpty)
                if let error { Text(error).foregroundStyle(.red) }
            } footer: {
                if Keys.simulated {
                    Text("Simulateur : la clé est logicielle, pas dans la Secure Enclave. Pour essai seulement.")
                        .foregroundStyle(.orange)
                } else if model.keyBlob == nil {
                    Text("La clé SSH sera créée dans la puce sécurisée de cet iPhone et ne la quittera jamais. Chaque signature demandera le verrou de l’appareil.")
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

struct PairedView: View {
    @EnvironmentObject private var model: Model
    @Environment(\.dismiss) private var dismiss
    let record: PairingRecord

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(record.fingerprint)
                        .font(.system(size: 44, weight: .semibold, design: .monospaced))
                        .frame(maxWidth: .infinity)
                        .accessibilityLabel(record.fingerprint.map { String($0) }.joined(separator: " "))
                } header: {
                    Text("Chiffres de vérification")
                } footer: {
                    Text("L’agent doit afficher les mêmes six chiffres. S’ils diffèrent, refusez sur l’agent : quelqu’un s’est placé entre les deux.")
                }
                Section {
                    if let line = model.publicKeyLine { PublicKeyView(line: line) }
                } header: {
                    Text("Clé à installer sur les serveurs")
                } footer: {
                    Text("Ajoutez cette ligne au fichier authorized_keys de chaque compte que cet iPhone doit ouvrir.")
                }
            }
            .navigationTitle(record.label.isEmpty ? "Appairé" : "Appairé à \(record.label)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Terminé") { dismiss() } }
        }
    }
}

struct PublicKeyView: View {
    let line: String

    var body: some View {
        Text(line)
            .font(.system(.footnote, design: .monospaced))
            .textSelection(.enabled)
        Button("Copier la clé") { UIPasteboard.general.string = line }
        ShareLink(item: line) { Text("Partager la clé") }
    }
}

// ---- requests ----

struct RequestsView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        List {
            if !model.status.isEmpty {
                Text(model.status)
                    .font(.callout)
                    .foregroundStyle(model.statusIsError ? .red : .secondary)
            }
            if model.requests.isEmpty {
                Text("Aucune demande en attente.").foregroundStyle(.secondary)
            }
            ForEach(model.requests) { r in RequestCard(request: r) }
        }
        .refreshable { model.start() }
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
    private var secondsLeft: Int { max(0, Int((Double(request.entry.exp) - model.now.timeIntervalSince1970).rounded(.up))) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(known.map { "\(user)@\($0)" } ?? "\(user)@ hôte inconnu")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("\(secondsLeft) s").monospacedDigit().foregroundStyle(.secondary)
            }
            Text(dest.fingerprint).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)

            if known == nil { unknownHost }

            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(view.hops.dropLast().enumerated()), id: \.offset) { _, hop in
                    Text("Via l’agent transféré à \(model.name(of: hop.fingerprint) ?? "hôte inconnu \(hop.fingerprint)")")
                }
                Text("Demandé par \(callerText), sur \(view.agent ?? "machine sans nom") — non vérifié")
                    .foregroundStyle(.secondary)
            }
            .font(.footnote)

            if let error { Text(error).font(.footnote).foregroundStyle(.red) }

            HStack {
                Button("Refuser", role: .destructive) { run { try await model.deny(request) } }
                    .buttonStyle(.bordered)
                Spacer()
                Button(known == nil ? "Faire confiance et approuver" : "Approuver") {
                    run { try await model.approve(request, newName: newName) }
                }
                .buttonStyle(.borderedProminent)
            }
            .disabled(busy)
        }
        .padding(.vertical, 6)
    }

    private var callerText: String {
        guard let c = view.caller, c.name != nil || c.pid != nil else { return "inconnu" }
        return (c.name ?? "processus") + (c.pid.map { " (pid \($0))" } ?? "")
    }

    @ViewBuilder private var unknownHost: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Cet iPhone n’a jamais approuvé ce serveur.").bold()
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
        .padding(10)
        .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 10))
    }

    private func run(_ work: @escaping () async throws -> Void) {
        error = nil
        Task {
            do { try await work() } catch { self.error = "Échec : \(describe(error))." }
        }
    }
}

// ---- settings ----

struct SettingsView: View {
    @EnvironmentObject private var model: Model
    @State private var confirmForget = false

    var body: some View {
        Form {
            if let line = model.publicKeyLine {
                Section("Clé SSH de cet iPhone") { PublicKeyView(line: line) }
            }
            if let p = model.pairing {
                Section {
                    LabeledContent("Machine", value: p.label.isEmpty ? "sans nom" : p.label)
                    LabeledContent("Chiffres de vérification", value: p.fingerprint)
                    LabeledContent("Relais", value: p.relay.host ?? p.relay.absoluteString)
                    Button("Oublier cette machine", role: .destructive) { confirmForget = true }
                } header: {
                    Text("Appairage")
                } footer: {
                    Text("Oublier retire cet iPhone du relais : il ne recevra plus de demandes. La clé reste valable sur les serveurs qui la listent ; retirez-la aussi de leur authorized_keys.")
                }
            }
            Section("Serveurs retenus") {
                if model.remembered.pins.isEmpty { Text("Aucun.").foregroundStyle(.secondary) }
                ForEach(model.remembered.pins.sorted(by: { $0.value < $1.value }), id: \.key) { fp, name in
                    VStack(alignment: .leading) {
                        Text(name).bold()
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
                Text(versionText).font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Réglages")
        .confirmationDialog("Oublier cette machine ?", isPresented: $confirmForget, titleVisibility: .visible) {
            Button("Oublier", role: .destructive) { Task { await model.forgetMachine() } }
        } message: {
            Text("Elle ne pourra plus rien demander à cet iPhone. Pour la retrouver, il faudra appairer à nouveau.")
        }
    }

    private var versionText: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "Clavix Approve \(v) (\(b))" + (Keys.simulated ? " — simulateur, clé logicielle" : "")
    }
}
