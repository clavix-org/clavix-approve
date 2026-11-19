// Reads the QR code that `clavix-agent pair` prints. Its payload is the
// pairing link `clavix-approve://pair?relay=<relay>#cva2-…`, which
// PairingCode accepts (https relays only, or http on loopback): one scan
// fills in both the code and the relay.

import ClavixCore
import SwiftUI
import VisionKit

struct QRScanner: UIViewControllerRepresentable {
    /// Called once, with the first pairing link seen.
    let found: (String) -> Void

    static var isAvailable: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        if !scanner.isScanning { try? scanner.startScanning() }
    }

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        scanner.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let found: (String) -> Void
        private var done = false
        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for case .barcode(let code) in items {
                // Any other QR code is ignored: only a pairing link is taken.
                guard let text = code.payloadStringValue, (try? PairingCode(text))?.relay != nil else { continue }
                done = true
                scanner.stopScanning()
                found(text)
                return
            }
        }
    }
}

struct ScanSheet: View {
    @Environment(\.dismiss) private var dismiss
    let found: (String) -> Void

    var body: some View {
        NavigationStack {
            QRScanner { text in
                found(text)
                dismiss()
            }
            .ignoresSafeArea()
            .navigationTitle("QR code d’appairage")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Annuler") { dismiss() } }
        }
    }
}
