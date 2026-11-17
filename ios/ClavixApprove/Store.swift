// What the app remembers besides its keys: the hosts the user named
// (pinned by host key fingerprint), the relay last used, and a short
// journal. A file of the app's own container, protected by the device's
// data protection.

import Foundation

struct Remembered: Codable {
    /// Host key fingerprint → name chosen on this device.
    var pins: [String: String] = [:]
    var lastRelay: URL?
    var journal: [JournalEntry] = []
}

struct JournalEntry: Codable, Identifiable, Hashable {
    var id = UUID()
    let at: Date
    let text: String
}

enum Store {
    static let journalSize = 60

    private static var url: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("remembered.json")
    }

    static func load() -> Remembered {
        guard let data = try? Data(contentsOf: url) else { return Remembered() }
        return (try? JSONDecoder().decode(Remembered.self, from: data)) ?? Remembered()
    }

    static func save(_ r: Remembered) {
        guard let data = try? JSONEncoder().encode(r) else { return }
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
