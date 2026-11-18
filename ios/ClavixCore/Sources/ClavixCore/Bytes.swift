// Byte helpers: the Swift twin of web/lib/bytes.js and of the SSH string
// encoding in web/lib/ssh.js.

import CryptoKit
import Foundation

public enum CoreError: Error, Equatable, CustomStringConvertible {
    case malformed(String)
    case crypto(String)

    public var description: String {
        switch self {
        case .malformed(let what): return what
        case .crypto(let what): return what
        }
    }
}

extension Data {
    /// base64url without padding.
    public var b64u: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Standard base64 without padding, as `ssh-keygen -l` prints it.
    var b64NoPadding: String {
        base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    /// Strict base64url (no padding, no other character), like `unb64u`.
    public init(b64u text: String) throws {
        guard text.unicodeScalars.allSatisfy({ c in
            ("A"..."Z").contains(c) || ("a"..."z").contains(c) || ("0"..."9").contains(c) || c == "-" || c == "_"
        }) else { throw CoreError.malformed("not base64url") }
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        switch s.count % 4 {
        case 0: break
        case 2: s += "=="
        case 3: s += "="
        default: throw CoreError.malformed("not base64url")
        }
        guard let d = Data(base64Encoded: s) else { throw CoreError.malformed("not base64url") }
        self = d
    }

    public var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex text: String) {
        guard text.count % 2 == 0 else { return nil }
        var out = Data(capacity: text.count / 2)
        var it = text.makeIterator()
        while let a = it.next(), let b = it.next() {
            guard let byte = UInt8(String([a, b]), radix: 16) else { return nil }
            out.append(byte)
        }
        self = out
    }

    static func random(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
    }

    var sha256: Data { Data(SHA256.hash(data: self)) }
}

func utf8(_ s: String) -> Data { Data(s.utf8) }

/// Constant time for equal lengths.
func equal(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}

/// SSH `string`: 4-byte big-endian length, then the bytes.
func sshString(_ bytes: Data) -> Data {
    let n = UInt32(bytes.count)
    return Data([UInt8(n >> 24), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)]) + bytes
}

func sshString(_ s: String) -> Data { sshString(utf8(s)) }

/// Reads the SSH wire format; every read throws on truncation.
struct Reader {
    private let bytes: [UInt8]
    private(set) var pos = 0

    init(_ data: Data) { bytes = [UInt8](data) }

    mutating func u8() throws -> UInt8 {
        guard pos < bytes.count else { throw CoreError.malformed("truncated") }
        defer { pos += 1 }
        return bytes[pos]
    }

    mutating func u32() throws -> Int {
        guard pos + 4 <= bytes.count else { throw CoreError.malformed("truncated") }
        let n = bytes[pos..<pos + 4].reduce(0) { ($0 << 8) | Int($1) }
        pos += 4
        return n
    }

    mutating func string() throws -> Data {
        let len = try u32()
        guard len <= bytes.count - pos else { throw CoreError.malformed("truncated") }
        defer { pos += len }
        return Data(bytes[pos..<pos + len])
    }

    mutating func text() throws -> String {
        guard let s = String(data: try string(), encoding: .utf8) else { throw CoreError.malformed("not UTF-8") }
        return s
    }

    var done: Bool { pos == bytes.count }
}
