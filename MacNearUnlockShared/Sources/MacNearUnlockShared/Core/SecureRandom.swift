import Foundation
import Security

public enum SecureRandom {
    /// Cryptographically secure random bytes from the system CSPRNG.
    ///
    /// Traps if the system generator fails: continuing with predictable nonces or
    /// keys would silently break every security property built on them.
    public static func bytes(_ count: Int) -> Data {
        precondition(count > 0 && count <= 4096, "Unreasonable random byte count")
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let base = buffer.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return data
    }
}

public enum ConstantTime {
    /// Compares two byte strings without an early exit on the first difference.
    /// The length is treated as public (all compared values have fixed, known sizes).
    public static func equals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return lhs.withUnsafeBytes { a in
            rhs.withUnsafeBytes { b in
                var difference: UInt8 = 0
                for index in 0..<a.count {
                    difference |= a[index] ^ b[index]
                }
                return difference == 0
            }
        }
    }
}

extension Data {
    /// Lowercase hex, for diagnostics of *public* values only (never secrets).
    public var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Overwrites the buffer with zeros. Best effort: copies made earlier by
    /// Foundation or the caller are not reachable from here.
    public mutating func wipe() {
        resetBytes(in: 0..<count)
    }
}

extension UUID {
    /// The 16 raw bytes, in RFC 4122 order.
    public var rawBytes: Data {
        withUnsafeBytes(of: uuid) { Data($0) }
    }

    /// First 8 hex characters — enough to correlate log lines without logging
    /// complete identifiers.
    public var shortID: String {
        String(uuidString.prefix(8))
    }
}
