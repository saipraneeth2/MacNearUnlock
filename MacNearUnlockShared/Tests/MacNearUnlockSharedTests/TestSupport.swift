import Foundation
@testable import MacNearUnlockShared

/// Manually advanced monotonic + wall clock.
final class ManualClock: MonotonicClock, WallClock, @unchecked Sendable {
    private let lock = NSLock()
    private var mono: UInt64 = 1_000_000_000
    private var wallDate = Date(timeIntervalSince1970: 1_800_000_000)

    func now() -> MonotonicInstant { lock.withLock { MonotonicInstant(nanoseconds: mono) } }
    func now() -> Date { lock.withLock { wallDate } }

    func advance(_ seconds: TimeInterval) {
        lock.withLock {
            mono += UInt64(seconds * 1_000_000_000)
            wallDate = wallDate.addingTimeInterval(seconds)
        }
    }

    /// Moves only the wall clock (simulates the user changing the date).
    func shiftWall(_ seconds: TimeInterval) {
        lock.withLock { wallDate = wallDate.addingTimeInterval(seconds) }
    }
}

struct FixedWall: WallClock {
    let date: Date
    func now() -> Date { date }
}

final class FakeSessionProvider: SessionStateProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var current: SessionSnapshot

    init(_ snapshot: SessionSnapshot) { current = snapshot }

    func snapshot() -> SessionSnapshot { lock.withLock { current } }
    func set(_ snapshot: SessionSnapshot) { lock.withLock { current = snapshot } }
}

enum Fixtures {
    static let user = "alice"
    static let uid: UInt32 = 501

    static func session(locked: Bool, user: String = user, uid: UInt32 = uid, onConsole: Bool = true) -> SessionSnapshot {
        SessionSnapshot(isAvailable: true, isScreenLocked: locked, isOnConsole: onConsole, isLoginDone: true, userName: user, userID: uid)
    }

    static func device(signer: SoftwareP256Signer, name: String = "Test iPhone", channelKey: Data = SecureRandom.bytes(32)) -> PairedDeviceRecord {
        PairedDeviceRecord(pairingID: UUID(), deviceID: UUID(), deviceName: name, publicKey: signer.publicKeyX963, channelKey: channelKey, pairedAtMillis: 0)
    }

    static func pinned(for device: PairedDeviceRecord, macID: UUID, macSigner: MessageSigner, macName: String = "Mac mini") -> PinnedMac {
        PinnedMac(pairingID: device.pairingID, macID: macID, macName: macName, macUsername: user, macPublicKey: macSigner.publicKeyX963, deviceID: device.deviceID, pairedAtMillis: 0)
    }
}

/// Signer that behaves like a cancelled / failed Face ID prompt.
final class FailingSigner: MessageSigner, @unchecked Sendable {
    struct Cancelled: Error {}
    let publicKeyX963: Data
    init(publicKey: Data) { publicKeyX963 = publicKey }
    func sign(_ message: Data, reason: String) async throws -> Data { throw Cancelled() }
}

/// Wraps a signer and counts signatures (to prove one biometric signature per approval).
final class CountingSigner: MessageSigner, @unchecked Sendable {
    private let inner: SoftwareP256Signer
    private let lock = NSLock()
    private var count = 0
    var signatures: Int { lock.withLock { count } }
    var publicKeyX963: Data { inner.publicKeyX963 }
    init(_ inner: SoftwareP256Signer = SoftwareP256Signer()) { self.inner = inner }
    func sign(_ message: Data, reason: String) async throws -> Data {
        lock.withLock { count += 1 }
        return try await inner.sign(message, reason: reason)
    }
}

func approval(for signed: SignedUnlockRequest, signer: MessageSigner) async throws -> UnlockApproval {
    let signature = try await signer.sign(signed.request.approvalSigningBytes(), reason: "test")
    return UnlockApproval(requestID: signed.request.requestID, pairingID: signed.request.pairingID, deviceID: signed.request.deviceID, signature: signature)
}

/// Identity equality so `Result<VerifiedApproval, ApprovalRejection>` can be compared in assertions.
extension VerifiedApproval: Equatable {
    public static func == (lhs: VerifiedApproval, rhs: VerifiedApproval) -> Bool { lhs === rhs }
}
