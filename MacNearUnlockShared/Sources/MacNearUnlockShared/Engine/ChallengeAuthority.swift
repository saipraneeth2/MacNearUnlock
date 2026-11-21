import Foundation

/// A trusted iPhone as stored on the Mac (Keychain, integrity-protected).
public struct PairedDeviceRecord: Codable, Equatable, Sendable, Identifiable {
    public let pairingID: UUID
    public let deviceID: UUID
    public var deviceName: String
    /// Pinned Secure Enclave public key (X9.63) whose signatures approve requests.
    public let publicKey: Data
    /// 256-bit per-pairing secret used as the TLS-PSK and for hello binders. Secret.
    public let channelKey: Data
    public let pairedAtMillis: UInt64

    public var id: UUID { pairingID }
    public var pskIdentity: String { "mnu1:" + pairingID.uuidString }

    public init(pairingID: UUID, deviceID: UUID, deviceName: String, publicKey: Data, channelKey: Data, pairedAtMillis: UInt64) {
        self.pairingID = pairingID
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.publicKey = publicKey
        self.channelKey = channelKey
        self.pairedAtMillis = pairedAtMillis
    }
}

extension PairedDeviceRecord: CustomStringConvertible, CustomDebugStringConvertible {
    /// Never prints the channel key.
    public var description: String {
        "PairedDevice(\(pairingID.shortID), \(deviceName), key \(KeyFingerprint.display(publicKey).prefix(9)))"
    }
    public var debugDescription: String { description }
}

public enum ApprovalRejection: Error, Equatable, Sendable {
    /// No challenge with this ID was ever issued (or it was issued long ago).
    case unsolicited
    /// The challenge was already consumed, declined, invalidated or expired.
    case replayed
    /// Approval arrived over another pairing's connection or names another device.
    case wrongDevice
    /// The device's pairing has been revoked.
    case revoked
    case expired
    case badSignature
    /// `.unlockSession` approvals require the expected user's locked console session.
    case sessionNotLocked
    case sessionUnavailable

    public var displayText: String {
        switch self {
        case .unsolicited: return "No matching request was issued"
        case .replayed: return "Request already used or withdrawn"
        case .wrongDevice: return "Approval came from a different device"
        case .revoked: return "Device pairing was revoked"
        case .expired: return "Request expired"
        case .badSignature: return "Signature verification failed"
        case .sessionNotLocked: return "Mac session is not locked for this user"
        case .sessionUnavailable: return "Mac session unavailable"
        }
    }
}

/// Proof that one specific challenge received a valid, fresh approval. Only
/// `ChallengeAuthority` can create one (internal initializer), so downstream code —
/// notably the experimental credential adapter — cannot run without it.
public final class VerifiedApproval: @unchecked Sendable {
    public let request: UnlockRequest
    public let verifiedAt: MonotonicInstant
    private let lock = NSLock()
    private var consumed = false

    init(request: UnlockRequest, verifiedAt: MonotonicInstant) {
        self.request = request
        self.verifiedAt = verifiedAt
    }

    public var requestID: UUID { request.requestID }
    public var action: UnlockAction { request.action }
    public var pairingID: UUID { request.pairingID }

    /// Returns true exactly once. Any consumer that performs an action must call
    /// this first, so one approval can never drive two actions.
    public func consume() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !consumed else { return false }
        consumed = true
        return true
    }

    public var isConsumed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return consumed
    }
}

public enum ChallengeIssueError: Error, Equatable, Sendable {
    case rateLimited
}

/// Mac-side issuer and verifier of single-use challenges.
///
/// Verification of an approval checks, in order: the challenge exists and is still
/// pending (else unsolicited/replayed); it was issued to the authenticated pairing
/// and device; the pairing is not revoked; the monotonic deadline and wall-clock
/// expiry have not passed; the DER signature verifies under the pinned device key
/// over signing bytes rebuilt from the Mac's own copy of the request; and the
/// current session still matches the action. Success consumes the challenge.
public final class ChallengeAuthority: @unchecked Sendable {
    public struct Configuration: Sendable {
        public var lifetime: TimeInterval
        public var maxIssuesPerMinutePerDevice: Int
        public var maxBadSignaturesPerRequest: Int

        public init(lifetime: TimeInterval = MNUProtocol.defaultApprovalLifetime, maxIssuesPerMinutePerDevice: Int = 6, maxBadSignaturesPerRequest: Int = 3) {
            self.lifetime = min(max(lifetime, MNUProtocol.approvalLifetimeRange.lowerBound), MNUProtocol.approvalLifetimeRange.upperBound)
            self.maxIssuesPerMinutePerDevice = maxIssuesPerMinutePerDevice
            self.maxBadSignaturesPerRequest = maxBadSignaturesPerRequest
        }
    }

    private struct Pending {
        let signed: SignedUnlockRequest
        let deadline: MonotonicInstant
        var badSignatures: Int
    }

    public let macID: UUID
    public let macName: String
    private let signer: MessageSigner
    private let monotonic: MonotonicClock
    private let wall: WallClock

    private let lock = NSLock()
    private var configuration: Configuration
    private var pending: [UUID: Pending] = [:]
    private var retired: [UUID: MonotonicInstant] = [:]
    private var recentNonces: [Data: MonotonicInstant] = [:]
    private var issueLimiter: SlidingWindowLimiter<UUID>

    public init(macID: UUID, macName: String, signer: MessageSigner, configuration: Configuration = Configuration(), monotonic: MonotonicClock = SystemMonotonicClock(), wall: WallClock = SystemWallClock()) {
        self.macID = macID
        self.macName = macName
        self.signer = signer
        self.configuration = configuration
        self.monotonic = monotonic
        self.wall = wall
        self.issueLimiter = SlidingWindowLimiter(limit: configuration.maxIssuesPerMinutePerDevice, window: 60)
    }

    public func updateLifetime(_ lifetime: TimeInterval) {
        lock.withLock {
            configuration = Configuration(lifetime: lifetime, maxIssuesPerMinutePerDevice: configuration.maxIssuesPerMinutePerDevice, maxBadSignaturesPerRequest: configuration.maxBadSignaturesPerRequest)
        }
    }

    // MARK: Issue

    public func issue(action: UnlockAction, for device: PairedDeviceRecord, macUsername: String) async throws -> SignedUnlockRequest {
        let (request, deadline): (UnlockRequest, MonotonicInstant) = try lock.withLock {
            let now = monotonic.now()
            guard issueLimiter.allow(device.pairingID, at: now) else { throw ChallengeIssueError.rateLimited }
            pruneRetired(now: now)
            var nonce = SecureRandom.bytes(MNUProtocol.nonceLength)
            // A 256-bit CSPRNG collision is not a realistic event; the check makes
            // the "never reuse a nonce" invariant explicit rather than assumed.
            while recentNonces[nonce] != nil { nonce = SecureRandom.bytes(MNUProtocol.nonceLength) }
            recentNonces[nonce] = now
            let issued = wall.now().millisecondsSince1970
            let lifetimeMillis = UInt64(configuration.lifetime * 1000)
            let request = UnlockRequest(
                requestID: UUID(),
                nonce: nonce,
                macID: macID,
                macName: macName,
                macUsername: macUsername,
                pairingID: device.pairingID,
                deviceID: device.deviceID,
                action: action,
                issuedAtMillis: issued,
                expiresAtMillis: issued + lifetimeMillis
            )
            return (request, now.advanced(bySeconds: configuration.lifetime))
        }
        let signature = try await signer.sign(request.requestSigningBytes(), reason: "Sign unlock request")
        let signed = SignedUnlockRequest(request: request, macSignature: signature)
        lock.withLock {
            // One outstanding challenge per pairing: a newer one retires the older.
            let now = monotonic.now()
            for (id, item) in pending where item.signed.request.pairingID == device.pairingID {
                pending[id] = nil
                retired[id] = now
            }
            pending[request.requestID] = Pending(signed: signed, deadline: deadline, badSignatures: 0)
        }
        return signed
    }

    // MARK: Verify

    public func verify(
        _ approval: UnlockApproval,
        authenticatedPairingID: UUID,
        device: PairedDeviceRecord?,
        session: SessionSnapshot,
        expectedUsername: String,
        expectedUID: UInt32
    ) -> Result<VerifiedApproval, ApprovalRejection> {
        lock.withLock {
            let now = monotonic.now()
            guard var item = pending[approval.requestID] else {
                return .failure(retired[approval.requestID] != nil ? .replayed : .unsolicited)
            }
            let request = item.signed.request

            guard approval.pairingID == authenticatedPairingID,
                  request.pairingID == authenticatedPairingID,
                  approval.deviceID == request.deviceID
            else { return .failure(.wrongDevice) }

            guard let device, device.pairingID == request.pairingID, device.deviceID == request.deviceID else {
                retire(approval.requestID, now: now)
                return .failure(.revoked)
            }

            guard now < item.deadline, wall.now().millisecondsSince1970 < request.expiresAtMillis else {
                retire(approval.requestID, now: now)
                return .failure(.expired)
            }

            let signingBytes = request.approvalSigningBytes()
            guard SignatureVerifier.isValid(signatureDER: approval.signature, message: signingBytes, publicKeyX963: device.publicKey) else {
                item.badSignatures += 1
                if item.badSignatures >= configuration.maxBadSignaturesPerRequest {
                    retire(approval.requestID, now: now)
                } else {
                    pending[approval.requestID] = item
                }
                return .failure(.badSignature)
            }

            guard request.macUsername == expectedUsername else {
                retire(approval.requestID, now: now)
                return .failure(.sessionUnavailable)
            }
            switch request.action {
            case .unlockSession:
                guard session.isLockedConsoleSession(of: expectedUsername, uid: expectedUID) else {
                    retire(approval.requestID, now: now)
                    return .failure(.sessionNotLocked)
                }
            case .authenticationTest:
                guard session.isAvailable, session.isLoginDone, session.userName == expectedUsername, session.userID == expectedUID else {
                    retire(approval.requestID, now: now)
                    return .failure(.sessionUnavailable)
                }
            }

            retire(approval.requestID, now: now)
            return .success(VerifiedApproval(request: request, verifiedAt: now))
        }
    }

    /// Retires a challenge the phone declined. Only the pairing it was issued to may decline it.
    @discardableResult
    public func decline(requestID: UUID, authenticatedPairingID: UUID) -> Bool {
        lock.withLock {
            guard let item = pending[requestID], item.signed.request.pairingID == authenticatedPairingID else { return false }
            retire(requestID, now: monotonic.now())
            return true
        }
    }

    // MARK: Invalidation

    /// Called on unlock, sleep, logout, user switch and settings changes.
    @discardableResult
    public func invalidateAll() -> [SignedUnlockRequest] {
        lock.withLock {
            let now = monotonic.now()
            let removed = Array(pending.values.map(\.signed))
            for id in pending.keys { retired[id] = now }
            pending.removeAll()
            return removed
        }
    }

    /// Called when a pairing is revoked or its connection is lost.
    @discardableResult
    public func invalidate(pairingID: UUID) -> [SignedUnlockRequest] {
        lock.withLock {
            let now = monotonic.now()
            var removed: [SignedUnlockRequest] = []
            for (id, item) in pending where item.signed.request.pairingID == pairingID {
                removed.append(item.signed)
                retire(id, now: now)
            }
            return removed
        }
    }

    /// Removes challenges whose monotonic deadline or wall-clock expiry passed.
    public func expireStale() -> [SignedUnlockRequest] {
        lock.withLock {
            let now = monotonic.now()
            let wallNow = wall.now().millisecondsSince1970
            var expired: [SignedUnlockRequest] = []
            for (id, item) in pending where now >= item.deadline || wallNow >= item.signed.request.expiresAtMillis {
                expired.append(item.signed)
                retire(id, now: now)
            }
            pruneRetired(now: now)
            return expired
        }
    }

    public var hasPending: Bool { lock.withLock { !pending.isEmpty } }

    public func pendingRequest(for pairingID: UUID) -> SignedUnlockRequest? {
        lock.withLock { pending.values.first { $0.signed.request.pairingID == pairingID }?.signed }
    }

    // MARK: Private (call with lock held)

    private func retire(_ id: UUID, now: MonotonicInstant) {
        pending[id] = nil
        retired[id] = now
    }

    private func pruneRetired(now: MonotonicInstant) {
        retired = retired.filter { now.seconds(since: $0.value) < MNUProtocol.replayRetention }
        recentNonces = recentNonces.filter { now.seconds(since: $0.value) < MNUProtocol.replayRetention }
    }
}
