import Foundation

/// A trusted Mac as stored on the iPhone (Keychain, this device only).
public struct PinnedMac: Codable, Equatable, Sendable, Identifiable {
    public let pairingID: UUID
    public let macID: UUID
    public var macName: String
    public let macUsername: String
    /// Pinned Mac identity key (X9.63). Requests must be signed by it.
    public let macPublicKey: Data
    /// This iPhone's identity for the pairing.
    public let deviceID: UUID
    public let pairedAtMillis: UInt64

    public var id: UUID { pairingID }
    public var pskIdentity: String { "mnu1:" + pairingID.uuidString }

    public init(pairingID: UUID, macID: UUID, macName: String, macUsername: String, macPublicKey: Data, deviceID: UUID, pairedAtMillis: UInt64) {
        self.pairingID = pairingID
        self.macID = macID
        self.macName = macName
        self.macUsername = macUsername
        self.macPublicKey = macPublicKey
        self.deviceID = deviceID
        self.pairedAtMillis = pairedAtMillis
    }
}

public enum RequestRejection: Error, Equatable, Sendable {
    case malformed
    case wrongMac
    case wrongPairing
    case wrongDevice
    case wrongUser
    case badSignature
    case expired
    case notYetValid
    case lifetimeTooLong
    case duplicate

    public var displayText: String {
        switch self {
        case .malformed: return "Malformed request"
        case .wrongMac: return "Request is for a different Mac"
        case .wrongPairing: return "Request is for a different pairing"
        case .wrongDevice: return "Request is for a different iPhone"
        case .wrongUser: return "Request names an unexpected Mac account"
        case .badSignature: return "Request was not signed by the paired Mac"
        case .expired: return "Request expired"
        case .notYetValid: return "Request timestamp is in the future"
        case .lifetimeTooLong: return "Request validity window is too long"
        case .duplicate: return "Request was already received"
        }
    }
}

/// iPhone-side validation of a challenge before the user is ever asked for Face ID.
/// Rejects anything not signed by the pinned Mac key, so a forged Bonjour
/// advertiser (or any other paired Mac) cannot obtain an approval signature.
public final class RequestValidator: @unchecked Sendable {
    private let wall: WallClock
    private let lock = NSLock()
    private var seen: [UUID: Date] = [:]

    public init(wall: WallClock = SystemWallClock()) {
        self.wall = wall
    }

    public func validate(_ signed: SignedUnlockRequest, pinned: PinnedMac) -> Result<UnlockRequest, RequestRejection> {
        let request = signed.request
        do {
            try request.validateShape()
            try validateSignatureShape(signed.macSignature)
        } catch {
            return .failure(.malformed)
        }
        guard request.macID == pinned.macID else { return .failure(.wrongMac) }
        guard request.pairingID == pinned.pairingID else { return .failure(.wrongPairing) }
        guard request.deviceID == pinned.deviceID else { return .failure(.wrongDevice) }
        guard request.macUsername == pinned.macUsername else { return .failure(.wrongUser) }
        guard SignatureVerifier.isValid(signatureDER: signed.macSignature, message: request.requestSigningBytes(), publicKeyX963: pinned.macPublicKey) else {
            return .failure(.badSignature)
        }
        guard request.lifetime <= MNUProtocol.approvalLifetimeRange.upperBound else { return .failure(.lifetimeTooLong) }

        let now = wall.now()
        let skew = MNUProtocol.clockSkewTolerance
        guard now.addingTimeInterval(skew) >= request.issuedAt else { return .failure(.notYetValid) }
        guard now <= request.expiresAt.addingTimeInterval(skew) else { return .failure(.expired) }

        return lock.withLock {
            seen = seen.filter { now.timeIntervalSince($0.value) < MNUProtocol.replayRetention }
            guard seen[request.requestID] == nil else { return .failure(.duplicate) }
            seen[request.requestID] = now
            return .success(request)
        }
    }
}
