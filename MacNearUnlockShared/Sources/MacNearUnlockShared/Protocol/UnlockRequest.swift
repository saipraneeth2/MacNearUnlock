import Foundation

/// What an approval authorizes. Bound into both signatures, so an approval for a
/// harmless authentication test can never be replayed as an unlock approval.
public enum UnlockAction: String, Codable, Sendable, CaseIterable {
    /// Approve access to the locked, already logged-in console session.
    case unlockSession = "unlock-session"
    /// Prove the end-to-end protocol works. Never changes the Mac's login state.
    case authenticationTest = "auth-test"

    var canonicalCode: UInt16 {
        switch self {
        case .unlockSession: return 1
        case .authenticationTest: return 2
        }
    }

    public var displayName: String {
        switch self {
        case .unlockSession: return "Unlock Mac session"
        case .authenticationTest: return "Authentication test (no unlock)"
        }
    }
}

public enum ProtocolValidationError: Error, Equatable, Sendable {
    case unsupportedVersion(UInt16)
    case invalidField(String)
}

/// A single-use challenge created by the Mac and signed with the Mac identity key.
///
/// Every field is covered by both the Mac's request signature and the iPhone's
/// approval signature, binding the approval to: this exact challenge (requestID +
/// 256-bit nonce), the intended Mac (macID), the intended macOS account
/// (macUsername), the specific pairing and phone (pairingID, deviceID), the action,
/// and the validity window.
public struct UnlockRequest: Codable, Equatable, Hashable, Sendable {
    public let protocolVersion: UInt16
    public let requestID: UUID
    public let nonce: Data
    public let macID: UUID
    public let macName: String
    public let macUsername: String
    public let pairingID: UUID
    public let deviceID: UUID
    public let action: UnlockAction
    public let issuedAtMillis: UInt64
    public let expiresAtMillis: UInt64

    public init(
        protocolVersion: UInt16 = MNUProtocol.protocolVersion,
        requestID: UUID,
        nonce: Data,
        macID: UUID,
        macName: String,
        macUsername: String,
        pairingID: UUID,
        deviceID: UUID,
        action: UnlockAction,
        issuedAtMillis: UInt64,
        expiresAtMillis: UInt64
    ) {
        self.protocolVersion = protocolVersion
        self.requestID = requestID
        self.nonce = nonce
        self.macID = macID
        self.macName = macName
        self.macUsername = macUsername
        self.pairingID = pairingID
        self.deviceID = deviceID
        self.action = action
        self.issuedAtMillis = issuedAtMillis
        self.expiresAtMillis = expiresAtMillis
    }

    public var issuedAt: Date { Date(millisecondsSince1970: issuedAtMillis) }
    public var expiresAt: Date { Date(millisecondsSince1970: expiresAtMillis) }
    public var lifetime: TimeInterval {
        expiresAtMillis > issuedAtMillis ? TimeInterval(expiresAtMillis - issuedAtMillis) / 1000 : 0
    }

    private func appendFields(to writer: inout CanonicalWriter) {
        writer.append(1, uint16: protocolVersion)
        writer.append(2, uuid: requestID)
        writer.append(3, nonce)
        writer.append(4, uuid: macID)
        writer.append(5, string: macName)
        writer.append(6, string: macUsername)
        writer.append(7, uuid: pairingID)
        writer.append(8, uuid: deviceID)
        writer.append(9, uint16: action.canonicalCode)
        writer.append(10, uint64: issuedAtMillis)
        writer.append(11, uint64: expiresAtMillis)
    }

    /// Bytes the Mac signs so the iPhone can verify the request came from the
    /// pinned Mac (defeats forged Bonjour advertisers).
    public func requestSigningBytes() -> Data {
        var writer = CanonicalWriter(domain: .unlockRequest)
        appendFields(to: &writer)
        return writer.bytes
    }

    /// Bytes the iPhone signs with its biometric-gated Secure Enclave key.
    /// The Mac always rebuilds these from its *own* stored copy of the request,
    /// never from anything the phone sends back.
    public func approvalSigningBytes() -> Data {
        var writer = CanonicalWriter(domain: .unlockApproval)
        appendFields(to: &writer)
        writer.append(32, string: "approve")
        return writer.bytes
    }

    /// Structural validation of untrusted input. Semantic checks (expiry, pinning,
    /// replay) happen in `RequestValidator` / `ChallengeAuthority`.
    public func validateShape() throws {
        guard protocolVersion == MNUProtocol.protocolVersion else {
            throw ProtocolValidationError.unsupportedVersion(protocolVersion)
        }
        guard nonce.count == MNUProtocol.nonceLength else { throw ProtocolValidationError.invalidField("nonce") }
        try validateText(macName, max: MNUProtocol.maxNameBytes, field: "macName")
        try validateText(macUsername, max: MNUProtocol.maxUsernameBytes, field: "macUsername")
        guard expiresAtMillis > issuedAtMillis else { throw ProtocolValidationError.invalidField("expiresAt") }
    }
}

/// Request plus the Mac identity signature over `requestSigningBytes()`.
public struct SignedUnlockRequest: Codable, Equatable, Sendable {
    public let request: UnlockRequest
    public let macSignature: Data

    public init(request: UnlockRequest, macSignature: Data) {
        self.request = request
        self.macSignature = macSignature
    }
}

func validateText(_ text: String, max: Int, field: String, allowEmpty: Bool = false) throws {
    let count = text.utf8.count
    guard count <= max, allowEmpty || count > 0 else { throw ProtocolValidationError.invalidField(field) }
    // Reject control characters: they have no legitimate use in names and can be
    // used to spoof UI text.
    guard !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        throw ProtocolValidationError.invalidField(field)
    }
}

func validateSignatureShape(_ signature: Data, field: String = "signature") throws {
    guard MNUProtocol.signatureLengthRange.contains(signature.count) else {
        throw ProtocolValidationError.invalidField(field)
    }
}
