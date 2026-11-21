import Foundation

// MARK: - Session messages

/// First message from the iPhone on a paired-session connection. The binder is an
/// HMAC under the pairing's channel key over the TLS exporter, proving the client
/// holds *this* pairing's key inside *this* TLS session.
public struct ClientHello: Codable, Equatable, Sendable {
    public let protocolVersion: UInt16
    public let pairingID: UUID
    public let deviceID: UUID
    public let appVersion: String
    public let binder: Data

    public init(protocolVersion: UInt16 = MNUProtocol.protocolVersion, pairingID: UUID, deviceID: UUID, appVersion: String, binder: Data) {
        self.protocolVersion = protocolVersion
        self.pairingID = pairingID
        self.deviceID = deviceID
        self.appVersion = appVersion
        self.binder = binder
    }
}

public enum MacLockState: String, Codable, Sendable {
    case unlocked
    case locked
    case unavailable
}

public struct MacSessionStatus: Codable, Equatable, Sendable {
    public let lockState: MacLockState
    public let engineState: UnlockState
    public let authenticationOnly: Bool
    public let requiresPhoneInitiation: Bool

    public init(lockState: MacLockState, engineState: UnlockState, authenticationOnly: Bool, requiresPhoneInitiation: Bool) {
        self.lockState = lockState
        self.engineState = engineState
        self.authenticationOnly = authenticationOnly
        self.requiresPhoneInitiation = requiresPhoneInitiation
    }
}

public struct ServerHello: Codable, Equatable, Sendable {
    public let protocolVersion: UInt16
    public let macID: UUID
    public let binder: Data
    public let status: MacSessionStatus

    public init(protocolVersion: UInt16 = MNUProtocol.protocolVersion, macID: UUID, binder: Data, status: MacSessionStatus) {
        self.protocolVersion = protocolVersion
        self.macID = macID
        self.binder = binder
        self.status = status
    }
}

/// iPhone (foreground, user tapped a button) asks the Mac to issue a challenge.
/// This never authorizes anything by itself.
public struct UnlockInitiation: Codable, Equatable, Sendable {
    public let action: UnlockAction
    public init(action: UnlockAction) { self.action = action }
}

/// iPhone's answer to a challenge. Only `requestID` is used to find the Mac's own
/// stored challenge; the signature is checked against bytes the Mac rebuilds itself.
public struct UnlockApproval: Codable, Equatable, Sendable {
    public let requestID: UUID
    public let pairingID: UUID
    public let deviceID: UUID
    public let signature: Data

    public init(requestID: UUID, pairingID: UUID, deviceID: UUID, signature: Data) {
        self.requestID = requestID
        self.pairingID = pairingID
        self.deviceID = deviceID
        self.signature = signature
    }
}

public enum DeclineReason: String, Codable, Sendable {
    case userDeclined
    case biometricCancelled
    case biometricUnavailable
    case biometricLockout
    case keyInvalidated
    case requestInvalid
}

public struct UnlockDecline: Codable, Equatable, Sendable {
    public let requestID: UUID
    public let reason: DeclineReason
    public init(requestID: UUID, reason: DeclineReason) {
        self.requestID = requestID
        self.reason = reason
    }
}

public enum ApprovalOutcome: String, Codable, Sendable {
    /// Signature verified; authentication-only mode, so the Mac was not unlocked.
    case verifiedAuthenticationOnly
    /// Signature verified; the experimental credential adapter attempted entry.
    case verifiedCredentialEntryAttempted
    /// Signature verified; the Mac reported the session unlocked afterwards.
    case unlocked
    case rejected
    case expired
    case failed
}

public struct ApprovalResult: Codable, Equatable, Sendable {
    public let requestID: UUID?
    public let outcome: ApprovalOutcome
    public let detail: String

    public init(requestID: UUID?, outcome: ApprovalOutcome, detail: String) {
        self.requestID = requestID
        self.outcome = outcome
        self.detail = String(detail.prefix(200))
    }
}

/// Either side ends a pairing. Sent only over an authenticated session.
public struct RevokeNotice: Codable, Equatable, Sendable {
    public let pairingID: UUID
    public init(pairingID: UUID) { self.pairingID = pairingID }
}

public struct ProtocolErrorMessage: Codable, Equatable, Sendable {
    public let code: String
    public let message: String
    public init(code: String, message: String) {
        self.code = String(code.prefix(64))
        self.message = String(message.prefix(200))
    }
}

// MARK: - Pairing messages

public struct PairHello: Codable, Equatable, Sendable {
    public let protocolVersion: UInt16
    public let deviceID: UUID
    public let deviceName: String
    /// Secure Enclave P-256 key (biometryCurrentSet) that will sign approvals.
    public let devicePublicKey: Data
    /// Ephemeral X25519 key for deriving the per-pairing channel key.
    public let ephemeralPublicKey: Data
    public let nonce: Data

    public init(protocolVersion: UInt16 = MNUProtocol.protocolVersion, deviceID: UUID, deviceName: String, devicePublicKey: Data, ephemeralPublicKey: Data, nonce: Data) {
        self.protocolVersion = protocolVersion
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.devicePublicKey = devicePublicKey
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce
    }
}

public struct PairChallenge: Codable, Equatable, Sendable {
    public let protocolVersion: UInt16
    public let pairingID: UUID
    public let macID: UUID
    public let macName: String
    public let macUsername: String
    public let macPublicKey: Data
    public let ephemeralPublicKey: Data
    public let nonce: Data
    /// Mac identity signature over the pairing transcript.
    public let transcriptSignature: Data

    public init(protocolVersion: UInt16 = MNUProtocol.protocolVersion, pairingID: UUID, macID: UUID, macName: String, macUsername: String, macPublicKey: Data, ephemeralPublicKey: Data, nonce: Data, transcriptSignature: Data) {
        self.protocolVersion = protocolVersion
        self.pairingID = pairingID
        self.macID = macID
        self.macName = macName
        self.macUsername = macUsername
        self.macPublicKey = macPublicKey
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce
        self.transcriptSignature = transcriptSignature
    }
}

/// iPhone's Face ID-gated signature over the transcript, sent only after the user
/// confirmed the verification code matches the Mac.
public struct PairConfirm: Codable, Equatable, Sendable {
    public let signature: Data
    public init(signature: Data) { self.signature = signature }
}

/// Mac's signature over the transcript + pairingID, sent only after the Mac user
/// also confirmed the code and the pairing was stored.
public struct PairComplete: Codable, Equatable, Sendable {
    public let pairingID: UUID
    public let signature: Data
    public init(pairingID: UUID, signature: Data) {
        self.pairingID = pairingID
        self.signature = signature
    }
}

public struct PairAbort: Codable, Equatable, Sendable {
    public let reason: String
    public init(reason: String) { self.reason = String(reason.prefix(200)) }
}

// MARK: - Envelope

public enum WireMessage: Equatable, Sendable {
    case clientHello(ClientHello)
    case serverHello(ServerHello)
    case status(MacSessionStatus)
    case initiate(UnlockInitiation)
    case unlockRequest(SignedUnlockRequest)
    case approval(UnlockApproval)
    case decline(UnlockDecline)
    case result(ApprovalResult)
    case revoke(RevokeNotice)
    case ping
    case pong
    case error(ProtocolErrorMessage)
    case pairHello(PairHello)
    case pairChallenge(PairChallenge)
    case pairConfirm(PairConfirm)
    case pairComplete(PairComplete)
    case pairAbort(PairAbort)

    public var typeName: String {
        switch self {
        case .clientHello: return "clientHello"
        case .serverHello: return "serverHello"
        case .status: return "status"
        case .initiate: return "initiate"
        case .unlockRequest: return "unlockRequest"
        case .approval: return "approval"
        case .decline: return "decline"
        case .result: return "result"
        case .revoke: return "revoke"
        case .ping: return "ping"
        case .pong: return "pong"
        case .error: return "error"
        case .pairHello: return "pairHello"
        case .pairChallenge: return "pairChallenge"
        case .pairConfirm: return "pairConfirm"
        case .pairComplete: return "pairComplete"
        case .pairAbort: return "pairAbort"
        }
    }

    /// Strict structural validation of untrusted input, applied to every decoded
    /// frame before it reaches protocol logic.
    public func validate() throws {
        switch self {
        case .clientHello(let hello):
            try requireVersion(hello.protocolVersion)
            try validateText(hello.appVersion, max: 32, field: "appVersion")
            guard hello.binder.count == MNUProtocol.binderLength else { throw ProtocolValidationError.invalidField("binder") }
        case .serverHello(let hello):
            try requireVersion(hello.protocolVersion)
            guard hello.binder.count == MNUProtocol.binderLength else { throw ProtocolValidationError.invalidField("binder") }
        case .status, .initiate, .revoke, .ping, .pong, .decline:
            break
        case .unlockRequest(let signed):
            try signed.request.validateShape()
            try validateSignatureShape(signed.macSignature)
        case .approval(let approval):
            try validateSignatureShape(approval.signature)
        case .result(let result):
            try validateText(result.detail, max: MNUProtocol.maxShortTextBytes, field: "detail", allowEmpty: true)
        case .error(let error):
            try validateText(error.code, max: 64, field: "code")
            try validateText(error.message, max: MNUProtocol.maxShortTextBytes, field: "message", allowEmpty: true)
        case .pairHello(let hello):
            try requireVersion(hello.protocolVersion)
            try validateText(hello.deviceName, max: MNUProtocol.maxNameBytes, field: "deviceName")
            guard SignatureVerifier.isValidPublicKey(hello.devicePublicKey) else { throw ProtocolValidationError.invalidField("devicePublicKey") }
            guard hello.ephemeralPublicKey.count == MNUProtocol.x25519PublicKeyLength else { throw ProtocolValidationError.invalidField("ephemeralPublicKey") }
            guard hello.nonce.count == MNUProtocol.nonceLength else { throw ProtocolValidationError.invalidField("nonce") }
        case .pairChallenge(let challenge):
            try requireVersion(challenge.protocolVersion)
            try validateText(challenge.macName, max: MNUProtocol.maxNameBytes, field: "macName")
            try validateText(challenge.macUsername, max: MNUProtocol.maxUsernameBytes, field: "macUsername")
            guard SignatureVerifier.isValidPublicKey(challenge.macPublicKey) else { throw ProtocolValidationError.invalidField("macPublicKey") }
            guard challenge.ephemeralPublicKey.count == MNUProtocol.x25519PublicKeyLength else { throw ProtocolValidationError.invalidField("ephemeralPublicKey") }
            guard challenge.nonce.count == MNUProtocol.nonceLength else { throw ProtocolValidationError.invalidField("nonce") }
            try validateSignatureShape(challenge.transcriptSignature)
        case .pairConfirm(let confirm):
            try validateSignatureShape(confirm.signature)
        case .pairComplete(let complete):
            try validateSignatureShape(complete.signature)
        case .pairAbort(let abort):
            try validateText(abort.reason, max: MNUProtocol.maxShortTextBytes, field: "reason", allowEmpty: true)
        }
    }

    private func requireVersion(_ version: UInt16) throws {
        guard version == MNUProtocol.protocolVersion else { throw ProtocolValidationError.unsupportedVersion(version) }
    }
}

extension WireMessage: Codable {
    private enum CodingKeys: String, CodingKey {
        case type
        case body
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "clientHello": self = .clientHello(try container.decode(ClientHello.self, forKey: .body))
        case "serverHello": self = .serverHello(try container.decode(ServerHello.self, forKey: .body))
        case "status": self = .status(try container.decode(MacSessionStatus.self, forKey: .body))
        case "initiate": self = .initiate(try container.decode(UnlockInitiation.self, forKey: .body))
        case "unlockRequest": self = .unlockRequest(try container.decode(SignedUnlockRequest.self, forKey: .body))
        case "approval": self = .approval(try container.decode(UnlockApproval.self, forKey: .body))
        case "decline": self = .decline(try container.decode(UnlockDecline.self, forKey: .body))
        case "result": self = .result(try container.decode(ApprovalResult.self, forKey: .body))
        case "revoke": self = .revoke(try container.decode(RevokeNotice.self, forKey: .body))
        case "ping": self = .ping
        case "pong": self = .pong
        case "error": self = .error(try container.decode(ProtocolErrorMessage.self, forKey: .body))
        case "pairHello": self = .pairHello(try container.decode(PairHello.self, forKey: .body))
        case "pairChallenge": self = .pairChallenge(try container.decode(PairChallenge.self, forKey: .body))
        case "pairConfirm": self = .pairConfirm(try container.decode(PairConfirm.self, forKey: .body))
        case "pairComplete": self = .pairComplete(try container.decode(PairComplete.self, forKey: .body))
        case "pairAbort": self = .pairAbort(try container.decode(PairAbort.self, forKey: .body))
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Unknown message type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(typeName, forKey: .type)
        switch self {
        case .clientHello(let body): try container.encode(body, forKey: .body)
        case .serverHello(let body): try container.encode(body, forKey: .body)
        case .status(let body): try container.encode(body, forKey: .body)
        case .initiate(let body): try container.encode(body, forKey: .body)
        case .unlockRequest(let body): try container.encode(body, forKey: .body)
        case .approval(let body): try container.encode(body, forKey: .body)
        case .decline(let body): try container.encode(body, forKey: .body)
        case .result(let body): try container.encode(body, forKey: .body)
        case .revoke(let body): try container.encode(body, forKey: .body)
        case .ping, .pong: break
        case .error(let body): try container.encode(body, forKey: .body)
        case .pairHello(let body): try container.encode(body, forKey: .body)
        case .pairChallenge(let body): try container.encode(body, forKey: .body)
        case .pairConfirm(let body): try container.encode(body, forKey: .body)
        case .pairComplete(let body): try container.encode(body, forKey: .body)
        case .pairAbort(let body): try container.encode(body, forKey: .body)
        }
    }
}
