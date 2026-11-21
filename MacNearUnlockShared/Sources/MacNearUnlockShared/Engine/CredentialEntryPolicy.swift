import Foundation

/// Facts gathered immediately before the EXPERIMENTAL credential adapter would type
/// anything. Kept as plain data so the go/no-go decision is a pure, unit-tested
/// function that is independent of AppKit, Accessibility and Keychain state.
public struct CredentialEntryInputs: Sendable, Equatable {
    public var adapterEnabled: Bool
    public var riskAcknowledged: Bool
    public var authenticationOnlyMode: Bool
    public var credentialArmed: Bool
    public var accessibilityTrusted: Bool
    public var postEventAccess: Bool
    public var approvalAction: UnlockAction
    public var approvalConsumedByCaller: Bool
    public var approvalAge: TimeInterval
    public var session: SessionSnapshot
    public var expectedUsername: String
    public var expectedUID: UInt32
    public var systemSleeping: Bool
    public var displayAsleep: Bool
    public var secureInputEnabled: Bool
    /// nil when the secure-input owner cannot be determined.
    public var secureInputOwnerIsLoginWindow: Bool?
    public var consecutiveFailures: Int
    public var attemptsInLastHour: Int
    public var secondsSinceLastAttempt: TimeInterval?

    public init(adapterEnabled: Bool, riskAcknowledged: Bool, authenticationOnlyMode: Bool, credentialArmed: Bool, accessibilityTrusted: Bool, postEventAccess: Bool, approvalAction: UnlockAction, approvalConsumedByCaller: Bool, approvalAge: TimeInterval, session: SessionSnapshot, expectedUsername: String, expectedUID: UInt32, systemSleeping: Bool, displayAsleep: Bool, secureInputEnabled: Bool, secureInputOwnerIsLoginWindow: Bool?, consecutiveFailures: Int, attemptsInLastHour: Int, secondsSinceLastAttempt: TimeInterval?) {
        self.adapterEnabled = adapterEnabled
        self.riskAcknowledged = riskAcknowledged
        self.authenticationOnlyMode = authenticationOnlyMode
        self.credentialArmed = credentialArmed
        self.accessibilityTrusted = accessibilityTrusted
        self.postEventAccess = postEventAccess
        self.approvalAction = approvalAction
        self.approvalConsumedByCaller = approvalConsumedByCaller
        self.approvalAge = approvalAge
        self.session = session
        self.expectedUsername = expectedUsername
        self.expectedUID = expectedUID
        self.systemSleeping = systemSleeping
        self.displayAsleep = displayAsleep
        self.secureInputEnabled = secureInputEnabled
        self.secureInputOwnerIsLoginWindow = secureInputOwnerIsLoginWindow
        self.consecutiveFailures = consecutiveFailures
        self.attemptsInLastHour = attemptsInLastHour
        self.secondsSinceLastAttempt = secondsSinceLastAttempt
    }
}

public enum CredentialEntryDenial: String, Error, Sendable, CaseIterable {
    case adapterDisabled = "Experimental adapter is disabled"
    case riskNotAcknowledged = "Security risk not acknowledged"
    case authenticationOnlyMode = "Authentication-only mode is on"
    case autoDisabledAfterFailures = "Disabled after repeated failures"
    case wrongAction = "Approval was not for an unlock"
    case approvalNotConsumed = "Approval token was not consumed by the caller"
    case approvalStale = "Approval is no longer fresh"
    case sessionUnavailable = "No logged-in console session (logged out, preboot or switched user)"
    case sessionNotLocked = "Screen is not locked"
    case sessionWrongUser = "Console session belongs to a different user"
    case systemAsleep = "System or display is asleep"
    case accessibilityMissing = "Accessibility / event-posting permission not granted"
    case secureFieldNotVerified = "Lock-screen password field not verified (secure input inactive)"
    case secureInputOwnedByOtherProcess = "Secure input is owned by a process other than loginwindow"
    case credentialNotArmed = "Stored credential is not armed for this app session"
    case rateLimited = "Attempt rate limit reached"
}

public enum CredentialEntryPolicy {
    public static let maxApprovalAge: TimeInterval = 5
    public static let maxConsecutiveFailures = 3
    public static let maxAttemptsPerHour = 5
    public static let minSecondsBetweenAttempts: TimeInterval = 10

    /// Returns nil only when every precondition holds. Ordered so configuration
    /// problems are reported before transient session conditions.
    public static func evaluate(_ input: CredentialEntryInputs) -> CredentialEntryDenial? {
        guard input.adapterEnabled else { return .adapterDisabled }
        guard input.riskAcknowledged else { return .riskNotAcknowledged }
        guard !input.authenticationOnlyMode else { return .authenticationOnlyMode }
        guard input.consecutiveFailures < maxConsecutiveFailures else { return .autoDisabledAfterFailures }
        guard input.approvalAction == .unlockSession else { return .wrongAction }
        guard input.approvalConsumedByCaller else { return .approvalNotConsumed }
        guard input.approvalAge >= 0, input.approvalAge <= maxApprovalAge else { return .approvalStale }

        let session = input.session
        guard session.isAvailable, session.isLoginDone, session.isOnConsole else { return .sessionUnavailable }
        guard session.userName == input.expectedUsername, session.userID == input.expectedUID else { return .sessionWrongUser }
        guard session.isScreenLocked else { return .sessionNotLocked }
        guard !input.systemSleeping, !input.displayAsleep else { return .systemAsleep }

        guard input.accessibilityTrusted, input.postEventAccess else { return .accessibilityMissing }
        guard input.secureInputEnabled else { return .secureFieldNotVerified }
        if input.secureInputOwnerIsLoginWindow == false { return .secureInputOwnedByOtherProcess }
        guard input.credentialArmed else { return .credentialNotArmed }

        guard input.attemptsInLastHour < maxAttemptsPerHour else { return .rateLimited }
        if let since = input.secondsSinceLastAttempt, since < minSecondsBetweenAttempts { return .rateLimited }
        return nil
    }
}
