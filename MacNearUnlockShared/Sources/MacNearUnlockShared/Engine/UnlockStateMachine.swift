import Foundation

/// Mac-side authentication state. The enum is exhaustive and every transition is
/// listed explicitly in `UnlockStateMachine.transition(from:on:)`; anything not
/// listed is rejected and leaves the state unchanged.
public enum UnlockState: String, Codable, Sendable, CaseIterable {
    /// Session unlocked, nothing pending (authentication tests may start here).
    case idle
    /// Console session locked and awake, no challenge outstanding.
    case locked
    /// Challenge created and being sent to a paired iPhone.
    case requesting
    /// Challenge delivered; waiting for the user to approve with Face ID.
    case awaitingBiometrics
    /// A fresh, correctly signed approval was accepted (consumed once).
    case verified
    /// Approval declined, malformed, wrongly signed or otherwise refused.
    case rejected
    /// Challenge lifetime elapsed before a valid approval arrived.
    case expired
    /// Asleep, logged out, switched away (fast user switching) or state unknown.
    case unavailable

    public var displayName: String {
        switch self {
        case .idle: return "Idle"
        case .locked: return "Locked"
        case .requesting: return "Requesting"
        case .awaitingBiometrics: return "Awaiting Face ID"
        case .verified: return "Verified"
        case .rejected: return "Rejected"
        case .expired: return "Expired"
        case .unavailable: return "Unavailable"
        }
    }
}

public enum UnlockEvent: Equatable, Sendable {
    case sessionUnlocked
    case sessionLocked
    case sessionUnavailable
    case requestIssued
    case requestDelivered
    case approvalVerified
    case approvalRejected
    case requestExpired
    /// Return to a resting state after a terminal outcome.
    case reset(locked: Bool)
}

public struct UnlockStateMachine: Sendable {
    public private(set) var state: UnlockState

    public init(initial: UnlockState = .unavailable) {
        state = initial
    }

    /// Pure transition table. `nil` means the event is not allowed in that state.
    public static func transition(from state: UnlockState, on event: UnlockEvent) -> UnlockState? {
        switch (state, event) {
        // Session facts override everything; the engine invalidates any pending
        // challenge whenever these fire.
        case (_, .sessionUnlocked): return .idle
        case (_, .sessionUnavailable): return .unavailable
        case (_, .sessionLocked): return .locked

        // A new challenge may start from a resting or terminal state; additional
        // challenges for other paired phones keep the in-flight state.
        case (.idle, .requestIssued), (.locked, .requestIssued),
             (.verified, .requestIssued), (.rejected, .requestIssued), (.expired, .requestIssued),
             (.requesting, .requestIssued):
            return .requesting
        case (.awaitingBiometrics, .requestIssued):
            return .awaitingBiometrics

        case (.requesting, .requestDelivered), (.awaitingBiometrics, .requestDelivered):
            return .awaitingBiometrics

        case (.awaitingBiometrics, .approvalVerified):
            return .verified

        case (.requesting, .approvalRejected), (.awaitingBiometrics, .approvalRejected):
            return .rejected

        case (.requesting, .requestExpired), (.awaitingBiometrics, .requestExpired):
            return .expired

        case (.verified, .reset(let locked)), (.rejected, .reset(let locked)), (.expired, .reset(let locked)),
             (.requesting, .reset(let locked)), (.awaitingBiometrics, .reset(let locked)),
             (.idle, .reset(let locked)), (.locked, .reset(let locked)):
            return locked ? .locked : .idle

        default:
            return nil
        }
    }

    /// Applies `event`; returns false (state unchanged) if the transition is invalid.
    @discardableResult
    public mutating func handle(_ event: UnlockEvent) -> Bool {
        guard let next = UnlockStateMachine.transition(from: state, on: event) else { return false }
        state = next
        return true
    }
}
