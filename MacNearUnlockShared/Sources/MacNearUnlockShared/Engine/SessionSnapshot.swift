import Foundation

/// Point-in-time view of the console session, parsed from
/// `CGSessionCopyCurrentDictionary()` (CoreGraphics, queried from the window
/// server) rather than from spoofable distributed notifications.
///
/// Documented keys (CGSession.h): kCGSSessionUserIDKey, kCGSSessionUserNameKey,
/// kCGSSessionOnConsoleKey, kCGSessionLoginDoneKey.
/// Undocumented keys used defensively: "CGSSessionScreenIsLocked" (present and
/// true while the screen is locked; absent when unlocked) and
/// "kCGSSessionSecureInputPID". Absence of the dictionary is treated as unavailable.
public struct SessionSnapshot: Equatable, Sendable {
    public var isAvailable: Bool
    public var isScreenLocked: Bool
    public var isOnConsole: Bool
    public var isLoginDone: Bool
    public var userName: String?
    public var userID: UInt32?
    public var secureInputPID: Int32?

    public init(isAvailable: Bool, isScreenLocked: Bool, isOnConsole: Bool, isLoginDone: Bool, userName: String?, userID: UInt32?, secureInputPID: Int32? = nil) {
        self.isAvailable = isAvailable
        self.isScreenLocked = isScreenLocked
        self.isOnConsole = isOnConsole
        self.isLoginDone = isLoginDone
        self.userName = userName
        self.userID = userID
        self.secureInputPID = secureInputPID
    }

    public static let unavailable = SessionSnapshot(isAvailable: false, isScreenLocked: false, isOnConsole: false, isLoginDone: false, userName: nil, userID: nil)

    public static func parse(_ dictionary: [String: Any]?) -> SessionSnapshot {
        guard let dictionary else { return .unavailable }
        func bool(_ key: String) -> Bool? {
            if let value = dictionary[key] as? Bool { return value }
            if let value = dictionary[key] as? NSNumber { return value.boolValue }
            return nil
        }
        func int(_ key: String) -> Int? {
            if let value = dictionary[key] as? Int { return value }
            if let value = dictionary[key] as? NSNumber { return value.intValue }
            return nil
        }
        let uid = int("kCGSSessionUserIDKey").flatMap { UInt32(exactly: $0) }
        let pid = int("kCGSSessionSecureInputPID").flatMap { Int32(exactly: $0) }
        return SessionSnapshot(
            isAvailable: true,
            isScreenLocked: bool("CGSSessionScreenIsLocked") ?? false,
            isOnConsole: bool("kCGSSessionOnConsoleKey") ?? false,
            isLoginDone: bool("kCGSessionLoginDoneKey") ?? false,
            userName: dictionary["kCGSSessionUserNameKey"] as? String,
            userID: uid,
            secureInputPID: (pid ?? 0) > 0 ? pid : nil
        )
    }

    /// Summary for the protocol and UI. A session that is not on the console
    /// (fast user switching), not fully logged in, or unreadable is "unavailable".
    public var lockState: MacLockState {
        guard isAvailable, isLoginDone, isOnConsole else { return .unavailable }
        return isScreenLocked ? .locked : .unlocked
    }

    /// True only for the exact situation this project targets: the expected user
    /// is logged in, owns the console, and the screen is locked.
    public func isLockedConsoleSession(of expectedUser: String, uid expectedUID: UInt32) -> Bool {
        guard lockState == .locked, let userName, let userID else { return false }
        return userName == expectedUser && userID == expectedUID
    }
}

public protocol SessionStateProviding: Sendable {
    func snapshot() -> SessionSnapshot
}
