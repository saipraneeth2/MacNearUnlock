import CoreGraphics
import Foundation
import MacNearUnlockShared

/// "Lock on departure": OFF by default and impossible to enable until a manual
/// test lock succeeded on this Mac.
///
/// Honest limits: the trigger is "no paired iPhone has an authenticated connection
/// for the grace period". iOS suspends the companion app shortly after it leaves
/// the foreground, so this fires when you switch apps or lock the phone, not only
/// when you walk away. It is NOT a proximity measurement. There is also no public
/// API to lock the screen; this posts the standard ⌃⌘Q shortcut (requires the
/// event-posting permission) and then confirms the lock through CGSession.
@MainActor
final class DepartureLockController {
    private let settings: AppSettings
    private var pending: Task<Void, Never>?
    private var sawConnection = false
    var log: ((EngineLogEntry.Level, String) -> Void)?

    init(settings: AppSettings) {
        self.settings = settings
    }

    func connectedDevicesChanged(_ connected: Set<UUID>, lockState: MacLockState) {
        if !connected.isEmpty {
            sawConnection = true
            if pending != nil {
                log?(.info, "Lock on departure cancelled: a paired iPhone reconnected")
            }
            pending?.cancel()
            pending = nil
            return
        }
        guard sawConnection else { return }
        // Every outcome below is logged so a hardware test can tell "not armed"
        // apart from "armed but failed to lock".
        guard settings.lockOnDeparture, settings.departureLockTested else {
            log?(.info, "No paired iPhone connected; lock on departure is off")
            return
        }
        guard lockState == .unlocked else {
            log?(.info, "No paired iPhone connected; Mac not unlocked (\(lockState.rawValue)), lock on departure not armed")
            return
        }
        sawConnection = false
        let grace = settings.departureGrace
        log?(.info, "Lock on departure armed: locking in \(Int(grace))s unless a paired iPhone reconnects")
        pending?.cancel()
        pending = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(grace * 1_000_000_000))
            guard !Task.isCancelled, let self, self.settings.lockOnDeparture else { return }
            guard CGSessionStateProvider().snapshot().lockState == .unlocked else { return }
            self.log?(.security, "Lock on departure: no paired iPhone connected for \(Int(grace))s; locking")
            let locked = await Self.lockScreen()
            self.log?(locked ? .info : .warning, locked ? "Screen locked" : "Lock on departure could not confirm the screen locked")
        }
    }

    /// Manual test; only a confirmed success allows enabling the feature.
    func testLock() async -> Bool {
        let ok = await Self.lockScreen()
        if ok { settings.departureLockTested = true }
        log?(ok ? .info : .warning, ok ? "Test lock succeeded" : "Test lock failed (grant Accessibility or check the ⌃⌘Q shortcut)")
        return ok
    }

    static func lockScreen() async -> Bool {
        guard CGPreflightPostEventAccess() else { return false }
        let source = CGEventSource(stateID: .hidSystemState)
        let control: CGKeyCode = 0x3B, command: CGKeyCode = 0x37, q: CGKeyCode = 0x0C
        let flags: CGEventFlags = [.maskControl, .maskCommand]
        let sequence: [(CGKeyCode, Bool, CGEventFlags)] = [
            (control, true, .maskControl), (command, true, flags),
            (q, true, flags), (q, false, flags),
            (command, false, .maskControl), (control, false, []),
        ]
        for (key, down, eventFlags) in sequence {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: down) else { return false }
            event.flags = eventFlags
            event.post(tap: .cghidEventTap)
            try? await Task.sleep(nanoseconds: 15_000_000)
        }
        for _ in 0..<20 {
            try? await Task.sleep(nanoseconds: 200_000_000)
            if CGSessionStateProvider().snapshot().lockState == .locked { return true }
        }
        return false
    }
}
