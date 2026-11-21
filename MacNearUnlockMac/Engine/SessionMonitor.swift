import AppKit
import CoreGraphics
import Foundation
import MacNearUnlockShared

/// Authoritative session state from the window server.
struct CGSessionStateProvider: SessionStateProviding {
    func snapshot() -> SessionSnapshot {
        SessionSnapshot.parse(CGSessionCopyCurrentDictionary() as? [String: Any])
    }
}

/// Turns system notifications into "re-check now" hints for the engine.
///
/// Distributed notifications such as `com.apple.screenIsLocked` can be posted by
/// any process in the session, so they are never trusted as facts: each one only
/// triggers a fresh `CGSessionCopyCurrentDictionary()` read inside the engine, which
/// additionally polls every two seconds in case a notification was missed while
/// this process was suspended (the race Glance documents around lid-close sleep).
@MainActor
final class SessionEventMonitor {
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []

    var onHint: ((String) -> Void)?
    var onWillSleep: (() -> Void)?
    var onDidWake: (() -> Void)?
    var onLogout: (() -> Void)?

    func start() {
        let distributed = DistributedNotificationCenter.default()
        for name in ["com.apple.screenIsLocked", "com.apple.screenIsUnlocked", "com.apple.screensaver.didstart", "com.apple.screensaver.didstop"] {
            add(distributed, Notification.Name(name)) { [weak self] in self?.onHint?(name) }
        }
        let workspace = NSWorkspace.shared.notificationCenter
        add(workspace, NSWorkspace.willSleepNotification) { [weak self] in self?.onWillSleep?() }
        add(workspace, NSWorkspace.didWakeNotification) { [weak self] in self?.onDidWake?() }
        add(workspace, NSWorkspace.screensDidSleepNotification) { [weak self] in self?.onHint?("screens did sleep") }
        add(workspace, NSWorkspace.screensDidWakeNotification) { [weak self] in self?.onHint?("screens did wake") }
        // Fast user switching: our session leaves / regains the console.
        add(workspace, NSWorkspace.sessionDidResignActiveNotification) { [weak self] in self?.onHint?("session resigned console") }
        add(workspace, NSWorkspace.sessionDidBecomeActiveNotification) { [weak self] in self?.onHint?("session became active") }
        add(workspace, NSWorkspace.willPowerOffNotification) { [weak self] in self?.onLogout?() }
    }

    func stop() {
        for (center, token) in observers { center.removeObserver(token) }
        observers.removeAll()
    }

    private func add(_ center: NotificationCenter, _ name: Notification.Name, _ handler: @escaping @MainActor () -> Void) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { handler() }
        }
        observers.append((center, token))
    }
}

/// Signals used by the experimental adapter and diagnostics.
enum ConsoleProbe {
    static var displayAsleep: Bool {
        CGDisplayIsAsleep(CGMainDisplayID()) != 0
    }

    /// Name of a process by PID (public libproc API), e.g. "loginwindow".
    static func processName(pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        let length = proc_name(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }
}
