import AppKit
import MacNearUnlockShared
import SwiftUI

@main
struct MacNearUnlockApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel.shared

    var body: some Scene {
        MenuBarExtra {
            MenuBarContentView()
                .environmentObject(model)
                .environmentObject(model.settings)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(model)
                .environmentObject(model.settings)
                .environmentObject(model.adapter)
        }
    }
}

/// A menu-bar-only app has no window or Dock icon, so make it discoverable:
/// on launch show a hint (and the pairing window if nothing is paired yet), and
/// do the same when the user opens the app again while it is already running.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async { AppModel.shared.presentAfterLaunch() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        AppModel.shared.presentOnReopen()
        return false
    }
}

struct MenuBarLabel: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Image(systemName: model.unlockState.menuSymbol)
            .accessibilityLabel("MacNearUnlock: \(model.unlockState.displayName)")
    }
}

extension UnlockState {
    var menuSymbol: String {
        switch self {
        case .idle: return "lock.open"
        case .locked: return "lock"
        case .requesting: return "iphone.radiowaves.left.and.right"
        case .awaitingBiometrics: return "faceid"
        case .verified: return "checkmark.shield"
        case .rejected: return "xmark.shield"
        case .expired: return "clock.badge.exclamationmark"
        case .unavailable: return "lock.slash"
        }
    }
}

extension MacLockState {
    var displayName: String {
        switch self {
        case .unlocked: return "Unlocked"
        case .locked: return "Locked"
        case .unavailable: return "Unavailable"
        }
    }
}
