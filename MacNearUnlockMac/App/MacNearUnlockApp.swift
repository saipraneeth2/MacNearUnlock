import AppKit
import MacNearUnlockShared
import SwiftUI

@main
struct MacNearUnlockApp: App {
    @StateObject private var model = AppModel()

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

        Window("Pair iPhone", id: "pairing") {
            PairingWindowView()
                .environmentObject(model)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
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
