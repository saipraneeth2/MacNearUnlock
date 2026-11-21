import AppKit
import SwiftUI

/// Shows the pairing window from anywhere: first launch, re-opening the app from
/// Finder/Xcode, the menu bar menu and Settings. It is AppKit-hosted so it can
/// appear before the user has ever found the menu bar icon (a menu-bar-only app
/// otherwise starts with no visible window at all).
@MainActor
final class PairingWindowPresenter {
    private var window: NSWindow?
    private var closeObserver: NSObjectProtocol?

    func show(model: AppModel) {
        NSApp.activate()
        if let window {
            window.makeKeyAndOrderFront(nil)
            return
        }
        let root = PairingWindowView(onClose: { [weak self] in self?.window?.close() })
            .environmentObject(model)
        let window = NSWindow(contentViewController: NSHostingController(rootView: root))
        window.title = "Pair iPhone"
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.center()
        closeObserver = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                model.cancelPairing()
                if let token = self?.closeObserver { NotificationCenter.default.removeObserver(token) }
                self?.closeObserver = nil
                self?.window = nil
            }
        }
        self.window = window
        window.makeKeyAndOrderFront(nil)
    }
}
