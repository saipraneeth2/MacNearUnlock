import AppKit
import MacNearUnlockShared
import SwiftUI

/// Small floating status pill, centred near the top of the main display. It does
/// not depend on a notch and works on a Mac mini with any external display.
///
/// It is an ordinary non-activating panel inside the user session. macOS does not
/// show third-party windows above the lock screen through public API, so while the
/// screen is locked the pill is simply not visible; this app deliberately does not
/// use private window-server calls to change that.
@MainActor
final class PillOverlayController {
    private let model = PillModel()
    private var panel: NSPanel?
    private var hideWork: Task<Void, Never>?

    func show(state: UnlockState, detail: String? = nil) {
        guard let content = PillContent(state: state, detail: detail) else { return }
        model.content = content
        let panel = self.panel ?? makePanel()
        self.panel = panel
        position(panel)
        panel.alphaValue = 0
        panel.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.2
            panel.animator().alphaValue = 1
        }
        NSAccessibility.post(element: panel, notification: .announcementRequested, userInfo: [.announcement: content.title, .priority: NSAccessibilityPriorityLevel.high.rawValue])
        hideWork?.cancel()
        if content.isTerminal {
            hideWork = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 3_500_000_000)
                guard !Task.isCancelled else { return }
                self?.hide()
            }
        }
    }

    func hide() {
        guard let panel else { return }
        NSAnimationContext.runAnimationGroup({ context in
            context.duration = 0.25
            panel.animator().alphaValue = 0
        }, completionHandler: {
            Task { @MainActor in panel.orderOut(nil) }
        })
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 360, height: 64), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .statusBar
        panel.ignoresMouseEvents = true
        panel.isReleasedWhenClosed = false
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle, .fullScreenAuxiliary]
        panel.contentView = NSHostingView(rootView: PillView(model: model))
        return panel
    }

    private func position(_ panel: NSPanel) {
        guard let screen = NSScreen.main ?? NSScreen.screens.first else { return }
        let size = NSSize(width: 360, height: 64)
        let frame = screen.visibleFrame
        panel.setFrame(NSRect(x: frame.midX - size.width / 2, y: frame.maxY - size.height - 12, width: size.width, height: size.height), display: true)
    }
}

struct PillContent: Equatable {
    let symbol: String
    let title: String
    let subtitle: String
    let tint: Color
    let isTerminal: Bool
    let pulses: Bool

    init?(state: UnlockState, detail: String?) {
        switch state {
        case .requesting:
            self.init(symbol: "iphone.radiowaves.left.and.right", title: "Sending request to iPhone", subtitle: detail ?? "Open MacNearUnlock on your iPhone", tint: .accentColor, isTerminal: false, pulses: true)
        case .awaitingBiometrics:
            self.init(symbol: "faceid", title: "Approve on iPhone with Face ID", subtitle: detail ?? "Tap Approve in the iPhone app", tint: .accentColor, isTerminal: false, pulses: true)
        case .verified:
            self.init(symbol: "checkmark.seal.fill", title: "Approved on iPhone", subtitle: detail ?? "Signature verified", tint: .green, isTerminal: true, pulses: false)
        case .rejected:
            self.init(symbol: "xmark.seal.fill", title: "Approval rejected", subtitle: detail ?? "Use your password", tint: .red, isTerminal: true, pulses: false)
        case .expired:
            self.init(symbol: "clock.badge.exclamationmark", title: "Request expired", subtitle: detail ?? "Start again from the iPhone", tint: .orange, isTerminal: true, pulses: false)
        case .idle, .locked, .unavailable:
            return nil
        }
    }

    private init(symbol: String, title: String, subtitle: String, tint: Color, isTerminal: Bool, pulses: Bool) {
        self.symbol = symbol
        self.title = title
        self.subtitle = subtitle
        self.tint = tint
        self.isTerminal = isTerminal
        self.pulses = pulses
    }
}

@MainActor
final class PillModel: ObservableObject {
    @Published var content: PillContent?
}

struct PillView: View {
    @ObservedObject var model: PillModel

    var body: some View {
        if let content = model.content {
            HStack(spacing: 12) {
                Image(systemName: content.symbol)
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(content.tint)
                    .symbolEffect(.pulse, isActive: content.pulses)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(content.title).font(.headline)
                    Text(content.subtitle).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 18)
            .frame(width: 360, height: 64)
            .background(.regularMaterial, in: Capsule())
            .overlay(Capsule().strokeBorder(.separator, lineWidth: 0.5))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(content.title). \(content.subtitle)")
        }
    }
}
