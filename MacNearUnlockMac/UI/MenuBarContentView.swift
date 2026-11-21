import AppKit
import MacNearUnlockShared
import SwiftUI

struct MenuBarContentView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var settings: AppSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: model.unlockState.menuSymbol)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text("MacNearUnlock").font(.headline)
                    Text("\(model.unlockState.displayName) · Session \(model.lockState.displayName)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            if settings.authenticationOnly {
                Label("Authentication-only mode: approvals are verified, the Mac is never unlocked by this app.", systemImage: "checkmark.shield")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if settings.experimentalEnabled {
                Label("Experimental credential entry is ON.", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            Divider()

            if model.devices.isEmpty {
                Text("No paired iPhone yet.").foregroundStyle(.secondary)
            } else {
                ForEach(model.devices) { device in
                    HStack {
                        Image(systemName: "iphone")
                        Text(device.deviceName)
                        Spacer()
                        let isConnected = model.connected.contains(device.pairingID)
                        Text(isConnected ? "Connected (same network)" : "App not connected")
                            .font(.caption)
                            .foregroundStyle(isConnected ? .green : .secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
            }

            if let result = model.lastResult {
                Text(result).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            Button {
                model.sendTestApproval()
            } label: {
                Label("Send Test Approval", systemImage: "checkmark.circle")
            }
            .disabled(model.connectedCount == 0)
            .help("Asks connected iPhones to approve an authentication test. Never unlocks the Mac.")

            Button {
                model.showPairingWindow()
            } label: {
                Label("Pair iPhone…", systemImage: "qrcode")
            }

            SettingsLink {
                Label("Settings…", systemImage: "gearshape")
            }
            .simultaneousGesture(TapGesture().onEnded { NSApp.activate() })

            Divider()

            Button("Quit MacNearUnlock") { NSApp.terminate(nil) }
                .keyboardShortcut("q")
        }
        .buttonStyle(.borderless)
        .padding(14)
        .frame(width: 320)
    }
}
