import MacNearUnlockShared
import SwiftUI

struct MacDetailView: View {
    @EnvironmentObject private var model: CompanionModel
    @Environment(\.dismiss) private var dismiss
    let pairingID: UUID
    @State private var confirmRemove = false

    var body: some View {
        if let pairing = model.pairings.first(where: { $0.id == pairingID }) {
            let runtime = model.runtime(for: pairingID)
            List {
                Section {
                    LabeledContent("Account", value: pairing.mac.macUsername)
                    LabeledContent("Connection", value: connectionText(runtime, reachable: model.isReachable(pairing)))
                    if let status = runtime.status {
                        LabeledContent("Mac session", value: status.lockState.rawValue.capitalized)
                        if status.authenticationOnly {
                            Text("This Mac is in authentication-only mode: approvals are verified, but the Mac is never unlocked by MacNearUnlock.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }

                if let request = runtime.request {
                    Section("Approval requested") {
                        RequestCard(pairing: pairing, request: request)
                    }
                } else {
                    Section {
                        Button {
                            model.requestUnlock(pairingID, action: .unlockSession)
                        } label: {
                            Label("Request Unlock", systemImage: "lock.open")
                        }
                        .disabled(runtime.connection != .connected || runtime.status?.lockState != .locked)
                        Button {
                            model.requestUnlock(pairingID, action: .authenticationTest)
                        } label: {
                            Label("Run Authentication Test", systemImage: "checkmark.shield")
                        }
                        .disabled(runtime.connection != .connected)
                    } footer: {
                        Text("You will see the request here, then approve it with Face ID. Face ID is never requested while this app is in the background or your iPhone is locked.")
                    }
                }

                if let message = runtime.message {
                    Section {
                        Label(message, systemImage: runtime.messageIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(runtime.messageIsError ? .red : .green)
                    }
                }

                Section("Security") {
                    LabeledContent("Mac key") {
                        Text(KeyFingerprint.display(pairing.mac.macPublicKey)).font(.caption.monospaced())
                    }
                    LabeledContent("Paired", value: Date(millisecondsSince1970: pairing.mac.pairedAtMillis).formatted(date: .abbreviated, time: .shortened))
                    if case .failed = runtime.connection {
                        Button("Retry Connection") { model.reconnect(pairingID) }
                    }
                    Button("Remove Pairing", role: .destructive) { confirmRemove = true }
                }
            }
            .navigationTitle(pairing.mac.macName)
            .confirmationDialog("Remove \(pairing.mac.macName)?", isPresented: $confirmRemove, titleVisibility: .visible) {
                Button("Remove Pairing", role: .destructive) {
                    model.remove(pairingID)
                    dismiss()
                }
            } message: {
                Text("This iPhone's signing key for this Mac is deleted. If the Mac is reachable it is told to forget this iPhone; otherwise revoke it in the Mac's Devices settings too.")
            }
        } else {
            ContentUnavailableView("Pairing removed", systemImage: "macmini")
        }
    }

    private func connectionText(_ runtime: CompanionModel.Runtime, reachable: Bool) -> String {
        switch runtime.connection {
        case .connected: return "Secure session (same network)"
        case .connecting, .authenticating: return "Connecting…"
        case .failed(let reason): return reachable ? "Failed: \(reason)" : "Not found on this network"
        case .idle: return reachable ? "Found on this network" : "Not found on this network"
        }
    }
}
