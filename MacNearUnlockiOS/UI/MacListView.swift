import MacNearUnlockShared
import SwiftUI

@main
struct MacNearUnlockiOSApp: App {
    @StateObject private var model = CompanionModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            MacListView()
                .environmentObject(model)
                // Only `.background` ends the sessions. The Face ID sheet (and
                // Control Center / Notification Center) make the scene
                // `.inactive` while the app is still on screen; dropping the
                // connection then made the Mac cancel the very request being
                // approved.
                .onChange(of: scenePhase) { _, phase in
                    model.setActive(phase != .background)
                }
                .onAppear { model.setActive(scenePhase != .background) }
        }
    }
}

struct MacListView: View {
    @EnvironmentObject private var model: CompanionModel
    @State private var showPairing = false
    @State private var path: [UUID] = []

    var body: some View {
        NavigationStack(path: $path) {
            List {
                ForEach(model.pendingRequests, id: \.1.requestID) { pairing, request in
                    Section {
                        RequestCard(pairing: pairing, request: request)
                    } header: {
                        Text("Approval requested")
                    }
                }

                Section {
                    ForEach(model.pairings) { pairing in
                        NavigationLink(value: pairing.id) {
                            MacRow(pairing: pairing, runtime: model.runtime(for: pairing.id), reachable: model.isReachable(pairing))
                        }
                    }
                } header: {
                    if !model.pairings.isEmpty { Text("Trusted Macs") }
                } footer: {
                    if !model.pairings.isEmpty {
                        Text("Approvals work only while this app is open on screen, and each one needs Face ID. Macs are found on your local network — that means reachable, not necessarily nearby.")
                    }
                }

                if let error = model.browser.lastError {
                    Section { Label(error, systemImage: "wifi.exclamationmark").font(.footnote) }
                }
            }
            .overlay {
                if model.pairings.isEmpty {
                    ContentUnavailableView {
                        Label("No Macs Paired", systemImage: "macmini")
                    } description: {
                        Text("On your Mac, choose Pair iPhone… from the MacNearUnlock menu, then tap + here and scan the code.")
                    } actions: {
                        Button("Pair a Mac") { showPairing = true }.buttonStyle(.borderedProminent)
                    }
                }
            }
            .navigationTitle("MacNearUnlock")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showPairing = true } label: { Label("Pair a Mac", systemImage: "plus") }
                }
            }
            .navigationDestination(for: UUID.self) { id in
                MacDetailView(pairingID: id)
            }
            .sheet(isPresented: $showPairing) {
                PairingFlowView()
                    .environmentObject(model)
            }
            .alert("Pairing removed", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(model.alert ?? "")
            }
        }
    }
}

struct MacRow: View {
    let pairing: StoredPairing
    let runtime: CompanionModel.Runtime
    let reachable: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "macmini")
                .font(.title2)
                .foregroundStyle(runtime.connection == .connected ? Color.accentColor : .secondary)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(pairing.mac.macName).font(.headline)
                Text(statusText).font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var statusText: String {
        switch runtime.connection {
        case .connected:
            switch runtime.status?.lockState {
            case .locked: return "Connected · Mac is locked"
            case .unlocked: return "Connected · Mac is unlocked"
            case .unavailable: return "Connected · Mac session unavailable"
            case nil: return "Connected"
            }
        case .connecting, .authenticating: return "Connecting…"
        case .failed: return reachable ? "Could not authenticate with this Mac" : "Not found on this network"
        case .idle: return reachable ? "Found on this network" : "Not found on this network"
        }
    }
}

struct RequestCard: View {
    @EnvironmentObject private var model: CompanionModel
    let pairing: StoredPairing
    let request: UnlockRequest

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(request.action == .unlockSession ? "Unlock \(request.macName)" : "Authentication test", systemImage: request.action == .unlockSession ? "lock.open" : "checkmark.shield")
                .font(.headline)
            Text(request.action == .unlockSession
                 ? "Approve access to the locked session of “\(request.macUsername)” on \(request.macName)."
                 : "Proves the secure connection and Face ID signing work. The Mac stays as it is.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let remaining = max(0, Int(request.expiresAt.timeIntervalSince(context.date)))
                Text(remaining > 0 ? "Expires in \(remaining) s" : "Expired")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(remaining > 5 ? Color.secondary : Color.red)
            }
            Button {
                Task { await model.approve(pairing.id) }
            } label: {
                Label("Approve with Face ID", systemImage: "faceid")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.runtime(for: pairing.id).busy)
            Button("Decline", role: .destructive) { model.decline(pairing.id) }
                .frame(maxWidth: .infinity)
        }
        .padding(.vertical, 6)
    }
}
