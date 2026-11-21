import AppKit
import MacNearUnlockShared
import ServiceManagement
import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettingsView().tabItem { Label("General", systemImage: "gearshape") }
            DevicesSettingsView().tabItem { Label("Devices", systemImage: "iphone") }
            AuthenticationSettingsView().tabItem { Label("Authentication", systemImage: "faceid") }
            SecuritySettingsView().tabItem { Label("Security", systemImage: "lock.shield") }
            DiagnosticsSettingsView().tabItem { Label("Diagnostics", systemImage: "stethoscope") }
        }
        .frame(width: 640, height: 560)
    }
}

// MARK: - General

struct GeneralSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var settings: AppSettings
    @State private var launchError: String?

    var body: some View {
        Form {
            Section("Status") {
                LabeledContent("Mac session", value: model.lockState.displayName)
                LabeledContent("Authentication state", value: model.unlockState.displayName)
                LabeledContent("Paired iPhones connected", value: "\(model.connectedCount) of \(model.devices.count)")
                LabeledContent("Listening") {
                    if let port = model.listenerPort {
                        Text("Port \(port)\(settings.autoDiscovery ? ", advertised via Bonjour" : ", Bonjour off")")
                    } else if model.devices.isEmpty {
                        Text("Not listening (no paired iPhone)").foregroundStyle(.secondary)
                    } else {
                        Text(model.listenerError ?? "Starting…").foregroundStyle(.secondary)
                    }
                }
            }
            Section("Startup") {
                Toggle("Open MacNearUnlock at login", isOn: Binding(
                    get: { settings.launchAtLoginStatus == .enabled || settings.launchAtLoginStatus == .requiresApproval },
                    set: { newValue in
                        do { try settings.setLaunchAtLogin(newValue); launchError = nil } catch { launchError = error.localizedDescription }
                    }
                ))
                if settings.launchAtLoginStatus == .requiresApproval {
                    HStack {
                        Text("Allow MacNearUnlock in Login Items to finish enabling.").foregroundStyle(.secondary)
                        Spacer()
                        Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                    }
                }
                if let launchError { Text(launchError).foregroundStyle(.red).font(.caption) }
                Text("The app starts only after you log in. It never runs at the FileVault pre-boot screen or the login window, so it cannot (and does not try to) sign you in after a restart or logout.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Discovery") {
                Toggle("Advertise this Mac with Bonjour (auto-discovery)", isOn: $settings.autoDiscovery)
                Text("Bonjour only shows that this Mac and the iPhone are on the same network. It is not proof of physical proximity and never authorizes anything by itself.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Display") {
                Toggle("Show status pill on screen", isOn: $settings.showPill)
                Text("The pill appears in your unlocked session. macOS does not let third-party windows appear over the lock screen through public APIs, so it is not shown while locked.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("This Mac") {
                LabeledContent("Name", value: model.macName)
                LabeledContent("Account", value: NSUserName())
                if let identity = model.identity {
                    LabeledContent("Identity key", value: identity.kind.rawValue)
                    LabeledContent("Fingerprint") { Text(identity.fingerprint).font(.caption.monospaced()).textSelection(.enabled) }
                } else {
                    Text(model.identityError ?? "Identity unavailable").foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { settings.refreshLaunchAtLogin() }
    }
}

// MARK: - Devices

struct DevicesSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var pendingRevoke: PairedDeviceRecord?

    var body: some View {
        Form {
            Section {
                if model.devices.isEmpty {
                    Text("No paired iPhones.").foregroundStyle(.secondary)
                }
                ForEach(model.devices) { device in
                    let isConnected = model.connected.contains(device.pairingID)
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: "iphone").font(.title2).foregroundStyle(isConnected ? .green : .secondary)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(device.deviceName).font(.headline)
                            Text("Paired \(Date(millisecondsSince1970: device.pairedAtMillis).formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption).foregroundStyle(.secondary)
                            Text("Key \(KeyFingerprint.display(device.publicKey))").font(.caption2.monospaced()).foregroundStyle(.secondary)
                            Text(isConnected ? "App connected over the local network" : "App not connected").font(.caption).foregroundStyle(isConnected ? .green : .secondary)
                        }
                        Spacer()
                        VStack(alignment: .trailing) {
                            Button("Test Approval") { model.sendTestApproval(to: device.pairingID) }.disabled(!isConnected)
                            Button("Revoke…", role: .destructive) { pendingRevoke = device }
                        }
                    }
                    .padding(.vertical, 4)
                }
            } header: {
                Text("Trusted iPhones")
            } footer: {
                Text("Revoking deletes the pinned key and channel key on this Mac immediately. The iPhone is told if it is connected; otherwise its next connection fails. You can also revoke from the iPhone.")
            }
            Section {
                Button {
                    model.showPairingWindow()
                } label: {
                    Label("Pair New iPhone…", systemImage: "qrcode")
                }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Revoke \(pendingRevoke?.deviceName ?? "")?", isPresented: Binding(get: { pendingRevoke != nil }, set: { if !$0 { pendingRevoke = nil } })) {
            Button("Revoke", role: .destructive) {
                if let device = pendingRevoke { model.revoke(device.pairingID) }
                pendingRevoke = nil
            }
        } message: {
            Text("This iPhone will no longer be able to approve anything for this Mac. Pair again to restore it.")
        }
    }
}

// MARK: - Authentication

struct AuthenticationSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var settings: AppSettings

    var body: some View {
        Form {
            Section {
                Toggle("Authentication-only mode", isOn: $settings.authenticationOnly)
                Text("Verifies every Face ID approval end-to-end — Secure Enclave signature, this Mac, this account, fresh 256-bit challenge, expiry, lock state and replay — and then stops. It never types, stores or changes anything related to your login. Recommended.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Requests") {
                Toggle("Require request from iPhone", isOn: $settings.requirePhoneInitiation)
                Text("When on, the Mac never pushes a request on its own; you start each attempt with a tap in the foreground iPhone app. Every approval always requires a fresh Face ID match on the iPhone — that cannot be turned off.")
                    .font(.caption).foregroundStyle(.secondary)
                LabeledContent("Approval expires after") {
                    HStack {
                        Slider(value: $settings.approvalLifetime, in: MNUProtocol.approvalLifetimeRange, step: 5).frame(width: 200)
                        Text("\(Int(settings.approvalLifetime)) s").monospacedDigit().frame(width: 44, alignment: .trailing)
                    }
                }
                Stepper(value: $settings.connectionTimeout, in: 15...300, step: 15) {
                    LabeledContent("Drop idle connections after", value: "\(Int(settings.connectionTimeout)) s")
                }
            }
            Section("Test") {
                LabeledContent("Current state", value: model.unlockState.displayName)
                Button("Send Test Approval to Connected iPhones") { model.sendTestApproval() }
                    .disabled(model.connectedCount == 0)
                Text("A test approval uses the identical protocol with the action “auth-test”, which the Mac never treats as an unlock.")
                    .font(.caption).foregroundStyle(.secondary)
                if let result = model.lastResult { Text(result).font(.caption) }
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Security

struct SecuritySettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var adapter: ExperimentalCredentialAdapter
    @State private var testingLock = false
    @State private var lockTestResult: String?
    @State private var showStoreSheet = false
    @State private var actionError: String?

    var body: some View {
        Form {
            Section {
                Text("“Departure” means no paired iPhone app has been connected for the grace period. iOS suspends the app soon after it leaves the screen, so this also fires when you switch apps or lock your phone. It is not a distance measurement.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button(testingLock ? "Locking…" : "Test Lock Now") {
                        testingLock = true
                        Task {
                            let ok = await model.departure.testLock()
                            lockTestResult = ok ? "Lock confirmed by CGSession." : "Could not confirm a lock. Grant Accessibility to MacNearUnlock and keep the ⌃⌘Q shortcut enabled."
                            testingLock = false
                        }
                    }
                    .disabled(testingLock)
                    if let lockTestResult { Text(lockTestResult).font(.caption) }
                }
                Toggle("Lock this Mac when no paired iPhone is connected", isOn: $settings.lockOnDeparture)
                    .disabled(!settings.departureLockTested)
                Stepper(value: $settings.departureGrace, in: 15...600, step: 15) {
                    LabeledContent("Grace period", value: "\(Int(settings.departureGrace)) s")
                }
                .disabled(!settings.lockOnDeparture)
            } header: {
                Text("Lock on departure (off by default)")
            } footer: {
                if !settings.departureLockTested {
                    Text("Run a successful test lock before this can be enabled.")
                } else {
                    Text("The countdown starts when the last connected iPhone disconnects, so turn this on while the iPhone app is open and connected.")
                }
            }

            Section {
                Label("Experimental and not an Apple authentication API", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text("""
                This optional adapter stores your Mac login password on this Mac (encrypted to a Secure Enclave key that needs your local Mac password or Apple Watch to arm) and, after a verified Face ID approval, types it into the lock screen with synthetic keyboard events — the same technique Glance uses. Storing a reversible copy of your password increases risk: anyone who can run code as you while it is armed could misuse it. It may stop working in any macOS update, never works after restart/logout/FileVault pre-boot, and your password always remains the normal way in.
                """)
                .font(.caption).foregroundStyle(.secondary)
                if !ExperimentalCredentialAdapter.isCompiledIn {
                    Text("Not compiled into this build.").foregroundStyle(.secondary)
                }
                Toggle("I understand the risks of storing a reversible Mac password", isOn: $settings.experimentalRiskAcknowledged)
                    .onChange(of: settings.experimentalRiskAcknowledged) { _, acknowledged in
                        if !acknowledged { adapter.setEnabled(false) }
                    }
                checklist
                if let actionError { Text(actionError).font(.caption).foregroundStyle(.red) }
                Toggle("Enable experimental credential entry", isOn: Binding(
                    get: { settings.experimentalEnabled },
                    set: { adapter.setEnabled($0) }
                ))
                .disabled(!settings.experimentalEnabled && !adapter.enableBlockers().isEmpty)
                if !settings.experimentalEnabled, !adapter.enableBlockers().isEmpty {
                    Text("To enable: " + adapter.enableBlockers().joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                }
                Text("Last result: \(adapter.lastOutcome)").font(.caption).foregroundStyle(.secondary)
            } header: {
                Text("Experimental lock-screen credential entry (off by default)")
            }
        }
        .formStyle(.grouped)
        .onAppear { adapter.refresh() }
        .sheet(isPresented: $showStoreSheet) {
            StorePasswordSheet { adapter.refresh() }
                .environmentObject(adapter)
        }
    }

    @ViewBuilder
    private var checklist: some View {
        check("Secure Enclave available", SecureEnclaveIdentitySigner.isAvailable)
        HStack {
            check("Accessibility & event posting granted", adapter.accessibilityTrusted && adapter.postEventAccess)
            Spacer()
            Button("Open Accessibility Settings") {
                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") { NSWorkspace.shared.open(url) }
            }
        }
        HStack {
            check("Mac password stored (encrypted, this Mac only)", adapter.vaultStored)
            Spacer()
            if adapter.vaultStored {
                Button("Delete", role: .destructive) {
                    #if EXPERIMENTAL_CREDENTIAL_ADAPTER
                    do { try adapter.deletePassword(); actionError = nil } catch { actionError = error.localizedDescription }
                    #endif
                }
            } else {
                Button("Store Password…") { showStoreSheet = true }
                    .disabled(!settings.experimentalRiskAcknowledged || !ExperimentalCredentialAdapter.isCompiledIn)
            }
        }
        HStack {
            check("Armed for this app session", adapter.vaultArmed)
            Spacer()
            if adapter.vaultArmed {
                Button("Disarm") { adapter.disarm() }
            } else {
                Button("Arm…") {
                    #if EXPERIMENTAL_CREDENTIAL_ADAPTER
                    Task {
                        do { try await adapter.arm(); actionError = nil } catch { actionError = error.localizedDescription }
                    }
                    #endif
                }
                .disabled(!adapter.vaultStored)
            }
        }
        check("Consecutive failures: \(settings.experimentalConsecutiveFailures) of \(CredentialEntryPolicy.maxConsecutiveFailures)", settings.experimentalConsecutiveFailures < CredentialEntryPolicy.maxConsecutiveFailures)
    }

    private func check(_ title: String, _ ok: Bool) -> some View {
        Label(title, systemImage: ok ? "checkmark.circle.fill" : "circle")
            .foregroundStyle(ok ? .primary : .secondary)
            .accessibilityValue(ok ? "done" : "not done")
    }
}

/// Local-only password entry. The text never leaves this process except to Open
/// Directory for verification; it is not logged and is wiped after use.
struct StorePasswordSheet: View {
    @EnvironmentObject private var adapter: ExperimentalCredentialAdapter
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var consent = false
    @State private var error: String?
    var onFinish: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Store Mac Login Password").font(.title2.bold())
            Text("Enter the password for “\(NSUserName())”. It is checked with macOS, encrypted to this Mac's Secure Enclave and never sent to your iPhone or the network.")
                .foregroundStyle(.secondary)
            SecureField("Mac login password", text: $password)
                .textFieldStyle(.roundedBorder)
                .textContentType(.password)
            Toggle("I consent to storing a reversible copy of my Mac password on this Mac", isOn: $consent)
            if let error { Text(error).foregroundStyle(.red).font(.caption) }
            HStack {
                Spacer()
                Button("Cancel") {
                    password = ""
                    dismiss()
                }
                Button("Verify & Store") { store() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || !consent)
            }
        }
        .padding(24)
        .frame(width: 440)
    }

    private func store() {
        #if EXPERIMENTAL_CREDENTIAL_ADAPTER
        var bytes = Data(password.utf8)
        password = ""
        do {
            try adapter.storePassword(&bytes)
            onFinish()
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
        #endif
    }
}

// MARK: - Diagnostics

struct DiagnosticsSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var adapter: ExperimentalCredentialAdapter
    @State private var snapshot: SessionSnapshot = .unavailable

    var body: some View {
        Form {
            Section("Session (CGSessionCopyCurrentDictionary)") {
                LabeledContent("Available", value: yes(snapshot.isAvailable))
                LabeledContent("Login complete", value: yes(snapshot.isLoginDone))
                LabeledContent("On console", value: yes(snapshot.isOnConsole))
                LabeledContent("Screen locked", value: yes(snapshot.isScreenLocked))
                LabeledContent("Session user is this account", value: yes(snapshot.userName == NSUserName() && snapshot.userID == getuid()))
                LabeledContent("Secure input active", value: yes(adapter.secureInputActive))
                LabeledContent("Display asleep", value: yes(ConsoleProbe.displayAsleep))
                Button("Refresh") { snapshot = model.currentSnapshot() }
            }
            Section("Security configuration") {
                LabeledContent("Protocol", value: "v\(MNUProtocol.protocolVersion), TLS 1.2 ECDHE-PSK-CHACHA20-POLY1305 + exporter binding")
                LabeledContent("Keychain", value: model.keychain.mode.rawValue)
                LabeledContent("Experimental adapter compiled in", value: yes(ExperimentalCredentialAdapter.isCompiledIn))
            }
            Section {
                Toggle("Debug logging", isOn: $settings.debugLogging)
                Text("Logs never contain passwords, keys, nonces or full signatures; request IDs are shortened.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Copy Log") {
                        let text = model.logEntries.map { "\($0.date.formatted(date: .omitted, time: .standard)) [\($0.level.rawValue)] \($0.message)" }.joined(separator: "\n")
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(text, forType: .string)
                    }
                    Button("Clear") { model.clearLog() }
                }
                ForEach(model.logEntries.reversed()) { entry in
                    HStack(alignment: .firstTextBaseline) {
                        Text(entry.date.formatted(date: .omitted, time: .standard)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        Text(entry.level.rawValue.uppercased()).font(.caption2.bold()).foregroundStyle(color(entry.level)).frame(width: 64, alignment: .leading)
                        Text(entry.message).font(.caption).textSelection(.enabled)
                    }
                }
            } header: {
                Text("Event log")
            }
        }
        .formStyle(.grouped)
        .onAppear { snapshot = model.currentSnapshot() }
    }

    private func yes(_ value: Bool) -> String { value ? "Yes" : "No" }

    private func color(_ level: EngineLogEntry.Level) -> Color {
        switch level {
        case .debug: return .secondary
        case .info: return .blue
        case .warning: return .orange
        case .security: return .purple
        }
    }
}
