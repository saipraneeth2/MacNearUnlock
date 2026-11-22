//
//  ExperimentalCredentialAdapter.swift
//  MacNearUnlock: EXPERIMENTAL, OFF BY DEFAULT
//
//  The only component that can act on a verified approval beyond reporting it.
//  It runs solely when ALL of the following hold (see CredentialEntryPolicy, which
//  is unit-tested in the shared package):
//    * compiled with EXPERIMENTAL_CREDENTIAL_ADAPTER,
//    * the user enabled it AND acknowledged the risk AND turned authentication-only off,
//    * it holds a freshly verified `.unlockSession` approval it consumed itself,
//    * the expected user's console session is logged in, on console and locked,
//    * the system and display are awake,
//    * Accessibility + event-posting permission were granted manually by the user,
//    * secure event input is active (a password field has focus) and, when the
//      owner can be determined, it is loginwindow,
//    * the vault was armed by a local authentication on this Mac,
//    * attempt rate limits and the consecutive-failure limit allow it.
//  After three consecutive failed attempts it disables itself and disarms the vault.
//

import ApplicationServices
import Carbon.HIToolbox
import CoreGraphics
import Foundation
import MacNearUnlockShared

@MainActor
final class ExperimentalCredentialAdapter: ObservableObject {
    @Published private(set) var lastOutcome = "Not used"
    @Published private(set) var vaultStored = false
    @Published private(set) var vaultArmed = false
    @Published private(set) var inFlight = false

    var log: ((EngineLogEntry.Level, String) -> Void)?

    #if EXPERIMENTAL_CREDENTIAL_ADAPTER
    static let isCompiledIn = true
    let vault: CredentialVault
    #else
    static let isCompiledIn = false
    #endif

    private let settings: AppSettings
    private let clock = SystemMonotonicClock()
    private var attemptTimes: [Date] = []
    private var lastAttempt: MonotonicInstant?

    init(settings: AppSettings, keychain: KeychainStore) {
        self.settings = settings
        #if EXPERIMENTAL_CREDENTIAL_ADAPTER
        vault = CredentialVault(keychain: keychain)
        #endif
        refresh()
    }

    var accessibilityTrusted: Bool { AXIsProcessTrusted() }
    var postEventAccess: Bool { CGPreflightPostEventAccess() }
    var secureInputActive: Bool { IsSecureEventInputEnabled() }

    func refresh() {
        #if EXPERIMENTAL_CREDENTIAL_ADAPTER
        vaultStored = vault.isStored
        vaultArmed = vault.isArmed
        #endif
    }

    /// Reasons enabling is refused right now (empty = may enable).
    func enableBlockers() -> [String] {
        var blockers: [String] = []
        if !Self.isCompiledIn { blockers.append("Adapter not compiled into this build") }
        if !settings.experimentalRiskAcknowledged { blockers.append("Acknowledge the security risk") }
        if settings.authenticationOnly { blockers.append("Turn off authentication-only mode") }
        if !vaultStored { blockers.append("Store your Mac password locally") }
        if !accessibilityTrusted || !postEventAccess { blockers.append("Grant Accessibility in System Settings") }
        return blockers
    }

    func setEnabled(_ enabled: Bool) {
        if enabled {
            guard enableBlockers().isEmpty else { return }
            settings.experimentalConsecutiveFailures = 0
            settings.experimentalEnabled = true
            log?(.security, "Experimental credential adapter ENABLED by user")
        } else {
            settings.experimentalEnabled = false
            disarm()
            log?(.security, "Experimental credential adapter disabled")
        }
    }

    #if EXPERIMENTAL_CREDENTIAL_ADAPTER
    func storePassword(_ password: inout Data) throws {
        try vault.store(password: &password)
        log?(.security, "Experimental: login password verified by Open Directory and stored (encrypted to Secure Enclave key)")
        refresh()
    }

    func arm() async throws {
        try await vault.arm(reason: "arm MacNearUnlock's experimental credential entry for this session")
        log?(.security, "Experimental: vault armed for up to \(Int(CredentialVault.armLifetime / 3600)) hours")
        refresh()
    }

    func deletePassword() throws {
        try vault.delete()
        settings.experimentalEnabled = false
        log?(.security, "Experimental: stored password deleted; adapter disabled")
        refresh()
    }
    #endif

    func disarm() {
        #if EXPERIMENTAL_CREDENTIAL_ADAPTER
        vault.disarm()
        #endif
        refresh()
    }

    // MARK: Approval handling

    func handle(_ approval: VerifiedApproval, engine: MacUnlockEngine, sessionProvider: SessionStateProviding, systemSleeping: Bool) {
        // Consume first: whatever happens next, this approval can drive nothing else.
        let consumed = approval.consume()
        refresh()
        let snapshot = sessionProvider.snapshot()
        let now = clock.now()
        attemptTimes = attemptTimes.filter { Date().timeIntervalSince($0) < 3600 }
        let inputs = CredentialEntryInputs(
            adapterEnabled: Self.isCompiledIn && settings.experimentalEnabled,
            riskAcknowledged: settings.experimentalRiskAcknowledged,
            authenticationOnlyMode: settings.authenticationOnly,
            credentialArmed: vaultArmed,
            accessibilityTrusted: accessibilityTrusted,
            postEventAccess: postEventAccess,
            approvalAction: approval.action,
            approvalConsumedByCaller: consumed,
            approvalAge: now.seconds(since: approval.verifiedAt),
            session: snapshot,
            expectedUsername: NSUserName(),
            expectedUID: getuid(),
            systemSleeping: systemSleeping,
            displayAsleep: ConsoleProbe.displayAsleep,
            secureInputEnabled: secureInputActive,
            secureInputOwnerIsLoginWindow: snapshot.secureInputPID.map { ConsoleProbe.processName(pid: $0) == "loginwindow" },
            consecutiveFailures: settings.experimentalConsecutiveFailures,
            attemptsInLastHour: attemptTimes.count,
            secondsSinceLastAttempt: lastAttempt.map { now.seconds(since: $0) }
        )
        if inFlight {
            finish(approval, engine: engine, outcome: .failed, detail: "Another credential entry attempt is in progress")
            return
        }
        if let denial = CredentialEntryPolicy.evaluate(inputs) {
            let outcome: ApprovalOutcome = denial == .adapterDisabled ? .verifiedAuthenticationOnly : .failed
            let detail = denial == .adapterDisabled
                ? "Approval verified. Credential entry is off, so the Mac stays locked; enter your password manually."
                : "Approval verified, but credential entry refused: \(denial.rawValue)."
            finish(approval, engine: engine, outcome: outcome, detail: detail)
            return
        }

        #if EXPERIMENTAL_CREDENTIAL_ADAPTER
        attemptTimes.append(Date())
        lastAttempt = now
        inFlight = true
        log?(.security, "Experimental: attempting credential entry for request \(approval.requestID.shortID)")
        let vault = self.vault
        let username = NSUserName()
        let uid = getuid()
        Task.detached(priority: .userInitiated) {
            let result = Self.performEntry(vault: vault, username: username, uid: uid)
            await MainActor.run {
                self.inFlight = false
                self.complete(result, approval: approval, engine: engine)
            }
        }
        #else
        finish(approval, engine: engine, outcome: .failed, detail: "Experimental adapter not compiled in")
        #endif
    }

    #if EXPERIMENTAL_CREDENTIAL_ADAPTER
    private enum EntryResult {
        case unlocked
        case stillLocked
        case refused(String)
    }

    /// Runs off the main thread. Re-checks the session immediately before typing.
    nonisolated private static func performEntry(vault: CredentialVault, username: String, uid: UInt32) -> EntryResult {
        let before = CGSessionStateProvider().snapshot()
        guard before.isLockedConsoleSession(of: username, uid: uid) else { return .refused("Session changed before entry") }
        guard IsSecureEventInputEnabled() else { return .refused("Password field not focused (secure input inactive)") }
        do {
            try vault.withPassword { try KeystrokeInjector.typeAndReturn($0) }
        } catch {
            return .refused(error.localizedDescription)
        }
        for _ in 0..<30 {
            Thread.sleep(forTimeInterval: 0.2)
            if CGSessionStateProvider().snapshot().lockState == .unlocked { return .unlocked }
        }
        return .stillLocked
    }

    private func complete(_ result: EntryResult, approval: VerifiedApproval, engine: MacUnlockEngine) {
        switch result {
        case .unlocked:
            settings.experimentalConsecutiveFailures = 0
            finish(approval, engine: engine, outcome: .unlocked, detail: "Mac unlocked by EXPERIMENTAL credential entry.")
        case .stillLocked, .refused:
            settings.experimentalConsecutiveFailures += 1
            var detail: String
            if case .refused(let reason) = result { detail = "Credential entry not performed: \(reason)." } else { detail = "Credential entry did not unlock the Mac." }
            if settings.experimentalConsecutiveFailures >= CredentialEntryPolicy.maxConsecutiveFailures {
                settings.experimentalEnabled = false
                vault.disarm()
                detail += " Experimental adapter disabled after repeated failures."
                log?(.security, "Experimental adapter AUTO-DISABLED after \(settings.experimentalConsecutiveFailures) consecutive failures")
            }
            finish(approval, engine: engine, outcome: .failed, detail: detail)
        }
        refresh()
    }
    #endif

    private func finish(_ approval: VerifiedApproval, engine: MacUnlockEngine, outcome: ApprovalOutcome, detail: String) {
        lastOutcome = detail
        log?(outcome == .unlocked ? .security : .info, "Experimental adapter: \(detail)")
        engine.reportOutcome(requestID: approval.requestID, pairingID: approval.pairingID, outcome: outcome, detail: detail)
    }
}
