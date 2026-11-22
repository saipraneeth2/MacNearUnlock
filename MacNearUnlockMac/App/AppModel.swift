import AppKit
import Combine
import Foundation
import MacNearUnlockShared
import os

/// Central coordinator for the Mac app. Owns the protocol engine, stores, pairing
/// host, overlay, departure lock and the (off-by-default) experimental adapter.
@MainActor
final class AppModel: ObservableObject {
    enum PairingPhase: Equatable {
        case idle
        case starting
        case waiting(PairingInvitation)
        case confirm(sas: ShortAuthenticationString, deviceName: String, fingerprint: String, phoneConfirmed: Bool, macConfirmed: Bool)
        case done(String)
        case failed(String)
    }

    static let shared = AppModel()

    let settings: AppSettings
    let keychain: KeychainStore
    let identity: MacIdentity?
    let identityError: String?
    let macName: String
    let sessionProvider = CGSessionStateProvider()
    let adapter: ExperimentalCredentialAdapter

    @Published private(set) var unlockState: UnlockState = .unavailable
    @Published private(set) var lockState: MacLockState = .unavailable
    @Published private(set) var devices: [PairedDeviceRecord] = []
    @Published private(set) var connected: Set<UUID> = []
    @Published private(set) var listenerPort: UInt16?
    @Published private(set) var listenerError: String?
    @Published private(set) var logEntries: [EngineLogEntry] = []
    @Published private(set) var lastResult: String?
    @Published private(set) var pairing: PairingPhase = .idle

    private let deviceStore: PairedDeviceStore
    private var engine: MacUnlockEngine?
    private var engineBridge: EngineBridge?
    private var pairingHost: PairingHost?
    private var pairingBridge: PairingBridge?
    private let monitor = SessionEventMonitor()
    private let pill = PillOverlayController()
    private let pairingWindow = PairingWindowPresenter()
    let departure: DepartureLockController
    private var isSleeping = false
    private var cancellables: Set<AnyCancellable> = []
    private let logger = Logger(subsystem: "MacNearUnlock", category: "engine")

    init() {
        let settings = AppSettings()
        self.settings = settings
        let keychain = KeychainStore(service: (Bundle.main.bundleIdentifier ?? "MacNearUnlock") + ".keys")
        self.keychain = keychain
        self.deviceStore = PairedDeviceStore(keychain: keychain)
        self.macName = Host.current().localizedName ?? "Mac"
        self.adapter = ExperimentalCredentialAdapter(settings: settings, keychain: keychain)
        self.departure = DepartureLockController(settings: settings)
        do {
            identity = try MacIdentityStore.loadOrCreate(keychain: keychain)
            identityError = nil
        } catch {
            identity = nil
            identityError = error.localizedDescription
        }
        devices = deviceStore.load()
        adapter.log = { [weak self] level, message in self?.appendLog(EngineLogEntry(level: level, message: message)) }
        departure.log = { [weak self] level, message in self?.appendLog(EngineLogEntry(level: level, message: message)) }
        startEngine()
        startMonitoring()
        settings.objectWillChange
            .sink { [weak self] _ in DispatchQueue.main.async { self?.applySettings() } }
            .store(in: &cancellables)
    }

    var connectedCount: Int { devices.filter { connected.contains($0.pairingID) }.count }

    // MARK: Discoverability

    func showPairingWindow() {
        pairingWindow.show(model: self)
    }

    func presentAfterLaunch() {
        if settings.showPill {
            pill.showHint(title: "MacNearUnlock is running", subtitle: "Click the lock icon in the menu bar, top right")
        }
        if devices.isEmpty { showPairingWindow() }
    }

    func presentOnReopen() {
        if devices.isEmpty {
            showPairingWindow()
        } else {
            pill.showHint(title: "MacNearUnlock is running", subtitle: "Click the lock icon in the menu bar, top right")
        }
    }

    // MARK: Engine

    private func startEngine() {
        guard let identity else {
            appendLog(EngineLogEntry(level: .warning, message: "Mac identity unavailable: \(identityError ?? "unknown")"))
            return
        }
        let engine = MacUnlockEngine(configuration: settings.engineConfiguration(identity: identity, macName: macName), signer: identity.signer, devices: devices, sessionProvider: sessionProvider)
        let bridge = EngineBridge(model: self)
        engine.delegate = bridge
        engineBridge = bridge
        self.engine = engine
        engine.start()
    }

    private func applySettings() {
        guard let identity else { return }
        if settings.authenticationOnly, settings.experimentalEnabled {
            adapter.setEnabled(false)
        }
        engine?.updateConfiguration(settings.engineConfiguration(identity: identity, macName: macName))
    }

    private func startMonitoring() {
        monitor.onHint = { [weak self] reason in self?.engine?.sessionDidChange(reason: reason) }
        monitor.onWillSleep = { [weak self] in
            self?.isSleeping = true
            self?.engine?.systemWillSleep()
        }
        monitor.onDidWake = { [weak self] in
            self?.isSleeping = false
            self?.engine?.systemDidWake()
        }
        monitor.onLogout = { [weak self] in
            self?.adapter.disarm()
            self?.engine?.stop()
        }
        monitor.start()
    }

    func sendTestApproval(to pairingID: UUID? = nil) {
        engine?.requestAuthenticationTest(pairingID: pairingID)
    }

    func revoke(_ pairingID: UUID) {
        do {
            try deviceStore.remove(pairingID: pairingID)
        } catch {
            appendLog(EngineLogEntry(level: .warning, message: "Could not remove pairing: \(error.localizedDescription)"))
        }
        reloadDevices()
    }

    func reloadDevices() {
        devices = deviceStore.load()
        engine?.updateDevices(devices)
    }

    func clearLog() { logEntries.removeAll() }

    func currentSnapshot() -> SessionSnapshot { sessionProvider.snapshot() }

    // MARK: Engine callbacks (main actor)

    fileprivate func engineStateChanged(_ state: UnlockState, lock: MacLockState) {
        unlockState = state
        lockState = lock
        if settings.showPill { pill.show(state: state) }
    }

    fileprivate func engineConnectedChanged(_ ids: Set<UUID>) {
        connected = ids
        departure.connectedDevicesChanged(ids, lockState: lockState)
    }

    fileprivate func engineVerified(_ approval: VerifiedApproval, authOnly: Bool) {
        let name = devices.first { $0.pairingID == approval.pairingID }?.deviceName ?? "iPhone"
        if authOnly {
            lastResult = "\(approval.action == .authenticationTest ? "Test approval" : "Unlock approval") verified from \(name) at \(Date().formatted(date: .omitted, time: .standard)); authentication only, login state unchanged."
            if settings.showPill { pill.show(state: .verified, detail: "Authentication only: Mac not unlocked") }
        } else if let engine {
            lastResult = "Unlock approval verified from \(name); handed to experimental adapter."
            adapter.handle(approval, engine: engine, sessionProvider: sessionProvider, systemSleeping: isSleeping)
        }
    }

    fileprivate func listenerChanged(port: UInt16?, error: String?) {
        listenerPort = port
        listenerError = error
    }

    fileprivate func appendLog(_ entry: EngineLogEntry) {
        if entry.level == .debug, !settings.debugLogging { return }
        // Protocol events use `notice` (the default level) so macOS persists them
        // to disk: `info` lives only in a small memory buffer and was dropped
        // within minutes during hardware testing. Messages never contain secrets.
        switch entry.level {
        case .security, .warning: logger.notice("[\(entry.level.rawValue, privacy: .public)] \(entry.message, privacy: .public)")
        case .info: logger.notice("\(entry.message, privacy: .public)")
        case .debug: logger.debug("\(entry.message, privacy: .public)")
        }
        logEntries.append(entry)
        if logEntries.count > 400 { logEntries.removeFirst(logEntries.count - 400) }
    }

    // MARK: Pairing

    func startPairing() {
        guard let identity else {
            pairing = .failed("Mac identity unavailable: \(identityError ?? "unknown error")")
            return
        }
        pairingHost?.cancel()
        let host = PairingHost(macID: identity.macID, macName: macName, macUsername: NSUserName(), signer: identity.signer, serviceName: macName)
        let bridge = PairingBridge(model: self, store: deviceStore)
        host.delegate = bridge
        pairingBridge = bridge
        pairingHost = host
        pairing = .starting
        host.start()
        appendLog(EngineLogEntry(level: .info, message: "Pairing invitation opened (expires in \(Int(MNUProtocol.pairingWindow))s)"))
    }

    func confirmPairingCode() {
        guard case .confirm(let sas, let name, let fingerprint, let phone, _) = pairing else { return }
        pairing = .confirm(sas: sas, deviceName: name, fingerprint: fingerprint, phoneConfirmed: phone, macConfirmed: true)
        pairingHost?.confirmByUser()
    }

    func rejectPairingCode() {
        pairingHost?.rejectByUser()
    }

    func cancelPairing() {
        if case .done = pairing {} else { pairingHost?.cancel() }
        pairingHost = nil
        pairing = .idle
    }

    fileprivate func pairingStarted(_ invitation: PairingInvitation) {
        pairing = .waiting(invitation)
    }

    fileprivate func pairingNeedsConfirmation(_ sas: ShortAuthenticationString, deviceName: String, fingerprint: String) {
        pairing = .confirm(sas: sas, deviceName: deviceName, fingerprint: fingerprint, phoneConfirmed: false, macConfirmed: false)
    }

    fileprivate func pairingPhoneConfirmed() {
        if case .confirm(let sas, let name, let fingerprint, _, let mac) = pairing {
            pairing = .confirm(sas: sas, deviceName: name, fingerprint: fingerprint, phoneConfirmed: true, macConfirmed: mac)
        }
    }

    fileprivate func pairingCompleted(_ record: PairedDeviceRecord) {
        pairing = .done(record.deviceName)
        appendLog(EngineLogEntry(level: .security, message: "Paired with \(record.deviceName) (key \(KeyFingerprint.display(record.publicKey).prefix(9)))"))
        reloadDevices()
    }

    fileprivate func pairingFailed(_ error: PairingError) {
        let message: String
        switch error {
        case .expired: message = "The invitation expired. Start again."
        case .fingerprintMismatch: message = "The iPhone saw a different Mac key than the QR code. Possible interception, so pairing stopped."
        case .badConfirmationSignature, .badTranscriptSignature, .badCompletionSignature: message = "A pairing signature did not verify. Pairing stopped."
        case .aborted(let reason): message = reason
        case .storageFailed: message = "The pairing could not be saved to the Keychain."
        default: message = "Pairing failed: \(error)"
        }
        if case .done = pairing { return }
        pairing = .failed(message)
        appendLog(EngineLogEntry(level: .security, message: "Pairing failed: \(message)"))
    }
}

// MARK: - Bridges (engine/pairing queues → main actor)

private final class EngineBridge: MacUnlockEngineDelegate {
    weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func engine(_ engine: MacUnlockEngine, didChangeState state: UnlockState, lockState: MacLockState) {
        DispatchQueue.main.async { [weak self] in self?.model?.engineStateChanged(state, lock: lockState) }
    }

    func engine(_ engine: MacUnlockEngine, connectedDevicesDidChange pairingIDs: Set<UUID>) {
        DispatchQueue.main.async { [weak self] in self?.model?.engineConnectedChanged(pairingIDs) }
    }

    func engine(_ engine: MacUnlockEngine, didVerify approval: VerifiedApproval, handledAsAuthenticationOnly: Bool) {
        DispatchQueue.main.async { [weak self] in self?.model?.engineVerified(approval, authOnly: handledAsAuthenticationOnly) }
    }

    func engine(_ engine: MacUnlockEngine, deviceRequestedRevocation pairingID: UUID) {
        DispatchQueue.main.async { [weak self] in self?.model?.revoke(pairingID) }
    }

    func engine(_ engine: MacUnlockEngine, listenerDidChange port: UInt16?, error: String?) {
        DispatchQueue.main.async { [weak self] in self?.model?.listenerChanged(port: port, error: error) }
    }

    func engine(_ engine: MacUnlockEngine, didLog entry: EngineLogEntry) {
        DispatchQueue.main.async { [weak self] in self?.model?.appendLog(entry) }
    }
}

private final class PairingBridge: PairingHostDelegate {
    weak var model: AppModel?
    private let store: PairedDeviceStore

    init(model: AppModel, store: PairedDeviceStore) {
        self.model = model
        self.store = store
    }

    func pairingHost(_ host: PairingHost, didStartWith invitation: PairingInvitation) {
        DispatchQueue.main.async { [weak self] in self?.model?.pairingStarted(invitation) }
    }

    func pairingHost(_ host: PairingHost, needsConfirmation sas: ShortAuthenticationString, deviceName: String, deviceKeyFingerprint: String) {
        DispatchQueue.main.async { [weak self] in self?.model?.pairingNeedsConfirmation(sas, deviceName: deviceName, fingerprint: deviceKeyFingerprint) }
    }

    func pairingHostPhoneDidConfirm(_ host: PairingHost) {
        DispatchQueue.main.async { [weak self] in self?.model?.pairingPhoneConfirmed() }
    }

    /// Runs on the pairing queue; persisting synchronously lets a Keychain failure abort the pairing.
    func pairingHost(_ host: PairingHost, didPair device: PairedDeviceRecord) throws {
        try store.add(device)
        DispatchQueue.main.async { [weak self] in self?.model?.pairingCompleted(device) }
    }

    func pairingHost(_ host: PairingHost, didFail error: PairingError) {
        DispatchQueue.main.async { [weak self] in self?.model?.pairingFailed(error) }
    }
}
