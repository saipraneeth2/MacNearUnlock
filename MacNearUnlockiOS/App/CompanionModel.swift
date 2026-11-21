import Combine
import Foundation
import MacNearUnlockShared
import Network
import UIKit

/// iPhone-side coordinator: trusted Macs, live sessions while the app is in the
/// foreground, pending requests and approval results.
@MainActor
final class CompanionModel: ObservableObject {
    struct Runtime: Equatable {
        var connection: ClientConnectionState = .idle
        var status: MacSessionStatus?
        var request: UnlockRequest?
        var message: String?
        var messageIsError = false
        var busy = false
    }

    @Published private(set) var pairings: [StoredPairing] = []
    @Published private(set) var runtime: [UUID: Runtime] = [:]
    @Published var alert: String?

    let browser = MacBrowser()
    private let store = PairingStore()
    private var clients: [UUID: MacSessionClient] = [:]
    private var isActive = false
    private var cancellables: Set<AnyCancellable> = []
    private let appVersion = (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "1.0"

    init() {
        pairings = store.load()
        // Views observe this model; forward the nested browser's changes to them.
        browser.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &cancellables)
        browser.$sessionEndpoints
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.connectAll() }
            .store(in: &cancellables)
    }

    func runtime(for id: UUID) -> Runtime { runtime[id] ?? Runtime() }

    var pendingRequests: [(StoredPairing, UnlockRequest)] {
        pairings.compactMap { pairing in runtime[pairing.id]?.request.map { (pairing, $0) } }
    }

    func isReachable(_ pairing: StoredPairing) -> Bool {
        browser.sessionEndpoints[pairing.mac.macID] != nil
    }

    // MARK: Foreground lifecycle

    /// Sessions exist only while the app is on screen. iOS suspends the app in the
    /// background, so there is no background Face ID prompt and no promise of one.
    func setActive(_ active: Bool) {
        guard active != isActive else { return }
        isActive = active
        if active {
            browser.start()
            connectAll()
        } else {
            for client in clients.values { client.disconnect() }
            clients.removeAll()
            for id in runtime.keys { runtime[id] = Runtime() }
            browser.stop()
        }
    }

    private func connectAll() {
        guard isActive else { return }
        for pairing in pairings { connectIfNeeded(pairing) }
    }

    func reconnect(_ pairingID: UUID) {
        guard let pairing = pairings.first(where: { $0.id == pairingID }) else { return }
        clients[pairingID]?.disconnect()
        clients[pairingID] = nil
        connectIfNeeded(pairing)
    }

    private func connectIfNeeded(_ pairing: StoredPairing) {
        guard clients[pairing.id] == nil, let endpoint = browser.sessionEndpoints[pairing.mac.macID] else { return }
        let client = MacSessionClient(pinned: pairing.mac, channelKey: pairing.channelKey, appVersion: appVersion)
        let id = pairing.id
        client.onStateChange = { [weak self] state in
            DispatchQueue.main.async { self?.connectionChanged(id, state) }
        }
        client.onStatus = { [weak self] status in
            DispatchQueue.main.async { self?.update(id) { $0.status = status } }
        }
        client.onRequest = { [weak self] request in
            DispatchQueue.main.async {
                self?.update(id) {
                    $0.request = request
                    $0.message = nil
                }
                UINotificationFeedbackGenerator().notificationOccurred(.warning)
            }
        }
        client.onRequestRejected = { [weak self] rejection in
            DispatchQueue.main.async { self?.update(id) { $0.message = "Ignored an invalid request: \(rejection.displayText)"; $0.messageIsError = true } }
        }
        client.onResult = { [weak self] result in
            DispatchQueue.main.async { self?.handleResult(id, result) }
        }
        client.onRevokedByMac = { [weak self] in
            DispatchQueue.main.async { self?.revokedByMac(id) }
        }
        clients[id] = client
        client.connect(to: endpoint)
    }

    private func connectionChanged(_ id: UUID, _ state: ClientConnectionState) {
        update(id) { runtime in
            runtime.connection = state
            if case .failed = state {
                runtime.request = nil
                runtime.status = nil
            }
        }
        if case .failed = state {
            clients[id] = nil
            // Retry later while in the foreground; a revoked pairing keeps failing at TLS.
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                guard let self, self.isActive, let pairing = self.pairings.first(where: { $0.id == id }) else { return }
                self.connectIfNeeded(pairing)
            }
        }
    }

    // MARK: User actions

    func requestUnlock(_ id: UUID, action: UnlockAction) {
        update(id) { $0.message = nil }
        clients[id]?.initiate(action)
    }

    func approve(_ id: UUID) async {
        guard let pairing = pairings.first(where: { $0.id == id }),
              let client = clients[id],
              let request = runtime(for: id).request
        else { return }
        update(id) { $0.busy = true }
        defer { update(id) { $0.busy = false } }
        do {
            let signer = try BiometricSigner.load(tag: pairing.keyTag, expectedBiometryState: pairing.biometryState)
            try await client.approve(request, signer: signer)
            update(id) {
                $0.request = nil
                $0.message = "Approved with Face ID. Waiting for the Mac to verify…"
                $0.messageIsError = false
            }
        } catch let error as BiometricError {
            client.decline(request, reason: error.declineReason)
            update(id) {
                $0.request = nil
                $0.message = error.localizedDescription
                $0.messageIsError = true
            }
        } catch let error as ClientError {
            update(id) { $0.request = nil; $0.message = error.localizedDescription; $0.messageIsError = true }
        } catch {
            update(id) { $0.request = nil; $0.message = "Could not send approval: \(error.localizedDescription)"; $0.messageIsError = true }
        }
    }

    func decline(_ id: UUID) {
        guard let request = runtime(for: id).request else { return }
        clients[id]?.decline(request, reason: .userDeclined)
        update(id) { $0.request = nil; $0.message = "Declined."; $0.messageIsError = false }
    }

    /// Removes the pairing locally (deleting the Secure Enclave key) and, when
    /// connected, tells the Mac to forget this iPhone too.
    func remove(_ id: UUID) {
        let finish = { [weak self] in
            DispatchQueue.main.async { self?.forget(id) }
        }
        if let client = clients[id] {
            client.sendRevoke { finish() }
        } else {
            finish()
        }
    }

    func add(outcome: PairingOutcome, keyTag: String, biometryState: Data?) throws {
        var all = pairings.filter { $0.mac.macID != outcome.mac.macID }
        // Re-pairing the same Mac replaces the old pairing and its key.
        for old in pairings where old.mac.macID == outcome.mac.macID {
            BiometricSigner.delete(tag: old.keyTag)
            clients[old.id]?.disconnect()
            clients[old.id] = nil
        }
        all.append(StoredPairing(mac: outcome.mac, channelKey: outcome.channelKey, keyTag: keyTag, biometryState: biometryState))
        try store.save(all)
        pairings = all
        connectAll()
    }

    // MARK: Private

    private func handleResult(_ id: UUID, _ result: ApprovalResult) {
        let isError: Bool
        switch result.outcome {
        case .verifiedAuthenticationOnly, .unlocked, .verifiedCredentialEntryAttempted: isError = false
        case .rejected, .expired, .failed: isError = true
        }
        update(id) { runtime in
            if let requestID = result.requestID, runtime.request?.requestID == requestID { runtime.request = nil }
            runtime.message = result.detail
            runtime.messageIsError = isError
        }
        UINotificationFeedbackGenerator().notificationOccurred(isError ? .error : .success)
    }

    private func revokedByMac(_ id: UUID) {
        let name = pairings.first { $0.id == id }?.mac.macName ?? "The Mac"
        forget(id)
        alert = "\(name) revoked this iPhone. Pair again to use it."
    }

    private func forget(_ id: UUID) {
        if let pairing = pairings.first(where: { $0.id == id }) { BiometricSigner.delete(tag: pairing.keyTag) }
        clients[id]?.disconnect()
        clients[id] = nil
        runtime[id] = nil
        pairings.removeAll { $0.id == id }
        try? store.save(pairings)
    }

    private func update(_ id: UUID, _ change: (inout Runtime) -> Void) {
        var value = runtime[id] ?? Runtime()
        change(&value)
        runtime[id] = value
    }
}
