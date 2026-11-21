import Foundation
import MacNearUnlockShared
import Network

/// Bonjour discovery on the local network.
///
/// Discovery is a convenience, never a trust signal: anyone on the network can
/// advertise any name or TXT record. A found service only tells us where to try a
/// TLS-PSK connection that a non-paired advertiser cannot complete, followed by
/// signature checks against the pinned Mac key.
@MainActor
final class MacBrowser: ObservableObject {
    /// Mac ID (from the untrusted TXT record) → endpoint to try.
    @Published private(set) var sessionEndpoints: [UUID: NWEndpoint] = [:]
    /// Bonjour names of Macs currently showing a pairing invitation.
    @Published private(set) var pairingServices: [String] = []
    @Published private(set) var lastError: String?

    private var sessionBrowser: NWBrowser?
    private var pairingBrowser: NWBrowser?

    func start() {
        guard sessionBrowser == nil else { return }
        let session = NWBrowser(for: .bonjourWithTXTRecord(type: MNUProtocol.serviceType, domain: nil), using: NWParameters())
        session.browseResultsChangedHandler = { [weak self] results, _ in
            MainActor.assumeIsolated { self?.updateSessions(results) }
        }
        session.stateUpdateHandler = { [weak self] state in
            MainActor.assumeIsolated { self?.handle(state) }
        }
        session.start(queue: .main)
        sessionBrowser = session

        let pairing = NWBrowser(for: .bonjour(type: MNUProtocol.pairingServiceType, domain: nil), using: NWParameters())
        pairing.browseResultsChangedHandler = { [weak self] results, _ in
            MainActor.assumeIsolated {
                self?.pairingServices = results.compactMap { result in
                    if case .service(let name, _, _, _) = result.endpoint { return name }
                    return nil
                }.sorted()
            }
        }
        pairing.start(queue: .main)
        pairingBrowser = pairing
    }

    func stop() {
        sessionBrowser?.cancel()
        pairingBrowser?.cancel()
        sessionBrowser = nil
        pairingBrowser = nil
        sessionEndpoints = [:]
        pairingServices = []
    }

    static func pairingEndpoint(serviceName: String) -> NWEndpoint {
        .service(name: serviceName, type: MNUProtocol.pairingServiceType, domain: "local.", interface: nil)
    }

    private func updateSessions(_ results: Set<NWBrowser.Result>) {
        var endpoints: [UUID: NWEndpoint] = [:]
        for result in results {
            guard case .bonjour(let txt) = result.metadata,
                  txt["v"] == String(MNUProtocol.protocolVersion),
                  let mid = txt["mid"], let macID = UUID(uuidString: mid)
            else { continue }
            endpoints[macID] = result.endpoint
        }
        sessionEndpoints = endpoints
    }

    private func handle(_ state: NWBrowser.State) {
        switch state {
        case .failed(let error), .waiting(let error):
            lastError = "Local network discovery unavailable (\(error.debugDescription)). Allow Local Network access for MacNearUnlock in Settings › Privacy & Security."
        case .ready:
            lastError = nil
        default:
            break
        }
    }
}
