import Foundation
import Network
import Security

/// TLS configuration shared by every MacNearUnlock connection.
///
/// TLS 1.2 with `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` (RFC 7905):
/// * mutual authentication by a per-pairing 256-bit pre-shared key (no CA, no
///   certificates, nothing to substitute on the local network);
/// * ephemeral ECDHE, so recorded traffic stays confidential even if a PSK later leaks;
/// * AEAD record protection.
///
/// TLS 1.3 external PSKs are not accepted by Network.framework on the SDKs tested
/// (handshake fails), so 1.2 is pinned deliberately — see docs/PROTOCOL.md.
public enum TLSPSK {
    public static let cipherSuiteRawValue: UInt16 = 0xCCAC

    public static func parameters(psks: [(key: Data, identity: String)], connectionTimeout: Int = 10) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        for psk in psks {
            precondition(psk.key.count == 32, "PSKs are always 256-bit")
            sec_protocol_options_add_pre_shared_key(options, psk.key.dispatchData, Data(psk.identity.utf8).dispatchData)
        }
        if let suite = tls_ciphersuite_t(rawValue: cipherSuiteRawValue) {
            sec_protocol_options_append_tls_ciphersuite(options, suite)
        }
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv12)

        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = max(2, connectionTimeout)
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 10
        tcp.keepaliveInterval = 5
        tcp.keepaliveCount = 3
        tcp.noDelay = true

        let parameters = NWParameters(tls: tls, tcp: tcp)
        parameters.includePeerToPeer = false
        parameters.allowLocalEndpointReuse = true
        return parameters
    }
}

extension Data {
    var dispatchData: __DispatchData {
        withUnsafeBytes { DispatchData(bytes: $0) } as __DispatchData
    }
}

/// Length-prefixed, validated message channel over an `NWConnection`.
///
/// All callbacks run on `queue`. Any framing, decoding, validation or rate-limit
/// violation closes the connection — there is no partial recovery from hostile input.
public final class FramedConnection: @unchecked Sendable {
    public let connection: NWConnection
    public let queue: DispatchQueue

    public var onReady: (@Sendable () -> Void)?
    public var onMessage: (@Sendable (WireMessage) -> Void)?
    /// Called once. `reason` is nil for an orderly close.
    public var onClose: (@Sendable (String?) -> Void)?

    private var closed = false
    private var becameReady = false
    private var bucket = TokenBucket(capacity: 20, refillPerSecond: 5)
    private let clock: MonotonicClock

    public init(connection: NWConnection, queue: DispatchQueue, clock: MonotonicClock = SystemMonotonicClock()) {
        self.connection = connection
        self.queue = queue
        self.clock = clock
    }

    public var didBecomeReady: Bool { becameReady }

    public func start() {
        connection.stateUpdateHandler = { [weak self] state in
            self?.handle(state)
        }
        connection.start(queue: queue)
    }

    /// Thread-safe close request. Captures `self` strongly on purpose: callers often
    /// drop their last reference right after cancelling, and a weak capture would
    /// leave the underlying socket open.
    public func cancel(reason: String? = nil) {
        queue.async { self.close(reason: reason) }
    }

    public func send(_ message: WireMessage, completion: (@Sendable (Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self, !self.closed else {
                completion?(FrameError.malformedBody)
                return
            }
            do {
                let frame = try FrameCodec.encode(message)
                self.connection.send(content: frame, completion: .contentProcessed { error in
                    completion?(error)
                })
            } catch {
                completion?(error)
                self.close(reason: "Failed to encode outgoing message")
            }
        }
    }

    /// RFC 5705 exporter for channel binding. Nil until the TLS handshake finished.
    public func exportKeyingMaterial() -> Data? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else { return nil }
        let protocolMetadata = metadata.securityProtocolMetadata
        // Defence in depth: refuse anything other than the pinned suite/version.
        guard sec_protocol_metadata_get_negotiated_tls_protocol_version(protocolMetadata) == .TLSv12,
              sec_protocol_metadata_get_negotiated_tls_ciphersuite(protocolMetadata).rawValue == TLSPSK.cipherSuiteRawValue
        else { return nil }
        let label = MNUProtocol.exporterLabel
        let secret = label.withCString { pointer in
            sec_protocol_metadata_create_secret(protocolMetadata, label.utf8.count, pointer, MNUProtocol.exporterLength)
        }
        guard let secret else { return nil }
        let data = Data(secret as DispatchData)
        return data.count == MNUProtocol.exporterLength ? data : nil
    }

    public var remoteDescription: String {
        switch connection.endpoint {
        case .hostPort(let host, _): return "\(host)"
        case .service(let name, _, _, _): return name
        default: return "peer"
        }
    }

    // MARK: Private (queue-confined)

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            becameReady = true
            onReady?()
            receiveHeader()
        case .failed(let error):
            close(reason: "Connection failed: \(error.debugDescription)")
        case .waiting(let error):
            // TLS authentication failures surface as `.waiting` on the client.
            close(reason: "Connection unavailable: \(error.debugDescription)")
        case .cancelled:
            close(reason: nil)
        default:
            break
        }
    }

    private func receiveHeader() {
        connection.receive(minimumIncompleteLength: FrameCodec.headerLength, maximumLength: FrameCodec.headerLength) { [weak self] data, _, isComplete, error in
            guard let self, !self.closed else { return }
            if let error {
                self.close(reason: "Receive failed: \(error.debugDescription)")
                return
            }
            guard let data, data.count == FrameCodec.headerLength else {
                self.close(reason: isComplete ? nil : "Truncated frame header")
                return
            }
            do {
                let length = try FrameCodec.bodyLength(fromHeader: data)
                self.receiveBody(length: length)
            } catch {
                self.close(reason: "Rejected frame header")
            }
        }
    }

    private func receiveBody(length: Int) {
        connection.receive(minimumIncompleteLength: length, maximumLength: length) { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            if let error {
                self.close(reason: "Receive failed: \(error.debugDescription)")
                return
            }
            guard let data, data.count == length else {
                self.close(reason: "Truncated frame body")
                return
            }
            guard self.bucket.tryConsume(at: self.clock.now()) else {
                self.close(reason: "Rate limit exceeded")
                return
            }
            let message: WireMessage
            do {
                message = try FrameCodec.decodeBody(data)
            } catch {
                self.close(reason: "Rejected malformed message")
                return
            }
            self.onMessage?(message)
            if !self.closed { self.receiveHeader() }
        }
    }

    private func close(reason: String?) {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        let handler = onClose
        onClose = nil
        onMessage = nil
        onReady = nil
        handler?(reason)
    }
}
