import Foundation
import Network

public enum ClientConnectionState: Equatable, Sendable {
    case idle
    case connecting
    case authenticating
    case connected
    case failed(String)
}

public enum ClientError: LocalizedError, Equatable, Sendable {
    case notConnected
    case unknownRequest
    case requestExpired

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "The connection to the Mac dropped before the approval was sent, so the Mac cancelled the request. Nothing was approved — tap the button again."
        case .unknownRequest:
            return "That request is no longer pending. Start a new one."
        case .requestExpired:
            return "That request expired. Start a new one."
        }
    }
}

/// iPhone side of a paired session. Connects with the pairing's TLS-PSK, proves and
/// checks channel binding, validates every challenge against the pinned Mac key,
/// and sends approvals signed by a caller-supplied (biometric) signer.
///
/// Callbacks run on an internal serial queue; UI code must hop to the main actor.
public final class MacSessionClient: @unchecked Sendable {
    public let pinned: PinnedMac
    private let channelKey: Data
    private let appVersion: String
    private let validator: RequestValidator
    private let wall: WallClock
    private let queue = DispatchQueue(label: "MacNearUnlock.client")

    private var channel: FramedConnection?
    private var state: ClientConnectionState = .idle
    private var validatedRequests: [UUID: UnlockRequest] = [:]
    private var helloDeadline: DispatchWorkItem?
    private var pingTimer: DispatchSourceTimer?

    public var onStateChange: (@Sendable (ClientConnectionState) -> Void)?
    public var onStatus: (@Sendable (MacSessionStatus) -> Void)?
    public var onRequest: (@Sendable (UnlockRequest) -> Void)?
    public var onRequestRejected: (@Sendable (RequestRejection) -> Void)?
    public var onResult: (@Sendable (ApprovalResult) -> Void)?
    public var onRevokedByMac: (@Sendable () -> Void)?

    public init(pinned: PinnedMac, channelKey: Data, appVersion: String, wall: WallClock = SystemWallClock()) {
        precondition(channelKey.count == 32)
        self.pinned = pinned
        self.channelKey = channelKey
        self.appVersion = String(appVersion.prefix(32))
        self.wall = wall
        self.validator = RequestValidator(wall: wall)
    }

    public func connect(to endpoint: NWEndpoint, timeout: Int = 10) {
        queue.async { [self] in
            channel?.cancel()
            let parameters = TLSPSK.parameters(psks: [(channelKey, pinned.pskIdentity)], connectionTimeout: timeout)
            let channel = FramedConnection(connection: NWConnection(to: endpoint, using: parameters), queue: queue)
            self.channel = channel
            setState(.connecting)
            channel.onReady = { [weak self, weak channel] in
                guard let self, let channel else { return }
                self.sendHello(on: channel)
            }
            channel.onMessage = { [weak self] message in self?.handle(message) }
            channel.onClose = { [weak self, weak channel] reason in
                guard let self, self.channel === channel else { return }
                self.helloDeadline?.cancel()
                self.pingTimer?.cancel()
                self.channel = nil
                self.validatedRequests.removeAll()
                if case .connected = self.state, reason == nil {
                    self.setState(.idle)
                } else {
                    self.setState(.failed(reason ?? "Disconnected"))
                }
            }
            channel.start()
        }
    }

    public func disconnect() {
        queue.async { [self] in
            helloDeadline?.cancel()
            pingTimer?.cancel()
            let current = channel
            channel = nil
            current?.cancel()
            validatedRequests.removeAll()
            setState(.idle)
        }
    }

    /// Ask the Mac to issue a challenge (requires an explicit user tap in the UI).
    public func initiate(_ action: UnlockAction) {
        queue.async { [self] in
            guard case .connected = state else { return }
            channel?.send(.initiate(UnlockInitiation(action: action)))
        }
    }

    /// Signs and sends an approval. `signer` must enforce a fresh biometric
    /// authorization per signature (the iOS `BiometricSigner` does, in hardware).
    public func approve(_ request: UnlockRequest, signer: MessageSigner) async throws {
        let stored: UnlockRequest? = queue.sync { validatedRequests[request.requestID] }
        guard let stored, stored == request else { throw ClientError.unknownRequest }
        guard wall.now() <= stored.expiresAt.addingTimeInterval(MNUProtocol.clockSkewTolerance) else { throw ClientError.requestExpired }
        let reason = stored.action == .unlockSession
            ? "Approve access to \(stored.macName) for \(stored.macUsername)"
            : "Approve authentication test for \(stored.macName)"
        let signature = try await signer.sign(stored.approvalSigningBytes(), reason: reason)
        let approval = UnlockApproval(requestID: stored.requestID, pairingID: pinned.pairingID, deviceID: pinned.deviceID, signature: signature)
        try queue.sync {
            guard case .connected = state, let channel else { throw ClientError.notConnected }
            // One signature per challenge: forget it so the UI cannot sign twice.
            validatedRequests[stored.requestID] = nil
            channel.send(.approval(approval))
        }
    }

    public func decline(_ request: UnlockRequest, reason: DeclineReason) {
        queue.async { [self] in
            validatedRequests[request.requestID] = nil
            channel?.send(.decline(UnlockDecline(requestID: request.requestID, reason: reason)))
        }
    }

    /// Tells the Mac to forget this pairing (the caller also deletes local keys).
    public func sendRevoke(completion: (@Sendable () -> Void)? = nil) {
        queue.async { [self] in
            guard case .connected = state, let channel else {
                completion?()
                return
            }
            channel.send(.revoke(RevokeNotice(pairingID: pinned.pairingID))) { _ in completion?() }
        }
    }

    // MARK: Private (queue-confined)

    private func sendHello(on channel: FramedConnection) {
        guard let exporter = channel.exportKeyingMaterial() else {
            channel.cancel(reason: "TLS channel binding unavailable")
            return
        }
        setState(.authenticating)
        let binder = ChannelBinding.clientBinder(channelKey: channelKey, pairingID: pinned.pairingID, deviceID: pinned.deviceID, exporter: exporter)
        channel.send(.clientHello(ClientHello(pairingID: pinned.pairingID, deviceID: pinned.deviceID, appVersion: appVersion, binder: binder)))
        let deadline = DispatchWorkItem { [weak self, weak channel] in
            guard let self, let channel, self.state != .connected else { return }
            channel.cancel(reason: "Mac did not complete authentication")
        }
        helloDeadline = deadline
        queue.asyncAfter(deadline: .now() + MNUProtocol.helloTimeout, execute: deadline)
    }

    private func handle(_ message: WireMessage) {
        guard let channel else { return }
        if state != .connected {
            guard case .serverHello(let hello) = message,
                  hello.macID == pinned.macID,
                  let exporter = channel.exportKeyingMaterial(),
                  ChannelBinding.matches(hello.binder, expected: ChannelBinding.serverBinder(channelKey: channelKey, pairingID: pinned.pairingID, macID: pinned.macID, exporter: exporter))
            else {
                channel.cancel(reason: "Mac failed authentication")
                return
            }
            helloDeadline?.cancel()
            setState(.connected)
            onStatus?(hello.status)
            startPing()
            return
        }
        switch message {
        case .status(let status):
            onStatus?(status)
        case .unlockRequest(let signed):
            switch validator.validate(signed, pinned: pinned) {
            case .success(let request):
                validatedRequests = validatedRequests.filter { wall.now() <= $0.value.expiresAt.addingTimeInterval(MNUProtocol.clockSkewTolerance) }
                validatedRequests[request.requestID] = request
                onRequest?(request)
            case .failure(let rejection):
                onRequestRejected?(rejection)
                channel.send(.decline(UnlockDecline(requestID: signed.request.requestID, reason: .requestInvalid)))
            }
        case .result(let result):
            if let id = result.requestID { validatedRequests[id] = nil }
            onResult?(result)
        case .revoke(let notice) where notice.pairingID == pinned.pairingID:
            onRevokedByMac?()
            channel.cancel(reason: "Pairing revoked on Mac")
        case .ping:
            channel.send(.pong)
        case .pong, .error:
            break
        default:
            channel.cancel(reason: "Unexpected message from Mac")
        }
    }

    private func startPing() {
        pingTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 15, repeating: 15)
        timer.setEventHandler { [weak self] in self?.channel?.send(.ping) }
        timer.resume()
        pingTimer = timer
    }

    private func setState(_ new: ClientConnectionState) {
        guard new != state else { return }
        state = new
        onStateChange?(new)
    }
}
