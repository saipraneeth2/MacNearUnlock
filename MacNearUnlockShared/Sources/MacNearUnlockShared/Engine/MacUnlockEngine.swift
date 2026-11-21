import Foundation
import Network

public struct EngineLogEntry: Sendable, Identifiable, Equatable {
    public enum Level: String, Sendable {
        case debug, info, warning, security
    }

    public let id = UUID()
    public let date: Date
    public let level: Level
    public let message: String

    public init(date: Date = Date(), level: Level, message: String) {
        self.date = date
        self.level = level
        self.message = message
    }
}

public struct MacEngineConfiguration: Sendable, Equatable {
    public var macID: UUID
    public var macName: String
    public var macUsername: String
    public var macUID: UInt32
    public var approvalLifetime: TimeInterval
    /// Verify approvals but never hand them to any credential-entry component.
    public var authenticationOnly: Bool
    /// When true (default) the Mac never pushes a challenge on its own; the user
    /// starts each attempt from the foreground iPhone app.
    public var requirePhoneInitiation: Bool
    public var advertiseBonjour: Bool
    public var preferredPort: UInt16
    /// Drop authenticated connections that send nothing (not even a ping) for this long.
    public var connectionIdleTimeout: TimeInterval

    public init(macID: UUID, macName: String, macUsername: String, macUID: UInt32, approvalLifetime: TimeInterval = MNUProtocol.defaultApprovalLifetime, authenticationOnly: Bool = true, requirePhoneInitiation: Bool = true, advertiseBonjour: Bool = true, preferredPort: UInt16 = MNUProtocol.preferredPort, connectionIdleTimeout: TimeInterval = 45) {
        self.macID = macID
        self.macName = macName
        self.macUsername = macUsername
        self.macUID = macUID
        self.approvalLifetime = approvalLifetime
        self.authenticationOnly = authenticationOnly
        self.requirePhoneInitiation = requirePhoneInitiation
        self.advertiseBonjour = advertiseBonjour
        self.preferredPort = preferredPort
        self.connectionIdleTimeout = connectionIdleTimeout
    }
}

public protocol MacUnlockEngineDelegate: AnyObject {
    func engine(_ engine: MacUnlockEngine, didChangeState state: UnlockState, lockState: MacLockState)
    func engine(_ engine: MacUnlockEngine, connectedDevicesDidChange pairingIDs: Set<UUID>)
    /// `handledAsAuthenticationOnly` is true when the engine already consumed the
    /// approval in authentication-only mode (or for a test action). Otherwise the
    /// receiver owns the approval and must call `reportOutcome` when finished.
    func engine(_ engine: MacUnlockEngine, didVerify approval: VerifiedApproval, handledAsAuthenticationOnly: Bool)
    func engine(_ engine: MacUnlockEngine, deviceRequestedRevocation pairingID: UUID)
    func engine(_ engine: MacUnlockEngine, listenerDidChange port: UInt16?, error: String?)
    func engine(_ engine: MacUnlockEngine, didLog entry: EngineLogEntry)
}

/// The Mac's protocol engine. All mutable state is confined to `queue`; delegate
/// callbacks are delivered on that queue (UI code must hop to the main actor).
public final class MacUnlockEngine: @unchecked Sendable {
    public weak var delegate: MacUnlockEngineDelegate?

    public let queue = DispatchQueue(label: "MacNearUnlock.engine")
    private var configuration: MacEngineConfiguration
    private let authority: ChallengeAuthority
    private let sessionProvider: SessionStateProviding
    private let monotonic: MonotonicClock
    private let signer: MessageSigner

    private var devices: [UUID: PairedDeviceRecord] = [:]
    private var listener: NWListener?
    private var listenerUsesFallbackPort = false
    private var peers: [ObjectIdentifier: Peer] = [:]
    private var machine = UnlockStateMachine()
    private var effectiveLock: MacLockState = .unavailable
    private var isSleeping = false
    private var timer: DispatchSourceTimer?
    private var tick = 0
    private var resetWork: DispatchWorkItem?
    private var running = false

    private final class Peer: @unchecked Sendable {
        let channel: FramedConnection
        var pairingID: UUID?
        var lastActivity: MonotonicInstant
        var suspiciousEvents = 0
        var helloDeadline: DispatchWorkItem?

        init(channel: FramedConnection, now: MonotonicInstant) {
            self.channel = channel
            self.lastActivity = now
        }
    }

    public init(configuration: MacEngineConfiguration, signer: MessageSigner, devices: [PairedDeviceRecord], sessionProvider: SessionStateProviding, monotonic: MonotonicClock = SystemMonotonicClock(), wall: WallClock = SystemWallClock()) {
        self.configuration = configuration
        self.signer = signer
        self.sessionProvider = sessionProvider
        self.monotonic = monotonic
        self.authority = ChallengeAuthority(
            macID: configuration.macID,
            macName: configuration.macName,
            signer: signer,
            configuration: .init(lifetime: configuration.approvalLifetime),
            monotonic: monotonic,
            wall: wall
        )
        for device in devices { self.devices[device.pairingID] = device }
    }

    public var macPublicKey: Data { signer.publicKeyX963 }

    // MARK: Public API (thread-safe)

    public func start() {
        queue.async { [self] in
            guard !running else { return }
            running = true
            startListener()
            refreshSession(reason: "engine start")
            startTimer()
        }
    }

    public func stop() {
        queue.sync {
            running = false
            timer?.cancel()
            timer = nil
            listener?.cancel()
            listener = nil
            for peer in peers.values { peer.channel.cancel() }
            peers.removeAll()
            authority.invalidateAll()
        }
    }

    public func updateDevices(_ records: [PairedDeviceRecord]) {
        queue.async { [self] in
            let newDevices = Dictionary(uniqueKeysWithValues: records.map { ($0.pairingID, $0) })
            let removed = Set(devices.keys).subtracting(newDevices.keys)
            let keysChanged = Set(devices.keys) != Set(newDevices.keys)
                || newDevices.contains { devices[$0.key]?.channelKey != $0.value.channelKey }
            devices = newDevices
            for pairingID in removed {
                authority.invalidate(pairingID: pairingID)
                for peer in peers.values where peer.pairingID == pairingID {
                    peer.channel.send(.revoke(RevokeNotice(pairingID: pairingID)))
                    let channel = peer.channel
                    queue.asyncAfter(deadline: .now() + 0.3) { channel.cancel(reason: "Pairing revoked") }
                }
                log(.security, "Pairing \(pairingID.shortID) revoked; pending challenges invalidated")
            }
            if keysChanged, running { startListener() }
            notifyConnectedDevices()
        }
    }

    public func updateConfiguration(_ new: MacEngineConfiguration) {
        queue.async { [self] in
            let old = configuration
            configuration = new
            if old.approvalLifetime != new.approvalLifetime { authority.updateLifetime(new.approvalLifetime) }
            if old.authenticationOnly != new.authenticationOnly || old.requirePhoneInitiation != new.requirePhoneInitiation {
                invalidateAllPending(detail: "Mac settings changed")
            }
            if running, old.advertiseBonjour != new.advertiseBonjour || old.preferredPort != new.preferredPort || old.macName != new.macName {
                startListener()
            }
            broadcastStatus()
        }
    }

    /// Re-reads the authoritative session state. Call on any lock/unlock/session
    /// notification; the engine also polls every two seconds.
    public func sessionDidChange(reason: String) {
        queue.async { [self] in refreshSession(reason: reason) }
    }

    public func systemWillSleep() {
        queue.async { [self] in
            isSleeping = true
            refreshSession(reason: "system will sleep")
        }
    }

    public func systemDidWake() {
        queue.async { [self] in
            isSleeping = false
            refreshSession(reason: "system did wake")
        }
    }

    /// Issues an `.authenticationTest` challenge to one (or every) connected phone.
    public func requestAuthenticationTest(pairingID: UUID? = nil) {
        queue.async { [self] in
            let targets = authenticatedPeers().filter { pairingID == nil || $0.pairingID == pairingID }
            if targets.isEmpty {
                log(.warning, "Authentication test: no paired iPhone is connected (open the iPhone app)")
            }
            for peer in targets { issue(.authenticationTest, to: peer) }
        }
    }

    /// Final outcome of an approval that was handed to the delegate.
    public func reportOutcome(requestID: UUID, pairingID: UUID, outcome: ApprovalOutcome, detail: String) {
        queue.async { [self] in
            send(.result(ApprovalResult(requestID: requestID, outcome: outcome, detail: detail)), toPairing: pairingID)
            refreshSession(reason: "outcome reported")
        }
    }

    public func currentState() -> (UnlockState, MacLockState) {
        queue.sync { (machine.state, effectiveLock) }
    }

    // MARK: Session tracking

    private func refreshSession(reason: String) {
        let snapshot = sessionProvider.snapshot()
        var lock = isSleeping ? .unavailable : snapshot.lockState
        if lock != .unavailable, snapshot.userName != configuration.macUsername || snapshot.userID != configuration.macUID {
            // Another account owns this console session: never act for it.
            lock = .unavailable
        }
        guard lock != effectiveLock else { return }
        let previous = effectiveLock
        effectiveLock = lock
        invalidateAllPending(detail: "Mac session changed")
        switch lock {
        case .unlocked: transition(.sessionUnlocked)
        case .locked: transition(.sessionLocked)
        case .unavailable: transition(.sessionUnavailable)
        }
        log(.info, "Session \(previous.rawValue) → \(lock.rawValue) (\(reason))")
        broadcastStatus()
        if lock == .locked, !configuration.requirePhoneInitiation {
            for peer in authenticatedPeers() { issue(.unlockSession, to: peer) }
        }
    }

    private func transition(_ event: UnlockEvent) {
        let before = machine.state
        guard machine.handle(event) else {
            log(.debug, "Ignored event \(event) in state \(before.rawValue)")
            return
        }
        if machine.state != before {
            delegate?.engine(self, didChangeState: machine.state, lockState: effectiveLock)
        }
        switch machine.state {
        case .verified, .rejected, .expired: scheduleReset()
        default: resetWork?.cancel()
        }
    }

    private func scheduleReset() {
        resetWork?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard !self.authority.hasPending else { return }
            self.transition(.reset(locked: self.effectiveLock == .locked))
            if self.effectiveLock == .unavailable { self.transition(.sessionUnavailable) }
            self.broadcastStatus()
        }
        resetWork = work
        queue.asyncAfter(deadline: .now() + 3, execute: work)
    }

    private func invalidateAllPending(detail: String) {
        let invalidated = authority.invalidateAll()
        for signed in invalidated {
            send(.result(ApprovalResult(requestID: signed.request.requestID, outcome: .failed, detail: detail)), toPairing: signed.request.pairingID)
        }
        if !invalidated.isEmpty { log(.info, "Invalidated \(invalidated.count) pending challenge(s): \(detail)") }
    }

    // MARK: Listener

    private func startListener() {
        listener?.stateUpdateHandler = nil
        listener?.newConnectionHandler = nil
        listener?.cancel()
        listener = nil
        guard !devices.isEmpty else {
            delegate?.engine(self, listenerDidChange: nil, error: nil)
            return
        }
        let parameters = TLSPSK.parameters(psks: devices.values.map { ($0.channelKey, $0.pskIdentity) })
        let port = listenerUsesFallbackPort ? nil : NWEndpoint.Port(rawValue: configuration.preferredPort)
        let created: NWListener
        do {
            created = try port.map { try NWListener(using: parameters, on: $0) } ?? NWListener(using: parameters)
        } catch {
            delegate?.engine(self, listenerDidChange: nil, error: "Could not create listener: \(error.localizedDescription)")
            return
        }
        if configuration.advertiseBonjour {
            let txt = NWTXTRecord(["v": String(MNUProtocol.protocolVersion), "mid": configuration.macID.uuidString])
            created.service = NWListener.Service(name: nil, type: MNUProtocol.serviceType, domain: nil, txtRecord: txt)
        }
        created.stateUpdateHandler = { [weak self, weak created] state in
            guard let self, let created, self.listener === created else { return }
            switch state {
            case .ready:
                self.delegate?.engine(self, listenerDidChange: created.port?.rawValue, error: nil)
                self.log(.info, "Listening on port \(created.port?.rawValue ?? 0)\(self.configuration.advertiseBonjour ? " (Bonjour advertised)" : " (Bonjour off)")")
            case .failed(let error):
                self.log(.warning, "Listener failed: \(error.debugDescription)")
                if !self.listenerUsesFallbackPort {
                    self.listenerUsesFallbackPort = true
                    self.startListener()
                } else {
                    self.delegate?.engine(self, listenerDidChange: nil, error: error.debugDescription)
                    self.queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                        guard let self, self.running, self.listener === created else { return }
                        self.startListener()
                    }
                }
            default:
                break
            }
        }
        created.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener = created
        created.start(queue: queue)
    }

    private func accept(_ connection: NWConnection) {
        guard peers.count < MNUProtocol.maxConnections else {
            connection.cancel()
            log(.warning, "Refused connection: too many concurrent connections")
            return
        }
        let channel = FramedConnection(connection: connection, queue: queue, clock: monotonic)
        let peer = Peer(channel: channel, now: monotonic.now())
        let key = ObjectIdentifier(peer)
        peers[key] = peer
        channel.onReady = { [weak self, weak peer] in
            guard let self, let peer else { return }
            let deadline = DispatchWorkItem { [weak peer] in
                guard let peer, peer.pairingID == nil else { return }
                peer.channel.cancel(reason: "Hello timeout")
            }
            peer.helloDeadline = deadline
            self.queue.asyncAfter(deadline: .now() + MNUProtocol.helloTimeout, execute: deadline)
        }
        channel.onMessage = { [weak self, weak peer] message in
            guard let self, let peer else { return }
            peer.lastActivity = self.monotonic.now()
            self.handle(message, from: peer)
        }
        channel.onClose = { [weak self] reason in
            self?.peerClosed(key: key, reason: reason)
        }
        channel.start()
    }

    private func peerClosed(key: ObjectIdentifier, reason: String?) {
        guard let peer = peers.removeValue(forKey: key) else { return }
        peer.helloDeadline?.cancel()
        guard let pairingID = peer.pairingID else {
            if let reason, !peer.channel.didBecomeReady {
                log(.security, "Unauthenticated connection rejected at TLS layer (\(reason))")
            }
            return
        }
        let stillConnected = peers.values.contains { $0.pairingID == pairingID }
        if !stillConnected {
            let invalidated = authority.invalidate(pairingID: pairingID)
            if !invalidated.isEmpty {
                log(.info, "Connection lost; invalidated \(invalidated.count) challenge(s) for \(pairingID.shortID)")
                transition(.approvalRejected)
            }
        }
        log(.info, "Device \(deviceName(pairingID)) disconnected\(reason.map { " (\($0))" } ?? "")")
        notifyConnectedDevices()
    }

    // MARK: Message handling

    private func handle(_ message: WireMessage, from peer: Peer) {
        guard let pairingID = peer.pairingID else {
            guard case .clientHello(let hello) = message else {
                log(.security, "Dropped connection: first message was not a hello")
                peer.channel.cancel(reason: "Protocol violation")
                return
            }
            handleHello(hello, from: peer)
            return
        }
        switch message {
        case .initiate(let initiation):
            handleInitiation(initiation, from: peer, pairingID: pairingID)
        case .approval(let approval):
            handleApproval(approval, from: peer, pairingID: pairingID)
        case .decline(let decline):
            if authority.decline(requestID: decline.requestID, authenticatedPairingID: pairingID) {
                log(.info, "Request \(decline.requestID.shortID) declined on iPhone (\(decline.reason.rawValue))")
                transition(.approvalRejected)
                send(.result(ApprovalResult(requestID: decline.requestID, outcome: .rejected, detail: "Declined on iPhone")), to: peer)
            }
        case .revoke(let notice):
            guard notice.pairingID == pairingID else {
                suspicious(peer, "revoke for another pairing")
                return
            }
            log(.security, "iPhone \(deviceName(pairingID)) revoked its pairing")
            delegate?.engine(self, deviceRequestedRevocation: pairingID)
        case .ping:
            send(.pong, to: peer)
        case .pong:
            break
        default:
            suspicious(peer, "unexpected \(message.typeName)")
        }
    }

    private func handleHello(_ hello: ClientHello, from peer: Peer) {
        guard let device = devices[hello.pairingID], device.deviceID == hello.deviceID else {
            log(.security, "Rejected hello for unknown pairing")
            peer.channel.cancel(reason: "Unknown pairing")
            return
        }
        guard let exporter = peer.channel.exportKeyingMaterial() else {
            log(.security, "Rejected hello: TLS channel binding unavailable")
            peer.channel.cancel(reason: "No channel binding")
            return
        }
        let expected = ChannelBinding.clientBinder(channelKey: device.channelKey, pairingID: device.pairingID, deviceID: device.deviceID, exporter: exporter)
        guard ChannelBinding.matches(hello.binder, expected: expected) else {
            log(.security, "Rejected hello: binder mismatch for \(device.pairingID.shortID)")
            peer.channel.cancel(reason: "Binder mismatch")
            return
        }
        peer.helloDeadline?.cancel()
        // Keep only the newest connection per pairing. Challenges issued to the old
        // connection die with it, exactly as if it had dropped.
        for other in peers.values where other !== peer && other.pairingID == device.pairingID {
            other.pairingID = nil
            other.channel.cancel(reason: "Superseded by a newer connection")
            if !authority.invalidate(pairingID: device.pairingID).isEmpty {
                transition(.approvalRejected)
            }
        }
        peer.pairingID = device.pairingID
        let binder = ChannelBinding.serverBinder(channelKey: device.channelKey, pairingID: device.pairingID, macID: configuration.macID, exporter: exporter)
        send(.serverHello(ServerHello(macID: configuration.macID, binder: binder, status: status())), to: peer)
        log(.info, "Device \(device.deviceName) authenticated (app \(hello.appVersion))")
        notifyConnectedDevices()
        if effectiveLock == .locked, !configuration.requirePhoneInitiation, authority.pendingRequest(for: device.pairingID) == nil {
            issue(.unlockSession, to: peer)
        }
    }

    private func handleInitiation(_ initiation: UnlockInitiation, from peer: Peer, pairingID: UUID) {
        refreshSession(reason: "iPhone initiation")
        switch initiation.action {
        case .unlockSession:
            guard effectiveLock == .locked else {
                send(.result(ApprovalResult(requestID: nil, outcome: .failed, detail: effectiveLock == .unlocked ? "Mac is not locked" : "Mac session unavailable (asleep, switched user or logged out)")), to: peer)
                return
            }
        case .authenticationTest:
            guard effectiveLock != .unavailable else {
                send(.result(ApprovalResult(requestID: nil, outcome: .failed, detail: "Mac session unavailable")), to: peer)
                return
            }
        }
        issue(initiation.action, to: peer)
    }

    private func issue(_ action: UnlockAction, to peer: Peer) {
        guard let pairingID = peer.pairingID, let device = devices[pairingID] else { return }
        let username = configuration.macUsername
        Task { [self] in
            do {
                let signed = try await authority.issue(action: action, for: device, macUsername: username)
                queue.async { [self] in
                    guard peer.pairingID == pairingID, peers[ObjectIdentifier(peer)] != nil else {
                        authority.invalidate(pairingID: pairingID)
                        return
                    }
                    transition(.requestIssued)
                    log(.info, "Issued \(action.rawValue) challenge \(signed.request.requestID.shortID) to \(device.deviceName), expires in \(Int(signed.request.lifetime))s")
                    let engineQueue = queue
                    peer.channel.send(.unlockRequest(signed)) { [weak self] error in
                        engineQueue.async { [weak self] in
                            guard let self else { return }
                            if error == nil {
                                self.transition(.requestDelivered)
                            } else {
                                self.authority.invalidate(pairingID: pairingID)
                                self.transition(.approvalRejected)
                            }
                        }
                    }
                }
            } catch ChallengeIssueError.rateLimited {
                queue.async { [self] in
                    log(.warning, "Challenge rate limit reached for \(device.deviceName)")
                    send(.result(ApprovalResult(requestID: nil, outcome: .failed, detail: "Too many requests; wait a minute")), to: peer)
                }
            } catch {
                queue.async { [self] in
                    log(.warning, "Could not sign challenge: \(error.localizedDescription)")
                }
            }
        }
    }

    private func handleApproval(_ approval: UnlockApproval, from peer: Peer, pairingID: UUID) {
        // Re-read the authoritative session state immediately before deciding.
        refreshSession(reason: "approval received")
        let snapshot = isSleeping ? SessionSnapshot.unavailable : sessionProvider.snapshot()
        let result = authority.verify(
            approval,
            authenticatedPairingID: pairingID,
            device: devices[pairingID],
            session: snapshot,
            expectedUsername: configuration.macUsername,
            expectedUID: configuration.macUID
        )
        switch result {
        case .success(let verified):
            transition(.approvalVerified)
            let authOnly = configuration.authenticationOnly || verified.action == .authenticationTest
            log(.security, "Approval VERIFIED for \(verified.action.rawValue) request \(verified.requestID.shortID) from \(deviceName(pairingID))")
            if authOnly {
                _ = verified.consume()
                send(.result(ApprovalResult(requestID: verified.requestID, outcome: .verifiedAuthenticationOnly, detail: "Approval verified. Authentication-only: the Mac's login state was not changed.")), to: peer)
            }
            delegate?.engine(self, didVerify: verified, handledAsAuthenticationOnly: authOnly)
        case .failure(let reason):
            log(.security, "Approval REJECTED (\(reason.displayText)) for request \(approval.requestID.shortID) from \(deviceName(pairingID))")
            switch reason {
            case .unsolicited, .replayed, .wrongDevice:
                suspicious(peer, reason.displayText)
            default:
                transition(.approvalRejected)
            }
            send(.result(ApprovalResult(requestID: approval.requestID, outcome: reason == .expired ? .expired : .rejected, detail: reason.displayText)), to: peer)
        }
    }

    private func suspicious(_ peer: Peer, _ what: String) {
        peer.suspiciousEvents += 1
        log(.security, "Suspicious message from \(peer.pairingID.map(deviceName) ?? "unauthenticated peer"): \(what)")
        if peer.suspiciousEvents >= 5 {
            peer.channel.cancel(reason: "Too many invalid messages")
        }
    }

    // MARK: Timer: expiry, idle connections, session polling

    private func startTimer() {
        timer?.cancel()
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 1, repeating: 1)
        source.setEventHandler { [weak self] in self?.onTick() }
        source.resume()
        timer = source
    }

    private func onTick() {
        tick += 1
        for signed in authority.expireStale() {
            log(.info, "Challenge \(signed.request.requestID.shortID) expired")
            transition(.requestExpired)
            send(.result(ApprovalResult(requestID: signed.request.requestID, outcome: .expired, detail: "Request expired")), toPairing: signed.request.pairingID)
        }
        if tick % 2 == 0 { refreshSession(reason: "poll") }
        let now = monotonic.now()
        for peer in peers.values where now.seconds(since: peer.lastActivity) > configuration.connectionIdleTimeout {
            peer.channel.cancel(reason: "Idle timeout")
        }
    }

    // MARK: Helpers

    private func status() -> MacSessionStatus {
        MacSessionStatus(lockState: effectiveLock, engineState: machine.state, authenticationOnly: configuration.authenticationOnly, requiresPhoneInitiation: configuration.requirePhoneInitiation)
    }

    private func broadcastStatus() {
        let current = status()
        for peer in authenticatedPeers() { send(.status(current), to: peer) }
    }

    private func authenticatedPeers() -> [Peer] {
        peers.values.filter { $0.pairingID != nil }
    }

    private func send(_ message: WireMessage, to peer: Peer) {
        peer.channel.send(message)
    }

    private func send(_ message: WireMessage, toPairing pairingID: UUID) {
        for peer in peers.values where peer.pairingID == pairingID { peer.channel.send(message) }
    }

    private func notifyConnectedDevices() {
        delegate?.engine(self, connectedDevicesDidChange: Set(peers.values.compactMap(\.pairingID)))
    }

    private func deviceName(_ pairingID: UUID) -> String {
        devices[pairingID]?.deviceName ?? pairingID.shortID
    }

    private func log(_ level: EngineLogEntry.Level, _ message: String) {
        delegate?.engine(self, didLog: EngineLogEntry(level: level, message: message))
    }
}
