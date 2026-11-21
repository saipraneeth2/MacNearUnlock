import Network
import XCTest
@testable import MacNearUnlockShared

// End-to-end tests over real TLS-PSK connections on 127.0.0.1. They exercise the
// same engine, client, pairing and verification code the apps use, with software
// keys standing in for the Secure Enclave and Face ID.

final class EngineRecorder: MacUnlockEngineDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var _states: [UnlockState] = []
    private var _logs: [EngineLogEntry] = []
    private var _verified: [(VerifiedApproval, Bool)] = []
    private var _revocations: [UUID] = []
    private var _port: UInt16?
    private var _connected: Set<UUID> = []
    var consumeAndReportUnlock = false

    var states: [UnlockState] { lock.withLock { _states } }
    var logs: [EngineLogEntry] { lock.withLock { _logs } }
    var verified: [(VerifiedApproval, Bool)] { lock.withLock { _verified } }
    var revocations: [UUID] { lock.withLock { _revocations } }
    var port: UInt16? { lock.withLock { _port } }
    var connected: Set<UUID> { lock.withLock { _connected } }

    func engine(_ engine: MacUnlockEngine, didChangeState state: UnlockState, lockState: MacLockState) { lock.withLock { _states.append(state) } }
    func engine(_ engine: MacUnlockEngine, connectedDevicesDidChange pairingIDs: Set<UUID>) { lock.withLock { _connected = pairingIDs } }
    func engine(_ engine: MacUnlockEngine, didVerify approval: VerifiedApproval, handledAsAuthenticationOnly: Bool) {
        lock.withLock { _verified.append((approval, handledAsAuthenticationOnly)) }
        if !handledAsAuthenticationOnly, consumeAndReportUnlock {
            XCTAssertTrue(approval.consume())
            engine.reportOutcome(requestID: approval.requestID, pairingID: approval.pairingID, outcome: .verifiedCredentialEntryAttempted, detail: "test adapter")
        }
    }
    func engine(_ engine: MacUnlockEngine, deviceRequestedRevocation pairingID: UUID) { lock.withLock { _revocations.append(pairingID) } }
    func engine(_ engine: MacUnlockEngine, listenerDidChange port: UInt16?, error: String?) { lock.withLock { _port = port } }
    func engine(_ engine: MacUnlockEngine, didLog entry: EngineLogEntry) { lock.withLock { _logs.append(entry) } }
}

final class ClientRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var _states: [ClientConnectionState] = []
    private var _requests: [UnlockRequest] = []
    private var _results: [ApprovalResult] = []
    private var _rejections: [RequestRejection] = []
    private var _statuses: [MacSessionStatus] = []
    private var _revoked = false

    var states: [ClientConnectionState] { lock.withLock { _states } }
    var requests: [UnlockRequest] { lock.withLock { _requests } }
    var results: [ApprovalResult] { lock.withLock { _results } }
    var rejections: [RequestRejection] { lock.withLock { _rejections } }
    var statuses: [MacSessionStatus] { lock.withLock { _statuses } }
    var revoked: Bool { lock.withLock { _revoked } }

    func attach(to client: MacSessionClient) {
        client.onStateChange = { [weak self] state in self?.lock.withLock { self?._states.append(state) } }
        client.onRequest = { [weak self] request in self?.lock.withLock { self?._requests.append(request) } }
        client.onResult = { [weak self] result in self?.lock.withLock { self?._results.append(result) } }
        client.onRequestRejected = { [weak self] rejection in self?.lock.withLock { self?._rejections.append(rejection) } }
        client.onStatus = { [weak self] status in self?.lock.withLock { self?._statuses.append(status) } }
        client.onRevokedByMac = { [weak self] in self?.lock.withLock { self?._revoked = true } }
    }
}

/// Minimal hand-driven peer for sending messages the real client would never send.
final class RawPeer: @unchecked Sendable {
    let channel: FramedConnection
    private let lock = NSLock()
    private var _received: [WireMessage] = []
    private var _closed: String??
    private var _ready = false

    var received: [WireMessage] { lock.withLock { _received } }
    var closed: Bool { lock.withLock { _closed != nil } }
    var ready: Bool { lock.withLock { _ready } }

    init(port: UInt16, key: Data, identity: String) {
        let connection = NWConnection(to: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!), using: TLSPSK.parameters(psks: [(key, identity)]))
        channel = FramedConnection(connection: connection, queue: DispatchQueue(label: "raw-peer"))
        channel.onReady = { [weak self] in self?.lock.withLock { self?._ready = true } }
        channel.onMessage = { [weak self] message in self?.lock.withLock { self?._received.append(message) } }
        channel.onClose = { [weak self] reason in self?.lock.withLock { self?._closed = .some(reason) } }
        channel.start()
    }

    func hello(pairingID: UUID, deviceID: UUID, binderKey: Data) {
        let exporter = channel.queue.sync { channel.exportKeyingMaterial() } ?? Data(count: 32)
        channel.send(.clientHello(ClientHello(pairingID: pairingID, deviceID: deviceID, appVersion: "raw", binder: ChannelBinding.clientBinder(channelKey: binderKey, pairingID: pairingID, deviceID: deviceID, exporter: exporter))))
    }
}

func eventually(_ timeout: TimeInterval = 5, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 20_000_000)
    }
    return condition()
}

final class LoopbackIntegrationTests: XCTestCase {
    private var engines: [MacUnlockEngine] = []
    private var clients: [MacSessionClient] = []

    override func tearDown() {
        clients.forEach { $0.disconnect() }
        engines.forEach { $0.stop() }
        clients = []
        engines = []
    }

    private struct Rig {
        let engine: MacUnlockEngine
        let recorder: EngineRecorder
        let session: FakeSessionProvider
        let macSigner: MessageSigner
        let config: MacEngineConfiguration
        let port: UInt16
    }

    private func makeEngine(devices: [PairedDeviceRecord], locked: Bool, authenticationOnly: Bool = true, macSigner: MessageSigner = SoftwareP256Signer(), macID: UUID = UUID()) async throws -> Rig {
        let session = FakeSessionProvider(Fixtures.session(locked: locked))
        let config = MacEngineConfiguration(macID: macID, macName: "Test Mac", macUsername: Fixtures.user, macUID: Fixtures.uid, approvalLifetime: 30, authenticationOnly: authenticationOnly, requirePhoneInitiation: true, advertiseBonjour: false, preferredPort: UInt16.random(in: 40_000...60_000))
        let engine = MacUnlockEngine(configuration: config, signer: macSigner, devices: devices, sessionProvider: session)
        let recorder = EngineRecorder()
        engine.delegate = recorder
        engines.append(engine)
        engine.start()
        let ready = await eventually { recorder.port != nil }
        XCTAssertTrue(ready, "engine listener did not start")
        return Rig(engine: engine, recorder: recorder, session: session, macSigner: macSigner, config: config, port: try XCTUnwrap(recorder.port))
    }

    private func connectClient(_ rig: Rig, device: PairedDeviceRecord) async throws -> (MacSessionClient, ClientRecorder) {
        let pinned = Fixtures.pinned(for: device, macID: rig.config.macID, macSigner: rig.macSigner, macName: rig.config.macName)
        let client = MacSessionClient(pinned: pinned, channelKey: device.channelKey, appVersion: "test")
        let recorder = ClientRecorder()
        recorder.attach(to: client)
        clients.append(client)
        client.connect(to: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: rig.port)!))
        let connected = await eventually { recorder.states.contains(.connected) }
        XCTAssertTrue(connected, "client did not authenticate: \(recorder.states)")
        return (client, recorder)
    }

    // MARK: Authentication-only

    func testAuthenticationOnlyModeEndToEnd() async throws {
        let phone = CountingSigner()
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let realDevice = PairedDeviceRecord(pairingID: device.pairingID, deviceID: device.deviceID, deviceName: device.deviceName, publicKey: phone.publicKeyX963, channelKey: device.channelKey, pairedAtMillis: 0)
        let rig = try await makeEngine(devices: [realDevice], locked: false)
        let (client, recorder) = try await connectClient(rig, device: realDevice)

        client.initiate(.authenticationTest)
        let gotRequest = await eventually { !recorder.requests.isEmpty }
        XCTAssertTrue(gotRequest)
        let request = try XCTUnwrap(recorder.requests.first)
        XCTAssertEqual(request.action, .authenticationTest)
        XCTAssertEqual(request.macUsername, Fixtures.user)

        try await client.approve(request, signer: phone)
        let gotResult = await eventually { recorder.results.contains { $0.outcome == .verifiedAuthenticationOnly } }
        XCTAssertTrue(gotResult, "results: \(recorder.results)")
        XCTAssertEqual(phone.signatures, 1, "exactly one biometric signature per approval")
        XCTAssertEqual(rig.recorder.verified.count, 1)
        XCTAssertEqual(rig.recorder.verified.first?.1, true, "handled as authentication-only")
        XCTAssertEqual(rig.recorder.verified.first?.0.isConsumed, true, "auth-only path consumes the token so nothing else can use it")
        XCTAssertTrue(rig.recorder.states.contains(.verified))

        // The client refuses to sign the same request twice.
        do {
            try await client.approve(request, signer: phone)
            XCTFail("second approval must be refused locally")
        } catch {
            XCTAssertEqual(error as? ClientError, .unknownRequest)
        }
    }

    func testUnlockActionInAuthenticationOnlyModeNeverReachesAdapter() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let rig = try await makeEngine(devices: [device], locked: true, authenticationOnly: true)
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.requests.isEmpty }
        try await client.approve(try XCTUnwrap(recorder.requests.first), signer: phone)
        _ = await eventually { !recorder.results.isEmpty }
        XCTAssertEqual(recorder.results.first?.outcome, .verifiedAuthenticationOnly)
        XCTAssertEqual(rig.recorder.verified.first?.1, true)
        XCTAssertEqual(rig.recorder.verified.first?.0.consume(), false, "token already consumed; an adapter could not use it")
    }

    func testUnlockApprovalHandedToDelegateWhenAuthenticationOnlyIsOff() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let rig = try await makeEngine(devices: [device], locked: true, authenticationOnly: false)
        rig.recorder.consumeAndReportUnlock = true
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.requests.isEmpty }
        try await client.approve(try XCTUnwrap(recorder.requests.first), signer: phone)
        let done = await eventually { recorder.results.contains { $0.outcome == .verifiedCredentialEntryAttempted } }
        XCTAssertTrue(done, "results: \(recorder.results)")
        XCTAssertEqual(rig.recorder.verified.first?.1, false)
    }

    func testUnlockRefusedWhenMacNotLocked() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: false)
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.results.isEmpty }
        XCTAssertEqual(recorder.results.first?.outcome, .failed)
        XCTAssertTrue(recorder.requests.isEmpty, "no challenge is issued for an unlocked Mac")
    }

    // MARK: Replay, forgery, unpaired devices

    func testReplayedApprovalRejectedOverNetwork() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let rig = try await makeEngine(devices: [device], locked: true)
        let peer = RawPeer(port: rig.port, key: device.channelKey, identity: device.pskIdentity)
        _ = await eventually { peer.ready }
        peer.hello(pairingID: device.pairingID, deviceID: device.deviceID, binderKey: device.channelKey)
        _ = await eventually { peer.received.contains { if case .serverHello = $0 { return true }; return false } }
        peer.channel.send(.initiate(UnlockInitiation(action: .unlockSession)))
        _ = await eventually { peer.received.contains { if case .unlockRequest = $0 { return true }; return false } }
        guard case .unlockRequest(let signed)? = peer.received.first(where: { if case .unlockRequest = $0 { return true }; return false }) else { return XCTFail("no request") }
        let reply = try await approval(for: signed, signer: phone)
        peer.channel.send(.approval(reply))
        peer.channel.send(.approval(reply))
        let both = await eventually { peer.received.filter { if case .result = $0 { return true }; return false }.count >= 2 }
        XCTAssertTrue(both)
        let outcomes = peer.received.compactMap { message -> ApprovalOutcome? in if case .result(let r) = message { return r.outcome }; return nil }
        XCTAssertEqual(outcomes.prefix(2), [.verifiedAuthenticationOnly, .rejected])
        XCTAssertEqual(rig.recorder.verified.count, 1, "an approval can be verified only once")
    }

    func testUnpairedDeviceCannotConnect() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: true)
        let stranger = RawPeer(port: rig.port, key: SecureRandom.bytes(32), identity: "mnu1:" + UUID().uuidString)
        let closed = await eventually { stranger.closed }
        XCTAssertTrue(closed)
        XCTAssertFalse(stranger.ready, "TLS-PSK handshake must fail for an unknown key")
        // Right identity, wrong key.
        let guesser = RawPeer(port: rig.port, key: SecureRandom.bytes(32), identity: device.pskIdentity)
        _ = await eventually { guesser.closed }
        XCTAssertFalse(guesser.ready)
    }

    func testPairedDeviceCannotImpersonateAnotherPairing() async throws {
        let deviceA = Fixtures.device(signer: SoftwareP256Signer(), name: "A")
        let deviceB = Fixtures.device(signer: SoftwareP256Signer(), name: "B")
        let rig = try await makeEngine(devices: [deviceA, deviceB], locked: true)
        // A completes TLS with its own key, then claims to be B.
        let peer = RawPeer(port: rig.port, key: deviceA.channelKey, identity: deviceA.pskIdentity)
        _ = await eventually { peer.ready }
        peer.hello(pairingID: deviceB.pairingID, deviceID: deviceB.deviceID, binderKey: deviceA.channelKey)
        let closed = await eventually { peer.closed }
        XCTAssertTrue(closed)
        XCTAssertFalse(peer.received.contains { if case .serverHello = $0 { return true }; return false })
        XCTAssertTrue(rig.recorder.logs.contains { $0.message.contains("binder mismatch") })
    }

    func testMessagesBeforeHelloAreRejected() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: true)
        let peer = RawPeer(port: rig.port, key: device.channelKey, identity: device.pskIdentity)
        _ = await eventually { peer.ready }
        peer.channel.send(.initiate(UnlockInitiation(action: .unlockSession)))
        let closed = await eventually { peer.closed }
        XCTAssertTrue(closed)
    }

    func testForgedMacWithStolenChannelKeyCannotObtainApproval() async throws {
        // Worst case: an impostor on the LAN somehow holds the pairing's channel key
        // and copies the Mac's identifiers, but not the Mac identity private key.
        let realMac = SoftwareP256Signer()
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let macID = UUID()
        let impostor = try await makeEngine(devices: [device], locked: true, macSigner: SoftwareP256Signer(), macID: macID)
        let pinned = Fixtures.pinned(for: device, macID: macID, macSigner: realMac, macName: "Test Mac")
        let client = MacSessionClient(pinned: pinned, channelKey: device.channelKey, appVersion: "test")
        let recorder = ClientRecorder()
        recorder.attach(to: client)
        clients.append(client)
        client.connect(to: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: impostor.port)!))
        _ = await eventually { recorder.states.contains(.connected) }
        client.initiate(.unlockSession)
        let rejected = await eventually { recorder.rejections.contains(.badSignature) }
        XCTAssertTrue(rejected)
        XCTAssertTrue(recorder.requests.isEmpty, "the user is never shown (or asked to approve) a forged request")
    }

    // MARK: Lifecycle

    func testLostConnectionInvalidatesPendingChallenge() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let rig = try await makeEngine(devices: [device], locked: true)
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.requests.isEmpty }
        let request = try XCTUnwrap(recorder.requests.first)
        client.disconnect()
        let noticed = await eventually { rig.recorder.connected.isEmpty }
        XCTAssertTrue(noticed, "Mac must notice the dropped connection")

        let peer = RawPeer(port: rig.port, key: device.channelKey, identity: device.pskIdentity)
        _ = await eventually { peer.ready }
        peer.hello(pairingID: device.pairingID, deviceID: device.deviceID, binderKey: device.channelKey)
        _ = await eventually { peer.received.contains { if case .serverHello = $0 { return true }; return false } }
        let signature = try await phone.sign(request.approvalSigningBytes(), reason: "")
        peer.channel.send(.approval(UnlockApproval(requestID: request.requestID, pairingID: device.pairingID, deviceID: device.deviceID, signature: signature)))
        _ = await eventually { peer.received.contains { if case .result = $0 { return true }; return false } }
        let outcome = peer.received.compactMap { message -> ApprovalOutcome? in if case .result(let r) = message { return r.outcome }; return nil }.first
        XCTAssertEqual(outcome, .rejected)
        XCTAssertTrue(rig.recorder.verified.isEmpty)
    }

    func testSessionUnlockInvalidatesPendingChallenge() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let rig = try await makeEngine(devices: [device], locked: true)
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.requests.isEmpty }
        let request = try XCTUnwrap(recorder.requests.first)
        rig.session.set(Fixtures.session(locked: false)) // user typed the password manually
        rig.engine.sessionDidChange(reason: "test")
        let invalidated = await eventually { recorder.results.contains { $0.requestID == request.requestID && $0.outcome == .failed } }
        XCTAssertTrue(invalidated)
        try? await client.approve(request, signer: phone)
        _ = await eventually { recorder.results.count >= 2 }
        XCTAssertTrue(rig.recorder.verified.isEmpty, "a stale approval after unlock must not verify")
    }

    func testSleepInvalidatesAndBlocksChallenges() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: true)
        let (client, recorder) = try await connectClient(rig, device: device)
        rig.engine.systemWillSleep()
        _ = await eventually { rig.recorder.states.last == .unavailable }
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.results.isEmpty }
        XCTAssertEqual(recorder.results.first?.outcome, .failed)
        XCTAssertTrue(recorder.requests.isEmpty)
        rig.engine.systemDidWake()
        let back = await eventually { rig.recorder.states.last == .locked }
        XCTAssertTrue(back)
    }

    func testBiometricCancellationProducesNoApproval() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: true)
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.requests.isEmpty }
        let request = try XCTUnwrap(recorder.requests.first)
        do {
            try await client.approve(request, signer: FailingSigner(publicKey: device.publicKey))
            XCTFail("cancelled Face ID must not produce an approval")
        } catch {}
        client.decline(request, reason: .biometricCancelled)
        let rejected = await eventually { rig.recorder.states.contains(.rejected) }
        XCTAssertTrue(rejected)
        XCTAssertTrue(rig.recorder.verified.isEmpty)
    }

    func testEnrollmentChangeInvalidatedKeyCannotApprove() async throws {
        // Models `.biometryCurrentSet` invalidation: after re-enrolment the old key is
        // gone; a newly generated key is not the pinned one, so re-pairing is required.
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: true)
        let (client, recorder) = try await connectClient(rig, device: device)
        client.initiate(.unlockSession)
        _ = await eventually { !recorder.requests.isEmpty }
        try await client.approve(try XCTUnwrap(recorder.requests.first), signer: SoftwareP256Signer())
        _ = await eventually { !recorder.results.isEmpty }
        XCTAssertEqual(recorder.results.first?.outcome, .rejected)
        XCTAssertTrue(rig.recorder.verified.isEmpty)
    }

    func testMacRevocationNotifiesPhoneAndBlocksReconnect() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let other = Fixtures.device(signer: SoftwareP256Signer(), name: "Other")
        let rig = try await makeEngine(devices: [device, other], locked: true)
        let (_, recorder) = try await connectClient(rig, device: device)
        rig.engine.updateDevices([other])
        let revoked = await eventually { recorder.revoked }
        XCTAssertTrue(revoked)
        try await Task.sleep(nanoseconds: 300_000_000)
        let retry = RawPeer(port: rig.port, key: device.channelKey, identity: device.pskIdentity)
        _ = await eventually(8) { retry.closed }
        XCTAssertFalse(retry.ready, "revoked channel key no longer completes TLS")
    }

    func testPhoneRevocationReachesMac() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let rig = try await makeEngine(devices: [device], locked: false)
        let (client, _) = try await connectClient(rig, device: device)
        client.sendRevoke()
        let got = await eventually { rig.recorder.revocations == [device.pairingID] }
        XCTAssertTrue(got)
    }

    // MARK: Pairing

    final class HostRecorder: PairingHostDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var _sas: ShortAuthenticationString?
        private var _paired: PairedDeviceRecord?
        private var _error: PairingError?
        private var _phoneConfirmed = false
        var sas: ShortAuthenticationString? { lock.withLock { _sas } }
        var paired: PairedDeviceRecord? { lock.withLock { _paired } }
        var error: PairingError? { lock.withLock { _error } }
        var phoneConfirmed: Bool { lock.withLock { _phoneConfirmed } }
        func pairingHost(_ host: PairingHost, didStartWith invitation: PairingInvitation) {}
        func pairingHost(_ host: PairingHost, needsConfirmation sas: ShortAuthenticationString, deviceName: String, deviceKeyFingerprint: String) { lock.withLock { _sas = sas } }
        func pairingHostPhoneDidConfirm(_ host: PairingHost) { lock.withLock { _phoneConfirmed = true } }
        func pairingHost(_ host: PairingHost, didPair device: PairedDeviceRecord) throws { lock.withLock { _paired = device } }
        func pairingHost(_ host: PairingHost, didFail error: PairingError) { lock.withLock { _error = error } }
    }

    final class PairClientRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _sas: ShortAuthenticationString?
        private var _outcome: PairingOutcome?
        private var _error: PairingError?
        var sas: ShortAuthenticationString? { lock.withLock { _sas } }
        var outcome: PairingOutcome? { lock.withLock { _outcome } }
        var error: PairingError? { lock.withLock { _error } }
        func attach(_ client: PairingClient) {
            client.onVerificationCode = { [weak self] sas, _ in self?.lock.withLock { self?._sas = sas } }
            client.onComplete = { [weak self] outcome in self?.lock.withLock { self?._outcome = outcome } }
            client.onFailure = { [weak self] error in self?.lock.withLock { self?._error = error } }
        }
    }

    private func startHost(macSigner: MessageSigner, macID: UUID = UUID()) async throws -> (PairingHost, HostRecorder, UInt16) {
        let host = PairingHost(macID: macID, macName: "Test Mac", macUsername: Fixtures.user, signer: macSigner, serviceName: "Test Mac", advertise: false)
        let recorder = HostRecorder()
        host.delegate = recorder
        host.start()
        var port: UInt16?
        _ = await eventually { port = host.currentPort(); return port != nil }
        return (host, recorder, try XCTUnwrap(port))
    }

    func testFullPairingThenAuthenticatedSession() async throws {
        let macSigner = SoftwareP256Signer()
        let macID = UUID()
        let (host, hostRecorder, port) = try await startHost(macSigner: macSigner, macID: macID)
        let scanned = try PairingInvitation(url: host.invitation.url) // as decoded from the QR code
        let phoneKey = CountingSigner()
        let client = PairingClient(invitation: scanned, deviceName: "Test iPhone", signer: phoneKey)
        let clientRecorder = PairClientRecorder()
        clientRecorder.attach(client)
        client.start(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!))

        let codesShown = await eventually { hostRecorder.sas != nil && clientRecorder.sas != nil }
        XCTAssertTrue(codesShown)
        XCTAssertEqual(hostRecorder.sas, clientRecorder.sas, "both screens must show the same verification code")

        host.confirmByUser()
        await client.confirm()
        let paired = await eventually { hostRecorder.paired != nil && clientRecorder.outcome != nil }
        XCTAssertTrue(paired, "host error: \(String(describing: hostRecorder.error)), client error: \(String(describing: clientRecorder.error))")
        let record = try XCTUnwrap(hostRecorder.paired)
        let outcome = try XCTUnwrap(clientRecorder.outcome)
        XCTAssertEqual(record.channelKey, outcome.channelKey)
        XCTAssertEqual(record.pairingID, outcome.mac.pairingID)
        XCTAssertEqual(record.publicKey, phoneKey.publicKeyX963, "Mac pinned the phone's key")
        XCTAssertEqual(outcome.mac.macPublicKey, macSigner.publicKeyX963, "phone pinned the Mac's key")
        XCTAssertEqual(outcome.mac.macID, macID)
        XCTAssertEqual(phoneKey.signatures, 1, "pairing confirmation required one biometric signature")

        // Use the freshly paired keys for a real session.
        let rig = try await makeEngine(devices: [record], locked: false, macSigner: macSigner, macID: macID)
        let session = MacSessionClient(pinned: outcome.mac, channelKey: outcome.channelKey, appVersion: "test")
        let sessionRecorder = ClientRecorder()
        sessionRecorder.attach(to: session)
        clients.append(session)
        session.connect(to: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: rig.port)!))
        _ = await eventually { sessionRecorder.states.contains(.connected) }
        session.initiate(.authenticationTest)
        _ = await eventually { !sessionRecorder.requests.isEmpty }
        try await session.approve(try XCTUnwrap(sessionRecorder.requests.first), signer: phoneKey)
        let verified = await eventually { sessionRecorder.results.contains { $0.outcome == .verifiedAuthenticationOnly } }
        XCTAssertTrue(verified)
    }

    func testPairingWithWrongCodeFailsAndBurnsInvitation() async throws {
        let (host, hostRecorder, port) = try await startHost(macSigner: SoftwareP256Signer())
        for _ in 0..<MNUProtocol.maxPairingHandshakeFailures {
            let wrong = try PairingInvitation(code: SecureRandom.bytes(10), macFingerprint: host.invitation.macFingerprint, serviceName: nil)
            let client = PairingClient(invitation: wrong, deviceName: "Attacker", signer: SoftwareP256Signer())
            let recorder = PairClientRecorder()
            recorder.attach(client)
            client.start(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!))
            _ = await eventually { recorder.error != nil }
            XCTAssertNil(recorder.sas)
        }
        let burned = await eventually { hostRecorder.error != nil }
        XCTAssertTrue(burned, "invitation must be burned after repeated failed handshakes")
        XCTAssertNil(hostRecorder.paired)
    }

    func testPairingRejectsMacKeyNotMatchingQRCode() async throws {
        let (host, hostRecorder, port) = try await startHost(macSigner: SoftwareP256Signer())
        // Correct code, but the QR fingerprint belongs to a different key (key substitution).
        let tampered = try PairingInvitation(code: host.invitation.code, macFingerprint: KeyFingerprint.sha256(SoftwareP256Signer().publicKeyX963), serviceName: nil)
        let client = PairingClient(invitation: tampered, deviceName: "iPhone", signer: SoftwareP256Signer())
        let recorder = PairClientRecorder()
        recorder.attach(client)
        client.start(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!))
        _ = await eventually { recorder.error != nil }
        XCTAssertEqual(recorder.error, .fingerprintMismatch)
        XCTAssertNil(recorder.sas, "no verification code is shown for a mismatching Mac")
        _ = await eventually { hostRecorder.error != nil }
        XCTAssertNil(hostRecorder.paired)
    }

    func testPairingAbortsWhenMacUserRejectsCode() async throws {
        let (host, hostRecorder, port) = try await startHost(macSigner: SoftwareP256Signer())
        let client = PairingClient(invitation: host.invitation, deviceName: "iPhone", signer: SoftwareP256Signer())
        let recorder = PairClientRecorder()
        recorder.attach(client)
        client.start(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!))
        _ = await eventually { hostRecorder.sas != nil }
        host.rejectByUser()
        await client.confirm()
        _ = await eventually { recorder.error != nil }
        XCTAssertNil(recorder.outcome)
        XCTAssertNil(hostRecorder.paired)
    }

    func testPairingAbortsWhenPhoneFaceIDCancelled() async throws {
        let (host, hostRecorder, port) = try await startHost(macSigner: SoftwareP256Signer())
        let client = PairingClient(invitation: host.invitation, deviceName: "iPhone", signer: FailingSigner(publicKey: SoftwareP256Signer().publicKeyX963))
        let recorder = PairClientRecorder()
        recorder.attach(client)
        client.start(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!))
        _ = await eventually { hostRecorder.sas != nil }
        host.confirmByUser()
        await client.confirm()
        _ = await eventually { hostRecorder.error != nil }
        XCTAssertNil(hostRecorder.paired, "Mac must not store a pairing without the phone's biometric confirmation")
    }
}
