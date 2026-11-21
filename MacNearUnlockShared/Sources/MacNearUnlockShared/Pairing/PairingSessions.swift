import CryptoKit
import Foundation
import Network

// MARK: - Mac side

public protocol PairingHostDelegate: AnyObject {
    func pairingHost(_ host: PairingHost, didStartWith invitation: PairingInvitation)
    /// Show `sas` and the device name; call `confirmByUser()` only if the user
    /// confirms the same code is shown on the iPhone.
    func pairingHost(_ host: PairingHost, needsConfirmation sas: ShortAuthenticationString, deviceName: String, deviceKeyFingerprint: String)
    func pairingHostPhoneDidConfirm(_ host: PairingHost)
    /// Persist the record. Throwing aborts the pairing (fail closed).
    func pairingHost(_ host: PairingHost, didPair device: PairedDeviceRecord) throws
    func pairingHost(_ host: PairingHost, didFail error: PairingError)
}

/// Runs one pairing invitation on the Mac: a dedicated TLS-PSK listener keyed by
/// the invitation code, advertised under `_mnupair._tcp` only while it is open.
public final class PairingHost: @unchecked Sendable {
    public weak var delegate: PairingHostDelegate?
    public let invitation: PairingInvitation

    private let macID: UUID
    private let macName: String
    private let macUsername: String
    private let signer: MessageSigner
    private let advertise: Bool
    private let queue = DispatchQueue(label: "MacNearUnlock.pairing-host")

    private var listener: NWListener?
    private var listenerReady = false
    private var channel: FramedConnection?
    private var failedHandshakes = 0
    private var finished = false
    private var expiry: DispatchWorkItem?

    private var hello: PairHello?
    private var challenge: PairChallenge?
    private var transcriptHash: Data?
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var phoneConfirmed = false
    private var userConfirmed = false

    /// `advertise: false` skips Bonjour (tests, or manual host entry).
    public init(macID: UUID, macName: String, macUsername: String, signer: MessageSigner, serviceName: String, advertise: Bool = true) {
        self.advertise = advertise
        self.macID = macID
        self.macName = macName
        self.macUsername = macUsername
        self.signer = signer
        self.invitation = PairingInvitation.generate(macPublicKey: signer.publicKeyX963, serviceName: serviceName)
    }

    public func start() {
        queue.async { [self] in
            let parameters = TLSPSK.parameters(psks: [(invitation.pskKey, PairingInvitation.pskIdentity)])
            guard let listener = try? NWListener(using: parameters) else {
                fail(.connectionFailed("Could not open pairing listener"))
                return
            }
            if advertise {
                listener.service = NWListener.Service(name: invitation.serviceName, type: MNUProtocol.pairingServiceType)
            }
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                if case .failed(let error) = state { self.fail(.connectionFailed(error.debugDescription)) }
                if case .ready = state {
                    self.listenerReady = true
                    self.delegate?.pairingHost(self, didStartWith: self.invitation)
                }
            }
            self.listener = listener
            listener.start(queue: queue)
            scheduleExpiry(after: MNUProtocol.pairingWindow)
        }
    }

    /// Listening port once the invitation is open (nil before or after).
    public func currentPort() -> UInt16? {
        queue.sync {
            guard listenerReady, !finished, let port = listener?.port?.rawValue, port != 0 else { return nil }
            return port
        }
    }

    public func cancel() {
        queue.async { [self] in
            guard !finished else { return }
            channel?.send(.pairAbort(PairAbort(reason: "Cancelled on Mac")))
            fail(.aborted("Cancelled"))
        }
    }

    public func confirmByUser() {
        queue.async { [self] in
            guard !finished, transcriptHash != nil else { return }
            userConfirmed = true
            completeIfReady()
        }
    }

    public func rejectByUser() {
        queue.async { [self] in
            guard !finished else { return }
            channel?.send(.pairAbort(PairAbort(reason: "Verification code rejected on Mac")))
            fail(.aborted("Verification code rejected on Mac"))
        }
    }

    // MARK: Private (queue-confined)

    private func accept(_ connection: NWConnection) {
        guard !finished, channel == nil else {
            connection.cancel()
            return
        }
        let channel = FramedConnection(connection: connection, queue: queue)
        self.channel = channel
        channel.onMessage = { [weak self] message in self?.handle(message) }
        channel.onClose = { [weak self, weak channel] reason in
            guard let self, let channel else { return }
            if self.channel === channel { self.channel = nil }
            guard !self.finished else { return }
            if !channel.didBecomeReady {
                // Wrong code (TLS-PSK mismatch) or a probe. Limit online guessing.
                self.failedHandshakes += 1
                if self.failedHandshakes >= MNUProtocol.maxPairingHandshakeFailures {
                    self.fail(.aborted("Too many failed pairing attempts; invitation burned"))
                }
            } else {
                self.fail(.aborted(reason ?? "iPhone disconnected"))
            }
        }
        channel.start()
    }

    private func handle(_ message: WireMessage) {
        guard !finished, let channel else { return }
        switch message {
        case .pairHello(let hello) where self.hello == nil:
            self.hello = hello
            guard let exporter = channel.exportKeyingMaterial() else {
                fail(.connectionFailed("No channel binding"))
                return
            }
            let ephemeral = Curve25519.KeyAgreement.PrivateKey()
            self.ephemeral = ephemeral
            let unsigned = PairChallenge(pairingID: UUID(), macID: macID, macName: macName, macUsername: macUsername, macPublicKey: signer.publicKeyX963, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation, nonce: SecureRandom.bytes(MNUProtocol.nonceLength), transcriptSignature: Data(repeating: 0, count: 8))
            let transcript = PairingCrypto.transcript(hello: hello, challenge: unsigned, exporter: exporter)
            let hash = Data(SHA256.hash(data: transcript))
            transcriptHash = hash
            let signer = self.signer
            Task { [self] in
                guard let signature = try? await signer.sign(transcript, reason: "Pair iPhone") else {
                    queue.async { self.fail(.connectionFailed("Could not sign pairing transcript")) }
                    return
                }
                queue.async { [self] in
                    guard !finished else { return }
                    let signed = PairChallenge(pairingID: unsigned.pairingID, macID: unsigned.macID, macName: unsigned.macName, macUsername: unsigned.macUsername, macPublicKey: unsigned.macPublicKey, ephemeralPublicKey: unsigned.ephemeralPublicKey, nonce: unsigned.nonce, transcriptSignature: signature)
                    challenge = signed
                    channel.send(.pairChallenge(signed))
                    scheduleExpiry(after: MNUProtocol.pairingWindow)
                    delegate?.pairingHost(self, needsConfirmation: PairingCrypto.shortAuthenticationString(transcriptHash: hash), deviceName: hello.deviceName, deviceKeyFingerprint: KeyFingerprint.display(hello.devicePublicKey))
                }
            }
        case .pairConfirm(let confirm):
            guard let hello, let transcriptHash, challenge != nil, !phoneConfirmed else {
                fail(.unexpectedMessage)
                return
            }
            guard SignatureVerifier.isValid(signatureDER: confirm.signature, message: PairingCrypto.confirmBytes(transcriptHash: transcriptHash), publicKeyX963: hello.devicePublicKey) else {
                channel.send(.pairAbort(PairAbort(reason: "Confirmation signature invalid")))
                fail(.badConfirmationSignature)
                return
            }
            phoneConfirmed = true
            delegate?.pairingHostPhoneDidConfirm(self)
            completeIfReady()
        case .pairAbort(let abort):
            fail(.aborted("iPhone: \(abort.reason)"))
        default:
            channel.send(.pairAbort(PairAbort(reason: "Unexpected message")))
            fail(.unexpectedMessage)
        }
    }

    private func completeIfReady() {
        guard phoneConfirmed, userConfirmed, !finished,
              let hello, let challenge, let transcriptHash, let ephemeral, let channel
        else { return }
        let channelKey: Data
        do {
            channelKey = try PairingCrypto.channelKey(privateKey: ephemeral, peerPublicKey: hello.ephemeralPublicKey, transcriptHash: transcriptHash)
        } catch {
            fail(.keyAgreementFailed)
            return
        }
        let record = PairedDeviceRecord(pairingID: challenge.pairingID, deviceID: hello.deviceID, deviceName: hello.deviceName, publicKey: hello.devicePublicKey, channelKey: channelKey, pairedAtMillis: Date().millisecondsSince1970)
        do {
            try delegate?.pairingHost(self, didPair: record)
        } catch {
            channel.send(.pairAbort(PairAbort(reason: "Mac could not store the pairing")))
            fail(.storageFailed)
            return
        }
        let signer = self.signer
        let bytes = PairingCrypto.completeBytes(transcriptHash: transcriptHash, pairingID: challenge.pairingID)
        finished = true
        expiry?.cancel()
        Task { [self] in
            let signature = try? await signer.sign(bytes, reason: "Complete pairing")
            queue.async { [self] in
                if let signature {
                    channel.send(.pairComplete(PairComplete(pairingID: challenge.pairingID, signature: signature))) { _ in
                        channel.cancel()
                    }
                } else {
                    channel.cancel()
                }
                listener?.cancel()
                listener = nil
            }
        }
    }

    private func scheduleExpiry(after seconds: TimeInterval) {
        expiry?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.finished else { return }
            self.channel?.send(.pairAbort(PairAbort(reason: "Pairing window expired")))
            self.fail(.expired)
        }
        expiry = work
        queue.asyncAfter(deadline: .now() + seconds, execute: work)
    }

    private func fail(_ error: PairingError) {
        guard !finished else { return }
        finished = true
        expiry?.cancel()
        listener?.cancel()
        listener = nil
        let current = channel
        channel = nil
        queue.asyncAfter(deadline: .now() + 0.3) { current?.cancel() }
        delegate?.pairingHost(self, didFail: error)
    }
}

// MARK: - iPhone side

/// Result of a successful pairing on the iPhone. `channelKey` is secret.
public struct PairingOutcome: Sendable {
    public let mac: PinnedMac
    public let channelKey: Data
}

public final class PairingClient: @unchecked Sendable {
    public var onVerificationCode: (@Sendable (ShortAuthenticationString, PairChallenge) -> Void)?
    public var onComplete: (@Sendable (PairingOutcome) -> Void)?
    public var onFailure: (@Sendable (PairingError) -> Void)?

    public let deviceID: UUID
    private let invitation: PairingInvitation
    private let deviceName: String
    private let signer: MessageSigner
    private let queue = DispatchQueue(label: "MacNearUnlock.pairing-client")

    private var channel: FramedConnection?
    private var hello: PairHello?
    private var challenge: PairChallenge?
    private var transcriptHash: Data?
    private var ephemeral = Curve25519.KeyAgreement.PrivateKey()
    private var confirmed = false
    private var finished = false

    /// `signer` must be the newly created biometric Secure Enclave key for this pairing.
    public init(invitation: PairingInvitation, deviceID: UUID = UUID(), deviceName: String, signer: MessageSigner) {
        self.invitation = invitation
        self.deviceID = deviceID
        self.deviceName = String(deviceName.prefix(64))
        self.signer = signer
    }

    public func start(endpoint: NWEndpoint) {
        queue.async { [self] in
            let parameters = TLSPSK.parameters(psks: [(invitation.pskKey, PairingInvitation.pskIdentity)])
            let channel = FramedConnection(connection: NWConnection(to: endpoint, using: parameters), queue: queue)
            self.channel = channel
            channel.onReady = { [weak self] in self?.sendHello() }
            channel.onMessage = { [weak self] message in self?.handle(message) }
            channel.onClose = { [weak self] reason in
                guard let self, !self.finished else { return }
                self.fail(.connectionFailed(reason ?? "Mac closed the pairing connection"))
            }
            channel.start()
        }
    }

    /// Call only after the user confirmed the code matches the Mac's screen. The
    /// signer prompts for Face ID; cancelling aborts the pairing.
    public func confirm() async {
        let state: (Data, PairChallenge)? = queue.sync {
            guard !finished, !confirmed, let transcriptHash, let challenge else { return nil }
            confirmed = true
            return (transcriptHash, challenge)
        }
        guard let (hash, _) = state else { return }
        do {
            let signature = try await signer.sign(PairingCrypto.confirmBytes(transcriptHash: hash), reason: "Confirm pairing with your Mac")
            queue.async { [self] in channel?.send(.pairConfirm(PairConfirm(signature: signature))) }
        } catch {
            queue.async { [self] in
                channel?.send(.pairAbort(PairAbort(reason: "Face ID confirmation cancelled")))
                fail(.aborted("Face ID confirmation did not complete"))
            }
        }
    }

    public func cancel(reason: String = "Cancelled on iPhone") {
        queue.async { [self] in
            guard !finished else { return }
            channel?.send(.pairAbort(PairAbort(reason: reason)))
            fail(.aborted(reason))
        }
    }

    // MARK: Private (queue-confined)

    private func sendHello() {
        let hello = PairHello(deviceID: deviceID, deviceName: deviceName, devicePublicKey: signer.publicKeyX963, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation, nonce: SecureRandom.bytes(MNUProtocol.nonceLength))
        self.hello = hello
        channel?.send(.pairHello(hello))
    }

    private func handle(_ message: WireMessage) {
        guard !finished, let channel else { return }
        switch message {
        case .pairChallenge(let challenge) where self.challenge == nil:
            guard let hello, let exporter = channel.exportKeyingMaterial() else {
                fail(.connectionFailed("No channel binding"))
                return
            }
            if let expected = invitation.macFingerprint,
               !ConstantTime.equals(KeyFingerprint.sha256(challenge.macPublicKey), expected) {
                channel.send(.pairAbort(PairAbort(reason: "Mac key does not match QR code")))
                fail(.fingerprintMismatch)
                return
            }
            let transcript = PairingCrypto.transcript(hello: hello, challenge: challenge, exporter: exporter)
            guard SignatureVerifier.isValid(signatureDER: challenge.transcriptSignature, message: transcript, publicKeyX963: challenge.macPublicKey) else {
                channel.send(.pairAbort(PairAbort(reason: "Mac transcript signature invalid")))
                fail(.badTranscriptSignature)
                return
            }
            let hash = Data(SHA256.hash(data: transcript))
            self.challenge = challenge
            transcriptHash = hash
            onVerificationCode?(PairingCrypto.shortAuthenticationString(transcriptHash: hash), challenge)
        case .pairComplete(let complete):
            guard confirmed, let hello, let challenge, let transcriptHash, complete.pairingID == challenge.pairingID else {
                fail(.unexpectedMessage)
                return
            }
            guard SignatureVerifier.isValid(signatureDER: complete.signature, message: PairingCrypto.completeBytes(transcriptHash: transcriptHash, pairingID: challenge.pairingID), publicKeyX963: challenge.macPublicKey) else {
                fail(.badCompletionSignature)
                return
            }
            guard let key = try? PairingCrypto.channelKey(privateKey: ephemeral, peerPublicKey: challenge.ephemeralPublicKey, transcriptHash: transcriptHash) else {
                fail(.keyAgreementFailed)
                return
            }
            finished = true
            let mac = PinnedMac(pairingID: challenge.pairingID, macID: challenge.macID, macName: challenge.macName, macUsername: challenge.macUsername, macPublicKey: challenge.macPublicKey, deviceID: hello.deviceID, pairedAtMillis: Date().millisecondsSince1970)
            onComplete?(PairingOutcome(mac: mac, channelKey: key))
            channel.cancel()
        case .pairAbort(let abort):
            fail(.aborted("Mac: \(abort.reason)"))
        default:
            fail(.unexpectedMessage)
        }
    }

    private func fail(_ error: PairingError) {
        guard !finished else { return }
        finished = true
        let current = channel
        channel = nil
        queue.asyncAfter(deadline: .now() + 0.3) { current?.cancel() }
        onFailure?(error)
    }
}
