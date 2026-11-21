import CryptoKit
import XCTest
@testable import MacNearUnlockShared

final class PairingCryptoTests: XCTestCase {
    func testInvitationURLRoundTrip() throws {
        let mac = SoftwareP256Signer()
        let invitation = PairingInvitation.generate(macPublicKey: mac.publicKeyX963, serviceName: "Alice's Mac mini")
        let parsed = try PairingInvitation(url: invitation.url)
        XCTAssertEqual(parsed, invitation)
        XCTAssertEqual(parsed.macFingerprint, KeyFingerprint.sha256(mac.publicKeyX963))
        XCTAssertEqual(parsed.pskKey, invitation.pskKey)
        XCTAssertEqual(parsed.pskKey.count, 32)
    }

    func testInvitationRejectsTampering() {
        let invitation = PairingInvitation.generate(macPublicKey: SoftwareP256Signer().publicKeyX963, serviceName: "Mac")
        let text = invitation.url.absoluteString
        for bad in [
            text.replacingOccurrences(of: "macnearunlock://", with: "https://"),
            text.replacingOccurrences(of: "v=1", with: "v=2"),
            text + "&c=AAAA",
            text.replacingOccurrences(of: "&f=", with: "&x="),
            "macnearunlock://pair?v=1&c=SHORT&f=AAAA",
        ] {
            XCTAssertThrowsError(try PairingInvitation(url: URL(string: bad)!), bad)
        }
    }

    func testManualCodeRoundTripAndLookalikes() throws {
        let invitation = PairingInvitation.generate(macPublicKey: SoftwareP256Signer().publicKeyX963, serviceName: "Mac")
        let display = invitation.displayCode
        XCTAssertEqual(display.count, 19) // 16 chars + 3 hyphens
        let manual = try PairingInvitation(manualCode: display.lowercased(), serviceName: nil)
        XCTAssertEqual(manual.code, invitation.code)
        XCTAssertNil(manual.macFingerprint)
        XCTAssertEqual(manual.pskKey, invitation.pskKey)
        XCTAssertEqual(CrockfordBase32.decode("0000-0000-0000-0000"), CrockfordBase32.decode("OOOO OOOO oooo OOOO"))
        XCTAssertNil(CrockfordBase32.decode("ABC"))
        XCTAssertNil(CrockfordBase32.decode("UUUU-UUUU-UUUU-UUUU"), "U is not in the Crockford alphabet")
    }

    func testBase32RoundTripRandom() {
        for _ in 0..<200 {
            let bytes = SecureRandom.bytes(10)
            XCTAssertEqual(CrockfordBase32.decode(CrockfordBase32.encode(bytes)), bytes)
        }
    }

    func testWordListIs256Unique() {
        XCTAssertEqual(VerificationWords.list.count, 256)
        XCTAssertEqual(Set(VerificationWords.list).count, 256)
    }

    private func handshake(macKey: SoftwareP256Signer, exporter: Data, macEphemeral: Curve25519.KeyAgreement.PrivateKey = .init(), phoneEphemeral: Curve25519.KeyAgreement.PrivateKey = .init()) -> (PairHello, PairChallenge) {
        let hello = PairHello(deviceID: UUID(), deviceName: "iPhone", devicePublicKey: SoftwareP256Signer().publicKeyX963, ephemeralPublicKey: phoneEphemeral.publicKey.rawRepresentation, nonce: SecureRandom.bytes(32))
        let challenge = PairChallenge(pairingID: UUID(), macID: UUID(), macName: "Mac", macUsername: "alice", macPublicKey: macKey.publicKeyX963, ephemeralPublicKey: macEphemeral.publicKey.rawRepresentation, nonce: SecureRandom.bytes(32), transcriptSignature: Data(count: 70))
        return (hello, challenge)
    }

    func testBothSidesDeriveSameSASAndChannelKey() throws {
        let macEphemeral = Curve25519.KeyAgreement.PrivateKey(), phoneEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let exporter = SecureRandom.bytes(32)
        let (hello, challenge) = handshake(macKey: SoftwareP256Signer(), exporter: exporter, macEphemeral: macEphemeral, phoneEphemeral: phoneEphemeral)
        let hash = PairingCrypto.transcriptHash(hello: hello, challenge: challenge, exporter: exporter)
        let macKey = try PairingCrypto.channelKey(privateKey: macEphemeral, peerPublicKey: hello.ephemeralPublicKey, transcriptHash: hash)
        let phoneKey = try PairingCrypto.channelKey(privateKey: phoneEphemeral, peerPublicKey: challenge.ephemeralPublicKey, transcriptHash: hash)
        XCTAssertEqual(macKey, phoneKey)
        XCTAssertEqual(macKey.count, 32)
        let sas = PairingCrypto.shortAuthenticationString(transcriptHash: hash)
        XCTAssertEqual(sas.digits.count, 7)
        XCTAssertEqual(sas.words.count, 4)
    }

    func testKeySubstitutionChangesVerificationCode() {
        // A MITM who substitutes the Mac key (or splits the TLS session) yields a
        // different transcript on each side, so the displayed codes differ.
        let exporter = SecureRandom.bytes(32)
        let (hello, challenge) = handshake(macKey: SoftwareP256Signer(), exporter: exporter)
        let substituted = PairChallenge(pairingID: challenge.pairingID, macID: challenge.macID, macName: challenge.macName, macUsername: challenge.macUsername, macPublicKey: SoftwareP256Signer().publicKeyX963, ephemeralPublicKey: challenge.ephemeralPublicKey, nonce: challenge.nonce, transcriptSignature: challenge.transcriptSignature)
        let real = PairingCrypto.shortAuthenticationString(transcriptHash: PairingCrypto.transcriptHash(hello: hello, challenge: challenge, exporter: exporter))
        let fake = PairingCrypto.shortAuthenticationString(transcriptHash: PairingCrypto.transcriptHash(hello: hello, challenge: substituted, exporter: exporter))
        XCTAssertNotEqual(real, fake)
        let otherSession = PairingCrypto.shortAuthenticationString(transcriptHash: PairingCrypto.transcriptHash(hello: hello, challenge: challenge, exporter: SecureRandom.bytes(32)))
        XCTAssertNotEqual(real, otherSession)
    }

    func testChannelBindersAreDirectionalAndKeyed() {
        let key = SecureRandom.bytes(32), exporter = SecureRandom.bytes(32)
        let pairing = UUID(), device = UUID(), mac = UUID()
        let client = ChannelBinding.clientBinder(channelKey: key, pairingID: pairing, deviceID: device, exporter: exporter)
        XCTAssertTrue(ChannelBinding.matches(client, expected: ChannelBinding.clientBinder(channelKey: key, pairingID: pairing, deviceID: device, exporter: exporter)))
        XCTAssertFalse(ChannelBinding.matches(client, expected: ChannelBinding.clientBinder(channelKey: SecureRandom.bytes(32), pairingID: pairing, deviceID: device, exporter: exporter)))
        XCTAssertFalse(ChannelBinding.matches(client, expected: ChannelBinding.clientBinder(channelKey: key, pairingID: pairing, deviceID: device, exporter: SecureRandom.bytes(32))))
        XCTAssertFalse(ChannelBinding.matches(client, expected: ChannelBinding.serverBinder(channelKey: key, pairingID: pairing, macID: device, exporter: exporter)))
        XCTAssertFalse(ChannelBinding.matches(ChannelBinding.serverBinder(channelKey: key, pairingID: pairing, macID: mac, exporter: exporter), expected: ChannelBinding.serverBinder(channelKey: key, pairingID: pairing, macID: UUID(), exporter: exporter)))
    }
}

final class CredentialEntryPolicyTests: XCTestCase {
    private func allowed() -> CredentialEntryInputs {
        CredentialEntryInputs(adapterEnabled: true, riskAcknowledged: true, authenticationOnlyMode: false, credentialArmed: true, accessibilityTrusted: true, postEventAccess: true, approvalAction: .unlockSession, approvalConsumedByCaller: true, approvalAge: 1, session: Fixtures.session(locked: true), expectedUsername: Fixtures.user, expectedUID: Fixtures.uid, systemSleeping: false, displayAsleep: false, secureInputEnabled: true, secureInputOwnerIsLoginWindow: true, consecutiveFailures: 0, attemptsInLastHour: 0, secondsSinceLastAttempt: nil)
    }

    func testAllPreconditionsMetAllows() {
        XCTAssertNil(CredentialEntryPolicy.evaluate(allowed()))
        var unknownOwner = allowed()
        unknownOwner.secureInputOwnerIsLoginWindow = nil
        XCTAssertNil(CredentialEntryPolicy.evaluate(unknownOwner))
    }

    func testEachPreconditionIndependentlyDenies() {
        let cases: [(CredentialEntryDenial, (inout CredentialEntryInputs) -> Void)] = [
            (.adapterDisabled, { $0.adapterEnabled = false }),
            (.riskNotAcknowledged, { $0.riskAcknowledged = false }),
            (.authenticationOnlyMode, { $0.authenticationOnlyMode = true }),
            (.autoDisabledAfterFailures, { $0.consecutiveFailures = 3 }),
            (.wrongAction, { $0.approvalAction = .authenticationTest }),
            (.approvalNotConsumed, { $0.approvalConsumedByCaller = false }),
            (.approvalStale, { $0.approvalAge = 6 }),
            (.sessionUnavailable, { $0.session = .unavailable }),
            (.sessionUnavailable, { $0.session = Fixtures.session(locked: true, onConsole: false) }),
            (.sessionWrongUser, { $0.session = Fixtures.session(locked: true, user: "bob", uid: 502) }),
            (.sessionNotLocked, { $0.session = Fixtures.session(locked: false) }),
            (.systemAsleep, { $0.displayAsleep = true }),
            (.systemAsleep, { $0.systemSleeping = true }),
            (.accessibilityMissing, { $0.accessibilityTrusted = false }),
            (.accessibilityMissing, { $0.postEventAccess = false }),
            (.secureFieldNotVerified, { $0.secureInputEnabled = false }),
            (.secureInputOwnedByOtherProcess, { $0.secureInputOwnerIsLoginWindow = false }),
            (.credentialNotArmed, { $0.credentialArmed = false }),
            (.rateLimited, { $0.attemptsInLastHour = 5 }),
            (.rateLimited, { $0.secondsSinceLastAttempt = 3 }),
        ]
        for (expected, mutate) in cases {
            var input = allowed()
            mutate(&input)
            XCTAssertEqual(CredentialEntryPolicy.evaluate(input), expected)
        }
    }
}
