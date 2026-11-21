import CryptoKit
import XCTest
@testable import MacNearUnlockShared

final class CanonicalEncodingTests: XCTestCase {
    func testEncodingIsDeterministic() {
        func make() -> Data {
            var writer = CanonicalWriter(domain: .unlockRequest)
            writer.append(1, string: "abc")
            writer.append(2, uint64: 42)
            return writer.bytes
        }
        XCTAssertEqual(make(), make())
    }

    func testLengthPrefixesPreventBoundaryAmbiguity() {
        var a = CanonicalWriter(domain: .unlockRequest)
        a.append(1, string: "ab")
        a.append(2, string: "c")
        var b = CanonicalWriter(domain: .unlockRequest)
        b.append(1, string: "a")
        b.append(2, string: "bc")
        XCTAssertNotEqual(a.bytes, b.bytes)
    }

    func testDomainSeparation() {
        var a = CanonicalWriter(domain: .unlockRequest)
        a.append(1, string: "x")
        var b = CanonicalWriter(domain: .unlockApproval)
        b.append(1, string: "x")
        XCTAssertNotEqual(a.bytes, b.bytes)
        XCTAssertTrue(a.bytes.starts(with: Data("MNU1".utf8)))
    }

    func testUnicodeIsNormalised() {
        // "é" precomposed vs. "e" + combining acute must sign identically.
        var a = CanonicalWriter(domain: .unlockRequest)
        a.append(1, string: "Caf\u{00E9}")
        var b = CanonicalWriter(domain: .unlockRequest)
        b.append(1, string: "Cafe\u{0301}")
        XCTAssertEqual(a.bytes, b.bytes)
    }

    func testExactLayout() {
        var writer = CanonicalWriter(domain: .unlockRequest)
        writer.append(7, uint16: 0x0102)
        let domain = Data(SigningDomain.unlockRequest.rawValue.utf8)
        var expected = Data("MNU1".utf8)
        expected.append(contentsOf: [0x00, UInt8(domain.count)])
        expected.append(domain)
        expected.append(contentsOf: [7, 0, 0, 0, 2, 0x01, 0x02])
        XCTAssertEqual(writer.bytes, expected)
    }

    func testAllDomainsDistinct() {
        XCTAssertEqual(Set(SigningDomain.allCases.map(\.rawValue)).count, SigningDomain.allCases.count)
    }
}

final class RequestSigningTests: XCTestCase {
    private func sampleRequest(action: UnlockAction = .unlockSession) -> UnlockRequest {
        UnlockRequest(requestID: UUID(), nonce: SecureRandom.bytes(32), macID: UUID(), macName: "Mac mini", macUsername: "alice", pairingID: UUID(), deviceID: UUID(), action: action, issuedAtMillis: 1_000, expiresAtMillis: 31_000)
    }

    func testSignatureVerifiesAndAnyFieldChangeBreaksIt() async throws {
        let signer = SoftwareP256Signer()
        let request = sampleRequest()
        let signature = try await signer.sign(request.approvalSigningBytes(), reason: "")
        XCTAssertTrue(SignatureVerifier.isValid(signatureDER: signature, message: request.approvalSigningBytes(), publicKeyX963: signer.publicKeyX963))

        let mutations: [UnlockRequest] = [
            UnlockRequest(requestID: UUID(), nonce: request.nonce, macID: request.macID, macName: request.macName, macUsername: request.macUsername, pairingID: request.pairingID, deviceID: request.deviceID, action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: SecureRandom.bytes(32), macID: request.macID, macName: request.macName, macUsername: request.macUsername, pairingID: request.pairingID, deviceID: request.deviceID, action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: request.nonce, macID: UUID(), macName: request.macName, macUsername: request.macUsername, pairingID: request.pairingID, deviceID: request.deviceID, action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: request.nonce, macID: request.macID, macName: request.macName, macUsername: "mallory", pairingID: request.pairingID, deviceID: request.deviceID, action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: request.nonce, macID: request.macID, macName: request.macName, macUsername: request.macUsername, pairingID: UUID(), deviceID: request.deviceID, action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: request.nonce, macID: request.macID, macName: request.macName, macUsername: request.macUsername, pairingID: request.pairingID, deviceID: UUID(), action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: request.nonce, macID: request.macID, macName: request.macName, macUsername: request.macUsername, pairingID: request.pairingID, deviceID: request.deviceID, action: .authenticationTest, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis),
            UnlockRequest(requestID: request.requestID, nonce: request.nonce, macID: request.macID, macName: request.macName, macUsername: request.macUsername, pairingID: request.pairingID, deviceID: request.deviceID, action: request.action, issuedAtMillis: request.issuedAtMillis, expiresAtMillis: request.expiresAtMillis + 1),
        ]
        for mutated in mutations {
            XCTAssertFalse(SignatureVerifier.isValid(signatureDER: signature, message: mutated.approvalSigningBytes(), publicKeyX963: signer.publicKeyX963))
        }
    }

    func testRequestSignatureCannotBeUsedAsApproval() async throws {
        let signer = SoftwareP256Signer()
        let request = sampleRequest()
        let requestSignature = try await signer.sign(request.requestSigningBytes(), reason: "")
        XCTAssertFalse(SignatureVerifier.isValid(signatureDER: requestSignature, message: request.approvalSigningBytes(), publicKeyX963: signer.publicKeyX963))
    }

    func testWrongKeyAndMalformedSignaturesRejected() async throws {
        let signer = SoftwareP256Signer()
        let other = SoftwareP256Signer()
        let message = sampleRequest().approvalSigningBytes()
        let signature = try await signer.sign(message, reason: "")
        XCTAssertFalse(SignatureVerifier.isValid(signatureDER: signature, message: message, publicKeyX963: other.publicKeyX963))
        XCTAssertFalse(SignatureVerifier.isValid(signatureDER: Data(), message: message, publicKeyX963: signer.publicKeyX963))
        XCTAssertFalse(SignatureVerifier.isValid(signatureDER: Data(repeating: 0x30, count: 72), message: message, publicKeyX963: signer.publicKeyX963))
        XCTAssertFalse(SignatureVerifier.isValid(signatureDER: signature + Data([0]), message: message, publicKeyX963: signer.publicKeyX963))
        XCTAssertFalse(SignatureVerifier.isValid(signatureDER: signature, message: message, publicKeyX963: Data(repeating: 4, count: 65)))
    }

    func testShapeValidation() {
        let good = sampleRequest()
        XCTAssertNoThrow(try good.validateShape())
        let shortNonce = UnlockRequest(requestID: UUID(), nonce: Data(count: 16), macID: UUID(), macName: "m", macUsername: "u", pairingID: UUID(), deviceID: UUID(), action: .unlockSession, issuedAtMillis: 1, expiresAtMillis: 2)
        XCTAssertThrowsError(try shortNonce.validateShape())
        let badVersion = UnlockRequest(protocolVersion: 99, requestID: UUID(), nonce: Data(count: 32), macID: UUID(), macName: "m", macUsername: "u", pairingID: UUID(), deviceID: UUID(), action: .unlockSession, issuedAtMillis: 1, expiresAtMillis: 2)
        XCTAssertThrowsError(try badVersion.validateShape())
        let controlChars = UnlockRequest(requestID: UUID(), nonce: Data(count: 32), macID: UUID(), macName: "Mac\u{202E}mini", macUsername: "u", pairingID: UUID(), deviceID: UUID(), action: .unlockSession, issuedAtMillis: 1, expiresAtMillis: 2)
        XCTAssertThrowsError(try controlChars.validateShape())
        let inverted = UnlockRequest(requestID: UUID(), nonce: Data(count: 32), macID: UUID(), macName: "m", macUsername: "u", pairingID: UUID(), deviceID: UUID(), action: .unlockSession, issuedAtMillis: 5, expiresAtMillis: 5)
        XCTAssertThrowsError(try inverted.validateShape())
    }

    func testConstantTimeEquals() {
        XCTAssertTrue(ConstantTime.equals(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(ConstantTime.equals(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(ConstantTime.equals(Data([1, 2, 3]), Data([1, 2])))
        let base = Data([9, 1, 2, 3])
        XCTAssertTrue(ConstantTime.equals(base.dropFirst(), Data([1, 2, 3])), "Must handle Data slices")
    }

    func testFingerprintDisplay() {
        let key = SoftwareP256Signer().publicKeyX963
        let display = KeyFingerprint.display(key)
        XCTAssertEqual(display.split(separator: " ").count, 8)
        XCTAssertEqual(display, KeyFingerprint.display(key))
    }
}

final class FrameCodecTests: XCTestCase {
    func testRoundTripAllMessageKinds() throws {
        let signer = SoftwareP256Signer()
        let request = UnlockRequest(requestID: UUID(), nonce: SecureRandom.bytes(32), macID: UUID(), macName: "Mac", macUsername: "u", pairingID: UUID(), deviceID: UUID(), action: .unlockSession, issuedAtMillis: 1, expiresAtMillis: 2)
        let messages: [WireMessage] = [
            .clientHello(ClientHello(pairingID: UUID(), deviceID: UUID(), appVersion: "1.0", binder: Data(count: 32))),
            .serverHello(ServerHello(macID: UUID(), binder: Data(count: 32), status: MacSessionStatus(lockState: .locked, engineState: .locked, authenticationOnly: true, requiresPhoneInitiation: true))),
            .initiate(UnlockInitiation(action: .authenticationTest)),
            .unlockRequest(SignedUnlockRequest(request: request, macSignature: Data(count: 70))),
            .approval(UnlockApproval(requestID: UUID(), pairingID: UUID(), deviceID: UUID(), signature: Data(count: 70))),
            .decline(UnlockDecline(requestID: UUID(), reason: .biometricCancelled)),
            .result(ApprovalResult(requestID: nil, outcome: .verifiedAuthenticationOnly, detail: "ok")),
            .revoke(RevokeNotice(pairingID: UUID())),
            .ping, .pong,
            .pairHello(PairHello(deviceID: UUID(), deviceName: "Phone", devicePublicKey: signer.publicKeyX963, ephemeralPublicKey: Data(count: 32), nonce: Data(count: 32))),
            .pairAbort(PairAbort(reason: "x")),
        ]
        for message in messages {
            let frame = try FrameCodec.encode(message)
            let length = try FrameCodec.bodyLength(fromHeader: frame.prefix(4))
            XCTAssertEqual(length, frame.count - 4)
            XCTAssertEqual(try FrameCodec.decodeBody(frame.dropFirst(4)), message)
        }
    }

    func testRejectsOversizedAndEmptyFrames() {
        XCTAssertThrowsError(try FrameCodec.bodyLength(fromHeader: Data([0, 0, 0, 0])))
        XCTAssertThrowsError(try FrameCodec.bodyLength(fromHeader: Data([0, 1, 0, 1]))) // 65537
        XCTAssertThrowsError(try FrameCodec.bodyLength(fromHeader: Data([0xFF, 0xFF, 0xFF, 0xFF])))
        XCTAssertThrowsError(try FrameCodec.bodyLength(fromHeader: Data([0, 0, 1])))
    }

    func testRejectsMalformedAndInvalidBodies() {
        XCTAssertThrowsError(try FrameCodec.decodeBody(Data("not json".utf8)))
        XCTAssertThrowsError(try FrameCodec.decodeBody(Data(#"{"type":"teleport"}"#.utf8)))
        // Valid JSON, invalid content: binder of wrong length.
        let bad = #"{"type":"clientHello","body":{"protocolVersion":1,"pairingID":"\#(UUID().uuidString)","deviceID":"\#(UUID().uuidString)","appVersion":"1","binder":"AAAA"}}"#
        XCTAssertThrowsError(try FrameCodec.decodeBody(Data(bad.utf8)))
        // Unsupported protocol version.
        let version = #"{"type":"clientHello","body":{"protocolVersion":2,"pairingID":"\#(UUID().uuidString)","deviceID":"\#(UUID().uuidString)","appVersion":"1","binder":"\#(Data(count: 32).base64EncodedString())"}}"#
        XCTAssertThrowsError(try FrameCodec.decodeBody(Data(version.utf8)))
    }

    func testAccumulatorHandlesPartialAndCoalescedFrames() throws {
        let a = try FrameCodec.encode(.ping)
        let b = try FrameCodec.encode(.pong)
        var accumulator = FrameAccumulator()
        let stream = a + b
        var received: [WireMessage] = []
        for byte in stream { received += try accumulator.append(Data([byte])) }
        XCTAssertEqual(received, [.ping, .pong])
        var second = FrameAccumulator()
        XCTAssertEqual(try second.append(stream), [.ping, .pong])
    }
}

final class RateLimiterTests: XCTestCase {
    func testTokenBucket() {
        var bucket = TokenBucket(capacity: 2, refillPerSecond: 1)
        let t0 = MonotonicInstant(nanoseconds: 0)
        XCTAssertTrue(bucket.tryConsume(at: t0))
        XCTAssertTrue(bucket.tryConsume(at: t0))
        XCTAssertFalse(bucket.tryConsume(at: t0))
        XCTAssertTrue(bucket.tryConsume(at: t0.advanced(bySeconds: 1.01)))
    }

    func testSlidingWindow() {
        var limiter = SlidingWindowLimiter<String>(limit: 2, window: 60)
        let t0 = MonotonicInstant(nanoseconds: 0)
        XCTAssertTrue(limiter.allow("a", at: t0))
        XCTAssertTrue(limiter.allow("a", at: t0))
        XCTAssertFalse(limiter.allow("a", at: t0))
        XCTAssertTrue(limiter.allow("b", at: t0))
        XCTAssertTrue(limiter.allow("a", at: t0.advanced(bySeconds: 61)))
    }
}

final class SessionSnapshotTests: XCTestCase {
    func testParsesLockedConsoleSession() {
        let snapshot = SessionSnapshot.parse([
            "kCGSSessionUserNameKey": "alice",
            "kCGSSessionUserIDKey": NSNumber(value: 501),
            "kCGSSessionOnConsoleKey": true,
            "kCGSessionLoginDoneKey": true,
            "CGSSessionScreenIsLocked": true,
            "kCGSSessionSecureInputPID": NSNumber(value: 123),
        ])
        XCTAssertEqual(snapshot.lockState, .locked)
        XCTAssertTrue(snapshot.isLockedConsoleSession(of: "alice", uid: 501))
        XCTAssertFalse(snapshot.isLockedConsoleSession(of: "bob", uid: 501))
        XCTAssertEqual(snapshot.secureInputPID, 123)
    }

    func testMissingLockKeyMeansUnlocked() {
        let snapshot = SessionSnapshot.parse(["kCGSSessionUserNameKey": "alice", "kCGSSessionUserIDKey": 501, "kCGSSessionOnConsoleKey": true, "kCGSessionLoginDoneKey": true])
        XCTAssertEqual(snapshot.lockState, .unlocked)
    }

    func testFastUserSwitchingAndLogoutAreUnavailable() {
        let switchedAway = SessionSnapshot.parse(["kCGSSessionUserNameKey": "alice", "kCGSSessionUserIDKey": 501, "kCGSSessionOnConsoleKey": false, "kCGSessionLoginDoneKey": true, "CGSSessionScreenIsLocked": true])
        XCTAssertEqual(switchedAway.lockState, .unavailable)
        XCTAssertFalse(switchedAway.isLockedConsoleSession(of: "alice", uid: 501))
        XCTAssertEqual(SessionSnapshot.parse(nil).lockState, .unavailable)
        let notLoggedIn = SessionSnapshot.parse(["kCGSSessionUserNameKey": "alice", "kCGSSessionUserIDKey": 501, "kCGSSessionOnConsoleKey": true, "kCGSessionLoginDoneKey": false])
        XCTAssertEqual(notLoggedIn.lockState, .unavailable)
    }
}
