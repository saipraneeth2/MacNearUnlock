import XCTest
@testable import MacNearUnlockShared

/// Mac-side approval verification (`ChallengeAuthority`).
final class ChallengeAuthorityTests: XCTestCase {
    private var clock: ManualClock!
    private var macSigner: SoftwareP256Signer!
    private var authority: ChallengeAuthority!
    private let macID = UUID()

    override func setUp() {
        clock = ManualClock()
        macSigner = SoftwareP256Signer()
        authority = ChallengeAuthority(macID: macID, macName: "Mac mini", signer: macSigner, configuration: .init(lifetime: 30), monotonic: clock, wall: clock)
    }

    private func verify(_ approval: UnlockApproval, device: PairedDeviceRecord?, pairing: UUID? = nil, session: SessionSnapshot = Fixtures.session(locked: true)) -> Result<VerifiedApproval, ApprovalRejection> {
        authority.verify(approval, authenticatedPairingID: pairing ?? approval.pairingID, device: device, session: session, expectedUsername: Fixtures.user, expectedUID: Fixtures.uid)
    }

    func testIssuedRequestHasFreshNonceAndValidMacSignature() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let first = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        clock.advance(1)
        let second = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        XCTAssertEqual(first.request.nonce.count, 32)
        XCTAssertNotEqual(first.request.nonce, second.request.nonce)
        XCTAssertNotEqual(first.request.requestID, second.request.requestID)
        XCTAssertTrue(SignatureVerifier.isValid(signatureDER: second.macSignature, message: second.request.requestSigningBytes(), publicKeyX963: macSigner.publicKeyX963))
        XCTAssertEqual(second.request.lifetime, 30, accuracy: 0.01)
    }

    func testValidApprovalIsVerifiedExactlyOnce() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signed, signer: phone)

        guard case .success(let verified) = verify(reply, device: device) else { return XCTFail("expected success") }
        XCTAssertEqual(verified.requestID, signed.request.requestID)
        XCTAssertEqual(verified.action, .unlockSession)
        XCTAssertTrue(verified.consume())
        XCTAssertFalse(verified.consume(), "A verified approval token can drive only one action")

        // Replaying the identical approval must fail.
        XCTAssertEqual(verify(reply, device: device), .failure(.replayed))
    }

    func testUnsolicitedApprovalRejected() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let forged = UnlockRequest(requestID: UUID(), nonce: SecureRandom.bytes(32), macID: macID, macName: "Mac mini", macUsername: Fixtures.user, pairingID: device.pairingID, deviceID: device.deviceID, action: .unlockSession, issuedAtMillis: clock.now().millisecondsSince1970, expiresAtMillis: clock.now().millisecondsSince1970 + 30_000)
        let signature = try await phone.sign(forged.approvalSigningBytes(), reason: "")
        let reply = UnlockApproval(requestID: forged.requestID, pairingID: device.pairingID, deviceID: device.deviceID, signature: signature)
        XCTAssertEqual(verify(reply, device: device), .failure(.unsolicited), "A correctly signed approval for a challenge the Mac never issued must fail")
    }

    func testUnpairedDeviceCannotApprove() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let attacker = SoftwareP256Signer()
        let reply = try await approval(for: signed, signer: attacker)
        XCTAssertEqual(verify(reply, device: device), .failure(.badSignature))
    }

    func testMultiplePairedPhonesCannotSatisfyEachOthersChallenges() async throws {
        let phoneA = SoftwareP256Signer(), phoneB = SoftwareP256Signer()
        let deviceA = Fixtures.device(signer: phoneA, name: "A"), deviceB = Fixtures.device(signer: phoneB, name: "B")
        let forA = try await authority.issue(action: .unlockSession, for: deviceA, macUsername: Fixtures.user)
        let forB = try await authority.issue(action: .unlockSession, for: deviceB, macUsername: Fixtures.user)

        // B signs A's challenge and sends it over B's authenticated connection.
        let signedByB = try await phoneB.sign(forA.request.approvalSigningBytes(), reason: "")
        let crossed = UnlockApproval(requestID: forA.request.requestID, pairingID: deviceB.pairingID, deviceID: deviceB.deviceID, signature: signedByB)
        XCTAssertEqual(verify(crossed, device: deviceB, pairing: deviceB.pairingID), .failure(.wrongDevice))

        // B claims A's pairing ID in the body but is authenticated as B.
        let spoofed = UnlockApproval(requestID: forA.request.requestID, pairingID: deviceA.pairingID, deviceID: deviceA.deviceID, signature: signedByB)
        XCTAssertEqual(verify(spoofed, device: deviceB, pairing: deviceB.pairingID), .failure(.wrongDevice))

        // Each phone's own approval still works.
        if case .failure(let error) = verify(try await approval(for: forA, signer: phoneA), device: deviceA) { XCTFail("A: \(error)") }
        if case .failure(let error) = verify(try await approval(for: forB, signer: phoneB), device: deviceB) { XCTFail("B: \(error)") }
    }

    func testApprovalForOneMacCannotAuthorizeAnother() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let otherMac = ChallengeAuthority(macID: UUID(), macName: "Other Mac", signer: SoftwareP256Signer(), monotonic: clock, wall: clock)
        let signedByA = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signedByA, signer: phone)
        // The other Mac never issued this request ID.
        XCTAssertEqual(otherMac.verify(reply, authenticatedPairingID: device.pairingID, device: device, session: Fixtures.session(locked: true), expectedUsername: Fixtures.user, expectedUID: Fixtures.uid), .failure(.unsolicited))

        // Even if the other Mac has a pending challenge with the same pairing, the
        // signature (bound to macID + nonce) does not transfer.
        let signedByB = try await otherMac.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let transplanted = UnlockApproval(requestID: signedByB.request.requestID, pairingID: device.pairingID, deviceID: device.deviceID, signature: reply.signature)
        XCTAssertEqual(otherMac.verify(transplanted, authenticatedPairingID: device.pairingID, device: device, session: Fixtures.session(locked: true), expectedUsername: Fixtures.user, expectedUID: Fixtures.uid), .failure(.badSignature))
    }

    func testExpiryUsesMonotonicDeadline() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signed, signer: phone)
        clock.advance(31)
        XCTAssertEqual(verify(reply, device: device), .failure(.expired))
        XCTAssertEqual(verify(reply, device: device), .failure(.replayed), "An expired challenge is retired for good")
    }

    func testWindingWallClockBackDoesNotExtendValidity() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signed, signer: phone)
        clock.advance(31)
        clock.shiftWall(-3600) // user sets the date back an hour
        XCTAssertEqual(verify(reply, device: device), .failure(.expired))
    }

    func testExpireStaleRetiresChallenges() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        _ = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        XCTAssertTrue(authority.expireStale().isEmpty)
        clock.advance(30)
        XCTAssertEqual(authority.expireStale().count, 1)
        XCTAssertFalse(authority.hasPending)
    }

    func testRevokedDeviceCannotApprove() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signed, signer: phone)
        // Device record removed from the store (revoked) before the approval arrives.
        XCTAssertEqual(verify(reply, device: nil), .failure(.revoked))

        // Revocation via invalidate(pairingID:) also kills pending challenges.
        let signed2 = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        authority.invalidate(pairingID: device.pairingID)
        do {
            let awaited = try await approval(for: signed2, signer: phone)
            XCTAssertEqual(verify(awaited, device: device), .failure(.replayed))
        }
    }

    func testSessionMustStillBeLockedForUnlockAction() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signed, signer: phone)
        XCTAssertEqual(verify(reply, device: device, session: Fixtures.session(locked: false)), .failure(.sessionNotLocked))

        let signed2 = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        do {
            let awaited = try await approval(for: signed2, signer: phone)
            XCTAssertEqual(verify(awaited, device: device, session: Fixtures.session(locked: true, user: "bob", uid: 502)), .failure(.sessionNotLocked), "Fast user switching to another account")
        }

        let signed3 = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        do {
            let awaited = try await approval(for: signed3, signer: phone)
            XCTAssertEqual(verify(awaited, device: device, session: .unavailable), .failure(.sessionNotLocked), "Logged out / asleep")
        }
    }

    func testAuthenticationTestWorksWhileUnlockedButCannotBecomeUnlock() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .authenticationTest, for: device, macUsername: Fixtures.user)
        let reply = try await approval(for: signed, signer: phone)
        guard case .success(let verified) = verify(reply, device: device, session: Fixtures.session(locked: false)) else { return XCTFail() }
        XCTAssertEqual(verified.action, .authenticationTest)
    }

    func testInvalidateAllOnSleepOrUnlock() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        XCTAssertEqual(authority.invalidateAll().count, 1)
        do {
            let awaited = try await approval(for: signed, signer: phone)
            XCTAssertEqual(verify(awaited, device: device), .failure(.replayed))
        }
    }

    func testNewChallengeRetiresPreviousForSamePairing() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let first = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        _ = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        do {
            let awaited = try await approval(for: first, signer: phone)
            XCTAssertEqual(verify(awaited, device: device), .failure(.replayed))
        }
    }

    func testBadSignatureBudget() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        let forged = UnlockApproval(requestID: signed.request.requestID, pairingID: device.pairingID, deviceID: device.deviceID, signature: Data(repeating: 0x30, count: 70))
        for _ in 0..<3 { XCTAssertEqual(verify(forged, device: device), .failure(.badSignature)) }
        // After three bad signatures the challenge is burned, even for the real phone.
        do {
            let awaited = try await approval(for: signed, signer: phone)
            XCTAssertEqual(verify(awaited, device: device), .failure(.replayed))
        }
    }

    func testDeclineRetiresOnlyOwnChallenge() async throws {
        let phone = SoftwareP256Signer()
        let device = Fixtures.device(signer: phone)
        let signed = try await authority.issue(action: .unlockSession, for: device, macUsername: Fixtures.user)
        XCTAssertFalse(authority.decline(requestID: signed.request.requestID, authenticatedPairingID: UUID()))
        XCTAssertTrue(authority.decline(requestID: signed.request.requestID, authenticatedPairingID: device.pairingID))
        do {
            let awaited = try await approval(for: signed, signer: phone)
            XCTAssertEqual(verify(awaited, device: device), .failure(.replayed))
        }
    }

    func testIssueRateLimit() async throws {
        let device = Fixtures.device(signer: SoftwareP256Signer())
        for _ in 0..<6 { _ = try await authority.issue(action: .authenticationTest, for: device, macUsername: Fixtures.user) }
        do {
            _ = try await authority.issue(action: .authenticationTest, for: device, macUsername: Fixtures.user)
            XCTFail("expected rate limit")
        } catch {
            XCTAssertEqual(error as? ChallengeIssueError, .rateLimited)
        }
        clock.advance(61)
        _ = try await authority.issue(action: .authenticationTest, for: device, macUsername: Fixtures.user)
    }

    func testLifetimeIsClamped() {
        XCTAssertEqual(ChallengeAuthority.Configuration(lifetime: 1).lifetime, 10)
        XCTAssertEqual(ChallengeAuthority.Configuration(lifetime: 9_999).lifetime, 120)
    }

    func testDeviceRecordDescriptionNeverLeaksChannelKey() {
        let key = Data(repeating: 0xAB, count: 32)
        let device = Fixtures.device(signer: SoftwareP256Signer(), channelKey: key)
        XCTAssertFalse(String(describing: device).lowercased().contains("abab"))
        XCTAssertFalse(String(reflecting: device).lowercased().contains("abab"))
    }
}

/// iPhone-side request validation (`RequestValidator`).
final class RequestValidatorTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func setup() -> (SoftwareP256Signer, PairedDeviceRecord, PinnedMac, RequestValidator) {
        let mac = SoftwareP256Signer()
        let device = Fixtures.device(signer: SoftwareP256Signer())
        let pinned = Fixtures.pinned(for: device, macID: UUID(), macSigner: mac)
        return (mac, device, pinned, RequestValidator(wall: FixedWall(date: now)))
    }

    private func request(for pinned: PinnedMac, macID: UUID? = nil, pairingID: UUID? = nil, deviceID: UUID? = nil, user: String? = nil, issued: Date? = nil, lifetime: UInt64 = 30_000) -> UnlockRequest {
        let issuedMillis = (issued ?? now).millisecondsSince1970
        return UnlockRequest(requestID: UUID(), nonce: SecureRandom.bytes(32), macID: macID ?? pinned.macID, macName: pinned.macName, macUsername: user ?? pinned.macUsername, pairingID: pairingID ?? pinned.pairingID, deviceID: deviceID ?? pinned.deviceID, action: .unlockSession, issuedAtMillis: issuedMillis, expiresAtMillis: issuedMillis + lifetime)
    }

    private func sign(_ request: UnlockRequest, with signer: MessageSigner) async throws -> SignedUnlockRequest {
        SignedUnlockRequest(request: request, macSignature: try await signer.sign(request.requestSigningBytes(), reason: ""))
    }

    func testValidRequestAccepted() async throws {
        let (mac, _, pinned, validator) = setup()
        let signed = try await sign(request(for: pinned), with: mac)
        XCTAssertEqual(validator.validate(signed, pinned: pinned), .success(signed.request))
    }

    func testForgedBonjourAdvertiserCannotImpersonatePairedMac() async throws {
        let (_, _, pinned, validator) = setup()
        // Attacker copies every identifier of the paired Mac but lacks its key.
        let impostor = SoftwareP256Signer()
        let signed = try await sign(request(for: pinned), with: impostor)
        XCTAssertEqual(validator.validate(signed, pinned: pinned), .failure(.badSignature))
    }

    func testRequestForAnotherMacOrDeviceRejected() async throws {
        let (mac, _, pinned, validator) = setup()
        do {
            let awaited = try await sign(request(for: pinned, macID: UUID()), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.wrongMac))
        }
        do {
            let awaited = try await sign(request(for: pinned, pairingID: UUID()), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.wrongPairing))
        }
        do {
            let awaited = try await sign(request(for: pinned, deviceID: UUID()), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.wrongDevice))
        }
        do {
            let awaited = try await sign(request(for: pinned, user: "root"), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.wrongUser))
        }
    }

    func testTimeWindowEnforced() async throws {
        let (mac, _, pinned, validator) = setup()
        do {
            let awaited = try await sign(request(for: pinned, issued: now.addingTimeInterval(-400)), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.expired))
        }
        do {
            let awaited = try await sign(request(for: pinned, issued: now.addingTimeInterval(400)), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.notYetValid))
        }
        do {
            let awaited = try await sign(request(for: pinned, lifetime: 3_600_000), with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.lifetimeTooLong))
        }
    }

    func testDuplicateRequestRejected() async throws {
        let (mac, _, pinned, validator) = setup()
        let signed = try await sign(request(for: pinned), with: mac)
        XCTAssertEqual(validator.validate(signed, pinned: pinned), .success(signed.request))
        XCTAssertEqual(validator.validate(signed, pinned: pinned), .failure(.duplicate))
    }

    func testMalformedRequestRejected() async throws {
        let (mac, _, pinned, validator) = setup()
        let good = request(for: pinned)
        let bad = UnlockRequest(requestID: good.requestID, nonce: Data(count: 8), macID: good.macID, macName: good.macName, macUsername: good.macUsername, pairingID: good.pairingID, deviceID: good.deviceID, action: good.action, issuedAtMillis: good.issuedAtMillis, expiresAtMillis: good.expiresAtMillis)
        do {
            let awaited = try await sign(bad, with: mac)
            XCTAssertEqual(validator.validate(awaited, pinned: pinned), .failure(.malformed))
        }
    }
}

final class UnlockStateMachineTests: XCTestCase {
    func testHappyPathUnlock() {
        var machine = UnlockStateMachine(initial: .idle)
        XCTAssertTrue(machine.handle(.sessionLocked)); XCTAssertEqual(machine.state, .locked)
        XCTAssertTrue(machine.handle(.requestIssued)); XCTAssertEqual(machine.state, .requesting)
        XCTAssertTrue(machine.handle(.requestDelivered)); XCTAssertEqual(machine.state, .awaitingBiometrics)
        XCTAssertTrue(machine.handle(.approvalVerified)); XCTAssertEqual(machine.state, .verified)
        XCTAssertTrue(machine.handle(.sessionUnlocked)); XCTAssertEqual(machine.state, .idle)
    }

    func testAuthenticationTestFromIdle() {
        var machine = UnlockStateMachine(initial: .idle)
        XCTAssertTrue(machine.handle(.requestIssued))
        XCTAssertTrue(machine.handle(.requestDelivered))
        XCTAssertTrue(machine.handle(.approvalVerified))
        XCTAssertTrue(machine.handle(.reset(locked: false)))
        XCTAssertEqual(machine.state, .idle)
    }

    func testInvalidTransitionsRejected() {
        var machine = UnlockStateMachine(initial: .locked)
        XCTAssertFalse(machine.handle(.approvalVerified), "Cannot verify without a delivered challenge")
        XCTAssertEqual(machine.state, .locked)
        XCTAssertFalse(machine.handle(.requestDelivered))
        XCTAssertFalse(machine.handle(.requestExpired))
        machine = UnlockStateMachine(initial: .requesting)
        XCTAssertFalse(machine.handle(.approvalVerified), "Approval cannot precede delivery")
        machine = UnlockStateMachine(initial: .unavailable)
        XCTAssertFalse(machine.handle(.requestIssued), "No challenges while asleep / logged out")
        machine = UnlockStateMachine(initial: .verified)
        XCTAssertFalse(machine.handle(.approvalVerified), "No double verification")
    }

    func testExpiryRejectionAndUnavailable() {
        var machine = UnlockStateMachine(initial: .awaitingBiometrics)
        XCTAssertTrue(machine.handle(.requestExpired)); XCTAssertEqual(machine.state, .expired)
        XCTAssertTrue(machine.handle(.reset(locked: true))); XCTAssertEqual(machine.state, .locked)
        XCTAssertTrue(machine.handle(.requestIssued))
        XCTAssertTrue(machine.handle(.approvalRejected)); XCTAssertEqual(machine.state, .rejected)
        XCTAssertTrue(machine.handle(.sessionUnavailable)); XCTAssertEqual(machine.state, .unavailable)
    }

    func testEveryStateHandlesSessionFacts() {
        for state in UnlockState.allCases {
            XCTAssertEqual(UnlockStateMachine.transition(from: state, on: .sessionUnlocked), .idle)
            XCTAssertEqual(UnlockStateMachine.transition(from: state, on: .sessionUnavailable), .unavailable)
            XCTAssertEqual(UnlockStateMachine.transition(from: state, on: .sessionLocked), .locked)
        }
    }
}
