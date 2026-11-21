# Testing

## Results (2026-11-21, macOS 27.0.1, Xcode 27.2, Swift 6.4.2)

| Run | Result |
| --- | --- |
| `swift test` in `MacNearUnlockShared` | **82 tests, 0 failures** (~7.5 s) |
| `xcodebuild test -scheme MacNearUnlockShared -destination 'platform=macOS'` | **82 / 0** |
| `xcodebuild test … -destination 'platform=iOS Simulator,name=iPhone 17 Pro'` (iOS 27.2) | **82 / 0** — includes the TLS-PSK loopback tests on the iOS runtime |
| `MacNearUnlockMac` Debug, signed (Apple Development, manual, hardened runtime) | Build succeeded, 0 warnings; `codesign --verify --deep --strict` OK |
| `MacNearUnlockMac` Release, unsigned | Build succeeded |
| `MacNearUnlockiOS` Debug, iOS Simulator | Build succeeded, 0 warnings; launched in Simulator, empty state renders |
| `MacNearUnlockiOS` Release, `generic/platform=iOS` (arm64), unsigned | Build succeeded |
| `MacNearUnlockiOS` signed device build | **Blocked**: no Apple account signed into Xcode → no provisioning profile (see SETUP.md §1) |
| Mac app smoke launch | Launched, created its Secure Enclave identity (login-keychain fallback), engine read real CGSession state (`unavailable → unlocked`), quit cleanly |

The smoke launch found a real bug: without a keychain-access-group entitlement, a data-protection keychain *lookup* returns "not found" while a *write* returns `errSecMissingEntitlement`, so the original read-based probe chose the wrong keychain and identity creation failed. `KeychainStore` now probes with a write. A second real bug was found by `testLostConnectionInvalidatesPendingChallenge`: `FramedConnection.cancel()` captured `self` weakly, so a client that dropped its last reference never closed the socket and the Mac kept the challenge alive. Both are fixed and covered.

## Automated coverage (82 tests)

| Requirement | Tests |
| --- | --- |
| Canonical, unambiguous signing bytes | `CanonicalEncodingTests` (determinism, boundary ambiguity, domain separation, NFC, exact layout) |
| Signing / verification; any field change breaks the signature | `RequestSigningTests.testSignatureVerifiesAndAnyFieldChangeBreaksIt`, `testRequestSignatureCannotBeUsedAsApproval`, `testWrongKeyAndMalformedSignaturesRejected` |
| Replay rejection; repeated approvals cannot unlock twice | `ChallengeAuthorityTests.testValidApprovalIsVerifiedExactlyOnce`, `LoopbackIntegrationTests.testReplayedApprovalRejectedOverNetwork`, `testAuthenticationOnlyModeEndToEnd` (client refuses a second signature) |
| Unsolicited / stale / malformed approvals | `testUnsolicitedApprovalRejected`, `testExpiryUsesMonotonicDeadline`, `testWindingWallClockBackDoesNotExtendValidity`, `testBadSignatureBudget`, `FrameCodecTests` |
| Wrong-device responses; multiple paired phones | `testMultiplePairedPhonesCannotSatisfyEachOthersChallenges`, `testPairedDeviceCannotImpersonateAnotherPairing` |
| Unpaired device cannot approve or connect | `testUnpairedDeviceCannotApprove`, `testUnpairedDeviceCannotConnect`, `testMessagesBeforeHelloAreRejected` |
| Approval for one Mac cannot authorize another | `testApprovalForOneMacCannotAuthorizeAnother`, `RequestValidatorTests.testRequestForAnotherMacOrDeviceRejected` |
| Forged Bonjour advertiser cannot impersonate a paired Mac | `RequestValidatorTests.testForgedBonjourAdvertiserCannotImpersonatePairedMac`, `testForgedMacWithStolenChannelKeyCannotObtainApproval`, `testUnpairedDeviceCannotConnect` (TLS-PSK) |
| Revoked keys (both directions) | `testRevokedDeviceCannotApprove`, `testMacRevocationNotifiesPhoneAndBlocksReconnect`, `testPhoneRevocationReachesMac` |
| Lost connection | `testLostConnectionInvalidatesPendingChallenge` |
| Sleep / unlock / fast user switching / logout (logic) | `testSleepInvalidatesAndBlocksChallenges`, `testSessionUnlockInvalidatesPendingChallenge`, `testSessionMustStillBeLockedForUnlockAction`, `SessionSnapshotTests` |
| Biometric cancellation; enrollment change | `testBiometricCancellationProducesNoApproval`, `testEnrollmentChangeInvalidatedKeyCannotApprove`, `testPairingAbortsWhenPhoneFaceIDCancelled` (modelled with failing / replaced signers) |
| Authentication-only mode independent of credential entry | `testAuthenticationOnlyModeEndToEnd`, `testUnlockActionInAuthenticationOnlyModeNeverReachesAdapter`, `testAuthenticationTestWorksWhileUnlockedButCannotBecomeUnlock` |
| Pairing: key substitution, SAS, wrong code | `testFullPairingThenAuthenticatedSession`, `testPairingRejectsMacKeyNotMatchingQRCode`, `testKeySubstitutionChangesVerificationCode`, `testPairingWithWrongCodeFailsAndBurnsInvitation`, `testPairingAbortsWhenMacUserRejectsCode` |
| Strict state machine | `UnlockStateMachineTests` |
| Experimental adapter gate (each precondition alone denies) | `CredentialEntryPolicyTests` |
| Rate limiting, constant-time compare, no key leakage in descriptions | `RateLimiterTests`, `testConstantTimeEquals`, `testDeviceRecordDescriptionNeverLeaksChannelKey` |

Mocks: software P-256 keys stand in for the Secure Enclave, `FailingSigner` for a cancelled Face ID prompt, a fake session provider for CGSession, and a manual clock for time. Transport tests use **real** Network.framework TLS-PSK on 127.0.0.1.

## Requires physical hardware (not executed)

Run these on the real Mac mini and a Face ID iPhone. Record pass/fail in this file.

| # | Test | Expected |
| --- | --- | --- |
| H1 | Pair via QR; compare codes; confirm on both | Paired on both; fingerprints match Settings › Devices |
| H2 | Authentication test from iPhone and from Mac menu | Face ID prompt each time; "verified (authentication only)" |
| H3 | Approve while looking away / with another face | Secure Enclave refuses; no approval sent |
| H4 | Cancel Face ID | "Face ID was cancelled"; Mac shows Rejected; nothing verified |
| H5 | Trigger Face ID lockout (5 failures) | Lockout message; no passcode prompt offered by the app |
| H6 | Add an alternate appearance in Face ID settings, then approve | "enrollment changed… re-pair"; old key unusable |
| H7 | Remove device passcode, reopen app | Key gone (`WhenPasscodeSetThisDeviceOnly`) → re-pair required |
| H8 | Lock Mac, Request Unlock, approve | Verified; Mac stays locked (auth-only); log shows `unlock-session` verified |
| H9 | Approve after the expiry countdown | Expired |
| H10 | Mac sleeps with a pending request, wake, approve old request | Rejected (invalidated on sleep) |
| H11 | Fast user switch to another account, approve | Unavailable / rejected |
| H12 | Log out, restart, FileVault pre-boot | App not running; nothing possible; password login normal |
| H13 | Background the iPhone app with a pending request | No Face ID prompt; connection drops; Mac invalidates request |
| H14 | Pair two iPhones; approve from each | Each approves only its own requests |
| H15 | Revoke on Mac while iPhone connected / disconnected | Phone notified / next connection fails |
| H16 | Turn off Wi-Fi on iPhone mid-request | Lost connection, request invalidated, reconnects later |
| H17 | Lock on departure: test lock, enable, background iPhone app | Mac locks after grace period (and you see why it is not proximity) |
| H18 | Experimental adapter — see EXPERIMENTAL_ADAPTER.md §Validation | Only with explicit decision to store the password |

Bonjour impersonation on a real network (H-optional): advertise `_mnunlock._tcp` with a copied TXT `mid` from another machine (`dns-sd -R`); the iPhone must fail to connect or reject requests.
