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
| `MacNearUnlockiOS` signed device build | Initially blocked (no Apple account in Xcode); after signing in, built with automatic provisioning and installed on an iPhone 16 Pro Max via `devicectl` |
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

## Hardware results

**2026-11-21 — Mac mini (M4, Mac16,10), macOS 27.0.1, Dell 1080p display; iPhone 16 Pro Max, iOS 27.2.1 (24B156).** Mac app built from `7f6db2b`, iPhone app from `25eb7d1`, authentication-only mode on. Evidence is the Mac app's engine log (`log show --info --predicate 'subsystem == "MacNearUnlock"'`).

| # | Result | Evidence |
| --- | --- | --- |
| H1 | **Pass** | Paired by QR at 15:39:15 (`Paired with iPhone`); iPhone authenticated over TLS-PSK one second later on port 47311 with Bonjour. |
| H2 | **Pass** (from iPhone) after fix `25eb7d1` | 15:44:01 auth-test challenge issued → 15:44:03 `Approval VERIFIED for auth-test`. Mac-menu-initiated test not yet run. |
| H8 | **Pass** | Locked 15:45:02; three separate `unlock-session` challenges each verified (15:45:07, 15:45:17, 15:45:28) with distinct request IDs; Mac stayed locked; unlocked by password at 15:45:37. Two more locked approvals verified at 15:51:21 and 15:53:08. |
| H3 / H4 | **Pass** (Mac side) | Two Face ID failures/cancellations: 15:53:43 (`unlock-session`, Mac locked) and 15:54:47 (`auth-test`) each logged `declined on iPhone (biometricCancelled)`; nothing verified. The log cannot tell H3 from H4 apart. |
| H9 | **Pass** | 15:54:55 challenge issued → 15:55:26 `Challenge … expired` (30 s lifetime); never verified. |
| H10 | **Pass** (twice) | 15:56:36 challenge issued → 15:56:41 `Invalidated 1 pending challenge(s): Mac session changed` + `unlocked → unavailable (system will sleep)` → wake read as locked, then unlocked. Repeated 15:57:10 → 15:57:16. |
| H16 | **Partial** | 15:56:04 iPhone dropped (`Operation timed out`, Wi‑Fi off) and re-authenticated at 15:56:10. No challenge was pending at the time, so invalidation-on-drop is not shown here (it is covered by `testLostConnectionInvalidatesPendingChallenge`). |
| H2 (Mac menu), H13 | **Not observed** | No matching entries. The Mac log only had entries from 15:51:21 on: the app logged routine events at `info` level, which macOS keeps in a small memory buffer and drops quickly (fixed in `f96a414`). |
| H5 | **Pass** | 16:08:48 and 16:08:59 `declined (biometricCancelled)` after failed matches; then 16:09:15, 16:09:17 and 16:09:24 each `declined (biometricLockout)` within 0–3 s of issue (no prompt possible while locked out); nothing verified. Two manual Decline taps logged as `userDeclined`. |
| H17 | **Pass** | Accessibility granted manually. `Test Lock Now` locked the Mac and CGSession confirmed it (16:21:07, 16:23:44). First automatic attempt did not fire because the option was not on when the iPhone left; a countdown log line was added. Retest: iPhone disconnected 16:27:45 → `Lock on departure armed: locking in 15s` → 16:28:01 `locking` → `unlocked → locked` → 16:28:02 `Screen locked`; unlocked by password 16:28:08; option turned off afterwards. Triggered by the iPhone app going to the Home Screen, confirming it is a connectivity signal, not proximity. |
| H12 | **Pass** (restart); log-out step not observed | Restarted 16:04:36 with FileVault on (`fdesetup status`). No MacNearUnlock activity between boot and console login at 16:05. `backgroundtaskmanagementd` listed the SMAppService login item at 16:05:13; `launchd` spawned the app at 16:05:32; the iPhone re-authenticated at 16:05:44. No separate log-out session appears in `last` (the 16:02:15 lock/unlock kept the same app process). |

Bug found on hardware and fixed: the Face ID sheet makes the iOS scene `.inactive`, and the app closed its session for anything other than `.active`. Each challenge was invalidated by the Mac 1–2 s after issue and the iPhone reported `ClientError error 0` (not connected). Fixed in `25eb7d1` by ending sessions only on `.background`. Also fixed after the first real launch (`7f6db2b`): the menu-bar-only Mac app showed no window at all, so it looked like it had not started.

Still to run: H2 from the Mac menu, H13 (with a request pending), H16 (with a request pending), H12 log-out step, H6, H7, H11, H14, H15, H18.

## Hardware test plan

Run these on the real Mac mini and a Face ID iPhone. Record pass/fail in the results table above.

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
