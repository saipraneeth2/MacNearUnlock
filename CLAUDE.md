# CLAUDE.md — working on MacNearUnlock

Security-sensitive project: an iPhone Face ID approval protocol for a locked Mac. Read `SECURITY.md` before changing anything in `MacNearUnlockShared/Sources/.../Engine`, `Crypto`, `Pairing`, `Transport`, or `MacNearUnlockMac/Experimental`.

## Commands

```bash
cd MacNearUnlockShared && swift test                       # 82 tests, ~10 s, no signing needed
xcodebuild -project MacNearUnlock.xcodeproj -scheme MacNearUnlockMac -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project MacNearUnlock.xcodeproj -scheme MacNearUnlockiOS -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
cd MacNearUnlockShared && xcodebuild test -scheme MacNearUnlockShared -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

Signing settings live in `Config/Local.xcconfig` (gitignored; template `Config/Local.xcconfig.example`). Never commit a team ID or personal bundle prefix.

## Layout

* `MacNearUnlockShared` (Swift 6 language mode): all protocol logic and the Mac/iPhone engines. Put new logic here so it can be unit-tested; keep platform glue in the apps.
* `MacNearUnlockMac` / `MacNearUnlockiOS` (Swift 5 mode): Xcode 16+ *synchronized folders* — new files in these folders are picked up automatically; do not hand-add file references to `project.pbxproj`.
* `MacNearUnlockMac/Experimental`: credential adapter, wrapped in `#if EXPERIMENTAL_CREDENTIAL_ADAPTER`.

## Invariants (do not weaken; add a test when touching them)

* Sign/verify only `CanonicalWriter` bytes; never JSON. Every signed byte string has a unique `SigningDomain`. Bump `MNUProtocol.protocolVersion` for any wire/signing change.
* The Mac verifies approvals against bytes rebuilt from **its own** pending challenge, with the device key from its own store.
* `VerifiedApproval` is constructible only inside the package and is consumed exactly once. Anything acting on an approval must call `consume()` first.
* CGSession is the source of truth for lock state; notifications are hints only.
* Pending challenges are invalidated on unlock, sleep, logout, user switch, lost/superseded connection, revocation and relevant settings changes.
* iPhone keys: Secure Enclave, `.biometryCurrentSet`, no passcode fallback, reuse duration 0, one key per pairing. Never add a passcode or "trust unlocked phone" path without a separate, explicit, documented policy.
* Never label network presence as proximity.
* No secrets in logs (`EngineLogEntry` messages are shown in the UI and sent to os_log as public).
* Authentication-only mode stays the default. The experimental adapter stays off by default and must pass `CredentialEntryPolicy`.

## Hard rules for agents

* Never ask for, type, store or echo the user's Mac login password or Apple Account password — not in chat, terminal, files or tests. Credential setup happens only in the app's local sheet, by the user.
* Never grant TCC permissions, edit system settings, disable SIP or run privileged installs. Ask before locking the screen or doing anything that changes login state.
* Do not use private frameworks (SkyLight, loginwindow SPI, `SACLockScreenImmediate`, …).
* `FramedConnection.cancel()` must capture `self` strongly (a weak capture once left sockets open — see the lost-connection test).
* On macOS, a keychain *lookup* without a keychain-access-group entitlement reports "not found", a *write* reports `errSecMissingEntitlement`; `KeychainStore` probes with a write for that reason.
