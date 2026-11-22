# Security model and threat analysis

MacNearUnlock lets a paired iPhone, after a fresh Face ID match, approve a short-lived challenge issued by a locked Mac. This document states what is protected, against whom, how, and what remains possible. If any claim here disagrees with the code, the code is wrong; open an issue.

## Non-negotiable rules

1. **No bypass of macOS security.** Nothing here touches FileVault, Secure Boot, SIP, TCC, the authorization database, PAM, loginwindow plug-ins or private authentication SPI. No permission is granted programmatically; Accessibility must be granted by the user in System Settings.
2. **No login after restart, logout or at the FileVault pre-boot screen.** The Mac app runs only inside a logged-in user session. Every action re-checks via `CGSessionCopyCurrentDictionary()` that the expected user is logged in (`kCGSessionLoginDoneKey`), owns the console (`kCGSSessionOnConsoleKey`) and is locked.
3. **The Mac password is always the fallback.** Nothing disables or replaces normal login.
4. **Every approval needs a fresh Face ID match, enforced by the iPhone's Secure Enclave**, not by an app boolean. No passcode fallback.
5. **Bonjour/network presence is never authorization and never "proximity".**
6. **Authentication-only mode is the default.** The experimental credential adapter is off, isolated, and gated (see below).
7. **No secrets in logs.** Logs contain shortened request IDs and outcomes only, never passwords, keys, nonces, full signatures or channel keys.

## Assets

| Asset | Where | Protection |
| --- | --- | --- |
| iPhone approval key (P-256) | iPhone Secure Enclave, one per paired Mac | Non-exportable; `.privateKeyUsage + .biometryCurrentSet`; `WhenPasscodeSetThisDeviceOnly`; invalidated by Face ID re-enrolment or passcode removal |
| Mac identity key (P-256) | Mac Secure Enclave (software fallback only if no SE) | Non-exportable; no user presence (must sign while locked; Mac mini has no Touch ID); SE blob stored in Keychain |
| Per-pairing channel key (256-bit) | Mac Keychain; iPhone Keychain (`WhenUnlockedThisDeviceOnly`) | Derived from ephemeral X25519 + transcript hash; used as TLS-PSK and binder key |
| Trusted-device list (pinned keys) | Mac Keychain (one item, not UserDefaults) | Keychain integrity; data-protection keychain when entitled, otherwise login keychain ACL'd to the app signature |
| Mac login password (experimental only) | Mac Keychain, ChaCha20-Poly1305 ciphertext | Key derived via ECDH with a Secure Enclave key requiring local user presence; armed in memory ≤ 12 h; never leaves the Mac |
| Access to the locked session | n/a | The whole protocol; final gate is the experimental adapter's policy |

## Adversaries and mitigations

### A1: Attacker on the same network (passive or active)
Can sniff, advertise Bonjour services, spoof names/TXT records, MITM TCP, replay traffic, flood connections.

* **Forged Bonjour advertiser / impersonated Mac:** connections require TLS-PSK with the per-pairing key (TLS 1.2 `ECDHE_PSK_WITH_CHACHA20_POLY1305`); an advertiser without it fails the handshake. Even with the key, every challenge must be signed by the pinned Mac identity key; the iPhone rejects anything else *before* showing it or prompting for Face ID. *Tests:* `testForgedBonjourAdvertiserCannotImpersonatePairedMac`, `testForgedMacWithStolenChannelKeyCannotObtainApproval`.
* **Unpaired device:** fails TLS (unknown identity → `-9864`, wrong key → bad MAC `-9820`). *Test:* `testUnpairedDeviceCannotConnect`.
* **One paired phone claiming to be another:** the hello binder is an HMAC under the claimed pairing's key over the TLS exporter, so the claimed pairing must match the PSK actually used. *Test:* `testPairedDeviceCannotImpersonateAnotherPairing`.
* **Replay:** challenges carry a 256-bit CSPRNG nonce and UUID, are single-use, and retired IDs are remembered for 10 minutes (longer than any validity window). *Tests:* `testValidApprovalIsVerifiedExactlyOnce`, `testReplayedApprovalRejectedOverNetwork`.
* **Recorded traffic:** ECDHE gives forward secrecy; pairing traffic keys never derive from the short code alone.
* **Downgrade:** only protocol version 1, only TLS 1.2 with the pinned suite; the exporter is refused if any other version/suite was negotiated.
* **Flooding:** ≤ 8 connections, 5-second hello deadline, 20-message burst / 5 msg/s per connection, 16 KiB frame cap, 6 challenges/min per device, idle timeout, connection dropped after 5 suspicious messages. A LAN attacker can still jam Wi-Fi; denial of service is out of scope.

### A2: Pairing-time attacker (key substitution)
* The QR code carries a one-time 80-bit code (keys the pairing TLS-PSK tunnel) **and** the SHA-256 fingerprint of the Mac identity key. The iPhone aborts if the Mac key differs (`testPairingRejectsMacKeyNotMatchingQRCode`).
* Both long-term keys sign/confirm a transcript that includes every handshake field and the TLS exporter, so a relay that splits the TLS session changes the transcript.
* A 6-digit + 4-word verification string from the transcript hash is compared on both screens before **both** sides confirm (Mac: click; iPhone: Face ID signature over the transcript). The Mac stores nothing without the phone's valid confirmation signature (`testPairingAbortsWhenPhoneFaceIDCancelled`).
* Manual-code pairing has no fingerprint; the verification-string comparison is then the defence.
* Invitations expire after 2 minutes and are burned after 3 failed TLS handshakes (`testPairingWithWrongCodeFailsAndBurnsInvitation`). Nothing auto-pairs on a device name, Apple Account, IP address or Bluetooth signal.

### A3: Someone with your iPhone
* Locked phone: the companion app cannot run its UI; Face ID is still required per approval.
* Unlocked phone, wrong face: the Secure Enclave refuses to sign. Reuse duration is 0 and the fallback button is hidden; `.biometryCurrentSet` cannot be satisfied with the passcode.
* Attacker enrols their own face: the key is permanently invalidated; the app also compares the enrolment hash and demands re-pairing.
* Mitigation if lost: revoke the iPhone from the Mac's Devices tab; it takes effect immediately.

### A4: Coercion or a look-alike
Face ID's attention requirement and false-accept rate are Apple's. A coerced user can be made to look at the phone; this design cannot prevent that. Authentication-only mode limits the damage to "the Mac logged a verified approval".

### A5: Malware running as you on the Mac
Out of scope for full protection: it can already keylog the password you type. Measures that still help:
* Distributed notifications (`com.apple.screenIsLocked`, …) are hints only; state comes from CGSession, re-read before every decision and polled every 2 s.
* Hardened runtime (no injection/debugging of the app).
* Keychain items are ACL'd to the app; on builds without a keychain-access-group entitlement they live in the login keychain, where another app must trigger a user-visible prompt.
* **Experimental adapter armed:** the wrapping key is in this process's memory for up to 12 hours; a process able to read that memory, or to make this app type into a field it controls, could misuse it. This is the main reason it is off by default.

### A6: Another macOS account (fast user switching)
Challenges are bound to the account that paired. When the console belongs to another user (`kCGSSessionOnConsoleKey == false` or user/UID mismatch) the engine reports *unavailable*, issues nothing and rejects approvals (`testSessionMustStillBeLockedForUnlockAction`).

### A7: Clock manipulation
Validity uses a Mac-local monotonic deadline (`CLOCK_MONOTONIC`, which counts through sleep) **and** the signed wall-clock expiry. Turning the clock back does not extend a challenge (`testWindingWallClockBackDoesNotExtendValidity`). Sleep, unlock, logout, lost connection, settings changes and revocation invalidate pending challenges.

## Approval verification (Mac), in order

1. Pending challenge exists (else *unsolicited* / *replayed*).
2. Approval arrived on the connection authenticated as the pairing the challenge was issued to; device ID matches (else *wrong device*).
3. Pairing still present (else *revoked*).
4. Monotonic deadline and wall-clock expiry not passed (else *expired*; retired).
5. DER ECDSA P-256 signature verifies under the **pinned** device key over canonical bytes **rebuilt from the Mac's own copy** of the challenge (3 bad signatures burn the challenge).
6. Fresh CGSession read: `.unlockSession` requires the expected user's locked console session; `.authenticationTest` requires the expected user's session.
7. Challenge retired; a single-use `VerifiedApproval` token is returned. Only `ChallengeAuthority` can create one; consuming it is atomic and one-shot.

## Proximity: what is and is not claimed

* Bonjour proves only that both devices can reach each other on a local network (which may be the whole building, a VPN or a bridged network). The UI says "same network", never "nearby".
* CoreBluetooth RSSI was evaluated and **not** used: it fluctuates by tens of dB with body orientation and walls, iOS restricts background BLE advertising/scanning, and RSSI is trivially relayed or amplified. It could only ever be a coarse hint, never a gate.
* Nearby Interaction (UWB) is not used: Mac mini has no UWB hardware and macOS does not offer it for this purpose.
* The real "presence" signal is a human tapping *Approve* and passing Face ID on a phone that must be in the foreground.

## Experimental credential adapter

Off by default; compiled only with `EXPERIMENTAL_CREDENTIAL_ADAPTER`; requires risk acknowledgement, authentication-only mode off, a password stored through a local consent sheet (verified with Open Directory, encrypted to a Secure Enclave key that needs **local** user presence to arm), Accessibility granted by you, a consumed `VerifiedApproval` < 5 s old, the expected locked console session, awake display, active secure input (owned by loginwindow when determinable), and rate limits (5/h, 10 s apart). Three consecutive failures disable it and disarm the vault. It never uses the pasteboard and never sends the password anywhere. Full evaluation: [docs/EXPERIMENTAL_ADAPTER.md](docs/EXPERIMENTAL_ADAPTER.md).

## Known limitations / residual risks

* Not native authentication: approvals are verified by an app in your session, not by loginwindow.
* Builds without a provisioning profile use the login keychain fallback (shown in Diagnostics).
* If the Mac stores a pairing but the phone never receives `pairComplete` (connection drop), the Mac lists a device the phone does not know; revoke it on the Mac.
* Lock on departure is a connectivity heuristic and fires when the iPhone app is backgrounded.
* Real-hardware validation of Face ID, Secure Enclave invalidation and the lock-screen adapter is still outstanding ([docs/TESTING.md](docs/TESTING.md)).

## Reporting

This is a personal project. Report problems privately to the repository owner; do not include passwords, keys or full logs of signed messages.
