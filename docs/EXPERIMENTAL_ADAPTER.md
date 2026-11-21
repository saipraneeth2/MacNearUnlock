# Experimental lock-screen credential adapter — evaluation

**Status: implemented, compiled in (`EXPERIMENTAL_CREDENTIAL_ADAPTER`), OFF by default, NOT validated on a real lock screen.**

## Why it was not validated

Validation needs three things that only you can do, and none were done in the automated session:

1. Store your **real Mac login password** — typed by you into the app's local sheet (never into a chat, terminal or file).
2. Grant **Accessibility** to MacNearUnlock in System Settings (no permission is granted programmatically).
3. **Lock the Mac** and approve from a **physical Face ID iPhone**, which also requires the iPhone build to be provisioned.

Until that happens the adapter stays disabled and its real-world behaviour on macOS 27 is unknown. The decision logic is unit-tested (`CredentialEntryPolicyTests`), and the engine path that hands it a verified approval is integration-tested with a stand-in (`testUnlockApprovalHandedToDelegateWhenAuthenticationOnlyIsOff`).

## How it differs from supported platform authentication

| | Platform login (password, Touch ID, Apple Watch) | This adapter |
| --- | --- | --- |
| Who decides | loginwindow / opendirectoryd / Secure Enclave | An app in your session decides, then types the password |
| Credential | Verified, never stored reversibly | Reversible copy stored (encrypted) on this Mac |
| Mechanism | Supported authentication APIs | Synthetic keyboard events (CGEvent, Accessibility) |
| After restart / logout / FileVault pre-boot | Works | Never works (app not running) — by design |
| Stability | Supported | May break in any macOS update |
| Focus | Built in | Inferred (secure input active, loginwindow owner when determinable) |
| Audit | System logs | App's own log |

## Design

* `CredentialVault`: password verified with Open Directory (`ODRecord.verifyPassword`) so a typo is never stored and later replayed into the lock screen; encrypted with ChaCha20-Poly1305 under a key from ECDH with a **Secure Enclave key whose ACL is `.privateKeyUsage + .userPresence`**. Arming requires local user presence on the Mac (password dialog / Apple Watch / Touch ID keyboard) — an iPhone Face ID result cannot satisfy a Mac Keychain/SE ACL and is not assumed to. Without a Secure Enclave the vault refuses to store (fail closed). Armed state is memory-only, ≤ 12 h.
* `ExperimentalCredentialAdapter`: consumes the `VerifiedApproval`, evaluates `CredentialEntryPolicy` (all of: enabled, acknowledged, auth-only off, < 3 consecutive failures, `.unlockSession` action, consumed, < 5 s old, expected user logged in + on console + locked, awake, Accessibility + event posting, secure input active and not owned by another process, vault armed, ≤ 5 attempts/hour, ≥ 10 s apart), re-checks the session right before typing, types via `KeystrokeInjector` (no pasteboard), then confirms success through CGSession within 6 s. Three consecutive failures disable it and disarm the vault.
* Isolation: everything lives in `MacNearUnlockMac/Experimental` inside `#if EXPERIMENTAL_CREDENTIAL_ADAPTER`; remove the flag from the target's *Active Compilation Conditions* to build without it.

## Validation procedure (when you decide to)

1. Pair and pass H1–H8 in [TESTING.md](TESTING.md) in authentication-only mode first.
2. Settings › Security: read the warning, tick the acknowledgement.
3. *Store Password…*: type your Mac password yourself in the sheet, tick consent, *Verify & Store*.
4. Grant Accessibility in System Settings › Privacy & Security › Accessibility (button provided).
5. *Arm…* (local authentication). Settings › Authentication: turn **off** authentication-only. Settings › Security: enable the adapter.
6. Lock the Mac. Wake the display and click/press a key so the password field has focus. On the iPhone: Request Unlock › Approve with Face ID.
7. Record: did it unlock? Did anything get typed elsewhere? Repeat after sleep/wake, with the display asleep, with fast user switching, and after a macOS update.
8. If it fails or behaves unexpectedly: turn it off, *Delete* the stored password, and keep using authentication-only mode. Report results in TESTING.md (H18).

## Known risks

* A reversible copy of your password exists; while armed, its key is in process memory.
* Synthetic events go to the focused field; the secure-input check reduces but cannot eliminate the chance of typing into the wrong secure field.
* macOS may ignore synthetic events at the lock screen in some versions, making it silently ineffective (the CGSession confirmation and auto-disable catch this).
* Typing a stale password (after you change it) counts as failed login attempts; three failures disable the adapter.
