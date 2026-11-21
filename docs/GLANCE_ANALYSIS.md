# Reference review: Glance

Reviewed https://github.com/jonnyoo/glance (MIT, © 2026 Jonathan Zhou) at the default branch on 2026-11-21: `LockMonitor.swift`, `FaceUnlockCoordinator.swift`, `KeystrokeInjector.swift`, `SecureCredentialManager.swift`, `KeychainManager.swift`, `LaunchAtLogin.swift`, plus `POCController`, `SessionAutoLocker` and `NotchOverlay/NotchSkyLight.swift`.

**Key fact:** Glance does not use any system Face ID / login API. It recognises a face with the Mac's camera (Vision + an ArcFace model + liveness heuristics), and on a match **types the stored Mac password into the lock screen with CGEvent keyboard events**, which requires Accessibility permission. It is therefore no evidence that an official remote-unlock API exists.

## What works well (and was adopted)

* **Authoritative lock state** — `CGSessionCopyCurrentDictionary()["CGSSessionScreenIsLocked"]` instead of trusting `com.apple.screenIsLocked`, which any same-user process can post. Adopted, extended with `OnConsole`, `LoginDone`, user name and UID checks (fast user switching, logout) and periodic polling.
* **Sleep race awareness** — the lock notification can arrive ~150 ms before suspend, and a lock can happen while the process is suspended; Glance re-derives state on wake. Adopted (wake → refresh; sleep → invalidate and report unavailable).
* **SMAppService.mainApp** as the source of truth for launch at login. Same approach, re-implemented.
* **Keychain update-then-add** to avoid delete/add races. Same pattern.
* **Proving authentication by a gated read-back** rather than trusting `SecItemAdd` success. Same spirit: here the Secure Enclave signature *is* the proof.
* **Keystroke details** — clear the field with ⌘→ ⌘⌫ (layout-independent), Unicode batches of ≤ 20 UTF-16 units without splitting surrogate pairs, real ⌘ key events. Adapted with attribution in `Experimental/KeystrokeInjector.swift`.

## What is fragile

* **CGEvent into loginwindow.** Depends on Accessibility trust and on loginwindow accepting synthetic HID events into its secure field — undocumented behaviour that can change in any release. Keyboard focus is not verified: the events go to whatever has focus. MacNearUnlock adds a secure-input check (`IsSecureEventInputEnabled`), an optional loginwindow ownership check, and a fresh CGSession check immediately before typing.
* **`CGSSessionScreenIsLocked`** is an undocumented key (observed absent when unlocked on macOS 27.0.1). Both projects rely on it; MacNearUnlock treats an unreadable dictionary as *unavailable*.
* **Private SkyLight SPI** (`NotchSkyLight.swift` dlopens `SkyLight.framework` to draw over the lock screen). Not used here; the pill is a normal panel, invisible while locked.
* **Session-wide credential key.** Glance unwraps its key once per launch with Touch ID/user presence and keeps it for the whole run; any accepted face then types the password. MacNearUnlock keeps the same "arm once" constraint (nothing can prompt on the lock screen, and a Mac mini has no Touch ID) but bounds it to 12 hours, disarms on failures/disable/quit, and requires a consumed, < 5 s old, Secure-Enclave-signed approval for every entry.
* **Notch geometry, Sparkle updater, camera pipeline** — irrelevant to a Mac mini.

## What is specific to camera face recognition (not reused)

The face pipeline (`FaceDetector`, `ArcFaceEmbedder`, `FaceAligner`, `FaceRecognitionPipeline`), liveness cues (glare, bezel detection, geometry) and their thresholds exist because Glance must decide on the Mac, from camera frames, whether the face is the owner and is live. The file header admits a replayed video can defeat liveness. MacNearUnlock replaces that whole decision with Apple's Face ID on the iPhone and a Secure Enclave signature the Mac verifies cryptographically — no camera, no model, no threshold on the Mac.
