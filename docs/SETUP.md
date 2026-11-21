# Setup

Tested toolchain: macOS 27.0.1, Xcode 27.2 (27B52), Swift 6.4.2, macOS/iOS 27.2 SDKs.
Deployment targets: macOS 14.0 (MenuBarExtra + `SettingsLink`/`openWindow`, SMAppService), iOS 17.0 (`ContentUnavailableView`, current `onChange`); iOS 18's `LADomainState` is used when available with a fallback.

You need: a Mac (Apple silicon or T2 for the Secure Enclave identity key), an iPhone with Face ID and a passcode, both on the same local network, and an Apple Developer account signed into Xcode for device installation.

## 1. Signing

1. Xcode › Settings › Accounts: sign in with your Apple Developer account. *(This is the step that blocked device builds in the automated session: no account was signed into Xcode on the build Mac.)*
2. Copy `Config/Local.xcconfig.example` to `Config/Local.xcconfig` and set:
   ```
   DEVELOPMENT_TEAM = <your 10-character team ID>
   MNU_BUNDLE_PREFIX = com.<you>.macnearunlock
   ```
   The team ID is the `OU` of your Apple Development certificate (Xcode › Settings › Accounts › Manage Certificates), not the identifier shown in the certificate's name.
3. Open `MacNearUnlock.xcodeproj`. Both targets use Automatic signing.

Without an account in Xcode the Mac app can still be signed manually with an existing Apple Development certificate:

```bash
xcodebuild -project MacNearUnlock.xcodeproj -scheme MacNearUnlockMac -configuration Debug -destination 'platform=macOS' CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="Apple Development" build
```

### Keychain mode on the Mac
With a provisioning profile that grants a keychain access group, the Mac app uses the data-protection keychain (`AfterFirstUnlockThisDeviceOnly`). Without one (manual signing, no profile) it automatically falls back to the login keychain, ACL'd to the app's signature. Settings › Diagnostics shows which is active.

## 2. Mac app

1. In Xcode's toolbar choose **MacNearUnlockMac › My Mac** and run (or copy the built `MacNearUnlockMac.app` to `/Applications` and open it). Running the iPhone scheme does not start the Mac app — each Run starts one app. A lock/shield icon appears in the menu bar; there is no Dock icon. While no iPhone is paired, the **Pair iPhone** window opens automatically at launch (and again if you open the app while it is already running); afterwards a short on-screen message points to the menu bar icon.
2. Settings › General › *Open MacNearUnlock at login* (uses `SMAppService.mainApp`; if macOS asks, approve it in System Settings › General › Login Items).
3. The first time the app listens, macOS asks for **Local Network** access — allow it.
4. Leave **Authentication-only mode** on.

## 3. iPhone app

1. Connect the iPhone, select it as the run destination for **MacNearUnlockiOS**, enable Developer Mode on the phone if asked, and run.
2. Allow **Local Network** (to find the Mac) and **Camera** (only for scanning the pairing QR code).
3. The app requires Face ID and a device passcode. In the Simulator it explains that a Secure Enclave is required and refuses to pair — by design.

## 4. Pair

1. Mac: menu bar icon › **Pair iPhone…**. A QR code and a 16-character code appear (valid 2 minutes, single use).
2. iPhone: **+** › *Scan QR Code* (or *Enter Code Manually* and pick the Mac).
3. Both screens show the same 6 digits and 4 words. Compare them.
4. Mac: **Codes Match — Trust This iPhone**. iPhone: **Codes Match — Confirm with Face ID**.
5. Both show "Paired". The Mac's Devices tab lists the iPhone with its key fingerprint.

If anything differs or a warning appears, cancel. Re-pairing the same Mac on the iPhone replaces the old key.

## 5. Authentication test (no unlock)

* iPhone: open the Mac › **Run Authentication Test** › **Approve with Face ID**, or
* Mac: menu bar › **Send Test Approval** while the iPhone app is open.

You should see "Approval verified. Authentication-only…" on the iPhone, a green pill on the Mac, and a `security` entry in Settings › Diagnostics.

## 6. Locked-Mac approval (still authentication-only)

1. Keep the iPhone app open on screen. Lock the Mac (⌃⌘Q).
2. iPhone: **Request Unlock** › **Approve with Face ID**.
3. The iPhone reports the approval was verified; the Mac stays locked (authentication-only). Unlock with your password and check the Diagnostics log for `Approval VERIFIED for unlock-session`.

Face ID is only requested while the app is in the foreground. It is never shown when the app is in the background or the phone is locked.

## 7. Optional features

* **Lock on departure** (Settings › Security): run *Test Lock Now* (needs Accessibility for event posting), then enable. Remember it triggers whenever the iPhone app stops being connected, including when you switch apps.
* **Experimental credential entry**: read [EXPERIMENTAL_ADAPTER.md](EXPERIMENTAL_ADAPTER.md) first. Every step — risk acknowledgement, turning off authentication-only, entering your Mac password in the app's own sheet, granting Accessibility, arming with your Mac password — is done by you, locally, on the Mac.

## Removing everything

* Mac: revoke devices in Settings › Devices, quit, delete the app. Remove the Keychain items whose service is `<bundle id>.keys` (Keychain Access, or `security delete-generic-password -s <bundle id>.keys -a mac-identity-v1`, `… -a paired-devices-v1`, `… -a experimental-credential-v1`) and the preferences with `defaults delete <bundle id>`.
* iPhone: remove each Mac in the app (deletes its Secure Enclave key), then delete the app.
