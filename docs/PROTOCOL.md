# Protocol v1

Source of truth: `MacNearUnlockShared/Sources/MacNearUnlockShared`.

## Transport

* TCP via Network.framework, wrapped in **TLS 1.2 with `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` (0xCCAC)** — mutual authentication by pre-shared key, ephemeral ECDHE (forward secrecy), AEAD records. Min = max = TLS 1.2; the negotiated version/suite is checked before use.
* **Why not TLS 1.3 or certificates?** Probed on macOS 27.2 SDK: TLS 1.3 with an external PSK fails (`-9858 handshake failed`); TLS 1.2 ECDHE-PSK works, a server with several PSKs selects the client's identity correctly, a wrong key fails with `-9820 bad MAC` and an unknown identity with `-9864`. Self-signed certificate pinning would need hand-built X.509 and a `SecIdentity`; PSK gives the same pinning property without a CA or certificate parsing.
* **Channel binding.** TLS does not tell the server which PSK the client used, so the first message carries `binder = HMAC-SHA256(channelKey, canonical(client-hello domain, pairingID, deviceID, exporter))`, where `exporter` is the RFC 5705 exporter (`EXPORTER-MacNearUnlock-v1`, 32 bytes) of this TLS session. The Mac answers with a server binder under the same key (with its Mac ID). Both are compared in constant time.
* Bonjour: `_mnunlock._tcp` (paired sessions; TXT `v=1`, `mid=<Mac ID>`; preferred port 47311, falls back to any) and `_mnupair._tcp` (only while a pairing invitation is open). TXT data is untrusted and only selects an endpoint to try.
* Framing: `u32be length | JSON(WireMessage)`; length 1…16384. JSON is a container only — nothing is ever signed over JSON. Every decoded message is validated (`WireMessage.validate()`): exact lengths for nonces (32), public keys (65, on-curve), X25519 keys (32), binders (32), DER signatures (8…72); string byte limits; no control characters; protocol version 1.
* Limits: 8 connections, hello within 5 s, 20-message burst refilling at 5/s, idle timeout (default 45 s; the phone pings every 15 s), 5 suspicious messages → disconnect.

## Canonical signing bytes

```
"MNU1" | u16be(len(domain)) | domain
then per field, tags strictly increasing:  u8 tag | u32be(len) | value
```

Strings are NFC-normalised UTF-8; integers big-endian; UUIDs as 16 raw bytes. Domains:

| Domain | Signed by | Used for |
| --- | --- | --- |
| `MacNearUnlock/v1/unlock-request` | Mac identity key | Challenge authenticity (checked by iPhone) |
| `MacNearUnlock/v1/unlock-approval` | iPhone SE key (Face ID) | Approval |
| `MacNearUnlock/v1/pairing-transcript` | Mac identity key | Pairing challenge |
| `MacNearUnlock/v1/pairing-confirm` | iPhone SE key (Face ID) | Pairing confirmation |
| `MacNearUnlock/v1/pairing-complete` | Mac identity key | Pairing completion |
| `…/client-hello`, `…/server-hello` | HMAC (channel key) | Channel binding |
| `…/sas`, `…/channel-psk`, `…/pairing-psk` | — | Key/SAS derivation labels |

## Challenge (`UnlockRequest`)

| Tag | Field | Notes |
| --- | --- | --- |
| 1 | protocolVersion | 1 |
| 2 | requestID | random UUID |
| 3 | nonce | 32 bytes from `SecRandomCopyBytes`; never reused (checked against a 10-minute set) |
| 4 | macID | Mac identity |
| 5 | macName | display |
| 6 | macUsername | target account (`NSUserName()`) |
| 7 | pairingID | pairing it was issued to |
| 8 | deviceID | iPhone it was issued to |
| 9 | action | 1 = unlock-session, 2 = auth-test |
| 10 | issuedAtMillis | wall clock |
| 11 | expiresAtMillis | issued + lifetime (10…120 s, default 30) |

The approval bytes are the same fields under the approval domain plus tag 32 = `"approve"`. The Mac also keeps a **monotonic deadline** (`CLOCK_MONOTONIC`, counts through sleep). The iPhone rejects requests not signed by the pinned Mac key, for another Mac/pairing/device/user, with lifetime > 120 s, outside ±120 s skew, or already seen.

## Messages

| Type | Direction | Purpose |
| --- | --- | --- |
| `clientHello` / `serverHello` | ⇄ | Version, IDs, binders, current Mac status |
| `status` | Mac → iPhone | Lock state, engine state, auth-only flag |
| `initiate` | iPhone → Mac | User tapped Request Unlock / Run Test |
| `unlockRequest` | Mac → iPhone | Signed challenge |
| `approval` | iPhone → Mac | requestID, pairingID, deviceID, DER signature |
| `decline` | iPhone → Mac | Declined / Face ID cancelled / lockout / key invalidated |
| `result` | Mac → iPhone | verifiedAuthenticationOnly, verifiedCredentialEntryAttempted, unlocked, rejected, expired, failed |
| `revoke` | ⇄ | Forget this pairing |
| `ping` / `pong`, `error` | ⇄ | Liveness, diagnostics |
| `pairHello`, `pairChallenge`, `pairConfirm`, `pairComplete`, `pairAbort` | ⇄ | Pairing |

## Pairing

1. Mac opens an invitation: 80-bit `code`, PSK `= HKDF-SHA256(code, salt "MacNearUnlock pairing salt v1", info pairing-psk)`, identity `mnu1-pair`, Bonjour `_mnupair._tcp` under the Mac's name. QR: `macnearunlock://pair?v=1&c=<Crockford base32 code>&f=<base64url SHA-256(Mac key)>&n=<service name>`.
2. iPhone creates a new Secure Enclave key (`.biometryCurrentSet`) and an ephemeral X25519 key, connects, sends `pairHello`.
3. Mac sends `pairChallenge` (pairingID, Mac ID/name/user, Mac key, ephemeral key, nonce) signed over the transcript (both messages + TLS exporter).
4. iPhone checks the QR fingerprint (if scanned) and the transcript signature. Both sides display the SAS (6 digits + 4 words) from `SHA-256(sas domain ‖ transcriptHash)`.
5. User confirms on both. iPhone sends `pairConfirm` = Face ID signature over the transcript hash; Mac verifies it.
6. Mac derives `channelKey = HKDF(X25519 shared secret, salt transcriptHash, info channel-psk)`, stores the device record, sends `pairComplete` signed over (transcriptHash, pairingID). iPhone verifies and stores.

Expiry 2 minutes; burned after 3 failed TLS handshakes; any abort discards everything and deletes the new iPhone key.

## Mac state machine

```
idle ──sessionLocked──► locked ──requestIssued──► requesting ──requestDelivered──► awaitingBiometrics
  ▲  ◄──sessionUnlocked── (any)                        │  approvalRejected / requestExpired │ approvalVerified
  │                                                    ▼                                    ▼
  │ reset(locked:false)                       rejected / expired ◄────────────────────── verified
(any) ──sessionUnavailable──► unavailable (sleep, logout, other user on console, unreadable session)
```

`idle → requesting` is allowed for authentication tests. Every transition not in `UnlockStateMachine.transition(from:on:)` is rejected and leaves the state unchanged (tested).
