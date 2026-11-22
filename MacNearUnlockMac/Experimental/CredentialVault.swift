//
//  CredentialVault.swift
//  MacNearUnlock: EXPERIMENTAL credential adapter
//
//  Stores the macOS login password ONLY after explicit local opt-in. Design:
//
//  * The password is entered in this app's own local setup sheet, verified once
//    against Open Directory, then encrypted (ChaCha20-Poly1305) under a key derived
//    from ECDH with a Secure Enclave P-256 key-agreement key whose access control
//    is `.privateKeyUsage + .userPresence`. The Secure Enclave key never leaves the
//    hardware; the ciphertext is useless on any other Mac.
//  * Decrypting requires local user presence ON THE MAC (login-password dialog,
//    Apple Watch, or Touch ID if a Touch ID keyboard exists). An iPhone Face ID
//    approval does NOT and cannot satisfy that; it is a separate device.
//  * Because a Mac mini has no biometrics and nothing can prompt on the lock screen,
//    the user "arms" the vault once while unlocked: one local authentication derives
//    the wrapping key, which stays only in this process's memory for at most
//    `armLifetime`. Quitting, re-launching, disabling the adapter or repeated
//    failures disarm it. If it is not armed, credential entry fails closed.
//  * The password is never sent over the network, never placed on the pasteboard,
//    never logged, and is decrypted only for the instant of typing.
//

#if EXPERIMENTAL_CREDENTIAL_ADAPTER
import CryptoKit
import Foundation
import LocalAuthentication
import MacNearUnlockShared
import OpenDirectory

enum CredentialVaultError: LocalizedError {
    case secureEnclaveUnavailable
    case emptyPassword
    case passwordRejected
    case notStored
    case notArmed
    case corrupted
    case authenticationFailed(String)

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable: return "This Mac has no Secure Enclave; the experimental adapter cannot protect a stored password and stays disabled."
        case .emptyPassword: return "Password is empty."
        case .passwordRejected: return "macOS did not accept that password for the current user. Nothing was stored."
        case .notStored: return "No password is stored."
        case .notArmed: return "The stored password is not armed for this app session."
        case .corrupted: return "Stored credential could not be decrypted; delete it and set it up again."
        case .authenticationFailed(let reason): return "Local authentication failed: \(reason)"
        }
    }
}

final class CredentialVault: @unchecked Sendable {
    static let armLifetime: TimeInterval = 12 * 60 * 60

    private struct Stored: Codable {
        let version: Int
        let username: String
        let secureEnclaveKey: Data
        let ephemeralPublicKey: Data
        let sealedBox: Data
    }

    private let keychain: KeychainStore
    private let account = "experimental-credential-v1"
    private let lock = NSLock()
    private var armedKey: SymmetricKey?
    private var armedAt: Date?

    init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    var isStored: Bool { keychain.exists(account) }

    var isArmed: Bool {
        lock.withLock {
            guard armedKey != nil, let armedAt else { return false }
            if Date().timeIntervalSince(armedAt) > CredentialVault.armLifetime {
                armedKey = nil
                self.armedAt = nil
                return false
            }
            return true
        }
    }

    /// Verifies `password` for the current macOS user and stores it encrypted.
    /// Wipes the caller's buffer on every path.
    func store(password: inout Data) throws {
        defer { password.wipe() }
        guard SecureEnclave.isAvailable else { throw CredentialVaultError.secureEnclaveUnavailable }
        guard !password.isEmpty else { throw CredentialVaultError.emptyPassword }
        try Self.verifyLoginPassword(password)

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error) else {
            throw CredentialVaultError.authenticationFailed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "access control")
        }
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        // Encrypting uses only the enclave *public* key: no prompt.
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let key = Self.wrappingKey(shared: shared, ephemeralPublic: ephemeral.publicKey.x963Representation, enclavePublic: enclaveKey.publicKey.x963Representation)
        let sealed = try ChaChaPoly.seal(password, using: key).combined
        let stored = Stored(version: 1, username: NSUserName(), secureEnclaveKey: enclaveKey.dataRepresentation, ephemeralPublicKey: ephemeral.publicKey.x963Representation, sealedBox: sealed)
        try keychain.write(account, data: try JSONEncoder().encode(stored))
        disarm()
    }

    /// One local authentication on this Mac (password dialog / Watch / Touch ID).
    func arm(reason: String) async throws {
        guard let data = try? keychain.read(account), let stored = try? JSONDecoder().decode(Stored.self, from: data) else {
            throw CredentialVaultError.notStored
        }
        guard stored.username == NSUserName() else { throw CredentialVaultError.corrupted }
        let context = LAContext()
        context.localizedReason = reason
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            throw CredentialVaultError.authenticationFailed(error.localizedDescription)
        }
        do {
            let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored.secureEnclaveKey, authenticationContext: context)
            let ephemeralPublic = try P256.KeyAgreement.PublicKey(x963Representation: stored.ephemeralPublicKey)
            let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)
            let key = Self.wrappingKey(shared: shared, ephemeralPublic: stored.ephemeralPublicKey, enclavePublic: enclaveKey.publicKey.x963Representation)
            var check = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: stored.sealedBox), using: key)
            check.wipe()
            lock.withLock {
                armedKey = key
                armedAt = Date()
            }
        } catch {
            throw CredentialVaultError.corrupted
        }
    }

    func disarm() {
        lock.withLock {
            armedKey = nil
            armedAt = nil
        }
    }

    /// Decrypts with the armed key, passes the bytes to `body`, then wipes them.
    func withPassword<T>(_ body: (Data) throws -> T) throws -> T {
        guard isArmed, let key = lock.withLock({ armedKey }) else { throw CredentialVaultError.notArmed }
        guard let data = try? keychain.read(account), let stored = try? JSONDecoder().decode(Stored.self, from: data) else {
            throw CredentialVaultError.notStored
        }
        var plaintext: Data
        do {
            plaintext = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: stored.sealedBox), using: key)
        } catch {
            throw CredentialVaultError.corrupted
        }
        defer { plaintext.wipe() }
        return try body(plaintext)
    }

    func delete() throws {
        disarm()
        try keychain.delete(account)
    }

    private static func wrappingKey(shared: SharedSecret, ephemeralPublic: Data, enclavePublic: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeralPublic + enclavePublic,
            sharedInfo: Data("MacNearUnlock/v1/experimental-credential".utf8),
            outputByteCount: 32
        )
    }

    /// Open Directory check so a mistyped password is never stored and later typed
    /// repeatedly into the lock screen (which could trigger account lockout).
    private static func verifyLoginPassword(_ password: Data) throws {
        // OpenDirectory takes an NSString; that transient copy cannot be wiped.
        guard let text = String(data: password, encoding: .utf8) else { throw CredentialVaultError.passwordRejected }
        do {
            let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication))
            let record = try node.record(withRecordType: kODRecordTypeUsers, name: NSUserName(), attributes: nil)
            try record.verifyPassword(text)
        } catch {
            throw CredentialVaultError.passwordRejected
        }
    }
}
#endif
