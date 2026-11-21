import CryptoKit
import Foundation
import LocalAuthentication
import MacNearUnlockShared
import Security

enum BiometricError: LocalizedError, Equatable {
    case secureEnclaveUnavailable
    case biometryNotAvailable
    case biometryNotEnrolled
    case passcodeNotSet
    case biometryLockout
    case cancelled
    case notRecognized
    /// Face ID enrollment changed since pairing (`.biometryCurrentSet`).
    case biometryChanged
    /// The Secure Enclave key no longer exists (deleted, or invalidated by an
    /// enrollment change or passcode removal).
    case keyMissing
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable: return "This device has no Secure Enclave (for example, the Simulator). A physical iPhone with Face ID is required."
        case .biometryNotAvailable: return "Face ID is not available. MacNearUnlock requires Face ID and does not fall back to the passcode."
        case .biometryNotEnrolled: return "Set up Face ID in Settings first."
        case .passcodeNotSet: return "Set a device passcode first; the signing key requires one."
        case .biometryLockout: return "Face ID is locked after too many attempts. Unlock your iPhone with its passcode, then try again."
        case .cancelled: return "Face ID was cancelled."
        case .notRecognized: return "Face ID did not recognize you."
        case .biometryChanged: return "Face ID enrollment changed since pairing. For security this pairing must be removed and created again."
        case .keyMissing: return "The signing key for this pairing is no longer valid. Remove the pairing and pair again."
        case .failed(let message): return message
        }
    }

    var requiresRepair: Bool { self == .biometryChanged || self == .keyMissing }

    var declineReason: DeclineReason {
        switch self {
        case .cancelled, .notRecognized: return .biometricCancelled
        case .biometryLockout: return .biometricLockout
        case .biometryChanged, .keyMissing: return .keyInvalidated
        default: return .biometricUnavailable
        }
    }

    static func from(_ error: Error?) -> BiometricError {
        guard let error else { return .failed("Unknown error") }
        if let laError = error as? LAError {
            switch laError.code {
            case .userCancel, .systemCancel, .appCancel, .userFallback: return .cancelled
            case .authenticationFailed: return .notRecognized
            case .biometryLockout: return .biometryLockout
            case .biometryNotEnrolled: return .biometryNotEnrolled
            case .biometryNotAvailable: return .biometryNotAvailable
            case .passcodeNotSet: return .passcodeNotSet
            default: return .failed(laError.localizedDescription)
            }
        }
        return .failed(error.localizedDescription)
    }
}

/// Approval signer backed by a Secure Enclave P-256 key created with
/// `.privateKeyUsage + .biometryCurrentSet` and
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.
///
/// * The private key is generated inside the Secure Enclave and is never exportable.
/// * The Secure Enclave itself refuses to sign unless the `LAContext` carries a fresh
///   Face ID match (reuse duration 0): the approval is not an app-controlled boolean.
/// * Enrolling a new face (or removing Face ID / the passcode) permanently
///   invalidates the key, forcing an explicit re-pair.
/// * No passcode fallback: `.biometryCurrentSet` cannot be satisfied by the passcode,
///   and the fallback button is hidden.
/// * The app never sees face images, templates or any biometric data.
final class BiometricSigner: MessageSigner, @unchecked Sendable {
    let tag: String
    let publicKeyX963: Data
    private let expectedBiometryState: Data?

    private init(tag: String, publicKeyX963: Data, expectedBiometryState: Data?) {
        self.tag = tag
        self.publicKeyX963 = publicKeyX963
        self.expectedBiometryState = expectedBiometryState
    }

    // MARK: Availability

    static func checkAvailability() throws {
        guard SecureEnclave.isAvailable else { throw BiometricError.secureEnclaveUnavailable }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw BiometricError.from(error)
        }
        guard context.biometryType == .faceID || context.biometryType == .opticID || context.biometryType == .touchID else {
            throw BiometricError.biometryNotAvailable
        }
    }

    /// Opaque hash of the current biometric enrollment (never biometric data).
    static func currentBiometryState() -> Data? {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return nil }
        return biometryState(of: context)
    }

    private static func biometryState(of context: LAContext) -> Data? {
        if #available(iOS 18.0, *) {
            return context.domainState.biometry.stateHash
        } else {
            return context.evaluatedPolicyDomainState
        }
    }

    private static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error) else {
            throw BiometricError.failed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Access control unavailable")
        }
        return access
    }

    // MARK: Key lifecycle

    static func create(tag: String) throws -> BiometricSigner {
        try checkAvailability()
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: try accessControl(),
            ] as [String: Any],
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw BiometricError.failed((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Could not create Secure Enclave key")
        }
        return BiometricSigner(tag: tag, publicKeyX963: try publicKey(of: privateKey), expectedBiometryState: nil)
    }

    static func load(tag: String, expectedBiometryState: Data?) throws -> BiometricSigner {
        let key = try fetch(tag: tag, context: nil)
        return BiometricSigner(tag: tag, publicKeyX963: try publicKey(of: key), expectedBiometryState: expectedBiometryState)
    }

    static func delete(tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func fetch(tag: String, context: LAContext?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw status == errSecItemNotFound ? BiometricError.keyMissing : BiometricError.failed("Keychain error \(status)")
        }
        return item as! SecKey
    }

    private static func publicKey(of privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              SignatureVerifier.isValidPublicKey(data)
        else { throw BiometricError.failed("Could not read the public key") }
        return data
    }

    // MARK: Signing (one Face ID match per signature)

    func sign(_ message: Data, reason: String) async throws -> Data {
        let context = LAContext()
        context.localizedFallbackTitle = "" // hide "Enter Passcode": no silent downgrade
        context.localizedCancelTitle = "Cancel"
        context.touchIDAuthenticationAllowableReuseDuration = 0
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw BiometricError.from(error)
        }
        if let expectedBiometryState, let current = Self.biometryState(of: context), current != expectedBiometryState {
            throw BiometricError.biometryChanged
        }
        let key = try Self.fetch(tag: tag, context: context)
        do {
            _ = try await context.evaluateAccessControl(try Self.accessControl(), operation: .useKeySign, localizedReason: reason)
        } catch {
            throw BiometricError.from(error)
        }
        // The Secure Enclave checks the context's biometric authorization here.
        return try await Task.detached(priority: .userInitiated) {
            var signError: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &signError) as Data? else {
                let underlying = signError?.takeRetainedValue() as Error?
                throw underlying.map { BiometricError.from($0) } ?? BiometricError.keyMissing
            }
            return signature
        }.value
    }
}
