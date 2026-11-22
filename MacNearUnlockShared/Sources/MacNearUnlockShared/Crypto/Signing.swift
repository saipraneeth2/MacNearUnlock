import CryptoKit
import Foundation

/// Produces ECDSA P-256 / SHA-256 signatures in DER (X9.62) form.
///
/// Implementations:
/// * `SecureEnclaveIdentitySigner`: Mac identity key (Secure Enclave, no biometry,
///   because a Mac mini has no Touch ID and must sign challenges while locked).
/// * iPhone `BiometricSigner` (in the iOS target): Secure Enclave key with
///   `.biometryCurrentSet`; every signature requires a fresh Face ID match that the
///   Secure Enclave itself enforces.
/// * `SoftwareP256Signer`: tests and Macs without a Secure Enclave.
public protocol MessageSigner: AnyObject, Sendable {
    /// X9.63 uncompressed public key (65 bytes).
    var publicKeyX963: Data { get }
    /// Signs `message` (SHA-256 is applied internally). `reason` is shown in any
    /// system authentication prompt the signer triggers.
    func sign(_ message: Data, reason: String) async throws -> Data
}

public enum SignatureVerifier {
    public static func isValidPublicKey(_ x963: Data) -> Bool {
        guard x963.count == MNUProtocol.p256PublicKeyLength, x963.first == 0x04 else { return false }
        return (try? P256.Signing.PublicKey(x963Representation: x963)) != nil
    }

    /// Verifies a DER ECDSA P-256 signature over `message` with a pinned key.
    /// Returns false (never throws) on any malformed input.
    public static func isValid(signatureDER: Data, message: Data, publicKeyX963: Data) -> Bool {
        guard MNUProtocol.signatureLengthRange.contains(signatureDER.count),
              publicKeyX963.count == MNUProtocol.p256PublicKeyLength,
              let key = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }
}

public enum KeyFingerprint {
    /// SHA-256 over the X9.63 public key bytes.
    public static func sha256(_ publicKeyX963: Data) -> Data {
        Data(SHA256.hash(data: publicKeyX963))
    }

    /// Human-comparable rendering of the first 16 bytes: "A1B2 C3D4 …" (8 groups).
    public static func display(_ publicKeyX963: Data) -> String {
        let digest = sha256(publicKeyX963).prefix(16)
        var groups: [String] = []
        var index = digest.startIndex
        while index < digest.endIndex {
            let next = digest.index(index, offsetBy: 2, limitedBy: digest.endIndex) ?? digest.endIndex
            groups.append(digest[index..<next].map { String(format: "%02X", $0) }.joined())
            index = next
        }
        return groups.joined(separator: " ")
    }
}

/// In-memory software key. Used by tests and as the Mac identity fallback when no
/// Secure Enclave exists. Never used for iPhone approvals.
public final class SoftwareP256Signer: MessageSigner, @unchecked Sendable {
    private let privateKey: P256.Signing.PrivateKey
    public let publicKeyX963: Data

    public init() {
        privateKey = P256.Signing.PrivateKey()
        publicKeyX963 = privateKey.publicKey.x963Representation
    }

    public init(rawRepresentation: Data) throws {
        privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
        publicKeyX963 = privateKey.publicKey.x963Representation
    }

    /// Only for persisting the fallback Mac identity in the local Keychain.
    public var rawRepresentation: Data { privateKey.rawRepresentation }

    public func sign(_ message: Data, reason: String) async throws -> Data {
        try privateKey.signature(for: message).derRepresentation
    }
}

/// Mac identity key held in the Secure Enclave. `dataRepresentation` is an opaque
/// blob encrypted by this Mac's Secure Enclave; it is not the private key and is
/// useless on any other device.
public final class SecureEnclaveIdentitySigner: MessageSigner, @unchecked Sendable {
    private let privateKey: SecureEnclave.P256.Signing.PrivateKey
    public let publicKeyX963: Data

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Creates a new key usable only on this device, without any user-presence
    /// requirement (it must sign challenges while the Mac is locked).
    public init() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            throw (error?.takeRetainedValue() as Error?) ?? CocoaError(.featureUnsupported)
        }
        privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        publicKeyX963 = privateKey.publicKey.x963Representation
    }

    public init(dataRepresentation: Data) throws {
        privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
        publicKeyX963 = privateKey.publicKey.x963Representation
    }

    public var dataRepresentation: Data { privateKey.dataRepresentation }

    public func sign(_ message: Data, reason: String) async throws -> Data {
        try privateKey.signature(for: message).derRepresentation
    }
}
