import Foundation
import MacNearUnlockShared

/// This Mac's long-term identity: a random Mac ID plus a P-256 signing key held in
/// the Secure Enclave (Apple silicon / T2). The key signs challenges and pairing
/// transcripts; it has no user-presence requirement because it must work while the
/// Mac is locked, and a Mac mini usually has no Touch ID.
struct MacIdentity {
    enum KeyKind: String, Codable {
        case secureEnclave = "Secure Enclave (non-exportable)"
        case software = "Software key in Keychain (no Secure Enclave found)"
    }

    let macID: UUID
    let signer: MessageSigner
    let kind: KeyKind

    var fingerprint: String { KeyFingerprint.display(signer.publicKeyX963) }
}

enum MacIdentityStore {
    private struct Stored: Codable {
        let macID: UUID
        let kind: MacIdentity.KeyKind
        /// Secure Enclave: opaque SE-encrypted blob. Software: raw private key.
        let keyData: Data
    }

    private static let account = "mac-identity-v1"

    static func loadOrCreate(keychain: KeychainStore) throws -> MacIdentity {
        if let data = try? keychain.read(account) {
            let stored = try JSONDecoder().decode(Stored.self, from: data)
            switch stored.kind {
            case .secureEnclave:
                return MacIdentity(macID: stored.macID, signer: try SecureEnclaveIdentitySigner(dataRepresentation: stored.keyData), kind: .secureEnclave)
            case .software:
                return MacIdentity(macID: stored.macID, signer: try SoftwareP256Signer(rawRepresentation: stored.keyData), kind: .software)
            }
        }
        let macID = UUID()
        let identity: MacIdentity
        let keyData: Data
        if SecureEnclaveIdentitySigner.isAvailable, let signer = try? SecureEnclaveIdentitySigner() {
            identity = MacIdentity(macID: macID, signer: signer, kind: .secureEnclave)
            keyData = signer.dataRepresentation
        } else {
            let signer = SoftwareP256Signer()
            identity = MacIdentity(macID: macID, signer: signer, kind: .software)
            keyData = signer.rawRepresentation
        }
        try keychain.write(account, data: try JSONEncoder().encode(Stored(macID: macID, kind: identity.kind, keyData: keyData)))
        return identity
    }

    /// Generates a new identity. Every existing pairing becomes invalid (phones pin
    /// the old key), so callers must also clear paired devices.
    static func reset(keychain: KeychainStore) throws {
        try keychain.delete(account)
    }
}

/// Trusted iPhones, stored as one Keychain item so the set of pinned public keys
/// and channel keys is integrity-protected (never in UserDefaults or plain files).
final class PairedDeviceStore {
    private let keychain: KeychainStore
    private let account = "paired-devices-v1"

    init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    func load() -> [PairedDeviceRecord] {
        guard let data = try? keychain.read(account),
              let records = try? JSONDecoder().decode([PairedDeviceRecord].self, from: data)
        else { return [] }
        return records.filter { SignatureVerifier.isValidPublicKey($0.publicKey) && $0.channelKey.count == 32 }
    }

    func save(_ records: [PairedDeviceRecord]) throws {
        if records.isEmpty {
            try keychain.delete(account)
        } else {
            try keychain.write(account, data: try JSONEncoder().encode(records))
        }
    }

    func add(_ record: PairedDeviceRecord) throws {
        var all = load().filter { $0.pairingID != record.pairingID }
        all.append(record)
        try save(all)
    }

    func remove(pairingID: UUID) throws {
        try save(load().filter { $0.pairingID != pairingID })
    }
}
