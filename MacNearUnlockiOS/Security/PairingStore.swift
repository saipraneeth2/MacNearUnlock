import Foundation
import MacNearUnlockShared
import Security

/// A trusted Mac on this iPhone: the pinned Mac identity, the per-pairing channel
/// key (TLS-PSK) and the tag of this pairing's Secure Enclave signing key.
struct StoredPairing: Codable, Identifiable, Equatable {
    var mac: PinnedMac
    let channelKey: Data
    let keyTag: String
    /// Opaque Face ID enrollment hash at pairing time (not biometric data).
    let biometryState: Data?

    var id: UUID { mac.pairingID }
}

/// Persists pairings as a single Keychain item: device-local
/// (`WhenUnlockedThisDeviceOnly`), excluded from iCloud Keychain and from backups
/// restored to other devices.
final class PairingStore {
    private let service = (Bundle.main.bundleIdentifier ?? "MacNearUnlock") + ".pairings"
    private let account = "pairings-v1"

    func load() -> [StoredPairing] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let pairings = try? JSONDecoder().decode([StoredPairing].self, from: data)
        else { return [] }
        return pairings
    }

    func save(_ pairings: [StoredPairing]) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if pairings.isEmpty {
            SecItemDelete(base as CFDictionary)
            return
        }
        let data = try JSONEncoder().encode(pairings)
        let update = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(update)) }
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }
}
