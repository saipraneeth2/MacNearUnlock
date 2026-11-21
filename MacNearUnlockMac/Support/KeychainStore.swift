import Foundation
import Security

enum KeychainError: LocalizedError {
    case notFound
    case unexpectedData
    case status(OSStatus)

    var errorDescription: String? {
        switch self {
        case .notFound: return "Keychain item not found."
        case .unexpectedData: return "Keychain item had an unexpected format."
        case .status(let status):
            return "Keychain error: " + ((SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)")
        }
    }
}

/// Generic-password storage for the Mac app.
///
/// Prefers the data-protection keychain (`kSecUseDataProtectionKeychain`) with
/// `AfterFirstUnlockThisDeviceOnly`, so items never sync and stay readable while
/// the screen is locked (the engine must verify approvals on a locked Mac). That
/// keychain requires a keychain-access-group entitlement, which in turn needs a
/// provisioning profile; when the build lacks it (`errSecMissingEntitlement`) the
/// store falls back to the user's login keychain, whose ACL is bound to this app's
/// code signature. The active mode is shown in Diagnostics.
final class KeychainStore {
    enum Mode: String {
        case dataProtection = "Data protection keychain (this device only)"
        case legacyLogin = "Login keychain (ACL bound to app signature)"
    }

    let service: String
    private(set) var mode: Mode = .dataProtection

    init(service: String) {
        self.service = service
        probeMode()
    }

    func read(_ account: String) throws -> Data {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { throw KeychainError.unexpectedData }
            return data
        case errSecItemNotFound:
            throw KeychainError.notFound
        default:
            throw KeychainError.status(status)
        }
    }

    func write(_ account: String, data: Data) throws {
        let update = SecItemUpdate(baseQuery(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw KeychainError.status(update) }
        var add = baseQuery(account)
        add[kSecValueData as String] = data
        if mode == .dataProtection {
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    func delete(_ account: String) throws {
        let status = SecItemDelete(baseQuery(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
    }

    func exists(_ account: String) -> Bool {
        var query = baseQuery(account)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    private func baseQuery(_ account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if mode == .dataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }

    /// Probes with a real write: without a keychain-access-group entitlement a
    /// lookup in the data-protection keychain just reports "not found", while a
    /// write reports `errSecMissingEntitlement` (observed on macOS 27).
    private func probeMode() {
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "mode-probe",
            kSecUseDataProtectionKeychain as String: true,
        ]
        var add = probe
        add[kSecValueData as String] = Data([1])
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecMissingEntitlement {
            mode = .legacyLogin
            return
        }
        mode = .dataProtection
        if status == errSecSuccess || status == errSecDuplicateItem {
            SecItemDelete(probe as CFDictionary)
        }
    }
}
