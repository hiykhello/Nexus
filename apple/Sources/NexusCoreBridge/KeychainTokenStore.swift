import Foundation
#if canImport(Security)
import Security
#endif

/// Swift 6 Sendable Keychain wrapper for storing the Nexus HTTP control Bearer token
/// securely inside the shared macOS/iOS App Group Keychain without plaintext disk files.
public struct KeychainTokenStore: Sendable {
    public let service: String
    public let account: String
    public let accessGroup: String?

    public init(
        service: String = "org.nexus.apple.control",
        account: String = "bearer-token",
        accessGroup: String? = nil
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }

    public func saveToken(_ token: String) -> Bool {
        #if canImport(Security)
        guard let data = token.data(using: .utf8) else { return false }
        var query = baseQuery()
        SecItemDelete(query as CFDictionary)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
        #else
        return !token.isEmpty
        #endif
    }

    public func loadToken() -> String? {
        #if canImport(Security)
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
        #else
        return nil
        #endif
    }

    public func deleteToken() {
        #if canImport(Security)
        SecItemDelete(baseQuery() as CFDictionary)
        #endif
    }

    #if canImport(Security)
    private func baseQuery() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }
    #endif
}
