// KeychainService.swift
// ZTLP
//
// Keychain wrapper for storing ZTLP identity data securely.
// Uses the shared app group keychain so both the main app and the
// Network Extension can access the same identity.

import Foundation
import Security

/// Errors from Keychain operations.
enum KeychainError: LocalizedError {
    case saveFailed(OSStatus)
    case readFailed(OSStatus)
    case deleteFailed(OSStatus)
    case notFound
    case unexpectedData
    case accessControlCreationFailed

    var errorDescription: String? {
        switch self {
        case .saveFailed(let status):
            return "Keychain save failed: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)"
        case .readFailed(let status):
            return "Keychain read failed: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)"
        case .deleteFailed(let status):
            return "Keychain delete failed: \(SecCopyErrorMessageString(status, nil) ?? "unknown" as CFString)"
        case .notFound:
            return "Item not found in Keychain"
        case .unexpectedData:
            return "Unexpected data format in Keychain"
        case .accessControlCreationFailed:
            return "Failed to create Keychain access control"
        }
    }
}

/// Service for storing and retrieving ZTLP identity data in the iOS Keychain.
///
/// Data is stored in the shared app group keychain so the Network Extension
/// (which runs in a separate process) can access the same identity.
final class KeychainService {

    /// Shared singleton using the ZTLP app group.
    static let shared = KeychainService(accessGroup: "group.com.ztlp.shared")

    /// Keychain access group (app group identifier).
    private let accessGroup: String

    /// Service identifier for keychain items.
    private let service = "com.ztlp.identity"

    init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    // MARK: - Identity Storage

    /// Save the identity JSON data to the keychain.
    ///
    /// - Parameters:
    ///   - data: The identity JSON as raw bytes.
    ///   - label: A human-readable label (e.g., "Primary Identity").
    func saveIdentity(_ data: Data, label: String = "Primary Identity") throws {
        // Delete existing item first (SecItemUpdate can be flaky)
        try? deleteIdentity()

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "identity",
            kSecAttrLabel as String: label,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    /// Load the identity JSON data from the keychain.
    ///
    /// - Returns: The raw identity JSON bytes, or nil if not found.
    func loadIdentity() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "identity",
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.unexpectedData
            }
            return data
        case errSecItemNotFound:
            throw KeychainError.notFound
        default:
            throw KeychainError.readFailed(status)
        }
    }

    /// Delete the stored identity from the keychain.
    func deleteIdentity() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "identity",
            kSecAttrAccessGroup as String: accessGroup,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }

    /// Check whether an identity exists in the keychain.
    func hasIdentity() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "identity",
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess
    }

    // MARK: - Generic Key-Value Storage

    /// Save arbitrary data to the keychain under a key.
    func save(data: Data, forKey key: String) throws {
        try? delete(forKey: key)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    /// Load data from the keychain for a key.
    func load(forKey key: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.unexpectedData
            }
            return data
        case errSecItemNotFound:
            throw KeychainError.notFound
        default:
            throw KeychainError.readFailed(status)
        }
    }

    /// Delete a key from the keychain.
    func delete(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrAccessGroup as String: accessGroup,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}
