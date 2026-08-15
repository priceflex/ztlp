// GatewayKeyPin.swift
// ZTLPTunnel (Network Extension)
//
// Trust-On-First-Use (TOFU) pinning for the gateway's static Noise
// public key, addressing SAST finding rhf-phvo: the handshake
// finalize call previously accepted ANY peer that completed the
// Noise_XX handshake with zero verification that it was actually the
// expected gateway.
//
// This is a minimal, self-contained Keychain helper rather than a
// dependency on the main app target's KeychainService.swift, because
// this Network Extension target does NOT currently link that file
// (single Sources build-file entry, confirmed via project.pbxproj) —
// pulling it in would require Xcode project surgery this fix
// deliberately avoids. Uses the SAME app group container
// ("group.com.ztlp.shared") as KeychainService.shared so a future
// main-app "reset gateway pin" UI could read/clear the same entries.

import Foundation
import Security

enum GatewayKeyPin {
    private static let service = "com.ztlp.shared"
    private static let accessGroup = "group.com.ztlp.shared"

    /// Verify the peer's static key against a pinned value for this
    /// target, or pin it if this is the first connection ever made to
    /// that target.
    ///
    /// - Returns: `nil` if the connection should proceed (first
    ///   connection, now pinned; or key matches the existing pin).
    ///   An `Error` if the peer's key does NOT match the pinned value
    ///   — the connection MUST be aborted in that case.
    static func verifyOrPin(target: String, peerKeyHex: String) -> Error? {
        let account = pinAccount(for: target)

        if let pinnedHex = load(account: account) {
            if pinnedHex.lowercased() == peerKeyHex.lowercased() {
                return nil
            }
            return NSError(
                domain: "ZTLPGatewayPin",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Gateway identity changed for \(target): pinned key does not match. " +
                        "This may indicate a man-in-the-middle attack, or the gateway was " +
                        "legitimately re-keyed (in which case the pin must be reset by the user)."
                ]
            )
        }

        // First connection to this target — pin it now.
        save(account: account, hex: peerKeyHex)
        return nil
    }

    private static func pinAccount(for target: String) -> String {
        "gateway_pin_\(target)"
    }

    private static func load(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func save(account: String, hex: String) {
        guard let data = hex.data(using: .utf8) else { return }
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }
}
