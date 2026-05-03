// SettingsViewModel.swift
// ZTLP
//
// Manages app settings, identity display, and about information.

import Foundation
import UIKit
import Combine
import NetworkExtension

/// ViewModel for the Settings screen.
@MainActor
final class SettingsViewModel: ObservableObject {

    // MARK: - Published State

    /// Identity information (loaded from keychain/bridge).
    @Published private(set) var identity: ZTLPIdentityInfo?

    /// Library version string.
    @Published private(set) var libraryVersion: String = "unknown"

    /// Whether the Secure Enclave is available on this device.
    @Published private(set) var secureEnclaveAvailable: Bool = false

    /// Whether the VPN configuration is installed.
    @Published private(set) var vpnConfigInstalled: Bool = false

    /// Status message for feedback.
    @Published private(set) var statusMessage: String?

    // MARK: - Dependencies

    let configuration: ZTLPConfiguration
    private let secureEnclave = SecureEnclaveService.shared

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.secureEnclaveAvailable = secureEnclave.isAvailable
        loadState()
    }

    // MARK: - Actions

    /// Load current state from the bridge and keychain.
    func loadState() {
        // Nebula pivot (S1.5): ZTLPBridge was deleted. Library version
        // and in-process identity loading are no-ops in the main app —
        // the Network Extension owns the ZTLP library surface now.
        libraryVersion = "n/a (NE-owned)"
        secureEnclaveAvailable = secureEnclave.isAvailable
        identity = nil
    }

    /// Regenerate the identity (destructive — new node ID).
    func regenerateIdentity() async {
        // Nebula pivot (S1.5): identity regeneration in the main app is
        // currently a no-op — it needs to run inside the Network
        // Extension. Surfaced as a feedback message for now.
        statusMessage = "Identity regeneration moved to the tunnel extension"
        UINotificationFeedbackGenerator().notificationOccurred(.warning)

        // Clear status after 3 seconds
        Task {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            statusMessage = nil
        }
    }

    /// Remove the VPN configuration from iOS Settings.
    func removeVPNConfiguration() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            for manager in managers {
                try await manager.removeFromPreferences()
            }
            vpnConfigInstalled = false
            statusMessage = "VPN configuration removed"
        } catch {
            statusMessage = "Failed to remove: \(error.localizedDescription)"
        }
    }

    /// Reset all settings and identity (factory reset).
    func factoryReset() async {
        // Remove VPN config
        await removeVPNConfiguration()

        // Delete identity from keychain
        try? KeychainService.shared.deleteIdentity()

        // Delete Secure Enclave key
        try? secureEnclave.deleteKey()

        // Reset configuration
        configuration.reset()

        // Clear identity
        identity = nil

        statusMessage = "All data cleared"
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }

    /// Export identity info as a shareable string.
    func exportIdentityString() -> String? {
        guard let id = identity else { return nil }
        return """
        ZTLP Identity
        Node ID: \(id.nodeId)
        Public Key: \(id.publicKey)
        Provider: \(id.providerType)
        Zone: \(id.zoneName ?? "not enrolled")
        """
    }

    // MARK: - Helpers

    private func defaultIdentityPath() -> String? {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.ztlp.shared"
        ) else { return nil }
        return containerURL.appendingPathComponent("identity.json").path
    }
}
