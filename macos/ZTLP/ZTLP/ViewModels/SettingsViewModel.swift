// SettingsViewModel.swift
// ZTLP macOS
//
// Manages app settings, identity display, and about information.
// Adapted from iOS — no UIKit, uses AppKit equivalents.
//
// Task 6c: the System-VPN (NetworkExtension) path is gone; "factory reset"
// now also uninstalls the root agent service via SMAppService.

import Foundation
import AppKit
import Combine

/// ViewModel for the Settings screen.
@MainActor
final class SettingsViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var identity: ZTLPIdentityInfo?
    @Published private(set) var libraryVersion: String = "unknown"
    @Published private(set) var statusMessage: String?

    // MARK: - Dependencies

    let configuration: ZTLPConfiguration
    private let bridge = ZTLPBridge.shared

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        loadState()
    }

    // MARK: - Actions

    func loadState() {
        libraryVersion = bridge.version
        loadIdentity()
    }

    private func loadIdentity() {
        do {
            try bridge.initialize()
            let handle: ZTLPIdentityHandle
            if let path = defaultIdentityPath(), FileManager.default.fileExists(atPath: path) {
                handle = try bridge.loadIdentity(from: path)
            } else {
                handle = try bridge.generateIdentity()
            }
            identity = ZTLPIdentityInfo.from(
                handle: handle,
                providerType: configuration.useSecureEnclave ? "secure_enclave" : "software"
            )
        } catch {
            identity = nil
        }
    }

    func regenerateIdentity() async {
        do {
            try bridge.initialize()

            let handle = try bridge.generateIdentity()

            identity = ZTLPIdentityInfo.from(
                handle: handle,
                providerType: "software"
            )

            if let path = defaultIdentityPath() {
                try handle.save(to: path)
            }

            statusMessage = "New identity generated"
            NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)

        } catch {
            statusMessage = "Failed: \(error.localizedDescription)"
            NSSound.beep()
        }

        Task {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            statusMessage = nil
        }
    }

    /// Factory reset: uninstall the root agent service, forget the app's
    /// identity + settings. Does NOT delete the daemon's config dir under
    /// /Library/Application Support/ZTLP (root-owned; see
    /// AgentServiceInstaller.unregister for why that stays a separate step).
    func factoryReset() async {
        AgentServiceInstaller.shared.unregister()
        try? KeychainService.shared.deleteIdentity()
        if let path = defaultIdentityPath() {
            try? FileManager.default.removeItem(atPath: path)
        }
        configuration.reset()
        identity = nil
        statusMessage = "All data cleared"
        NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
    }

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

    /// Copy text to the macOS clipboard.
    func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)
    }

    // MARK: - Helpers

    private func defaultIdentityPath() -> String? {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first
        guard let dir = appSupport?.appendingPathComponent("ZTLP") else { return nil }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("identity.json").path
    }
}
