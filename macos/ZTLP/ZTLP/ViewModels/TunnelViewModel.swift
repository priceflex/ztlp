// TunnelViewModel.swift
// ZTLP macOS
//
// Manages the VPN tunnel lifecycle from the main app's perspective.
// Communicates with the System Extension via NETunnelProviderManager
// and observes shared UserDefaults for real-time state updates.
// Adapted from iOS — no UIKit haptics, uses NSApp/AppKit equivalents.

import Foundation
import AppKit
import NetworkExtension
import Combine
import SwiftUI

/// ViewModel for the main connect/disconnect UI.
@MainActor
final class TunnelViewModel: ObservableObject {

    // MARK: - Published State

    @Published private(set) var status: ConnectionStatus = .disconnected
    @Published private(set) var stats = TrafficStats()
    @Published private(set) var zoneName: String = ""
    @Published private(set) var peerAddress: String = ""
    @Published private(set) var lastError: String?
    @Published private(set) var isVPNConfigInstalled: Bool = false

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let networkMonitor = NetworkMonitor.shared
    private let sysExtManager = SystemExtensionManager.shared
    private var cancellables = Set<AnyCancellable>()
    private var tunnelManager: NETunnelProviderManager?
    private var statsTimer: Timer?

    private let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared.macos")

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.zoneName = configuration.zoneName
        setupObservers()
        loadTunnelManager()
    }

    // MARK: - Actions

    func toggleConnection() {
        switch status {
        case .disconnected:
            connect()
        case .connected, .reconnecting:
            disconnect()
        default:
            break
        }
    }

    func connect() {
        guard status.canConnect else { return }

        lastError = nil
        status = .connecting

        // macOS haptic feedback (trackpad)
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        Task {
            do {
                let manager = try await loadOrCreateTunnelManager()
                self.tunnelManager = manager

                let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol)
                    ?? NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.ztlp.app.macos.system-extension"
                proto.serverAddress = configuration.relayAddress.isEmpty
                    ? configuration.targetNodeId
                    : configuration.relayAddress
                proto.providerConfiguration = [
                    "targetNodeId": configuration.targetNodeId,
                    "relayAddress": configuration.relayAddress,
                    "stunServer": configuration.stunServer,
                    "tunnelAddress": configuration.tunnelAddress,
                    "dnsServers": configuration.dnsServers,
                    "mtu": configuration.mtu,
                ]

                manager.protocolConfiguration = proto
                manager.localizedDescription = "ZTLP VPN"
                manager.isEnabled = true

                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()

                let session = manager.connection as! NETunnelProviderSession
                try session.startVPNTunnel()

                startStatsPolling()

            } catch {
                status = .disconnected
                lastError = error.localizedDescription
                NSSound.beep()
            }
        }
    }

    func disconnect() {
        guard status.canDisconnect else { return }

        status = .disconnecting
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        tunnelManager?.connection.stopVPNTunnel()
        stopStatsPolling()
    }

    func sendMessageToExtension(_ message: Data) async -> Data? {
        guard let session = tunnelManager?.connection as? NETunnelProviderSession else {
            return nil
        }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(message) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    // MARK: - Private

    private func loadOrCreateTunnelManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == "com.ztlp.app.macos.system-extension"
        }) {
            return existing
        }

        return NETunnelProviderManager()
    }

    private func loadTunnelManager() {
        Task {
            do {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                if let manager = managers.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == "com.ztlp.app.macos.system-extension"
                }) {
                    self.tunnelManager = manager
                    self.isVPNConfigInstalled = true
                    updateStatusFromConnection(manager.connection)
                }
            } catch {
                self.isVPNConfigInstalled = false
            }
        }
    }

    private func setupObservers() {
        NotificationCenter.default.publisher(
            for: .NEVPNStatusDidChange
        )
        .receive(on: DispatchQueue.main)
        .sink { [weak self] notification in
            guard let self = self,
                  let connection = notification.object as? NEVPNConnection else { return }
            self.updateStatusFromConnection(connection)
        }
        .store(in: &cancellables)

        networkMonitor.interfaceChangePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self, self.status == .connected else { return }
                self.status = .reconnecting
            }
            .store(in: &cancellables)

        configuration.$zoneName
            .receive(on: DispatchQueue.main)
            .assign(to: &$zoneName)
    }

    private func updateStatusFromConnection(_ connection: NEVPNConnection) {
        switch connection.status {
        case .invalid, .disconnected:
            status = .disconnected
            stats.connectedSince = nil
            stopStatsPolling()
        case .connecting:
            status = .connecting
        case .connected:
            status = .connected
            stats.connectedSince = connection.connectedDate
            startStatsPolling()
            NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
        case .reasserting:
            status = .reconnecting
        case .disconnecting:
            status = .disconnecting
        @unknown default:
            break
        }
    }

    // MARK: - Stats Polling

    private func startStatsPolling() {
        stopStatsPolling()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshStats()
            }
        }
    }

    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
    }

    private func refreshStats() {
        guard let defaults = sharedDefaults else { return }
        stats.bytesSent = UInt64(defaults.integer(forKey: "ztlp_bytes_sent"))
        stats.bytesReceived = UInt64(defaults.integer(forKey: "ztlp_bytes_received"))
        if let since = defaults.object(forKey: "ztlp_connected_since") as? TimeInterval, since > 0 {
            stats.connectedSince = Date(timeIntervalSince1970: since)
        }
        peerAddress = defaults.string(forKey: "ztlp_peer_address") ?? ""
    }
}
