// TunnelViewModel.swift
// ZTLP
//
// Manages the VPN tunnel lifecycle from the main app's perspective.
// Communicates with the Network Extension via NETunnelProviderManager
// and observes shared UserDefaults for real-time state updates.

import Foundation
import NetworkExtension
import Combine
import SwiftUI

/// ViewModel for the main connect/disconnect UI.
@MainActor
final class TunnelViewModel: ObservableObject {

    // MARK: - Published State

    /// Current connection status.
    @Published private(set) var status: ConnectionStatus = .disconnected

    /// Traffic statistics.
    @Published private(set) var stats = TrafficStats()

    /// The zone name (from enrollment or settings).
    @Published private(set) var zoneName: String = ""

    /// The peer address we're connected to.
    @Published private(set) var peerAddress: String = ""

    /// Last error message (cleared on next connect attempt).
    @Published private(set) var lastError: String?

    /// Whether the VPN configuration is installed in iOS Settings.
    @Published private(set) var isVPNConfigInstalled: Bool = false

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let networkMonitor = NetworkMonitor.shared
    private var cancellables = Set<AnyCancellable>()
    private var tunnelManager: NETunnelProviderManager?
    private var statsTimer: Timer?

    /// Shared UserDefaults (app group) for reading extension state.
    private let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared")

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.zoneName = configuration.zoneName

        setupObservers()
        loadTunnelManager()
    }

    // MARK: - Actions

    /// Toggle the VPN connection.
    func toggleConnection() {
        switch status {
        case .disconnected:
            connect()
        case .connected, .reconnecting:
            disconnect()
        default:
            break // Transitioning — ignore
        }
    }

    /// Start the VPN tunnel.
    func connect() {
        guard status.canConnect else { return }

        lastError = nil
        status = .connecting

        // Haptic feedback
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()

        Task {
            do {
                let manager = try await loadOrCreateTunnelManager()
                self.tunnelManager = manager

                // Configure the provider protocol
                let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol)
                    ?? NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.ztlp.app.tunnel"
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

                // Start the tunnel
                let session = manager.connection as! NETunnelProviderSession
                try session.startVPNTunnel()

                // Start polling stats
                startStatsPolling()

            } catch {
                status = .disconnected
                lastError = error.localizedDescription

                // Haptic feedback for error
                UINotificationFeedbackGenerator().notificationOccurred(.error)
            }
        }
    }

    /// Stop the VPN tunnel.
    func disconnect() {
        guard status.canDisconnect else { return }

        status = .disconnecting

        // Haptic feedback
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()

        tunnelManager?.connection.stopVPNTunnel()
        stopStatsPolling()
    }

    /// Send a message to the tunnel extension and get a response.
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

    /// Load or create the NETunnelProviderManager.
    private func loadOrCreateTunnelManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        // Find our existing manager
        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == "com.ztlp.app.tunnel"
        }) {
            return existing
        }

        // Create a new one
        return NETunnelProviderManager()
    }

    /// Load the tunnel manager and check initial state.
    private func loadTunnelManager() {
        Task {
            do {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                if let manager = managers.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == "com.ztlp.app.tunnel"
                }) {
                    self.tunnelManager = manager
                    self.isVPNConfigInstalled = true
                    updateStatusFromConnection(manager.connection)
                }
            } catch {
                // No manager found — that's fine for first launch
                self.isVPNConfigInstalled = false
            }
        }
    }

    /// Set up observers for VPN status and network changes.
    private func setupObservers() {
        // Observe VPN connection status changes
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

        // Observe network interface changes (WiFi ↔ Cellular)
        networkMonitor.interfaceChangePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newInterface in
                guard let self = self, self.status == .connected else { return }
                // Network changed while connected — the extension handles reconnection.
                // We just note it in the UI.
                self.status = .reconnecting
            }
            .store(in: &cancellables)

        // Observe configuration changes
        configuration.$zoneName
            .receive(on: DispatchQueue.main)
            .assign(to: &$zoneName)
    }

    /// Map NEVPNConnection.status to our ConnectionStatus.
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
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        case .reasserting:
            status = .reconnecting
        case .disconnecting:
            status = .disconnecting
        @unknown default:
            break
        }
    }

    // MARK: - Stats Polling

    /// Start polling traffic stats from shared UserDefaults.
    private func startStatsPolling() {
        stopStatsPolling()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshStats()
            }
        }
    }

    /// Stop the stats polling timer.
    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
    }

    /// Read latest stats from shared UserDefaults.
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
