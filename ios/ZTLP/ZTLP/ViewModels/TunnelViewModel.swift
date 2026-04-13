// TunnelViewModel.swift
// ZTLP
//
// Manages the tunnel lifecycle via NETunnelProviderManager.
// The actual ZTLP connection runs in the PacketTunnelProvider extension,
// which stays alive as a VPN process even when the main app is suspended.
//
// The main app controls the extension (start/stop) and observes its status
// via NEVPNStatusDidChange notifications and shared UserDefaults.
//
// The tunnel runs in the extension process, so app-launched service access
// stays available while the main app is backgrounded.

import Foundation
import NetworkExtension
import Combine
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

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

    /// VIP proxy status (nil when not active).
    @Published private(set) var vipStatus: String?

    /// The service URL users can open from the app UI (nil when not connected).
    @Published private(set) var serviceURL: String?

    /// Pretty service name for display (e.g., "vault.techrockstars.ztlp").
    @Published private(set) var serviceDisplayName: String?

    /// Whether the device is enrolled.
    var isEnrolled: Bool { configuration.isEnrolled }

    /// Current reconnect attempt number (from extension state).
    @Published private(set) var reconnectAttempt: Int = 0

    /// Whether auto-reconnect is enabled.
    @Published var autoReconnectEnabled: Bool = true

    // MARK: - Dependencies

    private let configuration: ZTLPConfiguration
    private let logger = TunnelLogger.shared
    private var cancellables = Set<AnyCancellable>()
    private var statsTimer: Timer?

    /// The NETunnelProviderManager instance (loaded or created).
    private var vpnManager: NETunnelProviderManager?

    /// Shared UserDefaults (app group) for reading extension state.
    private let sharedDefaults = UserDefaults(suiteName: "group.com.ztlp.shared")

    // MARK: - Constants

    /// Bundle identifier of the NetworkExtension target.
    private static let tunnelBundleId = "com.ztlp.app.tunnel"

    /// VPN profile display name.
    private static let vpnProfileName = "ZTLP"

    // MARK: - Init

    init(configuration: ZTLPConfiguration) {
        self.configuration = configuration
        self.zoneName = configuration.zoneName

        setupObservers()
        loadVPNManager()
    }

    // MARK: - Actions

    /// Open the service URL using the system browser.
    func openServiceInSafari() {
        #if canImport(UIKit)
        guard let urlStr = serviceURL, let url = URL(string: urlStr) else { return }
        UIApplication.shared.open(url)
        #endif
    }

    /// Toggle the connection.
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

    /// Start the tunnel via NetworkExtension.
    func connect() {
        guard status.canConnect else { return }

        lastError = nil
        status = .connecting
        logger.info("Starting VPN tunnel...", source: "App")

        #if canImport(UIKit)
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        #endif

        // Clear any previous error
        sharedDefaults?.removeObject(forKey: "ztlp_last_error")

        Task {
            await startVPN()
        }
    }

    /// Stop the tunnel.
    func disconnect() {
        guard status.canDisconnect else { return }

        status = .disconnecting
        logger.info("Stopping VPN tunnel...", source: "App")

        #if canImport(UIKit)
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        #endif

        vpnManager?.connection.stopVPNTunnel()
    }

    // MARK: - VPN Manager

    /// Load the existing NETunnelProviderManager or create a new one.
    private func loadVPNManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor in
                guard let self = self else { return }

                if let error = error {
                    self.logger.error("Failed to load VPN managers: \(error.localizedDescription)", source: "App")
                    return
                }

                // Find our manager by bundle ID
                if let existing = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == Self.tunnelBundleId
                }) {
                    self.vpnManager = existing
                    self.logger.info("Loaded existing VPN manager", source: "App")
                    self.syncStatusFromVPNConnection()
                } else {
                    self.logger.info("No existing VPN manager found, will create on connect", source: "App")
                }
            }
        }
    }

    /// Start the VPN by configuring and saving the NETunnelProviderManager.
    private func startVPN() async {
        do {
            let manager = vpnManager ?? NETunnelProviderManager()

            // Configure the provider protocol
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.tunnelBundleId
            proto.serverAddress = configuration.relayAddress.isEmpty
                ? configuration.targetNodeId
                : configuration.relayAddress

            // Build provider configuration dictionary with all connection parameters
            let zone = configuration.zoneName.isEmpty ? "techrockstars" : configuration.zoneName.replacingOccurrences(of: ".ztlp", with: "")
            let tunnelConfig = TunnelConfiguration(
                targetNodeId: configuration.targetNodeId,
                relayAddress: configuration.relayAddress.isEmpty ? nil : configuration.relayAddress,
                stunServer: configuration.stunServer,
                tunnelAddress: configuration.tunnelAddress,
                tunnelNetmask: "255.255.255.0",
                dnsServers: ["127.0.55.53"],
                mtu: configuration.mtu,
                identityPath: nil,
                fullTunnel: false,
                nsServer: configuration.nsServer.isEmpty ? nil : configuration.nsServer,
                serviceName: configuration.serviceName.isEmpty ? nil : configuration.serviceName,
                zoneName: zone
            )
            proto.providerConfiguration = tunnelConfig.toDictionary()

            // Don't disconnect on sleep — we want the tunnel to survive
            proto.disconnectOnSleep = false

            manager.protocolConfiguration = proto
            manager.localizedDescription = Self.vpnProfileName
            manager.isEnabled = true

            // Save preferences (may prompt user for VPN permission)
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                manager.saveToPreferences { error in
                    if let error = error {
                        cont.resume(throwing: error)
                    } else {
                        cont.resume()
                    }
                }
            }

            self.vpnManager = manager
            logger.info("VPN manager saved", source: "App")

            // iOS requires re-loading after save to get accurate state
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                manager.loadFromPreferences { error in
                    if let error = error {
                        cont.resume(throwing: error)
                    } else {
                        cont.resume()
                    }
                }
            }

            // Start the VPN
            try manager.connection.startVPNTunnel()
            logger.info("VPN start requested", source: "App")

            // Update service display info
            let svc = configuration.serviceName
            if !svc.isEmpty {
                serviceURL = "http://127.0.0.1:8080"
                serviceDisplayName = "\(svc).\(zone).ztlp"
            }

        } catch {
            logger.error("Failed to start VPN: \(error.localizedDescription)", source: "App")
            status = .disconnected
            lastError = error.localizedDescription

            #if canImport(UIKit)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            #endif
        }
    }

    // MARK: - Status Observation

    /// Set up observers for VPN status changes and configuration.
    private func setupObservers() {
        // Observe VPN status changes from the system
        NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] notification in
                guard let self = self else { return }
                guard let connection = notification.object as? NEVPNConnection else { return }
                self.handleVPNStatusChange(connection.status)
            }
            .store(in: &cancellables)

        // Observe configuration changes
        configuration.$zoneName
            .receive(on: DispatchQueue.main)
            .assign(to: &$zoneName)
    }

    /// Map NEVPNStatus to our ConnectionStatus.
    private func handleVPNStatusChange(_ vpnStatus: NEVPNStatus) {
        logger.debug("VPN status changed: \(vpnStatus.rawValue)", source: "App")

        switch vpnStatus {
        case .invalid:
            status = .disconnected
            clearConnectionInfo()

        case .disconnected:
            status = .disconnected
            clearConnectionInfo()
            stopStatsPolling()

            // Check if the extension reported an error
            if let errorMsg = sharedDefaults?.string(forKey: "ztlp_last_error"),
               !errorMsg.isEmpty {
                lastError = errorMsg
                logger.warn("Extension reported error: \(errorMsg)", source: "App")
            }

        case .connecting:
            status = .connecting

        case .connected:
            status = .connected
            reconnectAttempt = 0
            stats.connectedSince = Date()

            // Read peer address from shared state
            if let peer = sharedDefaults?.string(forKey: "ztlp_peer_address") {
                peerAddress = peer
            }

            // Set service URL
            let svc = configuration.serviceName
            if !svc.isEmpty {
                serviceURL = "http://127.0.0.1:8080"
                let zone = configuration.zoneName.isEmpty ? "techrockstars" : configuration.zoneName.replacingOccurrences(of: ".ztlp", with: "")
                serviceDisplayName = "\(svc).\(zone).ztlp"
                vipStatus = "VIP proxy active — \(svc).\(zone).ztlp"
            }

            logger.info("VPN connected", source: "App")

            #if canImport(UIKit)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            #endif

            // Start polling stats from the extension
            startStatsPolling()

        case .reasserting:
            status = .reconnecting

        case .disconnecting:
            status = .disconnecting

        @unknown default:
            break
        }
    }

    /// Sync status from the current VPN connection state.
    private func syncStatusFromVPNConnection() {
        guard let connection = vpnManager?.connection else { return }
        handleVPNStatusChange(connection.status)
    }

    /// Clear connection-related info on disconnect.
    private func clearConnectionInfo() {
        peerAddress = ""
        serviceURL = nil
        serviceDisplayName = nil
        vipStatus = nil
        stats = TrafficStats()
    }

    // MARK: - Stats Polling

    /// Start polling traffic stats from the extension via sendProviderMessage.
    private func startStatsPolling() {
        stopStatsPolling()
        statsTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.requestStats()
            }
        }
    }

    /// Stop the stats polling timer.
    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
    }

    /// Request traffic stats from the extension.
    private func requestStats() {
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return }
        guard vpnManager?.connection.status == .connected else { return }

        do {
            try session.sendProviderMessage(Data([2])) { [weak self] response in
                Task { @MainActor in
                    guard let self = self,
                          let data = response,
                          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                        return
                    }
                    if let sent = json["bytesSent"] as? UInt64 {
                        self.stats.bytesSent = sent
                    }
                    if let received = json["bytesReceived"] as? UInt64 {
                        self.stats.bytesReceived = received
                    }
                }
            }
        } catch {
            logger.debug("Failed to request stats: \(error.localizedDescription)", source: "App")
        }
    }
}
